//! Per-peer inbound message rate limiting (T123).
//!
//! This module provides `PeerRateLimiter`, a thread-safe rate limiter that tracks
//! message rates per peer using a token bucket algorithm. It is designed to prevent
//! a single Byzantine or misbehaving peer from flooding the node with consensus
//! messages.
//!
//! # Design
//!
//! The rate limiter uses a token bucket algorithm per peer:
//! - Each peer has a bucket of tokens (capacity = burst allowance)
//! - Tokens refill at `max_messages_per_second` rate
//! - Each `allow()` call consumes one token if available
//! - If no token is available, the message is rejected (should be dropped)
//!
//! # Thread Safety
//!
//! The implementation uses sharded locking to reduce contention:
//! - Peers are hashed into `NUM_SHARDS` buckets
//! - Each shard has its own `RwLock<HashMap<PeerId, TokenBucket>>`
//! - This allows concurrent rate-limit checks for different peers
//!
//! # Configuration
//!
//! The rate limiter is configured with:
//! - `max_messages_per_second`: Maximum sustained message rate per peer
//! - `burst_allowance`: Number of messages allowed in a burst above the rate
//!
//! # Safety
//!
//! Dropping inbound messages does not create safety violations in the consensus
//! protocol. It may delay QC formation and affect liveness, but cannot cause
//! conflicting commits. The HotStuff safety properties are preserved because:
//! - Votes can be re-sent if not acknowledged
//! - Proposals can be re-requested or will be re-sent by the leader
//! - The 3-chain commit rule doesn't depend on message delivery guarantees
//!
//! # Fail-Open Behavior
//!
//! If any internal error occurs (e.g., lock poisoning, arithmetic overflow),
//! the rate limiter fails open (allows the message) rather than panicking.
//! This ensures that transient issues don't cause node crashes.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

#[cfg(test)]
use std::time::Duration;

use crate::peer::PeerId;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default maximum messages per second per peer.
///
/// This is set conservatively high to avoid false positives during normal
/// consensus operation. A typical HotStuff consensus round involves:
/// - 1 proposal per round
/// - n votes per round (where n = number of validators)
///
/// For a 100-validator network at 10 rounds/second, legitimate traffic is
/// ~1000 messages/second aggregate, so ~10 msgs/s per peer. We set the limit
/// at 1000 msgs/s to allow for bursts and catch only clear abuse.
pub const DEFAULT_MAX_MESSAGES_PER_SECOND: u64 = 1_000;

/// Default burst allowance (number of tokens above the rate limit).
///
/// This allows short bursts of messages (e.g., during epoch transitions or
/// view changes) without triggering rate limiting.
pub const DEFAULT_BURST_ALLOWANCE: u64 = 100;

/// Number of shards for the rate limiter.
///
/// Using 16 shards provides good concurrency for typical validator set sizes
/// (4-100 validators) while keeping memory overhead low.
const NUM_SHARDS: usize = 16;

// ============================================================================
// PeerRateLimiterConfig
// ============================================================================

/// Configuration for the per-peer rate limiter.
#[derive(Debug, Clone, Copy)]
pub struct PeerRateLimiterConfig {
    /// Maximum messages per second per peer (sustained rate).
    pub max_messages_per_second: u64,

    /// Burst allowance above the rate limit (bucket capacity bonus).
    pub burst_allowance: u64,
}

impl Default for PeerRateLimiterConfig {
    fn default() -> Self {
        Self {
            max_messages_per_second: DEFAULT_MAX_MESSAGES_PER_SECOND,
            burst_allowance: DEFAULT_BURST_ALLOWANCE,
        }
    }
}

impl PeerRateLimiterConfig {
    /// Create a new configuration with the specified parameters.
    pub fn new(max_messages_per_second: u64, burst_allowance: u64) -> Self {
        Self {
            max_messages_per_second,
            burst_allowance,
        }
    }

    /// Create a configuration for testing with low limits.
    ///
    /// This is useful for unit tests that need to trigger rate limiting
    /// without sending thousands of messages.
    pub fn for_testing(max_messages_per_second: u64, burst_allowance: u64) -> Self {
        Self::new(max_messages_per_second, burst_allowance)
    }
}

// ============================================================================
// TokenBucket
// ============================================================================

/// A token bucket for rate limiting a single peer.
///
/// # Algorithm
///
/// The token bucket algorithm works as follows:
/// 1. The bucket has a capacity of `max_messages_per_second + burst_allowance`
/// 2. Tokens refill at `max_messages_per_second` tokens per second
/// 3. Each `allow()` call consumes one token
/// 4. If the bucket is empty, the message is rejected
///
/// # Time Tracking
///
/// We track `last_update` and compute elapsed time to calculate token refill.
/// This avoids the need for background tasks or timers.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens in the bucket.
    /// We use f64 for fractional token accumulation during refill.
    tokens: f64,

    /// Maximum bucket capacity (max_msgs/s + burst).
    capacity: f64,

    /// Token refill rate (tokens per second).
    refill_rate: f64,

    /// Last time the bucket was updated.
    last_update: Instant,
}

impl TokenBucket {
    /// Create a new token bucket with the given configuration.
    ///
    /// The bucket starts full (at capacity).
    fn new(config: &PeerRateLimiterConfig, now: Instant) -> Self {
        let capacity = (config.max_messages_per_second + config.burst_allowance) as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_rate: config.max_messages_per_second as f64,
            last_update: now,
        }
    }

    /// Try to consume a token from the bucket.
    ///
    /// Returns `true` if a token was consumed (message allowed),
    /// `false` if the bucket is empty (message should be dropped).
    fn try_consume(&mut self, now: Instant) -> bool {
        // Refill tokens based on elapsed time
        self.refill(now);

        // Try to consume a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last update.
    fn refill(&mut self, now: Instant) {
        // Calculate elapsed time
        let elapsed = now.saturating_duration_since(self.last_update);
        let elapsed_secs = elapsed.as_secs_f64();

        // Add tokens based on refill rate
        // Guard against very large elapsed times (e.g., clock jumps)
        let tokens_to_add = if elapsed_secs > 0.0 && elapsed_secs < 3600.0 {
            elapsed_secs * self.refill_rate
        } else if elapsed_secs >= 3600.0 {
            // If more than an hour has passed, just fill to capacity
            self.capacity
        } else {
            0.0
        };

        // Update tokens (capped at capacity)
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_update = now;
    }
}

// ============================================================================
// RateLimitShard
// ============================================================================

/// A single shard of the rate limiter.
///
/// Each shard contains a map of peer buckets protected by a RwLock.
struct RateLimitShard {
    /// Per-peer token buckets.
    buckets: RwLock<HashMap<PeerId, TokenBucket>>,
}

impl RateLimitShard {
    fn new() -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
        }
    }
}

// ============================================================================
// PeerRateLimiter
// ============================================================================

/// Per-peer inbound message rate limiter.
///
/// This struct provides thread-safe rate limiting for inbound consensus messages
/// on a per-peer basis using a sharded token bucket implementation.
///
/// # Usage
///
/// ```ignore
/// let limiter = PeerRateLimiter::new(PeerRateLimiterConfig::default());
///
/// // In the reader task, before forwarding a message:
/// if !limiter.allow(&peer_id, Instant::now()) {
///     // Drop the message, increment metrics
///     continue;
/// }
/// // Forward the message
/// ```
///
/// # Thread Safety
///
/// The rate limiter is safe to share across multiple reader tasks. It uses
/// sharded RwLocks to minimize contention when checking rates for different peers.
pub struct PeerRateLimiter {
    /// Configuration for the rate limiter.
    config: PeerRateLimiterConfig,

    /// Sharded storage for per-peer buckets.
    /// We use a fixed array of shards to avoid dynamic allocation.
    shards: [RateLimitShard; NUM_SHARDS],
}

impl PeerRateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: PeerRateLimiterConfig) -> Self {
        // Initialize shards
        // Note: We can't use array initialization syntax with non-Copy types,
        // so we use a workaround.
        let shards = std::array::from_fn(|_| RateLimitShard::new());

        Self { config, shards }
    }

    /// Create a new rate limiter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PeerRateLimiterConfig::default())
    }

    /// Check if a message from the given peer is allowed.
    ///
    /// Returns `true` if the message should be processed, `false` if it should
    /// be dropped due to rate limiting.
    ///
    /// # Arguments
    ///
    /// - `peer`: The peer ID that sent the message
    /// - `now`: The current time (use `Instant::now()`)
    ///
    /// # Fail-Open Behavior
    ///
    /// If any internal error occurs (lock poisoning), this method returns `true`
    /// to avoid dropping messages due to internal errors.
    pub fn allow(&self, peer: &PeerId, now: Instant) -> bool {
        let shard_idx = self.shard_index(peer);
        let shard = &self.shards[shard_idx];

        // Fast path: try to read and check existing bucket
        {
            let buckets = match shard.buckets.read() {
                Ok(b) => b,
                Err(_) => return true, // Fail open on lock poisoning
            };

            if buckets.contains_key(peer) {
                // We need write access to update the bucket, so we can't do it here.
                // Fall through to the slow path.
                drop(buckets);
            } else {
                drop(buckets);
            }
        }

        // Slow path: acquire write lock to update or create bucket
        let mut buckets = match shard.buckets.write() {
            Ok(b) => b,
            Err(_) => return true, // Fail open on lock poisoning
        };

        let bucket = buckets
            .entry(*peer)
            .or_insert_with(|| TokenBucket::new(&self.config, now));

        bucket.try_consume(now)
    }

    /// Get the shard index for a peer.
    fn shard_index(&self, peer: &PeerId) -> usize {
        // Use a simple hash of the peer ID
        (peer.0 as usize) % NUM_SHARDS
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PeerRateLimiterConfig {
        &self.config
    }

    /// Remove a peer's rate limit state (e.g., when the peer disconnects).
    ///
    /// This is optional but can help reduce memory usage for long-running nodes
    /// that see many transient peers.
    pub fn remove_peer(&self, peer: &PeerId) {
        let shard_idx = self.shard_index(peer);
        let shard = &self.shards[shard_idx];

        if let Ok(mut buckets) = shard.buckets.write() {
            buckets.remove(peer);
        }
    }

    /// Get the number of tracked peers across all shards.
    ///
    /// This is primarily for testing and metrics.
    pub fn tracked_peer_count(&self) -> usize {
        let mut count = 0;
        for shard in &self.shards {
            if let Ok(buckets) = shard.buckets.read() {
                count += buckets.len();
            }
        }
        count
    }

    /// Get the current token count for a peer (for testing).
    ///
    /// Returns `None` if the peer is not tracked.
    #[cfg(test)]
    pub fn get_tokens(&self, peer: &PeerId, now: Instant) -> Option<f64> {
        let shard_idx = self.shard_index(peer);
        let shard = &self.shards[shard_idx];

        let mut buckets = shard.buckets.write().ok()?;
        let bucket = buckets.get_mut(peer)?;
        bucket.refill(now);
        Some(bucket.tokens)
    }
}

impl Default for PeerRateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// Make PeerRateLimiter Send + Sync for use across async tasks
// This is safe because:
// - The config is immutable after construction
// - The shards use RwLock which is Send + Sync
unsafe impl Send for PeerRateLimiter {}
unsafe impl Sync for PeerRateLimiter {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_under_limit() {
        let config = PeerRateLimiterConfig::new(10, 5); // 10/s + 5 burst = 15 capacity
        let now = Instant::now();
        let mut bucket = TokenBucket::new(&config, now);

        // Should allow 15 messages immediately (bucket starts full)
        for _ in 0..15 {
            assert!(bucket.try_consume(now));
        }

        // 16th should be rejected
        assert!(!bucket.try_consume(now));
    }

    #[test]
    fn test_token_bucket_refills_over_time() {
        let config = PeerRateLimiterConfig::new(10, 0); // 10/s, no burst
        let now = Instant::now();
        let mut bucket = TokenBucket::new(&config, now);

        // Drain all tokens
        for _ in 0..10 {
            assert!(bucket.try_consume(now));
        }
        assert!(!bucket.try_consume(now));

        // After 100ms, should have ~1 token
        let later = now + Duration::from_millis(100);
        bucket.refill(later);
        assert!(bucket.tokens >= 0.9 && bucket.tokens <= 1.1);

        // After 1 second total, should be back to full
        let much_later = now + Duration::from_secs(1);
        bucket.refill(much_later);
        assert!((bucket.tokens - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_rate_limiter_allows_normal_traffic() {
        let config = PeerRateLimiterConfig::new(100, 10);
        let limiter = PeerRateLimiter::new(config);
        let peer = PeerId(42);
        let now = Instant::now();

        // Should allow first 110 messages (100 rate + 10 burst)
        for _ in 0..110 {
            assert!(limiter.allow(&peer, now));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess_traffic() {
        let config = PeerRateLimiterConfig::new(10, 5);
        let limiter = PeerRateLimiter::new(config);
        let peer = PeerId(42);
        let now = Instant::now();

        // Drain the bucket
        for _ in 0..15 {
            assert!(limiter.allow(&peer, now));
        }

        // Next message should be blocked
        assert!(!limiter.allow(&peer, now));
    }

    #[test]
    fn test_rate_limiter_tracks_peers_independently() {
        let config = PeerRateLimiterConfig::new(5, 0);
        let limiter = PeerRateLimiter::new(config);
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        let now = Instant::now();

        // Drain peer1's bucket
        for _ in 0..5 {
            assert!(limiter.allow(&peer1, now));
        }
        assert!(!limiter.allow(&peer1, now));

        // peer2 should still have full bucket
        for _ in 0..5 {
            assert!(limiter.allow(&peer2, now));
        }
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let config = PeerRateLimiterConfig::new(10, 0);
        let limiter = PeerRateLimiter::new(config);
        let peer = PeerId(42);
        let now = Instant::now();

        // Drain the bucket
        for _ in 0..10 {
            assert!(limiter.allow(&peer, now));
        }
        assert!(!limiter.allow(&peer, now));

        // After 1 second, bucket should be refilled
        let later = now + Duration::from_secs(1);
        for _ in 0..10 {
            assert!(limiter.allow(&peer, later));
        }
    }

    #[test]
    fn test_rate_limiter_remove_peer() {
        let config = PeerRateLimiterConfig::new(10, 0);
        let limiter = PeerRateLimiter::new(config);
        let peer = PeerId(42);
        let now = Instant::now();

        // Use some tokens
        limiter.allow(&peer, now);
        assert_eq!(limiter.tracked_peer_count(), 1);

        // Remove peer
        limiter.remove_peer(&peer);
        assert_eq!(limiter.tracked_peer_count(), 0);

        // Peer should get a fresh bucket
        // (starts with full capacity)
        for _ in 0..10 {
            assert!(limiter.allow(&peer, now));
        }
    }

    #[test]
    fn test_boundary_exactly_at_limit() {
        let config = PeerRateLimiterConfig::new(10, 0);
        let limiter = PeerRateLimiter::new(config);
        let peer = PeerId(42);
        let now = Instant::now();

        // Use exactly all tokens
        for i in 0..10 {
            assert!(limiter.allow(&peer, now), "Failed at message {}", i);
        }

        // Next should fail
        assert!(!limiter.allow(&peer, now));

        // But after getting 1 token back (100ms at 10/s)
        let later = now + Duration::from_millis(100);
        assert!(limiter.allow(&peer, later));
    }

    #[test]
    fn test_default_config_values() {
        let config = PeerRateLimiterConfig::default();
        assert_eq!(
            config.max_messages_per_second,
            DEFAULT_MAX_MESSAGES_PER_SECOND
        );
        assert_eq!(config.burst_allowance, DEFAULT_BURST_ALLOWANCE);
    }
}
