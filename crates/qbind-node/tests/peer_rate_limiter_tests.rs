//! Unit tests for the per-peer rate limiter (T123).
//!
//! This test module validates the correctness of `PeerRateLimiter` including:
//! - Token bucket algorithm behavior
//! - Per-peer tracking independence
//! - Rate limit enforcement and refill over time
//! - Boundary conditions (exactly at limit, just over limit)
//! - Thread safety under concurrent access
//!
//! These tests are placed in `crates/qbind-node/tests/` as required by the
//! task specification (no tests inside `src/` using `#[cfg(test)]`).

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use qbind_node::{
    PeerId, PeerRateLimiter, PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE,
    DEFAULT_MAX_MESSAGES_PER_SECOND,
};

// ============================================================================
// Basic functionality tests
// ============================================================================

/// Test that `allow()` returns true under normal traffic within the limit.
#[test]
fn test_allow_returns_true_under_normal_traffic() {
    let config = PeerRateLimiterConfig::new(100, 10); // 100/s + 10 burst = 110 capacity
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // First 110 messages should all be allowed (bucket starts full)
    for i in 0..110 {
        assert!(
            limiter.allow(&peer, now),
            "Message {} should be allowed within capacity",
            i
        );
    }
}

/// Test that when the per-peer limit is exceeded, `allow()` returns false.
#[test]
fn test_allow_returns_false_when_limit_exceeded() {
    let config = PeerRateLimiterConfig::new(10, 5); // 10/s + 5 burst = 15 capacity
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Drain all tokens
    for i in 0..15 {
        assert!(limiter.allow(&peer, now), "Message {} should be allowed", i);
    }

    // 16th message should be rejected
    assert!(
        !limiter.allow(&peer, now),
        "Message 16 should be rate-limited (bucket empty)"
    );

    // Multiple additional attempts should all fail
    for _ in 0..5 {
        assert!(
            !limiter.allow(&peer, now),
            "Should continue rejecting while bucket is empty"
        );
    }
}

/// Test that after enough time passes, `allow()` returns true again (bucket refill).
#[test]
fn test_bucket_refills_over_time() {
    let config = PeerRateLimiterConfig::new(10, 0); // 10/s, no burst
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Drain all tokens
    for _ in 0..10 {
        assert!(limiter.allow(&peer, now));
    }
    assert!(!limiter.allow(&peer, now));

    // After 1 second, bucket should be fully refilled
    let one_second_later = now + Duration::from_secs(1);
    for i in 0..10 {
        assert!(
            limiter.allow(&peer, one_second_later),
            "After 1s, message {} should be allowed",
            i
        );
    }
}

/// Test that partial refill works correctly.
#[test]
fn test_partial_bucket_refill() {
    let config = PeerRateLimiterConfig::new(10, 0); // 10/s
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Drain all tokens
    for _ in 0..10 {
        limiter.allow(&peer, now);
    }

    // After 100ms, should have ~1 token
    let hundred_ms_later = now + Duration::from_millis(100);
    assert!(
        limiter.allow(&peer, hundred_ms_later),
        "After 100ms at 10/s rate, should have ~1 token"
    );

    // Immediately asking for another should fail (only ~0 tokens left)
    assert!(
        !limiter.allow(&peer, hundred_ms_later),
        "Second message at same time should fail"
    );
}

// ============================================================================
// Per-peer independence tests
// ============================================================================

/// Test that multiple peers are tracked independently.
#[test]
fn test_peers_tracked_independently() {
    let config = PeerRateLimiterConfig::new(5, 0);
    let limiter = PeerRateLimiter::new(config);
    let peer1 = PeerId(1);
    let peer2 = PeerId(2);
    let peer3 = PeerId(3);
    let now = Instant::now();

    // Drain peer1's bucket
    for _ in 0..5 {
        assert!(limiter.allow(&peer1, now));
    }
    assert!(!limiter.allow(&peer1, now), "peer1 should be rate-limited");

    // peer2 should still have full bucket
    for i in 0..5 {
        assert!(
            limiter.allow(&peer2, now),
            "peer2 message {} should be allowed",
            i
        );
    }
    assert!(
        !limiter.allow(&peer2, now),
        "peer2 should now be rate-limited"
    );

    // peer3 is untouched
    for i in 0..5 {
        assert!(
            limiter.allow(&peer3, now),
            "peer3 message {} should be allowed",
            i
        );
    }
}

/// Test that the rate limiter correctly distributes peers across shards.
#[test]
fn test_sharding_distribution() {
    let config = PeerRateLimiterConfig::new(100, 0);
    let limiter = PeerRateLimiter::new(config);
    let now = Instant::now();

    // Create many peers to test sharding
    for i in 0..100 {
        let peer = PeerId(i as u64);
        assert!(limiter.allow(&peer, now));
    }

    // All peers should be tracked
    assert_eq!(limiter.tracked_peer_count(), 100);
}

// ============================================================================
// Boundary condition tests
// ============================================================================

/// Test behavior exactly at the rate limit boundary.
#[test]
fn test_boundary_exactly_at_limit() {
    let config = PeerRateLimiterConfig::new(10, 0);
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Use exactly all tokens
    for i in 0..10 {
        assert!(
            limiter.allow(&peer, now),
            "Message {} at limit should work",
            i
        );
    }

    // Next should fail (exactly at 0 tokens)
    assert!(!limiter.allow(&peer, now), "11th message should fail");

    // After getting 1 token back (100ms at 10/s), should allow exactly 1
    let hundred_ms_later = now + Duration::from_millis(100);
    assert!(
        limiter.allow(&peer, hundred_ms_later),
        "After 100ms, 1 token should be available"
    );
    assert!(
        !limiter.allow(&peer, hundred_ms_later),
        "After using the 1 token, next should fail"
    );
}

/// Test behavior when just over the limit.
#[test]
fn test_boundary_just_over_limit() {
    let config = PeerRateLimiterConfig::new(10, 0);
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Drain bucket plus one extra attempt
    for _ in 0..10 {
        limiter.allow(&peer, now);
    }

    // This is the first rejection
    let first_reject = limiter.allow(&peer, now);
    assert!(!first_reject, "Should reject at 11 messages");

    // More rejections
    assert!(!limiter.allow(&peer, now), "12th should also reject");
    assert!(!limiter.allow(&peer, now), "13th should also reject");
}

/// Test with zero burst allowance.
#[test]
fn test_zero_burst_allowance() {
    let config = PeerRateLimiterConfig::new(5, 0);
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Should only allow exactly 5 messages
    for _ in 0..5 {
        assert!(limiter.allow(&peer, now));
    }
    assert!(!limiter.allow(&peer, now));
}

/// Test with large burst allowance.
#[test]
fn test_large_burst_allowance() {
    let config = PeerRateLimiterConfig::new(10, 1000); // 10/s + 1000 burst
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Should allow 1010 messages in burst
    for i in 0..1010 {
        assert!(
            limiter.allow(&peer, now),
            "Message {} should be allowed with large burst",
            i
        );
    }
    assert!(!limiter.allow(&peer, now));
}

// ============================================================================
// Configuration tests
// ============================================================================

/// Test default configuration values.
#[test]
fn test_default_config_values() {
    let config = PeerRateLimiterConfig::default();
    assert_eq!(
        config.max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
    assert_eq!(config.burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

/// Test custom configuration.
#[test]
fn test_custom_config() {
    let config = PeerRateLimiterConfig::new(500, 50);
    assert_eq!(config.max_messages_per_second, 500);
    assert_eq!(config.burst_allowance, 50);
}

/// Test testing configuration helper.
#[test]
fn test_for_testing_config() {
    let config = PeerRateLimiterConfig::for_testing(5, 2);
    assert_eq!(config.max_messages_per_second, 5);
    assert_eq!(config.burst_allowance, 2);
}

// ============================================================================
// Peer removal tests
// ============================================================================

/// Test removing a peer's rate limit state.
#[test]
fn test_remove_peer() {
    let config = PeerRateLimiterConfig::new(10, 0);
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Use some tokens
    for _ in 0..5 {
        limiter.allow(&peer, now);
    }
    assert_eq!(limiter.tracked_peer_count(), 1);

    // Remove peer
    limiter.remove_peer(&peer);
    assert_eq!(limiter.tracked_peer_count(), 0);

    // Peer should get a fresh bucket (starts full)
    for _ in 0..10 {
        assert!(limiter.allow(&peer, now));
    }
}

/// Test removing a non-existent peer (should not panic).
#[test]
fn test_remove_nonexistent_peer() {
    let limiter = PeerRateLimiter::with_defaults();
    let peer = PeerId(999);

    // Should not panic
    limiter.remove_peer(&peer);
    assert_eq!(limiter.tracked_peer_count(), 0);
}

// ============================================================================
// Thread safety tests
// ============================================================================

/// Test concurrent access from multiple threads.
#[test]
fn test_thread_safety_concurrent_access() {
    let config = PeerRateLimiterConfig::new(1000, 100); // High limit to avoid rate limiting
    let limiter = Arc::new(PeerRateLimiter::new(config));

    let mut handles = vec![];

    // Spawn multiple threads, each using a different peer
    for peer_idx in 0..10 {
        let limiter_clone = Arc::clone(&limiter);
        let handle = thread::spawn(move || {
            let peer = PeerId(peer_idx as u64);
            let now = Instant::now();
            let mut allowed = 0;
            for _ in 0..100 {
                if limiter_clone.allow(&peer, now) {
                    allowed += 1;
                }
            }
            allowed
        });
        handles.push(handle);
    }

    // Join all threads and verify results
    let mut total_allowed = 0;
    for handle in handles {
        let allowed = handle.join().expect("Thread panicked");
        total_allowed += allowed;
    }

    // Each peer has capacity 1100 (1000 + 100), so all 100 messages per peer should be allowed
    assert_eq!(total_allowed, 1000);
}

/// Test concurrent access to the same peer from multiple threads.
#[test]
fn test_thread_safety_same_peer_concurrent() {
    let config = PeerRateLimiterConfig::new(100, 0);
    let limiter = Arc::new(PeerRateLimiter::new(config));
    let peer = PeerId(42);

    let mut handles = vec![];

    // Spawn multiple threads, all using the same peer
    for _ in 0..5 {
        let limiter_clone = Arc::clone(&limiter);
        let handle = thread::spawn(move || {
            let now = Instant::now();
            let mut allowed = 0;
            for _ in 0..50 {
                if limiter_clone.allow(&peer, now) {
                    allowed += 1;
                }
            }
            allowed
        });
        handles.push(handle);
    }

    // Join all threads
    let mut total_allowed = 0;
    for handle in handles {
        let allowed = handle.join().expect("Thread panicked");
        total_allowed += allowed;
    }

    // Total capacity is 100, so total allowed should be 100
    // (some threads will see rejections as they compete)
    assert_eq!(total_allowed, 100, "Total allowed should equal capacity");
}

// ============================================================================
// Time handling edge cases
// ============================================================================

/// Test behavior with very small time increments.
#[test]
fn test_small_time_increments() {
    let config = PeerRateLimiterConfig::new(1000, 0); // 1000/s = 1 per ms
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // Drain bucket
    for _ in 0..1000 {
        limiter.allow(&peer, now);
    }
    assert!(!limiter.allow(&peer, now));

    // After 1ms, should have ~1 token
    let one_ms_later = now + Duration::from_millis(1);
    assert!(limiter.allow(&peer, one_ms_later));
}

/// Test that time going backwards (or same time) doesn't cause issues.
#[test]
fn test_same_instant_multiple_calls() {
    let config = PeerRateLimiterConfig::new(10, 0);
    let limiter = PeerRateLimiter::new(config);
    let peer = PeerId(42);
    let now = Instant::now();

    // All calls at the exact same instant
    let mut allowed = 0;
    for _ in 0..20 {
        if limiter.allow(&peer, now) {
            allowed += 1;
        }
    }

    // Should only allow capacity (10)
    assert_eq!(allowed, 10);
}

// ============================================================================
// High load tests
// ============================================================================

/// Test behavior under high load (many messages, many peers).
#[test]
fn test_high_load_many_peers() {
    let config = PeerRateLimiterConfig::new(100, 10);
    let limiter = PeerRateLimiter::new(config);
    let now = Instant::now();

    // Create 1000 peers, each sending a few messages
    for peer_idx in 0..1000 {
        let peer = PeerId(peer_idx);
        for _ in 0..5 {
            limiter.allow(&peer, now);
        }
    }

    assert_eq!(limiter.tracked_peer_count(), 1000);
}

/// Test default limiter with default config.
#[test]
fn test_default_limiter() {
    let limiter = PeerRateLimiter::with_defaults();
    let peer = PeerId(42);
    let now = Instant::now();

    // Should be able to send many messages with default config
    // Default: 1000/s + 100 burst = 1100 capacity
    for i in 0..1100 {
        assert!(
            limiter.allow(&peer, now),
            "Message {} should be allowed with default config",
            i
        );
    }
}

// ============================================================================
// Debug trait tests
// ============================================================================

/// Test that config can be formatted for debugging.
#[test]
fn test_config_debug() {
    let config = PeerRateLimiterConfig::new(100, 10);
    let debug_str = format!("{:?}", config);
    assert!(debug_str.contains("100"));
    assert!(debug_str.contains("10"));
}
