//! Network and runtime observability metrics for the async consensus node.
//!
//! This module provides lightweight, atomic counter-based metrics for monitoring
//! the async node runtime and consensus networking layer. Metrics are designed
//! to be low-overhead and suitable for high-throughput consensus paths.
//!
//! # Design (T89)
//!
//! Following the existing `ConsensusSigMetrics` pattern in `qbind-consensus`,
//! we use `AtomicU64` counters with relaxed ordering for performance.
//!
//! # Metrics Categories
//!
//! - **Inbound network**: Messages received from peers (by type)
//! - **Outbound network**: Messages sent to peers (by type)
//! - **Channel health**: Queue drops, backpressure events
//! - **Runtime events**: Ticks, incoming messages, shutdowns processed
//! - **spawn_blocking**: Usage count and latency buckets
//! - **Per-peer metrics (T90.4)**: Inbound/outbound/disconnect counters per peer
//!
//! # Thread Safety
//!
//! All metrics are safe for concurrent access from multiple threads/tasks.
//! Counters use `Ordering::Relaxed` which is acceptable for observability
//! where exact ordering is not required.
//!
//! # Security
//!
//! Metrics intentionally do not expose:
//! - Cryptographic keys or signatures
//! - Message contents or payloads
//! - Suite IDs or validator identities
//!
//! Only aggregate counts, durations, and queue sizes are tracked.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::consensus_net_worker::ConsensusMsgPriority;
use crate::peer::PeerId;
use qbind_consensus::ValidatorId;
use qbind_net::kem_metrics::KemOpMetrics;

// ============================================================================
// NetworkMetrics - Inbound and outbound message tracking
// ============================================================================

/// Metrics for consensus network message flow.
///
/// Tracks inbound and outbound message counts by type, as well as
/// channel-related failures (drops, closures).
///
/// # Priority-Based Metrics (T90.3)
///
/// In addition to aggregate counters, we track metrics by priority:
/// - `consensus_net_outbound_total{kind="...", priority="critical|normal|low"}`
/// - `consensus_net_outbound_dropped_total{priority="normal|low"}` (critical should never drop)
///
/// # Prometheus-style naming
///
/// The getter methods follow Prometheus naming conventions:
/// - `consensus_net_inbound_total{kind="vote"}` → `inbound_vote_total()`
/// - `consensus_net_outbound_total{kind="vote_broadcast"}` → `outbound_vote_broadcast_total()`
/// - `consensus_net_outbound_dropped_total` → `outbound_dropped_total()`
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    // Inbound message counters
    inbound_vote_total: AtomicU64,
    inbound_proposal_total: AtomicU64,
    inbound_other_total: AtomicU64,

    // Outbound message counters (aggregate)
    outbound_vote_send_to_total: AtomicU64,
    outbound_vote_broadcast_total: AtomicU64,
    outbound_proposal_broadcast_total: AtomicU64,

    // Channel failure counters (aggregate)
    outbound_dropped_total: AtomicU64,
    inbound_channel_closed_total: AtomicU64,

    // Outbound queue depth (approximate, set by sender)
    outbound_queue_depth: AtomicU64,

    // ========================================================================
    // Priority-based metrics (T90.3)
    // ========================================================================

    // Outbound by priority - vote_send_to
    outbound_vote_send_to_critical: AtomicU64,
    outbound_vote_send_to_normal: AtomicU64,
    outbound_vote_send_to_low: AtomicU64,

    // Outbound by priority - vote_broadcast
    outbound_vote_broadcast_critical: AtomicU64,
    outbound_vote_broadcast_normal: AtomicU64,
    outbound_vote_broadcast_low: AtomicU64,

    // Outbound by priority - proposal_broadcast
    outbound_proposal_broadcast_critical: AtomicU64,
    outbound_proposal_broadcast_normal: AtomicU64,
    outbound_proposal_broadcast_low: AtomicU64,

    // Drops by priority (critical should never have drops)
    outbound_dropped_critical: AtomicU64,
    outbound_dropped_normal: AtomicU64,
    outbound_dropped_low: AtomicU64,

    // Critical channel metrics
    outbound_critical_total: AtomicU64,
    outbound_critical_worker_total: AtomicU64,

    // Critical backpressure wait time buckets (similar to SpawnBlockingMetrics)
    critical_wait_under_1ms: AtomicU64,
    critical_wait_1ms_to_10ms: AtomicU64,
    critical_wait_10ms_to_100ms: AtomicU64,
    critical_wait_over_100ms: AtomicU64,
}

impl NetworkMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Inbound message counters
    // ========================================================================

    /// Get count of inbound vote messages.
    pub fn inbound_vote_total(&self) -> u64 {
        self.inbound_vote_total.load(Ordering::Relaxed)
    }

    /// Get count of inbound proposal messages.
    pub fn inbound_proposal_total(&self) -> u64 {
        self.inbound_proposal_total.load(Ordering::Relaxed)
    }

    /// Get count of other inbound messages.
    pub fn inbound_other_total(&self) -> u64 {
        self.inbound_other_total.load(Ordering::Relaxed)
    }

    /// Increment inbound vote counter.
    pub fn inc_inbound_vote(&self) {
        self.inbound_vote_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment inbound proposal counter.
    pub fn inc_inbound_proposal(&self) {
        self.inbound_proposal_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment inbound other counter.
    pub fn inc_inbound_other(&self) {
        self.inbound_other_total.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Outbound message counters
    // ========================================================================

    /// Get count of targeted vote sends.
    pub fn outbound_vote_send_to_total(&self) -> u64 {
        self.outbound_vote_send_to_total.load(Ordering::Relaxed)
    }

    /// Get count of vote broadcasts.
    pub fn outbound_vote_broadcast_total(&self) -> u64 {
        self.outbound_vote_broadcast_total.load(Ordering::Relaxed)
    }

    /// Get count of proposal broadcasts.
    pub fn outbound_proposal_broadcast_total(&self) -> u64 {
        self.outbound_proposal_broadcast_total
            .load(Ordering::Relaxed)
    }

    /// Increment targeted vote send counter.
    pub fn inc_outbound_vote_send_to(&self) {
        self.outbound_vote_send_to_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment vote broadcast counter.
    pub fn inc_outbound_vote_broadcast(&self) {
        self.outbound_vote_broadcast_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment proposal broadcast counter.
    pub fn inc_outbound_proposal_broadcast(&self) {
        self.outbound_proposal_broadcast_total
            .fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Channel failure counters
    // ========================================================================

    /// Get count of dropped outbound messages.
    pub fn outbound_dropped_total(&self) -> u64 {
        self.outbound_dropped_total.load(Ordering::Relaxed)
    }

    /// Get count of inbound channel closures.
    pub fn inbound_channel_closed_total(&self) -> u64 {
        self.inbound_channel_closed_total.load(Ordering::Relaxed)
    }

    /// Increment outbound dropped counter.
    pub fn inc_outbound_dropped(&self) {
        self.outbound_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment inbound channel closed counter.
    pub fn inc_inbound_channel_closed(&self) {
        self.inbound_channel_closed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Queue depth (gauge-like)
    // ========================================================================

    /// Get approximate outbound queue depth.
    pub fn outbound_queue_depth(&self) -> u64 {
        self.outbound_queue_depth.load(Ordering::Relaxed)
    }

    /// Set the outbound queue depth (approximate).
    pub fn set_outbound_queue_depth(&self, depth: u64) {
        self.outbound_queue_depth.store(depth, Ordering::Relaxed);
    }

    // ========================================================================
    // Priority-based metrics (T90.3)
    // ========================================================================

    /// Increment outbound vote_send_to counter by priority.
    pub fn inc_outbound_vote_send_to_by_priority(&self, priority: ConsensusMsgPriority) {
        match priority {
            ConsensusMsgPriority::Critical => {
                self.outbound_vote_send_to_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Normal => {
                self.outbound_vote_send_to_normal
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Low => {
                self.outbound_vote_send_to_low
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment outbound vote_broadcast counter by priority.
    pub fn inc_outbound_vote_broadcast_by_priority(&self, priority: ConsensusMsgPriority) {
        match priority {
            ConsensusMsgPriority::Critical => {
                self.outbound_vote_broadcast_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Normal => {
                self.outbound_vote_broadcast_normal
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Low => {
                self.outbound_vote_broadcast_low
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment outbound proposal_broadcast counter by priority.
    pub fn inc_outbound_proposal_broadcast_by_priority(&self, priority: ConsensusMsgPriority) {
        match priority {
            ConsensusMsgPriority::Critical => {
                self.outbound_proposal_broadcast_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Normal => {
                self.outbound_proposal_broadcast_normal
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Low => {
                self.outbound_proposal_broadcast_low
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment outbound dropped counter by priority.
    pub fn inc_outbound_dropped_by_priority(&self, priority: ConsensusMsgPriority) {
        // Also increment aggregate counter
        self.outbound_dropped_total.fetch_add(1, Ordering::Relaxed);
        match priority {
            ConsensusMsgPriority::Critical => {
                self.outbound_dropped_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Normal => {
                self.outbound_dropped_normal.fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMsgPriority::Low => {
                self.outbound_dropped_low.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get dropped count by priority.
    pub fn outbound_dropped_by_priority(&self, priority: ConsensusMsgPriority) -> u64 {
        match priority {
            ConsensusMsgPriority::Critical => {
                self.outbound_dropped_critical.load(Ordering::Relaxed)
            }
            ConsensusMsgPriority::Normal => self.outbound_dropped_normal.load(Ordering::Relaxed),
            ConsensusMsgPriority::Low => self.outbound_dropped_low.load(Ordering::Relaxed),
        }
    }

    /// Increment critical channel send total.
    pub fn inc_outbound_critical_total(&self) {
        self.outbound_critical_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total critical messages sent to critical channel.
    pub fn outbound_critical_total(&self) -> u64 {
        self.outbound_critical_total.load(Ordering::Relaxed)
    }

    /// Increment critical worker successfully delivered count.
    pub fn inc_outbound_critical_worker_total(&self) {
        self.outbound_critical_worker_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total critical messages successfully delivered by worker.
    pub fn outbound_critical_worker_total(&self) -> u64 {
        self.outbound_critical_worker_total.load(Ordering::Relaxed)
    }

    /// Record the time spent waiting for backpressure in the critical worker.
    pub fn record_critical_backpressure_wait(&self, duration: std::time::Duration) {
        let millis = duration.as_millis();
        if millis < 1 {
            self.critical_wait_under_1ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.critical_wait_1ms_to_10ms
                .fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.critical_wait_10ms_to_100ms
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.critical_wait_over_100ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get critical wait time bucket counters.
    pub fn critical_wait_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.critical_wait_under_1ms.load(Ordering::Relaxed),
            self.critical_wait_1ms_to_10ms.load(Ordering::Relaxed),
            self.critical_wait_10ms_to_100ms.load(Ordering::Relaxed),
            self.critical_wait_over_100ms.load(Ordering::Relaxed),
        )
    }

    /// Get outbound counts by priority for vote_send_to.
    pub fn outbound_vote_send_to_by_priority(&self, priority: ConsensusMsgPriority) -> u64 {
        match priority {
            ConsensusMsgPriority::Critical => {
                self.outbound_vote_send_to_critical.load(Ordering::Relaxed)
            }
            ConsensusMsgPriority::Normal => {
                self.outbound_vote_send_to_normal.load(Ordering::Relaxed)
            }
            ConsensusMsgPriority::Low => self.outbound_vote_send_to_low.load(Ordering::Relaxed),
        }
    }

    /// Get outbound counts by priority for vote_broadcast.
    pub fn outbound_vote_broadcast_by_priority(&self, priority: ConsensusMsgPriority) -> u64 {
        match priority {
            ConsensusMsgPriority::Critical => self
                .outbound_vote_broadcast_critical
                .load(Ordering::Relaxed),
            ConsensusMsgPriority::Normal => {
                self.outbound_vote_broadcast_normal.load(Ordering::Relaxed)
            }
            ConsensusMsgPriority::Low => self.outbound_vote_broadcast_low.load(Ordering::Relaxed),
        }
    }

    /// Get outbound counts by priority for proposal_broadcast.
    pub fn outbound_proposal_broadcast_by_priority(&self, priority: ConsensusMsgPriority) -> u64 {
        match priority {
            ConsensusMsgPriority::Critical => self
                .outbound_proposal_broadcast_critical
                .load(Ordering::Relaxed),
            ConsensusMsgPriority::Normal => self
                .outbound_proposal_broadcast_normal
                .load(Ordering::Relaxed),
            ConsensusMsgPriority::Low => {
                self.outbound_proposal_broadcast_low.load(Ordering::Relaxed)
            }
        }
    }
}

// ============================================================================
// PeerNetworkMetrics - Per-peer network metrics (T90.4)
// ============================================================================

/// Maximum number of peers to track individually in metrics.
///
/// Peers beyond this limit are aggregated under a special "overflow" label
/// to prevent unbounded memory growth. This limit ensures O(1) memory usage
/// regardless of the total number of peers seen.
pub const MAX_TRACKED_PEERS: usize = 128;

/// Counters for a single peer.
///
/// This struct contains atomic counters for inbound messages, outbound messages,
/// and disconnection events for a single peer.
#[derive(Debug, Default)]
pub struct PeerCounters {
    /// Inbound vote messages from this peer.
    pub inbound_vote: AtomicU64,
    /// Inbound proposal messages from this peer.
    pub inbound_proposal: AtomicU64,
    /// Inbound other messages from this peer.
    pub inbound_other: AtomicU64,
    /// Outbound vote_send_to messages to this peer (critical priority).
    pub outbound_vote_send_to_critical: AtomicU64,
    /// Outbound vote_send_to messages to this peer (normal priority).
    pub outbound_vote_send_to_normal: AtomicU64,
    /// Outbound vote_send_to messages to this peer (low priority).
    pub outbound_vote_send_to_low: AtomicU64,
    /// Outbound vote_broadcast messages to this peer (critical priority).
    pub outbound_vote_broadcast_critical: AtomicU64,
    /// Outbound vote_broadcast messages to this peer (normal priority).
    pub outbound_vote_broadcast_normal: AtomicU64,
    /// Outbound vote_broadcast messages to this peer (low priority).
    pub outbound_vote_broadcast_low: AtomicU64,
    /// Outbound proposal_broadcast messages to this peer (critical priority).
    pub outbound_proposal_broadcast_critical: AtomicU64,
    /// Outbound proposal_broadcast messages to this peer (normal priority).
    pub outbound_proposal_broadcast_normal: AtomicU64,
    /// Outbound proposal_broadcast messages to this peer (low priority).
    pub outbound_proposal_broadcast_low: AtomicU64,
    /// Disconnection count (EOF).
    pub disconnect_eof: AtomicU64,
    /// Disconnection count (errors).
    pub disconnect_error: AtomicU64,
    /// Disconnection count (shutdown).
    pub disconnect_shutdown: AtomicU64,
    /// Outbound channel drops (channel full).
    pub outbound_drop: AtomicU64,
    /// Inbound message drops due to rate limiting (T123).
    pub rate_limit_drop: AtomicU64,
}

impl PeerCounters {
    /// Create a new PeerCounters with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Reason for a peer disconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// EOF on read (graceful close by remote peer).
    Eof,
    /// I/O or protocol error.
    Error,
    /// Local shutdown (intentional termination by this node).
    Shutdown,
}

/// Kind of inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundMsgKind {
    /// Vote message.
    Vote,
    /// Proposal message.
    Proposal,
    /// Other message types.
    Other,
}

/// Kind of outbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundMsgKind {
    /// Vote sent to a specific peer.
    VoteSendTo,
    /// Vote broadcast to all peers.
    VoteBroadcast,
    /// Proposal broadcast to all peers.
    ProposalBroadcast,
}

/// Per-peer network metrics tracker (T90.4).
///
/// This struct tracks network metrics on a per-peer basis:
/// - Inbound message counts by type (vote, proposal, other)
/// - Outbound message counts by type and priority
/// - Disconnect/error counters
///
/// # Bounded Peer Tracking
///
/// To prevent unbounded memory growth, only up to `MAX_TRACKED_PEERS` peers
/// are tracked individually. Additional peers are aggregated under an
/// "overflow" counter.
///
/// # PeerId Representation
///
/// PeerIds are represented as decimal strings (e.g., "42") in metrics output
/// for consistency and human readability.
///
/// # Thread Safety
///
/// All operations are thread-safe using RwLock for the peer map and atomic
/// operations for counters.
#[derive(Debug)]
pub struct PeerNetworkMetrics {
    /// Per-peer counters, keyed by PeerId.
    peers: RwLock<HashMap<PeerId, PeerCounters>>,
    /// Overflow counter for peers beyond MAX_TRACKED_PEERS.
    overflow: PeerCounters,
    /// Number of peers that were tracked but exceeded the limit.
    overflow_peer_count: AtomicU64,
}

impl Default for PeerNetworkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerNetworkMetrics {
    /// Create a new PeerNetworkMetrics instance.
    pub fn new() -> Self {
        PeerNetworkMetrics {
            peers: RwLock::new(HashMap::new()),
            overflow: PeerCounters::new(),
            overflow_peer_count: AtomicU64::new(0),
        }
    }

    /// Ensure a peer entry exists, returning true if the peer is individually tracked.
    fn ensure_peer_entry(&self, peer_id: PeerId) -> bool {
        // Fast path: check if peer already exists
        {
            let peers = match self.peers.read() {
                Ok(p) => p,
                Err(_) => return false,
            };
            if peers.contains_key(&peer_id) {
                return true;
            }
        }

        // Slow path: try to insert
        let mut peers = match self.peers.write() {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Double-check after acquiring write lock
        if peers.contains_key(&peer_id) {
            return true;
        }

        // Check capacity
        if peers.len() >= MAX_TRACKED_PEERS {
            self.overflow_peer_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        peers.insert(peer_id, PeerCounters::new());
        true
    }

    /// Increment inbound message counter for a peer.
    pub fn inc_inbound(&self, peer_id: PeerId, kind: InboundMsgKind) {
        if self.ensure_peer_entry(peer_id) {
            let peers = match self.peers.read() {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Some(counters) = peers.get(&peer_id) {
                match kind {
                    InboundMsgKind::Vote => counters.inbound_vote.fetch_add(1, Ordering::Relaxed),
                    InboundMsgKind::Proposal => {
                        counters.inbound_proposal.fetch_add(1, Ordering::Relaxed)
                    }
                    InboundMsgKind::Other => counters.inbound_other.fetch_add(1, Ordering::Relaxed),
                };
            }
        } else {
            // Overflow: count in the overflow bucket
            match kind {
                InboundMsgKind::Vote => self.overflow.inbound_vote.fetch_add(1, Ordering::Relaxed),
                InboundMsgKind::Proposal => self
                    .overflow
                    .inbound_proposal
                    .fetch_add(1, Ordering::Relaxed),
                InboundMsgKind::Other => {
                    self.overflow.inbound_other.fetch_add(1, Ordering::Relaxed)
                }
            };
        }
    }

    /// Increment outbound message counter for a peer.
    pub fn inc_outbound(
        &self,
        peer_id: PeerId,
        kind: OutboundMsgKind,
        priority: ConsensusMsgPriority,
    ) {
        if self.ensure_peer_entry(peer_id) {
            let peers = match self.peers.read() {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Some(counters) = peers.get(&peer_id) {
                Self::inc_outbound_counters(counters, kind, priority);
            }
        } else {
            Self::inc_outbound_counters(&self.overflow, kind, priority);
        }
    }

    /// Helper to increment outbound counters on a PeerCounters struct.
    fn inc_outbound_counters(
        counters: &PeerCounters,
        kind: OutboundMsgKind,
        priority: ConsensusMsgPriority,
    ) {
        match (kind, priority) {
            (OutboundMsgKind::VoteSendTo, ConsensusMsgPriority::Critical) => {
                counters
                    .outbound_vote_send_to_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::VoteSendTo, ConsensusMsgPriority::Normal) => {
                counters
                    .outbound_vote_send_to_normal
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::VoteSendTo, ConsensusMsgPriority::Low) => {
                counters
                    .outbound_vote_send_to_low
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::VoteBroadcast, ConsensusMsgPriority::Critical) => {
                counters
                    .outbound_vote_broadcast_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::VoteBroadcast, ConsensusMsgPriority::Normal) => {
                counters
                    .outbound_vote_broadcast_normal
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::VoteBroadcast, ConsensusMsgPriority::Low) => {
                counters
                    .outbound_vote_broadcast_low
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::ProposalBroadcast, ConsensusMsgPriority::Critical) => {
                counters
                    .outbound_proposal_broadcast_critical
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::ProposalBroadcast, ConsensusMsgPriority::Normal) => {
                counters
                    .outbound_proposal_broadcast_normal
                    .fetch_add(1, Ordering::Relaxed);
            }
            (OutboundMsgKind::ProposalBroadcast, ConsensusMsgPriority::Low) => {
                counters
                    .outbound_proposal_broadcast_low
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment disconnect counter for a peer.
    pub fn inc_disconnect(&self, peer_id: PeerId, reason: DisconnectReason) {
        if self.ensure_peer_entry(peer_id) {
            let peers = match self.peers.read() {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Some(counters) = peers.get(&peer_id) {
                match reason {
                    DisconnectReason::Eof => {
                        counters.disconnect_eof.fetch_add(1, Ordering::Relaxed)
                    }
                    DisconnectReason::Error => {
                        counters.disconnect_error.fetch_add(1, Ordering::Relaxed)
                    }
                    DisconnectReason::Shutdown => {
                        counters.disconnect_shutdown.fetch_add(1, Ordering::Relaxed)
                    }
                };
            }
        } else {
            match reason {
                DisconnectReason::Eof => {
                    self.overflow.disconnect_eof.fetch_add(1, Ordering::Relaxed)
                }
                DisconnectReason::Error => self
                    .overflow
                    .disconnect_error
                    .fetch_add(1, Ordering::Relaxed),
                DisconnectReason::Shutdown => self
                    .overflow
                    .disconnect_shutdown
                    .fetch_add(1, Ordering::Relaxed),
            };
        }
    }

    /// Increment outbound drop counter for a peer.
    pub fn inc_outbound_drop(&self, peer_id: PeerId) {
        if self.ensure_peer_entry(peer_id) {
            let peers = match self.peers.read() {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Some(counters) = peers.get(&peer_id) {
                counters.outbound_drop.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.overflow.outbound_drop.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment rate limit drop counter for a peer (T123).
    ///
    /// This is called when an inbound message from a peer is dropped due to
    /// per-peer rate limiting.
    pub fn inc_rate_limit_drop(&self, peer_id: PeerId) {
        if self.ensure_peer_entry(peer_id) {
            let peers = match self.peers.read() {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Some(counters) = peers.get(&peer_id) {
                counters.rate_limit_drop.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.overflow
                .rate_limit_drop
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get rate limit drop count for a specific peer (T123).
    pub fn peer_rate_limit_drop_count(&self, peer_id: PeerId) -> Option<u64> {
        let peers = self.peers.read().ok()?;
        let counters = peers.get(&peer_id)?;
        Some(counters.rate_limit_drop.load(Ordering::Relaxed))
    }

    /// Get total rate limit drop count across all tracked peers (T123).
    pub fn total_rate_limit_drops(&self) -> u64 {
        let mut total = 0u64;
        if let Ok(peers) = self.peers.read() {
            for counters in peers.values() {
                total += counters.rate_limit_drop.load(Ordering::Relaxed);
            }
        }
        total += self.overflow.rate_limit_drop.load(Ordering::Relaxed);
        total
    }

    /// Get the number of tracked peers.
    pub fn tracked_peer_count(&self) -> usize {
        self.peers.read().map(|p| p.len()).unwrap_or(0)
    }

    /// Get the number of overflow peers (those not individually tracked).
    pub fn overflow_peer_count(&self) -> u64 {
        self.overflow_peer_count.load(Ordering::Relaxed)
    }

    /// Get inbound counts for a specific peer.
    pub fn peer_inbound_counts(&self, peer_id: PeerId) -> Option<(u64, u64, u64)> {
        let peers = self.peers.read().ok()?;
        let counters = peers.get(&peer_id)?;
        Some((
            counters.inbound_vote.load(Ordering::Relaxed),
            counters.inbound_proposal.load(Ordering::Relaxed),
            counters.inbound_other.load(Ordering::Relaxed),
        ))
    }

    /// Get disconnect counts for a specific peer (eof, error, shutdown).
    pub fn peer_disconnect_counts(&self, peer_id: PeerId) -> Option<(u64, u64, u64)> {
        let peers = self.peers.read().ok()?;
        let counters = peers.get(&peer_id)?;
        Some((
            counters.disconnect_eof.load(Ordering::Relaxed),
            counters.disconnect_error.load(Ordering::Relaxed),
            counters.disconnect_shutdown.load(Ordering::Relaxed),
        ))
    }

    /// Format per-peer metrics as Prometheus-style output.
    ///
    /// # Format
    ///
    /// ```text
    /// consensus_net_peer_inbound_total{peer="42",kind="vote"} 123
    /// consensus_net_peer_inbound_total{peer="42",kind="proposal"} 45
    /// consensus_net_peer_outbound_total{peer="42",kind="vote_send_to",priority="critical"} 67
    /// consensus_net_peer_disconnect_total{peer="42",reason="eof"} 1
    /// ```
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Per-peer network metrics (T90.4)\n");

        let peers = match self.peers.read() {
            Ok(p) => p,
            Err(_) => return output,
        };

        // Sort peer IDs for deterministic output
        let mut peer_ids: Vec<_> = peers.keys().copied().collect();
        peer_ids.sort_by_key(|p| p.0);

        for peer_id in peer_ids {
            if let Some(counters) = peers.get(&peer_id) {
                let peer_str = peer_id.0.to_string();

                // Inbound metrics
                let inbound_vote = counters.inbound_vote.load(Ordering::Relaxed);
                let inbound_proposal = counters.inbound_proposal.load(Ordering::Relaxed);
                let inbound_other = counters.inbound_other.load(Ordering::Relaxed);

                if inbound_vote > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_inbound_total{{peer=\"{}\",kind=\"vote\"}} {}\n",
                        peer_str, inbound_vote
                    ));
                }
                if inbound_proposal > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_inbound_total{{peer=\"{}\",kind=\"proposal\"}} {}\n",
                        peer_str, inbound_proposal
                    ));
                }
                if inbound_other > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_inbound_total{{peer=\"{}\",kind=\"other\"}} {}\n",
                        peer_str, inbound_other
                    ));
                }

                // Outbound metrics
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "vote_send_to",
                    "critical",
                    counters
                        .outbound_vote_send_to_critical
                        .load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "vote_send_to",
                    "normal",
                    counters
                        .outbound_vote_send_to_normal
                        .load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "vote_send_to",
                    "low",
                    counters.outbound_vote_send_to_low.load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "vote_broadcast",
                    "critical",
                    counters
                        .outbound_vote_broadcast_critical
                        .load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "vote_broadcast",
                    "normal",
                    counters
                        .outbound_vote_broadcast_normal
                        .load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "vote_broadcast",
                    "low",
                    counters.outbound_vote_broadcast_low.load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "proposal_broadcast",
                    "critical",
                    counters
                        .outbound_proposal_broadcast_critical
                        .load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "proposal_broadcast",
                    "normal",
                    counters
                        .outbound_proposal_broadcast_normal
                        .load(Ordering::Relaxed),
                );
                Self::format_outbound_metric(
                    &mut output,
                    &peer_str,
                    "proposal_broadcast",
                    "low",
                    counters
                        .outbound_proposal_broadcast_low
                        .load(Ordering::Relaxed),
                );

                // Disconnect metrics
                let disconnect_eof = counters.disconnect_eof.load(Ordering::Relaxed);
                let disconnect_error = counters.disconnect_error.load(Ordering::Relaxed);
                let disconnect_shutdown = counters.disconnect_shutdown.load(Ordering::Relaxed);
                if disconnect_eof > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_disconnect_total{{peer=\"{}\",reason=\"eof\"}} {}\n",
                        peer_str, disconnect_eof
                    ));
                }
                if disconnect_error > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_disconnect_total{{peer=\"{}\",reason=\"error\"}} {}\n",
                        peer_str, disconnect_error
                    ));
                }
                if disconnect_shutdown > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_disconnect_total{{peer=\"{}\",reason=\"shutdown\"}} {}\n",
                        peer_str, disconnect_shutdown
                    ));
                }

                // Drop metrics
                let outbound_drop = counters.outbound_drop.load(Ordering::Relaxed);
                if outbound_drop > 0 {
                    output.push_str(&format!(
                        "consensus_net_peer_outbound_drop_total{{peer=\"{}\"}} {}\n",
                        peer_str, outbound_drop
                    ));
                }

                // Rate limit drop metrics (T123)
                let rate_limit_drop = counters.rate_limit_drop.load(Ordering::Relaxed);
                if rate_limit_drop > 0 {
                    output.push_str(&format!(
                        "qbind_net_per_peer_drops_total{{peer=\"{}\",reason=\"rate_limit\"}} {}\n",
                        peer_str, rate_limit_drop
                    ));
                }
            }
        }

        // Overflow metrics
        let overflow_count = self.overflow_peer_count.load(Ordering::Relaxed);
        if overflow_count > 0 {
            output.push_str(&format!(
                "consensus_net_peer_overflow_count {}\n",
                overflow_count
            ));
            // Include aggregate overflow counters
            let inbound_vote = self.overflow.inbound_vote.load(Ordering::Relaxed);
            let inbound_proposal = self.overflow.inbound_proposal.load(Ordering::Relaxed);
            let inbound_other = self.overflow.inbound_other.load(Ordering::Relaxed);
            if inbound_vote > 0 {
                output.push_str(&format!(
                    "consensus_net_peer_inbound_total{{peer=\"overflow\",kind=\"vote\"}} {}\n",
                    inbound_vote
                ));
            }
            if inbound_proposal > 0 {
                output.push_str(&format!(
                    "consensus_net_peer_inbound_total{{peer=\"overflow\",kind=\"proposal\"}} {}\n",
                    inbound_proposal
                ));
            }
            if inbound_other > 0 {
                output.push_str(&format!(
                    "consensus_net_peer_inbound_total{{peer=\"overflow\",kind=\"other\"}} {}\n",
                    inbound_other
                ));
            }
            // Overflow rate limit drops (T123)
            let rate_limit_drop = self.overflow.rate_limit_drop.load(Ordering::Relaxed);
            if rate_limit_drop > 0 {
                output.push_str(&format!(
                    "qbind_net_per_peer_drops_total{{peer=\"overflow\",reason=\"rate_limit\"}} {}\n",
                    rate_limit_drop
                ));
            }
        }

        output
    }

    /// Helper to format a single outbound metric line (only if count > 0).
    fn format_outbound_metric(
        output: &mut String,
        peer_str: &str,
        kind: &str,
        priority: &str,
        count: u64,
    ) {
        if count > 0 {
            output.push_str(&format!(
                "consensus_net_peer_outbound_total{{peer=\"{}\",kind=\"{}\",priority=\"{}\"}} {}\n",
                peer_str, kind, priority, count
            ));
        }
    }
}

// ============================================================================
// RuntimeMetrics - Event loop and processing tracking
// ============================================================================

/// Metrics for the async node runtime event loop.
///
/// Tracks consensus events processed by `AsyncNodeRunner` and provides
/// insight into the balance between timer ticks and network events.
///
/// # Prometheus-style naming
///
/// - `consensus_events_total{kind="tick"}` → `events_tick_total()`
/// - `consensus_events_total{kind="incoming_message"}` → `events_incoming_message_total()`
/// - `consensus_events_total{kind="shutdown"}` → `events_shutdown_total()`
#[derive(Debug, Default)]
pub struct RuntimeMetrics {
    // Event counters
    events_tick_total: AtomicU64,
    events_incoming_message_total: AtomicU64,
    events_shutdown_total: AtomicU64,

    // Processing rate (updated periodically)
    ticks_per_second: AtomicU64,
}

impl RuntimeMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Event counters
    // ========================================================================

    /// Get count of tick events processed.
    pub fn events_tick_total(&self) -> u64 {
        self.events_tick_total.load(Ordering::Relaxed)
    }

    /// Get count of incoming message events processed.
    pub fn events_incoming_message_total(&self) -> u64 {
        self.events_incoming_message_total.load(Ordering::Relaxed)
    }

    /// Get count of shutdown events processed.
    pub fn events_shutdown_total(&self) -> u64 {
        self.events_shutdown_total.load(Ordering::Relaxed)
    }

    /// Increment tick event counter.
    pub fn inc_events_tick(&self) {
        self.events_tick_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment incoming message event counter.
    pub fn inc_events_incoming_message(&self) {
        self.events_incoming_message_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment shutdown event counter.
    pub fn inc_events_shutdown(&self) {
        self.events_shutdown_total.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Processing rate
    // ========================================================================

    /// Get approximate ticks per second (updated periodically by runtime).
    pub fn ticks_per_second(&self) -> u64 {
        self.ticks_per_second.load(Ordering::Relaxed)
    }

    /// Set the ticks per second rate.
    pub fn set_ticks_per_second(&self, rate: u64) {
        self.ticks_per_second.store(rate, Ordering::Relaxed);
    }
}

// ============================================================================
// SpawnBlockingMetrics - Blocking task tracking
// ============================================================================

/// Metrics for `spawn_blocking` usage in the network adapter.
///
/// Tracks the number of blocking task spawns and provides coarse-grained
/// latency distribution via bucketed counters.
///
/// # Latency Buckets
///
/// Rather than a full histogram, we use simple bucket counters:
/// - `< 1ms`: Very fast operations
/// - `1ms - 10ms`: Normal operations
/// - `10ms - 100ms`: Slow operations
/// - `> 100ms`: Very slow operations (may indicate contention)
///
/// This approach avoids external histogram dependencies while providing
/// useful latency visibility.
#[derive(Debug, Default)]
pub struct SpawnBlockingMetrics {
    // Total spawn_blocking calls
    spawn_blocking_total: AtomicU64,

    // Latency bucket counters
    latency_under_1ms: AtomicU64,
    latency_1ms_to_10ms: AtomicU64,
    latency_10ms_to_100ms: AtomicU64,
    latency_over_100ms: AtomicU64,
}

impl SpawnBlockingMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total count of spawn_blocking calls.
    pub fn spawn_blocking_total(&self) -> u64 {
        self.spawn_blocking_total.load(Ordering::Relaxed)
    }

    /// Increment spawn_blocking counter.
    pub fn inc_spawn_blocking(&self) {
        self.spawn_blocking_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get count of operations completing in < 1ms.
    pub fn latency_under_1ms(&self) -> u64 {
        self.latency_under_1ms.load(Ordering::Relaxed)
    }

    /// Get count of operations completing in 1ms - 10ms.
    pub fn latency_1ms_to_10ms(&self) -> u64 {
        self.latency_1ms_to_10ms.load(Ordering::Relaxed)
    }

    /// Get count of operations completing in 10ms - 100ms.
    pub fn latency_10ms_to_100ms(&self) -> u64 {
        self.latency_10ms_to_100ms.load(Ordering::Relaxed)
    }

    /// Get count of operations completing in > 100ms.
    pub fn latency_over_100ms(&self) -> u64 {
        self.latency_over_100ms.load(Ordering::Relaxed)
    }

    /// Record a spawn_blocking operation with its duration.
    ///
    /// This increments the total counter and the appropriate latency bucket.
    pub fn record_blocking_duration(&self, duration: std::time::Duration) {
        self.inc_spawn_blocking();

        let millis = duration.as_millis();
        if millis < 1 {
            self.latency_under_1ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.latency_1ms_to_10ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.latency_10ms_to_100ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_over_100ms.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// ConsensusRoundMetrics - Consensus view/round duration tracking (T90.5)
// ============================================================================

/// Metrics for consensus round/view duration tracking.
///
/// Tracks how long each consensus view takes, which is useful for:
/// - Understanding consensus performance under load
/// - Debugging pacemaker timing behavior
/// - Identifying slow rounds that may indicate network issues
///
/// # Definition of "View Duration"
///
/// View duration is measured as the time between:
/// - The current view `v` being activated (via `advance_view()` or `set_view()`)
/// - The next view `v+1` being activated
///
/// This definition is independent of whether a commit occurred during the view.
///
/// # Caveats
///
/// - The first view duration after a restart includes time since the engine was
///   initialized, which may be longer than a typical view. This is acceptable
///   and documented.
/// - View durations are monotonic (using `std::time::Instant`), not wall-clock time.
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering, following the pattern
/// of other metrics in this module.
#[derive(Debug, Default)]
pub struct ConsensusRoundMetrics {
    /// Total number of view transitions observed.
    view_durations_count: AtomicU64,

    /// Sum of all view durations in milliseconds.
    view_durations_total_ms: AtomicU64,

    // Latency bucket counters (cumulative style for Prometheus histograms)
    /// Count of views completing in < 100ms.
    bucket_under_100ms: AtomicU64,
    /// Count of views completing in < 500ms.
    bucket_under_500ms: AtomicU64,
    /// Count of views completing in < 2000ms.
    bucket_under_2s: AtomicU64,
    /// Count of all views (equivalent to +Inf bucket).
    bucket_inf: AtomicU64,
}

impl ConsensusRoundMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a view duration.
    ///
    /// This method increments the count, adds to the total, and updates
    /// the appropriate histogram bucket.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration of the view (from activation to next view activation)
    pub fn record_view_duration(&self, duration: std::time::Duration) {
        let millis = duration.as_millis() as u64;

        // Increment count and total
        self.view_durations_count.fetch_add(1, Ordering::Relaxed);
        self.view_durations_total_ms
            .fetch_add(millis, Ordering::Relaxed);

        // Update histogram buckets (cumulative)
        // All durations count in +Inf bucket
        self.bucket_inf.fetch_add(1, Ordering::Relaxed);

        // Count in appropriate buckets (cumulative style)
        if millis < 2000 {
            self.bucket_under_2s.fetch_add(1, Ordering::Relaxed);
        }
        if millis < 500 {
            self.bucket_under_500ms.fetch_add(1, Ordering::Relaxed);
        }
        if millis < 100 {
            self.bucket_under_100ms.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get the total count of view transitions.
    pub fn view_durations_count(&self) -> u64 {
        self.view_durations_count.load(Ordering::Relaxed)
    }

    /// Get the sum of all view durations in milliseconds.
    pub fn view_durations_total_ms(&self) -> u64 {
        self.view_durations_total_ms.load(Ordering::Relaxed)
    }

    /// Get histogram bucket counts as (under_100ms, under_500ms, under_2s, inf).
    ///
    /// These are cumulative counts per Prometheus histogram conventions.
    pub fn bucket_counts(&self) -> (u64, u64, u64, u64) {
        (
            self.bucket_under_100ms.load(Ordering::Relaxed),
            self.bucket_under_500ms.load(Ordering::Relaxed),
            self.bucket_under_2s.load(Ordering::Relaxed),
            self.bucket_inf.load(Ordering::Relaxed),
        )
    }
}

// Implement ViewDurationRecorder for ConsensusRoundMetrics
// This allows ConsensusRoundMetrics to be used directly with BasicHotStuffEngine
impl qbind_consensus::ViewDurationRecorder for ConsensusRoundMetrics {
    fn record_view_duration(&self, duration: std::time::Duration, _from_view: u64, _to_view: u64) {
        // Delegate to the internal method
        ConsensusRoundMetrics::record_view_duration(self, duration);
    }
}

// ============================================================================
// ConnectionLimitMetrics - Connection limit rejection tracking (T105)
// ============================================================================

/// Metrics for connection limit enforcement (T105).
///
/// Tracks the number of connections rejected because the peer limit was exceeded.
/// Separate counters are maintained for inbound and outbound rejections.
///
/// # Prometheus-style naming
///
/// - `async_peer_inbound_rejected_limit_total` → `inbound_rejected_total()`
/// - `async_peer_outbound_rejected_limit_total` → `outbound_rejected_total()`
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct ConnectionLimitMetrics {
    /// Number of inbound connections rejected because the peer limit was exceeded.
    inbound_rejected_limit: AtomicU64,
    /// Number of outbound connections rejected because the peer limit was exceeded.
    outbound_rejected_limit: AtomicU64,
}

impl ConnectionLimitMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get count of inbound connections rejected due to limit.
    pub fn inbound_rejected_total(&self) -> u64 {
        self.inbound_rejected_limit.load(Ordering::Relaxed)
    }

    /// Get count of outbound connections rejected due to limit.
    pub fn outbound_rejected_total(&self) -> u64 {
        self.outbound_rejected_limit.load(Ordering::Relaxed)
    }

    /// Increment the inbound rejection counter.
    pub fn inc_inbound_rejected(&self) {
        self.inbound_rejected_limit.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the outbound rejection counter.
    pub fn inc_outbound_rejected(&self) {
        self.outbound_rejected_limit.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total rejections (inbound + outbound).
    pub fn total_rejected(&self) -> u64 {
        self.inbound_rejected_total() + self.outbound_rejected_total()
    }

    /// Format metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Connection limit metrics (T105)\n");
        output.push_str(&format!(
            "async_peer_inbound_rejected_limit_total {}\n",
            self.inbound_rejected_total()
        ));
        output.push_str(&format!(
            "async_peer_outbound_rejected_limit_total {}\n",
            self.outbound_rejected_total()
        ));
        output
    }
}

// ============================================================================
// StorageMetrics - RocksDB storage operation latency tracking (T107)
// ============================================================================

/// Storage operation types for latency tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOp {
    /// put_block operation.
    PutBlock,
    /// put_qc operation.
    PutQc,
    /// put_last_committed operation.
    PutLastCommitted,
    /// put_current_epoch operation.
    PutCurrentEpoch,
    /// get_block operation.
    GetBlock,
    /// get_qc operation.
    GetQc,
    /// get_last_committed operation.
    GetLastCommitted,
    /// get_current_epoch operation.
    GetCurrentEpoch,
}

impl StorageOp {
    /// Get the string label for this operation (used in metrics output).
    pub fn label(&self) -> &'static str {
        match self {
            StorageOp::PutBlock => "put_block",
            StorageOp::PutQc => "put_qc",
            StorageOp::PutLastCommitted => "put_last_committed",
            StorageOp::PutCurrentEpoch => "put_current_epoch",
            StorageOp::GetBlock => "get_block",
            StorageOp::GetQc => "get_qc",
            StorageOp::GetLastCommitted => "get_last_committed",
            StorageOp::GetCurrentEpoch => "get_current_epoch",
        }
    }
}

/// Metrics for a single storage operation type.
///
/// Tracks count, total duration, and histogram buckets for latency.
#[derive(Debug, Default)]
struct StorageOpMetrics {
    /// Total count of this operation.
    count: AtomicU64,
    /// Total duration in milliseconds for this operation.
    total_ms: AtomicU64,
    /// Count of operations completing in < 1ms.
    bucket_under_1ms: AtomicU64,
    /// Count of operations completing in 1ms - 10ms.
    bucket_1ms_to_10ms: AtomicU64,
    /// Count of operations completing in 10ms - 100ms.
    bucket_10ms_to_100ms: AtomicU64,
    /// Count of operations completing in > 100ms.
    bucket_over_100ms: AtomicU64,
}

impl StorageOpMetrics {
    fn record(&self, duration: std::time::Duration) {
        let millis = duration.as_millis() as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_ms.fetch_add(millis, Ordering::Relaxed);

        if millis < 1 {
            self.bucket_under_1ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.bucket_1ms_to_10ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.bucket_10ms_to_100ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.bucket_over_100ms.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn total_ms(&self) -> u64 {
        self.total_ms.load(Ordering::Relaxed)
    }

    fn buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.bucket_under_1ms.load(Ordering::Relaxed),
            self.bucket_1ms_to_10ms.load(Ordering::Relaxed),
            self.bucket_10ms_to_100ms.load(Ordering::Relaxed),
            self.bucket_over_100ms.load(Ordering::Relaxed),
        )
    }
}

/// Metrics for RocksDB consensus storage operations (T107).
///
/// Tracks latency histograms for key storage operations:
/// - put_block, put_qc, put_last_committed, put_current_epoch
/// - get_block, get_qc, get_last_committed, get_current_epoch
///
/// # Latency Buckets
///
/// Each operation tracks a simple histogram with 4 buckets:
/// - `< 1ms`: Very fast operations
/// - `1ms - 10ms`: Normal operations
/// - `10ms - 100ms`: Slow operations
/// - `> 100ms`: Very slow operations (may indicate disk issues)
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
/// This is acceptable for observability where exact ordering is not required.
///
/// # Prometheus-style naming
///
/// Output format in `format_metrics()`:
/// ```text
/// eezo_storage_op_duration_ms_count{op="put_block"} 42
/// eezo_storage_op_duration_ms_sum{op="put_block"} 100
/// eezo_storage_op_duration_ms_bucket{op="put_block",le="1"} 30
/// eezo_storage_op_duration_ms_bucket{op="put_block",le="10"} 38
/// eezo_storage_op_duration_ms_bucket{op="put_block",le="100"} 41
/// eezo_storage_op_duration_ms_bucket{op="put_block",le="+Inf"} 42
/// ```
#[derive(Debug, Default)]
pub struct StorageMetrics {
    put_block: StorageOpMetrics,
    put_qc: StorageOpMetrics,
    put_last_committed: StorageOpMetrics,
    put_current_epoch: StorageOpMetrics,
    get_block: StorageOpMetrics,
    get_qc: StorageOpMetrics,
    get_last_committed: StorageOpMetrics,
    get_current_epoch: StorageOpMetrics,
}

impl StorageMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a storage operation duration.
    ///
    /// This increments the count, adds to the total duration, and updates
    /// the appropriate histogram bucket.
    pub fn record(&self, op: StorageOp, duration: std::time::Duration) {
        match op {
            StorageOp::PutBlock => self.put_block.record(duration),
            StorageOp::PutQc => self.put_qc.record(duration),
            StorageOp::PutLastCommitted => self.put_last_committed.record(duration),
            StorageOp::PutCurrentEpoch => self.put_current_epoch.record(duration),
            StorageOp::GetBlock => self.get_block.record(duration),
            StorageOp::GetQc => self.get_qc.record(duration),
            StorageOp::GetLastCommitted => self.get_last_committed.record(duration),
            StorageOp::GetCurrentEpoch => self.get_current_epoch.record(duration),
        }
    }

    /// Get the count for a specific operation.
    pub fn op_count(&self, op: StorageOp) -> u64 {
        match op {
            StorageOp::PutBlock => self.put_block.count(),
            StorageOp::PutQc => self.put_qc.count(),
            StorageOp::PutLastCommitted => self.put_last_committed.count(),
            StorageOp::PutCurrentEpoch => self.put_current_epoch.count(),
            StorageOp::GetBlock => self.get_block.count(),
            StorageOp::GetQc => self.get_qc.count(),
            StorageOp::GetLastCommitted => self.get_last_committed.count(),
            StorageOp::GetCurrentEpoch => self.get_current_epoch.count(),
        }
    }

    /// Get the total duration in milliseconds for a specific operation.
    pub fn op_total_ms(&self, op: StorageOp) -> u64 {
        match op {
            StorageOp::PutBlock => self.put_block.total_ms(),
            StorageOp::PutQc => self.put_qc.total_ms(),
            StorageOp::PutLastCommitted => self.put_last_committed.total_ms(),
            StorageOp::PutCurrentEpoch => self.put_current_epoch.total_ms(),
            StorageOp::GetBlock => self.get_block.total_ms(),
            StorageOp::GetQc => self.get_qc.total_ms(),
            StorageOp::GetLastCommitted => self.get_last_committed.total_ms(),
            StorageOp::GetCurrentEpoch => self.get_current_epoch.total_ms(),
        }
    }

    /// Get histogram bucket counts for a specific operation.
    ///
    /// Returns (under_1ms, 1ms_to_10ms, 10ms_to_100ms, over_100ms).
    pub fn op_buckets(&self, op: StorageOp) -> (u64, u64, u64, u64) {
        match op {
            StorageOp::PutBlock => self.put_block.buckets(),
            StorageOp::PutQc => self.put_qc.buckets(),
            StorageOp::PutLastCommitted => self.put_last_committed.buckets(),
            StorageOp::PutCurrentEpoch => self.put_current_epoch.buckets(),
            StorageOp::GetBlock => self.get_block.buckets(),
            StorageOp::GetQc => self.get_qc.buckets(),
            StorageOp::GetLastCommitted => self.get_last_committed.buckets(),
            StorageOp::GetCurrentEpoch => self.get_current_epoch.buckets(),
        }
    }

    /// Format metrics for a single operation as Prometheus-style output.
    fn format_op_metrics(&self, output: &mut String, op: StorageOp) {
        let label = op.label();
        let count = self.op_count(op);
        let sum = self.op_total_ms(op);
        let (b1, b10, b100, binf) = self.op_buckets(op);

        // Cumulative histogram buckets
        let cum_1 = b1;
        let cum_10 = b1 + b10;
        let cum_100 = b1 + b10 + b100;
        let cum_inf = b1 + b10 + b100 + binf;

        output.push_str(&format!(
            "eezo_storage_op_duration_ms_count{{op=\"{}\"}} {}\n",
            label, count
        ));
        output.push_str(&format!(
            "eezo_storage_op_duration_ms_sum{{op=\"{}\"}} {}\n",
            label, sum
        ));
        output.push_str(&format!(
            "eezo_storage_op_duration_ms_bucket{{op=\"{}\",le=\"1\"}} {}\n",
            label, cum_1
        ));
        output.push_str(&format!(
            "eezo_storage_op_duration_ms_bucket{{op=\"{}\",le=\"10\"}} {}\n",
            label, cum_10
        ));
        output.push_str(&format!(
            "eezo_storage_op_duration_ms_bucket{{op=\"{}\",le=\"100\"}} {}\n",
            label, cum_100
        ));
        output.push_str(&format!(
            "eezo_storage_op_duration_ms_bucket{{op=\"{}\",le=\"+Inf\"}} {}\n",
            label, cum_inf
        ));
    }

    /// Format all storage metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Storage operation latency metrics (T107)\n");

        // Format metrics for all operations
        self.format_op_metrics(&mut output, StorageOp::PutBlock);
        self.format_op_metrics(&mut output, StorageOp::PutQc);
        self.format_op_metrics(&mut output, StorageOp::PutLastCommitted);
        self.format_op_metrics(&mut output, StorageOp::PutCurrentEpoch);
        self.format_op_metrics(&mut output, StorageOp::GetBlock);
        self.format_op_metrics(&mut output, StorageOp::GetQc);
        self.format_op_metrics(&mut output, StorageOp::GetLastCommitted);
        self.format_op_metrics(&mut output, StorageOp::GetCurrentEpoch);

        output
    }
}

// ============================================================================
// CommitMetrics - Commit latency tracking (T107)
// ============================================================================

/// Metrics for HotStuff commit latency (T107).
///
/// Tracks the time from commit trigger to completion, including persistence.
/// This measures the full commit path as seen by the harness.
///
/// # Latency Buckets
///
/// Simple histogram with 4 buckets:
/// - `< 1ms`: Very fast commits
/// - `1ms - 10ms`: Normal commits
/// - `10ms - 100ms`: Slow commits
/// - `> 100ms`: Very slow commits (may indicate persistence issues)
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
///
/// # Prometheus-style naming
///
/// Output format in `format_metrics()`:
/// ```text
/// eezo_commit_latency_ms_count 42
/// eezo_commit_latency_ms_sum 100
/// eezo_commit_latency_ms_bucket{le="1"} 30
/// eezo_commit_latency_ms_bucket{le="10"} 38
/// eezo_commit_latency_ms_bucket{le="100"} 41
/// eezo_commit_latency_ms_bucket{le="+Inf"} 42
/// ```
#[derive(Debug, Default)]
pub struct CommitMetrics {
    /// Total number of commits.
    commit_count: AtomicU64,
    /// Total commit duration in milliseconds.
    commit_total_ms: AtomicU64,
    /// Count of commits completing in < 1ms.
    bucket_under_1ms: AtomicU64,
    /// Count of commits completing in 1ms - 10ms.
    bucket_1ms_to_10ms: AtomicU64,
    /// Count of commits completing in 10ms - 100ms.
    bucket_10ms_to_100ms: AtomicU64,
    /// Count of commits completing in > 100ms.
    bucket_over_100ms: AtomicU64,
}

impl CommitMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a commit duration.
    ///
    /// This increments the count, adds to the total duration, and updates
    /// the appropriate histogram bucket.
    pub fn record_commit(&self, duration: std::time::Duration) {
        let millis = duration.as_millis() as u64;
        self.commit_count.fetch_add(1, Ordering::Relaxed);
        self.commit_total_ms.fetch_add(millis, Ordering::Relaxed);

        if millis < 1 {
            self.bucket_under_1ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.bucket_1ms_to_10ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.bucket_10ms_to_100ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.bucket_over_100ms.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get the total count of commits.
    pub fn commit_count(&self) -> u64 {
        self.commit_count.load(Ordering::Relaxed)
    }

    /// Get the total commit duration in milliseconds.
    pub fn commit_total_ms(&self) -> u64 {
        self.commit_total_ms.load(Ordering::Relaxed)
    }

    /// Get histogram bucket counts.
    ///
    /// Returns (under_1ms, 1ms_to_10ms, 10ms_to_100ms, over_100ms).
    pub fn bucket_counts(&self) -> (u64, u64, u64, u64) {
        (
            self.bucket_under_1ms.load(Ordering::Relaxed),
            self.bucket_1ms_to_10ms.load(Ordering::Relaxed),
            self.bucket_10ms_to_100ms.load(Ordering::Relaxed),
            self.bucket_over_100ms.load(Ordering::Relaxed),
        )
    }

    /// Format commit metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Commit latency metrics (T107)\n");

        let count = self.commit_count();
        let sum = self.commit_total_ms();
        let (b1, b10, b100, binf) = self.bucket_counts();

        // Cumulative histogram buckets
        let cum_1 = b1;
        let cum_10 = b1 + b10;
        let cum_100 = b1 + b10 + b100;
        let cum_inf = b1 + b10 + b100 + binf;

        output.push_str(&format!("eezo_commit_latency_ms_count {}\n", count));
        output.push_str(&format!("eezo_commit_latency_ms_sum {}\n", sum));
        output.push_str(&format!(
            "eezo_commit_latency_ms_bucket{{le=\"1\"}} {}\n",
            cum_1
        ));
        output.push_str(&format!(
            "eezo_commit_latency_ms_bucket{{le=\"10\"}} {}\n",
            cum_10
        ));
        output.push_str(&format!(
            "eezo_commit_latency_ms_bucket{{le=\"100\"}} {}\n",
            cum_100
        ));
        output.push_str(&format!(
            "eezo_commit_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            cum_inf
        ));

        output
    }
}

// ============================================================================
// SuiteTransitionMetrics - Suite transition tracking (T124)
// ============================================================================

/// Metrics for suite transitions across epochs.
///
/// Tracks allowed and rejected suite transitions with labels for
/// source and destination suites. This provides visibility into:
/// - How often suites change across epochs
/// - Whether transitions are upgrades or downgrades
/// - Which specific suite pairs are involved in transitions
///
/// # Prometheus-style naming
///
/// - `suite_epoch_transitions_total{from_suite="toy-sha3",to_suite="ml-dsa-44-reserved",result="ok"}`
/// - `suite_epoch_transitions_total{from_suite="ml-dsa-87-reserved",to_suite="ml-dsa-44-reserved",result="rejected"}`
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct SuiteTransitionMetrics {
    /// Total transitions (both ok and rejected).
    total_transitions: AtomicU64,
    /// Allowed transitions (equal or stronger security).
    ok_transitions: AtomicU64,
    /// Rejected transitions (downgrades).
    rejected_transitions: AtomicU64,
    /// Runtime transitions (both ok and rejected).
    runtime_total_transitions: AtomicU64,
    /// Runtime allowed transitions.
    runtime_ok_transitions: AtomicU64,
    /// Runtime rejected transitions.
    runtime_rejected_transitions: AtomicU64,
}

impl SuiteTransitionMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an allowed suite transition.
    ///
    /// This increments both the total counter and the ok counter.
    pub fn record_ok(&self) {
        self.total_transitions.fetch_add(1, Ordering::Relaxed);
        self.ok_transitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected suite transition.
    ///
    /// This increments both the total counter and the rejected counter.
    pub fn record_rejected(&self) {
        self.total_transitions.fetch_add(1, Ordering::Relaxed);
        self.rejected_transitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an allowed runtime suite transition.
    ///
    /// This increments both the runtime total counter and the runtime ok counter.
    pub fn record_runtime_ok(&self) {
        self.runtime_total_transitions
            .fetch_add(1, Ordering::Relaxed);
        self.runtime_ok_transitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected runtime suite transition.
    ///
    /// This increments both the runtime total counter and the runtime rejected counter.
    pub fn record_runtime_rejected(&self) {
        self.runtime_total_transitions
            .fetch_add(1, Ordering::Relaxed);
        self.runtime_rejected_transitions
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total number of transitions recorded.
    pub fn total_transitions(&self) -> u64 {
        self.total_transitions.load(Ordering::Relaxed)
    }

    /// Get number of allowed transitions.
    pub fn ok_transitions(&self) -> u64 {
        self.ok_transitions.load(Ordering::Relaxed)
    }

    /// Get number of rejected transitions.
    pub fn rejected_transitions(&self) -> u64 {
        self.rejected_transitions.load(Ordering::Relaxed)
    }

    /// Get total number of runtime transitions recorded.
    pub fn runtime_total_transitions(&self) -> u64 {
        self.runtime_total_transitions.load(Ordering::Relaxed)
    }

    /// Get number of allowed runtime transitions.
    pub fn runtime_ok_transitions(&self) -> u64 {
        self.runtime_ok_transitions.load(Ordering::Relaxed)
    }

    /// Get number of rejected runtime transitions.
    pub fn runtime_rejected_transitions(&self) -> u64 {
        self.runtime_rejected_transitions.load(Ordering::Relaxed)
    }

    /// Format metrics as Prometheus-style output.
    ///
    /// Note: This provides aggregate counts only. Per-suite-pair metrics
    /// would require more complex tracking (e.g., a hashmap of counters).
    /// For T124, aggregate counts are sufficient for basic visibility.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Suite transition metrics (T124)\n");
        output.push_str(&format!(
            "suite_epoch_transitions_total{{result=\"ok\"}} {}\n",
            self.ok_transitions()
        ));
        output.push_str(&format!(
            "suite_epoch_transitions_total{{result=\"rejected\"}} {}\n",
            self.rejected_transitions()
        ));
        output.push_str(&format!(
            "suite_epoch_transitions_total{{result=\"total\"}} {}\n",
            self.total_transitions()
        ));
        output.push_str("\n# Runtime suite transition metrics (T125)\n");
        output.push_str(&format!(
            "suite_epoch_runtime_transitions_total{{result=\"ok\"}} {}\n",
            self.runtime_ok_transitions()
        ));
        output.push_str(&format!(
            "suite_epoch_runtime_transitions_total{{result=\"rejected\"}} {}\n",
            self.runtime_rejected_transitions()
        ));
        output.push_str(&format!(
            "suite_epoch_runtime_transitions_total{{result=\"total\"}} {}\n",
            self.runtime_total_transitions()
        ));
        output
    }
}

// ============================================================================
// ConsensusProgressMetrics - Consensus progress tracking (T127)
// ============================================================================

/// Metrics for consensus progress tracking (T127).
///
/// This struct provides visibility into HotStuff consensus progress:
/// - QC formation frequency
/// - Vote collection activity
/// - View/leader transitions
///
/// These metrics help operators understand:
/// - Whether consensus is making progress
/// - How often QCs are formed
/// - Whether there are stalls (no view changes over time)
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering, following the pattern
/// of other metrics in this module.
///
/// # Prometheus-style naming
///
/// Output format in `format_metrics()`:
/// ```text
/// qbind_consensus_qcs_formed_total 42
/// qbind_consensus_votes_observed_total 1234
/// qbind_consensus_votes_observed_current_view 12
/// qbind_consensus_view_changes_total 41
/// qbind_consensus_leader_changes_total 41
/// ```
#[derive(Debug, Default)]
pub struct ConsensusProgressMetrics {
    /// Total number of QCs formed (successfully aggregated).
    qcs_formed_total: AtomicU64,

    /// Total number of votes observed (valid, epoch-correct votes accepted).
    votes_observed_total: AtomicU64,

    /// Approximate count of votes observed in the current view.
    /// This is a best-effort gauge that is reset on view change.
    /// May have minor drift under concurrent access, which is acceptable
    /// for observability purposes.
    votes_observed_current_view: AtomicU64,

    /// Total number of view changes.
    view_changes_total: AtomicU64,

    /// Total number of leader changes.
    /// Note: In the current round-robin implementation, leader changes
    /// approximately equals view changes. This is tracked separately
    /// to support future leader selection policies.
    leader_changes_total: AtomicU64,

    // ========================================================================
    // QC Formation Latency Histogram (optional but preferred)
    // ========================================================================
    /// Count of QC formation latencies.
    qc_formation_latency_count: AtomicU64,
    /// Sum of QC formation latencies in milliseconds.
    qc_formation_latency_sum_ms: AtomicU64,
    /// QC formation latency bucket: < 100ms
    qc_formation_latency_bucket_100ms: AtomicU64,
    /// QC formation latency bucket: < 500ms
    qc_formation_latency_bucket_500ms: AtomicU64,
    /// QC formation latency bucket: < 2000ms
    qc_formation_latency_bucket_2s: AtomicU64,
    /// QC formation latency bucket: +Inf (all)
    qc_formation_latency_bucket_inf: AtomicU64,
}

impl ConsensusProgressMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // QC Formation
    // ========================================================================

    /// Increment the QC formed counter.
    ///
    /// Call this exactly once per QC that is actually used by the engine
    /// (not for every deserialized QC).
    pub fn inc_qcs_formed(&self) {
        self.qcs_formed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of QCs formed.
    pub fn qcs_formed_total(&self) -> u64 {
        self.qcs_formed_total.load(Ordering::Relaxed)
    }

    // ========================================================================
    // Vote Observation
    // ========================================================================

    /// Increment the total votes observed counter.
    ///
    /// Call this when a valid, epoch-correct, suite-correct vote is accepted.
    pub fn inc_votes_observed(&self) {
        self.votes_observed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of votes observed.
    pub fn votes_observed_total(&self) -> u64 {
        self.votes_observed_total.load(Ordering::Relaxed)
    }

    /// Increment the current view votes counter.
    ///
    /// Call this when a vote for the current view is accepted.
    pub fn inc_votes_current_view(&self) {
        self.votes_observed_current_view
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the approximate count of votes in the current view.
    ///
    /// Note: This is a best-effort gauge. Under concurrent access during
    /// view transitions, this value may be slightly stale. This is acceptable
    /// for observability purposes.
    pub fn votes_observed_current_view(&self) -> u64 {
        self.votes_observed_current_view.load(Ordering::Relaxed)
    }

    /// Reset the current view votes counter.
    ///
    /// Call this when the engine advances to a new view.
    pub fn reset_votes_current_view(&self) {
        self.votes_observed_current_view.store(0, Ordering::Relaxed);
    }

    // ========================================================================
    // View / Leader Changes
    // ========================================================================

    /// Increment the view changes counter.
    ///
    /// Call this on each actual view change.
    pub fn inc_view_changes(&self) {
        self.view_changes_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of view changes.
    pub fn view_changes_total(&self) -> u64 {
        self.view_changes_total.load(Ordering::Relaxed)
    }

    /// Increment the leader changes counter.
    ///
    /// Call this when the leader changes (new view has a different leader).
    /// In the current round-robin implementation, this equals view changes.
    pub fn inc_leader_changes(&self) {
        self.leader_changes_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of leader changes.
    pub fn leader_changes_total(&self) -> u64 {
        self.leader_changes_total.load(Ordering::Relaxed)
    }

    // ========================================================================
    // QC Formation Latency Histogram
    // ========================================================================

    /// Record a QC formation latency.
    ///
    /// This tracks the time from view start to QC formation.
    pub fn record_qc_formation_latency(&self, duration: std::time::Duration) {
        // Safely convert u128 to u64, capping at u64::MAX to prevent silent overflow
        let millis = duration.as_millis().min(u64::MAX as u128) as u64;

        // Increment count and sum
        self.qc_formation_latency_count
            .fetch_add(1, Ordering::Relaxed);
        self.qc_formation_latency_sum_ms
            .fetch_add(millis, Ordering::Relaxed);

        // Update histogram buckets (cumulative)
        self.qc_formation_latency_bucket_inf
            .fetch_add(1, Ordering::Relaxed);

        if millis < 2000 {
            self.qc_formation_latency_bucket_2s
                .fetch_add(1, Ordering::Relaxed);
        }
        if millis < 500 {
            self.qc_formation_latency_bucket_500ms
                .fetch_add(1, Ordering::Relaxed);
        }
        if millis < 100 {
            self.qc_formation_latency_bucket_100ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get QC formation latency count.
    pub fn qc_formation_latency_count(&self) -> u64 {
        self.qc_formation_latency_count.load(Ordering::Relaxed)
    }

    /// Get QC formation latency sum in milliseconds.
    pub fn qc_formation_latency_sum_ms(&self) -> u64 {
        self.qc_formation_latency_sum_ms.load(Ordering::Relaxed)
    }

    /// Get QC formation latency bucket counts.
    ///
    /// Returns (under_100ms, under_500ms, under_2s, inf).
    pub fn qc_formation_latency_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.qc_formation_latency_bucket_100ms
                .load(Ordering::Relaxed),
            self.qc_formation_latency_bucket_500ms
                .load(Ordering::Relaxed),
            self.qc_formation_latency_bucket_2s.load(Ordering::Relaxed),
            self.qc_formation_latency_bucket_inf.load(Ordering::Relaxed),
        )
    }

    /// Format consensus progress metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Consensus progress metrics (T127)\n");

        // QC formation
        output.push_str(&format!(
            "qbind_consensus_qcs_formed_total {}\n",
            self.qcs_formed_total()
        ));

        // Vote observation
        output.push_str(&format!(
            "qbind_consensus_votes_observed_total {}\n",
            self.votes_observed_total()
        ));
        output.push_str(&format!(
            "qbind_consensus_votes_observed_current_view {}\n",
            self.votes_observed_current_view()
        ));

        // View/leader changes
        output.push_str(&format!(
            "qbind_consensus_view_changes_total {}\n",
            self.view_changes_total()
        ));
        output.push_str(&format!(
            "qbind_consensus_leader_changes_total {}\n",
            self.leader_changes_total()
        ));

        // QC formation latency histogram
        let count = self.qc_formation_latency_count();
        let sum = self.qc_formation_latency_sum_ms();
        let (b100, b500, b2s, binf) = self.qc_formation_latency_buckets();

        output.push_str(&format!(
            "qbind_consensus_qc_formation_latency_ms_count {}\n",
            count
        ));
        output.push_str(&format!(
            "qbind_consensus_qc_formation_latency_ms_sum {}\n",
            sum
        ));
        output.push_str(&format!(
            "qbind_consensus_qc_formation_latency_ms_bucket{{le=\"100\"}} {}\n",
            b100
        ));
        output.push_str(&format!(
            "qbind_consensus_qc_formation_latency_ms_bucket{{le=\"500\"}} {}\n",
            b500
        ));
        output.push_str(&format!(
            "qbind_consensus_qc_formation_latency_ms_bucket{{le=\"2000\"}} {}\n",
            b2s
        ));
        output.push_str(&format!(
            "qbind_consensus_qc_formation_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            binf
        ));

        output
    }
}

// Implement ConsensusProgressRecorder for ConsensusProgressMetrics
// This allows ConsensusProgressMetrics to be used as the metrics callback
// in the consensus engine (T127).
impl qbind_consensus::ConsensusProgressRecorder for ConsensusProgressMetrics {
    fn record_qc_formed(&self) {
        self.inc_qcs_formed();
    }

    fn record_qc_formed_with_latency(&self, latency: std::time::Duration) {
        self.inc_qcs_formed();
        self.record_qc_formation_latency(latency);
    }

    fn record_vote_observed(&self, is_for_current_view: bool) {
        self.inc_votes_observed();
        if is_for_current_view {
            self.inc_votes_current_view();
        }
    }

    fn record_view_change(&self, _from_view: u64, _to_view: u64) {
        self.inc_view_changes();
    }

    fn record_leader_change(&self) {
        self.inc_leader_changes();
    }

    fn reset_current_view_votes(&self) {
        self.reset_votes_current_view();
    }
}

// ============================================================================
// ValidatorVoteMetrics - Per-Validator Vote Tracking (T128)
// ============================================================================

/// Per-validator vote counters.
///
/// This struct holds atomic counters for a single validator's vote activity.
///
/// # Thread Safety
///
/// Both fields are atomic and can be updated independently. When reading both
/// values, note that `votes_total` may increment while `last_vote_view` stays
/// the same (if the vote is for a lower view than previously seen). This is
/// intentional: `votes_total` counts all valid votes, while `last_vote_view`
/// is monotonically increasing and represents the highest view voted for.
#[derive(Debug, Default)]
pub struct ValidatorVoteCounters {
    /// Total number of valid votes seen from this validator.
    pub votes_total: AtomicU64,
    /// The last view number where we recorded a valid vote from this validator.
    /// This value only increases (monotonic) and represents the highest view
    /// this validator has voted for.
    pub last_vote_view: AtomicU64,
}

impl ValidatorVoteCounters {
    /// Create new counters initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Maximum number of validators to track individually (T128).
///
/// This is set to accommodate typical validator set sizes. Validators beyond
/// this limit will not be tracked individually.
pub const MAX_TRACKED_VALIDATORS: usize = 256;

/// Per-validator vote metrics (T128).
///
/// This struct tracks per-validator vote participation:
/// - Total votes seen from each validator
/// - Last view where each validator voted
///
/// # Design Notes
///
/// - Uses `RwLock<HashMap<ValidatorId, ValidatorVoteCounters>>` for thread-safe access
/// - Bounded to `MAX_TRACKED_VALIDATORS` to prevent unbounded memory growth
/// - Only tracks valid, epoch-correct votes (rejected votes are not counted)
///
/// # Thread Safety
///
/// All operations are thread-safe using RwLock for the validator map and atomic
/// operations for individual counters. The read path acquires a read lock,
/// while writes acquire a write lock only when inserting new validators.
///
/// # Prometheus-style naming
///
/// Output format in `format_metrics()`:
/// ```text
/// qbind_consensus_validator_votes_total{validator="1"} 123
/// qbind_consensus_validator_last_vote_view{validator="1"} 456
/// ```
#[derive(Debug)]
pub struct ValidatorVoteMetrics {
    /// Per-validator counters, keyed by ValidatorId.
    validators: RwLock<HashMap<ValidatorId, ValidatorVoteCounters>>,
    /// Number of validators that exceeded the tracking limit.
    overflow_count: AtomicU64,
}

impl Default for ValidatorVoteMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorVoteMetrics {
    /// Create a new ValidatorVoteMetrics instance.
    pub fn new() -> Self {
        ValidatorVoteMetrics {
            validators: RwLock::new(HashMap::new()),
            overflow_count: AtomicU64::new(0),
        }
    }

    /// Ensure a validator entry exists, returning true if the validator is tracked.
    fn ensure_validator_entry(&self, validator_id: ValidatorId) -> bool {
        // Fast path: check if validator already exists
        {
            let validators = match self.validators.read() {
                Ok(v) => v,
                Err(_) => return false,
            };
            if validators.contains_key(&validator_id) {
                return true;
            }
        }

        // Slow path: try to insert
        let mut validators = match self.validators.write() {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Double-check after acquiring write lock
        if validators.contains_key(&validator_id) {
            return true;
        }

        // Check capacity
        if validators.len() >= MAX_TRACKED_VALIDATORS {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        validators.insert(validator_id, ValidatorVoteCounters::new());
        true
    }

    /// Record a vote from a validator.
    ///
    /// This increments the validator's total vote count and updates their
    /// last_vote_view if the new view is higher than the previous one.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator who cast the vote
    /// * `view` - The view number of the vote
    pub fn on_validator_vote(&self, validator_id: ValidatorId, view: u64) {
        if self.ensure_validator_entry(validator_id) {
            let validators = match self.validators.read() {
                Ok(v) => v,
                Err(_) => return,
            };
            if let Some(counters) = validators.get(&validator_id) {
                // Increment total votes
                counters.votes_total.fetch_add(1, Ordering::Relaxed);

                // Update last_vote_view if this view is higher (monotonic update)
                // Use compare-and-swap loop to ensure monotonicity
                loop {
                    let current = counters.last_vote_view.load(Ordering::Relaxed);
                    if view <= current {
                        break; // New view is not higher, don't update
                    }
                    match counters.last_vote_view.compare_exchange_weak(
                        current,
                        view,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,     // Successfully updated
                        Err(_) => continue, // Another thread updated, retry
                    }
                }
            }
        }
    }

    /// Get the total vote count for a specific validator.
    pub fn validator_votes_total(&self, validator_id: ValidatorId) -> Option<u64> {
        let validators = self.validators.read().ok()?;
        let counters = validators.get(&validator_id)?;
        Some(counters.votes_total.load(Ordering::Relaxed))
    }

    /// Get the last vote view for a specific validator.
    pub fn validator_last_vote_view(&self, validator_id: ValidatorId) -> Option<u64> {
        let validators = self.validators.read().ok()?;
        let counters = validators.get(&validator_id)?;
        Some(counters.last_vote_view.load(Ordering::Relaxed))
    }

    /// Get the number of tracked validators.
    pub fn tracked_validator_count(&self) -> usize {
        self.validators.read().map(|v| v.len()).unwrap_or(0)
    }

    /// Get the number of validators that exceeded the tracking limit.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }

    /// Compute the view lag for a specific validator (T129).
    ///
    /// Returns `max(0, highest_seen_view - last_vote_view)` for the validator.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to compute lag for
    /// * `highest_seen_view` - The highest view seen across the network
    ///
    /// # Returns
    ///
    /// * `Some(lag)` if the validator is tracked (has at least one recorded vote)
    /// * `None` if the validator is not tracked
    ///
    /// # Note
    ///
    /// Validators must have at least one vote recorded to be tracked. Untracked
    /// validators (those who have never voted) return `None`, not `highest_seen_view`.
    pub fn validator_view_lag(
        &self,
        validator_id: ValidatorId,
        highest_seen_view: u64,
    ) -> Option<u64> {
        let validators = self.validators.read().ok()?;
        let counters = validators.get(&validator_id)?;
        let last_vote_view = counters.last_vote_view.load(Ordering::Relaxed);
        Some(highest_seen_view.saturating_sub(last_vote_view))
    }

    /// Get all per-validator view lags given the highest seen view (T129).
    ///
    /// Returns a Vec of (ValidatorId, lag) pairs for all tracked validators.
    /// Only validators with at least one recorded vote are included.
    ///
    /// # Note
    ///
    /// Untracked validators (those who have never voted) are not included in the
    /// returned Vec. To check for validators that should have voted but haven't,
    /// compare against the known validator set separately.
    pub fn all_validator_view_lags(&self, highest_seen_view: u64) -> Vec<(ValidatorId, u64)> {
        let validators = match self.validators.read() {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let mut lags = Vec::with_capacity(validators.len());
        for (validator_id, counters) in validators.iter() {
            let last_vote_view = counters.last_vote_view.load(Ordering::Relaxed);
            let lag = highest_seen_view.saturating_sub(last_vote_view);
            lags.push((*validator_id, lag));
        }
        lags
    }

    /// Format per-validator metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Per-validator vote metrics (T128)\n");

        let validators = match self.validators.read() {
            Ok(v) => v,
            Err(_) => return output,
        };

        // Sort validator IDs for deterministic output
        let mut validator_ids: Vec<_> = validators.keys().copied().collect();
        validator_ids.sort_by_key(|v| v.0);

        for validator_id in validator_ids {
            if let Some(counters) = validators.get(&validator_id) {
                let votes_total = counters.votes_total.load(Ordering::Relaxed);
                let last_vote_view = counters.last_vote_view.load(Ordering::Relaxed);

                // Only output if there's been at least one vote.
                // We check votes_total rather than last_vote_view because:
                // - votes_total is the authoritative count of recorded votes
                // - last_vote_view could theoretically be 0 for a real vote at view 0
                // - This avoids outputting entries for validators that were added
                //   to the map but never had a vote recorded (shouldn't happen normally)
                if votes_total > 0 {
                    output.push_str(&format!(
                        "qbind_consensus_validator_votes_total{{validator=\"{}\"}} {}\n",
                        validator_id.0, votes_total
                    ));
                    output.push_str(&format!(
                        "qbind_consensus_validator_last_vote_view{{validator=\"{}\"}} {}\n",
                        validator_id.0, last_vote_view
                    ));
                }
            }
        }

        // Output overflow count if any
        let overflow = self.overflow_count.load(Ordering::Relaxed);
        if overflow > 0 {
            output.push_str(&format!(
                "qbind_consensus_validator_overflow_count {}\n",
                overflow
            ));
        }

        output
    }

    /// Format per-validator metrics including view lag (T129).
    ///
    /// This method extends `format_metrics()` to include per-validator view lag
    /// computed using the provided highest_seen_view.
    ///
    /// # Output Format
    ///
    /// ```text
    /// qbind_consensus_validator_votes_total{validator="1"} 123
    /// qbind_consensus_validator_last_vote_view{validator="1"} 456
    /// qbind_consensus_validator_view_lag{validator="1"} 10
    /// ```
    ///
    /// # Convention for Validators with No Votes
    ///
    /// Validators with no recorded votes yet (votes_total == 0) are not output.
    /// This maintains consistency with the existing behavior where we only output
    /// validators that have actually voted.
    pub fn format_metrics_with_view_lag(&self, highest_seen_view: u64) -> String {
        let mut output = String::new();
        output.push_str("\n# Per-validator vote metrics (T128, T129)\n");

        let validators = match self.validators.read() {
            Ok(v) => v,
            Err(_) => return output,
        };

        // Sort validator IDs for deterministic output
        let mut validator_ids: Vec<_> = validators.keys().copied().collect();
        validator_ids.sort_by_key(|v| v.0);

        for validator_id in validator_ids {
            if let Some(counters) = validators.get(&validator_id) {
                let votes_total = counters.votes_total.load(Ordering::Relaxed);
                let last_vote_view = counters.last_vote_view.load(Ordering::Relaxed);

                // Only output if there's been at least one vote.
                if votes_total > 0 {
                    output.push_str(&format!(
                        "qbind_consensus_validator_votes_total{{validator=\"{}\"}} {}\n",
                        validator_id.0, votes_total
                    ));
                    output.push_str(&format!(
                        "qbind_consensus_validator_last_vote_view{{validator=\"{}\"}} {}\n",
                        validator_id.0, last_vote_view
                    ));
                    // Per-validator view lag (T129)
                    let view_lag = highest_seen_view.saturating_sub(last_vote_view);
                    output.push_str(&format!(
                        "qbind_consensus_validator_view_lag{{validator=\"{}\"}} {}\n",
                        validator_id.0, view_lag
                    ));
                }
            }
        }

        // Output overflow count if any
        let overflow = self.overflow_count.load(Ordering::Relaxed);
        if overflow > 0 {
            output.push_str(&format!(
                "qbind_consensus_validator_overflow_count {}\n",
                overflow
            ));
        }

        output
    }
}

// Implement ValidatorVoteRecorder for ValidatorVoteMetrics (T128)
// This allows ValidatorVoteMetrics to be used as the callback for per-validator
// vote tracking in the consensus engine.
impl qbind_consensus::ValidatorVoteRecorder for ValidatorVoteMetrics {
    fn on_validator_vote(&self, validator_id: ValidatorId, view: u64) {
        ValidatorVoteMetrics::on_validator_vote(self, validator_id, view);
    }
}

// ============================================================================
// ValidatorEquivocationMetrics - Per-Validator Equivocation Tracking (T129)
// ============================================================================

/// Per-validator counters for equivocation tracking.
#[derive(Debug, Default)]
struct ValidatorEquivocationCounters {
    /// Total number of equivocation events from this validator.
    equivocations_total: AtomicU64,
    /// Whether this validator has ever equivocated (1 = true, 0 = false).
    /// This is a gauge-style metric that remains 1 once set.
    equivocating: AtomicU64,
}

/// Per-validator equivocation metrics (T129).
///
/// This struct tracks per-validator equivocation events:
/// - Total equivocation events per validator
/// - Whether each validator has ever equivocated (boolean gauge)
///
/// # Design Notes
///
/// - Uses `RwLock<HashMap<ValidatorId, ValidatorEquivocationCounters>>` for thread-safe access
/// - Bounded to `MAX_TRACKED_VALIDATORS` to prevent unbounded memory growth
/// - Only tracks validators that have at least one recorded equivocation
///
/// # Thread Safety
///
/// All operations are thread-safe using RwLock for the validator map and atomic
/// operations for individual counters.
///
/// # Prometheus-style naming
///
/// Output format in `format_metrics()`:
/// ```text
/// qbind_consensus_validator_equivocations_total{validator="1"} 2
/// qbind_consensus_validator_equivocating{validator="1"} 1
/// ```
#[derive(Debug)]
pub struct ValidatorEquivocationMetrics {
    /// Per-validator counters, keyed by ValidatorId.
    validators: RwLock<HashMap<ValidatorId, ValidatorEquivocationCounters>>,
    /// Number of validators that exceeded the tracking limit.
    overflow_count: AtomicU64,
}

impl Default for ValidatorEquivocationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorEquivocationMetrics {
    /// Create a new ValidatorEquivocationMetrics instance.
    pub fn new() -> Self {
        ValidatorEquivocationMetrics {
            validators: RwLock::new(HashMap::new()),
            overflow_count: AtomicU64::new(0),
        }
    }

    /// Ensure a validator entry exists, returning true if the validator is tracked.
    fn ensure_validator_entry(&self, validator_id: ValidatorId) -> bool {
        // Fast path: check if validator already exists
        {
            let validators = match self.validators.read() {
                Ok(v) => v,
                Err(_) => return false,
            };
            if validators.contains_key(&validator_id) {
                return true;
            }
        }

        // Slow path: try to insert
        let mut validators = match self.validators.write() {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Double-check after acquiring write lock
        if validators.contains_key(&validator_id) {
            return true;
        }

        // Check capacity
        if validators.len() >= MAX_TRACKED_VALIDATORS {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        validators.insert(validator_id, ValidatorEquivocationCounters::default());
        true
    }

    /// Record an equivocation event from a validator.
    ///
    /// This increments the validator's equivocation count and marks them as equivocating.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator who equivocated
    /// * `_view` - The view number where equivocation occurred (currently unused but may
    ///   be used for future per-view tracking)
    pub fn on_validator_equivocation(&self, validator_id: ValidatorId, _view: u64) {
        if self.ensure_validator_entry(validator_id) {
            let validators = match self.validators.read() {
                Ok(v) => v,
                Err(_) => return,
            };
            if let Some(counters) = validators.get(&validator_id) {
                // Increment equivocation counter
                counters.equivocations_total.fetch_add(1, Ordering::Relaxed);

                // Mark as equivocating (idempotent - stays 1 once set)
                counters.equivocating.store(1, Ordering::Relaxed);
            }
        }
    }

    /// Get the total equivocation count for a specific validator.
    pub fn validator_equivocations_total(&self, validator_id: ValidatorId) -> Option<u64> {
        let validators = self.validators.read().ok()?;
        let counters = validators.get(&validator_id)?;
        Some(counters.equivocations_total.load(Ordering::Relaxed))
    }

    /// Get whether a validator has equivocated (1 = true, 0 = false).
    pub fn validator_equivocating(&self, validator_id: ValidatorId) -> Option<u64> {
        let validators = self.validators.read().ok()?;
        let counters = validators.get(&validator_id)?;
        Some(counters.equivocating.load(Ordering::Relaxed))
    }

    /// Get the number of tracked validators (those who have equivocated).
    pub fn tracked_validator_count(&self) -> usize {
        self.validators.read().map(|v| v.len()).unwrap_or(0)
    }

    /// Get the number of validators that exceeded the tracking limit.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }

    /// Format per-validator equivocation metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Per-validator equivocation metrics (T129)\n");

        let validators = match self.validators.read() {
            Ok(v) => v,
            Err(_) => return output,
        };

        // Sort validator IDs for deterministic output
        let mut validator_ids: Vec<_> = validators.keys().copied().collect();
        validator_ids.sort_by_key(|v| v.0);

        for validator_id in validator_ids {
            if let Some(counters) = validators.get(&validator_id) {
                let equivocations_total = counters.equivocations_total.load(Ordering::Relaxed);
                let equivocating = counters.equivocating.load(Ordering::Relaxed);

                // Only output if there's been at least one equivocation
                if equivocations_total > 0 {
                    output.push_str(&format!(
                        "qbind_consensus_validator_equivocations_total{{validator=\"{}\"}} {}\n",
                        validator_id.0, equivocations_total
                    ));
                    output.push_str(&format!(
                        "qbind_consensus_validator_equivocating{{validator=\"{}\"}} {}\n",
                        validator_id.0, equivocating
                    ));
                }
            }
        }

        // Output overflow count if any
        let overflow = self.overflow_count.load(Ordering::Relaxed);
        if overflow > 0 {
            output.push_str(&format!(
                "qbind_consensus_validator_equivocation_overflow_count {}\n",
                overflow
            ));
        }

        output
    }
}

// Implement ValidatorEquivocationRecorder for ValidatorEquivocationMetrics (T129)
// This allows ValidatorEquivocationMetrics to be used as the callback for per-validator
// equivocation tracking in the consensus engine.
impl qbind_consensus::ValidatorEquivocationRecorder for ValidatorEquivocationMetrics {
    fn on_validator_equivocation(&self, validator_id: ValidatorId, view: u64) {
        ValidatorEquivocationMetrics::on_validator_equivocation(self, validator_id, view);
    }
}

// ============================================================================
// ViewLagMetrics - View Lag Gauge (T128)
// ============================================================================

/// View lag gauge metric (T128).
///
/// Tracks the difference between the highest view seen by this node
/// and the current view. This helps identify nodes that are lagging
/// behind the network.
///
/// # Definition
///
/// `view_lag = max(0, highest_seen_view - current_view)`
///
/// # Thread Safety
///
/// All operations use atomic operations with relaxed ordering.
#[derive(Debug, Default)]
pub struct ViewLagMetrics {
    /// The current view of this node.
    current_view: AtomicU64,
    /// The highest view number seen in any QC or proposal.
    highest_seen_view: AtomicU64,
}

impl ViewLagMetrics {
    /// Create a new ViewLagMetrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the current view.
    pub fn set_current_view(&self, view: u64) {
        self.current_view.store(view, Ordering::Relaxed);
    }

    /// Get the current view.
    pub fn current_view(&self) -> u64 {
        self.current_view.load(Ordering::Relaxed)
    }

    /// Update the highest seen view (monotonic - only increases).
    ///
    /// This should be called when processing a QC or proposal with a view
    /// higher than the current highest seen view.
    pub fn update_highest_seen_view(&self, view: u64) {
        // Use compare-and-swap loop to ensure monotonicity
        loop {
            let current = self.highest_seen_view.load(Ordering::Relaxed);
            if view <= current {
                break; // New view is not higher, don't update
            }
            match self.highest_seen_view.compare_exchange_weak(
                current,
                view,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,     // Successfully updated
                Err(_) => continue, // Another thread updated, retry
            }
        }
    }

    /// Get the highest seen view.
    pub fn highest_seen_view(&self) -> u64 {
        self.highest_seen_view.load(Ordering::Relaxed)
    }

    /// Get the current view lag.
    ///
    /// Returns `highest_seen_view - current_view` if positive, otherwise 0.
    pub fn view_lag(&self) -> u64 {
        let current = self.current_view.load(Ordering::Relaxed);
        let highest = self.highest_seen_view.load(Ordering::Relaxed);
        highest.saturating_sub(current)
    }

    /// Format view lag metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# View lag metrics (T128)\n");
        output.push_str(&format!(
            "qbind_consensus_current_view {}\n",
            self.current_view()
        ));
        output.push_str(&format!(
            "qbind_consensus_highest_seen_view {}\n",
            self.highest_seen_view()
        ));
        output.push_str(&format!("qbind_consensus_view_lag {}\n", self.view_lag()));
        output
    }
}

// ============================================================================
// T154 Metrics - DevNet Performance & Observability Baseline
// ============================================================================

// ============================================================================
// ConsensusT154Metrics - Consensus-level metrics for T154
// ============================================================================

/// Metrics for consensus-level observability (T154).
///
/// Tracks:
/// - Proposals total (accepted/rejected)
/// - Votes total (accepted/invalid)
/// - Timeouts total
/// - Current view number (gauge)
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct ConsensusT154Metrics {
    /// Total proposals received that were accepted.
    proposals_accepted: AtomicU64,
    /// Total proposals received that were rejected.
    proposals_rejected: AtomicU64,
    /// Total votes received that were accepted.
    votes_accepted: AtomicU64,
    /// Total votes received that were invalid.
    votes_invalid: AtomicU64,
    /// Total timeout messages processed.
    timeouts_total: AtomicU64,
    /// Current view number (gauge).
    view_number: AtomicU64,
}

impl ConsensusT154Metrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment accepted proposals counter.
    pub fn inc_proposal_accepted(&self) {
        self.proposals_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment rejected proposals counter.
    pub fn inc_proposal_rejected(&self) {
        self.proposals_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total accepted proposals.
    pub fn proposals_accepted(&self) -> u64 {
        self.proposals_accepted.load(Ordering::Relaxed)
    }

    /// Get total rejected proposals.
    pub fn proposals_rejected(&self) -> u64 {
        self.proposals_rejected.load(Ordering::Relaxed)
    }

    /// Increment accepted votes counter.
    pub fn inc_vote_accepted(&self) {
        self.votes_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment invalid votes counter.
    pub fn inc_vote_invalid(&self) {
        self.votes_invalid.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total accepted votes.
    pub fn votes_accepted(&self) -> u64 {
        self.votes_accepted.load(Ordering::Relaxed)
    }

    /// Get total invalid votes.
    pub fn votes_invalid(&self) -> u64 {
        self.votes_invalid.load(Ordering::Relaxed)
    }

    /// Increment timeouts counter.
    pub fn inc_timeout(&self) {
        self.timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total timeouts.
    pub fn timeouts_total(&self) -> u64 {
        self.timeouts_total.load(Ordering::Relaxed)
    }

    /// Set current view number.
    pub fn set_view_number(&self, view: u64) {
        self.view_number.store(view, Ordering::Relaxed);
    }

    /// Get current view number.
    pub fn view_number(&self) -> u64 {
        self.view_number.load(Ordering::Relaxed)
    }

    /// Format consensus T154 metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Consensus metrics (T154)\n");
        output.push_str(&format!(
            "qbind_consensus_proposals_total{{result=\"accepted\"}} {}\n",
            self.proposals_accepted()
        ));
        output.push_str(&format!(
            "qbind_consensus_proposals_total{{result=\"rejected\"}} {}\n",
            self.proposals_rejected()
        ));
        output.push_str(&format!(
            "qbind_consensus_votes_total{{result=\"accepted\"}} {}\n",
            self.votes_accepted()
        ));
        output.push_str(&format!(
            "qbind_consensus_votes_total{{result=\"invalid\"}} {}\n",
            self.votes_invalid()
        ));
        output.push_str(&format!(
            "qbind_consensus_timeouts_total {}\n",
            self.timeouts_total()
        ));
        output.push_str(&format!(
            "qbind_consensus_view_number {}\n",
            self.view_number()
        ));
        output
    }
}

// ============================================================================
// MempoolMetrics - Mempool metrics for T154
// ============================================================================

/// Metrics for mempool observability (T154).
///
/// Tracks:
/// - Current mempool size (gauge)
/// - Total transactions inserted
/// - Total transactions rejected (by reason)
/// - Total transactions committed (removed on commit)
///
/// # Security Note
///
/// No transaction contents, sender addresses, or nonces are exposed
/// in these metrics. Only aggregate counts are tracked.
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct MempoolMetrics {
    /// Current number of transactions in the mempool (gauge).
    size: AtomicU64,
    /// Total transactions inserted successfully.
    inserted_total: AtomicU64,
    /// Total transactions rejected due to mempool full.
    rejected_full: AtomicU64,
    /// Total transactions rejected due to invalid signature.
    rejected_invalid_sig: AtomicU64,
    /// Total transactions rejected due to invalid nonce.
    rejected_invalid_nonce: AtomicU64,
    /// Total transactions rejected for other reasons.
    rejected_other: AtomicU64,
    /// Total transactions committed (removed from mempool).
    committed_total: AtomicU64,
    /// Total transactions evicted due to low priority (T169).
    evicted_low_priority_total: AtomicU64,
    /// Whether fee-based priority is enabled (gauge: 0/1) (T169).
    priority_enabled: AtomicU64,
}

impl MempoolMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current mempool size.
    pub fn set_size(&self, size: u64) {
        self.size.store(size, Ordering::Relaxed);
    }

    /// Get the current mempool size.
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }

    /// Increment inserted counter.
    pub fn inc_inserted(&self) {
        self.inserted_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total inserted transactions.
    pub fn inserted_total(&self) -> u64 {
        self.inserted_total.load(Ordering::Relaxed)
    }

    /// Increment rejected counter by reason.
    pub fn inc_rejected(&self, reason: MempoolRejectReason) {
        match reason {
            MempoolRejectReason::Full => {
                self.rejected_full.fetch_add(1, Ordering::Relaxed);
            }
            MempoolRejectReason::InvalidSignature => {
                self.rejected_invalid_sig.fetch_add(1, Ordering::Relaxed);
            }
            MempoolRejectReason::InvalidNonce => {
                self.rejected_invalid_nonce.fetch_add(1, Ordering::Relaxed);
            }
            MempoolRejectReason::LowPriority => {
                // We use inc_evicted_low_priority for evictions, but for rejection
                // of new tx due to low priority, we can either use rejected_other
                // or add a new counter if needed.
                // T169 suggests qbind_mempool_evicted_low_priority_total for evictions.
                // For "reject new tx because it's lower than existing", we use this.
                self.rejected_other.fetch_add(1, Ordering::Relaxed);
            }
            MempoolRejectReason::Other => {
                self.rejected_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get rejected count by reason.
    pub fn rejected_by_reason(&self, reason: MempoolRejectReason) -> u64 {
        match reason {
            MempoolRejectReason::Full => self.rejected_full.load(Ordering::Relaxed),
            MempoolRejectReason::InvalidSignature => {
                self.rejected_invalid_sig.load(Ordering::Relaxed)
            }
            MempoolRejectReason::InvalidNonce => {
                self.rejected_invalid_nonce.load(Ordering::Relaxed)
            }
            MempoolRejectReason::LowPriority => self.rejected_other.load(Ordering::Relaxed),
            MempoolRejectReason::Other => self.rejected_other.load(Ordering::Relaxed),
        }
    }

    /// Get total rejected transactions.
    pub fn rejected_total(&self) -> u64 {
        self.rejected_full.load(Ordering::Relaxed)
            + self.rejected_invalid_sig.load(Ordering::Relaxed)
            + self.rejected_invalid_nonce.load(Ordering::Relaxed)
            + self.rejected_other.load(Ordering::Relaxed)
    }

    /// Increment committed counter.
    pub fn inc_committed(&self) {
        self.committed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment evicted_low_priority_total counter (T169).
    pub fn inc_evicted_low_priority(&self) {
        self.evicted_low_priority_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Set whether fee-priority is enabled (T169).
    pub fn set_priority_enabled(&self, enabled: bool) {
        self.priority_enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Get total evicted due to low priority (T169).
    pub fn evicted_low_priority_total(&self) -> u64 {
        self.evicted_low_priority_total.load(Ordering::Relaxed)
    }

    /// Get priority enabled status (T169).
    pub fn priority_enabled(&self) -> bool {
        self.priority_enabled.load(Ordering::Relaxed) == 1
    }

    /// Increment committed counter by amount.
    pub fn add_committed(&self, count: u64) {
        self.committed_total.fetch_add(count, Ordering::Relaxed);
    }

    /// Get total committed transactions.
    pub fn committed_total(&self) -> u64 {
        self.committed_total.load(Ordering::Relaxed)
    }

    /// Format mempool metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Mempool metrics (T154)\n");
        output.push_str(&format!("qbind_mempool_txs_total {}\n", self.size()));
        output.push_str(&format!(
            "qbind_mempool_inserted_total {}\n",
            self.inserted_total()
        ));
        output.push_str(&format!(
            "qbind_mempool_rejected_total{{reason=\"full\"}} {}\n",
            self.rejected_by_reason(MempoolRejectReason::Full)
        ));
        output.push_str(&format!(
            "qbind_mempool_rejected_total{{reason=\"invalid_signature\"}} {}\n",
            self.rejected_by_reason(MempoolRejectReason::InvalidSignature)
        ));
        output.push_str(&format!(
            "qbind_mempool_rejected_total{{reason=\"invalid_nonce\"}} {}\n",
            self.rejected_by_reason(MempoolRejectReason::InvalidNonce)
        ));
        output.push_str(&format!(
            "qbind_mempool_rejected_total{{reason=\"other\"}} {}\n",
            self.rejected_by_reason(MempoolRejectReason::Other)
        ));
        output.push_str(&format!(
            "qbind_mempool_committed_total {}\n",
            self.committed_total()
        ));
        output
    }
}

/// Reason for mempool rejection (T154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolRejectReason {
    /// Mempool is at capacity.
    Full,
    /// Transaction signature is invalid.
    InvalidSignature,
    /// Transaction nonce is invalid.
    InvalidNonce,
    /// Transaction priority too low (T169).
    LowPriority,
    /// Other rejection reason.
    Other,
}

// ============================================================================
// ExecutionMetrics - Execution metrics for T154
// ============================================================================

/// Metrics for execution layer observability (T154).
///
/// Tracks:
/// - Total transactions applied
/// - Block apply latency histogram
/// - Execution errors by reason
///
/// # Security Note
///
/// No transaction contents, state data, or specific error details
/// are exposed in these metrics. Only aggregate counts are tracked.
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct ExecutionMetrics {
    /// Total transactions applied successfully.
    txs_applied_total: AtomicU64,
    /// Total blocks applied.
    blocks_applied_total: AtomicU64,
    /// Sum of block apply times in milliseconds.
    block_apply_time_ms_sum: AtomicU64,
    /// Block apply time bucket: < 1ms.
    block_apply_bucket_1ms: AtomicU64,
    /// Block apply time bucket: < 10ms.
    block_apply_bucket_10ms: AtomicU64,
    /// Block apply time bucket: < 100ms.
    block_apply_bucket_100ms: AtomicU64,
    /// Block apply time bucket: >= 100ms.
    block_apply_bucket_over_100ms: AtomicU64,
    /// Total execution errors: nonce mismatch.
    errors_nonce_mismatch: AtomicU64,
    /// Total execution errors: other.
    errors_other: AtomicU64,

    // ========================================================================
    // T155: Async execution pipeline metrics
    // ========================================================================
    /// Current execution queue length (gauge) - T155.
    queue_len: AtomicU64,
    /// Number of times submit_block failed due to queue full - T155.
    queue_full_total: AtomicU64,
    /// Number of worker restarts (if worker panics/fails) - T155.
    worker_restarts_total: AtomicU64,

    // ========================================================================
    // T157: Stage A parallel execution metrics
    // ========================================================================
    /// Number of workers active for the last block (gauge) - T157.
    parallel_workers_active: AtomicU64,
    /// Total sender partitions observed (sum for histogram) - T157.
    parallel_sender_partitions_sum: AtomicU64,
    /// Sender partitions bucket: < 4 senders.
    parallel_sender_partitions_bucket_4: AtomicU64,
    /// Sender partitions bucket: < 16 senders.
    parallel_sender_partitions_bucket_16: AtomicU64,
    /// Sender partitions bucket: < 64 senders.
    parallel_sender_partitions_bucket_64: AtomicU64,
    /// Sender partitions bucket: >= 64 senders.
    parallel_sender_partitions_bucket_over_64: AtomicU64,
    /// Parallel block execution time sum in milliseconds - T157.
    parallel_block_time_ms_sum: AtomicU64,
    /// Parallel execution time bucket: < 1ms.
    parallel_block_bucket_1ms: AtomicU64,
    /// Parallel execution time bucket: < 10ms.
    parallel_block_bucket_10ms: AtomicU64,
    /// Parallel execution time bucket: < 100ms.
    parallel_block_bucket_100ms: AtomicU64,
    /// Parallel execution time bucket: >= 100ms.
    parallel_block_bucket_over_100ms: AtomicU64,
    /// Times we intentionally fell back to sequential - T157.
    parallel_fallback_total: AtomicU64,

    // ========================================================================
    // T187: Stage B parallel execution metrics
    // ========================================================================
    /// Stage B enabled gauge (0 or 1) - T187.
    stage_b_enabled: AtomicU64,
    /// Stage B blocks executed in parallel mode - T187.
    stage_b_blocks_parallel: AtomicU64,
    /// Stage B blocks executed in fallback mode - T187.
    stage_b_blocks_fallback: AtomicU64,
    /// Stage B mismatch/internal error count - T187.
    stage_b_mismatch_total: AtomicU64,
    /// Stage B levels histogram: < 4 levels.
    stage_b_levels_bucket_4: AtomicU64,
    /// Stage B levels histogram: < 16 levels.
    stage_b_levels_bucket_16: AtomicU64,
    /// Stage B levels histogram: < 64 levels.
    stage_b_levels_bucket_64: AtomicU64,
    /// Stage B levels histogram: >= 64 levels.
    stage_b_levels_bucket_over_64: AtomicU64,
    /// Stage B parallel execution time sum in milliseconds - T187.
    stage_b_parallel_time_ms_sum: AtomicU64,
    /// Stage B execution time bucket: < 1ms.
    stage_b_parallel_bucket_1ms: AtomicU64,
    /// Stage B execution time bucket: < 10ms.
    stage_b_parallel_bucket_10ms: AtomicU64,
    /// Stage B execution time bucket: < 100ms.
    stage_b_parallel_bucket_100ms: AtomicU64,
    /// Stage B execution time bucket: >= 100ms.
    stage_b_parallel_bucket_over_100ms: AtomicU64,
}

impl ExecutionMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment applied transactions counter.
    pub fn add_txs_applied(&self, count: u64) {
        self.txs_applied_total.fetch_add(count, Ordering::Relaxed);
    }

    /// Get total applied transactions.
    pub fn txs_applied_total(&self) -> u64 {
        self.txs_applied_total.load(Ordering::Relaxed)
    }

    /// Record a block application with its duration.
    pub fn record_block_apply(&self, duration: std::time::Duration) {
        self.blocks_applied_total.fetch_add(1, Ordering::Relaxed);
        let millis = duration.as_millis() as u64;
        self.block_apply_time_ms_sum
            .fetch_add(millis, Ordering::Relaxed);

        if millis < 1 {
            self.block_apply_bucket_1ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.block_apply_bucket_10ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.block_apply_bucket_100ms
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.block_apply_bucket_over_100ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get total blocks applied.
    pub fn blocks_applied_total(&self) -> u64 {
        self.blocks_applied_total.load(Ordering::Relaxed)
    }

    /// Get block apply time sum in milliseconds.
    pub fn block_apply_time_ms_sum(&self) -> u64 {
        self.block_apply_time_ms_sum.load(Ordering::Relaxed)
    }

    /// Get block apply latency buckets.
    pub fn block_apply_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.block_apply_bucket_1ms.load(Ordering::Relaxed),
            self.block_apply_bucket_10ms.load(Ordering::Relaxed),
            self.block_apply_bucket_100ms.load(Ordering::Relaxed),
            self.block_apply_bucket_over_100ms.load(Ordering::Relaxed),
        )
    }

    /// Increment error counter by reason.
    pub fn inc_error(&self, reason: ExecutionErrorReason) {
        match reason {
            ExecutionErrorReason::NonceMismatch => {
                self.errors_nonce_mismatch.fetch_add(1, Ordering::Relaxed);
            }
            ExecutionErrorReason::Other => {
                self.errors_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get error count by reason.
    pub fn errors_by_reason(&self, reason: ExecutionErrorReason) -> u64 {
        match reason {
            ExecutionErrorReason::NonceMismatch => {
                self.errors_nonce_mismatch.load(Ordering::Relaxed)
            }
            ExecutionErrorReason::Other => self.errors_other.load(Ordering::Relaxed),
        }
    }

    /// Get total errors.
    pub fn errors_total(&self) -> u64 {
        self.errors_nonce_mismatch.load(Ordering::Relaxed)
            + self.errors_other.load(Ordering::Relaxed)
    }

    // ========================================================================
    // T155: Async execution pipeline metrics
    // ========================================================================

    /// Set the current execution queue length (T155).
    pub fn set_queue_len(&self, len: u64) {
        self.queue_len.store(len, Ordering::Relaxed);
    }

    /// Get the current execution queue length (T155).
    pub fn queue_len(&self) -> u64 {
        self.queue_len.load(Ordering::Relaxed)
    }

    /// Increment queue full counter (T155).
    ///
    /// Call this when submit_block fails due to queue being full.
    pub fn inc_queue_full(&self) {
        self.queue_full_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total queue full count (T155).
    pub fn queue_full_total(&self) -> u64 {
        self.queue_full_total.load(Ordering::Relaxed)
    }

    /// Increment worker restart counter (T155).
    ///
    /// Call this if the execution worker is restarted due to panic or failure.
    pub fn inc_worker_restart(&self) {
        self.worker_restarts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total worker restart count (T155).
    pub fn worker_restarts_total(&self) -> u64 {
        self.worker_restarts_total.load(Ordering::Relaxed)
    }

    // ========================================================================
    // T157: Stage A parallel execution metrics
    // ========================================================================

    /// Set the number of parallel workers active for the current block (T157).
    pub fn set_parallel_workers_active(&self, workers: usize) {
        self.parallel_workers_active
            .store(workers as u64, Ordering::Relaxed);
    }

    /// Get the number of parallel workers active (T157).
    pub fn parallel_workers_active(&self) -> u64 {
        self.parallel_workers_active.load(Ordering::Relaxed)
    }

    /// Record sender partition count for a block (T157).
    ///
    /// This records the number of distinct senders in a block for histogram tracking.
    pub fn record_sender_partitions(&self, num_senders: usize) {
        let count = num_senders as u64;
        self.parallel_sender_partitions_sum
            .fetch_add(count, Ordering::Relaxed);

        if num_senders < 4 {
            self.parallel_sender_partitions_bucket_4
                .fetch_add(1, Ordering::Relaxed);
        } else if num_senders < 16 {
            self.parallel_sender_partitions_bucket_16
                .fetch_add(1, Ordering::Relaxed);
        } else if num_senders < 64 {
            self.parallel_sender_partitions_bucket_64
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.parallel_sender_partitions_bucket_over_64
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get sender partition histogram buckets (T157).
    pub fn sender_partitions_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.parallel_sender_partitions_bucket_4
                .load(Ordering::Relaxed),
            self.parallel_sender_partitions_bucket_16
                .load(Ordering::Relaxed),
            self.parallel_sender_partitions_bucket_64
                .load(Ordering::Relaxed),
            self.parallel_sender_partitions_bucket_over_64
                .load(Ordering::Relaxed),
        )
    }

    /// Get sender partition sum (T157).
    pub fn sender_partitions_sum(&self) -> u64 {
        self.parallel_sender_partitions_sum.load(Ordering::Relaxed)
    }

    /// Record parallel block execution time (T157).
    pub fn record_parallel_block_time(&self, duration: std::time::Duration) {
        let millis = duration.as_millis() as u64;
        self.parallel_block_time_ms_sum
            .fetch_add(millis, Ordering::Relaxed);

        if millis < 1 {
            self.parallel_block_bucket_1ms
                .fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.parallel_block_bucket_10ms
                .fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.parallel_block_bucket_100ms
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.parallel_block_bucket_over_100ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get parallel block time sum in milliseconds (T157).
    pub fn parallel_block_time_ms_sum(&self) -> u64 {
        self.parallel_block_time_ms_sum.load(Ordering::Relaxed)
    }

    /// Get parallel block time histogram buckets (T157).
    pub fn parallel_block_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.parallel_block_bucket_1ms.load(Ordering::Relaxed),
            self.parallel_block_bucket_10ms.load(Ordering::Relaxed),
            self.parallel_block_bucket_100ms.load(Ordering::Relaxed),
            self.parallel_block_bucket_over_100ms
                .load(Ordering::Relaxed),
        )
    }

    /// Increment parallel fallback counter (T157).
    ///
    /// Call this when execution falls back to sequential due to low sender count.
    pub fn inc_parallel_fallback(&self) {
        self.parallel_fallback_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total parallel fallbacks (T157).
    pub fn parallel_fallback_total(&self) -> u64 {
        self.parallel_fallback_total.load(Ordering::Relaxed)
    }

    // ========================================================================
    // T187: Stage B parallel execution metrics
    // ========================================================================

    /// Set the Stage B enabled gauge (T187).
    ///
    /// Call this on service creation to indicate Stage B status.
    pub fn set_stage_b_enabled(&self, enabled: bool) {
        self.stage_b_enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Get Stage B enabled status (T187).
    pub fn stage_b_enabled(&self) -> u64 {
        self.stage_b_enabled.load(Ordering::Relaxed)
    }

    /// Increment Stage B parallel blocks counter (T187).
    ///
    /// Call this when Stage B path runs successfully.
    pub fn inc_stage_b_parallel(&self) {
        self.stage_b_blocks_parallel.fetch_add(1, Ordering::Relaxed);
    }

    /// Get Stage B parallel blocks count (T187).
    pub fn stage_b_blocks_parallel(&self) -> u64 {
        self.stage_b_blocks_parallel.load(Ordering::Relaxed)
    }

    /// Increment Stage B fallback blocks counter (T187).
    ///
    /// Call this when Stage B path encounters an error and falls back to sequential.
    pub fn inc_stage_b_fallback(&self) {
        self.stage_b_blocks_fallback.fetch_add(1, Ordering::Relaxed);
    }

    /// Get Stage B fallback blocks count (T187).
    pub fn stage_b_blocks_fallback(&self) -> u64 {
        self.stage_b_blocks_fallback.load(Ordering::Relaxed)
    }

    /// Increment Stage B mismatch counter (T187).
    ///
    /// Call this when Stage B encounters an internal mismatch or unexpected violation.
    pub fn inc_stage_b_mismatch(&self) {
        self.stage_b_mismatch_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get Stage B mismatch count (T187).
    pub fn stage_b_mismatch_total(&self) -> u64 {
        self.stage_b_mismatch_total.load(Ordering::Relaxed)
    }

    /// Record Stage B schedule levels (T187).
    ///
    /// Records the number of levels in the parallel schedule for histogram tracking.
    pub fn record_stage_b_levels(&self, level_count: usize) {
        if level_count < 4 {
            self.stage_b_levels_bucket_4.fetch_add(1, Ordering::Relaxed);
        } else if level_count < 16 {
            self.stage_b_levels_bucket_16
                .fetch_add(1, Ordering::Relaxed);
        } else if level_count < 64 {
            self.stage_b_levels_bucket_64
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.stage_b_levels_bucket_over_64
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get Stage B levels histogram buckets (T187).
    pub fn stage_b_levels_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.stage_b_levels_bucket_4.load(Ordering::Relaxed),
            self.stage_b_levels_bucket_16.load(Ordering::Relaxed),
            self.stage_b_levels_bucket_64.load(Ordering::Relaxed),
            self.stage_b_levels_bucket_over_64.load(Ordering::Relaxed),
        )
    }

    /// Record Stage B parallel execution time (T187).
    pub fn record_stage_b_parallel_time(&self, duration: std::time::Duration) {
        let millis = duration.as_millis() as u64;
        self.stage_b_parallel_time_ms_sum
            .fetch_add(millis, Ordering::Relaxed);

        if millis < 1 {
            self.stage_b_parallel_bucket_1ms
                .fetch_add(1, Ordering::Relaxed);
        } else if millis < 10 {
            self.stage_b_parallel_bucket_10ms
                .fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.stage_b_parallel_bucket_100ms
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.stage_b_parallel_bucket_over_100ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get Stage B parallel time sum in milliseconds (T187).
    pub fn stage_b_parallel_time_ms_sum(&self) -> u64 {
        self.stage_b_parallel_time_ms_sum.load(Ordering::Relaxed)
    }

    /// Get Stage B parallel time histogram buckets (T187).
    pub fn stage_b_parallel_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.stage_b_parallel_bucket_1ms.load(Ordering::Relaxed),
            self.stage_b_parallel_bucket_10ms.load(Ordering::Relaxed),
            self.stage_b_parallel_bucket_100ms.load(Ordering::Relaxed),
            self.stage_b_parallel_bucket_over_100ms
                .load(Ordering::Relaxed),
        )
    }

    /// Format execution metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Execution metrics (T154/T155)\n");
        output.push_str(&format!(
            "qbind_execution_txs_applied_total {}\n",
            self.txs_applied_total()
        ));
        output.push_str(&format!(
            "qbind_execution_block_apply_seconds_count {}\n",
            self.blocks_applied_total()
        ));
        output.push_str(&format!(
            "qbind_execution_block_apply_seconds_sum {}\n",
            self.block_apply_time_ms_sum() as f64 / 1000.0
        ));

        let (b1, b10, b100, over) = self.block_apply_buckets();
        // Cumulative histogram buckets
        output.push_str(&format!(
            "qbind_execution_block_apply_seconds_bucket{{le=\"0.001\"}} {}\n",
            b1
        ));
        output.push_str(&format!(
            "qbind_execution_block_apply_seconds_bucket{{le=\"0.01\"}} {}\n",
            b1 + b10
        ));
        output.push_str(&format!(
            "qbind_execution_block_apply_seconds_bucket{{le=\"0.1\"}} {}\n",
            b1 + b10 + b100
        ));
        output.push_str(&format!(
            "qbind_execution_block_apply_seconds_bucket{{le=\"+Inf\"}} {}\n",
            b1 + b10 + b100 + over
        ));

        output.push_str(&format!(
            "qbind_execution_errors_total{{reason=\"nonce_mismatch\"}} {}\n",
            self.errors_by_reason(ExecutionErrorReason::NonceMismatch)
        ));
        output.push_str(&format!(
            "qbind_execution_errors_total{{reason=\"other\"}} {}\n",
            self.errors_by_reason(ExecutionErrorReason::Other)
        ));

        // T155: Async execution pipeline metrics
        output.push_str(&format!("qbind_execution_queue_len {}\n", self.queue_len()));
        output.push_str(&format!(
            "qbind_execution_queue_full_total {}\n",
            self.queue_full_total()
        ));
        output.push_str(&format!(
            "qbind_execution_worker_restarts_total {}\n",
            self.worker_restarts_total()
        ));

        // T157: Parallel execution metrics
        output.push_str("\n# T157: Stage A parallel execution metrics\n");
        output.push_str(&format!(
            "qbind_execution_parallel_workers_active {}\n",
            self.parallel_workers_active()
        ));

        // Sender partitions histogram
        let (sp4, sp16, sp64, sp_over) = self.sender_partitions_buckets();
        let sp_total = sp4 + sp16 + sp64 + sp_over;
        output.push_str(&format!(
            "qbind_execution_parallel_sender_partitions_bucket{{le=\"4\"}} {}\n",
            sp4
        ));
        output.push_str(&format!(
            "qbind_execution_parallel_sender_partitions_bucket{{le=\"16\"}} {}\n",
            sp4 + sp16
        ));
        output.push_str(&format!(
            "qbind_execution_parallel_sender_partitions_bucket{{le=\"64\"}} {}\n",
            sp4 + sp16 + sp64
        ));
        output.push_str(&format!(
            "qbind_execution_parallel_sender_partitions_bucket{{le=\"+Inf\"}} {}\n",
            sp_total
        ));
        output.push_str(&format!(
            "qbind_execution_parallel_sender_partitions_sum {}\n",
            self.sender_partitions_sum()
        ));
        output.push_str(&format!(
            "qbind_execution_parallel_sender_partitions_count {}\n",
            sp_total
        ));

        // Parallel block time histogram
        let (pb1, pb10, pb100, pb_over) = self.parallel_block_buckets();
        let pb_total = pb1 + pb10 + pb100 + pb_over;
        output.push_str(&format!(
            "qbind_execution_block_parallel_seconds_bucket{{le=\"0.001\"}} {}\n",
            pb1
        ));
        output.push_str(&format!(
            "qbind_execution_block_parallel_seconds_bucket{{le=\"0.01\"}} {}\n",
            pb1 + pb10
        ));
        output.push_str(&format!(
            "qbind_execution_block_parallel_seconds_bucket{{le=\"0.1\"}} {}\n",
            pb1 + pb10 + pb100
        ));
        output.push_str(&format!(
            "qbind_execution_block_parallel_seconds_bucket{{le=\"+Inf\"}} {}\n",
            pb_total
        ));
        output.push_str(&format!(
            "qbind_execution_block_parallel_seconds_sum {}\n",
            self.parallel_block_time_ms_sum() as f64 / 1000.0
        ));
        output.push_str(&format!(
            "qbind_execution_block_parallel_seconds_count {}\n",
            pb_total
        ));

        output.push_str(&format!(
            "qbind_execution_parallel_fallback_total {}\n",
            self.parallel_fallback_total()
        ));

        // T187: Stage B parallel execution metrics
        output.push_str("\n# T187: Stage B parallel execution metrics\n");
        output.push_str(&format!(
            "qbind_execution_stage_b_enabled {}\n",
            self.stage_b_enabled()
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_blocks_total{{mode=\"parallel\"}} {}\n",
            self.stage_b_blocks_parallel()
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_blocks_total{{mode=\"fallback\"}} {}\n",
            self.stage_b_blocks_fallback()
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_mismatch_total {}\n",
            self.stage_b_mismatch_total()
        ));

        // Stage B levels histogram
        let (sb4, sb16, sb64, sb_over) = self.stage_b_levels_buckets();
        let sb_total = sb4 + sb16 + sb64 + sb_over;
        output.push_str(&format!(
            "qbind_execution_stage_b_levels_histogram_bucket{{le=\"4\"}} {}\n",
            sb4
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_levels_histogram_bucket{{le=\"16\"}} {}\n",
            sb4 + sb16
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_levels_histogram_bucket{{le=\"64\"}} {}\n",
            sb4 + sb16 + sb64
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_levels_histogram_bucket{{le=\"+Inf\"}} {}\n",
            sb_total
        ));

        // Stage B parallel time histogram
        let (sbt1, sbt10, sbt100, sbt_over) = self.stage_b_parallel_buckets();
        let sbt_total = sbt1 + sbt10 + sbt100 + sbt_over;
        output.push_str(&format!(
            "qbind_execution_stage_b_parallel_seconds_bucket{{le=\"0.001\"}} {}\n",
            sbt1
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_parallel_seconds_bucket{{le=\"0.01\"}} {}\n",
            sbt1 + sbt10
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_parallel_seconds_bucket{{le=\"0.1\"}} {}\n",
            sbt1 + sbt10 + sbt100
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_parallel_seconds_bucket{{le=\"+Inf\"}} {}\n",
            sbt_total
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_parallel_seconds_sum {}\n",
            self.stage_b_parallel_time_ms_sum() as f64 / 1000.0
        ));
        output.push_str(&format!(
            "qbind_execution_stage_b_parallel_seconds_count {}\n",
            sbt_total
        ));

        output
    }
}

/// Reason for execution error (T154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionErrorReason {
    /// Nonce mismatch error.
    NonceMismatch,
    /// Other execution error.
    Other,
}

// ============================================================================
// SignerKeystoreMetrics - Signer and keystore metrics for T154
// ============================================================================

/// Metrics for signer and keystore observability (T154).
///
/// Tracks:
/// - Sign requests by kind (proposal/vote/timeout)
/// - Sign failures
/// - Keystore load success/failure by backend
///
/// # Security Note
///
/// No secrets, key IDs, passphrases, or key material are exposed
/// in these metrics. Only aggregate counts are tracked.
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct SignerKeystoreMetrics {
    /// Sign requests for proposals.
    sign_requests_proposal: AtomicU64,
    /// Sign requests for votes.
    sign_requests_vote: AtomicU64,
    /// Sign requests for timeouts.
    sign_requests_timeout: AtomicU64,
    /// Total sign failures.
    sign_failures_total: AtomicU64,
    /// Keystore load success: PlainFs backend.
    keystore_load_success_plainfs: AtomicU64,
    /// Keystore load success: EncryptedFsV1 backend.
    keystore_load_success_encrypted: AtomicU64,
    /// Keystore load failure: PlainFs backend.
    keystore_load_failure_plainfs: AtomicU64,
    /// Keystore load failure: EncryptedFsV1 backend.
    keystore_load_failure_encrypted: AtomicU64,
}

impl SignerKeystoreMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment sign request counter by kind.
    pub fn inc_sign_request(&self, kind: SignRequestKind) {
        match kind {
            SignRequestKind::Proposal => {
                self.sign_requests_proposal.fetch_add(1, Ordering::Relaxed);
            }
            SignRequestKind::Vote => {
                self.sign_requests_vote.fetch_add(1, Ordering::Relaxed);
            }
            SignRequestKind::Timeout => {
                self.sign_requests_timeout.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get sign request count by kind.
    pub fn sign_requests_by_kind(&self, kind: SignRequestKind) -> u64 {
        match kind {
            SignRequestKind::Proposal => self.sign_requests_proposal.load(Ordering::Relaxed),
            SignRequestKind::Vote => self.sign_requests_vote.load(Ordering::Relaxed),
            SignRequestKind::Timeout => self.sign_requests_timeout.load(Ordering::Relaxed),
        }
    }

    /// Get total sign requests.
    pub fn sign_requests_total(&self) -> u64 {
        self.sign_requests_proposal.load(Ordering::Relaxed)
            + self.sign_requests_vote.load(Ordering::Relaxed)
            + self.sign_requests_timeout.load(Ordering::Relaxed)
    }

    /// Increment sign failure counter.
    pub fn inc_sign_failure(&self) {
        self.sign_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total sign failures.
    pub fn sign_failures_total(&self) -> u64 {
        self.sign_failures_total.load(Ordering::Relaxed)
    }

    /// Record a keystore load success.
    pub fn inc_keystore_load_success(&self, backend: KeystoreBackendKind) {
        match backend {
            KeystoreBackendKind::PlainFs => {
                self.keystore_load_success_plainfs
                    .fetch_add(1, Ordering::Relaxed);
            }
            KeystoreBackendKind::EncryptedFsV1 => {
                self.keystore_load_success_encrypted
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a keystore load failure.
    pub fn inc_keystore_load_failure(&self, backend: KeystoreBackendKind) {
        match backend {
            KeystoreBackendKind::PlainFs => {
                self.keystore_load_failure_plainfs
                    .fetch_add(1, Ordering::Relaxed);
            }
            KeystoreBackendKind::EncryptedFsV1 => {
                self.keystore_load_failure_encrypted
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get keystore load success count by backend.
    pub fn keystore_load_success_by_backend(&self, backend: KeystoreBackendKind) -> u64 {
        match backend {
            KeystoreBackendKind::PlainFs => {
                self.keystore_load_success_plainfs.load(Ordering::Relaxed)
            }
            KeystoreBackendKind::EncryptedFsV1 => {
                self.keystore_load_success_encrypted.load(Ordering::Relaxed)
            }
        }
    }

    /// Get keystore load failure count by backend.
    pub fn keystore_load_failure_by_backend(&self, backend: KeystoreBackendKind) -> u64 {
        match backend {
            KeystoreBackendKind::PlainFs => {
                self.keystore_load_failure_plainfs.load(Ordering::Relaxed)
            }
            KeystoreBackendKind::EncryptedFsV1 => {
                self.keystore_load_failure_encrypted.load(Ordering::Relaxed)
            }
        }
    }

    /// Get total keystore load successes.
    pub fn keystore_load_success_total(&self) -> u64 {
        self.keystore_load_success_plainfs.load(Ordering::Relaxed)
            + self.keystore_load_success_encrypted.load(Ordering::Relaxed)
    }

    /// Get total keystore load failures.
    pub fn keystore_load_failure_total(&self) -> u64 {
        self.keystore_load_failure_plainfs.load(Ordering::Relaxed)
            + self.keystore_load_failure_encrypted.load(Ordering::Relaxed)
    }

    /// Format signer/keystore metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Signer/Keystore metrics (T154)\n");
        output.push_str(&format!(
            "qbind_signer_sign_requests_total{{kind=\"proposal\"}} {}\n",
            self.sign_requests_by_kind(SignRequestKind::Proposal)
        ));
        output.push_str(&format!(
            "qbind_signer_sign_requests_total{{kind=\"vote\"}} {}\n",
            self.sign_requests_by_kind(SignRequestKind::Vote)
        ));
        output.push_str(&format!(
            "qbind_signer_sign_requests_total{{kind=\"timeout\"}} {}\n",
            self.sign_requests_by_kind(SignRequestKind::Timeout)
        ));
        output.push_str(&format!(
            "qbind_signer_sign_failures_total {}\n",
            self.sign_failures_total()
        ));
        output.push_str(&format!(
            "qbind_keystore_load_success_total{{backend=\"PlainFs\"}} {}\n",
            self.keystore_load_success_by_backend(KeystoreBackendKind::PlainFs)
        ));
        output.push_str(&format!(
            "qbind_keystore_load_success_total{{backend=\"EncryptedFsV1\"}} {}\n",
            self.keystore_load_success_by_backend(KeystoreBackendKind::EncryptedFsV1)
        ));
        output.push_str(&format!(
            "qbind_keystore_load_failure_total{{backend=\"PlainFs\"}} {}\n",
            self.keystore_load_failure_by_backend(KeystoreBackendKind::PlainFs)
        ));
        output.push_str(&format!(
            "qbind_keystore_load_failure_total{{backend=\"EncryptedFsV1\"}} {}\n",
            self.keystore_load_failure_by_backend(KeystoreBackendKind::EncryptedFsV1)
        ));
        output
    }
}

/// Kind of sign request (T154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignRequestKind {
    /// Proposal signing.
    Proposal,
    /// Vote signing.
    Vote,
    /// Timeout signing.
    Timeout,
}

/// Keystore backend kind (T154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreBackendKind {
    /// PlainFs backend (unencrypted JSON).
    PlainFs,
    /// EncryptedFsV1 backend (AEAD encrypted).
    EncryptedFsV1,
}

// ============================================================================
// EnvironmentMetrics (T162) - Network environment info metric
// ============================================================================

/// Static metric indicating the network environment.
///
/// This metric exposes the selected network environment (DevNet/TestNet/MainNet)
/// as a gauge with a label, allowing operators to identify which network a node
/// is running on.
///
/// # Prometheus Format
///
/// ```text
/// qbind_build_env{network="devnet"} 1
/// ```
///
/// # Usage (T162)
///
/// ```ignore
/// use qbind_node::metrics::EnvironmentMetrics;
/// use qbind_types::NetworkEnvironment;
///
/// let metrics = EnvironmentMetrics::new(NetworkEnvironment::Testnet);
/// assert_eq!(metrics.network(), "testnet");
/// assert_eq!(metrics.chain_id_hex(), "0x51424e4454535400");
/// ```
#[derive(Debug, Clone)]
pub struct EnvironmentMetrics {
    /// The network environment string (lowercase).
    network: &'static str,
    /// The chain ID as a hex string (for logging/metrics).
    chain_id_hex: String,
    /// The domain scope (DEV/TST/MAIN).
    scope: &'static str,
}

impl EnvironmentMetrics {
    /// Create new environment metrics from a NetworkEnvironment.
    pub fn new(env: qbind_types::NetworkEnvironment) -> Self {
        let network = match env {
            qbind_types::NetworkEnvironment::Devnet => "devnet",
            qbind_types::NetworkEnvironment::Testnet => "testnet",
            qbind_types::NetworkEnvironment::Mainnet => "mainnet",
        };
        let chain_id_hex = format!("0x{:016x}", env.chain_id().as_u64());
        let scope = env.scope();
        Self {
            network,
            chain_id_hex,
            scope,
        }
    }

    /// Create default environment metrics (DevNet).
    pub fn default_devnet() -> Self {
        Self::new(qbind_types::NetworkEnvironment::Devnet)
    }

    /// Get the network string (lowercase).
    pub fn network(&self) -> &'static str {
        self.network
    }

    /// Get the chain ID as a hex string.
    pub fn chain_id_hex(&self) -> &str {
        &self.chain_id_hex
    }

    /// Get the domain scope (DEV/TST/MAIN).
    pub fn scope(&self) -> &'static str {
        self.scope
    }

    /// Format environment metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Environment metrics (T162)\n");
        // Static gauge indicating the environment
        output.push_str(&format!(
            "qbind_build_env{{network=\"{}\"}} 1\n",
            self.network
        ));
        // Chain ID as info metric
        output.push_str(&format!(
            "qbind_chain_id{{network=\"{}\",chain_id=\"{}\",scope=\"{}\"}} 1\n",
            self.network, self.chain_id_hex, self.scope
        ));
        output
    }
}

// ============================================================================
// VerifyPoolMetrics (T154) - Already exists in verify_pool.rs, but we add
// additional centralized access via NodeMetrics
// ============================================================================

// Note: VerifyPoolMetrics is already defined in verify_pool.rs and tracks:
// - qbind_verify_jobs_submitted_total
// - qbind_verify_jobs_dropped_total
// - qbind_verify_jobs_ok_total
// - qbind_verify_jobs_failed_total
// We'll integrate these into the NodeMetrics format_metrics output.

// ============================================================================
// NodeMetrics - Combined metrics container
// ============================================================================

use crate::channel_config::ChannelCapacityConfig;

/// Combined metrics for the async consensus node.
///
/// This struct aggregates all metrics categories and provides a single
/// point of access for observability.
///
/// # Usage
///
/// ```ignore
/// use qbind_node::metrics::NodeMetrics;
/// use qbind_node::channel_config::ChannelCapacityConfig;
/// use std::sync::Arc;
///
/// let metrics = Arc::new(NodeMetrics::new());
///
/// // Network events
/// metrics.network().inc_inbound_vote();
/// metrics.network().inc_outbound_vote_broadcast();
///
/// // Runtime events
/// metrics.runtime().inc_events_tick();
///
/// // Blocking operations
/// metrics.spawn_blocking().record_blocking_duration(duration);
///
/// // Per-peer metrics (T90.4)
/// metrics.peer_network().inc_inbound(PeerId(1), InboundMsgKind::Vote);
///
/// // Consensus round metrics (T90.5)
/// metrics.consensus_round().record_view_duration(Duration::from_millis(50));
///
/// // Connection limit metrics (T105)
/// metrics.connection_limit().inc_inbound_rejected();
///
/// // Storage metrics (T107)
/// metrics.storage().record(StorageOp::PutBlock, Duration::from_micros(500));
///
/// // Commit metrics (T107)
/// metrics.commit().record_commit(Duration::from_millis(5));
///
/// // Consensus progress metrics (T127)
/// metrics.progress().inc_qcs_formed();
/// metrics.progress().inc_votes_observed();
///
/// // Set channel capacity config for metrics export
/// metrics.set_channel_config(ChannelCapacityConfig::default());
///
/// // Environment metrics (T162)
/// metrics.set_environment(qbind_types::NetworkEnvironment::Testnet);
/// ```
// ============================================================================
// P2pMetrics - P2P transport metrics (T172)
// ============================================================================
/// Metrics for P2P transport layer (T172, T205).
///
/// Tracks connection counts, bytes sent/received, and message flow for the
/// P2P transport service. Extended in T205 to include discovery and liveness metrics.
///
/// # Prometheus-style naming
///
/// - `qbind_p2p_connections_current` → `connections_current()`
/// - `qbind_p2p_bytes_sent_total` → `bytes_sent_total()`
/// - `qbind_p2p_bytes_received_total` → `bytes_received_total()`
/// - `qbind_p2p_messages_sent_total{kind="..."}` → `messages_sent_total(kind)`
/// - `qbind_p2p_messages_received_total{kind="..."}` → `messages_received_total(kind)`
///
/// ## T205 Discovery/Liveness Metrics
///
/// - `qbind_p2p_outbound_peers` → `outbound_peers()`
/// - `qbind_p2p_inbound_peers` → `inbound_peers()`
/// - `qbind_p2p_known_peers` → `known_peers()`
/// - `qbind_p2p_discovery_enabled` → `discovery_enabled()` (0/1)
/// - `qbind_p2p_peer_discovered_total` → `peer_discovered_total()`
/// - `qbind_p2p_peer_evicted_total{reason="liveness"}` → `peer_evicted_liveness_total()`
/// - `qbind_p2p_heartbeat_sent_total` → `heartbeat_sent_total()`
/// - `qbind_p2p_heartbeat_failed_total` → `heartbeat_failed_total()`
#[derive(Debug, Default)]
pub struct P2pMetrics {
    connections_current: AtomicU64,
    bytes_sent_total: AtomicU64,
    bytes_received_total: AtomicU64,
    messages_sent_consensus: AtomicU64,
    messages_sent_dag: AtomicU64,
    messages_sent_control: AtomicU64,
    messages_received_consensus: AtomicU64,
    messages_received_dag: AtomicU64,
    messages_received_control: AtomicU64,

    // T205: Discovery and liveness metrics
    /// Current number of outbound peer connections.
    outbound_peers: AtomicU64,
    /// Current number of inbound peer connections.
    inbound_peers: AtomicU64,
    /// Current number of known peers in the peer table.
    known_peers: AtomicU64,
    /// Whether discovery is enabled (0 or 1).
    discovery_enabled: AtomicU64,
    /// Total number of peers discovered via peer exchange.
    peer_discovered_total: AtomicU64,
    /// Total number of peers evicted due to liveness failure.
    peer_evicted_liveness_total: AtomicU64,
    /// Total number of heartbeat Pings sent.
    heartbeat_sent_total: AtomicU64,
    /// Total number of heartbeats that failed (no Pong received).
    heartbeat_failed_total: AtomicU64,

    // T206: Diversity (anti-eclipse) metrics
    /// Current diversity mode (0=Off, 1=Warn, 2=Enforce).
    diversity_mode: AtomicU64,
    /// Current number of distinct outbound buckets.
    diversity_distinct_buckets: AtomicU64,
    /// Current max bucket fraction of outbound peers (basis points).
    diversity_max_bucket_fraction_bps: AtomicU64,
    /// Total peers rejected due to /24 prefix limit.
    peer_rejected_prefix24_total: AtomicU64,
    /// Total peers rejected due to /16 prefix limit.
    peer_rejected_prefix16_total: AtomicU64,
    /// Total peers rejected due to max fraction limit.
    peer_rejected_max_fraction_total: AtomicU64,
    /// Total diversity violations in warn mode.
    diversity_violation_warn_total: AtomicU64,
    /// Total diversity violations in enforce mode.
    diversity_violation_enforce_total: AtomicU64,
}

impl P2pMetrics {
    /// Create a new P2pMetrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get current number of P2P connections.
    pub fn connections_current(&self) -> u64 {
        self.connections_current.load(Ordering::Relaxed)
    }

    /// Set current number of P2P connections.
    pub fn set_connections_current(&self, count: u64) {
        self.connections_current.store(count, Ordering::Relaxed);
    }

    /// Get total bytes sent over P2P.
    pub fn bytes_sent_total(&self) -> u64 {
        self.bytes_sent_total.load(Ordering::Relaxed)
    }

    /// Increment total bytes sent.
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent_total.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total bytes received over P2P.
    pub fn bytes_received_total(&self) -> u64 {
        self.bytes_received_total.load(Ordering::Relaxed)
    }

    /// Increment total bytes received.
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received_total
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment sent message counter for a specific message kind.
    pub fn inc_message_sent(&self, kind: &str) {
        match kind {
            "consensus" => self.messages_sent_consensus.fetch_add(1, Ordering::Relaxed),
            "dag" => self.messages_sent_dag.fetch_add(1, Ordering::Relaxed),
            "control" => self.messages_sent_control.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Get sent message count for a specific kind.
    pub fn messages_sent_total(&self, kind: &str) -> u64 {
        match kind {
            "consensus" => self.messages_sent_consensus.load(Ordering::Relaxed),
            "dag" => self.messages_sent_dag.load(Ordering::Relaxed),
            "control" => self.messages_sent_control.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Increment received message counter for a specific message kind.
    pub fn inc_message_received(&self, kind: &str) {
        match kind {
            "consensus" => self
                .messages_received_consensus
                .fetch_add(1, Ordering::Relaxed),
            "dag" => self.messages_received_dag.fetch_add(1, Ordering::Relaxed),
            "control" => self
                .messages_received_control
                .fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Get received message count for a specific kind.
    pub fn messages_received_total(&self, kind: &str) -> u64 {
        match kind {
            "consensus" => self.messages_received_consensus.load(Ordering::Relaxed),
            "dag" => self.messages_received_dag.load(Ordering::Relaxed),
            "control" => self.messages_received_control.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    // ========================================================================
    // T205: Discovery and Liveness Metrics
    // ========================================================================

    /// Get current number of outbound peer connections.
    pub fn outbound_peers(&self) -> u64 {
        self.outbound_peers.load(Ordering::Relaxed)
    }

    /// Set current number of outbound peer connections.
    pub fn set_outbound_peers(&self, count: u64) {
        self.outbound_peers.store(count, Ordering::Relaxed);
    }

    /// Get current number of inbound peer connections.
    pub fn inbound_peers(&self) -> u64 {
        self.inbound_peers.load(Ordering::Relaxed)
    }

    /// Set current number of inbound peer connections.
    pub fn set_inbound_peers(&self, count: u64) {
        self.inbound_peers.store(count, Ordering::Relaxed);
    }

    /// Get current number of known peers in the peer table.
    pub fn known_peers(&self) -> u64 {
        self.known_peers.load(Ordering::Relaxed)
    }

    /// Set current number of known peers in the peer table.
    pub fn set_known_peers(&self, count: u64) {
        self.known_peers.store(count, Ordering::Relaxed);
    }

    /// Get whether discovery is enabled (0 or 1).
    pub fn discovery_enabled(&self) -> u64 {
        self.discovery_enabled.load(Ordering::Relaxed)
    }

    /// Set whether discovery is enabled.
    pub fn set_discovery_enabled(&self, enabled: bool) {
        self.discovery_enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Get total number of peers discovered via peer exchange.
    pub fn peer_discovered_total(&self) -> u64 {
        self.peer_discovered_total.load(Ordering::Relaxed)
    }

    /// Increment the peer discovered counter.
    pub fn inc_peer_discovered(&self) {
        self.peer_discovered_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total number of peers evicted due to liveness failure.
    pub fn peer_evicted_liveness_total(&self) -> u64 {
        self.peer_evicted_liveness_total.load(Ordering::Relaxed)
    }

    /// Increment the peer evicted (liveness) counter.
    pub fn inc_peer_evicted_liveness(&self) {
        self.peer_evicted_liveness_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total number of heartbeat Pings sent.
    pub fn heartbeat_sent_total(&self) -> u64 {
        self.heartbeat_sent_total.load(Ordering::Relaxed)
    }

    /// Increment the heartbeat sent counter.
    pub fn inc_heartbeat_sent(&self) {
        self.heartbeat_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total number of heartbeats that failed.
    pub fn heartbeat_failed_total(&self) -> u64 {
        self.heartbeat_failed_total.load(Ordering::Relaxed)
    }

    /// Increment the heartbeat failed counter.
    pub fn inc_heartbeat_failed(&self) {
        self.heartbeat_failed_total.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // T206: Diversity (Anti-Eclipse) Metrics
    // ========================================================================

    /// Get current diversity mode (0=Off, 1=Warn, 2=Enforce).
    pub fn diversity_mode(&self) -> u64 {
        self.diversity_mode.load(Ordering::Relaxed)
    }

    /// Set current diversity mode.
    pub fn set_diversity_mode(&self, mode: u64) {
        self.diversity_mode.store(mode, Ordering::Relaxed);
    }

    /// Get current number of distinct outbound buckets.
    pub fn diversity_distinct_buckets(&self) -> u64 {
        self.diversity_distinct_buckets.load(Ordering::Relaxed)
    }

    /// Set current number of distinct outbound buckets.
    pub fn set_diversity_distinct_buckets(&self, count: u64) {
        self.diversity_distinct_buckets
            .store(count, Ordering::Relaxed);
    }

    /// Get current max bucket fraction of outbound peers (basis points).
    pub fn diversity_max_bucket_fraction_bps(&self) -> u64 {
        self.diversity_max_bucket_fraction_bps
            .load(Ordering::Relaxed)
    }

    /// Set current max bucket fraction.
    pub fn set_diversity_max_bucket_fraction_bps(&self, bps: u64) {
        self.diversity_max_bucket_fraction_bps
            .store(bps, Ordering::Relaxed);
    }

    /// Get total peers rejected due to /24 prefix limit.
    pub fn peer_rejected_prefix24_total(&self) -> u64 {
        self.peer_rejected_prefix24_total.load(Ordering::Relaxed)
    }

    /// Increment peers rejected due to /24 prefix limit.
    pub fn inc_peer_rejected_prefix24(&self) {
        self.peer_rejected_prefix24_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total peers rejected due to /16 prefix limit.
    pub fn peer_rejected_prefix16_total(&self) -> u64 {
        self.peer_rejected_prefix16_total.load(Ordering::Relaxed)
    }

    /// Increment peers rejected due to /16 prefix limit.
    pub fn inc_peer_rejected_prefix16(&self) {
        self.peer_rejected_prefix16_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total peers rejected due to max fraction limit.
    pub fn peer_rejected_max_fraction_total(&self) -> u64 {
        self.peer_rejected_max_fraction_total
            .load(Ordering::Relaxed)
    }

    /// Increment peers rejected due to max fraction limit.
    pub fn inc_peer_rejected_max_fraction(&self) {
        self.peer_rejected_max_fraction_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a peer rejection by reason.
    pub fn record_peer_rejected_diversity(&self, reason: &str) {
        match reason {
            "prefix24" => self.inc_peer_rejected_prefix24(),
            "prefix16" => self.inc_peer_rejected_prefix16(),
            "max_fraction" => self.inc_peer_rejected_max_fraction(),
            _ => {}
        }
    }

    /// Get total diversity violations in warn mode.
    pub fn diversity_violation_warn_total(&self) -> u64 {
        self.diversity_violation_warn_total.load(Ordering::Relaxed)
    }

    /// Increment diversity violations in warn mode.
    pub fn inc_diversity_violation_warn(&self) {
        self.diversity_violation_warn_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total diversity violations in enforce mode.
    pub fn diversity_violation_enforce_total(&self) -> u64 {
        self.diversity_violation_enforce_total
            .load(Ordering::Relaxed)
    }

    /// Increment diversity violations in enforce mode.
    pub fn inc_diversity_violation_enforce(&self) {
        self.diversity_violation_enforce_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a diversity violation by mode.
    pub fn record_diversity_violation(&self, mode: &str) {
        match mode {
            "warn" => self.inc_diversity_violation_warn(),
            "enforce" => self.inc_diversity_violation_enforce(),
            _ => {}
        }
    }

    /// Format P2P metrics as Prometheus-compatible output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();

        output.push_str("# P2P transport metrics (T172)\n");
        output.push_str(&format!(
            "qbind_p2p_connections_current {}\n",
            self.connections_current()
        ));
        output.push_str(&format!(
            "qbind_p2p_bytes_sent_total {}\n",
            self.bytes_sent_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_bytes_received_total {}\n",
            self.bytes_received_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_messages_sent_total{{kind=\"consensus\"}} {}\n",
            self.messages_sent_total("consensus")
        ));
        output.push_str(&format!(
            "qbind_p2p_messages_sent_total{{kind=\"dag\"}} {}\n",
            self.messages_sent_total("dag")
        ));
        output.push_str(&format!(
            "qbind_p2p_messages_sent_total{{kind=\"control\"}} {}\n",
            self.messages_sent_total("control")
        ));
        output.push_str(&format!(
            "qbind_p2p_messages_received_total{{kind=\"consensus\"}} {}\n",
            self.messages_received_total("consensus")
        ));
        output.push_str(&format!(
            "qbind_p2p_messages_received_total{{kind=\"dag\"}} {}\n",
            self.messages_received_total("dag")
        ));
        output.push_str(&format!(
            "qbind_p2p_messages_received_total{{kind=\"control\"}} {}\n",
            self.messages_received_total("control")
        ));

        // T205: Discovery and liveness metrics
        output.push_str("\n# P2P discovery metrics (T205)\n");
        output.push_str(&format!(
            "qbind_p2p_outbound_peers {}\n",
            self.outbound_peers()
        ));
        output.push_str(&format!(
            "qbind_p2p_inbound_peers {}\n",
            self.inbound_peers()
        ));
        output.push_str(&format!("qbind_p2p_known_peers {}\n", self.known_peers()));
        output.push_str(&format!(
            "qbind_p2p_discovery_enabled {}\n",
            self.discovery_enabled()
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_discovered_total {}\n",
            self.peer_discovered_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_evicted_total{{reason=\"liveness\"}} {}\n",
            self.peer_evicted_liveness_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_heartbeat_sent_total {}\n",
            self.heartbeat_sent_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_heartbeat_failed_total {}\n",
            self.heartbeat_failed_total()
        ));

        // T206: Diversity metrics
        output.push_str("\n# P2P diversity metrics (T206)\n");
        output.push_str(&format!(
            "qbind_p2p_diversity_mode {}\n",
            self.diversity_mode()
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_distinct_buckets {}\n",
            self.diversity_distinct_buckets()
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_max_bucket_fraction_bps {}\n",
            self.diversity_max_bucket_fraction_bps()
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_rejected_diversity_total{{reason=\"prefix24\"}} {}\n",
            self.peer_rejected_prefix24_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_rejected_diversity_total{{reason=\"prefix16\"}} {}\n",
            self.peer_rejected_prefix16_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_rejected_diversity_total{{reason=\"max_fraction\"}} {}\n",
            self.peer_rejected_max_fraction_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_violation_total{{mode=\"warn\"}} {}\n",
            self.diversity_violation_warn_total()
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_violation_total{{mode=\"enforce\"}} {}\n",
            self.diversity_violation_enforce_total()
        ));

        output
    }
}

// ============================================================================
// MonetaryMetrics - Monetary engine telemetry metrics (T196)
// ============================================================================

/// Metrics for the monetary engine telemetry (shadow mode) (T196).
///
/// Exposes the monetary engine's computed values for observability without
/// affecting actual token balances or supply.
///
/// # Prometheus-style naming
///
/// - `qbind_monetary_phase` → `phase()` (0=Bootstrap, 1=Transition, 2=Mature)
/// - `qbind_monetary_r_target_annual_bps` → `r_target_annual_bps()`
/// - `qbind_monetary_r_inf_annual_bps` → `r_inf_annual_bps()`
/// - `qbind_monetary_fee_coverage_ratio` → `fee_coverage_ratio()`
/// - `qbind_monetary_phase_recommendation` → `phase_recommendation()` (0=Stay, 1=Advance, 2=HoldBack)
/// - `qbind_monetary_smoothed_annual_fee_revenue` → `smoothed_annual_fee_revenue()`
/// - `qbind_monetary_decisions_total` → `decisions_total()`
#[derive(Debug, Default)]
pub struct MonetaryMetrics {
    /// Current phase as an integer (0=Bootstrap, 1=Transition, 2=Mature)
    phase: AtomicU64,

    /// Target annual inflation rate in basis points (1 bps = 0.01%)
    r_target_annual_bps: AtomicU64,

    /// Recommended annual inflation rate in basis points
    r_inf_annual_bps: AtomicU64,

    /// Fee coverage ratio (scaled by 1e6 for precision)
    fee_coverage_ratio_scaled: AtomicU64,

    /// Phase recommendation (0=Stay, 1=Advance, 2=HoldBack)
    phase_recommendation: AtomicU64,

    /// Smoothed annual fee revenue (scaled by 1e6 for precision)
    smoothed_annual_fee_revenue_scaled: AtomicU64,

    /// Total monetary decisions computed
    decisions_total: AtomicU64,

    // ========================================================================
    // T197: Monetary Mode & Seigniorage Metrics
    // ========================================================================
    /// Current monetary mode (0=Off, 1=Shadow, 2=Active)
    mode: AtomicU64,

    /// Total issuance to validators (monotonically increasing counter)
    issuance_validators_total: AtomicU64,

    /// Total issuance to treasury (monotonically increasing counter)
    issuance_treasury_total: AtomicU64,

    /// Total issuance to insurance (monotonically increasing counter)
    issuance_insurance_total: AtomicU64,

    /// Total issuance to community (monotonically increasing counter)
    issuance_community_total: AtomicU64,

    /// Total decisions applied in shadow mode
    decisions_applied_shadow_total: AtomicU64,

    /// Total decisions applied in active mode
    decisions_applied_active_total: AtomicU64,

    // ========================================================================
    // T199: Monetary Epoch State Metrics
    // ========================================================================
    /// Last epoch index where monetary state was updated
    last_epoch_index: AtomicU64,

    /// Total epoch-level monetary decisions computed (T199)
    /// Increments once per epoch when MonetaryMode != Off
    epoch_decisions_total: AtomicU64,

    // ========================================================================
    // T204: Phase Transition Metrics
    // ========================================================================
    /// Stake ratio in basis points (0–10,000)
    stake_ratio_bps: AtomicU64,

    /// Total phase transitions from Bootstrap to Transition
    phase_transitions_bootstrap_to_transition: AtomicU64,

    /// Total phase transitions from Transition to Mature
    phase_transitions_transition_to_mature: AtomicU64,

    /// Fee coverage ratio in basis points (T204)
    fee_coverage_ratio_bps: AtomicU64,
}

impl MonetaryMetrics {
    /// Create a new MonetaryMetrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get current monetary phase as integer.
    pub fn phase(&self) -> u64 {
        self.phase.load(Ordering::Relaxed)
    }

    /// Set current monetary phase.
    pub fn set_phase(&self, phase: u64) {
        self.phase.store(phase, Ordering::Relaxed);
    }

    /// Get target annual inflation rate in basis points.
    pub fn r_target_annual_bps(&self) -> u64 {
        self.r_target_annual_bps.load(Ordering::Relaxed)
    }

    /// Set target annual inflation rate in basis points.
    pub fn set_r_target_annual_bps(&self, bps: u64) {
        self.r_target_annual_bps.store(bps, Ordering::Relaxed);
    }

    /// Get recommended annual inflation rate in basis points.
    pub fn r_inf_annual_bps(&self) -> u64 {
        self.r_inf_annual_bps.load(Ordering::Relaxed)
    }

    /// Set recommended annual inflation rate in basis points.
    pub fn set_r_inf_annual_bps(&self, bps: u64) {
        self.r_inf_annual_bps.store(bps, Ordering::Relaxed);
    }

    /// Get fee coverage ratio (returns scaled value, divide by 1e6 for actual).
    pub fn fee_coverage_ratio_scaled(&self) -> u64 {
        self.fee_coverage_ratio_scaled.load(Ordering::Relaxed)
    }

    /// Set fee coverage ratio (provide actual ratio, will be scaled by 1e6).
    pub fn set_fee_coverage_ratio(&self, ratio: f64) {
        let scaled = (ratio * 1_000_000.0).clamp(0.0, u64::MAX as f64) as u64;
        self.fee_coverage_ratio_scaled
            .store(scaled, Ordering::Relaxed);
    }

    /// Get phase recommendation as integer (0=Stay, 1=Advance, 2=HoldBack).
    pub fn phase_recommendation(&self) -> u64 {
        self.phase_recommendation.load(Ordering::Relaxed)
    }

    /// Set phase recommendation.
    pub fn set_phase_recommendation(&self, recommendation: u64) {
        self.phase_recommendation
            .store(recommendation, Ordering::Relaxed);
    }

    /// Get smoothed annual fee revenue (returns scaled value, divide by 1e6 for actual).
    pub fn smoothed_annual_fee_revenue_scaled(&self) -> u64 {
        self.smoothed_annual_fee_revenue_scaled
            .load(Ordering::Relaxed)
    }

    /// Set smoothed annual fee revenue (provide actual value, will be scaled by 1e6).
    pub fn set_smoothed_annual_fee_revenue(&self, revenue: f64) {
        let scaled = (revenue * 1_000_000.0).clamp(0.0, u64::MAX as f64) as u64;
        self.smoothed_annual_fee_revenue_scaled
            .store(scaled, Ordering::Relaxed);
    }

    /// Get total number of monetary decisions computed.
    pub fn decisions_total(&self) -> u64 {
        self.decisions_total.load(Ordering::Relaxed)
    }

    /// Increment decisions counter.
    pub fn inc_decisions(&self) {
        self.decisions_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a monetary decision and update all relevant gauges.
    ///
    /// This is a convenience method that updates all gauges from a `MonetaryDecision`
    /// and the associated state.
    ///
    /// # Arguments
    ///
    /// * `decision` - The computed monetary decision
    /// * `phase` - The current monetary phase (0=Bootstrap, 1=Transition, 2=Mature)
    /// * `fee_coverage_ratio` - The fee coverage ratio used in the computation
    /// * `smoothed_annual_fee_revenue` - The smoothed annual fee revenue
    pub fn record_decision(
        &self,
        effective_r_target_annual: f64,
        recommended_r_inf_annual: f64,
        phase: u64,
        phase_recommendation: u64,
        fee_coverage_ratio: f64,
        smoothed_annual_fee_revenue: f64,
    ) {
        // Convert rates to basis points (1 bps = 0.01% = 0.0001)
        let r_target_bps =
            (effective_r_target_annual * 10_000.0).clamp(0.0, u64::MAX as f64) as u64;
        let r_inf_bps = (recommended_r_inf_annual * 10_000.0).clamp(0.0, u64::MAX as f64) as u64;

        self.set_phase(phase);
        self.set_r_target_annual_bps(r_target_bps);
        self.set_r_inf_annual_bps(r_inf_bps);
        self.set_fee_coverage_ratio(fee_coverage_ratio);
        self.set_phase_recommendation(phase_recommendation);
        self.set_smoothed_annual_fee_revenue(smoothed_annual_fee_revenue);
        self.inc_decisions();
    }

    // ========================================================================
    // T197: Monetary Mode & Seigniorage Metrics
    // ========================================================================

    /// Get current monetary mode as integer (0=Off, 1=Shadow, 2=Active).
    pub fn mode(&self) -> u64 {
        self.mode.load(Ordering::Relaxed)
    }

    /// Set current monetary mode.
    pub fn set_mode(&self, mode: u64) {
        self.mode.store(mode, Ordering::Relaxed);
    }

    /// Get total issuance to validators.
    pub fn issuance_validators_total(&self) -> u64 {
        self.issuance_validators_total.load(Ordering::Relaxed)
    }

    /// Add issuance to validators counter.
    pub fn add_issuance_validators(&self, amount: u64) {
        self.issuance_validators_total
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Get total issuance to treasury.
    pub fn issuance_treasury_total(&self) -> u64 {
        self.issuance_treasury_total.load(Ordering::Relaxed)
    }

    /// Add issuance to treasury counter.
    pub fn add_issuance_treasury(&self, amount: u64) {
        self.issuance_treasury_total
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Get total issuance to insurance.
    pub fn issuance_insurance_total(&self) -> u64 {
        self.issuance_insurance_total.load(Ordering::Relaxed)
    }

    /// Add issuance to insurance counter.
    pub fn add_issuance_insurance(&self, amount: u64) {
        self.issuance_insurance_total
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Get total issuance to community.
    pub fn issuance_community_total(&self) -> u64 {
        self.issuance_community_total.load(Ordering::Relaxed)
    }

    /// Add issuance to community counter.
    pub fn add_issuance_community(&self, amount: u64) {
        self.issuance_community_total
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Get total decisions applied in shadow mode.
    pub fn decisions_applied_shadow_total(&self) -> u64 {
        self.decisions_applied_shadow_total.load(Ordering::Relaxed)
    }

    /// Increment shadow mode decisions counter.
    pub fn inc_decisions_applied_shadow(&self) {
        self.decisions_applied_shadow_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total decisions applied in active mode.
    pub fn decisions_applied_active_total(&self) -> u64 {
        self.decisions_applied_active_total.load(Ordering::Relaxed)
    }

    /// Increment active mode decisions counter.
    pub fn inc_decisions_applied_active(&self) {
        self.decisions_applied_active_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record seigniorage issuance (T197).
    ///
    /// Call this after computing seigniorage split to update issuance counters.
    /// Amounts are in the smallest token unit (e.g., wei).
    ///
    /// # Arguments
    ///
    /// * `to_validators` - Amount issued to validator pool
    /// * `to_treasury` - Amount issued to treasury
    /// * `to_insurance` - Amount issued to insurance fund
    /// * `to_community` - Amount issued to community programs
    pub fn record_seigniorage_issuance(
        &self,
        to_validators: u64,
        to_treasury: u64,
        to_insurance: u64,
        to_community: u64,
    ) {
        self.add_issuance_validators(to_validators);
        self.add_issuance_treasury(to_treasury);
        self.add_issuance_insurance(to_insurance);
        self.add_issuance_community(to_community);
    }

    // ========================================================================
    // T199: Monetary Epoch State Metrics
    // ========================================================================

    /// Get last epoch index where monetary state was updated.
    pub fn last_epoch_index(&self) -> u64 {
        self.last_epoch_index.load(Ordering::Relaxed)
    }

    /// Set last epoch index.
    pub fn set_last_epoch_index(&self, epoch: u64) {
        self.last_epoch_index.store(epoch, Ordering::Relaxed);
    }

    /// Get total epoch-level monetary decisions computed (T199).
    pub fn epoch_decisions_total(&self) -> u64 {
        self.epoch_decisions_total.load(Ordering::Relaxed)
    }

    /// Increment epoch-level decisions counter (T199).
    pub fn inc_epoch_decisions(&self) {
        self.epoch_decisions_total.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // T204: Phase Transition Metrics
    // ========================================================================

    /// Get stake ratio in basis points.
    pub fn stake_ratio_bps(&self) -> u64 {
        self.stake_ratio_bps.load(Ordering::Relaxed)
    }

    /// Set stake ratio in basis points.
    pub fn set_stake_ratio_bps(&self, bps: u64) {
        self.stake_ratio_bps.store(bps, Ordering::Relaxed);
    }

    /// Get fee coverage ratio in basis points (T204).
    pub fn fee_coverage_ratio_bps(&self) -> u64 {
        self.fee_coverage_ratio_bps.load(Ordering::Relaxed)
    }

    /// Set fee coverage ratio in basis points (T204).
    pub fn set_fee_coverage_ratio_bps(&self, bps: u64) {
        self.fee_coverage_ratio_bps.store(bps, Ordering::Relaxed);
    }

    /// Get total Bootstrap → Transition phase transitions.
    pub fn phase_transitions_bootstrap_to_transition(&self) -> u64 {
        self.phase_transitions_bootstrap_to_transition
            .load(Ordering::Relaxed)
    }

    /// Increment Bootstrap → Transition phase transition counter.
    pub fn inc_phase_transitions_bootstrap_to_transition(&self) {
        self.phase_transitions_bootstrap_to_transition
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get total Transition → Mature phase transitions.
    pub fn phase_transitions_transition_to_mature(&self) -> u64 {
        self.phase_transitions_transition_to_mature
            .load(Ordering::Relaxed)
    }

    /// Increment Transition → Mature phase transition counter.
    pub fn inc_phase_transitions_transition_to_mature(&self) {
        self.phase_transitions_transition_to_mature
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a phase transition (T204).
    ///
    /// Call this when a phase transition is applied. Updates the transition counters.
    ///
    /// # Arguments
    ///
    /// * `from_phase` - The phase before transition (0=Bootstrap, 1=Transition, 2=Mature)
    /// * `to_phase` - The phase after transition
    pub fn record_phase_transition(&self, from_phase: u64, to_phase: u64) {
        match (from_phase, to_phase) {
            (0, 1) => self.inc_phase_transitions_bootstrap_to_transition(),
            (1, 2) => self.inc_phase_transitions_transition_to_mature(),
            _ => {} // Invalid or no-op transition
        }
    }

    /// Record an epoch-level monetary decision (T199, T204 updated).
    ///
    /// Call this when updating MonetaryEpochState at an epoch boundary.
    /// Updates the last epoch index, relevant gauges, and increments the
    /// appropriate mode-specific counter (shadow or active).
    ///
    /// # Arguments
    ///
    /// * `epoch_index` - The epoch index being updated
    /// * `r_target_bps` - Target annual inflation rate in basis points
    /// * `r_inf_bps` - Recommended annual inflation rate in basis points
    /// * `phase` - Current monetary phase (0=Bootstrap, 1=Transition, 2=Mature)
    /// * `fee_coverage_ratio` - Fee coverage ratio (f64)
    /// * `mode` - Current monetary mode (1=Shadow, 2=Active)
    /// * `stake_ratio_bps` - Stake ratio in basis points (T204)
    /// * `fee_coverage_ratio_bps` - Fee coverage ratio in basis points (T204)
    /// * `phase_prev` - Previous phase (T204, for transition tracking)
    /// * `phase_transition_applied` - Whether a phase transition occurred (T204)
    #[allow(clippy::too_many_arguments)]
    pub fn record_epoch_decision_t204(
        &self,
        epoch_index: u64,
        r_target_bps: u64,
        r_inf_bps: u64,
        phase: u64,
        fee_coverage_ratio: f64,
        mode: u64,
        stake_ratio_bps_val: u64,
        fee_coverage_ratio_bps_val: u64,
        phase_prev: u64,
        phase_transition_applied: bool,
    ) {
        self.set_last_epoch_index(epoch_index);
        self.set_r_target_annual_bps(r_target_bps);
        self.set_r_inf_annual_bps(r_inf_bps);
        self.set_phase(phase);
        self.set_fee_coverage_ratio(fee_coverage_ratio);
        self.set_stake_ratio_bps(stake_ratio_bps_val);
        self.set_fee_coverage_ratio_bps(fee_coverage_ratio_bps_val);
        self.inc_epoch_decisions();

        // Increment mode-specific counter
        match mode {
            1 => self.inc_decisions_applied_shadow(),
            2 => self.inc_decisions_applied_active(),
            _ => {} // Off mode (0) doesn't record
        }

        // Record phase transition if one occurred (T204)
        if phase_transition_applied {
            self.record_phase_transition(phase_prev, phase);
        }
    }

    /// Record an epoch-level monetary decision (T199).
    ///
    /// Call this when updating MonetaryEpochState at an epoch boundary.
    /// Updates the last epoch index, relevant gauges, and increments the
    /// appropriate mode-specific counter (shadow or active).
    ///
    /// # Arguments
    ///
    /// * `epoch_index` - The epoch index being updated
    /// * `r_target_bps` - Target annual inflation rate in basis points
    /// * `r_inf_bps` - Recommended annual inflation rate in basis points
    /// * `phase` - Current monetary phase (0=Bootstrap, 1=Transition, 2=Mature)
    /// * `fee_coverage_ratio` - Fee coverage ratio
    /// * `mode` - Current monetary mode (1=Shadow, 2=Active)
    pub fn record_epoch_decision(
        &self,
        epoch_index: u64,
        r_target_bps: u64,
        r_inf_bps: u64,
        phase: u64,
        fee_coverage_ratio: f64,
        mode: u64,
    ) {
        self.set_last_epoch_index(epoch_index);
        self.set_r_target_annual_bps(r_target_bps);
        self.set_r_inf_annual_bps(r_inf_bps);
        self.set_phase(phase);
        self.set_fee_coverage_ratio(fee_coverage_ratio);
        self.inc_epoch_decisions();

        // Increment mode-specific counter
        match mode {
            1 => self.inc_decisions_applied_shadow(),
            2 => self.inc_decisions_applied_active(),
            _ => {} // Off mode (0) doesn't record
        }
    }

    /// Format metrics as Prometheus exposition format.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# T196: Monetary engine telemetry metrics (shadow mode)\n");

        output.push_str(&format!("qbind_monetary_phase {}\n", self.phase()));
        output.push_str(&format!(
            "qbind_monetary_r_target_annual_bps {}\n",
            self.r_target_annual_bps()
        ));
        output.push_str(&format!(
            "qbind_monetary_r_inf_annual_bps {}\n",
            self.r_inf_annual_bps()
        ));
        output.push_str(&format!(
            "qbind_monetary_fee_coverage_ratio_scaled {}\n",
            self.fee_coverage_ratio_scaled()
        ));
        output.push_str(&format!(
            "qbind_monetary_phase_recommendation {}\n",
            self.phase_recommendation()
        ));
        output.push_str(&format!(
            "qbind_monetary_smoothed_annual_fee_revenue_scaled {}\n",
            self.smoothed_annual_fee_revenue_scaled()
        ));
        output.push_str(&format!(
            "qbind_monetary_decisions_total {}\n",
            self.decisions_total()
        ));

        // T197: Monetary mode and seigniorage metrics
        output.push_str("\n# T197: Monetary mode and seigniorage metrics\n");
        output.push_str(&format!("qbind_monetary_mode {}\n", self.mode()));
        output.push_str(&format!(
            "qbind_monetary_issuance_total{{bucket=\"validators\"}} {}\n",
            self.issuance_validators_total()
        ));
        output.push_str(&format!(
            "qbind_monetary_issuance_total{{bucket=\"treasury\"}} {}\n",
            self.issuance_treasury_total()
        ));
        output.push_str(&format!(
            "qbind_monetary_issuance_total{{bucket=\"insurance\"}} {}\n",
            self.issuance_insurance_total()
        ));
        output.push_str(&format!(
            "qbind_monetary_issuance_total{{bucket=\"community\"}} {}\n",
            self.issuance_community_total()
        ));
        output.push_str(&format!(
            "qbind_monetary_decisions_applied_total{{mode=\"shadow\"}} {}\n",
            self.decisions_applied_shadow_total()
        ));
        output.push_str(&format!(
            "qbind_monetary_decisions_applied_total{{mode=\"active\"}} {}\n",
            self.decisions_applied_active_total()
        ));

        // T199: Epoch-level monetary state metrics
        output.push_str("\n# T199: Epoch-level monetary state metrics\n");
        output.push_str(&format!(
            "qbind_monetary_epoch_last_index {}\n",
            self.last_epoch_index()
        ));
        output.push_str(&format!(
            "qbind_monetary_epoch_decisions_total {}\n",
            self.epoch_decisions_total()
        ));

        // T204: Phase transition metrics
        output.push_str("\n# T204: Phase transition metrics\n");
        output.push_str(&format!(
            "qbind_monetary_stake_ratio_bps {}\n",
            self.stake_ratio_bps()
        ));
        output.push_str(&format!(
            "qbind_monetary_fee_coverage_ratio_bps {}\n",
            self.fee_coverage_ratio_bps()
        ));
        output.push_str(&format!(
            "qbind_monetary_phase_transitions_total{{from=\"Bootstrap\",to=\"Transition\"}} {}\n",
            self.phase_transitions_bootstrap_to_transition()
        ));
        output.push_str(&format!(
            "qbind_monetary_phase_transitions_total{{from=\"Transition\",to=\"Mature\"}} {}\n",
            self.phase_transitions_transition_to_mature()
        ));

        output
    }
}

// ============================================================================
// DagCouplingMetrics - DAG coupling validation metrics (T191)
// ============================================================================

/// Metrics for DAG coupling validation on the validator side (T191, T192).
///
/// Tracks validation outcomes by mode and result type, as well as rejections
/// when in Enforce mode. Also tracks block-level invariant checks (T192).
///
/// # Prometheus-style naming
///
/// ## Proposal Validation (T191)
/// - `qbind_dag_coupling_validation_total{mode="...", result="..."}` → `validation_total(mode, result)`
/// - `qbind_dag_coupling_rejected_total{reason="..."}` → `rejected_total(reason)`
///
/// ## Block-Level Invariant Checks (T192)
/// - `qbind_dag_coupling_block_check_total{mode="...", result="..."}` → `block_check_total(result)`
/// - `qbind_dag_coupling_block_mismatch_total` → `block_mismatch_total()`
/// - `qbind_dag_coupling_block_missing_total` → `block_missing_total()`
#[derive(Debug, Default)]
pub struct DagCouplingMetrics {
    // Validation totals by result (all modes)
    validation_ok: AtomicU64,
    validation_not_required: AtomicU64,
    validation_uncoupled_missing: AtomicU64,
    validation_uncoupled_mismatch: AtomicU64,
    validation_unknown_batches: AtomicU64,
    validation_internal_error: AtomicU64,

    // Rejection totals by reason (Enforce mode only)
    rejected_uncoupled_missing: AtomicU64,
    rejected_uncoupled_mismatch: AtomicU64,
    rejected_unknown_batches: AtomicU64,
    rejected_internal_error: AtomicU64,

    // T192: Block-level invariant check totals
    block_check_not_checked: AtomicU64,
    block_check_ok: AtomicU64,
    block_check_missing: AtomicU64,
    block_check_mismatch: AtomicU64,
    block_check_internal_error: AtomicU64,
}

impl DagCouplingMetrics {
    /// Create a new DagCouplingMetrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get validation count for a specific result.
    pub fn validation_total(&self, result: &str) -> u64 {
        match result {
            "ok" => self.validation_ok.load(Ordering::Relaxed),
            "not_required" => self.validation_not_required.load(Ordering::Relaxed),
            "uncoupled_missing" => self.validation_uncoupled_missing.load(Ordering::Relaxed),
            "uncoupled_mismatch" => self.validation_uncoupled_mismatch.load(Ordering::Relaxed),
            "unknown_batches" => self.validation_unknown_batches.load(Ordering::Relaxed),
            "internal_error" => self.validation_internal_error.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Get rejection count for a specific reason.
    pub fn rejected_total(&self, reason: &str) -> u64 {
        match reason {
            "uncoupled_missing" => self.rejected_uncoupled_missing.load(Ordering::Relaxed),
            "uncoupled_mismatch" => self.rejected_uncoupled_mismatch.load(Ordering::Relaxed),
            "unknown_batches" => self.rejected_unknown_batches.load(Ordering::Relaxed),
            "internal_error" => self.rejected_internal_error.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Get block-level invariant check count for a specific result (T192).
    pub fn block_check_total(&self, result: &str) -> u64 {
        match result {
            "not_checked" => self.block_check_not_checked.load(Ordering::Relaxed),
            "ok" => self.block_check_ok.load(Ordering::Relaxed),
            "missing" => self.block_check_missing.load(Ordering::Relaxed),
            "mismatch" => self.block_check_mismatch.load(Ordering::Relaxed),
            "internal_error" => self.block_check_internal_error.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Get total count of block-level mismatch violations (T192).
    pub fn block_mismatch_total(&self) -> u64 {
        self.block_check_mismatch.load(Ordering::Relaxed)
    }

    /// Get total count of block-level missing commitment violations (T192).
    pub fn block_missing_total(&self) -> u64 {
        self.block_check_missing.load(Ordering::Relaxed)
    }

    /// Record a validation result.
    pub fn record_validation(&self, result: &str) {
        match result {
            "ok" => {
                self.validation_ok.fetch_add(1, Ordering::Relaxed);
            }
            "not_required" => {
                self.validation_not_required.fetch_add(1, Ordering::Relaxed);
            }
            "uncoupled_missing" => {
                self.validation_uncoupled_missing
                    .fetch_add(1, Ordering::Relaxed);
            }
            "uncoupled_mismatch" => {
                self.validation_uncoupled_mismatch
                    .fetch_add(1, Ordering::Relaxed);
            }
            "unknown_batches" => {
                self.validation_unknown_batches
                    .fetch_add(1, Ordering::Relaxed);
            }
            "internal_error" => {
                self.validation_internal_error
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a rejection (Enforce mode only).
    pub fn record_rejection(&self, reason: &str) {
        match reason {
            "uncoupled_missing" => {
                self.rejected_uncoupled_missing
                    .fetch_add(1, Ordering::Relaxed);
            }
            "uncoupled_mismatch" => {
                self.rejected_uncoupled_mismatch
                    .fetch_add(1, Ordering::Relaxed);
            }
            "unknown_batches" => {
                self.rejected_unknown_batches
                    .fetch_add(1, Ordering::Relaxed);
            }
            "internal_error" => {
                self.rejected_internal_error.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a block-level invariant check result (T192).
    pub fn record_block_check(&self, result: &str) {
        match result {
            "not_checked" => {
                self.block_check_not_checked.fetch_add(1, Ordering::Relaxed);
            }
            "ok" => {
                self.block_check_ok.fetch_add(1, Ordering::Relaxed);
            }
            "missing" => {
                self.block_check_missing.fetch_add(1, Ordering::Relaxed);
            }
            "mismatch" => {
                self.block_check_mismatch.fetch_add(1, Ordering::Relaxed);
            }
            "internal_error" => {
                self.block_check_internal_error
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Format metrics for Prometheus export.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("# DAG coupling validation metrics (T191)\n");

        // Validation totals
        output.push_str(&format!(
            "qbind_dag_coupling_validation_total{{result=\"ok\"}} {}\n",
            self.validation_ok.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_validation_total{{result=\"not_required\"}} {}\n",
            self.validation_not_required.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_validation_total{{result=\"uncoupled_missing\"}} {}\n",
            self.validation_uncoupled_missing.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_validation_total{{result=\"uncoupled_mismatch\"}} {}\n",
            self.validation_uncoupled_mismatch.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_validation_total{{result=\"unknown_batches\"}} {}\n",
            self.validation_unknown_batches.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_validation_total{{result=\"internal_error\"}} {}\n",
            self.validation_internal_error.load(Ordering::Relaxed)
        ));

        // Rejection totals
        output.push_str(&format!(
            "qbind_dag_coupling_rejected_total{{reason=\"uncoupled_missing\"}} {}\n",
            self.rejected_uncoupled_missing.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_rejected_total{{reason=\"uncoupled_mismatch\"}} {}\n",
            self.rejected_uncoupled_mismatch.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_rejected_total{{reason=\"unknown_batches\"}} {}\n",
            self.rejected_unknown_batches.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_rejected_total{{reason=\"internal_error\"}} {}\n",
            self.rejected_internal_error.load(Ordering::Relaxed)
        ));

        // T192: Block-level invariant check totals
        output.push_str("\n# T192: Block-level DAG coupling invariant check metrics\n");
        output.push_str(&format!(
            "qbind_dag_coupling_block_check_total{{result=\"not_checked\"}} {}\n",
            self.block_check_not_checked.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_block_check_total{{result=\"ok\"}} {}\n",
            self.block_check_ok.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_block_check_total{{result=\"missing\"}} {}\n",
            self.block_check_missing.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_block_check_total{{result=\"mismatch\"}} {}\n",
            self.block_check_mismatch.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_block_check_total{{result=\"internal_error\"}} {}\n",
            self.block_check_internal_error.load(Ordering::Relaxed)
        ));

        // T192: Convenience counters for violations
        output.push_str(&format!(
            "qbind_dag_coupling_block_mismatch_total {}\n",
            self.block_check_mismatch.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "qbind_dag_coupling_block_missing_total {}\n",
            self.block_check_missing.load(Ordering::Relaxed)
        ));

        output
    }
}

#[derive(Debug)]
pub struct NodeMetrics {
    network: NetworkMetrics,
    runtime: RuntimeMetrics,
    spawn_blocking: SpawnBlockingMetrics,
    /// Per-peer network metrics (T90.4).
    peer_network: PeerNetworkMetrics,
    /// Consensus round/view duration metrics (T90.5).
    consensus_round: ConsensusRoundMetrics,
    /// Connection limit rejection metrics (T105).
    connection_limit: ConnectionLimitMetrics,
    /// Storage operation latency metrics (T107).
    storage: StorageMetrics,
    /// Commit latency metrics (T107).
    commit: CommitMetrics,
    /// Suite transition metrics (T124).
    suite_transition: SuiteTransitionMetrics,
    /// Consensus progress metrics (T127).
    progress: ConsensusProgressMetrics,
    /// Per-validator vote metrics (T128).
    validator_votes: ValidatorVoteMetrics,
    /// View lag gauge metrics (T128).
    view_lag: ViewLagMetrics,
    /// Per-validator equivocation metrics (T129).
    validator_equivocations: ValidatorEquivocationMetrics,
    /// KEM operation metrics (T137).
    kem_metrics: Arc<KemOpMetrics>,
    /// Configured channel capacities (for metrics export).
    channel_config: std::sync::RwLock<Option<ChannelCapacityConfig>>,
    /// Consensus T154 metrics (proposals, votes, timeouts, view).
    consensus_t154: ConsensusT154Metrics,
    /// Mempool metrics (T154).
    mempool: MempoolMetrics,
    /// Execution metrics (T154).
    execution: ExecutionMetrics,
    /// Signer/Keystore metrics (T154).
    signer_keystore: SignerKeystoreMetrics,
    /// Environment metrics (T162).
    environment: std::sync::RwLock<Option<EnvironmentMetrics>>,
    /// P2P transport metrics (T172).
    p2p: P2pMetrics,
    /// DAG coupling validation metrics (T191).
    dag_coupling: DagCouplingMetrics,
    /// Monetary engine telemetry metrics (T196).
    monetary: MonetaryMetrics,
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        NodeMetrics {
            network: NetworkMetrics::default(),
            runtime: RuntimeMetrics::default(),
            spawn_blocking: SpawnBlockingMetrics::default(),
            peer_network: PeerNetworkMetrics::new(),
            consensus_round: ConsensusRoundMetrics::new(),
            connection_limit: ConnectionLimitMetrics::new(),
            storage: StorageMetrics::new(),
            commit: CommitMetrics::new(),
            suite_transition: SuiteTransitionMetrics::new(),
            progress: ConsensusProgressMetrics::new(),
            validator_votes: ValidatorVoteMetrics::new(),
            view_lag: ViewLagMetrics::new(),
            validator_equivocations: ValidatorEquivocationMetrics::new(),
            kem_metrics: Arc::new(KemOpMetrics::new()),
            channel_config: std::sync::RwLock::new(None),
            consensus_t154: ConsensusT154Metrics::new(),
            mempool: MempoolMetrics::new(),
            execution: ExecutionMetrics::new(),
            signer_keystore: SignerKeystoreMetrics::new(),
            environment: std::sync::RwLock::new(None),
            p2p: P2pMetrics::new(),
            dag_coupling: DagCouplingMetrics::new(),
            monetary: MonetaryMetrics::new(),
        }
    }

    /// Get network metrics.
    pub fn network(&self) -> &NetworkMetrics {
        &self.network
    }

    /// Get runtime metrics.
    pub fn runtime(&self) -> &RuntimeMetrics {
        &self.runtime
    }

    /// Get spawn_blocking metrics.
    pub fn spawn_blocking(&self) -> &SpawnBlockingMetrics {
        &self.spawn_blocking
    }

    /// Get per-peer network metrics (T90.4).
    pub fn peer_network(&self) -> &PeerNetworkMetrics {
        &self.peer_network
    }

    /// Get consensus round/view duration metrics (T90.5).
    pub fn consensus_round(&self) -> &ConsensusRoundMetrics {
        &self.consensus_round
    }

    /// Get connection limit rejection metrics (T105).
    pub fn connection_limit(&self) -> &ConnectionLimitMetrics {
        &self.connection_limit
    }

    /// Get storage operation latency metrics (T107).
    pub fn storage(&self) -> &StorageMetrics {
        &self.storage
    }

    /// Get commit latency metrics (T107).
    pub fn commit(&self) -> &CommitMetrics {
        &self.commit
    }

    /// Get suite transition metrics (T124).
    pub fn suite_transition(&self) -> &SuiteTransitionMetrics {
        &self.suite_transition
    }

    /// Get consensus progress metrics (T127).
    pub fn progress(&self) -> &ConsensusProgressMetrics {
        &self.progress
    }

    /// Get per-validator vote metrics (T128).
    pub fn validator_votes(&self) -> &ValidatorVoteMetrics {
        &self.validator_votes
    }

    /// Get view lag metrics (T128).
    pub fn view_lag(&self) -> &ViewLagMetrics {
        &self.view_lag
    }

    /// Get per-validator equivocation metrics (T129).
    pub fn validator_equivocations(&self) -> &ValidatorEquivocationMetrics {
        &self.validator_equivocations
    }

    /// Get KEM operation metrics (T137).
    pub fn kem_metrics(&self) -> Arc<KemOpMetrics> {
        Arc::clone(&self.kem_metrics)
    }

    /// Get consensus T154 metrics (proposals, votes, timeouts, view).
    pub fn consensus_t154(&self) -> &ConsensusT154Metrics {
        &self.consensus_t154
    }

    /// Get mempool metrics (T154).
    pub fn mempool(&self) -> &MempoolMetrics {
        &self.mempool
    }

    /// Get execution metrics (T154).
    pub fn execution(&self) -> &ExecutionMetrics {
        &self.execution
    }

    /// Get signer/keystore metrics (T154).
    pub fn signer_keystore(&self) -> &SignerKeystoreMetrics {
        &self.signer_keystore
    }

    /// Get P2P transport metrics (T172).
    pub fn p2p(&self) -> &P2pMetrics {
        &self.p2p
    }

    /// Get DAG coupling validation metrics (T191).
    pub fn dag_coupling(&self) -> &DagCouplingMetrics {
        &self.dag_coupling
    }

    /// Get monetary engine telemetry metrics (T196).
    pub fn monetary(&self) -> &MonetaryMetrics {
        &self.monetary
    }

    /// Record a DAG coupling validation result (T191).
    ///
    /// This method records both the validation outcome and, if in Enforce mode,
    /// the rejection reason.
    ///
    /// # Arguments
    ///
    /// * `result` - The validation result from `validate_dag_coupling_for_proposal()`
    /// * `mode` - The current DAG coupling mode
    pub fn record_dag_coupling_validation(
        &self,
        result: &crate::hotstuff_node_sim::DagCouplingValidationResult,
        mode: &crate::node_config::DagCouplingMode,
    ) {
        use crate::hotstuff_node_sim::DagCouplingValidationResult;
        use crate::node_config::DagCouplingMode;

        // Record validation result
        let result_str = match result {
            DagCouplingValidationResult::Ok => "ok",
            DagCouplingValidationResult::NotRequired => "not_required",
            DagCouplingValidationResult::UncoupledMissing => "uncoupled_missing",
            DagCouplingValidationResult::UncoupledMismatch => "uncoupled_mismatch",
            DagCouplingValidationResult::UnknownBatches => "unknown_batches",
            DagCouplingValidationResult::InternalError(_) => "internal_error",
        };
        self.dag_coupling.record_validation(result_str);

        // In Enforce mode, also record rejection if validation failed
        if *mode == DagCouplingMode::Enforce {
            match result {
                DagCouplingValidationResult::UncoupledMissing => {
                    self.dag_coupling.record_rejection("uncoupled_missing");
                }
                DagCouplingValidationResult::UncoupledMismatch => {
                    self.dag_coupling.record_rejection("uncoupled_mismatch");
                }
                DagCouplingValidationResult::UnknownBatches => {
                    self.dag_coupling.record_rejection("unknown_batches");
                }
                DagCouplingValidationResult::InternalError(_) => {
                    self.dag_coupling.record_rejection("internal_error");
                }
                DagCouplingValidationResult::Ok | DagCouplingValidationResult::NotRequired => {
                    // No rejection
                }
            }
        }
    }

    /// Record a DAG coupling block-level invariant check result (T192).
    ///
    /// This method records the outcome of the post-commit block-level invariant
    /// check that verifies committed blocks have valid batch_commitment fields.
    ///
    /// # Arguments
    ///
    /// * `result` - The check result from `check_dag_coupling_invariant_for_committed_block()`
    /// * `mode` - The current DAG coupling mode
    pub fn record_dag_coupling_block_check(
        &self,
        result: &crate::hotstuff_node_sim::DagCouplingBlockCheckResult,
        #[allow(unused_variables)] mode: &crate::node_config::DagCouplingMode,
    ) {
        use crate::hotstuff_node_sim::DagCouplingBlockCheckResult;

        // Record block check result
        let result_str = match result {
            DagCouplingBlockCheckResult::NotChecked => "not_checked",
            DagCouplingBlockCheckResult::Ok => "ok",
            DagCouplingBlockCheckResult::MissingCommitment => "missing",
            DagCouplingBlockCheckResult::Mismatch => "mismatch",
            DagCouplingBlockCheckResult::InternalError(_) => "internal_error",
        };
        self.dag_coupling.record_block_check(result_str);
        // Note: `mode` is reserved for future use (e.g., mode-specific metrics labels)
    }

    /// Set the network environment for metrics export (T162).
    ///
    /// Call this during node initialization to record the selected
    /// environment in the metrics output.
    pub fn set_environment(&self, env: qbind_types::NetworkEnvironment) {
        if let Ok(mut guard) = self.environment.write() {
            *guard = Some(EnvironmentMetrics::new(env));
        }
    }

    /// Get the environment metrics (if set).
    pub fn environment(&self) -> Option<EnvironmentMetrics> {
        self.environment.read().ok().and_then(|g| g.clone())
    }

    /// Set the channel capacity configuration for metrics export.
    ///
    /// Call this during node initialization to record the effective
    /// channel capacities in the metrics output.
    pub fn set_channel_config(&self, config: ChannelCapacityConfig) {
        if let Ok(mut guard) = self.channel_config.write() {
            *guard = Some(config);
        }
    }

    /// Get the channel capacity configuration (if set).
    pub fn channel_config(&self) -> Option<ChannelCapacityConfig> {
        self.channel_config.read().ok().and_then(|g| g.clone())
    }

    /// Format metrics as a string for logging or HTTP endpoint.
    ///
    /// The output follows a Prometheus-compatible format where possible.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();

        // Network metrics
        output.push_str("# Network metrics\n");
        output.push_str(&format!(
            "consensus_net_inbound_total{{kind=\"vote\"}} {}\n",
            self.network.inbound_vote_total()
        ));
        output.push_str(&format!(
            "consensus_net_inbound_total{{kind=\"proposal\"}} {}\n",
            self.network.inbound_proposal_total()
        ));
        output.push_str(&format!(
            "consensus_net_inbound_total{{kind=\"other\"}} {}\n",
            self.network.inbound_other_total()
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"vote_send_to\"}} {}\n",
            self.network.outbound_vote_send_to_total()
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"vote_broadcast\"}} {}\n",
            self.network.outbound_vote_broadcast_total()
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"proposal_broadcast\"}} {}\n",
            self.network.outbound_proposal_broadcast_total()
        ));
        output.push_str(&format!(
            "consensus_net_outbound_dropped_total {}\n",
            self.network.outbound_dropped_total()
        ));
        output.push_str(&format!(
            "consensus_net_inbound_channel_closed_total {}\n",
            self.network.inbound_channel_closed_total()
        ));
        output.push_str(&format!(
            "consensus_net_outbound_queue_depth {}\n",
            self.network.outbound_queue_depth()
        ));

        // Runtime metrics
        output.push_str("\n# Runtime metrics\n");
        output.push_str(&format!(
            "consensus_events_total{{kind=\"tick\"}} {}\n",
            self.runtime.events_tick_total()
        ));
        output.push_str(&format!(
            "consensus_events_total{{kind=\"incoming_message\"}} {}\n",
            self.runtime.events_incoming_message_total()
        ));
        output.push_str(&format!(
            "consensus_events_total{{kind=\"shutdown\"}} {}\n",
            self.runtime.events_shutdown_total()
        ));
        output.push_str(&format!(
            "consensus_runtime_ticks_per_second {}\n",
            self.runtime.ticks_per_second()
        ));

        // spawn_blocking metrics
        // Histogram buckets are cumulative per Prometheus conventions:
        // - le="0.001": count of samples <= 1ms
        // - le="0.01": count of samples <= 10ms (includes all from le="0.001")
        // - le="0.1": count of samples <= 100ms (includes all from le="0.01")
        // - le="+Inf": count of all samples (total)
        output.push_str("\n# spawn_blocking metrics\n");
        output.push_str(&format!(
            "consensus_net_spawn_blocking_total {}\n",
            self.spawn_blocking.spawn_blocking_total()
        ));
        output.push_str(&format!(
            "consensus_net_spawn_blocking_duration_bucket{{le=\"0.001\"}} {}\n",
            self.spawn_blocking.latency_under_1ms()
        ));
        output.push_str(&format!(
            "consensus_net_spawn_blocking_duration_bucket{{le=\"0.01\"}} {}\n",
            self.spawn_blocking.latency_under_1ms() + self.spawn_blocking.latency_1ms_to_10ms()
        ));
        output.push_str(&format!(
            "consensus_net_spawn_blocking_duration_bucket{{le=\"0.1\"}} {}\n",
            self.spawn_blocking.latency_under_1ms()
                + self.spawn_blocking.latency_1ms_to_10ms()
                + self.spawn_blocking.latency_10ms_to_100ms()
        ));
        output.push_str(&format!(
            "consensus_net_spawn_blocking_duration_bucket{{le=\"+Inf\"}} {}\n",
            self.spawn_blocking.spawn_blocking_total()
        ));

        // Channel capacity configuration (T90.2)
        output.push_str("\n# Channel capacity configuration\n");
        if let Some(config) = self.channel_config() {
            output.push_str(&format!(
                "consensus_channel_config{{kind=\"event\"}} {}\n",
                config.consensus_event_capacity
            ));
            output.push_str(&format!(
                "consensus_channel_config{{kind=\"outbound_command\"}} {}\n",
                config.outbound_command_capacity
            ));
            output.push_str(&format!(
                "consensus_channel_config{{kind=\"async_peer_inbound\"}} {}\n",
                config.async_peer_inbound_capacity
            ));
            output.push_str(&format!(
                "consensus_channel_config{{kind=\"async_peer_outbound\"}} {}\n",
                config.async_peer_outbound_capacity
            ));
        } else {
            // Output default values if config not set
            output.push_str("consensus_channel_config{kind=\"event\"} 1024\n");
            output.push_str("consensus_channel_config{kind=\"outbound_command\"} 1024\n");
            output.push_str("consensus_channel_config{kind=\"async_peer_inbound\"} 1024\n");
            output.push_str("consensus_channel_config{kind=\"async_peer_outbound\"} 256\n");
        }

        // Priority-based metrics (T90.3)
        output.push_str("\n# Priority-based outbound metrics (T90.3)\n");
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"vote_send_to\", priority=\"critical\"}} {}\n",
            self.network
                .outbound_vote_send_to_by_priority(ConsensusMsgPriority::Critical)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"vote_send_to\", priority=\"normal\"}} {}\n",
            self.network
                .outbound_vote_send_to_by_priority(ConsensusMsgPriority::Normal)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"vote_broadcast\", priority=\"critical\"}} {}\n",
            self.network
                .outbound_vote_broadcast_by_priority(ConsensusMsgPriority::Critical)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"vote_broadcast\", priority=\"normal\"}} {}\n",
            self.network
                .outbound_vote_broadcast_by_priority(ConsensusMsgPriority::Normal)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"proposal_broadcast\", priority=\"critical\"}} {}\n",
            self.network.outbound_proposal_broadcast_by_priority(ConsensusMsgPriority::Critical)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_total{{kind=\"proposal_broadcast\", priority=\"normal\"}} {}\n",
            self.network
                .outbound_proposal_broadcast_by_priority(ConsensusMsgPriority::Normal)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_dropped_total{{priority=\"critical\"}} {}\n",
            self.network
                .outbound_dropped_by_priority(ConsensusMsgPriority::Critical)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_dropped_total{{priority=\"normal\"}} {}\n",
            self.network
                .outbound_dropped_by_priority(ConsensusMsgPriority::Normal)
        ));
        output.push_str(&format!(
            "consensus_net_outbound_dropped_total{{priority=\"low\"}} {}\n",
            self.network
                .outbound_dropped_by_priority(ConsensusMsgPriority::Low)
        ));

        // Critical worker metrics
        output.push_str("\n# Critical worker metrics (T90.3)\n");
        output.push_str(&format!(
            "consensus_net_outbound_critical_total {}\n",
            self.network.outbound_critical_total()
        ));
        output.push_str(&format!(
            "consensus_net_outbound_critical_worker_total {}\n",
            self.network.outbound_critical_worker_total()
        ));

        let (wait_under_1ms, wait_1ms_to_10ms, wait_10ms_to_100ms, wait_over_100ms) =
            self.network.critical_wait_buckets();
        output.push_str(&format!(
            "consensus_net_critical_backpressure_wait_bucket{{le=\"0.001\"}} {}\n",
            wait_under_1ms
        ));
        output.push_str(&format!(
            "consensus_net_critical_backpressure_wait_bucket{{le=\"0.01\"}} {}\n",
            wait_under_1ms + wait_1ms_to_10ms
        ));
        output.push_str(&format!(
            "consensus_net_critical_backpressure_wait_bucket{{le=\"0.1\"}} {}\n",
            wait_under_1ms + wait_1ms_to_10ms + wait_10ms_to_100ms
        ));
        output.push_str(&format!(
            "consensus_net_critical_backpressure_wait_bucket{{le=\"+Inf\"}} {}\n",
            wait_under_1ms + wait_1ms_to_10ms + wait_10ms_to_100ms + wait_over_100ms
        ));

        // Consensus round duration metrics (T90.5)
        output.push_str("\n# Consensus round duration metrics (T90.5)\n");
        output.push_str(&format!(
            "consensus_view_duration_count {}\n",
            self.consensus_round.view_durations_count()
        ));
        output.push_str(&format!(
            "consensus_view_duration_total_ms {}\n",
            self.consensus_round.view_durations_total_ms()
        ));
        let (bucket_100ms, bucket_500ms, bucket_2s, bucket_inf) =
            self.consensus_round.bucket_counts();
        output.push_str(&format!(
            "consensus_view_duration_bucket{{le=\"0.1\"}} {}\n",
            bucket_100ms
        ));
        output.push_str(&format!(
            "consensus_view_duration_bucket{{le=\"0.5\"}} {}\n",
            bucket_500ms
        ));
        output.push_str(&format!(
            "consensus_view_duration_bucket{{le=\"2.0\"}} {}\n",
            bucket_2s
        ));
        output.push_str(&format!(
            "consensus_view_duration_bucket{{le=\"+Inf\"}} {}\n",
            bucket_inf
        ));

        // Per-peer metrics (T90.4)
        output.push_str(&self.peer_network.format_metrics());

        // Connection limit metrics (T105)
        output.push_str(&self.connection_limit.format_metrics());

        // Storage operation latency metrics (T107)
        output.push_str(&self.storage.format_metrics());

        // Commit latency metrics (T107)
        output.push_str(&self.commit.format_metrics());

        // Suite transition metrics (T124)
        output.push_str(&self.suite_transition.format_metrics());

        // Consensus progress metrics (T127)
        output.push_str(&self.progress.format_metrics());

        // Per-validator vote metrics with view lag (T128, T129)
        // Uses highest_seen_view from ViewLagMetrics to compute per-validator lag
        let highest_seen_view = self.view_lag.highest_seen_view();
        output.push_str(
            &self
                .validator_votes
                .format_metrics_with_view_lag(highest_seen_view),
        );

        // View lag metrics (T128)
        output.push_str(&self.view_lag.format_metrics());

        // Per-validator equivocation metrics (T129)
        output.push_str(&self.validator_equivocations.format_metrics());

        // KEM operation metrics (T137)
        output.push_str(&self.format_kem_metrics());

        // T154 Metrics - DevNet Performance & Observability
        output.push_str(&self.consensus_t154.format_metrics());
        output.push_str(&self.mempool.format_metrics());
        output.push_str(&self.execution.format_metrics());
        output.push_str(&self.signer_keystore.format_metrics());

        output
    }

    /// Format KEM operation metrics in Prometheus-style text (T137).
    ///
    /// This formats the KEM metrics from KemOpMetrics into Prometheus format
    /// with appropriate metric names following the existing naming conventions.
    fn format_kem_metrics(&self) -> String {
        let kem = &self.kem_metrics;
        let mut output = String::new();
        output.push_str("\n# KEM operation metrics (T137)\n");

        // Total operation counts
        output.push_str(&format!(
            "qbind_net_kem_encaps_total {}\n",
            kem.encaps_total()
        ));
        output.push_str(&format!(
            "qbind_net_kem_decaps_total {}\n",
            kem.decaps_total()
        ));

        // Encapsulation latency buckets (cumulative histogram)
        let (encaps_0_1, encaps_1, encaps_10, encaps_inf) = kem.encaps_latency_buckets();
        output.push_str(&format!(
            "qbind_net_kem_encaps_latency_ms_bucket{{le=\"0.1\"}} {}\n",
            encaps_0_1
        ));
        output.push_str(&format!(
            "qbind_net_kem_encaps_latency_ms_bucket{{le=\"1\"}} {}\n",
            encaps_1
        ));
        output.push_str(&format!(
            "qbind_net_kem_encaps_latency_ms_bucket{{le=\"10\"}} {}\n",
            encaps_10
        ));
        output.push_str(&format!(
            "qbind_net_kem_encaps_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            encaps_inf
        ));
        output.push_str(&format!(
            "qbind_net_kem_encaps_latency_ms_count {}\n",
            encaps_inf
        ));

        // Decapsulation latency buckets (cumulative histogram)
        let (decaps_0_1, decaps_1, decaps_10, decaps_inf) = kem.decaps_latency_buckets();
        output.push_str(&format!(
            "qbind_net_kem_decaps_latency_ms_bucket{{le=\"0.1\"}} {}\n",
            decaps_0_1
        ));
        output.push_str(&format!(
            "qbind_net_kem_decaps_latency_ms_bucket{{le=\"1\"}} {}\n",
            decaps_1
        ));
        output.push_str(&format!(
            "qbind_net_kem_decaps_latency_ms_bucket{{le=\"10\"}} {}\n",
            decaps_10
        ));
        output.push_str(&format!(
            "qbind_net_kem_decaps_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            decaps_inf
        ));
        output.push_str(&format!(
            "qbind_net_kem_decaps_latency_ms_count {}\n",
            decaps_inf
        ));

        // Environment metrics (T162)
        if let Some(env_metrics) = self.environment() {
            output.push_str(&env_metrics.format_metrics());
        }

        // DAG coupling validation metrics (T191)
        output.push('\n');
        output.push_str(&self.dag_coupling.format_metrics());

        // Monetary engine telemetry metrics (T196)
        output.push_str(&self.monetary.format_metrics());

        output
    }

    /// Format metrics including crypto/PQC health section (T120).
    ///
    /// This method extends `format_metrics()` with a crypto-focused section that
    /// includes:
    /// - Per-suite signature verification metrics from `ConsensusSigMetrics`
    /// - KEMTLS handshake metrics (role-tagged) from `KemtlsMetrics`
    ///
    /// This allows answering:
    /// - "Which suite is being used?"
    /// - "How many verifications per suite?"
    /// - "Are any suites much slower than others?"
    /// - "Is KEMTLS handshake latency within expected ranges?"
    ///
    /// # Arguments
    ///
    /// * `consensus_sig_metrics` - Optional reference to consensus signature metrics
    /// * `kemtls_metrics` - Optional reference to KEMTLS handshake metrics
    pub fn format_metrics_with_crypto(
        &self,
        consensus_sig_metrics: Option<&qbind_consensus::ConsensusSigMetrics>,
        kemtls_metrics: Option<&crate::async_peer_manager::KemtlsMetrics>,
    ) -> String {
        let mut output = self.format_metrics();

        // Add crypto / PQC health section (T120)
        output.push_str("\n# Crypto / PQC metrics (T120)\n");

        // Per-suite consensus signature metrics
        if let Some(sig_metrics) = consensus_sig_metrics {
            output.push_str(&sig_metrics.format_per_suite_metrics());
        }

        // KEMTLS handshake metrics (role-tagged)
        if let Some(k_metrics) = kemtls_metrics {
            output.push_str(&k_metrics.format_metrics());
        }

        output
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn network_metrics_counters_work() {
        let metrics = NetworkMetrics::new();

        assert_eq!(metrics.inbound_vote_total(), 0);
        assert_eq!(metrics.inbound_proposal_total(), 0);
        assert_eq!(metrics.outbound_vote_broadcast_total(), 0);

        metrics.inc_inbound_vote();
        metrics.inc_inbound_vote();
        metrics.inc_inbound_proposal();
        metrics.inc_outbound_vote_broadcast();
        metrics.inc_outbound_dropped();

        assert_eq!(metrics.inbound_vote_total(), 2);
        assert_eq!(metrics.inbound_proposal_total(), 1);
        assert_eq!(metrics.outbound_vote_broadcast_total(), 1);
        assert_eq!(metrics.outbound_dropped_total(), 1);
    }

    #[test]
    fn runtime_metrics_counters_work() {
        let metrics = RuntimeMetrics::new();

        assert_eq!(metrics.events_tick_total(), 0);
        assert_eq!(metrics.events_incoming_message_total(), 0);

        metrics.inc_events_tick();
        metrics.inc_events_tick();
        metrics.inc_events_incoming_message();

        assert_eq!(metrics.events_tick_total(), 2);
        assert_eq!(metrics.events_incoming_message_total(), 1);
    }

    #[test]
    fn kem_metrics_formatting() {
        let metrics = NodeMetrics::new();

        // Manually record some KEM operations
        metrics
            .kem_metrics()
            .record_encaps(Duration::from_micros(50));
        metrics
            .kem_metrics()
            .record_encaps(Duration::from_millis(5));
        metrics
            .kem_metrics()
            .record_decaps(Duration::from_micros(200));

        // Format metrics and check that KEM metrics are present
        let formatted = metrics.format_metrics();

        // Check that KEM metric names are present
        assert!(formatted.contains("qbind_net_kem_encaps_total"));
        assert!(formatted.contains("qbind_net_kem_decaps_total"));
        assert!(formatted.contains("qbind_net_kem_encaps_latency_ms_bucket"));
        assert!(formatted.contains("qbind_net_kem_decaps_latency_ms_bucket"));
        assert!(formatted.contains("qbind_net_kem_encaps_latency_ms_count"));
        assert!(formatted.contains("qbind_net_kem_decaps_latency_ms_count"));

        // Check that values are non-zero
        assert!(formatted.contains("qbind_net_kem_encaps_total 2"));
        assert!(formatted.contains("qbind_net_kem_decaps_total 1"));
    }

    #[test]
    fn spawn_blocking_metrics_latency_buckets() {
        let metrics = SpawnBlockingMetrics::new();

        // Test different latency buckets
        metrics.record_blocking_duration(Duration::from_micros(500)); // < 1ms
        metrics.record_blocking_duration(Duration::from_millis(5)); // 1ms - 10ms
        metrics.record_blocking_duration(Duration::from_millis(50)); // 10ms - 100ms
        metrics.record_blocking_duration(Duration::from_millis(150)); // > 100ms

        assert_eq!(metrics.spawn_blocking_total(), 4);
        assert_eq!(metrics.latency_under_1ms(), 1);
        assert_eq!(metrics.latency_1ms_to_10ms(), 1);
        assert_eq!(metrics.latency_10ms_to_100ms(), 1);
        assert_eq!(metrics.latency_over_100ms(), 1);
    }

    #[test]
    fn node_metrics_aggregates_all_categories() {
        let metrics = NodeMetrics::new();

        metrics.network().inc_inbound_vote();
        metrics.runtime().inc_events_tick();
        metrics.spawn_blocking().inc_spawn_blocking();

        assert_eq!(metrics.network().inbound_vote_total(), 1);
        assert_eq!(metrics.runtime().events_tick_total(), 1);
        assert_eq!(metrics.spawn_blocking().spawn_blocking_total(), 1);
    }

    #[test]
    fn node_metrics_format_produces_valid_output() {
        let metrics = NodeMetrics::new();

        metrics.network().inc_inbound_vote();
        metrics.network().inc_inbound_proposal();
        metrics.runtime().inc_events_tick();
        metrics
            .spawn_blocking()
            .record_blocking_duration(Duration::from_micros(500));

        let output = metrics.format_metrics();

        assert!(output.contains("consensus_net_inbound_total{kind=\"vote\"} 1"));
        assert!(output.contains("consensus_net_inbound_total{kind=\"proposal\"} 1"));
        assert!(output.contains("consensus_events_total{kind=\"tick\"} 1"));
        assert!(output.contains("consensus_net_spawn_blocking_total 1"));
    }

    #[test]
    fn network_metrics_queue_depth_gauge() {
        let metrics = NetworkMetrics::new();

        assert_eq!(metrics.outbound_queue_depth(), 0);

        metrics.set_outbound_queue_depth(42);
        assert_eq!(metrics.outbound_queue_depth(), 42);

        metrics.set_outbound_queue_depth(0);
        assert_eq!(metrics.outbound_queue_depth(), 0);
    }

    #[test]
    fn node_metrics_channel_config_defaults_in_format() {
        let metrics = NodeMetrics::new();
        let output = metrics.format_metrics();

        // Without setting config, defaults should be output
        assert!(output.contains("consensus_channel_config{kind=\"event\"} 1024"));
        assert!(output.contains("consensus_channel_config{kind=\"outbound_command\"} 1024"));
        assert!(output.contains("consensus_channel_config{kind=\"async_peer_inbound\"} 1024"));
        assert!(output.contains("consensus_channel_config{kind=\"async_peer_outbound\"} 256"));
    }

    #[test]
    fn node_metrics_channel_config_custom_in_format() {
        let metrics = NodeMetrics::new();

        let config = ChannelCapacityConfig::new()
            .with_consensus_event_capacity(2048)
            .with_outbound_command_capacity(512)
            .with_async_peer_inbound_capacity(4096)
            .with_async_peer_outbound_capacity(128);

        metrics.set_channel_config(config);
        let output = metrics.format_metrics();

        assert!(output.contains("consensus_channel_config{kind=\"event\"} 2048"));
        assert!(output.contains("consensus_channel_config{kind=\"outbound_command\"} 512"));
        assert!(output.contains("consensus_channel_config{kind=\"async_peer_inbound\"} 4096"));
        assert!(output.contains("consensus_channel_config{kind=\"async_peer_outbound\"} 128"));
    }

    // ========================================================================
    // Per-peer metrics tests (T90.4)
    // ========================================================================

    #[test]
    fn peer_network_metrics_new_creates_empty_instance() {
        let metrics = PeerNetworkMetrics::new();
        assert_eq!(metrics.tracked_peer_count(), 0);
        assert_eq!(metrics.overflow_peer_count(), 0);
    }

    #[test]
    fn peer_network_metrics_tracks_inbound_by_peer() {
        let metrics = PeerNetworkMetrics::new();
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);

        metrics.inc_inbound(peer1, InboundMsgKind::Vote);
        metrics.inc_inbound(peer1, InboundMsgKind::Vote);
        metrics.inc_inbound(peer1, InboundMsgKind::Proposal);
        metrics.inc_inbound(peer2, InboundMsgKind::Vote);

        assert_eq!(metrics.tracked_peer_count(), 2);

        let (votes1, proposals1, other1) = metrics.peer_inbound_counts(peer1).unwrap();
        assert_eq!(votes1, 2);
        assert_eq!(proposals1, 1);
        assert_eq!(other1, 0);

        let (votes2, proposals2, other2) = metrics.peer_inbound_counts(peer2).unwrap();
        assert_eq!(votes2, 1);
        assert_eq!(proposals2, 0);
        assert_eq!(other2, 0);
    }

    #[test]
    fn peer_network_metrics_tracks_disconnect_by_peer() {
        let metrics = PeerNetworkMetrics::new();
        let peer = PeerId(42);

        metrics.inc_disconnect(peer, DisconnectReason::Eof);
        metrics.inc_disconnect(peer, DisconnectReason::Error);
        metrics.inc_disconnect(peer, DisconnectReason::Error);
        metrics.inc_disconnect(peer, DisconnectReason::Shutdown);

        let (eof, error, shutdown) = metrics.peer_disconnect_counts(peer).unwrap();
        assert_eq!(eof, 1);
        assert_eq!(error, 2);
        assert_eq!(shutdown, 1);
    }

    #[test]
    fn peer_network_metrics_tracks_outbound_by_peer_and_priority() {
        let metrics = PeerNetworkMetrics::new();
        let peer = PeerId(10);

        metrics.inc_outbound(
            peer,
            OutboundMsgKind::VoteSendTo,
            ConsensusMsgPriority::Critical,
        );
        metrics.inc_outbound(
            peer,
            OutboundMsgKind::VoteBroadcast,
            ConsensusMsgPriority::Normal,
        );
        metrics.inc_outbound(
            peer,
            OutboundMsgKind::ProposalBroadcast,
            ConsensusMsgPriority::Low,
        );

        // Verify peer is tracked
        assert_eq!(metrics.tracked_peer_count(), 1);

        // Verify in format output
        let output = metrics.format_metrics();
        assert!(output.contains("consensus_net_peer_outbound_total{peer=\"10\",kind=\"vote_send_to\",priority=\"critical\"} 1"));
        assert!(output.contains("consensus_net_peer_outbound_total{peer=\"10\",kind=\"vote_broadcast\",priority=\"normal\"} 1"));
        assert!(output.contains("consensus_net_peer_outbound_total{peer=\"10\",kind=\"proposal_broadcast\",priority=\"low\"} 1"));
    }

    #[test]
    fn peer_network_metrics_tracks_outbound_drops() {
        let metrics = PeerNetworkMetrics::new();
        let peer = PeerId(99);

        metrics.inc_outbound_drop(peer);
        metrics.inc_outbound_drop(peer);

        let output = metrics.format_metrics();
        assert!(output.contains("consensus_net_peer_outbound_drop_total{peer=\"99\"} 2"));
    }

    #[test]
    fn peer_network_metrics_respects_max_tracked_peers() {
        let metrics = PeerNetworkMetrics::new();

        // Add more peers than the limit
        for i in 0..MAX_TRACKED_PEERS + 10 {
            let peer = PeerId(i as u64);
            metrics.inc_inbound(peer, InboundMsgKind::Vote);
        }

        // Should cap at MAX_TRACKED_PEERS
        assert_eq!(metrics.tracked_peer_count(), MAX_TRACKED_PEERS);
        // Should have overflow count
        assert_eq!(metrics.overflow_peer_count(), 10);
    }

    #[test]
    fn peer_network_metrics_format_includes_overflow() {
        let metrics = PeerNetworkMetrics::new();

        // Add more peers than the limit
        for i in 0..MAX_TRACKED_PEERS + 5 {
            let peer = PeerId(i as u64);
            metrics.inc_inbound(peer, InboundMsgKind::Vote);
        }

        let output = metrics.format_metrics();
        assert!(output.contains("consensus_net_peer_overflow_count 5"));
        assert!(
            output.contains("consensus_net_peer_inbound_total{peer=\"overflow\",kind=\"vote\"} 5")
        );
    }

    #[test]
    fn peer_network_metrics_format_skips_zero_counts() {
        let metrics = PeerNetworkMetrics::new();
        let peer = PeerId(1);

        // Only increment vote, not proposal
        metrics.inc_inbound(peer, InboundMsgKind::Vote);

        let output = metrics.format_metrics();
        // Should contain vote metric
        assert!(output.contains("consensus_net_peer_inbound_total{peer=\"1\",kind=\"vote\"} 1"));
        // Should NOT contain proposal metric for this peer (would be 0)
        assert!(!output.contains("consensus_net_peer_inbound_total{peer=\"1\",kind=\"proposal\"}"));
    }

    #[test]
    fn node_metrics_includes_peer_metrics() {
        let metrics = NodeMetrics::new();
        let peer = PeerId(42);

        metrics
            .peer_network()
            .inc_inbound(peer, InboundMsgKind::Vote);
        metrics
            .peer_network()
            .inc_disconnect(peer, DisconnectReason::Eof);

        let output = metrics.format_metrics();
        assert!(output.contains("# Per-peer network metrics (T90.4)"));
        assert!(output.contains("consensus_net_peer_inbound_total{peer=\"42\",kind=\"vote\"} 1"));
        assert!(
            output.contains("consensus_net_peer_disconnect_total{peer=\"42\",reason=\"eof\"} 1")
        );
    }

    #[test]
    fn peer_id_representation_is_decimal() {
        let metrics = PeerNetworkMetrics::new();
        let peer = PeerId(12345);

        metrics.inc_inbound(peer, InboundMsgKind::Vote);

        let output = metrics.format_metrics();
        // Verify decimal representation is used
        assert!(output.contains("peer=\"12345\""));
        // Should NOT be hex or other format
        assert!(!output.contains("peer=\"0x"));
    }

    // ========================================================================
    // Consensus round metrics tests (T90.5)
    // ========================================================================

    #[test]
    fn consensus_round_metrics_new_creates_zero_counters() {
        let metrics = ConsensusRoundMetrics::new();
        assert_eq!(metrics.view_durations_count(), 0);
        assert_eq!(metrics.view_durations_total_ms(), 0);
        let (b100, b500, b2s, binf) = metrics.bucket_counts();
        assert_eq!(b100, 0);
        assert_eq!(b500, 0);
        assert_eq!(b2s, 0);
        assert_eq!(binf, 0);
    }

    #[test]
    fn consensus_round_metrics_record_view_duration_updates_count_and_total() {
        let metrics = ConsensusRoundMetrics::new();

        metrics.record_view_duration(Duration::from_millis(50));
        assert_eq!(metrics.view_durations_count(), 1);
        assert_eq!(metrics.view_durations_total_ms(), 50);

        metrics.record_view_duration(Duration::from_millis(100));
        assert_eq!(metrics.view_durations_count(), 2);
        assert_eq!(metrics.view_durations_total_ms(), 150);
    }

    #[test]
    fn consensus_round_metrics_bucket_under_100ms() {
        let metrics = ConsensusRoundMetrics::new();

        // 50ms should be in all buckets
        metrics.record_view_duration(Duration::from_millis(50));

        let (b100, b500, b2s, binf) = metrics.bucket_counts();
        assert_eq!(b100, 1, "50ms should be in <100ms bucket");
        assert_eq!(b500, 1, "50ms should be in <500ms bucket");
        assert_eq!(b2s, 1, "50ms should be in <2s bucket");
        assert_eq!(binf, 1, "50ms should be in +Inf bucket");
    }

    #[test]
    fn consensus_round_metrics_bucket_100ms_to_500ms() {
        let metrics = ConsensusRoundMetrics::new();

        // 200ms should be in 500ms, 2s, and inf buckets, but not 100ms
        metrics.record_view_duration(Duration::from_millis(200));

        let (b100, b500, b2s, binf) = metrics.bucket_counts();
        assert_eq!(b100, 0, "200ms should NOT be in <100ms bucket");
        assert_eq!(b500, 1, "200ms should be in <500ms bucket");
        assert_eq!(b2s, 1, "200ms should be in <2s bucket");
        assert_eq!(binf, 1, "200ms should be in +Inf bucket");
    }

    #[test]
    fn consensus_round_metrics_bucket_500ms_to_2s() {
        let metrics = ConsensusRoundMetrics::new();

        // 1000ms should be in 2s and inf buckets only
        metrics.record_view_duration(Duration::from_millis(1000));

        let (b100, b500, b2s, binf) = metrics.bucket_counts();
        assert_eq!(b100, 0, "1000ms should NOT be in <100ms bucket");
        assert_eq!(b500, 0, "1000ms should NOT be in <500ms bucket");
        assert_eq!(b2s, 1, "1000ms should be in <2s bucket");
        assert_eq!(binf, 1, "1000ms should be in +Inf bucket");
    }

    #[test]
    fn consensus_round_metrics_bucket_over_2s() {
        let metrics = ConsensusRoundMetrics::new();

        // 3000ms should only be in inf bucket
        metrics.record_view_duration(Duration::from_millis(3000));

        let (b100, b500, b2s, binf) = metrics.bucket_counts();
        assert_eq!(b100, 0, "3000ms should NOT be in <100ms bucket");
        assert_eq!(b500, 0, "3000ms should NOT be in <500ms bucket");
        assert_eq!(b2s, 0, "3000ms should NOT be in <2s bucket");
        assert_eq!(binf, 1, "3000ms should be in +Inf bucket");
    }

    #[test]
    fn consensus_round_metrics_multiple_durations() {
        let metrics = ConsensusRoundMetrics::new();

        // Mix of durations
        metrics.record_view_duration(Duration::from_millis(50)); // All buckets
        metrics.record_view_duration(Duration::from_millis(200)); // 500ms, 2s, inf
        metrics.record_view_duration(Duration::from_millis(1000)); // 2s, inf
        metrics.record_view_duration(Duration::from_millis(3000)); // inf only

        assert_eq!(metrics.view_durations_count(), 4);
        assert_eq!(metrics.view_durations_total_ms(), 4250);

        let (b100, b500, b2s, binf) = metrics.bucket_counts();
        assert_eq!(b100, 1, "Only 50ms in <100ms");
        assert_eq!(b500, 2, "50ms and 200ms in <500ms");
        assert_eq!(b2s, 3, "50ms, 200ms, 1000ms in <2s");
        assert_eq!(binf, 4, "All in +Inf");
    }

    #[test]
    fn node_metrics_includes_consensus_round_metrics() {
        let metrics = NodeMetrics::new();

        metrics
            .consensus_round()
            .record_view_duration(Duration::from_millis(50));
        metrics
            .consensus_round()
            .record_view_duration(Duration::from_millis(200));

        let output = metrics.format_metrics();
        assert!(output.contains("# Consensus round duration metrics (T90.5)"));
        assert!(output.contains("consensus_view_duration_count 2"));
        assert!(output.contains("consensus_view_duration_total_ms 250"));
        assert!(output.contains("consensus_view_duration_bucket{le=\"0.1\"} 1"));
        assert!(output.contains("consensus_view_duration_bucket{le=\"0.5\"} 2"));
        assert!(output.contains("consensus_view_duration_bucket{le=\"2.0\"} 2"));
        assert!(output.contains("consensus_view_duration_bucket{le=\"+Inf\"} 2"));
    }

    #[test]
    fn consensus_round_metrics_default_impl() {
        let metrics: ConsensusRoundMetrics = Default::default();
        assert_eq!(metrics.view_durations_count(), 0);
    }

    // ========================================================================
    // StorageMetrics tests (T107)
    // ========================================================================

    #[test]
    fn storage_metrics_new_creates_zero_counters() {
        let metrics = StorageMetrics::new();
        assert_eq!(metrics.op_count(StorageOp::PutBlock), 0);
        assert_eq!(metrics.op_count(StorageOp::PutQc), 0);
        assert_eq!(metrics.op_count(StorageOp::PutLastCommitted), 0);
        assert_eq!(metrics.op_count(StorageOp::PutCurrentEpoch), 0);
        assert_eq!(metrics.op_count(StorageOp::GetBlock), 0);
        assert_eq!(metrics.op_count(StorageOp::GetQc), 0);
        assert_eq!(metrics.op_count(StorageOp::GetLastCommitted), 0);
        assert_eq!(metrics.op_count(StorageOp::GetCurrentEpoch), 0);
    }

    #[test]
    fn storage_metrics_record_updates_count_and_total() {
        let metrics = StorageMetrics::new();

        metrics.record(StorageOp::PutBlock, Duration::from_millis(5));
        assert_eq!(metrics.op_count(StorageOp::PutBlock), 1);
        assert_eq!(metrics.op_total_ms(StorageOp::PutBlock), 5);

        metrics.record(StorageOp::PutBlock, Duration::from_millis(10));
        assert_eq!(metrics.op_count(StorageOp::PutBlock), 2);
        assert_eq!(metrics.op_total_ms(StorageOp::PutBlock), 15);
    }

    #[test]
    fn storage_metrics_buckets_under_1ms() {
        let metrics = StorageMetrics::new();

        // 500 microseconds should be in the <1ms bucket
        metrics.record(StorageOp::PutBlock, Duration::from_micros(500));

        let (b1, b10, b100, over) = metrics.op_buckets(StorageOp::PutBlock);
        assert_eq!(b1, 1, "500us should be in <1ms bucket");
        assert_eq!(b10, 0);
        assert_eq!(b100, 0);
        assert_eq!(over, 0);
    }

    #[test]
    fn storage_metrics_buckets_1ms_to_10ms() {
        let metrics = StorageMetrics::new();

        // 5ms should be in the 1-10ms bucket
        metrics.record(StorageOp::PutQc, Duration::from_millis(5));

        let (b1, b10, b100, over) = metrics.op_buckets(StorageOp::PutQc);
        assert_eq!(b1, 0);
        assert_eq!(b10, 1, "5ms should be in 1-10ms bucket");
        assert_eq!(b100, 0);
        assert_eq!(over, 0);
    }

    #[test]
    fn storage_metrics_buckets_10ms_to_100ms() {
        let metrics = StorageMetrics::new();

        // 50ms should be in the 10-100ms bucket
        metrics.record(StorageOp::PutLastCommitted, Duration::from_millis(50));

        let (b1, b10, b100, over) = metrics.op_buckets(StorageOp::PutLastCommitted);
        assert_eq!(b1, 0);
        assert_eq!(b10, 0);
        assert_eq!(b100, 1, "50ms should be in 10-100ms bucket");
        assert_eq!(over, 0);
    }

    #[test]
    fn storage_metrics_buckets_over_100ms() {
        let metrics = StorageMetrics::new();

        // 150ms should be in the >100ms bucket
        metrics.record(StorageOp::PutCurrentEpoch, Duration::from_millis(150));

        let (b1, b10, b100, over) = metrics.op_buckets(StorageOp::PutCurrentEpoch);
        assert_eq!(b1, 0);
        assert_eq!(b10, 0);
        assert_eq!(b100, 0);
        assert_eq!(over, 1, "150ms should be in >100ms bucket");
    }

    #[test]
    fn storage_metrics_all_operations() {
        let metrics = StorageMetrics::new();

        // Record for all operations
        metrics.record(StorageOp::PutBlock, Duration::from_millis(1));
        metrics.record(StorageOp::PutQc, Duration::from_millis(2));
        metrics.record(StorageOp::PutLastCommitted, Duration::from_millis(3));
        metrics.record(StorageOp::PutCurrentEpoch, Duration::from_millis(4));
        metrics.record(StorageOp::GetBlock, Duration::from_millis(5));
        metrics.record(StorageOp::GetQc, Duration::from_millis(6));
        metrics.record(StorageOp::GetLastCommitted, Duration::from_millis(7));
        metrics.record(StorageOp::GetCurrentEpoch, Duration::from_millis(8));

        assert_eq!(metrics.op_count(StorageOp::PutBlock), 1);
        assert_eq!(metrics.op_count(StorageOp::PutQc), 1);
        assert_eq!(metrics.op_count(StorageOp::PutLastCommitted), 1);
        assert_eq!(metrics.op_count(StorageOp::PutCurrentEpoch), 1);
        assert_eq!(metrics.op_count(StorageOp::GetBlock), 1);
        assert_eq!(metrics.op_count(StorageOp::GetQc), 1);
        assert_eq!(metrics.op_count(StorageOp::GetLastCommitted), 1);
        assert_eq!(metrics.op_count(StorageOp::GetCurrentEpoch), 1);
    }

    #[test]
    fn storage_metrics_format_includes_all_ops() {
        let metrics = StorageMetrics::new();

        metrics.record(StorageOp::PutBlock, Duration::from_millis(5));
        metrics.record(StorageOp::GetBlock, Duration::from_micros(500));

        let output = metrics.format_metrics();

        // Check that the output includes expected metric names
        assert!(output.contains("# Storage operation latency metrics (T107)"));
        assert!(output.contains("eezo_storage_op_duration_ms_count{op=\"put_block\"} 1"));
        assert!(output.contains("eezo_storage_op_duration_ms_sum{op=\"put_block\"} 5"));
        assert!(output.contains("eezo_storage_op_duration_ms_count{op=\"get_block\"} 1"));
        assert!(output.contains("eezo_storage_op_duration_ms_sum{op=\"get_block\"} 0"));
        // 500us rounds to 0ms
    }

    #[test]
    fn storage_op_label() {
        assert_eq!(StorageOp::PutBlock.label(), "put_block");
        assert_eq!(StorageOp::PutQc.label(), "put_qc");
        assert_eq!(StorageOp::PutLastCommitted.label(), "put_last_committed");
        assert_eq!(StorageOp::PutCurrentEpoch.label(), "put_current_epoch");
        assert_eq!(StorageOp::GetBlock.label(), "get_block");
        assert_eq!(StorageOp::GetQc.label(), "get_qc");
        assert_eq!(StorageOp::GetLastCommitted.label(), "get_last_committed");
        assert_eq!(StorageOp::GetCurrentEpoch.label(), "get_current_epoch");
    }

    // ========================================================================
    // CommitMetrics tests (T107)
    // ========================================================================

    #[test]
    fn commit_metrics_new_creates_zero_counters() {
        let metrics = CommitMetrics::new();
        assert_eq!(metrics.commit_count(), 0);
        assert_eq!(metrics.commit_total_ms(), 0);
        let (b1, b10, b100, over) = metrics.bucket_counts();
        assert_eq!(b1, 0);
        assert_eq!(b10, 0);
        assert_eq!(b100, 0);
        assert_eq!(over, 0);
    }

    #[test]
    fn commit_metrics_record_updates_count_and_total() {
        let metrics = CommitMetrics::new();

        metrics.record_commit(Duration::from_millis(5));
        assert_eq!(metrics.commit_count(), 1);
        assert_eq!(metrics.commit_total_ms(), 5);

        metrics.record_commit(Duration::from_millis(10));
        assert_eq!(metrics.commit_count(), 2);
        assert_eq!(metrics.commit_total_ms(), 15);
    }

    #[test]
    fn commit_metrics_buckets_under_1ms() {
        let metrics = CommitMetrics::new();

        metrics.record_commit(Duration::from_micros(500));

        let (b1, b10, b100, over) = metrics.bucket_counts();
        assert_eq!(b1, 1, "500us should be in <1ms bucket");
        assert_eq!(b10, 0);
        assert_eq!(b100, 0);
        assert_eq!(over, 0);
    }

    #[test]
    fn commit_metrics_buckets_1ms_to_10ms() {
        let metrics = CommitMetrics::new();

        metrics.record_commit(Duration::from_millis(5));

        let (b1, b10, b100, over) = metrics.bucket_counts();
        assert_eq!(b1, 0);
        assert_eq!(b10, 1, "5ms should be in 1-10ms bucket");
        assert_eq!(b100, 0);
        assert_eq!(over, 0);
    }

    #[test]
    fn commit_metrics_buckets_10ms_to_100ms() {
        let metrics = CommitMetrics::new();

        metrics.record_commit(Duration::from_millis(50));

        let (b1, b10, b100, over) = metrics.bucket_counts();
        assert_eq!(b1, 0);
        assert_eq!(b10, 0);
        assert_eq!(b100, 1, "50ms should be in 10-100ms bucket");
        assert_eq!(over, 0);
    }

    #[test]
    fn commit_metrics_buckets_over_100ms() {
        let metrics = CommitMetrics::new();

        metrics.record_commit(Duration::from_millis(150));

        let (b1, b10, b100, over) = metrics.bucket_counts();
        assert_eq!(b1, 0);
        assert_eq!(b10, 0);
        assert_eq!(b100, 0);
        assert_eq!(over, 1, "150ms should be in >100ms bucket");
    }

    #[test]
    fn commit_metrics_format_output() {
        let metrics = CommitMetrics::new();

        metrics.record_commit(Duration::from_millis(5));
        metrics.record_commit(Duration::from_millis(50));

        let output = metrics.format_metrics();

        assert!(output.contains("# Commit latency metrics (T107)"));
        assert!(output.contains("eezo_commit_latency_ms_count 2"));
        assert!(output.contains("eezo_commit_latency_ms_sum 55"));
    }

    #[test]
    fn node_metrics_includes_storage_metrics() {
        let metrics = NodeMetrics::new();

        metrics
            .storage()
            .record(StorageOp::PutBlock, Duration::from_millis(5));

        let output = metrics.format_metrics();
        assert!(output.contains("# Storage operation latency metrics (T107)"));
        assert!(output.contains("eezo_storage_op_duration_ms_count{op=\"put_block\"} 1"));
    }

    #[test]
    fn node_metrics_includes_commit_metrics() {
        let metrics = NodeMetrics::new();

        metrics.commit().record_commit(Duration::from_millis(5));

        let output = metrics.format_metrics();
        assert!(output.contains("# Commit latency metrics (T107)"));
        assert!(output.contains("eezo_commit_latency_ms_count 1"));
    }

    // ========================================================================
    // ConsensusProgressMetrics tests (T127)
    // ========================================================================

    #[test]
    fn consensus_progress_metrics_new_creates_zero_counters() {
        let metrics = ConsensusProgressMetrics::new();
        assert_eq!(metrics.qcs_formed_total(), 0);
        assert_eq!(metrics.votes_observed_total(), 0);
        assert_eq!(metrics.votes_observed_current_view(), 0);
        assert_eq!(metrics.view_changes_total(), 0);
        assert_eq!(metrics.leader_changes_total(), 0);
        assert_eq!(metrics.qc_formation_latency_count(), 0);
        assert_eq!(metrics.qc_formation_latency_sum_ms(), 0);
    }

    #[test]
    fn consensus_progress_metrics_inc_qcs_formed() {
        let metrics = ConsensusProgressMetrics::new();

        metrics.inc_qcs_formed();
        assert_eq!(metrics.qcs_formed_total(), 1);

        metrics.inc_qcs_formed();
        metrics.inc_qcs_formed();
        assert_eq!(metrics.qcs_formed_total(), 3);
    }

    #[test]
    fn consensus_progress_metrics_inc_votes_observed() {
        let metrics = ConsensusProgressMetrics::new();

        metrics.inc_votes_observed();
        assert_eq!(metrics.votes_observed_total(), 1);

        metrics.inc_votes_observed();
        metrics.inc_votes_observed();
        metrics.inc_votes_observed();
        assert_eq!(metrics.votes_observed_total(), 4);
    }

    #[test]
    fn consensus_progress_metrics_votes_current_view() {
        let metrics = ConsensusProgressMetrics::new();

        // Increment
        metrics.inc_votes_current_view();
        metrics.inc_votes_current_view();
        assert_eq!(metrics.votes_observed_current_view(), 2);

        // Reset
        metrics.reset_votes_current_view();
        assert_eq!(metrics.votes_observed_current_view(), 0);

        // Increment again after reset
        metrics.inc_votes_current_view();
        assert_eq!(metrics.votes_observed_current_view(), 1);
    }

    #[test]
    fn consensus_progress_metrics_view_changes() {
        let metrics = ConsensusProgressMetrics::new();

        metrics.inc_view_changes();
        assert_eq!(metrics.view_changes_total(), 1);

        metrics.inc_view_changes();
        metrics.inc_view_changes();
        assert_eq!(metrics.view_changes_total(), 3);
    }

    #[test]
    fn consensus_progress_metrics_leader_changes() {
        let metrics = ConsensusProgressMetrics::new();

        metrics.inc_leader_changes();
        assert_eq!(metrics.leader_changes_total(), 1);

        metrics.inc_leader_changes();
        assert_eq!(metrics.leader_changes_total(), 2);
    }

    #[test]
    fn consensus_progress_metrics_qc_formation_latency_buckets() {
        let metrics = ConsensusProgressMetrics::new();

        // < 100ms
        metrics.record_qc_formation_latency(Duration::from_millis(50));
        let (b100, b500, b2s, binf) = metrics.qc_formation_latency_buckets();
        assert_eq!(b100, 1, "50ms should be in <100ms bucket");
        assert_eq!(b500, 1, "50ms should be in <500ms bucket");
        assert_eq!(b2s, 1, "50ms should be in <2s bucket");
        assert_eq!(binf, 1, "50ms should be in +Inf bucket");

        // 100-500ms
        metrics.record_qc_formation_latency(Duration::from_millis(200));
        let (b100, b500, b2s, binf) = metrics.qc_formation_latency_buckets();
        assert_eq!(b100, 1, "200ms should NOT be in <100ms bucket");
        assert_eq!(b500, 2, "200ms should be in <500ms bucket");
        assert_eq!(b2s, 2, "200ms should be in <2s bucket");
        assert_eq!(binf, 2, "200ms should be in +Inf bucket");

        // 500-2000ms
        metrics.record_qc_formation_latency(Duration::from_millis(1000));
        let (b100, b500, b2s, binf) = metrics.qc_formation_latency_buckets();
        assert_eq!(b100, 1);
        assert_eq!(b500, 2);
        assert_eq!(b2s, 3);
        assert_eq!(binf, 3);

        // > 2000ms
        metrics.record_qc_formation_latency(Duration::from_millis(3000));
        let (b100, b500, b2s, binf) = metrics.qc_formation_latency_buckets();
        assert_eq!(b100, 1);
        assert_eq!(b500, 2);
        assert_eq!(b2s, 3);
        assert_eq!(binf, 4);

        // Check count and sum
        assert_eq!(metrics.qc_formation_latency_count(), 4);
        assert_eq!(
            metrics.qc_formation_latency_sum_ms(),
            50 + 200 + 1000 + 3000
        );
    }

    #[test]
    fn consensus_progress_metrics_format_output() {
        let metrics = ConsensusProgressMetrics::new();

        metrics.inc_qcs_formed();
        metrics.inc_qcs_formed();
        metrics.inc_votes_observed();
        metrics.inc_votes_observed();
        metrics.inc_votes_observed();
        metrics.inc_votes_current_view();
        metrics.inc_view_changes();
        metrics.inc_leader_changes();
        metrics.record_qc_formation_latency(Duration::from_millis(100));

        let output = metrics.format_metrics();

        assert!(output.contains("# Consensus progress metrics (T127)"));
        assert!(output.contains("qbind_consensus_qcs_formed_total 2"));
        assert!(output.contains("qbind_consensus_votes_observed_total 3"));
        assert!(output.contains("qbind_consensus_votes_observed_current_view 1"));
        assert!(output.contains("qbind_consensus_view_changes_total 1"));
        assert!(output.contains("qbind_consensus_leader_changes_total 1"));
        assert!(output.contains("qbind_consensus_qc_formation_latency_ms_count 1"));
        assert!(output.contains("qbind_consensus_qc_formation_latency_ms_sum 100"));
    }

    #[test]
    fn node_metrics_includes_consensus_progress_metrics() {
        let metrics = NodeMetrics::new();

        metrics.progress().inc_qcs_formed();
        metrics.progress().inc_votes_observed();
        metrics.progress().inc_view_changes();

        let output = metrics.format_metrics();
        assert!(output.contains("# Consensus progress metrics (T127)"));
        assert!(output.contains("qbind_consensus_qcs_formed_total 1"));
        assert!(output.contains("qbind_consensus_votes_observed_total 1"));
        assert!(output.contains("qbind_consensus_view_changes_total 1"));
    }

    #[test]
    fn consensus_progress_metrics_default_impl() {
        let metrics: ConsensusProgressMetrics = Default::default();
        assert_eq!(metrics.qcs_formed_total(), 0);
        assert_eq!(metrics.votes_observed_total(), 0);
    }
}
