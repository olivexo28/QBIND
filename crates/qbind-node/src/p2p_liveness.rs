//! T205: P2P Peer Liveness Manager
//!
//! This module provides the liveness subsystem for QBIND's P2P layer.
//! It monitors peer health through periodic heartbeats (Ping/Pong) and
//! evicts unresponsive peers.
//!
//! # Overview
//!
//! The Liveness Manager:
//!
//! - Periodically sends Ping messages to connected peers
//! - Tracks missed heartbeats and maintains liveness scores
//! - Evicts peers whose score drops below threshold
//! - Notifies Discovery Manager to backfill connections
//!
//! # Liveness Scoring
//!
//! Each peer has a score from 0-100:
//!
//! - Initial score: 80
//! - Successful Pong: +5 (capped at 100)
//! - Missed heartbeat: -15
//! - Score below `liveness_min_score`: peer is evicted
//!
//! # Integration
//!
//! The Liveness Manager integrates with:
//!
//! - `Peer` struct (existing Ping/Pong methods)
//! - `PeerTable` from Discovery Manager (score updates)
//! - Existing async executor (Tokio intervals)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::p2p::NodeId;
use crate::peer::PeerId;

// ============================================================================
// T205: PeerLivenessState - Per-peer liveness tracking
// ============================================================================

/// Per-peer liveness state (T205).
///
/// Tracks heartbeat timing and liveness score for a single peer.
#[derive(Clone, Debug)]
pub struct PeerLivenessState {
    /// The peer's identifier.
    pub peer_id: PeerId,

    /// The peer's node identifier (for PeerTable updates).
    pub node_id: Option<NodeId>,

    /// When we last sent a heartbeat (Ping) to this peer.
    pub last_heartbeat_sent: Option<Instant>,

    /// When we last received a heartbeat response (Pong) from this peer.
    pub last_heartbeat_received: Option<Instant>,

    /// Number of consecutive missed heartbeats.
    pub missed_heartbeats: u8,

    /// Liveness score (0-100).
    /// Initial score is 80. Score below threshold triggers eviction.
    pub score: u8,

    /// Whether we are currently waiting for a Pong.
    pub pending_pong: bool,
}

impl PeerLivenessState {
    /// Create a new liveness state for a peer.
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            node_id: None,
            last_heartbeat_sent: None,
            last_heartbeat_received: None,
            missed_heartbeats: 0,
            score: 80, // Initial score
            pending_pong: false,
        }
    }

    /// Create a new liveness state with an associated node ID.
    pub fn with_node_id(peer_id: PeerId, node_id: NodeId) -> Self {
        Self {
            peer_id,
            node_id: Some(node_id),
            last_heartbeat_sent: None,
            last_heartbeat_received: None,
            missed_heartbeats: 0,
            score: 80,
            pending_pong: false,
        }
    }

    /// Record that a Ping was sent.
    pub fn record_ping_sent(&mut self) {
        self.last_heartbeat_sent = Some(Instant::now());
        self.pending_pong = true;
    }

    /// Record that a Pong was received.
    ///
    /// Resets missed_heartbeats and increases score.
    pub fn record_pong_received(&mut self) {
        self.last_heartbeat_received = Some(Instant::now());
        self.missed_heartbeats = 0;
        self.pending_pong = false;

        // Increase score on successful response
        self.score = self.score.saturating_add(SCORE_INCREASE_ON_PONG).min(100);
    }

    /// Record that a heartbeat was missed.
    ///
    /// Increments missed_heartbeats and decreases score.
    pub fn record_missed_heartbeat(&mut self) {
        self.missed_heartbeats = self.missed_heartbeats.saturating_add(1);
        self.pending_pong = false;

        // Decrease score on missed heartbeat
        self.score = self.score.saturating_sub(SCORE_DECREASE_ON_MISS);
    }

    /// Check if we should send a heartbeat.
    ///
    /// Returns true if enough time has passed since the last heartbeat.
    pub fn should_send_heartbeat(&self, interval: Duration) -> bool {
        match self.last_heartbeat_sent {
            Some(t) => t.elapsed() >= interval,
            None => true, // Never sent a heartbeat, should send one
        }
    }

    /// Check if the pending Pong has timed out.
    ///
    /// Returns true if we sent a Ping but didn't receive a Pong within the interval.
    pub fn has_pong_timeout(&self, interval: Duration) -> bool {
        if !self.pending_pong {
            return false;
        }

        match self.last_heartbeat_sent {
            Some(t) => t.elapsed() >= interval,
            None => false,
        }
    }

    /// Check if this peer should be evicted.
    ///
    /// A peer should be evicted if:
    /// - `missed_heartbeats >= failure_threshold`, OR
    /// - `score < min_score`
    pub fn should_evict(&self, failure_threshold: u8, min_score: u8) -> bool {
        self.missed_heartbeats >= failure_threshold || self.score < min_score
    }

    /// Get the eviction reason if the peer should be evicted.
    pub fn eviction_reason(&self, failure_threshold: u8, min_score: u8) -> Option<EvictionReason> {
        if self.missed_heartbeats >= failure_threshold {
            Some(EvictionReason::MissedHeartbeats {
                count: self.missed_heartbeats,
                threshold: failure_threshold,
            })
        } else if self.score < min_score {
            Some(EvictionReason::LowScore {
                score: self.score,
                threshold: min_score,
            })
        } else {
            None
        }
    }
}

/// Score increase when a Pong is received.
pub const SCORE_INCREASE_ON_PONG: u8 = 5;

/// Score decrease when a heartbeat is missed.
pub const SCORE_DECREASE_ON_MISS: u8 = 15;

// ============================================================================
// T205: EvictionReason - Why a peer was evicted
// ============================================================================

/// Reason for evicting a peer (T205).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvictionReason {
    /// Peer missed too many consecutive heartbeats.
    MissedHeartbeats { count: u8, threshold: u8 },

    /// Peer's liveness score dropped below threshold.
    LowScore { score: u8, threshold: u8 },
}

impl std::fmt::Display for EvictionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvictionReason::MissedHeartbeats { count, threshold } => {
                write!(
                    f,
                    "missed {} consecutive heartbeats (threshold: {})",
                    count, threshold
                )
            }
            EvictionReason::LowScore { score, threshold } => {
                write!(f, "liveness score {} below threshold {}", score, threshold)
            }
        }
    }
}

// ============================================================================
// T205: LivenessManager - Manages liveness for all peers
// ============================================================================

/// Manager for peer liveness tracking (T205).
///
/// Tracks liveness state for all connected peers and provides
/// methods for heartbeat management and eviction decisions.
pub struct LivenessManager {
    /// Per-peer liveness states.
    peers: HashMap<PeerId, PeerLivenessState>,

    /// Configuration for liveness checks.
    config: LivenessConfig,
}

impl LivenessManager {
    /// Create a new liveness manager with the given configuration.
    pub fn new(config: LivenessConfig) -> Self {
        Self {
            peers: HashMap::new(),
            config,
        }
    }

    /// Add a new peer to track.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.peers
            .entry(peer_id)
            .or_insert_with(|| PeerLivenessState::new(peer_id));
    }

    /// Add a new peer with an associated node ID.
    pub fn add_peer_with_node_id(&mut self, peer_id: PeerId, node_id: NodeId) {
        self.peers
            .entry(peer_id)
            .or_insert_with(|| PeerLivenessState::with_node_id(peer_id, node_id));
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<PeerLivenessState> {
        self.peers.remove(peer_id)
    }

    /// Get the liveness state for a peer.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerLivenessState> {
        self.peers.get(peer_id)
    }

    /// Get a mutable reference to the liveness state for a peer.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerLivenessState> {
        self.peers.get_mut(peer_id)
    }

    /// Get the number of tracked peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if no peers are tracked.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Get all peers that need a heartbeat sent.
    ///
    /// Returns peer IDs for peers where enough time has passed since
    /// the last heartbeat was sent.
    pub fn peers_needing_heartbeat(&self) -> Vec<PeerId> {
        let interval = Duration::from_secs(self.config.probe_interval_secs);
        self.peers
            .values()
            .filter(|state| state.should_send_heartbeat(interval))
            .map(|state| state.peer_id)
            .collect()
    }

    /// Get all peers with timed-out pending Pongs.
    ///
    /// These peers sent Pings but didn't receive Pongs within the interval.
    pub fn peers_with_timeout(&self) -> Vec<PeerId> {
        let interval = Duration::from_secs(self.config.probe_interval_secs);
        self.peers
            .values()
            .filter(|state| state.has_pong_timeout(interval))
            .map(|state| state.peer_id)
            .collect()
    }

    /// Get all peers that should be evicted.
    ///
    /// Returns peer IDs and eviction reasons for peers that meet
    /// eviction criteria.
    pub fn peers_to_evict(&self) -> Vec<(PeerId, EvictionReason)> {
        self.peers
            .values()
            .filter_map(|state| {
                state
                    .eviction_reason(self.config.failure_threshold, self.config.min_score)
                    .map(|reason| (state.peer_id, reason))
            })
            .collect()
    }

    /// Record that a Ping was sent to a peer.
    ///
    /// If the peer is not being tracked, this is a no-op.
    pub fn record_ping_sent(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.record_ping_sent();
        }
    }

    /// Record that a Pong was received from a peer.
    ///
    /// If the peer is not being tracked, this is logged at trace level
    /// and otherwise ignored. This can happen during peer connection
    /// state transitions.
    pub fn record_pong_received(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.record_pong_received();
        } else {
            // Log at trace level - this can happen during state transitions
            // when a peer is removed before their pong arrives.
            eprintln!(
                "[T205] Liveness: received pong from untracked peer {:?} (ignored)",
                peer_id
            );
        }
    }

    /// Record that a peer missed a heartbeat.
    ///
    /// If the peer is not being tracked, this is a no-op.
    pub fn record_missed_heartbeat(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.record_missed_heartbeat();
        }
    }

    /// Process heartbeat timeouts for all peers.
    ///
    /// For each peer with a timed-out Pong, records a missed heartbeat.
    /// Returns the list of peers that were marked as missing a heartbeat.
    pub fn process_timeouts(&mut self) -> Vec<PeerId> {
        let timed_out = self.peers_with_timeout();
        for peer_id in &timed_out {
            self.record_missed_heartbeat(peer_id);
        }
        timed_out
    }

    /// Get the current liveness score for a peer.
    pub fn score(&self, peer_id: &PeerId) -> Option<u8> {
        self.peers.get(peer_id).map(|state| state.score)
    }

    /// Iterate over all peer states.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &PeerLivenessState)> {
        self.peers.iter()
    }
}

// ============================================================================
// T205: LivenessConfig - Configuration for liveness checks
// ============================================================================

/// Configuration for liveness checks (T205).
#[derive(Clone, Debug)]
pub struct LivenessConfig {
    /// Interval between heartbeat probes (seconds).
    pub probe_interval_secs: u64,

    /// Number of consecutive missed probes before marking unhealthy.
    pub failure_threshold: u8,

    /// Minimum score (0-100) before peer is disconnected.
    pub min_score: u8,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            probe_interval_secs: 30,
            failure_threshold: 3,
            min_score: 30,
        }
    }
}

impl LivenessConfig {
    /// Create a configuration from `NetworkTransportConfig` fields.
    pub fn from_network_config(
        liveness_probe_interval_secs: u64,
        liveness_failure_threshold: u8,
        liveness_min_score: u8,
    ) -> Self {
        Self {
            probe_interval_secs: liveness_probe_interval_secs,
            failure_threshold: liveness_failure_threshold,
            min_score: liveness_min_score,
        }
    }
}

// ============================================================================
// T205: Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_liveness_state_new() {
        let peer_id = PeerId(1);
        let state = PeerLivenessState::new(peer_id);

        assert_eq!(state.peer_id, peer_id);
        assert_eq!(state.score, 80);
        assert_eq!(state.missed_heartbeats, 0);
        assert!(!state.pending_pong);
        assert!(state.last_heartbeat_sent.is_none());
        assert!(state.last_heartbeat_received.is_none());
    }

    #[test]
    fn test_peer_liveness_state_record_ping_sent() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        state.record_ping_sent();

        assert!(state.last_heartbeat_sent.is_some());
        assert!(state.pending_pong);
    }

    #[test]
    fn test_peer_liveness_state_record_pong_received() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        state.record_ping_sent();
        state.record_missed_heartbeat(); // Simulate a missed heartbeat first
        assert_eq!(state.missed_heartbeats, 1);

        state.record_pong_received();

        assert!(state.last_heartbeat_received.is_some());
        assert!(!state.pending_pong);
        assert_eq!(state.missed_heartbeats, 0);
        // Score should increase: 80 - 15 + 5 = 70
        assert_eq!(state.score, 70);
    }

    #[test]
    fn test_peer_liveness_state_score_increase_capped_at_100() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        // Receive many pongs to try to exceed 100
        for _ in 0..10 {
            state.record_pong_received();
        }

        assert_eq!(state.score, 100);
    }

    #[test]
    fn test_peer_liveness_state_score_decrease() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        state.record_missed_heartbeat();
        assert_eq!(state.score, 65); // 80 - 15

        state.record_missed_heartbeat();
        assert_eq!(state.score, 50); // 65 - 15

        state.record_missed_heartbeat();
        assert_eq!(state.score, 35); // 50 - 15
    }

    #[test]
    fn test_peer_liveness_state_score_decrease_saturates() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        // Many missed heartbeats
        for _ in 0..10 {
            state.record_missed_heartbeat();
        }

        assert_eq!(state.score, 0);
    }

    #[test]
    fn test_peer_liveness_state_should_evict_missed_heartbeats() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        // Not evictable initially
        assert!(!state.should_evict(3, 30));

        // Miss heartbeats
        state.record_missed_heartbeat();
        state.record_missed_heartbeat();
        assert!(!state.should_evict(3, 30));

        state.record_missed_heartbeat();
        assert!(state.should_evict(3, 30));

        let reason = state.eviction_reason(3, 30);
        assert_eq!(
            reason,
            Some(EvictionReason::MissedHeartbeats {
                count: 3,
                threshold: 3
            })
        );
    }

    #[test]
    fn test_peer_liveness_state_should_evict_low_score() {
        let peer_id = PeerId(1);
        let mut state = PeerLivenessState::new(peer_id);

        // Decrease score below threshold
        state.score = 25;

        assert!(state.should_evict(3, 30));

        let reason = state.eviction_reason(3, 30);
        assert_eq!(
            reason,
            Some(EvictionReason::LowScore {
                score: 25,
                threshold: 30
            })
        );
    }

    #[test]
    fn test_liveness_manager_add_remove_peer() {
        let config = LivenessConfig::default();
        let mut manager = LivenessManager::new(config);

        let peer_id = PeerId(1);
        manager.add_peer(peer_id);

        assert_eq!(manager.len(), 1);
        assert!(manager.get(&peer_id).is_some());

        let removed = manager.remove_peer(&peer_id);
        assert!(removed.is_some());
        assert!(manager.is_empty());
    }

    #[test]
    fn test_liveness_manager_record_events() {
        let config = LivenessConfig::default();
        let mut manager = LivenessManager::new(config);

        let peer_id = PeerId(1);
        manager.add_peer(peer_id);

        manager.record_ping_sent(&peer_id);
        let state = manager.get(&peer_id).unwrap();
        assert!(state.pending_pong);

        manager.record_pong_received(&peer_id);
        let state = manager.get(&peer_id).unwrap();
        assert!(!state.pending_pong);
        assert_eq!(state.score, 85); // 80 + 5
    }

    #[test]
    fn test_liveness_manager_peers_to_evict() {
        let config = LivenessConfig {
            probe_interval_secs: 30,
            failure_threshold: 2,
            min_score: 30,
        };
        let mut manager = LivenessManager::new(config);

        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        manager.add_peer(peer1);
        manager.add_peer(peer2);

        // peer1: miss 2 heartbeats (threshold)
        manager.record_missed_heartbeat(&peer1);
        manager.record_missed_heartbeat(&peer1);

        // peer2: still healthy
        manager.record_pong_received(&peer2);

        let to_evict = manager.peers_to_evict();
        assert_eq!(to_evict.len(), 1);
        assert_eq!(to_evict[0].0, peer1);
    }

    #[test]
    fn test_liveness_config_default() {
        let config = LivenessConfig::default();

        assert_eq!(config.probe_interval_secs, 30);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.min_score, 30);
    }

    #[test]
    fn test_liveness_config_from_network_config() {
        let config = LivenessConfig::from_network_config(60, 5, 40);

        assert_eq!(config.probe_interval_secs, 60);
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.min_score, 40);
    }

    #[test]
    fn test_eviction_reason_display() {
        let reason1 = EvictionReason::MissedHeartbeats {
            count: 3,
            threshold: 3,
        };
        assert_eq!(
            reason1.to_string(),
            "missed 3 consecutive heartbeats (threshold: 3)"
        );

        let reason2 = EvictionReason::LowScore {
            score: 20,
            threshold: 30,
        };
        assert_eq!(reason2.to_string(), "liveness score 20 below threshold 30");
    }
}
