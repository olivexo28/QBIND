//! T205: P2P Dynamic Peer Discovery Manager
//!
//! This module provides the peer discovery subsystem for QBIND's P2P layer.
//! It manages a view of known peers, exchanges peer lists with connected peers,
//! and attempts to maintain a healthy peer set beyond static bootstrap peers.
//!
//! # Overview
//!
//! The Discovery Manager:
//!
//! - Maintains a `PeerTable` of known peers with metadata
//! - Periodically exchanges peer lists with connected peers
//! - Seeds from bootstrap peers and grows knowledge via gossip
//! - Enforces caps on known peers to avoid unbounded memory
//! - Selects candidates for outbound connections when below target
//!
//! # Integration
//!
//! The Discovery Manager integrates with the Liveness Manager through:
//! - Backfill requests when evicted peers need replacement
//! - Score updates from liveness probes
//!
//! # Wire Format
//!
//! Uses `PeerInfo` and `PeerList` messages from `qbind-wire::net` for
//! peer list exchange over existing KEMTLS-secured channels.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::p2p::NodeId;

// ============================================================================
// T205: PeerSource - Origin of peer knowledge
// ============================================================================

/// The source from which a peer was discovered (T205).
///
/// This enum tracks how we learned about a peer, which affects
/// eviction priority and connection behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSource {
    /// Peer was specified as a bootstrap peer in config.
    /// Bootstrap peers are never evicted and always reconnected.
    Bootstrap,

    /// Peer was specified in static config.
    /// Static peers are preferred over discovered peers.
    StaticConfig,

    /// Peer was discovered via peer list exchange.
    /// Discovered peers are evicted first when at capacity.
    Discovered,
}

// ============================================================================
// T205: PeerEntry - Individual peer metadata
// ============================================================================

/// Metadata about a known peer (T205).
///
/// This struct tracks all information about a peer needed for
/// connection management and eviction decisions.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    /// The peer's node identifier.
    pub peer_id: NodeId,

    /// The peer's network address (e.g., "192.168.1.1:9000").
    pub address: String,

    /// When we last saw this peer (either via message or peer list).
    pub last_seen: Instant,

    /// Liveness score (0-100). Updated by LivenessManager.
    /// Initial score is 80 for new peers.
    pub score: u8,

    /// How we learned about this peer.
    pub source: PeerSource,

    /// Whether we are currently connected to this peer.
    pub connected: bool,

    /// Number of consecutive connection failures.
    /// Reset to 0 on successful connection.
    pub connection_failures: u8,

    /// When we last attempted to connect to this peer.
    pub last_connection_attempt: Option<Instant>,
}

impl PeerEntry {
    /// Create a new peer entry with initial values.
    pub fn new(peer_id: NodeId, address: String, source: PeerSource) -> Self {
        Self {
            peer_id,
            address,
            last_seen: Instant::now(),
            score: 80, // Initial score for new peers
            source,
            connected: false,
            connection_failures: 0,
            last_connection_attempt: None,
        }
    }

    /// Check if this peer can be evicted.
    ///
    /// Bootstrap and static config peers cannot be evicted.
    pub fn can_evict(&self) -> bool {
        matches!(self.source, PeerSource::Discovered) && !self.connected
    }

    /// Check if this peer is eligible for connection attempt.
    ///
    /// A peer is eligible if:
    /// - Not currently connected
    /// - Has not failed too many times recently
    /// - Enough time has passed since last attempt (backoff)
    pub fn is_connection_candidate(&self, backoff_base: Duration) -> bool {
        if self.connected {
            return false;
        }

        // Check backoff based on failure count
        if let Some(last_attempt) = self.last_connection_attempt {
            let backoff = backoff_base * 2u32.pow(self.connection_failures.min(5) as u32);
            if last_attempt.elapsed() < backoff {
                return false;
            }
        }

        // Don't retry peers that have failed too many times
        self.connection_failures < 10
    }

    /// Record a connection attempt.
    pub fn record_connection_attempt(&mut self) {
        self.last_connection_attempt = Some(Instant::now());
    }

    /// Record a successful connection.
    pub fn record_connection_success(&mut self) {
        self.connected = true;
        self.connection_failures = 0;
        self.last_seen = Instant::now();
    }

    /// Record a connection failure.
    pub fn record_connection_failure(&mut self) {
        self.connected = false;
        self.connection_failures = self.connection_failures.saturating_add(1);
    }

    /// Record disconnection.
    pub fn record_disconnect(&mut self) {
        self.connected = false;
    }

    /// Update the peer's last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

// ============================================================================
// T205: PeerTable - Core data structure for peer management
// ============================================================================

/// A table of known peers for discovery (T205).
///
/// The `PeerTable` is the core data structure for peer discovery. It:
///
/// - Tracks all known peers with their metadata
/// - Enforces the `max_known_peers` cap
/// - Provides candidate selection for outbound connections
/// - Handles duplicate detection and updates
///
/// # Thread Safety
///
/// `PeerTable` is not internally synchronized. For async contexts,
/// wrap it in `Arc<Mutex<PeerTable>>` or use message passing.
pub struct PeerTable {
    /// Map from peer_id to peer entry.
    peers: HashMap<NodeId, PeerEntry>,

    /// Maximum number of peers to track.
    max_known_peers: usize,
}

impl PeerTable {
    /// Create a new peer table with the given capacity limit.
    pub fn new(max_known_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_known_peers,
        }
    }

    /// Return the number of peers in the table.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Return true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Return the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.peers.values().filter(|p| p.connected).count()
    }

    /// Insert or update a peer in the table.
    ///
    /// If the peer already exists, updates `last_seen` and potentially
    /// upgrades the source (e.g., Discovered → StaticConfig).
    ///
    /// If the table is at capacity and the peer is new, attempts to
    /// evict the lowest-priority peer to make room.
    ///
    /// Returns `true` if the peer was added (new peer), `false` if updated
    /// or if insertion failed (e.g., empty address for new peer).
    pub fn insert(&mut self, peer_id: NodeId, address: String, source: PeerSource) -> bool {
        if let Some(existing) = self.peers.get_mut(&peer_id) {
            // Update existing peer
            existing.touch();
            // Update address if the new address is non-empty and different
            if !address.is_empty() && existing.address != address {
                existing.address = address;
            }
            // Upgrade source if the new source is more authoritative
            if source_priority(source) > source_priority(existing.source) {
                existing.source = source;
            }
            return false;
        }

        // Reject new peers with empty addresses
        if address.is_empty() {
            return false;
        }

        // Check capacity and evict if needed
        if self.peers.len() >= self.max_known_peers {
            if !self.evict_one() {
                // Cannot evict anyone, table is full
                return false;
            }
        }

        // Insert new peer
        let entry = PeerEntry::new(peer_id, address, source);
        self.peers.insert(peer_id, entry);
        true
    }

    /// Remove a peer from the table.
    ///
    /// Returns the removed entry if it existed.
    pub fn remove(&mut self, peer_id: &NodeId) -> Option<PeerEntry> {
        self.peers.remove(peer_id)
    }

    /// Get a reference to a peer entry.
    pub fn get(&self, peer_id: &NodeId) -> Option<&PeerEntry> {
        self.peers.get(peer_id)
    }

    /// Get a mutable reference to a peer entry.
    pub fn get_mut(&mut self, peer_id: &NodeId) -> Option<&mut PeerEntry> {
        self.peers.get_mut(peer_id)
    }

    /// Check if a peer exists in the table.
    pub fn contains(&self, peer_id: &NodeId) -> bool {
        self.peers.contains_key(peer_id)
    }

    /// Iterate over all peers.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &PeerEntry)> {
        self.peers.iter()
    }

    /// Select candidates for outbound connection.
    ///
    /// Returns up to `count` peers that are:
    /// - Not currently connected
    /// - Eligible for connection attempt (backoff passed)
    /// - Sorted by priority (bootstrap first, then static, then discovered)
    pub fn select_candidates(&self, count: usize, backoff_base: Duration) -> Vec<NodeId> {
        let mut candidates: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, entry)| entry.is_connection_candidate(backoff_base))
            .collect();

        // Sort by priority: bootstrap > static > discovered, then by score
        candidates.sort_by(|(_, a), (_, b)| {
            // Higher priority sources first
            let source_cmp = source_priority(b.source).cmp(&source_priority(a.source));
            if source_cmp != std::cmp::Ordering::Equal {
                return source_cmp;
            }
            // Higher score first
            b.score.cmp(&a.score)
        });

        candidates
            .into_iter()
            .take(count)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get a random sample of peers for exchange.
    ///
    /// Returns up to `count` peers, preferring connected peers
    /// and excluding peers with low scores.
    pub fn sample_for_exchange(&self, count: usize) -> Vec<(&NodeId, &PeerEntry)> {
        let mut candidates: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, entry)| entry.score >= 30) // Exclude low-score peers
            .collect();

        // Sort by: connected first, then by last_seen
        candidates.sort_by(|(_, a), (_, b)| {
            // Connected first
            if a.connected != b.connected {
                return b.connected.cmp(&a.connected);
            }
            // More recent first (larger Instant = more recent)
            b.last_seen.cmp(&a.last_seen)
        });

        candidates.into_iter().take(count).collect()
    }

    /// Evict one peer to make room for a new entry.
    ///
    /// Returns `true` if a peer was evicted.
    fn evict_one(&mut self) -> bool {
        // Find the best candidate for eviction:
        // - Must be evictable (discovered, not connected)
        // - Prefer lowest score
        // - Then oldest last_seen
        let evict_id = self
            .peers
            .iter()
            .filter(|(_, entry)| entry.can_evict())
            .min_by(|(_, a), (_, b)| {
                // Lowest score first
                let score_cmp = a.score.cmp(&b.score);
                if score_cmp != std::cmp::Ordering::Equal {
                    return score_cmp;
                }
                // Oldest first
                b.last_seen.cmp(&a.last_seen)
            })
            .map(|(id, _)| *id);

        if let Some(id) = evict_id {
            self.peers.remove(&id);
            true
        } else {
            false
        }
    }
}

/// Get the priority of a peer source (higher = more authoritative).
fn source_priority(source: PeerSource) -> u8 {
    match source {
        PeerSource::Bootstrap => 2,
        PeerSource::StaticConfig => 1,
        PeerSource::Discovered => 0,
    }
}

// ============================================================================
// T205: DiscoveryConfig - Discovery configuration
// ============================================================================

/// Configuration for the Discovery Manager (T205).
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Whether discovery is enabled.
    pub enabled: bool,

    /// Interval between discovery exchanges (seconds).
    pub interval_secs: u64,

    /// Maximum number of known peers to track.
    pub max_known_peers: u32,

    /// Target number of outbound connections.
    pub target_outbound_peers: u32,

    /// Base backoff duration for connection retries.
    pub backoff_base: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            max_known_peers: 200,
            target_outbound_peers: 8,
            backoff_base: Duration::from_secs(5),
        }
    }
}

impl DiscoveryConfig {
    /// Create a configuration from `NetworkTransportConfig` fields.
    pub fn from_network_config(
        discovery_enabled: bool,
        discovery_interval_secs: u64,
        max_known_peers: u32,
        target_outbound_peers: u32,
    ) -> Self {
        Self {
            enabled: discovery_enabled,
            interval_secs: discovery_interval_secs,
            max_known_peers,
            target_outbound_peers,
            backoff_base: Duration::from_secs(5),
        }
    }
}

// ============================================================================
// T205: Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(seed: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NodeId::new(bytes)
    }

    #[test]
    fn test_peer_entry_new() {
        let peer_id = make_node_id(1);
        let entry = PeerEntry::new(
            peer_id,
            "127.0.0.1:9000".to_string(),
            PeerSource::Discovered,
        );

        assert_eq!(entry.peer_id, peer_id);
        assert_eq!(entry.address, "127.0.0.1:9000");
        assert_eq!(entry.score, 80);
        assert_eq!(entry.source, PeerSource::Discovered);
        assert!(!entry.connected);
        assert_eq!(entry.connection_failures, 0);
    }

    #[test]
    fn test_peer_entry_can_evict() {
        let peer_id = make_node_id(1);

        // Discovered peers can be evicted
        let mut entry = PeerEntry::new(
            peer_id,
            "127.0.0.1:9000".to_string(),
            PeerSource::Discovered,
        );
        assert!(entry.can_evict());

        // Connected peers cannot be evicted
        entry.connected = true;
        assert!(!entry.can_evict());

        // Bootstrap peers cannot be evicted
        let bootstrap =
            PeerEntry::new(peer_id, "127.0.0.1:9000".to_string(), PeerSource::Bootstrap);
        assert!(!bootstrap.can_evict());

        // Static config peers cannot be evicted
        let static_peer = PeerEntry::new(
            peer_id,
            "127.0.0.1:9000".to_string(),
            PeerSource::StaticConfig,
        );
        assert!(!static_peer.can_evict());
    }

    #[test]
    fn test_peer_entry_connection_tracking() {
        let peer_id = make_node_id(1);
        let mut entry = PeerEntry::new(
            peer_id,
            "127.0.0.1:9000".to_string(),
            PeerSource::Discovered,
        );

        // Initial state
        assert!(!entry.connected);
        assert_eq!(entry.connection_failures, 0);

        // Record failure
        entry.record_connection_failure();
        assert!(!entry.connected);
        assert_eq!(entry.connection_failures, 1);

        // Record success resets failures
        entry.record_connection_success();
        assert!(entry.connected);
        assert_eq!(entry.connection_failures, 0);

        // Record disconnect
        entry.record_disconnect();
        assert!(!entry.connected);
    }

    #[test]
    fn test_peer_table_insert() {
        let mut table = PeerTable::new(10);

        let peer1 = make_node_id(1);
        let peer2 = make_node_id(2);

        // Insert new peer returns true
        assert!(table.insert(peer1, "127.0.0.1:9001".to_string(), PeerSource::Discovered));
        assert_eq!(table.len(), 1);

        // Insert same peer returns false (update)
        assert!(!table.insert(peer1, "127.0.0.1:9001".to_string(), PeerSource::Discovered));
        assert_eq!(table.len(), 1);

        // Insert different peer returns true
        assert!(table.insert(peer2, "127.0.0.1:9002".to_string(), PeerSource::Discovered));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_peer_table_max_known_peers() {
        let mut table = PeerTable::new(3);

        // Insert 3 peers
        for i in 0..3 {
            let peer_id = make_node_id(i);
            assert!(table.insert(
                peer_id,
                format!("127.0.0.1:900{}", i),
                PeerSource::Discovered
            ));
        }
        assert_eq!(table.len(), 3);

        // Insert 4th peer should evict one
        let peer4 = make_node_id(4);
        assert!(table.insert(peer4, "127.0.0.1:9004".to_string(), PeerSource::Discovered));
        assert_eq!(table.len(), 3);
        assert!(table.contains(&peer4));
    }

    #[test]
    fn test_peer_table_no_evict_bootstrap() {
        let mut table = PeerTable::new(2);

        // Fill with bootstrap peers
        let bootstrap1 = make_node_id(1);
        let bootstrap2 = make_node_id(2);
        table.insert(
            bootstrap1,
            "127.0.0.1:9001".to_string(),
            PeerSource::Bootstrap,
        );
        table.insert(
            bootstrap2,
            "127.0.0.1:9002".to_string(),
            PeerSource::Bootstrap,
        );

        // Cannot insert another peer (bootstrap peers are not evictable)
        let peer3 = make_node_id(3);
        assert!(!table.insert(peer3, "127.0.0.1:9003".to_string(), PeerSource::Discovered));
        assert_eq!(table.len(), 2);
        assert!(!table.contains(&peer3));
    }

    #[test]
    fn test_peer_table_select_candidates() {
        let mut table = PeerTable::new(10);

        // Add some peers
        let peer1 = make_node_id(1);
        let peer2 = make_node_id(2);
        let peer3 = make_node_id(3);

        table.insert(peer1, "127.0.0.1:9001".to_string(), PeerSource::Bootstrap);
        table.insert(peer2, "127.0.0.1:9002".to_string(), PeerSource::Discovered);
        table.insert(
            peer3,
            "127.0.0.1:9003".to_string(),
            PeerSource::StaticConfig,
        );

        let backoff = Duration::from_secs(1);
        let candidates = table.select_candidates(10, backoff);

        // All should be candidates (none connected)
        assert_eq!(candidates.len(), 3);

        // Bootstrap should be first
        assert_eq!(candidates[0], peer1);
        // Static config second
        assert_eq!(candidates[1], peer3);
        // Discovered last
        assert_eq!(candidates[2], peer2);
    }

    #[test]
    fn test_peer_table_select_candidates_excludes_connected() {
        let mut table = PeerTable::new(10);

        let peer1 = make_node_id(1);
        let peer2 = make_node_id(2);

        table.insert(peer1, "127.0.0.1:9001".to_string(), PeerSource::Discovered);
        table.insert(peer2, "127.0.0.1:9002".to_string(), PeerSource::Discovered);

        // Mark peer1 as connected
        if let Some(entry) = table.get_mut(&peer1) {
            entry.record_connection_success();
        }

        let backoff = Duration::from_secs(1);
        let candidates = table.select_candidates(10, backoff);

        // Only peer2 should be a candidate
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], peer2);
    }

    #[test]
    fn test_peer_table_source_upgrade() {
        let mut table = PeerTable::new(10);

        let peer_id = make_node_id(1);

        // Insert as discovered
        table.insert(
            peer_id,
            "127.0.0.1:9001".to_string(),
            PeerSource::Discovered,
        );
        assert_eq!(table.get(&peer_id).unwrap().source, PeerSource::Discovered);

        // Upgrade to static config
        table.insert(
            peer_id,
            "127.0.0.1:9001".to_string(),
            PeerSource::StaticConfig,
        );
        assert_eq!(
            table.get(&peer_id).unwrap().source,
            PeerSource::StaticConfig
        );

        // Cannot downgrade
        table.insert(
            peer_id,
            "127.0.0.1:9001".to_string(),
            PeerSource::Discovered,
        );
        assert_eq!(
            table.get(&peer_id).unwrap().source,
            PeerSource::StaticConfig
        );
    }

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();

        assert!(config.enabled);
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.max_known_peers, 200);
        assert_eq!(config.target_outbound_peers, 8);
    }

    #[test]
    fn test_discovery_config_from_network_config() {
        let config = DiscoveryConfig::from_network_config(true, 60, 300, 16);

        assert!(config.enabled);
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.max_known_peers, 300);
        assert_eq!(config.target_outbound_peers, 16);
    }

    #[test]
    fn test_peer_table_rejects_empty_address() {
        let mut table = PeerTable::new(10);

        let peer_id = make_node_id(1);

        // Empty address for new peer should be rejected
        assert!(!table.insert(peer_id, "".to_string(), PeerSource::Discovered));
        assert!(table.is_empty());

        // But existing peer can be updated with non-empty address
        assert!(table.insert(
            peer_id,
            "127.0.0.1:9001".to_string(),
            PeerSource::Discovered
        ));
        assert_eq!(table.len(), 1);

        // Updating with empty address doesn't change the address
        assert!(!table.insert(peer_id, "".to_string(), PeerSource::Discovered));
        assert_eq!(table.get(&peer_id).unwrap().address, "127.0.0.1:9001");
    }
}
