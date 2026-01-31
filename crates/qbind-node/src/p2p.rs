//! T170: P2P Networking Abstractions
//!
//! This module provides the core abstractions for QBIND's P2P networking layer.
//! It defines node identities, message types, and service traits that will be
//! implemented in future tasks.
//!
//! # Status
//!
//! This is a **skeleton module** created as part of T170 (P2P Networking Design).
//! The traits and types are defined but not yet implemented. They serve as
//! forward-looking abstractions for the TestNet Beta and MainNet P2P stack.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                        │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
//! │  │  Consensus  │  │  DAG/Mempool │  │   Control   │         │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
//! │         │                │                │                 │
//! │         ▼                ▼                ▼                 │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │                   P2pService                        │    │
//! │  │   broadcast() / send_to() / subscribe()             │    │
//! │  └─────────────────────────────────────────────────────┘    │
//! │                           │                                  │
//! └───────────────────────────┼──────────────────────────────────┘
//!                             ▼
//!                    KEMTLS Transport
//! ```
//!
//! # Usage
//!
//! These types are not used in production code yet. They are provided for:
//! - Future implementation reference
//! - Type-safe message routing design
//! - Integration point documentation
//!
//! # See Also
//!
//! - [QBIND P2P Network Design](../../docs/network/QBIND_P2P_NETWORK_DESIGN.md)
//! - [QBIND DAG Mempool Design](../../docs/devnet/QBIND_DAG_MEMPOOL_DESIGN.md)

// ============================================================================
// Node Identity
// ============================================================================

/// A 32-byte node identifier for P2P networking (T170).
///
/// `NodeId` uniquely identifies a node on the P2P network. For validators,
/// this is derived from the network public key and has a 1:1 correspondence
/// with `ValidatorId`. For full nodes, `NodeId` exists without a corresponding
/// validator identity.
///
/// # Derivation
///
/// ```text
/// NodeId = SHA3-256(network_public_key)
/// ```
///
/// # Example
///
/// ```rust
/// use qbind_node::p2p::NodeId;
///
/// // Create a NodeId from raw bytes
/// let bytes = [0u8; 32];
/// let node_id = NodeId::new(bytes);
///
/// // Access the underlying bytes
/// assert_eq!(node_id.as_bytes(), &bytes);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create a new NodeId from raw bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a NodeId from a slice.
    ///
    /// # Panics
    ///
    /// Panics if the slice is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Self(bytes)
    }

    /// Get the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a NodeId with all zeros (useful for testing).
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NodeId({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl From<[u8; 32]> for NodeId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// P2P Message Types
// ============================================================================

/// Consensus network messages for P2P transport (T170, T173).
///
/// This enum wraps the existing consensus message types for P2P transport.
/// Messages are serialized using bincode for wire encoding.
///
/// # Message Types
///
/// - `Proposal`: Block proposals from leaders
/// - `Vote`: Votes for block proposals
/// - `Timeout`: Timeout messages for view-change
/// - `NewView`: New-view messages for view synchronization
///
/// # Wire Format
///
/// Each variant wraps the serialized form of the original wire message
/// to allow efficient encoding/decoding over the P2P layer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ConsensusNetMsg {
    /// A block proposal from a leader.
    /// Contains the serialized `BlockProposal` from `qbind-wire`.
    Proposal(Vec<u8>),

    /// A vote for a block proposal.
    /// Contains the serialized `Vote` from `qbind-wire`.
    Vote(Vec<u8>),

    /// A timeout message for view-change.
    /// Contains the serialized timeout message bytes.
    Timeout(Vec<u8>),

    /// A new-view message for view synchronization.
    /// Contains the serialized new-view message bytes.
    ///
    /// **Note (T173)**: This variant is reserved for future HotStuff view-change
    /// protocol extensions. The current consensus implementation uses direct
    /// timeout broadcast for view synchronization. When full new-view message
    /// support is added to `ConsensusNetworkFacade`, this variant will carry
    /// those messages.
    NewView(Vec<u8>),
}

/// DAG mempool network messages for P2P transport (T170, T173).
///
/// This enum wraps the existing DAG mempool message types for P2P transport.
/// Messages are serialized using bincode for wire encoding.
///
/// # Message Types
///
/// - `Batch`: A batch of transactions created by a validator
/// - `BatchAck`: Acknowledgment of a stored batch
/// - `BatchCertificate`: Availability certificate proving 2f+1 acks
///
/// # Wire Format
///
/// Each variant contains serialized data to allow efficient encoding/decoding.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum DagNetMsg {
    /// A batch of transactions from a validator.
    /// Contains the serialized `QbindBatch` data.
    Batch {
        /// Serialized batch data.
        data: Vec<u8>,
    },

    /// Acknowledgment that a batch has been stored.
    /// Contains the serialized `BatchAck` data.
    BatchAck {
        /// Serialized batch ack data.
        data: Vec<u8>,
    },

    /// Availability certificate proving quorum acknowledgment.
    /// Contains the serialized `BatchCertificate` data.
    BatchCertificate {
        /// Serialized certificate data.
        data: Vec<u8>,
    },
}

/// Control messages for P2P protocol (T170).
///
/// Control messages handle network-level operations like heartbeats,
/// peer discovery, and health checks.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ControlMsg {
    /// Heartbeat message to maintain connection liveness.
    Heartbeat {
        /// Sender's current view (for consensus time synchronization).
        view: u64,
        /// Unix timestamp (milliseconds).
        timestamp_ms: u64,
    },

    /// Peer exchange request.
    ///
    /// Used in TestNet Beta+ for basic peer discovery.
    PeerExchangeRequest {
        /// Maximum number of peers to return.
        max_peers: u32,
    },

    /// Peer exchange response.
    PeerExchangeResponse {
        /// List of known peer addresses.
        peers: Vec<PeerInfo>,
    },
}

/// Information about a peer for discovery (T170).
///
/// This struct contains the minimum information needed to connect to a peer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    /// The peer's NodeId.
    pub node_id: NodeId,
    /// The peer's network address (e.g., "192.168.1.1:9000").
    pub address: String,
    /// Whether the peer is a known validator.
    pub is_validator: bool,
}

/// P2P message wrapper for transport (T170).
///
/// This enum wraps all message types that can be sent over the P2P network.
/// It provides a unified interface for the P2P service to route messages
/// to the appropriate handlers.
///
/// # Stream Mapping
///
/// | Variant | Stream ID | Description |
/// | :--- | :--- | :--- |
/// | `Consensus` | `0x0001` | HotStuff consensus messages |
/// | `Dag` | `0x0002` / `0x0003` | DAG batches and availability |
/// | `Control` | `0x0004` | Heartbeats, peer discovery |
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum P2pMessage {
    /// Consensus messages (proposals, votes, timeouts).
    Consensus(ConsensusNetMsg),
    /// DAG mempool messages (batches, acks, certs).
    Dag(DagNetMsg),
    /// Control messages (heartbeats, discovery).
    Control(ControlMsg),
}

// ============================================================================
// P2P Service Trait
// ============================================================================

/// P2P service trait for network operations (T170).
///
/// This trait defines the interface for sending messages over the P2P network.
/// Implementations will handle routing, multiplexing, and transport.
///
/// # Current Status
///
/// This trait is defined but **not implemented** in T170. It serves as a
/// forward-looking abstraction for TestNet Beta and MainNet.
///
/// # Future Implementation
///
/// Future tasks will provide implementations that:
/// - Route messages to the correct overlay (consensus vs. DAG)
/// - Handle gossip propagation for DAG messages
/// - Provide backpressure and rate limiting
/// - Support subscription for incoming messages
///
/// # Example (Future)
///
/// ```rust,ignore
/// use qbind_node::p2p::{P2pService, P2pMessage, NodeId};
///
/// fn broadcast_proposal(service: &dyn P2pService, proposal: BlockProposal) {
///     let msg = P2pMessage::Consensus(ConsensusNetMsg::Proposal(proposal));
///     service.broadcast(msg);
/// }
/// ```
pub trait P2pService: Send + Sync {
    /// Broadcast a message to all connected peers.
    ///
    /// For consensus messages, this broadcasts to all validators.
    /// For DAG messages, this uses gossip with the configured fanout.
    fn broadcast(&self, msg: P2pMessage);

    /// Send a message to a specific peer.
    ///
    /// Returns without error if the peer is not connected (fire-and-forget).
    /// Connection management is handled separately.
    fn send_to(&self, peer: NodeId, msg: P2pMessage);

    /// Get the local node's NodeId.
    fn local_node_id(&self) -> NodeId;

    /// Get the list of currently connected peers.
    fn connected_peers(&self) -> Vec<NodeId>;

    /// Check if a specific peer is connected.
    fn is_connected(&self, peer: &NodeId) -> bool {
        self.connected_peers().contains(peer)
    }
}

// ============================================================================
// Null Implementation (for testing)
// ============================================================================

/// A no-op P2P service implementation for testing (T170).
///
/// This implementation does nothing and is used when P2P is disabled
/// or for testing components that require a `P2pService` but don't
/// need actual networking.
#[derive(Debug, Default)]
pub struct NullP2pService {
    local_id: NodeId,
}

impl NullP2pService {
    /// Create a new NullP2pService with the given local NodeId.
    pub fn new(local_id: NodeId) -> Self {
        Self { local_id }
    }

    /// Create a NullP2pService with a zero NodeId.
    pub fn zero() -> Self {
        Self {
            local_id: NodeId::zero(),
        }
    }
}

impl P2pService for NullP2pService {
    fn broadcast(&self, _msg: P2pMessage) {
        // No-op: messages are dropped
    }

    fn send_to(&self, _peer: NodeId, _msg: P2pMessage) {
        // No-op: messages are dropped
    }

    fn local_node_id(&self) -> NodeId {
        self.local_id
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        Vec::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_new() {
        let bytes = [42u8; 32];
        let node_id = NodeId::new(bytes);
        assert_eq!(node_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_node_id_from_slice() {
        let bytes = [1u8; 32];
        let node_id = NodeId::from_slice(&bytes);
        assert_eq!(node_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_node_id_zero() {
        let zero = NodeId::zero();
        assert_eq!(zero.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_node_id_display() {
        let bytes = [0xAB; 32];
        let node_id = NodeId::new(bytes);
        let display = format!("{}", node_id);
        assert!(display.contains("abababab")); // First 8 bytes hex
    }

    #[test]
    fn test_node_id_debug() {
        let bytes = [0xCD; 32];
        let node_id = NodeId::new(bytes);
        let debug = format!("{:?}", node_id);
        assert!(debug.contains("NodeId"));
        assert!(debug.contains("cdcdcdcd")); // First 8 bytes hex
    }

    #[test]
    fn test_node_id_from_array() {
        let bytes: [u8; 32] = [0xFF; 32];
        let node_id: NodeId = bytes.into();
        assert_eq!(node_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_node_id_equality() {
        let a = NodeId::new([1u8; 32]);
        let b = NodeId::new([1u8; 32]);
        let c = NodeId::new([2u8; 32]);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_node_id_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(NodeId::new([1u8; 32]));
        set.insert(NodeId::new([2u8; 32]));
        set.insert(NodeId::new([1u8; 32])); // Duplicate

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_p2p_message_variants() {
        let _consensus = P2pMessage::Consensus(ConsensusNetMsg::Vote(vec![1, 2, 3]));
        let _dag = P2pMessage::Dag(DagNetMsg::Batch {
            data: vec![4, 5, 6],
        });
        let _control = P2pMessage::Control(ControlMsg::Heartbeat {
            view: 1,
            timestamp_ms: 1234567890,
        });
    }

    #[test]
    fn test_control_msg_heartbeat() {
        let msg = ControlMsg::Heartbeat {
            view: 42,
            timestamp_ms: 1000,
        };
        if let ControlMsg::Heartbeat { view, timestamp_ms } = msg {
            assert_eq!(view, 42);
            assert_eq!(timestamp_ms, 1000);
        } else {
            panic!("Expected Heartbeat");
        }
    }

    #[test]
    fn test_peer_info() {
        let info = PeerInfo {
            node_id: NodeId::new([1u8; 32]),
            address: "192.168.1.1:9000".to_string(),
            is_validator: true,
        };

        assert!(info.is_validator);
        assert_eq!(info.address, "192.168.1.1:9000");
    }

    #[test]
    fn test_null_p2p_service() {
        let service = NullP2pService::zero();

        // Should not panic
        service.broadcast(P2pMessage::Dag(DagNetMsg::Batch { data: vec![] }));
        service.send_to(
            NodeId::zero(),
            P2pMessage::Dag(DagNetMsg::BatchAck { data: vec![] }),
        );

        // Should return zero NodeId
        assert_eq!(service.local_node_id(), NodeId::zero());

        // Should return empty peers
        assert!(service.connected_peers().is_empty());
        assert!(!service.is_connected(&NodeId::zero()));
    }

    #[test]
    fn test_null_p2p_service_with_custom_id() {
        let local_id = NodeId::new([0x42; 32]);
        let service = NullP2pService::new(local_id);

        assert_eq!(service.local_node_id(), local_id);
    }
}
