//! T173: P2P-backed consensus network implementation.
//!
//! This module provides `P2pConsensusNetwork`, a `ConsensusNetworkFacade` implementation
//! that uses `P2pService` (via `TcpKemTlsP2pService`) to send consensus messages.
//!
//! # Design (T173)
//!
//! The P2P consensus network maps existing consensus message types to `P2pMessage::Consensus`
//! variants and sends them via the P2P service:
//!
//! - `broadcast_proposal()` → `P2pMessage::Consensus(ConsensusNetMsg::Proposal(...))`
//! - `broadcast_vote()` → `P2pMessage::Consensus(ConsensusNetMsg::Vote(...))`
//! - `send_vote_to()` → Directed send to specific peer
//! - `send_timeout_msg()` → `P2pMessage::Consensus(ConsensusNetMsg::Timeout(...))`
//!
//! # Validator-to-NodeId Mapping
//!
//! The consensus layer uses `ValidatorId` for addressing, but the P2P layer uses `NodeId`.
//! This module provides a mapping layer via `ValidatorNodeMapping` trait.
//!
//! For simple deployments (T173), an identity mapping is used where `ValidatorId(n)` maps
//! to a `NodeId` derived from the validator's index.
//!
//! # Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use qbind_node::consensus_net_p2p::P2pConsensusNetwork;
//! use qbind_node::p2p::P2pService;
//!
//! let p2p_service: Arc<dyn P2pService> = /* ... */;
//! let num_validators = 4;
//! let network = P2pConsensusNetwork::new(p2p_service, num_validators);
//!
//! // Use with NodeHotstuffHarness
//! let harness = NodeHotstuffHarness::new(/* ... */)
//!     .with_net_facade(Box::new(network));
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::consensus_network_facade::ConsensusNetworkFacade;
use crate::p2p::{ConsensusNetMsg, NodeId, P2pMessage, P2pService};
use crate::peer::PeerId;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_wire::consensus::{BlockProposal, Vote};
use qbind_wire::io::WireEncode;

// ============================================================================
// ValidatorNodeMapping - Maps ValidatorId to NodeId for P2P
// ============================================================================

/// Trait for mapping ValidatorId to NodeId in P2P networking.
///
/// The consensus layer uses `ValidatorId` for addressing validators, but the
/// P2P layer uses `NodeId` (derived from network public keys). This trait
/// bridges the two addressing schemes.
pub trait ValidatorNodeMapping: Send + Sync {
    /// Get the NodeId for a ValidatorId.
    ///
    /// Returns `None` if the validator is not known.
    fn get_node_id(&self, validator_id: ValidatorId) -> Option<NodeId>;

    /// Get the ValidatorId for a NodeId.
    ///
    /// Returns `None` if the node is not a known validator.
    fn get_validator_id(&self, node_id: NodeId) -> Option<ValidatorId>;

    /// Get all known validator-node mappings.
    fn all_validators(&self) -> Vec<(ValidatorId, NodeId)>;
}

/// Simple identity mapping where ValidatorId(n) <-> NodeId from seed.
///
/// This mapping creates deterministic NodeIds from validator indices by
/// padding the validator index into a 32-byte array.
///
/// **Note**: This is suitable for testing and simple deployments. Production
/// systems should derive NodeIds from actual network public keys.
#[derive(Debug, Clone, Default)]
pub struct SimpleValidatorNodeMapping {
    /// Mapping from ValidatorId to NodeId.
    validator_to_node: HashMap<ValidatorId, NodeId>,
    /// Reverse mapping from NodeId to ValidatorId.
    node_to_validator: HashMap<NodeId, ValidatorId>,
}

impl SimpleValidatorNodeMapping {
    /// Create a new simple mapping with the given validator count.
    ///
    /// Creates deterministic NodeIds for validators 0..n by using
    /// the validator index as a seed.
    pub fn new(num_validators: usize) -> Self {
        let mut validator_to_node = HashMap::new();
        let mut node_to_validator = HashMap::new();

        for i in 0..num_validators {
            let validator_id = ValidatorId::new(i as u64);
            let node_id = Self::node_id_from_validator_index(i);

            validator_to_node.insert(validator_id, node_id);
            node_to_validator.insert(node_id, validator_id);
        }

        Self {
            validator_to_node,
            node_to_validator,
        }
    }

    /// Derive a NodeId from a validator index (for testing/simple deployments).
    fn node_id_from_validator_index(index: usize) -> NodeId {
        let mut bytes = [0u8; 32];
        let index_bytes = (index as u64).to_le_bytes();
        bytes[..8].copy_from_slice(&index_bytes);
        NodeId::new(bytes)
    }

    /// Add a specific validator-node mapping.
    pub fn add_mapping(&mut self, validator_id: ValidatorId, node_id: NodeId) {
        self.validator_to_node.insert(validator_id, node_id);
        self.node_to_validator.insert(node_id, validator_id);
    }
}

impl ValidatorNodeMapping for SimpleValidatorNodeMapping {
    fn get_node_id(&self, validator_id: ValidatorId) -> Option<NodeId> {
        self.validator_to_node.get(&validator_id).copied()
    }

    fn get_validator_id(&self, node_id: NodeId) -> Option<ValidatorId> {
        self.node_to_validator.get(&node_id).copied()
    }

    fn all_validators(&self) -> Vec<(ValidatorId, NodeId)> {
        self.validator_to_node
            .iter()
            .map(|(&v, &n)| (v, n))
            .collect()
    }
}

// ============================================================================
// P2pConsensusNetwork - P2P-backed ConsensusNetworkFacade
// ============================================================================

/// P2P-backed consensus network implementation (T173).
///
/// This struct implements `ConsensusNetworkFacade` using `P2pService` for
/// message transport. It wraps consensus messages (proposals, votes, timeouts)
/// in `P2pMessage::Consensus` variants and sends them via the P2P layer.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and uses interior mutability via `Arc` and
/// `RwLock` for the mapping.
///
/// # Metrics
///
/// Message sends increment P2P metrics counters for observability.
pub struct P2pConsensusNetwork {
    /// The underlying P2P service for message transport.
    p2p: Arc<dyn P2pService>,
    /// Mapping from ValidatorId to NodeId.
    mapping: Arc<RwLock<Box<dyn ValidatorNodeMapping>>>,
    /// Local validator ID (if this node is a validator).
    local_validator_id: Option<ValidatorId>,
}

impl std::fmt::Debug for P2pConsensusNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pConsensusNetwork")
            .field("p2p", &"<Arc<dyn P2pService>>")
            .field("local_validator_id", &self.local_validator_id)
            .finish()
    }
}

impl P2pConsensusNetwork {
    /// Create a new P2P consensus network with the given P2P service.
    ///
    /// Uses a simple identity mapping for validators.
    ///
    /// # Arguments
    ///
    /// * `p2p` - The P2P service for message transport
    /// * `num_validators` - Number of validators in the network
    pub fn new(p2p: Arc<dyn P2pService>, num_validators: usize) -> Self {
        Self {
            p2p,
            mapping: Arc::new(RwLock::new(Box::new(SimpleValidatorNodeMapping::new(
                num_validators,
            )))),
            local_validator_id: None,
        }
    }

    /// Create a new P2P consensus network with a custom validator mapping.
    ///
    /// # Arguments
    ///
    /// * `p2p` - The P2P service for message transport
    /// * `mapping` - Custom validator-to-node mapping
    pub fn with_mapping(p2p: Arc<dyn P2pService>, mapping: Box<dyn ValidatorNodeMapping>) -> Self {
        Self {
            p2p,
            mapping: Arc::new(RwLock::new(mapping)),
            local_validator_id: None,
        }
    }

    /// Set the local validator ID.
    ///
    /// This is used to filter out messages sent to self.
    pub fn with_local_validator(mut self, validator_id: ValidatorId) -> Self {
        self.local_validator_id = Some(validator_id);
        self
    }

    /// Get the local NodeId from the P2P service.
    pub fn local_node_id(&self) -> NodeId {
        self.p2p.local_node_id()
    }

    /// Get the list of connected peer NodeIds.
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.p2p.connected_peers()
    }

    /// Encode a vote to wire format for P2P transport.
    fn encode_vote(vote: &Vote) -> Vec<u8> {
        let mut out = Vec::new();
        vote.encode(&mut out);
        out
    }

    /// Encode a proposal to wire format for P2P transport.
    fn encode_proposal(proposal: &BlockProposal) -> Vec<u8> {
        let mut out = Vec::new();
        proposal.encode(&mut out);
        out
    }

    /// Get the NodeId for a ValidatorId.
    fn get_node_id(&self, validator_id: ValidatorId) -> Option<NodeId> {
        self.mapping.read().get_node_id(validator_id)
    }
}

impl ConsensusNetworkFacade for P2pConsensusNetwork {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        let node_id = self
            .get_node_id(target)
            .ok_or_else(|| NetworkError::Other(format!("no NodeId for validator {:?}", target)))?;

        let encoded = Self::encode_vote(vote);
        let msg = P2pMessage::Consensus(ConsensusNetMsg::Vote(encoded));

        self.p2p.send_to(node_id, msg);

        Ok(())
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        let encoded = Self::encode_vote(vote);
        let msg = P2pMessage::Consensus(ConsensusNetMsg::Vote(encoded));

        self.p2p.broadcast(msg);

        Ok(())
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let encoded = Self::encode_proposal(proposal);
        let msg = P2pMessage::Consensus(ConsensusNetMsg::Proposal(encoded));

        self.p2p.broadcast(msg);

        Ok(())
    }

    fn send_timeout_msg(&self, _target: PeerId, msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        // For T173, broadcast timeout messages to all peers.
        // Future versions may add directed timeout sends.
        let msg = P2pMessage::Consensus(ConsensusNetMsg::Timeout(msg_bytes));

        self.p2p.broadcast(msg);

        Ok(())
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::NullP2pService;

    #[test]
    fn test_simple_validator_node_mapping() {
        let mapping = SimpleValidatorNodeMapping::new(4);

        // Check forward mapping
        let v0 = ValidatorId::new(0);
        let v1 = ValidatorId::new(1);
        let v3 = ValidatorId::new(3);

        assert!(mapping.get_node_id(v0).is_some());
        assert!(mapping.get_node_id(v1).is_some());
        assert!(mapping.get_node_id(v3).is_some());

        // Different validators should have different NodeIds
        let n0 = mapping.get_node_id(v0).unwrap();
        let n1 = mapping.get_node_id(v1).unwrap();
        assert_ne!(n0, n1);

        // Check reverse mapping
        assert_eq!(mapping.get_validator_id(n0), Some(v0));
        assert_eq!(mapping.get_validator_id(n1), Some(v1));

        // Unknown validator should return None
        let unknown = ValidatorId::new(100);
        assert!(mapping.get_node_id(unknown).is_none());
    }

    #[test]
    fn test_p2p_consensus_network_creation() {
        let p2p = Arc::new(NullP2pService::zero());
        let network = P2pConsensusNetwork::new(p2p.clone(), 4);

        assert_eq!(network.local_node_id(), NodeId::zero());
        assert!(network.connected_peers().is_empty());
    }

    #[test]
    fn test_p2p_consensus_network_with_local_validator() {
        let p2p = Arc::new(NullP2pService::zero());
        let network = P2pConsensusNetwork::new(p2p, 4).with_local_validator(ValidatorId::new(0));

        assert_eq!(network.local_validator_id, Some(ValidatorId::new(0)));
    }

    #[test]
    fn test_p2p_consensus_network_broadcast_vote() {
        let p2p = Arc::new(NullP2pService::zero());
        let network = P2pConsensusNetwork::new(p2p, 4);

        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 1,
            round: 0,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            suite_id: 0,
            signature: vec![],
        };

        // Should succeed (null service drops the message)
        let result = network.broadcast_vote(&vote);
        assert!(result.is_ok());
    }

    #[test]
    fn test_p2p_consensus_network_broadcast_proposal() {
        let p2p = Arc::new(NullP2pService::zero());
        let network = P2pConsensusNetwork::new(p2p, 4);

        let proposal = BlockProposal {
            header: qbind_wire::consensus::BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height: 1,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                suite_id: 0,
                tx_count: 0,
                timestamp: 0,
                payload_kind: 0,
                next_epoch: 0,
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        };

        // Should succeed (null service drops the message)
        let result = network.broadcast_proposal(&proposal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_p2p_consensus_network_send_vote_to() {
        let p2p = Arc::new(NullP2pService::zero());
        let network = P2pConsensusNetwork::new(p2p, 4);

        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 1,
            round: 0,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            suite_id: 0,
            signature: vec![],
        };

        // Send to known validator should succeed
        let result = network.send_vote_to(ValidatorId::new(1), &vote);
        assert!(result.is_ok());

        // Send to unknown validator should fail
        let result = network.send_vote_to(ValidatorId::new(100), &vote);
        assert!(result.is_err());
    }

    #[test]
    fn test_p2p_consensus_network_send_timeout() {
        let p2p = Arc::new(NullP2pService::zero());
        let network = P2pConsensusNetwork::new(p2p, 4);

        let timeout_bytes = vec![1, 2, 3, 4];

        // Should succeed (broadcasts to all peers)
        let result = network.send_timeout_msg(PeerId(0), timeout_bytes);
        assert!(result.is_ok());
    }
}