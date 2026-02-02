//! Unified network interface for the consensus harness (T96, T96.1).
//!
//! This module provides `ConsensusNetworkFacade`, a trait that abstracts the
//! **outbound** network operations that `NodeHotstuffHarness` needs. This is the
//! **only** network interface the harness uses for sending votes and proposals.
//!
//! # Design (T96, T96.1)
//!
//! The goal is to collapse the "two worlds":
//! - Legacy blocking network path (`ConsensusNetAdapter` + `PeerManager`)
//! - Async network path (`AsyncPeerManagerImpl` + `ConsensusNetWorker`)
//!
//! Both implementations implement `ConsensusNetworkFacade`, allowing the harness
//! to use either without modification. The harness itself does not directly
//! reference `ConsensusNetAdapter` - all network concerns are hidden behind
//! either the facade (for outbound) or `ConsensusNode::with_consensus_network()`
//! (for inbound).
//!
//! # Implementations
//!
//! - `BlockingNetworkFacade`: Wraps `Arc<Mutex<PeerManager>>` for the legacy
//!   blocking network path. Production use case for synchronous networking.
//!
//! - `AsyncNetworkFacade`: Wraps `AsyncNetSender` for the async production path.
//!   Uses channel-based message queuing with priority support.
//!
//! - `DirectAsyncNetworkFacade`: Wraps `Arc<AsyncPeerManagerImpl>` for integration
//!   tests. Uses `block_in_place` to bridge sync/async boundary. **Test-only**.
//!
//! - `NullNetworkFacade`: No-op implementation for unit tests.
//!
//! # Usage
//!
//! ```ignore
//! // Attach a facade to the harness for outbound operations
//! let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)?
//!     .with_net_facade(Box::new(AsyncNetworkFacade::new(sender)));
//!
//! // Or use the blocking facade
//! let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)?
//!     .with_net_facade(Box::new(BlockingNetworkFacade::new(peer_manager)));
//! ```

use crate::peer::PeerId;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// ConsensusNetworkFacade trait (Part A)
// ============================================================================

/// A unified network interface for the consensus harness.
///
/// This trait captures what `NodeHotstuffHarness` actually needs from the network:
/// - Sending votes to specific validators
/// - Broadcasting votes to all validators
/// - Broadcasting proposals to all validators
/// - Broadcasting timeout messages (T146)
///
/// # Design Notes
///
/// - The trait uses `ValidatorId` for addressing, not `PeerId`, because the
///   consensus layer thinks in terms of validators.
/// - Implementations are responsible for mapping `ValidatorId` to `PeerId`.
/// - The trait is `Send + Sync` to allow sharing across threads/tasks.
/// - Methods use `&self` rather than `&mut self` where possible for flexibility.
///
/// # Error Handling
///
/// All methods return `Result<(), NetworkError>`. Implementations should map
/// their internal errors to `NetworkError::Other(String)` when needed.
pub trait ConsensusNetworkFacade: Send + Sync {
    /// Send a vote to a specific validator.
    ///
    /// # Arguments
    ///
    /// - `target`: The validator ID to send the vote to
    /// - `vote`: The vote message to send
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the send fails (e.g., peer not connected).
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError>;

    /// Broadcast a vote to all connected validators.
    ///
    /// # Arguments
    ///
    /// - `vote`: The vote message to broadcast
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the broadcast fails.
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError>;

    /// Broadcast a block proposal to all connected validators.
    ///
    /// # Arguments
    ///
    /// - `proposal`: The block proposal to broadcast
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the broadcast fails.
    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError>;

    /// Send a timeout message to a specific peer (T146).
    ///
    /// This is used for broadcasting TimeoutMsg when a view times out.
    /// The message is pre-serialized by the caller.
    ///
    /// # Arguments
    ///
    /// - `target`: The peer ID to send the timeout message to
    /// - `msg_bytes`: The pre-serialized timeout message
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the send fails.
    ///
    /// # Default Implementation
    ///
    /// The default implementation logs a warning and succeeds. Implementations
    /// that support timeout messages should override this method.
    fn send_timeout_msg(
        &self,
        _target: crate::peer::PeerId,
        _msg_bytes: Vec<u8>,
    ) -> Result<(), NetworkError> {
        // Default implementation for backwards compatibility
        // Implementations that support timeout messages should override this
        eprintln!(
            "[T146] Warning: send_timeout_msg not implemented for this facade, message dropped"
        );
        Ok(())
    }
}

// ============================================================================
// ValidatorPeerMapping - Maps ValidatorId to PeerId
// ============================================================================

/// Trait for mapping ValidatorId to PeerId.
///
/// This is used by network facades to translate between the consensus layer's
/// view (validators) and the network layer's view (peers).
pub trait ValidatorPeerMapping: Send + Sync {
    /// Get the PeerId for a ValidatorId.
    ///
    /// Returns `None` if the validator is not known/connected.
    fn get_peer_for_validator(&self, validator_id: ValidatorId) -> Option<PeerId>;

    /// Get the ValidatorId for a PeerId.
    ///
    /// Returns `None` if the peer is not associated with a validator.
    fn get_validator_for_peer(&self, peer_id: PeerId) -> Option<ValidatorId>;
}

/// Simple identity mapping where ValidatorId(n) <-> PeerId(n).
///
/// This is the default mapping used in tests where validators and peers have
/// matching IDs.
#[derive(Debug, Clone, Default)]
pub struct IdentityValidatorPeerMapping;

impl ValidatorPeerMapping for IdentityValidatorPeerMapping {
    fn get_peer_for_validator(&self, validator_id: ValidatorId) -> Option<PeerId> {
        Some(PeerId(validator_id.0))
    }

    fn get_validator_for_peer(&self, peer_id: PeerId) -> Option<ValidatorId> {
        Some(ValidatorId::new(peer_id.0))
    }
}

// ============================================================================
// BlockingNetworkFacade (Part B - Legacy compatibility)
// ============================================================================

use crate::consensus_net::ConsensusNetAdapter;
use crate::peer_manager::PeerManager;
use qbind_consensus::ConsensusNetwork;
use std::sync::{Arc, Mutex};

/// Blocking implementation of `ConsensusNetworkFacade` using the legacy network stack.
///
/// This facade wraps the existing blocking `PeerManager` and `ConsensusNetAdapter`
/// to provide backwards compatibility with the synchronous network path.
///
/// # Production Use
///
/// This is the **production** facade for the blocking (synchronous) network path.
/// Use this when:
/// - Running synchronous consensus tests
/// - Using the legacy `PeerManager`-based networking
/// - Compatibility with existing blocking infrastructure is required
///
/// For async production use, see [`AsyncNetworkFacade`].
///
/// # Thread Safety
///
/// The facade uses `Arc<Mutex<PeerManager>>` for thread-safe access to the
/// peer manager. This allows the facade to implement `Send + Sync`.
///
/// # Usage
///
/// ```ignore
/// let peer_manager = Arc::new(Mutex::new(PeerManager::new(/* ... */)));
/// let facade = BlockingNetworkFacade::new(peer_manager.clone());
///
/// // Use from the harness
/// facade.broadcast_vote(&vote)?;
/// ```
pub struct BlockingNetworkFacade {
    /// The underlying peer manager.
    peer_manager: Arc<Mutex<PeerManager>>,
    /// Mapping from ValidatorId to PeerId.
    mapping: Arc<dyn ValidatorPeerMapping>,
}

impl std::fmt::Debug for BlockingNetworkFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingNetworkFacade")
            .field("peer_manager", &"<Arc<Mutex<PeerManager>>>")
            .finish()
    }
}

impl BlockingNetworkFacade {
    /// Create a new `BlockingNetworkFacade` with identity mapping.
    ///
    /// # Arguments
    ///
    /// - `peer_manager`: Arc-wrapped peer manager for thread-safe access
    pub fn new(peer_manager: Arc<Mutex<PeerManager>>) -> Self {
        BlockingNetworkFacade {
            peer_manager,
            mapping: Arc::new(IdentityValidatorPeerMapping),
        }
    }

    /// Create a new `BlockingNetworkFacade` with custom validator-peer mapping.
    ///
    /// # Arguments
    ///
    /// - `peer_manager`: Arc-wrapped peer manager for thread-safe access
    /// - `mapping`: Custom mapping from ValidatorId to PeerId
    pub fn with_mapping(
        peer_manager: Arc<Mutex<PeerManager>>,
        mapping: Arc<dyn ValidatorPeerMapping>,
    ) -> Self {
        BlockingNetworkFacade {
            peer_manager,
            mapping,
        }
    }
}

impl ConsensusNetworkFacade for BlockingNetworkFacade {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        let peer_id = self
            .mapping
            .get_peer_for_validator(target)
            .ok_or_else(|| NetworkError::Other(format!("no peer for validator {:?}", target)))?;

        let mut peers = self
            .peer_manager
            .lock()
            .map_err(|_| NetworkError::Other("peer manager lock poisoned".to_string()))?;

        let mut adapter = ConsensusNetAdapter::new(&mut peers);
        ConsensusNetwork::send_vote_to(&mut adapter, peer_id, vote)
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        let mut peers = self
            .peer_manager
            .lock()
            .map_err(|_| NetworkError::Other("peer manager lock poisoned".to_string()))?;

        let mut adapter = ConsensusNetAdapter::new(&mut peers);
        ConsensusNetwork::broadcast_vote(&mut adapter, vote)
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let mut peers = self
            .peer_manager
            .lock()
            .map_err(|_| NetworkError::Other("peer manager lock poisoned".to_string()))?;

        let mut adapter = ConsensusNetAdapter::new(&mut peers);
        ConsensusNetwork::broadcast_proposal(&mut adapter, proposal)
    }
}

// ============================================================================
// AsyncNetworkFacade (Part B - Async path)
// ============================================================================

use crate::consensus_net_worker::AsyncNetSender;

/// Async implementation of `ConsensusNetworkFacade` using the new async network stack.
///
/// This facade wraps `AsyncNetSender` to provide a synchronous interface to the
/// async network path. The actual network sends are queued in a channel and
/// processed by a separate async task.
///
/// # Production Use
///
/// This is the **production** facade for the async network path. Use this when:
/// - Running production async consensus nodes
/// - Using the `AsyncNetSender` + channel-based outbound processing
/// - Priority-based message routing is required
///
/// For integration tests, consider [`DirectAsyncNetworkFacade`] instead.
///
/// # Design (T96)
///
/// The facade uses `AsyncNetSender` which:
/// - Queues outbound commands in an mpsc channel
/// - Uses priority-based routing (critical messages go through unbounded channel)
/// - Provides backpressure without blocking the consensus core
///
/// # Thread Safety
///
/// `AsyncNetSender` is `Clone + Send + Sync`, making this facade safe to share.
///
/// # Usage
///
/// ```ignore
/// let (sender, outbound_rx, critical_rx) = AsyncNetSender::with_channel(1024);
/// let facade = AsyncNetworkFacade::new(sender);
///
/// // Start the outbound processor
/// spawn_outbound_processor(peer_manager, outbound_rx);
/// spawn_critical_outbound_worker(critical_rx, outbound_tx);
///
/// // Use from the harness
/// facade.broadcast_vote(&vote)?;
/// ```
#[derive(Clone)]
pub struct AsyncNetworkFacade {
    /// The underlying async sender.
    sender: AsyncNetSender,
    /// Mapping from ValidatorId to PeerId.
    mapping: Arc<dyn ValidatorPeerMapping>,
}

impl std::fmt::Debug for AsyncNetworkFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncNetworkFacade")
            .field("sender", &self.sender)
            .finish()
    }
}

impl AsyncNetworkFacade {
    /// Create a new `AsyncNetworkFacade` with identity mapping.
    ///
    /// # Arguments
    ///
    /// - `sender`: The async net sender for queuing outbound messages
    pub fn new(sender: AsyncNetSender) -> Self {
        AsyncNetworkFacade {
            sender,
            mapping: Arc::new(IdentityValidatorPeerMapping),
        }
    }

    /// Create a new `AsyncNetworkFacade` with custom validator-peer mapping.
    ///
    /// # Arguments
    ///
    /// - `sender`: The async net sender for queuing outbound messages
    /// - `mapping`: Custom mapping from ValidatorId to PeerId
    pub fn with_mapping(sender: AsyncNetSender, mapping: Arc<dyn ValidatorPeerMapping>) -> Self {
        AsyncNetworkFacade { sender, mapping }
    }

    /// Get a reference to the underlying sender.
    pub fn sender(&self) -> &AsyncNetSender {
        &self.sender
    }
}

impl ConsensusNetworkFacade for AsyncNetworkFacade {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        let peer_id = self
            .mapping
            .get_peer_for_validator(target)
            .ok_or_else(|| NetworkError::Other(format!("no peer for validator {:?}", target)))?;

        // Use critical priority for votes (T90.3 policy: votes are consensus-critical)
        self.sender.send_vote_to_critical(peer_id, vote)
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        // Use critical priority for votes
        self.sender.broadcast_vote_critical(vote)
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        // Use critical priority for proposals
        self.sender.broadcast_proposal_critical(proposal)
    }
}

// ============================================================================
// DirectAsyncNetworkFacade (Part B - Direct async path using AsyncPeerManagerImpl)
// ============================================================================

use crate::async_peer_manager::AsyncPeerManagerImpl;

/// Direct async implementation of `ConsensusNetworkFacade` using `AsyncPeerManagerImpl`.
///
/// Unlike `AsyncNetworkFacade` which uses a channel-based sender, this facade
/// directly calls the async peer manager methods using `tokio::task::block_in_place`
/// to bridge the sync/async boundary.
///
/// # Test-Only
///
/// **This facade is intended for integration tests only**, not production use.
/// The `block_in_place` pattern has performance implications under high load.
///
/// For production use:
/// - Use [`BlockingNetworkFacade`] for synchronous networking
/// - Use [`AsyncNetworkFacade`] for async networking with proper channel separation
///
/// # Design (T96)
///
/// This facade is designed for the full-stack async tests where:
/// - The harness is still synchronous (for determinism)
/// - The network is fully async (AsyncPeerManagerImpl)
/// - We need to bridge the two worlds without intermediate channels
///
/// # Thread Safety
///
/// The facade holds an `Arc<AsyncPeerManagerImpl>` for shared access.
/// The `block_in_place` calls ensure we don't block the Tokio runtime.
///
/// # Performance Note
///
/// The `block_in_place` + `block_on` pattern creates a nested blocking context.
/// This is acceptable for integration tests but may impact performance under
/// high load in production scenarios.
///
/// # Requirements
///
/// Using `block_in_place` requires being inside a Tokio runtime with the
/// `multi_thread` feature enabled.
#[derive(Clone)]
pub struct DirectAsyncNetworkFacade {
    /// The underlying async peer manager.
    peer_manager: Arc<AsyncPeerManagerImpl>,
    /// Mapping from ValidatorId to PeerId.
    mapping: Arc<dyn ValidatorPeerMapping>,
}

impl std::fmt::Debug for DirectAsyncNetworkFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectAsyncNetworkFacade")
            .field("peer_manager", &"<Arc<AsyncPeerManagerImpl>>")
            .finish()
    }
}

impl DirectAsyncNetworkFacade {
    /// Create a new `DirectAsyncNetworkFacade` with identity mapping.
    ///
    /// # Arguments
    ///
    /// - `peer_manager`: Arc-wrapped async peer manager
    pub fn new(peer_manager: Arc<AsyncPeerManagerImpl>) -> Self {
        DirectAsyncNetworkFacade {
            peer_manager,
            mapping: Arc::new(IdentityValidatorPeerMapping),
        }
    }

    /// Create a new `DirectAsyncNetworkFacade` with custom validator-peer mapping.
    ///
    /// # Arguments
    ///
    /// - `peer_manager`: Arc-wrapped async peer manager
    /// - `mapping`: Custom mapping from ValidatorId to PeerId
    pub fn with_mapping(
        peer_manager: Arc<AsyncPeerManagerImpl>,
        mapping: Arc<dyn ValidatorPeerMapping>,
    ) -> Self {
        DirectAsyncNetworkFacade {
            peer_manager,
            mapping,
        }
    }

    /// Get a reference to the underlying peer manager.
    pub fn peer_manager(&self) -> &Arc<AsyncPeerManagerImpl> {
        &self.peer_manager
    }
}

impl ConsensusNetworkFacade for DirectAsyncNetworkFacade {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        use crate::async_peer_manager::AsyncPeerManager;

        let peer_id = self
            .mapping
            .get_peer_for_validator(target)
            .ok_or_else(|| NetworkError::Other(format!("no peer for validator {:?}", target)))?;

        // Use block_in_place to call async method from sync context
        // This is safe because we're in a Tokio runtime context
        let pm = self.peer_manager.clone();
        let vote = vote.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                AsyncPeerManager::send_vote_to(pm.as_ref(), peer_id, vote).await
            })
        })
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        use crate::async_peer_manager::AsyncPeerManager;

        let pm = self.peer_manager.clone();
        let vote = vote.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { AsyncPeerManager::broadcast_vote(pm.as_ref(), vote).await })
        })
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        use crate::async_peer_manager::AsyncPeerManager;

        let pm = self.peer_manager.clone();
        let proposal = proposal.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                AsyncPeerManager::broadcast_proposal(pm.as_ref(), proposal).await
            })
        })
    }
}

// ============================================================================
// NullNetworkFacade (for testing)
// ============================================================================

/// A no-op implementation of `ConsensusNetworkFacade` for testing.
///
/// All methods succeed without doing anything. Useful for unit tests where
/// network interaction is not needed.
#[derive(Debug, Clone, Default)]
pub struct NullNetworkFacade;

impl ConsensusNetworkFacade for NullNetworkFacade {
    fn send_vote_to(&self, _target: ValidatorId, _vote: &Vote) -> Result<(), NetworkError> {
        Ok(())
    }

    fn broadcast_vote(&self, _vote: &Vote) -> Result<(), NetworkError> {
        Ok(())
    }

    fn broadcast_proposal(&self, _proposal: &BlockProposal) -> Result<(), NetworkError> {
        Ok(())
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_mapping_works() {
        let mapping = IdentityValidatorPeerMapping;

        let validator = ValidatorId::new(42);
        let peer = mapping.get_peer_for_validator(validator);
        assert_eq!(peer, Some(PeerId(42)));

        let peer_id = PeerId(99);
        let validator = mapping.get_validator_for_peer(peer_id);
        assert_eq!(validator, Some(ValidatorId::new(99)));
    }

    #[test]
    fn null_facade_methods_succeed() {
        let facade = NullNetworkFacade;

        let vote = qbind_wire::consensus::Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 1,
            round: 0,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        };

        let proposal = qbind_wire::consensus::BlockProposal {
            header: qbind_wire::consensus::BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height: 1,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        };

        assert!(facade.send_vote_to(ValidatorId::new(0), &vote).is_ok());
        assert!(facade.broadcast_vote(&vote).is_ok());
        assert!(facade.broadcast_proposal(&proposal).is_ok());
    }

    #[test]
    fn async_network_facade_debug_impl() {
        let (sender, _outbound_rx, _critical_rx) = AsyncNetSender::with_channel(10);
        let facade = AsyncNetworkFacade::new(sender);

        let debug_str = format!("{:?}", facade);
        assert!(debug_str.contains("AsyncNetworkFacade"));
    }
}