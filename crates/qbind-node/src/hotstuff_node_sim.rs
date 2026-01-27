//! Node-level HotStuff harness for multi-node simulations over real TCP.
//!
//! This module provides `NodeHotstuffHarness`, a harness that wires together:
//! - `NetService` (TCP + KEMTLS + PeerManager)
//! - `ConsensusNode` (owns NetService + PeerValidatorMap)
//! - `BasicHotStuffEngine` + `HotStuffDriver`
//! - `NodeConsensusSim<D>`
//! - Optional `ConsensusStorage` for persistence (T82)
//! - Optional `ConsensusNetworkFacade` for outbound network operations (T96.1)
//!
//! This is a test-oriented harness for running multi-node HotStuff simulations
//! over real TCP sockets (loopback).
//!
//! # Network Interface (T96.1)
//!
//! The harness supports two modes for outbound network operations:
//!
//! 1. **Facade mode** (preferred): Attach a `ConsensusNetworkFacade` via
//!    `with_net_facade()`. All outbound operations go through the facade.
//!
//! 2. **Legacy mode**: If no facade is attached, the harness uses
//!    `ConsensusNode::with_consensus_network()` for network operations.
//!
//! In both modes, the harness does **not** directly reference `ConsensusNetAdapter`.
//! The adapter usage is hidden inside either the facade implementations or
//! the `ConsensusNode` abstraction.
//!
//! # Usage
//!
//! ```ignore
//! use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
//! use qbind_node::validator_config::NodeValidatorConfig;
//!
//! let cfg = NodeValidatorConfig { /* ... */ };
//! let mut harness = NodeHotstuffHarness::new_from_validator_config(&cfg)?;
//!
//! // Optionally attach a network facade for outbound operations
//! let harness = harness.with_net_facade(Box::new(AsyncNetworkFacade::new(sender)));
//!
//! // Run simulation steps
//! for _ in 0..100 {
//!     harness.step_once()?;
//! }
//! ```

use crate::block_store::{BlockStore, BlockStoreError};
use crate::commit_index::{CommitIndex, CommitIndexError};
use crate::consensus_network_facade::ConsensusNetworkFacade;
use crate::consensus_node::{
    ConsensusNode, ConsensusNodeError, NodeCommitInfo, NodeCommittedBlock,
};
use crate::consensus_sim::{NodeConsensusSim, NodeConsensusSimError};
use crate::net_service::{NetService, NetServiceConfig, NetServiceError};
use crate::storage::{ConsensusStorage, StorageError};
use crate::validator_config::NodeValidatorConfig;
use crate::verify_pool::{ConsensusVerifyPool, ConsensusVerifyPoolConfig};

use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use qbind_consensus::crypto_verifier::ConsensusSigBackendRegistry;
use qbind_consensus::driver::{ConsensusEngineAction, HotStuffDriver, ValidatorContext};
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::network::ConsensusNetworkEvent;
use qbind_consensus::pacemaker::{
    BasicTickPacemaker, Pacemaker, PacemakerConfig, PacemakerEvent, TimeoutPacemaker,
    TimeoutPacemakerConfig,
};
use qbind_consensus::timeout::TimeoutMsg;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, EpochStateProvider,
};
use qbind_consensus::verify_job::{ConsensusMsgKind, ConsensusVerifyJob};
use qbind_net::{ClientConnectionConfig, ServerConnectionConfig};
use qbind_wire::consensus::{BlockProposal, Vote};

use std::io;
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// QbindTransaction Wire Encoding Constants (T151)
// ============================================================================
// These constants define the wire format for QbindTransactions in block proposals.
// Format: sender(32) + nonce(8) + payload_len(4) + payload + sig_len(4) + sig + suite_id(2)

const TX_SENDER_SIZE: usize = 32;
const TX_NONCE_SIZE: usize = 8;
const TX_PAYLOAD_LEN_SIZE: usize = 4;
const TX_SIG_LEN_SIZE: usize = 4;
const TX_SUITE_ID_SIZE: usize = 2;

// ============================================================================
// Error types
// ============================================================================

/// Error type for `NodeHotstuffHarness` operations.
#[derive(Debug)]
pub enum NodeHotstuffHarnessError {
    /// Error from the underlying `NodeConsensusSim`.
    Sim(NodeConsensusSimError),
    /// Error from `NetService`.
    NetService(NetServiceError),
    /// Error from `ConsensusNode`.
    ConsensusNode(ConsensusNodeError),
    /// Error from commit index operations.
    CommitIndex(CommitIndexError<[u8; 32]>),
    /// Error from block store operations.
    BlockStore(BlockStoreError),
    /// Error from persistent storage operations.
    Storage(StorageError),
    /// Error from startup validation (T82.1).
    StartupValidation(crate::startup_validation::StartupValidationError),
    /// I/O error.
    Io(io::Error),
    /// Configuration or setup error.
    Config(String),
    /// A block was committed in the commit index, but no proposal was found in the block store.
    MissingProposalForCommittedBlock { block_id: [u8; 32], height: u64 },
    /// Error during epoch transition (T112).
    ///
    /// This error occurs when transitioning to a new epoch fails due to:
    /// - Non-sequential epoch transition (e.g., jumping from epoch 0 to 2)
    /// - Missing epoch state from provider
    /// - Validation failures
    EpochTransition(qbind_consensus::validator_set::EpochTransitionError),

    /// Runtime suite downgrade detected during epoch transition (T125).
    ///
    /// This error occurs when a reconfig block attempts to transition to an epoch
    /// with a weaker cryptographic suite than the current epoch, violating the
    /// cross-epoch suite monotonicity rule.
    RuntimeSuiteDowngrade {
        from_epoch: qbind_consensus::validator_set::EpochId,
        to_epoch: qbind_consensus::validator_set::EpochId,
        from_suite: qbind_crypto::ConsensusSigSuiteId,
        to_suite: qbind_crypto::ConsensusSigSuiteId,
    },
}

impl From<NodeConsensusSimError> for NodeHotstuffHarnessError {
    fn from(e: NodeConsensusSimError) -> Self {
        NodeHotstuffHarnessError::Sim(e)
    }
}

impl From<NetServiceError> for NodeHotstuffHarnessError {
    fn from(e: NetServiceError) -> Self {
        NodeHotstuffHarnessError::NetService(e)
    }
}

impl From<ConsensusNodeError> for NodeHotstuffHarnessError {
    fn from(e: ConsensusNodeError) -> Self {
        NodeHotstuffHarnessError::ConsensusNode(e)
    }
}

impl From<io::Error> for NodeHotstuffHarnessError {
    fn from(e: io::Error) -> Self {
        NodeHotstuffHarnessError::Io(e)
    }
}

impl From<CommitIndexError<[u8; 32]>> for NodeHotstuffHarnessError {
    fn from(e: CommitIndexError<[u8; 32]>) -> Self {
        NodeHotstuffHarnessError::CommitIndex(e)
    }
}

impl From<BlockStoreError> for NodeHotstuffHarnessError {
    fn from(e: BlockStoreError) -> Self {
        NodeHotstuffHarnessError::BlockStore(e)
    }
}

impl From<StorageError> for NodeHotstuffHarnessError {
    fn from(e: StorageError) -> Self {
        NodeHotstuffHarnessError::Storage(e)
    }
}

impl From<crate::startup_validation::StartupValidationError> for NodeHotstuffHarnessError {
    fn from(e: crate::startup_validation::StartupValidationError) -> Self {
        NodeHotstuffHarnessError::StartupValidation(e)
    }
}

impl From<qbind_consensus::validator_set::EpochTransitionError> for NodeHotstuffHarnessError {
    fn from(e: qbind_consensus::validator_set::EpochTransitionError) -> Self {
        NodeHotstuffHarnessError::EpochTransition(e)
    }
}

impl std::fmt::Display for NodeHotstuffHarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeHotstuffHarnessError::Sim(e) => write!(f, "sim error: {}", e),
            NodeHotstuffHarnessError::NetService(e) => write!(f, "net service error: {:?}", e),
            NodeHotstuffHarnessError::ConsensusNode(e) => {
                write!(f, "consensus node error: {:?}", e)
            }
            NodeHotstuffHarnessError::CommitIndex(e) => write!(f, "commit index error: {}", e),
            NodeHotstuffHarnessError::BlockStore(e) => write!(f, "block store error: {}", e),
            NodeHotstuffHarnessError::Storage(e) => write!(f, "storage error: {}", e),
            NodeHotstuffHarnessError::StartupValidation(e) => {
                write!(f, "startup validation error: {}", e)
            }
            NodeHotstuffHarnessError::Io(e) => write!(f, "io error: {}", e),
            NodeHotstuffHarnessError::Config(s) => write!(f, "config error: {}", s),
            NodeHotstuffHarnessError::MissingProposalForCommittedBlock { block_id, height } => {
                write!(
                    f,
                    "missing proposal for committed block at height {}: block_id={:?}",
                    height, block_id
                )
            }
            NodeHotstuffHarnessError::EpochTransition(e) => {
                write!(f, "epoch transition error: {}", e)
            }
            NodeHotstuffHarnessError::RuntimeSuiteDowngrade {
                from_epoch,
                to_epoch,
                from_suite,
                to_suite,
            } => {
                write!(
                    f,
                    "runtime suite downgrade detected from epoch {} to {}: {} → {}; \
                     cross-epoch suite monotonicity requires equal or stronger security",
                    from_epoch, to_epoch, from_suite, to_suite
                )
            }
        }
    }
}

impl std::error::Error for NodeHotstuffHarnessError {}

// ============================================================================
// NodeHotstuffHarness
// ============================================================================

/// A node-level HotStuff harness for multi-node simulations over real TCP.
///
/// This struct wraps:
/// - `NodeConsensusSim<HotStuffDriver<BasicHotStuffEngine<[u8; 32]>>>` which owns
///   the `ConsensusNode` (with real TCP networking) and the consensus driver
/// - `CommitIndex<[u8; 32]>` which tracks the canonical committed chain
/// - `BlockStore` which stores locally broadcast block proposals
/// - Optional `ConsensusStorage` for persistent storage (T82)
///
/// The harness provides a simplified interface for:
/// - Creating nodes from `NodeValidatorConfig`
/// - Running simulation steps
/// - Accessing consensus state (committed blocks, etc.)
/// - Persisting committed blocks and QCs to RocksDB (when storage is attached)
///
/// # Persistence (T82)
///
/// When an optional `ConsensusStorage` is attached via `with_storage()`:
/// - On startup, the harness loads the last committed block ID and restores state
/// - On each commit, blocks and QCs are persisted
/// - On restart, the node can resume from its last committed state
///
/// # Note
///
/// This is a test-only harness. The actual node-level wiring for production
/// will be done in a separate module.
///
/// # Network Interface (T96.1)
///
/// The harness uses `ConsensusNetworkFacade` for all outbound network operations
/// (sending votes and proposals). This abstraction allows the harness to work with
/// both blocking and async network implementations without knowing the details.
///
/// The `net_facade` field holds an optional network facade instance. When set,
/// all outbound operations go through the facade. When not set (legacy mode),
/// the harness uses `ConsensusNode::with_consensus_network()` for network operations.
///
/// Inbound operations (receiving messages) are handled via
/// `ConsensusNode::with_consensus_network()`, which abstracts away the underlying
/// network adapter.
pub struct NodeHotstuffHarness {
    /// The local validator ID for this node.
    pub validator_id: ValidatorId,
    /// The underlying simulation harness.
    pub sim: NodeConsensusSim<HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]>>,
    /// The commit index tracking the canonical committed chain.
    commit_index: CommitIndex<[u8; 32]>,
    /// Local block store for proposals broadcast by this node.
    block_store: BlockStore,
    /// Height of the last commit exposed via `drain_committed_blocks()`.
    /// `None` means no commits have been drained yet.
    last_drained_height: Option<u64>,
    /// Pacemaker controlling proposal timing.
    pacemaker: BasicTickPacemaker,
    /// Optional persistent storage backend (T82).
    /// When set, commits are persisted to disk.
    storage: Option<Arc<dyn ConsensusStorage>>,
    /// Optional network facade for outbound consensus operations (T96.1).
    ///
    /// When set, this is the interface the harness uses for sending votes and proposals.
    /// The facade abstracts away whether the underlying network is blocking or async.
    ///
    /// When `None`, the harness uses `ConsensusNode::with_consensus_network()` for
    /// network operations (legacy mode for backwards compatibility).
    net_facade: Option<Box<dyn ConsensusNetworkFacade>>,
    /// Optional epoch state (T100).
    ///
    /// When set, this provides the canonical view of the validator set for the
    /// current epoch. The harness can validate consistency between the epoch
    /// state and the driver's validator context.
    ///
    /// When `None`, the harness operates without epoch awareness (legacy mode).
    epoch_state: Option<EpochState>,
    /// Optional epoch state provider (T102.1).
    ///
    /// When set, this provider is used to fetch `EpochState` for epoch transitions.
    /// When a reconfig block commits, the harness uses this provider to get the
    /// next epoch's state and calls `transition_to_epoch()` on the engine.
    ///
    /// When `None`, epoch transitions are not handled (reconfig blocks are ignored).
    epoch_state_provider: Option<Arc<dyn EpochStateProvider>>,
    /// Optional metrics for observability (T107).
    ///
    /// When set, commit latency is recorded for each commit operation.
    metrics: Option<Arc<crate::metrics::NodeMetrics>>,

    /// Optional governance for runtime suite validation (T125).
    ///
    /// When set, used to extract suite IDs from epoch states for runtime
    /// suite downgrade protection.
    governance: Option<
        Arc<dyn qbind_consensus::governed_key_registry::ConsensusKeyGovernance + Send + Sync>,
    >,

    /// Suite policy for runtime validation (T125).
    ///
    /// Controls whether toy suites are allowed and minimum security bits.
    /// Defaults to dev policy to avoid breaking existing tests.
    suite_policy: crate::startup_validation::SuitePolicy,

    /// Validator signing key for signing votes and proposals (T143).
    ///
    /// **DEPRECATED (T148)**: Use `signer` field instead.
    /// This field is kept for backwards compatibility with tests that
    /// set it directly. When both `signer` and `signing_key` are set,
    /// `signer` takes precedence.
    signing_key: Option<std::sync::Arc<qbind_crypto::ValidatorSigningKey>>,

    /// Validator signer abstraction for consensus signing (T148).
    ///
    /// This signer encapsulates all consensus signing operations (proposals,
    /// votes, timeouts). It provides a clean abstraction boundary for future
    /// HSM or remote signer integration.
    ///
    /// When set, this takes precedence over `signing_key`.
    signer: Option<std::sync::Arc<dyn crate::validator_signer::ValidatorSigner>>,

    /// Timeout pacemaker for view-change protocol (T146).
    ///
    /// This pacemaker tracks real time and generates timeout events when no
    /// progress is made within the configured timeout period.
    timeout_pacemaker: TimeoutPacemaker,

    /// Whether timeout-based view-change is enabled (T146).
    ///
    /// When enabled, the harness will emit timeout messages and process timeout
    /// certificates for view changes. When disabled, the harness operates in
    /// legacy mode without timeouts.
    timeout_enabled: bool,

    /// Optional multi-threaded verification pool (T147).
    ///
    /// When set, incoming consensus messages are verified in parallel across
    /// multiple worker threads instead of synchronously on the main thread.
    /// This improves TPS by utilizing all available cores for PQ signature
    /// verification.
    verify_pool: Option<ConsensusVerifyPool<[u8; 32]>>,

    /// Pending proposals waiting for verification (T147).
    ///
    /// When a proposal is submitted to the verification pool, it is stored here
    /// until verification completes. The key is a unique job ID derived from
    /// (view, validator_id) to allow matching results back to the original message.
    pending_proposals: std::collections::HashMap<(u64, u64), BlockProposal>,

    /// Pending votes waiting for verification (T147).
    pending_votes: std::collections::HashMap<(u64, u64), Vote>,

    /// Optional mempool for transaction admission and block building (T151).
    ///
    /// When set, the harness pulls transactions from the mempool when building
    /// proposals and removes committed transactions on block commits.
    mempool: Option<Arc<dyn crate::mempool::Mempool>>,

    /// Optional execution adapter for applying committed blocks (T150/T151).
    ///
    /// When set, the harness calls the adapter's `apply_block()` on each commit
    /// to update execution state.
    execution_adapter:
        Option<Arc<parking_lot::Mutex<dyn crate::execution_adapter::ExecutionAdapter>>>,

    /// Maximum number of transactions per block (T151).
    ///
    /// Controls how many transactions are pulled from the mempool for proposals.
    max_txs_per_block: usize,
}

// Manual Debug implementation because Arc<dyn ConsensusStorage> doesn't implement Debug
impl std::fmt::Debug for NodeHotstuffHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeHotstuffHarness")
            .field("validator_id", &self.validator_id)
            .field("sim", &self.sim)
            .field("commit_index", &self.commit_index)
            .field("block_store", &self.block_store)
            .field("last_drained_height", &self.last_drained_height)
            .field("pacemaker", &self.pacemaker)
            .field("storage", &self.storage.is_some())
            .field("net_facade", &self.net_facade.is_some())
            .field(
                "epoch_state",
                &self.epoch_state.as_ref().map(|e| e.epoch_id()),
            )
            .field("epoch_state_provider", &self.epoch_state_provider.is_some())
            .field("metrics", &self.metrics.is_some())
            .field("governance", &self.governance.is_some())
            .field("suite_policy", &self.suite_policy)
            .field("signing_key", &self.signing_key.is_some())
            .field("signer", &self.signer.is_some())
            .field("timeout_pacemaker", &self.timeout_pacemaker)
            .field("timeout_enabled", &self.timeout_enabled)
            .field("verify_pool", &self.verify_pool.is_some())
            .field("pending_proposals", &self.pending_proposals.len())
            .field("pending_votes", &self.pending_votes.len())
            .field("mempool", &self.mempool.is_some())
            .field("execution_adapter", &self.execution_adapter.is_some())
            .field("max_txs_per_block", &self.max_txs_per_block)
            .finish()
    }
}

impl NodeHotstuffHarness {
    /// Create a new `NodeHotstuffHarness` from configuration components.
    ///
    /// This constructor takes pre-built components:
    /// - `NetServiceConfig` for TCP networking
    /// - `ConsensusValidatorSet` for the consensus engine
    /// - Local validator ID
    ///
    /// # Arguments
    ///
    /// - `local_id`: The validator ID for this node
    /// - `net_cfg`: Network service configuration
    /// - `consensus_validators`: Validator set for consensus
    /// - `id_map`: Peer-to-validator identity mapping
    ///
    /// # Returns
    ///
    /// A new `NodeHotstuffHarness` or an error if setup fails.
    pub fn new(
        local_id: ValidatorId,
        net_cfg: NetServiceConfig,
        consensus_validators: ConsensusValidatorSet,
        id_map: crate::identity_map::PeerValidatorMap,
    ) -> Result<Self, NodeHotstuffHarnessError> {
        // 1. Create NetService.
        let net_service = NetService::new(net_cfg)?;

        // 2. Build BasicHotStuffEngine.
        let engine = BasicHotStuffEngine::<[u8; 32]>::new(local_id, consensus_validators.clone());

        // 3. Build ValidatorContext from consensus_validators.
        let vctx = ValidatorContext::new(consensus_validators);

        // 4. Wrap engine in HotStuffDriver.
        let driver = HotStuffDriver::with_validators(engine, vctx);

        // 5. Build ConsensusNode with NetService and PeerValidatorMap.
        let consensus_node = ConsensusNode::with_id_map(net_service, id_map);

        // 6. Build NodeConsensusSim from node + driver.
        let sim = NodeConsensusSim::new(consensus_node, driver);

        // 7. Initialize an empty commit index.
        let commit_index = CommitIndex::new();

        // 8. Initialize an empty block store.
        let block_store = BlockStore::new();

        // 9. Initialize the pacemaker with min_ticks_between_proposals = 1.
        // This means "at most one proposal per view per step_once() call".
        let pm_cfg = PacemakerConfig {
            min_ticks_between_proposals: 1,
            ..PacemakerConfig::default()
        };
        let pacemaker = BasicTickPacemaker::new(pm_cfg);

        // 10. Initialize the HotStuff timeout pacemaker for view-change (T146).
        let timeout_pm_cfg = TimeoutPacemakerConfig::default();
        let timeout_pacemaker = TimeoutPacemaker::new(timeout_pm_cfg);

        Ok(NodeHotstuffHarness {
            validator_id: local_id,
            sim,
            commit_index,
            block_store,
            last_drained_height: None,
            pacemaker,
            storage: None,
            net_facade: None,
            epoch_state: None,
            epoch_state_provider: None,
            metrics: None,
            governance: None,
            suite_policy: crate::startup_validation::SuitePolicy::dev_default(),
            signing_key: None,
            signer: None,
            timeout_pacemaker,
            timeout_enabled: true, // Timeout enabled by default for liveness
            verify_pool: None,
            pending_proposals: std::collections::HashMap::new(),
            pending_votes: std::collections::HashMap::new(),
            mempool: None,
            execution_adapter: None,
            max_txs_per_block: 1000, // Default max txs per block
        })
    }

    /// Attach a persistent storage backend to this harness.
    ///
    /// When storage is attached:
    /// - On each commit, blocks and QCs are persisted to storage
    /// - The `last_committed` metadata is updated
    ///
    /// # Arguments
    ///
    /// - `storage`: An Arc to a `ConsensusStorage` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_storage(mut self, storage: Arc<dyn ConsensusStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Attach metrics for observability (T107).
    ///
    /// When metrics are attached, the harness records commit latency for each
    /// commit operation in the `CommitMetrics` component.
    ///
    /// # Arguments
    ///
    /// - `metrics`: An Arc to a `NodeMetrics` instance.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_node::metrics::NodeMetrics;
    /// use std::sync::Arc;
    ///
    /// let metrics = Arc::new(NodeMetrics::new());
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_metrics(metrics);
    /// ```
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::NodeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get the metrics instance, if attached.
    pub fn metrics(&self) -> Option<&Arc<crate::metrics::NodeMetrics>> {
        self.metrics.as_ref()
    }

    /// Attach a network facade for outbound consensus operations (T96.1).
    ///
    /// When a facade is attached, all outbound network operations (sending votes
    /// and proposals) go through the facade instead of directly using the
    /// underlying network adapter.
    ///
    /// # Arguments
    ///
    /// - `facade`: A boxed `ConsensusNetworkFacade` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // With async network facade
    /// let facade = AsyncNetworkFacade::new(sender);
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_net_facade(Box::new(facade));
    ///
    /// // With direct async facade
    /// let facade = DirectAsyncNetworkFacade::new(peer_manager);
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_net_facade(Box::new(facade));
    /// ```
    pub fn with_net_facade(mut self, facade: Box<dyn ConsensusNetworkFacade>) -> Self {
        self.net_facade = Some(facade);
        self
    }

    /// Attach an epoch state to this harness (T100).
    ///
    /// When an epoch state is attached:
    /// - The harness knows the canonical validator set for the current epoch.
    /// - The `validate_epoch_consistency()` method can verify consistency
    ///   between the epoch state and the driver's validator context.
    ///
    /// # Arguments
    ///
    /// - `epoch_state`: The epoch state representing the current epoch.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_consensus::validator_set::{EpochId, EpochState};
    ///
    /// let epoch_state = EpochState::genesis(validator_set);
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_epoch_state(epoch_state);
    /// ```
    pub fn with_epoch_state(mut self, epoch_state: EpochState) -> Self {
        self.epoch_state = Some(epoch_state);
        self
    }

    /// Attach an epoch state provider for epoch transitions (T102.1).
    ///
    /// When an epoch state provider is attached:
    /// - On commit of a reconfig block, the harness fetches the next epoch's state
    ///   from this provider.
    /// - If the epoch is found, `transition_to_epoch()` is called on the engine.
    /// - If the epoch is not found, the harness panics with a clear error.
    ///
    /// # Arguments
    ///
    /// - `provider`: An Arc to an `EpochStateProvider` implementation.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_consensus::validator_set::{EpochState, StaticEpochStateProvider};
    ///
    /// let provider = StaticEpochStateProvider::new()
    ///     .with_epoch(epoch0)
    ///     .with_epoch(epoch1);
    ///
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_epoch_state_provider(Arc::new(provider));
    /// ```
    pub fn with_epoch_state_provider(mut self, provider: Arc<dyn EpochStateProvider>) -> Self {
        self.epoch_state_provider = Some(provider);
        self
    }

    /// Attach governance for runtime suite validation (T125).
    ///
    /// When governance is attached, it's used to extract suite IDs from epoch
    /// states for runtime suite downgrade protection during epoch transitions.
    ///
    /// # Arguments
    ///
    /// - `governance`: An Arc to a `ConsensusKeyGovernance` implementation.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_governance(governance);
    /// ```
    pub fn with_governance(
        mut self,
        governance: Arc<
            dyn qbind_consensus::governed_key_registry::ConsensusKeyGovernance + Send + Sync,
        >,
    ) -> Self {
        self.governance = Some(governance);
        self
    }

    /// Attach a suite policy for runtime validation (T125).
    ///
    /// Controls whether toy suites are allowed and minimum security bits
    /// for runtime epoch transitions.
    ///
    /// # Arguments
    ///
    /// - `policy`: The suite policy to use for runtime validation.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_node::startup_validation::SuitePolicy;
    ///
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_suite_policy(SuitePolicy::prod_default());
    /// ```
    pub fn with_suite_policy(mut self, policy: crate::startup_validation::SuitePolicy) -> Self {
        self.suite_policy = policy;
        self
    }

    /// Attach a validator signer for consensus signing operations (T148).
    ///
    /// When a signer is attached, all consensus signing operations (proposals,
    /// votes, timeout messages) go through the signer abstraction. This enables
    /// pluggable signing backends (HSM, remote signer) without modifying harness code.
    ///
    /// When a signer is attached, it takes precedence over any directly-set
    /// `signing_key`. The `signing_key` field is kept for backwards compatibility.
    ///
    /// # Arguments
    ///
    /// - `signer`: An Arc to a `ValidatorSigner` implementation.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_node::validator_signer::{LocalKeySigner, ValidatorSigner};
    /// use std::sync::Arc;
    ///
    /// let signer: Arc<dyn ValidatorSigner> = Arc::new(LocalKeySigner::new(
    ///     validator_id,
    ///     100,
    ///     signing_key,
    /// ));
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_signer(signer);
    /// ```
    pub fn with_signer(
        mut self,
        signer: Arc<dyn crate::validator_signer::ValidatorSigner>,
    ) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Get the attached signer, if any (T148).
    pub fn signer(&self) -> Option<&Arc<dyn crate::validator_signer::ValidatorSigner>> {
        self.signer.as_ref()
    }

    /// Enable or disable the HotStuff timeout/view-change mechanism (T146).
    ///
    /// When enabled (default), the harness will:
    /// - Detect lack of progress via the timeout pacemaker.
    /// - Emit `TimeoutMsg` when the current view times out.
    /// - Form `TimeoutQC` when 2f+1 timeout messages are received.
    /// - Advance to higher views using `TimeoutQC`.
    ///
    /// Disabling timeouts is useful for tests that want deterministic
    /// view advancement without the complexity of timeout handling.
    ///
    /// # Arguments
    ///
    /// - `enabled`: Whether to enable timeout handling.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Disable timeouts for a deterministic test
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_timeout_enabled(false);
    /// ```
    pub fn with_timeout_enabled(mut self, enabled: bool) -> Self {
        self.timeout_enabled = enabled;
        self
    }

    /// Configure the timeout pacemaker with custom settings (T146).
    ///
    /// This allows customizing timeout durations and backoff behavior.
    ///
    /// # Arguments
    ///
    /// - `config`: The timeout pacemaker configuration.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_consensus::TimeoutPacemakerConfig;
    /// use std::time::Duration;
    ///
    /// let config = TimeoutPacemakerConfig {
    ///     base_timeout: Duration::from_millis(2000),
    ///     timeout_multiplier: 1.5,
    ///     max_timeout: Duration::from_secs(30),
    /// };
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_timeout_config(config);
    /// ```
    pub fn with_timeout_config(mut self, config: TimeoutPacemakerConfig) -> Self {
        self.timeout_pacemaker = TimeoutPacemaker::new(config);
        self
    }

    /// Attach a multi-threaded verification pool for consensus messages (T147).
    ///
    /// When a verification pool is attached:
    /// - Incoming votes and proposals are submitted to the pool for parallel verification
    /// - Verification happens across multiple worker threads
    /// - Results are drained in the main loop and processed through the engine
    ///
    /// When no pool is attached (default):
    /// - Messages are processed synchronously (legacy mode)
    ///
    /// # Arguments
    ///
    /// - `key_provider`: Provider for looking up validator public keys
    /// - `backend_registry`: Registry mapping suite IDs to verifier backends
    /// - `config`: Optional pool configuration (defaults to using all CPU cores)
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_node::verify_pool::ConsensusVerifyPoolConfig;
    ///
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_verify_pool(key_provider, backend_registry, None);
    /// ```
    pub fn with_verify_pool<K, B>(
        mut self,
        key_provider: Arc<K>,
        backend_registry: Arc<B>,
        config: Option<ConsensusVerifyPoolConfig>,
    ) -> Self
    where
        K: SuiteAwareValidatorKeyProvider + Send + Sync + 'static,
        B: ConsensusSigBackendRegistry + Send + Sync + 'static,
    {
        let config = config.unwrap_or_default();
        eprintln!(
            "[T147] Creating verification pool with {} workers",
            config.num_workers
        );
        self.verify_pool = Some(ConsensusVerifyPool::new(
            config,
            key_provider,
            backend_registry,
        ));
        self
    }

    /// Check if the verification pool is enabled.
    pub fn has_verify_pool(&self) -> bool {
        self.verify_pool.is_some()
    }

    /// Get verification pool metrics, if pool is attached.
    pub fn verify_pool_metrics(&self) -> Option<&crate::verify_pool::VerifyPoolMetrics> {
        self.verify_pool.as_ref().map(|p| p.metrics())
    }

    /// Attach a mempool for transaction admission and block building (T151).
    ///
    /// When a mempool is attached, the harness will:
    /// - Pull transactions from the mempool when building proposals
    /// - Remove committed transactions on block commits
    ///
    /// # Arguments
    ///
    /// * `mempool` - The mempool implementation to use
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_mempool(mut self, mempool: Arc<dyn crate::mempool::Mempool>) -> Self {
        self.mempool = Some(mempool);
        self
    }

    /// Attach an execution adapter for applying committed blocks (T151).
    ///
    /// When an execution adapter is attached, the harness calls its `apply_block()`
    /// method on each commit to update execution state.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The execution adapter to use
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_execution_adapter(
        mut self,
        adapter: Arc<parking_lot::Mutex<dyn crate::execution_adapter::ExecutionAdapter>>,
    ) -> Self {
        self.execution_adapter = Some(adapter);
        self
    }

    /// Set the maximum number of transactions per block (T151).
    ///
    /// Controls how many transactions are pulled from the mempool for proposals.
    ///
    /// # Arguments
    ///
    /// * `max_txs` - The maximum number of transactions per block
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn with_max_txs_per_block(mut self, max_txs: usize) -> Self {
        self.max_txs_per_block = max_txs;
        self
    }

    /// Get the epoch state provider, if attached.
    pub fn epoch_state_provider(&self) -> Option<&Arc<dyn EpochStateProvider>> {
        self.epoch_state_provider.as_ref()
    }

    /// Get the epoch state, if attached.
    pub fn epoch_state(&self) -> Option<&EpochState> {
        self.epoch_state.as_ref()
    }

    /// Validate consistency between the epoch state and the driver's validator context.
    ///
    /// This method checks that the validator set in the epoch state matches the
    /// validator set used by the HotStuff driver for vote validation and quorum
    /// computation.
    ///
    /// # Checks Performed
    ///
    /// 1. The number of validators matches.
    /// 2. All validator IDs in the epoch are present in the driver's validator context.
    /// 3. (Debug assertion) The local validator ID is in the epoch's validator set.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if consistency is verified (or no epoch state is attached).
    /// * `Err(NodeHotstuffHarnessError::Config(_))` if inconsistencies are found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let harness = NodeHotstuffHarness::new(...)?
    ///     .with_epoch_state(epoch_state);
    ///
    /// // Validate consistency before starting consensus
    /// harness.validate_epoch_consistency()?;
    /// ```
    pub fn validate_epoch_consistency(&self) -> Result<(), NodeHotstuffHarnessError> {
        let epoch_state = match &self.epoch_state {
            Some(es) => es,
            None => return Ok(()), // No epoch state attached - skip validation
        };

        // Get the validator context from the driver
        let driver_validators = match self.sim.driver.validators() {
            Some(ctx) => ctx,
            None => {
                // Driver has no validator context - this is likely legacy mode
                // We can't validate, but we shouldn't fail
                eprintln!(
                    "[T100] Warning: driver has no validator context, cannot validate epoch consistency"
                );
                return Ok(());
            }
        };

        // Check 1: Number of validators matches
        let epoch_count = epoch_state.len();
        let driver_count = driver_validators.set.len();
        if epoch_count != driver_count {
            return Err(NodeHotstuffHarnessError::Config(format!(
                "epoch has {} validators but driver has {}",
                epoch_count, driver_count
            )));
        }

        // Check 2: All epoch validators are in the driver's set
        for entry in epoch_state.iter() {
            if !driver_validators.is_member(entry.id) {
                return Err(NodeHotstuffHarnessError::Config(format!(
                    "epoch validator {:?} is not in driver's validator context",
                    entry.id
                )));
            }
        }

        // Debug assertion: local validator should be in the epoch
        debug_assert!(
            epoch_state.contains(self.validator_id),
            "local validator {:?} is not in epoch's validator set",
            self.validator_id
        );

        eprintln!(
            "[T100] Epoch consistency validated: epoch={}, validators={}, local_id={:?}",
            epoch_state.epoch_id(),
            epoch_count,
            self.validator_id
        );

        Ok(())
    }

    /// Load persisted state from storage on startup and initialize the consensus engine.
    ///
    /// This method should be called after attaching storage to restore:
    /// - The last committed block ID
    /// - The corresponding block and QC (if available)
    /// - Initialize the HotStuff engine state for safe resumption
    ///
    /// If no state is found (fresh node), this is a no-op and the engine
    /// starts from genesis.
    ///
    /// # Restart Semantics (T84)
    ///
    /// ## What is Restored
    ///
    /// - **Committed block**: Recognized by the engine as committed
    /// - **Committed height**: Used for height/view monotonicity
    /// - **Locked QC**: Set conservatively from the stored QC for the committed block
    /// - **Engine view**: Set to `committed_height + 1` to resume from next view
    /// - **Block store**: The committed block is loaded for state machine replay
    ///
    /// ## What is NOT Restored
    ///
    /// - **In-flight proposals**: Lost; leaders will re-propose as needed
    /// - **Pending votes**: Lost; votes that didn't form a QC are discarded
    /// - **High QC vs Locked QC distinction**: Treated conservatively as the same
    /// - **Vote accumulator**: Starts fresh; safe because we're past committed prefix
    /// - **Commit index**: Starts fresh; can be rebuilt from storage if needed
    ///
    /// ## Safety Guarantee
    ///
    /// This is safe because:
    /// 1. The committed prefix has a 3-chain QC and cannot be reverted (BFT safety)
    /// 2. Setting locked_qc prevents voting for blocks that conflict with our commit
    /// 3. Setting view to `committed_height + 1` prevents double-commits
    ///
    /// ## Liveness Trade-off
    ///
    /// The conservative locked_qc may delay voting until a proposal arrives with
    /// a QC at or above the locked view. This is acceptable for restart scenarios.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Option<[u8; 32]>)` with the last committed block ID if found,
    /// or `Ok(None)` if this is a fresh node.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage operations fail
    /// - `last_committed` references a block not found in storage (inconsistent state)
    /// - Schema version is incompatible (T104)
    pub fn load_persisted_state(&mut self) -> Result<Option<[u8; 32]>, NodeHotstuffHarnessError> {
        use qbind_consensus::qc::QuorumCertificate;

        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(None), // No storage attached
        };

        // T104: Check schema version compatibility before loading any data.
        // This ensures we fail fast if the database was created by a newer
        // version of the software with an incompatible data layout.
        crate::storage::ensure_compatible_schema(storage.as_ref())?;

        // Try to load last committed block ID
        let last_committed = storage.get_last_committed()?;

        let block_id = match last_committed {
            Some(id) => id,
            None => {
                eprintln!("[T84] No persisted state found - starting as fresh node");
                return Ok(None);
            }
        };

        // Log the loaded state for debugging
        eprintln!(
            "[T84] Loaded last committed block from storage: block_id={:?}",
            &block_id[..8] // Show first 8 bytes for brevity
        );

        // Load the block to get height info - this is required for restart
        let block = storage.get_block(&block_id)?.ok_or_else(|| {
            NodeHotstuffHarnessError::Storage(crate::storage::StorageError::Other(format!(
                "last_committed block_id {:?} not found in storage (inconsistent state)",
                &block_id[..8]
            )))
        })?;

        let committed_height = block.header.height;

        eprintln!(
            "[T84] Loaded block: height={}, suite_id={}, proposer_index={}",
            committed_height, block.header.suite_id, block.header.proposer_index
        );

        // Load the block into our in-memory store for potential state machine replay
        self.block_store.store_proposal_with_id(block_id, &block);

        // Try to load the QC for the committed block
        // This QC (if present) will be used as the locked_qc for restart
        let stored_qc = storage.get_qc(&block_id)?;

        // Build the locked_qc for restart
        // We use a conservative approach: treat the QC for the committed block as both
        // the committed QC and the locked QC. This may be more restrictive than necessary
        // (the actual locked_qc could be higher), but it's safe.
        //
        // We construct a logical QuorumCertificate from the wire QC.
        // The signers list is left empty because we don't need to re-verify the QC
        // (it was already verified when it was originally accepted).
        let locked_qc: Option<QuorumCertificate<[u8; 32]>> = stored_qc.as_ref().map(|wire_qc| {
            eprintln!(
                "[T84] Loaded QC for restart: height={}, suite_id={}, signers={}",
                wire_qc.height,
                wire_qc.suite_id,
                wire_qc.signatures.len()
            );
            // Convert wire QC to logical QC
            // Note: signers is empty because we're restoring from trusted storage;
            // the QC was already validated when it was originally stored.
            QuorumCertificate::new(
                wire_qc.block_id,
                wire_qc.height, // Use QC height as view
                vec![],         // Signers not needed for restart (already validated)
            )
        });

        // Also check for embedded QC in the block (this is the justify_qc for this block)
        // The embedded QC might be at a different view than the block-level QC
        // We use the higher view QC as our locked_qc for more conservative safety
        let embedded_locked_qc = block.qc.as_ref().map(|wire_qc| {
            eprintln!(
                "[T84] Found embedded QC: height={}, suite_id={}",
                wire_qc.height, wire_qc.suite_id
            );
            QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![])
        });

        // Choose the QC with the higher view as our locked_qc (more conservative)
        let final_locked_qc = match (locked_qc, embedded_locked_qc) {
            (Some(qc1), Some(qc2)) => {
                if qc1.view >= qc2.view {
                    Some(qc1)
                } else {
                    Some(qc2)
                }
            }
            (Some(qc), None) => Some(qc),
            (None, Some(qc)) => Some(qc),
            (None, None) => None,
        };

        // Initialize the consensus engine from restart state
        self.sim.driver.engine_mut().initialize_from_restart(
            block_id,
            committed_height,
            final_locked_qc,
        );

        eprintln!(
            "[T84] Engine initialized for restart: view={}, committed_height={}",
            self.sim.driver.engine().current_view(),
            committed_height
        );

        // T103: Restore epoch state on startup
        // Read the current epoch from storage (defaults to 0 if not present)
        let stored_epoch = storage.get_current_epoch()?.unwrap_or(0);

        eprintln!("[T103] Loaded epoch from storage: epoch={}", stored_epoch);

        // If the stored epoch is > 0, we need to restore the epoch state
        if stored_epoch > 0 {
            let epoch_id = EpochId::new(stored_epoch);

            // Get the epoch state provider
            let provider = self.epoch_state_provider.as_ref().ok_or_else(|| {
                NodeHotstuffHarnessError::Config(format!(
                    "Storage indicates epoch {}, but no epoch state provider is configured. \
                     Cannot restore epoch state on startup.",
                    stored_epoch
                ))
            })?;

            // Fetch the epoch state for the stored epoch
            let epoch_state = provider.get_epoch_state(epoch_id).ok_or_else(|| {
                NodeHotstuffHarnessError::Config(format!(
                    "Epoch {} is persisted in storage, but the epoch state provider \
                     does not have state for this epoch. Cannot restore epoch.",
                    stored_epoch
                ))
            })?;

            // Set the engine's current epoch
            self.sim.driver.engine_mut().set_current_epoch(stored_epoch);

            // Update the harness epoch_state to match
            self.epoch_state = Some(epoch_state);

            eprintln!(
                "[T103] Restored epoch {}: validator_count={}",
                stored_epoch,
                self.epoch_state.as_ref().map(|e| e.len()).unwrap_or(0)
            );
        } else {
            // Epoch 0 (genesis) - engine already defaults to epoch 0
            eprintln!("[T103] Starting in genesis epoch (epoch 0)");
        }

        Ok(Some(block_id))
    }

    /// Validate startup configuration using the provided governance and backend registry.
    ///
    /// This method should be called **before** starting the consensus loop to ensure:
    /// 1. All suite IDs referenced by governance have registered backends.
    /// 2. Persisted state (if any) uses configured suite IDs.
    ///
    /// # Type Parameters
    ///
    /// * `CG` - The governance type implementing `ValidatorEnumerator`.
    /// * `BR` - The backend registry type implementing `ConsensusSigBackendRegistry`.
    ///
    /// # Arguments
    ///
    /// * `governance` - Governance implementation for looking up validator keys.
    /// * `backend_registry` - Registry mapping suite IDs to verifier backends.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if validation passes.
    /// * `Err(NodeHotstuffHarnessError::StartupValidation(_))` if validation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)?
    ///     .with_storage(storage.clone());
    ///
    /// // Validate before starting consensus
    /// harness.validate_startup_with(governance.clone(), backend_registry.clone())?;
    ///
    /// // Load persisted state and start consensus
    /// harness.load_persisted_state()?;
    /// ```
    pub fn validate_startup_with<CG, BR>(
        &self,
        governance: Arc<CG>,
        backend_registry: Arc<BR>,
    ) -> Result<(), NodeHotstuffHarnessError>
    where
        CG: crate::startup_validation::ValidatorEnumerator + Send + Sync,
        BR: qbind_consensus::crypto_verifier::ConsensusSigBackendRegistry + Send + Sync,
    {
        // If no storage is attached, create a dummy empty storage for validation.
        // This allows governance validation to proceed even without persistence.
        let storage: Arc<dyn ConsensusStorage> = match &self.storage {
            Some(s) => s.clone(),
            None => Arc::new(crate::storage::InMemoryConsensusStorage::new()),
        };

        let validator = crate::startup_validation::ConsensusStartupValidator::new(
            governance,
            backend_registry,
            storage,
        );

        validator.validate()?;
        Ok(())
    }

    /// Create a new `NodeHotstuffHarness` from a `NodeValidatorConfig`.
    ///
    /// This is a convenience constructor that builds all necessary components
    /// from a validator configuration. It uses default values for:
    /// - Ping interval: 50ms
    /// - Liveness timeout: 60s
    /// - Max peers: 100
    ///
    /// # Arguments
    ///
    /// - `cfg`: The validator configuration
    /// - `client_cfg`: Client-side KEMTLS connection config
    /// - `server_cfg`: Server-side KEMTLS connection config
    ///
    /// # Returns
    ///
    /// A new `NodeHotstuffHarness` or an error if setup fails.
    ///
    /// # T143: ValidatorSigningKey Integration
    ///
    /// The signing key from `cfg.local.signing_key` is extracted and stored
    /// in the harness for signing votes and proposals.
    ///
    /// # T148: ValidatorSigner Abstraction
    ///
    /// The harness now uses the `ValidatorSigner` trait for all signing operations.
    /// A `LocalKeySigner` is created from the config's signing key and attached
    /// to the harness. This provides a clean boundary for future HSM/remote signer
    /// integration.
    ///
    /// # T149: Remote Signer Support
    ///
    /// Optionally accepts a `ValidatorSignerConfig` to control the signer backend:
    /// - `SignerBackend::LocalKeystore`: Direct in-process signing (default)
    /// - `SignerBackend::RemoteLoopback`: Remote signer protocol with loopback transport
    ///
    /// If `signer_cfg` is `None`, defaults to `LocalKeystore`.
    pub fn new_from_validator_config(
        cfg: &NodeValidatorConfig,
        client_cfg: ClientConnectionConfig,
        server_cfg: ServerConnectionConfig,
        signer_cfg: Option<crate::validator_config::ValidatorSignerConfig>,
    ) -> Result<Self, NodeHotstuffHarnessError> {
        // 1. Build NetServiceConfig + PeerValidatorMap from NodeValidatorConfig.
        let (net_cfg, id_map) = crate::validator_config::build_net_config_and_id_map_for_tests(
            cfg,
            client_cfg,
            server_cfg,
            Duration::from_millis(50),
            Duration::from_secs(60),
            100,
        );

        // 2. Build consensus-side validator set.
        let consensus_validators = cfg.build_consensus_validator_set_for_tests();

        // 3. Extract signing key from config (T143).
        // The signing key is stored as Arc<ValidatorSigningKey> in the config,
        // so we can clone the Arc (not the key bytes) to share it with the harness.
        // This avoids cloning the key material while still allowing the config
        // to be used elsewhere if needed.
        let signing_key = cfg.local.signing_key.clone();

        // 4. Build ValidatorSigner based on signer config (T148, T149).
        use crate::validator_config::EXPECTED_SUITE_ID;
        use crate::validator_signer::LocalKeySigner;

        // Default to LocalKeystore if no config provided
        let signer_cfg = signer_cfg.unwrap_or_default();

        let signer: Arc<dyn crate::validator_signer::ValidatorSigner> = match signer_cfg.backend {
            crate::validator_config::SignerBackend::LocalKeystore => {
                // Direct in-process signing with LocalKeySigner (T148)
                Arc::new(LocalKeySigner::new(
                    cfg.local.validator_id,
                    EXPECTED_SUITE_ID.as_u16(),
                    signing_key.clone(),
                ))
            }
            crate::validator_config::SignerBackend::RemoteLoopback => {
                // Remote signer protocol with loopback transport (T149)
                use crate::remote_signer::{LoopbackSignerTransport, RemoteSignerClient};

                // Create LocalKeySigner for the loopback transport
                let local_signer = Arc::new(LocalKeySigner::new(
                    cfg.local.validator_id,
                    EXPECTED_SUITE_ID.as_u16(),
                    signing_key.clone(),
                ));

                // Create loopback transport
                let transport = Arc::new(LoopbackSignerTransport::new(local_signer));

                // Create RemoteSignerClient
                Arc::new(RemoteSignerClient::new(
                    cfg.local.validator_id,
                    EXPECTED_SUITE_ID.as_u16(),
                    transport,
                ))
            }
        };

        // 5. Create the harness with the built components.
        let mut harness = Self::new(
            cfg.local.validator_id,
            net_cfg,
            consensus_validators,
            id_map,
        )?;

        // Attach both signer (T148) and signing_key (T143 backwards compat)
        harness.signer = Some(signer);
        harness.signing_key = Some(signing_key);

        Ok(harness)
    }

    /// One iteration of the node-side consensus simulation.
    ///
    /// This method:
    /// 1. Advances the network (accept, ping-sweep, prune) via `step_network()`
    /// 2. Polls for consensus events via `try_recv_one()`
    /// 3. Processes events through the `BasicHotStuffEngine` methods
    /// 4. Tries to propose if this node is the leader and pacemaker allows
    /// 5. Applies resulting actions back to the network
    /// 6. Drains new commits and applies them to the commit index
    ///
    /// This is a HotStuff-specific step function that directly drives the
    /// `BasicHotStuffEngine` for proposal generation, vote processing, and
    /// QC formation.
    ///
    /// # Backward Compatibility (T86)
    ///
    /// This method is preserved for compatibility with existing code. It
    /// delegates to `on_tick()` which contains the actual implementation.
    /// New code using the event-driven interface should call `on_tick()`
    /// directly.
    pub fn step_once(&mut self) -> Result<(), NodeHotstuffHarnessError> {
        self.on_tick()
    }

    // ========================================================================
    // Event-driven interface (T86)
    // ========================================================================

    /// Handle a consensus tick event.
    ///
    /// This method contains the tick-related logic extracted from `step_once()`:
    /// 1. Advances the network (accept, ping-sweep, prune)
    /// 2. Polls for and processes pending network messages
    /// 3. Consults the pacemaker and tries to propose if allowed
    /// 4. Drains and persists any new commits
    ///
    /// This method is **synchronous** - it does not depend on Tokio directly.
    /// The async `AsyncNodeRunner` calls this method on timer ticks and when
    /// it receives `ConsensusEvent::Tick` from the channel.
    ///
    /// # Note
    ///
    /// For compatibility, `step_once()` is preserved and calls this method.
    /// New code should prefer calling `on_tick()` directly when using the
    /// event-driven interface.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if network, consensus, or storage fails.
    pub fn on_tick(&mut self) -> Result<(), NodeHotstuffHarnessError> {
        use crate::peer::PeerId;
        use std::time::Instant;

        // 1. Advance network (accept, ping-sweep, prune).
        self.sim.node.step_network()?;

        // 2. Process pending network events.
        // We process multiple events per step to ensure responsiveness.
        // Run all iterations to ensure we don't miss any messages.
        // We use with_consensus_network() to abstract away the underlying adapter (T96.1).
        for _ in 0..10 {
            // Non-blocking poll for one event via the ConsensusNode abstraction.
            let maybe_event: Option<ConsensusNetworkEvent<PeerId>> = self
                .sim
                .node
                .with_consensus_network(|net| net.try_recv_one())
                .map_err(|e| NodeHotstuffHarnessError::Config(format!("network error: {}", e)))?;

            if let Some(event) = maybe_event {
                self.process_network_event(event)?;
            }
            // Continue all iterations to ensure we process all pending messages.
            // With non-blocking I/O, messages may arrive at any time.
        }

        // 2b. T147: Drain verification results and process verified messages.
        // This must happen after network events are submitted to the pool but before
        // the pacemaker logic, so that verified votes can contribute to QC formation.
        self.drain_verification_results()?;

        // 3. Consult the pacemaker to decide if we should try to propose.
        // Get the current view from the engine.
        let engine_view = self.sim.driver.engine().current_view();
        let should_try = self.pacemaker.on_tick(engine_view);

        // 3b. T146: Check timeout pacemaker for timeout/view-change events.
        // This is independent of the regular proposal pacemaker.
        if self.timeout_enabled {
            let timeout_event = self
                .timeout_pacemaker
                .on_tick_with_time(Instant::now(), engine_view);
            match timeout_event {
                PacemakerEvent::None => {
                    // No timeout event, continue normally
                }
                PacemakerEvent::Timeout { view } => {
                    // Emit a TimeoutMsg for this view
                    self.emit_timeout_msg(view)?;
                }
                PacemakerEvent::NewView { view } => {
                    // Advance to the new view (triggered by TimeoutCertificate)
                    eprintln!(
                        "[T146] NewView event: advancing from view {} to view {}",
                        engine_view, view
                    );
                    self.sim.driver.engine_mut().set_view(view);
                    self.timeout_pacemaker.on_progress();
                }
                PacemakerEvent::ShouldPropose => {
                    // This event is not used by TimeoutPacemaker in current implementation
                }
            }
        }

        // 4. Try to propose if the pacemaker allows and we are the leader.
        // Note: try_propose() internally checks if we're the leader for the current view.
        if should_try {
            for action in self.sim.driver.engine_mut().try_propose() {
                self.apply_action(action)?;
            }
        }

        // 5. Drain new commits and apply to commit index.
        self.drain_and_persist_commits()?;

        Ok(())
    }

    /// Emit a TimeoutMsg when the current view times out (T146).
    ///
    /// This method constructs and broadcasts a `TimeoutMsg` containing:
    /// - The timed-out view number
    /// - The node's highest known QC (high_qc)
    /// - The node's validator ID
    /// - A signature over (view, high_qc, validator_id) using ML-DSA-44
    ///
    /// # Arguments
    ///
    /// - `view`: The view number that has timed out.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if signing or broadcasting fails.
    fn emit_timeout_msg(&mut self, view: u64) -> Result<(), NodeHotstuffHarnessError> {
        use qbind_consensus::timeout::TIMEOUT_SUITE_ID;

        // Get the highest QC known to this node (may be None)
        let high_qc = self.sim.driver.engine().state().locked_qc().cloned();

        // Sign the timeout message
        // T148: Use signer abstraction if available (preferred path)
        // T146: Fallback to signing_key for backwards compatibility
        let signature = if let Some(ref signer) = self.signer {
            // Use ValidatorSigner abstraction (T148)
            match signer.sign_timeout(view, high_qc.as_ref()) {
                Ok(sig_bytes) => sig_bytes,
                Err(e) => {
                    eprintln!(
                        "[T148] Warning: Failed to sign TimeoutMsg via signer: {:?}",
                        e
                    );
                    vec![0u8; 64] // Fallback for now
                }
            }
        } else if let Some(ref signing_key) = self.signing_key {
            // Fallback: Use the direct signing key (T146 legacy path)
            use qbind_consensus::timeout_signing_bytes;
            let sign_bytes = timeout_signing_bytes(view, high_qc.as_ref(), self.validator_id);
            match signing_key.sign(&sign_bytes) {
                Ok(sig_bytes) => sig_bytes,
                Err(e) => {
                    eprintln!("[T146] Warning: Failed to sign TimeoutMsg: {:?}", e);
                    vec![0u8; 64] // Fallback for now
                }
            }
        } else {
            // No signer or signing key available - use dummy signature for testing
            eprintln!(
                "[T146] Warning: No signer/signing key available for TimeoutMsg, using dummy signature"
            );
            vec![0u8; 64]
        };

        // Construct the TimeoutMsg using the constructor
        let mut timeout_msg = TimeoutMsg::new(view, high_qc, self.validator_id);
        timeout_msg.set_signature(signature);

        // Verify the suite_id is correct (should be 100 for ML-DSA-44)
        debug_assert_eq!(timeout_msg.suite_id, TIMEOUT_SUITE_ID);

        eprintln!(
            "[T146] Emitting TimeoutMsg for view {} from validator {:?}",
            view, self.validator_id
        );

        // Broadcast to all peers
        self.broadcast_timeout_msg(&timeout_msg)?;

        Ok(())
    }

    /// Broadcast a TimeoutMsg to all connected peers.
    fn broadcast_timeout_msg(
        &mut self,
        timeout_msg: &TimeoutMsg<[u8; 32]>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        // Serialize the timeout message for network transmission
        let msg_bytes = self.serialize_timeout_msg(timeout_msg);

        // Use the network facade if available for broadcasting
        if let Some(ref facade) = self.net_facade {
            // Get peer IDs from the identity map
            let peer_ids: Vec<crate::peer::PeerId> = self
                .sim
                .node
                .id_map()
                .iter()
                .map(|(peer_id, _)| *peer_id)
                .collect();

            // Send to each peer via the facade
            for peer_id in &peer_ids {
                if let Err(e) = facade.send_timeout_msg(*peer_id, msg_bytes.clone()) {
                    eprintln!(
                        "[T146] Warning: Failed to send TimeoutMsg to peer {:?}: {:?}",
                        peer_id, e
                    );
                }
            }

            eprintln!(
                "[T146] Broadcast TimeoutMsg to {} peers via facade",
                peer_ids.len()
            );
        } else {
            // No facade attached - timeout messages won't be sent over network
            // This is fine for some test scenarios
            eprintln!("[T146] TimeoutMsg broadcast skipped (no facade attached)");
        }

        Ok(())
    }

    /// Serialize a TimeoutMsg for network transmission.
    fn serialize_timeout_msg(&self, timeout_msg: &TimeoutMsg<[u8; 32]>) -> Vec<u8> {
        // Simple serialization format:
        // - view (8 bytes, LE)
        // - has_high_qc (1 byte: 0 or 1)
        // - if has_high_qc: block_id (32 bytes) + qc_view (8 bytes)
        // - validator_id (8 bytes, LE)
        // - suite_id (1 byte)
        // - signature_len (4 bytes, LE)
        // - signature (variable)
        let mut bytes = Vec::new();

        // View
        bytes.extend_from_slice(&timeout_msg.view.to_le_bytes());

        // High QC (optional)
        if let Some(ref qc) = timeout_msg.high_qc {
            bytes.push(1u8); // has_high_qc = true
            bytes.extend_from_slice(&qc.block_id);
            bytes.extend_from_slice(&qc.view.to_le_bytes());
        } else {
            bytes.push(0u8); // has_high_qc = false
        }

        // Validator ID
        bytes.extend_from_slice(&timeout_msg.validator_id.0.to_le_bytes());

        // Suite ID
        bytes.push(timeout_msg.suite_id);

        // Signature (length-prefixed)
        let sig_len = timeout_msg.signature.len() as u32;
        bytes.extend_from_slice(&sig_len.to_le_bytes());
        bytes.extend_from_slice(&timeout_msg.signature);

        bytes
    }

    /// Handle an incoming consensus message from the network.
    ///
    /// This method processes a single consensus message (vote or proposal)
    /// received from another validator. It is designed to be called by the
    /// async runtime when a message arrives via the event channel.
    ///
    /// # Arguments
    ///
    /// * `event` - The consensus network event containing the message.
    ///   This is a `ConsensusNetworkEvent<PeerId>` which can be:
    ///   - `IncomingVote { from, vote }` - A vote from another validator
    ///   - `IncomingProposal { from, proposal }` - A block proposal
    ///
    /// # Processing
    ///
    /// - **Proposals**: Stored in the block store, then processed by the engine.
    ///   Any resulting action (e.g., broadcast a vote) is applied.
    ///
    /// - **Votes**: Processed by the engine's vote accumulator. If a QC is
    ///   formed, the pacemaker is notified.
    ///
    /// # Note
    ///
    /// This method is **synchronous** - it does not depend on Tokio directly.
    /// It may be called from within `on_tick()` (for messages from the network
    /// layer) or from the async runtime when messages arrive via the channel.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if processing fails.
    pub fn on_incoming_message(
        &mut self,
        event: ConsensusNetworkEvent<crate::peer::PeerId>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        self.process_network_event(event)?;
        // After processing an incoming message, drain any commits that may have resulted.
        self.drain_and_persist_commits()?;
        Ok(())
    }

    /// Internal helper to process a single network event.
    ///
    /// This is shared between `on_tick()` (which polls the network) and
    /// `on_incoming_message()` (which receives events from the channel).
    ///
    /// # Verification Pool Mode (T147)
    ///
    /// When a verification pool is attached, incoming messages are:
    /// 1. Parsed and stored in `pending_proposals`/`pending_votes`
    /// 2. Submitted to the verification pool as jobs
    /// 3. Processed later when results are available (see `drain_verification_results`)
    ///
    /// When no pool is attached, messages are processed synchronously (legacy mode).
    fn process_network_event(
        &mut self,
        event: ConsensusNetworkEvent<crate::peer::PeerId>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        // T147: If verification pool is attached, submit jobs instead of synchronous processing
        if self.verify_pool.is_some() {
            return self.process_network_event_async(event);
        }

        // Legacy synchronous processing (no verification pool)
        match event {
            ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
                // Store the incoming proposal in the block store (idempotent).
                // This ensures that followers have proposals available for
                // committed blocks proposed by other validators.
                self.block_store.insert(proposal.clone())?;

                // Look up the ValidatorId for this peer
                let from_validator = self
                    .sim
                    .node
                    .get_validator_for_peer(&from)
                    .unwrap_or(ValidatorId::new(from.0));

                // Process the proposal through the engine
                let action = self
                    .sim
                    .driver
                    .engine_mut()
                    .on_proposal_event(from_validator, &proposal);

                // Apply any resulting action
                if let Some(action) = action {
                    self.apply_action(action)?;
                }
            }
            ConsensusNetworkEvent::IncomingVote { from, vote } => {
                // Look up the ValidatorId for this peer
                let from_validator = self
                    .sim
                    .node
                    .get_validator_for_peer(&from)
                    .unwrap_or(ValidatorId::new(from.0));

                // Process the vote through the engine
                let result = self
                    .sim
                    .driver
                    .engine_mut()
                    .on_vote_event(from_validator, &vote);

                // If a QC was formed, notify the pacemaker
                if let Ok(Some(qc)) = result {
                    self.pacemaker.on_qc(qc.view);
                }
            }
        }
        Ok(())
    }

    /// T147: Process a network event asynchronously via the verification pool.
    ///
    /// This method submits verification jobs and stores pending messages.
    /// The actual processing happens when results are drained.
    fn process_network_event_async(
        &mut self,
        event: ConsensusNetworkEvent<crate::peer::PeerId>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        let pool = self.verify_pool.as_ref().expect("verify_pool must be Some");

        match event {
            ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
                // Store the incoming proposal in the block store (idempotent).
                self.block_store.insert(proposal.clone())?;

                // Look up the ValidatorId for this peer
                let from_validator = self
                    .sim
                    .node
                    .get_validator_for_peer(&from)
                    .unwrap_or(ValidatorId::new(from.0));

                // Generate a unique key for this pending message
                let key = (proposal.header.round, from_validator.as_u64());

                // Create verification job
                let job = ConsensusVerifyJob::new_proposal(
                    proposal.header.round,
                    proposal.header.payload_hash,
                    from_validator,
                    proposal.header.suite_id,
                    proposal.signing_preimage(),
                    proposal.signature.clone(),
                );

                // Submit job (best effort - drop if queue full)
                if pool.submit(job).is_ok() {
                    // Store pending proposal for later processing
                    self.pending_proposals.insert(key, proposal);
                } else {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "[T147] Dropped proposal verification job (queue full): view={}",
                        proposal.header.round
                    );
                }
            }
            ConsensusNetworkEvent::IncomingVote { from, vote } => {
                // Look up the ValidatorId for this peer
                let from_validator = self
                    .sim
                    .node
                    .get_validator_for_peer(&from)
                    .unwrap_or(ValidatorId::new(from.0));

                // Generate a unique key for this pending message
                let key = (vote.round, from_validator.as_u64());

                // Create verification job
                let job = ConsensusVerifyJob::new_vote(
                    vote.round,
                    vote.block_id,
                    from_validator,
                    vote.suite_id,
                    vote.signing_preimage(),
                    vote.signature.clone(),
                );

                // Submit job (best effort - drop if queue full)
                if pool.submit(job).is_ok() {
                    // Store pending vote for later processing
                    self.pending_votes.insert(key, vote);
                } else {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "[T147] Dropped vote verification job (queue full): view={}",
                        vote.round
                    );
                }
            }
        }
        Ok(())
    }

    /// T147: Drain verification results and process verified messages.
    ///
    /// This method should be called in the main loop to process messages
    /// that have been verified by the pool.
    fn drain_verification_results(&mut self) -> Result<(), NodeHotstuffHarnessError> {
        let pool = match &self.verify_pool {
            Some(p) => p,
            None => return Ok(()), // No pool attached
        };

        // Drain all available results
        let results = pool.drain_results();

        for result in results {
            let key = (result.job.view, result.job.validator_id.as_u64());

            if !result.ok {
                // Verification failed - drop the message
                #[cfg(debug_assertions)]
                eprintln!(
                    "[T147] Verification failed for {:?} from validator {:?}: {:?}",
                    result.job.kind, result.job.validator_id, result.error
                );

                // Remove pending message
                match result.job.kind {
                    ConsensusMsgKind::Proposal => {
                        self.pending_proposals.remove(&key);
                    }
                    ConsensusMsgKind::Vote | ConsensusMsgKind::Timeout => {
                        self.pending_votes.remove(&key);
                    }
                }
                continue;
            }

            // Verification succeeded - process the message
            match result.job.kind {
                ConsensusMsgKind::Proposal => {
                    if let Some(proposal) = self.pending_proposals.remove(&key) {
                        // Process the proposal through the engine
                        let action = self
                            .sim
                            .driver
                            .engine_mut()
                            .on_proposal_event(result.job.validator_id, &proposal);

                        // Apply any resulting action
                        if let Some(action) = action {
                            self.apply_action(action)?;
                        }
                    }
                }
                ConsensusMsgKind::Vote => {
                    if let Some(vote) = self.pending_votes.remove(&key) {
                        // Process the vote through the engine
                        let engine_result = self
                            .sim
                            .driver
                            .engine_mut()
                            .on_vote_event(result.job.validator_id, &vote);

                        // If a QC was formed, notify the pacemaker
                        if let Ok(Some(qc)) = engine_result {
                            self.pacemaker.on_qc(qc.view);
                        }
                    }
                }
                ConsensusMsgKind::Timeout => {
                    // Timeout messages are handled separately via the timeout accumulator
                    // For now, we just remove the pending entry
                    self.pending_votes.remove(&key);
                }
            }
        }

        Ok(())
    }

    /// Internal helper to drain commits and persist them to storage.
    fn drain_and_persist_commits(&mut self) -> Result<(), NodeHotstuffHarnessError> {
        use std::time::Instant;

        let new_commits: Vec<NodeCommitInfo<[u8; 32]>> = self.sim.drain_commits();
        if !new_commits.is_empty() {
            // Record commit start time for latency tracking (T107)
            let commit_start = Instant::now();

            // Apply to in-memory commit index first
            self.commit_index.apply_commits(new_commits.clone())?;

            // T151: Apply committed blocks to execution adapter (if attached)
            // We need to decode transactions and create QbindBlocks for the adapter
            if let Some(ref execution_adapter) = self.execution_adapter {
                for commit_info in &new_commits {
                    // Get the block proposal from store
                    if let Some(stored_block) = self.block_store.get(&commit_info.block_id) {
                        // Decode transactions from proposal.txs
                        let mut decoded_txs = Vec::new();
                        for tx_bytes in &stored_block.proposal.txs {
                            // Decode QbindTransaction from bytes
                            // Format: sender(TX_SENDER_SIZE) + nonce(TX_NONCE_SIZE) + payload_len(TX_PAYLOAD_LEN_SIZE) + payload + sig_len(TX_SIG_LEN_SIZE) + sig + suite_id(TX_SUITE_ID_SIZE)
                            if tx_bytes.len() < TX_SENDER_SIZE + TX_NONCE_SIZE + TX_PAYLOAD_LEN_SIZE
                            {
                                eprintln!("[T151] WARNING: Invalid transaction encoding, skipping");
                                continue;
                            }

                            let mut offset = 0;

                            // sender (TX_SENDER_SIZE bytes)
                            let mut sender = [0u8; TX_SENDER_SIZE];
                            sender.copy_from_slice(&tx_bytes[offset..offset + TX_SENDER_SIZE]);
                            offset += TX_SENDER_SIZE;

                            // nonce (TX_NONCE_SIZE bytes, LE)
                            let nonce = u64::from_le_bytes(
                                tx_bytes[offset..offset + TX_NONCE_SIZE]
                                    .try_into()
                                    .expect("slice with incorrect length"),
                            );
                            offset += TX_NONCE_SIZE;

                            // payload_len (TX_PAYLOAD_LEN_SIZE bytes, LE)
                            let payload_len = u32::from_le_bytes(
                                tx_bytes[offset..offset + TX_PAYLOAD_LEN_SIZE]
                                    .try_into()
                                    .expect("slice with incorrect length"),
                            ) as usize;
                            offset += TX_PAYLOAD_LEN_SIZE;

                            if tx_bytes.len() < offset + payload_len + TX_SIG_LEN_SIZE {
                                eprintln!("[T151] WARNING: Invalid transaction encoding (payload), skipping");
                                continue;
                            }

                            // payload
                            let payload = tx_bytes[offset..offset + payload_len].to_vec();
                            offset += payload_len;

                            // signature_len (TX_SIG_LEN_SIZE bytes, LE)
                            let sig_len = u32::from_le_bytes(
                                tx_bytes[offset..offset + TX_SIG_LEN_SIZE]
                                    .try_into()
                                    .expect("slice with incorrect length"),
                            ) as usize;
                            offset += TX_SIG_LEN_SIZE;

                            if tx_bytes.len() < offset + sig_len + TX_SUITE_ID_SIZE {
                                eprintln!("[T151] WARNING: Invalid transaction encoding (signature), skipping");
                                continue;
                            }

                            // signature
                            let signature = qbind_ledger::UserSignature::new(
                                tx_bytes[offset..offset + sig_len].to_vec(),
                            );
                            offset += sig_len;

                            // suite_id (TX_SUITE_ID_SIZE bytes, LE)
                            let suite_id = u16::from_le_bytes(
                                tx_bytes[offset..offset + TX_SUITE_ID_SIZE]
                                    .try_into()
                                    .expect("slice with incorrect length"),
                            );

                            let tx = qbind_ledger::QbindTransaction {
                                sender,
                                nonce,
                                payload,
                                signature,
                                suite_id,
                            };

                            decoded_txs.push(tx);
                        }

                        // Create QbindBlock
                        let qbind_block = crate::execution_adapter::QbindBlock::new(
                            stored_block.proposal.clone(),
                            decoded_txs.clone(),
                        );

                        // Apply block to execution adapter
                        let mut adapter = execution_adapter.lock();
                        if let Err(e) = adapter.apply_block(&qbind_block) {
                            eprintln!(
                                "[T151] WARNING: Execution adapter failed for block at height {}: {}",
                                commit_info.height, e
                            );
                            // For T151, we log the error but don't fail the commit
                            // Future versions may have different error policies
                        }

                        // T151: Remove committed transactions from mempool
                        if let Some(ref mempool) = self.mempool {
                            mempool.remove_committed(&decoded_txs);
                        }
                    }
                }
            }

            // If storage is attached, persist the commits (T82)
            if let Some(storage) = &self.storage {
                for commit_info in &new_commits {
                    // Try to get the block from our in-memory store
                    if let Some(stored_block) = self.block_store.get(&commit_info.block_id) {
                        // Persist the block (including suite_id via wire encoding)
                        storage.put_block(&commit_info.block_id, &stored_block.proposal)?;

                        // If the block has a QC, persist it too
                        if let Some(ref qc) = stored_block.proposal.qc {
                            storage.put_qc(&commit_info.block_id, qc)?;
                        }
                    }

                    // Update last committed (critical for restart)
                    storage.put_last_committed(&commit_info.block_id)?;

                    // Debug log for observability (Part E)
                    eprintln!(
                        "[T82] Persisted commit: block_id={:?}, height={}",
                        &commit_info.block_id[..8],
                        commit_info.height
                    );
                }
            }

            // Record commit latency if metrics are attached (T107)
            // We record one duration for the entire batch of commits
            if let Some(ref metrics) = self.metrics {
                metrics.commit().record_commit(commit_start.elapsed());
            }

            // T102.1: Check for reconfig blocks and perform epoch transitions
            for commit_info in &new_commits {
                self.handle_potential_reconfig_commit(&commit_info.block_id)?;
            }
        }
        Ok(())
    }

    /// T102.1: Handle potential epoch transition when a reconfig block commits.
    ///
    /// This method checks if a committed block is a reconfig block (payload_kind == RECONFIG).
    /// If so, it fetches the next epoch's state from the provider and transitions
    /// the engine to the new epoch.
    ///
    /// # Atomic Epoch Transition (T112)
    ///
    /// To ensure crash-safe epoch transitions, operations are ordered as follows:
    /// 1. Validate the epoch state (fetch from provider, check non-empty)
    /// 2. Persist the new epoch to storage FIRST
    /// 3. Then update the in-memory engine state
    ///
    /// This ordering ensures that if we crash:
    /// - Before step 2: Storage still has old epoch, engine was at old epoch → consistent
    /// - After step 2 but before step 3: Storage has new epoch, engine was at old epoch
    ///   → On restart, we restore from storage and correctly see new epoch
    /// - After step 3: Both storage and engine have new epoch → consistent
    ///
    /// The key insight is: storage is the source of truth on restart. As long as
    /// storage is updated atomically before engine state, restart will always see
    /// a consistent view.
    ///
    /// # Test-Only Public Access (T125.1)
    ///
    /// This method is public for testing purposes to allow integration tests
    /// to directly test runtime suite downgrade protection. It should not be
    /// used in production code.
    #[doc(hidden)]
    pub fn test_handle_potential_reconfig_commit(
        &mut self,
        block_id: &[u8; 32],
    ) -> Result<(), NodeHotstuffHarnessError> {
        self.handle_potential_reconfig_commit(block_id)
    }

    fn handle_potential_reconfig_commit(
        &mut self,
        block_id: &[u8; 32],
    ) -> Result<(), NodeHotstuffHarnessError> {
        // Get the stored block to check its payload type
        let stored_block = match self.block_store.get(block_id) {
            Some(b) => b,
            None => {
                // Block not in store - this can happen for commits we received
                // proposals for from other validators. Skip reconfig check.
                return Ok(());
            }
        };

        let proposal = &stored_block.proposal;

        // Check if this is a reconfig block
        if proposal.header.payload_kind != qbind_wire::PAYLOAD_KIND_RECONFIG {
            // Normal block - nothing to do
            return Ok(());
        }

        let next_epoch = proposal.header.next_epoch;
        let next_epoch_id = EpochId::new(next_epoch);

        eprintln!(
            "[T102.1] Reconfig block committed at height {}, next_epoch={}",
            proposal.header.height, next_epoch
        );

        // Get the epoch state provider
        let provider = match &self.epoch_state_provider {
            Some(p) => p,
            None => {
                eprintln!(
                    "[T102.1] WARNING: No epoch state provider configured, \
                     skipping epoch transition to epoch {}",
                    next_epoch
                );
                return Ok(());
            }
        };

        // Fetch the epoch state for the next epoch
        let epoch_state = match provider.get_epoch_state(next_epoch_id) {
            Some(state) => state,
            None => {
                // This is a hard error - we committed a reconfig block but
                // don't have the epoch state for the transition
                return Err(NodeHotstuffHarnessError::Config(format!(
                    "epoch state not available for epoch {} (reconfig block committed at height {})",
                    next_epoch, proposal.header.height
                )));
            }
        };

        // Validate the epoch state against governance (strict mode)
        // For now, we just check that the epoch state is non-empty
        // (validate_with_governance requires governance and backend registry which
        // we don't have at this layer; that's done at startup validation)
        if epoch_state.is_empty() {
            return Err(NodeHotstuffHarnessError::Config(format!(
                "epoch {} has empty validator set",
                next_epoch
            )));
        }

        // T125: Runtime suite validation for epoch transitions
        self.validate_runtime_suite_transition(&epoch_state, next_epoch_id)?;

        // Get the validator set from the epoch state
        let new_validator_set = epoch_state.validators().clone();

        // T112: Persist the new epoch to storage FIRST (before updating engine state).
        // This ensures that if we crash after persistence but before engine update,
        // restart will correctly restore from storage and see the new epoch.
        if let Some(storage) = &self.storage {
            storage.put_current_epoch(next_epoch)?;
            eprintln!(
                "[T112] Persisted epoch {} to storage BEFORE engine transition",
                next_epoch
            );
        }

        // Now transition the engine to the new epoch (T112: after storage persistence)
        // If this fails, storage already has the new epoch - on restart we'll
        // correctly restore to the new epoch from storage.
        self.sim
            .driver
            .engine_mut()
            .transition_to_epoch(next_epoch_id, new_validator_set)?;

        // Update the epoch_state field to reflect the new epoch
        self.epoch_state = Some(epoch_state);

        eprintln!(
            "[T102.1] Successfully transitioned to epoch {} (validator_count={})",
            next_epoch,
            self.epoch_state.as_ref().map(|e| e.len()).unwrap_or(0)
        );

        Ok(())
    }

    /// Apply a consensus engine action to the network (T96.1).
    ///
    /// When a `BroadcastProposal` action is received, the proposal is:
    /// 1. Signed using the validator signing key (T143)
    /// 2. Stored in the local `BlockStore` for later retrieval
    /// 3. Broadcast to all connected peers via the network facade
    ///
    /// When a `BroadcastVote` or `SendVoteTo` action is received, the vote is:
    /// 1. Signed using the validator signing key (T143)
    /// 2. Broadcast/sent to the appropriate peers
    ///
    /// This ensures that locally proposed blocks are available for:
    /// - Commit index lookups
    /// - State machine replay
    /// - Debugging and inspection
    ///
    /// # Network Interface
    ///
    /// If a network facade is attached (via `with_net_facade`), all outbound
    /// operations go through the facade. Otherwise, we use
    /// `ConsensusNode::with_consensus_network()` as a fallback (legacy mode).
    ///
    /// # T143: ValidatorSigningKey Integration
    ///
    /// Votes and proposals are signed using the validator signing key before
    /// broadcasting. If no signing key is configured, actions are broadcast
    /// without signatures (for backward compatibility in tests).
    ///
    /// # T148: ValidatorSigner Abstraction
    ///
    /// When a signer is attached (via `with_signer`), it takes precedence over
    /// direct signing key usage. This provides a clean abstraction boundary
    /// for future HSM/remote signer integration.
    fn apply_action(
        &mut self,
        mut action: ConsensusEngineAction<ValidatorId>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        // T151: Populate proposal with transactions from mempool BEFORE signing
        if let ConsensusEngineAction::BroadcastProposal(ref mut proposal) = action {
            if let Some(ref mempool) = self.mempool {
                let txs = mempool.get_block_candidates(self.max_txs_per_block);

                // Serialize transactions to Vec<Vec<u8>>
                // For now, use simple serialization: for QbindTransaction, we need to encode it
                // We'll use a simple format since QbindTransaction doesn't have WireEncode yet
                proposal.txs = txs
                    .iter()
                    .map(|tx| {
                        // Simple serialization: we'll encode as a bincode-style format
                        // For T151, we'll use a minimal encoding
                        let mut bytes = Vec::new();
                        // sender (TX_SENDER_SIZE bytes)
                        bytes.extend_from_slice(&tx.sender);
                        // nonce (TX_NONCE_SIZE bytes, LE)
                        bytes.extend_from_slice(&tx.nonce.to_le_bytes());
                        // payload length (TX_PAYLOAD_LEN_SIZE bytes, LE)
                        bytes.extend_from_slice(&(tx.payload.len() as u32).to_le_bytes());
                        // payload
                        bytes.extend_from_slice(&tx.payload);
                        // signature length (TX_SIG_LEN_SIZE bytes, LE)
                        bytes.extend_from_slice(&(tx.signature.bytes.len() as u32).to_le_bytes());
                        // signature
                        bytes.extend_from_slice(&tx.signature.bytes);
                        // suite_id (TX_SUITE_ID_SIZE bytes, LE)
                        bytes.extend_from_slice(&tx.suite_id.to_le_bytes());
                        bytes
                    })
                    .collect();

                proposal.header.tx_count = proposal.txs.len() as u32;
            }
        }

        // T148: Sign via signer abstraction (takes precedence over signing_key)
        // T143: Fallback to direct signing_key for backwards compatibility
        if let Some(ref signer) = self.signer {
            // Use ValidatorSigner abstraction (T148 - preferred path)
            match &mut action {
                ConsensusEngineAction::BroadcastProposal(ref mut proposal) => {
                    // Update suite_id to match the signer's suite
                    proposal.header.suite_id = signer.suite_id();

                    // Sign the proposal via signer
                    let preimage = proposal.signing_preimage();
                    match signer.sign_proposal(&preimage) {
                        Ok(signature) => {
                            proposal.signature = signature;
                        }
                        Err(e) => {
                            return Err(NodeHotstuffHarnessError::Config(format!(
                                "Failed to sign proposal via signer: {:?}",
                                e
                            )));
                        }
                    }
                }
                ConsensusEngineAction::BroadcastVote(ref mut vote) => {
                    // Update suite_id to match the signer's suite
                    vote.suite_id = signer.suite_id();

                    // Sign the vote via signer
                    let preimage = vote.signing_preimage();
                    match signer.sign_vote(&preimage) {
                        Ok(signature) => {
                            vote.signature = signature;
                        }
                        Err(e) => {
                            return Err(NodeHotstuffHarnessError::Config(format!(
                                "Failed to sign vote via signer: {:?}",
                                e
                            )));
                        }
                    }
                }
                ConsensusEngineAction::SendVoteTo { ref mut vote, .. } => {
                    // Update suite_id to match the signer's suite
                    vote.suite_id = signer.suite_id();

                    // Sign the vote via signer
                    let preimage = vote.signing_preimage();
                    match signer.sign_vote(&preimage) {
                        Ok(signature) => {
                            vote.signature = signature;
                        }
                        Err(e) => {
                            return Err(NodeHotstuffHarnessError::Config(format!(
                                "Failed to sign vote via signer: {:?}",
                                e
                            )));
                        }
                    }
                }
                ConsensusEngineAction::Noop => {
                    // Nothing to sign
                }
            }
        } else if let Some(ref signing_key) = self.signing_key {
            // Fallback: Direct signing key usage (T143 - legacy path)
            match &mut action {
                ConsensusEngineAction::BroadcastProposal(ref mut proposal) => {
                    // Update suite_id to ML-DSA-44 (100) before signing
                    use qbind_crypto::suite_catalog::SUITE_PQ_RESERVED_1;
                    proposal.header.suite_id = SUITE_PQ_RESERVED_1.as_u16();

                    // Sign the proposal
                    let preimage = proposal.signing_preimage();
                    match signing_key.sign(&preimage) {
                        Ok(signature) => {
                            proposal.signature = signature;
                        }
                        Err(e) => {
                            return Err(NodeHotstuffHarnessError::Config(format!(
                                "Failed to sign proposal: {:?}",
                                e
                            )));
                        }
                    }
                }
                ConsensusEngineAction::BroadcastVote(ref mut vote) => {
                    use qbind_crypto::suite_catalog::SUITE_PQ_RESERVED_1;
                    vote.suite_id = SUITE_PQ_RESERVED_1.as_u16();

                    let preimage = vote.signing_preimage();
                    match signing_key.sign(&preimage) {
                        Ok(signature) => {
                            vote.signature = signature;
                        }
                        Err(e) => {
                            return Err(NodeHotstuffHarnessError::Config(format!(
                                "Failed to sign vote: {:?}",
                                e
                            )));
                        }
                    }
                }
                ConsensusEngineAction::SendVoteTo { ref mut vote, .. } => {
                    use qbind_crypto::suite_catalog::SUITE_PQ_RESERVED_1;
                    vote.suite_id = SUITE_PQ_RESERVED_1.as_u16();

                    let preimage = vote.signing_preimage();
                    match signing_key.sign(&preimage) {
                        Ok(signature) => {
                            vote.signature = signature;
                        }
                        Err(e) => {
                            return Err(NodeHotstuffHarnessError::Config(format!(
                                "Failed to sign vote: {:?}",
                                e
                            )));
                        }
                    }
                }
                ConsensusEngineAction::Noop => {
                    // Nothing to sign
                }
            }
        }

        // Handle the BroadcastProposal action specially to store the proposal first
        if let ConsensusEngineAction::BroadcastProposal(ref proposal) = action {
            // Store the proposal in our local block store before broadcasting.
            // This ensures we have a copy of all proposals we create.
            let _block_id = self.block_store.store_proposal(proposal);
        }

        // Dispatch to the appropriate network interface
        if let Some(ref facade) = self.net_facade {
            // Use the attached network facade (T96.1 - preferred path)
            self.apply_action_via_facade(action, facade.as_ref())
        } else {
            // Fallback: use with_consensus_network (legacy path)
            self.apply_action_via_node(action)
        }
    }

    /// Apply an action via the network facade (T96.1 - preferred path).
    fn apply_action_via_facade(
        &self,
        action: ConsensusEngineAction<ValidatorId>,
        facade: &dyn ConsensusNetworkFacade,
    ) -> Result<(), NodeHotstuffHarnessError> {
        match action {
            ConsensusEngineAction::BroadcastProposal(proposal) => {
                facade.broadcast_proposal(&proposal).map_err(|e| {
                    NodeHotstuffHarnessError::Config(format!("broadcast proposal error: {}", e))
                })?;
            }
            ConsensusEngineAction::BroadcastVote(vote) => {
                facade.broadcast_vote(&vote).map_err(|e| {
                    NodeHotstuffHarnessError::Config(format!("broadcast vote error: {}", e))
                })?;
            }
            ConsensusEngineAction::SendVoteTo { to, vote } => {
                // The facade handles ValidatorId directly - no PeerId conversion needed
                facade.send_vote_to(to, &vote).map_err(|e| {
                    NodeHotstuffHarnessError::Config(format!("send vote error: {}", e))
                })?;
            }
            ConsensusEngineAction::Noop => {
                // Nothing to do
            }
        }
        Ok(())
    }

    /// Apply an action via ConsensusNode::with_consensus_network (legacy fallback).
    fn apply_action_via_node(
        &mut self,
        action: ConsensusEngineAction<ValidatorId>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        use crate::peer::PeerId;

        self.sim.node.with_consensus_network(|net| {
            match action {
                ConsensusEngineAction::BroadcastProposal(proposal) => {
                    net.broadcast_proposal(&proposal).map_err(|e| {
                        NodeHotstuffHarnessError::Config(format!("broadcast proposal error: {}", e))
                    })
                }
                ConsensusEngineAction::BroadcastVote(vote) => {
                    net.broadcast_vote(&vote).map_err(|e| {
                        NodeHotstuffHarnessError::Config(format!("broadcast vote error: {}", e))
                    })
                }
                ConsensusEngineAction::SendVoteTo { to, vote } => {
                    // Convert ValidatorId to PeerId
                    // For now, use a simple mapping: ValidatorId(n) -> PeerId(n)
                    let peer_id = PeerId(to.0);
                    net.send_vote_to(peer_id, &vote).map_err(|e| {
                        NodeHotstuffHarnessError::Config(format!("send vote error: {}", e))
                    })
                }
                ConsensusEngineAction::Noop => Ok(()),
            }
        })
    }

    /// Get the local address the node is listening on.
    ///
    /// Useful for tests that bind to port 0 and need the actual assigned port.
    ///
    /// Note: This requires mutable access because the underlying `ConsensusNode`
    /// API uses mutable references for accessing `NetService`.
    pub fn local_addr(&mut self) -> io::Result<std::net::SocketAddr> {
        self.sim.node.net_service().local_addr()
    }

    /// Get the committed block ID, if any.
    ///
    /// Returns the block ID of the most recently committed block, or `None`
    /// if no block has been committed yet.
    pub fn committed_block(&self) -> Option<&[u8; 32]> {
        self.sim.driver.engine().committed_block()
    }

    /// Get the current view of the consensus engine.
    pub fn current_view(&self) -> u64 {
        self.sim.driver.engine().current_view()
    }

    /// Check if this node is the leader for the current view.
    pub fn is_leader_for_current_view(&self) -> bool {
        self.sim.driver.engine().is_leader_for_current_view()
    }

    /// Get the number of connected peers.
    pub fn peer_count(&mut self) -> usize {
        self.sim.node.net_service().peers().len()
    }

    /// Access the underlying driver for advanced inspection.
    pub fn driver(&self) -> &HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]> {
        &self.sim.driver
    }

    /// Mutably access the underlying driver.
    pub fn driver_mut(&mut self) -> &mut HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]> {
        &mut self.sim.driver
    }

    /// Drain all new committed blocks known to this node's HotStuff driver.
    ///
    /// This method returns all commits that have occurred since the last call
    /// to `drain_commits()`, and marks them as consumed. Subsequent calls will
    /// only return commits that occurred after the previous call.
    ///
    /// # Returns
    ///
    /// A vector of `NodeCommitInfo` representing all new commits. Returns an
    /// empty vector if no new commits have occurred.
    pub fn drain_commits(&mut self) -> Vec<NodeCommitInfo<[u8; 32]>> {
        self.sim.drain_commits()
    }

    /// Returns the current committed tip from the commit index, if any.
    ///
    /// This reflects the highest committed block tracked by the node's commit index.
    pub fn commit_tip(&self) -> Option<&NodeCommitInfo<[u8; 32]>> {
        self.commit_index.tip()
    }

    /// Returns the current committed height from the commit index, if any.
    ///
    /// This is the height of the highest committed block tracked by the node.
    pub fn committed_height(&self) -> Option<u64> {
        self.commit_index.tip().map(|c| c.height)
    }

    /// Returns the number of committed blocks tracked by the commit index.
    pub fn commit_count(&self) -> usize {
        self.commit_index.len()
    }

    // ========================================================================
    // BlockStore accessors
    // ========================================================================

    /// Access the block store.
    ///
    /// Returns a reference to the local block store containing all
    /// proposals that have been broadcast by this node.
    pub fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    /// Mutably access the block store.
    ///
    /// Allows direct manipulation of the block store, such as clearing
    /// old proposals or adding proposals received from other sources.
    pub fn block_store_mut(&mut self) -> &mut BlockStore {
        &mut self.block_store
    }

    /// Get the number of proposals stored in the block store.
    ///
    /// This reflects the number of proposals that have been broadcast
    /// by this node (and stored locally).
    pub fn block_store_count(&self) -> usize {
        self.block_store.len()
    }

    /// Retrieve a stored block from the block store by its block ID.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The block ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the stored `StoredBlock`, or `None` if not found.
    pub fn get_proposal(&self, block_id: &[u8; 32]) -> Option<&crate::block_store::StoredBlock> {
        self.block_store.get(block_id)
    }

    // ========================================================================
    // Draining committed blocks
    // ========================================================================

    /// Drain newly committed blocks (height > last_drained_height) in ascending
    /// height order. Each block is returned exactly once.
    ///
    /// Returns an empty `Vec` if there are no new commits.
    ///
    /// # Errors
    ///
    /// Returns `NodeHotstuffHarnessError::MissingProposalForCommittedBlock` if a
    /// committed block's proposal is not found in the block store. This should not
    /// happen in normal operation.
    pub fn drain_committed_blocks(
        &mut self,
    ) -> Result<Vec<NodeCommittedBlock<[u8; 32]>>, NodeHotstuffHarnessError> {
        let mut result = Vec::new();
        let last = self.last_drained_height;

        let mut max_seen = last;

        for (height, info) in self.commit_index.iter_by_height() {
            // Skip heights that have already been drained
            if let Some(last_h) = last {
                if *height <= last_h {
                    continue;
                }
            }

            let block_id = info.block_id;
            let stored = self.block_store.get(&block_id).ok_or(
                NodeHotstuffHarnessError::MissingProposalForCommittedBlock {
                    block_id,
                    height: *height,
                },
            )?;

            // Clone the Arc handle only, not the full proposal
            let proposal_arc = stored.proposal.clone();

            let committed = NodeCommittedBlock {
                block_id,
                view: info.view,
                height: info.height,
                proposal: proposal_arc,
            };
            result.push(committed);

            max_seen = Some(max_seen.map_or(*height, |curr| curr.max(*height)));
        }

        // Update the drain cursor
        if let Some(max_h) = max_seen {
            self.last_drained_height = Some(max_h);
        }

        Ok(result)
    }

    // ========================================================================
    // Pruning
    // ========================================================================

    /// Prune internal commit index and block store below the given height.
    ///
    /// Safe to call after the ledger has applied all commits up to at least `min_height`.
    pub fn prune_below_height(&mut self, min_height: u64) {
        self.commit_index.prune_below(min_height);
        self.block_store.prune_below(min_height);
    }

    /// T125: Validate runtime suite transition from current epoch to next epoch.
    ///
    /// This method checks that the transition from the current epoch's suite
    /// to the next epoch's suite is allowed under the current suite policy.
    /// It enforces cross-epoch suite monotonicity at runtime.
    ///
    /// # Arguments
    ///
    /// * `next_epoch_state` - The epoch state for the next epoch.
    /// * `next_epoch_id` - The ID of the next epoch.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the transition is allowed (equal or stronger security).
    /// * `Err(NodeHotstuffHarnessError::RuntimeSuiteDowngrade)` if the transition
    ///   is a downgrade (weaker security).
    ///
    /// # Implementation Details
    ///
    /// 1. If governance is not attached, fail fast for prod policy (T125.1 Part B).
    /// 2. Determine the current epoch's suite ID using `EpochState::epoch_suite_id()`.
    /// 3. Determine the next epoch's suite ID using the same method.
    /// 4. Use `SuitePolicy::check_transition_allowed()` to validate the transition.
    /// 5. Record metrics for allowed/rejected transitions.
    /// 6. Log the transition attempt (success or failure).
    fn validate_runtime_suite_transition(
        &self,
        next_epoch_state: &EpochState,
        next_epoch_id: EpochId,
    ) -> Result<(), NodeHotstuffHarnessError> {
        use qbind_crypto::suite_catalog::{effective_security_bits, suite_name};

        // T125.1 Part B: Fail fast if governance is not attached for prod-like deployments
        let governance = match &self.governance {
            Some(g) => g,
            None => {
                // For prod policy, fail fast if governance is not attached
                if !self.suite_policy.allow_toy {
                    return Err(NodeHotstuffHarnessError::Config(format!(
                        "Cannot validate runtime suite transition for epoch {}: \
                         governance is not attached (required for prod policy)",
                        next_epoch_id
                    )));
                }
                // For dev policy, skip validation with warning (backward compatibility)
                eprintln!(
                    "[T125] WARNING: No governance attached, skipping runtime suite validation for epoch {}",
                    next_epoch_id
                );
                return Ok(());
            }
        };

        // Determine current epoch's suite ID
        let current_epoch_id = self.sim.driver.engine().current_epoch();
        let current_epoch_state = match &self.epoch_state {
            Some(es) if es.epoch_id() == EpochId::new(current_epoch_id) => es,
            _ => {
                // Couldn't determine current epoch state - this might be the first epoch
                // or we're not tracking epoch state.
                // For prod policy, fail fast if we can't determine current epoch state
                if !self.suite_policy.allow_toy {
                    return Err(NodeHotstuffHarnessError::Config(format!(
                        "Cannot validate runtime suite transition for epoch {}: \
                         could not determine current epoch state (current_epoch={})",
                        next_epoch_id, current_epoch_id
                    )));
                }
                // For dev policy, skip validation with warning
                eprintln!(
                    "[T125] WARNING: Could not determine current epoch state (current_epoch={}), \
                     skipping runtime suite validation for epoch {}",
                    current_epoch_id, next_epoch_id
                );
                return Ok(());
            }
        };

        let from_suite = match current_epoch_state.epoch_suite_id(governance.as_ref()) {
            Ok(Some(suite)) => suite,
            Ok(None) => {
                // Couldn't determine suite for current epoch (mixed suites or no validators)
                // For prod policy, fail fast if we can't determine suite
                if !self.suite_policy.allow_toy {
                    return Err(NodeHotstuffHarnessError::Config(format!(
                        "Cannot validate runtime suite transition for epoch {}: \
                         could not determine suite for current epoch {} (mixed suites or no validators)",
                        next_epoch_id, current_epoch_id
                    )));
                }
                // For dev policy, skip validation with warning
                eprintln!(
                    "[T125] WARNING: Could not determine suite for current epoch {}, \
                     skipping runtime suite validation for epoch {}",
                    current_epoch_id, next_epoch_id
                );
                return Ok(());
            }
            Err(mixed_suites) => {
                // Mixed suites in current epoch
                // For prod policy, fail fast if epoch has mixed suites
                if !self.suite_policy.allow_toy {
                    return Err(NodeHotstuffHarnessError::Config(format!(
                        "Cannot validate runtime suite transition for epoch {}: \
                         current epoch {} has mixed suites {:?} (should have been rejected by startup validation)",
                        next_epoch_id, current_epoch_id, mixed_suites
                    )));
                }
                // For dev policy, skip validation with warning
                eprintln!(
                    "[T125] WARNING: Mixed suites in current epoch {}: {:?}, \
                     skipping runtime suite validation for epoch {}",
                    current_epoch_id, mixed_suites, next_epoch_id
                );
                return Ok(());
            }
        };

        let to_suite = match next_epoch_state.epoch_suite_id(governance.as_ref()) {
            Ok(Some(suite)) => suite,
            Ok(None) => {
                // Couldn't determine suite for next epoch (mixed suites or no validators)
                // This is always an error - we should be able to determine the suite for the next epoch
                return Err(NodeHotstuffHarnessError::Config(format!(
                    "Could not determine suite for next epoch {} (mixed suites or no validators)",
                    next_epoch_id
                )));
            }
            Err(mixed_suites) => {
                // Mixed suites in next epoch - this is always an error
                return Err(NodeHotstuffHarnessError::Config(format!(
                    "Mixed suites in next epoch {}: {:?}",
                    next_epoch_id, mixed_suites
                )));
            }
        };

        // Check if transition is allowed
        match self
            .suite_policy
            .check_transition_allowed(from_suite, to_suite)
        {
            Ok(()) => {
                // Transition allowed - record metrics and log
                if let Some(metrics) = &self.metrics {
                    metrics.suite_transition().record_runtime_ok();
                }

                let from_bits = effective_security_bits(from_suite);
                let to_bits = effective_security_bits(to_suite);
                let from_name = suite_name(from_suite);
                let to_name = suite_name(to_suite);

                eprintln!(
                    "[T125] Runtime suite transition allowed: epoch {} → {}: {} ({} bits) → {} ({} bits)",
                    current_epoch_id, next_epoch_id,
                    from_name, from_bits,
                    to_name, to_bits
                );
                Ok(())
            }
            Err(_err) => {
                // Transition rejected - record metrics and return error
                if let Some(metrics) = &self.metrics {
                    metrics.suite_transition().record_runtime_rejected();
                }

                let from_bits = effective_security_bits(from_suite);
                let to_bits = effective_security_bits(to_suite);
                let from_name = suite_name(from_suite);
                let to_name = suite_name(to_suite);

                eprintln!(
                    "[T125] ERROR: Runtime suite transition rejected: epoch {} → {}: {} ({} bits) → {} ({} bits)",
                    current_epoch_id, next_epoch_id,
                    from_name, from_bits,
                    to_name, to_bits
                );

                Err(NodeHotstuffHarnessError::RuntimeSuiteDowngrade {
                    from_epoch: EpochId::new(current_epoch_id),
                    to_epoch: next_epoch_id,
                    from_suite,
                    to_suite,
                })
            }
        }
    }

    /// Submit a transaction to the mempool (T151).
    ///
    /// This method provides a simple API for injecting user transactions into the node.
    /// The transaction is verified and admitted according to mempool policy.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to submit
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the transaction was admitted to the mempool
    /// * `Err(MempoolError)` if the transaction was rejected
    ///
    /// # Errors
    ///
    /// Returns `MempoolError::Invalid` if no mempool is configured.
    pub fn submit_transaction(
        &self,
        tx: qbind_ledger::QbindTransaction,
    ) -> Result<(), crate::mempool::MempoolError> {
        if let Some(ref mempool) = self.mempool {
            mempool.insert(tx)
        } else {
            Err(crate::mempool::MempoolError::Invalid(
                "no mempool configured".to_string(),
            ))
        }
    }
}