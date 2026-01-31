//! Node-local block pipeline for the qbind post-quantum blockchain.
//!
//! This crate integrates:
//!  - qbind-wire (BlockProposal, Transaction, WireDecode)
//!  - qbind-consensus (ValidatorSet, HotStuffState, BlockVerifyConfig, hotstuff_decide_and_maybe_record_vote)
//!  - qbind-runtime (BlockExecutor, BlockExecutionResult)
//!  - qbind-ledger (AccountStore)
//!  - qbind-crypto (CryptoProvider)
//!
//! Given a BlockProposal, validator set, HotStuffState, CryptoProvider, AccountStore, and BlockExecutor:
//!  1. Verify the block under consensus rules (structural + HotStuff safety).
//!  2. Decode transactions from the proposal.
//!  3. Execute them sequentially using BlockExecutor.
//!  4. Return a structured outcome.
//!
//! # Async Runtime (T85)
//!
//! The `async_runner` module provides `AsyncNodeRunner`, a Tokio-driven async wrapper
//! around the synchronous consensus loop. This allows the node's "heart" to be an
//! async event loop driven by `tokio::time::interval`, while keeping the consensus
//! core synchronous and deterministic.
//!
//! # Async Consensus Network Worker (T87)
//!
//! The `consensus_net_worker` module provides `ConsensusNetWorker`, an async worker
//! that bridges the existing network stack to the `AsyncNodeRunner` via the
//! `ConsensusEventSender` channel. This establishes a clear separation:
//! - Network worker(s): async tasks managing sockets, KEMTLS, and producing events
//! - Runtime: `AsyncNodeRunner` consuming events and driving the harness
//! - Consensus core: synchronous HotStuff logic
//!
//! # Observability (T89)
//!
//! The `metrics` module provides lightweight atomic counter-based metrics for
//! monitoring the async node runtime and consensus networking layer:
//! - Inbound/outbound message counts by type
//! - Channel health (drops, backpressure)
//! - Runtime event processing rates
//! - spawn_blocking usage and latency buckets
//!
//! # Async Peer Manager (T90.1)
//!
//! The `async_peer_manager` module provides `AsyncPeerManager` trait and
//! `AsyncPeerManagerImpl`, a fully async implementation using Tokio networking
//! primitives. This is the new path for consensus networking that replaces the
//! blocking `PeerManager` + `spawn_blocking` bridge.
//!
//! Enable with the `async-peer-manager` feature flag:
//! - When enabled: uses `AsyncPeerManagerImpl` for fully async networking
//! - When disabled (legacy): uses the blocking `PeerManager` + `spawn_blocking` path
//!
//! The async peer manager is currently the default for development and testing,
//! while the legacy path exists as a fallback until parity is proven.
//!
//! # Channel Capacity Configuration (T90.2)
//!
//! The `channel_config` module provides `ChannelCapacityConfig` for tuning
//! async channel capacities via configuration or environment variables:
//! - `QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY`: ConsensusEvent channel
//! - `QBIND_OUTBOUND_COMMAND_CHANNEL_CAPACITY`: Outbound command channel
//! - `QBIND_ASYNC_PEER_INBOUND_CAPACITY`: AsyncPeerManager inbound channel
//! - `QBIND_ASYNC_PEER_OUTBOUND_CAPACITY`: AsyncPeerManager per-peer outbound
//!
//! No networking, no DAG, no signing or IO.
//!
//! # DAG Mempool (T158)
//!
//! The `dag_mempool` module provides the core data structures and implementation
//! for a DAG-based mempool. This is an alternative to the FIFO mempool that:
//! - Organizes transactions into signed batches
//! - Forms a DAG structure via parent references
//! - Provides deterministic frontier selection for proposals
//!
//! See `dag_mempool` module documentation for details.

pub mod async_peer_manager;
pub mod async_runner;
pub mod block_store;
pub mod channel_config;
pub mod cli;
pub mod commit_index;
pub mod consensus_net;
pub mod consensus_net_p2p;
pub mod consensus_net_worker;
pub mod consensus_network_facade;
pub mod consensus_node;
pub mod consensus_sim;
pub mod dag_mempool;
pub mod evm_commit;
pub mod evm_state_store;
pub mod execution_adapter;
pub mod hotstuff_node_sim;
pub mod identity_map;
pub mod keystore;
pub mod ledger_bridge;
pub mod load_harness;
pub mod mempool;
pub mod metrics;
pub mod metrics_http;
pub mod net_service;
pub mod node_config;
pub mod p2p;
pub mod p2p_inbound;
pub mod p2p_node_builder;
pub mod p2p_tcp;
pub mod peer;
pub mod peer_manager;
pub mod peer_rate_limiter;
pub mod remote_signer;
pub mod secure_channel;
pub mod startup_validation;
pub mod storage;
pub mod validator_config;
pub mod validator_signer;
pub mod verify_pool;

pub use async_runner::{
    AsyncNodeError, AsyncNodeRunner, ConsensusEvent, ConsensusEventReceiver, ConsensusEventSender,
    DEFAULT_EVENT_CHANNEL_CAPACITY,
};
pub use block_store::{BlockStore, BlockStoreError, SharedProposal, StoredBlock};
pub use channel_config::ChannelCapacityConfig;
pub use commit_index::{CommitIndex, CommitIndexError};
pub use consensus_net::{ConsensusNetAdapter, ConsensusNetError, ConsensusNetEvent};
pub use consensus_net_worker::{
    process_outbound_command_blocking, spawn_critical_outbound_worker,
    spawn_critical_outbound_worker_with_metrics, spawn_inbound_processor,
    spawn_inbound_processor_with_metrics, spawn_outbound_processor,
    spawn_outbound_processor_with_metrics, AsyncConsensusNetAdapter, AsyncNetSender,
    ConsensusMsgPriority, ConsensusNetSender, ConsensusNetService, ConsensusNetWorker,
    ConsensusNetWorkerError, CriticalCommandReceiver, InboundEventSender, OutboundCommand,
    OutboundCommandReceiver,
};
pub use consensus_node::{
    ConsensusNode, ConsensusNodeError as NetConsensusNodeError, NodeCommitInfo, NodeCommittedBlock,
};
pub use consensus_sim::{NodeConsensusSim, NodeConsensusSimError};
pub use hotstuff_node_sim::{NodeHotstuffHarness, NodeHotstuffHarnessError, ProposerSource};
pub use identity_map::PeerValidatorMap;
pub use ledger_bridge::{InMemoryNodeLedgerHarness, NodeLedgerError, NodeLedgerHarness};

// EVM execution bridge exports (T151)
pub use evm_commit::{
    init_evm_account, init_evm_contract, EvmCommitError, EvmCommitResult, EvmExecutionBridge,
};

// EVM state storage exports (T153)
pub use evm_state_store::FileEvmStateStorage;

// T150 Execution Adapter exports
pub use execution_adapter::{
    ExecutionAdapter, ExecutionAdapterError, InMemoryExecutionAdapter, QbindBlock,
};

// T155 Async Execution Service exports
pub use execution_adapter::{
    AsyncExecError, AsyncExecutionService, SingleThreadExecutionService,
    SingleThreadExecutionServiceConfig,
};

// T151 Mempool exports
pub use mempool::{
    BalanceProvider, InMemoryBalanceProvider, InMemoryKeyProvider, InMemoryMempool, KeyProvider,
    KeyProviderError, Mempool, MempoolConfig, MempoolError,
};

// T158 DAG Mempool exports
pub use dag_mempool::{
    batch_signing_preimage, compute_batch_id, compute_tx_id, BatchError, BatchId, BatchRef,
    BatchSignature, DagMempool, DagMempoolConfig, DagMempoolError, DagMempoolMetrics,
    DagMempoolStats, InMemoryDagMempool, QbindBatch, TxId, BATCH_DOMAIN_TAG,
};

// T165 DAG Availability exports
pub use dag_mempool::{
    BatchAck, BatchAckResult, BatchAckTracker, BatchCertificate, SignatureBytes,
};

// T162 Node Config exports
pub use node_config::{
    parse_environment, NodeConfig, ParseEnvironmentError, DEFAULT_ENVIRONMENT, VALID_ENVIRONMENTS,
};

// T163 Execution Profile exports
pub use node_config::{
    parse_execution_profile, ExecutionProfile, DEFAULT_EXECUTION_PROFILE, VALID_EXECUTION_PROFILES,
};

// T165 DAG Availability Config exports
pub use node_config::DagAvailabilityConfig;

// T170 Network Transport Config exports
pub use node_config::NetworkTransportConfig;

// T173 Network Mode exports
pub use node_config::{parse_network_mode, NetworkMode};

// T170 P2P Service exports
pub use p2p::{
    ConsensusNetMsg, ControlMsg, DagNetMsg, NodeId, NullP2pService, P2pMessage, P2pService,
    PeerInfo,
};

// T174 P2P Inbound exports
pub use p2p_inbound::{
    ChannelConsensusHandler, ChannelDagHandler, ConsensusInboundHandler, ControlInboundHandler,
    DagInboundHandler, NullConsensusHandler, NullControlHandler, NullDagHandler, P2pInboundDemuxer,
};

// T175 CLI exports
pub use cli::{CliArgs, CliError};

// T175 P2P Node Builder exports
pub use p2p_node_builder::{P2pNodeBuilder, P2pNodeContext, P2pNodeError};

// T175 Address parsing exports
pub use node_config::{
    parse_socket_addr, ParseAddrError, DEFAULT_NETWORK_MODE, DEFAULT_P2P_LISTEN_ADDR,
    VALID_NETWORK_MODES,
};

pub use load_harness::{
    run_load_harness, LoadGenerator, LoadHarnessConfig, LoadHarnessError, LoadHarnessResult,
    LoopbackNetService,
};
pub use metrics::{
    CommitMetrics, ConsensusProgressMetrics, ConsensusT154Metrics, DisconnectReason,
    EnvironmentMetrics, ExecutionErrorReason, ExecutionMetrics, InboundMsgKind,
    KeystoreBackendKind, MempoolMetrics, MempoolRejectReason, NetworkMetrics, NodeMetrics,
    OutboundMsgKind, P2pMetrics, PeerCounters, PeerNetworkMetrics, RuntimeMetrics, SignRequestKind,
    SignerKeystoreMetrics, SpawnBlockingMetrics, StorageMetrics, StorageOp,
    ValidatorEquivocationMetrics, ValidatorVoteCounters, ValidatorVoteMetrics, ViewLagMetrics,
    MAX_TRACKED_PEERS, MAX_TRACKED_VALIDATORS,
};

// Metrics HTTP server exports (T126)
pub use metrics_http::{
    spawn_metrics_http_server, spawn_metrics_http_server_with_addr,
    spawn_metrics_http_server_with_crypto, CryptoMetricsRefs, MetricsHttpConfig, MetricsHttpError,
    METRICS_HTTP_ADDR_ENV,
};
pub use net_service::{NetService, NetServiceConfig, NetServiceError};
pub use peer::{Peer, PeerId};
pub use peer_manager::{PeerManager, PeerManagerError};
pub use peer_rate_limiter::{
    PeerRateLimiter, PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE,
    DEFAULT_MAX_MESSAGES_PER_SECOND,
};
pub use startup_validation::{
    ConsensusStartupValidator, StartupValidationError, SuitePolicy, ValidatorEnumerator,
};
pub use storage::{
    ensure_compatible_schema, ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage,
    StorageError, CURRENT_SCHEMA_VERSION,
};
pub use validator_config::{
    build_net_config_and_id_map_for_tests, derive_validator_public_key,
    make_local_validator_config_from_keystore, make_local_validator_config_with_identity_check,
    make_local_validator_config_with_keystore,
    make_local_validator_config_with_keystore_and_identity_check,
    verify_signing_key_matches_identity, IdentityMismatchError, KeystoreWithIdentityError,
    LocalValidatorConfig, LocalValidatorIdentity, NodeValidatorConfig, RemoteValidatorConfig,
    SignerBackend, ValidatorKeystoreConfig, ValidatorSignerConfig, EXPECTED_SUITE_ID,
};

// Validator signer abstraction exports (T148)
pub use validator_signer::{
    make_local_validator_signer, LocalKeySigner, SignError, ValidatorSigner,
};

// Remote signer exports (T149)
pub use remote_signer::{
    LoopbackSignerTransport, RemoteSignError, RemoteSignRequest, RemoteSignRequestKind,
    RemoteSignResponse, RemoteSignerClient, RemoteSignerTransport,
};

// Verification pool exports (T147)
pub use verify_pool::{
    ConsensusVerifyPool, ConsensusVerifyPoolConfig, SubmitError, VerifyPoolMetrics,
};

// Keystore exports (T144)
pub use keystore::{
    FsValidatorKeystore, KeystoreConfig, KeystoreError, LocalKeystoreEntryId, ValidatorKeystore,
};

// Async peer manager exports (T90.1, T91, T120)
pub use async_peer_manager::{
    AsyncPeerManager, AsyncPeerManagerConfig, AsyncPeerManagerError, AsyncPeerManagerImpl,
    KemtlsHandshakeFailureReason, KemtlsMetrics, KemtlsRole, SharedAsyncPeerManager,
    TransportSecurityMode,
};

// Secure channel exports (T92)
pub use secure_channel::{
    accept_kemtls_async, connect_kemtls_async, AsyncChannelError, ChannelError, SecureChannel,
    SecureChannelAsync,
};

// Consensus network facade exports (T96)
pub use consensus_network_facade::{
    AsyncNetworkFacade, BlockingNetworkFacade, ConsensusNetworkFacade, DirectAsyncNetworkFacade,
    IdentityValidatorPeerMapping, NullNetworkFacade, ValidatorPeerMapping,
};

// T173: P2P consensus network exports
pub use consensus_net_p2p::{
    P2pConsensusNetwork, SimpleValidatorNodeMapping, ValidatorNodeMapping,
};

use std::sync::Arc;

use qbind_consensus::{
    hotstuff_decide_and_maybe_record_vote, BlockVerifyConfig, ConsensusNodeError, HotStuffState,
    ValidatorSet, VoteDecision,
};
use qbind_crypto::CryptoProvider;
use qbind_ledger::AccountStore;
use qbind_runtime::{BlockExecutionResult, BlockExecutor};
use qbind_wire::consensus::BlockProposal;
use qbind_wire::io::WireDecode;
use qbind_wire::tx::Transaction;

/// Node-level errors that can occur when processing a block.
#[derive(Debug)]
pub enum NodeError {
    /// Consensus verification or HotStuff safety failed.
    Consensus(ConsensusNodeError),

    /// Wire-level decoding of transactions failed.
    Wire(String),

    /// Execution of one or more transactions failed in a fatal way.
    ///
    /// Note: BlockExecutionResult already records per-tx failures. This error
    /// variant is for global, unrecoverable execution errors (e.g., internal
    /// invariants).
    Execution(String),
}

impl From<ConsensusNodeError> for NodeError {
    fn from(e: ConsensusNodeError) -> Self {
        NodeError::Consensus(e)
    }
}

/// Result of applying a single block to local state.
#[derive(Debug)]
pub struct BlockApplyOutcome {
    /// Block height.
    pub height: u64,
    /// Block round.
    pub round: u64,
    /// Block payload hash (used as the block identifier).
    pub block_id: [u8; 32],
    /// Outcome of executing all transactions.
    pub exec_result: BlockExecutionResult,
    /// Whether this node decided it *should* vote for this block.
    pub vote_decision: VoteDecision,
}

/// A minimal node-core that can verify and execute blocks locally.
///
/// This struct does NOT handle networking, leader selection, or DAG.
/// It only provides a deterministic pipeline:
///   BlockProposal -> consensus checks -> transaction decode -> execution.
pub struct Node<S: AccountStore> {
    validator_set: ValidatorSet,
    consensus_state: HotStuffState,
    verify_cfg: BlockVerifyConfig,
    block_executor: BlockExecutor<S>,
    crypto: Arc<dyn CryptoProvider>,
}

impl<S: AccountStore> Node<S> {
    /// Create a new Node with the given validator set, HotStuffState, config, crypto provider,
    /// and a default BlockExecutor.
    pub fn new(
        validator_set: ValidatorSet,
        consensus_state: HotStuffState,
        verify_cfg: BlockVerifyConfig,
        crypto: Arc<dyn CryptoProvider>,
    ) -> Self {
        Node {
            validator_set,
            consensus_state,
            verify_cfg,
            block_executor: BlockExecutor::new(),
            crypto,
        }
    }

    /// Accessors for tests or external code.
    pub fn consensus_state(&self) -> &HotStuffState {
        &self.consensus_state
    }

    pub fn consensus_state_mut(&mut self) -> &mut HotStuffState {
        &mut self.consensus_state
    }

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Apply a block locally: verify under consensus rules, decode txs, execute them.
    ///
    /// Semantics:
    ///  1) Use HotStuff consensus to decide if this node *would* vote for the block.
    ///     - hotstuff_decide_and_maybe_record_vote(..., record = false)
    ///  2) Decode each tx blob into a Transaction.
    ///  3) Execute the txs sequentially via BlockExecutor.
    ///  4) Return a BlockApplyOutcome with height, round, block_id, execution result, and vote decision.
    ///
    /// This function does NOT:
    ///  - send any network messages,
    ///  - sign votes,
    ///  - update locks or commit heights.
    pub fn apply_block(
        &mut self,
        store: &mut S,
        proposal: &BlockProposal,
    ) -> Result<BlockApplyOutcome, NodeError> {
        // 1) Consensus check: structural + HotStuff safety, but do NOT record vote.
        let vote_decision = hotstuff_decide_and_maybe_record_vote(
            &self.validator_set,
            self.crypto.as_ref(),
            &self.verify_cfg,
            &mut self.consensus_state,
            proposal,
            /* record = */ false,
        )
        .map_err(NodeError::Consensus)?;

        // 2) Decode txs into Transactions.
        let mut txs = Vec::with_capacity(proposal.txs.len());
        for blob in &proposal.txs {
            let mut slice: &[u8] = blob;
            let tx = Transaction::decode(&mut slice)
                .map_err(|e| NodeError::Wire(format!("failed to decode transaction: {:?}", e)))?;
            if !slice.is_empty() {
                return Err(NodeError::Wire(
                    "extra bytes after transaction decode".to_string(),
                ));
            }
            txs.push(tx);
        }

        // 3) Execute block via BlockExecutor.
        let exec_result = self
            .block_executor
            .execute_block(store, self.crypto.clone(), &txs);

        // 4) Build outcome.
        let outcome = BlockApplyOutcome {
            height: proposal.header.height,
            round: proposal.header.round,
            block_id: proposal.header.payload_hash,
            exec_result,
            vote_decision,
        };

        Ok(outcome)
    }
}