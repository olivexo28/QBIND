//! T150 Execution Adapter for integrating L1 execution with consensus commits.
//!
//! This module provides `ExecutionAdapter` trait and `InMemoryExecutionAdapter`
//! implementation for wiring HotStuff block commits to the execution layer.
//!
//! ## Architecture (T150 - Synchronous)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │               NodeHotstuffHarness                           │
//! │    (consensus + networking, produces committed blocks)      │
//! └─────────────────────────────────────────────────────────────┘
//!                           │ on_commit()
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │               ExecutionAdapter                              │
//! │    (apply_block: runs ExecutionEngine on each tx)           │
//! └─────────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      State                                   │
//! │    (InMemoryState or persistent backend)                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Architecture (T155 - Async Execution Pipeline)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │               NodeHotstuffHarness                           │
//! │    (consensus + networking, produces committed blocks)      │
//! └─────────────────────────────────────────────────────────────┘
//!                           │ on_commit() - non-blocking
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │           AsyncExecutionService (T155)                       │
//! │    (submit_block: enqueues to bounded channel)              │
//! └─────────────────────────────────────────────────────────────┘
//!                           │ bounded channel
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │           SingleThreadExecutionService Worker               │
//! │    (dedicated thread, processes blocks in FIFO order)       │
//! └─────────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      State                                   │
//! │    (InMemoryState or persistent backend)                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Design Notes
//!
//! - `QbindBlock` wraps consensus BlockProposal with decoded `QbindTransaction`s
//! - `ExecutionAdapter` is the commit hook interface (synchronous)
//! - `AsyncExecutionService` (T155) provides non-blocking commit interface
//! - `SingleThreadExecutionService` (T155) runs execution on a dedicated worker thread
//! - `InMemoryExecutionAdapter` uses `InMemoryState` + `ExecutionEngine`
//! - On first execution error, the adapter returns the error immediately
//! - Future versions may support different error policies (continue, revert, etc.)

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use qbind_ledger::{
    execute_block_stage_b, AccountStateUpdater, AccountStateView, CachedPersistentAccountState,
    ExecutionEngine, ExecutionEngineError, InMemoryAccountState, InMemoryState, ParallelExecConfig,
    PersistentAccountState, QbindTransaction, RocksDbAccountState, SenderPartitionedNonceExecutor,
    StateUpdater, TransferPayload, VmV0ExecutionEngine,
};
use qbind_types::Hash32;
use qbind_wire::consensus::BlockProposal;

use crate::metrics::ExecutionMetrics;
use crate::node_config::ExecutionProfile;

// ============================================================================
// T164: FlushableState Trait
// ============================================================================

/// Trait for state backends that support flushing to durable storage (T164).
///
/// This trait allows the VM v0 execution loop to work with both in-memory
/// and persistent state backends through a common interface.
trait FlushableState {
    /// Flush any pending state changes to durable storage.
    ///
    /// For in-memory backends, this is a no-op.
    /// For persistent backends, this ensures data is written to disk.
    fn flush_state(&self) -> Result<(), qbind_ledger::StorageError>;
}

impl FlushableState for InMemoryAccountState {
    fn flush_state(&self) -> Result<(), qbind_ledger::StorageError> {
        // In-memory state doesn't need flushing
        Ok(())
    }
}

impl<P: PersistentAccountState> FlushableState for CachedPersistentAccountState<P> {
    fn flush_state(&self) -> Result<(), qbind_ledger::StorageError> {
        self.flush()
    }
}

// ============================================================================
// T187: Stage B State Extraction Helper
// ============================================================================

/// Extract accounts touched by transactions into an InMemoryAccountState.
///
/// This function reads the sender and recipient accounts from the source state
/// and creates a snapshot suitable for Stage B execution.
fn extract_touched_accounts<S: AccountStateView>(
    state: &S,
    transactions: &[QbindTransaction],
) -> InMemoryAccountState {
    use std::collections::HashSet;

    let mut touched = HashSet::new();

    for tx in transactions {
        touched.insert(tx.sender);

        // Try to decode recipient from payload
        if let Some(transfer) = TransferPayload::decode(&tx.payload) {
            touched.insert(transfer.recipient);
        }
    }

    let mut snapshot = InMemoryAccountState::new();
    for account in touched {
        let account_state = state.get_account_state(&account);
        snapshot.set_account_state(&account, account_state);
    }

    snapshot
}

/// Apply state changes from Stage B execution back to the main state.
fn apply_state_changes<S: AccountStateUpdater + AccountStateView>(
    state: &mut S,
    final_state: &InMemoryAccountState,
) {
    for (account, account_state) in final_state.iter() {
        state.set_account_state(account, account_state.clone());
    }
}

// ============================================================================
// QbindBlock - Block wrapper with decoded transactions
// ============================================================================

/// A QBIND block with decoded transactions for execution.
///
/// This wraps a consensus `BlockProposal` with its transactions decoded into
/// `QbindTransaction` format. The block_id is derived from the proposal's
/// payload hash.
#[derive(Clone, Debug)]
pub struct QbindBlock {
    /// The unique block identifier (payload hash from consensus).
    pub block_id: Hash32,
    /// The parent block identifier.
    pub parent_id: Hash32,
    /// The view/height number.
    pub view: u64,
    /// The decoded transactions in order.
    pub txs: Vec<QbindTransaction>,
    /// The original block proposal (for metadata access).
    pub proposal: Arc<BlockProposal>,
}

impl QbindBlock {
    /// Create a new QbindBlock from a proposal and decoded transactions.
    pub fn new(proposal: Arc<BlockProposal>, txs: Vec<QbindTransaction>) -> Self {
        Self {
            block_id: proposal.header.payload_hash,
            parent_id: proposal.header.parent_block_id,
            view: proposal.header.height,
            txs,
            proposal,
        }
    }

    /// Create an empty QbindBlock (no transactions).
    pub fn empty(proposal: Arc<BlockProposal>) -> Self {
        Self::new(proposal, Vec::new())
    }

    /// Get the block height (alias for view).
    pub fn height(&self) -> u64 {
        self.view
    }

    /// Get the number of transactions.
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }
}

// ============================================================================
// ExecutionAdapter Trait
// ============================================================================

/// Adapter for applying committed blocks to the execution layer.
///
/// This trait is the commit hook interface: when consensus commits a block,
/// the adapter's `apply_block()` is called to execute all transactions.
///
/// ## Error Policy
///
/// For T150, the adapter stops on the first execution error and returns it.
/// Future versions may implement different policies:
/// - Continue on error (mark tx as failed, proceed)
/// - Rollback entire block on any error
/// - Custom error handling per tx type
pub trait ExecutionAdapter: Send + Sync {
    /// Apply a committed block to state.
    ///
    /// Executes all transactions in order. On first error, returns immediately.
    ///
    /// # Arguments
    ///
    /// * `block` - The block with decoded transactions to execute
    ///
    /// # Returns
    ///
    /// `Ok(())` if all transactions succeeded, `Err` on first failure.
    fn apply_block(&mut self, block: &QbindBlock) -> Result<(), ExecutionAdapterError>;

    /// Get the current block height (last successfully applied block).
    fn current_height(&self) -> u64;
}

/// Errors that can occur during block execution via the adapter.
#[derive(Debug)]
pub struct ExecutionAdapterError {
    /// The block height where the error occurred.
    pub height: u64,
    /// The transaction index within the block (if applicable).
    pub tx_index: Option<usize>,
    /// The underlying execution error.
    pub error: ExecutionEngineError,
}

impl std::fmt::Display for ExecutionAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.tx_index {
            Some(idx) => write!(
                f,
                "execution error at height {} tx {}: {}",
                self.height, idx, self.error
            ),
            None => write!(
                f,
                "execution error at height {}: {}",
                self.height, self.error
            ),
        }
    }
}

impl std::error::Error for ExecutionAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

// ============================================================================
// InMemoryExecutionAdapter
// ============================================================================

/// In-memory execution adapter using `InMemoryState` and a pluggable engine.
///
/// This is the reference implementation for T150:
/// - State: `InMemoryState` (HashMap-based key-value store)
/// - Engine: Any `ExecutionEngine` implementation (typically `NonceExecutionEngine`)
///
/// ## Usage
///
/// ```ignore
/// use qbind_node::execution_adapter::{InMemoryExecutionAdapter, QbindBlock};
/// use qbind_ledger::{NonceExecutionEngine, InMemoryState};
///
/// let engine = NonceExecutionEngine::new();
/// let mut adapter = InMemoryExecutionAdapter::new(engine);
///
/// // On block commit from consensus:
/// adapter.apply_block(&qbind_block)?;
/// ```
pub struct InMemoryExecutionAdapter {
    /// The underlying state.
    state: InMemoryState,
    /// The execution engine.
    engine: Arc<dyn ExecutionEngine>,
    /// The current block height (last successfully applied).
    current_height: u64,
}

impl InMemoryExecutionAdapter {
    /// Create a new adapter with empty state.
    pub fn new<E: ExecutionEngine + 'static>(engine: E) -> Self {
        Self {
            state: InMemoryState::new(),
            engine: Arc::new(engine),
            current_height: 0,
        }
    }

    /// Create an adapter with pre-initialized state.
    pub fn with_state<E: ExecutionEngine + 'static>(engine: E, state: InMemoryState) -> Self {
        Self {
            state,
            engine: Arc::new(engine),
            current_height: 0,
        }
    }

    /// Get a reference to the underlying state.
    pub fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Get a mutable reference to the underlying state.
    pub fn state_mut(&mut self) -> &mut InMemoryState {
        &mut self.state
    }

    /// Get the execution engine.
    pub fn engine(&self) -> &dyn ExecutionEngine {
        self.engine.as_ref()
    }
}

impl ExecutionAdapter for InMemoryExecutionAdapter {
    fn apply_block(&mut self, block: &QbindBlock) -> Result<(), ExecutionAdapterError> {
        let height = block.height();

        // Execute each transaction in order
        for (idx, tx) in block.txs.iter().enumerate() {
            self.engine
                .execute_tx(&mut self.state as &mut dyn StateUpdater, tx)
                .map_err(|e| ExecutionAdapterError {
                    height,
                    tx_index: Some(idx),
                    error: e,
                })?;
        }

        // Update height on success
        self.current_height = height;

        Ok(())
    }

    fn current_height(&self) -> u64 {
        self.current_height
    }
}

impl std::fmt::Debug for InMemoryExecutionAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryExecutionAdapter")
            .field("state_entries", &self.state.len())
            .field("current_height", &self.current_height)
            .finish()
    }
}

// ============================================================================
// T155: AsyncExecutionService - Async Execution Pipeline
// ============================================================================

/// Error type for async execution service operations.
#[derive(Debug, Clone)]
pub enum AsyncExecError {
    /// The execution queue is full; cannot accept more blocks.
    QueueFull,
    /// The execution service is shutting down.
    ShuttingDown,
}

impl std::fmt::Display for AsyncExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsyncExecError::QueueFull => write!(f, "execution queue full"),
            AsyncExecError::ShuttingDown => write!(f, "service shutting down"),
        }
    }
}

impl std::error::Error for AsyncExecError {}

/// Async execution service trait for non-blocking block execution (T155).
///
/// This trait provides a non-blocking interface for submitting committed blocks
/// to an execution pipeline. The implementation processes blocks asynchronously
/// on a dedicated worker thread while preserving commit order.
///
/// # Properties
///
/// - `submit_block` is non-blocking from the consensus/harness perspective
/// - Blocks are executed in FIFO order (commit order preserved)
/// - Backpressure is applied via bounded queue; `QueueFull` is returned if full
/// - Deterministic execution: no reordering across validators
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow sharing across threads.
pub trait AsyncExecutionService: Send + Sync {
    /// Enqueue a committed block for asynchronous execution.
    ///
    /// This method is non-blocking. The block is placed in a bounded queue
    /// for processing by a dedicated worker thread.
    ///
    /// # Arguments
    ///
    /// * `block` - The committed block with decoded transactions
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the block was successfully enqueued
    /// - `Err(AsyncExecError::QueueFull)` if the queue is at capacity
    /// - `Err(AsyncExecError::ShuttingDown)` if the service is shutting down
    fn submit_block(&self, block: QbindBlock) -> Result<(), AsyncExecError>;

    /// Get the current execution queue length (approximate).
    ///
    /// This is primarily for observability and testing. The value may be
    /// slightly stale due to concurrent operations.
    fn queue_len(&self) -> usize;
}

/// Internal task structure for the execution worker.
struct ExecTask {
    /// The block to execute.
    block: QbindBlock,
    /// Timestamp when the task was submitted (for latency tracking).
    #[allow(dead_code)]
    submitted_at: Instant,
}

/// R150 (test-utils only): worker-local observation/flush control messages.
///
/// These travel on a SEPARATE unbounded control channel and are serviced by the
/// VM-v0 worker ONLY when no block is pending (see `vm_v0_next_task`), so an
/// observation reflects the state produced by every block enqueued before it —
/// a same-owner, FIFO-correlated read of the worker's own backend. This is a
/// non-authorizing, test-only boundary gated entirely behind the pre-existing
/// `test-utils` feature: it is absent from every default build and adds no
/// default production behavior, no external account-state mutation, and no
/// signer/authority surface. The worker remains the sole writer of the backend.
#[cfg(feature = "test-utils")]
enum WorkerControl {
    /// Read one account's state from the worker-owned backend (no mutation).
    ObserveAccount {
        account: qbind_types::AccountId,
        reply: Sender<qbind_ledger::AccountState>,
    },
    /// Flush the worker-owned backend to durable storage.
    Flush {
        reply: Sender<Result<(), String>>,
    },
}

/// R150 (test-utils only): identifiable bounded outcome of a worker-local
/// observation. A `Timeout`/`WorkerGone` is an explicit non-result — it never
/// fabricates or implies any state value.
#[cfg(feature = "test-utils")]
#[derive(Debug)]
pub enum WorkerObserveError {
    /// The worker is gone (service shutting down / control channel closed); no
    /// observation was made.
    WorkerGone,
    /// The worker did not answer within the bounded wait; no observation claimed.
    Timeout,
    /// The worker reported a flush failure.
    Flush(String),
}

#[cfg(feature = "test-utils")]
impl std::fmt::Display for WorkerObserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerObserveError::WorkerGone => write!(f, "execution worker is gone; no observation"),
            WorkerObserveError::Timeout => {
                write!(f, "execution worker did not answer within the bounded wait")
            }
            WorkerObserveError::Flush(e) => write!(f, "worker-owned backend flush failed: {}", e),
        }
    }
}

#[cfg(feature = "test-utils")]
impl std::error::Error for WorkerObserveError {}

/// Configuration for the single-threaded execution service.
#[derive(Debug, Clone)]
pub struct SingleThreadExecutionServiceConfig {
    /// Maximum queue capacity (bounded channel size).
    pub queue_capacity: usize,
    /// Configuration for Stage A parallel execution (T157).
    pub parallel_config: ParallelExecConfig,
    /// Execution profile selection (T163).
    ///
    /// - `NonceOnly`: Uses Stage A parallel nonce execution (DevNet default)
    /// - `VmV0`: Uses sequential VM v0 execution with account balances (TestNet Alpha)
    pub execution_profile: ExecutionProfile,
    /// State directory for VM v0 persistence (T164).
    ///
    /// When set and `execution_profile` is `VmV0`, the service uses RocksDB-backed
    /// persistent storage at this path. When `None`, uses in-memory state only.
    pub state_dir: Option<PathBuf>,
    /// Whether Stage B conflict-graph parallel execution is enabled (T186).
    ///
    /// When `true` and `execution_profile` is `VmV0`, the service uses the
    /// Stage B conflict-graph scheduler to execute blocks in parallel.
    /// When `false`, blocks are executed sequentially (existing behavior).
    ///
    /// Stage B produces identical state and receipts as sequential execution.
    pub stage_b_enabled: bool,
}

impl Default for SingleThreadExecutionServiceConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            parallel_config: ParallelExecConfig::default(),
            execution_profile: ExecutionProfile::NonceOnly,
            state_dir: None,
            stage_b_enabled: false,
        }
    }
}

impl SingleThreadExecutionServiceConfig {
    /// Create a new config with the specified queue capacity.
    pub fn with_queue_capacity(mut self, capacity: usize) -> Self {
        self.queue_capacity = capacity;
        self
    }

    /// Set the parallel execution configuration (T157).
    pub fn with_parallel_config(mut self, config: ParallelExecConfig) -> Self {
        self.parallel_config = config;
        self
    }

    /// Disable parallel execution (force sequential) (T157).
    pub fn sequential_only(mut self) -> Self {
        self.parallel_config = ParallelExecConfig::sequential();
        self
    }

    /// Set the execution profile (T163).
    pub fn with_execution_profile(mut self, profile: ExecutionProfile) -> Self {
        self.execution_profile = profile;
        self
    }

    /// Set the state directory for VM v0 persistence (T164).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the state directory. The directory will be created if
    ///   it doesn't exist.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = SingleThreadExecutionServiceConfig::vm_v0()
    ///     .with_state_dir("/data/vm_v0_state");
    /// ```
    pub fn with_state_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.state_dir = Some(path.into());
        self
    }

    /// Enable or disable Stage B parallel execution (T186).
    ///
    /// When enabled and `execution_profile` is `VmV0`, the service uses the
    /// Stage B conflict-graph scheduler for parallel block execution.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether Stage B parallel execution should be enabled
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = SingleThreadExecutionServiceConfig::vm_v0()
    ///     .with_stage_b_enabled(true);
    /// ```
    pub fn with_stage_b_enabled(mut self, enabled: bool) -> Self {
        self.stage_b_enabled = enabled;
        self
    }

    /// Create a config for VM v0 execution (TestNet Alpha) (T163).
    pub fn vm_v0() -> Self {
        Self {
            queue_capacity: 1024,
            parallel_config: ParallelExecConfig::default(),
            execution_profile: ExecutionProfile::VmV0,
            state_dir: None,
            stage_b_enabled: false,
        }
    }

    /// Create a config for VM v0 execution with persistent state (T164).
    ///
    /// # Arguments
    ///
    /// * `state_dir` - Path to the state directory.
    pub fn vm_v0_persistent<P: Into<PathBuf>>(state_dir: P) -> Self {
        Self {
            queue_capacity: 1024,
            parallel_config: ParallelExecConfig::default(),
            execution_profile: ExecutionProfile::VmV0,
            state_dir: Some(state_dir.into()),
            stage_b_enabled: false,
        }
    }
}

/// C15(i) — typed initialization failure for
/// [`SingleThreadExecutionService::try_with_config`].
///
/// A requested persistent account-state backend MUST open successfully before
/// an executable service is published. Any failure here yields a typed refusal
/// and publishes NO service, worker, or capability — there is never a silent
/// in-memory fallback for a requested persistent backend.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionServiceInitError {
    /// A persistent `state_dir` was requested together with a non-`VmV0`
    /// execution profile. Persistence is only supported by `VmV0`; this
    /// contradictory configuration is rejected before any backend open or
    /// worker spawn — never accepted silently as in-memory success.
    #[error(
        "contradictory configuration: a persistent state_dir was requested but \
         execution_profile is {profile:?} (persistence requires VmV0)"
    )]
    ContradictoryConfig { profile: ExecutionProfile },
    /// The requested persistent backend at `path` failed to open. No executable
    /// service is published and there is no in-memory fallback.
    #[error("failed to open requested persistent account state at {path}: {source}")]
    OpenState {
        path: PathBuf,
        #[source]
        source: qbind_ledger::StorageError,
    },
    /// The requested backend opened, but the execution worker thread could not
    /// be spawned. This is reported distinctly from a backend-open failure; the
    /// successfully-opened backend is dropped (closed) as ordinary ownership
    /// cleanup, and no service is published.
    #[error("failed to spawn execution worker thread: {source}")]
    WorkerSpawn {
        #[source]
        source: std::io::Error,
    },
}

/// Single-threaded async execution service (T155).
///
/// This service runs block execution on a dedicated worker thread,
/// processing blocks in FIFO order via a bounded channel.
///
/// # Architecture
///
/// ```text
/// ┌───────────────────┐     bounded channel     ┌───────────────────┐
/// │  Consensus Thread │ ───────────────────────▶│   Worker Thread   │
/// │  (submit_block)   │                         │   (loop: recv,    │
/// └───────────────────┘                         │    apply_block)   │
///                                               └───────────────────┘
///                                                        │
///                                                        ▼
///                                               ┌───────────────────┐
///                                               │  InMemoryState    │
///                                               └───────────────────┘
/// ```
///
/// # Ordering Guarantees
///
/// - Blocks are executed in the order they are submitted (FIFO)
/// - No parallel execution within the service (single worker thread)
/// - Deterministic: all validators execute blocks in the same commit order
///
/// # Metrics
///
/// When metrics are provided, the service records:
/// - `qbind_execution_queue_len`: Current queue depth (gauge)
/// - `qbind_execution_queue_full_total`: Times submit failed due to full queue
/// - `qbind_execution_txs_applied_total`: Transactions successfully applied
/// - `qbind_execution_block_apply_seconds`: Block application latency
/// - `qbind_execution_errors_total`: Execution errors by reason
pub struct SingleThreadExecutionService {
    /// Sender side of the bounded channel for submitting blocks.
    sender: Sender<ExecTask>,
    /// Flag indicating if the service is shutting down.
    shutdown: Arc<AtomicBool>,
    /// Optional metrics for observability.
    metrics: Option<Arc<ExecutionMetrics>>,
    /// Approximate queue length (updated by worker).
    queue_len: Arc<AtomicU64>,
    /// Queue full counter (for metrics).
    queue_full_count: Arc<AtomicU64>,
    /// Worker restart counter (for metrics).
    worker_restarts: Arc<AtomicU64>,
    /// R150 (test-utils only): sender for worker-local observation/flush control
    /// requests. Absent from default builds. Used only by the gated `observe_*`
    /// methods; it does not change block submission or any default behavior.
    #[cfg(feature = "test-utils")]
    control_sender: Sender<WorkerControl>,
}

impl SingleThreadExecutionService {
    /// Create a new single-threaded execution service with default configuration.
    ///
    /// # Arguments
    ///
    /// * `engine` - The execution engine to use for applying blocks
    pub fn new<E: ExecutionEngine + 'static>(engine: E) -> Self {
        Self::with_config(engine, SingleThreadExecutionServiceConfig::default(), None)
    }

    /// Create a new service with custom configuration and optional metrics.
    ///
    /// # Arguments
    ///
    /// * `engine` - The execution engine to use
    /// * `config` - Service configuration
    /// * `metrics` - Optional metrics for observability
    pub fn with_config<E: ExecutionEngine + 'static>(
        engine: E,
        config: SingleThreadExecutionServiceConfig,
        metrics: Option<Arc<ExecutionMetrics>>,
    ) -> Self {
        // C15(i): `with_config` is an infallible, MEMORY-ONLY convenience. A
        // requested persistent backend (`state_dir = Some`) is a programmer
        // precondition violation on this entry point — NOT a supported
        // persistent initializer, and NOT evidence of a typed C15(i)
        // initialization refusal. Persistent backends MUST use
        // [`Self::try_with_config`], which opens the backend before publishing
        // an executable service and returns a typed error on failure.
        assert!(
            config.state_dir.is_none(),
            "SingleThreadExecutionService::with_config is memory-only \
             (config.state_dir must be None); use try_with_config(..) for a \
             requested persistent backend"
        );
        // Memory-only: no persistent backend is opened here; the worker builds
        // in-memory state for the selected profile.
        Self::build_and_spawn(engine, config, metrics, None)
            .expect("in-memory execution worker thread failed to spawn")
    }

    /// Create a service, synchronously initializing a requested persistent
    /// backend BEFORE any executable service capability is published (C15(i)).
    ///
    /// * `execution_profile == VmV0` with `state_dir == Some(path)`: the RocksDB
    ///   account-state backend at `path` is opened ONCE here, on the calling
    ///   thread, before the task channel or worker is created. The
    ///   successfully-opened backend is MOVED into the worker (single owner);
    ///   there is no second open and no in-memory fallback. An open failure
    ///   returns [`ExecutionServiceInitError::OpenState`] and publishes no
    ///   service, worker, or capability.
    /// * `state_dir == Some(path)` with a non-`VmV0` profile is rejected as
    ///   [`ExecutionServiceInitError::ContradictoryConfig`] before any open or
    ///   spawn — never treated as silent memory success.
    /// * `state_dir == None` (any profile) is genuine memory-only: no backend is
    ///   opened and the service is published with in-memory state.
    ///
    /// A worker-thread spawn failure is reported as
    /// [`ExecutionServiceInitError::WorkerSpawn`], distinct from a backend-open
    /// failure. Successful initialization binds the service to the opened
    /// backend; it does NOT by itself assert worker liveness or any later
    /// write/shutdown/durability guarantee.
    pub fn try_with_config<E: ExecutionEngine + 'static>(
        engine: E,
        config: SingleThreadExecutionServiceConfig,
        metrics: Option<Arc<ExecutionMetrics>>,
    ) -> Result<Self, ExecutionServiceInitError> {
        // Resolve the requested backend BEFORE publishing anything. Matched on
        // `state_dir` first so the cases are exhaustive without relying on a
        // match guard (guarded arms do not count toward exhaustivity): a
        // requested persistent backend with any non-`VmV0` profile is rejected
        // as contradictory (fail-closed for any future non-`VmV0` profile too),
        // never silently accepted as in-memory.
        let preopened = match config.state_dir.as_ref() {
            // Genuine, explicitly-selected memory-only: no persistence requested
            // (any profile). Nothing is opened.
            None => None,
            Some(path) => match config.execution_profile {
                ExecutionProfile::VmV0 => {
                    let state = RocksDbAccountState::open(path).map_err(|source| {
                        ExecutionServiceInitError::OpenState {
                            path: path.clone(),
                            source,
                        }
                    })?;
                    eprintln!(
                        "[C15(i)] opened persistent VM-v0 account state at {} before \
                         publishing execution service",
                        path.display()
                    );
                    Some(state)
                }
                // A persistent `state_dir` with a non-`VmV0` profile is a
                // contradictory configuration: rejected BEFORE any open or
                // worker spawn, never treated as silent memory success.
                profile => {
                    return Err(ExecutionServiceInitError::ContradictoryConfig { profile });
                }
            },
        };
        Self::build_and_spawn(engine, config, metrics, preopened)
            .map_err(|source| ExecutionServiceInitError::WorkerSpawn { source })
    }

    /// Build the task channel and spawn the execution worker, handing it the
    /// optional pre-opened persistent backend. Shared by `with_config`
    /// (memory-only, `preopened == None`) and `try_with_config`. Returns the
    /// spawn result so a worker-spawn failure is surfaced distinctly; on spawn
    /// failure the moved-in `preopened` backend is dropped (closed) as ordinary
    /// ownership cleanup and no service is published.
    fn build_and_spawn<E: ExecutionEngine + 'static>(
        engine: E,
        config: SingleThreadExecutionServiceConfig,
        metrics: Option<Arc<ExecutionMetrics>>,
        preopened: Option<RocksDbAccountState>,
    ) -> std::io::Result<Self> {
        let (sender, receiver) = bounded::<ExecTask>(config.queue_capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let queue_len = Arc::new(AtomicU64::new(0));
        let queue_full_count = Arc::new(AtomicU64::new(0));
        let worker_restarts = Arc::new(AtomicU64::new(0));

        // R150 (test-utils only): unbounded control channel for worker-local
        // observation/flush. The worker services it only when no block is pending,
        // so it never reorders or affects block execution. Absent in default builds.
        #[cfg(feature = "test-utils")]
        let (control_sender, control_receiver) = crossbeam_channel::unbounded::<WorkerControl>();

        // Clone references for the worker thread
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_queue_len = Arc::clone(&queue_len);
        let worker_metrics = metrics.clone();
        let parallel_config = config.parallel_config.clone();
        let execution_profile = config.execution_profile;
        let stage_b_enabled = config.stage_b_enabled;

        // Spawn the dedicated worker thread. Fallible spawn so a worker-thread
        // creation failure becomes an identifiable initialization error rather
        // than an unconditional panic; `try_with_config` maps it to
        // `WorkerSpawn`, `with_config` (memory-only) keeps the prior
        // panic-on-failure behavior via `.expect`.
        thread::Builder::new()
            .name("qbind-exec-worker".to_string())
            .spawn(move || {
                Self::worker_loop(
                    engine,
                    receiver,
                    worker_shutdown,
                    worker_queue_len,
                    worker_metrics,
                    parallel_config,
                    execution_profile,
                    preopened,
                    stage_b_enabled,
                    #[cfg(feature = "test-utils")]
                    control_receiver,
                );
            })?;

        Ok(Self {
            sender,
            shutdown,
            metrics,
            queue_len,
            queue_full_count,
            worker_restarts,
            #[cfg(feature = "test-utils")]
            control_sender,
        })
    }
    /// - `VmV0`: Uses sequential VM v0 execution with account balances (T163)
    /// - `VmV0` + `stage_b_enabled`: Uses Stage B conflict-graph parallel execution (T186)
    #[allow(clippy::too_many_arguments)]
    fn worker_loop<E: ExecutionEngine>(
        _engine: E, // Kept for backward compatibility but unused in T157+
        receiver: Receiver<ExecTask>,
        shutdown: Arc<AtomicBool>,
        queue_len: Arc<AtomicU64>,
        metrics: Option<Arc<ExecutionMetrics>>,
        parallel_config: ParallelExecConfig,
        execution_profile: ExecutionProfile,
        preopened: Option<RocksDbAccountState>,
        stage_b_enabled: bool,
        // R150 (test-utils only): worker-local observation/flush control channel.
        #[cfg(feature = "test-utils")] control_receiver: Receiver<WorkerControl>,
    ) {
        let mut current_height: u64 = 0;

        match execution_profile {
            ExecutionProfile::NonceOnly => {
                // NonceOnly never requests a persistent backend; `try_with_config`
                // rejects (NonceOnly + Some) and `with_config` is memory-only, so
                // `preopened` is always None here. Drop it explicitly.
                let _ = preopened;
                // NonceOnly has no persistent backend to observe; drop the control
                // receiver so a mistaken observation call reports WorkerGone.
                #[cfg(feature = "test-utils")]
                let _ = control_receiver;
                Self::worker_loop_nonce_only(
                    receiver,
                    shutdown,
                    queue_len,
                    metrics,
                    parallel_config,
                    &mut current_height,
                );
            }
            ExecutionProfile::VmV0 => {
                Self::worker_loop_vm_v0(
                    receiver,
                    shutdown,
                    queue_len,
                    metrics,
                    preopened,
                    &mut current_height,
                    stage_b_enabled,
                    #[cfg(feature = "test-utils")]
                    control_receiver,
                );
            }
        }

        eprintln!(
            "[T163] Execution worker shutting down at height {} (profile={:?}, stage_b={})",
            current_height, execution_profile, stage_b_enabled
        );
    }

    /// Worker loop for NonceOnly profile (T157 Stage A parallelism).
    fn worker_loop_nonce_only(
        receiver: Receiver<ExecTask>,
        shutdown: Arc<AtomicBool>,
        queue_len: Arc<AtomicU64>,
        metrics: Option<Arc<ExecutionMetrics>>,
        parallel_config: ParallelExecConfig,
        current_height: &mut u64,
    ) {
        let mut state = InMemoryState::new();

        // T157: Create the sender-partitioned parallel executor
        let parallel_executor = SenderPartitionedNonceExecutor::new(parallel_config);

        loop {
            // Check for shutdown
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            // R167 (test-only): deterministic receive-boundary observation for the
            // internal supervised-idle-close candidate. Absent from non-test builds;
            // in tests it is a no-op unless a gate is installed on THIS worker thread
            // (only the supervised candidate's test spawns install one), so legacy
            // worker threads are unaffected.
            // R193 (test-only): independent top-of-loop state probe — reports the REAL worker's
            // current height and the exercised sender's actual nonce, sampled directly from the live
            // `state`, INDEPENDENTLY of the executor-result hook. Absent from non-test builds; a no-op
            // unless the R193 fixture installed a gate. It witnesses the denied case (state unchanged)
            // as well as the executed case (real nonce/height change).
            #[cfg(test)]
            supervised_idle_close::idle_state_probe_test_hook(*current_height, &state);
            #[cfg(test)]
            supervised_start_checkpoint::prod_state_probe_test_hook(*current_height, &state);
            #[cfg(test)]
            supervised_idle_close::recv_boundary_test_hook();

            // Receive next task (blocking)
            match receiver.recv() {
                Ok(task) => {
                    // Update queue length
                    let len = receiver.len();
                    queue_len.store(len as u64, Ordering::Relaxed);

                    // R198/R199 (production, opt-in): fail-closed start checkpoint for the private
                    // supervised-start candidate. Worker MODE is explicit and independent of the
                    // authority lookup: a legacy worker never entered candidate mode, so the decision
                    // returns StartOutcome::Legacy with NO gate lock and existing behavior is
                    // unchanged. A candidate worker (R199: entered candidate mode at spawn) consults
                    // its per-worker Weak authority under the SAME mutex as admission and cutoff and
                    // validates the dequeued work against the EXACT occurrence bound on the single
                    // admission (R200: the block self-id AND the ordered execution input, so a dequeued
                    // body sharing a self-id but carrying different execution input is denied here,
                    // before effects); a Deny (candidate mode without installed authority / committed
                    // cutoff / missing / poisoned / inconsistent occurrence / different execution input
                    // / second one-shot entry) skips the executor AND the height update below
                    // (continue), before any irreversible effect, with no fallback to legacy
                    // execution. The pause/bypass/observe/fault hooks are #[cfg(test)] (deterministic
                    // timing + enforcement-bypass discrimination only).
                    #[cfg(test)]
                    supervised_start_checkpoint::prod_decision_pause_test_hook(&task.block);
                    let r198_start = supervised_start_checkpoint::prod_start_decision(&task.block);
                    #[cfg(test)]
                    let r198_start =
                        supervised_start_checkpoint::prod_maybe_bypass_test_hook(r198_start);
                    #[cfg(test)]
                    supervised_start_checkpoint::prod_decision_observed_test_hook(r198_start);
                    if matches!(r198_start, supervised_start_checkpoint::StartOutcome::Deny) {
                        continue;
                    }
                    #[cfg(test)]
                    supervised_start_checkpoint::prod_granted_pre_effect_test_hook();

                    // R191 (test-only): one-shot start-grant checkpoint, AFTER the real dequeue
                    // and BEFORE the first execution effect. Absent from non-test builds; a no-op
                    // unless THIS worker installed a start-grant gate (only the R191 fixture spawn
                    // does), so legacy workers and every other test are unaffected. A denial skips
                    // the executor AND the height update below (continue), so a dequeued occurrence
                    // refused a start after the common cutoff reaches NO execute_* call.
                    #[cfg(test)]
                    if !supervised_idle_close::start_grant_test_hook(&task.block) {
                        continue;
                    }
                    // R191 (test-only): independent executor-entry witness — fired at the SOLE site
                    // immediately preceding both the executor call and the height update, so a count
                    // of zero proves the executor was not entered (no receipts, no state mutation,
                    // no height advance). No-op unless a gate is installed; independent of the grant.
                    #[cfg(test)]
                    supervised_idle_close::executor_entry_test_hook();
                    #[cfg(test)]
                    supervised_start_checkpoint::prod_executor_entry_test_hook();

                    // Apply the block using T157 parallel executor
                    let block_start = Instant::now();
                    let tx_count = task.block.tx_count();

                    // T157: Use sender-partitioned parallel execution
                    match parallel_executor
                        .execute_block_sender_partitioned(&task.block.txs, &mut state)
                    {
                        Ok((receipts, stats)) => {
                            let block_duration = block_start.elapsed();
                            *current_height = task.block.height();

                            // Count successful transactions
                            let success_count =
                                receipts.iter().filter(|r| r.success).count() as u64;
                            let error_count = receipts.iter().filter(|r| !r.success).count() as u64;

                            // R192 (test-only): independent execution-EFFECT witness, fired ONLY
                            // after the real executor returned Ok, reporting the ACTUAL success/error
                            // counts and the advanced height for THIS occurrence. Absent from non-test
                            // builds; a no-op unless a start-grant gate is installed on this worker
                            // (only the R192 fixture spawn installs one). It distinguishes a denied
                            // occurrence (no entry, no effect) from a granted one (entry AND a real
                            // state effect), so the zero-effect oracle in A1 is discriminating.
                            #[cfg(test)]
                            supervised_idle_close::executor_result_test_hook(
                                success_count,
                                error_count,
                                *current_height,
                            );
                            #[cfg(test)]
                            supervised_start_checkpoint::prod_executor_result_test_hook(
                                success_count,
                                error_count,
                                *current_height,
                            );

                            // Update metrics
                            if let Some(ref m) = metrics {
                                m.add_txs_applied(success_count);
                                m.record_block_apply(block_duration);

                                // T157: Parallel execution metrics
                                m.set_parallel_workers_active(stats.workers_used);
                                m.record_sender_partitions(stats.num_senders);
                                m.record_parallel_block_time(block_duration);

                                if !stats.used_parallel {
                                    m.inc_parallel_fallback();
                                }

                                // Record errors (count nonce mismatches from receipts)
                                for receipt in &receipts {
                                    if !receipt.success {
                                        use crate::metrics::ExecutionErrorReason;
                                        m.inc_error(ExecutionErrorReason::NonceMismatch);
                                    }
                                }
                            }

                            // Brief log (no sensitive content)
                            if tx_count > 0 {
                                eprintln!(
                                    "[T157] Applied block {} ({} txs, {} senders, parallel={}) in {:?}",
                                    task.block.height(),
                                    tx_count,
                                    stats.num_senders,
                                    stats.used_parallel,
                                    block_duration
                                );
                            }

                            if error_count > 0 {
                                eprintln!(
                                    "[T157] Block {} had {} tx errors",
                                    task.block.height(),
                                    error_count
                                );
                            }
                        }
                        Err(e) => {
                            // Internal execution error (should be rare)
                            eprintln!(
                                "[T157] Execution error at height {}: {:?}",
                                task.block.height(),
                                e
                            );

                            if let Some(ref m) = metrics {
                                use crate::metrics::ExecutionErrorReason;
                                m.inc_error(ExecutionErrorReason::Other);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Channel closed, exit
                    break;
                }
            }
        }
    }

    /// Worker loop for VmV0 profile (T163 sequential VM execution).
    ///
    /// # T164: Persistent State
    ///
    /// When `state_dir` is provided, uses RocksDB-backed persistent storage.
    /// State is flushed after each committed block to ensure durability.
    ///
    /// # T186: Stage B Parallel Execution
    ///
    /// When `stage_b_enabled` is `true`, uses the Stage B conflict-graph scheduler
    /// to execute blocks in parallel. Stage B produces identical state and receipts
    /// as sequential execution.
    fn worker_loop_vm_v0(
        receiver: Receiver<ExecTask>,
        shutdown: Arc<AtomicBool>,
        queue_len: Arc<AtomicU64>,
        metrics: Option<Arc<ExecutionMetrics>>,
        preopened: Option<RocksDbAccountState>,
        current_height: &mut u64,
        stage_b_enabled: bool,
        // R150 (test-utils only): worker-local observation/flush control channel.
        #[cfg(feature = "test-utils")] control_receiver: Receiver<WorkerControl>,
    ) {
        let engine = VmV0ExecutionEngine::new();

        // T187: Log Stage B status at startup
        if stage_b_enabled {
            eprintln!(
                "[T187] VM v0 Stage B parallel execution enabled (conflict-graph scheduler active)"
            );
        } else {
            eprintln!("[T187] VM v0 Stage B parallel execution disabled (sequential execution)");
        }

        // C15(i): a requested persistent backend (if any) was opened BEFORE this
        // service was published and is handed in here as `preopened`. The worker
        // never opens a backend and never falls back to in-memory for a
        // requested-persistent service: `Some` ⇒ use that exact opened backend;
        // `None` ⇒ genuine, explicitly-selected memory-only (no persistence
        // requested). The prior in-worker open-with-fallback is removed.
        match preopened {
            Some(persistent) => {
                eprintln!("[C15(i)] VM v0 using the pre-opened persistent account-state backend");
                let mut state = CachedPersistentAccountState::new(persistent);
                Self::run_vm_v0_loop(
                    &engine,
                    &mut state,
                    receiver,
                    shutdown,
                    queue_len,
                    metrics,
                    current_height,
                    true, // persistent
                    stage_b_enabled,
                    #[cfg(feature = "test-utils")]
                    control_receiver,
                );
            }
            None => {
                // Explicit memory-only (T163 behavior): no persistence requested.
                eprintln!("[T164] VM v0 using in-memory state (no persistence)");
                let mut state = InMemoryAccountState::new();
                Self::run_vm_v0_loop(
                    &engine,
                    &mut state,
                    receiver,
                    shutdown,
                    queue_len,
                    metrics,
                    current_height,
                    false, // not persistent
                    stage_b_enabled,
                    #[cfg(feature = "test-utils")]
                    control_receiver,
                );
            }
        }
    }

    /// Inner loop for VM v0 execution.
    ///
    /// Generic over the state backend to support both in-memory and persistent state.
    ///
    /// # T186: Stage B Parallel Execution
    ///
    /// When `stage_b_enabled` is `true`, the execution loop attempts to use Stage B
    /// conflict-graph parallel execution for improved throughput. Stage B produces
    /// identical results as sequential execution.
    ///
    /// **Note**: Stage B currently requires converting state to/from InMemoryAccountState
    /// for each block. For persistent backends, this adds overhead but preserves correctness.
    #[allow(clippy::too_many_arguments)]
    fn run_vm_v0_loop<S: qbind_ledger::AccountStateUpdater + FlushableState>(
        engine: &VmV0ExecutionEngine,
        state: &mut S,
        receiver: Receiver<ExecTask>,
        shutdown: Arc<AtomicBool>,
        queue_len: Arc<AtomicU64>,
        metrics: Option<Arc<ExecutionMetrics>>,
        current_height: &mut u64,
        is_persistent: bool,
        stage_b_enabled: bool,
        // R150 (test-utils only): worker-local observation/flush control channel.
        #[cfg(feature = "test-utils")] control_receiver: Receiver<WorkerControl>,
    ) {
        // T187: Set Stage B enabled metric at startup
        if let Some(ref m) = metrics {
            m.set_stage_b_enabled(stage_b_enabled);
        }

        loop {
            // Check for shutdown
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            // Receive next task (blocking). In default builds this is exactly
            // `receiver.recv()` (R149 behavior). Under `test-utils`, the gated
            // helper additionally services worker-local observation/flush control
            // requests, but ONLY when no block is pending — so an observation
            // reflects every block enqueued before it (same-owner, FIFO). R150.
            #[cfg(not(feature = "test-utils"))]
            let recv_outcome = receiver.recv();
            #[cfg(feature = "test-utils")]
            let recv_outcome = Self::vm_v0_next_task(&receiver, &control_receiver, state);
            match recv_outcome {
                Ok(task) => {
                    // Update queue length
                    let len = receiver.len();
                    queue_len.store(len as u64, Ordering::Relaxed);

                    let block_start = Instant::now();
                    let tx_count = task.block.tx_count();

                    // T187: Actual Stage B execution path
                    // Stage B uses conflict-graph parallel execution when enabled.
                    // It produces identical state and receipts as sequential execution.
                    let (results, stage_b_used, stage_b_stats) = if stage_b_enabled && tx_count > 1
                    {
                        // Stage B path: use conflict-graph parallel execution
                        // Extract touched accounts into a snapshot for Stage B execution
                        let snapshot = extract_touched_accounts(state, &task.block.txs);
                        let stage_b_start = Instant::now();

                        // Execute using Stage B parallel scheduler
                        let (stage_b_results, final_state, stats) =
                            execute_block_stage_b(&task.block.txs, &snapshot);

                        // Apply state changes back to main state
                        apply_state_changes(state, &final_state);

                        let stage_b_duration = stage_b_start.elapsed();

                        // T187: Record Stage B metrics
                        if let Some(ref m) = metrics {
                            m.inc_stage_b_parallel();
                            m.record_stage_b_levels(stats.level_count);
                            m.record_stage_b_parallel_time(stage_b_duration);
                        }

                        eprintln!(
                            "[T187] Stage B executed block {} ({} txs, {} levels, max_level_size={}, parallel={}) in {:?}",
                            task.block.height(),
                            tx_count,
                            stats.level_count,
                            stats.max_level_size,
                            stats.used_parallel,
                            stage_b_duration
                        );

                        (stage_b_results, true, Some(stats))
                    } else {
                        // Sequential path: existing behavior
                        let results = engine.execute_block(state, &task.block.txs);
                        (results, false, None)
                    };

                    // T164: Flush state after block execution if using persistent backend
                    if is_persistent {
                        if let Err(e) = state.flush_state() {
                            eprintln!(
                                "[T164] Failed to flush state at height {}: {:?}",
                                task.block.height(),
                                e
                            );
                        }
                    }

                    let block_duration = block_start.elapsed();
                    *current_height = task.block.height();

                    // Count successful transactions
                    let success_count = results.iter().filter(|r| r.success).count() as u64;
                    let error_count = results.iter().filter(|r| !r.success).count() as u64;

                    // Update metrics
                    if let Some(ref m) = metrics {
                        m.add_txs_applied(success_count);
                        m.record_block_apply(block_duration);

                        // T187: Set workers based on Stage B stats
                        if let Some(ref stats) = stage_b_stats {
                            m.set_parallel_workers_active(stats.workers_used);
                        } else {
                            // Sequential execution uses 1 worker
                            m.set_parallel_workers_active(1);
                        }
                        m.record_parallel_block_time(block_duration);

                        // Record errors by type
                        for result in &results {
                            if !result.success {
                                use crate::metrics::ExecutionErrorReason;
                                if let Some(ref err) = result.error {
                                    match err {
                                        qbind_ledger::VmV0Error::NonceMismatch { .. } => {
                                            m.inc_error(ExecutionErrorReason::NonceMismatch);
                                        }
                                        qbind_ledger::VmV0Error::InsufficientBalance { .. } => {
                                            m.inc_error(ExecutionErrorReason::Other);
                                        }
                                        qbind_ledger::VmV0Error::MalformedPayload => {
                                            m.inc_error(ExecutionErrorReason::Other);
                                        }
                                        // T168: Gas-related errors
                                        qbind_ledger::VmV0Error::GasLimitExceeded { .. } => {
                                            m.inc_error(ExecutionErrorReason::Other);
                                        }
                                        qbind_ledger::VmV0Error::InsufficientBalanceForFee {
                                            ..
                                        } => {
                                            m.inc_error(ExecutionErrorReason::Other);
                                        }
                                        // M18: Arithmetic overflow errors
                                        qbind_ledger::VmV0Error::ArithmeticOverflow { .. } => {
                                            m.inc_error(ExecutionErrorReason::Other);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Brief log (no sensitive content)
                    if tx_count > 0 && !stage_b_used {
                        let persistence_info = if is_persistent {
                            "persistent"
                        } else {
                            "in-memory"
                        };
                        let stage_b_info = if stage_b_enabled {
                            ", stage_b=enabled"
                        } else {
                            ""
                        };
                        eprintln!(
                            "[T187] Applied block {} ({} txs, VM v0 sequential, {}{}) in {:?}",
                            task.block.height(),
                            tx_count,
                            persistence_info,
                            stage_b_info,
                            block_duration
                        );
                    }

                    if error_count > 0 {
                        eprintln!(
                            "[T164] Block {} had {} tx errors",
                            task.block.height(),
                            error_count
                        );
                    }
                }
                Err(_) => {
                    // Channel closed, exit
                    break;
                }
            }
        }
    }

    /// R150 (test-utils only): obtain the next block task for the VM-v0 worker
    /// while servicing worker-local observation/flush control requests.
    ///
    /// Pending blocks are ALWAYS preferred: a control request is serviced only
    /// when the block channel is empty, so any observation reflects the state
    /// produced by every block enqueued before it (same-owner, FIFO-correlated).
    /// Blocks and controls are each `recv`-blocking (no busy-wait). Returns the
    /// next block, or `RecvError` once the block channel is disconnected.
    #[cfg(feature = "test-utils")]
    fn vm_v0_next_task<S: qbind_ledger::AccountStateUpdater + FlushableState>(
        receiver: &Receiver<ExecTask>,
        control: &Receiver<WorkerControl>,
        state: &mut S,
    ) -> Result<ExecTask, crossbeam_channel::RecvError> {
        loop {
            // Prefer any already-enqueued block (FIFO before controls).
            match receiver.try_recv() {
                Ok(task) => return Ok(task),
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    return Err(crossbeam_channel::RecvError);
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {}
            }
            // No pending block: block until a block arrives or a control request
            // is ready, then loop (re-checking blocks first).
            crossbeam_channel::select! {
                recv(receiver) -> msg => return msg,
                recv(control) -> msg => match msg {
                    Ok(ctrl) => Self::handle_worker_control(state, ctrl),
                    // Control channel closed: block solely on blocks thereafter.
                    Err(_) => return receiver.recv(),
                },
            }
        }
    }

    /// R150 (test-utils only): service one worker-local control request against
    /// the worker-owned backend. Reads are non-mutating; flush is the same flush
    /// the worker performs after each persistent block. Never affects block
    /// execution, ordering, or any default behavior.
    #[cfg(feature = "test-utils")]
    fn handle_worker_control<S: qbind_ledger::AccountStateUpdater + FlushableState>(
        state: &mut S,
        ctrl: WorkerControl,
    ) {
        match ctrl {
            WorkerControl::ObserveAccount { account, reply } => {
                let observed = state.get_account_state(&account);
                let _ = reply.send(observed);
            }
            WorkerControl::Flush { reply } => {
                let result = state.flush_state().map_err(|e| format!("{:?}", e));
                let _ = reply.send(result);
            }
        }
    }

    /// R150 (test-utils only): read one account's state FROM THE WORKER-OWNED
    /// backend, after every block submitted before this call has been executed.
    ///
    /// This is the only sanctioned way for a test to observe post-execution
    /// persistent state under the single-owner contract: the request is serviced
    /// by the worker that exclusively owns the backend, in FIFO order behind all
    /// prior blocks. Returns an identifiable `WorkerObserveError` (never a
    /// fabricated value) if the worker is gone or does not answer within the
    /// bounded wait. VmV0 persistent/in-memory workers answer; a NonceOnly
    /// service has no such backend and reports `WorkerGone`.
    #[cfg(feature = "test-utils")]
    pub fn observe_account_state(
        &self,
        account: qbind_types::AccountId,
    ) -> Result<qbind_ledger::AccountState, WorkerObserveError> {
        let (reply_tx, reply_rx) = bounded(1);
        self.control_sender
            .send(WorkerControl::ObserveAccount {
                account,
                reply: reply_tx,
            })
            .map_err(|_| WorkerObserveError::WorkerGone)?;
        reply_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .map_err(|_| WorkerObserveError::Timeout)
    }

    /// R150 (test-utils only): flush the WORKER-OWNED backend to durable storage,
    /// in FIFO order behind all prior blocks. Returns an identifiable error on a
    /// flush failure, a gone worker, or a bounded-wait timeout.
    #[cfg(feature = "test-utils")]
    pub fn observe_flush(&self) -> Result<(), WorkerObserveError> {
        let (reply_tx, reply_rx) = bounded(1);
        self.control_sender
            .send(WorkerControl::Flush { reply: reply_tx })
            .map_err(|_| WorkerObserveError::WorkerGone)?;
        match reply_rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(WorkerObserveError::Flush(e)),
            Err(_) => Err(WorkerObserveError::Timeout),
        }
    }

    /// Get the queue full counter value.
    pub fn queue_full_count(&self) -> u64 {
        self.queue_full_count.load(Ordering::Relaxed)
    }

    /// Get the worker restart counter value.
    pub fn worker_restarts(&self) -> u64 {
        self.worker_restarts.load(Ordering::Relaxed)
    }

    /// Signal the service to shut down.
    ///
    /// After calling this, `submit_block` will return `ShuttingDown`.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if the service is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

impl AsyncExecutionService for SingleThreadExecutionService {
    fn submit_block(&self, block: QbindBlock) -> Result<(), AsyncExecError> {
        // Check shutdown first
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(AsyncExecError::ShuttingDown);
        }

        let task = ExecTask {
            block,
            submitted_at: Instant::now(),
        };

        // Try to send (non-blocking)
        match self.sender.try_send(task) {
            Ok(()) => {
                // Update queue length
                self.queue_len
                    .store(self.sender.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                self.queue_full_count.fetch_add(1, Ordering::Relaxed);

                // Update metrics if available
                if let Some(ref m) = self.metrics {
                    m.inc_queue_full();
                }

                Err(AsyncExecError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => Err(AsyncExecError::ShuttingDown),
        }
    }

    fn queue_len(&self) -> usize {
        self.queue_len.load(Ordering::Relaxed) as usize
    }
}

impl std::fmt::Debug for SingleThreadExecutionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleThreadExecutionService")
            .field("queue_len", &self.queue_len())
            .field("shutdown", &self.is_shutting_down())
            .field("queue_full_count", &self.queue_full_count())
            .finish()
    }
}

impl Drop for SingleThreadExecutionService {
    fn drop(&mut self) {
        // Signal shutdown when the service is dropped
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_ledger::{get_account_nonce, NonceExecutionEngine};
    use qbind_wire::consensus::BlockHeader;

    fn test_account_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn make_test_proposal(height: u64) -> Arc<BlockProposal> {
        Arc::new(BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1337,
                epoch: 0,
                height,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [height as u8; 32],
                proposer_index: 0,
                suite_id: 0,
                tx_count: 0,
                timestamp: 1704067200 + height,
                payload_kind: 0,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: Vec::new(),
            signature: Vec::new(),
        })
    }

    #[test]
    fn test_qbind_block_creation() {
        let proposal = make_test_proposal(1);
        let txs = vec![
            QbindTransaction::new(test_account_id(0xAA), 0, b"tx0".to_vec()),
            QbindTransaction::new(test_account_id(0xBB), 0, b"tx1".to_vec()),
        ];

        let block = QbindBlock::new(proposal.clone(), txs);

        assert_eq!(block.height(), 1);
        assert_eq!(block.tx_count(), 2);
        assert_eq!(block.block_id, proposal.header.payload_hash);
    }

    #[test]
    fn test_adapter_empty_block() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let proposal = make_test_proposal(1);
        let block = QbindBlock::empty(proposal);

        let result = adapter.apply_block(&block);
        assert!(result.is_ok());
        assert_eq!(adapter.current_height(), 1);
    }

    #[test]
    fn test_adapter_single_tx_success() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let sender = test_account_id(0xAA);
        let tx = QbindTransaction::new(sender, 0, b"hello".to_vec());

        let proposal = make_test_proposal(1);
        let block = QbindBlock::new(proposal, vec![tx]);

        let result = adapter.apply_block(&block);
        assert!(result.is_ok());
        assert_eq!(adapter.current_height(), 1);

        // Verify nonce was updated
        let nonce = get_account_nonce(adapter.state(), &sender);
        assert_eq!(nonce, 1);
    }

    #[test]
    fn test_adapter_multiple_txs_success() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let sender = test_account_id(0xBB);
        let txs = vec![
            QbindTransaction::new(sender, 0, b"tx0".to_vec()),
            QbindTransaction::new(sender, 1, b"tx1".to_vec()),
            QbindTransaction::new(sender, 2, b"tx2".to_vec()),
        ];

        let proposal = make_test_proposal(1);
        let block = QbindBlock::new(proposal, txs);

        let result = adapter.apply_block(&block);
        assert!(result.is_ok());

        // Verify final nonce
        let nonce = get_account_nonce(adapter.state(), &sender);
        assert_eq!(nonce, 3);
    }

    #[test]
    fn test_adapter_sequential_blocks() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let sender = test_account_id(0xCC);

        // Block 1: nonce 0 -> 1
        let block1 = QbindBlock::new(
            make_test_proposal(1),
            vec![QbindTransaction::new(sender, 0, b"b1".to_vec())],
        );
        adapter.apply_block(&block1).unwrap();
        assert_eq!(adapter.current_height(), 1);

        // Block 2: nonce 1 -> 2
        let block2 = QbindBlock::new(
            make_test_proposal(2),
            vec![QbindTransaction::new(sender, 1, b"b2".to_vec())],
        );
        adapter.apply_block(&block2).unwrap();
        assert_eq!(adapter.current_height(), 2);

        // Block 3: nonce 2 -> 3
        let block3 = QbindBlock::new(
            make_test_proposal(3),
            vec![QbindTransaction::new(sender, 2, b"b3".to_vec())],
        );
        adapter.apply_block(&block3).unwrap();
        assert_eq!(adapter.current_height(), 3);

        // Final nonce should be 3
        let nonce = get_account_nonce(adapter.state(), &sender);
        assert_eq!(nonce, 3);
    }

    #[test]
    fn test_adapter_nonce_mismatch_error() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let sender = test_account_id(0xDD);

        // Try to execute with wrong nonce (1 instead of 0)
        let tx = QbindTransaction::new(sender, 1, b"wrong".to_vec());
        let block = QbindBlock::new(make_test_proposal(1), vec![tx]);

        let result = adapter.apply_block(&block);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.height, 1);
        assert_eq!(err.tx_index, Some(0));

        // State should be unchanged (no partial updates)
        let nonce = get_account_nonce(adapter.state(), &sender);
        assert_eq!(nonce, 0);
    }

    #[test]
    fn test_adapter_error_stops_execution() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let sender = test_account_id(0xEE);

        // Block with: valid tx (nonce 0), invalid tx (nonce 5), valid tx (nonce 1)
        let txs = vec![
            QbindTransaction::new(sender, 0, b"ok".to_vec()),
            QbindTransaction::new(sender, 5, b"bad".to_vec()), // wrong nonce
            QbindTransaction::new(sender, 1, b"never".to_vec()), // never reached
        ];
        let block = QbindBlock::new(make_test_proposal(1), txs);

        let result = adapter.apply_block(&block);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.tx_index, Some(1)); // Error at second tx

        // First tx was executed, so nonce is 1
        // (Note: This is T150 behavior - no rollback)
        let nonce = get_account_nonce(adapter.state(), &sender);
        assert_eq!(nonce, 1);
    }

    #[test]
    fn test_adapter_multiple_senders() {
        let engine = NonceExecutionEngine::new();
        let mut adapter = InMemoryExecutionAdapter::new(engine);

        let sender_a = test_account_id(0xA1);
        let sender_b = test_account_id(0xB2);

        let txs = vec![
            QbindTransaction::new(sender_a, 0, b"a0".to_vec()),
            QbindTransaction::new(sender_b, 0, b"b0".to_vec()),
            QbindTransaction::new(sender_a, 1, b"a1".to_vec()),
            QbindTransaction::new(sender_b, 1, b"b1".to_vec()),
        ];

        let block = QbindBlock::new(make_test_proposal(1), txs);
        adapter.apply_block(&block).unwrap();

        assert_eq!(get_account_nonce(adapter.state(), &sender_a), 2);
        assert_eq!(get_account_nonce(adapter.state(), &sender_b), 2);
    }

    // ========================================================================
    // T155: AsyncExecutionService Tests
    // ========================================================================

    #[test]
    fn test_single_thread_service_creation() {
        let engine = NonceExecutionEngine::new();
        let service = SingleThreadExecutionService::new(engine);

        assert_eq!(service.queue_len(), 0);
        assert!(!service.is_shutting_down());
    }

    #[test]
    fn test_single_thread_service_with_config() {
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::default().with_queue_capacity(16);
        let service = SingleThreadExecutionService::with_config(engine, config, None);

        assert_eq!(service.queue_len(), 0);
        assert!(!service.is_shutting_down());
    }

    // ====================================================================
    // C15(i) — required-persistence initialization (R149) defensive controls.
    // Isolated disposable temp data; no external deps; no live node/startup.
    // ====================================================================

    /// Isolated disposable temp directory (no external `tempfile` dependency).
    fn r149_tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "qbind-r149-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&p).expect("create isolated temp dir");
        p
    }

    /// Supported requested persistence: a fresh state dir opens successfully and
    /// the service is published bound to a REAL on-disk backend (not in-memory).
    #[test]
    fn c15i_try_with_config_opens_persistent_backend_before_publishing() {
        let base = r149_tmp_dir("ok");
        let state_path = base.join("vm_v0_state");
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0_persistent(&state_path);
        let service = SingleThreadExecutionService::try_with_config(engine, config, None)
            .expect("requested persistent backend must initialize");
        assert_eq!(service.queue_len(), 0);
        assert!(!service.is_shutting_down());
        // Bound to a real on-disk backend: RocksDB created the state directory at
        // the requested path during the synchronous pre-publish open.
        assert!(
            state_path.exists(),
            "persistent backend directory must exist on disk after successful init"
        );
        drop(service);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Ordinary open failure ⇒ typed `OpenState` refusal, NO service published,
    /// NO in-memory fallback. Deterministic failure: request a backend whose
    /// parent path is a regular FILE (directory creation fails with ENOTDIR).
    #[test]
    fn c15i_try_with_config_refuses_open_failure_without_service() {
        let base = r149_tmp_dir("fail");
        let blocker = base.join("not_a_dir");
        std::fs::write(&blocker, b"x").expect("write blocker file");
        let state_path = blocker.join("vm_v0_state");
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0_persistent(&state_path);
        let result = SingleThreadExecutionService::try_with_config(engine, config, None);
        match result {
            Err(ExecutionServiceInitError::OpenState { path, .. }) => {
                assert_eq!(path, state_path);
            }
            Err(other) => panic!("expected OpenState refusal, got {:?}", other),
            Ok(_) => panic!("expected a typed OpenState refusal, got a published service"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Contradictory config: persistence requested with a non-`VmV0` profile ⇒
    /// typed invalid-config refusal BEFORE any open/spawn, never silent memory.
    #[test]
    fn c15i_try_with_config_rejects_contradictory_nonceonly_plus_state_dir() {
        let base = r149_tmp_dir("contradictory");
        let config = SingleThreadExecutionServiceConfig::default() // NonceOnly
            .with_state_dir(base.join("state"));
        let engine = NonceExecutionEngine::new();
        let result = SingleThreadExecutionService::try_with_config(engine, config, None);
        assert!(matches!(
            result,
            Err(ExecutionServiceInitError::ContradictoryConfig {
                profile: ExecutionProfile::NonceOnly
            })
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Genuine memory-only via the fallible API succeeds with no backend opened:
    /// VmV0 + `state_dir=None` and the default NonceOnly both return `Ok`.
    #[test]
    fn c15i_try_with_config_memory_only_is_ok_for_none_state_dir() {
        let svc1 = SingleThreadExecutionService::try_with_config(
            NonceExecutionEngine::new(),
            SingleThreadExecutionServiceConfig::vm_v0(), // VmV0 + state_dir None
            None,
        )
        .expect("memory-only VmV0 must succeed");
        assert!(!svc1.is_shutting_down());
        let svc2 = SingleThreadExecutionService::try_with_config(
            NonceExecutionEngine::new(),
            SingleThreadExecutionServiceConfig::default(), // NonceOnly + None
            None,
        )
        .expect("memory-only NonceOnly must succeed");
        assert!(!svc2.is_shutting_down());
    }

    /// Legacy infallible `with_config` enforces its memory-only precondition with
    /// a PANIC on a persistent config. This is a programmer-precondition failure,
    /// explicitly NOT a typed persistent-initialization refusal.
    #[test]
    #[should_panic(expected = "memory-only")]
    fn c15i_legacy_with_config_persistent_is_programmer_precondition_panic() {
        let base = r149_tmp_dir("legacy");
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0_persistent(base.join("state"));
        let _ = SingleThreadExecutionService::with_config(engine, config, None);
    }

    /// R150 positive persistent-execution witness (test-utils only).
    ///
    /// Genuine evidence that a requested persistent service executes on, and is
    /// observed through, ONE worker-owned backend:
    ///   known funded state  →  an ACTUAL nonzero state transition executed by
    ///   the worker (submit_block)  →  correlated observation from the SAME
    ///   worker-owned backend (FIFO behind the block)  →  successful explicit
    ///   flush.
    /// This exercises LOCAL execution via the real async service, deliberately
    /// NOT consensus-commit qualification. It does not assert restart, durability,
    /// shutdown, atomicity, fencing, or readiness. A separate ordinary memory-only
    /// positive is `c15i_try_with_config_memory_only_is_ok_for_none_state_dir`.
    #[cfg(feature = "test-utils")]
    #[test]
    fn c15i_r150_persistent_execution_witness_same_owner_observation() {
        let base = r149_tmp_dir("r150-witness");
        let state_path = base.join("vm_v0_state");
        let sender = test_account_id(0x11);
        let recipient = test_account_id(0x22);

        // Pre-initialization funding: open, fund, flush, RELEASE the setup handle
        // (the single-owner precondition) — no second writable handle is retained.
        {
            let persistent =
                RocksDbAccountState::open(&state_path).expect("open funding handle");
            let mut funding = CachedPersistentAccountState::new(persistent);
            funding.set_account_state(&sender, qbind_ledger::AccountState::new(0, 1000));
            funding.set_account_state(&recipient, qbind_ledger::AccountState::new(0, 0));
            funding.flush().expect("flush funding");
        } // released

        // Hand exclusive ownership of the funded backend to the service.
        let config = SingleThreadExecutionServiceConfig::vm_v0_persistent(&state_path);
        let service =
            SingleThreadExecutionService::try_with_config(NonceExecutionEngine::new(), config, None)
                .expect("persistent VM-v0 service must initialize");

        // Pre-execution observation THROUGH the worker-owned backend: the funded
        // state is visible, the recipient starts at zero.
        let before_sender = service
            .observe_account_state(sender)
            .expect("observe funded sender");
        assert_eq!(before_sender.balance, 1000, "funded sender visible pre-exec");
        let before_recipient = service
            .observe_account_state(recipient)
            .expect("observe recipient");
        assert_eq!(before_recipient.balance, 0, "recipient starts at zero");

        // Submit a real transfer block to the service (LOCAL execution).
        let transfer_amount = 100u128;
        let payload = TransferPayload::new(recipient, transfer_amount).encode();
        let tx = QbindTransaction::new(sender, 0, payload);
        let block = QbindBlock::new(make_test_proposal(1), vec![tx]);
        service.submit_block(block).expect("submit_block");

        // Correlated observation of the ACTUAL nonzero state transition from the
        // SAME worker-owned backend (serviced in FIFO order AFTER the block).
        let after_sender = service
            .observe_account_state(sender)
            .expect("observe sender after execution");
        let after_recipient = service
            .observe_account_state(recipient)
            .expect("observe recipient after execution");
        assert_eq!(
            after_sender.balance,
            1000 - transfer_amount,
            "sender debited by exactly the transfer amount (worker-owned backend)"
        );
        assert_eq!(
            after_recipient.balance, transfer_amount,
            "recipient credited the exact transfer amount — a genuine nonzero transition"
        );
        assert_ne!(
            after_recipient.balance, before_recipient.balance,
            "recipient balance genuinely changed (not unchanged/detached state)"
        );
        assert_eq!(after_sender.nonce, 1, "sender nonce advanced by the applied tx");

        // Explicit flush of the worker-owned backend succeeds.
        service.observe_flush().expect("explicit worker-owned flush");

        drop(service);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_single_thread_service_submit_empty_block() {
        let engine = NonceExecutionEngine::new();
        let service = SingleThreadExecutionService::new(engine);

        let proposal = make_test_proposal(1);
        let block = QbindBlock::empty(proposal);

        // Submit should succeed
        let result = service.submit_block(block);
        assert!(result.is_ok());

        // Wait briefly for worker to process
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    #[test]
    fn test_single_thread_service_submit_block_with_txs() {
        let engine = NonceExecutionEngine::new();
        let service = SingleThreadExecutionService::new(engine);

        let sender = test_account_id(0xAA);
        let txs = vec![
            QbindTransaction::new(sender, 0, b"tx0".to_vec()),
            QbindTransaction::new(sender, 1, b"tx1".to_vec()),
        ];

        let proposal = make_test_proposal(1);
        let block = QbindBlock::new(proposal, txs);

        let result = service.submit_block(block);
        assert!(result.is_ok());

        // Wait for processing
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    fn test_single_thread_service_queue_full() {
        let engine = NonceExecutionEngine::new();
        // Create service with tiny queue
        let config = SingleThreadExecutionServiceConfig::default().with_queue_capacity(1);
        let service = SingleThreadExecutionService::with_config(engine, config, None);

        // Submit multiple blocks quickly to fill the queue
        let mut queue_full_seen = false;
        for i in 0..100 {
            let proposal = make_test_proposal(i);
            let block = QbindBlock::empty(proposal);

            match service.submit_block(block) {
                Ok(()) => {}
                Err(AsyncExecError::QueueFull) => {
                    queue_full_seen = true;
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        // Should have seen queue full at some point
        assert!(queue_full_seen || service.queue_full_count() > 0);
    }

    #[test]
    fn test_single_thread_service_shutdown() {
        let engine = NonceExecutionEngine::new();
        let service = SingleThreadExecutionService::new(engine);

        // Signal shutdown
        service.shutdown();
        assert!(service.is_shutting_down());

        // Subsequent submits should fail
        let proposal = make_test_proposal(1);
        let block = QbindBlock::empty(proposal);
        let result = service.submit_block(block);

        assert!(matches!(result, Err(AsyncExecError::ShuttingDown)));
    }

    #[test]
    fn test_single_thread_service_multiple_blocks_sequential() {
        let engine = NonceExecutionEngine::new();
        let service = SingleThreadExecutionService::new(engine);

        let sender = test_account_id(0xBB);

        // Submit multiple blocks in order
        for i in 0u64..5 {
            let txs = vec![QbindTransaction::new(
                sender,
                i,
                format!("tx{}", i).into_bytes(),
            )];
            let proposal = make_test_proposal(i + 1);
            let block = QbindBlock::new(proposal, txs);

            let result = service.submit_block(block);
            assert!(result.is_ok(), "Block {} submission failed", i + 1);
        }

        // Wait for all processing
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Queue should be drained
        assert_eq!(service.queue_len(), 0);
    }

    #[test]
    fn test_async_exec_error_display() {
        let err1 = AsyncExecError::QueueFull;
        assert_eq!(format!("{}", err1), "execution queue full");

        let err2 = AsyncExecError::ShuttingDown;
        assert_eq!(format!("{}", err2), "service shutting down");
    }

    #[test]
    fn test_single_thread_service_debug() {
        let engine = NonceExecutionEngine::new();
        let service = SingleThreadExecutionService::new(engine);

        let debug_str = format!("{:?}", service);
        assert!(debug_str.contains("SingleThreadExecutionService"));
        assert!(debug_str.contains("queue_len"));
        assert!(debug_str.contains("shutdown"));
    }
}

/// R167 — C05 first supervised idle close on the REAL memory-only NonceOnly worker.
///
/// This is an **internal, opt-in, unwired candidate** (Option B + restricted P1 from
/// the R166/R167 decision). It drives the actual production
/// [`SingleThreadExecutionService::worker_loop_nonce_only`] receive path on a real
/// spawned worker thread; it is NOT a shadow worker and NOT a public API. It is kept
/// off every production caller (simulator, harnesses, binaries) and off the legacy
/// `AsyncExecutionService` trait surface:
///
/// * One **non-clonable owner** ([`SupervisedNonceOwner`]) retains the sole worker
///   `JoinHandle`; a submit-only [`SupervisedSubmitView`] shares admission without
///   exposing `shutdown(&self)`, the observer seam, or any raw
///   `Arc<SingleThreadExecutionService>`.
/// * **Eligibility (restricted P1):** only a worker with ZERO successful admissions
///   over its lifetime may be closed. The first successful enqueue, the eligibility
///   check, and removal of the sole sender are serialized under one lock. A prior
///   admission always refuses the limited close and leaves admission + supervision
///   unchanged.
/// * **Wake:** an eligible close removes the sole task sender, disconnecting the
///   channel and waking the real receive path — no flag, no task, no sentinel, no
///   external sender drop.
/// * **Termination:** a bounded observation reports `Pending`/`ReadyToJoin` from a
///   readiness signal only; a separate, possibly-blocking `join` consumes the handle
///   and supplies the authoritative normal/panic result. Readiness is not an observed
///   join. A duplicate join is refused.
///
/// The legacy sender path, nonblocking `submit_block`, `shutdown(&self)`, `Drop`, the
/// public trait and error variants, the C15(i) persistent constructors, and the
/// shipping VM-v0 opener are all untouched. This candidate opens no storage and
/// supports only memory-only `NonceOnly`; any other configuration is refused before a
/// channel is created or a worker spawned. Busy-drain/custody, persistent write/flush
/// propagation, durable completion, reuse authorization, and restart-safe quarantine
/// remain out of scope (separate obligations).
mod supervised_idle_close {
    #![allow(dead_code)]

    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use crossbeam_channel::{bounded, Sender, TrySendError};

    use crate::node_config::ExecutionProfile;

    use super::{ExecTask, QbindBlock, SingleThreadExecutionService, SingleThreadExecutionServiceConfig};

    /// Generous failsafe for test waits; a healthy run never approaches it.
    const FAILSAFE: Duration = Duration::from_secs(10);

    // ----------------------------------------------------------------------
    // Readiness signal (latching, bounded wait)
    // ----------------------------------------------------------------------

    /// A latching one-shot signal. Used for the worker's exit *readiness* (fired by a
    /// drop-guard on the worker body) and, in tests, for deterministic rendezvous.
    struct Signal {
        state: Mutex<bool>,
        cv: Condvar,
    }
    impl Signal {
        fn new() -> Self {
            Signal { state: Mutex::new(false), cv: Condvar::new() }
        }
        fn fire(&self) {
            let mut g = self.state.lock().unwrap();
            *g = true;
            self.cv.notify_all();
        }
        /// Block until fired. Returns true if fired, false if `timeout` elapsed.
        fn wait(&self, timeout: Duration) -> bool {
            let g = self.state.lock().unwrap();
            let (_g, res) = self.cv.wait_timeout_while(g, timeout, |fired| !*fired).unwrap();
            !res.timed_out()
        }
    }

    /// Fires a readiness `Signal` when the worker body returns (normal OR panic unwind).
    /// Readiness is NOT an observed join; the authoritative result comes from `join`.
    struct FireOnDrop(Arc<Signal>);
    impl Drop for FireOnDrop {
        fn drop(&mut self) {
            self.0.fire();
        }
    }

    // ----------------------------------------------------------------------
    // Public-ish (crate-internal) outcome vocabulary
    // ----------------------------------------------------------------------

    /// Why the supervised entry refused to start.
    #[derive(Debug)]
    enum SupervisedInitError {
        /// Only the memory-only `NonceOnly` profile is supported on this path.
        UnsupportedProfile,
        /// A persistent backend (`state_dir = Some`) is not supported here.
        UnsupportedPersistentState,
        /// The worker thread failed to spawn.
        WorkerSpawn { source: std::io::Error },
    }

    /// Outcome of a supervised-view submission (mirrors the legacy mapping, on a
    /// SEPARATE path — the legacy nonblocking `submit_block` is untouched).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SubmitOutcome {
        Admitted,
        QueueFull,
        ShuttingDown,
    }

    /// Why the limited close was refused.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CloseRefused {
        /// A prior successful admission makes this worker ineligible for the limited
        /// close; admission and supervision are left unchanged.
        Admitted,
    }

    /// Bounded observation of the worker's exit readiness. Never a termination claim.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Readiness {
        Pending,
        ReadyToJoin,
    }

    /// Authoritative termination evidence from an actual join.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TermEvidence {
        Normal,
        Panic,
    }

    /// Result of requesting a join through the owner.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum JoinOutcome {
        Terminated(TermEvidence),
        /// The sole handle was already consumed by a prior join.
        AlreadyJoined,
    }

    // ----------------------------------------------------------------------
    // Shared admission gate (one serialization boundary)
    // ----------------------------------------------------------------------

    struct GateInner {
        /// The SOLE task sender. The owner's eligible close `take`s it (drop →
        /// channel disconnect → the real receive path wakes). The view never removes
        /// it; losing all views cannot drop it while the owner holds the gate.
        sender: Option<Sender<ExecTask>>,
        /// Set true on the FIRST successful enqueue, under this lock.
        admitted: bool,
    }

    /// The shared admission gate. The owner and the submit view both hold an
    /// `Arc<SupervisedGate>`, but only the owner has the capability to remove the
    /// sender (close); the view can only enqueue. The single `Mutex` serializes a
    /// successful enqueue, the never-admitted eligibility check, and sender removal.
    struct SupervisedGate {
        inner: Mutex<GateInner>,
    }

    /// Submit-only shared view. Clonable so admission can be shared, but it exposes
    /// only `submit`; no shutdown, no observer, no sender removal, no raw service Arc.
    #[derive(Clone)]
    struct SupervisedSubmitView {
        gate: Arc<SupervisedGate>,
    }
    impl SupervisedSubmitView {
        fn submit(&self, block: QbindBlock) -> SubmitOutcome {
            #[cfg(test)]
            contention_probe_entry(&self.gate);
            let mut inner = self.gate.inner.lock().unwrap();
            #[cfg(test)]
            contention_hold_after_lock();
            match inner.sender.as_ref() {
                None => SubmitOutcome::ShuttingDown,
                Some(tx) => {
                    let task = ExecTask { block, submitted_at: Instant::now() };
                    match tx.try_send(task) {
                        Ok(()) => {
                            inner.admitted = true; // record the first/each successful enqueue
                            SubmitOutcome::Admitted
                        }
                        Err(TrySendError::Full(_)) => SubmitOutcome::QueueFull,
                        Err(TrySendError::Disconnected(_)) => SubmitOutcome::ShuttingDown,
                    }
                }
            }
        }
    }

    /// The non-clonable supervising owner: sole holder of the worker `JoinHandle` and
    /// the only party that may request the limited close.
    struct SupervisedNonceOwner {
        gate: Arc<SupervisedGate>,
        handle: Option<JoinHandle<()>>,
        ready: Arc<Signal>,
        joined: Option<TermEvidence>,
    }
    impl SupervisedNonceOwner {
        /// Limited close: eligible ONLY if the worker never had a successful admission.
        /// On eligibility, removes the sole sender (disconnect → wakes the real receive
        /// path). On a prior admission, refuses and leaves admission + supervision
        /// unchanged. The eligibility check and sender removal are serialized with
        /// enqueue under the gate lock.
        fn try_close_idle(&self) -> Result<(), CloseRefused> {
            #[cfg(test)]
            contention_probe_entry(&self.gate);
            let mut inner = self.gate.inner.lock().unwrap();
            #[cfg(test)]
            contention_hold_after_lock();
            if inner.admitted {
                return Err(CloseRefused::Admitted); // state unchanged
            }
            inner.sender = None; // remove the sole sender under the same serialization
            Ok(())
        }

        /// Bounded readiness observation; retains the handle. Never a join.
        fn observe_ready(&self, deadline: Duration) -> Readiness {
            if self.ready.wait(deadline) {
                Readiness::ReadyToJoin
            } else {
                Readiness::Pending
            }
        }

        /// The authoritative, possibly-blocking join. Consumes the sole handle once;
        /// a second call cannot obtain a join.
        fn join(&mut self) -> JoinOutcome {
            match self.handle.take() {
                Some(h) => {
                    let ev = match h.join() {
                        Ok(()) => TermEvidence::Normal,
                        Err(_) => TermEvidence::Panic,
                    };
                    self.joined = Some(ev);
                    JoinOutcome::Terminated(ev)
                }
                None => JoinOutcome::AlreadyJoined,
            }
        }

        fn is_admitted(&self) -> bool {
            self.gate.inner.lock().unwrap().admitted
        }
        fn sender_present(&self) -> bool {
            self.gate.inner.lock().unwrap().sender.is_some()
        }
    }

    // ----------------------------------------------------------------------
    // Spawn core — reuses the actual NonceOnly worker receive path
    // ----------------------------------------------------------------------

    /// Shared spawn core. Rejects unsupported configurations BEFORE creating a channel
    /// or spawning. `worker_prelude` runs at the very start of the worker thread
    /// (production: a no-op; tests: installs a receive-boundary gate).
    fn spawn_core<F>(
        config: &SingleThreadExecutionServiceConfig,
        worker_prelude: F,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView), SupervisedInitError>
    where
        F: FnOnce() + Send + 'static,
    {
        // Refuse unsupported configurations before opening storage or spawning.
        match config.execution_profile {
            ExecutionProfile::NonceOnly => {}
            _ => return Err(SupervisedInitError::UnsupportedProfile),
        }
        if config.state_dir.is_some() {
            return Err(SupervisedInitError::UnsupportedPersistentState);
        }

        let (tx, rx) = bounded::<ExecTask>(config.queue_capacity);
        let shutdown = Arc::new(AtomicBool::new(false)); // moved to worker; owner closes via sender removal
        let queue_len = Arc::new(AtomicU64::new(0));
        let parallel_config = config.parallel_config.clone();
        let ready = Arc::new(Signal::new());
        let ready_w = Arc::clone(&ready);

        let handle = thread::Builder::new()
            .name("qbind-exec-worker".to_string())
            .spawn(move || {
                worker_prelude();
                // Readiness fires when the real worker body returns (normal or panic).
                let _fire = FireOnDrop(ready_w);
                let mut current_height: u64 = 0;
                // The ACTUAL production NonceOnly receive path.
                SingleThreadExecutionService::worker_loop_nonce_only(
                    rx,
                    shutdown,
                    queue_len,
                    None,
                    parallel_config,
                    &mut current_height,
                );
            })
            .map_err(|source| SupervisedInitError::WorkerSpawn { source })?;

        let gate = Arc::new(SupervisedGate {
            inner: Mutex::new(GateInner { sender: Some(tx), admitted: false }),
        });
        let owner = SupervisedNonceOwner {
            gate: Arc::clone(&gate),
            handle: Some(handle),
            ready,
            joined: None,
        };
        let view = SupervisedSubmitView { gate };
        Ok((owner, view))
    }

    /// Internal opt-in supervised entry (memory-only NonceOnly). Unwired; no caller.
    fn spawn_supervised_nonce_only(
        config: &SingleThreadExecutionServiceConfig,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView), SupervisedInitError> {
        spawn_core(config, || {})
    }

    // ----------------------------------------------------------------------
    // Test-only deterministic receive-boundary instrumentation (per-visit)
    // ----------------------------------------------------------------------

    /// A deterministic, PER-VISIT gate at the real worker's receive boundary. On each
    /// loop iteration the worker announces it has reached the boundary (one token per
    /// visit) and then waits for one release token, so a test can observe *successive*
    /// visits distinctly — a latching signal cannot. `await_visit`/`release_one` are the
    /// test side; `worker_visit` is the worker side.
    /// R172: the unique marker carried by the ONE intentional guarded-worker panic, so
    /// the expected worker panic is identifiable in stderr separately from any unrelated
    /// output. The control asserts success through the owner's actual join, never via an
    /// outer `#[should_panic]`.
    #[cfg(test)]
    const R172_GUARDED_WORKER_PANIC_MARKER: &str =
        "R172-INTENTIONAL-GUARDED-NONCE-WORKER-PANIC-after-readiness-guard";

    #[cfg(test)]
    struct RecvBoundaryGate {
        reached_tx: crossbeam_channel::Sender<()>,
        reached_rx: crossbeam_channel::Receiver<()>,
        release_tx: crossbeam_channel::Sender<()>,
        release_rx: crossbeam_channel::Receiver<()>,
        // R172: per-worker, opt-in one-shot fault arm + a consumption ack. Disarmed by
        // default, so every other control's release behavior is byte-for-byte unchanged.
        // This is NOT a global panic hook and holds no shared admission/readiness lock.
        fault_armed: std::sync::atomic::AtomicBool,
        fault_ack_tx: crossbeam_channel::Sender<()>,
        fault_ack_rx: crossbeam_channel::Receiver<()>,
    }
    #[cfg(test)]
    impl RecvBoundaryGate {
        fn new() -> Self {
            let (reached_tx, reached_rx) = crossbeam_channel::unbounded();
            let (release_tx, release_rx) = crossbeam_channel::unbounded();
            let (fault_ack_tx, fault_ack_rx) = crossbeam_channel::unbounded();
            RecvBoundaryGate {
                reached_tx,
                reached_rx,
                release_tx,
                release_rx,
                fault_armed: std::sync::atomic::AtomicBool::new(false),
                fault_ack_tx,
                fault_ack_rx,
            }
        }
        /// Test side: block until the worker reports reaching the boundary once more.
        fn await_visit(&self) {
            self.reached_rx
                .recv_timeout(FAILSAFE)
                .expect("worker reached the receive boundary");
        }
        /// Test side: release exactly one held visit so the worker proceeds past it.
        fn release_one(&self) {
            self.release_tx.send(()).expect("release one boundary visit");
        }
        /// Worker side: announce this visit and wait (bounded) for one release token.
        /// R172: after the release, if (and only if) this worker's fault has been armed,
        /// announce consumption (a deterministic fixture ack) and panic deliberately —
        /// INSIDE the guarded worker body, where the `FireOnDrop` readiness guard is
        /// already installed, so the unwind fires readiness and the retained owner's join
        /// observes `Panic`. No shared admission or readiness lock is held here, and no
        /// global panic hook is used. Disarmed by default, so every other control
        /// proceeds exactly as before.
        fn worker_visit(&self) {
            let _ = self.reached_tx.send(());
            let _ = self.release_rx.recv_timeout(FAILSAFE);
            if self.fault_armed.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = self.fault_ack_tx.send(());
                panic!("{}", R172_GUARDED_WORKER_PANIC_MARKER);
            }
        }
        /// Test side: arm this worker's one-shot fault. Set BEFORE the matching
        /// `release_one`, so the worker observes it just after the release token.
        fn arm_fault(&self) {
            self.fault_armed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        /// Test side: block (bounded) until the worker acknowledges consuming the fault
        /// command — deterministic proof the expected command was taken.
        fn await_fault_ack(&self) {
            self.fault_ack_rx
                .recv_timeout(FAILSAFE)
                .expect("worker consumed the armed fault command");
        }
    }

    #[cfg(test)]
    thread_local! {
        static RECV_GATE: std::cell::RefCell<Option<Arc<RecvBoundaryGate>>> =
            const { std::cell::RefCell::new(None) };
    }
    #[cfg(test)]
    fn install_recv_gate(gate: Arc<RecvBoundaryGate>) {
        RECV_GATE.with(|g| *g.borrow_mut() = Some(gate));
    }

    /// Called from the real `worker_loop_nonce_only` immediately before each blocking
    /// `receiver.recv()` (test builds only). A no-op unless a gate was installed on this
    /// worker thread, so legacy workers are unaffected. Each call is one boundary visit.
    #[cfg(test)]
    pub(super) fn recv_boundary_test_hook() {
        let gate = RECV_GATE.with(|g| g.borrow().clone());
        if let Some(gate) = gate {
            gate.worker_visit();
        }
    }

    #[cfg(test)]
    fn spawn_supervised_nonce_only_with_gate(
        config: &SingleThreadExecutionServiceConfig,
        gate: Arc<RecvBoundaryGate>,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView), SupervisedInitError> {
        spawn_core(config, move || install_recv_gate(gate))
    }

    #[cfg(test)]
    impl SupervisedNonceOwner {
        /// Test-only, well-accounted teardown step: unconditionally remove the sole
        /// sender (disconnecting the real receive path). This is NOT the
        /// eligibility-gated close. The readiness observation and the actual join are
        /// performed SEPARATELY by the test, so every join — including teardown —
        /// follows a bounded readiness check. The non-test owner algorithm is unchanged.
        fn teardown_remove_sender(&self) {
            let mut inner = self.gate.inner.lock().unwrap();
            inner.sender = None;
        }
    }

    // ----------------------------------------------------------------------
    // Real-worker lifecycle controls (memory-only NonceOnly)
    // ----------------------------------------------------------------------

    #[cfg(test)]
    use qbind_wire::consensus::{BlockHeader, BlockProposal};

    #[cfg(test)]
    fn make_proposal(height: u64) -> Arc<BlockProposal> {
        Arc::new(BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1337,
                epoch: 0,
                height,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [height as u8; 32],
                proposer_index: 0,
                suite_id: 0,
                tx_count: 0,
                timestamp: 1704067200 + height,
                payload_kind: 0,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: Vec::new(),
            signature: Vec::new(),
        })
    }

    #[cfg(test)]
    fn nonce_config() -> SingleThreadExecutionServiceConfig {
        // Default is memory-only NonceOnly (state_dir None).
        SingleThreadExecutionServiceConfig::default()
    }

    /// Control 1: a never-admitted real worker reaches the receive boundary; the owner
    /// close takes the sole sender; a bounded readiness observation precedes the actual
    /// normal join, which is verified separately. Post-close submit is refused through
    /// the same view, owner + view still alive. No task, sentinel, or external drop.
    #[cfg(test)]
    #[test]
    fn never_admitted_idle_close_and_actual_join() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, view) =
            spawn_supervised_nonce_only_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        gate.await_visit(); // the real worker reached the receive boundary (held there)
        assert_eq!(owner.try_close_idle(), Ok(()), "never-admitted worker is eligible");
        gate.release_one(); // worker proceeds into recv → disconnect → exit

        // Bounded readiness observation BEFORE the actual join; then join separately.
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(
            owner.join(),
            JoinOutcome::Terminated(TermEvidence::Normal),
            "the sole owner obtains the actual normal join"
        );
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::ShuttingDown,
            "post-close submit is refused through the same live view"
        );
    }

    /// Control 2: hold the never-admitted real worker at the boundary, close through the
    /// owner, and observe a bounded wait return Pending with the handle retained; release
    /// the gate, observe readiness, then a real join through the SAME owner. Admission
    /// stays closed and a second join cannot be obtained.
    #[cfg(test)]
    #[test]
    fn pending_wait_then_actual_join_same_owner() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, view) =
            spawn_supervised_nonce_only_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        gate.await_visit(); // worker reached and is held at the boundary
        assert_eq!(owner.try_close_idle(), Ok(()), "eligible close removes the sole sender");

        // Worker is deterministically held at the boundary → not terminated → pending.
        assert_eq!(owner.observe_ready(Duration::from_millis(100)), Readiness::Pending);
        assert!(owner.handle.is_some(), "a pending observation retains the handle");

        gate.release_one(); // let the worker proceed to recv → disconnect → exit
        // Bounded readiness observation BEFORE the actual join; then join separately.
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));

        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(2))),
            SubmitOutcome::ShuttingDown,
            "admission stays closed after the join"
        );
        assert_eq!(owner.join(), JoinOutcome::AlreadyJoined, "a second join cannot be obtained");
    }

    /// Control 3: after one real successful admission, independently observe a DISTINCT
    /// second visit to the real receive boundary (the worker handled the one inert item
    /// to the loop boundary under the controlled schedule — no success/persistence/
    /// eligibility is claimed from it). AFTER that observation the same owner still
    /// refuses the limited close, and the refusal leaves the sender, the sticky
    /// prior-admission state, and supervision intact. A separate, well-accounted teardown
    /// (explicit sender cleanup + gate release) precedes a bounded readiness observation
    /// and the actual join.
    #[cfg(test)]
    #[test]
    fn refuse_close_after_real_admission() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, view) =
            spawn_supervised_nonce_only_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        gate.await_visit(); // first boundary visit, before any item
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::Admitted,
            "one real successful admission on the actual worker path"
        );
        gate.release_one(); // worker receives and handles the one inert item on the real path

        // DISTINCT second visit: the worker returned to the receive boundary after
        // handling the item. (Narrow claim: handled-to-loop-boundary only.)
        gate.await_visit();

        // After that observation the limited close still refuses, leaving everything intact.
        assert_eq!(
            owner.try_close_idle(),
            Err(CloseRefused::Admitted),
            "a prior admission still refuses the limited close after the 2nd visit"
        );
        assert!(owner.sender_present(), "a refused close leaves the sole sender intact");
        assert!(owner.is_admitted(), "sticky prior-admission eligibility state remains");
        assert!(owner.handle.is_some(), "supervision (the join handle) is retained");

        // Separate, well-accounted teardown: explicit sender cleanup + gate release,
        // then a bounded readiness observation, then the actual join (verified separately).
        owner.teardown_remove_sender();
        gate.release_one(); // release the held second visit → worker proceeds → disconnect → exit
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// Control 4: the serialization yields the selected results in both positions —
    /// close-first (eligible; later submit refused) and admission-first (close refused).
    /// Every actual join follows a bounded readiness observation, including teardown.
    #[cfg(test)]
    #[test]
    fn serialization_close_first_and_admission_first() {
        // close-first: eligible close removes the sender before any admission.
        {
            let (mut owner, view) = spawn_supervised_nonce_only(&nonce_config()).expect("spawn");
            assert_eq!(owner.try_close_idle(), Ok(()));
            assert_eq!(
                view.submit(QbindBlock::empty(make_proposal(1))),
                SubmitOutcome::ShuttingDown,
                "submit after a close-first is refused"
            );
            assert!(!owner.is_admitted(), "no admission recorded after a close-first");
            assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        }
        // admission-first: a prior successful admission refuses the close; teardown joins.
        {
            let (mut owner, view) = spawn_supervised_nonce_only(&nonce_config()).expect("spawn");
            assert_eq!(view.submit(QbindBlock::empty(make_proposal(2))), SubmitOutcome::Admitted);
            assert_eq!(owner.try_close_idle(), Err(CloseRefused::Admitted));
            owner.teardown_remove_sender();
            assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        }
    }

    /// Control 5: unsupported configurations are refused before a channel is created or a
    /// worker is spawned. No backend is opened.
    #[cfg(test)]
    #[test]
    fn unsupported_config_refuses_before_spawn() {
        let mut vmv0 = SingleThreadExecutionServiceConfig::default();
        vmv0.execution_profile = ExecutionProfile::VmV0;
        match spawn_supervised_nonce_only(&vmv0) {
            Err(SupervisedInitError::UnsupportedProfile) => {}
            Err(e) => panic!("expected UnsupportedProfile, got a different error: {:?}", e),
            Ok(_) => panic!("expected UnsupportedProfile refusal, but a worker was created"),
        }

        let mut persistent = SingleThreadExecutionServiceConfig::default();
        persistent.state_dir = Some(std::path::PathBuf::from("/tmp/r167-should-not-open"));
        match spawn_supervised_nonce_only(&persistent) {
            Err(SupervisedInitError::UnsupportedPersistentState) => {}
            Err(e) => panic!("expected UnsupportedPersistentState, got a different error: {:?}", e),
            Ok(_) => panic!("expected UnsupportedPersistentState refusal, but a worker was created"),
        }
    }

    // ----------------------------------------------------------------------
    // R171: owner-abandonment characterization (memory-only NonceOnly worker)
    //
    // These two controls characterize the CURRENT behavior when the sole
    // supervising owner — the only holder of the worker `JoinHandle` — is
    // consumed (dropped with its original handle still inside) while a submit
    // view survives. The owner is dropped WHOLE: no handle is taken out first,
    // and no side reference to the shared admission gate or the task sender is
    // retained. The only capabilities kept alive are the sole submit view and an
    // independent clone of ONLY the readiness signal.
    //
    // After abandonment there is NO owner, hence NO observed join. Every
    // post-abandonment observation here is strictly `exit-readiness` (the
    // worker body returned, firing the drop-guard signal) and is NOT a
    // termination claim, a normal-versus-panic result, an execution-success
    // claim, a durability claim, or any reuse authorization. The pre-close
    // `Admitted` outcome in control 1 documents an UNQUALIFIED current behavior
    // of the unwired candidate and does NOT approve it as a shipping policy; a
    // future owner-disposal policy is a separate design decision.
    //
    // Cleanup bound / gate watchdog: the deterministic `RecvBoundaryGate` is a
    // pair of unbounded crossbeam rendezvous channels whose worker side waits
    // with `recv_timeout(FAILSAFE)` (10 s), and whose `await_visit` likewise
    // waits bounded. On the SUCCESS path each control explicitly drops the last
    // view (disconnecting the sole sender) and releases the held boundary visit,
    // so the detached worker proceeds into `recv()`, observes the disconnect,
    // and exits. On a FAILURE (panic) path, unwinding drops the local `view`
    // (sender disconnect) and the local gate handle, and the worker's
    // `recv_timeout(FAILSAFE)` watchdog releases it within the bounded limit so
    // no detached worker is left blocked indefinitely. Abandonment keeps no
    // side gate/sender reference, so the sole sender's lifetime is governed only
    // by the surviving view (control 1) or was already removed at close
    // (control 2).

    /// R171 control 1 — abandoned BEFORE close: a surviving submit view can still
    /// admit one inert item after the intact owner (handle inside) is dropped,
    /// prior to any close or admission. The worker handles the item through to a
    /// distinct second receive-boundary entry under the controlled schedule;
    /// dropping the last view then disconnects the sole sender and the detached
    /// worker reaches bounded exit-readiness, observed only through the
    /// independent cloned signal. No join, no termination/durability/reuse claim.
    #[cfg(test)]
    #[test]
    fn owner_dropped_before_close_surviving_view_still_admits() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (owner, view) =
            spawn_supervised_nonce_only_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        gate.await_visit(); // the real worker reached the first receive boundary (held)

        // Keep the sole submit view and an INDEPENDENT clone of ONLY the readiness
        // signal. Then consume the intact owner WHOLE — its original join handle
        // still inside — before any close or admission. No side reference to the
        // shared admission gate or the task sender is retained.
        let ready_clone = Arc::clone(&owner.ready);
        assert!(owner.handle.is_some(), "the owner is abandoned with its sole handle still attached");
        drop(owner); // detaches the worker handle; the view still holds the gate + sole sender

        // The surviving view still admits one inert item (CURRENT, unqualified
        // behavior of the unwired candidate — not a shipping-policy approval).
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::Admitted,
            "a surviving view admits one inert item after the intact owner is dropped before close"
        );

        gate.release_one(); // worker receives and handles the one inert item on the real path

        // DISTINCT second receive-boundary entry: the worker returned to the
        // boundary after handling the item (handled-to-loop-boundary only — no
        // success/persistence/eligibility is claimed from it).
        gate.await_visit();

        // Drop the last view → the sole sender disconnects; release the held 2nd
        // visit → the detached worker proceeds into recv(), sees the disconnect,
        // and exits. Observe bounded exit-readiness via the independent cloned
        // signal ONLY — there is no owner and therefore no observed join.
        drop(view);
        gate.release_one();
        assert!(
            ready_clone.wait(FAILSAFE),
            "bounded exit-readiness via the independent cloned signal (no observed join)"
        );
    }

    /// R171 control 2 — abandoned AFTER an accepted idle close: the qualified
    /// close on a never-admitted worker removes the sole sender; dropping the
    /// owner (handle inside) before any join leaves the surviving view refusing
    /// submission with `ShuttingDown`. Sender removal already happened at close.
    /// Releasing the worker reaches bounded exit-readiness, observed only through
    /// the independent cloned signal. No join, no termination/durability/reuse claim.
    #[cfg(test)]
    #[test]
    fn owner_dropped_after_accepted_close_surviving_view_refuses() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (owner, view) =
            spawn_supervised_nonce_only_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        gate.await_visit(); // the real worker reached the first receive boundary (held)

        // Accept the qualified close on this never-admitted worker. The close
        // removes the sole sender under the gate lock.
        assert_eq!(owner.try_close_idle(), Ok(()), "never-admitted worker is eligible for the idle close");
        assert!(!owner.sender_present(), "sender removal already happened at close");

        // Keep the submit view and an INDEPENDENT clone of ONLY the readiness
        // signal; consume the intact owner WHOLE (handle inside) BEFORE joining.
        // No side reference to the gate or the (already-removed) sender is kept.
        let ready_clone = Arc::clone(&owner.ready);
        assert!(owner.handle.is_some(), "the owner is abandoned with its sole handle still attached");
        drop(owner); // abandon before any join → no observed join is possible

        // The surviving view refuses submission: the sole sender was removed at close.
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::ShuttingDown,
            "the surviving view refuses submission after an accepted idle close"
        );

        // Drop the last view and release the held worker; the sender was already
        // gone at close, so recv() sees the disconnect and the worker exits.
        // Observe bounded exit-readiness via the independent cloned signal ONLY.
        drop(view);
        gate.release_one();
        assert!(
            ready_clone.wait(FAILSAFE),
            "bounded exit-readiness via the independent cloned signal (no observed join)"
        );
    }

    // ----------------------------------------------------------------------
    // R172: guarded worker panic with the owner RETAINED (memory-only NonceOnly)
    // ----------------------------------------------------------------------

    /// R172 control 8 — a guarded abnormal worker exit observed through the RETAINED
    /// owner's actual join. A never-admitted real `NonceOnly` worker (no admission, no
    /// close request) is driven to its first real receive boundary; an explicit,
    /// per-worker, test-only fault command makes it panic **inside the guarded worker
    /// body** — after the `FireOnDrop` readiness guard is installed — so the unwind fires
    /// readiness and the SAME owner obtains authoritative `Terminated(Panic)` from the
    /// real `JoinHandle::join` (a repeat join reports `AlreadyJoined`). After the join the
    /// sole sender is STILL present and no admission was ever recorded, yet a submit
    /// returns `ShuttingDown` because the receiver was lost to the unwind — the identical
    /// outcome to an accepted idle close arising from a DIFFERENT internal state.
    ///
    /// Characterization only: beyond the single observed join this claims no
    /// normal-versus-panic distribution, settlement, durability, reuse, or owner-disposal
    /// / fault policy. The fault is a per-worker arm consumed with a deterministic ack and
    /// a unique panic marker (identifiable in stderr); it holds no shared admission or
    /// readiness lock and installs no global panic hook. Success is asserted on the owner,
    /// never via an outer `#[should_panic]`. The bounded readiness wait is a diagnostic
    /// window and does NOT bound Rust's actual join.
    #[cfg(test)]
    #[test]
    fn guarded_worker_panic_owner_retained_join_observes_panic() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, view) =
            spawn_supervised_nonce_only_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        // Live owner + view, zero admissions, no close request.
        assert!(!owner.is_admitted(), "no admission before the fault");
        assert!(owner.sender_present(), "the sole sender is present before the fault");

        gate.await_visit(); // the real worker reached the first receive boundary (held)

        // Arm this worker's one-shot fault BEFORE releasing, then release the held visit.
        // The worker consumes the command (deterministic ack) and panics inside the
        // guarded body — after the readiness guard, holding no admission/readiness lock.
        gate.arm_fault();
        gate.release_one();
        gate.await_fault_ack(); // deterministic proof the expected fault command was consumed

        // Bounded readiness while the SAME owner still holds the handle (a diagnostic
        // window — it does NOT bound Rust's actual join).
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert!(owner.handle.is_some(), "the retained owner still holds its sole handle");

        // Authoritative termination evidence from the ACTUAL join: Panic. The repeat join
        // cannot obtain the (already consumed) handle.
        assert_eq!(
            owner.join(),
            JoinOutcome::Terminated(TermEvidence::Panic),
            "the retained owner's real join observes the guarded worker panic"
        );
        assert_eq!(owner.join(), JoinOutcome::AlreadyJoined, "a second join cannot be obtained");

        // After join, before cleanup: the sole sender is STILL present and no admission
        // was ever recorded — yet a submit returns ShuttingDown because the receiver was
        // lost when the worker unwound. Same outcome as an idle close, DIFFERENT state.
        assert!(owner.sender_present(), "the sole sender remains present after the panic join");
        assert!(!owner.is_admitted(), "no admission was recorded");
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::ShuttingDown,
            "submit maps the now-disconnected receiver to ShuttingDown with the sender still present"
        );
        // The disconnected-receiver refusal leaves the gate state unchanged.
        assert!(owner.sender_present(), "sender still present after the refused submit");
        assert!(!owner.is_admitted(), "still no admission after the refused submit");

        // Explicit fixture cleanup (success path): drop the last view and the gate; the
        // worker already terminated via the observed panic. On a failure path the gate's
        // recv_timeout(FAILSAFE) watchdog plus the unwinding sender-drop bound cleanup.
        drop(view);
        drop(gate);
    }

    // ----------------------------------------------------------------------
    // R177: Option A — distinct controller + surviving supervisor (test-only)
    //
    // Models an explicit, supported *controller withdrawal* while a single
    // supervisor survives. The supervisor holds the ACTUAL SupervisedNonceOwner
    // (the shared gate, the sole JoinHandle, and the disposition). The controller
    // is a distinct, non-clonable capability bound to its paired worker; its only
    // power is to request a withdrawal, which commits the never-admitted fence
    // through the supervisor's real `try_close_idle`. A successful withdrawal
    // CONSUMES (retires) the controller ONLY after the fence commits; a refused
    // withdrawal returns the controller unconsumed and publishes no success. These
    // are deterministic serial schedules, not concurrent-contention evidence. The
    // never-admitted cutoff here removes the sole sender; a general admission-state
    // fence independent of sender removal is a separate design. Final-supervisor
    // loss, poison/blocked-gate handling, and any disposition record that outlives
    // the supervisor are OUT OF SCOPE (R176 §2/§5). No non-test byte is changed.
    // ----------------------------------------------------------------------

    #[cfg(test)]
    static R177_WORKER_SEQ: AtomicU64 = AtomicU64::new(1);

    /// A distinct, non-clonable controller capability bound to one worker. It is not
    /// `Clone`/`Copy`, so it is move-only: a successful withdrawal consumes it.
    #[cfg(test)]
    struct TestController {
        worker_id: u64,
    }

    /// Outcome of an explicit controller withdrawal. `Refused` carries the controller
    /// back, so the capability is preserved (unconsumed) on refusal.
    #[cfg(test)]
    enum WithdrawOutcome {
        Retired,
        Refused(TestController),
    }

    /// The surviving supervisor: sole holder of the real owner (gate + sole JoinHandle +
    /// disposition), plus a test-local record of the withdrawal disposition. It outlives
    /// controller withdrawal and is the only party that observes readiness and performs
    /// the consume-once join.
    #[cfg(test)]
    struct TestSupervisor {
        owner: SupervisedNonceOwner,
        worker_id: u64,
        controller_retired: bool,
    }
    #[cfg(test)]
    impl TestSupervisor {
        /// Execute an explicit withdrawal requested by `controller` (which must be the one
        /// bound to this supervisor's worker). The never-admitted cutoff is the real
        /// `try_close_idle`: on `Ok` the fence has committed (sole sender removed under the
        /// enqueue lock) and the controller is retired (consumed by move + state flag); on
        /// `Err(Admitted)` the restricted withdrawal is refused, the controller is returned
        /// unconsumed, and no success is published. A refusal leaves state unchanged.
        fn withdraw(&mut self, controller: TestController) -> WithdrawOutcome {
            assert_eq!(
                controller.worker_id, self.worker_id,
                "the controller must be bound to its paired worker"
            );
            match self.owner.try_close_idle() {
                Ok(()) => {
                    self.controller_retired = true; // directly-checked retirement state
                    // `controller` is dropped here → retired ONLY after the fence committed
                    WithdrawOutcome::Retired
                }
                Err(CloseRefused::Admitted) => WithdrawOutcome::Refused(controller),
            }
        }
        fn controller_retired(&self) -> bool {
            self.controller_retired
        }
        fn sender_present(&self) -> bool {
            self.owner.sender_present()
        }
        fn is_admitted(&self) -> bool {
            self.owner.is_admitted()
        }
        fn handle_present(&self) -> bool {
            self.owner.handle.is_some()
        }
        fn observe_ready(&self, deadline: Duration) -> Readiness {
            self.owner.observe_ready(deadline)
        }
        fn join(&mut self) -> JoinOutcome {
            self.owner.join()
        }
        fn teardown_remove_sender(&self) {
            self.owner.teardown_remove_sender();
        }
    }

    /// Spawn the real memory-only NonceOnly worker and split the result into a surviving
    /// supervisor, a distinct bound controller, and the submit view.
    #[cfg(test)]
    fn spawn_controller_supervisor_with_gate(
        config: &SingleThreadExecutionServiceConfig,
        gate: Arc<RecvBoundaryGate>,
    ) -> Result<(TestSupervisor, TestController, SupervisedSubmitView), SupervisedInitError> {
        let (owner, view) = spawn_supervised_nonce_only_with_gate(config, gate)?;
        let worker_id = R177_WORKER_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let supervisor = TestSupervisor { owner, worker_id, controller_retired: false };
        let controller = TestController { worker_id };
        Ok((supervisor, controller, view))
    }

    /// R177 control 9 — WITHDRAWAL-FIRST. On a never-admitted real worker the controller
    /// withdraws under the actual enqueue cutoff; the controller retires ONLY after the
    /// fence commits; a pre-existing view then refuses; and the SAME supervisor still holds
    /// the sole handle and separately observes the actual normal join. Withdrawal and
    /// joined termination are reported as DISTINCT observations.
    #[cfg(test)]
    #[test]
    fn controller_withdrawal_first_supervisor_retains_handle_and_joins() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut supervisor, controller, view) =
            spawn_controller_supervisor_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        gate.await_visit(); // real worker held at the first receive boundary; no lifetime admission
        assert!(!supervisor.is_admitted(), "never-admitted precondition");
        assert!(supervisor.sender_present(), "sender present before withdrawal");

        // Explicit withdrawal under the actual cutoff; success retires the controller
        // (consumed by move) ONLY after the fence commits.
        match supervisor.withdraw(controller) {
            WithdrawOutcome::Retired => {}
            WithdrawOutcome::Refused(_) => panic!("a never-admitted withdrawal must commit the fence"),
        }

        // Fence committed: sender removed; controller retired; a pre-existing view refuses;
        // the SAME supervisor still holds the original sole handle.
        assert!(!supervisor.sender_present(), "the withdrawal cutoff removed the sole sender");
        assert!(supervisor.controller_retired(), "the controller retired after the fence committed");
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::ShuttingDown,
            "a pre-existing view refuses after the withdrawal cutoff"
        );
        assert!(supervisor.handle_present(), "the surviving supervisor retains the sole join handle");

        // Distinct observation: release the held worker, observe bounded readiness, then
        // obtain the actual normal join through the SAME supervisor.
        gate.release_one();
        assert_eq!(supervisor.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(
            supervisor.join(),
            JoinOutcome::Terminated(TermEvidence::Normal),
            "the surviving supervisor obtains the actual normal join after withdrawal"
        );
        assert_eq!(supervisor.join(), JoinOutcome::AlreadyJoined, "a second join cannot be obtained");
    }

    /// R177 control 10 — SUBMIT-FIRST. One real admission precedes the withdrawal attempt.
    /// The authoritative inert body is retained UPSTREAM (the real `submit` consumes its
    /// own body and returns only an outcome — R176 Correction A), so the custodian still
    /// holds an authoritative body afterward. The restricted withdrawal is then refused
    /// (`Err(Admitted)` via the controller), and the controller, the sender, the original
    /// handle, and the sticky prior-admission state all remain intact. A separate, bounded
    /// teardown performs the actual join on the retained handle. This establishes a refusal
    /// of restricted withdrawal only; it asserts no admitted-work settlement or start/drain.
    #[cfg(test)]
    #[test]
    fn controller_submit_first_withdrawal_refused_controller_and_handle_intact() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut supervisor, controller, view) =
            spawn_controller_supervisor_with_gate(&nonce_config(), Arc::clone(&gate)).expect("spawn");

        // R79: the custodian retains its OWN authoritative inert body, independent of the
        // body handed to `submit` (which consumes it and returns only an outcome).
        let authoritative_body = QbindBlock::empty(make_proposal(7));

        gate.await_visit(); // first boundary visit, before any item
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(7))),
            SubmitOutcome::Admitted,
            "one real successful admission on the actual worker path"
        );
        gate.release_one(); // worker receives and handles the one inert item
        gate.await_visit(); // distinct second visit (handled-to-loop-boundary)

        // The restricted withdrawal is refused by the sticky prior admission; the controller
        // is returned unconsumed and no success is published.
        let controller = match supervisor.withdraw(controller) {
            WithdrawOutcome::Refused(c) => c,
            WithdrawOutcome::Retired => panic!("a prior admission must refuse the restricted withdrawal"),
        };
        assert!(!supervisor.controller_retired(), "a refused withdrawal does not retire the controller");
        assert!(supervisor.sender_present(), "a refused withdrawal leaves the sole sender intact");
        assert!(supervisor.is_admitted(), "sticky prior-admission state remains true");
        assert!(supervisor.handle_present(), "the supervisor retains the sole join handle");
        // The upstream custodian still holds its authoritative body (submit returned none).
        assert_eq!(authoritative_body.height(), 7, "the custodian retains its own authoritative body");

        // The returned controller is still usable: a second attempt is still refused.
        let _controller = match supervisor.withdraw(controller) {
            WithdrawOutcome::Refused(c) => c,
            WithdrawOutcome::Retired => panic!("still admitted: the withdrawal stays refused"),
        };

        // Separate, bounded teardown on the retained handle: remove the sender, release the
        // held visit, observe readiness, then the actual join.
        supervisor.teardown_remove_sender();
        gate.release_one();
        assert_eq!(supervisor.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(supervisor.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    // ----------------------------------------------------------------------
    // R180: real submit-versus-withdrawal contention witness on the shared gate
    // (test-only). Opt-in, per-thread fixture instrumentation at the ACTUAL lock
    // sites of SupervisedSubmitView::submit and SupervisedNonceOwner::try_close_idle:
    //   * the HOLDER thread installs CONTENTION_HOLD; just after it acquires the real
    //     gate guard (before enqueue/cutoff) `contention_hold_after_lock` announces the
    //     guard is held and parks (bounded) until released, so the guard stays held
    //     across the competing operation's entry.
    //   * the PROBER thread installs CONTENTION_PROBE; at the competing operation's real
    //     method entry `contention_probe_entry` does a scoped `try_lock` on the SAME gate
    //     and reports whether it WouldBlock — a diagnostic overlap/contention witness.
    // Both hooks are no-ops unless their thread-local is installed, so the ten prior
    // controls and every production statement are unaffected. The probe shows overlap and
    // contention on the gate; it does NOT prove the ordinary blocking call was already
    // parked. After release, both calls run their existing lock and result paths.
    // ----------------------------------------------------------------------

    #[cfg(test)]
    struct ContentionHold {
        held_tx: crossbeam_channel::Sender<()>,
        release_rx: crossbeam_channel::Receiver<()>,
    }
    #[cfg(test)]
    struct ContentionProbe {
        wouldblock_tx: crossbeam_channel::Sender<bool>,
    }
    #[cfg(test)]
    thread_local! {
        static CONTENTION_HOLD: std::cell::RefCell<Option<Arc<ContentionHold>>> =
            const { std::cell::RefCell::new(None) };
        static CONTENTION_PROBE: std::cell::RefCell<Option<Arc<ContentionProbe>>> =
            const { std::cell::RefCell::new(None) };
    }
    #[cfg(test)]
    fn install_contention_hold(h: Arc<ContentionHold>) {
        CONTENTION_HOLD.with(|c| *c.borrow_mut() = Some(h));
    }
    #[cfg(test)]
    fn install_contention_probe(p: Arc<ContentionProbe>) {
        CONTENTION_PROBE.with(|c| *c.borrow_mut() = Some(p));
    }

    /// Called at the REAL entry of `submit` / `try_close_idle` (test builds only). If
    /// this thread is a prober, do a scoped `try_lock` on the SAME gate and report
    /// whether it WouldBlock. No-op otherwise. Diagnostic only.
    #[cfg(test)]
    fn contention_probe_entry(gate: &SupervisedGate) {
        let probe = CONTENTION_PROBE.with(|c| c.borrow().clone());
        if let Some(probe) = probe {
            let wouldblock =
                matches!(gate.inner.try_lock(), Err(std::sync::TryLockError::WouldBlock));
            let _ = probe.wouldblock_tx.send(wouldblock);
        }
    }

    /// Called just after `submit` / `try_close_idle` acquire the real gate guard (test
    /// builds only). If this thread is the holder, announce the guard is held and park
    /// (bounded by FAILSAFE) until released, keeping the guard held. No-op otherwise.
    #[cfg(test)]
    fn contention_hold_after_lock() {
        let hold = CONTENTION_HOLD.with(|c| c.borrow().clone());
        if let Some(hold) = hold {
            let _ = hold.held_tx.send(());
            let _ = hold.release_rx.recv_timeout(FAILSAFE);
        }
    }

    /// Spawn the real memory-only NonceOnly worker (no receive-boundary gate) and split
    /// into a surviving supervisor, a distinct bound controller, and the submit view.
    #[cfg(test)]
    fn spawn_controller_supervisor(
        config: &SingleThreadExecutionServiceConfig,
    ) -> Result<(TestSupervisor, TestController, SupervisedSubmitView), SupervisedInitError> {
        let (owner, view) = spawn_supervised_nonce_only(config)?;
        let worker_id = R177_WORKER_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let supervisor = TestSupervisor { owner, worker_id, controller_retired: false };
        let controller = TestController { worker_id };
        Ok((supervisor, controller, view))
    }

    /// R180 control 11 — a DIRECT witness of real submit-versus-withdrawal contention on
    /// the shared admission gate, covering BOTH winner orders. In each order the first
    /// operation parks holding the actual gate guard (before enqueue/cutoff) while the
    /// competing real operation, at its own method entry, finds the SAME gate `try_lock`
    /// → WouldBlock; both then run their ordinary lock/result paths after release.
    #[cfg(test)]
    #[test]
    fn real_gate_contention_both_winner_orders() {
        // ---- Withdrawal wins: withdrawal holds the gate; a competing submit probes ----
        {
            let (mut supervisor, controller, view) =
                spawn_controller_supervisor(&nonce_config()).expect("spawn");
            let (held_tx, held_rx) = crossbeam_channel::unbounded::<()>();
            let (release_tx, release_rx) = crossbeam_channel::unbounded::<()>();
            let (wb_tx, wb_rx) = crossbeam_channel::unbounded::<bool>();
            let hold = Arc::new(ContentionHold { held_tx, release_rx });
            let probe = Arc::new(ContentionProbe { wouldblock_tx: wb_tx });

            // Holder thread: withdrawal via the R177 supervisor; holds the real gate guard
            // inside try_close_idle (before the cutoff) until released.
            let holder = std::thread::spawn(move || {
                install_contention_hold(hold);
                let outcome = supervisor.withdraw(controller);
                (supervisor, outcome)
            });
            held_rx
                .recv_timeout(FAILSAFE)
                .expect("withdrawal acquired and holds the gate guard");

            // Prober thread: the competing real submit; its entry try_locks the SAME gate
            // (WouldBlock witnessed), then runs its ordinary blocking lock path.
            let prober = std::thread::spawn(move || {
                install_contention_probe(probe);
                view.submit(QbindBlock::empty(make_proposal(1)))
            });
            assert!(
                wb_rx.recv_timeout(FAILSAFE).expect("submit probe reported"),
                "the competing submit encounters the SAME gate held (try_lock WouldBlock)"
            );

            // Release the holder; both calls now run their existing lock/result paths.
            let _ = release_tx.send(());
            let (mut supervisor, outcome) = holder.join().expect("holder joins");
            let submit_outcome = prober.join().expect("prober joins");

            match outcome {
                WithdrawOutcome::Retired => {}
                WithdrawOutcome::Refused(_) => panic!("never-admitted withdrawal must retire"),
            }
            assert!(!supervisor.sender_present(), "the cutoff removed the sole sender before retirement");
            assert!(supervisor.controller_retired(), "the controller retired after the committed cutoff");
            assert!(!supervisor.is_admitted(), "sticky admission stays false");
            assert!(supervisor.handle_present(), "the same supervisor retains the original handle");
            assert_eq!(
                submit_outcome,
                SubmitOutcome::ShuttingDown,
                "the competing submit is refused after the withdrawal cutoff"
            );
            // Bounded readiness, then the actual normal join, separately.
            assert_eq!(supervisor.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(supervisor.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        }

        // ---- Submit wins: submit holds the gate; a competing withdrawal probes ----
        {
            let (mut supervisor, controller, view) =
                spawn_controller_supervisor(&nonce_config()).expect("spawn");
            // R79: retain an authoritative inert body upstream, independent of the body
            // handed to the real enqueue (submit consumes its own body).
            let authoritative_body = QbindBlock::empty(make_proposal(7));
            let (held_tx, held_rx) = crossbeam_channel::unbounded::<()>();
            let (release_tx, release_rx) = crossbeam_channel::unbounded::<()>();
            let (wb_tx, wb_rx) = crossbeam_channel::unbounded::<bool>();
            let hold = Arc::new(ContentionHold { held_tx, release_rx });
            let probe = Arc::new(ContentionProbe { wouldblock_tx: wb_tx });

            // Holder thread: the real submit; holds the real gate guard inside submit
            // (before enqueue) until released.
            let holder = std::thread::spawn(move || {
                install_contention_hold(hold);
                view.submit(QbindBlock::empty(make_proposal(7)))
            });
            held_rx
                .recv_timeout(FAILSAFE)
                .expect("submit acquired and holds the gate guard");

            // Prober thread: the competing withdrawal; its entry try_locks the SAME gate
            // (WouldBlock witnessed), then runs its ordinary blocking lock path.
            let prober = std::thread::spawn(move || {
                install_contention_probe(probe);
                let outcome = supervisor.withdraw(controller);
                (supervisor, outcome)
            });
            assert!(
                wb_rx.recv_timeout(FAILSAFE).expect("withdrawal probe reported"),
                "the competing withdrawal encounters the SAME gate held (try_lock WouldBlock)"
            );

            let _ = release_tx.send(());
            let submit_outcome = holder.join().expect("holder joins");
            let (mut supervisor, outcome) = prober.join().expect("prober joins");

            assert_eq!(submit_outcome, SubmitOutcome::Admitted, "the holding submit admits the item");
            let returned_controller = match outcome {
                WithdrawOutcome::Refused(ctrl) => ctrl,
                WithdrawOutcome::Retired => panic!("a prior admission must refuse the withdrawal"),
            };
            assert!(!supervisor.controller_retired(), "a refused withdrawal does not retire the controller");
            assert!(supervisor.is_admitted(), "sticky prior-admission is recorded");
            assert!(supervisor.sender_present(), "the sole sender remains present after the refused withdrawal");
            assert!(supervisor.handle_present(), "the supervisor retains the original handle");
            assert_eq!(authoritative_body.height(), 7, "the custodian retains its own authoritative body");

            // Fixture cleanup (distinct from withdrawal policy): drop the returned
            // controller, remove the sender, then bounded readiness and the actual join.
            drop(returned_controller);
            supervisor.teardown_remove_sender();
            assert_eq!(supervisor.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(supervisor.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        }
    }

    // ----------------------------------------------------------------------
    // R184 — private, unwired restricted controller-withdrawal candidate
    // ----------------------------------------------------------------------
    //
    // Additive implementation of the R183 decision packet (option B). NON-TEST private
    // items: a move-only `WithdrawalController` bound to one worker by the gate
    // allocation's identity (a `Weak<SupervisedGate>` used for identity ONLY — never
    // upgraded), issued ONLY by a live spawn through ONE shared issuance core; a
    // `WithdrawalOutcome`; and `SupervisedNonceOwner::withdraw`, whose OWN short critical
    // section mirrors the enqueue serialization. The surviving supervisor is the existing
    // owner, which keeps the sole join handle (`withdraw` never moves or joins it).
    //
    // Precedence (matches R183): the wrong-worker identity check runs BEFORE any gate is
    // locked or changed; then, under the SAME mutex as enqueue, a poisoned acquisition,
    // sticky prior admission, and an already-absent sender are each a distinct,
    // NON-consuming outcome. ONLY a fresh, eligible present-sender removal commits a
    // withdrawal and consumes the token; `WrongWorker`, `PoisonedGate`, `Admitted`, and
    // `AlreadyFenced` each return the SAME token unconsumed.
    //
    // No existing item is modified; `try_close_idle`, `submit`, the gate types, and the
    // eleven integrated controls are byte-identical. Unwired: no production caller, no
    // public API, no trait/error change. OUT OF SCOPE (R183 §2.4): queued-start drain,
    // admitted-work settlement, external disposition record, final-supervisor loss,
    // lost-handle recovery, general submit-poison policy, durable quarantine, controller
    // reuse/transfer, persistence, activation.

    /// Opaque, non-clonable withdrawal capability bound to exactly one supervised worker.
    /// Move-only (NOT `Clone`/`Copy`): a committed withdrawal consumes it. Carries
    /// identity ONLY — a `Weak<SupervisedGate>` that is NEVER upgraded (no `upgrade()` is
    /// exposed or used), so it cannot extend the life of the gate value, the sole sender,
    /// or the worker. The constructor is private to this module and is reachable ONLY via
    /// `spawn_nonce_only_with_controller_core`; there is no `Default`/public constructor,
    /// no reissue, and no transfer. Identity is always issued from a LIVE, non-empty gate
    /// allocation, so the `Weak::new()` empty-pointer `ptr_eq` hazard cannot arise.
    struct WithdrawalController {
        gate_id: std::sync::Weak<SupervisedGate>, // identity only; never upgraded
    }

    /// Outcome of an explicit, identity-checked controller withdrawal. Every non-success
    /// variant RETURNS the controller (unconsumed); only `Withdrawn` consumes it. No
    /// `#[derive(Debug)]`: `WithdrawalController` is intentionally opaque/non-`Debug`, and
    /// callers/tests match the outcome rather than format it.
    enum WithdrawalOutcome {
        /// Never admitted AND the sole sender was present → removed under the enqueue lock
        /// (a fresh fence committed now). The controller is CONSUMED (retired).
        Withdrawn,
        /// The controller is not bound to this worker → refused BEFORE any lock; the SAME
        /// controller is returned, usable on its own worker.
        WrongWorker(WithdrawalController),
        /// A prior successful admission → restricted withdrawal refused; controller, sole
        /// sender, sticky admission, and sole handle all preserved; controller returned.
        Admitted(WithdrawalController),
        /// Never admitted, but the sole sender was ALREADY absent → an already-fenced
        /// request; NO fresh fence; controller returned (no false success).
        AlreadyFenced(WithdrawalController),
        /// The gate mutex was POISONED → acquisition FAILED; NO confirmed fence; controller
        /// returned with the cutoff UNCONFIRMED. The poisoned guard is NOT inspected here.
        PoisonedGate(WithdrawalController),
    }

    impl SupervisedNonceOwner {
        /// This worker's gate identity — a `Weak` downgraded from the live gate `Arc`.
        /// Used ONLY for `Weak::ptr_eq` identity comparison; never upgraded.
        fn gate_identity(&self) -> std::sync::Weak<SupervisedGate> {
            std::sync::Arc::downgrade(&self.gate)
        }

        /// Explicit, identity-checked restricted withdrawal requested by `controller`.
        /// MAY BLOCK on the gate mutex (an ordinary method, NOT a destructor); a short
        /// critical section gives NO acquisition time bound. It NEVER joins or moves the
        /// worker handle, and NEVER panics on a poisoned mutex. The identity check runs
        /// BEFORE any lock, so a wrong worker is refused with no gate locked or changed.
        /// ONLY an eligible, never-admitted, present-sender removal commits a fresh fence
        /// and consumes the token; wrong-worker, poisoned, prior-admission, and
        /// already-fenced each return the SAME token unconsumed.
        fn withdraw(&self, controller: WithdrawalController) -> WithdrawalOutcome {
            // (1) Identity FIRST — no lock taken, no state changed on mismatch.
            if !std::sync::Weak::ptr_eq(&controller.gate_id, &self.gate_identity()) {
                return WithdrawalOutcome::WrongWorker(controller);
            }
            // R187: opt-in contention probe — AFTER the worker-identity comparison and BEFORE
            // ordinary gate acquisition; a no-op unless a probe is installed on this thread, so
            // wrong-worker refusal (which touches no gate) and every production path are unaffected.
            #[cfg(test)]
            contention_probe_entry(&self.gate);
            // (2) Same serialization boundary as enqueue. Poison is a typed, non-panicking
            //     UNCONFIRMED outcome; the poisoned guard is deliberately NOT inspected.
            let mut inner = match self.gate.inner.lock() {
                Ok(guard) => guard,
                Err(_poisoned) => return WithdrawalOutcome::PoisonedGate(controller),
            };
            // R187: opt-in holder hook — AFTER the real clean guard is obtained and BEFORE reading
            // prior admission or sender state; a no-op unless a hold is installed on this thread.
            #[cfg(test)]
            contention_hold_after_lock();
            if inner.admitted {
                return WithdrawalOutcome::Admitted(controller); // sticky; state unchanged
            }
            if inner.sender.is_none() {
                return WithdrawalOutcome::AlreadyFenced(controller); // already fenced; no false success
            }
            inner.sender = None; // the fresh, eligible never-admitted fence commits here
            drop(inner);
            // `controller` is dropped here → CONSUMED only AFTER the fence committed.
            WithdrawalOutcome::Withdrawn
        }
    }

    /// Shared issuance core (prelude-aware): spawn the real memory-only `NonceOnly` worker
    /// and issue its single bound controller through ONE code path, so the normal entry
    /// and the test-gated wrapper cannot diverge (no second token constructor). The
    /// controller's identity is downgraded from the SAME live gate `Arc` the owner holds,
    /// so it is non-empty and worker-exact.
    fn spawn_nonce_only_with_controller_core<F>(
        config: &SingleThreadExecutionServiceConfig,
        worker_prelude: F,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView, WithdrawalController), SupervisedInitError>
    where
        F: FnOnce() + Send + 'static,
    {
        let (owner, view) = spawn_core(config, worker_prelude)?;
        let controller = WithdrawalController { gate_id: std::sync::Arc::downgrade(&owner.gate) };
        Ok((owner, view, controller))
    }

    /// Normal, ungated private entry (memory-only `NonceOnly`). Unwired; no caller.
    /// Supplies a no-op worker prelude and issues the controller through the shared core.
    fn spawn_supervised_nonce_only_with_controller(
        config: &SingleThreadExecutionServiceConfig,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView, WithdrawalController), SupervisedInitError> {
        spawn_nonce_only_with_controller_core(config, || {})
    }

    /// Test-only wrapper that installs the deterministic receive-boundary gate as the
    /// worker prelude and issues the controller through the SAME shared core — NOT a
    /// separate token constructor.
    #[cfg(test)]
    fn spawn_supervised_nonce_only_with_controller_gated(
        config: &SingleThreadExecutionServiceConfig,
        gate: Arc<RecvBoundaryGate>,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView, WithdrawalController), SupervisedInitError> {
        spawn_nonce_only_with_controller_core(config, move || install_recv_gate(gate))
    }

    #[cfg(test)]
    impl WithdrawalController {
        /// Test-only identity check: is this controller bound to `owner`'s worker gate?
        /// Uses the same `Weak::ptr_eq` identity the production `withdraw` uses.
        fn is_bound_to(&self, owner: &SupervisedNonceOwner) -> bool {
            std::sync::Weak::ptr_eq(&self.gate_id, &owner.gate_identity())
        }
    }

    // ----------------------------------------------------------------------
    // R184 acceptance controls AC-1..AC-6 (exercise the REAL new private entry).
    // Deterministic rendezvous via the existing `RecvBoundaryGate`; no sleeps/time
    // bounds as a witness. AC-1/AC-3/AC-6 exercise the NORMAL UNGATED entry.
    // (The R182 `real_gate_contention_both_winner_orders` witness overlaps the OLD close
    // path; it supplies NO direct overlap observation for this new `withdraw` method —
    // AC-1..AC-6 are deterministic SERIAL schedules.)
    // ----------------------------------------------------------------------

    /// AC-1 — WRONG-WORKER refusal, BOTH directions, refused BEFORE any gate change; each
    /// returned token then succeeds on its OWN worker; both workers untouched by the
    /// mismatched calls. Exercises the normal ungated entry; cleans up via proper closes
    /// (the successful withdrawals) and joined observations.
    #[cfg(test)]
    #[test]
    fn ac1_wrong_worker_refused_token_returned_and_usable() {
        // Normal ungated entry: each real worker parks on its empty receive queue (never
        // admitted), so no receive-boundary gate is needed.
        let (mut o1, _v1, c1) =
            spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn w1");
        let (mut o2, _v2, c2) =
            spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn w2");

        // Both wrong-worker directions: refused with NO gate locked or changed; token back.
        let c2 = match o1.withdraw(c2) {
            WithdrawalOutcome::WrongWorker(c) => c,
            _ => panic!("c2 is not bound to w1 → must be WrongWorker"),
        };
        let c1 = match o2.withdraw(c1) {
            WithdrawalOutcome::WrongWorker(c) => c,
            _ => panic!("c1 is not bound to w2 → must be WrongWorker"),
        };
        // Both workers untouched by the mismatched calls.
        assert!(o1.sender_present() && !o1.is_admitted() && o1.handle.is_some());
        assert!(o2.sender_present() && !o2.is_admitted() && o2.handle.is_some());
        // Returned tokens still carry their own workers' identity...
        assert!(c1.is_bound_to(&o1) && c2.is_bound_to(&o2));
        // ...and succeed there: a fresh eligible removal commits and consumes the token.
        match o1.withdraw(c1) {
            WithdrawalOutcome::Withdrawn => {}
            _ => panic!("c1 on its own worker w1 must withdraw"),
        }
        match o2.withdraw(c2) {
            WithdrawalOutcome::Withdrawn => {}
            _ => panic!("c2 on its own worker w2 must withdraw"),
        }
        // Proper closes committed (both senders removed) → joined observations, separately.
        assert!(!o1.sender_present() && !o2.sender_present());
        assert_eq!(o1.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(o1.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        assert_eq!(o2.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(o2.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// AC-2 — explicit WITHDRAWAL WINS on a never-admitted worker (fresh eligible removal,
    /// token consumed); a pre-existing view then refuses through the real submit path; the
    /// supervisor retains the sole handle and separately observes the actual normal join.
    #[cfg(test)]
    #[test]
    fn ac2_withdrawal_wins_then_submit_refused_and_joins() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, view, controller) =
            spawn_supervised_nonce_only_with_controller_gated(&nonce_config(), Arc::clone(&gate))
                .expect("spawn");
        gate.await_visit(); // real worker held at the first receive boundary; never admitted
        assert!(!owner.is_admitted() && owner.sender_present());

        match owner.withdraw(controller) {
            WithdrawalOutcome::Withdrawn => {} // token consumed only AFTER the fence committed
            _ => panic!("a never-admitted bound withdrawal must commit the fence"),
        }
        assert!(!owner.sender_present() && !owner.is_admitted() && owner.handle.is_some());
        // The pre-existing view now refuses through the real submit path.
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(1))),
            SubmitOutcome::ShuttingDown
        );
        // Release the held worker so it reaches the disconnected recv; then join, separately.
        gate.release_one();
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// AC-3 — PRIOR ADMISSION refuses the restricted withdrawal and preserves the
    /// controller, sole sender, sticky admission, and sole handle; R79 authoritative body
    /// retained upstream; scoped fixture cleanup is kept separate from withdrawal policy.
    /// Exercises the normal ungated entry.
    #[cfg(test)]
    #[test]
    fn ac3_prior_admission_refuses_and_preserves_controller() {
        let (mut owner, view, controller) =
            spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn");
        // R79: retain an authoritative inert body upstream, independent of the submitted
        // body (the real submit consumes its own body).
        let authoritative_body = QbindBlock::empty(make_proposal(7));
        assert_eq!(
            view.submit(QbindBlock::empty(make_proposal(7))),
            SubmitOutcome::Admitted
        );

        let returned = match owner.withdraw(controller) {
            WithdrawalOutcome::Admitted(c) => c, // refused; controller returned UNCONSUMED
            _ => panic!("a prior admission must refuse the restricted withdrawal"),
        };
        assert!(owner.is_admitted() && owner.sender_present() && owner.handle.is_some());
        assert!(returned.is_bound_to(&owner), "the refused controller is the same bound token");
        assert_eq!(authoritative_body.height(), 7, "the custodian retains its own authoritative body");

        // Scoped fixture cleanup (distinct from withdrawal policy).
        drop(returned);
        owner.teardown_remove_sender();
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// AC-4 — ALREADY-FENCED reported DISTINCTLY (never a false `Withdrawn`) when a token
    /// is presented AFTER an OLD owner-side close has removed the sole sender; the token is
    /// returned; the supervisor retains the sole handle and later observes the actual join.
    #[cfg(test)]
    #[test]
    fn ac4_already_fenced_after_old_close_is_distinct() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, _view, controller) =
            spawn_supervised_nonce_only_with_controller_gated(&nonce_config(), Arc::clone(&gate))
                .expect("spawn");
        gate.await_visit();
        assert!(!owner.is_admitted() && owner.sender_present());
        // The OLD owner-side close removes the sole sender (never admitted → Ok).
        assert!(owner.try_close_idle().is_ok());
        assert!(!owner.sender_present());
        // The NEW withdraw now reports already-fenced — NOT a fresh success.
        let returned = match owner.withdraw(controller) {
            WithdrawalOutcome::AlreadyFenced(c) => c,
            _ => panic!("an already-absent sender must report AlreadyFenced, not Withdrawn"),
        };
        assert!(returned.is_bound_to(&owner));
        assert!(!owner.sender_present() && !owner.is_admitted() && owner.handle.is_some());
        // Cleanup: release the held worker → disconnected recv → exit → join.
        drop(returned);
        gate.release_one();
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// AC-5 — a POISONED gate gives NO false success: `withdraw` returns `PoisonedGate`
    /// (unconfirmed cutoff) without inspecting the poisoned guard; the returned token keeps
    /// its worker identity, the original sole handle is intact, and the sender/admission
    /// state is unchanged. The poisoned guard is used via `PoisonError::into_inner` ONLY in
    /// test inspection/teardown, AFTER the outcome is obtained; production poison is not
    /// repaired. An intentional unwind message is emitted by the poisoning helper.
    #[cfg(test)]
    #[test]
    fn ac5_poisoned_gate_no_false_success_and_token_returned() {
        let gate = Arc::new(RecvBoundaryGate::new());
        let (mut owner, _view, controller) =
            spawn_supervised_nonce_only_with_controller_gated(&nonce_config(), Arc::clone(&gate))
                .expect("spawn");
        gate.await_visit(); // worker held at the boundary; never admitted; sender present

        // Intentionally poison the SAME gate mutex: a helper thread acquires the gate guard
        // and panics while holding it (std marks the mutex poisoned on unwind). Join it
        // (bounded: it panics immediately after locking) and expect the panic.
        let poison_gate = Arc::clone(&owner.gate);
        let poisoner = std::thread::spawn(move || {
            let _held = poison_gate.inner.lock().unwrap();
            panic!("R184-INTENTIONAL-GATE-POISON");
        });
        assert!(poisoner.join().is_err(), "the poisoning helper panicked while holding the gate");

        // Production withdraw: typed, non-panicking unconfirmed outcome; guard NOT inspected.
        let returned = match owner.withdraw(controller) {
            WithdrawalOutcome::PoisonedGate(c) => c,
            _ => panic!("a poisoned gate must yield PoisonedGate, never a false success"),
        };
        assert!(returned.is_bound_to(&owner), "the returned token keeps its worker identity");
        assert!(owner.handle.is_some(), "the supervisor retains the original sole handle");

        // Test-only inspection/teardown via `into_inner` ONLY now (after the outcome). This
        // does NOT repair production poison — it is fixture cleanup on a doomed worker.
        {
            let mut guard = match owner.gate.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            assert!(guard.sender.is_some(), "the unconfirmed cutoff left the sole sender present");
            assert!(!guard.admitted, "admission state is unchanged (never admitted)");
            guard.sender = None; // fixture teardown: remove the sender (guard released next)
        }
        drop(returned);
        gate.release_one(); // release the worker's receive-boundary gate → disconnected recv → exit
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// AC-6 — dropping the controller alone is INERT: the sole sender stays live, no fence
    /// commits, and there is no withdrawal/join evidence. A SEPARATE explicit owner-side
    /// close then removes the sender before the bounded readiness and the actual join.
    /// Exercises the normal ungated entry.
    #[cfg(test)]
    #[test]
    fn ac6_controller_drop_is_inert_then_explicit_close_joins() {
        let (mut owner, _view, controller) =
            spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn");
        // Dropping the controller commits no fence and yields no withdrawal/join evidence.
        drop(controller);
        assert!(owner.sender_present(), "controller drop leaves the sole sender live");
        assert!(!owner.is_admitted());
        assert!(owner.handle.is_some());
        // A SEPARATE explicit owner-side close removes the sender; then join, separately.
        assert!(owner.try_close_idle().is_ok());
        assert!(!owner.sender_present());
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// R187 — witness real same-gate contention between the NEW `SupervisedNonceOwner::withdraw`
    /// and the real `SupervisedSubmitView::submit`, in BOTH winner orders, through the real private
    /// constructor `spawn_supervised_nonce_only_with_controller` (no old test supervisor). In each
    /// order a holder thread parks holding the ACTUAL gate guard (via the opt-in R182 hold hook)
    /// while the competing operation, at its OWN method entry, finds the SAME gate
    /// `try_lock -> WouldBlock` (the opt-in probe hook). For `withdraw` the probe fires only AFTER
    /// the worker-identity check, so wrong-worker refusal (which touches no gate) is unaffected. The
    /// positive probe proves overlap/contention at that instant; it does NOT prove the competing
    /// ordinary blocking call had already parked, and asserts NO acquisition/join time bound.
    /// Deterministic channels + bounded (FAILSAFE) fixture waits; no sleeps as the witness.
    #[cfg(test)]
    #[test]
    fn withdraw_gate_contention_both_winner_orders() {
        // ---- Withdrawal wins: the NEW withdraw holds the gate; a competing submit probes ----
        {
            let (mut owner, view, controller) =
                spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn");
            let (held_tx, held_rx) = crossbeam_channel::unbounded::<()>();
            let (release_tx, release_rx) = crossbeam_channel::unbounded::<()>();
            let (wb_tx, wb_rx) = crossbeam_channel::unbounded::<bool>();
            let hold = Arc::new(ContentionHold { held_tx, release_rx });
            let probe = Arc::new(ContentionProbe { wouldblock_tx: wb_tx });

            // Holder thread: the NEW withdraw on a bound, never-admitted controller holds the real
            // gate guard inside withdraw (after the identity check, before the cutoff) until released.
            let holder = std::thread::spawn(move || {
                install_contention_hold(hold);
                let outcome = owner.withdraw(controller);
                (owner, outcome)
            });
            held_rx
                .recv_timeout(FAILSAFE)
                .expect("withdraw acquired and holds the gate guard");

            // Prober thread: the competing real submit; its entry try_locks the SAME gate
            // (WouldBlock witnessed), then runs its ordinary blocking lock path.
            let prober = std::thread::spawn(move || {
                install_contention_probe(probe);
                view.submit(QbindBlock::empty(make_proposal(1)))
            });
            assert!(
                wb_rx.recv_timeout(FAILSAFE).expect("submit probe reported"),
                "the competing submit encounters the SAME gate held (try_lock WouldBlock)"
            );

            // Release the holder; both calls now run their existing lock/result paths.
            let _ = release_tx.send(());
            let (mut owner, outcome) = holder.join().expect("holder joins");
            let submit_outcome = prober.join().expect("prober joins");

            match outcome {
                WithdrawalOutcome::Withdrawn => {}
                _ => panic!("a never-admitted bound withdrawal must commit the fence"),
            }
            assert!(!owner.sender_present(), "the cutoff removed the sole sender");
            assert!(!owner.is_admitted(), "sticky admission stays false");
            assert!(owner.handle.is_some(), "the owner retains the original sole handle");
            assert_eq!(
                submit_outcome,
                SubmitOutcome::ShuttingDown,
                "the competing submit is refused after the withdrawal cutoff"
            );
            // Bounded readiness, then the actual normal join, separately.
            assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        }

        // ---- Submit wins: the real submit holds the gate; a competing NEW withdraw probes ----
        {
            let (mut owner, view, controller) =
                spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn");
            // R79: retain an authoritative inert body upstream, independent of the body handed to
            // the real enqueue (submit consumes its own body).
            let authoritative_body = QbindBlock::empty(make_proposal(7));
            let (held_tx, held_rx) = crossbeam_channel::unbounded::<()>();
            let (release_tx, release_rx) = crossbeam_channel::unbounded::<()>();
            let (wb_tx, wb_rx) = crossbeam_channel::unbounded::<bool>();
            let hold = Arc::new(ContentionHold { held_tx, release_rx });
            let probe = Arc::new(ContentionProbe { wouldblock_tx: wb_tx });

            // Holder thread: the real submit holds the real gate guard inside submit (before
            // enqueue) until released.
            let holder = std::thread::spawn(move || {
                install_contention_hold(hold);
                view.submit(QbindBlock::empty(make_proposal(7)))
            });
            held_rx
                .recv_timeout(FAILSAFE)
                .expect("submit acquired and holds the gate guard");

            // Prober thread: the competing NEW withdraw; its entry (AFTER the identity check)
            // try_locks the SAME gate (WouldBlock witnessed), then runs its ordinary lock path.
            let prober = std::thread::spawn(move || {
                install_contention_probe(probe);
                let outcome = owner.withdraw(controller);
                (owner, outcome)
            });
            assert!(
                wb_rx.recv_timeout(FAILSAFE).expect("withdraw probe reported"),
                "the competing withdraw encounters the SAME gate held (try_lock WouldBlock)"
            );

            let _ = release_tx.send(());
            let submit_outcome = holder.join().expect("holder joins");
            let (mut owner, outcome) = prober.join().expect("prober joins");

            assert_eq!(submit_outcome, SubmitOutcome::Admitted, "the holding submit admits the item");
            let returned_controller = match outcome {
                WithdrawalOutcome::Admitted(c) => c,
                _ => panic!("a prior admission must refuse the withdrawal with Admitted(controller)"),
            };
            assert!(
                returned_controller.is_bound_to(&owner),
                "the refused withdrawal returns the original bound controller"
            );
            assert!(owner.is_admitted(), "sticky prior-admission is recorded");
            assert!(owner.sender_present(), "the sole sender remains present after the refused withdrawal");
            assert!(owner.handle.is_some(), "the owner retains the original sole handle");
            assert_eq!(authoritative_body.height(), 7, "the custodian retains its own authoritative body");

            // Fixture cleanup (distinct from the refusal): drop the returned controller, remove the
            // sender, then bounded readiness and the actual join.
            drop(returned_controller);
            owner.teardown_remove_sender();
            assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        }
    }

    // ----------------------------------------------------------------------
    // R194 — finish A1 state and body evidence for the C05 shutdown witness
    // ----------------------------------------------------------------------
    // Supersedes the (unpublished) R193 witness and completes its A1 evidence on three narrow points:
    //  1. ORDERED A1 SNAPSHOTS. A1 now requires an ordered (initial → final) pair of independent
    //     worker-state samples, keyed to the admitted occurrence: denial `(0,0) → (0,0)`, bypass
    //     `(0,0) → (7,1)`. A baseline-only trace is explicitly rejected (the ordered predicate needs a
    //     distinct post-decision sample), so loss of the post-denial sample fails the test. The
    //     independent executor-entry and executor-result checks are kept.
    //  2. COHERENT FIXTURE BODY. `state_changing_body` now builds a synthetic proposal whose
    //     `header.tx_count` and raw `txs` list AGREE with the ordered decoded execution input (one
    //     transaction, encoded with the same proposal-`txs` format the sim producer uses). The bound
    //     proposal/body is checked at the actual dequeue, and the fixture committed id stays DISTINCT
    //     from the block's self-derived `block_id`.
    //  3. REFUSED LATE SUBMIT AS ITS OWN OCCURRENCE. The fresh post-admission-cutoff submit is bound
    //     as a separate refused occurrence (own id + custodian): it submits a clone of its bound body,
    //     asserts `ShuttingDown`, records `RefusedSubmission`, verifies exact retained content, and
    //     asserts no second dequeue. This refused action is mirrored in BOTH A1 schedules (denial and
    //     bypass) so the two compared schedules have identical pre-decision actions.
    // The worker-loop call sites (unchanged from R193) are #[cfg(test)]; removing them and this block
    // reconstructs the base adapter byte-for-byte. No non-test projection, existing control, call path,
    // or workflow changes. OUT OF SCOPE: healthy drain, cancellation, retry/replay, durability, and any
    // settlement/retirement authority (a test observation retires nothing; custody is retained until a
    // separate authorized protocol). Final-supervisor loss stays UNQUALIFIED.

    #[cfg(test)]
    const R194_GRANTED_WORK_FAULT_MARKER: &str = "R194-INTENTIONAL-GRANTED-WORK-FAULT";
    #[cfg(test)]
    const R194_RENDEZVOUS_HARNESS_ERROR: &str = "R194-RENDEZVOUS-HARNESS-ERROR";
    #[cfg(test)]
    const R194_MISSING_GATE_HARNESS_ERROR: &str = "R194-MISSING-GATE-EVIDENCE-DURING-GRANT";
    /// A committed-id marker clearly DISTINCT from any `[height; 32]` self-derived block id used here.
    #[cfg(test)]
    const R194_COMMITTED_ID: [u8; 32] = [0xC0u8; 32];

    #[cfg(test)]
    static R194_OCCURRENCE_SEQ: AtomicU64 = AtomicU64::new(1);

    /// Per-worker, opt-in start-grant gate installed on the worker thread by the R194 fixture spawn
    /// ONLY. It holds a `Weak<SupervisedGate>` — NOT a strong `Arc` — so the parked worker never keeps
    /// the gate or its sole sender alive. The committed-cutoff read upgrades the weak reference
    /// transiently and releases the strong reference before any wait/executor/receive. All worker→test
    /// events carry the occurrence id. Waits are bounded by FAILSAFE; a broken rendezvous or missing
    /// gate evidence panics with a HARNESS marker (never a silent deny/grant/release).
    #[cfg(test)]
    struct StartGrantGate {
        occurrence_id: u64,
        probe_sender: [u8; 32],
        expected_body: QbindBlock,
        supervised: Mutex<Option<std::sync::Weak<SupervisedGate>>>,
        bypass_cutoff_enforcement: AtomicBool,
        fault_armed: AtomicBool,
        reached_tx: crossbeam_channel::Sender<u64>,
        dequeue_body_tx: crossbeam_channel::Sender<(u64, bool)>, // (occ, dequeued == bound body)
        grant_ack_tx: crossbeam_channel::Sender<u64>,
        denial_tx: crossbeam_channel::Sender<u64>,
        pre_effect_tx: crossbeam_channel::Sender<u64>,
        executor_entered_tx: crossbeam_channel::Sender<u64>,
        result_tx: crossbeam_channel::Sender<(u64, u64, u64, u64)>, // (occ, success, error, new_height)
        fault_witness_tx: crossbeam_channel::Sender<u64>,
        state_probe_tx: crossbeam_channel::Sender<(u64, u64, u64)>, // (occ, current_height, probe nonce)
        decision_release_rx: crossbeam_channel::Receiver<()>,
        pre_effect_release_rx: crossbeam_channel::Receiver<()>,
    }
    #[cfg(test)]
    impl StartGrantGate {
        fn set_supervised(&self, weak: std::sync::Weak<SupervisedGate>) {
            *self.supervised.lock().unwrap() = Some(weak);
        }
        /// Read committed cutoff on the REAL gate under the SAME lock as enqueue/removal, via a
        /// TRANSIENT weak upgrade whose strong reference is dropped before this returns. Missing gate
        /// evidence during a grant attempt fails the fixture explicitly.
        fn cutoff_committed(&self) -> bool {
            let weak = self
                .supervised
                .lock()
                .unwrap()
                .clone()
                .expect("R194: the weak supervised gate is installed before the grant decision");
            match weak.upgrade() {
                Some(strong) => {
                    let committed = strong.inner.lock().unwrap().sender.is_none();
                    drop(strong); // release the transient strong reference before any wait/executor
                    committed
                }
                None => panic!("{}", R194_MISSING_GATE_HARNESS_ERROR),
            }
        }
    }
    #[cfg(test)]
    thread_local! {
        static START_GRANT_GATE: std::cell::RefCell<Option<Arc<StartGrantGate>>> =
            const { std::cell::RefCell::new(None) };
    }
    #[cfg(test)]
    fn install_start_grant_gate(gate: Arc<StartGrantGate>) {
        START_GRANT_GATE.with(|g| *g.borrow_mut() = Some(gate));
    }
    #[cfg(test)]
    fn current_start_grant_gate() -> Option<Arc<StartGrantGate>> {
        START_GRANT_GATE.with(|g| g.borrow().clone())
    }

    /// Top-of-loop INDEPENDENT state probe (test builds only): reports the REAL worker's current
    /// height and the exercised sender's actual nonce, sampled from the live `state`, independently of
    /// the executor-result hook. No-op unless a gate is installed.
    #[cfg(test)]
    pub(super) fn idle_state_probe_test_hook(current_height: u64, state: &super::InMemoryState) {
        if let Some(gate) = current_start_grant_gate() {
            let nonce = qbind_ledger::get_account_nonce(state, &gate.probe_sender);
            let _ = gate.state_probe_tx.send((gate.occurrence_id, current_height, nonce));
        }
    }

    /// Called from the real worker BETWEEN the dequeue and the first execution effect (test builds
    /// only). Receives the ACTUAL dequeued block and validates it (proposal + ordered decoded txs)
    /// against the bound authoritative body, occurrence-keyed. Then reads committed cutoff on the real
    /// gate (transient weak upgrade) and either issues an occurrence-keyed denial or grants. Returns
    /// true → proceed; false → the worker skips the executor + height update. No gate → true (legacy).
    /// A broken rendezvous panics (HARNESS).
    #[cfg(test)]
    pub(super) fn start_grant_test_hook(dequeued: &QbindBlock) -> bool {
        let gate = match current_start_grant_gate() {
            Some(g) => g,
            None => return true,
        };
        let occ = gate.occurrence_id;
        let _ = gate.reached_tx.send(occ);
        let matched = bodies_identical(dequeued, &gate.expected_body);
        let _ = gate.dequeue_body_tx.send((occ, matched));
        if gate.decision_release_rx.recv_timeout(FAILSAFE).is_err() {
            panic!("{}", R194_RENDEZVOUS_HARNESS_ERROR);
        }
        let committed = gate.cutoff_committed();
        let bypass = gate.bypass_cutoff_enforcement.load(std::sync::atomic::Ordering::SeqCst);
        if committed && !bypass {
            let _ = gate.denial_tx.send(occ);
            return false;
        }
        let _ = gate.grant_ack_tx.send(occ);
        let _ = gate.pre_effect_tx.send(occ);
        if gate.pre_effect_release_rx.recv_timeout(FAILSAFE).is_err() {
            panic!("{}", R194_RENDEZVOUS_HARNESS_ERROR);
        }
        if gate.fault_armed.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = gate.fault_witness_tx.send(occ);
            panic!("{}", R194_GRANTED_WORK_FAULT_MARKER);
        }
        true
    }
    /// Independent executor-ENTRY witness (test builds only). Occurrence-keyed; no-op unless gated.
    #[cfg(test)]
    pub(super) fn executor_entry_test_hook() {
        if let Some(gate) = current_start_grant_gate() {
            let _ = gate.executor_entered_tx.send(gate.occurrence_id);
        }
    }
    /// Independent execution-EFFECT witness, AFTER the real executor returned Ok (test builds only).
    #[cfg(test)]
    pub(super) fn executor_result_test_hook(success_count: u64, error_count: u64, new_height: u64) {
        if let Some(gate) = current_start_grant_gate() {
            let _ = gate
                .result_tx
                .send((gate.occurrence_id, success_count, error_count, new_height));
        }
    }

    /// One recorded disposition per occurrence (one-shot).
    #[cfg(test)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum OccurrenceDisposition {
        RefusedSubmission,
        AdmittedUngranted,
        GrantedEffectsUnknown,
        TerminatedNormalUnsettled,
        TerminatedPanicUnsettled,
    }
    /// A distinct upstream R79 custodian: retains the EXACT authoritative body and a fixture-supplied
    /// committed id (DISTINCT from `block_id`), bound to a unique local occurrence, before submit.
    #[cfg(test)]
    struct OccurrenceCustodian {
        occurrence_id: u64,
        committed_id: [u8; 32],
        body: QbindBlock,
        disposition: Option<OccurrenceDisposition>,
    }
    #[cfg(test)]
    impl OccurrenceCustodian {
        fn bind(occurrence_id: u64, committed_id: [u8; 32], body: QbindBlock) -> Self {
            OccurrenceCustodian { occurrence_id, committed_id, body, disposition: None }
        }
        fn record(&mut self, d: OccurrenceDisposition) {
            assert!(self.disposition.is_none(), "one recorded disposition per occurrence");
            self.disposition = Some(d);
        }
    }

    /// The proposal-`txs` blob encoding used by the sim producer (`hotstuff_node_sim`): the existing
    /// fixture encoding facility. sender‖nonce(le)‖payload_len(le)‖payload‖sig_len(le)‖sig‖suite_id(le).
    #[cfg(test)]
    fn encode_fixture_tx(tx: &super::QbindTransaction) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tx.sender);
        bytes.extend_from_slice(&tx.nonce.to_le_bytes());
        bytes.extend_from_slice(&(tx.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&tx.payload);
        bytes.extend_from_slice(&(tx.signature.bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&tx.signature.bytes);
        bytes.extend_from_slice(&tx.suite_id.to_le_bytes());
        bytes
    }

    /// The synthetic proposal's declared `tx_count` and raw `txs` list AGREE with the ordered decoded
    /// execution input (each raw blob is the encoding of the corresponding decoded transaction).
    #[cfg(test)]
    fn body_is_coherent(b: &QbindBlock) -> bool {
        b.proposal.header.tx_count as usize == b.txs.len()
            && b.proposal.txs.len() == b.txs.len()
            && b.proposal
                .txs
                .iter()
                .zip(b.txs.iter())
                .all(|(raw, tx)| *raw == encode_fixture_tx(tx))
    }

    /// Field-by-field, ORDERED body-content equality (NOT `tx_count()==tx_count()`): block id, parent,
    /// view, the full proposal (stable authoritative bytes via `BlockProposal: PartialEq` — which now
    /// includes a coherent `tx_count` and raw `txs` list), tx count, and each transaction's sender,
    /// nonce, and payload bytes in order.
    #[cfg(test)]
    fn bodies_identical(a: &QbindBlock, b: &QbindBlock) -> bool {
        if a.block_id != b.block_id || a.parent_id != b.parent_id || a.view != b.view {
            return false;
        }
        if *a.proposal != *b.proposal {
            return false;
        }
        if a.txs.len() != b.txs.len() {
            return false;
        }
        a.txs
            .iter()
            .zip(b.txs.iter())
            .all(|(x, y)| x.sender == y.sender && x.nonce == y.nonce && x.payload == y.payload)
    }

    /// Build ONE valid, deterministic, state-changing NonceOnly body: a single fresh-sender, nonce-0
    /// transaction. The synthetic proposal is COHERENT — `header.tx_count == 1` and `proposal.txs`
    /// carries the encoded blob of that one transaction — so the declared count/list agree with the
    /// ordered decoded execution input. The real executor applies it (`success_count == 1`,
    /// exercised-sender nonce 0→1, height → `height`). `height` stays well below `R194_COMMITTED_ID`'s
    /// byte so `block_id = [height; 32]` is DISTINCT from the custodian's committed id.
    #[cfg(test)]
    fn state_changing_body(height: u64, sender_tag: u8) -> QbindBlock {
        let tx = super::QbindTransaction::new([sender_tag; 32], 0, b"r194-state-change".to_vec());
        let mut proposal = (*make_proposal(height)).clone();
        proposal.header.tx_count = 1;
        proposal.txs = vec![encode_fixture_tx(&tx)];
        QbindBlock::new(Arc::new(proposal), vec![tx])
    }

    /// Drain all currently-available state-probe samples (occ, current_height, probe-sender nonce).
    #[cfg(test)]
    fn drain_state_probes(
        rx: &crossbeam_channel::Receiver<(u64, u64, u64)>,
    ) -> Vec<(u64, u64, u64)> {
        let mut v = Vec::new();
        while let Ok(p) = rx.try_recv() {
            v.push(p);
        }
        v
    }

    /// Require an ORDERED (initial, final) pair of independent worker-state samples, all keyed to
    /// `occ`. Returns `((init_height, init_nonce), (final_height, final_nonce))`, or `None` when fewer
    /// than two samples exist (so a baseline-only trace is rejected) or any sample keys to a different
    /// occurrence.
    #[cfg(test)]
    fn ordered_snapshots(
        probes: &[(u64, u64, u64)],
        occ: u64,
    ) -> Option<((u64, u64), (u64, u64))> {
        if probes.len() < 2 || !probes.iter().all(|(o, _, _)| *o == occ) {
            return None;
        }
        let first = probes.first().unwrap();
        let last = probes.last().unwrap();
        Some(((first.1, first.2), (last.1, last.2)))
    }

    /// Spawn the real memory-only NonceOnly worker with the start-grant gate installed as the worker
    /// prelude, then hand the gate the owner's WEAK gate identity (worker keeps neither gate nor sender
    /// alive).
    #[cfg(test)]
    fn spawn_start_gated(
        config: &SingleThreadExecutionServiceConfig,
        gate: Arc<StartGrantGate>,
    ) -> Result<(SupervisedNonceOwner, SupervisedSubmitView, WithdrawalController), SupervisedInitError>
    {
        let gate_for_prelude = Arc::clone(&gate);
        let (owner, view, controller) =
            spawn_nonce_only_with_controller_core(config, move || {
                install_start_grant_gate(gate_for_prelude)
            })?;
        gate.set_supervised(owner.gate_identity());
        Ok((owner, view, controller))
    }

    /// Test-side ends of a `StartGrantGate` (all worker→test events occurrence-keyed).
    #[cfg(test)]
    struct GateEnds {
        reached_rx: crossbeam_channel::Receiver<u64>,
        dequeue_body_rx: crossbeam_channel::Receiver<(u64, bool)>,
        grant_ack_rx: crossbeam_channel::Receiver<u64>,
        denial_rx: crossbeam_channel::Receiver<u64>,
        pre_effect_rx: crossbeam_channel::Receiver<u64>,
        executor_entered_rx: crossbeam_channel::Receiver<u64>,
        result_rx: crossbeam_channel::Receiver<(u64, u64, u64, u64)>,
        fault_witness_rx: crossbeam_channel::Receiver<u64>,
        state_probe_rx: crossbeam_channel::Receiver<(u64, u64, u64)>,
        decision_release_tx: crossbeam_channel::Sender<()>,
        pre_effect_release_tx: crossbeam_channel::Sender<()>,
    }
    #[cfg(test)]
    fn new_start_grant_gate(
        occurrence_id: u64,
        probe_sender: [u8; 32],
        expected_body: QbindBlock,
    ) -> (Arc<StartGrantGate>, GateEnds) {
        let (reached_tx, reached_rx) = crossbeam_channel::unbounded::<u64>();
        let (dequeue_body_tx, dequeue_body_rx) = crossbeam_channel::unbounded::<(u64, bool)>();
        let (grant_ack_tx, grant_ack_rx) = crossbeam_channel::unbounded::<u64>();
        let (denial_tx, denial_rx) = crossbeam_channel::unbounded::<u64>();
        let (pre_effect_tx, pre_effect_rx) = crossbeam_channel::unbounded::<u64>();
        let (executor_entered_tx, executor_entered_rx) = crossbeam_channel::unbounded::<u64>();
        let (result_tx, result_rx) = crossbeam_channel::unbounded::<(u64, u64, u64, u64)>();
        let (fault_witness_tx, fault_witness_rx) = crossbeam_channel::unbounded::<u64>();
        let (state_probe_tx, state_probe_rx) = crossbeam_channel::unbounded::<(u64, u64, u64)>();
        let (decision_release_tx, decision_release_rx) = crossbeam_channel::unbounded::<()>();
        let (pre_effect_release_tx, pre_effect_release_rx) = crossbeam_channel::unbounded::<()>();
        let gate = Arc::new(StartGrantGate {
            occurrence_id,
            probe_sender,
            expected_body,
            supervised: Mutex::new(None),
            bypass_cutoff_enforcement: AtomicBool::new(false),
            fault_armed: AtomicBool::new(false),
            reached_tx,
            dequeue_body_tx,
            grant_ack_tx,
            denial_tx,
            pre_effect_tx,
            executor_entered_tx,
            result_tx,
            fault_witness_tx,
            state_probe_tx,
            decision_release_rx,
            pre_effect_release_rx,
        });
        let ends = GateEnds {
            reached_rx,
            dequeue_body_rx,
            grant_ack_rx,
            denial_rx,
            pre_effect_rx,
            executor_entered_rx,
            result_rx,
            fault_witness_rx,
            state_probe_rx,
            decision_release_tx,
            pre_effect_release_tx,
        };
        (gate, ends)
    }

    /// A0 — zero admissions preserved; the start-grant/effect seam is inert when no gate is installed.
    #[cfg(test)]
    #[test]
    fn r194_a0_zero_admission_preserved_seam_inert() {
        let (mut owner, _view, controller) =
            spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn");
        assert!(!owner.is_admitted(), "never admitted");
        match owner.withdraw(controller) {
            WithdrawalOutcome::Withdrawn => {}
            _ => panic!("A0: a never-admitted withdrawal must still commit the fence"),
        }
        assert!(!owner.sender_present() && !owner.is_admitted() && owner.handle.is_some());
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// R194 ownership witness — idle disconnect WITHOUT explicit sender removal (unchanged from the
    /// accepted R193 fix). Because the fixture holds only a WEAK gate reference, dropping the external
    /// supervisor, view, and controller (WITHOUT `teardown_remove_sender`) drops the gate and its sole
    /// sender → disconnect → wake, observed through a TEST-OWNED cloned readiness signal and a
    /// TEST-OWNED handle. Final-supervisor loss remains UNQUALIFIED; this is a bounded idle-wake only.
    #[cfg(test)]
    #[test]
    fn r194_idle_disconnect_without_explicit_sender_removal() {
        let occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = state_changing_body(11, 0xD1);
        let (gate, _ends) = new_start_grant_gate(occ, [0xD1u8; 32], body);
        let (mut owner, view, controller) =
            spawn_start_gated(&nonce_config(), Arc::clone(&gate)).expect("spawn");
        let ready_probe = Arc::clone(&owner.ready);
        let handle = owner.handle.take().expect("the supervisor still holds the sole handle");
        assert!(owner.sender_present(), "the sole sender is present before releasing external holders");
        drop(owner);
        drop(view);
        drop(controller);
        assert!(
            ready_probe.wait(FAILSAFE),
            "idle disconnect without explicit sender removal must wake the parked worker"
        );
        assert!(handle.join().is_ok(), "the worker joins normally after idle disconnect");
    }

    /// A1 — admit ONE tagged occurrence carrying a VALID, COHERENT state-changing body; acknowledge the
    /// real dequeue AND validate the dequeued block against the bound body; commit the common cutoff;
    /// bind a fresh post-cutoff submit as its OWN refused occurrence (ShuttingDown, exact body retained,
    /// no second dequeue); then release the decision. The worker issues an occurrence-keyed denial →
    /// zero entry, zero effect, and the ordered independent snapshots are `(0,0) → (0,0)`. NEGATIVE
    /// CONTROL — the IDENTICAL pre-decision schedule (same body, same cutoff, same refused late submit)
    /// with enforcement bypassed enters the executor and the ordered snapshots are `(0,0) → (7,1)`. A
    /// baseline-only trace is rejected in both. Committed ids distinct from block_id; bodies retained.
    #[cfg(test)]
    #[test]
    fn r194_a1_admitted_then_cutoff_then_denied_no_effect() {
        // ---- Denied schedule ----
        let occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let canonical = state_changing_body(7, 0xA1);
        assert_eq!(canonical.block_id, [7u8; 32], "self-derived block id is the payload hash");
        assert!(body_is_coherent(&canonical), "fixture body: proposal count/txs agree with decoded input");
        let (gate, ends) = new_start_grant_gate(occ, [0xA1u8; 32], canonical.clone());
        let (mut owner, view, _controller) =
            spawn_start_gated(&nonce_config(), Arc::clone(&gate)).expect("spawn");
        let mut custodian = OccurrenceCustodian::bind(occ, R194_COMMITTED_ID, canonical.clone());
        assert_ne!(custodian.committed_id, custodian.body.block_id, "committed id distinct from block_id");
        assert_eq!(view.submit(canonical.clone()), SubmitOutcome::Admitted);
        assert!(owner.is_admitted(), "sticky admission recorded");
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("A1: real dequeue acknowledged"), occ);
        assert_eq!(
            ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("A1: dequeue-body report"),
            (occ, true),
            "the ACTUAL dequeued task matches the bound coherent body"
        );
        owner.teardown_remove_sender();
        assert!(!owner.sender_present(), "cutoff removed the sole sender");
        // Fresh post-admission-cutoff submit, bound as its OWN refused occurrence.
        let (late_disp, late_occ) = a1_refused_late_submit(&view);
        assert_eq!(late_disp, OccurrenceDisposition::RefusedSubmission);
        assert_ne!(late_occ, occ, "the refused late submit is a distinct occurrence");
        ends.decision_release_tx.send(()).expect("release the grant decision");
        assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("A1: worker issued a denial"), occ);
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        assert!(ends.executor_entered_rx.try_recv().is_err(), "A1: ZERO executor entry");
        assert!(ends.result_rx.try_recv().is_err(), "A1: ZERO execution effect");
        assert!(ends.grant_ack_rx.try_recv().is_err(), "A1: no grant acknowledged");
        assert!(ends.reached_rx.try_recv().is_err(), "A1: no second dequeue (late submit refused)");
        // ORDERED independent snapshots: a baseline-only trace is rejected; require (0,0) → (0,0).
        let probes = drain_state_probes(&ends.state_probe_rx);
        assert!(!probes.is_empty(), "A1: the independent state probe fired");
        assert!(
            ordered_snapshots(&probes[..1], occ).is_none(),
            "A1: a baseline-only trace is rejected (ordered initial+final required)"
        );
        let (init, fin) = ordered_snapshots(&probes, occ).expect("A1: ordered baseline+final snapshots");
        assert_eq!(init, (0, 0), "A1 denial baseline (height,nonce) = (0,0)");
        assert_eq!(fin, (0, 0), "A1 denial post-decision (height,nonce) = (0,0)");
        custodian.record(OccurrenceDisposition::AdmittedUngranted);
        assert_eq!(custodian.disposition, Some(OccurrenceDisposition::AdmittedUngranted));
        assert!(bodies_identical(&custodian.body, &canonical) && custodian.body.height() == 7);

        // ---- NEGATIVE CONTROL: identical pre-decision schedule, enforcement bypassed ----
        let occ2 = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body2 = state_changing_body(7, 0xA1);
        assert!(body_is_coherent(&body2));
        let (gate2, ends2) = new_start_grant_gate(occ2, [0xA1u8; 32], body2.clone());
        gate2.bypass_cutoff_enforcement.store(true, std::sync::atomic::Ordering::SeqCst);
        let (mut owner2, view2, _c2) =
            spawn_start_gated(&nonce_config(), Arc::clone(&gate2)).expect("spawn");
        assert_eq!(view2.submit(body2.clone()), SubmitOutcome::Admitted);
        assert_eq!(ends2.reached_rx.recv_timeout(FAILSAFE).expect("dequeue ack (bypass)"), occ2);
        assert_eq!(ends2.dequeue_body_rx.recv_timeout(FAILSAFE).expect("dequeue-body (bypass)"), (occ2, true));
        owner2.teardown_remove_sender();
        assert!(!owner2.sender_present());
        // IDENTICAL pre-decision action: the same refused late submit, bound as its own occurrence.
        let (late_disp2, late_occ2) = a1_refused_late_submit(&view2);
        assert_eq!(late_disp2, OccurrenceDisposition::RefusedSubmission);
        assert_ne!(late_occ2, occ2);
        ends2.decision_release_tx.send(()).expect("release decision (bypass)");
        assert_eq!(ends2.grant_ack_rx.recv_timeout(FAILSAFE).expect("bypass grants"), occ2);
        assert_eq!(ends2.pre_effect_rx.recv_timeout(FAILSAFE).expect("held pre-effect"), occ2);
        ends2.pre_effect_release_tx.send(()).expect("release pre-effect");
        assert_eq!(ends2.executor_entered_rx.recv_timeout(FAILSAFE).expect("entered (bypass)"), occ2);
        let (rocc, success, errors, height) =
            ends2.result_rx.recv_timeout(FAILSAFE).expect("real effect observed (bypass)");
        assert_eq!((rocc, success, errors, height), (occ2, 1, 0, 7), "bypass: real applied effect");
        assert_eq!(owner2.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner2.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        assert!(ends2.reached_rx.try_recv().is_err(), "bypass: no second dequeue (late submit refused)");
        let probes2 = drain_state_probes(&ends2.state_probe_rx);
        assert!(
            ordered_snapshots(&probes2[..1], occ2).is_none(),
            "bypass: a baseline-only trace is rejected"
        );
        let (init2, fin2) = ordered_snapshots(&probes2, occ2).expect("bypass ordered snapshots");
        assert_eq!(init2, (0, 0), "bypass baseline (0,0)");
        assert_eq!(fin2, (7, 1), "bypass post-decision (7,1) — real nonce/height change");
    }

    /// Shared refused-late-submit action for both A1 schedules: bind a fresh occurrence, submit a clone
    /// of its bound body AFTER the admitted-work cutoff, require `ShuttingDown`, record the refusal, and
    /// verify the exact retained body. Returns `(disposition, occurrence_id)`.
    #[cfg(test)]
    fn a1_refused_late_submit(view: &SupervisedSubmitView) -> (OccurrenceDisposition, u64) {
        let late_occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let late_body = state_changing_body(7, 0xA1);
        let mut late_custodian = OccurrenceCustodian::bind(late_occ, R194_COMMITTED_ID, late_body.clone());
        assert_ne!(late_custodian.committed_id, late_custodian.body.block_id);
        assert_eq!(
            view.submit(late_body.clone()),
            SubmitOutcome::ShuttingDown,
            "a fresh submit after the admitted-work cutoff is refused, admitting nothing"
        );
        late_custodian.record(OccurrenceDisposition::RefusedSubmission);
        assert!(
            bodies_identical(&late_custodian.body, &late_body),
            "the refused occurrence retains its exact body in custody"
        );
        (late_custodian.disposition.unwrap(), late_occ)
    }

    /// A2 — grant the one-shot start BEFORE the cutoff (occurrence-keyed ack + dequeued-body match);
    /// held at pre-effect; cutoff committed; release → granted work enters the real executor AFTER
    /// cutoff with a REAL effect (success 1, height 2), confirmed by the ordered probe `(0,0) → (2,1)`.
    /// Disposition `GrantedEffectsUnknown`. Schedule unchanged from R193 (grant-ack order preserved).
    #[cfg(test)]
    #[test]
    fn r194_a2_grant_before_cutoff_executes_after_cutoff() {
        let occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let canonical = state_changing_body(2, 0xB2);
        assert!(body_is_coherent(&canonical));
        let (gate, ends) = new_start_grant_gate(occ, [0xB2u8; 32], canonical.clone());
        let (mut owner, view, _controller) =
            spawn_start_gated(&nonce_config(), Arc::clone(&gate)).expect("spawn");
        let mut custodian = OccurrenceCustodian::bind(occ, R194_COMMITTED_ID, canonical.clone());
        assert_ne!(custodian.committed_id, custodian.body.block_id);
        assert_eq!(view.submit(canonical.clone()), SubmitOutcome::Admitted);
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("A2: dequeue ack"), occ);
        assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("A2: dequeue-body"), (occ, true));
        ends.decision_release_tx.send(()).expect("release decision");
        assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("A2: grant acknowledged"), occ);
        assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held before first effect"), occ);
        owner.teardown_remove_sender();
        assert!(!owner.sender_present(), "cutoff committed while the grant is held");
        ends.pre_effect_release_tx.send(()).expect("release past the pre-effect hold");
        assert_eq!(ends.executor_entered_rx.recv_timeout(FAILSAFE).expect("entered after cutoff"), occ);
        let (rocc, success, errors, height) =
            ends.result_rx.recv_timeout(FAILSAFE).expect("A2: real effect after cutoff");
        assert_eq!((rocc, success, errors, height), (occ, 1, 0, 2));
        custodian.record(OccurrenceDisposition::GrantedEffectsUnknown);
        assert!(bodies_identical(&custodian.body, &canonical));
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
        let probes = drain_state_probes(&ends.state_probe_rx);
        let (init, fin) = ordered_snapshots(&probes, occ).expect("A2 ordered snapshots");
        assert_eq!(init, (0, 0), "A2 baseline (0,0)");
        assert_eq!(fin, (2, 1), "A2 post-cutoff execution (height 2, nonce 1)");
    }

    /// A3 — a NEW submit through the REAL view after an idle (never-admitted) cutoff returns
    /// `ShuttingDown`, admits nothing, and the upstream custodian keeps the exact body (committed id
    /// distinct from block_id).
    #[cfg(test)]
    #[test]
    fn r194_a3_submit_after_idle_cutoff_refused() {
        let occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (mut owner, view, _controller) =
            spawn_supervised_nonce_only_with_controller(&nonce_config()).expect("spawn");
        let canonical = state_changing_body(9, 0xA3);
        let mut custodian = OccurrenceCustodian::bind(occ, R194_COMMITTED_ID, canonical.clone());
        assert_ne!(custodian.committed_id, custodian.body.block_id);
        assert!(owner.try_close_idle().is_ok(), "cutoff closes admission (never admitted)");
        assert!(!owner.sender_present());
        assert_eq!(
            view.submit(canonical.clone()),
            SubmitOutcome::ShuttingDown,
            "A3: a new submit after the idle cutoff is refused, admitting nothing"
        );
        assert!(!owner.is_admitted(), "no admission from a refused submit");
        custodian.record(OccurrenceDisposition::RefusedSubmission);
        assert!(bodies_identical(&custodian.body, &canonical) && custodian.body.height() == 9);
        assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
        assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
    }

    /// A4 — bounded wait and observed termination class on granted work (schedule unchanged from R193).
    /// NORMAL: grant (ack) → held → bounded `Pending` with the ORIGINAL handle → cutoff → release →
    /// real entry + effect → consuming join `Terminated(Normal)`. PANIC: an opt-in guarded fault is
    /// witnessed (occurrence-keyed, pre-executor) and unwinds BEFORE entry → join `Terminated(Panic)`,
    /// no entry/effect; repeat join `AlreadyJoined`. The dequeued block is validated against the bound body.
    #[cfg(test)]
    #[test]
    fn r194_a4_bounded_wait_then_termination_normal_and_panic() {
        // ---- Normal termination ----
        {
            let occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let canonical = state_changing_body(5, 0xA4);
            let (gate, ends) = new_start_grant_gate(occ, [0xA4u8; 32], canonical.clone());
            let (mut owner, view, _controller) =
                spawn_start_gated(&nonce_config(), Arc::clone(&gate)).expect("spawn");
            let mut custodian = OccurrenceCustodian::bind(occ, R194_COMMITTED_ID, canonical.clone());
            assert_eq!(view.submit(canonical.clone()), SubmitOutcome::Admitted);
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("dequeue ack"), occ);
            assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("dequeue-body"), (occ, true));
            ends.decision_release_tx.send(()).expect("release decision");
            assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("granted"), occ);
            assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held pre-effect"), occ);
            assert_eq!(owner.observe_ready(Duration::from_millis(100)), Readiness::Pending);
            assert!(owner.handle.is_some(), "the supervisor retains the original handle");
            owner.teardown_remove_sender();
            ends.pre_effect_release_tx.send(()).expect("release pre-effect");
            assert_eq!(ends.executor_entered_rx.recv_timeout(FAILSAFE).expect("entered"), occ);
            let (rocc, success, _errors, height) =
                ends.result_rx.recv_timeout(FAILSAFE).expect("real effect");
            assert_eq!((rocc, success, height), (occ, 1, 5));
            assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Normal));
            custodian.record(OccurrenceDisposition::TerminatedNormalUnsettled);
            assert!(bodies_identical(&custodian.body, &canonical), "effects unsettled; exact body retained");
        }
        // ---- Panic termination (opt-in guarded fault on granted work) ----
        {
            let occ = R194_OCCURRENCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let canonical = state_changing_body(6, 0xA5);
            let (gate, ends) = new_start_grant_gate(occ, [0xA5u8; 32], canonical.clone());
            gate.fault_armed.store(true, std::sync::atomic::Ordering::SeqCst);
            let (mut owner, view, _controller) =
                spawn_start_gated(&nonce_config(), Arc::clone(&gate)).expect("spawn");
            let mut custodian = OccurrenceCustodian::bind(occ, R194_COMMITTED_ID, canonical.clone());
            assert_eq!(view.submit(canonical.clone()), SubmitOutcome::Admitted);
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("dequeue ack"), occ);
            assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("dequeue-body"), (occ, true));
            ends.decision_release_tx.send(()).expect("release decision");
            assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("granted"), occ);
            assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held pre-effect"), occ);
            owner.teardown_remove_sender();
            ends.pre_effect_release_tx.send(()).expect("release pre-effect");
            assert_eq!(
                ends.fault_witness_rx.recv_timeout(FAILSAFE).expect("guarded fault fired"),
                occ,
                "the injected guarded fault is witnessed, occurrence-keyed, pre-executor"
            );
            assert_eq!(owner.observe_ready(FAILSAFE), Readiness::ReadyToJoin);
            assert_eq!(owner.join(), JoinOutcome::Terminated(TermEvidence::Panic));
            assert!(ends.executor_entered_rx.try_recv().is_err(), "the faulted grant never entered the executor");
            assert!(ends.result_rx.try_recv().is_err(), "no effect from a faulted grant");
            custodian.record(OccurrenceDisposition::TerminatedPanicUnsettled);
            assert!(bodies_identical(&custodian.body, &canonical), "adverse outcome preserved; body retained");
            assert_eq!(owner.join(), JoinOutcome::AlreadyJoined, "a repeat join obtains no result");
        }
    }
}

// ============================================================================
// R198 — private, unwired, memory-only NonceOnly production-build prototype:
// explicit lifetime admission + fail-closed one-shot start decision at the shared
// worker's pre-executor checkpoint (owner-authorized opt-in branch).
// ============================================================================
//
// This is a LOCAL, UNWIRED prototype. It reuses the real `worker_loop_nonce_only`
// through one owner-authorized opt-in production branch: `prod_start_decision()` is
// compiled in all builds. R199: worker MODE is explicit and independent of the
// authority lookup — a worker that never entered candidate mode returns
// `StartOutcome::Legacy` WITHOUT taking any gate lock, so legacy memory-only workers
// (and the VmV0 path, which uses a different loop) are behaviorally unchanged, while a
// candidate worker whose authority is NOT installed FAILS CLOSED (Deny) rather than
// silently running the legacy path. The candidate worker consults its per-worker
// `Weak<SupervisedProdGate>` authority under the SAME mutex that serializes successful
// enqueue, cutoff, and the one-shot start decision, and validates the dequeued work
// against the EXACT generation-scoped occurrence bound on the single admission (R200:
// the block self-id AND the ordered execution input — the self-id alone is insufficient,
// since bodies can share a self-id while carrying different execution input whose effects
// differ); a committed cutoff, a missing/poisoned authority, an inconsistent occurrence
// (generation mismatch), different/missing execution input, or a second one-shot entry all
// FAIL CLOSED (Deny) before the executor and the height update — never a fallback to legacy
// execution. The candidate enforces ONE lifetime admission explicitly (even after a
// dequeue frees queue capacity), keeps cutoff refusal distinct from capacity/lifetime
// refusal, returns the refused body to the caller so upstream custody is preserved
// exactly, and reports owner/submit poison as TYPED unresolved outcomes (never a silent
// successful cutoff/admission). A distinct owner `close_admission` can cut off after
// that single success. The worker keeps only a `Weak` across receive; the transient
// strong ref + guard are released before any wait/executor/join. The pause/release
// rendezvous, the enforcement bypass, the occurrence tamper, and the injected guarded
// fault are all `#[cfg(test)]`. UNWIRED: no production caller, no authoritative
// committed-ID / exact-body custody source, no settlement; final-supervisor loss
// remains UNQUALIFIED; C05 OPEN.
mod supervised_start_checkpoint {
    #![allow(dead_code)]

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Condvar, Mutex, Weak};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use crossbeam_channel::{bounded, Sender, TrySendError};

    use crate::node_config::ExecutionProfile;
    use super::{ExecTask, QbindBlock, SingleThreadExecutionService, SingleThreadExecutionServiceConfig};
    #[cfg(test)]
    use qbind_wire::consensus::{BlockHeader, BlockProposal};

    #[cfg(test)]
    const FAILSAFE: Duration = Duration::from_secs(10);
    #[cfg(test)]
    const R198_FAULT_MARKER: &str = "R198-INTENTIONAL-GRANTED-WORK-FAULT";
    #[cfg(test)]
    const R198_RENDEZVOUS_HARNESS_ERROR: &str = "R198-RENDEZVOUS-HARNESS-ERROR";
    /// A committed-id marker distinct from any `[height; 32]` self-derived block id used here.
    #[cfg(test)]
    const R198_COMMITTED_ID: [u8; 32] = [0xC1u8; 32];

    /// Per-spawn generation, binding an installed authority to exactly one gate.
    static PROD_GENERATION_SEQ: AtomicU64 = AtomicU64::new(1);

    /// The production decision returned at the shared-loop pre-executor checkpoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum StartOutcome {
        /// No candidate authority installed on this worker → legacy behavior, no gate lock taken.
        Legacy,
        /// Candidate: start granted (cutoff not committed at the moment of decision).
        Grant,
        /// Candidate: fail-closed denial (committed cutoff / missing / poisoned / inconsistent
        /// occurrence / second one-shot entry), returned BEFORE any irreversible effect.
        Deny,
    }

    /// Latching one-shot signal (self-contained copy; mirrors the idle-close `Signal`).
    struct ProdSignal {
        state: Mutex<bool>,
        cv: Condvar,
    }
    impl ProdSignal {
        fn new() -> Self {
            ProdSignal { state: Mutex::new(false), cv: Condvar::new() }
        }
        fn fire(&self) {
            let mut g = self.state.lock().unwrap();
            *g = true;
            self.cv.notify_all();
        }
        fn wait(&self, timeout: Duration) -> bool {
            let g = self.state.lock().unwrap();
            let (_g, res) = self.cv.wait_timeout_while(g, timeout, |fired| !*fired).unwrap();
            !res.timed_out()
        }
    }
    struct FireProdReady(Arc<ProdSignal>);
    impl Drop for FireProdReady {
        fn drop(&mut self) {
            self.0.fire();
        }
    }

    #[derive(Debug)]
    pub(super) enum ProdInitError {
        UnsupportedProfile,
        UnsupportedPersistentState,
        WorkerSpawn { source: std::io::Error },
    }

    /// Candidate submit outcome. Cutoff (`ShuttingDown`), capacity (`QueueFull`), the lifetime
    /// one-admission limit (`LifetimeExhausted`), and a poisoned gate (`Poisoned`) are DISTINCT
    /// refusals. R199: every refusal returns the refused `QbindBlock` to the caller so upstream body
    /// custody is preserved exactly (never dropped), and poison is a typed refusal — never a silent
    /// admission.
    #[derive(Debug)]
    enum ProdSubmitOutcome {
        Admitted,
        QueueFull(QbindBlock),
        ShuttingDown(QbindBlock),
        LifetimeExhausted(QbindBlock),
        Poisoned(QbindBlock),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProdReadiness {
        Pending,
        ReadyToJoin,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProdTerm {
        Normal,
        Panic,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProdJoin {
        Terminated(ProdTerm),
        AlreadyJoined,
    }

    /// Candidate gate: successful enqueue, cutoff, and the one-shot grant decision all serialize on
    /// `inner`. `admissions_used` enforces the lifetime bound; `closed` is the owner cutoff;
    /// `grant_decided` makes the start decision one-shot.
    struct ProdGateInner {
        sender: Option<Sender<ExecTask>>,
        admissions_used: u32,
        closed: bool,
        grant_decided: bool,
        /// R200: the exact generation-scoped binding recorded on the single successful admission (the
        /// admitting generation + the exact admitted-task encoding, incl. ordered execution input); the
        /// pre-executor decision validates the dequeued work against it. `None` until an admission
        /// binds it.
        occurrence: Option<OccurrenceBinding>,
    }
    struct SupervisedProdGate {
        inner: Mutex<ProdGateInner>,
        generation: u64,
    }

    /// Per-worker authority: a `Weak` to the gate (never a strong/sender-owning ref) plus the
    /// generation it is bound to (an inconsistent generation fails closed).
    #[derive(Clone)]
    struct ProdAuthority {
        gate: Weak<SupervisedProdGate>,
        generation: u64,
    }

    /// R199: the explicit per-worker mode, set at spawn INDEPENDENTLY of whether an authority is
    /// installed. Legacy (the const default for every non-candidate worker) selects the existing
    /// behavior with no gate lock; Candidate opts into the fail-closed decision even when the
    /// authority is absent.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WorkerMode {
        Legacy,
        Candidate,
    }

    thread_local! {
        static PROD_MODE: std::cell::Cell<WorkerMode> =
            const { std::cell::Cell::new(WorkerMode::Legacy) };
        static PROD_AUTHORITY: std::cell::RefCell<Option<ProdAuthority>> =
            const { std::cell::RefCell::new(None) };
    }
    /// Enter candidate mode on this worker. Called by the candidate spawn prelude BEFORE (and
    /// independently of) any authority install, so "deliberate candidate selection" is distinct from
    /// "authority availability".
    fn enter_candidate_mode() {
        PROD_MODE.with(|c| c.set(WorkerMode::Candidate));
    }
    fn current_mode() -> WorkerMode {
        PROD_MODE.with(|c| c.get())
    }
    fn install_prod_authority(a: ProdAuthority) {
        PROD_AUTHORITY.with(|c| *c.borrow_mut() = Some(a));
    }
    fn current_authority() -> Option<ProdAuthority> {
        PROD_AUTHORITY.with(|c| c.borrow().clone())
    }

    /// R200: the EXACT admitted-task occurrence encoding, derived IDENTICALLY at admission (bind, under
    /// the gate lock) and at the pre-executor decision (validate, under the gate lock). It captures the
    /// block's self-identity (block id / parent id / view) AND the ORDERED EXECUTION INPUT (every
    /// decoded transaction's sender, nonce, payload, signature and suite id, in order) — because the
    /// block's self-id ALONE is insufficient evidence: two coherent bodies can share a self-id while
    /// carrying different execution input, whose effects differ. This is a candidate-only exact body
    /// binding over the existing `QbindBlock` representation; it adds NO protocol identity and performs
    /// NO consensus verification. Production.
    fn occurrence_encoding(block: &QbindBlock) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&block.block_id);
        v.extend_from_slice(&block.parent_id);
        v.extend_from_slice(&block.view.to_le_bytes());
        v.extend_from_slice(&(block.txs.len() as u64).to_le_bytes());
        for tx in &block.txs {
            v.extend_from_slice(&tx.sender);
            v.extend_from_slice(&tx.nonce.to_le_bytes());
            v.extend_from_slice(&(tx.payload.len() as u64).to_le_bytes());
            v.extend_from_slice(&tx.payload);
            v.extend_from_slice(&(tx.signature.bytes.len() as u64).to_le_bytes());
            v.extend_from_slice(&tx.signature.bytes);
            v.extend_from_slice(&tx.suite_id.to_le_bytes());
        }
        v
    }

    /// R200: the generation-scoped binding recorded on the single successful admission. It pins the
    /// admitting generation AND the exact admitted-task encoding, so the decision can reject either a
    /// cross-generation reuse or a dequeued body whose ordered execution input differs from the
    /// admitted one (even when the block self-id matches).
    #[derive(Clone)]
    struct OccurrenceBinding {
        generation: u64,
        encoding: Vec<u8>,
    }

    /// PRODUCTION decision at the worker's pre-executor checkpoint (compiled in all builds). R199: a
    /// worker that never entered candidate mode → `Legacy` with NO gate lock (unchanged legacy
    /// behavior). A candidate worker with NO installed authority → `Deny` (fail-closed; never legacy).
    /// Otherwise a one-shot, fail-closed read under the SAME mutex as admission/cutoff: a dead gate
    /// (`upgrade` None), a generation mismatch, a poisoned mutex, a second entry, a missing occurrence
    /// binding, or a binding that does not match the dequeued work each yield `Deny`; otherwise
    /// `sender.is_none() || closed` ⇒ `Deny`, else `Grant`. The transient strong reference and the
    /// guard are dropped before returning, so the worker holds no gate across the subsequent
    /// wait/executor/join.
    pub(super) fn prod_start_decision(dequeued: &QbindBlock) -> StartOutcome {
        // R203 (test-only observation; no production effect): a function-scope trace declared FIRST, so
        // it is dropped LAST — strictly after the mutex guard and the transient strong `Arc` on EVERY
        // path, including the early fail-closed denials below. Each branch stores its class into the
        // trace's pending cell from the SINGLE real authority lookup / Weak upgrade / mutex lock /
        // occurrence check the decision itself performs (no duplicate probes). The pending class is
        // emitted by the trace's `Drop`, which skips emission while `std::thread::panicking()` so a
        // panic is never recorded as a normal decision class. Absent from every non-test build; the
        // `#[cfg(test)]` branch stores add only braces around the unchanged `return StartOutcome::Deny`
        // statements — stripping every `#[cfg(test)]` item yields the exact R200 decision projection.
        #[cfg(test)]
        let trace = RawClassTrace::new();
        // R199: deliberate mode first — legacy workers take no lock and are behavior-neutral.
        match current_mode() {
            WorkerMode::Legacy => return StartOutcome::Legacy,
            WorkerMode::Candidate => {}
        }
        // Candidate mode: a missing installation is a fail-closed denial, NOT legacy execution.
        let auth = match current_authority() {
            None => {
                #[cfg(test)]
                trace.set(DecisionClass::MissingAuthority);
                return StartOutcome::Deny; // fail-closed: candidate mode, authority not installed
            }
            Some(a) => a,
        };
        let strong = match auth.gate.upgrade() {
            None => {
                #[cfg(test)]
                trace.set(DecisionClass::DeadGate);
                return StartOutcome::Deny; // fail-closed: dead Weak (missing gate)
            }
            Some(s) => s,
        };
        if strong.generation != auth.generation {
            #[cfg(test)]
            trace.set(DecisionClass::WrongGeneration);
            return StartOutcome::Deny; // fail-closed: inconsistent occurrence
        }
        // R200: the EXACT admitted-task encoding of the actual dequeued work (self-id + ordered
        // execution input), derived identically to the admission-time binding. Computed outside the
        // lock.
        let encoding = occurrence_encoding(dequeued);
        let committed = {
            let mut inner = match strong.inner.lock() {
                Err(_) => {
                    #[cfg(test)]
                    trace.set(DecisionClass::Poisoned);
                    return StartOutcome::Deny; // fail-closed: poisoned
                }
                Ok(g) => g,
            };
            if inner.grant_decided {
                #[cfg(test)]
                trace.set(DecisionClass::OneShot);
                return StartOutcome::Deny; // one-shot: a second dequeue is denied
            }
            inner.grant_decided = true;
            // R200: the dequeued work must match the EXACT occurrence bound on the single admission —
            // both the admitting generation and the ordered execution input. A dequeued body sharing
            // the block self-id but carrying different execution input is DENIED here, before effects.
            match &inner.occurrence {
                None => {
                    #[cfg(test)]
                    trace.set(DecisionClass::NoOccurrence);
                    return StartOutcome::Deny; // fail-closed: no admitted occurrence
                }
                Some(b) if b.generation != strong.generation => {
                    #[cfg(test)]
                    trace.set(DecisionClass::OccurrenceMismatch);
                    return StartOutcome::Deny; // cross-generation
                }
                Some(b) if b.encoding != encoding => {
                    #[cfg(test)]
                    trace.set(DecisionClass::OccurrenceMismatch);
                    return StartOutcome::Deny; // different execution input
                }
                Some(_) => {}
            }
            inner.closed || inner.sender.is_none()
        };
        // R201 (test-only observation; no production effect): the VALIDATED generation-scoped admitted
        // key from the successful mode+authority+generation+occurrence comparison above. Captured after
        // the mutex is released and carried to test observers only on a real grant. Absent from every
        // non-test build, so the production decision/return is byte-for-byte unchanged.
        #[cfg(test)]
        let checked_key = strong.generation;
        drop(strong);
        if committed {
            #[cfg(test)]
            trace.set(DecisionClass::CommittedCutoff);
            StartOutcome::Deny
        } else {
            // R203 (test-only): the raw grant classification is stored in the trace and emitted by its
            // `Drop` after this frame's resources unwind; the checked key is recorded for the grant/
            // execution witnesses (also only after `strong` was dropped above).
            #[cfg(test)]
            trace.set(DecisionClass::Grant);
            #[cfg(test)]
            record_checked_key(checked_key);
            StartOutcome::Grant
        }
    }

    struct ProdSubmitView {
        gate: Arc<SupervisedProdGate>,
    }
    impl ProdSubmitView {
        /// Enqueue under the gate lock. R199: a poisoned gate is a TYPED `Poisoned` refusal first (the
        /// body is never admitted). Then cutoff (`ShuttingDown`); then the explicit lifetime bound
        /// (`LifetimeExhausted`) checked BEFORE `try_send` so a dequeue that freed capacity does NOT
        /// re-open admission; then capacity (`QueueFull`). Every refusal returns the refused body so
        /// the caller retains exact custody. On the single success the occurrence is bound.
        fn submit(&self, block: QbindBlock) -> ProdSubmitOutcome {
            let mut inner = match self.gate.inner.lock() {
                Err(_) => return ProdSubmitOutcome::Poisoned(block), // typed; never a silent admission
                Ok(g) => g,
            };
            if inner.closed {
                return ProdSubmitOutcome::ShuttingDown(block);
            }
            if inner.sender.is_none() {
                return ProdSubmitOutcome::ShuttingDown(block);
            }
            if inner.admissions_used >= 1 {
                return ProdSubmitOutcome::LifetimeExhausted(block);
            }
            let encoding = occurrence_encoding(&block);
            let generation = self.gate.generation;
            let task = ExecTask { block, submitted_at: Instant::now() };
            let tx = inner.sender.as_ref().unwrap();
            match tx.try_send(task) {
                Ok(()) => {
                    inner.admissions_used += 1;
                    // R200: bind the EXACT admitted task (generation + ordered execution input) on the
                    // single success.
                    inner.occurrence = Some(OccurrenceBinding { generation, encoding });
                    ProdSubmitOutcome::Admitted
                }
                Err(TrySendError::Full(t)) => ProdSubmitOutcome::QueueFull(t.block),
                Err(TrySendError::Disconnected(t)) => ProdSubmitOutcome::ShuttingDown(t.block),
            }
        }
    }

    /// R199: typed owner cutoff outcome. A poisoned gate is reported as `Poisoned` and is NOT treated
    /// as a successful cutoff/settlement.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProdCloseOutcome {
        Closed,
        Poisoned,
    }

    struct ProdOwner {
        gate: Arc<SupervisedProdGate>,
        handle: Option<JoinHandle<()>>,
        ready: Arc<ProdSignal>,
    }
    impl ProdOwner {
        /// Distinct owner cutoff: close admission AND remove the sole sender under the gate lock —
        /// permitted even AFTER the single successful admission (unlike `withdraw`/`try_close_idle`,
        /// which stay byte-identical and refuse once admitted). R199: a poisoned gate yields
        /// `ProdCloseOutcome::Poisoned` and changes nothing — never a silent successful cutoff.
        fn close_admission(&self) -> ProdCloseOutcome {
            match self.gate.inner.lock() {
                Err(_) => ProdCloseOutcome::Poisoned,
                Ok(mut inner) => {
                    inner.closed = true;
                    inner.sender = None;
                    ProdCloseOutcome::Closed
                }
            }
        }
        /// Poison-tolerant reads (R200: test-gated diagnostics). The data behind a poisoned mutex is
        /// not corrupted, so a FIXTURE may inspect it after a genuine poison via `into_inner` — but
        /// such a read never qualifies contents for a production decision, and these accessors are not
        /// compiled into a shipping build.
        #[cfg(test)]
        fn is_closed(&self) -> bool {
            match self.gate.inner.lock() {
                Ok(g) => g.closed,
                Err(e) => e.into_inner().closed,
            }
        }
        #[cfg(test)]
        fn admissions_used(&self) -> u32 {
            match self.gate.inner.lock() {
                Ok(g) => g.admissions_used,
                Err(e) => e.into_inner().admissions_used,
            }
        }
        #[cfg(test)]
        fn sender_present(&self) -> bool {
            match self.gate.inner.lock() {
                Ok(g) => g.sender.is_some(),
                Err(e) => e.into_inner().sender.is_some(),
            }
        }
        fn observe_ready(&self, deadline: Duration) -> ProdReadiness {
            if self.ready.wait(deadline) {
                ProdReadiness::ReadyToJoin
            } else {
                ProdReadiness::Pending
            }
        }
        fn join(&mut self) -> ProdJoin {
            match self.handle.take() {
                Some(h) => ProdJoin::Terminated(match h.join() {
                    Ok(()) => ProdTerm::Normal,
                    Err(_) => ProdTerm::Panic,
                }),
                None => ProdJoin::AlreadyJoined,
            }
        }
    }

    /// R199/R200: how the candidate worker's authority is installed, INDEPENDENT of candidate mode
    /// (which the prelude always enters). `Bound` is the ONLY production variant (authority bound to
    /// the gate's own generation); the ordinary private `spawn_prod` selects only `Bound`. R200: the
    /// fail-closed test overrides `Generation` (binds a wrong generation — inconsistent occurrence) and
    /// `Absent` (enters candidate mode but installs NO authority) are `#[cfg(test)]`, so they are not
    /// compiled into a shipping build.
    enum AuthoritySpec {
        Bound,
        #[cfg(test)]
        Generation(u64),
        #[cfg(test)]
        Absent,
    }

    /// Spawn the candidate worker on the REAL `worker_loop_nonce_only`. Refuses non-`NonceOnly` /
    /// persistent configs BEFORE creating a channel or spawning (like `spawn_core`). The gate (with
    /// the sole sender) is created first so a `Weak` authority can be installed by the prelude. R199:
    /// the prelude ALWAYS enters candidate mode first, then installs the authority per `auth_spec`.
    fn spawn_prod_core<F>(
        config: &SingleThreadExecutionServiceConfig,
        auth_spec: AuthoritySpec,
        extra_prelude: F,
    ) -> Result<(ProdOwner, ProdSubmitView), ProdInitError>
    where
        F: FnOnce() + Send + 'static,
    {
        match config.execution_profile {
            ExecutionProfile::NonceOnly => {}
            _ => return Err(ProdInitError::UnsupportedProfile),
        }
        if config.state_dir.is_some() {
            return Err(ProdInitError::UnsupportedPersistentState);
        }

        let (tx, rx) = bounded::<ExecTask>(config.queue_capacity);
        let generation = PROD_GENERATION_SEQ.fetch_add(1, Ordering::SeqCst);
        let gate = Arc::new(SupervisedProdGate {
            inner: Mutex::new(ProdGateInner {
                sender: Some(tx),
                admissions_used: 0,
                closed: false,
                grant_decided: false,
                occurrence: None,
            }),
            generation,
        });
        // R199: candidate mode is entered unconditionally; the authority is installed per spec (and
        // may be absent in test, so a candidate worker without an authority still fails closed).
        let authority_opt = match auth_spec {
            AuthoritySpec::Bound => Some(ProdAuthority {
                gate: Arc::downgrade(&gate),
                generation,
            }),
            #[cfg(test)]
            AuthoritySpec::Absent => None,
            #[cfg(test)]
            AuthoritySpec::Generation(g) => Some(ProdAuthority {
                gate: Arc::downgrade(&gate),
                generation: g,
            }),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let queue_len = Arc::new(AtomicU64::new(0));
        let parallel_config = config.parallel_config.clone();
        let ready = Arc::new(ProdSignal::new());
        let ready_w = Arc::clone(&ready);

        let handle = thread::Builder::new()
            .name("qbind-exec-worker".to_string())
            .spawn(move || {
                // R199: enter candidate mode FIRST (deliberate selection), independent of whether an
                // authority is installed. Capture no sender-owning strong reference.
                enter_candidate_mode();
                if let Some(authority) = authority_opt {
                    install_prod_authority(authority);
                }
                extra_prelude();
                let _fire = FireProdReady(ready_w);
                let mut current_height: u64 = 0;
                SingleThreadExecutionService::worker_loop_nonce_only(
                    rx,
                    shutdown,
                    queue_len,
                    None,
                    parallel_config,
                    &mut current_height,
                );
            })
            .map_err(|source| ProdInitError::WorkerSpawn { source })?;

        let owner = ProdOwner { gate: Arc::clone(&gate), handle: Some(handle), ready };
        let view = ProdSubmitView { gate };
        Ok((owner, view))
    }

    /// Ordinary production entry (unwired; no caller).
    fn spawn_prod(
        config: &SingleThreadExecutionServiceConfig,
    ) -> Result<(ProdOwner, ProdSubmitView), ProdInitError> {
        spawn_prod_core(config, AuthoritySpec::Bound, || {})
    }

    // ------------------------------------------------------------------------
    // Test-only deterministic harness (pause/release, bypass, injected fault) and controls.
    // The DECISION under test is the production `prod_start_decision`; only timing/observation,
    // the enforcement bypass, and the guarded fault are test-gated.
    // ------------------------------------------------------------------------

    #[cfg(test)]
    struct ProdHarness {
        /// R201: the fixture body-fold label — DIAGNOSTIC only (before-decision rendezvous + state
        /// probe + denial correlation). It is NOT a validated admission key.
        occurrence_id: u64,
        /// R201: the VALIDATED generation-scoped admitted key, recorded by the production decision only
        /// on a real grant (0 = no checked grant: no validated key / a synthetic bypass / a denial).
        checked_key: AtomicU64,
        probe_sender: [u8; 32],
        expected_body: QbindBlock,
        bypass: AtomicBool,
        fault_armed: AtomicBool,
        reached_tx: crossbeam_channel::Sender<u64>,
        decision_release_rx: crossbeam_channel::Receiver<()>,
        dequeue_body_tx: crossbeam_channel::Sender<(u64, bool)>,
        grant_ack_tx: crossbeam_channel::Sender<u64>,
        denial_tx: crossbeam_channel::Sender<u64>,
        pre_effect_tx: crossbeam_channel::Sender<u64>,
        pre_effect_release_rx: crossbeam_channel::Receiver<()>,
        fault_witness_tx: crossbeam_channel::Sender<u64>,
        executor_entered_tx: crossbeam_channel::Sender<u64>,
        result_tx: crossbeam_channel::Sender<(u64, u64, u64, u64)>,
        state_probe_tx: crossbeam_channel::Sender<(u64, u64, u64)>,
        /// R202: the RAW decision classification recorded by the production decision at its actual
        /// source branch, BEFORE any enforcement-bypass rewrite — so the real outcome survives in the
        /// trace even when a synthetic bypass later emits a Grant.
        raw_class_tx: crossbeam_channel::Sender<DecisionClass>,
    }
    /// R202: the classification of the actual production decision branch (test-only observation; the
    /// production decision's return stays `StartOutcome`). Distinguishes matched cutoff, the several
    /// missing/unavailable-authority branches, and invalid-binding branches.
    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DecisionClass {
        Grant,
        CommittedCutoff,
        MissingAuthority,
        DeadGate,
        WrongGeneration,
        Poisoned,
        OneShot,
        NoOccurrence,
        OccurrenceMismatch,
    }
    #[cfg(test)]
    thread_local! {
        static PROD_HARNESS: std::cell::RefCell<Option<Arc<ProdHarness>>> =
            const { std::cell::RefCell::new(None) };
    }
    #[cfg(test)]
    fn install_prod_harness(h: Arc<ProdHarness>) {
        PROD_HARNESS.with(|c| *c.borrow_mut() = Some(h));
    }
    #[cfg(test)]
    fn current_harness() -> Option<Arc<ProdHarness>> {
        PROD_HARNESS.with(|c| c.borrow().clone())
    }
    /// R201 (test-only): the production decision calls this on a REAL grant to carry the validated
    /// generation-scoped admitted key to the grant/execution witnesses. A synthetic bypass or a denial
    /// never calls it, so `checked_key` stays 0 ("no checked grant").
    #[cfg(test)]
    fn record_checked_key(generation: u64) {
        if let Some(h) = current_harness() {
            h.checked_key.store(generation, Ordering::SeqCst);
        }
    }
    /// R202 (test-only): emit a branch classification to the harness channel (a gate-free thread-local
    /// send). R203: this is now invoked ONLY from `RawClassTrace::drop`, i.e. AFTER the decision frame's
    /// mutex guard and transient strong `Arc` have dropped, on every path.
    #[cfg(test)]
    fn record_raw_class(class: DecisionClass) {
        if let Some(h) = current_harness() {
            let _ = h.raw_class_tx.send(class);
        }
    }
    /// R203 (test-only): a function-scope trace that captures the decision's class at the real branch
    /// and DEFERS emission to `Drop`. Declared as the first local in `prod_start_decision`, it is
    /// destroyed LAST — strictly after the mutex guard and the transient strong `Arc` on every path,
    /// including early fail-closed denials. `Drop` skips emission while the thread is unwinding, so a
    /// panic is never recorded as a normal decision class. Absent from non-test builds.
    #[cfg(test)]
    struct RawClassTrace {
        pending: std::cell::Cell<Option<DecisionClass>>,
    }
    #[cfg(test)]
    impl RawClassTrace {
        fn new() -> Self {
            RawClassTrace { pending: std::cell::Cell::new(None) }
        }
        fn set(&self, class: DecisionClass) {
            self.pending.set(Some(class));
        }
    }
    #[cfg(test)]
    impl Drop for RawClassTrace {
        fn drop(&mut self) {
            if std::thread::panicking() {
                return; // never record a normal decision class during an unwind
            }
            if let Some(class) = self.pending.get() {
                record_raw_class(class);
            }
        }
    }

    /// Top-of-loop independent state probe (test builds only): real height + exercised-sender nonce.
    #[cfg(test)]
    pub(super) fn prod_state_probe_test_hook(current_height: u64, state: &super::InMemoryState) {
        if let Some(h) = current_harness() {
            let nonce = qbind_ledger::get_account_nonce(state, &h.probe_sender);
            let _ = h.state_probe_tx.send((h.occurrence_id, current_height, nonce));
        }
    }
    /// Deterministic timing ONLY: announce the real dequeue + the bound-body match, then block until
    /// the test releases the decision (so the test can commit — or not — the cutoff first).
    #[cfg(test)]
    pub(super) fn prod_decision_pause_test_hook(dequeued: &QbindBlock) {
        if let Some(h) = current_harness() {
            let _ = h.reached_tx.send(h.occurrence_id);
            let _ = h.dequeue_body_tx.send((h.occurrence_id, bodies_identical(dequeued, &h.expected_body)));
            if h.decision_release_rx.recv_timeout(FAILSAFE).is_err() {
                panic!("{}", R198_RENDEZVOUS_HARNESS_ERROR);
            }
        }
    }
    /// Enforcement-bypass discrimination (test builds only): with the IDENTICAL cutoff-first schedule,
    /// turn a production `Deny` into `Grant` to prove the zero-effect oracle has teeth. R201: this is a
    /// SYNTHETIC grant — the real production decision denied and recorded NO checked key, so the grant/
    /// execution witnesses below carry `checked_key == 0`, labelling the bypass as synthetic while the
    /// real outcome is retained.
    #[cfg(test)]
    pub(super) fn prod_maybe_bypass_test_hook(out: StartOutcome) -> StartOutcome {
        if let Some(h) = current_harness() {
            if h.bypass.load(Ordering::SeqCst) && matches!(out, StartOutcome::Deny) {
                return StartOutcome::Grant;
            }
        }
        out
    }
    /// R201: witness of the (possibly bypassed) production outcome. A grant emits the VALIDATED checked
    /// key (the generation recorded by the real decision; 0 for a synthetic bypass). A denial emits the
    /// diagnostic fixture label on the DENIAL channel — explicit invalid/unavailable identity, never a
    /// checked grant.
    #[cfg(test)]
    pub(super) fn prod_decision_observed_test_hook(out: StartOutcome) {
        if let Some(h) = current_harness() {
            match out {
                StartOutcome::Grant => {
                    let _ = h.grant_ack_tx.send(h.checked_key.load(Ordering::SeqCst));
                }
                StartOutcome::Deny => {
                    let _ = h.denial_tx.send(h.occurrence_id);
                }
                StartOutcome::Legacy => {}
            }
        }
    }
    /// Granted work held at the pre-effect rendezvous (test builds only); explicit release, then an
    /// opt-in guarded fault that unwinds BEFORE executor entry. R201: emits the checked key.
    #[cfg(test)]
    pub(super) fn prod_granted_pre_effect_test_hook() {
        if let Some(h) = current_harness() {
            let _ = h.pre_effect_tx.send(h.checked_key.load(Ordering::SeqCst));
            if h.pre_effect_release_rx.recv_timeout(FAILSAFE).is_err() {
                panic!("{}", R198_RENDEZVOUS_HARNESS_ERROR);
            }
            if h.fault_armed.load(Ordering::SeqCst) {
                let _ = h.fault_witness_tx.send(h.checked_key.load(Ordering::SeqCst));
                panic!("{}", R198_FAULT_MARKER);
            }
        }
    }
    /// Independent executor-ENTRY witness (test builds only). R201: emits the checked key.
    #[cfg(test)]
    pub(super) fn prod_executor_entry_test_hook() {
        if let Some(h) = current_harness() {
            let _ = h.executor_entered_tx.send(h.checked_key.load(Ordering::SeqCst));
        }
    }
    /// Independent execution-EFFECT witness, after the executor returned Ok (test builds only).
    /// R201: emits the checked key.
    #[cfg(test)]
    pub(super) fn prod_executor_result_test_hook(success_count: u64, error_count: u64, new_height: u64) {
        if let Some(h) = current_harness() {
            let _ = h.result_tx.send((
                h.checked_key.load(Ordering::SeqCst),
                success_count,
                error_count,
                new_height,
            ));
        }
    }

    #[cfg(test)]
    fn bodies_identical(a: &QbindBlock, b: &QbindBlock) -> bool {
        if a.block_id != b.block_id || a.parent_id != b.parent_id || a.view != b.view {
            return false;
        }
        if *a.proposal != *b.proposal {
            return false;
        }
        if a.txs.len() != b.txs.len() {
            return false;
        }
        a.txs
            .iter()
            .zip(b.txs.iter())
            .all(|(x, y)| x.sender == y.sender && x.nonce == y.nonce && x.payload == y.payload)
    }
    /// R201: FULL typed equality for refusal-custody assertions — the entire ordered decoded
    /// transaction vector INCLUDING decoded `signature.bytes` and `suite_id` (which `bodies_identical`
    /// omits), plus the full proposal and block metadata. A decoded-only difference (e.g. a substituted
    /// decoded signature or suite) with an unchanged raw proposal is caught here but NOT by
    /// `bodies_identical`.
    #[cfg(test)]
    fn bodies_fully_equal(a: &QbindBlock, b: &QbindBlock) -> bool {
        if a.block_id != b.block_id || a.parent_id != b.parent_id || a.view != b.view {
            return false;
        }
        if *a.proposal != *b.proposal {
            return false;
        }
        if a.txs.len() != b.txs.len() {
            return false;
        }
        a.txs.iter().zip(b.txs.iter()).all(|(x, y)| {
            x.sender == y.sender
                && x.nonce == y.nonce
                && x.payload == y.payload
                && x.signature.bytes == y.signature.bytes
                && x.suite_id == y.suite_id
        })
    }
    /// R201: a body identical to `base` EXCEPT the first decoded tx's signature bytes — the SAME raw
    /// proposal (shared `Arc`) and the same block self-id, differing only in a decoded field.
    #[cfg(test)]
    fn with_decoded_signature(base: &QbindBlock, sig: Vec<u8>) -> QbindBlock {
        let mut txs = base.txs.clone();
        assert!(!txs.is_empty(), "fixture body must have a tx");
        txs[0].signature.bytes = sig;
        QbindBlock::new(base.proposal.clone(), txs)
    }
    /// R201: a body identical to `base` EXCEPT the first decoded tx's suite id — same raw proposal/self-id.
    #[cfg(test)]
    fn with_decoded_suite(base: &QbindBlock, suite_id: u16) -> QbindBlock {
        let mut txs = base.txs.clone();
        assert!(!txs.is_empty(), "fixture body must have a tx");
        txs[0].suite_id = suite_id;
        QbindBlock::new(base.proposal.clone(), txs)
    }
    #[cfg(test)]
    fn encode_fixture_tx(tx: &super::QbindTransaction) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tx.sender);
        bytes.extend_from_slice(&tx.nonce.to_le_bytes());
        bytes.extend_from_slice(&(tx.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&tx.payload);
        bytes.extend_from_slice(&(tx.signature.bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&tx.signature.bytes);
        bytes.extend_from_slice(&tx.suite_id.to_le_bytes());
        bytes
    }
    /// One valid, coherent, state-changing NonceOnly body (fresh sender, nonce 0). `height` stays
    /// below `R198_COMMITTED_ID`'s byte so `block_id = [height;32]` is distinct from the committed id.
    /// Minimal synthetic proposal (mirrors the idle-close test helper).
    #[cfg(test)]
    fn make_r198_proposal(height: u64) -> Arc<BlockProposal> {
        Arc::new(BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1337,
                epoch: 0,
                height,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [height as u8; 32],
                proposer_index: 0,
                suite_id: 0,
                tx_count: 0,
                timestamp: 1704067200 + height,
                payload_kind: 0,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: Vec::new(),
            signature: Vec::new(),
        })
    }
    #[cfg(test)]
    fn state_changing_body(height: u64, sender_tag: u8) -> QbindBlock {
        let tx = super::QbindTransaction::new([sender_tag; 32], 0, b"r198-state-change".to_vec());
        let mut proposal = (*make_r198_proposal(height)).clone();
        proposal.header.tx_count = 1;
        proposal.txs = vec![encode_fixture_tx(&tx)];
        QbindBlock::new(Arc::new(proposal), vec![tx])
    }
    #[cfg(test)]
    fn drain_state_probes(
        rx: &crossbeam_channel::Receiver<(u64, u64, u64)>,
    ) -> Vec<(u64, u64, u64)> {
        let mut v = Vec::new();
        while let Ok(p) = rx.try_recv() {
            v.push(p);
        }
        v
    }
    #[cfg(test)]
    fn ordered_snapshots(
        probes: &[(u64, u64, u64)],
        occ: u64,
    ) -> Option<((u64, u64), (u64, u64))> {
        if probes.len() < 2 || !probes.iter().all(|(o, _, _)| *o == occ) {
            return None;
        }
        let first = probes.first().unwrap();
        let last = probes.last().unwrap();
        Some(((first.1, first.2), (last.1, last.2)))
    }

    /// R200: the witnessed occurrence key is DERIVED FROM THE FULL ORDERED EXECUTION-INPUT ENCODING of
    /// the actual bound work (a 64-bit FNV-1a fold over `occurrence_encoding`), NOT merely the block
    /// self-id — so two bodies that share a block self-id but carry different execution input get
    /// DISTINCT witness keys. Non-cryptographic; a witness label only, not a decision primitive.
    #[cfg(test)]
    fn witness_id(block: &QbindBlock) -> u64 {
        let enc = occurrence_encoding(block);
        let mut acc: u64 = 0xcbf29ce484222325;
        for b in &enc {
            acc ^= *b as u64;
            acc = acc.wrapping_mul(0x00000100000001b3);
        }
        acc
    }

    /// R200: distinct fixture ATTEMPT IDs for the separately-keyed refusal-custody controls — each
    /// pre-bound before its submit and distinct from any admitted occurrence key.
    #[cfg(test)]
    const R200_ATTEMPT_CUTOFF: u64 = 0xA77E_0C07;
    #[cfg(test)]
    const R200_ATTEMPT_LIFETIME: u64 = 0xA77E_11FE;
    #[cfg(test)]
    const R200_ATTEMPT_POISON: u64 = 0xA77E_9015;

    /// R199: the refusal disposition recorded for a non-admitted submit (distinct per refusal type).
    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RefusalDisposition {
        Cutoff,
        LifetimeExhausted,
        QueueFull,
        Poisoned,
    }
    /// R200 (R194 custody oracle, separately keyed): each refusal is bound to its own pre-submit fixture
    /// ATTEMPT ID (distinct from the admitted occurrence) with a RETAINED pre-submit reference copy; on
    /// refusal the RETURNED body is asserted byte-identical to that retained reference, the disposition
    /// is typed, and the fixture committed id is kept distinct from the body's own block id.
    #[cfg(test)]
    struct RefusedCustody {
        attempt_id: u64,
        committed_id: [u8; 32],
        reference: QbindBlock,
        returned: QbindBlock,
        disposition: RefusalDisposition,
    }
    #[cfg(test)]
    fn bind_refusal(attempt_id: u64, reference: QbindBlock, outcome: ProdSubmitOutcome) -> RefusedCustody {
        let (returned, disposition) = match outcome {
            ProdSubmitOutcome::ShuttingDown(b) => (b, RefusalDisposition::Cutoff),
            ProdSubmitOutcome::LifetimeExhausted(b) => (b, RefusalDisposition::LifetimeExhausted),
            ProdSubmitOutcome::QueueFull(b) => (b, RefusalDisposition::QueueFull),
            ProdSubmitOutcome::Poisoned(b) => (b, RefusalDisposition::Poisoned),
            ProdSubmitOutcome::Admitted => panic!("Admitted is not a refusal"),
        };
        RefusedCustody { attempt_id, committed_id: R198_COMMITTED_ID, reference, returned, disposition }
    }

    /// R199/R200 test-only owner accessors: a gate handle for genuine-poison injection, the gate's
    /// generation, and a tamper of the stored occurrence binding so the PRODUCTION decision's binding
    /// comparison can be exercised with a VALID authority/gate/generation (mismatched or missing work).
    #[cfg(test)]
    impl ProdOwner {
        fn gate_arc(&self) -> Arc<SupervisedProdGate> {
            Arc::clone(&self.gate)
        }
        fn gate_generation(&self) -> u64 {
            self.gate.generation
        }
        fn test_force_occurrence(&self, occ: Option<OccurrenceBinding>) {
            let mut inner = self.gate.inner.lock().unwrap();
            inner.occurrence = occ;
        }
    }

    /// R200 test-only fault: admit (enqueue) `work` but bind the occurrence to `bound_ref`'s EXACT
    /// execution-input encoding instead — modelling a dequeued body whose ordered execution input
    /// differs from the admitted reference while (optionally) sharing the block self-id. The PRODUCTION
    /// decision then re-derives the dequeued encoding and must DENY. This fault cannot arise from the
    /// production `submit` (which binds exactly what it enqueues); it is injected only in tests.
    #[cfg(test)]
    impl ProdSubmitView {
        fn test_admit_with_mismatched_binding(
            &self,
            work: QbindBlock,
            bound_ref: &QbindBlock,
        ) -> ProdSubmitOutcome {
            let mut inner = self.gate.inner.lock().unwrap();
            if inner.closed || inner.sender.is_none() {
                return ProdSubmitOutcome::ShuttingDown(work);
            }
            if inner.admissions_used >= 1 {
                return ProdSubmitOutcome::LifetimeExhausted(work);
            }
            let bound = OccurrenceBinding {
                generation: self.gate.generation,
                encoding: occurrence_encoding(bound_ref),
            };
            let task = ExecTask { block: work, submitted_at: Instant::now() };
            match inner.sender.as_ref().unwrap().try_send(task) {
                Ok(()) => {
                    inner.admissions_used += 1;
                    inner.occurrence = Some(bound);
                    ProdSubmitOutcome::Admitted
                }
                Err(TrySendError::Full(t)) => ProdSubmitOutcome::QueueFull(t.block),
                Err(TrySendError::Disconnected(t)) => ProdSubmitOutcome::ShuttingDown(t.block),
            }
        }
    }

    #[cfg(test)]
    struct ProdEnds {
        reached_rx: crossbeam_channel::Receiver<u64>,
        decision_release_tx: crossbeam_channel::Sender<()>,
        dequeue_body_rx: crossbeam_channel::Receiver<(u64, bool)>,
        grant_ack_rx: crossbeam_channel::Receiver<u64>,
        denial_rx: crossbeam_channel::Receiver<u64>,
        pre_effect_rx: crossbeam_channel::Receiver<u64>,
        pre_effect_release_tx: crossbeam_channel::Sender<()>,
        fault_witness_rx: crossbeam_channel::Receiver<u64>,
        executor_entered_rx: crossbeam_channel::Receiver<u64>,
        result_rx: crossbeam_channel::Receiver<(u64, u64, u64, u64)>,
        state_probe_rx: crossbeam_channel::Receiver<(u64, u64, u64)>,
        raw_class_rx: crossbeam_channel::Receiver<DecisionClass>,
    }
    /// R199: `occurrence_id` is DERIVED from `expected_body` (the real bound work), not supplied by
    /// the caller — so every witness is keyed to the actual occurrence binding.
    #[cfg(test)]
    fn new_prod_harness(probe_sender: [u8; 32], expected_body: QbindBlock) -> (Arc<ProdHarness>, ProdEnds) {
        let occurrence_id = witness_id(&expected_body);
        let (reached_tx, reached_rx) = crossbeam_channel::unbounded::<u64>();
        let (decision_release_tx, decision_release_rx) = crossbeam_channel::unbounded::<()>();
        let (dequeue_body_tx, dequeue_body_rx) = crossbeam_channel::unbounded::<(u64, bool)>();
        let (grant_ack_tx, grant_ack_rx) = crossbeam_channel::unbounded::<u64>();
        let (denial_tx, denial_rx) = crossbeam_channel::unbounded::<u64>();
        let (pre_effect_tx, pre_effect_rx) = crossbeam_channel::unbounded::<u64>();
        let (pre_effect_release_tx, pre_effect_release_rx) = crossbeam_channel::unbounded::<()>();
        let (fault_witness_tx, fault_witness_rx) = crossbeam_channel::unbounded::<u64>();
        let (executor_entered_tx, executor_entered_rx) = crossbeam_channel::unbounded::<u64>();
        let (result_tx, result_rx) = crossbeam_channel::unbounded::<(u64, u64, u64, u64)>();
        let (state_probe_tx, state_probe_rx) = crossbeam_channel::unbounded::<(u64, u64, u64)>();
        let (raw_class_tx, raw_class_rx) = crossbeam_channel::unbounded::<DecisionClass>();
        let h = Arc::new(ProdHarness {
            occurrence_id,
            checked_key: AtomicU64::new(0),
            probe_sender,
            expected_body,
            bypass: AtomicBool::new(false),
            fault_armed: AtomicBool::new(false),
            reached_tx,
            decision_release_rx,
            dequeue_body_tx,
            grant_ack_tx,
            denial_tx,
            pre_effect_tx,
            pre_effect_release_rx,
            fault_witness_tx,
            executor_entered_tx,
            result_tx,
            state_probe_tx,
            raw_class_tx,
        });
        let ends = ProdEnds {
            reached_rx,
            decision_release_tx,
            dequeue_body_rx,
            grant_ack_rx,
            denial_rx,
            pre_effect_rx,
            pre_effect_release_tx,
            fault_witness_rx,
            executor_entered_rx,
            result_rx,
            state_probe_rx,
            raw_class_rx,
        };
        (h, ends)
    }
    #[cfg(test)]
    fn spawn_prod_gated(
        config: &SingleThreadExecutionServiceConfig,
        harness: Arc<ProdHarness>,
    ) -> Result<(ProdOwner, ProdSubmitView), ProdInitError> {
        spawn_prod_core(config, AuthoritySpec::Bound, move || install_prod_harness(harness))
    }
    /// Like `spawn_prod_gated` but installs an authority bound to a WRONG generation, so the
    /// production decision fails closed on the inconsistent-occurrence check.
    #[cfg(test)]
    fn spawn_prod_gated_wrong_generation(
        config: &SingleThreadExecutionServiceConfig,
        harness: Arc<ProdHarness>,
    ) -> Result<(ProdOwner, ProdSubmitView), ProdInitError> {
        spawn_prod_core(config, AuthoritySpec::Generation(u64::MAX), move || {
            install_prod_harness(harness)
        })
    }
    /// R199: candidate mode entered but NO authority installed — the decision must fail closed (Deny),
    /// NOT fall back to legacy execution. Distinct from a dead `Weak`.
    #[cfg(test)]
    fn spawn_prod_gated_absent_authority(
        config: &SingleThreadExecutionServiceConfig,
        harness: Arc<ProdHarness>,
    ) -> Result<(ProdOwner, ProdSubmitView), ProdInitError> {
        spawn_prod_core(config, AuthoritySpec::Absent, move || install_prod_harness(harness))
    }
    #[cfg(test)]
    fn r198_config() -> SingleThreadExecutionServiceConfig {
        // Default is memory-only NonceOnly (state_dir None).
        SingleThreadExecutionServiceConfig::default()
    }

    // ------------------------------------------------------------------------
    // Acceptance controls (test-only). Each exercises the REAL production
    // `prod_start_decision` compiled in this build. R202: the decision records
    // its RAW branch classification (DecisionClass) at the actual source branch
    // BEFORE any enforcement-bypass rewrite — so matched cutoff, the several
    // missing/unavailable-authority branches, and invalid-binding branches are
    // distinct, and the real outcome survives a synthetic bypass. Grant/
    // execution witnesses carry the validated generation checked key; diagnostic
    // body labels stay distinct from it.
    // ------------------------------------------------------------------------

    /// P0 — zero admission: no submit; the distinct owner cutoff closes admission; readiness + join.
    #[cfg(test)]
    #[test]
    fn r198_p0_zero_admission_close_then_join() {
        let (gate_h, _ends) = new_prod_harness([0xE0u8; 32], state_changing_body(3, 0xE0));
        let (mut owner, _view) = spawn_prod_gated(&r198_config(), gate_h).expect("spawn");
        assert!(owner.sender_present() && !owner.is_closed() && owner.admissions_used() == 0);
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        assert!(owner.is_closed() && !owner.sender_present());
        assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
    }

    /// P1 — denied post-cutoff + R202 Row-2: the SAME schedule carries the RAW cutoff denial AND the
    /// synthetic bypass execution. Schedule 1 (no bypass): real decision denies on committed cutoff
    /// (`DecisionClass::CommittedCutoff`), zero effect, ordered `(0,0)→(0,0)`. Schedule 2 (bypass): the
    /// real decision ALSO classifies `CommittedCutoff` (recorded before the rewrite), while the
    /// synthetic grant/execution observations carry the synthetic checked key `0` and a real effect
    /// `(7,1)`. The two identical-body workers (`occ == occ2`) occupy distinct generations.
    #[cfg(test)]
    #[test]
    fn r198_p1_denied_post_cutoff_no_effect() {
        let canonical = state_changing_body(7, 0xA1);
        assert_eq!(canonical.block_id, [7u8; 32]);
        let occ = witness_id(&canonical);
        let (h, ends) = new_prod_harness([0xA1u8; 32], canonical.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        let gen1 = owner.gate_generation();
        assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(owner.admissions_used(), 1);
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("dequeue reached"), occ);
        assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("body match"), (occ, true));
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        assert!(!owner.sender_present());
        ends.decision_release_tx.send(()).expect("release decision");
        assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("worker Deny"), occ);
        let rc1 = ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class");
        println!("[R203-TRACE] cutoff(sched1) raw_class={:?} checked_grant=none effect=none", rc1);
        assert_eq!(rc1, DecisionClass::CommittedCutoff, "sched1 raw decision = matched cutoff");
        assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
        assert!(ends.executor_entered_rx.try_recv().is_err(), "zero executor entry");
        assert!(ends.result_rx.try_recv().is_err(), "zero effect");
        assert!(ends.grant_ack_rx.try_recv().is_err(), "no grant");
        let probes = drain_state_probes(&ends.state_probe_rx);
        assert!(ordered_snapshots(&probes[..1], occ).is_none(), "baseline-only rejected");
        let (init, fin) = ordered_snapshots(&probes, occ).expect("ordered snapshots");
        assert_eq!((init, fin), ((0, 0), (0, 0)), "denied: baseline and final both unchanged");

        // Schedule 2: identical body + cutoff-first, enforcement bypassed. Row 2 — the raw decision
        // still classifies CommittedCutoff (recorded before the rewrite), the bypass grant/execution
        // carry the synthetic checked key 0, and the effect is real.
        let body2 = state_changing_body(7, 0xA1);
        let occ2 = witness_id(&body2);
        assert_eq!(occ, occ2, "identical bodies share the diagnostic fold");
        let (h2, ends2) = new_prod_harness([0xA1u8; 32], body2.clone());
        h2.bypass.store(true, Ordering::SeqCst);
        let (mut owner2, view2) = spawn_prod_gated(&r198_config(), h2).expect("spawn");
        let gen2 = owner2.gate_generation();
        assert_ne!(gen1, gen2, "identical bodies occupy DISTINCT generations");
        assert!(matches!(view2.submit(body2.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(ends2.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ2);
        assert_eq!(ends2.dequeue_body_rx.recv_timeout(FAILSAFE).expect("body"), (occ2, true));
        assert_eq!(owner2.close_admission(), ProdCloseOutcome::Closed);
        ends2.decision_release_tx.send(()).expect("release");
        let key2 = ends2.grant_ack_rx.recv_timeout(FAILSAFE).expect("bypass grants");
        let rc2 = ends2.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class");
        assert_eq!(key2, 0, "synthetic (no checked key)");
        assert_eq!(rc2, DecisionClass::CommittedCutoff, "sched2 RAW decision = matched cutoff (survives the bypass rewrite)");
        assert_eq!(ends2.pre_effect_rx.recv_timeout(FAILSAFE).expect("held"), 0);
        ends2.pre_effect_release_tx.send(()).expect("release pre-effect");
        assert_eq!(ends2.executor_entered_rx.recv_timeout(FAILSAFE).expect("entered"), 0);
        let (ro, s, e, ht) = ends2.result_rx.recv_timeout(FAILSAFE).expect("effect");
        println!("[R203-TRACE] cutoff+bypass(sched2) raw_class={:?} synthetic_grant_key={} effect=(nonce={},height={})", rc2, key2, s, ht);
        assert_eq!((ro, s, e, ht), (0, 1, 0, 7), "synthetic key, real effect");
        assert_eq!(owner2.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner2.join(), ProdJoin::Terminated(ProdTerm::Normal));
        let probes2 = drain_state_probes(&ends2.state_probe_rx);
        let (i2, f2) = ordered_snapshots(&probes2, occ2).expect("ordered");
        assert_eq!((i2, f2), ((0, 0), (7, 1)), "bypass: baseline unchanged, final real nonce/height");
    }

    /// P2 — grant before cutoff: REAL grant (`DecisionClass::Grant`); grant/execution witnesses carry
    /// the validated checked key (`== gate_generation()`, `!= occ`); executes after cutoff, `(2,1)`.
    #[cfg(test)]
    #[test]
    fn r198_p2_grant_before_cutoff_executes_after_cutoff() {
        let canonical = state_changing_body(2, 0xB2);
        let occ = witness_id(&canonical);
        let (h, ends) = new_prod_harness([0xB2u8; 32], canonical.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        let gen = owner.gate_generation();
        assert_ne!(gen, occ, "checked key (generation) differs from the diagnostic body fold");
        assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
        assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("body"), (occ, true));
        ends.decision_release_tx.send(()).expect("release decision pre-cutoff");
        assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("granted on checked key"), gen);
        assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::Grant);
        assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held"), gen);
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        assert!(!owner.sender_present());
        ends.pre_effect_release_tx.send(()).expect("release pre-effect");
        assert_eq!(ends.executor_entered_rx.recv_timeout(FAILSAFE).expect("entered after cutoff"), gen);
        let (ro, s, e, ht) = ends.result_rx.recv_timeout(FAILSAFE).expect("effect");
        assert_eq!((ro, s, e, ht), (gen, 1, 0, 2));
        assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
        let probes = drain_state_probes(&ends.state_probe_rx);
        let (i, f) = ordered_snapshots(&probes, occ).expect("ordered");
        assert_eq!((i, f), ((0, 0), (2, 1)));
    }

    /// P3 — fresh submit after the owner cutoff is refused (`ShuttingDown`), no second dequeue; the raw
    /// decision of the admitted occurrence is matched cutoff. Separately-keyed FULL-equality custody.
    #[cfg(test)]
    #[test]
    fn r198_p3_late_submit_after_cutoff_refused() {
        let canonical = state_changing_body(5, 0xC3);
        let occ = witness_id(&canonical);
        let (h, ends) = new_prod_harness([0xC3u8; 32], canonical.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        let reference = state_changing_body(5, 0xC3);
        let cust = bind_refusal(R200_ATTEMPT_CUTOFF, reference.clone(), view.submit(reference.clone()));
        assert_eq!(cust.attempt_id, R200_ATTEMPT_CUTOFF);
        assert_ne!(cust.attempt_id, occ, "attempt id distinct from the admitted occurrence");
        assert_eq!(cust.disposition, RefusalDisposition::Cutoff);
        assert!(bodies_fully_equal(&cust.returned, &cust.reference), "returned == retained reference (full decoded equality)");
        assert!(bodies_fully_equal(&cust.returned, &reference));
        assert_ne!(cust.committed_id, cust.returned.block_id, "committed id distinct from block id");
        ends.decision_release_tx.send(()).expect("release");
        assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny"), occ);
        assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::CommittedCutoff);
        assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
        assert!(ends.reached_rx.try_recv().is_err(), "no second dequeue");
        assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
    }

    /// P4 — explicit lifetime admission limit: second OPEN submit → `LifetimeExhausted` (full-equality
    /// custody); the first occurrence grants (`DecisionClass::Grant`) and executes on the checked key.
    #[cfg(test)]
    #[test]
    fn r198_p4_lifetime_admission_limit_after_dequeue() {
        let canonical = state_changing_body(4, 0xD4);
        let occ = witness_id(&canonical);
        let (h, ends) = new_prod_harness([0xD4u8; 32], canonical.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        let gen = owner.gate_generation();
        assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
        assert!(!owner.is_closed(), "admission still open");
        assert_eq!(owner.sender_present(), true);
        let reference = state_changing_body(4, 0xD4);
        let cust = bind_refusal(R200_ATTEMPT_LIFETIME, reference.clone(), view.submit(reference.clone()));
        assert_eq!(cust.attempt_id, R200_ATTEMPT_LIFETIME);
        assert_ne!(cust.attempt_id, occ, "attempt id distinct from the admitted occurrence");
        assert_eq!(cust.disposition, RefusalDisposition::LifetimeExhausted);
        assert!(bodies_fully_equal(&cust.returned, &cust.reference), "returned == retained reference (full decoded equality)");
        assert_ne!(cust.committed_id, cust.returned.block_id, "committed id distinct from block id");
        assert_eq!(owner.admissions_used(), 1);
        ends.decision_release_tx.send(()).expect("release");
        assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("granted"), gen);
        assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::Grant);
        assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held"), gen);
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        ends.pre_effect_release_tx.send(()).expect("release pre-effect");
        let (ro, s, _e, ht) = ends.result_rx.recv_timeout(FAILSAFE).expect("effect");
        assert_eq!((ro, s, ht), (gen, 1, 4));
        assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
    }

    /// P5 — idle disconnect WITHOUT the owner cutoff → disconnect → real join.
    #[cfg(test)]
    #[test]
    fn r198_p5_idle_disconnect_without_close() {
        let (h, _ends) = new_prod_harness([0xD5u8; 32], state_changing_body(5, 0xD5));
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        let ready_probe = Arc::clone(&owner.ready);
        let handle = owner.handle.take().expect("handle");
        assert!(owner.sender_present());
        drop(owner);
        drop(view);
        assert!(ready_probe.wait(FAILSAFE), "idle disconnect wakes the parked worker");
        assert!(handle.join().is_ok(), "real normal join");
    }

    /// P6 — bounded wait + termination class on granted work. Normal + panic: both are REAL grants
    /// (`DecisionClass::Grant`); grant/execution/fault witnesses carry the checked key.
    #[cfg(test)]
    #[test]
    fn r198_p6_bounded_wait_then_termination_normal_and_panic() {
        // Normal.
        {
            let canonical = state_changing_body(5, 0xA4);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xA4u8; 32], canonical.clone());
            let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
            let gen = owner.gate_generation();
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("granted"), gen);
            assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::Grant);
            assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held"), gen);
            assert_eq!(owner.observe_ready(Duration::from_millis(100)), ProdReadiness::Pending);
            assert!(owner.handle.is_some(), "original handle retained");
            assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
            ends.pre_effect_release_tx.send(()).expect("release pre-effect");
            assert_eq!(ends.executor_entered_rx.recv_timeout(FAILSAFE).expect("entered"), gen);
            let (ro, s, _e, ht) = ends.result_rx.recv_timeout(FAILSAFE).expect("effect");
            assert_eq!((ro, s, ht), (gen, 1, 5));
            assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
            assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
        }
        // Panic (opt-in guarded fault).
        {
            let canonical = state_changing_body(6, 0xA5);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xA5u8; 32], canonical.clone());
            h.fault_armed.store(true, Ordering::SeqCst);
            let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
            let gen = owner.gate_generation();
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.grant_ack_rx.recv_timeout(FAILSAFE).expect("granted"), gen);
            assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::Grant);
            assert_eq!(ends.pre_effect_rx.recv_timeout(FAILSAFE).expect("held"), gen);
            assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
            ends.pre_effect_release_tx.send(()).expect("release pre-effect");
            assert_eq!(ends.fault_witness_rx.recv_timeout(FAILSAFE).expect("fault fired"), gen);
            assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
            assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Panic));
            assert!(ends.executor_entered_rx.try_recv().is_err(), "no executor entry");
            assert!(ends.result_rx.try_recv().is_err(), "no effect");
            assert_eq!(owner.join(), ProdJoin::AlreadyJoined);
        }
    }

    /// P7 — fail-closed outcomes with R202 DISTINCT classifications: (a) wrong generation →
    /// `WrongGeneration`; (b) dead `Weak` → `DeadGate`; (c) candidate mode, authority NOT installed →
    /// `MissingAuthority`. Each: Deny, no entry/effect, NO checked grant.
    #[cfg(test)]
    #[test]
    fn r198_p7_fail_closed_missing_and_inconsistent() {
        // (a) inconsistent occurrence (wrong generation).
        {
            let canonical = state_changing_body(7, 0xF7);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xF7u8; 32], canonical.clone());
            let (mut owner, view) = spawn_prod_gated_wrong_generation(&r198_config(), h).expect("spawn");
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (wrong generation)"), occ);
            assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::WrongGeneration);
            assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
            assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
            assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
            assert!(ends.executor_entered_rx.try_recv().is_err(), "no entry");
            assert!(ends.result_rx.try_recv().is_err(), "no effect");
            assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
        }
        // (b) dead Weak (gate dropped before the decision reads it).
        {
            let canonical = state_changing_body(7, 0xF8);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xF8u8; 32], canonical.clone());
            let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
            let ready_probe = Arc::clone(&owner.ready);
            let handle = owner.handle.take().expect("handle");
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            drop(owner);
            drop(view);
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (dead Weak)"), occ);
            assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::DeadGate);
            assert!(ready_probe.wait(FAILSAFE), "worker exits after fail-closed deny");
            assert!(handle.join().is_ok(), "real normal join");
            assert!(ends.executor_entered_rx.try_recv().is_err(), "no entry");
            assert!(ends.result_rx.try_recv().is_err(), "no effect");
            assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
        }
        // (c) candidate mode, authority NOT installed → MissingAuthority (never legacy fallback).
        {
            let canonical = state_changing_body(7, 0xF9);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xF9u8; 32], canonical.clone());
            let (mut owner, view) = spawn_prod_gated_absent_authority(&r198_config(), h).expect("spawn");
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (absent authority)"), occ);
            let rc = ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class");
            let checked = ends.grant_ack_rx.try_recv().ok();
            println!("[R203-TRACE] missing-authority raw_class={:?} checked_grant={:?} effect=none", rc, checked);
            assert_eq!(rc, DecisionClass::MissingAuthority);
            assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
            assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
            assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
            assert!(ends.executor_entered_rx.try_recv().is_err(), "no entry");
            assert!(ends.result_rx.try_recv().is_err(), "no effect");
            assert!(checked.is_none(), "no checked grant");
        }
    }

    /// P8 — occurrence binding mismatch (generic): valid gate, binding tamper-forced to (a) a different
    /// encoding → `OccurrenceMismatch`, and (b) `None` → `NoOccurrence`. Each Deny, no entry/effect,
    /// no checked grant.
    #[cfg(test)]
    #[test]
    fn r198_p8_occurrence_binding_mismatch_denied() {
        // (a) mismatched occurrence encoding.
        {
            let canonical = state_changing_body(8, 0xE8);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xE8u8; 32], canonical.clone());
            let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("body"), (occ, true));
            owner.test_force_occurrence(Some(OccurrenceBinding {
                generation: owner.gate_generation(),
                encoding: vec![0xAAu8; 8],
            }));
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (mismatched encoding)"), occ);
            assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::OccurrenceMismatch);
            assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
            assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
            assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
            assert!(ends.executor_entered_rx.try_recv().is_err(), "no entry");
            assert!(ends.result_rx.try_recv().is_err(), "no effect");
            assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
        }
        // (b) missing work evidence (binding forced to None) with a valid gate.
        {
            let canonical = state_changing_body(8, 0xE7);
            let occ = witness_id(&canonical);
            let (h, ends) = new_prod_harness([0xE7u8; 32], canonical.clone());
            let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
            assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
            assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
            owner.test_force_occurrence(None);
            ends.decision_release_tx.send(()).expect("release");
            assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (missing work evidence)"), occ);
            assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::NoOccurrence);
            assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
            assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
            assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
            assert!(ends.executor_entered_rx.try_recv().is_err(), "no entry");
            assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
        }
    }

    /// P9 — genuine poison → production decision poison arm (`DecisionClass::Poisoned`) → Deny, safe
    /// teardown + observed join; typed `Poisoned` owner cutoff + submit; custody full-equal.
    #[cfg(test)]
    #[test]
    fn r198_p9_poison_fail_closed_and_typed_refusals() {
        let canonical = state_changing_body(9, 0xE9);
        let occ = witness_id(&canonical);
        let (h, ends) = new_prod_harness([0xE9u8; 32], canonical.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        let gate = owner.gate_arc();
        let ready_probe = Arc::clone(&owner.ready);
        let handle = owner.handle.take().expect("handle");
        assert!(matches!(view.submit(canonical.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
        let gate_poison = Arc::clone(&gate);
        let _ = std::thread::spawn(move || {
            let _g = gate_poison.inner.lock().unwrap();
            panic!("R199-INTENTIONAL-GATE-POISON");
        })
        .join();
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Poisoned);
        let reference = state_changing_body(9, 0xE9);
        let cust = bind_refusal(R200_ATTEMPT_POISON, reference.clone(), view.submit(reference.clone()));
        assert_eq!(cust.attempt_id, R200_ATTEMPT_POISON);
        assert_ne!(cust.attempt_id, occ, "attempt id distinct from the admitted occurrence");
        assert_eq!(cust.disposition, RefusalDisposition::Poisoned);
        assert!(bodies_fully_equal(&cust.returned, &cust.reference), "returned == retained reference (full decoded equality)");
        assert_ne!(cust.committed_id, cust.returned.block_id, "committed id distinct from block id");
        ends.decision_release_tx.send(()).expect("release");
        assert_eq!(ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (poison)"), occ);
        assert_eq!(ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class"), DecisionClass::Poisoned);
        drop(view);
        drop(gate);
        drop(owner);
        assert!(ready_probe.wait(FAILSAFE), "worker exits after fail-closed poison deny");
        assert!(handle.join().is_ok(), "observed normal join");
        assert!(ends.executor_entered_rx.try_recv().is_err(), "no entry");
        assert!(ends.result_rx.try_recv().is_err(), "no effect");
        assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
    }

    /// P10 — same-self-id / different-execution-input denial: valid authority + open gate; the raw
    /// decision classifies `OccurrenceMismatch` (invalid binding, NOT a matched cutoff / missing
    /// authority), B emits NO checked grant, zero entry/result, baseline+final `(0,0)`.
    #[cfg(test)]
    #[test]
    fn r200_p10_same_self_id_different_input_denied() {
        let admitted_ref = state_changing_body(8, 0xC1); // bound reference A
        let work = state_changing_body(8, 0xC2); // dequeued work B
        assert_eq!(admitted_ref.block_id, [8u8; 32]);
        assert_eq!(work.block_id, admitted_ref.block_id, "SAME block self-id");
        assert_ne!(
            occurrence_encoding(&admitted_ref),
            occurrence_encoding(&work),
            "DIFFERENT ordered execution input"
        );
        let occ = witness_id(&work);
        let (h, ends) = new_prod_harness([0xC2u8; 32], work.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        assert!(matches!(
            view.test_admit_with_mismatched_binding(work.clone(), &admitted_ref),
            ProdSubmitOutcome::Admitted
        ));
        assert_eq!(ends.reached_rx.recv_timeout(FAILSAFE).expect("reached"), occ);
        assert_eq!(ends.dequeue_body_rx.recv_timeout(FAILSAFE).expect("body"), (occ, true));
        assert!(!owner.is_closed(), "gate still open");
        assert_eq!(owner.sender_present(), true);
        ends.decision_release_tx.send(()).expect("release");
        assert_eq!(
            ends.denial_rx.recv_timeout(FAILSAFE).expect("Deny (same self-id, different input)"),
            occ
        );
        let rc = ends.raw_class_rx.recv_timeout(FAILSAFE).expect("raw class");
        let checked = ends.grant_ack_rx.try_recv().ok();
        println!("[R203-TRACE] mismatch raw_class={:?} checked_grant={:?} effect=none", rc, checked);
        assert_eq!(rc, DecisionClass::OccurrenceMismatch, "invalid binding, not a matched cutoff / missing authority");
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        assert_eq!(owner.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner.join(), ProdJoin::Terminated(ProdTerm::Normal));
        assert!(ends.executor_entered_rx.try_recv().is_err(), "zero executor entry");
        assert!(ends.result_rx.try_recv().is_err(), "zero effect");
        assert!(checked.is_none(), "B never emits a checked grant");
        let probes = drain_state_probes(&ends.state_probe_rx);
        let (init, fin) = ordered_snapshots(&probes, occ).expect("ordered snapshots");
        assert_eq!((init, fin), ((0, 0), (0, 0)), "denied: baseline and final nonce/height unchanged");
    }

    /// P11 — R201 refusal-custody full-equality sensitivity (decoded signature + suite id) with the raw
    /// proposal unchanged, and a real cutoff refusal returning the exact signature-variant body.
    #[cfg(test)]
    #[test]
    fn r201_p11_refusal_custody_full_decoded_equality() {
        let base = state_changing_body(11, 0xB1);
        let sig_variant = with_decoded_signature(&base, vec![0x5Au8, 0xA5u8]);
        let suite_variant = with_decoded_suite(&base, base.txs[0].suite_id ^ 0x1);
        assert_eq!(sig_variant.block_id, base.block_id);
        assert_eq!(suite_variant.block_id, base.block_id);
        assert!(*base.proposal == *sig_variant.proposal, "raw proposal unchanged (sig variant)");
        assert!(*base.proposal == *suite_variant.proposal, "raw proposal unchanged (suite variant)");
        assert!(bodies_identical(&base, &sig_variant), "bodies_identical is blind to a decoded signature difference");
        assert!(!bodies_fully_equal(&base, &sig_variant), "bodies_fully_equal catches the decoded signature difference");
        assert!(bodies_identical(&base, &suite_variant), "bodies_identical is blind to a decoded suite difference");
        assert!(!bodies_fully_equal(&base, &suite_variant), "bodies_fully_equal catches the decoded suite difference");

        let (h, ends) = new_prod_harness([0xB1u8; 32], base.clone());
        let (mut owner, view) = spawn_prod_gated(&r198_config(), h).expect("spawn");
        let handle = owner.handle.take().expect("handle");
        let ready_probe = Arc::clone(&owner.ready);
        assert_eq!(owner.close_admission(), ProdCloseOutcome::Closed);
        let cust = bind_refusal(0xA77E_51A0u64, sig_variant.clone(), view.submit(sig_variant.clone()));
        assert_eq!(cust.disposition, RefusalDisposition::Cutoff);
        assert_ne!(cust.attempt_id, witness_id(&base), "attempt id distinct from the body fold");
        assert!(bodies_fully_equal(&cust.returned, &cust.reference), "returned == retained variant reference (full)");
        assert!(bodies_fully_equal(&cust.returned, &sig_variant));
        assert!(!bodies_fully_equal(&cust.returned, &base), "returned is NOT the base: decoded signature preserved");
        assert!(bodies_identical(&cust.returned, &base), "self-id/proposal/decoded-core still match the base");
        assert_ne!(cust.committed_id, cust.returned.block_id, "committed id distinct from block id");
        drop(view);
        assert!(ready_probe.wait(FAILSAFE), "idle disconnect wakes the worker");
        assert!(handle.join().is_ok(), "real normal join");
        assert!(ends.reached_rx.try_recv().is_err(), "no dequeue");
        assert!(ends.grant_ack_rx.try_recv().is_err(), "no checked grant");
    }

    /// P12 — R202 Row-1: two INDEPENDENT candidate workers given the SAME EXACT body both reach a real
    /// Grant; each emitted checked key equals its own validated worker generation, the two keys DIFFER
    /// (even though the bodies — and the diagnostic fold `occ` — are identical), and each real effect
    /// carries its own worker's key. This is the distinguishable-checked-observation evidence R201 left
    /// open (R201's P1 produced a denial + a synthetic bypass, not two real grants).
    #[cfg(test)]
    #[test]
    fn r202_p12_equal_bodies_distinct_checked_grants() {
        let body = state_changing_body(12, 0xC2);
        let occ = witness_id(&body);
        // Worker A.
        let (ha, ends_a) = new_prod_harness([0xC2u8; 32], body.clone());
        let (mut owner_a, view_a) = spawn_prod_gated(&r198_config(), ha).expect("spawn A");
        let gen_a = owner_a.gate_generation();
        // Worker B (same exact body).
        let (hb, ends_b) = new_prod_harness([0xC2u8; 32], body.clone());
        let (mut owner_b, view_b) = spawn_prod_gated(&r198_config(), hb).expect("spawn B");
        let gen_b = owner_b.gate_generation();
        assert_ne!(gen_a, gen_b, "two workers occupy distinct generations");
        // Both admit the SAME exact body.
        assert!(matches!(view_a.submit(body.clone()), ProdSubmitOutcome::Admitted));
        assert!(matches!(view_b.submit(body.clone()), ProdSubmitOutcome::Admitted));
        assert_eq!(ends_a.reached_rx.recv_timeout(FAILSAFE).expect("A reached"), occ);
        assert_eq!(ends_b.reached_rx.recv_timeout(FAILSAFE).expect("B reached"), occ);
        assert_eq!(ends_a.dequeue_body_rx.recv_timeout(FAILSAFE).expect("A body"), (occ, true));
        assert_eq!(ends_b.dequeue_body_rx.recv_timeout(FAILSAFE).expect("B body"), (occ, true));
        // Release both decisions on an OPEN gate → two REAL grants.
        ends_a.decision_release_tx.send(()).expect("release A");
        ends_b.decision_release_tx.send(()).expect("release B");
        let key_a = ends_a.grant_ack_rx.recv_timeout(FAILSAFE).expect("A grants");
        let key_b = ends_b.grant_ack_rx.recv_timeout(FAILSAFE).expect("B grants");
        assert_eq!(key_a, gen_a, "A's checked key == A's validated generation");
        assert_eq!(key_b, gen_b, "B's checked key == B's validated generation");
        assert_ne!(key_a, key_b, "equal bodies yield DISTINGUISHABLE checked observations");
        assert_eq!(ends_a.raw_class_rx.recv_timeout(FAILSAFE).expect("A raw"), DecisionClass::Grant);
        assert_eq!(ends_b.raw_class_rx.recv_timeout(FAILSAFE).expect("B raw"), DecisionClass::Grant);
        assert_eq!(ends_a.pre_effect_rx.recv_timeout(FAILSAFE).expect("A held"), gen_a);
        assert_eq!(ends_b.pre_effect_rx.recv_timeout(FAILSAFE).expect("B held"), gen_b);
        // Let each execute; each effect corresponds to its own key.
        ends_a.pre_effect_release_tx.send(()).expect("release A pre-effect");
        ends_b.pre_effect_release_tx.send(()).expect("release B pre-effect");
        assert_eq!(ends_a.executor_entered_rx.recv_timeout(FAILSAFE).expect("A entered"), gen_a);
        assert_eq!(ends_b.executor_entered_rx.recv_timeout(FAILSAFE).expect("B entered"), gen_b);
        let (ra, sa, _ea, hta) = ends_a.result_rx.recv_timeout(FAILSAFE).expect("A effect");
        let (rb, sb, _eb, htb) = ends_b.result_rx.recv_timeout(FAILSAFE).expect("B effect");
        println!(
            "[R203-TRACE] equal-body-grant A raw_class=Grant checked_key={} effect=(nonce={},height={}) | B raw_class=Grant checked_key={} effect=(nonce={},height={}) | keys_distinct={}",
            key_a, sa, hta, key_b, sb, htb, key_a != key_b
        );
        assert_eq!((ra, sa, hta), (gen_a, 1, 12), "A effect carries A's key");
        assert_eq!((rb, sb, htb), (gen_b, 1, 12), "B effect carries B's key");
        assert_eq!(owner_a.close_admission(), ProdCloseOutcome::Closed);
        assert_eq!(owner_b.close_admission(), ProdCloseOutcome::Closed);
        assert_eq!(owner_a.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner_b.observe_ready(FAILSAFE), ProdReadiness::ReadyToJoin);
        assert_eq!(owner_a.join(), ProdJoin::Terminated(ProdTerm::Normal));
        assert_eq!(owner_b.join(), ProdJoin::Terminated(ProdTerm::Normal));
    }
}
