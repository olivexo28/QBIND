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
            #[cfg(test)]
            supervised_idle_close::recv_boundary_test_hook();

            // Receive next task (blocking)
            match receiver.recv() {
                Ok(task) => {
                    // Update queue length
                    let len = receiver.len();
                    queue_len.store(len as u64, Ordering::Relaxed);

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
}
