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
        let (sender, receiver) = bounded::<ExecTask>(config.queue_capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let queue_len = Arc::new(AtomicU64::new(0));
        let queue_full_count = Arc::new(AtomicU64::new(0));
        let worker_restarts = Arc::new(AtomicU64::new(0));

        // Clone references for the worker thread
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_queue_len = Arc::clone(&queue_len);
        let worker_metrics = metrics.clone();
        let parallel_config = config.parallel_config.clone();
        let execution_profile = config.execution_profile;
        let state_dir = config.state_dir.clone();
        let stage_b_enabled = config.stage_b_enabled;

        // Spawn the dedicated worker thread
        thread::spawn(move || {
            Self::worker_loop(
                engine,
                receiver,
                worker_shutdown,
                worker_queue_len,
                worker_metrics,
                parallel_config,
                execution_profile,
                state_dir,
                stage_b_enabled,
            );
        });

        Self {
            sender,
            shutdown,
            metrics,
            queue_len,
            queue_full_count,
            worker_restarts,
        }
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
        state_dir: Option<PathBuf>,
        stage_b_enabled: bool,
    ) {
        let mut current_height: u64 = 0;

        match execution_profile {
            ExecutionProfile::NonceOnly => {
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
                    state_dir,
                    &mut current_height,
                    stage_b_enabled,
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
        state_dir: Option<PathBuf>,
        current_height: &mut u64,
        stage_b_enabled: bool,
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

        // T164: Initialize state backend based on configuration
        match state_dir {
            Some(ref path) => {
                // Use persistent state
                match RocksDbAccountState::open(path) {
                    Ok(persistent) => {
                        eprintln!("[T164] VM v0 using persistent state at {:?}", path);
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
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[T164] Failed to open persistent state at {:?}: {:?}, falling back to in-memory",
                            path, e
                        );
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
                        );
                    }
                }
            }
            None => {
                // Use in-memory state (T163 behavior)
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

            // Receive next task (blocking)
            match receiver.recv() {
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
