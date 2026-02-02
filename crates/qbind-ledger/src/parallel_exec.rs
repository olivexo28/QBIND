//! T171: Stage B Parallel Execution Skeleton
//!
//! This module provides the core primitives for conflict-graph-based parallel
//! execution of VM v0 transactions. It introduces:
//!
//! - `TxIndex`: Identifier for a transaction within a block
//! - `TxReadWriteSet`: Read/write set for a single transaction
//! - `ConflictGraph`: Dependency graph over transactions in a block
//! - `ParallelSchedule`: Deterministic schedule (levels) for parallel execution
//!
//! # Design Goals
//!
//! 1. **Determinism**: All conflict detection and scheduling are purely deterministic
//!    functions of the block contents. No randomness is used.
//! 2. **Single-block scope**: The scheduler only reasons within one block; consensus
//!    ordering of blocks is unchanged.
//! 3. **VM semantics preserved**: Stage B must be observationally equivalent to
//!    sequential VM v0 execution for any block.
//!
//! # Status
//!
//! T171 provides the initial Stage B skeleton and tests. This is **NOT** wired into
//! the production node yet. The test-only parallel executor validates correctness
//! by comparing parallel execution results with sequential execution.
//!
//! # VM v0 Semantics
//!
//! In VM v0 (pure transfers):
//! - A transfer reads sender + recipient accounts
//! - A transfer writes sender + recipient accounts (nonce + balance)
//!
//! Two transactions conflict if they touch the same AccountId. Since transfers
//! both read and write accounts, any shared account creates a conflict.

use qbind_types::AccountId;
use std::collections::HashSet;

use crate::{AccountStateUpdater, QbindTransaction, TransferPayload};

// ============================================================================
// Core Types
// ============================================================================

/// Identifier for a transaction within a block.
///
/// This is a simple index into the block's transaction list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxIndex(pub usize);

/// Read/write set for a single transaction.
///
/// In VM v0, both reads and writes touch the sender and recipient accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxReadWriteSet {
    /// Accounts read by this transaction.
    pub reads: Vec<AccountId>,
    /// Accounts written by this transaction.
    pub writes: Vec<AccountId>,
}

impl TxReadWriteSet {
    /// Create a new read/write set.
    pub fn new(reads: Vec<AccountId>, writes: Vec<AccountId>) -> Self {
        Self { reads, writes }
    }

    /// Get all accounts touched by this transaction (reads ∪ writes).
    pub fn all_accounts(&self) -> HashSet<AccountId> {
        let mut accounts = HashSet::new();
        for acc in &self.reads {
            accounts.insert(*acc);
        }
        for acc in &self.writes {
            accounts.insert(*acc);
        }
        accounts
    }
}

/// Conflict graph over a single block.
///
/// This represents the dependency structure of transactions. An edge from
/// transaction j to transaction i (where j < i in block order) means that
/// j must execute before i due to a conflict.
///
/// # Invariants
///
/// - `dependencies[i]` contains only indices j where j < i
/// - The graph is acyclic by construction (edges only go forward in block order)
#[derive(Clone, Debug)]
pub struct ConflictGraph {
    /// Number of transactions in the block.
    pub tx_count: usize,
    /// For each tx, the set of tx indices that must precede it.
    pub dependencies: Vec<Vec<TxIndex>>,
}

impl ConflictGraph {
    /// Create a new conflict graph with no dependencies.
    pub fn new(tx_count: usize) -> Self {
        Self {
            tx_count,
            dependencies: vec![Vec::new(); tx_count],
        }
    }

    /// Add a dependency: tx at `later` depends on tx at `earlier`.
    ///
    /// # Panics
    ///
    /// Panics if `earlier >= later` (would violate acyclicity).
    pub fn add_dependency(&mut self, earlier: TxIndex, later: TxIndex) {
        assert!(
            earlier.0 < later.0,
            "dependency must go forward: {} -> {}",
            earlier.0,
            later.0
        );
        self.dependencies[later.0].push(earlier);
    }

    /// Check if transaction `later` depends on transaction `earlier`.
    pub fn has_dependency(&self, earlier: TxIndex, later: TxIndex) -> bool {
        if earlier.0 >= later.0 {
            return false;
        }
        self.dependencies[later.0].contains(&earlier)
    }

    /// Get the number of direct dependencies for a transaction.
    pub fn dependency_count(&self, tx: TxIndex) -> usize {
        self.dependencies[tx.0].len()
    }
}

/// A deterministic Stage B schedule for a block.
///
/// Represented as "levels": each level is a set of tx indices that can be
/// executed in parallel, and levels must be executed in order.
///
/// # Invariants
///
/// - Each transaction appears in exactly one level
/// - Within a level, no two transactions have a dependency between them
/// - Levels are ordered such that all dependencies of a transaction are in earlier levels
/// - Transaction indices within each level are sorted for determinism
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelSchedule {
    /// Levels of parallel execution. Each level is a sorted list of tx indices.
    pub levels: Vec<Vec<TxIndex>>,
}

impl ParallelSchedule {
    /// Create a new empty schedule.
    pub fn new() -> Self {
        Self { levels: Vec::new() }
    }

    /// Get the total number of transactions in the schedule.
    pub fn tx_count(&self) -> usize {
        self.levels.iter().map(|level| level.len()).sum()
    }

    /// Get the number of levels (parallelism depth).
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }

    /// Check if the schedule is fully sequential (each level has exactly one tx).
    pub fn is_sequential(&self) -> bool {
        self.levels.iter().all(|level| level.len() == 1)
    }

    /// Check if the schedule is fully parallel (single level with all txs).
    pub fn is_fully_parallel(&self) -> bool {
        self.levels.len() == 1
    }
}

impl Default for ParallelSchedule {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Read/Write Set Extraction
// ============================================================================

/// Extract the read/write set for a VM v0 transaction.
///
/// For VM v0 transfers:
/// - reads = [sender, recipient]
/// - writes = [sender, recipient]
///
/// Returns `None` if the transaction payload cannot be decoded as a transfer.
///
/// # Arguments
///
/// * `tx` - The transaction to analyze
///
/// # Returns
///
/// The read/write set, or `None` if the payload is malformed.
pub fn extract_read_write_set(tx: &QbindTransaction) -> Option<TxReadWriteSet> {
    // Decode the payload as a transfer
    let transfer = TransferPayload::decode(&tx.payload)?;

    // In VM v0, transfers read and write both sender and recipient
    let reads = vec![tx.sender, transfer.recipient];
    let writes = vec![tx.sender, transfer.recipient];

    Some(TxReadWriteSet::new(reads, writes))
}

/// Extract read/write sets for all transactions in a block.
///
/// Transactions with malformed payloads are assigned an empty read/write set.
/// This allows the scheduler to proceed even with invalid transactions
/// (which will fail during execution anyway).
pub fn extract_all_read_write_sets(transactions: &[QbindTransaction]) -> Vec<TxReadWriteSet> {
    transactions
        .iter()
        .map(|tx| extract_read_write_set(tx).unwrap_or_else(|| TxReadWriteSet::new(vec![], vec![])))
        .collect()
}

// ============================================================================
// Conflict Graph Construction
// ============================================================================

/// Build a conflict graph for a block of transactions.
///
/// Two transactions conflict if they touch the same account. In VM v0,
/// since transfers both read and write accounts, any shared account
/// creates a conflict.
///
/// # Algorithm
///
/// For each transaction i (0..n):
///   For each earlier transaction j (0..i):
///     If i and j share any account in reads ∪ writes:
///       Add dependency j → i
///
/// This is O(n²) in the number of transactions. Future optimizations could
/// use a map from AccountId → last-writer tx index for O(n × accounts) complexity.
///
/// # Determinism
///
/// The algorithm processes transactions in a fixed order (0..n-1) and adds
/// dependencies based on account overlap. No randomness is used.
pub fn build_conflict_graph(transactions: &[QbindTransaction]) -> ConflictGraph {
    let n = transactions.len();
    let mut graph = ConflictGraph::new(n);

    // Extract read/write sets for all transactions
    let rw_sets = extract_all_read_write_sets(transactions);

    // Build conflict edges
    for i in 0..n {
        let accounts_i = rw_sets[i].all_accounts();

        for (j, rw_set_j) in rw_sets.iter().enumerate().take(i) {
            let accounts_j = rw_set_j.all_accounts();

            // Check for any overlap
            let has_conflict = accounts_i.iter().any(|acc| accounts_j.contains(acc));

            if has_conflict {
                graph.add_dependency(TxIndex(j), TxIndex(i));
            }
        }
    }

    graph
}

// ============================================================================
// Schedule Construction
// ============================================================================

/// Build a deterministic parallel schedule from a conflict graph.
///
/// Uses a topological layering algorithm:
/// 1. Maintain dependency counts for each transaction
/// 2. In each level, select all txs with zero remaining dependencies
/// 3. Sort selected txs by index for determinism
/// 4. Add as next level, decrement dependency counts for successors
/// 5. Repeat until all txs are scheduled
///
/// # Determinism
///
/// The algorithm is fully deterministic:
/// - Transactions are selected by dependency count (zero = ready)
/// - Ready transactions are sorted by index before adding to level
/// - No randomness or hash-dependent iteration
///
/// # Panics
///
/// Panics if the graph contains a cycle (should never happen by construction).
pub fn build_parallel_schedule(graph: &ConflictGraph) -> ParallelSchedule {
    let n = graph.tx_count;
    if n == 0 {
        return ParallelSchedule::new();
    }

    // Initialize dependency counts
    let mut remaining_deps: Vec<usize> = graph.dependencies.iter().map(|d| d.len()).collect();

    // Build reverse adjacency: for each tx, which txs depend on it?
    let mut dependents: Vec<Vec<TxIndex>> = vec![Vec::new(); n];
    for i in 0..n {
        for &dep in &graph.dependencies[i] {
            dependents[dep.0].push(TxIndex(i));
        }
    }

    let mut schedule = ParallelSchedule::new();
    let mut scheduled = vec![false; n];
    let mut scheduled_count = 0;

    while scheduled_count < n {
        // Collect all ready transactions (zero remaining dependencies)
        let mut ready: Vec<TxIndex> = (0..n)
            .filter(|&i| !scheduled[i] && remaining_deps[i] == 0)
            .map(TxIndex)
            .collect();

        // Sort by index for determinism
        ready.sort_by_key(|tx| tx.0);

        // Assert progress (avoid infinite loop on cyclic graph)
        assert!(
            !ready.is_empty(),
            "no ready transactions but {} remain; graph may be cyclic",
            n - scheduled_count
        );

        // Add this level
        schedule.levels.push(ready.clone());

        // Mark as scheduled and update dependency counts
        for &tx in &ready {
            scheduled[tx.0] = true;
            scheduled_count += 1;

            // Decrement dependency count for all dependents
            for &dependent in &dependents[tx.0] {
                remaining_deps[dependent.0] = remaining_deps[dependent.0].saturating_sub(1);
            }
        }
    }

    schedule
}

// ============================================================================
// T186: Production Stage B Parallel Executor
// ============================================================================

/// Statistics from a Stage B parallel execution.
///
/// This struct provides metrics about how the Stage B conflict-graph scheduler
/// executed a block. It can be used for observability and performance analysis.
#[derive(Clone, Debug, Default)]
pub struct StageBExecStats {
    /// Number of transactions in the block.
    pub tx_count: usize,
    /// Number of levels in the parallel schedule.
    pub level_count: usize,
    /// Average level size (transactions per level).
    pub avg_level_size: f64,
    /// Maximum level size (maximum parallelism achieved).
    pub max_level_size: usize,
    /// Whether parallel execution was used (false if schedule was sequential).
    pub used_parallel: bool,
    /// Number of worker threads used (approximate, from Rayon).
    pub workers_used: usize,
}

/// Thread-safe per-account state for Stage B parallel execution (T186).
///
/// Uses per-account locks for lock-free parallel execution within a level.
/// The scheduler guarantees no two transactions in the same level touch
/// the same account, so write conflicts should not occur in practice.
pub struct StageBPerAccountState {
    accounts: std::sync::Arc<
        std::sync::RwLock<
            std::collections::HashMap<
                AccountId,
                std::sync::Arc<std::sync::RwLock<crate::AccountState>>,
            >,
        >,
    >,
}

impl StageBPerAccountState {
    /// Create a new per-account state.
    pub fn new() -> Self {
        Self {
            accounts: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Create from an existing InMemoryAccountState.
    pub fn from_in_memory(state: &crate::InMemoryAccountState) -> Self {
        let mut accounts = std::collections::HashMap::new();
        for (account, account_state) in state.iter() {
            accounts.insert(
                *account,
                std::sync::Arc::new(std::sync::RwLock::new(account_state.clone())),
            );
        }
        Self {
            accounts: std::sync::Arc::new(std::sync::RwLock::new(accounts)),
        }
    }

    /// Get the lock for a specific account, creating it if necessary.
    fn get_account_lock(
        &self,
        account: &AccountId,
    ) -> std::sync::Arc<std::sync::RwLock<crate::AccountState>> {
        // First, try to read
        {
            let accounts = self.accounts.read().unwrap();
            if let Some(lock) = accounts.get(account) {
                return std::sync::Arc::clone(lock);
            }
        }

        // Need to create - acquire write lock
        let mut accounts = self.accounts.write().unwrap();
        accounts
            .entry(*account)
            .or_insert_with(|| {
                std::sync::Arc::new(std::sync::RwLock::new(crate::AccountState::default()))
            })
            .clone()
    }

    /// Get account state (read).
    pub fn get(&self, account: &AccountId) -> crate::AccountState {
        let lock = self.get_account_lock(account);
        let guard = lock.read().unwrap();
        guard.clone()
    }

    /// Set account state (write).
    pub fn set(&self, account: &AccountId, state: crate::AccountState) {
        let lock = self.get_account_lock(account);
        let mut guard = lock.write().unwrap();
        *guard = state;
    }

    /// Convert to InMemoryAccountState.
    pub fn to_in_memory(&self) -> crate::InMemoryAccountState {
        let accounts = self.accounts.read().unwrap();
        let mut state = crate::InMemoryAccountState::new();
        for (account, lock) in accounts.iter() {
            let guard = lock.read().unwrap();
            let account_state = guard.clone();
            state.set_account_state(account, account_state.clone());
        }
        state
    }
}

impl Default for StageBPerAccountState {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute a single transaction against StageBPerAccountState (T186).
///
/// This manually implements the VM v0 execution logic against the
/// per-account state wrapper for parallel execution.
fn execute_tx_on_stage_b_state(
    state: &StageBPerAccountState,
    tx: &crate::QbindTransaction,
) -> crate::VmV0TxResult {
    use crate::{TransferPayload, VmV0Error};

    // Decode payload
    let transfer = match TransferPayload::decode(&tx.payload) {
        Some(t) => t,
        None => return crate::VmV0TxResult::failure(VmV0Error::MalformedPayload),
    };

    // Get sender state
    let sender_state = state.get(&tx.sender);

    // Check nonce
    if tx.nonce != sender_state.nonce {
        return crate::VmV0TxResult::failure(VmV0Error::NonceMismatch {
            expected: sender_state.nonce,
            got: tx.nonce,
        });
    }

    // Check balance
    if sender_state.balance < transfer.amount {
        return crate::VmV0TxResult::failure(VmV0Error::InsufficientBalance {
            balance: sender_state.balance,
            needed: transfer.amount,
        });
    }

    // Update sender
    let new_sender_state = crate::AccountState {
        nonce: sender_state.nonce + 1,
        balance: sender_state.balance - transfer.amount,
    };
    state.set(&tx.sender, new_sender_state);

    // Update recipient
    let recipient_state = state.get(&transfer.recipient);
    let new_recipient_state = crate::AccountState {
        nonce: recipient_state.nonce,
        balance: recipient_state.balance + transfer.amount,
    };
    state.set(&transfer.recipient, new_recipient_state);

    crate::VmV0TxResult::success()
}

/// Execute a block using Stage B conflict-graph parallel scheduling (T186).
///
/// This is the production API for Stage B parallel execution. It uses the
/// conflict-graph scheduler to execute transactions in parallel while
/// preserving determinism.
///
/// # Algorithm
///
/// 1. Build conflict graph from transactions
/// 2. Build parallel schedule (topological layering)
/// 3. For each level:
///    - Execute all transactions in that level in parallel using Rayon
///    - Within a level, transactions touch disjoint accounts (by scheduler invariant)
/// 4. Return results in original block order
///
/// # Thread Safety
///
/// The scheduler guarantees that transactions in the same level touch disjoint
/// accounts. Therefore, parallel execution within a level is safe without
/// per-account locking conflicts.
///
/// # Determinism
///
/// Stage B execution is fully deterministic:
/// - Same inputs → same outputs (receipts and final state)
/// - No randomness in conflict detection or scheduling
/// - Level execution is parallel but result ordering is deterministic
///
/// # Arguments
///
/// * `transactions` - The transactions to execute in block order
/// * `initial_state` - The account state at the start of the block
///
/// # Returns
///
/// A tuple of:
/// - `Vec<VmV0TxResult>` - Results for each transaction in block order
/// - `InMemoryAccountState` - The final state after all transactions
/// - `StageBExecStats` - Execution statistics
pub fn execute_block_stage_b(
    transactions: &[crate::QbindTransaction],
    initial_state: &crate::InMemoryAccountState,
) -> (
    Vec<crate::VmV0TxResult>,
    crate::InMemoryAccountState,
    StageBExecStats,
) {
    use rayon::prelude::*;

    if transactions.is_empty() {
        return (
            Vec::new(),
            initial_state.clone(),
            StageBExecStats::default(),
        );
    }

    // Build conflict graph and schedule
    let graph = build_conflict_graph(transactions);
    let schedule = build_parallel_schedule(&graph);

    // Compute stats
    let tx_count = transactions.len();
    let level_count = schedule.level_count();
    let max_level_size = schedule.levels.iter().map(|l| l.len()).max().unwrap_or(0);
    let avg_level_size = if level_count > 0 {
        tx_count as f64 / level_count as f64
    } else {
        0.0
    };
    let used_parallel = max_level_size > 1;
    let workers_used = rayon::current_num_threads();

    // Create per-account state from initial state
    let state = StageBPerAccountState::from_in_memory(initial_state);

    // Results array (pre-allocated for each transaction)
    let results: std::sync::Arc<std::sync::RwLock<Vec<Option<crate::VmV0TxResult>>>> =
        std::sync::Arc::new(std::sync::RwLock::new(vec![None; transactions.len()]));

    // Execute each level in order
    for level in &schedule.levels {
        // Execute transactions in this level in parallel
        let level_results: Vec<(usize, crate::VmV0TxResult)> = level
            .par_iter()
            .map(|&tx_idx| {
                let tx = &transactions[tx_idx.0];
                let result = execute_tx_on_stage_b_state(&state, tx);
                (tx_idx.0, result)
            })
            .collect();

        // Store results
        let mut results_guard = results.write().unwrap();
        for (idx, result) in level_results {
            results_guard[idx] = Some(result);
        }
    }

    // Extract results in order
    let results_guard = results.read().unwrap();
    let results_vec: Vec<crate::VmV0TxResult> = results_guard
        .iter()
        .map(|opt| opt.clone().expect("all results should be set"))
        .collect();

    let final_state = state.to_in_memory();
    let stats = StageBExecStats {
        tx_count,
        level_count,
        avg_level_size,
        max_level_size,
        used_parallel,
        workers_used,
    };

    (results_vec, final_state, stats)
}

// ============================================================================
// Test-Only Parallel Executor
// ============================================================================

#[cfg(test)]
pub mod test_executor {
    //! Test-only parallel executor for Stage B validation.
    //!
    //! This module provides a parallel executor that uses the conflict graph
    //! scheduler to execute transactions in parallel using Rayon. It is used
    //! only in tests to validate that parallel execution produces the same
    //! results as sequential execution.

    use super::*;
    use crate::{
        AccountState, AccountStateUpdater, AccountStateView, InMemoryAccountState,
        VmV0ExecutionEngine, VmV0TxResult,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// Thread-safe account state wrapper for parallel execution.
    ///
    /// Uses RwLock to allow concurrent reads and serialized writes.
    /// Since the scheduler ensures no two concurrent transactions touch
    /// the same account, write conflicts should not occur in practice.
    pub struct ConcurrentAccountState {
        inner: RwLock<HashMap<AccountId, AccountState>>,
    }

    impl ConcurrentAccountState {
        /// Create a new concurrent account state.
        pub fn new() -> Self {
            Self {
                inner: RwLock::new(HashMap::new()),
            }
        }

        /// Create from an existing InMemoryAccountState.
        pub fn from_in_memory(state: &InMemoryAccountState) -> Self {
            let mut inner = HashMap::new();
            for (account, account_state) in state.iter() {
                inner.insert(*account, account_state.clone());
            }
            Self {
                inner: RwLock::new(inner),
            }
        }

        /// Initialize an account with the given balance.
        pub fn init_account(&self, account: &AccountId, balance: u128) {
            let mut inner = self.inner.write().unwrap();
            inner.insert(*account, AccountState::with_balance(balance));
        }

        /// Convert to InMemoryAccountState.
        pub fn to_in_memory(&self) -> InMemoryAccountState {
            let inner = self.inner.read().unwrap();
            let mut state = InMemoryAccountState::new();
            for (account, account_state) in inner.iter() {
                state.set_account_state(account, account_state.clone());
            }
            state
        }
    }

    impl Default for ConcurrentAccountState {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AccountStateView for ConcurrentAccountState {
        fn get_account_state(&self, account: &AccountId) -> AccountState {
            let inner = self.inner.read().unwrap();
            inner.get(account).cloned().unwrap_or_default()
        }
    }

    impl AccountStateUpdater for ConcurrentAccountState {
        fn set_account_state(&mut self, account: &AccountId, state: AccountState) {
            let mut inner = self.inner.write().unwrap();
            inner.insert(*account, state);
        }
    }

    /// Per-account state wrapper for lock-free parallel execution within a level.
    ///
    /// Since the scheduler guarantees no two transactions in the same level
    /// touch the same account, we can use per-account locks instead of a
    /// global lock.
    pub struct PerAccountState {
        accounts: Arc<RwLock<HashMap<AccountId, Arc<RwLock<AccountState>>>>>,
    }

    impl PerAccountState {
        /// Create a new per-account state.
        pub fn new() -> Self {
            Self {
                accounts: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        /// Create from an existing InMemoryAccountState.
        pub fn from_in_memory(state: &InMemoryAccountState) -> Self {
            let mut accounts = HashMap::new();
            for (account, account_state) in state.iter() {
                accounts.insert(*account, Arc::new(RwLock::new(account_state.clone())));
            }
            Self {
                accounts: Arc::new(RwLock::new(accounts)),
            }
        }

        /// Initialize an account with the given balance.
        pub fn init_account(&self, account: &AccountId, balance: u128) {
            let mut accounts = self.accounts.write().unwrap();
            accounts.insert(
                *account,
                Arc::new(RwLock::new(AccountState::with_balance(balance))),
            );
        }

        /// Get the lock for a specific account, creating it if necessary.
        fn get_account_lock(&self, account: &AccountId) -> Arc<RwLock<AccountState>> {
            // First, try to read
            {
                let accounts = self.accounts.read().unwrap();
                if let Some(lock) = accounts.get(account) {
                    return Arc::clone(lock);
                }
            }

            // Need to create - acquire write lock
            let mut accounts = self.accounts.write().unwrap();
            accounts
                .entry(*account)
                .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
                .clone()
        }

        /// Get account state (read).
        pub fn get(&self, account: &AccountId) -> AccountState {
            let lock = self.get_account_lock(account);
            let guard = lock.read().unwrap();
            guard.clone()
        }

        /// Set account state (write).
        pub fn set(&self, account: &AccountId, state: AccountState) {
            let lock = self.get_account_lock(account);
            let mut guard = lock.write().unwrap();
            *guard = state;
        }

        /// Convert to InMemoryAccountState.
        pub fn to_in_memory(&self) -> InMemoryAccountState {
            let accounts = self.accounts.read().unwrap();
            let mut state = InMemoryAccountState::new();
            for (account, lock) in accounts.iter() {
                let guard = lock.read().unwrap();
                let account_state = guard.clone();
                state.set_account_state(account, account_state);
            }
            state
        }
    }

    impl Default for PerAccountState {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clone for PerAccountState {
        fn clone(&self) -> Self {
            let accounts = self.accounts.read().unwrap();
            let mut new_accounts = HashMap::new();
            for (account, lock) in accounts.iter() {
                let state = lock.read().unwrap().clone();
                new_accounts.insert(*account, Arc::new(RwLock::new(state)));
            }
            Self {
                accounts: Arc::new(RwLock::new(new_accounts)),
            }
        }
    }

    /// Execute a single transaction against PerAccountState.
    ///
    /// This manually implements the VM v0 execution logic against the
    /// per-account state wrapper.
    fn execute_tx_on_per_account(state: &PerAccountState, tx: &QbindTransaction) -> VmV0TxResult {
        use crate::{TransferPayload, VmV0Error};

        // Decode payload
        let transfer = match TransferPayload::decode(&tx.payload) {
            Some(t) => t,
            None => return VmV0TxResult::failure(VmV0Error::MalformedPayload),
        };

        // Get sender state
        let sender_state = state.get(&tx.sender);

        // Check nonce
        if tx.nonce != sender_state.nonce {
            return VmV0TxResult::failure(VmV0Error::NonceMismatch {
                expected: sender_state.nonce,
                got: tx.nonce,
            });
        }

        // Check balance
        if sender_state.balance < transfer.amount {
            return VmV0TxResult::failure(VmV0Error::InsufficientBalance {
                balance: sender_state.balance,
                needed: transfer.amount,
            });
        }

        // Update sender
        let new_sender_state = AccountState {
            nonce: sender_state.nonce + 1,
            balance: sender_state.balance - transfer.amount,
        };
        state.set(&tx.sender, new_sender_state);

        // Update recipient
        let recipient_state = state.get(&transfer.recipient);
        let new_recipient_state = AccountState {
            nonce: recipient_state.nonce,
            balance: recipient_state.balance + transfer.amount,
        };
        state.set(&transfer.recipient, new_recipient_state);

        VmV0TxResult::success()
    }

    /// Execute a block sequentially using VmV0ExecutionEngine.
    ///
    /// This is the baseline for comparison with parallel execution.
    pub fn execute_block_sequential(
        transactions: &[QbindTransaction],
        initial_state: &InMemoryAccountState,
    ) -> (Vec<VmV0TxResult>, InMemoryAccountState) {
        let mut state = initial_state.clone();
        let engine = VmV0ExecutionEngine::new();
        let results = engine.execute_block(&mut state, transactions);
        (results, state)
    }

    /// Execute a block in parallel using the Stage B scheduler.
    ///
    /// # Algorithm
    ///
    /// 1. Build conflict graph from transactions
    /// 2. Build parallel schedule
    /// 3. For each level:
    ///    - Execute all transactions in that level in parallel using Rayon
    ///    - Within a level, transactions touch disjoint accounts (by scheduler invariant)
    /// 4. Return results in original block order
    ///
    /// # Thread Safety
    ///
    /// The scheduler guarantees that transactions in the same level touch disjoint
    /// accounts. Therefore, parallel execution within a level is safe without
    /// per-account locking conflicts.
    pub fn execute_block_parallel(
        transactions: &[QbindTransaction],
        initial_state: &InMemoryAccountState,
    ) -> (Vec<VmV0TxResult>, InMemoryAccountState) {
        use rayon::prelude::*;

        if transactions.is_empty() {
            return (Vec::new(), initial_state.clone());
        }

        // Build conflict graph and schedule
        let graph = build_conflict_graph(transactions);
        let schedule = build_parallel_schedule(&graph);

        // Create per-account state from initial state
        let state = PerAccountState::from_in_memory(initial_state);

        // Results array (pre-allocated for each transaction)
        let results: Arc<RwLock<Vec<Option<VmV0TxResult>>>> =
            Arc::new(RwLock::new(vec![None; transactions.len()]));

        // Execute each level in order
        for level in &schedule.levels {
            // Execute transactions in this level in parallel
            let level_results: Vec<(usize, VmV0TxResult)> = level
                .par_iter()
                .map(|&tx_idx| {
                    let tx = &transactions[tx_idx.0];
                    let result = execute_tx_on_per_account(&state, tx);
                    (tx_idx.0, result)
                })
                .collect();

            // Store results
            let mut results_guard = results.write().unwrap();
            for (idx, result) in level_results {
                results_guard[idx] = Some(result);
            }
        }

        // Extract results in order
        let results_guard = results.read().unwrap();
        let results_vec: Vec<VmV0TxResult> = results_guard
            .iter()
            .map(|opt| opt.clone().expect("all results should be set"))
            .collect();

        let final_state = state.to_in_memory();
        (results_vec, final_state)
    }

    /// Compare two account states for equality.
    pub fn states_equal(a: &InMemoryAccountState, b: &InMemoryAccountState) -> bool {
        // Collect all accounts from both states
        let accounts_a: std::collections::HashSet<_> = a.iter().map(|(acc, _)| *acc).collect();
        let accounts_b: std::collections::HashSet<_> = b.iter().map(|(acc, _)| *acc).collect();

        // Check same accounts
        if accounts_a != accounts_b {
            return false;
        }

        // Check same state for each account
        for acc in accounts_a {
            if a.get_account_state(&acc) != b.get_account_state(&acc) {
                return false;
            }
        }

        true
    }

    /// Compare two result vectors for equality.
    pub fn results_equal(a: &[VmV0TxResult], b: &[VmV0TxResult]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        for (ra, rb) in a.iter().zip(b.iter()) {
            if ra.success != rb.success {
                return false;
            }
            // Note: We compare success/failure only, not gas (which is 0 for non-gas mode)
        }
        true
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QbindTransaction, TransferPayload};

    fn test_account_id(byte: u8) -> AccountId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn make_transfer_tx(
        sender_byte: u8,
        recipient_byte: u8,
        nonce: u64,
        amount: u128,
    ) -> QbindTransaction {
        let sender = test_account_id(sender_byte);
        let recipient = test_account_id(recipient_byte);
        let payload = TransferPayload::new(recipient, amount).encode();
        QbindTransaction::new(sender, nonce, payload)
    }

    // ========================================================================
    // TxReadWriteSet Tests
    // ========================================================================

    #[test]
    fn test_read_write_set_all_accounts() {
        let acc_a = test_account_id(0xAA);
        let acc_b = test_account_id(0xBB);
        let acc_c = test_account_id(0xCC);

        let rw = TxReadWriteSet::new(vec![acc_a, acc_b], vec![acc_b, acc_c]);
        let all = rw.all_accounts();

        assert!(all.contains(&acc_a));
        assert!(all.contains(&acc_b));
        assert!(all.contains(&acc_c));
        assert_eq!(all.len(), 3);
    }

    // ========================================================================
    // Read/Write Set Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_read_write_set_valid_transfer() {
        let tx = make_transfer_tx(0xAA, 0xBB, 0, 100);
        let rw = extract_read_write_set(&tx).expect("should decode");

        let sender = test_account_id(0xAA);
        let recipient = test_account_id(0xBB);

        assert_eq!(rw.reads, vec![sender, recipient]);
        assert_eq!(rw.writes, vec![sender, recipient]);
    }

    #[test]
    fn test_extract_read_write_set_malformed() {
        let sender = test_account_id(0xAA);
        let tx = QbindTransaction::new(sender, 0, vec![0xDE, 0xAD]);
        let rw = extract_read_write_set(&tx);
        assert!(rw.is_none());
    }

    // ========================================================================
    // Conflict Graph Tests
    // ========================================================================

    #[test]
    fn test_conflict_graph_empty() {
        let graph = ConflictGraph::new(0);
        assert_eq!(graph.tx_count, 0);
        assert!(graph.dependencies.is_empty());
    }

    #[test]
    fn test_conflict_graph_add_dependency() {
        let mut graph = ConflictGraph::new(3);
        graph.add_dependency(TxIndex(0), TxIndex(2));
        graph.add_dependency(TxIndex(1), TxIndex(2));

        assert!(graph.has_dependency(TxIndex(0), TxIndex(2)));
        assert!(graph.has_dependency(TxIndex(1), TxIndex(2)));
        assert!(!graph.has_dependency(TxIndex(0), TxIndex(1)));
        assert_eq!(graph.dependency_count(TxIndex(2)), 2);
    }

    #[test]
    #[should_panic(expected = "dependency must go forward")]
    fn test_conflict_graph_invalid_dependency() {
        let mut graph = ConflictGraph::new(3);
        graph.add_dependency(TxIndex(2), TxIndex(1)); // Invalid: backward edge
    }

    // ========================================================================
    // Schedule Tests
    // ========================================================================

    #[test]
    fn test_parallel_schedule_empty() {
        let schedule = ParallelSchedule::new();
        assert_eq!(schedule.tx_count(), 0);
        assert_eq!(schedule.level_count(), 0);
    }

    #[test]
    fn test_parallel_schedule_is_sequential() {
        let mut schedule = ParallelSchedule::new();
        schedule.levels.push(vec![TxIndex(0)]);
        schedule.levels.push(vec![TxIndex(1)]);
        schedule.levels.push(vec![TxIndex(2)]);

        assert!(schedule.is_sequential());
        assert!(!schedule.is_fully_parallel());
    }

    #[test]
    fn test_parallel_schedule_is_fully_parallel() {
        let mut schedule = ParallelSchedule::new();
        schedule
            .levels
            .push(vec![TxIndex(0), TxIndex(1), TxIndex(2)]);

        assert!(schedule.is_fully_parallel());
        assert!(!schedule.is_sequential());
    }

    // ========================================================================
    // Build Conflict Graph Tests
    // ========================================================================

    #[test]
    fn test_build_conflict_graph_no_conflicts() {
        // Three transactions with disjoint accounts
        let transactions = vec![
            make_transfer_tx(0x01, 0x02, 0, 10), // A -> B
            make_transfer_tx(0x03, 0x04, 0, 10), // C -> D
            make_transfer_tx(0x05, 0x06, 0, 10), // E -> F
        ];

        let graph = build_conflict_graph(&transactions);

        assert_eq!(graph.tx_count, 3);
        assert_eq!(graph.dependency_count(TxIndex(0)), 0);
        assert_eq!(graph.dependency_count(TxIndex(1)), 0);
        assert_eq!(graph.dependency_count(TxIndex(2)), 0);
    }

    #[test]
    fn test_build_conflict_graph_sender_chain() {
        // Three transactions from the same sender
        let transactions = vec![
            make_transfer_tx(0xAA, 0x01, 0, 10), // AA -> 01
            make_transfer_tx(0xAA, 0x02, 1, 10), // AA -> 02
            make_transfer_tx(0xAA, 0x03, 2, 10), // AA -> 03
        ];

        let graph = build_conflict_graph(&transactions);

        assert_eq!(graph.tx_count, 3);
        // tx1 depends on tx0 (shared sender AA)
        assert!(graph.has_dependency(TxIndex(0), TxIndex(1)));
        // tx2 depends on tx0 and tx1 (shared sender AA)
        assert!(graph.has_dependency(TxIndex(0), TxIndex(2)));
        assert!(graph.has_dependency(TxIndex(1), TxIndex(2)));
    }

    #[test]
    fn test_build_conflict_graph_shared_recipient() {
        // Two senders sending to the same recipient
        let transactions = vec![
            make_transfer_tx(0xAA, 0xCC, 0, 10), // AA -> CC
            make_transfer_tx(0xBB, 0xCC, 0, 10), // BB -> CC
        ];

        let graph = build_conflict_graph(&transactions);

        assert_eq!(graph.tx_count, 2);
        // tx1 depends on tx0 (shared recipient CC)
        assert!(graph.has_dependency(TxIndex(0), TxIndex(1)));
    }

    // ========================================================================
    // Build Schedule Tests
    // ========================================================================

    #[test]
    fn test_build_schedule_empty() {
        let graph = ConflictGraph::new(0);
        let schedule = build_parallel_schedule(&graph);
        assert!(schedule.levels.is_empty());
    }

    #[test]
    fn test_build_schedule_no_conflicts() {
        // No dependencies -> single level with all txs
        let transactions = vec![
            make_transfer_tx(0x01, 0x02, 0, 10),
            make_transfer_tx(0x03, 0x04, 0, 10),
            make_transfer_tx(0x05, 0x06, 0, 10),
        ];

        let graph = build_conflict_graph(&transactions);
        let schedule = build_parallel_schedule(&graph);

        assert_eq!(schedule.level_count(), 1);
        assert_eq!(schedule.tx_count(), 3);
        assert!(schedule.is_fully_parallel());
    }

    #[test]
    fn test_build_schedule_fully_sequential() {
        // All txs touch the same account -> linear schedule
        let transactions = vec![
            make_transfer_tx(0xAA, 0x01, 0, 10),
            make_transfer_tx(0xAA, 0x02, 1, 10),
            make_transfer_tx(0xAA, 0x03, 2, 10),
        ];

        let graph = build_conflict_graph(&transactions);
        let schedule = build_parallel_schedule(&graph);

        assert_eq!(schedule.level_count(), 3);
        assert!(schedule.is_sequential());
    }

    #[test]
    fn test_build_schedule_mixed() {
        // tx0: A -> B
        // tx1: C -> D (independent of tx0)
        // tx2: A -> E (depends on tx0)
        let transactions = vec![
            make_transfer_tx(0xAA, 0xBB, 0, 10), // tx0: A -> B
            make_transfer_tx(0xCC, 0xDD, 0, 10), // tx1: C -> D
            make_transfer_tx(0xAA, 0xEE, 1, 10), // tx2: A -> E (depends on tx0)
        ];

        let graph = build_conflict_graph(&transactions);
        let schedule = build_parallel_schedule(&graph);

        // Level 0: tx0, tx1 (no deps)
        // Level 1: tx2 (depends on tx0)
        assert_eq!(schedule.level_count(), 2);
        assert_eq!(schedule.levels[0].len(), 2);
        assert_eq!(schedule.levels[1].len(), 1);

        // Verify tx indices are sorted within levels
        assert!(schedule.levels[0][0].0 < schedule.levels[0][1].0);
    }

    #[test]
    fn test_schedule_determinism() {
        let transactions = vec![
            make_transfer_tx(0x01, 0x02, 0, 10),
            make_transfer_tx(0x03, 0x04, 0, 10),
            make_transfer_tx(0x01, 0x05, 1, 10),
            make_transfer_tx(0x03, 0x06, 1, 10),
        ];

        // Run multiple times
        let graph1 = build_conflict_graph(&transactions);
        let schedule1 = build_parallel_schedule(&graph1);

        let graph2 = build_conflict_graph(&transactions);
        let schedule2 = build_parallel_schedule(&graph2);

        let graph3 = build_conflict_graph(&transactions);
        let schedule3 = build_parallel_schedule(&graph3);

        // All schedules should be identical
        assert_eq!(schedule1, schedule2);
        assert_eq!(schedule2, schedule3);
    }

    // ========================================================================
    // T186: Stage B Production Executor Tests
    // ========================================================================

    use crate::AccountStateView;
    // ========================================================================

    #[test]
    fn test_stage_b_exec_empty_block() {
        let initial_state = crate::InMemoryAccountState::new();
        let transactions: Vec<crate::QbindTransaction> = vec![];

        let (results, final_state, stats) = execute_block_stage_b(&transactions, &initial_state);

        assert!(results.is_empty());
        assert_eq!(stats.tx_count, 0);
        assert_eq!(stats.level_count, 0);
        // Empty state should be unchanged
        assert!(final_state.iter().count() == 0);
    }

    #[test]
    fn test_stage_b_exec_single_tx() {
        use crate::{AccountState, AccountStateUpdater};

        let mut initial_state = crate::InMemoryAccountState::new();
        let sender = test_account_id(0xAA);
        let recipient = test_account_id(0xBB);

        // Initialize sender with balance
        initial_state.set_account_state(&sender, AccountState::with_balance(1000));

        let transactions = vec![make_transfer_tx(0xAA, 0xBB, 0, 100)];

        let (results, final_state, stats) = execute_block_stage_b(&transactions, &initial_state);

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(stats.tx_count, 1);
        assert_eq!(stats.level_count, 1);

        // Verify state changes
        assert_eq!(final_state.get_account_state(&sender).balance, 900);
        assert_eq!(final_state.get_account_state(&sender).nonce, 1);
        assert_eq!(final_state.get_account_state(&recipient).balance, 100);
    }

    #[test]
    fn test_stage_b_exec_parallel_non_conflicting() {
        use crate::{AccountState, AccountStateUpdater};

        let mut initial_state = crate::InMemoryAccountState::new();

        // Set up 4 independent senders
        let sender_a = test_account_id(0x01);
        let sender_b = test_account_id(0x02);
        let sender_c = test_account_id(0x03);
        let sender_d = test_account_id(0x04);

        initial_state.set_account_state(&sender_a, AccountState::with_balance(1000));
        initial_state.set_account_state(&sender_b, AccountState::with_balance(1000));
        initial_state.set_account_state(&sender_c, AccountState::with_balance(1000));
        initial_state.set_account_state(&sender_d, AccountState::with_balance(1000));

        // 4 non-conflicting transfers (each to a unique recipient)
        let transactions = vec![
            make_transfer_tx(0x01, 0x11, 0, 100),
            make_transfer_tx(0x02, 0x12, 0, 100),
            make_transfer_tx(0x03, 0x13, 0, 100),
            make_transfer_tx(0x04, 0x14, 0, 100),
        ];

        let (results, final_state, stats) = execute_block_stage_b(&transactions, &initial_state);

        assert_eq!(results.len(), 4);
        for result in &results {
            assert!(result.success);
        }

        // Non-conflicting txs should be parallel (single level)
        assert_eq!(stats.tx_count, 4);
        assert_eq!(stats.level_count, 1);
        assert_eq!(stats.max_level_size, 4);
        assert!(stats.used_parallel);

        // Verify final state
        assert_eq!(final_state.get_account_state(&sender_a).balance, 900);
        assert_eq!(final_state.get_account_state(&sender_b).balance, 900);
        assert_eq!(final_state.get_account_state(&sender_c).balance, 900);
        assert_eq!(final_state.get_account_state(&sender_d).balance, 900);
    }

    #[test]
    fn test_stage_b_exec_sequential_conflicting() {
        use crate::{AccountState, AccountStateUpdater};

        let mut initial_state = crate::InMemoryAccountState::new();
        let sender = test_account_id(0xAA);

        initial_state.set_account_state(&sender, AccountState::with_balance(1000));

        // 3 sequential transfers from the same sender (must be sequential)
        let transactions = vec![
            make_transfer_tx(0xAA, 0x01, 0, 100),
            make_transfer_tx(0xAA, 0x02, 1, 100),
            make_transfer_tx(0xAA, 0x03, 2, 100),
        ];

        let (results, final_state, stats) = execute_block_stage_b(&transactions, &initial_state);

        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(result.success);
        }

        // Conflicting txs should be sequential (3 levels)
        assert_eq!(stats.tx_count, 3);
        assert_eq!(stats.level_count, 3);
        assert_eq!(stats.max_level_size, 1);
        assert!(!stats.used_parallel);

        // Verify final state
        assert_eq!(final_state.get_account_state(&sender).balance, 700);
        assert_eq!(final_state.get_account_state(&sender).nonce, 3);
    }

    #[test]
    fn test_stage_b_exec_matches_sequential() {
        use crate::{AccountState, AccountStateUpdater, VmV0ExecutionEngine};

        let mut initial_state = crate::InMemoryAccountState::new();

        // Set up multiple senders
        let sender_a = test_account_id(0x01);
        let sender_b = test_account_id(0x02);

        initial_state.set_account_state(&sender_a, AccountState::with_balance(1000));
        initial_state.set_account_state(&sender_b, AccountState::with_balance(1000));

        // Mix of parallel and sequential txs
        let transactions = vec![
            make_transfer_tx(0x01, 0x11, 0, 50), // A -> X
            make_transfer_tx(0x02, 0x12, 0, 50), // B -> Y (parallel with above)
            make_transfer_tx(0x01, 0x13, 1, 50), // A -> Z (sequential with first)
        ];

        // Execute with Stage B
        let (stage_b_results, stage_b_state, _stats) =
            execute_block_stage_b(&transactions, &initial_state);

        // Execute sequentially for comparison
        let engine = VmV0ExecutionEngine::new();
        let mut seq_state = initial_state.clone();
        let seq_results = engine.execute_block(&mut seq_state, &transactions);

        // Results should match
        assert_eq!(stage_b_results.len(), seq_results.len());
        for (sb, sq) in stage_b_results.iter().zip(seq_results.iter()) {
            assert_eq!(sb.success, sq.success, "Result success mismatch");
        }

        // Final state should match
        let sender_a_sb = stage_b_state.get_account_state(&sender_a);
        let sender_a_sq = seq_state.get_account_state(&sender_a);
        assert_eq!(
            sender_a_sb.balance, sender_a_sq.balance,
            "Sender A balance mismatch"
        );
        assert_eq!(
            sender_a_sb.nonce, sender_a_sq.nonce,
            "Sender A nonce mismatch"
        );

        let sender_b_sb = stage_b_state.get_account_state(&sender_b);
        let sender_b_sq = seq_state.get_account_state(&sender_b);
        assert_eq!(
            sender_b_sb.balance, sender_b_sq.balance,
            "Sender B balance mismatch"
        );
        assert_eq!(
            sender_b_sb.nonce, sender_b_sq.nonce,
            "Sender B nonce mismatch"
        );
    }

    #[test]
    fn test_stage_b_stats_populated() {
        use crate::{AccountState, AccountStateUpdater};

        let mut initial_state = crate::InMemoryAccountState::new();
        let sender = test_account_id(0xAA);
        initial_state.set_account_state(&sender, AccountState::with_balance(1000));

        let transactions = vec![make_transfer_tx(0xAA, 0xBB, 0, 100)];

        let (_results, _final_state, stats) = execute_block_stage_b(&transactions, &initial_state);

        assert_eq!(stats.tx_count, 1);
        assert_eq!(stats.level_count, 1);
        assert_eq!(stats.avg_level_size, 1.0);
        assert_eq!(stats.max_level_size, 1);
        assert!(!stats.used_parallel);
        assert!(stats.workers_used > 0); // Rayon should report workers
    }
}