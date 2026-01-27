//! T150 Execution Adapter for integrating L1 execution with consensus commits.
//!
//! This module provides `ExecutionAdapter` trait and `InMemoryExecutionAdapter`
//! implementation for wiring HotStuff block commits to the execution layer.
//!
//! ## Architecture
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
//! ## Design Notes
//!
//! - `QbindBlock` wraps consensus BlockProposal with decoded `QbindTransaction`s
//! - `ExecutionAdapter` is the commit hook interface
//! - `InMemoryExecutionAdapter` uses `InMemoryState` + `ExecutionEngine`
//! - On first execution error, the adapter returns the error immediately
//! - Future versions may support different error policies (continue, revert, etc.)

use std::sync::Arc;

use qbind_ledger::{
    ExecutionEngine, ExecutionEngineError, InMemoryState, QbindTransaction, StateUpdater,
};
use qbind_types::Hash32;
use qbind_wire::consensus::BlockProposal;

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
}
