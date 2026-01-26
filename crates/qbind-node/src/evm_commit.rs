//! EVM execution integration for committed blocks (T151).
//!
//! This module provides `EvmExecutionBridge`, a component that executes
//! EVM transactions when blocks are committed via HotStuff consensus.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │               NodeHotstuffHarness                           │
//! │    (consensus + networking, produces committed blocks)      │
//! └─────────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │               EvmExecutionBridge                            │
//! │    (extracts QbindTx from proposals, applies via Revm)      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  NodeCommittedBlock → QbindBlock → apply_qbind_block()      │
//! │  Updates EvmLedger state, verifies roots                    │
//! └─────────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      EvmLedger                              │
//! │    (persistent EVM account state)                           │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Commit Flow
//!
//! When a block is committed:
//! 1. `NodeHotstuffHarness` produces a `NodeCommittedBlock`
//! 2. `EvmExecutionBridge::apply_committed_block()` is called
//! 3. The bridge converts the proposal's txs to `QbindTx` format
//! 4. It calls `apply_qbind_block()` with the execution engine
//! 5. On success, state is updated and roots are stored
//! 6. On failure, the node panics (fatal invariant violation for T151)
//!
//! ## Non-Goals for T151
//!
//! - Full mempool integration (blocks are constructed externally)
//! - Cross-shard execution
//! - State proofs or light client support

use std::collections::HashMap;

use qbind_runtime::{
    apply_qbind_block, Address, BlockApplyError, BlockProposerId, EvmAccountState, EvmLedger,
    QbindBlock, QbindBlockBody, QbindBlockHeader, QbindTx, TxReceipt, H256, ZERO_H256,
};

#[cfg(feature = "default")]
use qbind_runtime::{RevmConfig, RevmExecutionEngine};

use crate::consensus_node::NodeCommittedBlock;

// ============================================================================
// Error type
// ============================================================================

/// Errors that can occur during EVM execution of committed blocks.
#[derive(Debug)]
pub enum EvmCommitError {
    /// Block apply failed (root mismatch or execution error).
    BlockApply(BlockApplyError),

    /// Fatal error: committed block execution failed unexpectedly.
    /// In T151, this causes a panic. Future versions may handle this differently.
    Fatal(String),
}

impl std::fmt::Display for EvmCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvmCommitError::BlockApply(e) => write!(f, "block apply error: {}", e),
            EvmCommitError::Fatal(msg) => write!(f, "fatal error: {}", msg),
        }
    }
}

impl std::error::Error for EvmCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EvmCommitError::BlockApply(e) => Some(e),
            _ => None,
        }
    }
}

impl From<BlockApplyError> for EvmCommitError {
    fn from(e: BlockApplyError) -> Self {
        EvmCommitError::BlockApply(e)
    }
}

// ============================================================================
// EvmExecutionBridge
// ============================================================================

/// Result of applying a committed block to the EVM ledger.
#[derive(Debug, Clone)]
pub struct EvmCommitResult {
    /// Block height.
    pub height: u64,

    /// Block ID (payload hash from consensus).
    pub block_id: [u8; 32],

    /// Transaction receipts from execution.
    pub receipts: Vec<TxReceipt>,

    /// Computed state root after execution.
    pub state_root: H256,

    /// Computed transactions root.
    pub tx_root: H256,

    /// Computed receipts root.
    pub receipts_root: H256,

    /// Total gas used by all transactions in this block (T152).
    pub gas_used: u64,
}

/// Bridge that executes EVM transactions when blocks are committed.
///
/// This component is responsible for:
/// - Converting consensus block proposals to `QbindBlock` format
/// - Executing transactions via the Revm execution engine
/// - Maintaining the EVM ledger state
/// - Computing and storing state roots
///
/// ## Thread Safety
///
/// `EvmExecutionBridge` is NOT thread-safe. It should be called from
/// a single thread that owns the ledger state. This matches the
/// single-threaded consensus model where blocks are committed sequentially.
pub struct EvmExecutionBridge {
    /// The EVM ledger containing account states.
    ledger: EvmLedger,

    /// The Revm execution engine.
    #[cfg(feature = "default")]
    engine: RevmExecutionEngine,

    /// Current block height (for sanity checks).
    current_height: u64,

    /// History of committed block roots (for debugging/verification).
    committed_roots: HashMap<u64, EvmCommitResult>,
}

impl EvmExecutionBridge {
    /// Create a new EVM execution bridge with an empty ledger.
    #[cfg(feature = "default")]
    pub fn new(chain_id: u64) -> Self {
        EvmExecutionBridge {
            ledger: EvmLedger::new(),
            engine: RevmExecutionEngine::new(RevmConfig::new(chain_id)),
            current_height: 0,
            committed_roots: HashMap::new(),
        }
    }

    /// Create a new bridge with a pre-initialized ledger.
    #[cfg(feature = "default")]
    pub fn with_ledger(chain_id: u64, ledger: EvmLedger) -> Self {
        EvmExecutionBridge {
            ledger,
            engine: RevmExecutionEngine::new(RevmConfig::new(chain_id)),
            current_height: 0,
            committed_roots: HashMap::new(),
        }
    }

    /// Get a reference to the EVM ledger.
    pub fn ledger(&self) -> &EvmLedger {
        &self.ledger
    }

    /// Get a mutable reference to the EVM ledger.
    pub fn ledger_mut(&mut self) -> &mut EvmLedger {
        &mut self.ledger
    }

    /// Get the current block height.
    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    /// Get the result of a committed block by height.
    pub fn get_commit_result(&self, height: u64) -> Option<&EvmCommitResult> {
        self.committed_roots.get(&height)
    }

    /// Apply a committed block from consensus to the EVM ledger.
    ///
    /// This method:
    /// 1. Converts the consensus block to a `QbindBlock`
    /// 2. Executes all transactions via the Revm engine
    /// 3. Updates the EVM ledger state
    /// 4. Returns the execution result with roots
    ///
    /// ## Panics
    ///
    /// For T151, this method panics on execution failure. This is a fatal
    /// invariant violation: a committed block must be executable under
    /// the current state. Future versions may handle this differently.
    ///
    /// ## Arguments
    ///
    /// - `block`: The committed block from consensus
    /// - `evm_txs`: The EVM transactions to execute (decoded from proposal)
    ///
    /// ## Returns
    ///
    /// On success, returns `EvmCommitResult` with receipts and computed roots.
    #[cfg(feature = "default")]
    pub fn apply_committed_block(
        &mut self,
        block: &NodeCommittedBlock<[u8; 32]>,
        evm_txs: Vec<QbindTx>,
    ) -> Result<EvmCommitResult, EvmCommitError> {
        let height = block.height;

        // Build QbindBlock from consensus data
        let qbind_block = QbindBlock::new(
            QbindBlockHeader::new(
                ZERO_H256, // Parent hash not tracked yet
                ZERO_H256, // Don't verify state root (compute it)
                ZERO_H256, // Don't verify tx root (compute it)
                ZERO_H256, // Don't verify receipts root (compute it)
                height,
                block.proposal.header.timestamp, // Already in seconds
                BlockProposerId::new(block.proposal.header.proposer_index as u64),
            ),
            QbindBlockBody::new(evm_txs),
        );

        // Execute the block
        let result = apply_qbind_block(&self.engine, &mut self.ledger, &qbind_block)?;

        // Update tracking
        self.current_height = height;

        let commit_result = EvmCommitResult {
            height,
            block_id: block.block_id,
            receipts: result.receipts,
            state_root: result.new_state_root,
            tx_root: result.tx_root,
            receipts_root: result.receipts_root,
            gas_used: result.block_gas_used,
        };

        self.committed_roots.insert(height, commit_result.clone());

        Ok(commit_result)
    }

    /// Apply a committed block with an empty transaction list.
    ///
    /// This is a convenience method for blocks that don't contain EVM transactions.
    #[cfg(feature = "default")]
    pub fn apply_empty_committed_block(
        &mut self,
        block: &NodeCommittedBlock<[u8; 32]>,
    ) -> Result<EvmCommitResult, EvmCommitError> {
        self.apply_committed_block(block, Vec::new())
    }

    /// Compute the current state root of the ledger.
    pub fn compute_state_root(&self) -> H256 {
        self.ledger.compute_state_root()
    }
}

impl std::fmt::Debug for EvmExecutionBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmExecutionBridge")
            .field("current_height", &self.current_height)
            .field("account_count", &self.ledger.account_count())
            .field("committed_blocks", &self.committed_roots.len())
            .finish()
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Initialize an EVM account in the ledger.
///
/// This is a helper for setting up test scenarios or genesis state.
pub fn init_evm_account(
    ledger: &mut EvmLedger,
    addr: Address,
    balance: qbind_runtime::U256,
    nonce: u64,
) {
    ledger.put_account(
        addr,
        EvmAccountState {
            balance,
            nonce,
            code: Vec::new(),
            storage: HashMap::new(),
        },
    );
}

/// Initialize an EVM contract in the ledger.
pub fn init_evm_contract(
    ledger: &mut EvmLedger,
    addr: Address,
    code: Vec<u8>,
    balance: qbind_runtime::U256,
) {
    ledger.put_account(
        addr,
        EvmAccountState {
            balance,
            nonce: 1, // Contracts start with nonce 1
            code,
            storage: HashMap::new(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_runtime::U256;
    use qbind_wire::consensus::{BlockHeader, BlockProposal};
    use std::sync::Arc;

    fn make_test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    fn make_test_proposal(height: u64, round: u64) -> Arc<BlockProposal> {
        Arc::new(BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1337,
                epoch: 0,
                height,
                round,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                suite_id: 0,
                tx_count: 0,
                timestamp: 1704067200, // 2024-01-01 00:00:00 UTC
                payload_kind: 0,       // Normal
                next_epoch: 0,
            },
            qc: None,
            txs: Vec::new(),
            signature: Vec::new(),
        })
    }

    fn make_committed_block(height: u64) -> NodeCommittedBlock<[u8; 32]> {
        NodeCommittedBlock {
            height,
            view: 1,
            block_id: [height as u8; 32],
            proposal: make_test_proposal(height, 1),
        }
    }

    #[test]
    fn test_evm_execution_bridge_creation() {
        let bridge = EvmExecutionBridge::new(1337);
        assert_eq!(bridge.current_height(), 0);
        assert_eq!(bridge.ledger().account_count(), 0);
    }

    #[test]
    fn test_apply_empty_block() {
        let mut bridge = EvmExecutionBridge::new(1337);

        let block = make_committed_block(1);
        let result = bridge.apply_empty_committed_block(&block);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.height, 1);
        assert!(result.receipts.is_empty());
    }

    #[test]
    fn test_apply_transfer_block() {
        let mut bridge = EvmExecutionBridge::new(1337);

        // Setup initial state
        let addr_a = make_test_addr(0xA1);
        let addr_b = make_test_addr(0xB2);

        init_evm_account(
            bridge.ledger_mut(),
            addr_a,
            U256::from_u128(1_000_000_000_000_000_000),
            0,
        );

        // Create transfer tx
        let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );

        let block = make_committed_block(1);
        let result = bridge.apply_committed_block(&block, vec![tx]);

        assert!(result.is_ok(), "apply failed: {:?}", result.err());
        let result = result.unwrap();

        assert_eq!(result.receipts.len(), 1);
        assert!(result.receipts[0].success);

        // Verify B received the transfer
        let b_account = bridge
            .ledger()
            .get_account(&addr_b)
            .expect("B should exist");
        assert_eq!(b_account.balance.to_u64(), Some(100_000));
    }

    #[test]
    fn test_sequential_blocks() {
        let mut bridge = EvmExecutionBridge::new(1337);

        let addr_a = make_test_addr(0xA1);
        let addr_b = make_test_addr(0xB2);

        init_evm_account(
            bridge.ledger_mut(),
            addr_a,
            U256::from_u128(10_000_000_000_000_000_000),
            0,
        );

        // Block 1
        let tx1 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );
        let block1 = make_committed_block(1);
        bridge
            .apply_committed_block(&block1, vec![tx1])
            .expect("block 1 should apply");

        // Block 2 (nonce = 1)
        let tx2 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(50_000), 1).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );
        let block2 = make_committed_block(2);
        bridge
            .apply_committed_block(&block2, vec![tx2])
            .expect("block 2 should apply");

        // Verify final state
        assert_eq!(bridge.current_height(), 2);

        let b_account = bridge
            .ledger()
            .get_account(&addr_b)
            .expect("B should exist");
        assert_eq!(b_account.balance.to_u64(), Some(150_000));

        let a_account = bridge
            .ledger()
            .get_account(&addr_a)
            .expect("A should exist");
        assert_eq!(a_account.nonce, 2);
    }

    #[test]
    fn test_commit_result_tracking() {
        let mut bridge = EvmExecutionBridge::new(1337);

        let block1 = make_committed_block(1);
        bridge.apply_empty_committed_block(&block1).unwrap();

        let block2 = make_committed_block(2);
        bridge.apply_empty_committed_block(&block2).unwrap();

        // Check that results are tracked
        assert!(bridge.get_commit_result(1).is_some());
        assert!(bridge.get_commit_result(2).is_some());
        assert!(bridge.get_commit_result(3).is_none());

        // Verify heights
        assert_eq!(bridge.get_commit_result(1).unwrap().height, 1);
        assert_eq!(bridge.get_commit_result(2).unwrap().height, 2);
    }
}
