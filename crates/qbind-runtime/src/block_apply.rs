//! Block application logic for executing QBIND blocks.
//!
//! This module provides the `apply_qbind_block` function that:
//! 1. Executes all transactions in a block via the execution engine
//! 2. Updates ledger state
//! 3. Computes and validates Merkle roots
//!
//! ## Determinism
//!
//! Block application is deterministic: given the same:
//! - Pre-state (EvmLedger)
//! - Block (QbindBlock)
//! - Execution engine configuration
//!
//! The result will always be identical: same receipts, same post-state,
//! same computed roots.

use std::fmt;

use crate::block::{compute_receipts_root, compute_tx_root, QbindBlock, H256, ZERO_H256};
use crate::evm_state::{EvmLedger, LedgerStateView};
use crate::execution_engine::{EvmExecutionError, ExecutionEngine, TxReceipt};
use crate::qbind_tx::{QbindBlockEnv, QbindTx};
use crate::Address;

// ============================================================================
// Block apply result and error types
// ============================================================================

/// Result of successfully applying a block.
#[derive(Clone, Debug)]
pub struct BlockApplyResult {
    /// Transaction receipts, one per transaction.
    pub receipts: Vec<TxReceipt>,

    /// The new state root after block execution.
    pub new_state_root: H256,

    /// The computed transactions root.
    pub tx_root: H256,

    /// The computed receipts root.
    pub receipts_root: H256,
}

/// Errors that can occur when applying a block.
#[derive(Debug)]
pub enum BlockApplyError {
    /// Execution engine returned an error.
    Execution(EvmExecutionError),

    /// Header root does not match computed root.
    RootMismatch {
        /// Which root mismatched.
        kind: RootMismatchKind,
        /// Expected value from header.
        expected: H256,
        /// Computed value from execution.
        computed: H256,
    },

    /// Block number is invalid for the current ledger state.
    InvalidBlockNumber { expected: u64, got: u64 },

    /// Internal error during block application.
    Internal(String),
}

/// Which type of root had a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootMismatchKind {
    StateRoot,
    TxRoot,
    ReceiptsRoot,
}

impl fmt::Display for BlockApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockApplyError::Execution(e) => write!(f, "execution error: {}", e),
            BlockApplyError::RootMismatch {
                kind,
                expected,
                computed,
            } => {
                write!(
                    f,
                    "{:?} mismatch: expected {:?}, computed {:?}",
                    kind, expected, computed
                )
            }
            BlockApplyError::InvalidBlockNumber { expected, got } => {
                write!(
                    f,
                    "invalid block number: expected {}, got {}",
                    expected, got
                )
            }
            BlockApplyError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for BlockApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlockApplyError::Execution(e) => Some(e),
            _ => None,
        }
    }
}

// ============================================================================
// Block apply function
// ============================================================================

/// Apply a QBIND block to the EVM ledger.
///
/// This function:
/// 1. Creates a block environment from the header
/// 2. Executes all transactions via the execution engine
/// 3. Computes tx_root, receipts_root, and new_state_root
/// 4. Validates roots against header (if non-zero)
/// 5. On success, commits state changes and returns result
///
/// ## Root Validation
///
/// If any of the header's roots are non-zero, they are validated against
/// the computed values. If they don't match, `BlockApplyError::RootMismatch`
/// is returned and **no state changes are committed**.
///
/// Zero roots in the header are treated as "don't verify" - this allows
/// block proposers to first execute a block to compute roots, then
/// include them in the header.
///
/// ## Type Parameters
///
/// - `E`: The execution engine type (e.g., `RevmExecutionEngine`)
///
/// ## Arguments
///
/// - `engine`: The execution engine to use
/// - `ledger`: The EVM ledger to apply changes to
/// - `block`: The block to apply
///
/// ## Returns
///
/// On success, returns `BlockApplyResult` with receipts and computed roots.
/// On failure, returns `BlockApplyError` and the ledger is **unchanged**.
pub fn apply_qbind_block<E>(
    engine: &E,
    ledger: &mut EvmLedger,
    block: &QbindBlock,
) -> Result<BlockApplyResult, BlockApplyError>
where
    E: ExecutionEngine<
        Tx = QbindTx,
        BlockEnv = QbindBlockEnv,
        Receipt = TxReceipt,
        ExecutionError = EvmExecutionError,
    >,
{
    // Take a snapshot for potential rollback
    let snapshot = ledger.snapshot();

    // Build block environment from header
    let block_env = QbindBlockEnv {
        number: block.header.number,
        timestamp: block.header.timestamp,
        basefee: 1_000_000_000, // 1 Gwei default for T151
        gas_limit: 30_000_000,  // 30M gas limit
        coinbase: Address::zero(),
        chain_id: 1337,
        prev_randao: crate::U256::zero(),
    };

    // Create state view over ledger
    let mut state_view = LedgerStateView::new(ledger);

    // Execute all transactions
    let receipts = engine
        .execute_block(&block_env, &mut state_view, &block.body.transactions)
        .map_err(BlockApplyError::Execution)?;

    // Compute roots
    let tx_root = compute_tx_root(&block.body);
    let receipts_root = compute_receipts_root(&receipts);
    let new_state_root = state_view.ledger().compute_state_root();

    // Validate roots against header (if non-zero)
    if block.header.tx_root != ZERO_H256 && block.header.tx_root != tx_root {
        // Rollback
        ledger.restore(snapshot);
        return Err(BlockApplyError::RootMismatch {
            kind: RootMismatchKind::TxRoot,
            expected: block.header.tx_root,
            computed: tx_root,
        });
    }

    if block.header.receipts_root != ZERO_H256 && block.header.receipts_root != receipts_root {
        ledger.restore(snapshot);
        return Err(BlockApplyError::RootMismatch {
            kind: RootMismatchKind::ReceiptsRoot,
            expected: block.header.receipts_root,
            computed: receipts_root,
        });
    }

    if block.header.state_root != ZERO_H256 && block.header.state_root != new_state_root {
        ledger.restore(snapshot);
        return Err(BlockApplyError::RootMismatch {
            kind: RootMismatchKind::StateRoot,
            expected: block.header.state_root,
            computed: new_state_root,
        });
    }

    // Success - state is already committed through the state view
    Ok(BlockApplyResult {
        receipts,
        new_state_root,
        tx_root,
        receipts_root,
    })
}

/// Execute a block without root validation, returning computed roots.
///
/// This is useful for block proposers who need to compute roots
/// before including them in the block header.
///
/// Unlike `apply_qbind_block`, this function:
/// - Does NOT validate roots against the header
/// - Always applies state changes on successful execution
///
/// ## Arguments
///
/// - `engine`: The execution engine to use
/// - `ledger`: The EVM ledger to apply changes to
/// - `block`: The block to execute
///
/// ## Returns
///
/// On success, returns `BlockApplyResult` with receipts and computed roots.
/// The ledger state is updated.
pub fn execute_qbind_block_for_proposal<E>(
    engine: &E,
    ledger: &mut EvmLedger,
    block: &QbindBlock,
) -> Result<BlockApplyResult, BlockApplyError>
where
    E: ExecutionEngine<
        Tx = QbindTx,
        BlockEnv = QbindBlockEnv,
        Receipt = TxReceipt,
        ExecutionError = EvmExecutionError,
    >,
{
    // Build block environment from header
    let block_env = QbindBlockEnv {
        number: block.header.number,
        timestamp: block.header.timestamp,
        basefee: 1_000_000_000,
        gas_limit: 30_000_000,
        coinbase: Address::zero(),
        chain_id: 1337,
        prev_randao: crate::U256::zero(),
    };

    // Create state view over ledger
    let mut state_view = LedgerStateView::new(ledger);

    // Execute all transactions
    let receipts = engine
        .execute_block(&block_env, &mut state_view, &block.body.transactions)
        .map_err(BlockApplyError::Execution)?;

    // Compute roots
    let tx_root = compute_tx_root(&block.body);
    let receipts_root = compute_receipts_root(&receipts);
    let new_state_root = state_view.ledger().compute_state_root();

    Ok(BlockApplyResult {
        receipts,
        new_state_root,
        tx_root,
        receipts_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockProposerId, QbindBlockBody, QbindBlockHeader};
    use crate::evm_types::{EvmAccountState, U256};

    #[cfg(feature = "evm")]
    use crate::revm_engine::{RevmConfig, RevmExecutionEngine};

    fn make_test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    #[cfg(feature = "evm")]
    fn make_engine() -> RevmExecutionEngine {
        RevmExecutionEngine::new(RevmConfig::new(1337))
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_apply_empty_block() {
        let engine = make_engine();
        let mut ledger = EvmLedger::new();

        let block = QbindBlock::new(
            QbindBlockHeader::new(
                ZERO_H256,
                ZERO_H256,
                ZERO_H256,
                ZERO_H256,
                1,
                1704067200,
                BlockProposerId::new(0),
            ),
            QbindBlockBody::empty(),
        );

        let result = apply_qbind_block(&engine, &mut ledger, &block);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.receipts.is_empty());
        assert_eq!(result.tx_root, ZERO_H256);
        assert_eq!(result.receipts_root, ZERO_H256);
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_apply_transfer_block() {
        let engine = make_engine();
        let mut ledger = EvmLedger::new();

        // Setup initial state
        let addr_a = make_test_addr(0xA1);
        let addr_b = make_test_addr(0xB2);

        ledger.put_account(
            addr_a,
            EvmAccountState {
                balance: U256::from_u128(1_000_000_000_000_000_000),
                nonce: 0,
                code: Vec::new(),
                storage: std::collections::HashMap::new(),
            },
        );

        // Create block with transfer
        let tx = crate::QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );

        let block = QbindBlock::new(
            QbindBlockHeader::new(
                ZERO_H256,
                ZERO_H256, // Don't verify state root
                ZERO_H256, // Don't verify tx root
                ZERO_H256, // Don't verify receipts root
                1,
                1704067200,
                BlockProposerId::new(0),
            ),
            QbindBlockBody::new(vec![tx]),
        );

        let result = apply_qbind_block(&engine, &mut ledger, &block);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let result = result.unwrap();
        assert_eq!(result.receipts.len(), 1);
        assert!(result.receipts[0].success);

        // Verify state changes
        let b_account = ledger.get_account(&addr_b).expect("B should exist");
        assert_eq!(b_account.balance.to_u64(), Some(100_000));

        let a_account = ledger.get_account(&addr_a).expect("A should exist");
        assert_eq!(a_account.nonce, 1);
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_root_mismatch_rollback() {
        let engine = make_engine();
        let mut ledger = EvmLedger::new();

        let addr_a = make_test_addr(0xA1);
        let addr_b = make_test_addr(0xB2);

        ledger.put_account(
            addr_a,
            EvmAccountState {
                balance: U256::from_u128(1_000_000_000_000_000_000),
                nonce: 0,
                code: Vec::new(),
                storage: std::collections::HashMap::new(),
            },
        );

        // Record initial state
        let initial_state_root = ledger.compute_state_root();

        let tx = crate::QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );

        // Create block with WRONG tx_root
        let wrong_root = [0xFF; 32];
        let block = QbindBlock::new(
            QbindBlockHeader::new(
                ZERO_H256,
                ZERO_H256,
                wrong_root, // Wrong tx root!
                ZERO_H256,
                1,
                1704067200,
                BlockProposerId::new(0),
            ),
            QbindBlockBody::new(vec![tx]),
        );

        let result = apply_qbind_block(&engine, &mut ledger, &block);
        assert!(result.is_err());

        match result.err().unwrap() {
            BlockApplyError::RootMismatch { kind, .. } => {
                assert_eq!(kind, RootMismatchKind::TxRoot);
            }
            other => panic!("expected RootMismatch, got {:?}", other),
        }

        // Verify state was rolled back
        let final_state_root = ledger.compute_state_root();
        assert_eq!(initial_state_root, final_state_root);

        // B should NOT have received anything
        assert!(ledger.get_account(&addr_b).is_none());
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_deterministic_execution() {
        let engine = make_engine();

        let addr_a = make_test_addr(0xA1);
        let addr_b = make_test_addr(0xB2);

        let initial_account = EvmAccountState {
            balance: U256::from_u128(1_000_000_000_000_000_000),
            nonce: 0,
            code: Vec::new(),
            storage: std::collections::HashMap::new(),
        };

        // Create two identical ledgers
        let mut ledger1 = EvmLedger::new();
        let mut ledger2 = EvmLedger::new();

        ledger1.put_account(addr_a, initial_account.clone());
        ledger2.put_account(addr_a, initial_account);

        let tx = crate::QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );

        let block = QbindBlock::new(
            QbindBlockHeader::new(
                ZERO_H256,
                ZERO_H256,
                ZERO_H256,
                ZERO_H256,
                1,
                1704067200,
                BlockProposerId::new(0),
            ),
            QbindBlockBody::new(vec![tx]),
        );

        let result1 = apply_qbind_block(&engine, &mut ledger1, &block.clone()).unwrap();
        let result2 = apply_qbind_block(&engine, &mut ledger2, &block).unwrap();

        // Results should be identical
        assert_eq!(result1.tx_root, result2.tx_root);
        assert_eq!(result1.receipts_root, result2.receipts_root);
        assert_eq!(result1.new_state_root, result2.new_state_root);
        assert_eq!(result1.receipts.len(), result2.receipts.len());
    }
}