//! T152 Block Apply Gas Tests
//!
//! Tests for gas accounting integration in block application:
//! - Single tx gas accounting verification
//! - Cumulative gas across multiple transactions
//! - Effective gas price in receipts
//! - Block gas_used verification

use std::collections::HashMap;

use qbind_runtime::{
    apply_qbind_block, execute_qbind_block_for_proposal, Address, BlockProposerId, EvmAccountState,
    EvmLedger, QbindBlock, QbindBlockBody, QbindBlockHeader, QbindTx, RevmConfig,
    RevmExecutionEngine, U256, ZERO_H256,
};

// ============================================================================
// Helper functions
// ============================================================================

fn make_address(byte: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = byte;
    Address::from_bytes(bytes)
}

fn make_engine() -> RevmExecutionEngine {
    RevmExecutionEngine::new(RevmConfig::new(1337))
}

fn setup_account_with_balance(ledger: &mut EvmLedger, addr: Address, balance: u128) {
    ledger.put_account(
        addr,
        EvmAccountState {
            balance: U256::from_u128(balance),
            nonce: 0,
            code: Vec::new(),
            storage: HashMap::new(),
        },
    );
}

// ============================================================================
// Test: Single tx gas accounting
// ============================================================================

#[test]
fn test_single_tx_gas_accounting() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Give A plenty of balance
    setup_account_with_balance(&mut ledger, addr_a, 10_000_000_000_000_000_000);

    // Create transfer tx
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
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

    let result = apply_qbind_block(&engine, &mut ledger, &block).expect("block should apply");

    // Verify receipts have gas accounting
    assert_eq!(result.receipts.len(), 1);
    assert!(result.receipts[0].success);
    assert_eq!(result.receipts[0].gas_used, 21000);
    assert_eq!(result.receipts[0].cumulative_gas_used, 21000);

    // Verify effective_gas_price is set (should be basefee + tip)
    // basefee = 1_000_000_000 (from block_apply.rs default)
    // max_fee = 1_000_000_000, max_priority = 1_000_000_000
    // effective = 1B + min(1B, 1B - 1B) = 1B + 0 = 1B
    assert_eq!(result.receipts[0].effective_gas_price, 1_000_000_000);

    // Verify block gas used
    assert_eq!(result.block_gas_used, 21000);
}

// ============================================================================
// Test: Two-tx block cumulative gas
// ============================================================================

#[test]
fn test_two_tx_cumulative_gas() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);
    let addr_c = make_address(0xC3);

    setup_account_with_balance(&mut ledger, addr_a, 10_000_000_000_000_000_000);
    setup_account_with_balance(&mut ledger, addr_b, 10_000_000_000_000_000_000);

    // Two transfers
    let tx1 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let tx2 = QbindTx::transfer(addr_b, addr_c, U256::from_u64(50_000), 0).with_gas(
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
        QbindBlockBody::new(vec![tx1, tx2]),
    );

    let result = apply_qbind_block(&engine, &mut ledger, &block).expect("block should apply");

    assert_eq!(result.receipts.len(), 2);

    // First tx
    assert_eq!(result.receipts[0].gas_used, 21000);
    assert_eq!(result.receipts[0].cumulative_gas_used, 21000);

    // Second tx
    assert_eq!(result.receipts[1].gas_used, 21000);
    assert_eq!(result.receipts[1].cumulative_gas_used, 42000);

    // Block total
    assert_eq!(result.block_gas_used, 42000);
}

// ============================================================================
// Test: Effective gas price in receipt
// ============================================================================

#[test]
fn test_effective_gas_price_in_receipt() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 10_000_000_000_000_000_000);

    // Use different max_fee and max_priority_fee
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        2_000_000_000, // max_fee = 2 Gwei
        500_000_000,   // max_priority = 0.5 Gwei
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

    let result = apply_qbind_block(&engine, &mut ledger, &block).expect("block should apply");

    // basefee = 1_000_000_000
    // headroom = 2_000_000_000 - 1_000_000_000 = 1_000_000_000
    // tip = min(500_000_000, 1_000_000_000) = 500_000_000
    // effective = 1_000_000_000 + 500_000_000 = 1_500_000_000
    assert_eq!(result.receipts[0].effective_gas_price, 1_500_000_000);
}

// ============================================================================
// Test: Block gas_used verification
// ============================================================================

#[test]
fn test_block_gas_used_header_verification() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 10_000_000_000_000_000_000);

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    // Create block with correct gas_used in header
    let block = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            1,
            1704067200,
            BlockProposerId::new(0),
        )
        .with_gas(21000, 30_000_000), // Correct gas_used
        QbindBlockBody::new(vec![tx]),
    );

    let result = apply_qbind_block(&engine, &mut ledger, &block);
    assert!(result.is_ok(), "block with correct gas_used should apply");
}

#[test]
fn test_block_gas_used_mismatch_rejected() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 10_000_000_000_000_000_000);

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    // Create block with WRONG gas_used in header
    let block = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            1,
            1704067200,
            BlockProposerId::new(0),
        )
        .with_gas(99999, 30_000_000), // Wrong gas_used!
        QbindBlockBody::new(vec![tx]),
    );

    let result = apply_qbind_block(&engine, &mut ledger, &block);
    assert!(result.is_err(), "block with wrong gas_used should fail");

    // Error message should mention gas_used mismatch
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("gas_used mismatch"),
        "error should mention gas_used: {}",
        err_msg
    );
}

// ============================================================================
// Test: execute_qbind_block_for_proposal returns block_gas_used
// ============================================================================

#[test]
fn test_proposal_execution_returns_gas_used() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 10_000_000_000_000_000_000);

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    // Proposer doesn't set gas_used, it's computed
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

    let result =
        execute_qbind_block_for_proposal(&engine, &mut ledger, &block).expect("should succeed");

    // block_gas_used should be computed
    assert_eq!(result.block_gas_used, 21000);
}

// ============================================================================
// Test: Empty block has zero gas
// ============================================================================

#[test]
fn test_empty_block_zero_gas() {
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

    let result = apply_qbind_block(&engine, &mut ledger, &block).expect("empty block should apply");

    assert!(result.receipts.is_empty());
    assert_eq!(result.block_gas_used, 0);
}
