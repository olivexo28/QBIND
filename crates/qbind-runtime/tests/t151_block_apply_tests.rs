//! T151 Block Apply Tests
//!
//! Tests for the QBIND block application logic that wires execution
//! to ledger state updates.
//!
//! These tests verify:
//! 1. Empty block application
//! 2. Simple transfer block
//! 3. Contract deployment + call in a block
//! 4. Root mismatch detection and rollback
//! 5. Deterministic execution
//! 6. Out-of-gas handling

use std::collections::HashMap;

use qbind_runtime::{
    apply_qbind_block, execute_qbind_block_for_proposal, Address, BlockApplyError, BlockProposerId,
    EvmAccountState, EvmLedger, QbindBlock, QbindBlockBody, QbindBlockHeader, QbindTx, RevmConfig,
    RevmExecutionEngine, RootMismatchKind, U256, ZERO_H256,
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
// Test 5.1.1: Empty block
// ============================================================================

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
    assert!(
        result.is_ok(),
        "empty block should apply: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert!(result.receipts.is_empty());
    assert_eq!(result.tx_root, ZERO_H256);
    assert_eq!(result.receipts_root, ZERO_H256);
}

// ============================================================================
// Test 5.1.2: Simple transfer block
// ============================================================================

#[test]
fn test_apply_simple_transfer_block() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    // Setup: A has 1 ETH
    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);

    // Create block with single transfer
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

    let result = apply_qbind_block(&engine, &mut ledger, &block);
    assert!(
        result.is_ok(),
        "transfer block should apply: {:?}",
        result.err()
    );

    let result = result.unwrap();

    // Verify receipts
    assert_eq!(result.receipts.len(), 1);
    assert!(result.receipts[0].success, "transfer should succeed");
    assert_eq!(result.receipts[0].gas_used, 21000);

    // Verify state changes
    let b_account = ledger.get_account(&addr_b).expect("B should exist");
    assert_eq!(b_account.balance.to_u64(), Some(100_000));

    let a_account = ledger.get_account(&addr_a).expect("A should exist");
    assert_eq!(a_account.nonce, 1);

    // Verify roots are non-zero
    assert_ne!(result.tx_root, ZERO_H256);
    assert_ne!(result.receipts_root, ZERO_H256);
}

// ============================================================================
// Test 5.1.3: Multiple transfers in a block
// ============================================================================

#[test]
fn test_apply_multiple_transfers_block() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);
    let addr_c = make_address(0xC3);

    // Setup initial balances
    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);
    setup_account_with_balance(&mut ledger, addr_b, 1_000_000_000_000_000_000);

    // A -> B, B -> C
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

    let result = apply_qbind_block(&engine, &mut ledger, &block).expect("should succeed");

    assert_eq!(result.receipts.len(), 2);
    assert!(result.receipts[0].success);
    assert!(result.receipts[1].success);

    // Verify C got the value
    let c_account = ledger.get_account(&addr_c).expect("C should exist");
    assert_eq!(c_account.balance.to_u64(), Some(50_000));

    // Verify cumulative gas
    assert_eq!(result.receipts[0].cumulative_gas_used, 21000);
    assert_eq!(result.receipts[1].cumulative_gas_used, 42000);
}

// ============================================================================
// Test 5.1.4: Root mismatch - tx_root
// ============================================================================

#[test]
fn test_root_mismatch_tx_root() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);

    // Record initial state
    let initial_state_root = ledger.compute_state_root();

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
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
        BlockApplyError::RootMismatch {
            kind,
            expected,
            computed,
        } => {
            assert_eq!(kind, RootMismatchKind::TxRoot);
            assert_eq!(expected, wrong_root);
            assert_ne!(computed, wrong_root);
        }
        other => panic!("expected RootMismatch, got {:?}", other),
    }

    // Verify state was rolled back
    let final_state_root = ledger.compute_state_root();
    assert_eq!(initial_state_root, final_state_root);

    // B should NOT have received anything
    assert!(ledger.get_account(&addr_b).is_none());
}

// ============================================================================
// Test 5.1.5: Root mismatch - state_root
// ============================================================================

#[test]
fn test_root_mismatch_state_root() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);

    let initial_state_root = ledger.compute_state_root();

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    // Create block with WRONG state_root
    let wrong_root = [0xAA; 32];
    let block = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            wrong_root, // Wrong state root!
            ZERO_H256,
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
            assert_eq!(kind, RootMismatchKind::StateRoot);
        }
        other => panic!("expected RootMismatch, got {:?}", other),
    }

    // State should be rolled back
    assert_eq!(ledger.compute_state_root(), initial_state_root);
}

// ============================================================================
// Test 5.1.6: Deterministic execution
// ============================================================================

#[test]
fn test_deterministic_block_execution() {
    let engine = make_engine();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Setup two identical ledgers
    let mut ledger1 = EvmLedger::new();
    let mut ledger2 = EvmLedger::new();

    setup_account_with_balance(&mut ledger1, addr_a, 1_000_000_000_000_000_000);
    setup_account_with_balance(&mut ledger2, addr_a, 1_000_000_000_000_000_000);

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

    let result1 = apply_qbind_block(&engine, &mut ledger1, &block.clone()).unwrap();
    let result2 = apply_qbind_block(&engine, &mut ledger2, &block).unwrap();

    // All roots must match
    assert_eq!(result1.tx_root, result2.tx_root);
    assert_eq!(result1.receipts_root, result2.receipts_root);
    assert_eq!(result1.new_state_root, result2.new_state_root);

    // Receipts must match
    assert_eq!(result1.receipts.len(), result2.receipts.len());
    assert_eq!(result1.receipts[0].success, result2.receipts[0].success);
    assert_eq!(result1.receipts[0].gas_used, result2.receipts[0].gas_used);

    // Final ledger states must match
    assert_eq!(ledger1.compute_state_root(), ledger2.compute_state_root());
}

// ============================================================================
// Test 5.1.7: Sequential block determinism
// ============================================================================

#[test]
fn test_sequential_block_determinism() {
    let engine = make_engine();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    let mut ledger1 = EvmLedger::new();
    let mut ledger2 = EvmLedger::new();

    setup_account_with_balance(&mut ledger1, addr_a, 10_000_000_000_000_000_000);
    setup_account_with_balance(&mut ledger2, addr_a, 10_000_000_000_000_000_000);

    // Block 1: A -> B
    let block1 = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            1,
            1704067200,
            BlockProposerId::new(0),
        ),
        QbindBlockBody::new(vec![QbindTx::transfer(
            addr_a,
            addr_b,
            U256::from_u64(100_000),
            0,
        )
        .with_gas(21000, 1_000_000_000, 1_000_000_000)]),
    );

    // Block 2: A -> B again (nonce = 1)
    let block2 = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            2,
            1704067300,
            BlockProposerId::new(0),
        ),
        QbindBlockBody::new(vec![QbindTx::transfer(
            addr_a,
            addr_b,
            U256::from_u64(50_000),
            1, // nonce = 1
        )
        .with_gas(21000, 1_000_000_000, 1_000_000_000)]),
    );

    // Apply to both ledgers
    apply_qbind_block(&engine, &mut ledger1, &block1).unwrap();
    apply_qbind_block(&engine, &mut ledger1, &block2).unwrap();

    apply_qbind_block(&engine, &mut ledger2, &block1).unwrap();
    apply_qbind_block(&engine, &mut ledger2, &block2).unwrap();

    // Final states must match
    assert_eq!(ledger1.compute_state_root(), ledger2.compute_state_root());

    // B should have 150,000
    let b_account = ledger1.get_account(&addr_b).unwrap();
    assert_eq!(b_account.balance.to_u64(), Some(150_000));
}

// ============================================================================
// Test 5.1.8: execute_qbind_block_for_proposal (no validation)
// ============================================================================

#[test]
fn test_execute_for_proposal() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    // Create block with placeholder roots (will be ignored)
    let block = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            [0x11; 32], // Placeholder - ignored
            [0x22; 32], // Placeholder - ignored
            [0x33; 32], // Placeholder - ignored
            1,
            1704067200,
            BlockProposerId::new(0),
        ),
        QbindBlockBody::new(vec![tx]),
    );

    // execute_qbind_block_for_proposal ignores header roots
    let result = execute_qbind_block_for_proposal(&engine, &mut ledger, &block);
    assert!(result.is_ok(), "proposal execution should succeed");

    let result = result.unwrap();

    // State was updated (not rolled back)
    let b_account = ledger.get_account(&addr_b).expect("B should exist");
    assert_eq!(b_account.balance.to_u64(), Some(100_000));

    // Computed roots are correct for use in the final header
    assert_ne!(result.tx_root, ZERO_H256);
    assert_ne!(result.receipts_root, ZERO_H256);
    assert_ne!(result.new_state_root, ZERO_H256);
}

// ============================================================================
// Test 5.1.9: Contract deployment in a block
// ============================================================================

#[test]
fn test_contract_deployment_block() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let deployer = make_address(0xD1);

    setup_account_with_balance(&mut ledger, deployer, 10_000_000_000_000_000_000);

    // Simple contract init code: PUSH1 0 PUSH1 0 RETURN (returns empty)
    let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];

    let tx = QbindTx::create(deployer, init_code, U256::zero(), 0, 1_000_000).with_gas(
        1_000_000,
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

    let result = apply_qbind_block(&engine, &mut ledger, &block);
    assert!(
        result.is_ok(),
        "deployment should succeed: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert_eq!(result.receipts.len(), 1);

    // Deployer nonce should increment
    let deployer_account = ledger
        .get_account(&deployer)
        .expect("deployer should exist");
    assert_eq!(deployer_account.nonce, 1);
}

// ============================================================================
// Test 5.1.10: OOG in block
// ============================================================================

#[test]
fn test_oog_transaction_in_block() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);

    // Transaction with insufficient gas
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        10_000,
        1_000_000_000,
        1_000_000_000,
    ); // Only 10k gas, need 21k

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

    let result = apply_qbind_block(&engine, &mut ledger, &block);

    // The block may either fail to apply (validation error) or succeed with failed tx
    // Either way, B should NOT have received value
    match result {
        Ok(result) => {
            // If block applied, check the receipt
            assert_eq!(result.receipts.len(), 1);
            assert!(!result.receipts[0].success, "OOG tx should fail");
        }
        Err(_) => {
            // Block-level validation error is also acceptable
        }
    }

    // B should have nothing
    assert!(
        ledger.get_account(&addr_b).is_none()
            || ledger.get_account(&addr_b).unwrap().balance.is_zero()
    );
}

// ============================================================================
// Test 5.1.11: Valid roots verification
// ============================================================================

#[test]
fn test_apply_with_correct_roots() {
    let engine = make_engine();
    let mut ledger = EvmLedger::new();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    setup_account_with_balance(&mut ledger, addr_a, 1_000_000_000_000_000_000);

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    // First, compute the correct roots
    let mut temp_ledger = EvmLedger::new();
    setup_account_with_balance(&mut temp_ledger, addr_a, 1_000_000_000_000_000_000);

    let temp_block = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            ZERO_H256,
            1,
            1704067200,
            BlockProposerId::new(0),
        ),
        QbindBlockBody::new(vec![tx.clone()]),
    );

    let temp_result =
        execute_qbind_block_for_proposal(&engine, &mut temp_ledger, &temp_block).unwrap();

    // Now create a block with the correct roots
    let block = QbindBlock::new(
        QbindBlockHeader::new(
            ZERO_H256,
            temp_result.new_state_root,
            temp_result.tx_root,
            temp_result.receipts_root,
            1,
            1704067200,
            BlockProposerId::new(0),
        ),
        QbindBlockBody::new(vec![tx]),
    );

    // Apply should succeed with matching roots
    let result = apply_qbind_block(&engine, &mut ledger, &block);
    assert!(
        result.is_ok(),
        "block with correct roots should apply: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert_eq!(result.tx_root, temp_result.tx_root);
    assert_eq!(result.receipts_root, temp_result.receipts_root);
    assert_eq!(result.new_state_root, temp_result.new_state_root);
}
