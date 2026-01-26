//! T151 Commit Execution Integration Tests
//!
//! Tests for the EVM execution bridge integration with consensus commit.
//!
//! These tests verify:
//! 1. EVM execution bridge creation and initialization
//! 2. Empty block commit through the bridge
//! 3. Transfer block commit with state updates
//! 4. Sequential block commits with nonce tracking
//! 5. Deterministic state root computation

use std::collections::HashMap;
use std::sync::Arc;

use qbind_node::evm_commit::{init_evm_account, EvmExecutionBridge};
use qbind_node::NodeCommittedBlock;
use qbind_runtime::{Address, EvmAccountState, EvmLedger, QbindTx, U256};
use qbind_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Helper functions
// ============================================================================

fn make_address(byte: u8) -> Address {
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
            payload_hash: [height as u8; 32],
            proposer_index: 0,
            suite_id: 0,
            tx_count: 0,
            timestamp: 1704067200 + height, // Increment timestamp per block
            payload_kind: 0,
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

// ============================================================================
// Test: Bridge creation
// ============================================================================

#[test]
fn test_bridge_creation() {
    let bridge = EvmExecutionBridge::new(1337);
    assert_eq!(bridge.current_height(), 0);
    assert_eq!(bridge.ledger().account_count(), 0);
}

#[test]
fn test_bridge_with_initial_ledger() {
    let mut ledger = EvmLedger::new();
    let addr = make_address(1);

    ledger.put_account(
        addr,
        EvmAccountState {
            balance: U256::from_u64(1000),
            nonce: 0,
            code: Vec::new(),
            storage: HashMap::new(),
        },
    );

    let bridge = EvmExecutionBridge::with_ledger(1337, ledger);
    assert_eq!(bridge.ledger().account_count(), 1);
}

// ============================================================================
// Test: Empty block commit
// ============================================================================

#[test]
fn test_commit_empty_block() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let block = make_committed_block(1);
    let result = bridge.apply_empty_committed_block(&block);

    assert!(
        result.is_ok(),
        "empty block commit failed: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert_eq!(result.height, 1);
    assert!(result.receipts.is_empty());
    assert_eq!(bridge.current_height(), 1);
}

// ============================================================================
// Test: Transfer block commit
// ============================================================================

#[test]
fn test_commit_transfer_block() {
    let mut bridge = EvmExecutionBridge::new(1337);

    // Setup initial state
    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(1_000_000_000_000_000_000),
        0,
    );

    // Create transfer
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    let block = make_committed_block(1);
    let result = bridge.apply_committed_block(&block, vec![tx]);

    assert!(result.is_ok(), "transfer commit failed: {:?}", result.err());

    let result = result.unwrap();
    assert_eq!(result.receipts.len(), 1);
    assert!(result.receipts[0].success);

    // Verify state
    let b = bridge
        .ledger()
        .get_account(&addr_b)
        .expect("B should exist");
    assert_eq!(b.balance.to_u64(), Some(100_000));

    let a = bridge
        .ledger()
        .get_account(&addr_a)
        .expect("A should exist");
    assert_eq!(a.nonce, 1);
}

// ============================================================================
// Test: Sequential block commits
// ============================================================================

#[test]
fn test_sequential_block_commits() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    // Block 1: A -> B (100k)
    let tx1 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block1 = make_committed_block(1);
    bridge
        .apply_committed_block(&block1, vec![tx1])
        .expect("block 1 should commit");

    // Block 2: A -> B (50k, nonce = 1)
    let tx2 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(50_000), 1).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block2 = make_committed_block(2);
    bridge
        .apply_committed_block(&block2, vec![tx2])
        .expect("block 2 should commit");

    // Block 3: A -> B (25k, nonce = 2)
    let tx3 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(25_000), 2).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block3 = make_committed_block(3);
    bridge
        .apply_committed_block(&block3, vec![tx3])
        .expect("block 3 should commit");

    // Verify final state
    assert_eq!(bridge.current_height(), 3);

    let b = bridge
        .ledger()
        .get_account(&addr_b)
        .expect("B should exist");
    assert_eq!(b.balance.to_u64(), Some(175_000)); // 100k + 50k + 25k

    let a = bridge
        .ledger()
        .get_account(&addr_a)
        .expect("A should exist");
    assert_eq!(a.nonce, 3);
}

// ============================================================================
// Test: Commit result tracking
// ============================================================================

#[test]
fn test_commit_result_tracking() {
    let mut bridge = EvmExecutionBridge::new(1337);

    // Commit 3 empty blocks
    for height in 1..=3 {
        let block = make_committed_block(height);
        bridge.apply_empty_committed_block(&block).unwrap();
    }

    // Verify tracking
    for height in 1..=3 {
        let result = bridge.get_commit_result(height);
        assert!(
            result.is_some(),
            "result for height {} should exist",
            height
        );
        assert_eq!(result.unwrap().height, height);
    }

    assert!(bridge.get_commit_result(4).is_none());
    assert!(bridge.get_commit_result(0).is_none());
}

// ============================================================================
// Test: Deterministic state roots
// ============================================================================

#[test]
fn test_deterministic_state_roots() {
    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Create two independent bridges with same initial state
    let mut bridge1 = EvmExecutionBridge::new(1337);
    let mut bridge2 = EvmExecutionBridge::new(1337);

    init_evm_account(
        bridge1.ledger_mut(),
        addr_a,
        U256::from_u128(1_000_000_000_000_000_000),
        0,
    );
    init_evm_account(
        bridge2.ledger_mut(),
        addr_a,
        U256::from_u128(1_000_000_000_000_000_000),
        0,
    );

    // Same transaction
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    let block = make_committed_block(1);

    let result1 = bridge1
        .apply_committed_block(&block.clone(), vec![tx.clone()])
        .unwrap();
    let result2 = bridge2.apply_committed_block(&block, vec![tx]).unwrap();

    // Roots must match
    assert_eq!(result1.state_root, result2.state_root);
    assert_eq!(result1.tx_root, result2.tx_root);
    assert_eq!(result1.receipts_root, result2.receipts_root);

    // Final ledger states must match
    assert_eq!(bridge1.compute_state_root(), bridge2.compute_state_root());
}

// ============================================================================
// Test: State root verification across multiple blocks
// ============================================================================

#[test]
fn test_state_root_evolution() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    let root_0 = bridge.compute_state_root();

    // Block 1
    let tx1 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block1 = make_committed_block(1);
    let result1 = bridge.apply_committed_block(&block1, vec![tx1]).unwrap();

    let root_1 = bridge.compute_state_root();
    assert_eq!(root_1, result1.state_root);
    assert_ne!(root_0, root_1); // State changed

    // Block 2
    let tx2 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(50_000), 1).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block2 = make_committed_block(2);
    let result2 = bridge.apply_committed_block(&block2, vec![tx2]).unwrap();

    let root_2 = bridge.compute_state_root();
    assert_eq!(root_2, result2.state_root);
    assert_ne!(root_1, root_2); // State changed again
}

// ============================================================================
// Test: Multiple transactions per block
// ============================================================================

#[test]
fn test_multiple_transactions_per_block() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);
    let addr_c = make_address(0xC3);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );
    init_evm_account(
        bridge.ledger_mut(),
        addr_b,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    // Block with 2 txs: A -> B, B -> C
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

    let block = make_committed_block(1);
    let result = bridge
        .apply_committed_block(&block, vec![tx1, tx2])
        .unwrap();

    assert_eq!(result.receipts.len(), 2);
    assert!(result.receipts[0].success);
    assert!(result.receipts[1].success);

    // Verify cumulative gas
    assert_eq!(result.receipts[0].cumulative_gas_used, 21000);
    assert_eq!(result.receipts[1].cumulative_gas_used, 42000);

    // Verify final balances
    let c = bridge
        .ledger()
        .get_account(&addr_c)
        .expect("C should exist");
    assert_eq!(c.balance.to_u64(), Some(50_000));
}
