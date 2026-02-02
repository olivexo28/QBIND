//! T152 Commit Gas Integration Tests
//!
//! Node-level tests for gas accounting through the EVM execution bridge:
//! - Committed block gas accounting
//! - Gas metadata in commit result
//! - Cross-bridge determinism

use std::sync::Arc;

use qbind_node::evm_commit::{init_evm_account, EvmExecutionBridge};
use qbind_node::NodeCommittedBlock;
use qbind_runtime::{Address, QbindTx, U256};
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

fn make_committed_block(height: u64) -> NodeCommittedBlock<[u8; 32]> {
    NodeCommittedBlock {
        height,
        view: 1,
        block_id: [height as u8; 32],
        proposal: make_test_proposal(height, 1),
    }
}

// ============================================================================
// Test: Committed block gas accounting
// ============================================================================

#[test]
fn test_committed_block_gas_accounting() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    // Create transfer tx
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    let block = make_committed_block(1);
    let result = bridge
        .apply_committed_block(&block, vec![tx])
        .expect("commit should succeed");

    // Verify gas accounting in result
    assert_eq!(result.gas_used, 21000);
    assert_eq!(result.receipts.len(), 1);
    assert_eq!(result.receipts[0].gas_used, 21000);
    assert_eq!(result.receipts[0].cumulative_gas_used, 21000);
    assert!(result.receipts[0].effective_gas_price > 0);
}

// ============================================================================
// Test: Multiple tx gas accumulation
// ============================================================================

#[test]
fn test_multiple_tx_gas_accumulation() {
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

    // Two transfers in one block
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
        .expect("commit should succeed");

    // Block gas should be sum of all tx gas
    assert_eq!(result.gas_used, 42000);

    // Receipts should have correct cumulative gas
    assert_eq!(result.receipts[0].cumulative_gas_used, 21000);
    assert_eq!(result.receipts[1].cumulative_gas_used, 42000);
}

// ============================================================================
// Test: Empty block gas is zero
// ============================================================================

#[test]
fn test_empty_block_gas_zero() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let block = make_committed_block(1);
    let result = bridge
        .apply_empty_committed_block(&block)
        .expect("empty block should commit");

    assert_eq!(result.gas_used, 0);
    assert!(result.receipts.is_empty());
}

// ============================================================================
// Test: Cross-bridge gas determinism
// ============================================================================

#[test]
fn test_cross_bridge_gas_determinism() {
    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Create two independent bridges with same initial state
    let mut bridge1 = EvmExecutionBridge::new(1337);
    let mut bridge2 = EvmExecutionBridge::new(1337);

    init_evm_account(
        bridge1.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );
    init_evm_account(
        bridge2.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    // Same transaction
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        500_000_000,
    );

    let block = make_committed_block(1);

    let result1 = bridge1
        .apply_committed_block(&block.clone(), vec![tx.clone()])
        .expect("bridge1 should succeed");
    let result2 = bridge2
        .apply_committed_block(&block, vec![tx])
        .expect("bridge2 should succeed");

    // All gas-related fields must match
    assert_eq!(result1.gas_used, result2.gas_used);
    assert_eq!(result1.receipts.len(), result2.receipts.len());
    assert_eq!(result1.receipts[0].gas_used, result2.receipts[0].gas_used);
    assert_eq!(
        result1.receipts[0].effective_gas_price,
        result2.receipts[0].effective_gas_price
    );
    assert_eq!(
        result1.receipts[0].cumulative_gas_used,
        result2.receipts[0].cumulative_gas_used
    );

    // State roots must match (includes gas effects on balances)
    assert_eq!(result1.state_root, result2.state_root);
    assert_eq!(result1.receipts_root, result2.receipts_root);
}

// ============================================================================
// Test: Sequential blocks accumulate correctly
// ============================================================================

#[test]
fn test_sequential_blocks_gas() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(100_000_000_000_000_000_000),
        0,
    );

    // Block 1
    let tx1 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block1 = make_committed_block(1);
    let result1 = bridge
        .apply_committed_block(&block1, vec![tx1])
        .expect("block 1 should commit");

    assert_eq!(result1.gas_used, 21000);

    // Block 2
    let tx2 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(50_000), 1).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );
    let block2 = make_committed_block(2);
    let result2 = bridge
        .apply_committed_block(&block2, vec![tx2])
        .expect("block 2 should commit");

    // Each block has independent gas accounting
    assert_eq!(result2.gas_used, 21000);
    assert_eq!(result2.receipts[0].cumulative_gas_used, 21000);

    // Can retrieve both results
    let stored1 = bridge.get_commit_result(1).expect("result 1 should exist");
    let stored2 = bridge.get_commit_result(2).expect("result 2 should exist");

    assert_eq!(stored1.gas_used, 21000);
    assert_eq!(stored2.gas_used, 21000);
}

// ============================================================================
// Test: Effective gas price consistency
// ============================================================================

#[test]
fn test_effective_gas_price_consistency() {
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    // Use specific gas price parameters
    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        2_000_000_000, // max_fee = 2 Gwei
        500_000_000,   // max_priority = 0.5 Gwei
    );

    let block = make_committed_block(1);
    let result = bridge
        .apply_committed_block(&block, vec![tx])
        .expect("should succeed");

    // The effective gas price should be computed correctly
    // basefee (from block_apply) = 1 Gwei = 1_000_000_000
    // headroom = 2G - 1G = 1G
    // tip = min(0.5G, 1G) = 0.5G
    // effective = 1G + 0.5G = 1.5G
    assert_eq!(result.receipts[0].effective_gas_price, 1_500_000_000);
}
