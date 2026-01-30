//! T168: Gas Integration Tests
//!
//! These tests verify gas-aware mempool admission and block execution
//! in an integrated node environment.

use qbind_ledger::{
    AccountStateView, ExecutionGasConfig, InMemoryAccountState, QbindTransaction, TransferPayload,
    TransferPayloadV1, VmV0ExecutionEngine,
};
use qbind_node::{InMemoryMempool, Mempool, MempoolConfig, MempoolError};
use qbind_types::AccountId;

// ============================================================================
// Helper Functions
// ============================================================================

fn test_account_id(byte: u8) -> AccountId {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

// ============================================================================
// Part 5.2: Integration Tests for Mempool Gas Admission
// ============================================================================

#[test]
fn mempool_gas_checks_are_skipped_without_balance_provider() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create mempool with gas enabled but NO balance provider
    let mut config = MempoolConfig::default();
    config.gas_config = Some(ExecutionGasConfig::enabled());
    config.max_nonce_gap = 0; // Disable nonce tracking

    let mempool = InMemoryMempool::with_config(config);

    // Create a v1 payload with insufficient gas_limit
    // This would normally be rejected, but without a balance provider,
    // the gas limit check still runs, and it should fail
    let v1_payload = TransferPayloadV1::new(recipient, 100, 10_000, 0);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    let result = mempool.insert(tx);

    // Should fail with InsufficientGasLimit (gas check runs even without balance provider)
    assert!(result.is_err());
    match result.unwrap_err() {
        MempoolError::InsufficientGasLimit { required, limit } => {
            assert!(required > limit);
            assert_eq!(limit, 10_000);
        }
        other => panic!("expected InsufficientGasLimit, got {:?}", other),
    }
}

#[test]
fn mempool_accepts_tx_with_sufficient_gas_limit() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create mempool with gas enabled but no key/balance providers
    let mut config = MempoolConfig::default();
    config.gas_config = Some(ExecutionGasConfig::enabled());
    config.max_nonce_gap = 0;

    let mempool = InMemoryMempool::with_config(config);

    // Create a valid v1 transaction with sufficient gas_limit
    let v1_payload = TransferPayloadV1::new(recipient, 100, 100_000, 0);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    // Should succeed (no balance check since no balance provider)
    let result = mempool.insert(tx);
    assert!(result.is_ok());
    assert_eq!(mempool.size(), 1);
}

#[test]
fn mempool_accepts_fee_free_v0_tx_with_gas_enabled() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut config = MempoolConfig::default();
    config.gas_config = Some(ExecutionGasConfig::enabled());
    config.max_nonce_gap = 0;

    let mempool = InMemoryMempool::with_config(config);

    // v0 payload should be accepted (derives gas_limit >= gas_cost automatically)
    let v0_payload = TransferPayload::new(recipient, 500).encode();
    let tx = QbindTransaction::new(sender, 0, v0_payload);

    let result = mempool.insert(tx);
    assert!(result.is_ok());
}

#[test]
fn gas_disabled_preserves_mempool_behavior() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create mempool WITHOUT gas config (disabled)
    let config = MempoolConfig::default();
    assert!(config.gas_config.is_none());

    let mempool = InMemoryMempool::with_config(config);
    assert!(!mempool.is_gas_enabled());

    // Even a transaction with low gas_limit should be accepted
    let v1_payload = TransferPayloadV1::new(recipient, 100, 1, 0); // gas_limit = 1 (way too low)
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    // Should succeed because gas checks are disabled
    let result = mempool.insert(tx);
    assert!(result.is_ok(), "should accept when gas disabled");
}

// ============================================================================
// Part 5.2: Integration Tests for Block Execution with Gas
// ============================================================================

#[test]
fn block_execution_respects_block_gas_limit() {
    // Create engine with a tiny block gas limit
    let gas_config = ExecutionGasConfig::enabled_with_limit(80_000);
    let engine = VmV0ExecutionEngine::with_gas_config(gas_config);

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create account state
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000_000);

    // Create 5 transactions - each v0 transfer costs ~37k gas
    // Block limit is 80k, so only 2 transactions should fit (~74k < 80k)
    let mut transactions = Vec::new();
    for nonce in 0..5u64 {
        let payload = TransferPayload::new(recipient, 100).encode();
        let tx = QbindTransaction::new(sender, nonce, payload);
        transactions.push(tx);
    }

    // Execute the block
    let results = engine.execute_block(&mut state, &transactions);

    // Should execute only 2 transactions (2 * ~37k = ~74k < 80k)
    // Third transaction would push us over (3 * ~37k = ~111k > 80k)
    assert_eq!(
        results.len(),
        2,
        "should execute exactly 2 transactions before hitting gas limit"
    );

    // Verify state
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 10_000_000 - 200); // 2 * 100
    assert_eq!(sender_state.nonce, 2);
}

#[test]
fn gas_disabled_executes_all_transactions() {
    // Create engine with gas DISABLED
    let engine = VmV0ExecutionEngine::new();
    assert!(!engine.is_gas_enabled());

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000);

    // Create 5 transactions
    let mut transactions = Vec::new();
    for nonce in 0..5u64 {
        let payload = TransferPayload::new(recipient, 100).encode();
        let tx = QbindTransaction::new(sender, nonce, payload);
        transactions.push(tx);
    }

    // All 5 should be executed (no gas limit)
    let results = engine.execute_block(&mut state, &transactions);
    assert_eq!(results.len(), 5);

    // All should succeed
    for result in &results {
        assert!(result.success);
        assert_eq!(result.gas_used, 0, "gas not tracked when disabled");
    }

    // Verify final state
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 10_000 - 500); // 5 * 100
    assert_eq!(sender_state.nonce, 5);
}

// ============================================================================
// Backward Compatibility Tests
// ============================================================================

#[test]
fn backward_compat_v0_transactions_work_as_before() {
    // Run the same test with gas disabled to verify pre-T168 behavior is preserved
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1000);

    // Create a standard v0 transfer
    let payload = TransferPayload::new(recipient, 100).encode();
    let tx = QbindTransaction::new(sender, 0, payload);

    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed exactly as before T168
    assert!(result.success);
    assert!(result.error.is_none());

    // State should reflect only the transfer amount (no fee)
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 900);
    assert_eq!(sender_state.nonce, 1);

    let recipient_state = state.get_account_state(&recipient);
    assert_eq!(recipient_state.balance, 100);
}
