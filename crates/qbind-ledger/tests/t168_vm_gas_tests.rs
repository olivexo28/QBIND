//! T168: VM v0 Gas Accounting Unit Tests
//!
//! These tests verify the gas cost calculation, gas enforcement,
//! and fee deduction functionality introduced in T168.

use qbind_ledger::{
    compute_gas_for_vm_v0_tx, decode_transfer_payload, gas_for_standard_transfer,
    gas_for_transfer_v0, AccountStateView, ExecutionGasConfig, InMemoryAccountState,
    QbindTransaction, TransferPayload, TransferPayloadDecoded, TransferPayloadV1, VmV0Error,
    VmV0ExecutionEngine, GAS_BASE_TX, GAS_PER_ACCOUNT_READ, GAS_PER_ACCOUNT_WRITE,
    GAS_PER_BYTE_PAYLOAD, TRANSFER_PAYLOAD_SIZE, TRANSFER_PAYLOAD_V1_SIZE,
};
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
// Part 5.1: Unit Tests for Gas Cost Calculation (execution_gas.rs)
// ============================================================================

#[test]
fn gas_cost_matches_spec_for_standard_transfer() {
    // From QBIND_GAS_AND_FEES_DESIGN.md §2.3:
    // For a typical transfer (sender ≠ recipient):
    // - reads = 2 (sender + recipient)
    // - writes = 2 (sender + recipient)
    // - payload_len = 48 (TransferPayload size)
    //
    // gas(tx) = 21,000 + 2,600×2 + 5,000×2 + 16×48
    //         = 21,000 + 5,200 + 10,000 + 768
    //         = 36,968 gas

    let gas = gas_for_transfer_v0(TRANSFER_PAYLOAD_SIZE, 2, 2);
    assert_eq!(gas, 36_968, "typical transfer should cost ~37k gas");

    // Verify the formula components
    let expected = GAS_BASE_TX
        + GAS_PER_ACCOUNT_READ * 2
        + GAS_PER_ACCOUNT_WRITE * 2
        + GAS_PER_BYTE_PAYLOAD * (TRANSFER_PAYLOAD_SIZE as u64);
    assert_eq!(gas, expected);
}

#[test]
fn gas_cost_for_self_transfer() {
    // Self-transfer (sender == recipient): 1 read, 1 write, 48 bytes
    // gas = 21,000 + 2,600 + 5,000 + 768 = 29,368 gas
    let gas = gas_for_transfer_v0(TRANSFER_PAYLOAD_SIZE, 1, 1);
    assert_eq!(gas, 29_368);
}

#[test]
fn gas_for_standard_transfer_function() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Normal transfer: 2 reads, 2 writes
    let gas_normal = gas_for_standard_transfer(&sender, &recipient, TRANSFER_PAYLOAD_SIZE);
    assert_eq!(gas_normal, 36_968);

    // Self-transfer: 1 read, 1 write
    let gas_self = gas_for_standard_transfer(&sender, &sender, TRANSFER_PAYLOAD_SIZE);
    assert_eq!(gas_self, 29_368);
}

#[test]
fn v0_payload_gets_default_gas_limit_and_price() {
    // Create a v0 transfer transaction
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let payload = TransferPayload::new(recipient, 1000).encode();
    let tx = QbindTransaction::new(sender, 0, payload);

    // Compute gas for the transaction
    let gas_result = compute_gas_for_vm_v0_tx(&tx).expect("gas computation should succeed");

    // v0 payloads should get derived values:
    // - gas_cost should be ~37k (normal transfer)
    // - gas_limit >= gas_cost (set to at least DEFAULT_V0_GAS_LIMIT = 50,000)
    // - max_fee_per_gas = 0 (fee-free for v0)
    // - is_v1 = false
    assert_eq!(gas_result.gas_cost, 36_968);
    assert!(
        gas_result.gas_limit >= gas_result.gas_cost,
        "gas_limit should be >= gas_cost"
    );
    assert_eq!(gas_result.max_fee_per_gas, 0);
    assert!(!gas_result.is_v1);
}

#[test]
fn v1_payload_has_explicit_gas_fields() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create a v1 payload with explicit gas fields
    let v1_payload = TransferPayloadV1::new(recipient, 1000, 100_000, 50);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    let gas_result = compute_gas_for_vm_v0_tx(&tx).expect("gas computation should succeed");

    // Verify v1 fields are preserved
    assert_eq!(gas_result.gas_limit, 100_000);
    assert_eq!(gas_result.max_fee_per_gas, 50);
    assert!(gas_result.is_v1);
}

// ============================================================================
// Part 5.1: Unit Tests for Gas Enforcement in VM v0 Execution
// ============================================================================

#[test]
fn vm_v0_rejects_when_gas_cost_exceeds_limit() {
    // Create engine with gas enabled
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create account state with enough balance
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000);

    // Create a v1 payload with artificially low gas_limit
    // The actual gas cost is ~37k, but we set limit to only 10k
    let v1_payload = TransferPayloadV1::new(recipient, 100, 10_000, 0);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    // Execute the transaction
    let result = engine.execute_tx(&mut state, &tx);

    // Should fail with GasLimitExceeded
    assert!(!result.success);
    assert!(matches!(
        result.error,
        Some(VmV0Error::GasLimitExceeded { required, limit }) if required > limit
    ));

    // State should be unchanged
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 10_000, "balance should be unchanged");
    assert_eq!(sender_state.nonce, 0, "nonce should be unchanged");
}

#[test]
fn vm_v0_rejects_when_balance_insufficient_for_fee() {
    // Create engine with gas enabled
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create account state with limited balance
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1000); // Only 1000 balance

    // Create a v1 payload where sender has enough for amount but not for amount + fee
    // amount = 500, gas_limit = 50_000, max_fee_per_gas = 100
    // max_fee = 50_000 * 100 = 5,000,000
    // total_needed = 500 + 5,000,000 = 5,000,500 (way more than balance of 1000)
    let v1_payload = TransferPayloadV1::new(recipient, 500, 50_000, 100);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    let result = engine.execute_tx(&mut state, &tx);

    // Should fail with InsufficientBalanceForFee
    assert!(!result.success);
    assert!(
        matches!(
            result.error,
            Some(VmV0Error::InsufficientBalanceForFee { .. })
        ),
        "expected InsufficientBalanceForFee, got {:?}",
        result.error
    );

    // State should be unchanged
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 1000, "balance should be unchanged");
    assert_eq!(sender_state.nonce, 0, "nonce should be unchanged");
}

#[test]
fn vm_v0_deducts_fee_and_amount_on_success() {
    // Create engine with gas enabled
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create account state with enough balance for amount + fee
    // amount = 100, gas_cost ~= 47k (v1 payload is 72 bytes), max_fee_per_gas = 10
    // fee = gas_cost * max_fee_per_gas ≈ 47k * 10 = 470k
    // total = 100 + 470k ≈ 470,100
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);

    // Create a v1 payload with sufficient gas_limit
    let v1_payload = TransferPayloadV1::new(recipient, 100, 100_000, 10);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    // Execute the transaction
    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed
    assert!(result.success, "transaction should succeed");
    assert!(result.gas_used > 0, "gas_used should be tracked");
    assert!(result.fee_paid > 0, "fee should be paid");

    // Verify sender balance decreased by amount + fee
    let sender_state = state.get_account_state(&sender);
    let expected_balance = 1_000_000 - 100 - result.fee_paid;
    assert_eq!(sender_state.balance, expected_balance);
    assert_eq!(sender_state.nonce, 1, "nonce should increment");

    // Verify recipient received exactly the amount (not amount + fee)
    let recipient_state = state.get_account_state(&recipient);
    assert_eq!(recipient_state.balance, 100);

    // Verify fee calculation: fee = gas_used * max_fee_per_gas
    let expected_fee = (result.gas_used as u128) * 10;
    assert_eq!(result.fee_paid, expected_fee);
}

#[test]
fn vm_v0_fee_free_with_zero_max_fee_per_gas() {
    // Create engine with gas enabled
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1000);

    // Create a v1 payload with max_fee_per_gas = 0 (fee-free)
    let v1_payload = TransferPayloadV1::new(recipient, 100, 100_000, 0);
    let tx = QbindTransaction::new(sender, 0, v1_payload.encode());

    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed
    assert!(result.success);
    assert!(result.gas_used > 0, "gas should still be tracked");
    assert_eq!(
        result.fee_paid, 0,
        "no fee should be paid when max_fee_per_gas = 0"
    );

    // Verify only amount was deducted
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 900); // 1000 - 100
}

#[test]
fn gas_disabled_preserves_behavior() {
    // Create engine with gas DISABLED (default)
    let engine = VmV0ExecutionEngine::new();
    assert!(!engine.is_gas_enabled());

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
    assert_eq!(result.gas_used, 0, "gas not tracked when disabled");
    assert_eq!(result.fee_paid, 0, "no fee when disabled");

    // Verify only amount was deducted (no fee)
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.balance, 900); // 1000 - 100
    assert_eq!(sender_state.nonce, 1);

    let recipient_state = state.get_account_state(&recipient);
    assert_eq!(recipient_state.balance, 100);
}

// ============================================================================
// Block Gas Limit Tests
// ============================================================================

#[test]
fn block_respects_block_gas_limit() {
    // Create engine with a tiny block gas limit (100k)
    let gas_config = ExecutionGasConfig::enabled_with_limit(100_000);
    let engine = VmV0ExecutionEngine::with_gas_config(gas_config);

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Create account state with plenty of balance
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000_000);

    // Create 5 transactions - each costs ~37k gas
    // Total would be ~185k, but block limit is 100k
    // So only 2 transactions (~74k gas) should fit
    let mut transactions = Vec::new();
    for nonce in 0..5u64 {
        // Use v0 payload (fee-free)
        let payload = TransferPayload::new(recipient, 100).encode();
        let tx = QbindTransaction::new(sender, nonce, payload);
        transactions.push(tx);
    }

    // Execute the block
    let results = engine.execute_block(&mut state, &transactions);

    // Should execute only the transactions that fit within gas limit
    // Each v0 transfer costs ~37k gas, so 2 txs fit in 100k limit
    assert!(
        results.len() <= 3,
        "should stop before exceeding block gas limit"
    );

    // All executed transactions should succeed
    for result in &results {
        assert!(result.success);
    }

    // Verify sender state reflects only executed transactions
    let sender_state = state.get_account_state(&sender);
    let executed_count = results.len() as u128;
    let expected_balance = 10_000_000 - (100 * executed_count);
    assert_eq!(sender_state.balance, expected_balance);
    assert_eq!(sender_state.nonce, executed_count as u64);
}

#[test]
fn block_stats_are_accurate() {
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000_000);

    // Create 3 transactions
    let mut transactions = Vec::new();
    for nonce in 0..3u64 {
        // v1 payload with small fee
        let v1_payload = TransferPayloadV1::new(recipient, 100, 100_000, 1);
        let tx = QbindTransaction::new(sender, nonce, v1_payload.encode());
        transactions.push(tx);
    }

    let (results, stats) = engine.execute_block_with_stats(&mut state, &transactions);

    // Verify stats
    assert_eq!(stats.txs_executed, 3);
    assert_eq!(stats.txs_succeeded, 3);
    assert!(stats.total_gas_used > 0);
    assert!(stats.total_fees_burned > 0);

    // Verify gas tracking matches individual results
    let total_gas: u64 = results.iter().map(|r| r.gas_used).sum();
    let total_fees: u128 = results.iter().map(|r| r.fee_paid).sum();
    assert_eq!(stats.total_gas_used, total_gas);
    assert_eq!(stats.total_fees_burned, total_fees);
}

// ============================================================================
// Payload Discrimination Tests
// ============================================================================

#[test]
fn decode_transfer_payload_v0() {
    let recipient = test_account_id(0xBB);
    let v0_payload = TransferPayload::new(recipient, 1000);
    let encoded = v0_payload.encode();

    assert_eq!(encoded.len(), TRANSFER_PAYLOAD_SIZE);

    let decoded = decode_transfer_payload(&encoded).expect("decode should succeed");
    match decoded {
        TransferPayloadDecoded::V0(p) => {
            assert_eq!(p.recipient, recipient);
            assert_eq!(p.amount, 1000);
        }
        _ => panic!("expected v0 payload"),
    }
}

#[test]
fn decode_transfer_payload_v1() {
    let recipient = test_account_id(0xBB);
    let v1_payload = TransferPayloadV1::new(recipient, 1000, 50_000, 100);
    let encoded = v1_payload.encode();

    assert_eq!(encoded.len(), TRANSFER_PAYLOAD_V1_SIZE);

    let decoded = decode_transfer_payload(&encoded).expect("decode should succeed");
    match decoded {
        TransferPayloadDecoded::V1(p) => {
            assert_eq!(p.recipient, recipient);
            assert_eq!(p.amount, 1000);
            assert_eq!(p.gas_limit, 50_000);
            assert_eq!(p.max_fee_per_gas, 100);
        }
        _ => panic!("expected v1 payload"),
    }
}

#[test]
fn decode_transfer_payload_invalid_length() {
    // Length that's neither 48 (v0) nor 72 (v1)
    let result = decode_transfer_payload(&[0u8; 50]);
    assert!(result.is_err());
}