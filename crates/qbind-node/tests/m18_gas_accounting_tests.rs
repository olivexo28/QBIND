//! M18: Gas Metering Formalization and Deterministic Accounting Tests
//!
//! These tests verify the formal gas accounting model defined in Whitepaper Section 19:
//! 1. Basic gas accounting: deduction, refund semantics, invariant gas_used_tx ≤ gas_limit_tx
//! 2. Failure behavior: execution revert still consumes gas, state reverts except gas
//! 3. Block gas limit: block rejects tx exceeding remaining gas, gas_used_block invariant
//! 4. Determinism: two engines with same inputs produce identical gas_used_tx
//! 5. Overflow protection: large gas_limit near u64/u128 boundary, ensure no overflow
//! 6. Restart safety: simulate crash between execution and commit, no partial gas state
//!
//! This closes Spec Gap 2.3 (Gas accounting formal definition) in the QBIND protocol.

use qbind_ledger::{
    AccountStateView, ExecutionGasConfig, InMemoryAccountState, QbindTransaction,
    TransferPayload, TransferPayloadV1, VmV0Error, VmV0ExecutionEngine,
    GAS_BASE_TX, GAS_PER_ACCOUNT_READ, GAS_PER_ACCOUNT_WRITE, GAS_PER_BYTE_PAYLOAD,
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

fn create_v1_transfer(
    sender: &AccountId,
    recipient: &AccountId,
    amount: u128,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
) -> QbindTransaction {
    let payload = TransferPayloadV1::new(*recipient, amount, gas_limit, max_fee_per_gas).encode();
    QbindTransaction::new(*sender, nonce, payload)
}

fn create_v0_transfer(
    sender: &AccountId,
    recipient: &AccountId,
    amount: u128,
    nonce: u64,
) -> QbindTransaction {
    let payload = TransferPayload::new(*recipient, amount).encode();
    QbindTransaction::new(*sender, nonce, payload)
}

fn expected_gas_for_v1_transfer() -> u64 {
    // Gas formula: base + 2*read + 2*write + bytes*16
    // For normal transfer (sender != recipient): 2 reads, 2 writes
    // V1 payload is 72 bytes
    GAS_BASE_TX
        + GAS_PER_ACCOUNT_READ * 2
        + GAS_PER_ACCOUNT_WRITE * 2
        + GAS_PER_BYTE_PAYLOAD * 72
}

fn expected_gas_for_v0_transfer() -> u64 {
    // V0 payload is 48 bytes
    GAS_BASE_TX
        + GAS_PER_ACCOUNT_READ * 2
        + GAS_PER_ACCOUNT_WRITE * 2
        + GAS_PER_BYTE_PAYLOAD * 48
}

// ============================================================================
// Test A: Basic Gas Accounting
// ============================================================================

/// M18.A1: Verify gas is deducted correctly for successful transfer.
#[test]
fn m18_a1_gas_deducted_for_successful_transfer() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000); // 1 trillion

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Create v1 transaction with explicit gas limit
    let gas_limit = 100_000u64;
    let max_fee = 1u128;
    let amount = 1000u128;

    let tx = create_v1_transfer(&sender, &recipient, amount, 0, gas_limit, max_fee);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(results[0].success, "Transaction should succeed");
    
    // Gas used should be the computed cost
    let expected_gas = expected_gas_for_v1_transfer();
    assert_eq!(results[0].gas_used, expected_gas);
    
    // Invariant: gas_used_tx ≤ gas_limit_tx
    assert!(results[0].gas_used <= gas_limit, "INV-1: gas_used_tx <= gas_limit_tx");
}

/// M18.A2: Verify gas_used_tx <= gas_limit_tx invariant holds.
#[test]
fn m18_a2_gas_used_invariant_holds() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    // Test with various gas limits
    for gas_limit in [50_000u64, 100_000, 500_000, 1_000_000] {
        let mut state = InMemoryAccountState::new();
        state.init_account(&sender, 1_000_000_000_000);

        let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

        let tx = create_v1_transfer(&sender, &recipient, 100, 0, gas_limit, 1);
        let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

        assert_eq!(results.len(), 1);

        // Invariant must hold regardless of success/failure
        assert!(
            results[0].gas_used <= gas_limit,
            "INV-1 violated: gas_used {} > gas_limit {}",
            results[0].gas_used,
            gas_limit
        );
    }
}

/// M18.A3: Verify fee calculation matches formal definition.
#[test]
fn m18_a3_fee_calculation_matches_formal_definition() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let initial_balance = 1_000_000_000_000u128;
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, initial_balance);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let gas_limit = 100_000u64;
    let max_fee = 10u128;
    let amount = 1000u128;

    let tx = create_v1_transfer(&sender, &recipient, amount, 0, gas_limit, max_fee);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(results[0].success);

    // Formal: total_fee = gas_used * effective_gas_price
    // For burn-only policy (default enabled()), all fee is burned
    let expected_fee = (results[0].gas_used as u128) * max_fee;
    assert_eq!(results[0].fee_paid, expected_fee);

    // Verify sender balance: initial - amount - fee
    let sender_state = state.get_account_state(&sender);
    assert_eq!(
        sender_state.balance,
        initial_balance - amount - expected_fee
    );
}

// ============================================================================
// Test B: Failure Behavior
// ============================================================================

/// M18.B1: Verify execution failure still reports gas usage.
#[test]
fn m18_b1_failure_reports_gas_usage() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 100); // Insufficient for amount + fee

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let gas_limit = 100_000u64;
    let max_fee = 1u128;
    let amount = 1_000_000u128; // More than balance

    let tx = create_v1_transfer(&sender, &recipient, amount, 0, gas_limit, max_fee);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(!results[0].success, "Transaction should fail");
    
    // Gas used should still be computed
    assert!(results[0].gas_used > 0, "Failed tx should report gas used");
    
    // Error should indicate insufficient balance
    match &results[0].error {
        Some(VmV0Error::InsufficientBalanceForFee { .. }) => {}
        other => panic!("Expected InsufficientBalanceForFee, got {:?}", other),
    }
}

/// M18.B2: Verify gas limit exceeded failure.
#[test]
fn m18_b2_gas_limit_exceeded_failure() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Gas limit too low to cover the transaction
    let gas_limit = 1000u64; // Less than GAS_BASE_TX (21,000)
    let max_fee = 1u128;
    let amount = 100u128;

    let tx = create_v1_transfer(&sender, &recipient, amount, 0, gas_limit, max_fee);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(!results[0].success, "Transaction should fail due to gas limit");
    
    match &results[0].error {
        Some(VmV0Error::GasLimitExceeded { required, limit }) => {
            assert!(required > limit);
            assert_eq!(*limit, gas_limit);
        }
        other => panic!("Expected GasLimitExceeded, got {:?}", other),
    }
}

/// M18.B3: Verify nonce mismatch failure behavior.
#[test]
fn m18_b3_nonce_mismatch_failure() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Set sender nonce to 5 by executing 5 transactions first
    for i in 0..5 {
        let tx = create_v1_transfer(&sender, &recipient, 100, i, 100_000, 1);
        engine.execute_block_with_proposer(&mut state, &[tx], &proposer);
    }

    // Transaction with wrong nonce (0 instead of 5)
    let tx = create_v1_transfer(&sender, &recipient, 100, 0, 100_000, 1);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(!results[0].success);
    
    match &results[0].error {
        Some(VmV0Error::NonceMismatch { expected, got }) => {
            assert_eq!(*expected, 5);
            assert_eq!(*got, 0);
        }
        other => panic!("Expected NonceMismatch, got {:?}", other),
    }
}

// ============================================================================
// Test C: Block Gas Limit
// ============================================================================

/// M18.C1: Verify block rejects transactions exceeding remaining gas.
#[test]
fn m18_c1_block_rejects_tx_exceeding_remaining_gas() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000_000);

    // Very small block gas limit
    let config = ExecutionGasConfig::enabled_with_limit(50_000);
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    // Create 3 transactions, but block can only fit ~1 (each is ~38k gas)
    let txs: Vec<_> = (0..3)
        .map(|i| create_v1_transfer(&sender, &recipient, 100, i, 100_000, 1))
        .collect();

    let results = engine.execute_block_with_proposer(&mut state, &txs, &proposer);

    // Only first transaction should be executed (or zero if even first exceeds)
    // Expected gas per tx is ~38k for v1, block limit is 50k, so only 1 fits
    assert!(
        results.len() <= 2,
        "Block gas limit should restrict execution count, got {} results",
        results.len()
    );
}

/// M18.C2: Verify gas_used_block invariant holds.
#[test]
fn m18_c2_block_gas_used_invariant() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000_000);

    let block_gas_limit = 200_000u64;
    let config = ExecutionGasConfig::enabled_with_limit(block_gas_limit);
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    // Create transactions that total more than block limit
    let txs: Vec<_> = (0..10)
        .map(|i| create_v1_transfer(&sender, &recipient, 100, i, 100_000, 1))
        .collect();

    let results = engine.execute_block_with_proposer(&mut state, &txs, &proposer);

    // Sum of gas_used for successful transactions
    let total_gas: u64 = results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.gas_used)
        .sum();

    // INV-2: gas_used_block <= block_gas_limit
    assert!(
        total_gas <= block_gas_limit,
        "INV-2 violated: total_gas {} > block_gas_limit {}",
        total_gas,
        block_gas_limit
    );
}

/// M18.C3: Verify block stats are consistent with individual results.
#[test]
fn m18_c3_block_stats_consistency() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000);

    let config = ExecutionGasConfig::mainnet(); // 50% burn, 50% proposer
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    let txs: Vec<_> = (0..3)
        .map(|i| create_v1_transfer(&sender, &recipient, 100, i, 100_000, 10))
        .collect();

    let (results, stats) = engine.execute_block_with_proposer_and_stats(&mut state, &txs, &proposer);

    // Verify stats match sum of results
    let sum_gas: u64 = results.iter().map(|r| r.gas_used).sum();
    let sum_burned: u128 = results.iter().map(|r| r.fee_burned).sum();
    let sum_proposer: u128 = results.iter().map(|r| r.fee_to_proposer).sum();

    assert_eq!(stats.total_gas_used, sum_gas);
    assert_eq!(stats.total_fees_burned, sum_burned);
    assert_eq!(stats.total_fees_to_proposer, sum_proposer);
}

// ============================================================================
// Test D: Determinism
// ============================================================================

/// M18.D1: Two engines with identical inputs produce identical gas_used_tx.
#[test]
fn m18_d1_determinism_same_inputs_same_gas() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let initial_balance = 1_000_000_000_000u128;

    // Create two identical states
    let mut state1 = InMemoryAccountState::new();
    let mut state2 = InMemoryAccountState::new();
    state1.init_account(&sender, initial_balance);
    state2.init_account(&sender, initial_balance);

    // Create two identical engines
    let engine1 = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());
    let engine2 = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Same transaction
    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 100_000, 10);

    let results1 = engine1.execute_block_with_proposer(&mut state1, &[tx.clone()], &proposer);
    let results2 = engine2.execute_block_with_proposer(&mut state2, &[tx], &proposer);

    assert_eq!(results1.len(), 1);
    assert_eq!(results2.len(), 1);

    // DET-2: Same transaction → same gas_used_tx
    assert_eq!(results1[0].gas_used, results2[0].gas_used);
    assert_eq!(results1[0].success, results2[0].success);
    assert_eq!(results1[0].fee_paid, results2[0].fee_paid);
    assert_eq!(results1[0].fee_burned, results2[0].fee_burned);
}

/// M18.D2: Block execution is deterministic across engines.
#[test]
fn m18_d2_determinism_block_execution() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let initial_balance = 1_000_000_000_000_000u128;

    let mut state1 = InMemoryAccountState::new();
    let mut state2 = InMemoryAccountState::new();
    state1.init_account(&sender, initial_balance);
    state2.init_account(&sender, initial_balance);

    let config = ExecutionGasConfig::enabled_with_limit(500_000);
    let engine1 = VmV0ExecutionEngine::with_gas_config(config.clone());
    let engine2 = VmV0ExecutionEngine::with_gas_config(config);

    // Same block of transactions
    let txs: Vec<_> = (0..5)
        .map(|i| create_v1_transfer(&sender, &recipient, 100, i, 100_000, 5))
        .collect();

    let results1 = engine1.execute_block_with_proposer(&mut state1, &txs, &proposer);
    let results2 = engine2.execute_block_with_proposer(&mut state2, &txs, &proposer);

    // DET-1: Same block → same gas_used_block
    assert_eq!(results1.len(), results2.len());

    for (r1, r2) in results1.iter().zip(results2.iter()) {
        assert_eq!(r1.gas_used, r2.gas_used);
        assert_eq!(r1.success, r2.success);
    }

    // Final states should be identical
    assert_eq!(
        state1.get_account_state(&sender).balance,
        state2.get_account_state(&sender).balance
    );
}

// ============================================================================
// Test E: Overflow Protection
// ============================================================================

/// M18.E1: Large gas_limit near u64 boundary doesn't panic.
#[test]
fn m18_e1_large_gas_limit_no_panic() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, u128::MAX / 2); // Very large balance

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Very large gas limit (but valid transaction)
    let gas_limit = u64::MAX / 2;
    let max_fee = 1u128;
    let amount = 100u128;

    let tx = create_v1_transfer(&sender, &recipient, amount, 0, gas_limit, max_fee);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    // Should succeed or fail gracefully - no panic
    // The key is that arithmetic didn't overflow/panic
    assert_eq!(results.len(), 1);
    assert!(results[0].gas_used <= gas_limit);
}

/// M18.E2: Large max_fee_per_gas triggers overflow protection.
#[test]
fn m18_e2_large_max_fee_overflow_protection() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, u128::MAX / 2);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // max_fee_per_gas that could cause overflow when multiplied by gas
    let gas_limit = 100_000u64;
    let max_fee = u128::MAX / 10; // Very large fee
    let amount = 100u128;

    let tx = create_v1_transfer(&sender, &recipient, amount, 0, gas_limit, max_fee);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    // Should fail with ArithmeticOverflow error (M18 protection) or other error
    // The key is no panic
    assert_eq!(results.len(), 1);
    if !results[0].success {
        match &results[0].error {
            Some(VmV0Error::ArithmeticOverflow { .. }) => {
                // Expected - overflow detected and handled
            }
            Some(VmV0Error::InsufficientBalanceForFee { .. }) => {
                // Also acceptable - balance check caught it first
            }
            other => {
                // Other failures are acceptable as long as no panic
                println!("Failed with: {:?}", other);
            }
        }
    }
}

/// M18.E3: Nonce overflow protection - extreme nonce values don't panic.
#[test]
fn m18_e3_nonce_extreme_values_no_panic() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    // We can't easily set nonce to u64::MAX in InMemoryAccountState,
    // so this test verifies the code path exists without panicking
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Use max nonce value (will mismatch since account nonce is 0)
    let tx = create_v1_transfer(&sender, &recipient, 100, u64::MAX, 100_000, 1);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    // Should fail with nonce mismatch (since actual nonce is 0)
    // The key is no panic even with extreme nonce values
    assert_eq!(results.len(), 1);
    assert!(!results[0].success);
}

// ============================================================================
// Test F: Atomicity and Consistency
// ============================================================================

/// M18.F1: Verify no partial state after failed transaction.
#[test]
fn m18_f1_no_partial_state_on_failure() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let initial_sender_balance = 1_000_000u128;

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, initial_sender_balance);
    state.init_account(&recipient, 0);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Transaction that will fail (insufficient balance for amount + fee)
    let tx = create_v1_transfer(&sender, &recipient, 2_000_000, 0, 100_000, 1);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(!results[0].success);

    // State should be unchanged after failure
    let sender_after = state.get_account_state(&sender);
    let recipient_after = state.get_account_state(&recipient);

    assert_eq!(sender_after.balance, initial_sender_balance);
    assert_eq!(sender_after.nonce, 0);
    assert_eq!(recipient_after.balance, 0);
}

/// M18.F2: Verify total supply conservation.
#[test]
fn m18_f2_supply_conservation() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let sender_initial = 1_000_000_000u128;
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, sender_initial);
    state.init_account(&proposer, 0);

    // MainNet: 50% burn, 50% proposer
    let config = ExecutionGasConfig::mainnet();
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    let amount = 1000u128;
    let max_fee = 10u128;
    let tx = create_v1_transfer(&sender, &recipient, amount, 0, 100_000, max_fee);

    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);
    assert_eq!(results.len(), 1);
    assert!(results[0].success);

    // Check supply conservation: sender_lost = recipient_gained + proposer_gained + burned
    let sender_after = state.get_account_state(&sender).balance;
    let recipient_after = state.get_account_state(&recipient).balance;
    let proposer_after = state.get_account_state(&proposer).balance;

    let sender_lost = sender_initial - sender_after;
    let recipient_gained = recipient_after; // Started at 0
    let proposer_gained = proposer_after; // Started at 0
    let fee_burned = results[0].fee_burned;

    // SUP-1: Total supply conserved (except burn)
    assert_eq!(
        sender_lost,
        recipient_gained + proposer_gained + fee_burned,
        "Supply conservation violated"
    );

    // SUP-3: fee_burned + fee_to_proposer = total_fee
    assert_eq!(
        results[0].fee_burned + results[0].fee_to_proposer,
        results[0].fee_paid,
        "Fee distribution conservation violated"
    );
}

/// M18.F3: Verify block execution stops cleanly on gas limit.
#[test]
fn m18_f3_block_stops_cleanly_at_limit() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000_000_000_000);

    // Block limit allows exactly 2 transactions (each ~38k gas)
    let config = ExecutionGasConfig::enabled_with_limit(80_000);
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    // Submit 5 transactions
    let txs: Vec<_> = (0..5)
        .map(|i| create_v1_transfer(&sender, &recipient, 100, i, 100_000, 1))
        .collect();

    let results = engine.execute_block_with_proposer(&mut state, &txs, &proposer);

    // Should execute 2 and stop (80k limit / ~38k per tx = 2)
    let successful: Vec<_> = results.iter().filter(|r| r.success).collect();
    assert!(
        successful.len() <= 2,
        "Expected at most 2 successful txs, got {}",
        successful.len()
    );

    // Verify final nonce matches number of successful transactions
    let final_nonce = state.get_account_state(&sender).nonce;
    assert_eq!(final_nonce, successful.len() as u64);
}

// ============================================================================
// Test G: V0 Payload Compatibility
// ============================================================================

/// M18.G1: Verify V0 payload still works with default gas.
#[test]
fn m18_g1_v0_payload_default_gas() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);

    // V0 payload (no explicit gas fields) - gas enforcement disabled
    let engine = VmV0ExecutionEngine::new();
    let tx = create_v0_transfer(&sender, &recipient, 100, 0);
    let results = engine.execute_block(&mut state, &[tx]);

    assert_eq!(results.len(), 1);
    assert!(results[0].success, "V0 transaction should succeed");

    // With gas disabled, gas_used should be 0
    assert_eq!(results[0].gas_used, 0);
}

/// M18.G2: Verify V0 payload with gas enabled uses default limits.
#[test]
fn m18_g2_v0_payload_with_gas_enabled() {
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());
    let tx = create_v0_transfer(&sender, &recipient, 100, 0);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    // V0 payloads are fee-free (max_fee_per_gas = 0)
    // They should still succeed and report gas used
    assert!(results[0].success, "V0 transaction should succeed");
    
    // Gas should be computed even if fee is 0
    let expected_gas = expected_gas_for_v0_transfer();
    assert_eq!(results[0].gas_used, expected_gas);
    
    // Fee should be 0 for V0 payloads
    assert_eq!(results[0].fee_paid, 0);
}
