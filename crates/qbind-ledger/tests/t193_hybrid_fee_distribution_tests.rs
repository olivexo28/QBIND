//! T193: Hybrid Fee Distribution Tests
//!
//! This module tests the hybrid fee distribution feature introduced in T193:
//! - Burn + Proposer Reward distribution
//! - MainNet 50/50 configuration
//! - Balance + burned + proposer conservation invariants
//! - DevNet/TestNet burn-only behavior confirmation

use qbind_ledger::{
    AccountStateView, ExecutionGasConfig, FeeDistributionPolicy, InMemoryAccountState,
    QbindTransaction, TransferPayload, TransferPayloadV1, VmV0ExecutionEngine,
};
use qbind_types::AccountId;

// ============================================================================
// Test Helpers
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

// ============================================================================
// Burn-Only Tests (DevNet / TestNet Alpha / TestNet Beta behavior)
// ============================================================================

#[test]
fn test_burn_only_no_proposer_rewards() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    // Setup state
    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);
    state.init_account(&proposer, 0); // Proposer starts with 0

    // Create engine with burn-only policy (default for TestNet)
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Execute a transfer with proposer
    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 50_000, 10);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(results[0].success);

    // Verify proposer received NOTHING (burn-only)
    let proposer_state = state.get_account_state(&proposer);
    assert_eq!(
        proposer_state.balance, 0,
        "Proposer should receive nothing in burn-only mode"
    );

    // Verify fee was burned (sender paid, nobody received)
    assert!(results[0].fee_paid > 0);
    assert_eq!(results[0].fee_burned, results[0].fee_paid);
    assert_eq!(results[0].fee_to_proposer, 0);
}

#[test]
fn test_burn_only_stats() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000_000);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Execute multiple transfers
    let txs: Vec<_> = (0..3)
        .map(|i| create_v1_transfer(&sender, &recipient, 1000, i, 50_000, 10))
        .collect();

    let (results, stats) =
        engine.execute_block_with_proposer_and_stats(&mut state, &txs, &proposer);

    assert_eq!(stats.txs_executed, 3);
    assert_eq!(stats.txs_succeeded, 3);

    // All fees burned, none to proposer
    assert!(stats.total_fees_burned > 0);
    assert_eq!(stats.total_fees_to_proposer, 0);

    // Total fees should equal burned (conservation)
    // M18: total_fees() now returns Option<u128>
    assert_eq!(stats.total_fees().unwrap(), stats.total_fees_burned);

    // Individual results should all be burn-only
    for r in &results {
        assert_eq!(r.fee_to_proposer, 0);
        assert_eq!(r.fee_paid, r.fee_burned);
    }
}

// ============================================================================
// MainNet Hybrid Distribution Tests (50% burn, 50% proposer)
// ============================================================================

#[test]
fn test_mainnet_hybrid_distribution() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);
    state.init_account(&proposer, 100); // Proposer starts with some balance

    let initial_proposer_balance = 100u128;

    // Create engine with MainNet config (50/50 split)
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    // Execute a transfer
    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 50_000, 10);
    let (results, stats) =
        engine.execute_block_with_proposer_and_stats(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(results[0].success);

    // Verify the split
    let total_fee = results[0].fee_paid;
    let fee_burned = results[0].fee_burned;
    let fee_to_proposer = results[0].fee_to_proposer;

    // Conservation: burned + proposer = total
    assert_eq!(
        fee_burned + fee_to_proposer,
        total_fee,
        "Fee conservation violated"
    );

    // 50/50 split (may have rounding)
    let expected_proposer = total_fee * 5000 / 10000;
    let expected_burn = total_fee - expected_proposer;
    assert_eq!(fee_to_proposer, expected_proposer);
    assert_eq!(fee_burned, expected_burn);

    // Verify proposer balance increased
    let proposer_state = state.get_account_state(&proposer);
    assert_eq!(
        proposer_state.balance,
        initial_proposer_balance + fee_to_proposer,
        "Proposer balance should increase by fee_to_proposer"
    );

    // Verify stats match
    assert_eq!(stats.total_fees_burned, fee_burned);
    assert_eq!(stats.total_fees_to_proposer, fee_to_proposer);
}

#[test]
fn test_mainnet_multiple_transactions() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 100_000_000);
    state.init_account(&proposer, 0);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    // Execute 5 transactions
    let txs: Vec<_> = (0..5)
        .map(|i| create_v1_transfer(&sender, &recipient, 10_000, i, 50_000, 10))
        .collect();

    let (results, stats) =
        engine.execute_block_with_proposer_and_stats(&mut state, &txs, &proposer);

    assert_eq!(stats.txs_executed, 5);
    assert_eq!(stats.txs_succeeded, 5);

    // Accumulate from individual results
    let sum_burned: u128 = results.iter().map(|r| r.fee_burned).sum();
    let sum_proposer: u128 = results.iter().map(|r| r.fee_to_proposer).sum();
    let sum_total: u128 = results.iter().map(|r| r.fee_paid).sum();

    // Stats should match individual sums
    assert_eq!(stats.total_fees_burned, sum_burned);
    assert_eq!(stats.total_fees_to_proposer, sum_proposer);

    // Conservation for all transactions combined
    assert_eq!(sum_burned + sum_proposer, sum_total);

    // Proposer received the expected amount
    let proposer_state = state.get_account_state(&proposer);
    assert_eq!(proposer_state.balance, sum_proposer);
}

// ============================================================================
// Balance Conservation Tests
// ============================================================================

#[test]
fn test_total_balance_conservation_burn_only() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    let initial_sender = 10_000_000u128;
    state.init_account(&sender, initial_sender);
    state.init_account(&recipient, 0);
    state.init_account(&proposer, 0);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    let txs: Vec<_> = (0..3)
        .map(|i| create_v1_transfer(&sender, &recipient, 100_000, i, 50_000, 10))
        .collect();

    let (_, stats) = engine.execute_block_with_proposer_and_stats(&mut state, &txs, &proposer);

    // Conservation check:
    // initial_total = final_total + total_fees_burned
    // (Since burn-only, no fees go to proposer)
    let final_sender = state.get_account_state(&sender).balance;
    let final_recipient = state.get_account_state(&recipient).balance;
    let final_proposer = state.get_account_state(&proposer).balance;

    let final_total = final_sender + final_recipient + final_proposer;
    let total_burned = stats.total_fees_burned;

    assert_eq!(
        initial_sender,
        final_total + total_burned,
        "Balance + burned fees should equal initial balance"
    );
}

#[test]
fn test_total_balance_conservation_mainnet() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    let initial_sender = 10_000_000u128;
    let initial_proposer = 50_000u128;
    state.init_account(&sender, initial_sender);
    state.init_account(&recipient, 0);
    state.init_account(&proposer, initial_proposer);

    let initial_total = initial_sender + initial_proposer;

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    let txs: Vec<_> = (0..5)
        .map(|i| create_v1_transfer(&sender, &recipient, 50_000, i, 50_000, 10))
        .collect();

    let (_, stats) = engine.execute_block_with_proposer_and_stats(&mut state, &txs, &proposer);

    // Conservation check:
    // initial_total = final_total + total_fees_burned
    // (Proposer reward is NOT burned, so it stays in circulation)
    let final_sender = state.get_account_state(&sender).balance;
    let final_recipient = state.get_account_state(&recipient).balance;
    let final_proposer = state.get_account_state(&proposer).balance;

    let final_total = final_sender + final_recipient + final_proposer;
    let total_burned = stats.total_fees_burned;

    assert_eq!(
        initial_total,
        final_total + total_burned,
        "Total balance (sender + recipient + proposer) + burned fees should equal initial total"
    );

    // The proposer gained their rewards
    assert!(final_proposer > initial_proposer);
    assert_eq!(
        final_proposer,
        initial_proposer + stats.total_fees_to_proposer
    );
}

// ============================================================================
// Custom Fee Policy Tests
// ============================================================================

#[test]
fn test_custom_fee_policy_70_30() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000_000); // Higher balance
    state.init_account(&proposer, 0);

    // 70% burn, 30% proposer
    let policy = FeeDistributionPolicy::new(7_000, 3_000);
    let config = ExecutionGasConfig::enabled_with_policy(policy);
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 50_000, 10);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert!(results[0].success);

    let total = results[0].fee_paid;
    let burn = results[0].fee_burned;
    let prop = results[0].fee_to_proposer;

    // Verify split (30% to proposer)
    let expected_proposer = total * 3000 / 10000;
    let expected_burn = total - expected_proposer;

    assert_eq!(prop, expected_proposer);
    assert_eq!(burn, expected_burn);
    assert_eq!(burn + prop, total);

    // Proposer received their share
    assert_eq!(state.get_account_state(&proposer).balance, prop);
}

#[test]
fn test_proposer_only_policy() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 10_000_000); // Higher balance
    state.init_account(&proposer, 0);

    // 0% burn, 100% proposer
    let policy = FeeDistributionPolicy::new(0, 10_000);
    let config = ExecutionGasConfig::enabled_with_policy(policy);
    let engine = VmV0ExecutionEngine::with_gas_config(config);

    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 50_000, 10);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert!(results[0].success);

    // All fees to proposer, nothing burned
    assert_eq!(results[0].fee_burned, 0);
    assert_eq!(results[0].fee_to_proposer, results[0].fee_paid);

    // Proposer got everything
    assert_eq!(
        state.get_account_state(&proposer).balance,
        results[0].fee_paid
    );
}

// ============================================================================
// Failed Transaction Tests
// ============================================================================

#[test]
fn test_failed_tx_no_fee_distribution() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1000); // Low balance, will fail
    state.init_account(&proposer, 0);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    // This transfer should fail (insufficient balance for amount + fee)
    let tx = create_v1_transfer(&sender, &recipient, 900, 0, 50_000, 10);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert_eq!(results.len(), 1);
    assert!(!results[0].success, "Transaction should fail");

    // Failed transactions should NOT distribute fees
    assert_eq!(results[0].fee_paid, 0);
    assert_eq!(results[0].fee_burned, 0);
    assert_eq!(results[0].fee_to_proposer, 0);

    // Proposer should receive nothing
    assert_eq!(state.get_account_state(&proposer).balance, 0);

    // Sender balance unchanged
    assert_eq!(state.get_account_state(&sender).balance, 1000);
}

#[test]
fn test_mixed_success_failure_fee_distribution() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 5_000_000); // Higher balance
    state.init_account(&proposer, 0);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    let txs = vec![
        create_v1_transfer(&sender, &recipient, 10_000, 0, 50_000, 10), // Success
        create_v1_transfer(&sender, &recipient, 10_000, 1, 50_000, 10), // Success
        create_v1_transfer(&sender, &recipient, 10_000, 3, 50_000, 10), // Nonce skip - fail
    ];

    let (results, stats) =
        engine.execute_block_with_proposer_and_stats(&mut state, &txs, &proposer);

    // 2 should succeed, 1 should fail (nonce mismatch)
    assert!(results[0].success);
    assert!(results[1].success);
    assert!(!results[2].success);

    // Only successful txs contribute to fees
    let successful_fees: u128 = results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.fee_paid)
        .sum();
    let successful_proposer: u128 = results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.fee_to_proposer)
        .sum();
    let successful_burned: u128 = results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.fee_burned)
        .sum();

    assert_eq!(stats.total_fees_to_proposer, successful_proposer);
    assert_eq!(stats.total_fees_burned, successful_burned);
    // M18: total_fees() now returns Option<u128>
    assert_eq!(stats.total_fees().unwrap(), successful_fees);

    // Proposer received only from successful txs
    assert_eq!(
        state.get_account_state(&proposer).balance,
        successful_proposer
    );
}

// ============================================================================
// Backward Compatibility Tests
// ============================================================================

#[test]
fn test_execute_block_without_proposer_burns_all() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);

    // Even with MainNet config, execute_block (without proposer) should work
    // In this case, proposer rewards are effectively burned
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 50_000, 10);
    let results = engine.execute_block(&mut state, &[tx]);

    assert_eq!(results.len(), 1);
    assert!(results[0].success);

    // Fee was distributed according to policy, but proposer portion wasn't credited
    // (since no proposer was provided)
    // The result still tracks what WOULD have been distributed
    assert!(
        results[0].fee_to_proposer > 0,
        "Policy specifies proposer reward"
    );
    assert!(results[0].fee_burned > 0, "Policy specifies burn portion");
}

#[test]
fn test_gas_disabled_no_fees() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);
    state.init_account(&proposer, 0);

    // Gas disabled (DevNet mode) - must use v0 payload
    let engine = VmV0ExecutionEngine::new();

    let tx = create_v0_transfer(&sender, &recipient, 1000, 0);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert!(results[0].success);

    // No fees when gas is disabled
    assert_eq!(results[0].fee_paid, 0);
    assert_eq!(results[0].fee_burned, 0);
    assert_eq!(results[0].fee_to_proposer, 0);

    // Proposer received nothing
    assert_eq!(state.get_account_state(&proposer).balance, 0);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_zero_fee_transaction() {
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);
    let proposer = test_account_id(0xFF);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);
    state.init_account(&proposer, 100);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    // Zero max_fee_per_gas = zero total fee
    let tx = create_v1_transfer(&sender, &recipient, 1000, 0, 50_000, 0);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &proposer);

    assert!(results[0].success);
    assert_eq!(results[0].fee_paid, 0);
    assert_eq!(results[0].fee_burned, 0);
    assert_eq!(results[0].fee_to_proposer, 0);

    // Proposer balance unchanged
    assert_eq!(state.get_account_state(&proposer).balance, 100);
}

#[test]
fn test_proposer_is_sender() {
    // Edge case: proposer is also the sender
    let sender_proposer = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender_proposer, 1_000_000);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    let initial_balance = state.get_account_state(&sender_proposer).balance;

    let tx = create_v1_transfer(&sender_proposer, &recipient, 10_000, 0, 50_000, 10);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &sender_proposer);

    assert!(results[0].success);

    let final_balance = state.get_account_state(&sender_proposer).balance;
    let recipient_balance = state.get_account_state(&recipient).balance;
    let fee_paid = results[0].fee_paid;
    let fee_to_proposer = results[0].fee_to_proposer;
    let fee_burned = results[0].fee_burned;

    // Sender paid: transfer_amount + fee_paid
    // Sender received back: fee_to_proposer
    // Net effect on sender: -(transfer_amount + fee_burned)
    assert_eq!(
        initial_balance,
        final_balance + 10_000 + fee_burned,
        "Sender-proposer net effect should be transfer + burned fees only"
    );

    // Recipient received transfer amount
    assert_eq!(recipient_balance, 10_000);

    // Fee conservation
    assert_eq!(fee_burned + fee_to_proposer, fee_paid);
}

#[test]
fn test_proposer_is_recipient() {
    // Edge case: proposer is also the recipient
    let sender = test_account_id(0xAA);
    let recipient_proposer = test_account_id(0xBB);

    let mut state = InMemoryAccountState::new();
    state.init_account(&sender, 1_000_000);
    state.init_account(&recipient_proposer, 100);

    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::mainnet());

    let initial_rp_balance = state.get_account_state(&recipient_proposer).balance;

    let tx = create_v1_transfer(&sender, &recipient_proposer, 10_000, 0, 50_000, 10);
    let results = engine.execute_block_with_proposer(&mut state, &[tx], &recipient_proposer);

    assert!(results[0].success);

    let final_rp_balance = state.get_account_state(&recipient_proposer).balance;
    let fee_to_proposer = results[0].fee_to_proposer;

    // Recipient-proposer should receive: transfer_amount + fee_to_proposer
    assert_eq!(
        final_rp_balance,
        initial_rp_balance + 10_000 + fee_to_proposer
    );
}
