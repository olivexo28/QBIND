//! T177 VM v0 Property-Based Tests
//!
//! This module provides property-based tests for VM v0 execution to strengthen
//! the TestNet Alpha execution layer by:
//!
//! - Exercising randomized sequences of transfers over many accounts
//! - Checking key safety invariants:
//!   - P1: No negative balances / no overflow
//!   - P2: Total balance conservation (no mint/burn in Alpha)
//!   - P3: Nonce monotonicity for each sender
//!   - P4: Determinism (same inputs → same outputs)
//!   - P5: No effect from failing txs
//!
//! This helps mitigate TA-R1 ("Execution / VM" risk) from the TestNet Alpha audit.
//!
//! Reference: [QBIND_TESTNET_ALPHA_AUDIT.md §4.2 (TA-R1)](../../docs/testnet/QBIND_TESTNET_ALPHA_AUDIT.md)

use proptest::prelude::*;
use qbind_ledger::{
    AccountStateView, InMemoryAccountState, QbindTransaction, TransferPayload, VmV0ExecutionEngine,
    VmV0TxResult,
};
use std::collections::HashMap;

// ============================================================================
// Test configuration constants
// ============================================================================

/// Maximum number of accounts in generated test scenarios.
const MAX_ACCOUNTS: usize = 16;

/// Minimum number of accounts in generated test scenarios.
const MIN_ACCOUNTS: usize = 2;

/// Maximum initial balance for generated accounts.
const MAX_INITIAL_BALANCE: u128 = 10_000_000;

/// Maximum transfer amount.
const MAX_TRANSFER_AMOUNT: u128 = 1_000_000;

/// Maximum transaction sequence length.
const MAX_TX_SEQUENCE_LEN: usize = 50;

/// Number of proptest cases for standard invariants.
const PROPTEST_CASES: u32 = 100;

/// Number of proptest cases for edge case scenarios.
const EDGE_CASE_PROPTEST_CASES: u32 = 50;

// ============================================================================
// Helper types and functions
// ============================================================================

/// Test account ID from an index.
fn test_account_id(idx: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = idx;
    id
}

/// A generated transfer transaction descriptor.
#[derive(Debug, Clone)]
struct TransferSpec {
    sender_idx: u8,
    recipient_idx: u8,
    amount: u128,
}

/// Initial state for property testing.
#[derive(Debug, Clone)]
struct InitialState {
    /// Map from account index to initial balance.
    accounts: Vec<(u8, u128)>,
}

impl InitialState {
    /// Build an InMemoryAccountState from this InitialState.
    fn build(&self) -> InMemoryAccountState {
        let mut state = InMemoryAccountState::new();
        for (idx, balance) in &self.accounts {
            state.init_account(&test_account_id(*idx), *balance);
        }
        state
    }

    /// Compute total initial balance.
    fn total_balance(&self) -> u128 {
        self.accounts.iter().map(|(_, b)| *b).sum()
    }

    /// Get list of account indices.
    fn account_indices(&self) -> Vec<u8> {
        self.accounts.iter().map(|(idx, _)| *idx).collect()
    }
}

/// Execute a sequence of transfer specs and return results + final state.
fn execute_transfers(
    initial_state: &InitialState,
    transfers: &[TransferSpec],
) -> (Vec<VmV0TxResult>, InMemoryAccountState) {
    let mut state = initial_state.build();
    let engine = VmV0ExecutionEngine::new();

    // Track expected nonces for each sender
    let mut nonces: HashMap<u8, u64> = HashMap::new();

    let txs: Vec<QbindTransaction> = transfers
        .iter()
        .map(|spec| {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *nonces.get(&spec.sender_idx).unwrap_or(&0);
            nonces.insert(spec.sender_idx, nonce + 1);
            let payload = TransferPayload::new(recipient, spec.amount).encode();
            QbindTransaction::new(sender, nonce, payload)
        })
        .collect();

    let results = engine.execute_block(&mut state, &txs);
    (results, state)
}

/// Execute transfers with explicitly provided nonces (for testing nonce mismatches).
fn execute_transfers_with_nonces(
    initial_state: &InitialState,
    transfers: &[(TransferSpec, u64)],
) -> (Vec<VmV0TxResult>, InMemoryAccountState) {
    let mut state = initial_state.build();
    let engine = VmV0ExecutionEngine::new();

    let txs: Vec<QbindTransaction> = transfers
        .iter()
        .map(|(spec, nonce)| {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let payload = TransferPayload::new(recipient, spec.amount).encode();
            QbindTransaction::new(sender, *nonce, payload)
        })
        .collect();

    let results = engine.execute_block(&mut state, &txs);
    (results, state)
}

/// Compute total balance across all known accounts in a state.
fn compute_total_balance(state: &InMemoryAccountState, account_indices: &[u8]) -> u128 {
    let mut seen_accounts: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut total: u128 = 0;

    // Add balances from known accounts
    for idx in account_indices {
        let account = test_account_id(*idx);
        seen_accounts.insert(account);
        total += state.get_account_state(&account).balance;
    }

    // Also iterate all accounts in state (in case recipients were created)
    for (account, account_state) in state.iter() {
        if !seen_accounts.contains(account) {
            total += account_state.balance;
        }
    }

    total
}

// ============================================================================
// Proptest strategies
// ============================================================================

/// Strategy to generate a single account (index, initial_balance).
fn account_strategy() -> impl Strategy<Value = (u8, u128)> {
    (0u8..255, 0u128..=MAX_INITIAL_BALANCE)
}

/// Strategy to generate initial state with 2-16 accounts.
fn initial_state_strategy() -> impl Strategy<Value = InitialState> {
    prop::collection::vec(account_strategy(), MIN_ACCOUNTS..=MAX_ACCOUNTS).prop_map(|accounts| {
        // Ensure unique indices by deduplicating
        let mut seen = std::collections::HashSet::new();
        let unique_accounts: Vec<(u8, u128)> = accounts
            .into_iter()
            .filter(|(idx, _)| seen.insert(*idx))
            .collect();

        // Ensure at least MIN_ACCOUNTS
        let accounts = if unique_accounts.len() < MIN_ACCOUNTS {
            let mut result = unique_accounts;
            for i in 0u8..255 {
                if result.len() >= MIN_ACCOUNTS {
                    break;
                }
                if !seen.contains(&i) {
                    result.push((i, 1000)); // Default balance
                    seen.insert(i);
                }
            }
            result
        } else {
            unique_accounts
        };

        InitialState { accounts }
    })
}

/// Strategy to generate a transfer given available account indices.
fn transfer_strategy(indices: Vec<u8>) -> impl Strategy<Value = TransferSpec> {
    let indices_clone = indices.clone();
    (
        prop::sample::select(indices),
        prop::sample::select(indices_clone),
        0u128..=MAX_TRANSFER_AMOUNT,
    )
        .prop_map(|(sender_idx, recipient_idx, amount)| TransferSpec {
            sender_idx,
            recipient_idx,
            amount,
        })
}

/// Strategy to generate a sequence of transfers.
fn transfer_sequence_strategy(
    initial_state: &InitialState,
) -> impl Strategy<Value = Vec<TransferSpec>> {
    let indices = initial_state.account_indices();
    prop::collection::vec(transfer_strategy(indices), 1..=MAX_TX_SEQUENCE_LEN)
}

/// Combined strategy for initial state + transfer sequence.
fn scenario_strategy() -> impl Strategy<Value = (InitialState, Vec<TransferSpec>)> {
    initial_state_strategy().prop_flat_map(|initial_state| {
        let state_clone = initial_state.clone();
        transfer_sequence_strategy(&initial_state)
            .prop_map(move |transfers| (state_clone.clone(), transfers))
    })
}

// ============================================================================
// Property P1: No Negative Balances / No Overflow
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// P1: After executing any sequence of transfers, all account balances must be >= 0.
    /// With u128, this means no underflow should occur (which would panic or wrap).
    /// The VM should reject insufficient balance transfers gracefully.
    #[test]
    fn prop_no_negative_balances((initial_state, transfers) in scenario_strategy()) {
        let (_results, final_state) = execute_transfers(&initial_state, &transfers);

        // All results should have executed without panics (implicit - if we got here, no panic)

        // Check all accounts have valid state (balances are always >= 0 with u128).
        // The main invariant here is that execution didn't panic and produced valid state.
        for (account, account_state) in final_state.iter() {
            // Verify the account state is accessible and has reasonable values
            // (nonce should be <= number of transactions, balance should be >= 0 implicitly)
            prop_assert!(account_state.nonce <= transfers.len() as u64 * 2,
                "Account {:?} has unexpectedly high nonce: {}", account, account_state.nonce);
        }

        // Also verify all original accounts still exist with valid state
        for idx in initial_state.account_indices() {
            let account = test_account_id(idx);
            let state = final_state.get_account_state(&account);
            // Verify state is accessible (the test passes if no panic occurred)
            let _ = state.balance;
            let _ = state.nonce;
        }
    }
}

// ============================================================================
// Property P2: Total Balance Conservation (No Mint/Burn in Alpha)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// P2: The sum of all balances before and after executing transfers must be equal.
    /// TestNet Alpha has no fees, no minting, no burning - transfers only move funds.
    #[test]
    fn prop_total_balance_conservation((initial_state, transfers) in scenario_strategy()) {
        let initial_total = initial_state.total_balance();

        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        // Collect all account indices that might have balances
        let mut all_indices: std::collections::HashSet<u8> = initial_state
            .account_indices()
            .into_iter()
            .collect();

        // Add recipient indices from transfers
        for spec in &transfers {
            all_indices.insert(spec.recipient_idx);
        }

        // Compute final total balance
        let all_indices_vec: Vec<u8> = all_indices.into_iter().collect();
        let final_total = compute_total_balance(&final_state, &all_indices_vec);

        prop_assert_eq!(
            initial_total,
            final_total,
            "Total balance must be conserved. Initial: {}, Final: {}, Success count: {}",
            initial_total,
            final_total,
            results.iter().filter(|r| r.success).count()
        );
    }
}

// ============================================================================
// Property P3: Nonce Monotonicity
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// P3: For each account, the final nonce equals the number of successfully
    /// applied txs with that account as sender. Nonces only increase.
    #[test]
    fn prop_nonce_monotonicity((initial_state, transfers) in scenario_strategy()) {
        let (_results, final_state) = execute_transfers(&initial_state, &transfers);

        // Track expected nonces (count successful txs per sender)
        let mut state_copy = initial_state.build();
        let engine = VmV0ExecutionEngine::new();
        let mut expected_nonces: HashMap<u8, u64> = HashMap::new();

        // Initialize expected nonces from initial state
        for idx in initial_state.account_indices() {
            expected_nonces.insert(idx, 0);
        }

        // Replay execution to count successful txs per sender
        let mut current_nonces: HashMap<u8, u64> = HashMap::new();
        for spec in &transfers {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *current_nonces.get(&spec.sender_idx).unwrap_or(&0);
            current_nonces.insert(spec.sender_idx, nonce + 1);

            let payload = TransferPayload::new(recipient, spec.amount).encode();
            let tx = QbindTransaction::new(sender, nonce, payload);

            let result = engine.execute_tx(&mut state_copy, &tx);
            if result.success {
                *expected_nonces.entry(spec.sender_idx).or_insert(0) += 1;
            }
        }

        // Verify final nonces match expected
        for (idx, expected_nonce) in expected_nonces {
            let account = test_account_id(idx);
            let final_nonce = final_state.get_account_state(&account).nonce;
            prop_assert_eq!(
                final_nonce,
                expected_nonce,
                "Account {} nonce mismatch: expected {}, got {}",
                idx,
                expected_nonce,
                final_nonce
            );
        }
    }
}

// ============================================================================
// Property P4: Determinism
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// P4: Running the same tx sequence from the same initial state twice
    /// must produce identical final states (per account nonce and balance).
    #[test]
    fn prop_deterministic_execution((initial_state, transfers) in scenario_strategy()) {
        // Execute twice
        let (results1, final_state1) = execute_transfers(&initial_state, &transfers);
        let (results2, final_state2) = execute_transfers(&initial_state, &transfers);

        // Results should be identical
        prop_assert_eq!(
            results1.len(),
            results2.len(),
            "Result count mismatch: {} vs {}",
            results1.len(),
            results2.len()
        );

        for (i, (r1, r2)) in results1.iter().zip(results2.iter()).enumerate() {
            prop_assert_eq!(
                r1.success,
                r2.success,
                "Transaction {} success mismatch: {} vs {}",
                i,
                r1.success,
                r2.success
            );
        }

        // Collect all account indices
        let mut all_indices: std::collections::HashSet<u8> = initial_state
            .account_indices()
            .into_iter()
            .collect();
        for spec in &transfers {
            all_indices.insert(spec.recipient_idx);
        }

        // Final states should be identical
        for idx in all_indices {
            let account = test_account_id(idx);
            let state1 = final_state1.get_account_state(&account);
            let state2 = final_state2.get_account_state(&account);

            prop_assert_eq!(
                state1.nonce,
                state2.nonce,
                "Account {} nonce mismatch: {} vs {}",
                idx,
                state1.nonce,
                state2.nonce
            );
            prop_assert_eq!(
                state1.balance,
                state2.balance,
                "Account {} balance mismatch: {} vs {}",
                idx,
                state1.balance,
                state2.balance
            );
        }
    }
}

// ============================================================================
// Property P5: Failing Transactions Do Not Mutate State
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// P5: Transactions that fail (nonce mismatch, insufficient balance) must not
    /// change global state. The state after skipping failing txs equals the state
    /// after including them.
    #[test]
    fn prop_failing_txs_no_state_change((initial_state, transfers) in scenario_strategy()) {
        let engine = VmV0ExecutionEngine::new();

        // Execute all transfers
        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        // Now execute only successful transfers
        let mut state_only_success = initial_state.build();
        let mut current_nonces: HashMap<u8, u64> = HashMap::new();

        for (i, spec) in transfers.iter().enumerate() {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *current_nonces.get(&spec.sender_idx).unwrap_or(&0);
            current_nonces.insert(spec.sender_idx, nonce + 1);

            let payload = TransferPayload::new(recipient, spec.amount).encode();
            let tx = QbindTransaction::new(sender, nonce, payload);

            // Only execute if original was successful
            if results[i].success {
                let _ = engine.execute_tx(&mut state_only_success, &tx);
            }
        }

        // States should match
        let mut all_indices: std::collections::HashSet<u8> = initial_state
            .account_indices()
            .into_iter()
            .collect();
        for spec in &transfers {
            all_indices.insert(spec.recipient_idx);
        }

        for idx in all_indices {
            let account = test_account_id(idx);
            let state_full = final_state.get_account_state(&account);
            let state_success_only = state_only_success.get_account_state(&account);

            prop_assert_eq!(
                state_full.nonce,
                state_success_only.nonce,
                "Account {} nonce mismatch (full vs success-only): {} vs {}",
                idx,
                state_full.nonce,
                state_success_only.nonce
            );
            prop_assert_eq!(
                state_full.balance,
                state_success_only.balance,
                "Account {} balance mismatch (full vs success-only): {} vs {}",
                idx,
                state_full.balance,
                state_success_only.balance
            );
        }
    }
}

// ============================================================================
// Edge Case Tests: Self-Transfers
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EDGE_CASE_PROPTEST_CASES))]

    /// Edge case: Self-transfers (sender == recipient) should be valid
    /// and not change the balance (only increment nonce).
    #[test]
    fn prop_self_transfers_preserve_balance(
        account_idx in 0u8..255,
        initial_balance in 1000u128..=MAX_INITIAL_BALANCE,
        transfer_count in 1usize..=10,
        amounts in prop::collection::vec(0u128..=1000u128, 1..=10)
    ) {
        let initial_state = InitialState {
            accounts: vec![(account_idx, initial_balance)],
        };

        // Create self-transfers
        let transfers: Vec<TransferSpec> = amounts
            .into_iter()
            .take(transfer_count)
            .map(|amount| TransferSpec {
                sender_idx: account_idx,
                recipient_idx: account_idx,
                amount: amount.min(initial_balance), // Ensure valid amounts
            })
            .collect();

        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        let account = test_account_id(account_idx);
        let final_account = final_state.get_account_state(&account);

        // Balance should be unchanged (self-transfers don't change net balance)
        prop_assert_eq!(
            final_account.balance,
            initial_balance,
            "Self-transfer should preserve balance: initial {}, final {}",
            initial_balance,
            final_account.balance
        );

        // Nonce should equal number of successful transfers
        let success_count = results.iter().filter(|r| r.success).count() as u64;
        prop_assert_eq!(
            final_account.nonce,
            success_count,
            "Nonce should equal success count: {} vs {}",
            final_account.nonce,
            success_count
        );
    }
}

// ============================================================================
// Edge Case Tests: Hot Account (Many Recipients)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EDGE_CASE_PROPTEST_CASES))]

    /// Edge case: Long chains of sequential transfers from one hot account to many recipients.
    #[test]
    fn prop_hot_account_to_many_recipients(
        sender_idx in 0u8..10,
        initial_balance in 100_000u128..=MAX_INITIAL_BALANCE,
        recipient_count in 2usize..=10,
        amount_per_recipient in 1u128..=1000
    ) {
        // Create initial state with hot sender and cold recipients
        let mut accounts = vec![(sender_idx, initial_balance)];
        let recipient_indices: Vec<u8> = (0..recipient_count as u8)
            .filter(|i| *i != sender_idx)
            .take(recipient_count)
            .collect();

        for &ridx in &recipient_indices {
            if ridx != sender_idx {
                accounts.push((ridx, 0)); // Recipients start with 0 balance
            }
        }

        let initial_state = InitialState { accounts };
        let initial_total = initial_state.total_balance();

        // Create transfers from hot account to each recipient
        let transfers: Vec<TransferSpec> = recipient_indices
            .iter()
            .map(|&recipient_idx| TransferSpec {
                sender_idx,
                recipient_idx,
                amount: amount_per_recipient,
            })
            .collect();

        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        // Count successful transfers
        let success_count = results.iter().filter(|r| r.success).count();

        // Verify sender's balance decreased correctly
        let sender = test_account_id(sender_idx);
        let sender_final = final_state.get_account_state(&sender);
        let expected_sender_balance = initial_balance.saturating_sub(
            success_count as u128 * amount_per_recipient
        );
        prop_assert_eq!(
            sender_final.balance,
            expected_sender_balance,
            "Sender balance incorrect: expected {}, got {}",
            expected_sender_balance,
            sender_final.balance
        );

        // Verify total balance is conserved
        let mut all_indices: std::collections::HashSet<u8> = std::collections::HashSet::new();
        all_indices.insert(sender_idx);
        for &idx in &recipient_indices {
            all_indices.insert(idx);
        }
        let all_indices_vec: Vec<u8> = all_indices.into_iter().collect();
        let final_total = compute_total_balance(&final_state, &all_indices_vec);

        prop_assert_eq!(
            initial_total,
            final_total,
            "Total balance conservation failed: {} vs {}",
            initial_total,
            final_total
        );
    }
}

// ============================================================================
// Edge Case Tests: Many Tiny Dust Transfers
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EDGE_CASE_PROPTEST_CASES))]

    /// Edge case: Many tiny (dust) transfers to stress test the system.
    #[test]
    fn prop_many_dust_transfers(
        sender_idx in 0u8..10,
        recipient_idx in 10u8..20,
        initial_balance in 10_000u128..=100_000,
        transfer_count in 10usize..=50
    ) {
        let initial_state = InitialState {
            accounts: vec![(sender_idx, initial_balance), (recipient_idx, 0)],
        };
        let initial_total = initial_state.total_balance();

        // Create many tiny transfers (amount = 1)
        let transfers: Vec<TransferSpec> = (0..transfer_count)
            .map(|_| TransferSpec {
                sender_idx,
                recipient_idx,
                amount: 1, // Dust transfers
            })
            .collect();

        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        let success_count = results.iter().filter(|r| r.success).count();

        // Verify sender balance
        let sender = test_account_id(sender_idx);
        let sender_final = final_state.get_account_state(&sender);
        prop_assert_eq!(
            sender_final.balance,
            initial_balance - success_count as u128,
            "Sender balance after dust transfers: expected {}, got {}",
            initial_balance - success_count as u128,
            sender_final.balance
        );

        // Verify recipient balance
        let recipient = test_account_id(recipient_idx);
        let recipient_final = final_state.get_account_state(&recipient);
        prop_assert_eq!(
            recipient_final.balance,
            success_count as u128,
            "Recipient balance: expected {}, got {}",
            success_count,
            recipient_final.balance
        );

        // Verify total balance conservation
        let final_total = compute_total_balance(&final_state, &[sender_idx, recipient_idx]);
        prop_assert_eq!(
            initial_total,
            final_total,
            "Balance conservation after dust transfers: {} vs {}",
            initial_total,
            final_total
        );
    }
}

// ============================================================================
// Edge Case Tests: Large Balance Near Overflow Boundary
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EDGE_CASE_PROPTEST_CASES))]

    /// Edge case: Large amounts near u128 boundary (within safe range).
    /// We use u128::MAX / 2 as a "large but safe" boundary to avoid overflow in sums.
    #[test]
    fn prop_large_balance_transfers(
        sender_idx in 0u8..10,
        recipient_idx in 10u8..20,
        // Use balances up to ~10^35 which is large but won't overflow when summed
        initial_balance in (u128::MAX / 1000)..(u128::MAX / 100),
        transfer_ratio in 1u128..=100
    ) {
        // Transfer a fraction of the balance
        let transfer_amount = initial_balance / transfer_ratio;

        let initial_state = InitialState {
            accounts: vec![(sender_idx, initial_balance), (recipient_idx, 0)],
        };
        let initial_total = initial_state.total_balance();

        let transfers = vec![TransferSpec {
            sender_idx,
            recipient_idx,
            amount: transfer_amount,
        }];

        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        // Should succeed (we have enough balance)
        prop_assert!(
            results[0].success,
            "Large transfer should succeed: amount={}, balance={}",
            transfer_amount,
            initial_balance
        );

        // Verify balances
        let sender = test_account_id(sender_idx);
        let recipient = test_account_id(recipient_idx);
        let sender_final = final_state.get_account_state(&sender);
        let recipient_final = final_state.get_account_state(&recipient);

        prop_assert_eq!(
            sender_final.balance,
            initial_balance - transfer_amount,
            "Sender balance after large transfer"
        );
        prop_assert_eq!(
            recipient_final.balance,
            transfer_amount,
            "Recipient balance after large transfer"
        );

        // Verify total balance conservation
        let final_total = compute_total_balance(&final_state, &[sender_idx, recipient_idx]);
        prop_assert_eq!(
            initial_total,
            final_total,
            "Balance conservation with large amounts: {} vs {}",
            initial_total,
            final_total
        );
    }
}

// ============================================================================
// Edge Case Tests: Nonce Mismatch Rejection
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EDGE_CASE_PROPTEST_CASES))]

    /// Edge case: Transactions with incorrect nonces should be rejected
    /// and not change state.
    #[test]
    fn prop_nonce_mismatch_rejection(
        sender_idx in 0u8..10,
        recipient_idx in 10u8..20,
        initial_balance in 1000u128..=10_000,
        wrong_nonce in 1u64..=100  // Should be 0 for first tx
    ) {
        let initial_state = InitialState {
            accounts: vec![(sender_idx, initial_balance), (recipient_idx, 0)],
        };

        // Create transfer with wrong nonce
        let transfers = vec![(
            TransferSpec {
                sender_idx,
                recipient_idx,
                amount: 100,
            },
            wrong_nonce, // Wrong nonce (should be 0)
        )];

        let (results, final_state) = execute_transfers_with_nonces(&initial_state, &transfers);

        // Should fail
        prop_assert!(
            !results[0].success,
            "Transfer with wrong nonce should fail: nonce={}, expected=0",
            wrong_nonce
        );

        // State should be unchanged
        let sender = test_account_id(sender_idx);
        let sender_final = final_state.get_account_state(&sender);
        prop_assert_eq!(
            sender_final.balance,
            initial_balance,
            "Sender balance should be unchanged after nonce mismatch"
        );
        prop_assert_eq!(
            sender_final.nonce,
            0,
            "Sender nonce should be unchanged after nonce mismatch"
        );
    }
}

// ============================================================================
// Edge Case Tests: Insufficient Balance Rejection
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(EDGE_CASE_PROPTEST_CASES))]

    /// Edge case: Transfers with insufficient balance should be rejected
    /// and not change state.
    #[test]
    fn prop_insufficient_balance_rejection(
        sender_idx in 0u8..10,
        recipient_idx in 10u8..20,
        initial_balance in 100u128..=1000,
        excess_multiplier in 2u128..=10
    ) {
        let transfer_amount = initial_balance * excess_multiplier; // More than balance

        let initial_state = InitialState {
            accounts: vec![(sender_idx, initial_balance), (recipient_idx, 0)],
        };

        let transfers = vec![TransferSpec {
            sender_idx,
            recipient_idx,
            amount: transfer_amount,
        }];

        let (results, final_state) = execute_transfers(&initial_state, &transfers);

        // Should fail
        prop_assert!(
            !results[0].success,
            "Transfer with insufficient balance should fail: amount={}, balance={}",
            transfer_amount,
            initial_balance
        );

        // State should be unchanged
        let sender = test_account_id(sender_idx);
        let sender_final = final_state.get_account_state(&sender);
        prop_assert_eq!(
            sender_final.balance,
            initial_balance,
            "Sender balance should be unchanged after insufficient balance"
        );
        prop_assert_eq!(
            sender_final.nonce,
            0,
            "Sender nonce should be unchanged after insufficient balance rejection"
        );
    }
}

// ============================================================================
// Unit Tests (Non-Property Based)
// ============================================================================

#[test]
fn test_basic_transfer_roundtrip() {
    let initial_state = InitialState {
        accounts: vec![(0, 1000), (1, 0)],
    };

    let transfers = vec![TransferSpec {
        sender_idx: 0,
        recipient_idx: 1,
        amount: 100,
    }];

    let (results, final_state) = execute_transfers(&initial_state, &transfers);

    assert!(results[0].success, "Transfer should succeed");

    let sender = test_account_id(0);
    let recipient = test_account_id(1);

    assert_eq!(final_state.get_account_state(&sender).balance, 900);
    assert_eq!(final_state.get_account_state(&sender).nonce, 1);
    assert_eq!(final_state.get_account_state(&recipient).balance, 100);
    assert_eq!(final_state.get_account_state(&recipient).nonce, 0);
}

#[test]
fn test_malformed_payload_rejected() {
    let mut state = InMemoryAccountState::new();
    state.init_account(&test_account_id(0), 1000);

    let engine = VmV0ExecutionEngine::new();

    // Create transaction with malformed payload
    let tx = QbindTransaction::new(test_account_id(0), 0, vec![0xFF; 10]); // Wrong size

    let result = engine.execute_tx(&mut state, &tx);

    assert!(!result.success, "Malformed payload should fail");

    // State should be unchanged
    let account = state.get_account_state(&test_account_id(0));
    assert_eq!(account.balance, 1000);
    assert_eq!(account.nonce, 0);
}

#[test]
fn test_zero_amount_transfer_succeeds() {
    let initial_state = InitialState {
        accounts: vec![(0, 1000), (1, 500)],
    };

    let transfers = vec![TransferSpec {
        sender_idx: 0,
        recipient_idx: 1,
        amount: 0, // Zero amount transfer
    }];

    let (results, final_state) = execute_transfers(&initial_state, &transfers);

    assert!(results[0].success, "Zero amount transfer should succeed");

    // Balances unchanged
    assert_eq!(
        final_state.get_account_state(&test_account_id(0)).balance,
        1000
    );
    assert_eq!(
        final_state.get_account_state(&test_account_id(1)).balance,
        500
    );

    // Sender nonce incremented
    assert_eq!(final_state.get_account_state(&test_account_id(0)).nonce, 1);
}

#[test]
fn test_recipient_account_creation() {
    let initial_state = InitialState {
        accounts: vec![(0, 1000)], // Only sender exists
    };

    let transfers = vec![TransferSpec {
        sender_idx: 0,
        recipient_idx: 99, // Non-existent account
        amount: 100,
    }];

    let (results, final_state) = execute_transfers(&initial_state, &transfers);

    assert!(results[0].success, "Transfer to new account should succeed");

    // Recipient account should be created with transferred balance
    let recipient = test_account_id(99);
    let recipient_state = final_state.get_account_state(&recipient);
    assert_eq!(recipient_state.balance, 100);
    assert_eq!(recipient_state.nonce, 0); // New accounts start with nonce 0
}
