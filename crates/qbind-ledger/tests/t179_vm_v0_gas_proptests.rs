//! T179 VM v0 Gas-Enabled Property-Based Tests
//!
//! This module provides property-based tests for VM v0 execution with gas enforcement
//! enabled, validating fee accounting invariants and gas limit behavior.
//!
//! Goals:
//! - Validate gas-enabled execution maintains balance + fee conservation
//! - Ensure nonce monotonicity with gas enforcement
//! - Verify failed transactions don't consume fees
//! - Confirm block gas limits are respected
//!
//! These tests use the actual gas implementation from T168 (`execution_gas.rs`)
//! and run with `ExecutionGasConfig.enabled = true`.
//!
//! Reference: [QBIND_TESTNET_BETA_SPEC.md §3](../../docs/testnet/QBIND_TESTNET_BETA_SPEC.md)
//! Reference: [QBIND_TESTNET_BETA_AUDIT_SKELETON.md §2.2 (TB-R1, TB-R3)](../../docs/testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md)

use proptest::prelude::*;
use qbind_ledger::{
    AccountStateView, ExecutionGasConfig, InMemoryAccountState, QbindTransaction, TransferPayload,
    TransferPayloadV1, VmV0ExecutionEngine, VmV0TxResult,
};
use std::collections::HashMap;

// ============================================================================
// Test configuration constants
// ============================================================================

/// Maximum number of accounts in generated test scenarios.
const MAX_ACCOUNTS: usize = 8;

/// Minimum number of accounts in generated test scenarios.
const MIN_ACCOUNTS: usize = 2;

/// Maximum initial balance for generated accounts (high enough for fees).
const MAX_INITIAL_BALANCE: u128 = 100_000_000;

/// Maximum transfer amount.
const MAX_TRANSFER_AMOUNT: u128 = 1_000_000;

/// Maximum transaction sequence length.
const MAX_TX_SEQUENCE_LEN: usize = 30;

/// Number of proptest cases for gas properties.
const GAS_PROPTEST_CASES: u32 = 50;

/// Maximum max_fee_per_gas for generated transactions.
const MAX_FEE_PER_GAS: u128 = 100;

/// Block gas limit for tests that need a smaller limit.
const TEST_BLOCK_GAS_LIMIT: u64 = 200_000;

// ============================================================================
// Helper types and functions
// ============================================================================

/// Test account ID from an index.
fn test_account_id(idx: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = idx;
    id
}

/// A generated gas-enabled transfer transaction descriptor.
#[derive(Debug, Clone)]
struct GasTransferSpec {
    sender_idx: u8,
    recipient_idx: u8,
    amount: u128,
    gas_limit: u64,
    max_fee_per_gas: u128,
    use_v1_payload: bool,
}

/// Initial state for gas property testing.
#[derive(Debug, Clone)]
struct GasInitialState {
    /// Map from account index to initial balance.
    accounts: Vec<(u8, u128)>,
}

impl GasInitialState {
    /// Build an InMemoryAccountState from this GasInitialState.
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

/// Execute a sequence of gas-enabled transfer specs and return results + final state.
fn execute_gas_transfers(
    initial_state: &GasInitialState,
    transfers: &[GasTransferSpec],
) -> (Vec<VmV0TxResult>, InMemoryAccountState, u128) {
    let mut state = initial_state.build();
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

    // Track nonces for each sender
    let mut nonces: HashMap<u8, u64> = HashMap::new();
    let mut total_fees_burned: u128 = 0;

    let txs: Vec<QbindTransaction> = transfers
        .iter()
        .map(|spec| {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *nonces.get(&spec.sender_idx).unwrap_or(&0);
            nonces.insert(spec.sender_idx, nonce + 1);

            let payload = if spec.use_v1_payload {
                TransferPayloadV1::new(recipient, spec.amount, spec.gas_limit, spec.max_fee_per_gas)
                    .encode()
            } else {
                TransferPayload::new(recipient, spec.amount).encode()
            };

            QbindTransaction::new(sender, nonce, payload)
        })
        .collect();

    let results = engine.execute_block(&mut state, &txs);

    // Sum up fees burned from successful transactions
    for result in &results {
        if result.success {
            total_fees_burned += result.fee_paid;
        }
    }

    (results, state, total_fees_burned)
}

/// Execute gas-enabled transfers with a custom block gas limit.
fn execute_gas_transfers_with_limit(
    initial_state: &GasInitialState,
    transfers: &[GasTransferSpec],
    block_gas_limit: u64,
) -> (Vec<VmV0TxResult>, InMemoryAccountState, u128) {
    let mut state = initial_state.build();
    let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled_with_limit(
        block_gas_limit,
    ));

    // Track nonces for each sender
    let mut nonces: HashMap<u8, u64> = HashMap::new();
    let mut total_fees_burned: u128 = 0;

    let txs: Vec<QbindTransaction> = transfers
        .iter()
        .map(|spec| {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *nonces.get(&spec.sender_idx).unwrap_or(&0);
            nonces.insert(spec.sender_idx, nonce + 1);

            let payload = if spec.use_v1_payload {
                TransferPayloadV1::new(recipient, spec.amount, spec.gas_limit, spec.max_fee_per_gas)
                    .encode()
            } else {
                TransferPayload::new(recipient, spec.amount).encode()
            };

            QbindTransaction::new(sender, nonce, payload)
        })
        .collect();

    let results = engine.execute_block(&mut state, &txs);

    // Sum up fees burned from successful transactions
    for result in &results {
        if result.success {
            total_fees_burned += result.fee_paid;
        }
    }

    (results, state, total_fees_burned)
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
/// Ensures sufficient balance for gas fees.
fn gas_account_strategy() -> impl Strategy<Value = (u8, u128)> {
    (0u8..100, 10_000_000u128..=MAX_INITIAL_BALANCE)
}

/// Strategy to generate initial state with 2-8 accounts.
fn gas_initial_state_strategy() -> impl Strategy<Value = GasInitialState> {
    prop::collection::vec(gas_account_strategy(), MIN_ACCOUNTS..=MAX_ACCOUNTS).prop_map(
        |accounts| {
            // Ensure unique indices
            let mut seen = std::collections::HashSet::new();
            let unique_accounts: Vec<(u8, u128)> = accounts
                .into_iter()
                .filter(|(idx, _)| seen.insert(*idx))
                .collect();

            // Ensure minimum accounts
            let accounts = if unique_accounts.len() < MIN_ACCOUNTS {
                let mut result = unique_accounts;
                for i in 0u8..255 {
                    if result.len() >= MIN_ACCOUNTS {
                        break;
                    }
                    if !seen.contains(&i) {
                        result.push((i, 50_000_000));
                        seen.insert(i);
                    }
                }
                result
            } else {
                unique_accounts
            };

            GasInitialState { accounts }
        },
    )
}

/// Strategy to generate a gas-enabled v1 transfer given available account indices.
fn gas_transfer_v1_strategy(indices: Vec<u8>) -> impl Strategy<Value = GasTransferSpec> {
    let indices_clone = indices.clone();
    (
        prop::sample::select(indices),
        prop::sample::select(indices_clone),
        1u128..=MAX_TRANSFER_AMOUNT,
        50_000u64..=150_000u64,  // gas_limit range (above typical ~37k)
        0u128..=MAX_FEE_PER_GAS, // max_fee_per_gas
    )
        .prop_map(
            |(sender_idx, recipient_idx, amount, gas_limit, max_fee_per_gas)| GasTransferSpec {
                sender_idx,
                recipient_idx,
                amount,
                gas_limit,
                max_fee_per_gas,
                use_v1_payload: true,
            },
        )
}

/// Strategy to generate a gas-enabled v0 transfer (fee-free).
fn gas_transfer_v0_strategy(indices: Vec<u8>) -> impl Strategy<Value = GasTransferSpec> {
    let indices_clone = indices.clone();
    (
        prop::sample::select(indices),
        prop::sample::select(indices_clone),
        1u128..=MAX_TRANSFER_AMOUNT,
    )
        .prop_map(|(sender_idx, recipient_idx, amount)| GasTransferSpec {
            sender_idx,
            recipient_idx,
            amount,
            gas_limit: 50_000,  // default for v0
            max_fee_per_gas: 0, // v0 is fee-free
            use_v1_payload: false,
        })
}

/// Strategy to generate a sequence of gas-enabled transfers (mixed v0/v1).
fn gas_transfer_sequence_strategy(
    initial_state: &GasInitialState,
) -> impl Strategy<Value = Vec<GasTransferSpec>> {
    let indices = initial_state.account_indices();
    let indices_v0 = indices.clone();
    prop::collection::vec(
        any::<bool>().prop_flat_map(move |use_v1| {
            if use_v1 {
                gas_transfer_v1_strategy(indices.clone()).boxed()
            } else {
                gas_transfer_v0_strategy(indices_v0.clone()).boxed()
            }
        }),
        1..=MAX_TX_SEQUENCE_LEN,
    )
}

/// Combined strategy for initial state + gas transfer sequence.
fn gas_scenario_strategy() -> impl Strategy<Value = (GasInitialState, Vec<GasTransferSpec>)> {
    gas_initial_state_strategy().prop_flat_map(|initial_state| {
        let state_clone = initial_state.clone();
        gas_transfer_sequence_strategy(&initial_state)
            .prop_map(move |transfers| (state_clone.clone(), transfers))
    })
}

// ============================================================================
// Property G1: Non-negative balances and no overflow under gas-on
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GAS_PROPTEST_CASES))]

    /// G1: After executing any generated sequence with gas enabled:
    /// - All balances remain within u128 range (no underflow/panic)
    /// - Execution completes without panic
    #[test]
    fn prop_g1_no_negative_balances_with_gas((initial_state, transfers) in gas_scenario_strategy()) {
        let (_results, final_state, _fees) = execute_gas_transfers(&initial_state, &transfers);

        // If we got here without panic, no underflow occurred
        // Verify all accounts have valid state
        for (account, account_state) in final_state.iter() {
            // Balance should be >= 0 (implicit with u128)
            // Nonce should be reasonable
            prop_assert!(
                account_state.nonce <= transfers.len() as u64 * 2,
                "Account {:?} has unexpectedly high nonce: {}",
                account,
                account_state.nonce
            );
        }

        // Also verify all original accounts still exist with valid state
        for idx in initial_state.account_indices() {
            let account = test_account_id(idx);
            let state = final_state.get_account_state(&account);
            // Balance is always >= 0 with u128
            let _ = state.balance;
            let _ = state.nonce;
        }
    }
}

// ============================================================================
// Property G2: "Balance + burned fees" conservation
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GAS_PROPTEST_CASES))]

    /// G2: The sum of all balances before and after executing transfers
    /// plus the total burned fees must be equal.
    ///
    /// sum(initial_balances) == sum(final_balances) + total_burned_fees
    #[test]
    fn prop_g2_balance_plus_fees_conservation((initial_state, transfers) in gas_scenario_strategy()) {
        let initial_total = initial_state.total_balance();

        let (results, final_state, total_fees_burned) = execute_gas_transfers(&initial_state, &transfers);

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

        // Conservation: initial = final + fees burned
        let computed_total = final_total.saturating_add(total_fees_burned);

        prop_assert_eq!(
            initial_total,
            computed_total,
            "Balance + fees conservation failed. Initial: {}, Final: {}, Fees burned: {}, Computed: {}, Success count: {}",
            initial_total,
            final_total,
            total_fees_burned,
            computed_total,
            results.iter().filter(|r| r.success).count()
        );
    }
}

// ============================================================================
// Property G3: Nonce monotonicity with gas-on
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GAS_PROPTEST_CASES))]

    /// G3: For each account, the final nonce equals the number of successfully
    /// applied txs with that account as sender. Nonces only increase.
    #[test]
    fn prop_g3_nonce_monotonicity_with_gas((initial_state, transfers) in gas_scenario_strategy()) {
        let (results, final_state, _fees) = execute_gas_transfers(&initial_state, &transfers);

        // Track expected nonces (count successful txs per sender)
        let mut expected_nonces: HashMap<u8, u64> = HashMap::new();

        // Initialize expected nonces from initial state
        for idx in initial_state.account_indices() {
            expected_nonces.insert(idx, 0);
        }

        // Count successful transactions per sender
        let mut current_nonces: HashMap<u8, u64> = HashMap::new();
        for (i, spec) in transfers.iter().enumerate() {
            let _nonce = *current_nonces.get(&spec.sender_idx).unwrap_or(&0);
            current_nonces.insert(spec.sender_idx, _nonce + 1);

            // If this tx index is within results and succeeded, increment expected nonce
            if i < results.len() && results[i].success {
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
                "Account {} nonce mismatch with gas-on: expected {}, got {}",
                idx,
                expected_nonce,
                final_nonce
            );
        }
    }
}

// ============================================================================
// Property G4: Gas-charged only for successful execution
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GAS_PROPTEST_CASES))]

    /// G4: For any transaction that fails pre-execution:
    /// - Sender's balance and nonce remain unchanged
    /// - No burned fee is accounted for that tx
    #[test]
    fn prop_g4_failed_txs_no_fee_charge((initial_state, transfers) in gas_scenario_strategy()) {
        let mut state = initial_state.build();
        let engine = VmV0ExecutionEngine::with_gas_config(ExecutionGasConfig::enabled());

        // Track nonces for each sender
        let mut nonces: HashMap<u8, u64> = HashMap::new();

        // Execute transactions one by one and verify failed ones don't charge fees
        for spec in &transfers {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *nonces.get(&spec.sender_idx).unwrap_or(&0);
            nonces.insert(spec.sender_idx, nonce + 1);

            let payload = if spec.use_v1_payload {
                TransferPayloadV1::new(recipient, spec.amount, spec.gas_limit, spec.max_fee_per_gas)
                    .encode()
            } else {
                TransferPayload::new(recipient, spec.amount).encode()
            };

            let tx = QbindTransaction::new(sender, nonce, payload);

            // Capture state before execution
            let sender_state_before = state.get_account_state(&sender);

            // Execute single transaction
            let result = engine.execute_tx(&mut state, &tx);

            if !result.success {
                // Failed transactions should not change sender's state
                let sender_state_after = state.get_account_state(&sender);

                prop_assert_eq!(
                    sender_state_before.balance,
                    sender_state_after.balance,
                    "Failed tx changed sender balance from {} to {}",
                    sender_state_before.balance,
                    sender_state_after.balance
                );

                prop_assert_eq!(
                    sender_state_before.nonce,
                    sender_state_after.nonce,
                    "Failed tx changed sender nonce from {} to {}",
                    sender_state_before.nonce,
                    sender_state_after.nonce
                );

                // Failed transactions should have 0 fee paid
                prop_assert_eq!(
                    result.fee_paid,
                    0,
                    "Failed tx should have fee_paid = 0, got {}",
                    result.fee_paid
                );
            }
        }
    }
}

// ============================================================================
// Property G5: Block gas limit not exceeded
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GAS_PROPTEST_CASES))]

    /// G5: For a block-sized sequence with a configured block gas limit,
    /// the sum of gas for all executed transactions never exceeds the limit.
    #[test]
    fn prop_g5_block_gas_limit_respected((initial_state, transfers) in gas_scenario_strategy()) {
        // Use a smaller block gas limit to test the limit enforcement
        let block_gas_limit = TEST_BLOCK_GAS_LIMIT;

        let (results, _final_state, _fees) = execute_gas_transfers_with_limit(
            &initial_state,
            &transfers,
            block_gas_limit,
        );

        // Sum up gas used by successful transactions
        let total_gas_used: u64 = results.iter()
            .filter(|r| r.success)
            .map(|r| r.gas_used)
            .sum();

        prop_assert!(
            total_gas_used <= block_gas_limit,
            "Block gas limit exceeded: used {}, limit {}",
            total_gas_used,
            block_gas_limit
        );
    }
}

// ============================================================================
// Additional Gas Edge Case Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GAS_PROPTEST_CASES))]

    /// Edge case: Self-transfers with gas should preserve balance minus fees.
    #[test]
    fn prop_self_transfers_with_gas_fee_deduction(
        account_idx in 0u8..10,
        initial_balance in 50_000_000u128..=100_000_000u128,
        transfer_count in 1usize..=5,
        max_fee_per_gas in 1u128..=10u128,
    ) {
        let initial_state = GasInitialState {
            accounts: vec![(account_idx, initial_balance)],
        };

        // Create self-transfers with v1 payloads (to have non-zero fees)
        let transfers: Vec<GasTransferSpec> = (0..transfer_count)
            .map(|_| GasTransferSpec {
                sender_idx: account_idx,
                recipient_idx: account_idx,
                amount: 0, // Zero amount self-transfer
                gas_limit: 50_000,
                max_fee_per_gas,
                use_v1_payload: true,
            })
            .collect();

        let (results, final_state, total_fees_burned) = execute_gas_transfers(&initial_state, &transfers);

        let account = test_account_id(account_idx);
        let final_account = final_state.get_account_state(&account);

        // Conservation: initial balance = final balance + fees burned
        let success_count = results.iter().filter(|r| r.success).count();

        prop_assert_eq!(
            initial_balance,
            final_account.balance.saturating_add(total_fees_burned),
            "Self-transfer balance + fees should equal initial. Initial: {}, Final: {}, Fees: {}, Successes: {}",
            initial_balance,
            final_account.balance,
            total_fees_burned,
            success_count
        );
    }

    /// Edge case: Transactions with too-low gas_limit should fail.
    #[test]
    fn prop_too_low_gas_limit_rejected(
        sender_idx in 0u8..10,
        recipient_idx in 10u8..20,
        initial_balance in 50_000_000u128..=100_000_000u128,
        amount in 100u128..=1000u128,
    ) {
        let initial_state = GasInitialState {
            accounts: vec![(sender_idx, initial_balance), (recipient_idx, 0)],
        };

        // Create a transfer with artificially low gas_limit (below typical ~38k for v1)
        let transfers = vec![GasTransferSpec {
            sender_idx,
            recipient_idx,
            amount,
            gas_limit: 10_000, // Way too low for v1 transfer (~48k)
            max_fee_per_gas: 10,
            use_v1_payload: true,
        }];

        let (results, final_state, total_fees_burned) = execute_gas_transfers(&initial_state, &transfers);

        // Should fail with GasLimitExceeded
        prop_assert!(!results[0].success, "Too-low gas_limit transfer should fail");

        // Sender state should be unchanged
        let sender = test_account_id(sender_idx);
        let sender_final = final_state.get_account_state(&sender);
        prop_assert_eq!(
            sender_final.balance,
            initial_balance,
            "Sender balance should be unchanged after gas limit rejection"
        );
        prop_assert_eq!(
            sender_final.nonce,
            0,
            "Sender nonce should be unchanged after gas limit rejection"
        );

        // No fees should be burned
        prop_assert_eq!(total_fees_burned, 0, "No fees should be burned for failed tx");
    }

    /// Edge case: v0 payloads (fee-free) should work correctly with gas enabled.
    #[test]
    fn prop_v0_payload_fee_free_with_gas_enabled(
        sender_idx in 0u8..10,
        recipient_idx in 10u8..20,
        initial_balance in 10_000_000u128..=50_000_000u128,
        amount in 1000u128..=100_000u128,
    ) {
        let initial_state = GasInitialState {
            accounts: vec![(sender_idx, initial_balance), (recipient_idx, 0)],
        };

        // Use v0 payload (no explicit gas fields, fee-free)
        let transfers = vec![GasTransferSpec {
            sender_idx,
            recipient_idx,
            amount,
            gas_limit: 50_000, // Ignored for v0
            max_fee_per_gas: 0, // v0 is always fee-free
            use_v1_payload: false,
        }];

        let (results, final_state, total_fees_burned) = execute_gas_transfers(&initial_state, &transfers);

        // Should succeed
        prop_assert!(results[0].success, "v0 payload transfer should succeed");

        // No fees should be burned (v0 is fee-free)
        prop_assert_eq!(total_fees_burned, 0, "v0 payload should have zero fees");

        // Verify balances
        let sender = test_account_id(sender_idx);
        let recipient = test_account_id(recipient_idx);
        let sender_final = final_state.get_account_state(&sender);
        let recipient_final = final_state.get_account_state(&recipient);

        prop_assert_eq!(
            sender_final.balance,
            initial_balance - amount,
            "Sender balance should decrease by amount only (no fee)"
        );
        prop_assert_eq!(
            recipient_final.balance,
            amount,
            "Recipient should receive exact amount"
        );
    }
}

// ============================================================================
// Unit Tests (Non-Property Based)
// ============================================================================

#[test]
fn test_basic_gas_transfer_with_fee() {
    let initial_state = GasInitialState {
        accounts: vec![(0, 10_000_000), (1, 0)],
    };

    let transfers = vec![GasTransferSpec {
        sender_idx: 0,
        recipient_idx: 1,
        amount: 1000,
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        use_v1_payload: true,
    }];

    let (results, final_state, total_fees_burned) =
        execute_gas_transfers(&initial_state, &transfers);

    assert!(results[0].success, "Transfer should succeed");
    assert!(results[0].gas_used > 0, "Gas should be used");
    assert!(results[0].fee_paid > 0, "Fee should be paid");

    // Verify fee calculation: fee = gas_used * max_fee_per_gas
    let expected_fee = (results[0].gas_used as u128) * 10;
    assert_eq!(results[0].fee_paid, expected_fee);
    assert_eq!(total_fees_burned, expected_fee);

    // Verify sender balance: initial - amount - fee
    let sender = test_account_id(0);
    let sender_final = final_state.get_account_state(&sender);
    assert_eq!(sender_final.balance, 10_000_000 - 1000 - expected_fee);
    assert_eq!(sender_final.nonce, 1);

    // Verify recipient received exact amount
    let recipient = test_account_id(1);
    let recipient_final = final_state.get_account_state(&recipient);
    assert_eq!(recipient_final.balance, 1000);
}

#[test]
fn test_insufficient_balance_for_fee_rejected() {
    let initial_state = GasInitialState {
        accounts: vec![(0, 1000), (1, 0)], // Only 1000 balance
    };

    // Try to transfer with high fee that exceeds balance
    let transfers = vec![GasTransferSpec {
        sender_idx: 0,
        recipient_idx: 1,
        amount: 100,
        gas_limit: 100_000,
        max_fee_per_gas: 100, // Fee would be ~4.8M, way more than balance
        use_v1_payload: true,
    }];

    let (results, final_state, total_fees_burned) =
        execute_gas_transfers(&initial_state, &transfers);

    assert!(
        !results[0].success,
        "Transfer should fail due to insufficient balance for fee"
    );
    assert_eq!(total_fees_burned, 0, "No fees should be burned");

    // Sender state should be unchanged
    let sender = test_account_id(0);
    let sender_final = final_state.get_account_state(&sender);
    assert_eq!(sender_final.balance, 1000);
    assert_eq!(sender_final.nonce, 0);
}

#[test]
fn test_block_gas_limit_stops_execution() {
    let initial_state = GasInitialState {
        accounts: vec![(0, 100_000_000)],
    };

    // Create many transfers that would exceed the small block limit
    // Each v1 transfer costs ~48k gas, so with 100k limit, at most 2 should fit
    let _recipient = test_account_id(1);
    let transfers: Vec<GasTransferSpec> = (0..10)
        .map(|_| GasTransferSpec {
            sender_idx: 0,
            recipient_idx: 1,
            amount: 100,
            gas_limit: 100_000,
            max_fee_per_gas: 1,
            use_v1_payload: true,
        })
        .collect();

    let block_gas_limit = 100_000;
    let (results, _final_state, _fees) =
        execute_gas_transfers_with_limit(&initial_state, &transfers, block_gas_limit);

    // Should have fewer results than transfers (block limit reached)
    assert!(
        results.len() <= 3,
        "Block should stop before exceeding gas limit, got {} results",
        results.len()
    );

    // Total gas used should be <= block limit
    let total_gas: u64 = results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.gas_used)
        .sum();
    assert!(
        total_gas <= block_gas_limit,
        "Total gas {} exceeds limit {}",
        total_gas,
        block_gas_limit
    );
}

#[test]
fn test_balance_fee_conservation_exact() {
    let initial_balance: u128 = 100_000_000;
    let initial_state = GasInitialState {
        accounts: vec![(0, initial_balance), (1, 0)],
    };

    let amount: u128 = 50_000;
    let transfers = vec![GasTransferSpec {
        sender_idx: 0,
        recipient_idx: 1,
        amount,
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        use_v1_payload: true,
    }];

    let (results, final_state, total_fees_burned) =
        execute_gas_transfers(&initial_state, &transfers);

    assert!(results[0].success);

    let sender = test_account_id(0);
    let recipient = test_account_id(1);
    let sender_final = final_state.get_account_state(&sender);
    let recipient_final = final_state.get_account_state(&recipient);

    // Conservation: initial = sender_final + recipient_final + fees
    let final_total = sender_final.balance + recipient_final.balance + total_fees_burned;
    assert_eq!(
        initial_balance, final_total,
        "Balance conservation failed: {} != {}",
        initial_balance, final_total
    );
}

#[test]
fn test_determinism_with_gas() {
    let initial_state = GasInitialState {
        accounts: vec![(0, 100_000_000), (1, 50_000_000)],
    };

    let transfers = vec![
        GasTransferSpec {
            sender_idx: 0,
            recipient_idx: 1,
            amount: 10_000,
            gas_limit: 100_000,
            max_fee_per_gas: 5,
            use_v1_payload: true,
        },
        GasTransferSpec {
            sender_idx: 1,
            recipient_idx: 0,
            amount: 5_000,
            gas_limit: 100_000,
            max_fee_per_gas: 3,
            use_v1_payload: true,
        },
    ];

    // Execute twice
    let (results1, state1, fees1) = execute_gas_transfers(&initial_state, &transfers);
    let (results2, state2, fees2) = execute_gas_transfers(&initial_state, &transfers);

    // Results should be identical
    assert_eq!(results1.len(), results2.len());
    for (r1, r2) in results1.iter().zip(results2.iter()) {
        assert_eq!(r1.success, r2.success);
        assert_eq!(r1.gas_used, r2.gas_used);
        assert_eq!(r1.fee_paid, r2.fee_paid);
    }

    // Fees should be identical
    assert_eq!(fees1, fees2);

    // States should be identical
    for idx in [0u8, 1u8] {
        let account = test_account_id(idx);
        let s1 = state1.get_account_state(&account);
        let s2 = state2.get_account_state(&account);
        assert_eq!(
            s1.balance, s2.balance,
            "Balance mismatch for account {}",
            idx
        );
        assert_eq!(s1.nonce, s2.nonce, "Nonce mismatch for account {}", idx);
    }
}