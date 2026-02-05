//! T201: Seigniorage Application & Routing Tests
//!
//! This module contains comprehensive tests for T201 seigniorage application
//! and routing at epoch boundaries.
//!
//! # Test Coverage
//!
//! - **Conservation**: Epoch issuance equals sum of all splits
//! - **Validator Rewards Conservation**: Sum of validator rewards equals validators slice
//! - **Zero Stake/Issuance**: No panics, zero outputs
//! - **Mode Semantics**: Off/Shadow/Active mode behaviors
//! - **MainNet Split**: 82/12/4/2 configuration

use qbind_ledger::{
    compute_epoch_seigniorage, compute_epoch_state, process_epoch_seigniorage, MonetaryAccounts,
    MonetaryEngineConfig, MonetaryEpochInputs, MonetaryEpochState, MonetaryMode, MonetaryPhase,
    PhaseParameters, SeigniorageAccounting, SeigniorageApplicationResult, SeigniorageSplit,
    SeigniorageStateMutator, ValidatorStake, SEIGNIORAGE_SPLIT_MAINNET_T201,
};
use std::collections::HashMap;

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns a default configuration for testing.
fn test_config() -> MonetaryEngineConfig {
    MonetaryEngineConfig {
        pqc_premium_compute: 0.30,
        pqc_premium_bandwidth: 0.15,
        pqc_premium_storage: 0.10,
        bootstrap: PhaseParameters {
            r_target_annual: 0.05,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12,
            ema_lambda_bps: 700,
            max_delta_r_inf_per_epoch_bps: 25, // T203: 0.25% max change per epoch
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10,
            ema_lambda_bps: 300,
            max_delta_r_inf_per_epoch_bps: 10, // T203: 0.10% max change per epoch
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,
            inflation_floor_annual: 0.01,
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08,
            ema_lambda_bps: 150,
            max_delta_r_inf_per_epoch_bps: 5, // T203: 0.05% max change per epoch
        },
        alpha_fee_offset: 1.0,
    }
}

/// Returns the MainNet default seigniorage split (82/12/4/2).
fn mainnet_split() -> SeigniorageSplit {
    SEIGNIORAGE_SPLIT_MAINNET_T201
}

/// Returns a test epoch state with the given staked supply and inflation rate.
fn test_epoch_state(
    epoch_index: u64,
    staked_supply: u128,
    r_inf_annual: f64,
) -> MonetaryEpochState {
    let mut state = MonetaryEpochState::default();
    state.epoch_index = epoch_index;
    state.staked_supply = staked_supply;
    state.decision.recommended_r_inf_annual = r_inf_annual;
    state
}

/// Creates validator stakes with equal distribution.
fn equal_validator_stakes(count: usize, total_stake: u128) -> Vec<ValidatorStake> {
    let per_validator = total_stake / count as u128;
    let remainder = total_stake % count as u128;

    let mut stakes = Vec::with_capacity(count);
    for i in 0..count {
        let stake = if i == count - 1 {
            per_validator + remainder
        } else {
            per_validator
        };
        stakes.push(ValidatorStake {
            validator_id: i as u64 + 1,
            stake,
        });
    }
    stakes
}

/// Simple in-memory state mutator for testing.
struct TestStateMutator {
    balances: HashMap<[u8; 32], u128>,
}

impl TestStateMutator {
    fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    fn get_balance(&self, account: &[u8; 32]) -> u128 {
        *self.balances.get(account).unwrap_or(&0)
    }

    fn total_supply(&self) -> u128 {
        self.balances.values().sum()
    }
}

impl SeigniorageStateMutator for TestStateMutator {
    fn credit_account(&mut self, account: &[u8; 32], amount: u128) -> bool {
        let balance = self.balances.entry(*account).or_insert(0);
        *balance = balance.saturating_add(amount);
        true
    }
}

/// Simple validator account lookup for testing.
fn test_validator_account(validator_id: u64) -> [u8; 32] {
    let mut account = [0u8; 32];
    account[0..8].copy_from_slice(&validator_id.to_be_bytes());
    account[8] = 0xFF; // Marker to distinguish from monetary accounts
    account
}

// ============================================================================
// Test 1: Epoch Issuance Conservation
// ============================================================================

/// Test: Total epoch issuance equals sum of all seigniorage splits.
#[test]
fn test_epoch_issuance_conservation() {
    let split = mainnet_split();
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775); // 7.75% inflation
    let stakes = equal_validator_stakes(4, 1_000_000_000);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    // Verify conservation
    assert!(result.is_conserved(), "Issuance should equal sum of splits");
    assert_eq!(
        result.accounting.total_issuance, result.total_issuance,
        "Accounting total should match result total"
    );

    // Verify split conservation explicitly
    let sum = result
        .accounting
        .to_validators
        .saturating_add(result.accounting.to_treasury)
        .saturating_add(result.accounting.to_insurance)
        .saturating_add(result.accounting.to_community);
    assert_eq!(
        sum, result.total_issuance,
        "Sum of splits {} should equal total issuance {}",
        sum, result.total_issuance
    );
}

/// Test: Conservation holds for various issuance amounts.
#[test]
fn test_epoch_issuance_conservation_various_amounts() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(10, 1_000_000);

    let test_amounts = [0.0, 0.01, 0.05, 0.0775, 0.10, 0.12];

    for &r_inf in &test_amounts {
        let epoch_state = test_epoch_state(0, 1_000_000, r_inf);
        let result =
            compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

        assert!(
            result.is_conserved(),
            "Conservation failed for r_inf={}",
            r_inf
        );
    }
}

// ============================================================================
// Test 2: Validator Rewards Conservation
// ============================================================================

/// Test: Sum of validator rewards equals validators slice.
#[test]
fn test_validator_rewards_conservation() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 10_000_000);
    let epoch_state = test_epoch_state(100, 10_000_000, 0.0775);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    assert!(
        result.validator_rewards_conserved(),
        "Validator rewards should be conserved"
    );

    // Verify explicitly
    if let Some(ref dist) = result.validator_distribution {
        let reward_sum: u128 = dist.rewards.iter().map(|r| r.reward).sum();
        assert_eq!(
            reward_sum, result.accounting.to_validators,
            "Sum of validator rewards {} should equal validators slice {}",
            reward_sum, result.accounting.to_validators
        );
    }
}

/// Test: Validator rewards conservation with unequal stakes.
#[test]
fn test_validator_rewards_conservation_unequal_stakes() {
    let split = mainnet_split();
    let stakes = vec![
        ValidatorStake {
            validator_id: 1,
            stake: 1_000_000,
        },
        ValidatorStake {
            validator_id: 2,
            stake: 2_000_000,
        },
        ValidatorStake {
            validator_id: 3,
            stake: 3_000_000,
        },
        ValidatorStake {
            validator_id: 4,
            stake: 4_000_000,
        },
    ];
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();
    let epoch_state = test_epoch_state(100, total_stake, 0.0775);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    assert!(result.is_conserved());
    assert!(result.validator_rewards_conserved());

    // Verify proportional distribution
    if let Some(ref dist) = result.validator_distribution {
        // Validator 4 has 40% of stake, should get ~40% of rewards
        let v4_reward = dist.rewards[3].reward;
        let v1_reward = dist.rewards[0].reward;

        // V4 (40%) should have ~4x the reward of V1 (10%)
        assert!(
            v4_reward >= v1_reward * 3,
            "V4 ({}) should have ~4x reward of V1 ({})",
            v4_reward,
            v1_reward
        );
    }
}

// ============================================================================
// Test 3: Zero Stake or Zero Issuance Behavior
// ============================================================================

/// Test: Zero stake produces zero issuance without panics.
#[test]
fn test_zero_stake_or_zero_issuance_behavior_zero_stake() {
    let split = mainnet_split();
    let stakes: Vec<ValidatorStake> = vec![];
    let epoch_state = test_epoch_state(100, 0, 0.0775);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    // Should not panic, should produce zero issuance
    assert_eq!(result.total_issuance, 0);
    assert!(result.is_conserved());
    assert!(result.validator_rewards_conserved());
}

/// Test: Zero inflation rate produces zero issuance.
#[test]
fn test_zero_stake_or_zero_issuance_behavior_zero_inflation() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000, 0.0); // 0% inflation

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    assert_eq!(result.total_issuance, 0);
    assert!(result.is_conserved());
    assert!(result.validator_rewards_conserved());
}

/// Test: Zero epochs per year produces zero issuance.
#[test]
fn test_zero_stake_or_zero_issuance_behavior_zero_epochs() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000, 0.0775);

    // Use 0 epochs per year (edge case)
    let result = compute_epoch_seigniorage(&epoch_state, 0, &split, &stakes, MonetaryMode::Shadow);

    assert_eq!(result.total_issuance, 0);
    assert!(result.is_conserved());
}

/// Test: Empty validator set with non-zero stake.
#[test]
fn test_zero_stake_or_zero_issuance_behavior_empty_validators() {
    let split = mainnet_split();
    let stakes: Vec<ValidatorStake> = vec![];
    let epoch_state = test_epoch_state(100, 1_000_000, 0.0775);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    // Should still compute issuance (for treasury/insurance/community)
    // but validators portion won't have distribution
    assert!(result.total_issuance > 0);
    assert!(result.is_conserved());

    // Validator distribution should be present but empty
    assert!(result.validator_distribution.is_some());
    if let Some(ref dist) = result.validator_distribution {
        assert!(dist.rewards.is_empty());
    }
}

// ============================================================================
// Test 4: MonetaryMode::Off Does Nothing
// ============================================================================

/// Test: Off mode returns immediately with no computations.
#[test]
fn test_monetary_mode_off_does_nothing() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);

    let result = compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Off);

    // Off mode should produce zero issuance and no computations
    assert_eq!(result.mode, MonetaryMode::Off);
    assert_eq!(result.total_issuance, 0);
    assert_eq!(result.accounting.total_issuance, 0);
    assert_eq!(result.accounting.to_validators, 0);
    assert_eq!(result.accounting.to_treasury, 0);
    assert_eq!(result.accounting.to_insurance, 0);
    assert_eq!(result.accounting.to_community, 0);
    assert!(result.validator_distribution.is_none());
    assert!(!result.balances_updated);
}

/// Test: process_epoch_seigniorage with Off mode returns immediately.
#[test]
fn test_monetary_mode_off_process_returns_early() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);
    let accounts = MonetaryAccounts::test_accounts();
    let mut state = TestStateMutator::new();

    let result = process_epoch_seigniorage(
        &epoch_state,
        100,
        &split,
        &stakes,
        MonetaryMode::Off,
        Some(&accounts),
        test_validator_account,
        Some(&mut state),
    );

    // Should not update state even though accounts and state are provided
    assert_eq!(result.mode, MonetaryMode::Off);
    assert_eq!(result.total_issuance, 0);
    assert!(!result.balances_updated);
    assert_eq!(state.total_supply(), 0);
}

// ============================================================================
// Test 5: MonetaryMode::Shadow Updates Metrics Only
// ============================================================================

/// Test: Shadow mode computes values but doesn't update balances.
#[test]
fn test_monetary_mode_shadow_updates_metrics_only() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);
    let accounts = MonetaryAccounts::test_accounts();
    let mut state = TestStateMutator::new();

    let result = process_epoch_seigniorage(
        &epoch_state,
        100,
        &split,
        &stakes,
        MonetaryMode::Shadow,
        Some(&accounts),
        test_validator_account,
        Some(&mut state),
    );

    // Shadow mode should compute values
    assert_eq!(result.mode, MonetaryMode::Shadow);
    assert!(
        result.total_issuance > 0,
        "Should compute positive issuance"
    );
    assert!(result.is_conserved());
    assert!(result.validator_rewards_conserved());

    // But should NOT update balances
    assert!(!result.balances_updated);
    assert_eq!(state.total_supply(), 0, "State should remain unchanged");
}

/// Test: Shadow mode with no state mutator still computes correctly.
#[test]
fn test_monetary_mode_shadow_without_state() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);

    let result = process_epoch_seigniorage::<_, TestStateMutator>(
        &epoch_state,
        100,
        &split,
        &stakes,
        MonetaryMode::Shadow,
        None,
        test_validator_account,
        None,
    );

    // Should still compute values
    assert_eq!(result.mode, MonetaryMode::Shadow);
    assert!(result.total_issuance > 0);
    assert!(result.is_conserved());
    assert!(!result.balances_updated);
}

// ============================================================================
// Test 6: MonetaryMode::Active Updates Balances
// ============================================================================

/// Test: Active mode computes values AND updates balances.
#[test]
fn test_monetary_mode_active_updates_balances() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);
    let accounts = MonetaryAccounts::test_accounts();
    let mut state = TestStateMutator::new();

    let result = process_epoch_seigniorage(
        &epoch_state,
        100,
        &split,
        &stakes,
        MonetaryMode::Active,
        Some(&accounts),
        test_validator_account,
        Some(&mut state),
    );

    // Active mode should compute values
    assert_eq!(result.mode, MonetaryMode::Active);
    assert!(result.total_issuance > 0);
    assert!(result.is_conserved());
    assert!(result.validator_rewards_conserved());

    // AND update balances
    assert!(result.balances_updated, "Balances should be updated");

    // Verify state was actually modified
    let total_credited = state.total_supply();
    assert_eq!(
        total_credited, result.total_issuance,
        "Total credited {} should equal total issuance {}",
        total_credited, result.total_issuance
    );

    // Verify individual account balances
    assert_eq!(
        state.get_balance(&accounts.treasury),
        result.accounting.to_treasury
    );
    assert_eq!(
        state.get_balance(&accounts.insurance),
        result.accounting.to_insurance
    );
    assert_eq!(
        state.get_balance(&accounts.community),
        result.accounting.to_community
    );

    // Verify validator account balances
    if let Some(ref dist) = result.validator_distribution {
        for reward in &dist.rewards {
            let account = test_validator_account(reward.validator_id);
            assert_eq!(
                state.get_balance(&account),
                reward.reward,
                "Validator {} balance mismatch",
                reward.validator_id
            );
        }
    }
}

/// Test: Active mode without accounts does not update balances.
#[test]
fn test_monetary_mode_active_without_accounts() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);
    let mut state = TestStateMutator::new();

    let result = process_epoch_seigniorage(
        &epoch_state,
        100,
        &split,
        &stakes,
        MonetaryMode::Active,
        None, // No accounts provided
        test_validator_account,
        Some(&mut state),
    );

    // Should compute values but NOT update balances
    assert_eq!(result.mode, MonetaryMode::Active);
    assert!(result.total_issuance > 0);
    assert!(
        !result.balances_updated,
        "Should not update without accounts"
    );
    assert_eq!(state.total_supply(), 0);
}

/// Test: Active mode without state mutator does not update balances.
#[test]
fn test_monetary_mode_active_without_state() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);
    let accounts = MonetaryAccounts::test_accounts();

    let result = process_epoch_seigniorage::<_, TestStateMutator>(
        &epoch_state,
        100,
        &split,
        &stakes,
        MonetaryMode::Active,
        Some(&accounts),
        test_validator_account,
        None, // No state mutator provided
    );

    // Should compute values but NOT update balances
    assert_eq!(result.mode, MonetaryMode::Active);
    assert!(result.total_issuance > 0);
    assert!(
        !result.balances_updated,
        "Should not update without state mutator"
    );
}

// ============================================================================
// Test 7: MainNet Default Split (82/12/4/2)
// ============================================================================

/// Test: MainNet default split is valid and sums to 100%.
#[test]
fn test_mainnet_split_valid() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_T201;

    assert_eq!(split.validators_bps, 8200, "Validators should be 82%");
    assert_eq!(split.treasury_bps, 1200, "Treasury should be 12%");
    assert_eq!(split.insurance_bps, 400, "Insurance should be 4%");
    assert_eq!(split.community_bps, 200, "Community should be 2%");

    assert!(split.is_valid(), "Split should sum to 10000 bps");
    assert_eq!(split.sum(), 10_000);
}

/// Test: MainNet split produces correct percentages.
#[test]
fn test_mainnet_split_percentages() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_T201;
    let epoch_state = test_epoch_state(100, 10_000_000, 0.0775);
    let stakes = equal_validator_stakes(4, 10_000_000);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    // Verify percentages (allow for rounding)
    let total = result.total_issuance as f64;
    if total > 0.0 {
        let validators_pct = (result.accounting.to_validators as f64 / total) * 100.0;
        let treasury_pct = (result.accounting.to_treasury as f64 / total) * 100.0;
        let insurance_pct = (result.accounting.to_insurance as f64 / total) * 100.0;
        let community_pct = (result.accounting.to_community as f64 / total) * 100.0;

        // Allow 0.5% tolerance for rounding
        assert!(
            (validators_pct - 82.0).abs() < 0.5,
            "Validators should be ~82%, got {}%",
            validators_pct
        );
        assert!(
            (treasury_pct - 12.0).abs() < 0.5,
            "Treasury should be ~12%, got {}%",
            treasury_pct
        );
        assert!(
            (insurance_pct - 4.0).abs() < 0.5,
            "Insurance should be ~4%, got {}%",
            insurance_pct
        );
        assert!(
            (community_pct - 2.0).abs() < 0.5,
            "Community should be ~2%, got {}%",
            community_pct
        );
    }
}

// ============================================================================
// Test 8: Integration with T199 compute_epoch_state
// ============================================================================

/// Test: Full pipeline from MonetaryEpochInputs through to seigniorage application.
#[test]
fn test_full_pipeline_integration() {
    let config = test_config();
    let split = mainnet_split();

    // Create realistic inputs
    let stakes = vec![
        ValidatorStake {
            validator_id: 1,
            stake: 1_000_000,
        },
        ValidatorStake {
            validator_id: 2,
            stake: 2_000_000,
        },
        ValidatorStake {
            validator_id: 3,
            stake: 3_000_000,
        },
        ValidatorStake {
            validator_id: 4,
            stake: 4_000_000,
        },
    ];
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

    // Step 1: Compute epoch state (T199)
    let inputs = MonetaryEpochInputs {
        epoch_index: 100,
        raw_epoch_fees: 1000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: total_stake,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.6,
        days_since_launch: 365,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None, // T203: No previous rate
    };

    let epoch_state = compute_epoch_state(&config, &inputs);

    // Step 2: Compute seigniorage (T201)
    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    // Verify end-to-end correctness
    assert!(result.total_issuance > 0, "Should have positive issuance");
    assert!(result.is_conserved(), "Should conserve issuance");
    assert!(
        result.validator_rewards_conserved(),
        "Should conserve validator rewards"
    );

    // Verify stake invariant
    if let Some(ref dist) = result.validator_distribution {
        assert!(dist.stake_invariant_ok(), "Stake invariant should hold");
    }
}

// ============================================================================
// Test 9: Determinism
// ============================================================================

/// Test: Same inputs always produce same outputs.
#[test]
fn test_seigniorage_determinism() {
    let split = mainnet_split();
    let stakes = equal_validator_stakes(4, 1_000_000_000);
    let epoch_state = test_epoch_state(100, 1_000_000_000, 0.0775);

    // Compute multiple times
    let results: Vec<_> = (0..5)
        .map(|_| {
            compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow)
        })
        .collect();

    // All should be identical
    for (i, result) in results.iter().enumerate().skip(1) {
        assert_eq!(
            result.total_issuance, results[0].total_issuance,
            "Run {} differs in total_issuance",
            i
        );
        assert_eq!(
            result.accounting, results[0].accounting,
            "Run {} differs in accounting",
            i
        );
        assert_eq!(
            result.validator_distribution, results[0].validator_distribution,
            "Run {} differs in validator_distribution",
            i
        );
    }
}

// ============================================================================
// Test 10: Large Values
// ============================================================================

/// Test: Works correctly with large stake values (trillion tokens).
#[test]
fn test_large_values() {
    let split = mainnet_split();
    let large_stake: u128 = 1_000_000_000_000; // 1 trillion tokens
    let stakes = equal_validator_stakes(100, large_stake);
    let epoch_state = test_epoch_state(100, large_stake, 0.0775);

    let result =
        compute_epoch_seigniorage(&epoch_state, 100, &split, &stakes, MonetaryMode::Shadow);

    assert!(result.total_issuance > 0);
    assert!(result.is_conserved());
    assert!(result.validator_rewards_conserved());

    // Verify no overflow occurred
    if let Some(ref dist) = result.validator_distribution {
        assert_eq!(dist.rewards.len(), 100);
        for reward in &dist.rewards {
            assert!(reward.reward > 0, "All validators should receive rewards");
        }
    }
}

// ============================================================================
// Test 11: SeigniorageApplicationResult Methods
// ============================================================================

/// Test: off_mode() creates correct result.
#[test]
fn test_seigniorage_application_result_off_mode() {
    let result = SeigniorageApplicationResult::off_mode(42);

    assert_eq!(result.epoch_index, 42);
    assert_eq!(result.mode, MonetaryMode::Off);
    assert_eq!(result.total_issuance, 0);
    assert!(result.validator_distribution.is_none());
    assert!(!result.balances_updated);
}

/// Test: is_conserved() returns correct values.
#[test]
fn test_seigniorage_application_result_is_conserved() {
    // Create a balanced accounting
    let accounting = SeigniorageAccounting {
        total_issuance: 100,
        to_validators: 82,
        to_treasury: 12,
        to_insurance: 4,
        to_community: 2,
    };

    let result = SeigniorageApplicationResult::computed(
        0,
        100,
        accounting,
        None,
        false,
        MonetaryMode::Shadow,
    );

    assert!(result.is_conserved());

    // Create an unbalanced accounting (shouldn't happen in practice)
    let bad_accounting = SeigniorageAccounting {
        total_issuance: 100,
        to_validators: 50,
        to_treasury: 20,
        to_insurance: 10,
        to_community: 10, // Sum = 90, not 100
    };

    let bad_result = SeigniorageApplicationResult::computed(
        0,
        100,
        bad_accounting,
        None,
        false,
        MonetaryMode::Shadow,
    );

    assert!(!bad_result.is_conserved());
}
