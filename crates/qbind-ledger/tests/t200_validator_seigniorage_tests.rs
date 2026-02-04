//! T200: Validator Seigniorage Distribution Tests
//!
//! Tests for the epoch issuance computation and validator reward distribution logic.
//!
//! # Test Coverage
//!
//! - **Epoch Issuance**: Correct computation from MonetaryEpochState
//! - **Validator Rewards**: Stake-proportional distribution with conservation
//! - **Determinism**: Same inputs always produce same outputs
//! - **Rounding**: Remainder is assigned to last validator, no over-mint
//! - **Edge Cases**: Zero values, large values, stake mismatch

use qbind_ledger::{
    compute_epoch_issuance, compute_epoch_state, compute_seigniorage_split, compute_validator_rewards,
    MonetaryEngineConfig, MonetaryEpochInputs, MonetaryEpochState, MonetaryPhase, PhaseParameters,
    SeigniorageSplit, ValidatorReward, ValidatorStake, MAINNET_EPOCHS_PER_YEAR,
};

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
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10,
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,
            inflation_floor_annual: 0.01,
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08,
        },
        alpha_fee_offset: 1.0,
    }
}

/// MainNet default seigniorage split: ~82/12/4/2 (validators/treasury/insurance/community).
fn mainnet_seigniorage_split() -> SeigniorageSplit {
    SeigniorageSplit::new(8_200, 1_200, 400, 200)
}

// ============================================================================
// Test 1: Full T200 Pipeline Integration
// ============================================================================

/// Test: Full pipeline from MonetaryEpochInputs → issuance → seigniorage split → validator rewards.
///
/// This test verifies the complete T200 flow:
/// 1. Compute MonetaryEpochState from inputs (T199)
/// 2. Compute epoch issuance from state (T200)
/// 3. Split issuance among validators/treasury/insurance/community (T197)
/// 4. Distribute validator slice to individual validators (T200)
#[test]
fn test_full_t200_pipeline() {
    let config = test_config();
    let split = mainnet_seigniorage_split();

    // Create validator stakes
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 1_000_000 },
        ValidatorStake { validator_id: 2, stake: 2_000_000 },
        ValidatorStake { validator_id: 3, stake: 3_000_000 },
        ValidatorStake { validator_id: 4, stake: 4_000_000 },
    ];
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum(); // 10M

    // Step 1: Compute epoch state
    let inputs = MonetaryEpochInputs {
        epoch_index: 100,
        raw_epoch_fees: 1000, // Low fees
        previous_smoothed_annual_fee_revenue: 0,
        staked_supply: total_stake,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.6,
        days_since_launch: 365,
        fee_volatility: 1.0,
        epochs_per_year: 100, // Simple epochs for testing
    };

    let epoch_state = compute_epoch_state(&config, &inputs);

    // Step 2: Compute epoch issuance
    let issuance = compute_epoch_issuance(&epoch_state, inputs.epochs_per_year);
    assert!(issuance > 0, "Should have positive issuance");

    // Step 3: Split issuance
    let accounting = compute_seigniorage_split(issuance, &split);
    assert!(accounting.is_balanced());

    // Verify split percentages (82% to validators)
    let validators_share = accounting.to_validators;
    assert!(validators_share > 0);
    // Should be approximately 82% of issuance
    let expected_validators_share = (issuance * 8200) / 10000;
    assert!(
        validators_share >= expected_validators_share - 1 && validators_share <= expected_validators_share + 1,
        "Validators share {} should be ~{} (82%)",
        validators_share, expected_validators_share
    );

    // Step 4: Distribute to validators
    let distribution = compute_validator_rewards(validators_share, &stakes, total_stake).unwrap();

    assert!(distribution.is_balanced());
    assert!(distribution.stake_invariant_ok());
    assert_eq!(distribution.rewards.len(), 4);

    // Verify proportional distribution:
    // Validator 1 has 10% of stake → should get ~10% of rewards
    // Validator 4 has 40% of stake → should get ~40% of rewards
    let v1_reward = distribution.rewards[0].reward;
    let v4_reward = distribution.rewards[3].reward;

    // Allow small rounding error
    assert!(
        v4_reward >= v1_reward * 3,
        "Validator 4 (40%) should have ~4x reward of Validator 1 (10%)"
    );
}

// ============================================================================
// Test 2: Epoch Issuance Computation
// ============================================================================

/// Test: Epoch issuance formula matches the design doc.
#[test]
fn test_epoch_issuance_formula() {
    // issuance_epoch = r_inf × S_t / epochs_per_year
    // Using bps: issuance = (S_t × r_inf_bps) / (epochs_per_year × 10000)

    let mut state = MonetaryEpochState::default();
    state.staked_supply = 100_000_000_000; // 100B tokens
    state.decision.recommended_r_inf_annual = 0.10; // 10% = 1000 bps

    // With 100 epochs/year:
    // issuance = (100B * 1000) / (100 * 10000) = 1e14 / 1e6 = 100,000,000
    let issuance = compute_epoch_issuance(&state, 100);
    assert_eq!(issuance, 100_000_000);

    // With MAINNET_EPOCHS_PER_YEAR (52560):
    // issuance = (100B * 1000) / (52560 * 10000) = 1e14 / 5.256e8 ≈ 190,258
    let issuance_mainnet = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);
    assert_eq!(issuance_mainnet, 190_258);
}

/// Test: Epoch issuance with various inflation rates.
#[test]
fn test_epoch_issuance_various_rates() {
    let mut state = MonetaryEpochState::default();
    state.staked_supply = 1_000_000_000; // 1B tokens

    // Test various inflation rates
    let test_cases = [
        (0.01, 100),   // 1% = 100 bps
        (0.05, 500),   // 5% = 500 bps
        (0.0775, 775), // 7.75% (Bootstrap with PQC)
        (0.12, 1200),  // 12% max cap
    ];

    for (rate, expected_bps) in test_cases {
        state.decision.recommended_r_inf_annual = rate;
        let bps = state.r_inf_annual_bps();
        assert_eq!(bps, expected_bps as u64, "Rate {} should give {} bps", rate, expected_bps);

        let issuance = compute_epoch_issuance(&state, 100);
        // issuance = (1B * bps) / (100 * 10000)
        let expected_issuance = (1_000_000_000u128 * expected_bps as u128) / 1_000_000;
        assert_eq!(issuance, expected_issuance, "Issuance mismatch for rate {}", rate);
    }
}

// ============================================================================
// Test 3: Validator Reward Distribution
// ============================================================================

/// Test: Rewards are distributed proportionally to stake.
#[test]
fn test_rewards_proportional_to_stake() {
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 1000 },
        ValidatorStake { validator_id: 2, stake: 2000 },
        ValidatorStake { validator_id: 3, stake: 3000 },
        ValidatorStake { validator_id: 4, stake: 4000 },
    ];

    let distribution = compute_validator_rewards(10000, &stakes, 10000).unwrap();

    // Perfect distribution: each gets stake amount
    assert_eq!(distribution.rewards[0].reward, 1000);
    assert_eq!(distribution.rewards[1].reward, 2000);
    assert_eq!(distribution.rewards[2].reward, 3000);
    assert_eq!(distribution.rewards[3].reward, 4000);
}

/// Test: Rounding remainder goes to last validator (deterministic).
#[test]
fn test_rounding_remainder_assignment() {
    // 7 validators with 100 stake each = 700 total stake, distribute 1000 tokens
    // Each validator gets: floor(1000 * 100 / 700) = floor(142.857...) = 142
    // Total allocated: 7 * 142 = 994
    // Remainder: 1000 - 994 = 6
    // Last validator gets: 142 + 6 = 148
    let stakes: Vec<ValidatorStake> = (1..=7)
        .map(|id| ValidatorStake { validator_id: id, stake: 100 })
        .collect();

    let distribution = compute_validator_rewards(1000, &stakes, 700).unwrap();

    // First 6 get floor(1000 * 100 / 700) = 142
    for i in 0..6 {
        assert_eq!(distribution.rewards[i].reward, 142);
    }
    // Last gets 142 + remainder (6) = 148
    assert_eq!(distribution.rewards[6].reward, 148);

    // Total must be exactly 1000
    let total: u128 = distribution.rewards.iter().map(|r| r.reward).sum();
    assert_eq!(total, 1000);
    assert!(distribution.is_balanced());
}

/// Test: Stake invariant failure returns None.
#[test]
fn test_stake_invariant_failure() {
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 100 },
        ValidatorStake { validator_id: 2, stake: 200 },
    ];

    // Sum of stakes (300) doesn't match expected (500)
    let result = compute_validator_rewards(1000, &stakes, 500);
    assert!(result.is_none(), "Should fail when stake invariant is violated");
}

// ============================================================================
// Test 4: Conservation Tests
// ============================================================================

/// Test: Total rewards always equals input issuance (conservation).
#[test]
fn test_reward_conservation() {
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 17 },
        ValidatorStake { validator_id: 2, stake: 31 },
        ValidatorStake { validator_id: 3, stake: 47 },
        ValidatorStake { validator_id: 4, stake: 53 },
        ValidatorStake { validator_id: 5, stake: 61 },
    ];
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

    // Test many different issuance values
    for issuance in [0, 1, 7, 100, 999, 1000, 10007, 100_000, 1_000_000_000] {
        let distribution = compute_validator_rewards(issuance, &stakes, total_stake).unwrap();

        let sum_rewards: u128 = distribution.rewards.iter().map(|r| r.reward).sum();
        assert_eq!(
            sum_rewards, issuance,
            "Conservation failed for issuance {}",
            issuance
        );
        assert!(distribution.is_balanced());
        assert_eq!(distribution.total_distributed, issuance);
    }
}

/// Test: Seigniorage + validator distribution conserves total.
#[test]
fn test_end_to_end_conservation() {
    let split = mainnet_seigniorage_split();
    let stakes: Vec<ValidatorStake> = (1..=10)
        .map(|id| ValidatorStake { validator_id: id, stake: 1000 })
        .collect();
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

    for total_issuance in [0, 1, 100, 10000, 1_000_000, 1_000_000_000] {
        // Split issuance
        let accounting = compute_seigniorage_split(total_issuance, &split);
        assert!(accounting.is_balanced());

        // Distribute validator share
        if accounting.to_validators > 0 {
            let distribution = compute_validator_rewards(accounting.to_validators, &stakes, total_stake).unwrap();
            assert!(distribution.is_balanced());
        }

        // Total split should equal original issuance
        let split_total = accounting.to_validators
            + accounting.to_treasury
            + accounting.to_insurance
            + accounting.to_community;
        assert_eq!(split_total, total_issuance);
    }
}

// ============================================================================
// Test 5: Determinism Tests
// ============================================================================

/// Test: Epoch issuance is deterministic.
#[test]
fn test_epoch_issuance_deterministic() {
    let mut state = MonetaryEpochState::default();
    state.staked_supply = 123_456_789_012;
    state.decision.recommended_r_inf_annual = 0.0675;

    let issuance1 = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);
    let issuance2 = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);

    assert_eq!(issuance1, issuance2, "Epoch issuance should be deterministic");
}

/// Test: Validator rewards are deterministic.
#[test]
fn test_validator_rewards_deterministic() {
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 123 },
        ValidatorStake { validator_id: 2, stake: 456 },
        ValidatorStake { validator_id: 3, stake: 789 },
    ];
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

    let dist1 = compute_validator_rewards(10000, &stakes, total_stake).unwrap();
    let dist2 = compute_validator_rewards(10000, &stakes, total_stake).unwrap();

    assert_eq!(dist1, dist2, "Validator rewards should be deterministic");

    for i in 0..stakes.len() {
        assert_eq!(dist1.rewards[i], dist2.rewards[i]);
    }
}

// ============================================================================
// Test 6: Edge Cases
// ============================================================================

/// Test: Zero staked supply produces zero issuance.
#[test]
fn test_zero_stake_zero_issuance() {
    let mut state = MonetaryEpochState::default();
    state.staked_supply = 0;
    state.decision.recommended_r_inf_annual = 0.10;

    let issuance = compute_epoch_issuance(&state, 100);
    assert_eq!(issuance, 0);
}

/// Test: Zero inflation rate produces zero issuance.
#[test]
fn test_zero_inflation_zero_issuance() {
    let mut state = MonetaryEpochState::default();
    state.staked_supply = 1_000_000_000;
    state.decision.recommended_r_inf_annual = 0.0;

    let issuance = compute_epoch_issuance(&state, 100);
    assert_eq!(issuance, 0);
}

/// Test: Empty validator set with zero issuance.
#[test]
fn test_empty_validators() {
    let stakes: Vec<ValidatorStake> = vec![];
    let distribution = compute_validator_rewards(0, &stakes, 0).unwrap();

    assert!(distribution.rewards.is_empty());
    assert_eq!(distribution.total_distributed, 0);
    assert!(distribution.is_balanced());
}

/// Test: Single validator gets all rewards.
#[test]
fn test_single_validator() {
    let stakes = vec![ValidatorStake { validator_id: 42, stake: 1000 }];
    let distribution = compute_validator_rewards(5000, &stakes, 1000).unwrap();

    assert_eq!(distribution.rewards.len(), 1);
    assert_eq!(distribution.rewards[0].validator_id, 42);
    assert_eq!(distribution.rewards[0].reward, 5000);
}

/// Test: Large values don't overflow.
#[test]
fn test_large_values_no_overflow() {
    let mut state = MonetaryEpochState::default();
    // 100 trillion tokens (larger than likely real supply)
    state.staked_supply = 100_000_000_000_000;
    state.decision.recommended_r_inf_annual = 0.12; // Max cap

    let issuance = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);
    assert!(issuance > 0);
    assert!(issuance < state.staked_supply, "Issuance should be < total stake");

    // Large validator stakes
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 10_000_000_000_000 },
        ValidatorStake { validator_id: 2, stake: 20_000_000_000_000 },
        ValidatorStake { validator_id: 3, stake: 30_000_000_000_000 },
        ValidatorStake { validator_id: 4, stake: 40_000_000_000_000 },
    ];
    let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

    let distribution = compute_validator_rewards(issuance, &stakes, total_stake).unwrap();
    assert!(distribution.is_balanced());
}

/// Test: Very unequal stake distribution.
#[test]
fn test_unequal_stake_distribution() {
    // One validator has 99.99% of stake
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 1 },
        ValidatorStake { validator_id: 2, stake: 1 },
        ValidatorStake { validator_id: 3, stake: 999_998 },
    ];

    let distribution = compute_validator_rewards(1_000_000, &stakes, 1_000_000).unwrap();

    // Validator 3 should get almost all rewards
    assert_eq!(distribution.rewards[0].reward, 1);
    assert_eq!(distribution.rewards[1].reward, 1);
    assert_eq!(distribution.rewards[2].reward, 999_998);
    assert!(distribution.is_balanced());
}

// ============================================================================
// Test 7: MainNet Configuration
// ============================================================================

/// Test: MainNet default seigniorage split (82/12/4/2).
#[test]
fn test_mainnet_seigniorage_split() {
    let split = mainnet_seigniorage_split();

    assert!(split.is_valid());
    assert_eq!(split.validators_bps, 8200); // 82%
    assert_eq!(split.treasury_bps, 1200);   // 12%
    assert_eq!(split.insurance_bps, 400);   // 4%
    assert_eq!(split.community_bps, 200);   // 2%
    assert_eq!(split.sum(), 10000);

    // Test distribution
    let accounting = compute_seigniorage_split(1_000_000, &split);

    assert_eq!(accounting.to_validators, 820_000);
    // Treasury gets remainder from rounding
    assert!(accounting.to_treasury >= 120_000);
    assert_eq!(accounting.to_insurance, 40_000);
    assert_eq!(accounting.to_community, 20_000);
    assert!(accounting.is_balanced());
}

/// Test: MainNet epochs per year constant.
#[test]
fn test_mainnet_epochs_per_year() {
    // 52,560 epochs = 365 days × 24 hours × 6 epochs/hour (10-minute epochs)
    assert_eq!(MAINNET_EPOCHS_PER_YEAR, 52_560);

    // Verify: 365 * 24 * 6 = 52,560
    let calculated = 365 * 24 * 6;
    assert_eq!(MAINNET_EPOCHS_PER_YEAR, calculated);
}

// ============================================================================
// Test 8: Integration with MonetaryMode (Semantics)
// ============================================================================

/// Test: Validator rewards struct correctly tracks invariants.
#[test]
fn test_validator_reward_distribution_invariants() {
    let stakes = vec![
        ValidatorStake { validator_id: 1, stake: 100 },
        ValidatorStake { validator_id: 2, stake: 200 },
        ValidatorStake { validator_id: 3, stake: 300 },
    ];

    let distribution = compute_validator_rewards(1000, &stakes, 600).unwrap();

    // Check all invariants
    assert!(distribution.is_balanced(), "Should be balanced");
    assert!(distribution.stake_invariant_ok(), "Stake invariant should hold");
    assert_eq!(distribution.total_validators_issuance, 1000);
    assert_eq!(distribution.expected_staked_supply, 600);
    assert_eq!(distribution.actual_staked_supply, 600);
    assert_eq!(distribution.total_distributed, 1000);
}

/// Test: ValidatorStake and ValidatorReward have correct fields.
#[test]
fn test_validator_types() {
    let stake = ValidatorStake {
        validator_id: 42,
        stake: 1_000_000,
    };
    assert_eq!(stake.validator_id, 42);
    assert_eq!(stake.stake, 1_000_000);

    let reward = ValidatorReward {
        validator_id: 42,
        reward: 500,
    };
    assert_eq!(reward.validator_id, 42);
    assert_eq!(reward.reward, 500);
}