//! T203: Rate-of-Change Limiter Tests
//!
//! This module contains comprehensive tests for the rate-of-change limiters
//! implemented in T203, verifying:
//!
//! - **clamp_inflation_rate_change**: Basic correctness with known values
//! - **Epoch 0 behavior**: No clamping applied when no previous rate exists
//! - **Upward clamping**: Rate increases are limited to max_delta
//! - **Downward clamping**: Rate decreases are limited to max_delta
//! - **Within band**: No clamping when change is within allowed delta
//! - **Convergence**: Multi-epoch convergence to target
//! - **Phase-specific limits**: Different max_delta per phase
//! - **Monotonicity**: Increasing fees never increase r_inf above unclamped
//! - **Edge cases**: Zero stake, very large values, boundary conditions

use qbind_ledger::{
    clamp_inflation_rate_change, compute_epoch_state, MonetaryEngineConfig, MonetaryEpochInputs,
    MonetaryPhase, PhaseParameters,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns a default configuration for testing with T203 rate-of-change limits.
fn test_config() -> MonetaryEngineConfig {
    MonetaryEngineConfig {
        pqc_premium_compute: 0.30,
        pqc_premium_bandwidth: 0.15,
        pqc_premium_storage: 0.10,
        bootstrap: PhaseParameters {
            r_target_annual: 0.05,       // 5% base (7.75% PQC-adjusted)
            inflation_floor_annual: 0.0, // no floor in Bootstrap
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12, // 12% cap
            ema_lambda_bps: 700,             // T202: 7% EMA factor
            max_delta_r_inf_per_epoch_bps: 25, // T203: 0.25% max change per epoch
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,       // 4% base
            inflation_floor_annual: 0.0, // no floor in Transition
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10, // 10% cap
            ema_lambda_bps: 300,             // T202: 3% EMA factor
            max_delta_r_inf_per_epoch_bps: 10, // T203: 0.10% max change per epoch
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,        // 3% base
            inflation_floor_annual: 0.01, // 1% floor in Mature
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08, // 8% cap
            ema_lambda_bps: 150,             // T202: 1.5% EMA factor
            max_delta_r_inf_per_epoch_bps: 5, // T203: 0.05% max change per epoch
        },
        alpha_fee_offset: 1.0,
    }
}

/// Returns a config with larger max_delta for faster convergence tests.
fn fast_delta_config() -> MonetaryEngineConfig {
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
            max_delta_r_inf_per_epoch_bps: 100, // 1.0% max change per epoch
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10,
            ema_lambda_bps: 300,
            max_delta_r_inf_per_epoch_bps: 50, // 0.5% max change per epoch
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,
            inflation_floor_annual: 0.01,
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08,
            ema_lambda_bps: 150,
            max_delta_r_inf_per_epoch_bps: 25, // 0.25% max change per epoch
        },
        alpha_fee_offset: 1.0,
    }
}

/// Returns default inputs for Bootstrap phase.
fn default_inputs() -> MonetaryEpochInputs {
    MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 0,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None, // T203: No previous rate for epoch 0
    }
}

// ============================================================================
// Test 1: clamp_inflation_rate_change - Basic Correctness
// ============================================================================

/// Test: Clamp upward movement (rate increasing).
#[test]
fn test_clamp_upward_movement() {
    // r_prev = 1000 bps (10%), r_bounded = 1500 bps (15%), max_delta = 200 bps (2%)
    // Expected: 1000 + 200 = 1200 bps
    let result = clamp_inflation_rate_change(1000, 1500, 200);
    assert_eq!(result, 1200, "Upward movement should be clamped to 1200 bps");
}

/// Test: Clamp downward movement (rate decreasing).
#[test]
fn test_clamp_downward_movement() {
    // r_prev = 1000 bps, r_bounded = 300 bps, max_delta = 200 bps
    // Expected: 1000 - 200 = 800 bps
    let result = clamp_inflation_rate_change(1000, 300, 200);
    assert_eq!(result, 800, "Downward movement should be clamped to 800 bps");
}

/// Test: No clamp when within band.
#[test]
fn test_no_clamp_within_band() {
    // r_prev = 1000 bps, r_bounded = 1100 bps, max_delta = 200 bps
    // Expected: 1100 bps (no clamping needed)
    let result = clamp_inflation_rate_change(1000, 1100, 200);
    assert_eq!(result, 1100, "No clamping should occur when within band");

    // Same for downward
    let result2 = clamp_inflation_rate_change(1000, 850, 200);
    assert_eq!(result2, 850, "No clamping should occur when within band (downward)");
}

/// Test: No change when r_bounded == r_prev.
#[test]
fn test_no_change_equal_rates() {
    let result = clamp_inflation_rate_change(1000, 1000, 200);
    assert_eq!(result, 1000, "Should return same rate when no change");
}

/// Test: max_delta = 0 returns r_prev (edge case / defensive).
#[test]
fn test_zero_max_delta() {
    let result = clamp_inflation_rate_change(1000, 1500, 0);
    assert_eq!(result, 1000, "Zero max_delta should prevent any change");

    let result2 = clamp_inflation_rate_change(1000, 300, 0);
    assert_eq!(result2, 1000, "Zero max_delta should prevent any change (downward)");
}

/// Test: Saturating arithmetic for large values.
#[test]
fn test_saturating_arithmetic() {
    // Test near u32::MAX
    let result = clamp_inflation_rate_change(u32::MAX - 100, u32::MAX, 50);
    assert_eq!(result, u32::MAX - 50, "Should saturate at upper bound");

    // Test near 0
    let result2 = clamp_inflation_rate_change(50, 0, 100);
    assert_eq!(result2, 0, "Should saturate at 0 (lower bound)");

    // Test overflow prevention
    let result3 = clamp_inflation_rate_change(u32::MAX - 50, u32::MAX, u32::MAX);
    // With max_delta = u32::MAX, upper bound would overflow, but saturating_add handles it
    assert_eq!(result3, u32::MAX, "Should handle overflow with saturating_add");
}

// ============================================================================
// Test 2: Epoch 0 Behavior (No Clamping)
// ============================================================================

/// Test: Epoch 0 uses bounded rate directly (no clamping).
#[test]
fn test_epoch_0_no_clamping() {
    let config = test_config();
    let inputs = MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 0,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None, // No previous rate
    };

    let state = compute_epoch_state(&config, &inputs);

    // With zero fees and PQC multiplier = 1.55, effective target = 0.0775 (775 bps)
    // No clamping should occur since prev_r_inf_annual_bps is None
    let expected_r_inf = 0.0775;
    assert!(
        (state.decision.recommended_r_inf_annual - expected_r_inf).abs() < 1e-6,
        "Epoch 0 should use unclamped rate: expected {}, got {}",
        expected_r_inf,
        state.decision.recommended_r_inf_annual
    );
}

// ============================================================================
// Test 3: Convergence Over Multiple Epochs
// ============================================================================

/// Test: Gradual convergence to target over multiple epochs.
#[test]
fn test_convergence_multiple_epochs() {
    let config = fast_delta_config(); // 100 bps max_delta for faster convergence

    // Start with a high previous rate (1200 bps = 12%)
    // Target with fees should be lower, so we converge downward
    let mut prev_r_inf_bps: Option<u32> = Some(1200);
    let mut prev_ema = 0u128;

    // Simulate 20 epochs with constant high fees that drive rate down
    for epoch in 0..20 {
        let inputs = MonetaryEpochInputs {
            epoch_index: epoch,
            raw_epoch_fees: 50_000, // High fees to drive rate down
            previous_smoothed_annual_fee_revenue: 0,
            previous_ema_fees_per_epoch: prev_ema,
            staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100 + (epoch * 3) as u64,
            fee_volatility: 1.0,
            epochs_per_year: 100,
            prev_r_inf_annual_bps: prev_r_inf_bps,
        };

        let state = compute_epoch_state(&config, &inputs);

        // Check that rate change is bounded
        if let Some(prev) = prev_r_inf_bps {
            let current_bps = (state.decision.recommended_r_inf_annual * 10_000.0).round() as u32;
            let delta = if current_bps > prev {
                current_bps - prev
            } else {
                prev - current_bps
            };
            assert!(
                delta <= 100, // max_delta_r_inf_per_epoch_bps for Bootstrap is 100
                "Epoch {}: Rate change {} exceeds max_delta 100",
                epoch,
                delta
            );
        }

        prev_r_inf_bps = Some((state.decision.recommended_r_inf_annual * 10_000.0).round() as u32);
        prev_ema = state.ema_fees_per_epoch;
    }

    // After 20 epochs, rate should have converged closer to target
    // With high fees, the target should be lower than starting 1200 bps
    let final_rate = prev_r_inf_bps.unwrap();
    assert!(
        final_rate < 1200,
        "Rate should have decreased from starting point: final = {}",
        final_rate
    );
}

// ============================================================================
// Test 4: Phase-Specific Limits
// ============================================================================

/// Test: Different phases have different max_delta values.
#[test]
fn test_phase_specific_limits() {
    let config = test_config();

    // Bootstrap: max_delta = 25 bps
    let bootstrap_inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 100_000, // High fees to trigger large rate change
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 1_000,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(775), // Previous rate = 7.75%
    };

    let bootstrap_state = compute_epoch_state(&config, &bootstrap_inputs);
    let bootstrap_delta = ((bootstrap_state.decision.recommended_r_inf_annual * 10_000.0).round() as i32 - 775).abs();
    assert!(
        bootstrap_delta <= 25,
        "Bootstrap phase delta {} should be <= 25 bps",
        bootstrap_delta
    );

    // Transition: max_delta = 10 bps
    let transition_inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 100_000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 1_000,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Transition,
        bonded_ratio: 0.5,
        days_since_launch: 1500,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(620), // Previous rate = 6.2%
    };

    let transition_state = compute_epoch_state(&config, &transition_inputs);
    let transition_delta = ((transition_state.decision.recommended_r_inf_annual * 10_000.0).round() as i32 - 620).abs();
    assert!(
        transition_delta <= 10,
        "Transition phase delta {} should be <= 10 bps",
        transition_delta
    );

    // Mature: max_delta = 5 bps
    let mature_inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 100_000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 1_000,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Mature,
        bonded_ratio: 0.5,
        days_since_launch: 3000,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(465), // Previous rate = 4.65%
    };

    let mature_state = compute_epoch_state(&config, &mature_inputs);
    let mature_delta = ((mature_state.decision.recommended_r_inf_annual * 10_000.0).round() as i32 - 465).abs();
    assert!(
        mature_delta <= 5,
        "Mature phase delta {} should be <= 5 bps",
        mature_delta
    );
}

// ============================================================================
// Test 5: Monotonicity Check
// ============================================================================

/// Test: Increasing fees never increase r_inf above unclamped value.
/// This tests that Δ-limit is allowed to delay reduction but never reverse it.
#[test]
fn test_monotonicity_increasing_fees() {
    let config = fast_delta_config();

    let mut prev_r_inf_bps: Option<u32> = Some(1000); // Start at 10%
    let mut prev_ema = 0u128;

    // Simulate increasing fees over epochs
    for epoch in 0..10 {
        let fees = 10_000 * (epoch + 1) as u128; // Increasing fees

        let inputs = MonetaryEpochInputs {
            epoch_index: epoch,
            raw_epoch_fees: fees,
            previous_smoothed_annual_fee_revenue: 0,
            previous_ema_fees_per_epoch: prev_ema,
            staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100 + (epoch * 3) as u64,
            fee_volatility: 1.0,
            epochs_per_year: 100,
            prev_r_inf_annual_bps: prev_r_inf_bps,
        };

        let state = compute_epoch_state(&config, &inputs);
        let current_bps = (state.decision.recommended_r_inf_annual * 10_000.0).round() as u32;

        // Rate should never increase above previous when fees are increasing
        // (fees drive rate down, so rate should stay same or decrease)
        if let Some(prev) = prev_r_inf_bps {
            assert!(
                current_bps <= prev + 1, // Allow 1 bps for rounding
                "Epoch {}: Rate {} should not exceed previous {} with increasing fees",
                epoch,
                current_bps,
                prev
            );
        }

        prev_r_inf_bps = Some(current_bps);
        prev_ema = state.ema_fees_per_epoch;
    }
}

// ============================================================================
// Test 6: Edge Cases
// ============================================================================

/// Test: Zero staked supply doesn't cause issues.
#[test]
fn test_zero_staked_supply() {
    let config = test_config();
    let inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 1000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 0,
        circulating_supply: 100_000_000, // Zero stake
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.0,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(500),
    };

    let state = compute_epoch_state(&config, &inputs);

    // Should not panic, and rate change should be bounded
    let current_bps = (state.decision.recommended_r_inf_annual * 10_000.0).round() as i32;
    let delta = (current_bps - 500).abs();
    assert!(
        delta <= 25,
        "Rate change {} should be bounded even with zero stake",
        delta
    );
}

/// Test: Very large staked supply.
#[test]
fn test_large_staked_supply() {
    let config = test_config();
    let inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: u128::MAX / 1000, // Large but not overflow-inducing
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: u128::MAX / 1000,
        circulating_supply: 100_000_000, // Large stake
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.6,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(775),
    };

    let state = compute_epoch_state(&config, &inputs);

    // Should not panic, and rate change should be bounded
    let current_bps = (state.decision.recommended_r_inf_annual * 10_000.0).round() as i32;
    let delta = (current_bps - 775).abs();
    assert!(
        delta <= 25,
        "Rate change {} should be bounded with large stake",
        delta
    );
}

/// Test: Rate near cap with Δ-limit.
#[test]
fn test_rate_near_cap() {
    let config = test_config();

    // Previous rate is near cap (1200 bps = 12%, cap is 1200)
    let inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 0, // No fees to push rate up
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(1190), // Just below cap
    };

    let state = compute_epoch_state(&config, &inputs);

    // Rate should not exceed cap (1200 bps)
    assert!(
        state.decision.recommended_r_inf_annual <= 0.12,
        "Rate {} should not exceed cap 0.12",
        state.decision.recommended_r_inf_annual
    );

    // Rate change should be bounded
    let current_bps = (state.decision.recommended_r_inf_annual * 10_000.0).round() as i32;
    let delta = (current_bps - 1190).abs();
    assert!(
        delta <= 25,
        "Rate change {} should be bounded near cap",
        delta
    );
}

/// Test: Rate near floor with Δ-limit (Mature phase).
#[test]
fn test_rate_near_floor() {
    let config = test_config();

    // Previous rate is near floor (100 bps = 1%, floor is 100 in Mature)
    let inputs = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 1_000_000, // High fees to push rate down
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 500_000,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Mature,
        bonded_ratio: 0.5,
        days_since_launch: 3000,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(105), // Just above floor
    };

    let state = compute_epoch_state(&config, &inputs);

    // Rate should not drop below floor (100 bps = 1%)
    assert!(
        state.decision.recommended_r_inf_annual >= 0.01,
        "Rate {} should not drop below floor 0.01",
        state.decision.recommended_r_inf_annual
    );

    // Rate change should be bounded (max_delta = 5 for Mature)
    let current_bps = (state.decision.recommended_r_inf_annual * 10_000.0).round() as i32;
    let delta = (current_bps - 105).abs();
    assert!(
        delta <= 5,
        "Rate change {} should be bounded near floor",
        delta
    );
}

// ============================================================================
// Test 7: Configuration Validation
// ============================================================================

/// Test: max_delta_r_inf_per_epoch_bps must be > 0.
#[test]
fn test_config_validation_delta_must_be_positive() {
    let mut config = test_config();
    config.bootstrap.max_delta_r_inf_per_epoch_bps = 0;

    let result = config.validate();
    assert!(result.is_err(), "Config with zero max_delta should fail validation");
    assert!(
        result.unwrap_err().contains("max_delta_r_inf_per_epoch_bps"),
        "Error should mention max_delta_r_inf_per_epoch_bps"
    );
}

/// Test: Valid configuration passes validation.
#[test]
fn test_config_validation_valid() {
    let config = test_config();
    let result = config.validate();
    assert!(result.is_ok(), "Valid config should pass validation");
}

// ============================================================================
// Test 8: Determinism
// ============================================================================

/// Test: Rate-of-change limiting is deterministic.
#[test]
fn test_determinism() {
    let config = test_config();
    let inputs = MonetaryEpochInputs {
        epoch_index: 5,
        raw_epoch_fees: 12345,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 10000,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 150,
        fee_volatility: 1.2,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(750),
    };

    // Compute state multiple times
    let state1 = compute_epoch_state(&config, &inputs);
    let state2 = compute_epoch_state(&config, &inputs);
    let state3 = compute_epoch_state(&config, &inputs);

    // All results should be identical
    assert_eq!(
        state1.decision.recommended_r_inf_annual,
        state2.decision.recommended_r_inf_annual,
        "Rate should be deterministic"
    );
    assert_eq!(
        state2.decision.recommended_r_inf_annual,
        state3.decision.recommended_r_inf_annual,
        "Rate should be deterministic"
    );
}