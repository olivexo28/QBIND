//! T202: EMA Fee Smoothing Tests
//!
//! This module contains comprehensive tests for the EMA-based fee smoothing
//! implemented in T202, verifying:
//!
//! - **ema_step**: Basic correctness with known values
//! - **Phase-specific behavior**: Different λ values for Bootstrap/Transition/Mature
//! - **Initialization**: Epoch 0 behavior with no previous state
//! - **Integration**: Multi-epoch fee series with gradual EMA changes
//! - **Edge cases**: Zero fees, large values, saturating arithmetic

use qbind_ledger::{
    compute_ema_fee_revenue, compute_epoch_state, ema_step, MonetaryEngineConfig,
    MonetaryEpochInputs, MonetaryPhase, PhaseParameters,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns a default configuration for testing with T202 EMA parameters.
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
            ema_lambda_bps: 700,               // 7% for Bootstrap
            max_delta_r_inf_per_epoch_bps: 25, // T203: 0.25% max change per epoch
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10,
            ema_lambda_bps: 300,               // 3% for Transition
            max_delta_r_inf_per_epoch_bps: 10, // T203: 0.10% max change per epoch
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,
            inflation_floor_annual: 0.01,
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08,
            ema_lambda_bps: 150,              // 1.5% for Mature
            max_delta_r_inf_per_epoch_bps: 5, // T203: 0.05% max change per epoch
        },
        alpha_fee_offset: 1.0,
    }
}

/// Returns default inputs for Bootstrap phase.
#[allow(dead_code)]
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
// Test 1: ema_step Basic Correctness
// ============================================================================

/// Test: Simple known values with λ=0.5 (5000 bps).
#[test]
fn test_ema_step_half_weight() {
    // λ=5000 bps means 50% weight on new value, 50% on previous
    // EMA = 0.5 * 200 + 0.5 * 100 = 150
    let ema = ema_step(100, 200, 5000);
    assert_eq!(ema, 150, "Expected EMA=150 for λ=50%, got {}", ema);

    // Same test with reversed values
    let ema2 = ema_step(200, 100, 5000);
    assert_eq!(ema2, 150, "Expected EMA=150 for λ=50%, got {}", ema2);
}

/// Test: λ=0.1 (1000 bps) - slow smoothing.
#[test]
fn test_ema_step_slow_smoothing() {
    // λ=1000 bps means 10% weight on new value, 90% on previous
    // EMA = 0.1 * 200 + 0.9 * 100 = 20 + 90 = 110
    let ema = ema_step(100, 200, 1000);
    assert_eq!(ema, 110, "Expected EMA=110 for λ=10%, got {}", ema);
}

/// Test: λ=0.9 (9000 bps) - fast smoothing.
#[test]
fn test_ema_step_fast_smoothing() {
    // λ=9000 bps means 90% weight on new value, 10% on previous
    // EMA = 0.9 * 200 + 0.1 * 100 = 180 + 10 = 190
    let ema = ema_step(100, 200, 9000);
    assert_eq!(ema, 190, "Expected EMA=190 for λ=90%, got {}", ema);
}

/// Test: λ=0.07 (700 bps) - Bootstrap default.
#[test]
fn test_ema_step_bootstrap_lambda() {
    // λ=700 bps (7%) as configured for Bootstrap
    // EMA = 0.07 * 1000 + 0.93 * 500 = 70 + 465 = 535
    let ema = ema_step(500, 1000, 700);
    assert_eq!(ema, 535, "Expected EMA=535 for λ=7%, got {}", ema);
}

/// Test: Constant fees produce constant EMA.
#[test]
fn test_ema_step_constant_fees() {
    // If prev_ema == fees_t, EMA should remain the same
    let ema = ema_step(1000, 1000, 5000);
    assert_eq!(ema, 1000, "Constant fees should produce constant EMA");

    let ema2 = ema_step(1000, 1000, 700);
    assert_eq!(ema2, 1000, "Constant fees should produce constant EMA");
}

/// Test: Zero prev_ema with positive fees.
#[test]
fn test_ema_step_zero_prev() {
    // λ=700 bps: EMA = 0.07 * 1000 + 0.93 * 0 = 70
    let ema = ema_step(0, 1000, 700);
    assert_eq!(ema, 70, "Expected EMA=70 for zero prev, got {}", ema);
}

/// Test: Positive prev_ema with zero fees.
#[test]
fn test_ema_step_zero_fees() {
    // λ=700 bps: EMA = 0.07 * 0 + 0.93 * 1000 = 930
    let ema = ema_step(1000, 0, 700);
    assert_eq!(ema, 930, "Expected EMA=930 for zero fees, got {}", ema);
}

// ============================================================================
// Test 2: Phase-Specific Behavior
// ============================================================================

/// Test: Different λ for Bootstrap/Transition/Mature produces different EMA response.
/// Bootstrap (λ=700 bps) should respond faster than Mature (λ=150 bps).
#[test]
fn test_phase_specific_lambda() {
    let prev_ema = 1000;
    let new_fees = 2000; // Doubling the fees

    // Bootstrap: λ=700 bps
    let ema_bootstrap = ema_step(prev_ema, new_fees, 700);
    // EMA = 0.07 * 2000 + 0.93 * 1000 = 140 + 930 = 1070
    assert_eq!(ema_bootstrap, 1070);

    // Transition: λ=300 bps
    let ema_transition = ema_step(prev_ema, new_fees, 300);
    // EMA = 0.03 * 2000 + 0.97 * 1000 = 60 + 970 = 1030
    assert_eq!(ema_transition, 1030);

    // Mature: λ=150 bps
    let ema_mature = ema_step(prev_ema, new_fees, 150);
    // EMA = 0.015 * 2000 + 0.985 * 1000 = 30 + 985 = 1015
    assert_eq!(ema_mature, 1015);

    // Bootstrap responds fastest (largest change)
    assert!(
        ema_bootstrap > ema_transition,
        "Bootstrap should respond faster than Transition"
    );
    assert!(
        ema_transition > ema_mature,
        "Transition should respond faster than Mature"
    );
}

/// Test: Over multiple epochs, Bootstrap EMA tracks fees more quickly than Mature.
#[test]
fn test_phase_specific_multi_epoch_tracking() {
    // Start both at EMA=1000, then apply fees=2000 for 10 epochs
    let initial_ema = 1000u128;
    let new_fees = 2000u128;
    let epochs = 10;

    let mut ema_bootstrap = initial_ema;
    let mut ema_mature = initial_ema;

    for _ in 0..epochs {
        ema_bootstrap = ema_step(ema_bootstrap, new_fees, 700);
        ema_mature = ema_step(ema_mature, new_fees, 150);
    }

    // After 10 epochs, Bootstrap should be much closer to 2000
    // Bootstrap: roughly (1 - 0.93^10) * 1000 closer to target
    // Mature: roughly (1 - 0.985^10) * 1000 closer to target
    assert!(
        ema_bootstrap > ema_mature,
        "Bootstrap (λ=7%) should track faster than Mature (λ=1.5%): {} vs {}",
        ema_bootstrap,
        ema_mature
    );

    // Bootstrap should be significantly closer to 2000
    let bootstrap_diff = 2000 - ema_bootstrap;
    let mature_diff = 2000 - ema_mature;
    assert!(
        bootstrap_diff < mature_diff,
        "Bootstrap should be closer to target: {} vs {}",
        bootstrap_diff,
        mature_diff
    );
}

// ============================================================================
// Test 3: Initialization (Epoch 0 Behavior)
// ============================================================================

/// Test: Epoch 0 with no prev_state → ema_fees_per_epoch == fees_t.
#[test]
fn test_epoch_0_initialization() {
    let config = test_config();

    let inputs = MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 5000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0, // First epoch, no previous EMA
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 1,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };

    let state = compute_epoch_state(&config, &inputs);

    // Epoch 0 with no previous EMA should use raw fees directly
    assert_eq!(
        state.ema_fees_per_epoch, 5000,
        "Epoch 0 EMA should equal raw fees"
    );
    assert_eq!(
        state.smoothed_annual_fee_revenue,
        5000 * 100,
        "Annualized should be EMA * epochs_per_year"
    );
}

/// Test: Epoch 1+ values follow the EMA recurrence.
#[test]
fn test_epoch_1_plus_ema_recurrence() {
    let config = test_config();

    // Epoch 0: Initialize with 1000 fees
    let inputs_0 = MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 1000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 1,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state_0 = compute_epoch_state(&config, &inputs_0);
    assert_eq!(state_0.ema_fees_per_epoch, 1000);

    // Epoch 1: Fees double to 2000
    let inputs_1 = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 2000,
        previous_smoothed_annual_fee_revenue: state_0.smoothed_annual_fee_revenue,
        previous_ema_fees_per_epoch: state_0.ema_fees_per_epoch,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 4,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state_1 = compute_epoch_state(&config, &inputs_1);

    // λ=700 bps: EMA = 0.07 * 2000 + 0.93 * 1000 = 140 + 930 = 1070
    assert_eq!(
        state_1.ema_fees_per_epoch, 1070,
        "Epoch 1 EMA should follow recurrence: expected 1070, got {}",
        state_1.ema_fees_per_epoch
    );

    // Epoch 2: Fees stay at 2000
    let inputs_2 = MonetaryEpochInputs {
        epoch_index: 2,
        raw_epoch_fees: 2000,
        previous_smoothed_annual_fee_revenue: state_1.smoothed_annual_fee_revenue,
        previous_ema_fees_per_epoch: state_1.ema_fees_per_epoch,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 7,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state_2 = compute_epoch_state(&config, &inputs_2);

    // λ=700 bps: EMA = 0.07 * 2000 + 0.93 * 1070 = 140 + 995.1 = 1135 (floor)
    assert_eq!(
        state_2.ema_fees_per_epoch, 1135,
        "Epoch 2 EMA should continue recurrence: expected 1135, got {}",
        state_2.ema_fees_per_epoch
    );
}

// ============================================================================
// Test 4: Integration with compute_epoch_state()
// ============================================================================

/// Test: Multi-epoch synthetic series shows EMA changes gradually, not jumping to fees_t.
#[test]
fn test_multi_epoch_gradual_change() {
    let config = test_config();

    // Start with stable fees of 1000 for several epochs, then spike to 5000
    let mut prev_ema = 1000u128;
    let mut prev_smoothed = 100_000u128;

    // Simulate 5 epochs of stable fees
    for epoch in 0..5 {
        let inputs = MonetaryEpochInputs {
            epoch_index: epoch,
            raw_epoch_fees: 1000,
            previous_smoothed_annual_fee_revenue: prev_smoothed,
            previous_ema_fees_per_epoch: if epoch == 0 { 0 } else { prev_ema },
            staked_supply: 10_000_000,
            circulating_supply: 100_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100 + epoch * 3,
            fee_volatility: 1.0,
            epochs_per_year: 100,
            prev_r_inf_annual_bps: None,
        };
        let state = compute_epoch_state(&config, &inputs);
        assert_eq!(
            state.ema_fees_per_epoch, 1000,
            "Stable fees should maintain EMA at 1000"
        );
        prev_ema = state.ema_fees_per_epoch;
        prev_smoothed = state.smoothed_annual_fee_revenue;
    }

    // Now spike fees to 5000
    let spike_inputs = MonetaryEpochInputs {
        epoch_index: 5,
        raw_epoch_fees: 5000,
        previous_smoothed_annual_fee_revenue: prev_smoothed,
        previous_ema_fees_per_epoch: prev_ema,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 115,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state_spike = compute_epoch_state(&config, &spike_inputs);

    // EMA should NOT jump to 5000, but move gradually
    // λ=700 bps: EMA = 0.07 * 5000 + 0.93 * 1000 = 350 + 930 = 1280
    assert_eq!(
        state_spike.ema_fees_per_epoch, 1280,
        "EMA should change gradually, not jump to 5000"
    );
    assert!(
        state_spike.ema_fees_per_epoch < 5000,
        "EMA should not reach spike value immediately"
    );
    assert!(
        state_spike.ema_fees_per_epoch > 1000,
        "EMA should increase from previous value"
    );
}

/// Test: smoothed_annual_fee_revenue is ema_fees_per_epoch * epochs_per_year.
#[test]
fn test_smoothed_annual_is_ema_times_epochs() {
    let config = test_config();

    let inputs = MonetaryEpochInputs {
        epoch_index: 5,
        raw_epoch_fees: 2500,
        previous_smoothed_annual_fee_revenue: 100_000,
        previous_ema_fees_per_epoch: 1000,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 115,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state = compute_epoch_state(&config, &inputs);

    // Verify relationship
    let expected_smoothed = state.ema_fees_per_epoch * 100;
    assert_eq!(
        state.smoothed_annual_fee_revenue, expected_smoothed,
        "smoothed_annual = ema * epochs_per_year"
    );
}

/// Test: r_inf changes smoothly across epochs due to EMA, not spiking.
#[test]
fn test_r_inf_changes_smoothly() {
    let config = test_config();

    // Start with moderate fees (EMA = 1000 after epoch 0)
    let inputs_0 = MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 1000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 100,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state_0 = compute_epoch_state(&config, &inputs_0);
    let r_inf_0 = state_0.decision.recommended_r_inf_annual;

    // Epoch 1: Spike to 10x fees
    let inputs_1 = MonetaryEpochInputs {
        epoch_index: 1,
        raw_epoch_fees: 10_000, // 10x the original fees
        previous_smoothed_annual_fee_revenue: state_0.smoothed_annual_fee_revenue,
        previous_ema_fees_per_epoch: state_0.ema_fees_per_epoch,
        staked_supply: 10_000_000,
        circulating_supply: 100_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 103,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };
    let state_1 = compute_epoch_state(&config, &inputs_1);
    let r_inf_1 = state_1.decision.recommended_r_inf_annual;

    // Due to EMA smoothing, r_inf should change gradually
    // With λ=7%, EMA goes from 1000 to 0.07*10000 + 0.93*1000 = 700 + 930 = 1630
    // This is less than 2x, so change should be moderate

    // The key insight: without EMA (raw fees), annualized would be 10x (from 100,000 to 1,000,000)
    // With EMA, it goes from 100,000 to 163,000 - a gradual increase

    // r_inf_0: fee_offset = 100,000 / 10,000,000 = 0.01, r_raw = 0.0775 - 0.01 = 0.0675
    // r_inf_1: fee_offset = 163,000 / 10,000,000 = 0.0163, r_raw = 0.0775 - 0.0163 = 0.0612
    // Change is about 0.0063, or ~9% relative change - that's gradual!

    let change_pct = (r_inf_0 - r_inf_1).abs() / r_inf_0;
    assert!(
        change_pct < 0.15, // Less than 15% relative change
        "r_inf change should be gradual: r_inf_0={}, r_inf_1={}, change_pct={}",
        r_inf_0,
        r_inf_1,
        change_pct
    );
}

// ============================================================================
// Test 5: Edge Cases
// ============================================================================

/// Test: fees_t = 0 for many epochs → EMA decays to 0.
#[test]
fn test_zero_fees_decay() {
    let mut ema = 10_000u128;
    let lambda_bps = 700u16;

    // Apply zero fees for 100 epochs
    for _ in 0..100 {
        ema = ema_step(ema, 0, lambda_bps);
    }

    // EMA should decay significantly (0.93^100 ≈ 0.0006)
    // 10_000 * 0.0006 ≈ 6, so should be very small
    assert!(
        ema < 100,
        "EMA should decay to near 0 after many epochs of zero fees: got {}",
        ema
    );
}

/// Test: Large fees_t values do not overflow (saturating behavior).
#[test]
fn test_large_values_no_overflow() {
    // Very large values that could cause overflow if not handled properly
    let large_prev = u128::MAX / 20_000; // Safe for multiplication by 10_000
    let large_fees = u128::MAX / 20_000;

    // Should not panic
    let ema = ema_step(large_prev, large_fees, 5000);

    // Result should be reasonable (average of two equal values)
    assert_eq!(
        ema, large_prev,
        "Large values should produce average without overflow"
    );
}

/// Test: Saturating arithmetic prevents overflow.
#[test]
fn test_saturating_arithmetic() {
    // Maximum possible values that would overflow standard arithmetic
    let max_val = u128::MAX / 2;

    // Should saturate rather than overflow
    let ema = ema_step(max_val, max_val, 5000);

    // Result should be valid (not garbage from overflow)
    assert!(
        ema <= max_val,
        "Result should not exceed input due to saturation"
    );
}

/// Test: λ = 0 (edge case, should be rejected by validation but ema_step handles it).
#[test]
fn test_lambda_zero_edge_case() {
    // λ=0 means all weight on previous, none on new
    let ema = ema_step(1000, 2000, 0);
    // EMA = 0 * 2000 + 1 * 1000 = 1000
    assert_eq!(ema, 1000, "λ=0 should keep previous EMA");
}

/// Test: λ = 10000 (edge case, 100% weight on new value).
#[test]
fn test_lambda_max_edge_case() {
    // λ=10000 means all weight on new, none on previous
    let ema = ema_step(1000, 2000, 10000);
    // EMA = 1 * 2000 + 0 * 1000 = 2000
    assert_eq!(ema, 2000, "λ=10000 should use only new fees");
}

// ============================================================================
// Test 6: Validation
// ============================================================================

/// Test: Config validation rejects invalid ema_lambda_bps values.
#[test]
fn test_config_validation() {
    let valid_config = test_config();
    assert!(
        valid_config.validate().is_ok(),
        "Valid config should pass validation"
    );

    // Test invalid Bootstrap lambda
    let mut invalid_config = test_config();
    invalid_config.bootstrap.ema_lambda_bps = 0;
    assert!(
        invalid_config.validate().is_err(),
        "λ=0 should fail validation"
    );

    let mut invalid_config2 = test_config();
    invalid_config2.transition.ema_lambda_bps = 10000;
    assert!(
        invalid_config2.validate().is_err(),
        "λ=10000 should fail validation"
    );

    let mut invalid_config3 = test_config();
    invalid_config3.mature.ema_lambda_bps = 15000;
    assert!(
        invalid_config3.validate().is_err(),
        "λ>10000 should fail validation"
    );
}

// ============================================================================
// Test 7: compute_ema_fee_revenue Direct Tests
// ============================================================================

/// Test: compute_ema_fee_revenue returns correct tuple.
#[test]
fn test_compute_ema_fee_revenue_direct() {
    let params = PhaseParameters {
        r_target_annual: 0.05,
        inflation_floor_annual: 0.0,
        fee_smoothing_half_life_days: 30.0,
        max_annual_inflation_cap: 0.12,
        ema_lambda_bps: 700,
        max_delta_r_inf_per_epoch_bps: 25, // T203
    };

    // Epoch 0 initialization
    let (ema, smoothed) = compute_ema_fee_revenue(1000, 0, 100, &params, 0);
    assert_eq!(ema, 1000, "Epoch 0 EMA should equal raw fees");
    assert_eq!(smoothed, 100_000, "Annualized = EMA * epochs");

    // Epoch 1+ with previous EMA
    let (ema2, smoothed2) = compute_ema_fee_revenue(2000, 1000, 100, &params, 1);
    // λ=700: EMA = 0.07 * 2000 + 0.93 * 1000 = 1070
    assert_eq!(ema2, 1070);
    assert_eq!(smoothed2, 107_000);
}
