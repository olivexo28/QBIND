//! T195: Monetary Engine v1 Tests
//!
//! This module contains comprehensive tests for the monetary engine, verifying:
//! - Basic correctness of inflation rate calculation
//! - PQC premium effects on target rate
//! - Fee offset monotonicity
//! - Floor and cap application
//! - Phase transition recommendations

use qbind_ledger::{
    compute_monetary_decision, MonetaryEngineConfig, MonetaryInputs, MonetaryPhase,
    PhaseParameters, PhaseTransitionRecommendation,
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
            r_target_annual: 0.05,       // 5% base
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

/// Returns default inputs in Bootstrap phase with zero fees.
fn test_inputs_bootstrap() -> MonetaryInputs {
    MonetaryInputs {
        phase: MonetaryPhase::Bootstrap,
        total_staked_tokens: 1_000_000.0,
        smoothed_annual_fee_revenue: 0.0,
        bonded_ratio: 0.3,
        fee_coverage_ratio: 0.2,
        fee_volatility: 2.5,
        days_since_launch: 100, // Early in Bootstrap
    }
}

/// Returns default inputs in Transition phase.
fn test_inputs_transition() -> MonetaryInputs {
    MonetaryInputs {
        phase: MonetaryPhase::Transition,
        total_staked_tokens: 1_000_000.0,
        smoothed_annual_fee_revenue: 0.0,
        bonded_ratio: 0.5,
        fee_coverage_ratio: 0.4,
        fee_volatility: 1.8,
        days_since_launch: 4 * 365, // In Transition period
    }
}

/// Returns default inputs in Mature phase.
fn test_inputs_mature() -> MonetaryInputs {
    MonetaryInputs {
        phase: MonetaryPhase::Mature,
        total_staked_tokens: 1_000_000.0,
        smoothed_annual_fee_revenue: 0.0,
        bonded_ratio: 0.6,
        fee_coverage_ratio: 0.7,
        fee_volatility: 1.0,
        days_since_launch: 10 * 365, // Well into Mature phase
    }
}

// ============================================================================
// Basic Correctness Tests
// ============================================================================

/// Test 1: When fees are zero, result should be ≈ effective_r_target (clamped by floor/cap).
#[test]
fn fees_zero_returns_r_target_or_floor() {
    let cfg = test_config();
    let inputs = test_inputs_bootstrap();

    let decision = compute_monetary_decision(&cfg, &inputs);

    // PQC multiplier = 1 + 0.30 + 0.15 + 0.10 = 1.55
    // Effective target = 0.05 * 1.55 = 0.0775
    let expected_effective_target = 0.05 * 1.55;
    assert!(
        (decision.effective_r_target_annual - expected_effective_target).abs() < 1e-9,
        "Expected effective_r_target ≈ {}, got {}",
        expected_effective_target,
        decision.effective_r_target_annual
    );

    // With zero fees and no floor in Bootstrap, r_inf should equal effective_r_target
    assert!(
        (decision.recommended_r_inf_annual - expected_effective_target).abs() < 1e-9,
        "Expected r_inf ≈ {}, got {}",
        expected_effective_target,
        decision.recommended_r_inf_annual
    );

    assert!(!decision.inflation_floor_applied);
    assert!(!decision.inflation_cap_applied);
}

/// Test 2: Increasing smoothed_annual_fee_revenue while holding everything else constant
/// must not increase r_inf (monotonically decreasing or constant).
#[test]
fn fees_increase_reduces_inflation_monotonically() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();

    let fee_levels: [f64; 5] = [0.0, 10_000.0, 20_000.0, 40_000.0, 80_000.0];
    let mut prev_r_inf = f64::MAX;

    for fee in fee_levels {
        inputs.smoothed_annual_fee_revenue = fee;
        let decision = compute_monetary_decision(&cfg, &inputs);

        assert!(
            decision.recommended_r_inf_annual <= prev_r_inf,
            "Inflation should not increase when fees increase: fee={}, r_inf={}, prev_r_inf={}",
            fee,
            decision.recommended_r_inf_annual,
            prev_r_inf
        );

        prev_r_inf = decision.recommended_r_inf_annual;
    }
}

/// Test 3: With PQC premiums turned on, effective_r_target must strictly exceed base target.
#[test]
fn pqc_premium_increases_effective_r_target() {
    // Config with no PQC premiums
    let cfg_no_pqc = MonetaryEngineConfig {
        pqc_premium_compute: 0.0,
        pqc_premium_bandwidth: 0.0,
        pqc_premium_storage: 0.0,
        ..test_config()
    };

    // Config with PQC premiums
    let cfg_with_pqc = test_config();

    let inputs = test_inputs_bootstrap();

    let decision_no_pqc = compute_monetary_decision(&cfg_no_pqc, &inputs);
    let decision_with_pqc = compute_monetary_decision(&cfg_with_pqc, &inputs);

    // Without PQC: effective_r_target = base_target = 0.05
    assert!(
        (decision_no_pqc.effective_r_target_annual - 0.05).abs() < 1e-9,
        "Expected effective_r_target = 0.05 without PQC, got {}",
        decision_no_pqc.effective_r_target_annual
    );

    // With PQC: effective_r_target = 0.05 * 1.55 = 0.0775
    assert!(
        decision_with_pqc.effective_r_target_annual > decision_no_pqc.effective_r_target_annual,
        "PQC premiums should increase effective_r_target: {} > {}",
        decision_with_pqc.effective_r_target_annual,
        decision_no_pqc.effective_r_target_annual
    );
}

// ============================================================================
// Floor & Cap Tests
// ============================================================================

/// Test 4: Floor is applied when r_raw is above zero but below floor.
#[test]
fn floor_applied_when_raw_above_zero_but_below_floor() {
    // Create a config where floor > effective_r_target after fee offset
    let cfg = MonetaryEngineConfig {
        pqc_premium_compute: 0.0,
        pqc_premium_bandwidth: 0.0,
        pqc_premium_storage: 0.0,
        bootstrap: PhaseParameters {
            r_target_annual: 0.015, // 1.5% base (low so fees can bring it below floor)
            inflation_floor_annual: 0.01, // 1% floor
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12,
            ema_lambda_bps: 700,
            max_delta_r_inf_per_epoch_bps: 25, // T203
        },
        ..test_config()
    };

    let mut inputs = test_inputs_bootstrap();
    // Set fees to reduce r_raw to ~0.5% (below floor but above 0)
    // r_raw = 0.015 - (1.0 * 10_000 / 1_000_000) = 0.015 - 0.01 = 0.005
    inputs.smoothed_annual_fee_revenue = 10_000.0;

    let decision = compute_monetary_decision(&cfg, &inputs);

    // r_raw = 0.005, floor = 0.01
    // Since r_raw >= 0 and r_raw < floor, floor should be applied
    assert_eq!(
        decision.recommended_r_inf_annual, 0.01,
        "Expected floor of 1%, got {}",
        decision.recommended_r_inf_annual
    );
    assert!(
        decision.inflation_floor_applied,
        "Floor should be applied when r_raw < floor and r_raw >= 0"
    );
    assert!(!decision.inflation_cap_applied);
}

/// Test 5: Cap is applied when r_raw exceeds cap.
#[test]
fn cap_applied_when_raw_above_cap() {
    // Create a config with high PQC premiums to push target above cap
    let cfg = MonetaryEngineConfig {
        pqc_premium_compute: 1.0,   // Very high
        pqc_premium_bandwidth: 0.5, // Very high
        pqc_premium_storage: 0.5,   // Very high
        bootstrap: PhaseParameters {
            r_target_annual: 0.08, // 8% base
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12, // 12% cap
            ema_lambda_bps: 700,
            max_delta_r_inf_per_epoch_bps: 25, // T203
        },
        ..test_config()
    };

    let inputs = test_inputs_bootstrap();

    // PQC multiplier = 1 + 1.0 + 0.5 + 0.5 = 3.0
    // Effective target = 0.08 * 3.0 = 0.24 (way above cap)
    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.recommended_r_inf_annual, 0.12,
        "Expected cap of 12%, got {}",
        decision.recommended_r_inf_annual
    );
    assert!(
        decision.inflation_cap_applied,
        "Cap should be applied when r_raw > cap"
    );
}

/// Test: When r_raw < 0, clamp to 0 (floor not applied)
#[test]
fn negative_raw_clamps_to_zero_floor_not_applied() {
    let cfg = test_config();
    let mut inputs = test_inputs_mature();

    // Set very high fees to drive r_raw negative
    // Effective target in Mature = 0.03 * 1.55 = 0.0465
    // Fee offset = 1.0 * (100_000 / 1_000_000) = 0.10
    // r_raw = 0.0465 - 0.10 = -0.0535 (negative)
    inputs.smoothed_annual_fee_revenue = 100_000.0;

    let decision = compute_monetary_decision(&cfg, &inputs);

    // Since r_raw < 0, clamp to 0 (floor is NOT applied because floor only applies when r_raw >= 0)
    assert_eq!(
        decision.recommended_r_inf_annual, 0.0,
        "Expected 0% when r_raw is negative, got {}",
        decision.recommended_r_inf_annual
    );
    assert!(
        !decision.inflation_floor_applied,
        "Floor should NOT be applied when r_raw < 0"
    );
}

/// Test: In Mature phase, floor is applied when r_raw is between 0 and floor
#[test]
fn mature_phase_floor_applied_correctly() {
    let cfg = test_config();
    let mut inputs = test_inputs_mature();

    // Set fees to bring r_raw just above 0 but below floor (1%)
    // Effective target in Mature = 0.03 * 1.55 = 0.0465
    // We want r_raw ≈ 0.005 (between 0 and 0.01 floor)
    // 0.005 = 0.0465 - (1.0 * fee / 1_000_000)
    // fee = (0.0465 - 0.005) * 1_000_000 = 41_500
    inputs.smoothed_annual_fee_revenue = 41_500.0;

    let decision = compute_monetary_decision(&cfg, &inputs);

    // r_raw should be around 0.005, which is below floor of 0.01
    assert_eq!(
        decision.recommended_r_inf_annual, 0.01,
        "Expected floor of 1% in Mature phase, got {}",
        decision.recommended_r_inf_annual
    );
    assert!(
        decision.inflation_floor_applied,
        "Floor should be applied in Mature phase when r_raw is above 0 but below floor"
    );
}

// ============================================================================
// Phase Transition Tests
// ============================================================================

/// Test 6: Bootstrap stays (HoldBack) when time condition is met but metrics are bad.
#[test]
fn bootstrap_stays_when_metrics_bad() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();

    // Time condition met (>= 3 years)
    inputs.days_since_launch = 4 * 365;

    // Bad metrics: low bonded ratio
    inputs.bonded_ratio = 0.2; // Below 0.5 threshold
    inputs.fee_coverage_ratio = 0.4; // Above 0.3 threshold
    inputs.fee_volatility = 1.5; // Below 2.0 threshold

    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::HoldBack,
        "Should recommend HoldBack when time is met but bonded_ratio is too low"
    );
}

/// Test: Bootstrap stays (Stay) when time condition is NOT met.
#[test]
fn bootstrap_stays_when_time_not_met() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();

    // Time condition NOT met
    inputs.days_since_launch = 2 * 365; // Less than 3 years

    // Good metrics
    inputs.bonded_ratio = 0.6;
    inputs.fee_coverage_ratio = 0.5;
    inputs.fee_volatility = 1.0;

    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::Stay,
        "Should recommend Stay when time condition is not met"
    );
}

/// Test 7: Bootstrap advances to Transition when all thresholds are satisfied.
#[test]
fn bootstrap_advances_to_transition_when_metrics_ok() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();

    // Time condition met
    inputs.days_since_launch = 3 * 365 + 1;

    // Good metrics
    inputs.bonded_ratio = 0.5; // >= 0.5
    inputs.fee_coverage_ratio = 0.3; // >= 0.3
    inputs.fee_volatility = 2.0; // <= 2.0

    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::Advance,
        "Should recommend Advance when all conditions are satisfied"
    );
}

/// Test: Transition holds back when metrics are not ready.
#[test]
fn transition_holdback_when_metrics_bad() {
    let cfg = test_config();
    let mut inputs = test_inputs_transition();

    // Time condition met (>= 7 years)
    inputs.days_since_launch = 8 * 365;

    // Bad metrics: fee_coverage too low
    inputs.bonded_ratio = 0.6; // >= 0.5
    inputs.fee_coverage_ratio = 0.4; // < 0.6 (threshold for Mature)
    inputs.fee_volatility = 1.0; // <= 1.5

    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::HoldBack,
        "Should recommend HoldBack when fee_coverage is too low for Mature"
    );
}

/// Test: Transition advances to Mature when all conditions are met.
#[test]
fn transition_advances_to_mature_when_metrics_ok() {
    let cfg = test_config();
    let mut inputs = test_inputs_transition();

    // Time condition met (>= 7 years)
    inputs.days_since_launch = 7 * 365;

    // Good metrics
    inputs.bonded_ratio = 0.5; // >= 0.5
    inputs.fee_coverage_ratio = 0.6; // >= 0.6
    inputs.fee_volatility = 1.5; // <= 1.5

    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::Advance,
        "Should recommend Advance to Mature when all conditions are satisfied"
    );
}

/// Test 8: From Mature phase, we never recommend Advance.
#[test]
fn mature_stays_when_at_top_phase() {
    let cfg = test_config();
    let inputs = test_inputs_mature();

    let decision = compute_monetary_decision(&cfg, &inputs);

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::Stay,
        "Should always Stay when already in Mature phase"
    );
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test: Zero staked tokens should not cause division by zero.
#[test]
fn zero_staked_tokens_handled_gracefully() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();
    inputs.total_staked_tokens = 0.0;
    inputs.smoothed_annual_fee_revenue = 1000.0;

    // Should not panic; fee offset should be 0
    let decision = compute_monetary_decision(&cfg, &inputs);

    // With zero stake, fee offset = 0, so r_inf = effective_r_target
    let expected = 0.05 * 1.55;
    assert!(
        (decision.recommended_r_inf_annual - expected).abs() < 1e-9,
        "Expected r_inf ≈ {} with zero stake, got {}",
        expected,
        decision.recommended_r_inf_annual
    );
}

/// Test: Very small staked tokens (near epsilon) handled.
#[test]
fn very_small_staked_tokens_handled() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();
    inputs.total_staked_tokens = 1e-15; // Very small
    inputs.smoothed_annual_fee_revenue = 1000.0;

    // Should not panic (might produce extreme fee offset but should be capped)
    let decision = compute_monetary_decision(&cfg, &inputs);

    // Result should be clamped to at least 0
    assert!(
        decision.recommended_r_inf_annual >= 0.0,
        "r_inf should never be negative"
    );
}

/// Test: Large fee revenue drives inflation to zero.
#[test]
fn large_fees_drive_inflation_to_zero() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();
    inputs.smoothed_annual_fee_revenue = 1_000_000.0; // 100% fee rate (fee = stake)

    let decision = compute_monetary_decision(&cfg, &inputs);

    // Fee offset = 1.0 * (1_000_000 / 1_000_000) = 1.0 (100%)
    // r_raw = 0.0775 - 1.0 = -0.9225 (very negative)
    // Clamped to 0
    assert_eq!(
        decision.recommended_r_inf_annual, 0.0,
        "Large fees should drive inflation to 0"
    );
}

/// Test: Different phases produce different inflation targets.
#[test]
fn different_phases_produce_different_targets() {
    let cfg = test_config();

    let decision_bootstrap = compute_monetary_decision(&cfg, &test_inputs_bootstrap());
    let decision_transition = compute_monetary_decision(&cfg, &test_inputs_transition());
    let decision_mature = compute_monetary_decision(&cfg, &test_inputs_mature());

    // PQC multiplier = 1.55 for all
    // Bootstrap: 0.05 * 1.55 = 0.0775
    // Transition: 0.04 * 1.55 = 0.062
    // Mature: 0.03 * 1.55 = 0.0465

    assert!(
        (decision_bootstrap.effective_r_target_annual - 0.0775).abs() < 1e-9,
        "Bootstrap effective target should be 0.0775"
    );
    assert!(
        (decision_transition.effective_r_target_annual - 0.062).abs() < 1e-9,
        "Transition effective target should be 0.062"
    );
    assert!(
        (decision_mature.effective_r_target_annual - 0.0465).abs() < 1e-9,
        "Mature effective target should be 0.0465"
    );
}

/// Test: Alpha fee offset coefficient scales fee impact.
#[test]
fn alpha_scales_fee_offset() {
    let cfg_low_alpha = MonetaryEngineConfig {
        alpha_fee_offset: 0.5, // Lower alpha
        ..test_config()
    };

    let cfg_high_alpha = MonetaryEngineConfig {
        alpha_fee_offset: 1.5, // Higher alpha
        ..test_config()
    };

    let mut inputs = test_inputs_bootstrap();
    inputs.smoothed_annual_fee_revenue = 20_000.0;

    let decision_low = compute_monetary_decision(&cfg_low_alpha, &inputs);
    let decision_high = compute_monetary_decision(&cfg_high_alpha, &inputs);

    // Higher alpha means stronger fee offset, thus lower inflation
    assert!(
        decision_low.recommended_r_inf_annual > decision_high.recommended_r_inf_annual,
        "Higher alpha should result in lower inflation: low_alpha_r_inf={} > high_alpha_r_inf={}",
        decision_low.recommended_r_inf_annual,
        decision_high.recommended_r_inf_annual
    );
}

// ============================================================================
// Monotonicity Tests
// ============================================================================

/// Test: Inflation is monotonically non-increasing with increasing fees.
#[test]
fn inflation_monotonic_with_fees() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();

    let mut prev_r_inf = f64::MAX;

    for fee in (0..=100).map(|i| i as f64 * 1000.0) {
        inputs.smoothed_annual_fee_revenue = fee;
        let decision = compute_monetary_decision(&cfg, &inputs);

        assert!(
            decision.recommended_r_inf_annual <= prev_r_inf,
            "Inflation should be monotonically non-increasing with fees: fee={}, r_inf={}, prev={}",
            fee,
            decision.recommended_r_inf_annual,
            prev_r_inf
        );

        prev_r_inf = decision.recommended_r_inf_annual;
    }
}

/// Test: Inflation is monotonically non-decreasing with increasing stake (given fixed fee revenue).
#[test]
fn inflation_monotonic_with_stake() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();
    inputs.smoothed_annual_fee_revenue = 50_000.0; // Fixed fee revenue

    let mut prev_r_inf = 0.0;

    for stake in (1..=10).map(|i| i as f64 * 200_000.0) {
        inputs.total_staked_tokens = stake;
        let decision = compute_monetary_decision(&cfg, &inputs);

        assert!(
            decision.recommended_r_inf_annual >= prev_r_inf,
            "Inflation should be non-decreasing with increasing stake: stake={}, r_inf={}, prev={}",
            stake,
            decision.recommended_r_inf_annual,
            prev_r_inf
        );

        prev_r_inf = decision.recommended_r_inf_annual;
    }
}

// ============================================================================
// Decision Field Tests
// ============================================================================

/// Test: All decision fields are populated correctly.
#[test]
fn decision_fields_populated() {
    let cfg = test_config();
    let inputs = test_inputs_bootstrap();

    let decision = compute_monetary_decision(&cfg, &inputs);

    // Verify all fields are reasonable
    assert!(
        decision.effective_r_target_annual > 0.0,
        "effective_r_target_annual should be positive"
    );
    assert!(
        decision.recommended_r_inf_annual >= 0.0,
        "recommended_r_inf_annual should be non-negative"
    );
    // inflation_floor_applied and inflation_cap_applied are boolean, always valid
    // phase_recommendation is an enum, always valid
}

/// Test: HoldBack is different from Stay.
#[test]
fn holdback_vs_stay_distinction() {
    let cfg = test_config();
    let mut inputs = test_inputs_bootstrap();

    // Time NOT met -> Stay
    inputs.days_since_launch = 100;
    let decision_stay = compute_monetary_decision(&cfg, &inputs);
    assert_eq!(
        decision_stay.phase_recommendation,
        PhaseTransitionRecommendation::Stay
    );

    // Time met but metrics bad -> HoldBack
    inputs.days_since_launch = 4 * 365;
    inputs.bonded_ratio = 0.1; // Too low
    let decision_holdback = compute_monetary_decision(&cfg, &inputs);
    assert_eq!(
        decision_holdback.phase_recommendation,
        PhaseTransitionRecommendation::HoldBack
    );

    // Verify they are distinct
    assert_ne!(
        PhaseTransitionRecommendation::Stay,
        PhaseTransitionRecommendation::HoldBack,
        "Stay and HoldBack should be distinct variants"
    );
}