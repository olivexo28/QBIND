//! T204: Phase Transition Logic Tests
//!
//! This module contains comprehensive tests for the phase transition logic
//! implemented in T204, verifying:
//!
//! - **Time gates**: No early transition before epoch thresholds
//! - **Economic gates**: Fee coverage and stake ratio requirements
//! - **Bootstrap → Transition**: All gates satisfied
//! - **Transition → Mature**: All gates satisfied
//! - **Monotonicity**: Phase never goes backwards, never skips
//! - **Terminal behavior**: Mature phase stays Mature
//! - **Determinism**: Same inputs yield identical outcomes

use qbind_ledger::{
    compute_epoch_state, compute_fee_coverage_ratio_bps, compute_phase_transition,
    compute_stake_ratio_bps, MonetaryEngineConfig, MonetaryEpochInputs, MonetaryPhase,
    PhaseParameters, PhaseTransitionReason, EPOCHS_PER_YEAR_10_MIN, EPOCH_MATURE_START,
    EPOCH_TRANSITION_START, FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS,
    FEE_COVERAGE_TRANSITION_TO_MATURE_BPS, STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS,
    STAKE_RATIO_TRANSITION_TO_MATURE_BPS,
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
            max_annual_inflation_cap: 0.12,    // 12% cap
            ema_lambda_bps: 700,               // T202: 7% EMA factor
            max_delta_r_inf_per_epoch_bps: 25, // T203: 0.25% max change per epoch
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,       // 4% base
            inflation_floor_annual: 0.0, // no floor in Transition
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10,    // 10% cap
            ema_lambda_bps: 300,               // T202: 3% EMA factor
            max_delta_r_inf_per_epoch_bps: 10, // T203: 0.10% max change per epoch
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,        // 3% base
            inflation_floor_annual: 0.01, // 1% floor in Mature
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08,   // 8% cap
            ema_lambda_bps: 150,              // T202: 1.5% EMA factor
            max_delta_r_inf_per_epoch_bps: 5, // T203: 0.05% max change per epoch
        },
        alpha_fee_offset: 1.0,
    }
}

/// Returns default inputs for Bootstrap phase.
#[allow(dead_code)]
fn default_bootstrap_inputs() -> MonetaryEpochInputs {
    MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 0,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 1_000_000,
        circulating_supply: 10_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.1,
        days_since_launch: 0,
        fee_volatility: 1.0,
        epochs_per_year: 100, // Simple: 100 epochs per year for testing
        prev_r_inf_annual_bps: None,
    }
}

// ============================================================================
// Test 1: Constant Verification
// ============================================================================

#[test]
fn test_epoch_constants_are_correct() {
    // Verify the constants match the design doc
    assert_eq!(EPOCHS_PER_YEAR_10_MIN, 52_560);
    assert_eq!(EPOCH_TRANSITION_START, 3 * 52_560); // 157,680
    assert_eq!(EPOCH_MATURE_START, 7 * 52_560); // 367,920

    // Verify thresholds
    assert_eq!(FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS, 2000); // 20%
    assert_eq!(STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS, 3000); // 30%
    assert_eq!(FEE_COVERAGE_TRANSITION_TO_MATURE_BPS, 5000); // 50%
    assert_eq!(STAKE_RATIO_TRANSITION_TO_MATURE_BPS, 4000); // 40%
}

// ============================================================================
// Test 2: No Early Transition Before Time Gates
// ============================================================================

#[test]
fn test_no_early_transition_before_time_gates_bootstrap() {
    // Bootstrap, epoch_index < EPOCH_TRANSITION_START, metrics all "perfect"
    // Should stay in Bootstrap
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START - 1, // Just before threshold
        10000,                      // 100% fee coverage (perfect)
        10000,                      // 100% stake ratio (perfect)
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Bootstrap);
    assert_eq!(outcome.reason, PhaseTransitionReason::TimeGateNotMet);
}

#[test]
fn test_no_early_transition_before_time_gates_transition() {
    // Transition, epoch_index < EPOCH_MATURE_START, metrics all "perfect"
    // Should stay in Transition
    let outcome = compute_phase_transition(
        MonetaryPhase::Transition,
        EPOCH_MATURE_START - 1, // Just before threshold
        10000,                  // 100% fee coverage (perfect)
        10000,                  // 100% stake ratio (perfect)
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    assert_eq!(outcome.reason, PhaseTransitionReason::TimeGateNotMet);
}

#[test]
fn test_epoch_zero_stays_bootstrap() {
    // Epoch 0 should definitely stay in Bootstrap
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        0,     // Epoch 0
        10000, // Perfect metrics
        10000,
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Bootstrap);
    assert_eq!(outcome.reason, PhaseTransitionReason::TimeGateNotMet);
}

// ============================================================================
// Test 3: Bootstrap → Transition When All Gates Satisfied
// ============================================================================

#[test]
fn test_bootstrap_to_transition_all_gates_satisfied() {
    // epoch_index >= EPOCH_TRANSITION_START, coverage >= 0.20, stake >= 0.30
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START, // Exactly at threshold
        2500,                   // 25% fee coverage (>= 20%)
        3500,                   // 35% stake ratio (>= 30%)
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    assert_eq!(
        outcome.reason,
        PhaseTransitionReason::AdvancedBootstrapToTransition
    );
}

#[test]
fn test_bootstrap_to_transition_exactly_at_thresholds() {
    // Exactly at the economic thresholds
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START,
        FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS, // Exactly 20%
        STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS,  // Exactly 30%
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    assert_eq!(
        outcome.reason,
        PhaseTransitionReason::AdvancedBootstrapToTransition
    );
}

#[test]
fn test_bootstrap_stays_when_fee_coverage_too_low() {
    // Fee coverage just below threshold
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START,
        FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS - 1, // Just below 20%
        STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS,      // Exactly 30%
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Bootstrap);
    assert_eq!(outcome.reason, PhaseTransitionReason::EconomicGatesNotMet);
}

#[test]
fn test_bootstrap_stays_when_stake_ratio_too_low() {
    // Stake ratio just below threshold
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START,
        FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS, // Exactly 20%
        STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS - 1, // Just below 30%
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Bootstrap);
    assert_eq!(outcome.reason, PhaseTransitionReason::EconomicGatesNotMet);
}

#[test]
fn test_bootstrap_stays_when_both_below_threshold() {
    // Both metrics below threshold
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START,
        1000, // 10% fee coverage (< 20%)
        2000, // 20% stake ratio (< 30%)
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Bootstrap);
    assert_eq!(outcome.reason, PhaseTransitionReason::EconomicGatesNotMet);
}

// ============================================================================
// Test 4: Transition → Mature When All Gates Satisfied
// ============================================================================

#[test]
fn test_transition_to_mature_all_gates_satisfied() {
    // epoch_index >= EPOCH_MATURE_START, coverage >= 0.50, stake >= 0.40
    let outcome = compute_phase_transition(
        MonetaryPhase::Transition,
        EPOCH_MATURE_START, // Exactly at threshold
        6000,               // 60% fee coverage (>= 50%)
        5000,               // 50% stake ratio (>= 40%)
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Mature);
    assert_eq!(
        outcome.reason,
        PhaseTransitionReason::AdvancedTransitionToMature
    );
}

#[test]
fn test_transition_to_mature_exactly_at_thresholds() {
    // Exactly at the economic thresholds
    let outcome = compute_phase_transition(
        MonetaryPhase::Transition,
        EPOCH_MATURE_START,
        FEE_COVERAGE_TRANSITION_TO_MATURE_BPS, // Exactly 50%
        STAKE_RATIO_TRANSITION_TO_MATURE_BPS,  // Exactly 40%
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Mature);
    assert_eq!(
        outcome.reason,
        PhaseTransitionReason::AdvancedTransitionToMature
    );
}

#[test]
fn test_transition_stays_when_fee_coverage_too_low() {
    // Fee coverage just below threshold
    let outcome = compute_phase_transition(
        MonetaryPhase::Transition,
        EPOCH_MATURE_START,
        FEE_COVERAGE_TRANSITION_TO_MATURE_BPS - 1, // Just below 50%
        STAKE_RATIO_TRANSITION_TO_MATURE_BPS,      // Exactly 40%
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    assert_eq!(outcome.reason, PhaseTransitionReason::EconomicGatesNotMet);
}

#[test]
fn test_transition_stays_when_stake_ratio_too_low() {
    // Stake ratio just below threshold
    let outcome = compute_phase_transition(
        MonetaryPhase::Transition,
        EPOCH_MATURE_START,
        FEE_COVERAGE_TRANSITION_TO_MATURE_BPS,    // Exactly 50%
        STAKE_RATIO_TRANSITION_TO_MATURE_BPS - 1, // Just below 40%
    );

    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    assert_eq!(outcome.reason, PhaseTransitionReason::EconomicGatesNotMet);
}

// ============================================================================
// Test 5: Monotonicity - No Backwards Transitions
// ============================================================================

#[test]
fn test_transition_never_returns_to_bootstrap() {
    // Once in Transition, no combination of metrics ever returns to Bootstrap
    // Even with zero metrics
    let outcome = compute_phase_transition(
        MonetaryPhase::Transition,
        0, // Very early epoch
        0, // Zero fee coverage
        0, // Zero stake ratio
    );

    // Should stay in Transition, not go back to Bootstrap
    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    // Time gate for Mature not met
    assert_eq!(outcome.reason, PhaseTransitionReason::TimeGateNotMet);
}

#[test]
fn test_mature_never_returns_to_transition() {
    // Once in Mature, no combination of metrics ever returns to Transition
    let outcome = compute_phase_transition(
        MonetaryPhase::Mature,
        0, // Very early epoch
        0, // Zero fee coverage
        0, // Zero stake ratio
    );

    // Should stay in Mature
    assert_eq!(outcome.next_phase, MonetaryPhase::Mature);
    assert_eq!(outcome.reason, PhaseTransitionReason::None);
}

#[test]
fn test_mature_stays_mature_with_any_metrics() {
    // Mature phase with various metric combinations
    let test_cases = vec![
        (0, 0),         // Zero metrics
        (10000, 10000), // Perfect metrics
        (5000, 5000),   // Medium metrics
        (100, 100),     // Low metrics
    ];

    for (fee_coverage, stake_ratio) in test_cases {
        let outcome = compute_phase_transition(
            MonetaryPhase::Mature,
            EPOCH_MATURE_START + 100,
            fee_coverage,
            stake_ratio,
        );

        assert_eq!(
            outcome.next_phase,
            MonetaryPhase::Mature,
            "Mature phase should stay Mature with fee_coverage={}, stake_ratio={}",
            fee_coverage,
            stake_ratio
        );
        assert_eq!(outcome.reason, PhaseTransitionReason::None);
    }
}

// ============================================================================
// Test 6: No Phase Skipping (Bootstrap → Mature directly is impossible)
// ============================================================================

#[test]
fn test_cannot_skip_transition_phase() {
    // Bootstrap with all metrics perfect and epoch at MATURE threshold
    // Should only advance to Transition, not directly to Mature
    let outcome = compute_phase_transition(
        MonetaryPhase::Bootstrap,
        EPOCH_MATURE_START, // At Mature threshold, but still in Bootstrap
        10000,              // Perfect fee coverage
        10000,              // Perfect stake ratio
    );

    // Should advance to Transition, not Mature
    assert_eq!(outcome.next_phase, MonetaryPhase::Transition);
    assert_eq!(
        outcome.reason,
        PhaseTransitionReason::AdvancedBootstrapToTransition
    );
}

// ============================================================================
// Test 7: Terminal Behavior - Mature Stays Mature
// ============================================================================

#[test]
fn test_mature_is_terminal_at_various_epochs() {
    let test_epochs = vec![
        0,
        EPOCH_TRANSITION_START,
        EPOCH_MATURE_START,
        EPOCH_MATURE_START + 1_000_000,
        u64::MAX - 1,
    ];

    for epoch in test_epochs {
        let outcome = compute_phase_transition(
            MonetaryPhase::Mature,
            epoch,
            5000, // Some metrics
            5000,
        );

        assert_eq!(
            outcome.next_phase,
            MonetaryPhase::Mature,
            "Mature should stay Mature at epoch {}",
            epoch
        );
    }
}

// ============================================================================
// Test 8: Determinism - Same Inputs Yield Identical Outcomes
// ============================================================================

#[test]
fn test_determinism_bootstrap() {
    let inputs = (
        MonetaryPhase::Bootstrap,
        EPOCH_TRANSITION_START + 100,
        2500u32,
        3500u32,
    );

    let outcome1 = compute_phase_transition(inputs.0, inputs.1, inputs.2, inputs.3);
    let outcome2 = compute_phase_transition(inputs.0, inputs.1, inputs.2, inputs.3);
    let outcome3 = compute_phase_transition(inputs.0, inputs.1, inputs.2, inputs.3);

    assert_eq!(outcome1, outcome2);
    assert_eq!(outcome2, outcome3);
}

#[test]
fn test_determinism_transition() {
    let inputs = (
        MonetaryPhase::Transition,
        EPOCH_MATURE_START + 100,
        6000u32,
        5000u32,
    );

    let outcome1 = compute_phase_transition(inputs.0, inputs.1, inputs.2, inputs.3);
    let outcome2 = compute_phase_transition(inputs.0, inputs.1, inputs.2, inputs.3);
    let outcome3 = compute_phase_transition(inputs.0, inputs.1, inputs.2, inputs.3);

    assert_eq!(outcome1, outcome2);
    assert_eq!(outcome2, outcome3);
}

// ============================================================================
// Test 9: Helper Functions
// ============================================================================

#[test]
fn test_compute_stake_ratio_bps() {
    // 30% staked
    assert_eq!(compute_stake_ratio_bps(3_000_000, 10_000_000), 3000);

    // 50% staked
    assert_eq!(compute_stake_ratio_bps(5_000_000, 10_000_000), 5000);

    // 100% staked
    assert_eq!(compute_stake_ratio_bps(10_000_000, 10_000_000), 10000);

    // 0% staked
    assert_eq!(compute_stake_ratio_bps(0, 10_000_000), 0);

    // Zero circulating supply
    assert_eq!(compute_stake_ratio_bps(1_000_000, 0), 0);

    // More staked than circulating (impossible but should cap at 100%)
    assert_eq!(compute_stake_ratio_bps(15_000_000, 10_000_000), 10000);
}

#[test]
fn test_compute_fee_coverage_ratio_bps() {
    // 25% fee coverage: fees = 25, budget = 1000 * 0.10 = 100
    assert_eq!(compute_fee_coverage_ratio_bps(25, 1000, 0.10), 2500);

    // 100% fee coverage
    assert_eq!(compute_fee_coverage_ratio_bps(100, 1000, 0.10), 10000);

    // 50% fee coverage
    assert_eq!(compute_fee_coverage_ratio_bps(50, 1000, 0.10), 5000);

    // Zero stake
    assert_eq!(compute_fee_coverage_ratio_bps(100, 0, 0.10), 0);

    // Zero r_target
    assert_eq!(compute_fee_coverage_ratio_bps(100, 1000, 0.0), 0);

    // Very small r_target (below MIN_R_TARGET)
    assert_eq!(compute_fee_coverage_ratio_bps(100, 1000, 0.00001), 0);
}

// ============================================================================
// Test 10: Integration with compute_epoch_state
// ============================================================================

#[test]
fn test_epoch_state_includes_phase_transition_fields() {
    let config = test_config();
    let inputs = MonetaryEpochInputs {
        epoch_index: 0,
        raw_epoch_fees: 0, // Zero fees to ensure positive inflation rate
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 1_000_000,
        circulating_supply: 10_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.1,
        days_since_launch: 0,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };

    let state = compute_epoch_state(&config, &inputs);

    // Verify T204 fields are populated
    assert_eq!(state.phase, MonetaryPhase::Bootstrap); // No transition at epoch 0
    assert_eq!(state.phase_prev, MonetaryPhase::Bootstrap);
    assert!(!state.phase_transition_applied);
    assert_eq!(state.stake_ratio_bps, 1000); // 10% = 1000 bps
                                             // fee_coverage_ratio_bps can be 0 if fees are 0
                                             // r_inf_annual_bps should be the target rate (775 bps for 7.75%) when no fee offset
    assert!(
        state.r_inf_annual_bps > 0,
        "r_inf_annual_bps should be > 0 when no fee offset, got {}",
        state.r_inf_annual_bps
    );
}

#[test]
fn test_epoch_state_transition_applied() {
    let config = test_config();

    // Create inputs that would trigger a Bootstrap → Transition transition
    let inputs = MonetaryEpochInputs {
        epoch_index: EPOCH_TRANSITION_START,
        raw_epoch_fees: 100_000_000, // High fees for good coverage
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 100_000_000,
        staked_supply: 5_000_000, // 50% staked (> 30% threshold)
        circulating_supply: 10_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 3 * 365, // 3 years
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(500),
    };

    let state = compute_epoch_state(&config, &inputs);

    // Check stake ratio meets threshold
    assert!(
        state.stake_ratio_bps >= STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS,
        "Stake ratio {} should be >= {}",
        state.stake_ratio_bps,
        STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS
    );

    // If both gates are met, transition should occur
    if state.fee_coverage_ratio_bps >= FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS {
        assert_eq!(state.phase, MonetaryPhase::Transition);
        assert_eq!(state.phase_prev, MonetaryPhase::Bootstrap);
        assert!(state.phase_transition_applied);
    }
}

#[test]
fn test_epoch_state_no_transition_before_time_gate() {
    let config = test_config();

    // Create inputs with great metrics but before time gate
    let inputs = MonetaryEpochInputs {
        epoch_index: EPOCH_TRANSITION_START - 1, // Just before threshold
        raw_epoch_fees: 100_000_000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 100_000_000,
        staked_supply: 5_000_000,
        circulating_supply: 10_000_000,
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.5,
        days_since_launch: 3 * 365 - 1,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: Some(500),
    };

    let state = compute_epoch_state(&config, &inputs);

    // Should stay in Bootstrap because time gate not met
    assert_eq!(state.phase, MonetaryPhase::Bootstrap);
    assert_eq!(state.phase_prev, MonetaryPhase::Bootstrap);
    assert!(!state.phase_transition_applied);
}

// ============================================================================
// Test 11: Edge Cases
// ============================================================================

#[test]
fn test_zero_circulating_supply() {
    let config = test_config();
    let inputs = MonetaryEpochInputs {
        epoch_index: EPOCH_TRANSITION_START,
        raw_epoch_fees: 1000,
        previous_smoothed_annual_fee_revenue: 0,
        previous_ema_fees_per_epoch: 0,
        staked_supply: 0,
        circulating_supply: 0, // Edge case
        phase: MonetaryPhase::Bootstrap,
        bonded_ratio: 0.0,
        days_since_launch: 1000,
        fee_volatility: 1.0,
        epochs_per_year: 100,
        prev_r_inf_annual_bps: None,
    };

    let state = compute_epoch_state(&config, &inputs);

    // Should handle zero circulating supply gracefully
    assert_eq!(state.stake_ratio_bps, 0);
    // Should stay in Bootstrap (economic gates not met)
    assert_eq!(state.phase, MonetaryPhase::Bootstrap);
}

#[test]
fn test_maximum_epoch_values() {
    // Test with very large epoch values
    let outcome = compute_phase_transition(MonetaryPhase::Transition, u64::MAX - 1, 10000, 10000);

    // Should advance to Mature since time gate is definitely met
    assert_eq!(outcome.next_phase, MonetaryPhase::Mature);
}

#[test]
fn test_large_supply_values() {
    // Test with large supply values that might overflow
    let staked = 1_000_000_000_000_000_000u128; // 10^18
    let circulating = 10_000_000_000_000_000_000u128; // 10^19

    let ratio = compute_stake_ratio_bps(staked, circulating);
    assert_eq!(ratio, 1000); // 10%
}
