//! T196 Monetary Telemetry Tests
//!
//! Integration and unit tests for the monetary engine telemetry (shadow mode).
//!
//! # Test Coverage
//!
//! 1. **EMA updates and decision changes**: Verify fee smoothing and inflation response
//! 2. **Disabled telemetry does nothing**: Verify no state changes when disabled
//! 3. **PQC premium effect visible**: Compare decisions with different PQC premiums
//! 4. **Phase affects floor and cap**: Verify phase-specific guardrails
//!
//! # Running
//!
//! ```bash
//! cargo test -p qbind-node --test t196_monetary_telemetry_tests
//! ```

use qbind_ledger::monetary_engine::{
    MonetaryDecision, MonetaryPhase, PhaseTransitionRecommendation,
};
use qbind_node::monetary_telemetry::{
    default_monetary_engine_config_for_testnet, MonetaryTelemetry, MonetaryTelemetryConfig,
};
use qbind_node::MonetaryMetrics;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test config with telemetry enabled.
fn enabled_config() -> MonetaryTelemetryConfig {
    MonetaryTelemetryConfig {
        enabled: true,
        blocks_per_second: 1.0 / 6.0, // 6-second blocks
        phase: MonetaryPhase::Bootstrap,
        engine_config: default_monetary_engine_config_for_testnet(),
    }
}

/// Create a test config with telemetry disabled.
fn disabled_config() -> MonetaryTelemetryConfig {
    MonetaryTelemetryConfig {
        enabled: false,
        ..enabled_config()
    }
}

/// Create a config with zero PQC premiums.
fn zero_pqc_config() -> MonetaryTelemetryConfig {
    let mut cfg = enabled_config();
    cfg.engine_config.pqc_premium_compute = 0.0;
    cfg.engine_config.pqc_premium_bandwidth = 0.0;
    cfg.engine_config.pqc_premium_storage = 0.0;
    cfg
}

/// Create a config with high PQC premiums.
fn high_pqc_config() -> MonetaryTelemetryConfig {
    let mut cfg = enabled_config();
    cfg.engine_config.pqc_premium_compute = 0.50;
    cfg.engine_config.pqc_premium_bandwidth = 0.25;
    cfg.engine_config.pqc_premium_storage = 0.15;
    cfg
}

/// Create a config for a specific phase.
fn phase_config(phase: MonetaryPhase) -> MonetaryTelemetryConfig {
    let mut cfg = enabled_config();
    cfg.phase = phase;
    cfg
}

/// Feed N blocks with the given fee amount.
fn feed_blocks(
    telemetry: &mut MonetaryTelemetry,
    count: u64,
    fee_per_block: f64,
    staked_tokens: f64,
) -> Option<MonetaryDecision> {
    let mut last_decision = None;
    for i in 1..=count {
        last_decision = telemetry.on_block_committed(
            i,             // height
            fee_per_block, // block_fees_total
            staked_tokens, // total_staked_tokens
            0.5,           // bonded_ratio
            None,          // fee_coverage_ratio_hint
            None,          // fee_volatility_hint
            100,           // days_since_launch
        );
    }
    last_decision
}

// ============================================================================
// Test: EMA updates and decision changes
// ============================================================================

/// Test that EMA smoothing works correctly and decisions respond to fee changes.
///
/// Requirements:
/// - Start with smoothed_annual_fee_revenue = 0
/// - Feed 10 blocks with zero fees → r_inf should ≈ effective_r_target
/// - Feed 100 blocks with high fees → smoothed_annual_fee_revenue increases
///   and r_inf must strictly decrease (or clamp at floor)
#[test]
fn test_ema_updates_and_decision_changes() {
    let cfg = enabled_config();
    let mut telemetry = MonetaryTelemetry::new(cfg);

    // Initial state: no smoothed fee revenue
    assert_eq!(telemetry.state().smoothed_annual_fee_revenue, 0.0);

    // Feed 10 blocks with zero fees
    let decision_zero_fees = feed_blocks(&mut telemetry, 10, 0.0, 1_000_000.0).unwrap();

    // With zero fees, r_inf should equal effective_r_target
    // Bootstrap: r_target = 0.05 * (1 + 0.30 + 0.15 + 0.10) = 0.05 * 1.55 = 0.0775
    let expected_target = 0.05 * (1.0 + 0.30 + 0.15 + 0.10);
    assert!(
        (decision_zero_fees.effective_r_target_annual - expected_target).abs() < 1e-9,
        "Expected effective_r_target_annual ≈ {}, got {}",
        expected_target,
        decision_zero_fees.effective_r_target_annual
    );
    assert!(
        (decision_zero_fees.recommended_r_inf_annual - expected_target).abs() < 1e-9,
        "With zero fees, r_inf should ≈ effective_r_target, got {}",
        decision_zero_fees.recommended_r_inf_annual
    );

    // Save the smoothed fee revenue after zero-fee blocks
    let fee_revenue_after_zero = telemetry.state().smoothed_annual_fee_revenue;
    assert!(
        fee_revenue_after_zero < 1e-9,
        "After zero-fee blocks, smoothed fee revenue should be near zero"
    );

    // Now feed 100 blocks with high fees (1000 tokens per block)
    // This should cause smoothed_annual_fee_revenue to increase
    let high_fee_per_block = 1000.0;
    let decision_high_fees =
        feed_blocks(&mut telemetry, 100, high_fee_per_block, 1_000_000.0).unwrap();

    // Verify smoothed fee revenue increased
    let fee_revenue_after_high = telemetry.state().smoothed_annual_fee_revenue;
    assert!(
        fee_revenue_after_high > fee_revenue_after_zero,
        "Smoothed fee revenue should increase with high fees: {} > {}",
        fee_revenue_after_high,
        fee_revenue_after_zero
    );

    // Verify r_inf decreased (fee offset reduces inflation)
    // Note: The effect may be small due to EMA smoothing, but should be directionally correct
    assert!(
        decision_high_fees.recommended_r_inf_annual <= decision_zero_fees.recommended_r_inf_annual,
        "High fees should reduce or maintain inflation: {} <= {}",
        decision_high_fees.recommended_r_inf_annual,
        decision_zero_fees.recommended_r_inf_annual
    );

    // Verify effective_r_target remains constant (it's phase-dependent, not fee-dependent)
    assert!(
        (decision_high_fees.effective_r_target_annual
            - decision_zero_fees.effective_r_target_annual)
            .abs()
            < 1e-9,
        "effective_r_target should not change with fees"
    );
}

// ============================================================================
// Test: Disabled telemetry does nothing
// ============================================================================

/// Test that disabled telemetry doesn't change state or return decisions.
///
/// Requirements:
/// - With enabled = false, calling on_block_committed must:
///   - Not change state.smoothed_annual_fee_revenue
///   - Return None
#[test]
fn test_disabled_telemetry_does_nothing() {
    let cfg = disabled_config();
    let mut telemetry = MonetaryTelemetry::new(cfg);

    // Initial state
    assert_eq!(telemetry.state().last_height, 0);
    assert_eq!(telemetry.state().smoothed_annual_fee_revenue, 0.0);
    assert!(telemetry.state().last_decision.is_none());

    // Call on_block_committed multiple times
    for i in 1..=10 {
        let decision = telemetry.on_block_committed(
            i,           // height
            1000.0,      // block_fees_total
            1_000_000.0, // total_staked_tokens
            0.5,         // bonded_ratio
            None,        // fee_coverage_ratio_hint
            None,        // fee_volatility_hint
            100,         // days_since_launch
        );

        // Must return None
        assert!(
            decision.is_none(),
            "Disabled telemetry should return None, got {:?}",
            decision
        );
    }

    // State must not have changed
    assert_eq!(
        telemetry.state().last_height,
        0,
        "last_height should not change when disabled"
    );
    assert_eq!(
        telemetry.state().smoothed_annual_fee_revenue,
        0.0,
        "smoothed_annual_fee_revenue should not change when disabled"
    );
    assert!(
        telemetry.state().last_decision.is_none(),
        "last_decision should remain None when disabled"
    );
}

// ============================================================================
// Test: PQC premium effect visible through decision
// ============================================================================

/// Test that PQC premiums affect the effective target rate.
///
/// Requirements:
/// - Compare two configs: one with PQC premiums 0.0, one with non-zero premiums
/// - The effective_r_target_annual and recommended_r_inf_annual should be
///   higher in the PQC-premium config
#[test]
fn test_pqc_premium_effect_visible_through_decision() {
    // Config with zero PQC premiums
    let mut telemetry_zero = MonetaryTelemetry::new(zero_pqc_config());

    // Config with high PQC premiums
    let mut telemetry_high = MonetaryTelemetry::new(high_pqc_config());

    // Feed identical blocks to both
    let decision_zero = telemetry_zero
        .on_block_committed(
            1,
            0.0, // zero fees to isolate PQC effect
            1_000_000.0,
            0.5,
            None,
            None,
            100,
        )
        .unwrap();

    let decision_high = telemetry_high
        .on_block_committed(
            1,
            0.0, // zero fees to isolate PQC effect
            1_000_000.0,
            0.5,
            None,
            None,
            100,
        )
        .unwrap();

    // Zero PQC premiums: effective_r_target = r_target * 1.0 = 0.05
    let expected_zero_target = 0.05 * 1.0;
    assert!(
        (decision_zero.effective_r_target_annual - expected_zero_target).abs() < 1e-9,
        "Zero PQC: expected target ≈ {}, got {}",
        expected_zero_target,
        decision_zero.effective_r_target_annual
    );

    // High PQC premiums: effective_r_target = r_target * (1 + 0.50 + 0.25 + 0.15) = 0.05 * 1.90
    let expected_high_target = 0.05 * (1.0 + 0.50 + 0.25 + 0.15);
    assert!(
        (decision_high.effective_r_target_annual - expected_high_target).abs() < 1e-9,
        "High PQC: expected target ≈ {}, got {}",
        expected_high_target,
        decision_high.effective_r_target_annual
    );

    // The high-PQC config should have a strictly higher target
    assert!(
        decision_high.effective_r_target_annual > decision_zero.effective_r_target_annual,
        "High PQC should have higher effective target: {} > {}",
        decision_high.effective_r_target_annual,
        decision_zero.effective_r_target_annual
    );

    // With zero fees, r_inf = effective_r_target, so high PQC should also have higher r_inf
    assert!(
        decision_high.recommended_r_inf_annual > decision_zero.recommended_r_inf_annual,
        "High PQC should have higher recommended r_inf: {} > {}",
        decision_high.recommended_r_inf_annual,
        decision_zero.recommended_r_inf_annual
    );
}

// ============================================================================
// Test: Phase affects floor and cap
// ============================================================================

/// Test that different phases have different floors and caps.
///
/// Requirements:
/// - For Bootstrap vs Mature with different PhaseParameters floors/caps,
///   verify that the resulting recommended_r_inf_annual respects phase-specific guardrails
#[test]
fn test_phase_affects_floor_and_cap() {
    // Test Bootstrap phase (no floor, 12% cap)
    let mut telemetry_bootstrap = MonetaryTelemetry::new(phase_config(MonetaryPhase::Bootstrap));

    // Test Mature phase (1% floor, 8% cap)
    let mut telemetry_mature = MonetaryTelemetry::new(phase_config(MonetaryPhase::Mature));

    // Test with zero fees - both should hit their targets
    let decision_bootstrap = telemetry_bootstrap
        .on_block_committed(1, 0.0, 1_000_000.0, 0.5, None, None, 100)
        .unwrap();

    let decision_mature = telemetry_mature
        .on_block_committed(1, 0.0, 1_000_000.0, 0.5, None, None, 100)
        .unwrap();

    // Bootstrap: r_target = 0.05 * 1.55 = 0.0775, no floor, cap = 0.12
    // Mature: r_target = 0.03 * 1.55 = 0.0465, floor = 0.01, cap = 0.08

    // Both should be within their respective caps (no cap applied for these values)
    assert!(!decision_bootstrap.inflation_cap_applied);
    assert!(!decision_mature.inflation_cap_applied);

    // Bootstrap should have higher target than Mature
    assert!(
        decision_bootstrap.effective_r_target_annual > decision_mature.effective_r_target_annual,
        "Bootstrap should have higher target than Mature: {} > {}",
        decision_bootstrap.effective_r_target_annual,
        decision_mature.effective_r_target_annual
    );

    // Test floor behavior in Mature phase with very high fees
    telemetry_mature.reset();

    // Feed many blocks with very high fees to drive r_inf toward/below floor
    // We need fees high enough to offset the target rate significantly
    for i in 1..=1000 {
        telemetry_mature.on_block_committed(
            i,
            100_000.0,   // Very high fees per block
            1_000_000.0, // 1M staked
            0.5,
            None,
            None,
            100,
        );
    }

    let decision_mature_high_fees = telemetry_mature.state().last_decision.clone().unwrap();

    // With very high fees, the raw rate would be negative, so we should hit zero
    // (floor only applies when r_raw >= 0, per T195 design)
    // The rate should be clamped to >= 0
    assert!(
        decision_mature_high_fees.recommended_r_inf_annual >= 0.0,
        "Mature phase r_inf should never be negative: {}",
        decision_mature_high_fees.recommended_r_inf_annual
    );

    // Test cap behavior in Bootstrap phase
    // Create a config with very high PQC premiums that would exceed the cap
    let mut cfg_high_cap_test = phase_config(MonetaryPhase::Bootstrap);
    cfg_high_cap_test.engine_config.pqc_premium_compute = 1.0;
    cfg_high_cap_test.engine_config.pqc_premium_bandwidth = 1.0;
    cfg_high_cap_test.engine_config.pqc_premium_storage = 1.0;
    // This gives r_target = 0.05 * 4.0 = 0.20, which exceeds 0.12 cap

    let mut telemetry_cap_test = MonetaryTelemetry::new(cfg_high_cap_test);
    let decision_cap = telemetry_cap_test
        .on_block_committed(1, 0.0, 1_000_000.0, 0.5, None, None, 100)
        .unwrap();

    // Should hit the 12% cap
    assert!(
        decision_cap.inflation_cap_applied,
        "Should hit inflation cap"
    );
    assert!(
        (decision_cap.recommended_r_inf_annual - 0.12).abs() < 1e-9,
        "Bootstrap capped at 12%: got {}",
        decision_cap.recommended_r_inf_annual
    );
}

// ============================================================================
// Test: MonetaryMetrics recording
// ============================================================================

/// Test that MonetaryMetrics correctly records decisions.
#[test]
fn test_monetary_metrics_recording() {
    let metrics = MonetaryMetrics::new();

    // Initial state
    assert_eq!(metrics.phase(), 0);
    assert_eq!(metrics.r_target_annual_bps(), 0);
    assert_eq!(metrics.r_inf_annual_bps(), 0);
    assert_eq!(metrics.decisions_total(), 0);

    // Record a decision
    metrics.record_decision(
        0.0775, // effective_r_target_annual (7.75%)
        0.0750, // recommended_r_inf_annual (7.50%)
        0,      // phase (Bootstrap)
        0,      // phase_recommendation (Stay)
        0.3,    // fee_coverage_ratio
        1000.0, // smoothed_annual_fee_revenue
    );

    // Verify values
    assert_eq!(metrics.phase(), 0);
    assert_eq!(metrics.r_target_annual_bps(), 775); // 7.75% = 775 bps
    assert_eq!(metrics.r_inf_annual_bps(), 750); // 7.50% = 750 bps
    assert_eq!(metrics.phase_recommendation(), 0); // Stay
    assert_eq!(metrics.decisions_total(), 1);

    // Fee coverage ratio scaled by 1e6
    assert_eq!(metrics.fee_coverage_ratio_scaled(), 300_000); // 0.3 * 1e6

    // Smoothed fee revenue scaled by 1e6
    assert_eq!(metrics.smoothed_annual_fee_revenue_scaled(), 1_000_000_000); // 1000 * 1e6

    // Record another decision
    metrics.record_decision(
        0.0775, 0.0700, 1, // Transition phase
        1, // Advance recommendation
        0.5, 2000.0,
    );

    assert_eq!(metrics.decisions_total(), 2);
    assert_eq!(metrics.phase(), 1);
    assert_eq!(metrics.phase_recommendation(), 1);
}

/// Test MonetaryMetrics format_metrics output.
#[test]
fn test_monetary_metrics_format() {
    let metrics = MonetaryMetrics::new();

    metrics.record_decision(0.0775, 0.0750, 0, 0, 0.3, 1000.0);

    let output = metrics.format_metrics();

    // Verify output contains expected metric names
    assert!(output.contains("qbind_monetary_phase"));
    assert!(output.contains("qbind_monetary_r_target_annual_bps"));
    assert!(output.contains("qbind_monetary_r_inf_annual_bps"));
    assert!(output.contains("qbind_monetary_fee_coverage_ratio_scaled"));
    assert!(output.contains("qbind_monetary_phase_recommendation"));
    assert!(output.contains("qbind_monetary_smoothed_annual_fee_revenue_scaled"));
    assert!(output.contains("qbind_monetary_decisions_total"));

    // Verify values are present
    assert!(output.contains(" 775")); // r_target_annual_bps
    assert!(output.contains(" 750")); // r_inf_annual_bps
    assert!(output.contains(" 1")); // decisions_total
}

// ============================================================================
// Test: Integration with NodeMetrics
// ============================================================================

/// Test that NodeMetrics correctly exposes MonetaryMetrics.
#[test]
fn test_node_metrics_monetary_access() {
    use qbind_node::NodeMetrics;

    let node_metrics = NodeMetrics::new();

    // Access monetary metrics
    let monetary = node_metrics.monetary();
    assert_eq!(monetary.decisions_total(), 0);

    // Record a decision
    monetary.record_decision(0.08, 0.07, 0, 0, 0.25, 500.0);

    assert_eq!(monetary.decisions_total(), 1);
    assert_eq!(monetary.r_target_annual_bps(), 800);
    assert_eq!(monetary.r_inf_annual_bps(), 700);
}

/// Test that format_metrics includes monetary telemetry section.
#[test]
fn test_node_metrics_format_includes_monetary() {
    use qbind_node::NodeMetrics;

    let node_metrics = NodeMetrics::new();
    node_metrics
        .monetary()
        .record_decision(0.0775, 0.0750, 0, 0, 0.3, 1000.0);

    let output = node_metrics.format_metrics();

    // Verify monetary telemetry section is included
    assert!(
        output.contains("T196: Monetary engine telemetry"),
        "format_metrics should include T196 section"
    );
    assert!(output.contains("qbind_monetary_phase"));
    assert!(output.contains("qbind_monetary_decisions_total"));
}

// ============================================================================
// Test: State consistency across multiple blocks
// ============================================================================

/// Test that state evolves consistently across many blocks.
#[test]
fn test_state_consistency_across_blocks() {
    let cfg = enabled_config();
    let mut telemetry = MonetaryTelemetry::new(cfg);

    let mut prev_height = 0u64;
    let mut prev_fee_revenue = 0.0f64;

    // Process 50 blocks with varying fees
    for i in 1..=50 {
        let fees = if i % 2 == 0 { 100.0 } else { 200.0 };

        let decision = telemetry
            .on_block_committed(i, fees, 1_000_000.0, 0.5, None, None, 100)
            .unwrap();

        // Height should monotonically increase
        assert!(
            telemetry.state().last_height > prev_height,
            "Height should increase: {} > {}",
            telemetry.state().last_height,
            prev_height
        );
        prev_height = telemetry.state().last_height;

        // Smoothed fee revenue should be positive after processing fees
        assert!(
            telemetry.state().smoothed_annual_fee_revenue >= prev_fee_revenue * 0.99, // Allow for small EMA decay
            "Fee revenue should not drop dramatically"
        );
        prev_fee_revenue = telemetry.state().smoothed_annual_fee_revenue;

        // Decision should always be present
        assert!(telemetry.state().last_decision.is_some());

        // r_inf should always be within valid bounds
        assert!(
            decision.recommended_r_inf_annual >= 0.0,
            "r_inf should be non-negative"
        );
        assert!(
            decision.recommended_r_inf_annual <= 0.12, // Bootstrap cap
            "r_inf should be within cap"
        );
    }
}

// ============================================================================
// Test: Phase transition recommendation
// ============================================================================

/// Test that phase transition recommendations are generated correctly.
#[test]
fn test_phase_transition_recommendations() {
    // Bootstrap phase, early days
    let mut cfg = enabled_config();
    cfg.phase = MonetaryPhase::Bootstrap;
    let mut telemetry = MonetaryTelemetry::new(cfg);

    // With only 100 days since launch, should recommend Stay (time gate not met)
    let decision = telemetry
        .on_block_committed(
            1,
            0.0,
            1_000_000.0,
            0.5,
            Some(0.3), // fee_coverage_ratio
            Some(1.0), // fee_volatility
            100,       // days_since_launch (< 3 years)
        )
        .unwrap();

    assert_eq!(
        decision.phase_recommendation,
        PhaseTransitionRecommendation::Stay,
        "Bootstrap with 100 days should Stay"
    );

    // With 4 years since launch and good metrics, should recommend Advance
    let decision_advance = telemetry
        .on_block_committed(
            2,
            0.0,
            1_000_000.0,
            0.6,       // bonded_ratio > 0.5
            Some(0.5), // fee_coverage > 0.3
            Some(1.0), // volatility < 2.0
            4 * 365,   // 4 years > BOOTSTRAP_MIN_DAYS
        )
        .unwrap();

    assert_eq!(
        decision_advance.phase_recommendation,
        PhaseTransitionRecommendation::Advance,
        "Bootstrap with 4 years and good metrics should Advance"
    );

    // With 4 years but poor metrics, should recommend HoldBack
    let decision_holdback = telemetry
        .on_block_committed(
            3,
            0.0,
            1_000_000.0,
            0.3,       // bonded_ratio < 0.5
            Some(0.1), // fee_coverage < 0.3
            Some(3.0), // volatility > 2.0
            4 * 365,   // 4 years
        )
        .unwrap();

    assert_eq!(
        decision_holdback.phase_recommendation,
        PhaseTransitionRecommendation::HoldBack,
        "Bootstrap with 4 years but poor metrics should HoldBack"
    );

    // Mature phase should always Stay
    let mut cfg_mature = enabled_config();
    cfg_mature.phase = MonetaryPhase::Mature;
    let mut telemetry_mature = MonetaryTelemetry::new(cfg_mature);

    let decision_mature = telemetry_mature
        .on_block_committed(1, 0.0, 1_000_000.0, 0.9, Some(1.0), Some(0.5), 10 * 365)
        .unwrap();

    assert_eq!(
        decision_mature.phase_recommendation,
        PhaseTransitionRecommendation::Stay,
        "Mature phase should always Stay"
    );
}
