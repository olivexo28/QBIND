//! Tests for per-validator equivocation metrics (T129) in qbind-node.
//!
//! These tests verify that the ValidatorEquivocationMetrics struct correctly tracks
//! per-validator equivocation events and integrates with NodeMetrics.

use qbind_consensus::ValidatorId;
use qbind_node::{NodeMetrics, ValidatorEquivocationMetrics, MAX_TRACKED_VALIDATORS};

// ============================================================================
// Tests: Basic ValidatorEquivocationMetrics Functionality
// ============================================================================

#[test]
fn equivocation_metrics_new_starts_empty() {
    let metrics = ValidatorEquivocationMetrics::new();
    assert_eq!(metrics.tracked_validator_count(), 0);
    assert_eq!(metrics.overflow_count(), 0);
}

#[test]
fn records_equivocation_for_new_validator() {
    let metrics = ValidatorEquivocationMetrics::new();

    metrics.on_validator_equivocation(ValidatorId(1), 0);

    assert_eq!(metrics.tracked_validator_count(), 1);
    assert_eq!(
        metrics.validator_equivocations_total(ValidatorId(1)),
        Some(1)
    );
    assert_eq!(metrics.validator_equivocating(ValidatorId(1)), Some(1));
}

#[test]
fn multiple_equivocations_increments_counter() {
    let metrics = ValidatorEquivocationMetrics::new();

    metrics.on_validator_equivocation(ValidatorId(1), 0);
    metrics.on_validator_equivocation(ValidatorId(1), 1);
    metrics.on_validator_equivocation(ValidatorId(1), 2);

    assert_eq!(
        metrics.validator_equivocations_total(ValidatorId(1)),
        Some(3)
    );
    // equivocating gauge remains 1 (once equivocated, stays 1)
    assert_eq!(metrics.validator_equivocating(ValidatorId(1)), Some(1));
}

#[test]
fn records_equivocations_for_multiple_validators() {
    let metrics = ValidatorEquivocationMetrics::new();

    metrics.on_validator_equivocation(ValidatorId(1), 0);
    metrics.on_validator_equivocation(ValidatorId(2), 0);
    metrics.on_validator_equivocation(ValidatorId(1), 1);

    assert_eq!(metrics.tracked_validator_count(), 2);
    assert_eq!(
        metrics.validator_equivocations_total(ValidatorId(1)),
        Some(2)
    );
    assert_eq!(
        metrics.validator_equivocations_total(ValidatorId(2)),
        Some(1)
    );
}

#[test]
fn non_equivocating_validators_not_tracked() {
    let metrics = ValidatorEquivocationMetrics::new();

    // Only add equivocation for validator 1
    metrics.on_validator_equivocation(ValidatorId(1), 0);

    // Validator 2 has no equivocations
    assert_eq!(metrics.validator_equivocations_total(ValidatorId(2)), None);
    assert_eq!(metrics.validator_equivocating(ValidatorId(2)), None);
}

#[test]
fn returns_none_for_unknown_validator() {
    let metrics = ValidatorEquivocationMetrics::new();

    assert_eq!(
        metrics.validator_equivocations_total(ValidatorId(999)),
        None
    );
    assert_eq!(metrics.validator_equivocating(ValidatorId(999)), None);
}

// ============================================================================
// Tests: Formatting
// ============================================================================

#[test]
fn format_metrics_empty_when_no_equivocations() {
    let metrics = ValidatorEquivocationMetrics::new();
    let output = metrics.format_metrics();

    assert!(output.contains("# Per-validator equivocation metrics (T129)"));
    // Should not contain any qbind_consensus_validator_equivocations_total lines
    assert!(!output.contains("qbind_consensus_validator_equivocations_total{"));
}

#[test]
fn format_metrics_includes_equivocating_validators() {
    let metrics = ValidatorEquivocationMetrics::new();

    metrics.on_validator_equivocation(ValidatorId(1), 5);
    metrics.on_validator_equivocation(ValidatorId(1), 10);
    metrics.on_validator_equivocation(ValidatorId(42), 3);

    let output = metrics.format_metrics();

    assert!(output.contains("qbind_consensus_validator_equivocations_total{validator=\"1\"} 2"));
    assert!(output.contains("qbind_consensus_validator_equivocating{validator=\"1\"} 1"));
    assert!(output.contains("qbind_consensus_validator_equivocations_total{validator=\"42\"} 1"));
    assert!(output.contains("qbind_consensus_validator_equivocating{validator=\"42\"} 1"));
}

#[test]
fn format_metrics_output_sorted_by_validator_id() {
    let metrics = ValidatorEquivocationMetrics::new();

    // Add validators out of order
    metrics.on_validator_equivocation(ValidatorId(3), 0);
    metrics.on_validator_equivocation(ValidatorId(1), 0);
    metrics.on_validator_equivocation(ValidatorId(2), 0);

    let output = metrics.format_metrics();

    // Validator 1 should appear before 2, and 2 before 3
    let pos_1 = output.find("validator=\"1\"").unwrap();
    let pos_2 = output.find("validator=\"2\"").unwrap();
    let pos_3 = output.find("validator=\"3\"").unwrap();

    assert!(pos_1 < pos_2, "Validator 1 should appear before 2");
    assert!(pos_2 < pos_3, "Validator 2 should appear before 3");
}

// ============================================================================
// Tests: Bounded Tracking
// ============================================================================

#[test]
fn respects_max_tracked_validators_limit() {
    let metrics = ValidatorEquivocationMetrics::new();

    // Add validators up to the limit
    for i in 0..MAX_TRACKED_VALIDATORS {
        metrics.on_validator_equivocation(ValidatorId(i as u64), 0);
    }

    assert_eq!(metrics.tracked_validator_count(), MAX_TRACKED_VALIDATORS);
    assert_eq!(metrics.overflow_count(), 0);

    // Adding more should increment overflow count
    metrics.on_validator_equivocation(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 1), 0);
    metrics.on_validator_equivocation(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 2), 0);

    assert_eq!(metrics.tracked_validator_count(), MAX_TRACKED_VALIDATORS);
    assert_eq!(metrics.overflow_count(), 2);
}

#[test]
fn overflow_shown_in_format_metrics() {
    let metrics = ValidatorEquivocationMetrics::new();

    // Fill up to max
    for i in 0..MAX_TRACKED_VALIDATORS {
        metrics.on_validator_equivocation(ValidatorId(i as u64), 0);
    }

    // Overflow
    metrics.on_validator_equivocation(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 100), 0);

    let output = metrics.format_metrics();
    assert!(output.contains("qbind_consensus_validator_equivocation_overflow_count 1"));
}

#[test]
fn existing_validator_still_tracked_after_overflow() {
    let metrics = ValidatorEquivocationMetrics::new();

    // Add one validator first
    metrics.on_validator_equivocation(ValidatorId(1), 0);

    // Fill up the rest
    for i in 2..=MAX_TRACKED_VALIDATORS {
        metrics.on_validator_equivocation(ValidatorId(i as u64), 0);
    }

    // Now adding new validators should overflow
    metrics.on_validator_equivocation(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 100), 0);
    assert_eq!(metrics.overflow_count(), 1);

    // But the original validator should still be tracked
    metrics.on_validator_equivocation(ValidatorId(1), 5);
    assert_eq!(
        metrics.validator_equivocations_total(ValidatorId(1)),
        Some(2)
    );
}

// ============================================================================
// Tests: Integration with NodeMetrics
// ============================================================================

#[test]
fn node_metrics_has_validator_equivocations() {
    let metrics = NodeMetrics::new();

    metrics
        .validator_equivocations()
        .on_validator_equivocation(ValidatorId(1), 0);

    assert_eq!(
        metrics
            .validator_equivocations()
            .validator_equivocations_total(ValidatorId(1)),
        Some(1)
    );
    assert_eq!(
        metrics
            .validator_equivocations()
            .validator_equivocating(ValidatorId(1)),
        Some(1)
    );
}

#[test]
fn node_metrics_format_includes_equivocation_metrics() {
    let metrics = NodeMetrics::new();

    metrics
        .validator_equivocations()
        .on_validator_equivocation(ValidatorId(1), 5);

    let output = metrics.format_metrics();

    assert!(output.contains("# Per-validator equivocation metrics (T129)"));
    assert!(output.contains("qbind_consensus_validator_equivocations_total{validator=\"1\"} 1"));
    assert!(output.contains("qbind_consensus_validator_equivocating{validator=\"1\"} 1"));
}

#[test]
fn validator_equivocation_metrics_default_impl() {
    let metrics: ValidatorEquivocationMetrics = Default::default();
    assert_eq!(metrics.tracked_validator_count(), 0);
    assert_eq!(metrics.overflow_count(), 0);
}
