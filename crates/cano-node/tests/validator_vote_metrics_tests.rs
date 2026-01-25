//! Tests for per-validator vote metrics (T128) in cano-node.
//!
//! These tests verify that the ValidatorVoteMetrics struct correctly tracks
//! per-validator vote participation and integrates with NodeMetrics.

use cano_consensus::ValidatorId;
use cano_node::{NodeMetrics, ValidatorVoteMetrics, MAX_TRACKED_VALIDATORS};

// ============================================================================
// Tests: Basic ValidatorVoteMetrics Functionality
// ============================================================================

#[test]
fn validator_vote_metrics_new_starts_empty() {
    let metrics = ValidatorVoteMetrics::new();
    assert_eq!(metrics.tracked_validator_count(), 0);
    assert_eq!(metrics.overflow_count(), 0);
}

#[test]
fn records_vote_for_new_validator() {
    let metrics = ValidatorVoteMetrics::new();

    metrics.on_validator_vote(ValidatorId(1), 0);

    assert_eq!(metrics.tracked_validator_count(), 1);
    assert_eq!(metrics.validator_votes_total(ValidatorId(1)), Some(1));
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(1)), Some(0));
}

#[test]
fn records_multiple_votes_for_same_validator() {
    let metrics = ValidatorVoteMetrics::new();

    metrics.on_validator_vote(ValidatorId(1), 0);
    metrics.on_validator_vote(ValidatorId(1), 1);
    metrics.on_validator_vote(ValidatorId(1), 2);

    assert_eq!(metrics.validator_votes_total(ValidatorId(1)), Some(3));
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(1)), Some(2));
}

#[test]
fn records_votes_for_multiple_validators() {
    let metrics = ValidatorVoteMetrics::new();

    metrics.on_validator_vote(ValidatorId(1), 0);
    metrics.on_validator_vote(ValidatorId(2), 0);
    metrics.on_validator_vote(ValidatorId(3), 1);
    metrics.on_validator_vote(ValidatorId(1), 2);

    assert_eq!(metrics.tracked_validator_count(), 3);
    assert_eq!(metrics.validator_votes_total(ValidatorId(1)), Some(2));
    assert_eq!(metrics.validator_votes_total(ValidatorId(2)), Some(1));
    assert_eq!(metrics.validator_votes_total(ValidatorId(3)), Some(1));
}

#[test]
fn last_vote_view_is_monotonic() {
    let metrics = ValidatorVoteMetrics::new();

    // Increasing views should update
    metrics.on_validator_vote(ValidatorId(1), 0);
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(1)), Some(0));

    metrics.on_validator_vote(ValidatorId(1), 5);
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(1)), Some(5));

    metrics.on_validator_vote(ValidatorId(1), 10);
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(1)), Some(10));

    // Lower view should NOT update last_vote_view (monotonic)
    metrics.on_validator_vote(ValidatorId(1), 3);
    assert_eq!(
        metrics.validator_last_vote_view(ValidatorId(1)),
        Some(10),
        "Lower view should not update"
    );

    // But votes_total should still increment
    assert_eq!(metrics.validator_votes_total(ValidatorId(1)), Some(4));
}

#[test]
fn returns_none_for_unknown_validator() {
    let metrics = ValidatorVoteMetrics::new();

    assert_eq!(metrics.validator_votes_total(ValidatorId(999)), None);
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(999)), None);
}

// ============================================================================
// Tests: Formatting
// ============================================================================

#[test]
fn format_metrics_empty_when_no_votes() {
    let metrics = ValidatorVoteMetrics::new();
    let output = metrics.format_metrics();

    assert!(output.contains("# Per-validator vote metrics (T128)"));
    // Should not contain any cano_consensus_validator_votes_total lines
    assert!(!output.contains("cano_consensus_validator_votes_total{"));
}

#[test]
fn format_metrics_includes_validators_with_votes() {
    let metrics = ValidatorVoteMetrics::new();

    metrics.on_validator_vote(ValidatorId(1), 5);
    metrics.on_validator_vote(ValidatorId(1), 10);
    metrics.on_validator_vote(ValidatorId(42), 3);

    let output = metrics.format_metrics();

    assert!(output.contains("cano_consensus_validator_votes_total{validator=\"1\"} 2"));
    assert!(output.contains("cano_consensus_validator_last_vote_view{validator=\"1\"} 10"));
    assert!(output.contains("cano_consensus_validator_votes_total{validator=\"42\"} 1"));
    assert!(output.contains("cano_consensus_validator_last_vote_view{validator=\"42\"} 3"));
}

#[test]
fn format_metrics_output_sorted_by_validator_id() {
    let metrics = ValidatorVoteMetrics::new();

    // Add validators out of order
    metrics.on_validator_vote(ValidatorId(3), 0);
    metrics.on_validator_vote(ValidatorId(1), 0);
    metrics.on_validator_vote(ValidatorId(2), 0);

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
    let metrics = ValidatorVoteMetrics::new();

    // Add validators up to the limit
    for i in 0..MAX_TRACKED_VALIDATORS {
        metrics.on_validator_vote(ValidatorId(i as u64), 0);
    }

    assert_eq!(metrics.tracked_validator_count(), MAX_TRACKED_VALIDATORS);
    assert_eq!(metrics.overflow_count(), 0);

    // Adding more should increment overflow count
    metrics.on_validator_vote(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 1), 0);
    metrics.on_validator_vote(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 2), 0);

    assert_eq!(metrics.tracked_validator_count(), MAX_TRACKED_VALIDATORS);
    assert_eq!(metrics.overflow_count(), 2);
}

#[test]
fn overflow_shown_in_format_metrics() {
    let metrics = ValidatorVoteMetrics::new();

    // Fill up to max
    for i in 0..MAX_TRACKED_VALIDATORS {
        metrics.on_validator_vote(ValidatorId(i as u64), 0);
    }

    // Overflow
    metrics.on_validator_vote(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 100), 0);

    let output = metrics.format_metrics();
    assert!(output.contains("cano_consensus_validator_overflow_count 1"));
}

#[test]
fn existing_validator_still_tracked_after_overflow() {
    let metrics = ValidatorVoteMetrics::new();

    // Add one validator first
    metrics.on_validator_vote(ValidatorId(1), 0);

    // Fill up the rest
    for i in 2..=MAX_TRACKED_VALIDATORS {
        metrics.on_validator_vote(ValidatorId(i as u64), 0);
    }

    // Now adding new validators should overflow
    metrics.on_validator_vote(ValidatorId(MAX_TRACKED_VALIDATORS as u64 + 100), 0);
    assert_eq!(metrics.overflow_count(), 1);

    // But the original validator should still be tracked
    metrics.on_validator_vote(ValidatorId(1), 5);
    assert_eq!(metrics.validator_votes_total(ValidatorId(1)), Some(2));
    assert_eq!(metrics.validator_last_vote_view(ValidatorId(1)), Some(5));
}

// ============================================================================
// Tests: Integration with NodeMetrics
// ============================================================================

#[test]
fn node_metrics_has_validator_votes() {
    let metrics = NodeMetrics::new();

    metrics
        .validator_votes()
        .on_validator_vote(ValidatorId(1), 0);

    assert_eq!(
        metrics
            .validator_votes()
            .validator_votes_total(ValidatorId(1)),
        Some(1)
    );
}

#[test]
fn node_metrics_format_includes_validator_votes() {
    let metrics = NodeMetrics::new();

    metrics
        .validator_votes()
        .on_validator_vote(ValidatorId(1), 5);

    let output = metrics.format_metrics();

    // Updated header reflects both T128 and T129
    assert!(output.contains("# Per-validator vote metrics (T128, T129)"));
    assert!(output.contains("cano_consensus_validator_votes_total{validator=\"1\"} 1"));
    assert!(output.contains("cano_consensus_validator_last_vote_view{validator=\"1\"} 5"));
}

#[test]
fn node_metrics_has_view_lag() {
    let metrics = NodeMetrics::new();

    metrics.view_lag().set_current_view(5);
    metrics.view_lag().update_highest_seen_view(10);

    assert_eq!(metrics.view_lag().view_lag(), 5);
}

#[test]
fn node_metrics_format_includes_view_lag() {
    let metrics = NodeMetrics::new();

    metrics.view_lag().set_current_view(5);
    metrics.view_lag().update_highest_seen_view(10);

    let output = metrics.format_metrics();

    assert!(output.contains("# View lag metrics (T128)"));
    assert!(output.contains("cano_consensus_current_view 5"));
    assert!(output.contains("cano_consensus_highest_seen_view 10"));
    assert!(output.contains("cano_consensus_view_lag 5"));
}

#[test]
fn validator_vote_metrics_default_impl() {
    let metrics: ValidatorVoteMetrics = Default::default();
    assert_eq!(metrics.tracked_validator_count(), 0);
    assert_eq!(metrics.overflow_count(), 0);
}

// ============================================================================
// Tests: Per-Validator View Lag (T129)
// ============================================================================

#[test]
fn validator_view_lag_single_validator_correct_lag() {
    let metrics = ValidatorVoteMetrics::new();

    // Validator voted at view 5
    metrics.on_validator_vote(ValidatorId(1), 5);

    // highest_seen_view = 10, so lag = 10 - 5 = 5
    let lag = metrics.validator_view_lag(ValidatorId(1), 10);
    assert_eq!(lag, Some(5));
}

#[test]
fn validator_view_lag_multiple_validators_different_lags() {
    let metrics = ValidatorVoteMetrics::new();

    // Different validators at different views
    metrics.on_validator_vote(ValidatorId(1), 5);
    metrics.on_validator_vote(ValidatorId(2), 8);
    metrics.on_validator_vote(ValidatorId(3), 10);

    // highest_seen_view = 10
    let lag_1 = metrics.validator_view_lag(ValidatorId(1), 10);
    let lag_2 = metrics.validator_view_lag(ValidatorId(2), 10);
    let lag_3 = metrics.validator_view_lag(ValidatorId(3), 10);

    assert_eq!(lag_1, Some(5)); // 10 - 5 = 5
    assert_eq!(lag_2, Some(2)); // 10 - 8 = 2
    assert_eq!(lag_3, Some(0)); // 10 - 10 = 0
}

#[test]
fn validator_view_lag_updates_with_new_votes() {
    let metrics = ValidatorVoteMetrics::new();

    // Initial vote at view 5
    metrics.on_validator_vote(ValidatorId(1), 5);
    assert_eq!(metrics.validator_view_lag(ValidatorId(1), 15), Some(10));

    // Update to view 12
    metrics.on_validator_vote(ValidatorId(1), 12);
    assert_eq!(metrics.validator_view_lag(ValidatorId(1), 15), Some(3));

    // Vote at lower view doesn't change lag (last_vote_view stays 12)
    metrics.on_validator_vote(ValidatorId(1), 8);
    assert_eq!(metrics.validator_view_lag(ValidatorId(1), 15), Some(3));
}

#[test]
fn validator_view_lag_returns_none_for_unknown_validator() {
    let metrics = ValidatorVoteMetrics::new();

    let lag = metrics.validator_view_lag(ValidatorId(999), 10);
    assert_eq!(lag, None);
}

#[test]
fn validator_view_lag_saturating_sub_prevents_underflow() {
    let metrics = ValidatorVoteMetrics::new();

    // Validator voted at view 100
    metrics.on_validator_vote(ValidatorId(1), 100);

    // If highest_seen_view is lower (shouldn't happen, but test safety)
    let lag = metrics.validator_view_lag(ValidatorId(1), 50);
    assert_eq!(lag, Some(0)); // saturating_sub returns 0
}

#[test]
fn all_validator_view_lags_returns_all_tracked() {
    let metrics = ValidatorVoteMetrics::new();

    metrics.on_validator_vote(ValidatorId(1), 5);
    metrics.on_validator_vote(ValidatorId(2), 8);
    metrics.on_validator_vote(ValidatorId(3), 10);

    let lags = metrics.all_validator_view_lags(15);
    assert_eq!(lags.len(), 3);

    // Sort for deterministic comparison
    let mut sorted: Vec<_> = lags.iter().map(|(id, lag)| (id.0, *lag)).collect();
    sorted.sort_by_key(|(id, _)| *id);

    assert_eq!(sorted, vec![(1, 10), (2, 7), (3, 5)]);
}

#[test]
fn format_metrics_with_view_lag_includes_lag() {
    let metrics = ValidatorVoteMetrics::new();

    metrics.on_validator_vote(ValidatorId(1), 5);
    metrics.on_validator_vote(ValidatorId(2), 8);

    let output = metrics.format_metrics_with_view_lag(10);

    // Should contain view lag for each validator
    assert!(output.contains("cano_consensus_validator_view_lag{validator=\"1\"} 5"));
    assert!(output.contains("cano_consensus_validator_view_lag{validator=\"2\"} 2"));
}

#[test]
fn node_metrics_format_includes_view_lag_per_validator() {
    let metrics = NodeMetrics::new();

    // Record votes
    metrics
        .validator_votes()
        .on_validator_vote(ValidatorId(1), 5);

    // Set highest_seen_view
    metrics.view_lag().update_highest_seen_view(10);

    let output = metrics.format_metrics();

    // Per-validator view lag should be present
    assert!(output.contains("cano_consensus_validator_view_lag{validator=\"1\"} 5"));
}
