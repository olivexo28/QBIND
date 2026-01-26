//! Tests for view lag metrics (T128).
//!
//! These tests verify that the ViewLagMetrics struct correctly tracks
//! the view lag gauge: highest_seen_view - current_view.

use qbind_node::ViewLagMetrics;

// ============================================================================
// Tests: Basic ViewLagMetrics Functionality
// ============================================================================

#[test]
fn view_lag_metrics_new_starts_at_zero() {
    let metrics = ViewLagMetrics::new();
    assert_eq!(metrics.current_view(), 0);
    assert_eq!(metrics.highest_seen_view(), 0);
    assert_eq!(metrics.view_lag(), 0);
}

#[test]
fn view_lag_is_zero_when_current_equals_highest() {
    let metrics = ViewLagMetrics::new();

    metrics.set_current_view(5);
    metrics.update_highest_seen_view(5);

    assert_eq!(metrics.current_view(), 5);
    assert_eq!(metrics.highest_seen_view(), 5);
    assert_eq!(metrics.view_lag(), 0);
}

#[test]
fn view_lag_is_zero_when_current_exceeds_highest() {
    let metrics = ViewLagMetrics::new();

    metrics.update_highest_seen_view(5);
    metrics.set_current_view(10);

    assert_eq!(metrics.current_view(), 10);
    assert_eq!(metrics.highest_seen_view(), 5);
    // view_lag should be 0 when current > highest (using saturating_sub)
    assert_eq!(metrics.view_lag(), 0);
}

#[test]
fn view_lag_computed_correctly_when_behind() {
    let metrics = ViewLagMetrics::new();

    metrics.set_current_view(5);
    metrics.update_highest_seen_view(10);

    assert_eq!(metrics.current_view(), 5);
    assert_eq!(metrics.highest_seen_view(), 10);
    assert_eq!(metrics.view_lag(), 5);
}

#[test]
fn highest_seen_view_is_monotonic() {
    let metrics = ViewLagMetrics::new();

    // Increasing updates should take effect
    metrics.update_highest_seen_view(5);
    assert_eq!(metrics.highest_seen_view(), 5);

    metrics.update_highest_seen_view(10);
    assert_eq!(metrics.highest_seen_view(), 10);

    // Lower update should be ignored (monotonic)
    metrics.update_highest_seen_view(7);
    assert_eq!(
        metrics.highest_seen_view(),
        10,
        "Lower view should not update"
    );

    // Same view should be ignored
    metrics.update_highest_seen_view(10);
    assert_eq!(metrics.highest_seen_view(), 10);
}

#[test]
fn current_view_can_be_set_freely() {
    let metrics = ViewLagMetrics::new();

    // Current view is not monotonic (can be set to any value)
    metrics.set_current_view(10);
    assert_eq!(metrics.current_view(), 10);

    metrics.set_current_view(5);
    assert_eq!(metrics.current_view(), 5);

    metrics.set_current_view(20);
    assert_eq!(metrics.current_view(), 20);
}

#[test]
fn view_lag_changes_as_views_update() {
    let metrics = ViewLagMetrics::new();

    // Start: both at 0, lag = 0
    assert_eq!(metrics.view_lag(), 0);

    // See a higher view from network: lag = 5
    metrics.update_highest_seen_view(5);
    assert_eq!(metrics.view_lag(), 5);

    // Advance our view: lag = 3
    metrics.set_current_view(2);
    assert_eq!(metrics.view_lag(), 3);

    // See an even higher view: lag = 8
    metrics.update_highest_seen_view(10);
    assert_eq!(metrics.view_lag(), 8);

    // Catch up: lag = 0
    metrics.set_current_view(10);
    assert_eq!(metrics.view_lag(), 0);

    // Overtake (shouldn't happen normally, but handled gracefully)
    metrics.set_current_view(15);
    assert_eq!(metrics.view_lag(), 0);
}

#[test]
fn format_metrics_includes_all_fields() {
    let metrics = ViewLagMetrics::new();

    metrics.set_current_view(5);
    metrics.update_highest_seen_view(10);

    let output = metrics.format_metrics();

    assert!(output.contains("# View lag metrics (T128)"));
    assert!(output.contains("qbind_consensus_current_view 5"));
    assert!(output.contains("qbind_consensus_highest_seen_view 10"));
    assert!(output.contains("qbind_consensus_view_lag 5"));
}

#[test]
fn format_metrics_shows_zero_lag() {
    let metrics = ViewLagMetrics::new();

    metrics.set_current_view(10);
    metrics.update_highest_seen_view(10);

    let output = metrics.format_metrics();

    assert!(output.contains("qbind_consensus_view_lag 0"));
}

#[test]
fn view_lag_metrics_default_impl() {
    let metrics: ViewLagMetrics = Default::default();
    assert_eq!(metrics.current_view(), 0);
    assert_eq!(metrics.highest_seen_view(), 0);
    assert_eq!(metrics.view_lag(), 0);
}

// ============================================================================
// Tests: Large Values
// ============================================================================

#[test]
fn handles_large_view_numbers() {
    let metrics = ViewLagMetrics::new();

    let large_view = u64::MAX / 2;

    metrics.set_current_view(large_view);
    metrics.update_highest_seen_view(large_view + 100);

    assert_eq!(metrics.view_lag(), 100);
}

#[test]
fn saturating_sub_prevents_underflow() {
    let metrics = ViewLagMetrics::new();

    // Set current to max, highest to 0
    metrics.set_current_view(u64::MAX);
    // highest_seen_view is 0

    // This should not panic or overflow
    let lag = metrics.view_lag();
    assert_eq!(lag, 0);
}
