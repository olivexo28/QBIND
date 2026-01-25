//! Tests for KEMTLS role-based PQC metrics (T120).
//!
//! These tests verify that the KEMTLS metrics correctly track:
//! - Client vs server role distinction
//! - Latency buckets per role
//! - Metrics formatting includes role labels
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p cano-node --test kemtls_pqc_metrics_tests -- --test-threads=1
//! ```
//!
//! Note: `--test-threads=1` is recommended for consistency. The `KemtlsMetrics`
//! struct uses atomic counters and is thread-safe, but single-threaded execution
//! makes test assertions more predictable.

use std::time::Duration;

use cano_node::{KemtlsHandshakeFailureReason, KemtlsMetrics, KemtlsRole};

// ============================================================================
// Part A: Role-based success metrics tests
// ============================================================================

/// Test that role-based success counters start at zero.
#[test]
fn role_based_success_counters_start_at_zero() {
    let metrics = KemtlsMetrics::new();

    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Client),
        0,
        "client success should start at 0"
    );
    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Server),
        0,
        "server success should start at 0"
    );
}

/// Test that client success is recorded correctly.
#[test]
fn client_success_recorded_correctly() {
    let metrics = KemtlsMetrics::new();

    // Record 3 client successes
    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Client);
    metrics.record_handshake_success_with_role(Duration::from_millis(10), KemtlsRole::Client);
    metrics.record_handshake_success_with_role(Duration::from_millis(15), KemtlsRole::Client);

    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Client),
        3,
        "client success should be 3"
    );
    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Server),
        0,
        "server success should still be 0"
    );

    // Aggregate should also show 3
    assert_eq!(
        metrics.handshake_success_total(),
        3,
        "aggregate success should be 3"
    );
}

/// Test that server success is recorded correctly.
#[test]
fn server_success_recorded_correctly() {
    let metrics = KemtlsMetrics::new();

    // Record 2 server successes
    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Server);
    metrics.record_handshake_success_with_role(Duration::from_millis(10), KemtlsRole::Server);

    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Server),
        2,
        "server success should be 2"
    );
    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Client),
        0,
        "client success should still be 0"
    );
}

/// Test that both client and server successes are tracked independently.
#[test]
fn client_and_server_tracked_independently() {
    let metrics = KemtlsMetrics::new();

    // Record 3 client and 2 server successes
    for _ in 0..3 {
        metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Client);
    }
    for _ in 0..2 {
        metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Server);
    }

    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Client),
        3,
        "client success should be 3"
    );
    assert_eq!(
        metrics.handshake_success_by_role(KemtlsRole::Server),
        2,
        "server success should be 2"
    );
    assert_eq!(
        metrics.handshake_success_total(),
        5,
        "aggregate success should be 5"
    );
}

// ============================================================================
// Part B: Role-based failure metrics tests
// ============================================================================

/// Test that role-based failure counters start at zero.
#[test]
fn role_based_failure_counters_start_at_zero() {
    let metrics = KemtlsMetrics::new();

    for reason in [
        KemtlsHandshakeFailureReason::Io,
        KemtlsHandshakeFailureReason::Protocol,
        KemtlsHandshakeFailureReason::Crypto,
        KemtlsHandshakeFailureReason::Timeout,
        KemtlsHandshakeFailureReason::Other,
    ] {
        assert_eq!(
            metrics.handshake_failure_by_role_and_reason(KemtlsRole::Client, reason),
            0,
            "client {:?} failure should start at 0",
            reason
        );
        assert_eq!(
            metrics.handshake_failure_by_role_and_reason(KemtlsRole::Server, reason),
            0,
            "server {:?} failure should start at 0",
            reason
        );
    }
}

/// Test that client failures are recorded correctly by reason.
#[test]
fn client_failures_recorded_by_reason() {
    let metrics = KemtlsMetrics::new();

    // Record different failure types for client
    metrics.inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Io, KemtlsRole::Client);
    metrics.inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Io, KemtlsRole::Client);
    metrics.inc_handshake_failure_with_role(
        KemtlsHandshakeFailureReason::Protocol,
        KemtlsRole::Client,
    );
    metrics
        .inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Crypto, KemtlsRole::Client);

    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Client,
            KemtlsHandshakeFailureReason::Io
        ),
        2,
        "client Io failure should be 2"
    );
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Client,
            KemtlsHandshakeFailureReason::Protocol
        ),
        1,
        "client Protocol failure should be 1"
    );
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Client,
            KemtlsHandshakeFailureReason::Crypto
        ),
        1,
        "client Crypto failure should be 1"
    );

    // Server should still have 0 failures
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Server,
            KemtlsHandshakeFailureReason::Io
        ),
        0,
        "server Io failure should be 0"
    );
}

/// Test that server failures are recorded correctly by reason.
#[test]
fn server_failures_recorded_by_reason() {
    let metrics = KemtlsMetrics::new();

    // Record different failure types for server
    metrics
        .inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Timeout, KemtlsRole::Server);
    metrics
        .inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Other, KemtlsRole::Server);
    metrics
        .inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Other, KemtlsRole::Server);

    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Server,
            KemtlsHandshakeFailureReason::Timeout
        ),
        1,
        "server Timeout failure should be 1"
    );
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Server,
            KemtlsHandshakeFailureReason::Other
        ),
        2,
        "server Other failure should be 2"
    );

    // Client should still have 0 failures
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Client,
            KemtlsHandshakeFailureReason::Timeout
        ),
        0,
        "client Timeout failure should be 0"
    );
}

/// Test that role-based failures also increment aggregate counters.
#[test]
fn role_based_failures_increment_aggregate() {
    let metrics = KemtlsMetrics::new();

    // Record failures for both roles
    metrics.inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Io, KemtlsRole::Client);
    metrics.inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Io, KemtlsRole::Server);
    metrics.inc_handshake_failure_with_role(
        KemtlsHandshakeFailureReason::Protocol,
        KemtlsRole::Client,
    );

    // Check aggregate counters
    assert_eq!(
        metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Io),
        2,
        "aggregate Io failure should be 2"
    );
    assert_eq!(
        metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Protocol),
        1,
        "aggregate Protocol failure should be 1"
    );
    assert_eq!(
        metrics.handshake_failure_total(),
        3,
        "total failures should be 3"
    );
}

// ============================================================================
// Part C: Role-based latency bucket tests
// ============================================================================

/// Test that role-based latency buckets start at zero.
#[test]
fn role_based_latency_buckets_start_at_zero() {
    let metrics = KemtlsMetrics::new();

    let (c_under_10ms, c_to_100ms, c_to_1s, c_over_1s) =
        metrics.latency_buckets_by_role(KemtlsRole::Client);
    assert_eq!(c_under_10ms, 0);
    assert_eq!(c_to_100ms, 0);
    assert_eq!(c_to_1s, 0);
    assert_eq!(c_over_1s, 0);

    let (s_under_10ms, s_to_100ms, s_to_1s, s_over_1s) =
        metrics.latency_buckets_by_role(KemtlsRole::Server);
    assert_eq!(s_under_10ms, 0);
    assert_eq!(s_to_100ms, 0);
    assert_eq!(s_to_1s, 0);
    assert_eq!(s_over_1s, 0);
}

/// Test that client latency buckets are populated correctly.
#[test]
fn client_latency_buckets_populated() {
    let metrics = KemtlsMetrics::new();

    // Record client successes with different latencies
    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Client); // < 10ms
    metrics.record_handshake_success_with_role(Duration::from_millis(50), KemtlsRole::Client); // 10-100ms
    metrics.record_handshake_success_with_role(Duration::from_millis(500), KemtlsRole::Client); // 100ms-1s
    metrics.record_handshake_success_with_role(Duration::from_secs(2), KemtlsRole::Client); // > 1s

    let (under_10ms, to_100ms, to_1s, over_1s) =
        metrics.latency_buckets_by_role(KemtlsRole::Client);
    assert_eq!(under_10ms, 1, "client under_10ms should be 1");
    assert_eq!(to_100ms, 1, "client to_100ms should be 1");
    assert_eq!(to_1s, 1, "client to_1s should be 1");
    assert_eq!(over_1s, 1, "client over_1s should be 1");

    // Server buckets should still be zero
    let (s_under_10ms, s_to_100ms, s_to_1s, s_over_1s) =
        metrics.latency_buckets_by_role(KemtlsRole::Server);
    assert_eq!(s_under_10ms, 0);
    assert_eq!(s_to_100ms, 0);
    assert_eq!(s_to_1s, 0);
    assert_eq!(s_over_1s, 0);
}

/// Test that server latency buckets are populated correctly.
#[test]
fn server_latency_buckets_populated() {
    let metrics = KemtlsMetrics::new();

    // Record server successes with different latencies
    metrics.record_handshake_success_with_role(Duration::from_millis(3), KemtlsRole::Server); // < 10ms
    metrics.record_handshake_success_with_role(Duration::from_millis(7), KemtlsRole::Server); // < 10ms
    metrics.record_handshake_success_with_role(Duration::from_millis(75), KemtlsRole::Server); // 10-100ms

    let (under_10ms, to_100ms, to_1s, over_1s) =
        metrics.latency_buckets_by_role(KemtlsRole::Server);
    assert_eq!(under_10ms, 2, "server under_10ms should be 2");
    assert_eq!(to_100ms, 1, "server to_100ms should be 1");
    assert_eq!(to_1s, 0, "server to_1s should be 0");
    assert_eq!(over_1s, 0, "server over_1s should be 0");
}

/// Test that role-based latency also populates aggregate buckets.
#[test]
fn role_based_latency_populates_aggregate() {
    let metrics = KemtlsMetrics::new();

    // Record successes for both roles
    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Client);
    metrics.record_handshake_success_with_role(Duration::from_millis(8), KemtlsRole::Server);
    metrics.record_handshake_success_with_role(Duration::from_millis(50), KemtlsRole::Client);

    // Check aggregate buckets
    let (under_10ms, to_100ms, to_1s, over_1s) = metrics.latency_buckets();
    assert_eq!(under_10ms, 2, "aggregate under_10ms should be 2");
    assert_eq!(to_100ms, 1, "aggregate to_100ms should be 1");
    assert_eq!(to_1s, 0, "aggregate to_1s should be 0");
    assert_eq!(over_1s, 0, "aggregate over_1s should be 0");
}

// ============================================================================
// Part D: format_metrics tests
// ============================================================================

/// Test that format_metrics includes role-based success labels.
#[test]
fn format_metrics_includes_role_success_labels() {
    let metrics = KemtlsMetrics::new();

    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Client);
    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Server);

    let output = metrics.format_metrics();

    assert!(
        output.contains("kemtls_handshake_success_total{role=\"client\"} 1"),
        "output should contain client success: {}",
        output
    );
    assert!(
        output.contains("kemtls_handshake_success_total{role=\"server\"} 1"),
        "output should contain server success: {}",
        output
    );
}

/// Test that format_metrics includes role-based failure labels.
#[test]
fn format_metrics_includes_role_failure_labels() {
    let metrics = KemtlsMetrics::new();

    metrics.inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Io, KemtlsRole::Client);
    metrics.inc_handshake_failure_with_role(
        KemtlsHandshakeFailureReason::Protocol,
        KemtlsRole::Server,
    );

    let output = metrics.format_metrics();

    assert!(
        output.contains("kemtls_handshake_failure_total{role=\"client\",reason=\"io\"} 1"),
        "output should contain client io failure: {}",
        output
    );
    assert!(
        output.contains("kemtls_handshake_failure_total{role=\"server\",reason=\"protocol\"} 1"),
        "output should contain server protocol failure: {}",
        output
    );
}

/// Test that format_metrics includes role-based latency bucket labels.
#[test]
fn format_metrics_includes_role_latency_labels() {
    let metrics = KemtlsMetrics::new();

    metrics.record_handshake_success_with_role(Duration::from_millis(5), KemtlsRole::Client);
    metrics.record_handshake_success_with_role(Duration::from_millis(50), KemtlsRole::Server);

    let output = metrics.format_metrics();

    assert!(
        output.contains("kemtls_handshake_duration_bucket{role=\"client\",le=\"0.01\"} 1"),
        "output should contain client latency bucket: {}",
        output
    );
    assert!(
        output.contains("kemtls_handshake_duration_bucket{role=\"server\",le=\"0.1\"} 1"),
        "output should contain server latency bucket: {}",
        output
    );
}

/// Test that format_metrics includes T120 header.
#[test]
fn format_metrics_includes_t120_header() {
    let metrics = KemtlsMetrics::new();

    let output = metrics.format_metrics();

    assert!(
        output.contains("T91, T113, T120") || output.contains("T120"),
        "output should mention T120: {}",
        output
    );
}

// ============================================================================
// Part E: KemtlsRole Display trait tests
// ============================================================================

/// Test that KemtlsRole Display trait produces expected output.
#[test]
fn kemtls_role_display() {
    assert_eq!(format!("{}", KemtlsRole::Client), "client");
    assert_eq!(format!("{}", KemtlsRole::Server), "server");
}

// ============================================================================
// Part F: PlainTcp mode should not affect KEMTLS metrics
// ============================================================================

/// Test that KEMTLS metrics don't increment when no handshakes occur.
#[test]
fn kemtls_metrics_unchanged_without_handshakes() {
    let metrics = KemtlsMetrics::new();

    // Simulate some activity that doesn't involve KEMTLS
    // (In a real scenario, PlainTcp mode would not call KEMTLS metrics methods)

    // All counters should remain at zero
    assert_eq!(metrics.handshake_success_total(), 0);
    assert_eq!(metrics.handshake_failure_total(), 0);
    assert_eq!(metrics.handshake_success_by_role(KemtlsRole::Client), 0);
    assert_eq!(metrics.handshake_success_by_role(KemtlsRole::Server), 0);
}

// ============================================================================
// Part G: Mixed metrics scenario
// ============================================================================

/// Test a realistic mixed scenario with successes and failures for both roles.
#[test]
fn mixed_metrics_scenario() {
    let metrics = KemtlsMetrics::new();

    // Simulate realistic usage:
    // - 10 client successes (various latencies)
    // - 8 server successes (various latencies)
    // - 2 client failures (Io, Protocol)
    // - 1 server failure (Timeout)

    for i in 0..10 {
        let duration = Duration::from_millis((i + 1) * 5); // 5ms, 10ms, ..., 50ms
        metrics.record_handshake_success_with_role(duration, KemtlsRole::Client);
    }

    for i in 0..8 {
        let duration = Duration::from_millis((i + 1) * 10); // 10ms, 20ms, ..., 80ms
        metrics.record_handshake_success_with_role(duration, KemtlsRole::Server);
    }

    metrics.inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Io, KemtlsRole::Client);
    metrics.inc_handshake_failure_with_role(
        KemtlsHandshakeFailureReason::Protocol,
        KemtlsRole::Client,
    );
    metrics
        .inc_handshake_failure_with_role(KemtlsHandshakeFailureReason::Timeout, KemtlsRole::Server);

    // Verify counts
    assert_eq!(metrics.handshake_success_total(), 18);
    assert_eq!(metrics.handshake_success_by_role(KemtlsRole::Client), 10);
    assert_eq!(metrics.handshake_success_by_role(KemtlsRole::Server), 8);
    assert_eq!(metrics.handshake_failure_total(), 3);
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Client,
            KemtlsHandshakeFailureReason::Io
        ),
        1
    );
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Client,
            KemtlsHandshakeFailureReason::Protocol
        ),
        1
    );
    assert_eq!(
        metrics.handshake_failure_by_role_and_reason(
            KemtlsRole::Server,
            KemtlsHandshakeFailureReason::Timeout
        ),
        1
    );

    // Verify latency buckets have data
    let (client_under_10ms, _, _, _) = metrics.latency_buckets_by_role(KemtlsRole::Client);
    let (server_under_10ms, _, _, _) = metrics.latency_buckets_by_role(KemtlsRole::Server);
    assert!(
        client_under_10ms > 0,
        "client should have some fast handshakes"
    );
    // Server's first handshake is 10ms which falls in the 10-100ms bucket, not under_10ms
    assert_eq!(
        server_under_10ms, 0,
        "server's shortest is 10ms, not under 10ms"
    );

    // Verify format_metrics produces non-empty output
    let output = metrics.format_metrics();
    assert!(!output.is_empty());
    assert!(output.len() > 100, "output should be substantial");
}
