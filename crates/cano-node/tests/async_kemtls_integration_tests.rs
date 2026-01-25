//! Integration tests for Async KEMTLS handshake integration (T91).
//!
//! These tests verify the KEMTLS integration into `AsyncPeerManagerImpl`:
//! - `TransportSecurityMode` configuration and environment variable parsing
//! - `KemtlsMetrics` tracking of handshake success/failure counts
//! - Config wiring for PlainTcp vs Kemtls modes
//! - Load harness regression (still works with PlainTcp)

use std::sync::Arc;
use std::time::Duration;

use cano_node::load_harness::{run_load_harness, LoadHarnessConfig};
use cano_node::{
    AsyncPeerManagerConfig, AsyncPeerManagerImpl, KemtlsHandshakeFailureReason, KemtlsMetrics,
    NodeMetrics, TransportSecurityMode,
};

// ============================================================================
// TransportSecurityMode Tests
// ============================================================================

#[test]
fn transport_security_mode_parsing_plain_variants() {
    // All variants of "plain" should parse to PlainTcp
    assert_eq!(
        TransportSecurityMode::from_str("plain"),
        Some(TransportSecurityMode::PlainTcp)
    );
    assert_eq!(
        TransportSecurityMode::from_str("PLAIN"),
        Some(TransportSecurityMode::PlainTcp)
    );
    assert_eq!(
        TransportSecurityMode::from_str("plaintcp"),
        Some(TransportSecurityMode::PlainTcp)
    );
    assert_eq!(
        TransportSecurityMode::from_str("PlainTcp"),
        Some(TransportSecurityMode::PlainTcp)
    );
}

#[test]
fn transport_security_mode_parsing_kemtls_variants() {
    // All variants of "kemtls" should parse to Kemtls
    assert_eq!(
        TransportSecurityMode::from_str("kemtls"),
        Some(TransportSecurityMode::Kemtls)
    );
    assert_eq!(
        TransportSecurityMode::from_str("KEMTLS"),
        Some(TransportSecurityMode::Kemtls)
    );
    assert_eq!(
        TransportSecurityMode::from_str("Kemtls"),
        Some(TransportSecurityMode::Kemtls)
    );
}

#[test]
fn transport_security_mode_parsing_invalid() {
    // Invalid strings should return None
    assert_eq!(TransportSecurityMode::from_str("tls"), None);
    assert_eq!(TransportSecurityMode::from_str("ssl"), None);
    assert_eq!(TransportSecurityMode::from_str(""), None);
    assert_eq!(TransportSecurityMode::from_str("invalid"), None);
}

#[test]
fn transport_security_mode_default_is_kemtls() {
    // Default should be Kemtls (secure by default)
    assert_eq!(
        TransportSecurityMode::default(),
        TransportSecurityMode::Kemtls
    );
}

// ============================================================================
// KemtlsMetrics Tests
// ============================================================================

#[test]
fn kemtls_metrics_tracks_multiple_successes() {
    let metrics = KemtlsMetrics::new();

    for _ in 0..10 {
        metrics.record_handshake_success(Duration::from_millis(50));
    }

    assert_eq!(metrics.handshake_success_total(), 10);
    assert_eq!(metrics.handshake_failure_total(), 0);
}

#[test]
fn kemtls_metrics_tracks_multiple_failures() {
    let metrics = KemtlsMetrics::new();

    // Simulate various failure types
    for _ in 0..3 {
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Io);
    }
    for _ in 0..2 {
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Protocol);
    }
    metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Crypto);

    assert_eq!(metrics.handshake_success_total(), 0);
    assert_eq!(metrics.handshake_failure_total(), 6);
    assert_eq!(
        metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Io),
        3
    );
    assert_eq!(
        metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Protocol),
        2
    );
    assert_eq!(
        metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Crypto),
        1
    );
}

#[test]
fn kemtls_metrics_latency_buckets_cover_all_ranges() {
    let metrics = KemtlsMetrics::new();

    // Test each latency bucket
    metrics.record_handshake_success(Duration::from_millis(1)); // <10ms
    metrics.record_handshake_success(Duration::from_millis(9)); // <10ms
    metrics.record_handshake_success(Duration::from_millis(10)); // 10-100ms
    metrics.record_handshake_success(Duration::from_millis(50)); // 10-100ms
    metrics.record_handshake_success(Duration::from_millis(100)); // 100ms-1s
    metrics.record_handshake_success(Duration::from_millis(500)); // 100ms-1s
    metrics.record_handshake_success(Duration::from_secs(1)); // >1s
    metrics.record_handshake_success(Duration::from_secs(5)); // >1s

    let (under_10ms, to_100ms, to_1s, over_1s) = metrics.latency_buckets();
    assert_eq!(under_10ms, 2);
    assert_eq!(to_100ms, 2);
    assert_eq!(to_1s, 2);
    assert_eq!(over_1s, 2);
}

#[test]
fn kemtls_metrics_format_is_prometheus_compatible() {
    let metrics = KemtlsMetrics::new();

    metrics.record_handshake_success(Duration::from_millis(5));
    metrics.record_handshake_success(Duration::from_millis(50));
    metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Protocol);

    let output = metrics.format_metrics();

    // Verify Prometheus metric naming conventions
    assert!(output.contains("kemtls_handshake_success_total 2"));
    assert!(output.contains("kemtls_handshake_failure_total{reason=\"protocol\"} 1"));

    // Verify histogram bucket format (cumulative)
    assert!(output.contains("kemtls_handshake_duration_bucket{le=\"0.01\"} 1"));
    assert!(output.contains("kemtls_handshake_duration_bucket{le=\"0.1\"} 2"));
}

// ============================================================================
// AsyncPeerManagerConfig Tests
// ============================================================================

#[test]
fn async_peer_manager_config_default_uses_plaintcp_for_backward_compat() {
    // Note: The default behavior may depend on environment variable.
    // Without the env var, it should default to PlainTcp for tests.
    // Clear any existing env var for this test
    std::env::remove_var("CANO_TRANSPORT_SECURITY_MODE");

    let config = AsyncPeerManagerConfig::default();
    // Default is PlainTcp for backward compatibility with existing tests
    assert_eq!(
        config.transport_security_mode,
        TransportSecurityMode::PlainTcp
    );
}

#[test]
fn async_peer_manager_config_builder_sets_security_mode() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls);

    assert_eq!(
        config.transport_security_mode,
        TransportSecurityMode::Kemtls
    );
}

#[test]
fn async_peer_manager_config_kemtls_requires_server_config() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls);

    // KEMTLS mode without server_config is invalid
    assert!(config.is_kemtls_config_missing());

    let config_plain = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp);

    // PlainTcp mode doesn't require server_config
    assert!(!config_plain.is_kemtls_config_missing());
}

// ============================================================================
// AsyncPeerManagerImpl Tests
// ============================================================================

#[tokio::test]
async fn async_peer_manager_impl_provides_kemtls_metrics_accessor() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp);
    let manager = AsyncPeerManagerImpl::new(config);

    let metrics = manager.kemtls_metrics();

    // Metrics should be initially empty
    assert_eq!(metrics.handshake_success_total(), 0);
    assert_eq!(metrics.handshake_failure_total(), 0);
}

#[tokio::test]
async fn async_peer_manager_impl_provides_transport_mode_accessor() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp);
    let manager = AsyncPeerManagerImpl::new(config);

    assert_eq!(
        manager.transport_security_mode(),
        TransportSecurityMode::PlainTcp
    );
}

#[tokio::test]
async fn async_peer_manager_plaintcp_mode_works_without_server_config() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp)
        .with_listen_addr("127.0.0.1:0".parse().unwrap());

    let mut manager = AsyncPeerManagerImpl::new(config);

    // Should be able to bind and start listener in PlainTcp mode
    let addr = manager.bind().await.expect("should bind successfully");
    assert_ne!(addr.port(), 0);
}

// ============================================================================
// Load Harness Regression Tests
// ============================================================================

#[tokio::test]
async fn load_harness_works_with_plaintcp_mode() {
    // The load harness uses LoopbackNetService, which doesn't use the
    // AsyncPeerManager directly. This test verifies the harness still works
    // and is independent of transport security mode.
    let config = LoadHarnessConfig::default()
        .with_message_count(20)
        .with_rate_per_second(1000)
        .with_verbose(false);

    let result = run_load_harness(config).await;
    assert!(result.is_ok(), "load harness should complete successfully");

    let harness_result = result.unwrap();
    assert!(harness_result.completed);
    assert_eq!(harness_result.messages_injected, 20);
}

#[tokio::test]
async fn load_harness_metrics_are_collected() {
    let config = LoadHarnessConfig::default()
        .with_message_count(50)
        .with_rate_per_second(1000)
        .with_vote_ratio(0.8) // 80% votes
        .with_verbose(false);

    let result = run_load_harness(config).await.unwrap();

    // Verify metrics were collected
    let network = result.metrics.network();
    let total_inbound = network.inbound_vote_total() + network.inbound_proposal_total();
    assert!(total_inbound > 0, "should have recorded inbound messages");

    // With 80% vote ratio, we expect more votes than proposals
    let votes = network.inbound_vote_total();
    let proposals = network.inbound_proposal_total();
    assert!(
        votes > proposals,
        "should have more votes than proposals with 0.8 ratio"
    );
}

// ============================================================================
// Integration with NodeMetrics Tests
// ============================================================================

#[tokio::test]
async fn async_peer_manager_with_metrics_still_works() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp);
    let mut manager = AsyncPeerManagerImpl::with_metrics(config, metrics.clone());

    // Should be able to bind and work normally
    let addr = manager.bind().await.expect("should bind successfully");
    assert_ne!(addr.port(), 0);

    // Verify NodeMetrics format includes expected sections
    let output = metrics.format_metrics();
    assert!(output.contains("# Network metrics"));
    assert!(output.contains("# Runtime metrics"));
}

// ============================================================================
// Debug Output Tests
// ============================================================================

#[test]
fn async_peer_manager_impl_debug_includes_transport_mode() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp);
    let manager = AsyncPeerManagerImpl::new(config);

    let debug_str = format!("{:?}", manager);

    assert!(debug_str.contains("transport_security_mode: PlainTcp"));
}

#[test]
fn async_peer_manager_impl_debug_includes_kemtls_mode() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls);
    let manager = AsyncPeerManagerImpl::new(config);

    let debug_str = format!("{:?}", manager);

    assert!(debug_str.contains("transport_security_mode: Kemtls"));
}
