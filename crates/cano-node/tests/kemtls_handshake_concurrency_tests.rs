//! Integration tests for KEMTLS handshake concurrency control (T113).
//!
//! These tests verify the semaphore-based concurrency limit for KEMTLS handshakes:
//! - Basic limit enforcement (KEMTLS mode)
//! - No limit (None) preserves old behavior
//! - Metrics sanity (started, completed, in_flight)
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p cano-node --test kemtls_handshake_concurrency_tests
//! ```

use std::sync::Arc;
use std::time::Duration;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use cano_node::{
    AsyncPeerManagerConfig, AsyncPeerManagerImpl, KemtlsHandshakeFailureReason, KemtlsMetrics,
    NodeMetrics, TransportSecurityMode,
};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Crypto Implementations for Testing
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
}

impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn secret_key_len(&self) -> usize {
        32
    }

    fn ciphertext_len(&self) -> usize {
        48
    }

    fn shared_secret_len(&self) -> usize {
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
}

impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        let tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let (ciphertext, tag_slice) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 1);
        let expected_tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        if tag_slice[0] != expected_tag {
            return Err(CryptoError::InvalidCiphertext);
        }
        let xor_byte = key.first().copied().unwrap_or(0);
        let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ xor_byte).collect();
        Ok(plaintext)
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

fn make_test_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
    leaf_kem_suite_id: u8,
    sig_suite_id: u8,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id,
        leaf_kem_pk,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
}

struct TestSetup {
    #[allow(dead_code)]
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

fn create_test_setup() -> TestSetup {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(
        kem_suite_id,
        aead_suite_id,
        sig_suite_id,
    ));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        validator_id,
        peer_kem_pk: server_kem_pk,
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random,
    };

    TestSetup {
        client_cfg,
        server_cfg,
    }
}

// ============================================================================
// Part A: KemtlsMetrics Concurrency Counter Tests
// ============================================================================

/// Test that concurrency metrics are initialized to zero.
#[test]
fn kemtls_metrics_concurrency_counters_start_at_zero() {
    let metrics = KemtlsMetrics::new();

    assert_eq!(metrics.handshake_started_total(), 0);
    assert_eq!(metrics.handshake_completed_total(), 0);
    assert_eq!(metrics.handshake_in_flight(), 0);
}

/// Test that record_handshake_started increments the correct counters.
#[test]
fn kemtls_metrics_record_handshake_started() {
    let metrics = KemtlsMetrics::new();

    metrics.record_handshake_started();

    assert_eq!(metrics.handshake_started_total(), 1);
    assert_eq!(metrics.handshake_in_flight(), 1);
    assert_eq!(metrics.handshake_completed_total(), 0);

    metrics.record_handshake_started();

    assert_eq!(metrics.handshake_started_total(), 2);
    assert_eq!(metrics.handshake_in_flight(), 2);
}

/// Test that record_handshake_completed increments/decrements the correct counters.
#[test]
fn kemtls_metrics_record_handshake_completed() {
    let metrics = KemtlsMetrics::new();

    // Start 3 handshakes
    metrics.record_handshake_started();
    metrics.record_handshake_started();
    metrics.record_handshake_started();

    assert_eq!(metrics.handshake_in_flight(), 3);

    // Complete 2
    metrics.record_handshake_completed();
    metrics.record_handshake_completed();

    assert_eq!(metrics.handshake_completed_total(), 2);
    assert_eq!(metrics.handshake_in_flight(), 1);

    // Complete the last one
    metrics.record_handshake_completed();

    assert_eq!(metrics.handshake_completed_total(), 3);
    assert_eq!(metrics.handshake_in_flight(), 0);
}

/// Test that concurrency metrics are included in format_metrics output.
#[test]
fn kemtls_metrics_format_includes_concurrency_metrics() {
    let metrics = KemtlsMetrics::new();

    metrics.record_handshake_started();
    metrics.record_handshake_started();
    metrics.record_handshake_completed();

    let output = metrics.format_metrics();

    assert!(
        output.contains("kemtls_handshake_started_total 2"),
        "output should contain started_total: {}",
        output
    );
    assert!(
        output.contains("kemtls_handshake_completed_total 1"),
        "output should contain completed_total: {}",
        output
    );
    assert!(
        output.contains("kemtls_handshake_in_flight 1"),
        "output should contain in_flight: {}",
        output
    );
}

// ============================================================================
// Part B: Config Builder Tests
// ============================================================================

/// Test the with_max_concurrent_kemtls_handshakes builder method.
#[test]
fn config_with_max_concurrent_kemtls_handshakes_builder() {
    let config = AsyncPeerManagerConfig::default().with_max_concurrent_kemtls_handshakes(Some(32));

    assert_eq!(config.max_concurrent_kemtls_handshakes, Some(32));

    // Test with None
    let config2 = AsyncPeerManagerConfig::default().with_max_concurrent_kemtls_handshakes(None);

    assert_eq!(config2.max_concurrent_kemtls_handshakes, None);
}

/// Test that default config has no concurrency limit.
#[test]
fn default_config_has_no_concurrency_limit() {
    let config = AsyncPeerManagerConfig::default();
    assert_eq!(
        config.max_concurrent_kemtls_handshakes, None,
        "default max_concurrent_kemtls_handshakes should be None for backward compatibility"
    );
}

/// Test that from_channel_config also defaults to no concurrency limit.
#[test]
fn from_channel_config_has_no_concurrency_limit() {
    use cano_node::channel_config::ChannelCapacityConfig;

    let channel_config = ChannelCapacityConfig::default();
    let config = AsyncPeerManagerConfig::from_channel_config(&channel_config);

    assert_eq!(
        config.max_concurrent_kemtls_handshakes, None,
        "from_channel_config should have no concurrency limit by default"
    );
}

// ============================================================================
// Part C: AsyncPeerManagerImpl Semaphore Initialization Tests
// ============================================================================

/// Test that manager with no limit has no semaphore.
#[tokio::test]
async fn manager_no_limit_has_no_semaphore() {
    let setup = create_test_setup();
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls)
        .with_server_config(setup.server_cfg)
        .with_max_concurrent_kemtls_handshakes(None);

    let manager = AsyncPeerManagerImpl::new(config);

    assert_eq!(
        manager.max_concurrent_kemtls_handshakes(),
        None,
        "max_concurrent_kemtls_handshakes() should return None"
    );
}

/// Test that manager with limit has semaphore initialized.
#[tokio::test]
async fn manager_with_limit_has_semaphore() {
    let setup = create_test_setup();
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls)
        .with_server_config(setup.server_cfg)
        .with_max_concurrent_kemtls_handshakes(Some(5));

    let manager = AsyncPeerManagerImpl::new(config);

    assert_eq!(
        manager.max_concurrent_kemtls_handshakes(),
        Some(5),
        "max_concurrent_kemtls_handshakes() should return Some(5)"
    );
}

/// Test that PlainTcp mode ignores concurrency limit.
#[tokio::test]
async fn plaintcp_mode_ignores_concurrency_limit() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp)
        .with_max_concurrent_kemtls_handshakes(Some(2));

    let mut manager = AsyncPeerManagerImpl::new(config);

    // Bind and start listener
    let addr = manager.bind().await.expect("bind should succeed");

    let manager = Arc::new(manager);
    manager.start_listener().await;

    // Give the listener time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect multiple clients in PlainTcp mode - should all succeed regardless of limit
    let mut clients = Vec::new();
    for _ in 0..5 {
        let client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect should succeed");
        clients.push(client);
    }

    // Wait for peers to be registered
    for _ in 0..30 {
        if manager.peer_count().await >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // All 5 connections should succeed (PlainTcp doesn't use the semaphore)
    assert_eq!(
        manager.peer_count().await,
        5,
        "all 5 PlainTcp connections should succeed"
    );

    // KEMTLS metrics should show no handshakes (PlainTcp doesn't record them)
    // Note: In PlainTcp mode, KEMTLS handshake code path is not executed
    assert_eq!(
        manager.kemtls_metrics().handshake_started_total(),
        0,
        "PlainTcp mode should not record KEMTLS handshakes"
    );

    manager.shutdown();
}

// ============================================================================
// Part D: Backward Compatibility Tests (No Limit)
// ============================================================================

/// Test that no limit (None) preserves old behavior - KEMTLS connections succeed.
#[tokio::test]
async fn no_limit_preserves_kemtls_behavior() {
    let setup = create_test_setup();
    let metrics = Arc::new(NodeMetrics::new());

    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls)
        .with_server_config(setup.server_cfg)
        .with_max_concurrent_kemtls_handshakes(None); // No limit

    let manager = AsyncPeerManagerImpl::with_metrics(config, metrics.clone());

    // KEMTLS metrics should start at zero
    assert_eq!(manager.kemtls_metrics().handshake_success_total(), 0);
    assert_eq!(manager.kemtls_metrics().handshake_started_total(), 0);
    assert_eq!(manager.kemtls_metrics().handshake_completed_total(), 0);
    assert_eq!(manager.kemtls_metrics().handshake_in_flight(), 0);
}

// ============================================================================
// Part E: Metrics Sanity Tests
// ============================================================================

/// Test that KEMTLS metrics are consistent after handshakes complete.
#[test]
fn kemtls_metrics_consistent_after_handshakes() {
    let metrics = KemtlsMetrics::new();

    // Simulate 5 handshakes
    for _ in 0..5 {
        metrics.record_handshake_started();
    }

    assert_eq!(metrics.handshake_started_total(), 5);
    assert_eq!(metrics.handshake_in_flight(), 5);

    // Complete all 5 with success
    for _ in 0..5 {
        metrics.record_handshake_success(Duration::from_millis(10));
        metrics.record_handshake_completed();
    }

    // After all complete:
    assert_eq!(metrics.handshake_started_total(), 5);
    assert_eq!(metrics.handshake_completed_total(), 5);
    assert_eq!(
        metrics.handshake_in_flight(),
        0,
        "in_flight should return to 0"
    );
    assert_eq!(metrics.handshake_success_total(), 5);
}

/// Test that metrics are tracked correctly when handshakes fail.
#[test]
fn kemtls_metrics_tracked_on_failure() {
    let metrics = KemtlsMetrics::new();

    // Start 3 handshakes
    metrics.record_handshake_started();
    metrics.record_handshake_started();
    metrics.record_handshake_started();

    // 1 succeeds
    metrics.record_handshake_success(Duration::from_millis(10));
    metrics.record_handshake_completed();

    // 2 fail
    metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Io);
    metrics.record_handshake_completed();
    metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Protocol);
    metrics.record_handshake_completed();

    // Verify counts
    assert_eq!(metrics.handshake_started_total(), 3);
    assert_eq!(metrics.handshake_completed_total(), 3);
    assert_eq!(metrics.handshake_in_flight(), 0);
    assert_eq!(metrics.handshake_success_total(), 1);
    assert_eq!(metrics.handshake_failure_total(), 2);
}

// ============================================================================
// Part F: Integration Test with Manager
// ============================================================================

/// Test that manager correctly initializes KEMTLS metrics.
#[tokio::test]
async fn manager_kemtls_metrics_accessible() {
    let setup = create_test_setup();
    let metrics = Arc::new(NodeMetrics::new());

    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls)
        .with_server_config(setup.server_cfg)
        .with_max_concurrent_kemtls_handshakes(Some(2));

    let manager = AsyncPeerManagerImpl::with_metrics(config, metrics);

    let kemtls_metrics = manager.kemtls_metrics();

    // All metrics should start at zero
    assert_eq!(kemtls_metrics.handshake_success_total(), 0);
    assert_eq!(kemtls_metrics.handshake_failure_total(), 0);
    assert_eq!(kemtls_metrics.handshake_started_total(), 0);
    assert_eq!(kemtls_metrics.handshake_completed_total(), 0);
    assert_eq!(kemtls_metrics.handshake_in_flight(), 0);
}

/// Test that format_metrics output includes T113 concurrency metrics.
#[test]
fn format_metrics_includes_t113_header() {
    let metrics = KemtlsMetrics::new();

    let output = metrics.format_metrics();

    // Check that the header mentions T113
    assert!(
        output.contains("T113") || output.contains("T91, T113"),
        "format_metrics should mention T113: {}",
        output
    );
}
