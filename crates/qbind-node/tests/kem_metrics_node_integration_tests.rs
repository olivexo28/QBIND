//! Integration tests for KEM metrics wiring into NodeMetrics (T137).
//!
//! These tests verify that KEM operation metrics are properly:
//! - Wired into NodeMetrics
//! - Recorded during actual KEMTLS handshakes
//! - Exposed via the /metrics HTTP endpoint
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test kem_metrics_node_integration_tests
//! ```

use std::sync::Arc;
use std::time::Duration;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::validator_config::inject_kem_metrics_into_configs;
use qbind_node::NodeMetrics;
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

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
        // Simulate some work (for latency measurement)
        std::thread::sleep(Duration::from_micros(50));
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
        // Simulate some work (for latency measurement)
        std::thread::sleep(Duration::from_micros(50));
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

fn create_test_setup() -> (ClientConnectionConfig, ServerConnectionConfig) {
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
        cookie_config: None,
        local_validator_id: validator_id,
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

    (client_cfg, server_cfg)
}

// ============================================================================
// KEM Metrics Integration Tests
// ============================================================================

#[test]
fn kem_metrics_wired_into_node_metrics() {
    let metrics = NodeMetrics::new();

    // Verify that KEM metrics are accessible
    let kem_metrics = metrics.kem_metrics();
    assert_eq!(kem_metrics.encaps_total(), 0);
    assert_eq!(kem_metrics.decaps_total(), 0);

    // Record some operations
    kem_metrics.record_encaps(Duration::from_micros(50));
    kem_metrics.record_decaps(Duration::from_millis(1));

    // Verify counts increased
    assert_eq!(kem_metrics.encaps_total(), 1);
    assert_eq!(kem_metrics.decaps_total(), 1);
}

#[test]
fn kem_metrics_injected_into_handshake_configs() {
    let metrics = NodeMetrics::new();
    let (client_cfg, server_cfg) = create_test_setup();

    // Inject metrics into configs
    let (client_cfg_with_metrics, server_cfg_with_metrics) =
        inject_kem_metrics_into_configs(client_cfg, server_cfg, metrics.kem_metrics());

    // Verify metrics are present
    assert!(client_cfg_with_metrics
        .handshake_config
        .kem_metrics
        .is_some());
    assert!(server_cfg_with_metrics
        .handshake_config
        .kem_metrics
        .is_some());

    // Verify they're the same instance
    let client_metrics = client_cfg_with_metrics
        .handshake_config
        .kem_metrics
        .as_ref()
        .unwrap();
    let server_metrics = server_cfg_with_metrics
        .handshake_config
        .kem_metrics
        .as_ref()
        .unwrap();

    // Record on client side
    client_metrics.record_encaps(Duration::from_micros(50));

    // Verify it's visible on server side (same Arc)
    assert_eq!(server_metrics.encaps_total(), 1);
}

#[tokio::test]
async fn kem_metrics_recorded_during_handshake() {
    use qbind_net::handshake::{ClientHandshake, ServerHandshake};

    let metrics = NodeMetrics::new();
    let (client_cfg, server_cfg) = create_test_setup();

    // Inject metrics
    let (client_cfg_with_metrics, server_cfg_with_metrics) =
        inject_kem_metrics_into_configs(client_cfg, server_cfg, metrics.kem_metrics());

    // Create handshakes
    let mut client_handshake = ClientHandshake::new(
        client_cfg_with_metrics.handshake_config.clone(),
        client_cfg_with_metrics.client_random,
    );

    let mut server_handshake = ServerHandshake::new(
        server_cfg_with_metrics.handshake_config.clone(),
        server_cfg_with_metrics.server_random,
    );

    // Perform client-side encapsulation (this should record metrics)
    let peer_kem_pk = client_cfg_with_metrics.peer_kem_pk.clone();
    let client_init = client_handshake
        .start(client_cfg_with_metrics.validator_id, &peer_kem_pk)
        .expect("client handshake start failed");

    // Verify encaps was recorded
    assert!(metrics.kem_metrics().encaps_total() > 0);

    // Perform server-side decapsulation (this should record metrics)
    let crypto = server_cfg_with_metrics.handshake_config.crypto.as_ref();
    let (_server_accept, _handshake_result) = server_handshake
        .handle_client_init(crypto, &client_init)
        .expect("server handshake failed");

    // Verify decaps was recorded
    assert!(metrics.kem_metrics().decaps_total() > 0);

    // Verify latency buckets are non-zero
    let (_, _, _, encaps_inf) = metrics.kem_metrics().encaps_latency_buckets();
    let (_, _, _, decaps_inf) = metrics.kem_metrics().decaps_latency_buckets();
    assert!(encaps_inf > 0);
    assert!(decaps_inf > 0);
}

#[test]
fn kem_metrics_formatted_in_http_endpoint() {
    let metrics = NodeMetrics::new();

    // Record some operations
    metrics
        .kem_metrics()
        .record_encaps(Duration::from_micros(50));
    metrics
        .kem_metrics()
        .record_decaps(Duration::from_millis(1));

    // Format metrics (as would be done by /metrics endpoint)
    let formatted = metrics.format_metrics();

    // Verify KEM metrics section is present
    assert!(formatted.contains("# KEM operation metrics (T137)"));
    assert!(formatted.contains("qbind_net_kem_encaps_total"));
    assert!(formatted.contains("qbind_net_kem_decaps_total"));
    assert!(formatted.contains("qbind_net_kem_encaps_latency_ms_bucket"));
    assert!(formatted.contains("qbind_net_kem_decaps_latency_ms_bucket"));

    // Verify values are present
    assert!(formatted.contains("qbind_net_kem_encaps_total 1"));
    assert!(formatted.contains("qbind_net_kem_decaps_total 1"));
}