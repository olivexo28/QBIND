//! KEM operation metrics tests for KEMTLS handshake.
//!
//! This test suite validates that KEM operation metrics (encaps/decaps counts
//! and latency) are correctly recorded during KEMTLS handshakes.
//!
//! Tests cover:
//! - Successful handshake metrics collection
//! - Corrupted ciphertext path (metrics still recorded)
//! - Multi-handshake case (monotonic increase, no panics)

use std::sync::Arc;

use qbind_crypto::{
    AeadSuite, CryptoError, MlKem768Backend, SignatureSuite, StaticCryptoProvider,
    KEM_SUITE_ML_KEM_768,
};
use qbind_net::{
    ClientHandshake, ClientHandshakeConfig, KemOpMetrics, KemPrivateKey, MutualAuthMode,
    ServerHandshake, ServerHandshakeConfig,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing (reused from t135)
// ============================================================================

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

/// Create a test crypto provider with ML-KEM-768, dummy AEAD, and dummy signature suites.
fn make_ml_kem_provider(aead_suite_id: u8, sig_suite_id: u8) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(MlKem768Backend::new()))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

/// Create a synthetic NetworkDelegationCert for testing.
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

// ============================================================================
// Tests
// ============================================================================

/// Test that a successful handshake records KEM metrics correctly.
///
/// This test validates:
/// - encaps_total >= 1
/// - decaps_total >= 1
/// - At least one latency bucket is incremented for each op
#[test]
fn successful_handshake_records_metrics() {
    let kem_suite_id = KEM_SUITE_ML_KEM_768;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_ml_kem_provider(aead_suite_id, sig_suite_id));

    // Create shared metrics instance
    let metrics = Arc::new(KemOpMetrics::new());

    // Generate real ML-KEM-768 keypair
    let (server_kem_pk, server_kem_sk) =
        MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen failed");

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

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

    // Client config with metrics
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: Some(metrics.clone()),
        local_delegation_cert: None, // M8: No client cert for backward compat tests
    };

    // Server config with metrics
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: Some(metrics.clone()),
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Disabled, // M8: Disabled for backward compat tests
        trusted_client_roots: None,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Complete handshake
    let client_init = client
        .start(validator_id, &server_kem_pk)
        .expect("client start should succeed");

    let (server_accept, _server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("server handle_client_init should succeed");

    let _client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("client handle_server_accept should succeed");

    // Verify metrics
    assert!(
        metrics.encaps_total() >= 1,
        "encaps_total should be at least 1"
    );
    assert!(
        metrics.decaps_total() >= 1,
        "decaps_total should be at least 1"
    );

    // Verify latency buckets are incremented
    let (_encaps_0_1, _encaps_1, encaps_10, encaps_inf) = metrics.encaps_latency_buckets();
    assert!(encaps_inf >= 1, "encaps_latency_inf should be at least 1");
    assert!(
        encaps_10 >= 1,
        "encaps_latency_under_10ms should be at least 1"
    );

    let (_decaps_0_1, _decaps_1, decaps_10, decaps_inf) = metrics.decaps_latency_buckets();
    assert!(decaps_inf >= 1, "decaps_latency_inf should be at least 1");
    assert!(
        decaps_10 >= 1,
        "decaps_latency_under_10ms should be at least 1"
    );
}

/// Test that corrupted ciphertext still records metrics.
///
/// This test validates:
/// - KEM operations still get counted even when ciphertext is corrupted
/// - The handshake ultimately fails due to AEAD / key schedule, not due to metrics
#[test]
fn corrupted_ciphertext_still_records_metrics() {
    let kem_suite_id = KEM_SUITE_ML_KEM_768;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_ml_kem_provider(aead_suite_id, sig_suite_id));
    let metrics = Arc::new(KemOpMetrics::new());

    let (server_kem_pk, server_kem_sk) =
        MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen failed");

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

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

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: Some(metrics.clone()),
        local_delegation_cert: None, // M8: No client cert for backward compat tests
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: Some(metrics.clone()),
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Disabled, // M8: Disabled for backward compat tests
        trusted_client_roots: None,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client generates ClientInit
    let mut client_init = client
        .start(validator_id, &server_kem_pk)
        .expect("client start should succeed");

    // Corrupt the KEM ciphertext
    client_init.kem_ct[0] ^= 0xff;
    client_init.kem_ct[100] ^= 0xaa;

    // Server should still process the handshake (ML-KEM implicit rejection)
    let (server_accept, mut server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("server handle_client_init should not fail at decaps");

    // Client completes handshake
    let mut client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("client handle_server_accept should not fail");

    // Verify metrics were recorded
    assert!(
        metrics.encaps_total() >= 1,
        "encaps_total should be recorded even with corrupted ciphertext"
    );
    assert!(
        metrics.decaps_total() >= 1,
        "decaps_total should be recorded even with corrupted ciphertext"
    );

    // Verify that the handshake fails due to mismatched shared secrets (AEAD failure)
    // not due to metrics
    let aad = b"QBIND:test";
    let plaintext = b"Hello from client!";

    let ciphertext = client_result
        .session
        .c2s
        .seal(aad, plaintext)
        .expect("client c2s seal should succeed");

    // Server should fail to decrypt (wrong shared secret due to corrupted ciphertext)
    // DummyAead's tag check will pass, but decrypted plaintext will be wrong
    let decrypted = server_result
        .session
        .c2s
        .open(aad, &ciphertext)
        .expect("DummyAead open succeeds even with wrong key");

    assert_ne!(
        &decrypted[..],
        plaintext,
        "Decrypted plaintext should be wrong when shared secrets don't match"
    );
}

/// Test multiple handshakes to verify metrics aggregate correctly.
///
/// This test validates:
/// - Counts and bucket aggregates behave as expected (monotonic increase)
/// - No panics during multiple handshakes
#[test]
fn multi_handshake_metrics_aggregate() {
    let kem_suite_id = KEM_SUITE_ML_KEM_768;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_ml_kem_provider(aead_suite_id, sig_suite_id));
    let metrics = Arc::new(KemOpMetrics::new());

    let (server_kem_pk, server_kem_sk) =
        MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen failed");

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

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

    const N: usize = 7; // Number of handshakes to perform

    for i in 0..N {
        let client_cfg = ClientHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: provider.clone(),
            peer_root_network_pk: root_network_pk.clone(),
            kem_metrics: Some(metrics.clone()),
            local_delegation_cert: None, // M8: No client cert for backward compat tests
        };

        let server_cfg = ServerHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: provider.clone(),
            local_root_network_pk: root_network_pk.clone(),
            local_delegation_cert: cert_bytes.clone(),
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk.clone())),
            kem_metrics: Some(metrics.clone()),
            cookie_config: None,
            local_validator_id: validator_id,
            mutual_auth_mode: MutualAuthMode::Disabled, // M8: Disabled for backward compat tests
            trusted_client_roots: None,
        };

        let mut client_random = [0u8; 32];
        client_random[0] = i as u8; // Vary randomness slightly

        let mut server_random = [0u8; 32];
        server_random[0] = (i + 1) as u8;

        let mut client = ClientHandshake::new(client_cfg, client_random);
        let mut server = ServerHandshake::new(server_cfg, server_random);

        let client_init = client
            .start(validator_id, &server_kem_pk)
            .unwrap_or_else(|_| panic!("handshake {}: client start should succeed", i));

        let (server_accept, _server_result) = server
            .handle_client_init(&*provider, &client_init)
            .unwrap_or_else(|_| {
                panic!("handshake {}: server handle_client_init should succeed", i)
            });

        let _client_result = client
            .handle_server_accept(&*provider, &client_init, &server_accept)
            .unwrap_or_else(|_| {
                panic!(
                    "handshake {}: client handle_server_accept should succeed",
                    i
                )
            });

        // Verify metrics increase monotonically
        assert_eq!(
            metrics.encaps_total(),
            (i + 1) as u64,
            "encaps_total should increase after each handshake"
        );
        assert_eq!(
            metrics.decaps_total(),
            (i + 1) as u64,
            "decaps_total should increase after each handshake"
        );
    }

    // Final verification
    assert_eq!(metrics.encaps_total(), N as u64);
    assert_eq!(metrics.decaps_total(), N as u64);

    let (_encaps_0_1, _encaps_1, encaps_10, encaps_inf) = metrics.encaps_latency_buckets();
    assert_eq!(encaps_inf, N as u64, "encaps_latency_inf should equal N");
    assert!(
        encaps_10 >= 1,
        "encaps_latency_under_10ms should be at least 1"
    );

    let (_decaps_0_1, _decaps_1, decaps_10, decaps_inf) = metrics.decaps_latency_buckets();
    assert_eq!(decaps_inf, N as u64, "decaps_latency_inf should equal N");
    assert!(
        decaps_10 >= 1,
        "decaps_latency_under_10ms should be at least 1"
    );
}

/// Test that format_for_tests produces readable output.
#[test]
fn format_for_tests_produces_readable_output() {
    let metrics = KemOpMetrics::new();
    metrics.record_encaps(std::time::Duration::from_micros(50));
    metrics.record_decaps(std::time::Duration::from_millis(1));

    let formatted = metrics.format_for_tests();
    assert!(formatted.contains("KEM Metrics:"));
    assert!(formatted.contains("encaps_total: 1"));
    assert!(formatted.contains("decaps_total: 1"));
    assert!(formatted.contains("encaps_latency_buckets:"));
    assert!(formatted.contains("decaps_latency_buckets:"));
}