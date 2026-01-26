//! KEMTLS handshake tests using ML-KEM-768 backend.
//!
//! This test suite validates that the KEMTLS handshake in qbind-net correctly
//! uses the ML-KEM-768 backend (implemented in T134) for key exchange.
//!
//! Tests cover:
//! - End-to-end handshake with ML-KEM-768
//! - Shared secret derivation and matching
//! - Corrupted ciphertext rejection (implicit rejection via AEAD failure)
//! - Configuration and suite selection
//!
//! # T140 Update
//!
//! This test suite now uses real ChaCha20-Poly1305 AEAD instead of DummyAead,
//! providing production-grade authenticated encryption for the KEMTLS data path.

use std::sync::Arc;

use qbind_crypto::{
    ChaCha20Poly1305Backend, CryptoError, CryptoProvider, MlKem768Backend, SignatureSuite,
    StaticCryptoProvider, AEAD_SUITE_CHACHA20_POLY1305, KEM_SUITE_ML_KEM_768,
};
use qbind_net::{
    ClientHandshake, ClientHandshakeConfig, KemPrivateKey, ServerHandshake, ServerHandshakeConfig,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing (signature only - AEAD uses real ChaCha20-Poly1305)
// ============================================================================

/// A DummySig that always verifies successfully (for testing only).
///
/// Note: Real ML-DSA-44 signatures are tested separately. This test focuses
/// on ML-KEM-768 + real AEAD integration.
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
        // Always succeed for testing
        Ok(())
    }
}

/// Create a test crypto provider with ML-KEM-768, real ChaCha20-Poly1305 AEAD, and dummy signature.
///
/// # T140 Update
///
/// This now uses `ChaCha20Poly1305Backend` instead of `DummyAead` for production-grade
/// authenticated encryption in the KEMTLS data path.
fn make_ml_kem_provider(sig_suite_id: u8) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(MlKem768Backend::new()))
        .with_aead_suite(Arc::new(ChaCha20Poly1305Backend::new()))
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
        sig_bytes: vec![0u8; 64], // Dummy signature
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that a complete KEMTLS handshake using ML-KEM-768 succeeds end-to-end.
///
/// This test validates:
/// - Client and server complete the handshake successfully
/// - The derived shared secrets match (verified via successful AEAD operations)
/// - The code path actually used ML-KEM-768 (suite ID 100)
/// - Real ChaCha20-Poly1305 AEAD works correctly with derived keys (T140)
#[test]
fn ml_kem_768_handshake_roundtrip_succeeds() {
    let kem_suite_id = KEM_SUITE_ML_KEM_768; // 100
    let aead_suite_id = AEAD_SUITE_CHACHA20_POLY1305; // 101 - real AEAD (T140)
    let sig_suite_id: u8 = 3;

    // Create test provider with ML-KEM-768 and real ChaCha20-Poly1305 AEAD
    let provider = Arc::new(make_ml_kem_provider(sig_suite_id));

    // Generate real ML-KEM-768 keypair for the server
    let (server_kem_pk, server_kem_sk) =
        MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen failed");

    // Verify key sizes match ML-KEM-768 specification
    assert_eq!(server_kem_pk.len(), 1184); // ML_KEM_768_PUBLIC_KEY_SIZE
    assert_eq!(server_kem_sk.len(), 2400); // ML_KEM_768_SECRET_KEY_SIZE

    // Create validator identity
    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    // Create delegation cert
    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    // Encode cert to bytes
    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    // Root network pk (for signature verification - dummy just accepts)
    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Client config
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    // Server config
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
    };

    // Client random
    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    // Server random
    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    // Create handshake state machines
    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Step 1: Client generates ClientInit
    let client_init = client
        .start(validator_id, &server_kem_pk)
        .expect("client start should succeed");

    // Verify ML-KEM-768 suite ID is used
    assert_eq!(client_init.kem_suite_id, KEM_SUITE_ML_KEM_768);
    assert_eq!(client_init.kem_ct.len(), 1088); // ML_KEM_768_CIPHERTEXT_SIZE

    // Step 2: Server handles ClientInit, produces ServerAccept
    let (server_accept, mut server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("server handle_client_init should succeed");

    assert_eq!(server_accept.kem_suite_id, KEM_SUITE_ML_KEM_768);
    assert_eq!(server_result.kem_suite_id, KEM_SUITE_ML_KEM_768);

    // Step 3: Client handles ServerAccept, produces HandshakeResult
    let mut client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("client handle_server_accept should succeed");

    // Verify both sides agree on metadata
    assert_eq!(client_result.kem_suite_id, server_result.kem_suite_id);
    assert_eq!(client_result.kem_suite_id, KEM_SUITE_ML_KEM_768);
    assert_eq!(client_result.aead_suite_id, server_result.aead_suite_id);
    assert_eq!(client_result.peer_validator_id, validator_id);
    assert_eq!(server_result.peer_validator_id, validator_id);

    // Step 4: Verify shared secrets match by testing AEAD operations
    // If shared secrets don't match, AEAD operations will fail
    let aad = b"QBIND:test";
    let plaintext = b"Hello from client!";

    // Client encrypts, server decrypts (c2s direction)
    let ciphertext = client_result
        .session
        .c2s
        .seal(aad, plaintext)
        .expect("client c2s seal should succeed");

    let decrypted = server_result
        .session
        .c2s
        .open(aad, &ciphertext)
        .expect("server c2s open should succeed");

    assert_eq!(&decrypted[..], plaintext);

    // Server encrypts, client decrypts (s2c direction)
    let plaintext_s2c = b"Hello from server!";
    let ciphertext_s2c = server_result
        .session
        .s2c
        .seal(aad, plaintext_s2c)
        .expect("server s2c seal should succeed");

    let decrypted_s2c = client_result
        .session
        .s2c
        .open(aad, &ciphertext_s2c)
        .expect("client s2c open should succeed");

    assert_eq!(&decrypted_s2c[..], plaintext_s2c);
}

/// Test that corrupting the KEM ciphertext causes the handshake to fail.
///
/// ML-KEM uses implicit rejection: corrupted ciphertext still produces a shared secret,
/// but it will be different from the client's secret. This causes AEAD authentication
/// to fail, which should surface as a handshake or session failure.
///
/// # T140 Update
///
/// With real ChaCha20-Poly1305 AEAD, corrupted ciphertext now correctly causes AEAD
/// authentication failure (unlike DummyAead which didn't properly reject mismatched keys).
#[test]
fn ml_kem_768_corrupted_ciphertext_causes_failure() {
    let kem_suite_id = KEM_SUITE_ML_KEM_768;
    let aead_suite_id = AEAD_SUITE_CHACHA20_POLY1305; // 101 - real AEAD (T140)
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_ml_kem_provider(sig_suite_id));

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

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
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

    // Server should still process the handshake (ML-KEM implicit rejection means
    // decapsulation succeeds but produces wrong shared secret)
    let (server_accept, mut server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("server handle_client_init should not fail at decaps");

    // Client completes handshake
    let mut client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("client handle_server_accept should not fail");

    // Now verify that the shared secrets don't match by checking AEAD authentication
    // The client and server have different shared secrets due to KEM ciphertext corruption.
    // With real ChaCha20-Poly1305, the AEAD authentication tag will fail to verify
    // because the keys are different.

    let aad = b"QBIND:test";
    let plaintext = b"Hello from client!";

    // Client encrypts with its (correct) shared secret
    let ciphertext = client_result
        .session
        .c2s
        .seal(aad, plaintext)
        .expect("client c2s seal should succeed");

    // Server tries to decrypt, but it has the wrong shared secret (due to corrupted KEM ciphertext)
    // With real ChaCha20-Poly1305, this should fail authentication
    let result = server_result.session.c2s.open(aad, &ciphertext);

    // With real AEAD, decryption should fail due to authentication failure
    assert!(
        result.is_err(),
        "Real AEAD should reject ciphertext encrypted with different key (T140)"
    );
}

/// Test that explicitly configuring ML-KEM-768 suite ID works correctly.
///
/// This verifies that the configuration path from kem_suite_id → provider → handshake
/// correctly routes to ML-KEM-768.
///
/// # T140 Update
///
/// This test now also verifies that ChaCha20-Poly1305 AEAD is correctly configured.
#[test]
fn ml_kem_768_configuration_test() {
    let kem_suite_id = KEM_SUITE_ML_KEM_768;
    let aead_suite_id = AEAD_SUITE_CHACHA20_POLY1305; // 101 - real AEAD (T140)
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_ml_kem_provider(sig_suite_id));

    // Verify provider has ML-KEM-768 registered
    let kem = provider.kem_suite(KEM_SUITE_ML_KEM_768);
    assert!(kem.is_some(), "ML-KEM-768 should be registered in provider");
    let kem = kem.unwrap();
    assert_eq!(kem.suite_id(), KEM_SUITE_ML_KEM_768);
    assert_eq!(kem.public_key_len(), 1184);
    assert_eq!(kem.ciphertext_len(), 1088);

    // T140: Verify provider has ChaCha20-Poly1305 AEAD registered
    let aead = provider.aead_suite(AEAD_SUITE_CHACHA20_POLY1305);
    assert!(
        aead.is_some(),
        "ChaCha20-Poly1305 should be registered in provider (T140)"
    );
    let aead = aead.unwrap();
    assert_eq!(aead.suite_id(), AEAD_SUITE_CHACHA20_POLY1305);
    assert_eq!(
        aead.key_len(),
        32,
        "ChaCha20-Poly1305 key length should be 32 bytes"
    );
    assert_eq!(
        aead.nonce_len(),
        12,
        "ChaCha20-Poly1305 nonce length should be 12 bytes"
    );
    assert_eq!(
        aead.tag_len(),
        16,
        "ChaCha20-Poly1305 tag length should be 16 bytes"
    );

    // Generate keypair
    let (server_kem_pk, server_kem_sk) =
        MlKem768Backend::generate_keypair().expect("keygen failed");

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

    // Explicitly configure with ML-KEM-768 suite ID
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id: KEM_SUITE_ML_KEM_768, // Explicit
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id: KEM_SUITE_ML_KEM_768, // Explicit
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Complete handshake
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    assert_eq!(client_init.kem_suite_id, KEM_SUITE_ML_KEM_768);

    let (server_accept, mut server_result) =
        server.handle_client_init(&*provider, &client_init).unwrap();
    assert_eq!(server_result.kem_suite_id, KEM_SUITE_ML_KEM_768);

    let mut client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .unwrap();
    assert_eq!(client_result.kem_suite_id, KEM_SUITE_ML_KEM_768);

    // Verify AEAD works (proves shared secrets match)
    let aad = b"QBIND:test";
    let plaintext = b"test message";
    let ciphertext = client_result.session.c2s.seal(aad, plaintext).unwrap();
    let decrypted = server_result.session.c2s.open(aad, &ciphertext).unwrap();
    assert_eq!(&decrypted[..], plaintext);
}
