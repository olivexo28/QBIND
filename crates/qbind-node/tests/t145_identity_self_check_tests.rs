//! T145: Integration tests for validator identity self-check.
//!
//! These tests verify that:
//! - The identity self-check correctly validates matching keys
//! - The identity self-check correctly rejects mismatched keys
//! - The identity self-check correctly rejects mismatched suite IDs
//! - Startup fails fast with clear errors on mismatch
//! - No key material is leaked in error messages

use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::ValidatorPublicKey;
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, ValidatorSigningKey};

use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::keystore::{FsValidatorKeystore, KeystoreConfig};
use qbind_node::validator_config::{
    derive_validator_public_key, make_local_validator_config_with_identity_check,
    make_local_validator_config_with_keystore_and_identity_check,
    verify_signing_key_matches_identity, IdentityMismatchError, LocalValidatorIdentity,
    NodeValidatorConfig, ValidatorKeystoreConfig, EXPECTED_SUITE_ID,
};
use tempfile::TempDir;

// ============================================================================
// Test Setup Helpers
// ============================================================================

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

struct TestSetup {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

// Dummy implementations for testing (same as T143/T144 tests)
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
        ct.extend_from_slice(b"ct-padding");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok((ct, ss))
    }
    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding");
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
        leaf_kem_pk,
        leaf_kem_suite_id,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
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
// Hex encoding helper (same as keystore module)
// ============================================================================

fn encode_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Helper to create a test keystore file.
fn write_keystore_file(dir: &TempDir, entry_id: &str, suite_id: u8, key_hex: &str) {
    let path = dir.path().join(format!("{}.json", entry_id));
    let mut file = File::create(path).expect("create file");
    writeln!(
        file,
        r#"{{"suite_id": {}, "private_key_hex": "{}"}}"#,
        suite_id, key_hex
    )
    .expect("write file");
}

// ============================================================================
// Part 1: Unit Tests for verify_signing_key_matches_identity
// ============================================================================

/// Test that verify_signing_key_matches_identity succeeds for matching keys.
#[test]
fn verify_identity_succeeds_for_matching_keys() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let signing_key = ValidatorSigningKey::new(sk);

    let identity = LocalValidatorIdentity {
        validator_id: ValidatorId::new(1),
        public_key: ValidatorPublicKey(pk),
        suite_id: EXPECTED_SUITE_ID,
    };

    let result = verify_signing_key_matches_identity(&signing_key, &identity);
    assert!(
        result.is_ok(),
        "verification should succeed for matching keys"
    );
}

/// Test that verify_signing_key_matches_identity fails for wrong public key.
#[test]
fn verify_identity_fails_for_wrong_public_key() {
    // Generate two keypairs
    let (_, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, _) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let signing_key = ValidatorSigningKey::new(sk1);

    // Create identity with pk2 (different from sk1)
    let identity = LocalValidatorIdentity {
        validator_id: ValidatorId::new(1),
        public_key: ValidatorPublicKey(pk2),
        suite_id: EXPECTED_SUITE_ID,
    };

    let result = verify_signing_key_matches_identity(&signing_key, &identity);

    match result {
        Err(IdentityMismatchError::PublicKeyMismatch { validator_id }) => {
            assert_eq!(validator_id, ValidatorId::new(1));
        }
        other => panic!("expected PublicKeyMismatch error, got: {:?}", other),
    }
}

/// Test that verify_signing_key_matches_identity fails for wrong suite ID.
#[test]
fn verify_identity_fails_for_wrong_suite_id() {
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let signing_key = ValidatorSigningKey::new(sk);

    // Create identity with wrong suite ID (99 instead of 100)
    let identity = LocalValidatorIdentity {
        validator_id: ValidatorId::new(1),
        public_key: ValidatorPublicKey(pk),
        suite_id: ConsensusSigSuiteId::new(99), // Wrong!
    };

    let result = verify_signing_key_matches_identity(&signing_key, &identity);

    match result {
        Err(IdentityMismatchError::SuiteIdMismatch {
            validator_id,
            expected,
            actual,
        }) => {
            assert_eq!(validator_id, ValidatorId::new(1));
            assert_eq!(expected, EXPECTED_SUITE_ID);
            assert_eq!(actual, ConsensusSigSuiteId::new(99));
        }
        other => panic!("expected SuiteIdMismatch error, got: {:?}", other),
    }
}

/// Test that error messages do not contain key material.
#[test]
fn error_messages_do_not_leak_key_material() {
    let (_, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, _) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let signing_key = ValidatorSigningKey::new(sk1);

    let identity = LocalValidatorIdentity {
        validator_id: ValidatorId::new(42),
        public_key: ValidatorPublicKey(pk2.clone()),
        suite_id: EXPECTED_SUITE_ID,
    };

    let result = verify_signing_key_matches_identity(&signing_key, &identity);
    let err = result.unwrap_err();

    let error_str = format!("{}", err);
    let debug_str = format!("{:?}", err);

    // Error message should contain validator ID
    assert!(
        error_str.contains("42") || debug_str.contains("42"),
        "error should mention validator ID"
    );

    // Error message should NOT contain public key bytes (check for hex patterns)
    // Convert first few bytes of pk2 to hex and check they're not in error
    let pk2_hex_start = encode_hex(&pk2[..16]);
    assert!(
        !error_str.contains(&pk2_hex_start) && !debug_str.contains(&pk2_hex_start),
        "error should not contain public key bytes"
    );
}

// ============================================================================
// Part 2: Unit Tests for derive_validator_public_key
// ============================================================================

/// Test that derive_validator_public_key returns correct values.
#[test]
fn derive_validator_public_key_returns_correct_values() {
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let signing_key = ValidatorSigningKey::new(sk);

    let (derived_pk, suite_id) =
        derive_validator_public_key(&signing_key).expect("derivation should succeed");

    assert_eq!(derived_pk.0, pk, "derived public key should match");
    assert_eq!(suite_id, EXPECTED_SUITE_ID, "suite ID should be 100");
}

// ============================================================================
// Part 3: Integration Tests - Happy Path
// ============================================================================

/// Test that make_local_validator_config_with_identity_check succeeds for matching keys.
#[test]
fn make_config_with_identity_check_happy_path() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk));

    // Create keystore config
    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
    };

    // Use the identity-checked function
    let result = make_local_validator_config_with_identity_check(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk.clone(),
        &keystore_cfg,
    );

    assert!(
        result.is_ok(),
        "make_local_validator_config_with_identity_check should succeed for matching keys"
    );

    let config = result.unwrap();
    assert_eq!(config.validator_id, ValidatorId::new(1));
    assert_eq!(config.consensus_pk, pk);
}

/// Test that signing works after identity-checked config creation.
#[test]
fn signing_works_after_identity_check() {
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk));

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
    };

    let config = make_local_validator_config_with_identity_check(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk.clone(),
        &keystore_cfg,
    )
    .expect("config creation should succeed");

    // Verify the signing key works
    let message = b"test message for identity-checked config";
    let signature = config
        .signing_key
        .sign(message)
        .expect("signing should succeed");

    // Verify the signature
    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(1, &pk, message, &signature).is_ok(),
        "signature should verify"
    );
}

/// Test that harness can use identity-checked config.
#[test]
fn harness_works_with_identity_checked_config() {
    let setup = create_test_setup();

    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk));

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
    };

    let local_config = make_local_validator_config_with_identity_check(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        pk.clone(),
        &keystore_cfg,
    )
    .expect("config creation should succeed");

    let config = NodeValidatorConfig {
        local: local_config,
        remotes: vec![],
    };

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &config,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Harness creation should succeed");

    // Run one step
    harness.step_once().expect("step_once should succeed");

    // Verify a proposal was created
    let proposals: Vec<_> = harness
        .block_store()
        .iter()
        .map(|(_, stored)| stored.proposal.clone())
        .collect();

    assert!(!proposals.is_empty(), "Should have at least one proposal");

    // Verify the signature
    let proposal = &proposals[0];
    let backend = MlDsa44Backend::new();
    let preimage = proposal.signing_preimage();
    assert!(
        backend
            .verify_proposal(1, &pk, &preimage, &proposal.signature)
            .is_ok(),
        "Proposal signature should verify"
    );
}

// ============================================================================
// Part 4: Integration Tests - Mismatch Scenarios
// ============================================================================

/// Test that make_local_validator_config_with_identity_check fails for wrong public key.
#[test]
fn make_config_with_identity_check_fails_for_wrong_public_key() {
    // Generate two keypairs
    let (_, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, _) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Write keystore with sk1
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk1));

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
    };

    // Try to create config with pk2 (doesn't match sk1)
    let result = make_local_validator_config_with_identity_check(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk2, // Wrong public key!
        &keystore_cfg,
    );

    match result {
        Err(qbind_node::KeystoreWithIdentityError::Identity(
            IdentityMismatchError::PublicKeyMismatch { validator_id },
        )) => {
            assert_eq!(validator_id, ValidatorId::new(1));
        }
        other => panic!(
            "expected Identity(PublicKeyMismatch) error, got: {:?}",
            other
        ),
    }
}

/// Test that make_local_validator_config_with_keystore_and_identity_check fails for wrong public key.
#[test]
fn make_config_with_keystore_and_identity_check_fails_for_wrong_public_key() {
    // Generate two keypairs
    let (_, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, _) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Write keystore with sk1
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk1));

    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    // Try to create config with pk2 (doesn't match sk1)
    let result = make_local_validator_config_with_keystore_and_identity_check(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk2, // Wrong public key!
        &keystore,
        "validator1",
    );

    match result {
        Err(qbind_node::KeystoreWithIdentityError::Identity(
            IdentityMismatchError::PublicKeyMismatch { validator_id },
        )) => {
            assert_eq!(validator_id, ValidatorId::new(1));
        }
        other => panic!(
            "expected Identity(PublicKeyMismatch) error, got: {:?}",
            other
        ),
    }
}

/// Test that startup fails fast with clear error for public key mismatch.
#[test]
fn startup_fails_fast_for_public_key_mismatch() {
    let (_, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, _) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk1));

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
    };

    let result = make_local_validator_config_with_identity_check(
        ValidatorId::new(42),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk2,
        &keystore_cfg,
    );

    assert!(result.is_err(), "should fail for mismatched keys");

    let error_str = format!("{}", result.unwrap_err());
    assert!(
        error_str.contains("identity")
            || error_str.contains("public key")
            || error_str.contains("mismatch"),
        "error should mention identity or public key mismatch: {}",
        error_str
    );
}

// ============================================================================
// Part 5: Additional Edge Cases
// ============================================================================

/// Test that keystore not found error propagates correctly.
#[test]
fn keystore_not_found_error_propagates() {
    let temp_dir = TempDir::new().expect("create temp dir");
    // Don't write any keystore file

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "nonexistent".to_string(),
    };

    let result = make_local_validator_config_with_identity_check(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        vec![1, 2, 3],
        &keystore_cfg,
    );

    match result {
        Err(qbind_node::KeystoreWithIdentityError::Keystore(
            qbind_node::KeystoreError::NotFound(entry),
        )) => {
            assert_eq!(entry, "nonexistent");
        }
        other => panic!("expected Keystore(NotFound) error, got: {:?}", other),
    }
}

/// Test that identity-checked config preserves all fields correctly.
#[test]
fn identity_checked_config_preserves_all_fields() {
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", 100, &encode_hex(&sk));

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
    };

    let config = make_local_validator_config_with_identity_check(
        ValidatorId::new(42),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        pk.clone(),
        &keystore_cfg,
    )
    .expect("config creation should succeed");

    // Verify all fields are preserved
    assert_eq!(config.validator_id, ValidatorId::new(42));
    assert_eq!(
        config.listen_addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080)
    );
    assert_eq!(config.consensus_pk, pk);

    // Verify signing key works
    let message = b"test";
    let signature = config.signing_key.sign(message).expect("sign should work");
    let backend = MlDsa44Backend::new();
    assert!(backend.verify_vote(42, &pk, message, &signature).is_ok());
}

/// Test that Debug output for IdentityMismatchError doesn't leak key material.
#[test]
fn identity_mismatch_error_debug_is_safe() {
    let err = IdentityMismatchError::PublicKeyMismatch {
        validator_id: ValidatorId::new(123),
    };

    let debug_str = format!("{:?}", err);

    // Should contain validator ID
    assert!(
        debug_str.contains("123"),
        "debug should contain validator ID"
    );

    // Should NOT contain any large hex strings (key material)
    // Check that there are no 64+ character hex sequences
    let hex_pattern = debug_str.chars().filter(|c| c.is_ascii_hexdigit()).count();
    assert!(
        hex_pattern < 50,
        "debug output should not contain key bytes (hex count: {})",
        hex_pattern
    );
}

/// Test that LocalValidatorIdentity can be cloned.
#[test]
fn local_validator_identity_is_clone() {
    let identity = LocalValidatorIdentity {
        validator_id: ValidatorId::new(1),
        public_key: ValidatorPublicKey(vec![1, 2, 3]),
        suite_id: EXPECTED_SUITE_ID,
    };

    let cloned = identity.clone();
    assert_eq!(cloned.validator_id, identity.validator_id);
    assert_eq!(cloned.public_key, identity.public_key);
    assert_eq!(cloned.suite_id, identity.suite_id);
}

/// Test that EXPECTED_SUITE_ID is 100 (ML-DSA-44).
#[test]
fn expected_suite_id_is_correct() {
    assert_eq!(EXPECTED_SUITE_ID.0, 100, "EXPECTED_SUITE_ID should be 100");
}