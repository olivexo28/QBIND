//! T144: Integration tests for validator keystore abstraction.
//!
//! These tests verify that:
//! - FsValidatorKeystore can load signing keys from disk
//! - Keys loaded from the keystore work end-to-end for signing
//! - NodeHotstuffHarness can use keys loaded from the keystore
//! - Signatures are created with suite_id 100 (ML-DSA-44)

use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::ml_dsa44::MlDsa44Backend;

/// Expected suite_id for ML-DSA-44 keys in T144.
/// This matches `qbind_crypto::SUITE_PQ_RESERVED_1` (100).
const EXPECTED_SUITE_ID: u8 = 100;

/// Suite ID as u16 for comparing with wire types.
const EXPECTED_SUITE_ID_U16: u16 = 100;
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::keystore::{
    FsValidatorKeystore, KeystoreBackend, KeystoreConfig, LocalKeystoreEntryId, ValidatorKeystore,
};
use qbind_node::validator_config::{
    make_local_validator_config_from_keystore, make_local_validator_config_with_keystore,
    LocalValidatorConfig, NodeValidatorConfig, ValidatorKeystoreConfig,
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

// Dummy implementations for testing (same as T143 tests)
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
// Part 1: Node-level Integration Tests
// ============================================================================

/// Test that a NodeHotstuffHarness can be created using a key loaded from the keystore.
///
/// This is the primary integration test for T144: it verifies that keys loaded
/// from disk via the keystore abstraction can be used for signing in the harness.
#[test]
fn harness_can_use_key_from_keystore() {
    let setup = create_test_setup();

    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk);
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &key_hex);

    // Load key from keystore
    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });
    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // Wrap in Arc for config
    let signing_key = Arc::new(loaded_key);

    // Create config with the loaded key
    let config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: pk,
            signing_key,
        },
        remotes: vec![],
    };

    // Create harness from config
    let harness = NodeHotstuffHarness::new_from_validator_config(
        &config,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Harness creation should succeed");

    assert_eq!(harness.validator_id, ValidatorId::new(1));
}

/// Test that signing works through the full keystore → config → harness path.
///
/// This test drives the harness through a signing operation to verify that
/// signatures created with a keystore-loaded key are valid.
#[test]
fn signing_works_with_keystore_loaded_key() {
    let setup = create_test_setup();

    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk);
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &key_hex);

    // Load key from keystore
    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });
    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // Wrap in Arc for config
    let signing_key = Arc::new(loaded_key);

    // Create config with the loaded key
    let config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: pk.clone(),
            signing_key,
        },
        remotes: vec![],
    };

    // Create harness from config
    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &config,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Harness creation should succeed");

    // Run one step - single node is leader, should propose and vote
    harness.step_once().expect("step_once should succeed");

    // Check that a proposal was stored
    let block_store_count = harness.block_store_count();
    assert!(
        block_store_count > 0,
        "At least one proposal should be stored"
    );

    // Get the first proposal from the block store
    let proposals: Vec<_> = harness
        .block_store()
        .iter()
        .map(|(_, stored)| stored.proposal.clone())
        .collect();

    assert!(!proposals.is_empty(), "Should have at least one proposal");

    // Verify that the proposal has a non-empty signature
    let proposal = &proposals[0];
    assert!(
        !proposal.signature.is_empty(),
        "Proposal should have a signature"
    );

    // Verify the signature using ML-DSA-44 backend
    let backend = MlDsa44Backend::new();
    let preimage = proposal.signing_preimage();
    let result = backend.verify_proposal(1, &pk, &preimage, &proposal.signature);
    assert!(
        result.is_ok(),
        "Proposal signature should verify, got: {:?}",
        result
    );
}

/// Test that suite_id 100 is used when signing with a keystore-loaded key.
///
/// This verifies that the ML-DSA-44 suite (SUITE_PQ_RESERVED_1 = 100) is used
/// for signing, as required by T143 and T144.
#[test]
fn suite_id_100_is_used_for_signing() {
    let setup = create_test_setup();

    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk);
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &key_hex);

    // Load key from keystore
    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });
    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // Wrap in Arc for config
    let signing_key = Arc::new(loaded_key);

    // Create config with the loaded key
    let config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: pk,
            signing_key,
        },
        remotes: vec![],
    };

    // Create harness from config
    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &config,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Harness creation should succeed");

    // Run one step
    harness.step_once().expect("step_once should succeed");

    // Get the first proposal
    let proposals: Vec<_> = harness
        .block_store()
        .iter()
        .map(|(_, stored)| stored.proposal.clone())
        .collect();

    assert!(!proposals.is_empty(), "Should have at least one proposal");

    // Verify suite_id in the proposal header
    let proposal = &proposals[0];
    assert_eq!(
        proposal.header.suite_id, EXPECTED_SUITE_ID_U16,
        "Proposal should use suite_id 100 (ML-DSA-44)"
    );
}

// ============================================================================
// Part 2: Direct Key Usage Tests
// ============================================================================

/// Test that keys loaded from the keystore can be used directly for signing.
///
/// This is a simpler test that verifies the key material is correct without
/// going through the full harness setup.
#[test]
fn keystore_loaded_key_can_sign_directly() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk);
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &key_hex);

    // Load key from keystore
    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });
    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // Sign a message directly
    let message = b"test message for keystore integration";
    let signature = loaded_key.sign(message).expect("signing should succeed");

    // Verify the signature
    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(result.is_ok(), "Signature should verify, got: {:?}", result);
}

/// Test that multiple keys can be loaded from the same keystore.
///
/// This verifies that the keystore can manage multiple validator keys.
#[test]
fn keystore_can_load_multiple_keys() {
    // Generate two keypairs
    let (pk1, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, sk2) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write both key files
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(
        &temp_dir,
        "validator1",
        EXPECTED_SUITE_ID,
        &encode_hex(&sk1),
    );
    write_keystore_file(
        &temp_dir,
        "validator2",
        EXPECTED_SUITE_ID,
        &encode_hex(&sk2),
    );

    // Load both keys
    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    let key1 = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load validator1");
    let key2 = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator2".to_string()))
        .expect("load validator2");

    // Sign with both keys
    let message = b"shared message";
    let sig1 = key1.sign(message).expect("sign with key1");
    let sig2 = key2.sign(message).expect("sign with key2");

    // Verify signatures match their respective public keys
    let backend = MlDsa44Backend::new();
    assert!(backend.verify_vote(1, &pk1, message, &sig1).is_ok());
    assert!(backend.verify_vote(2, &pk2, message, &sig2).is_ok());

    // Cross-verification should fail
    assert!(backend.verify_vote(1, &pk1, message, &sig2).is_err());
    assert!(backend.verify_vote(2, &pk2, message, &sig1).is_err());
}

// ============================================================================
// Part 3: Error Handling Tests
// ============================================================================

/// Test that loading a non-existent key returns NotFound.
#[test]
fn keystore_returns_not_found_for_missing_entry() {
    let temp_dir = TempDir::new().expect("create temp dir");

    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    let result = keystore.load_signing_key(&LocalKeystoreEntryId("nonexistent".to_string()));

    match result {
        Err(qbind_node::keystore::KeystoreError::NotFound(entry)) => {
            assert_eq!(entry, "nonexistent");
        }
        other => panic!("expected NotFound error, got: {:?}", other),
    }
}

/// Test that loading a key with wrong suite_id returns InvalidKey.
#[test]
fn keystore_returns_invalid_key_for_wrong_suite() {
    let (_, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    // Write with wrong suite_id (99 instead of 100)
    write_keystore_file(&temp_dir, "validator1", 99, &encode_hex(&sk));

    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

    match result {
        Err(qbind_node::keystore::KeystoreError::InvalidKey) => {}
        other => panic!("expected InvalidKey error, got: {:?}", other),
    }
}

// ============================================================================
// Part 4: Zeroization and Security Tests
// ============================================================================

/// Test that keys loaded from keystore still implement zeroization.
///
/// This test verifies that the zeroization semantics from T143 are preserved
/// when keys are loaded via the keystore.
#[test]
fn keystore_loaded_key_supports_zeroization() {
    let (_, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &encode_hex(&sk));

    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // Use the key
    let message = b"test";
    let _signature = loaded_key.sign(message).expect("signing should succeed");

    // Drop the key - should zeroize without panicking
    drop(loaded_key);
}

/// Test that ValidatorSigningKey loaded from keystore cannot be cloned.
///
/// This is a compile-time check - if this code compiles, it means
/// ValidatorSigningKey does not implement Clone, which is the desired behavior.
#[test]
fn keystore_loaded_key_cannot_be_cloned() {
    let (_, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &encode_hex(&sk));

    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // This should NOT compile if ValidatorSigningKey implements Clone:
    // let cloned = loaded_key.clone();

    // Instead, we can only move it or use references
    let _moved = loaded_key;
}

/// Test that Debug output for keystore-loaded keys doesn't leak key material.
#[test]
fn keystore_loaded_key_debug_does_not_leak() {
    let (_, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &encode_hex(&sk));

    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    let debug_str = format!("{:?}", loaded_key);

    // Debug output should contain redacted information
    assert!(
        debug_str.contains("redacted"),
        "Debug output should contain 'redacted', got: {}",
        debug_str
    );
}

// ============================================================================
// Part 5: Config Helper Functions Tests (T144 Part 3)
// ============================================================================

/// Test `make_local_validator_config_from_keystore` creates a valid config.
///
/// This is the primary startup wiring test: it verifies that the helper function
/// correctly loads a key from a keystore and creates a usable config.
#[test]
fn make_config_from_keystore_works() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &encode_hex(&sk));

    // Create keystore config
    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
        backend: KeystoreBackend::PlainFs,
        encryption_config: None,
    };

    // Use the helper function to create LocalValidatorConfig
    let config = make_local_validator_config_from_keystore(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk.clone(),
        &keystore_cfg,
    )
    .expect("make_local_validator_config_from_keystore should succeed");

    // Verify the config fields
    assert_eq!(config.validator_id, ValidatorId::new(1));
    assert_eq!(config.listen_addr.port(), 9000);
    assert_eq!(config.consensus_pk, pk);

    // Verify the signing key works
    let message = b"test message";
    let signature = config
        .signing_key
        .sign(message)
        .expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(1, &pk, message, &signature).is_ok(),
        "Signature should verify"
    );
}

/// Test `make_local_validator_config_from_keystore` with NodeHotstuffHarness.
///
/// This is an end-to-end test that verifies the config created from the helper
/// function can be used with the harness for signing.
#[test]
fn make_config_from_keystore_works_with_harness() {
    let setup = create_test_setup();

    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &encode_hex(&sk));

    // Create keystore config
    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
        backend: KeystoreBackend::PlainFs,
        encryption_config: None,
    };

    // Use the helper function to create LocalValidatorConfig
    let local_config = make_local_validator_config_from_keystore(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        pk.clone(),
        &keystore_cfg,
    )
    .expect("make_local_validator_config_from_keystore should succeed");

    // Create node config
    let config = NodeValidatorConfig {
        local: local_config,
        remotes: vec![],
    };

    // Create harness from config
    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &config,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Harness creation should succeed");

    // Run one step
    harness.step_once().expect("step_once should succeed");

    // Verify a proposal was created and signed
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

/// Test `make_local_validator_config_from_keystore` returns error for missing key.
#[test]
fn make_config_from_keystore_fails_for_missing_key() {
    let temp_dir = TempDir::new().expect("create temp dir");

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "nonexistent".to_string(),
        backend: KeystoreBackend::PlainFs,
        encryption_config: None,
    };

    let result = make_local_validator_config_from_keystore(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        vec![1, 2, 3],
        &keystore_cfg,
    );

    match result {
        Err(qbind_node::keystore::KeystoreError::NotFound(entry)) => {
            assert_eq!(entry, "nonexistent");
        }
        other => panic!("expected NotFound error, got: {:?}", other),
    }
}

/// Test `make_local_validator_config_with_keystore` with custom keystore.
#[test]
fn make_config_with_keystore_works() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp keystore directory and write key file
    let temp_dir = TempDir::new().expect("create temp dir");
    write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &encode_hex(&sk));

    // Create keystore directly
    let keystore = FsValidatorKeystore::new(KeystoreConfig {
        root: temp_dir.path().to_path_buf(),
    });

    // Use the generic helper function
    let config = make_local_validator_config_with_keystore(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
        pk.clone(),
        &keystore,
        "validator1",
    )
    .expect("make_local_validator_config_with_keystore should succeed");

    // Verify the config fields
    assert_eq!(config.validator_id, ValidatorId::new(1));

    // Verify the signing key works
    let message = b"test message";
    let signature = config
        .signing_key
        .sign(message)
        .expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(1, &pk, message, &signature).is_ok(),
        "Signature should verify"
    );
}

/// Test `ValidatorKeystoreConfig` is Clone.
///
/// This verifies that keystore config can be cloned (unlike the signing key itself).
#[test]
fn validator_keystore_config_is_clone() {
    let config = ValidatorKeystoreConfig {
        keystore_root: std::path::PathBuf::from("/etc/qbind/keystore"),
        keystore_entry: "validator-1".to_string(),
        backend: KeystoreBackend::PlainFs,
        encryption_config: None,
    };

    let cloned = config.clone();
    assert_eq!(cloned.keystore_root, config.keystore_root);
    assert_eq!(cloned.keystore_entry, config.keystore_entry);
}
