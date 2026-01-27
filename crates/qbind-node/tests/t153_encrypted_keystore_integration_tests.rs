//! T153: Integration tests for encrypted validator keystore.
//!
//! These tests verify that:
//! - EncryptedFsValidatorKeystore integrates with node startup
//! - Encrypted keys work end-to-end with consensus
//! - Identity self-check works with encrypted keys
//! - All existing T144-T152 behaviors remain unchanged

use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::DEFAULT_PBKDF2_ITERATIONS;

/// Expected suite_id for ML-DSA-44 keys.
const EXPECTED_SUITE_ID: u8 = 100;

use qbind_crypto::AeadSuite;
use qbind_node::keystore::{
    EncryptedFsValidatorKeystore, EncryptedKeystoreConfig, KeystoreBackend, LocalKeystoreEntryId,
    ValidatorKeystore,
};
use qbind_node::validator_config::{
    make_local_validator_config_from_keystore, verify_signing_key_matches_identity,
    LocalValidatorIdentity, ValidatorKeystoreConfig,
};
use tempfile::TempDir;

// ============================================================================
// Test Setup Helpers
// ============================================================================

// Helper to encode bytes as hex
fn encode_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Helper to create an encrypted keystore file.
fn write_encrypted_keystore_file(
    dir: &TempDir,
    entry_id: &str,
    suite_id: u8,
    key_hex: &str,
    passphrase: &str,
    kdf_iterations: u32,
) {
    use qbind_crypto::{
        derive_key_pbkdf2, ChaCha20Poly1305Backend, CHACHA20_POLY1305_NONCE_SIZE, PBKDF2_SALT_SIZE,
    };

    // Generate deterministic salt and nonce for testing
    let salt = {
        let mut s = [0u8; PBKDF2_SALT_SIZE];
        for (i, byte) in entry_id.as_bytes().iter().enumerate() {
            if i < PBKDF2_SALT_SIZE {
                s[i] = *byte;
            }
        }
        s
    };

    let nonce = {
        let mut n = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        for (i, byte) in entry_id.as_bytes().iter().rev().enumerate() {
            if i < CHACHA20_POLY1305_NONCE_SIZE {
                n[i] = byte.wrapping_add(1);
            }
        }
        n
    };

    // Derive encryption key
    let encryption_key = derive_key_pbkdf2(passphrase.as_bytes(), &salt, kdf_iterations);

    // Create plaintext JSON
    let plaintext_json = format!(r#"{{"private_key_hex": "{}"}}"#, key_hex);

    // Encrypt
    let aead = ChaCha20Poly1305Backend::new();
    let ciphertext = aead
        .seal(&encryption_key, &nonce, b"", plaintext_json.as_bytes())
        .expect("encryption should succeed");

    // Write encrypted file
    let path = dir.path().join(format!("{}.enc", entry_id));
    let mut file = File::create(path).expect("create file");
    writeln!(
        file,
        r#"{{
  "version": 1,
  "suite_id": {},
  "aead": "ChaCha20-Poly1305",
  "kdf": "PBKDF2-HMAC-SHA256",
  "kdf_iterations": {},
  "salt_hex": "{}",
  "nonce_hex": "{}",
  "ciphertext_hex": "{}"
}}"#,
        suite_id,
        kdf_iterations,
        encode_hex(&salt),
        encode_hex(&nonce),
        encode_hex(&ciphertext)
    )
    .expect("write file");
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn encrypted_keystore_load_and_sign() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create temp directory and encrypted keystore file
    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk);
    let passphrase = "test-encrypted-keystore-passphrase";

    // Set passphrase in environment
    std::env::set_var("QBIND_TEST_ENC_PASSPHRASE", passphrase);

    write_encrypted_keystore_file(
        &temp_dir,
        "validator1",
        EXPECTED_SUITE_ID,
        &key_hex,
        passphrase,
        DEFAULT_PBKDF2_ITERATIONS,
    );

    // Load key using encrypted keystore
    let enc_config = EncryptedKeystoreConfig {
        passphrase_env_var: "QBIND_TEST_ENC_PASSPHRASE".to_string(),
        kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
    };
    let keystore = EncryptedFsValidatorKeystore::new(temp_dir.path().to_path_buf(), enc_config);
    let loaded_key = keystore
        .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
        .expect("load_signing_key should succeed");

    // Sign a message
    let message = b"consensus vote for block 42";
    let signature = loaded_key.sign(message).expect("signing should succeed");

    // Verify signature with the original public key
    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(
        result.is_ok(),
        "signature verification should succeed, got: {:?}",
        result
    );

    // Clean up
    std::env::remove_var("QBIND_TEST_ENC_PASSPHRASE");
}

#[test]
fn encrypted_keystore_with_identity_check() {
    use qbind_crypto::ConsensusSigSuiteId;

    // Generate keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk);
    let passphrase = "identity-check-passphrase";

    std::env::set_var("QBIND_TEST_IDENTITY_PASSPHRASE", passphrase);

    write_encrypted_keystore_file(
        &temp_dir,
        "validator1",
        EXPECTED_SUITE_ID,
        &key_hex,
        passphrase,
        DEFAULT_PBKDF2_ITERATIONS,
    );

    // Create ValidatorKeystoreConfig with encrypted backend
    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
        backend: KeystoreBackend::EncryptedFsV1,
        encryption_config: Some(EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_IDENTITY_PASSPHRASE".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        }),
    };

    // Load validator config
    let validator_id = ValidatorId::new(1);
    let listen_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let local_config = make_local_validator_config_from_keystore(
        validator_id,
        listen_addr,
        pk.clone(),
        &keystore_cfg,
    )
    .expect("should load config from encrypted keystore");

    // Create identity for self-check
    let identity = LocalValidatorIdentity {
        validator_id,
        public_key: qbind_consensus::ValidatorPublicKey(pk),
        suite_id: ConsensusSigSuiteId::new(EXPECTED_SUITE_ID as u16),
    };

    // Verify identity self-check passes
    let result = verify_signing_key_matches_identity(&local_config.signing_key, &identity);
    assert!(
        result.is_ok(),
        "identity self-check should pass, got: {:?}",
        result
    );

    std::env::remove_var("QBIND_TEST_IDENTITY_PASSPHRASE");
}

#[test]
fn encrypted_keystore_wrong_public_key_fails_identity_check() {
    use qbind_crypto::ConsensusSigSuiteId;

    // Generate two different keypairs
    let (pk1, sk1) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");
    let (pk2, _sk2) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let temp_dir = TempDir::new().expect("create temp dir");
    let key_hex = encode_hex(&sk1);
    let passphrase = "mismatch-check-passphrase";

    std::env::set_var("QBIND_TEST_MISMATCH_PASSPHRASE", passphrase);

    write_encrypted_keystore_file(
        &temp_dir,
        "validator1",
        EXPECTED_SUITE_ID,
        &key_hex,
        passphrase,
        DEFAULT_PBKDF2_ITERATIONS,
    );

    let keystore_cfg = ValidatorKeystoreConfig {
        keystore_root: temp_dir.path().to_path_buf(),
        keystore_entry: "validator1".to_string(),
        backend: KeystoreBackend::EncryptedFsV1,
        encryption_config: Some(EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_MISMATCH_PASSPHRASE".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        }),
    };

    let validator_id = ValidatorId::new(1);
    let listen_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

    // Load config with pk1's key
    let local_config = make_local_validator_config_from_keystore(
        validator_id,
        listen_addr,
        pk1.clone(),
        &keystore_cfg,
    )
    .expect("should load config");

    // Create identity with pk2 (mismatched)
    let identity = LocalValidatorIdentity {
        validator_id,
        public_key: qbind_consensus::ValidatorPublicKey(pk2), // Wrong public key!
        suite_id: ConsensusSigSuiteId::new(EXPECTED_SUITE_ID as u16),
    };

    // Identity check should fail
    let result = verify_signing_key_matches_identity(&local_config.signing_key, &identity);
    assert!(
        result.is_err(),
        "identity self-check should fail for mismatched public key"
    );

    std::env::remove_var("QBIND_TEST_MISMATCH_PASSPHRASE");
}
