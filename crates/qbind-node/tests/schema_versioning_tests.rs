//! Tests for consensus storage schema versioning (T104).
//!
//! These tests verify:
//! - Schema version can be stored and retrieved
//! - Existing DB with no schema version key is accepted (v0 compatible)
//! - Future schema version is rejected with clear error
//! - ensure_compatible_schema behaves correctly for both storage implementations

use qbind_node::storage::{
    ensure_compatible_schema, ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage,
    StorageError, CURRENT_SCHEMA_VERSION,
};

use tempfile::TempDir;

// ============================================================================
// InMemoryConsensusStorage Schema Version Tests
// ============================================================================

#[test]
fn in_memory_schema_version_initially_none() {
    let storage = InMemoryConsensusStorage::new();

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert!(
        version.is_none(),
        "Fresh storage should have no schema version"
    );
}

#[test]
fn in_memory_schema_version_put_get_roundtrip() {
    let storage = InMemoryConsensusStorage::new();

    // Set schema version
    storage
        .put_schema_version(1)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(version, Some(1), "Schema version should be 1");

    // Update schema version
    storage
        .put_schema_version(2)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(version, Some(2), "Schema version should be updated to 2");
}

#[test]
fn in_memory_ensure_compatible_no_version_key() {
    let storage = InMemoryConsensusStorage::new();

    // No schema version key = legacy v0 = compatible
    let result = ensure_compatible_schema(&storage);
    assert!(
        result.is_ok(),
        "Missing schema version should be treated as compatible v0"
    );
}

#[test]
fn in_memory_ensure_compatible_current_version() {
    let storage = InMemoryConsensusStorage::new();

    storage
        .put_schema_version(CURRENT_SCHEMA_VERSION)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    assert!(
        result.is_ok(),
        "Current schema version should be compatible"
    );
}

#[test]
fn in_memory_ensure_compatible_older_version() {
    let storage = InMemoryConsensusStorage::new();

    // Version 0 is explicitly stored (not missing)
    storage
        .put_schema_version(0)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    assert!(
        result.is_ok(),
        "Older schema version (v0) should be compatible"
    );
}

#[test]
fn in_memory_ensure_compatible_future_version_rejected() {
    let storage = InMemoryConsensusStorage::new();

    // Set a future schema version
    let future_version = CURRENT_SCHEMA_VERSION + 1;
    storage
        .put_schema_version(future_version)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    assert!(result.is_err(), "Future schema version should be rejected");

    match result {
        Err(StorageError::IncompatibleSchema {
            stored_version,
            current_version,
        }) => {
            assert_eq!(stored_version, future_version);
            assert_eq!(current_version, CURRENT_SCHEMA_VERSION);
        }
        other => panic!("Expected IncompatibleSchema error, got {:?}", other),
    }
}

#[test]
fn in_memory_incompatible_schema_error_message() {
    let storage = InMemoryConsensusStorage::new();

    let future_version = CURRENT_SCHEMA_VERSION + 10;
    storage
        .put_schema_version(future_version)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // Verify the error message is informative
    assert!(
        err_msg.contains("incompatible schema version"),
        "Error should mention incompatible schema: {}",
        err_msg
    );
    assert!(
        err_msg.contains(&future_version.to_string()),
        "Error should mention stored version {}: {}",
        future_version,
        err_msg
    );
    assert!(
        err_msg.contains(&CURRENT_SCHEMA_VERSION.to_string()),
        "Error should mention current version {}: {}",
        CURRENT_SCHEMA_VERSION,
        err_msg
    );
}

// ============================================================================
// RocksDbConsensusStorage Schema Version Tests
// ============================================================================

#[test]
fn rocksdb_schema_version_initially_none() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert!(
        version.is_none(),
        "Fresh RocksDB should have no schema version"
    );
}

#[test]
fn rocksdb_schema_version_put_get_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Set schema version
    storage
        .put_schema_version(1)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(version, Some(1), "Schema version should be 1");

    // Update schema version
    storage
        .put_schema_version(42)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(version, Some(42), "Schema version should be updated to 42");
}

#[test]
fn rocksdb_schema_version_persists_across_reopen() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Write schema version
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");
        storage
            .put_schema_version(CURRENT_SCHEMA_VERSION)
            .expect("put_schema_version failed");
    }

    // Reopen and verify
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen database");
        let version = storage
            .get_schema_version()
            .expect("get_schema_version failed");
        assert_eq!(
            version,
            Some(CURRENT_SCHEMA_VERSION),
            "Schema version should persist across reopen"
        );
    }
}

#[test]
fn rocksdb_ensure_compatible_no_version_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // No schema version key = legacy v0 = compatible
    let result = ensure_compatible_schema(&storage);
    assert!(
        result.is_ok(),
        "Missing schema version should be treated as compatible v0"
    );
}

#[test]
fn rocksdb_ensure_compatible_current_version() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    storage
        .put_schema_version(CURRENT_SCHEMA_VERSION)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    assert!(
        result.is_ok(),
        "Current schema version should be compatible"
    );
}

#[test]
fn rocksdb_ensure_compatible_older_version() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Version 0 is explicitly stored
    storage
        .put_schema_version(0)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    assert!(
        result.is_ok(),
        "Older schema version (v0) should be compatible"
    );
}

#[test]
fn rocksdb_ensure_compatible_future_version_rejected() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Set a future schema version
    let future_version = CURRENT_SCHEMA_VERSION + 1;
    storage
        .put_schema_version(future_version)
        .expect("put_schema_version failed");

    let result = ensure_compatible_schema(&storage);
    assert!(result.is_err(), "Future schema version should be rejected");

    match result {
        Err(StorageError::IncompatibleSchema {
            stored_version,
            current_version,
        }) => {
            assert_eq!(stored_version, future_version);
            assert_eq!(current_version, CURRENT_SCHEMA_VERSION);
        }
        other => panic!("Expected IncompatibleSchema error, got {:?}", other),
    }
}

#[test]
fn rocksdb_future_version_rejected_after_reopen() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Write future schema version
    let future_version = CURRENT_SCHEMA_VERSION + 100;
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");
        storage
            .put_schema_version(future_version)
            .expect("put_schema_version failed");
    }

    // Reopen and verify rejection
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen database");
        let result = ensure_compatible_schema(&storage);
        assert!(
            result.is_err(),
            "Future schema version should be rejected after reopen"
        );

        match result {
            Err(StorageError::IncompatibleSchema {
                stored_version,
                current_version,
            }) => {
                assert_eq!(stored_version, future_version);
                assert_eq!(current_version, CURRENT_SCHEMA_VERSION);
            }
            other => panic!("Expected IncompatibleSchema error, got {:?}", other),
        }
    }
}

// ============================================================================
// Schema Version Constant Tests
// ============================================================================

#[test]
fn current_schema_version_is_one() {
    // Schema version 1 is the initial versioned layout
    assert_eq!(
        CURRENT_SCHEMA_VERSION, 1,
        "CURRENT_SCHEMA_VERSION should be 1 for the initial versioned layout"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn rocksdb_schema_version_max_u32() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Test max u32 value roundtrip
    let max_version = u32::MAX;
    storage
        .put_schema_version(max_version)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(
        version,
        Some(max_version),
        "Max u32 should roundtrip correctly"
    );

    // This should definitely be rejected as incompatible
    let result = ensure_compatible_schema(&storage);
    assert!(result.is_err(), "Max u32 version should be rejected");
}

#[test]
fn in_memory_schema_version_max_u32() {
    let storage = InMemoryConsensusStorage::new();

    // Test max u32 value roundtrip
    let max_version = u32::MAX;
    storage
        .put_schema_version(max_version)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(
        version,
        Some(max_version),
        "Max u32 should roundtrip correctly"
    );

    // This should definitely be rejected as incompatible
    let result = ensure_compatible_schema(&storage);
    assert!(result.is_err(), "Max u32 version should be rejected");
}

#[test]
fn rocksdb_schema_version_zero() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Explicitly store version 0 (different from missing key)
    storage
        .put_schema_version(0)
        .expect("put_schema_version failed");

    let version = storage
        .get_schema_version()
        .expect("get_schema_version failed");
    assert_eq!(version, Some(0), "Version 0 should roundtrip correctly");

    // Version 0 should be compatible with current
    let result = ensure_compatible_schema(&storage);
    assert!(result.is_ok(), "Version 0 should be compatible");
}

// ============================================================================
// Integration with Existing Storage Functions
// ============================================================================

#[test]
fn rocksdb_schema_version_does_not_interfere_with_other_meta_keys() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Store schema version
    storage
        .put_schema_version(CURRENT_SCHEMA_VERSION)
        .expect("put_schema_version failed");

    // Store current epoch
    storage
        .put_current_epoch(42)
        .expect("put_current_epoch failed");

    // Store last committed
    let block_id = [99u8; 32];
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed failed");

    // All values should be independently retrievable
    assert_eq!(
        storage.get_schema_version().unwrap(),
        Some(CURRENT_SCHEMA_VERSION),
        "Schema version should be correct"
    );
    assert_eq!(
        storage.get_current_epoch().unwrap(),
        Some(42),
        "Current epoch should be correct"
    );
    assert_eq!(
        storage.get_last_committed().unwrap(),
        Some(block_id),
        "Last committed should be correct"
    );
}

#[test]
fn in_memory_schema_version_does_not_interfere_with_other_fields() {
    let storage = InMemoryConsensusStorage::new();

    // Store schema version
    storage
        .put_schema_version(CURRENT_SCHEMA_VERSION)
        .expect("put_schema_version failed");

    // Store current epoch
    storage
        .put_current_epoch(100)
        .expect("put_current_epoch failed");

    // Store last committed
    let block_id = [42u8; 32];
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed failed");

    // All values should be independently retrievable
    assert_eq!(
        storage.get_schema_version().unwrap(),
        Some(CURRENT_SCHEMA_VERSION),
        "Schema version should be correct"
    );
    assert_eq!(
        storage.get_current_epoch().unwrap(),
        Some(100),
        "Current epoch should be correct"
    );
    assert_eq!(
        storage.get_last_committed().unwrap(),
        Some(block_id),
        "Last committed should be correct"
    );
}

// ============================================================================
// Harness Integration Tests (load_persisted_state)
// ============================================================================

// These tests require more setup infrastructure. The schema compatibility
// check is invoked via `load_persisted_state()` in NodeHotstuffHarness.
// The core functionality tests above verify the compatibility logic;
// these additional tests ensure it integrates correctly with the harness.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::validator_config::{make_test_local_validator_config, NodeValidatorConfig};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// Dummy crypto implementations for testing
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

/// Test that load_persisted_state succeeds when storage has no schema version (legacy v0).
#[test]
fn harness_load_persisted_state_accepts_missing_schema_version() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg, None)
            .expect("Failed to create harness")
            .with_storage(storage.clone());

    // Storage has no schema version key (legacy v0)
    assert!(storage.get_schema_version().unwrap().is_none());

    // load_persisted_state should succeed for fresh node
    let result = harness.load_persisted_state();
    assert!(
        result.is_ok(),
        "load_persisted_state should accept missing schema version"
    );
}

/// Test that load_persisted_state succeeds when storage has current schema version.
#[test]
fn harness_load_persisted_state_accepts_current_schema_version() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Pre-set schema version to current
    storage.put_schema_version(CURRENT_SCHEMA_VERSION).unwrap();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg, None)
            .expect("Failed to create harness")
            .with_storage(storage.clone());

    // load_persisted_state should succeed
    let result = harness.load_persisted_state();
    assert!(
        result.is_ok(),
        "load_persisted_state should accept current schema version"
    );
}

/// Test that load_persisted_state fails when storage has future schema version.
#[test]
fn harness_load_persisted_state_rejects_future_schema_version() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Pre-set schema version to future
    let future_version = CURRENT_SCHEMA_VERSION + 1;
    storage.put_schema_version(future_version).unwrap();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg, None)
            .expect("Failed to create harness")
            .with_storage(storage.clone());

    // load_persisted_state should fail with incompatible schema error
    let result = harness.load_persisted_state();
    assert!(
        result.is_err(),
        "load_persisted_state should reject future schema version"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("incompatible schema version"),
        "Error should mention incompatible schema: {}",
        err_msg
    );
}

/// Test with RocksDB that load_persisted_state rejects future schema version.
#[test]
fn harness_rocksdb_load_persisted_state_rejects_future_schema_version() {
    let setup = create_test_setup();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage =
        Arc::new(RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB"));

    // Pre-set schema version to future
    let future_version = CURRENT_SCHEMA_VERSION + 5;
    storage.put_schema_version(future_version).unwrap();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg, None)
            .expect("Failed to create harness")
            .with_storage(storage);

    // load_persisted_state should fail with incompatible schema error
    let result = harness.load_persisted_state();
    assert!(
        result.is_err(),
        "load_persisted_state should reject future schema version"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("incompatible schema version"),
        "Error should mention incompatible schema: {}",
        err_msg
    );
}
