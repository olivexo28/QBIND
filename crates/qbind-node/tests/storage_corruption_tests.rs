//! T109: Storage Corruption & Restart Behavior Tests
//!
//! These tests verify that QBIND behaves correctly when consensus storage
//! (RocksDB) is corrupted or inconsistent:
//!
//! - Fail-fast behavior on clearly invalid on-disk state
//! - No "silent boot" into a subtly inconsistent state
//! - Re-use of existing error paths (StorageError, StartupValidationError, NodeHotstuffHarnessError)
//!
//! # Test Scenarios
//!
//! - **Scenario A**: Missing block backing `last_committed`
//! - **Scenario B**: Corrupt QC bytes in storage
//! - **Scenario C**: Epoch mismatch (stored epoch vs provider)
//! - **Scenario D**: Incompatible schema version
//!
//! # Running These Tests
//!
//! ```bash
//! cargo test -p qbind-node --test storage_corruption_tests -- --test-threads=1
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tempfile::TempDir;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::storage::{
    ensure_compatible_schema, ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage,
    StorageError, CURRENT_SCHEMA_VERSION,
};
use qbind_node::validator_config::{make_test_local_validator_config, NodeValidatorConfig};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test BlockProposal at the given height.
fn make_test_proposal(height: u64, epoch: u64) -> BlockProposal {
    let mut parent_block_id = [0u8; 32];
    parent_block_id[0..8].copy_from_slice(&height.saturating_sub(1).to_le_bytes());

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id,
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1704067200 + height,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![0xAA, 0xBB, 0xCC],
    }
}

/// Create a test QuorumCertificate at the given height.
fn make_test_qc(height: u64, block_id: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0b00000111],
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
    }
}

/// Create a unique block_id for testing.
fn make_block_id(seed: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0..8].copy_from_slice(&seed.to_le_bytes());
    id[24..32].copy_from_slice(&(seed ^ 0xDEADBEEF).to_le_bytes());
    id
}

/// Create a validator set with the given validator IDs.
fn make_validator_set(ids: &[u64]) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = ids
        .iter()
        .map(|&i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Helper to write corrupt bytes directly to a RocksDB key.
///
/// This bypasses the storage API to simulate on-disk corruption.
fn corrupt_rocksdb_key(db_path: &std::path::Path, key: &[u8], corrupt_bytes: &[u8]) {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    let db = rocksdb::DB::open(&opts, db_path).expect("Failed to reopen RocksDB for corruption");
    db.put(key, corrupt_bytes)
        .expect("Failed to write corrupt data");
}

/// Helper to build a QC key for direct RocksDB manipulation.
fn build_qc_key(block_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 32);
    key.extend_from_slice(b"q:");
    key.extend_from_slice(block_id);
    key
}

/// Helper to build a block key for direct RocksDB manipulation.
fn build_block_key(block_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 32);
    key.extend_from_slice(b"b:");
    key.extend_from_slice(block_id);
    key
}

/// Assert that a result is an error with a message containing expected substrings.
fn assert_error_contains<T: std::fmt::Debug, E: std::fmt::Display + std::fmt::Debug>(
    result: Result<T, E>,
    error_context: &str,
    expected_substrings: &[&str],
) {
    assert!(
        result.is_err(),
        "{} should fail, got: {:?}",
        error_context,
        result
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    let any_match = expected_substrings.iter().any(|s| err_msg.contains(s));
    assert!(
        any_match,
        "{}: Error message '{}' should contain one of {:?}",
        error_context, err_msg, expected_substrings
    );
}

// ============================================================================
// Crypto test implementations (copied from schema_versioning_tests.rs)
// ============================================================================

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

fn create_single_node_config() -> NodeValidatorConfig {
    NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    }
}

// ============================================================================
// Scenario A: Missing block backing last_committed
// ============================================================================

/// Test that startup fails when `meta:last_committed` points to a block
/// that does not exist in storage.
///
/// This tests the consistency check in `load_persisted_state()`.
#[test]
fn scenario_a_missing_block_for_last_committed_in_memory() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Write a last_committed block ID, but do NOT store the actual block
    let fake_block_id = make_block_id(999);
    storage
        .put_last_committed(&fake_block_id)
        .expect("put_last_committed should succeed");

    // Verify the inconsistency exists
    assert_eq!(
        storage.get_last_committed().unwrap(),
        Some(fake_block_id),
        "last_committed should be set"
    );
    assert!(
        storage.get_block(&fake_block_id).unwrap().is_none(),
        "block should NOT exist (this is the corruption)"
    );

    // Create harness with this corrupted storage
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage);

    // Load persisted state should fail with a clear error
    let result = harness.load_persisted_state();

    assert!(
        result.is_err(),
        "load_persisted_state should fail when last_committed block is missing"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // Verify the error message indicates the problem
    assert!(
        err_msg.contains("not found") || err_msg.contains("inconsistent"),
        "Error should indicate missing/inconsistent block: {}",
        err_msg
    );
}

/// Test the same scenario with RocksDB storage.
#[test]
fn scenario_a_missing_block_for_last_committed_rocksdb() {
    let setup = create_test_setup();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage =
        Arc::new(RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB"));

    // Write a last_committed block ID, but do NOT store the actual block
    let fake_block_id = make_block_id(888);
    storage
        .put_last_committed(&fake_block_id)
        .expect("put_last_committed should succeed");

    // Create harness with this corrupted storage
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage);

    // Load persisted state should fail
    let result = harness.load_persisted_state();

    assert!(
        result.is_err(),
        "load_persisted_state should fail when last_committed block is missing in RocksDB"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("not found") || err_msg.contains("inconsistent"),
        "Error should indicate missing/inconsistent block: {}",
        err_msg
    );
}

// ============================================================================
// Scenario B: Corrupt QC bytes in storage
// ============================================================================

/// Test that corrupted QC bytes cause a decode error, not silent acceptance.
///
/// This tests the codec error path in `get_qc()`.
#[test]
fn scenario_b_corrupt_qc_bytes_rocksdb() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // First, store a valid block and QC using the storage API
    let block_id = make_block_id(100);
    let block = make_test_proposal(10, 0);
    let qc = make_test_qc(10, block_id);

    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB");
        storage
            .put_block(&block_id, &block)
            .expect("put_block should succeed");
        storage
            .put_qc(&block_id, &qc)
            .expect("put_qc should succeed");
        storage
            .put_last_committed(&block_id)
            .expect("put_last_committed should succeed");

        // Verify we can read the QC correctly first
        let loaded_qc = storage.get_qc(&block_id).expect("get_qc should succeed");
        assert!(loaded_qc.is_some(), "QC should exist after storing");
    }

    // Corrupt the QC bytes using the helper function
    let qc_key = build_qc_key(&block_id);
    let corrupt_bytes = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB]; // Invalid wire format
    corrupt_rocksdb_key(&db_path, &qc_key, &corrupt_bytes);

    // Reopen storage and try to read the corrupted QC
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    let result = storage.get_qc(&block_id);

    assert!(
        result.is_err(),
        "get_qc should fail when QC bytes are corrupted, got: {:?}",
        result
    );

    let err = result.unwrap_err();

    // Verify it's a codec/decode error
    match &err {
        StorageError::Codec(msg) => {
            assert!(
                msg.contains("decode") || msg.contains("failed"),
                "Codec error should mention decode failure: {}",
                msg
            );
        }
        other => {
            // Also accept other error types as long as it's not silent success
            eprintln!("Got non-Codec error (still acceptable): {:?}", other);
        }
    }
}

/// Test that corrupted block bytes cause a decode error.
#[test]
fn scenario_b_corrupt_block_bytes_rocksdb() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Store a valid block
    let block_id = make_block_id(200);
    let block = make_test_proposal(20, 0);

    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB");
        storage
            .put_block(&block_id, &block)
            .expect("put_block should succeed");

        // Verify we can read the block correctly first
        let loaded_block = storage
            .get_block(&block_id)
            .expect("get_block should succeed");
        assert!(loaded_block.is_some(), "Block should exist after storing");
    }

    // Corrupt the block bytes using the helper function
    let block_key = build_block_key(&block_id);
    let corrupt_bytes = vec![0x00, 0x01, 0x02]; // Too short to be a valid block
    corrupt_rocksdb_key(&db_path, &block_key, &corrupt_bytes);

    // Reopen and try to read
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    let result = storage.get_block(&block_id);

    assert!(
        result.is_err(),
        "get_block should fail when block bytes are corrupted"
    );

    let err = result.unwrap_err();
    match &err {
        StorageError::Codec(_) => {
            // Expected
        }
        other => {
            eprintln!(
                "Got non-Codec error (still acceptable as long as it's not silent): {:?}",
                other
            );
        }
    }
}

/// Test that corrupt last_committed length causes an error.
#[test]
fn scenario_b_corrupt_last_committed_length_rocksdb() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Store a valid last_committed
    let block_id = make_block_id(300);

    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB");
        storage
            .put_last_committed(&block_id)
            .expect("put_last_committed should succeed");
    }

    // Corrupt the last_committed value (wrong length)
    let corrupt_bytes = vec![0x42u8; 16]; // Should be 32 bytes
    corrupt_rocksdb_key(&db_path, b"meta:last_committed", &corrupt_bytes);

    // Reopen and try to read
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    let result = storage.get_last_committed();

    assert_error_contains(
        result,
        "get_last_committed with wrong-length value",
        &["length", "32"],
    );
}

// ============================================================================
// Scenario C: Epoch mismatch (stored epoch vs provider)
// ============================================================================

/// Test that startup fails when the stored epoch is not available in the
/// epoch state provider.
#[test]
fn scenario_c_epoch_mismatch_missing_epoch_in_provider() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Set up storage with a valid block and last_committed
    let block_id = make_block_id(400);
    let block = make_test_proposal(10, 5); // Block in epoch 5
    storage
        .put_block(&block_id, &block)
        .expect("put_block should succeed");
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed should succeed");

    // Store epoch 5 in storage
    storage
        .put_current_epoch(5)
        .expect("put_current_epoch should succeed");

    // Create epoch state provider with only epochs 0 and 1
    let validators = make_validator_set(&[1, 2, 3]);
    let epoch0 = EpochState::genesis(validators.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators);

    let provider = Arc::new(
        StaticEpochStateProvider::new()
            .with_epoch(epoch0)
            .with_epoch(epoch1),
    );

    // Create harness with this mismatched configuration
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage)
            .with_epoch_state_provider(provider);

    // Load persisted state should fail because epoch 5 is not in the provider
    let result = harness.load_persisted_state();

    assert!(
        result.is_err(),
        "load_persisted_state should fail when stored epoch is not in provider"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // Verify the error mentions the epoch problem
    assert!(
        err_msg.contains("epoch") || err_msg.contains("5"),
        "Error should mention epoch mismatch: {}",
        err_msg
    );
}

/// Test that startup succeeds when stored epoch IS in the provider.
#[test]
fn scenario_c_epoch_match_success() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Set up storage with a valid block and last_committed
    let block_id = make_block_id(500);
    let block = make_test_proposal(10, 1); // Block in epoch 1
    storage
        .put_block(&block_id, &block)
        .expect("put_block should succeed");
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed should succeed");

    // Store epoch 1 in storage
    storage
        .put_current_epoch(1)
        .expect("put_current_epoch should succeed");

    // Create epoch state provider with epochs 0 and 1
    let validators = make_validator_set(&[1, 2, 3]);
    let epoch0 = EpochState::genesis(validators.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators);

    let provider = Arc::new(
        StaticEpochStateProvider::new()
            .with_epoch(epoch0)
            .with_epoch(epoch1),
    );

    // Create harness
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage)
            .with_epoch_state_provider(provider);

    // Load persisted state should succeed
    let result = harness.load_persisted_state();

    assert!(
        result.is_ok(),
        "load_persisted_state should succeed when epoch is available: {:?}",
        result.err()
    );
}

/// Test that startup fails when epoch > 0 is stored but no provider is configured.
#[test]
fn scenario_c_epoch_without_provider() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Set up storage with a valid block
    let block_id = make_block_id(600);
    let block = make_test_proposal(10, 2); // Block in epoch 2
    storage
        .put_block(&block_id, &block)
        .expect("put_block should succeed");
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed should succeed");

    // Store epoch 2 in storage (non-zero epoch requires provider)
    storage
        .put_current_epoch(2)
        .expect("put_current_epoch should succeed");

    // Create harness WITHOUT epoch state provider
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage);
    // Note: NOT calling with_epoch_state_provider()

    // Load persisted state should fail
    let result = harness.load_persisted_state();

    assert!(
        result.is_err(),
        "load_persisted_state should fail when epoch > 0 but no provider configured"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("provider") || err_msg.contains("epoch"),
        "Error should mention missing provider or epoch: {}",
        err_msg
    );
}

// ============================================================================
// Scenario D: Incompatible schema version
// ============================================================================

/// Test that a future schema version is rejected during load_persisted_state.
#[test]
fn scenario_d_incompatible_schema_version_in_memory() {
    let setup = create_test_setup();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Write a future schema version
    let future_version = CURRENT_SCHEMA_VERSION + 10;
    storage
        .put_schema_version(future_version)
        .expect("put_schema_version should succeed");

    // Create harness
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage);

    // Load persisted state should fail due to incompatible schema
    let result = harness.load_persisted_state();

    assert!(
        result.is_err(),
        "load_persisted_state should fail with incompatible schema version"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("incompatible schema") || err_msg.contains("schema version"),
        "Error should mention incompatible schema: {}",
        err_msg
    );
}

/// Test with RocksDB storage.
#[test]
fn scenario_d_incompatible_schema_version_rocksdb() {
    let setup = create_test_setup();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage =
        Arc::new(RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB"));

    // Write a future schema version
    let future_version = CURRENT_SCHEMA_VERSION + 100;
    storage
        .put_schema_version(future_version)
        .expect("put_schema_version should succeed");

    // Create harness
    let cfg = create_single_node_config();
    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, setup.client_cfg, setup.server_cfg)
            .expect("harness creation should succeed")
            .with_storage(storage);

    // Load persisted state should fail
    let result = harness.load_persisted_state();

    assert!(
        result.is_err(),
        "load_persisted_state should fail with incompatible schema version in RocksDB"
    );
}

/// Test that ensure_compatible_schema fails for a future version written directly.
#[test]
fn scenario_d_ensure_compatible_schema_direct_check() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Create database and write future schema version directly
    {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &db_path).expect("Failed to open RocksDB");

        let future_version: u32 = CURRENT_SCHEMA_VERSION + 50;
        let version_bytes = future_version.to_be_bytes();
        db.put(b"meta:schema_version", &version_bytes)
            .expect("Failed to write schema version");
    }

    // Open with storage API and check compatibility
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    let result = ensure_compatible_schema(&storage);

    assert!(
        result.is_err(),
        "ensure_compatible_schema should fail for future version"
    );

    let err = result.unwrap_err();
    match err {
        StorageError::IncompatibleSchema {
            stored_version,
            current_version,
        } => {
            assert!(
                stored_version > current_version,
                "Stored version {} should be greater than current {}",
                stored_version,
                current_version
            );
        }
        other => {
            panic!("Expected IncompatibleSchema error, got {:?}", other);
        }
    }
}

/// Test that corrupted schema version bytes cause an error.
#[test]
fn scenario_d_corrupt_schema_version_bytes_rocksdb() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Create database and write corrupt schema version
    {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let _ = rocksdb::DB::open(&opts, &db_path).expect("Failed to open RocksDB");
    }

    // Write corrupt schema version (wrong length - should be 4 bytes)
    let corrupt_bytes = vec![0xFF, 0xFE]; // Only 2 bytes instead of 4
    corrupt_rocksdb_key(&db_path, b"meta:schema_version", &corrupt_bytes);

    // Open with storage API
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    let result = storage.get_schema_version();

    assert_error_contains(
        result,
        "get_schema_version with wrong-length bytes",
        &["length", "4"],
    );
}

// ============================================================================
// Additional edge cases
// ============================================================================

/// Test that corrupt epoch bytes cause an error.
#[test]
fn corrupt_epoch_bytes_rocksdb() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Create database
    {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let _ = rocksdb::DB::open(&opts, &db_path).expect("Failed to open RocksDB");
    }

    // Write corrupt epoch (wrong length - should be 8 bytes)
    let corrupt_bytes = vec![0xFF, 0xFE, 0xFD]; // Only 3 bytes instead of 8
    corrupt_rocksdb_key(&db_path, b"meta:current_epoch", &corrupt_bytes);

    // Open with storage API
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    let result = storage.get_current_epoch();

    assert_error_contains(
        result,
        "get_current_epoch with wrong-length bytes",
        &["length", "8"],
    );
}

/// Test that block + QC + last_committed can all coexist and be independently corrupted.
#[test]
fn independent_key_corruption_does_not_affect_others() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let block_id1 = make_block_id(700);
    let block_id2 = make_block_id(701);

    // Store multiple valid entries
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB");

        let block1 = make_test_proposal(7, 0);
        let block2 = make_test_proposal(8, 0);
        let qc1 = make_test_qc(7, block_id1);
        let qc2 = make_test_qc(8, block_id2);

        storage.put_block(&block_id1, &block1).expect("put_block 1");
        storage.put_block(&block_id2, &block2).expect("put_block 2");
        storage.put_qc(&block_id1, &qc1).expect("put_qc 1");
        storage.put_qc(&block_id2, &qc2).expect("put_qc 2");
        storage
            .put_last_committed(&block_id2)
            .expect("put_last_committed");
        storage.put_current_epoch(0).expect("put_current_epoch");
        storage
            .put_schema_version(CURRENT_SCHEMA_VERSION)
            .expect("put_schema_version");
    }

    // Corrupt only QC for block_id1 using the helper function
    let qc_key = build_qc_key(&block_id1);
    let corrupt_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    corrupt_rocksdb_key(&db_path, &qc_key, &corrupt_bytes);

    // Verify other entries are still readable
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");

    // Block 1 should still be readable
    let block1 = storage
        .get_block(&block_id1)
        .expect("get_block 1 should work");
    assert!(block1.is_some(), "Block 1 should be readable");

    // Block 2 should be readable
    let block2 = storage
        .get_block(&block_id2)
        .expect("get_block 2 should work");
    assert!(block2.is_some(), "Block 2 should be readable");

    // QC 1 should fail (corrupted)
    let qc1 = storage.get_qc(&block_id1);
    assert!(qc1.is_err(), "QC 1 should fail due to corruption");

    // QC 2 should still be readable
    let qc2 = storage.get_qc(&block_id2).expect("get_qc 2 should work");
    assert!(qc2.is_some(), "QC 2 should be readable");

    // last_committed should be readable
    let lc = storage
        .get_last_committed()
        .expect("get_last_committed should work");
    assert_eq!(lc, Some(block_id2));

    // epoch should be readable
    let epoch = storage
        .get_current_epoch()
        .expect("get_current_epoch should work");
    assert_eq!(epoch, Some(0));

    // schema version should be readable
    let schema = storage
        .get_schema_version()
        .expect("get_schema_version should work");
    assert_eq!(schema, Some(CURRENT_SCHEMA_VERSION));
}
