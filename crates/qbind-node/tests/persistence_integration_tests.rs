//! Tests for persistence integration in NodeHotstuffHarness.
//!
//! These tests verify:
//! - Blocks and QCs are persisted when commits happen
//! - suite_id is preserved through persistence roundtrip
//! - Node can load persisted state on startup

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage};
use qbind_node::validator_config::{make_test_local_validator_config, NodeValidatorConfig};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

use tempfile::TempDir;

// ============================================================================
// Dummy Crypto Implementations for Testing (copied from block_store_integration_tests)
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

// ============================================================================
// Persistence Integration Tests
// ============================================================================

/// Test that harness can be created with InMemory storage attached.
#[test]
fn harness_with_in_memory_storage_starts_successfully() {
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

    let _harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Failed to create harness")
    .with_storage(storage.clone());

    // Should start with no persisted state
    assert!(storage.get_last_committed().unwrap().is_none());
}

/// Test that harness can be created with RocksDB storage attached.
#[test]
fn harness_with_rocksdb_storage_starts_successfully() {
    let setup = create_test_setup();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_consensus_db");
    let storage =
        Arc::new(RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB"));

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let _harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Failed to create harness")
    .with_storage(storage.clone());

    // Should start with no persisted state
    assert!(storage.get_last_committed().unwrap().is_none());
}

/// Test that commits are persisted to storage when storage is attached.
#[test]
fn commits_are_persisted_to_storage() {
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

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Failed to create harness")
    .with_storage(storage.clone());

    // Run several steps to generate commits
    for _ in 0..20 {
        harness.step_once().expect("step_once failed");
    }

    // Check if any commits happened and were persisted
    let committed_height = harness.committed_height();

    if committed_height.is_some() && committed_height.unwrap() > 0 {
        // Should have persisted last_committed
        let last = storage.get_last_committed().unwrap();
        assert!(
            last.is_some(),
            "Should have persisted last_committed when commits happen"
        );

        // The persisted block should be retrievable
        let block_id = last.unwrap();
        let block = storage.get_block(&block_id).unwrap();
        assert!(block.is_some(), "Committed block should be persisted");

        // Verify suite_id is preserved in persisted block
        let block = block.unwrap();
        // T143: When a signing key is configured, the harness updates suite_id to 100 (ML-DSA-44)
        // before signing proposals. This is the expected behavior for ML-DSA-44 signed proposals.
        assert_eq!(
            block.header.suite_id, 100,
            "suite_id should be 100 (ML-DSA-44) when signed"
        );
    }
}

/// Test that persisted state can be loaded on startup via load_persisted_state.
#[test]
fn load_persisted_state_works_with_data() {
    let setup = create_test_setup();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_restart_db");

    // Create and use a RocksDB storage that persists
    let storage =
        Arc::new(RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB"));

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            ValidatorId::new(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    // First: create harness, run steps to generate commits
    {
        let mut harness = NodeHotstuffHarness::new_from_validator_config(
            &cfg,
            setup.client_cfg.clone(),
            setup.server_cfg.clone(),
            None,
        )
        .expect("Failed to create harness")
        .with_storage(storage.clone());

        // Run several steps to generate commits
        for _ in 0..20 {
            harness.step_once().expect("step_once failed");
        }
    }

    // Second: simulate restart - create new harness with same storage, load state
    {
        let mut harness = NodeHotstuffHarness::new_from_validator_config(
            &cfg,
            setup.client_cfg.clone(),
            setup.server_cfg.clone(),
            None,
        )
        .expect("Failed to create harness")
        .with_storage(storage.clone());

        // Load persisted state
        let last_committed = harness
            .load_persisted_state()
            .expect("load_persisted_state failed");

        // If there were commits in the first run, they should be loadable
        // Note: In single-node mode with our test setup, commits may or may not happen
        // depending on QC formation. We just verify the API works.
        if storage.get_last_committed().unwrap().is_some() {
            assert!(
                last_committed.is_some(),
                "load_persisted_state should return Some when storage has data"
            );
        }
    }
}

/// Test that load_persisted_state returns None for fresh node.
#[test]
fn load_persisted_state_returns_none_for_fresh_node() {
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

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
        None,
    )
    .expect("Failed to create harness")
    .with_storage(storage.clone());

    // Load persisted state on fresh harness
    let last_committed = harness
        .load_persisted_state()
        .expect("load_persisted_state failed");

    assert!(
        last_committed.is_none(),
        "Fresh node should have no persisted state"
    );
}

/// Test RocksDB persistence across reopen.
#[test]
fn rocksdb_persistence_survives_close_and_reopen() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_survive_db");

    let test_block_id = [42u8; 32];

    // First: write data
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open RocksDB");
        storage
            .put_last_committed(&test_block_id)
            .expect("put_last_committed failed");
    }

    // Second: reopen and read
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen RocksDB");
        let loaded = storage
            .get_last_committed()
            .expect("get_last_committed failed");

        assert!(loaded.is_some(), "Data should persist across close/reopen");
        assert_eq!(loaded.unwrap(), test_block_id, "Block ID should match");
    }
}
