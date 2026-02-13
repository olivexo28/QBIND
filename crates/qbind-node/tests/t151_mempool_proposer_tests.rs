//! T151 Integration Tests: Mempool + Proposer + Execution
//!
//! These tests verify the end-to-end flow:
//! - User submits QbindTransaction via submit_transaction()
//! - Mempool admits valid txs, rejects invalid ones
//! - Leader pulls txs from mempool for block proposals
//! - Committed blocks execute via ExecutionAdapter
//! - Mempool removes committed txs

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::ValidatorSigningKey;
use qbind_ledger::{get_account_nonce, NonceExecutionEngine, QbindTransaction, UserPublicKey};
use qbind_net::{ClientConnectionConfig, MutualAuthMode, ServerConnectionConfig};
use qbind_node::{
    validator_config::{make_test_local_validator_config, NodeValidatorConfig},
    InMemoryExecutionAdapter, InMemoryKeyProvider, InMemoryMempool, LocalKeySigner, Mempool,
    MempoolConfig, NodeHotstuffHarness,
};
use qbind_types::AccountId;

// ============================================================================
// Test Helpers
// ============================================================================

fn test_account_id(byte: u8) -> AccountId {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_signed_tx(sender: AccountId, nonce: u64, payload: &[u8], sk: &[u8]) -> QbindTransaction {
    let mut tx = QbindTransaction::new(sender, nonce, payload.to_vec());
    tx.sign(sk).expect("signing should succeed");
    tx
}

/// Create test client/server configs for the harness (copied from end-to-end test)
fn create_test_configs() -> (ClientConnectionConfig, ServerConnectionConfig) {
    use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
    use qbind_net::{ClientHandshakeConfig, KemPrivateKey, ServerHandshakeConfig};
    use qbind_wire::io::WireEncode;
    use qbind_wire::net::NetworkDelegationCert;

    struct DummyKem(u8);
    impl KemSuite for DummyKem {
        fn suite_id(&self) -> u8 {
            self.0
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
            ct.resize(48, 0);
            let mut ss = pk.to_vec();
            ss.resize(48, 0);
            Ok((ct, ss))
        }
        fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let mut ss = ct[..32.min(ct.len())].to_vec();
            ss.resize(48, 0);
            Ok(ss)
        }
    }

    struct DummySig(u8);
    impl SignatureSuite for DummySig {
        fn suite_id(&self) -> u8 {
            self.0
        }
        fn public_key_len(&self) -> usize {
            32
        }
        fn signature_len(&self) -> usize {
            64
        }
        fn verify(&self, _pk: &[u8], _msg: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    struct DummyAead(u8);
    impl AeadSuite for DummyAead {
        fn suite_id(&self) -> u8 {
            self.0
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
            let xor = key.first().copied().unwrap_or(0);
            let mut ct: Vec<u8> = plaintext.iter().map(|b| b ^ xor).collect();
            let tag = ct.iter().fold(0u8, |acc, &b| acc ^ b);
            ct.push(tag);
            Ok(ct)
        }
        fn open(
            &self,
            key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            ct_tag: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            if ct_tag.is_empty() {
                return Err(CryptoError::InvalidCiphertext);
            }
            let (ct, tag_slice) = ct_tag.split_at(ct_tag.len() - 1);
            let expected_tag = ct.iter().fold(0u8, |acc, &b| acc ^ b);
            if tag_slice[0] != expected_tag {
                return Err(CryptoError::InvalidCiphertext);
            }
            let xor = key.first().copied().unwrap_or(0);
            Ok(ct.iter().map(|b| b ^ xor).collect())
        }
    }

    let provider = Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem(1)))
            .with_aead_suite(Arc::new(DummyAead(2)))
            .with_signature_suite(Arc::new(DummySig(3))),
    );

    let validator_id = [0u8; 32];
    let root_key_id = [0u8; 32];
    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let cert = NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id: 1,
        leaf_kem_pk: server_kem_pk.clone(),
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id: 3,
        sig_bytes: vec![0u8; 64],
    };

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let client_cfg = ClientConnectionConfig {
        handshake_config: ClientHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: provider.clone(),
            peer_root_network_pk: vec![0u8; 32],
            kem_metrics: None,
            local_delegation_cert: None, // M8: No client cert for backward compat tests
        },
        client_random: [0u8; 32],
        validator_id,
        peer_kem_pk: server_kem_pk,
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: ServerHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: provider,
            local_root_network_pk: vec![0u8; 32],
            local_delegation_cert: cert_bytes,
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: validator_id,
            mutual_auth_mode: MutualAuthMode::Disabled, // M8: Disabled for backward compat tests
            trusted_client_roots: None,
        },
        server_random: [0u8; 32],
    };

    (client_cfg, server_cfg)
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Test: End-to-end transaction flow from submission to execution
///
/// 1. Create harness with mempool and execution adapter
/// 2. Submit valid transactions via submit_transaction()
/// 3. Drive consensus until block is proposed and committed
/// 4. Verify transactions were executed (nonces updated)
/// 5. Verify mempool is empty after commit
#[test]
fn test_end_to_end_tx_inclusion() {
    // Generate a keypair for transactions
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);
    let sender = test_account_id(0xAA);

    // Create key provider for mempool signature verification
    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(sender, pk.clone());

    // Create mempool with key provider
    let mempool_config = MempoolConfig {
        max_txs: 100,
        max_nonce_gap: 1000,
        gas_config: None,
        enable_fee_priority: false,
    };
    let mempool = Arc::new(InMemoryMempool::with_key_provider(
        mempool_config,
        Arc::new(key_provider),
    ));

    // Create execution adapter
    let engine = NonceExecutionEngine::new();
    let adapter = Arc::new(Mutex::new(InMemoryExecutionAdapter::new(engine)));

    // Create a single-node harness with proper config
    let local_id = ValidatorId::new(1);
    let (client_cfg, server_cfg) = create_test_configs();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            local_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let _validators = ConsensusValidatorSet::new(vec![ValidatorSetEntry {
        id: local_id,
        voting_power: 1,
    }])
    .expect("validator set creation failed");

    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation failed")
            .with_mempool(mempool.clone())
            .with_execution_adapter(adapter.clone())
            .with_max_txs_per_block(10);

    // Create and set up a signer
    let (_signer_pk_bytes, signer_sk) =
        MlDsa44Backend::generate_keypair().expect("signer keygen failed");
    let signing_key = ValidatorSigningKey::new(signer_sk);
    let signer = Arc::new(LocalKeySigner::new(local_id, 100, Arc::new(signing_key)));
    harness = harness.with_signer(signer);

    // Submit 3 valid transactions
    let tx1 = make_signed_tx(sender, 0, b"tx1", &sk);
    let tx2 = make_signed_tx(sender, 1, b"tx2", &sk);
    let tx3 = make_signed_tx(sender, 2, b"tx3", &sk);

    harness.submit_transaction(tx1).expect("tx1 submit failed");
    harness.submit_transaction(tx2).expect("tx2 submit failed");
    harness.submit_transaction(tx3).expect("tx3 submit failed");

    // Verify mempool has 3 txs
    assert_eq!(mempool.size(), 3, "mempool should have 3 transactions");

    // Drive consensus until we get a commit
    // We need to step multiple times to get through proposal -> vote -> commit
    let mut committed_height: Option<u64> = None;
    for i in 0..20 {
        harness.step_once().expect("step_once failed");

        if let Some(height) = harness.committed_height() {
            if height > 0 {
                committed_height = Some(height);
                eprintln!(
                    "[Test] Committed block at height {} after {} steps",
                    height,
                    i + 1
                );
                break;
            }
        }
    }

    assert!(
        committed_height.is_some(),
        "Expected at least one commit after 20 steps"
    );

    // Verify mempool is now empty (txs were removed on commit)
    assert_eq!(mempool.size(), 0, "mempool should be empty after commit");

    // Verify execution state: all 3 txs should have been executed
    let adapter_lock = adapter.lock();
    let state = adapter_lock.state();

    // Check that nonce for sender is now 3 (0, 1, 2 executed)
    let nonce = get_account_nonce(state, &sender);
    assert_eq!(nonce, 3, "nonce should be 3 after executing txs 0, 1, 2");
}

/// Test: Mempool rejects transactions when at capacity
#[test]
fn test_mempool_capacity_enforcement() {
    // Create mempool with small capacity
    let mempool_config = MempoolConfig {
        max_txs: 2,
        max_nonce_gap: 0, // Disable nonce checking for this test
        gas_config: None,
        enable_fee_priority: false,
    };
    let mempool = Arc::new(InMemoryMempool::with_config(mempool_config));

    // Create a single-node harness
    let local_id = ValidatorId::new(1);
    let (client_cfg, server_cfg) = create_test_configs();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            local_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation failed")
            .with_mempool(mempool.clone())
            .with_max_txs_per_block(10);

    let sender = test_account_id(0xBB);
    let tx1 = QbindTransaction::new(sender, 0, b"tx1".to_vec());
    let tx2 = QbindTransaction::new(sender, 1, b"tx2".to_vec());
    let tx3 = QbindTransaction::new(sender, 2, b"tx3".to_vec());

    // First two should succeed
    assert!(harness.submit_transaction(tx1).is_ok());
    assert!(harness.submit_transaction(tx2).is_ok());
    assert_eq!(mempool.size(), 2);

    // Third should fail (capacity reached)
    let result = harness.submit_transaction(tx3);
    assert!(result.is_err());
    assert_eq!(mempool.size(), 2, "mempool size should not increase");
}

/// Test: Invalid transactions are rejected at mempool admission
#[test]
fn test_invalid_tx_rejection() {
    // Generate a keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);
    let sender = test_account_id(0xCC);

    // Create key provider
    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(sender, pk);

    // Create mempool with key provider (signature verification enabled)
    let mempool_config = MempoolConfig {
        max_txs: 100,
        max_nonce_gap: 1000,
        gas_config: None,
        enable_fee_priority: false,
    };
    let mempool = Arc::new(InMemoryMempool::with_key_provider(
        mempool_config,
        Arc::new(key_provider),
    ));

    // Create harness
    let local_id = ValidatorId::new(1);
    let (client_cfg, server_cfg) = create_test_configs();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            local_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation failed")
            .with_mempool(mempool.clone())
            .with_max_txs_per_block(10);

    // Valid tx should succeed
    let valid_tx = make_signed_tx(sender, 0, b"valid", &sk);
    assert!(harness.submit_transaction(valid_tx).is_ok());
    assert_eq!(mempool.size(), 1);

    // Invalid tx (bad signature) should fail
    let mut invalid_tx = QbindTransaction::new(sender, 1, b"invalid".to_vec());
    // Use ML_DSA_44_SIGNATURE_SIZE from qbind_crypto
    use qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE;
    invalid_tx.signature = qbind_ledger::UserSignature::new(vec![0u8; ML_DSA_44_SIGNATURE_SIZE]);
    let result = harness.submit_transaction(invalid_tx);
    assert!(result.is_err(), "invalid tx should be rejected");
    assert_eq!(mempool.size(), 1, "mempool size should not increase");
}

/// Test: Deterministic transaction ordering
///
/// Submit same txs in same order to two mempools, verify they produce
/// same ordering of candidates.
#[test]
fn test_deterministic_tx_order() {
    // Create two identical mempools
    let config = MempoolConfig {
        max_txs: 100,
        max_nonce_gap: 0,
        gas_config: None,
        enable_fee_priority: false,
    };
    let mempool1 = InMemoryMempool::with_config(config.clone());
    let mempool2 = InMemoryMempool::with_config(config);

    let sender = test_account_id(0xDD);

    // Submit same txs to both mempools
    for i in 0..5 {
        let tx = QbindTransaction::new(sender, i, format!("tx{}", i).into_bytes());
        mempool1.insert(tx.clone()).expect("insert failed");
        mempool2.insert(tx).expect("insert failed");
    }

    // Get candidates from both
    let candidates1 = mempool1.get_block_candidates(10);
    let candidates2 = mempool2.get_block_candidates(10);

    // Should be identical
    assert_eq!(candidates1.len(), candidates2.len());
    for (tx1, tx2) in candidates1.iter().zip(candidates2.iter()) {
        assert_eq!(tx1.sender, tx2.sender);
        assert_eq!(tx1.nonce, tx2.nonce);
        assert_eq!(tx1.payload, tx2.payload);
    }
}

/// Test: Proposer respects max_txs_per_block limit
///
/// Fill mempool with many txs, verify proposal only includes up to max_txs_per_block.
#[test]
fn test_max_txs_per_block_limit() {
    // Create mempool with many slots
    let mempool_config = MempoolConfig {
        max_txs: 1000,
        max_nonce_gap: 0,
        gas_config: None,
        enable_fee_priority: false,
    };
    let mempool = Arc::new(InMemoryMempool::with_config(mempool_config));

    // Create execution adapter
    let engine = NonceExecutionEngine::new();
    let adapter = Arc::new(Mutex::new(InMemoryExecutionAdapter::new(engine)));

    // Create harness with small max_txs_per_block
    let local_id = ValidatorId::new(1);
    let (client_cfg, server_cfg) = create_test_configs();

    let cfg = NodeValidatorConfig {
        local: make_test_local_validator_config(
            local_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            vec![],
        ),
        remotes: vec![],
    };

    let mut harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation failed")
            .with_mempool(mempool.clone())
            .with_execution_adapter(adapter.clone())
            .with_max_txs_per_block(3); // Only 3 txs per block

    // Set up signer
    let (_signer_pk_bytes, signer_sk) =
        MlDsa44Backend::generate_keypair().expect("signer keygen failed");
    let signing_key = ValidatorSigningKey::new(signer_sk);
    let signer = Arc::new(LocalKeySigner::new(local_id, 100, Arc::new(signing_key)));
    harness = harness.with_signer(signer);

    // Submit 10 transactions (all without signatures for simplicity)
    let sender = test_account_id(0xEE);
    for i in 0..10 {
        let tx = QbindTransaction::new(sender, i, format!("tx{}", i).into_bytes());
        mempool.insert(tx).expect("insert failed");
    }

    assert_eq!(mempool.size(), 10);

    // Drive consensus to get a commit
    for _ in 0..20 {
        harness.step_once().expect("step_once failed");
        if harness.committed_height().is_some() {
            break;
        }
    }

    // Check that only 3 txs were executed (max_txs_per_block limit)
    let adapter_lock = adapter.lock();
    let state = adapter_lock.state();
    let nonce = get_account_nonce(state, &sender);

    // We expect 3 txs executed (nonce 0, 1, 2)
    assert_eq!(
        nonce, 3,
        "Only 3 txs should be executed due to max_txs_per_block"
    );

    // Mempool should have 7 remaining (10 - 3)
    assert_eq!(mempool.size(), 7, "mempool should have 7 remaining txs");
}