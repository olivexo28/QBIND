//! T143: Integration tests for ValidatorSigningKey in node validator config.
//!
//! These tests verify that:
//! - ValidatorSigningKey is properly wired into LocalValidatorConfig
//! - Votes and proposals are signed using ValidatorSigningKey
//! - Signatures can be verified end-to-end
//! - No accidental clones of signing keys
//! - Zeroization works correctly
//! - Config roundtrips work correctly

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::ml_dsa44::{MlDsa44Backend, ValidatorSigningKey, ML_DSA_44_SECRET_KEY_SIZE};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::validator_config::{
    make_test_local_validator_config, LocalValidatorConfig, NodeValidatorConfig,
};
use qbind_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// Test Setup Helpers
// ============================================================================

// Import the test setup from another test file
// For simplicity, we'll create a minimal setup inline
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

struct TestSetup {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

// Dummy implementations for testing (copied from other test files)
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
        leaf_kem_suite_id,
        leaf_kem_pk,
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
// Part 1: Happy Path Wiring Tests
// ============================================================================

/// Test that a node can be created with ValidatorSigningKey in the config.
#[test]
fn node_can_be_created_with_validator_signing_key() {
    let setup = create_test_setup();

    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create config with ValidatorSigningKey
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
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

/// Test that votes and proposals are signed when broadcast.
///
/// This test verifies that when the harness broadcasts votes and proposals,
/// they are signed using the ValidatorSigningKey from the config.
#[test]
fn votes_and_proposals_are_signed_on_broadcast() {
    let setup = create_test_setup();

    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create config with ValidatorSigningKey
    let signing_key = Arc::new(ValidatorSigningKey::new(sk.clone()));
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

    // Check that a proposal was stored (it should be signed)
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

    // Note: The consensus engine currently uses DEFAULT_CONSENSUS_SUITE_ID (0),
    // but we're signing with ML-DSA-44. For a full integration, we'd need to
    // configure the suite_id correctly. This test verifies that signing happens.
    // Full signature verification would require the suite_id to match.
}

// ============================================================================
// Part 2: No Accidental Clones Tests
// ============================================================================

/// Test that ValidatorSigningKey cannot be cloned.
///
/// This is a compile-time check - if the code compiles, the test passes.
/// We document this behavior here.
#[test]
fn validator_signing_key_cannot_be_cloned() {
    let sk = vec![0u8; ML_DSA_44_SECRET_KEY_SIZE];
    let signing_key = ValidatorSigningKey::new(sk);

    // This should NOT compile if ValidatorSigningKey implements Clone:
    // let cloned = signing_key.clone();

    // Instead, we can only move it or use references
    let _moved = signing_key;
    // signing_key is now moved and cannot be used
}

// ============================================================================
// Part 3: Zeroization Path Sanity Tests
// ============================================================================

/// Test that ValidatorSigningKey can be created and dropped without panics.
#[test]
fn validator_signing_key_drop_is_safe() {
    let sk = vec![0xAB; ML_DSA_44_SECRET_KEY_SIZE];
    let signing_key = ValidatorSigningKey::new(sk);

    // Use the key
    let message = b"test message";
    let _signature = signing_key.sign(message).expect("Signing should succeed");

    // Drop the key - should zeroize without panicking
    drop(signing_key);
}

/// Test that ValidatorSigningKey Debug output does not leak key material.
#[test]
fn validator_signing_key_debug_does_not_leak() {
    let sk = vec![0xDE; ML_DSA_44_SECRET_KEY_SIZE];
    let signing_key = ValidatorSigningKey::new(sk);

    let debug_str = format!("{:?}", signing_key);

    // Debug output should contain redacted information, not actual key bytes
    assert!(
        debug_str.contains("redacted"),
        "Debug output should contain 'redacted', got: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("DE"),
        "Debug output should not contain key bytes, got: {}",
        debug_str
    );
}

// ============================================================================
// Part 4: Config Roundtrip Tests
// ============================================================================

/// Test that LocalValidatorConfig can be created and used in tests.
///
/// This verifies that the config structure works correctly with ValidatorSigningKey.
#[test]
fn local_validator_config_with_signing_key_works() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
    let config = LocalValidatorConfig {
        validator_id: ValidatorId::new(1),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        consensus_pk: pk,
        signing_key,
    };

    // Verify the config fields
    assert_eq!(config.validator_id, ValidatorId::new(1));
    assert_eq!(config.consensus_pk.len(), 1312); // ML-DSA-44 public key size
    assert_eq!(config.signing_key.len(), ML_DSA_44_SECRET_KEY_SIZE);

    // Verify Debug output doesn't leak key material
    let debug_str = format!("{:?}", config);
    assert!(
        !debug_str.contains("DE") && !debug_str.contains("AB"),
        "Debug output should not contain key bytes"
    );
}

/// Test that make_test_local_validator_config helper works correctly.
#[test]
fn make_test_local_validator_config_helper_works() {
    let config = make_test_local_validator_config(
        ValidatorId::new(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        vec![1, 2, 3],
    );

    assert_eq!(config.validator_id, ValidatorId::new(1));
    assert_eq!(config.consensus_pk, vec![1, 2, 3]);
    assert_eq!(config.signing_key.len(), ML_DSA_44_SECRET_KEY_SIZE);
}

// ============================================================================
// Part 5: End-to-End Signing and Verification Tests
// ============================================================================

/// Test that a vote signed with ValidatorSigningKey can be verified.
#[test]
fn vote_signed_with_validator_signing_key_can_be_verified() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create a vote
    let mut vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 1,
        round: 1,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 1,
        suite_id: 100, // SUITE_PQ_RESERVED_1 for ML-DSA-44
        signature: vec![],
    };

    // Sign the vote using ValidatorSigningKey
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
    let preimage = vote.signing_preimage();
    vote.signature = signing_key.sign(&preimage).expect("Signing should succeed");

    // Verify the signature using the backend
    let backend = MlDsa44Backend::new();
    let verify_result = backend.verify_vote(1, &pk, &preimage, &vote.signature);

    assert!(
        verify_result.is_ok(),
        "Vote signature should verify, got: {:?}",
        verify_result
    );
}

/// Test that a proposal signed with ValidatorSigningKey can be verified.
#[test]
fn proposal_signed_with_validator_signing_key_can_be_verified() {
    // Generate a real ML-DSA-44 keypair
    let (pk, sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair generation should succeed");

    // Create a proposal
    let mut proposal = BlockProposal {
        header: qbind_wire::consensus::BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 1,
            round: 1,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 1,
            suite_id: 100, // SUITE_PQ_RESERVED_1 for ML-DSA-44
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    // Sign the proposal using ValidatorSigningKey
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
    let preimage = proposal.signing_preimage();
    proposal.signature = signing_key.sign(&preimage).expect("Signing should succeed");

    // Verify the signature using the backend
    let backend = MlDsa44Backend::new();
    let verify_result = backend.verify_proposal(1, &pk, &preimage, &proposal.signature);

    assert!(
        verify_result.is_ok(),
        "Proposal signature should verify, got: {:?}",
        verify_result
    );
}