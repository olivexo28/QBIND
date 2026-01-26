//! Integration tests for remote signer harness wiring (T149).
//!
//! These tests validate that:
//! 1. The ValidatorSignerConfig is correctly wired
//! 2. Both LocalKeystore and RemoteLoopback backends can be instantiated
//! 3. The remote signer can be used for basic signing operations

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::{MlDsa44Backend, ValidatorSigningKey};
use qbind_node::{RemoteSignerClient, SignerBackend, ValidatorSigner, ValidatorSignerConfig};

// ============================================================================
// Signer Backend Configuration Tests
// ============================================================================

/// Test that ValidatorSignerConfig defaults to LocalKeystore.
#[test]
fn validator_signer_config_defaults_to_local_keystore() {
    let cfg = ValidatorSignerConfig::default();

    assert_eq!(cfg.backend, SignerBackend::LocalKeystore);
    assert!(cfg.remote_endpoint.is_none());
}

/// Test that ValidatorSignerConfig can be created for RemoteLoopback.
#[test]
fn validator_signer_config_supports_remote_loopback() {
    let cfg = ValidatorSignerConfig {
        backend: SignerBackend::RemoteLoopback,
        remote_endpoint: None,
    };

    assert_eq!(cfg.backend, SignerBackend::RemoteLoopback);
}

/// Test that SignerBackend enum has correct variants.
#[test]
fn signer_backend_enum_variants() {
    let local = SignerBackend::LocalKeystore;
    let remote = SignerBackend::RemoteLoopback;

    assert_eq!(local, SignerBackend::LocalKeystore);
    assert_eq!(remote, SignerBackend::RemoteLoopback);

    // Test default
    assert_eq!(SignerBackend::default(), SignerBackend::LocalKeystore);
}

// ============================================================================
// RemoteSignerClient Direct Usage Tests
// ============================================================================

/// Test that RemoteSignerClient can sign proposals via loopback transport.
#[test]
fn remote_signer_client_can_sign_proposals() {
    use qbind_node::{LocalKeySigner, LoopbackSignerTransport};

    let validator_id = ValidatorId::new(1);
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));

    // Create LocalKeySigner
    let local_signer = Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));

    // Create loopback transport
    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));

    // Create RemoteSignerClient
    let client = RemoteSignerClient::new(validator_id, 100, transport);

    // Sign a test preimage
    let preimage = b"test proposal preimage";
    let signature = client.sign_proposal(preimage).expect("signing failed");

    // Verify signature
    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    let backend = MlDsa44Backend::new();
    assert!(
        backend
            .verify_proposal(1, &pk, preimage, &signature)
            .is_ok(),
        "Signature should verify"
    );
}

/// Test that RemoteSignerClient can sign votes via loopback transport.
#[test]
fn remote_signer_client_can_sign_votes() {
    use qbind_node::{LocalKeySigner, LoopbackSignerTransport};

    let validator_id = ValidatorId::new(2);
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));

    let local_signer = Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));
    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));
    let client = RemoteSignerClient::new(validator_id, 100, transport);

    let preimage = b"test vote preimage";
    let signature = client.sign_vote(preimage).expect("signing failed");

    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(2, &pk, preimage, &signature).is_ok(),
        "Vote signature should verify"
    );
}

/// Test that RemoteSignerClient can sign timeouts via loopback transport.
#[test]
fn remote_signer_client_can_sign_timeouts() {
    use qbind_consensus::qc::QuorumCertificate;
    use qbind_node::{LocalKeySigner, LoopbackSignerTransport};

    let validator_id = ValidatorId::new(3);
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));

    let local_signer = Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));
    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));
    let client = RemoteSignerClient::new(validator_id, 100, transport);

    // Sign timeout with high_qc
    let high_qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId::new(1)]);
    let signature = client
        .sign_timeout(10, Some(&high_qc))
        .expect("timeout signing failed");

    // Verify
    use qbind_consensus::timeout::timeout_signing_bytes;
    let preimage = timeout_signing_bytes(10, Some(&high_qc), validator_id);

    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(3, &pk, &preimage, &signature).is_ok(),
        "Timeout signature should verify"
    );
}

// ============================================================================
// ValidatorSigner Trait Object Tests
// ============================================================================

/// Test that RemoteSignerClient works through Arc<dyn ValidatorSigner>.
#[test]
fn remote_signer_client_works_as_trait_object() {
    use qbind_node::{LocalKeySigner, LoopbackSignerTransport};

    let validator_id = ValidatorId::new(4);
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));

    let local_signer = Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));
    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));
    let client = RemoteSignerClient::new(validator_id, 100, transport);

    // Use as trait object
    let signer: Arc<dyn ValidatorSigner> = Arc::new(client);

    assert_eq!(*signer.validator_id(), validator_id);
    assert_eq!(signer.suite_id(), 100);

    // Sign through trait object
    let preimage = b"trait object test";
    let signature = signer.sign_proposal(preimage).expect("signing failed");

    // Verify
    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    let backend = MlDsa44Backend::new();
    assert!(
        backend
            .verify_proposal(4, &pk, preimage, &signature)
            .is_ok(),
        "Signature through trait object should verify"
    );
}

// ============================================================================
// Configuration Validity Tests
// ============================================================================

/// Test that ValidatorSignerConfig can be cloned.
#[test]
fn validator_signer_config_is_cloneable() {
    let cfg1 = ValidatorSignerConfig {
        backend: SignerBackend::RemoteLoopback,
        remote_endpoint: Some("test://endpoint".to_string()),
    };

    let cfg2 = cfg1.clone();

    assert_eq!(cfg1.backend, cfg2.backend);
    assert_eq!(cfg1.remote_endpoint, cfg2.remote_endpoint);
}

/// Test that ValidatorSignerConfig Debug output is reasonable.
#[test]
fn validator_signer_config_debug_output() {
    let cfg = ValidatorSignerConfig {
        backend: SignerBackend::RemoteLoopback,
        remote_endpoint: Some("test://endpoint".to_string()),
    };

    let debug_str = format!("{:?}", cfg);

    assert!(debug_str.contains("ValidatorSignerConfig"));
    assert!(debug_str.contains("RemoteLoopback"));
    assert!(debug_str.contains("test://endpoint"));
}