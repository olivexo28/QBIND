//! Unit tests for the remote signer client and loopback transport (T149).
//!
//! These tests validate:
//! 1. Signature equivalence: RemoteSignerClient + LoopbackSignerTransport produces
//!    identical signatures to LocalKeySigner for the same preimages
//! 2. Suite mismatch handling: Unauthorized errors when suite_id doesn't match
//! 3. Transport error handling: Clean error propagation without panics
//! 4. Debug output redaction: No key material in Debug output

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate;
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::ValidatorSigningKey;
use qbind_node::remote_signer::{
    LoopbackSignerTransport, RemoteSignError, RemoteSignRequest, RemoteSignRequestKind,
    RemoteSignResponse, RemoteSignerClient, RemoteSignerTransport,
};
use qbind_node::validator_signer::{LocalKeySigner, SignError, ValidatorSigner};

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a deterministic test keypair and LocalKeySigner.
fn make_test_signer(validator_id: ValidatorId) -> (Vec<u8>, Arc<LocalKeySigner>) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
    let signer = Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));
    (pk, signer)
}

/// Create a RemoteSignerClient with loopback transport using the given LocalKeySigner.
fn make_loopback_client(
    validator_id: ValidatorId,
    local_signer: Arc<LocalKeySigner>,
) -> RemoteSignerClient {
    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));
    RemoteSignerClient::new(validator_id, 100, transport)
}

// ============================================================================
// Signature Equivalence Tests
// ============================================================================

/// Test that proposal signatures from RemoteSignerClient match LocalKeySigner.
#[test]
fn remote_signer_proposal_signature_equivalence() {
    let validator_id = ValidatorId::new(1);
    let (pk, local_signer) = make_test_signer(validator_id);
    let remote_client = make_loopback_client(validator_id, local_signer.clone());

    // Sign a proposal preimage
    let preimage = b"test proposal preimage with domain separator";

    let local_sig = local_signer
        .sign_proposal(preimage)
        .expect("local signing failed");

    let remote_sig = remote_client
        .sign_proposal(preimage)
        .expect("remote signing failed");

    // Note: ML-DSA signatures are non-deterministic (include randomness),
    // so signatures won't be bit-for-bit identical. Instead, we verify that
    // both signatures are valid.

    // Both should verify
    let backend = MlDsa44Backend::new();
    assert!(
        backend
            .verify_proposal(1, &pk, preimage, &local_sig)
            .is_ok(),
        "local signature should verify"
    );
    assert!(
        backend
            .verify_proposal(1, &pk, preimage, &remote_sig)
            .is_ok(),
        "remote signature should verify"
    );
}

/// Test that vote signatures from RemoteSignerClient match LocalKeySigner.
#[test]
fn remote_signer_vote_signature_equivalence() {
    let validator_id = ValidatorId::new(2);
    let (pk, local_signer) = make_test_signer(validator_id);
    let remote_client = make_loopback_client(validator_id, local_signer.clone());

    // Sign a vote preimage
    let preimage = b"test vote preimage with domain separator";

    let local_sig = local_signer
        .sign_vote(preimage)
        .expect("local signing failed");

    let remote_sig = remote_client
        .sign_vote(preimage)
        .expect("remote signing failed");

    // Note: ML-DSA signatures are non-deterministic, verify both are valid

    // Both should verify
    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(2, &pk, preimage, &local_sig).is_ok(),
        "local vote signature should verify"
    );
    assert!(
        backend.verify_vote(2, &pk, preimage, &remote_sig).is_ok(),
        "remote vote signature should verify"
    );
}

/// Test that timeout signatures from RemoteSignerClient match LocalKeySigner.
#[test]
fn remote_signer_timeout_signature_equivalence() {
    let validator_id = ValidatorId::new(3);
    let (pk, local_signer) = make_test_signer(validator_id);
    let remote_client = make_loopback_client(validator_id, local_signer.clone());

    // Sign timeout without high_qc
    let view = 10u64;
    let high_qc = None;

    let local_sig = local_signer
        .sign_timeout(view, high_qc)
        .expect("local timeout signing failed");

    let remote_sig = remote_client
        .sign_timeout(view, high_qc)
        .expect("remote timeout signing failed");

    // Note: ML-DSA signatures are non-deterministic, verify both are valid

    // Reconstruct preimage for verification
    use qbind_consensus::timeout::timeout_signing_bytes;
    let preimage = timeout_signing_bytes::<[u8; 32]>(view, high_qc, validator_id);

    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(3, &pk, &preimage, &local_sig).is_ok(),
        "local timeout signature should verify"
    );
    assert!(
        backend.verify_vote(3, &pk, &preimage, &remote_sig).is_ok(),
        "remote timeout signature should verify"
    );
}

/// Test timeout signatures with high_qc match between local and remote.
#[test]
fn remote_signer_timeout_with_high_qc_equivalence() {
    let validator_id = ValidatorId::new(4);
    let (pk, local_signer) = make_test_signer(validator_id);
    let remote_client = make_loopback_client(validator_id, local_signer.clone());

    // Create a high_qc
    let high_qc = QuorumCertificate::new([42u8; 32], 5, vec![ValidatorId::new(1)]);
    let view = 15u64;

    let local_sig = local_signer
        .sign_timeout(view, Some(&high_qc))
        .expect("local timeout signing with high_qc failed");

    let remote_sig = remote_client
        .sign_timeout(view, Some(&high_qc))
        .expect("remote timeout signing with high_qc failed");

    // Note: ML-DSA signatures are non-deterministic, verify both are valid

    // Verify both
    use qbind_consensus::timeout::timeout_signing_bytes;
    let preimage = timeout_signing_bytes(view, Some(&high_qc), validator_id);

    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(4, &pk, &preimage, &local_sig).is_ok(),
        "local timeout+high_qc signature should verify"
    );
    assert!(
        backend.verify_vote(4, &pk, &preimage, &remote_sig).is_ok(),
        "remote timeout+high_qc signature should verify"
    );
}

// ============================================================================
// Suite Mismatch Tests
// ============================================================================

/// Test that suite_id mismatch results in Unauthorized error.
#[test]
fn remote_signer_suite_mismatch_returns_error() {
    let validator_id = ValidatorId::new(5);
    let (_pk, local_signer) = make_test_signer(validator_id);

    // Create loopback transport with correct suite_id (100)
    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));

    // Create RemoteSignerClient with WRONG suite_id (200)
    let wrong_suite_client = RemoteSignerClient::new(validator_id, 200, transport);

    // Try to sign - should fail due to suite mismatch
    let preimage = b"test preimage";
    let result = wrong_suite_client.sign_proposal(preimage);

    assert!(
        result.is_err(),
        "Signing with mismatched suite_id should fail"
    );

    match result {
        Err(SignError::InvalidKey) => {
            // Expected: Unauthorized from transport maps to InvalidKey
        }
        Err(SignError::CryptoError) => {
            // Also acceptable
        }
        Ok(_) => panic!("Expected error due to suite mismatch"),
    }
}

/// Test that validator_id mismatch results in Unauthorized error.
#[test]
fn remote_signer_validator_id_mismatch_returns_error() {
    let validator_id = ValidatorId::new(6);
    let (_pk, local_signer) = make_test_signer(validator_id);

    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));

    // Create RemoteSignerClient with WRONG validator_id
    let wrong_id_client = RemoteSignerClient::new(ValidatorId::new(999), 100, transport);

    // Try to sign - should fail due to validator_id mismatch
    let preimage = b"test preimage";
    let result = wrong_id_client.sign_proposal(preimage);

    assert!(
        result.is_err(),
        "Signing with mismatched validator_id should fail"
    );
}

// ============================================================================
// Transport Error Handling Tests
// ============================================================================

/// Mock transport that always returns TransportError.
struct FailingTransport;

impl RemoteSignerTransport for FailingTransport {
    fn send_sign_request(
        &self,
        _request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError> {
        Err(RemoteSignError::TransportError)
    }
}

/// Test that transport errors are handled gracefully.
#[test]
fn remote_signer_transport_error_handling() {
    let transport = Arc::new(FailingTransport);
    let client = RemoteSignerClient::new(ValidatorId::new(7), 100, transport);

    let preimage = b"test preimage";
    let result = client.sign_proposal(preimage);

    assert!(
        result.is_err(),
        "Transport error should propagate as signing error"
    );

    match result {
        Err(SignError::CryptoError) => {
            // Expected: transport errors map to CryptoError
        }
        Err(SignError::InvalidKey) => {
            // Also acceptable
        }
        Ok(_) => panic!("Expected error from failing transport"),
    }
}

/// Mock transport that returns Timeout error.
struct TimeoutTransport;

impl RemoteSignerTransport for TimeoutTransport {
    fn send_sign_request(
        &self,
        _request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError> {
        Err(RemoteSignError::Timeout)
    }
}

/// Test that timeout errors are handled gracefully.
#[test]
fn remote_signer_timeout_error_handling() {
    let transport = Arc::new(TimeoutTransport);
    let client = RemoteSignerClient::new(ValidatorId::new(8), 100, transport);

    let result = client.sign_vote(b"test");

    assert!(
        result.is_err(),
        "Timeout error should propagate as signing error"
    );
}

/// Mock transport that returns CryptoError.
struct CryptoErrorTransport;

impl RemoteSignerTransport for CryptoErrorTransport {
    fn send_sign_request(
        &self,
        _request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError> {
        Ok(RemoteSignResponse {
            signature: None,
            error: Some(RemoteSignError::CryptoError),
        })
    }
}

/// Test that crypto errors from transport are propagated correctly.
#[test]
fn remote_signer_crypto_error_propagation() {
    let transport = Arc::new(CryptoErrorTransport);
    let client = RemoteSignerClient::new(ValidatorId::new(9), 100, transport);

    let result = client.sign_proposal(b"test");

    assert!(result.is_err(), "CryptoError should propagate");
    assert!(matches!(result, Err(SignError::CryptoError)));
}

// ============================================================================
// Debug Output Tests
// ============================================================================

/// Test that RemoteSignerClient Debug does not leak key material.
#[test]
fn remote_signer_client_debug_redacts_secrets() {
    let validator_id = ValidatorId::new(10);
    let (_pk, local_signer) = make_test_signer(validator_id);
    let client = make_loopback_client(validator_id, local_signer);

    let debug_str = format!("{:?}", client);

    assert!(debug_str.contains("RemoteSignerClient"));
    assert!(debug_str.contains("validator_id"));
    assert!(debug_str.contains("suite_id"));
    assert!(debug_str.contains("<redacted>"));
    // Should not contain any key bytes or transport details
    assert!(!debug_str.contains("signing_key"));
}

/// Test that LoopbackSignerTransport Debug does not leak key material.
#[test]
fn loopback_transport_debug_redacts_secrets() {
    let validator_id = ValidatorId::new(11);
    let (_pk, local_signer) = make_test_signer(validator_id);
    let transport = LoopbackSignerTransport::new(local_signer);

    let debug_str = format!("{:?}", transport);

    assert!(debug_str.contains("LoopbackSignerTransport"));
    assert!(debug_str.contains("<redacted>"));
    // Should not contain key material
    assert!(!debug_str.contains("[0, 0, 0"));
}

// ============================================================================
// ValidatorSigner Trait Tests
// ============================================================================

/// Test that RemoteSignerClient can be used as Arc<dyn ValidatorSigner>.
#[test]
fn remote_signer_client_as_trait_object() {
    let validator_id = ValidatorId::new(12);
    let (pk, local_signer) = make_test_signer(validator_id);
    let client = make_loopback_client(validator_id, local_signer);

    // Use as trait object
    let signer: Arc<dyn ValidatorSigner> = Arc::new(client);

    assert_eq!(*signer.validator_id(), validator_id);
    assert_eq!(signer.suite_id(), 100);

    // Sign through trait object
    let preimage = b"trait object test";
    let signature = signer.sign_proposal(preimage).expect("signing failed");

    // Verify
    let backend = MlDsa44Backend::new();
    assert!(
        backend
            .verify_proposal(12, &pk, preimage, &signature)
            .is_ok(),
        "signature from trait object should verify"
    );
}

/// Test that RemoteSignerClient is Send + Sync.
#[test]
fn remote_signer_client_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RemoteSignerClient>();
    assert_send_sync::<LoopbackSignerTransport>();
}

// ============================================================================
// Request/Response Type Tests
// ============================================================================

/// Test RemoteSignRequestKind enum.
#[test]
fn remote_sign_request_kind_variants() {
    let proposal = RemoteSignRequestKind::Proposal;
    let vote = RemoteSignRequestKind::Vote;
    let timeout = RemoteSignRequestKind::Timeout;

    assert_eq!(proposal, RemoteSignRequestKind::Proposal);
    assert_eq!(vote, RemoteSignRequestKind::Vote);
    assert_eq!(timeout, RemoteSignRequestKind::Timeout);

    // Test Debug
    assert!(format!("{:?}", proposal).contains("Proposal"));
}

/// Test RemoteSignError variants and Display.
#[test]
fn remote_sign_error_display() {
    let errors = vec![
        RemoteSignError::InvalidKey,
        RemoteSignError::CryptoError,
        RemoteSignError::Unauthorized,
        RemoteSignError::TransportError,
        RemoteSignError::Timeout,
    ];

    for error in errors {
        let display_str = format!("{}", error);
        assert!(!display_str.is_empty(), "Error should have display message");

        // Should not contain sensitive data
        assert!(!display_str.contains("0x"));
        assert!(!display_str.contains("["));
    }
}

/// Test RemoteSignRequest construction.
#[test]
fn remote_sign_request_construction() {
    let request = RemoteSignRequest {
        validator_id: ValidatorId::new(1),
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: vec![1, 2, 3, 4],
    };

    assert_eq!(request.validator_id, ValidatorId::new(1));
    assert_eq!(request.suite_id, 100);
    assert_eq!(request.kind, RemoteSignRequestKind::Proposal);
    assert_eq!(request.view, None);
    assert_eq!(request.preimage, vec![1, 2, 3, 4]);
}

/// Test RemoteSignResponse construction.
#[test]
fn remote_sign_response_construction() {
    // Success case
    let success = RemoteSignResponse {
        signature: Some(vec![1, 2, 3]),
        error: None,
    };
    assert!(success.signature.is_some());
    assert!(success.error.is_none());

    // Error case
    let error = RemoteSignResponse {
        signature: None,
        error: Some(RemoteSignError::CryptoError),
    };
    assert!(error.signature.is_none());
    assert!(error.error.is_some());
}
