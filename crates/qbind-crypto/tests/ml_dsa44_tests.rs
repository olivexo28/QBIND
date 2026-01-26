//! Tests for ML-DSA-44 consensus signature backend.
//!
//! These tests verify the ML-DSA-44 post-quantum signature backend:
//! - Keypair generation produces correct sizes
//! - Sign/verify roundtrip works
//! - Verification fails for modified message, signature, or wrong key
//! - Backend integrates with ConsensusSigVerifier trait

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ml_dsa44::{
    MlDsa44Backend, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SECRET_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE,
};

// ============================================================================
// Key and signature size tests
// ============================================================================

/// Test that ML-DSA-44 key and signature sizes match FIPS 204 spec.
#[test]
fn ml_dsa_44_sizes_match_spec() {
    // Per FIPS 204 ML-DSA-44:
    // - Public key: 1,312 bytes
    // - Secret key: 2,560 bytes
    // - Signature: 2,420 bytes
    assert_eq!(ML_DSA_44_PUBLIC_KEY_SIZE, 1312);
    assert_eq!(ML_DSA_44_SECRET_KEY_SIZE, 2560);
    assert_eq!(ML_DSA_44_SIGNATURE_SIZE, 2420);
}

/// Test that generated keypairs have correct sizes.
#[test]
fn keygen_produces_correct_sizes() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    assert_eq!(
        pk.len(),
        ML_DSA_44_PUBLIC_KEY_SIZE,
        "public key size mismatch"
    );
    assert_eq!(
        sk.len(),
        ML_DSA_44_SECRET_KEY_SIZE,
        "secret key size mismatch"
    );
}

/// Test that signatures have correct size.
#[test]
fn signature_has_correct_size() {
    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message";
    let sig = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");
    assert_eq!(
        sig.len(),
        ML_DSA_44_SIGNATURE_SIZE,
        "signature size mismatch"
    );
}

// ============================================================================
// Sign and verify roundtrip tests
// ============================================================================

/// Test basic sign/verify roundtrip.
#[test]
fn sign_verify_roundtrip() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message for ML-DSA-44";

    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(result.is_ok(), "verification should succeed");
}

/// Test that empty message can be signed and verified.
#[test]
fn sign_verify_empty_message() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"";

    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(result.is_ok(), "empty message verification should succeed");
}

/// Test that long message can be signed and verified.
#[test]
fn sign_verify_long_message() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    // 1 MB message
    let message = vec![0xab_u8; 1024 * 1024];

    let signature = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, &message, &signature);
    assert!(result.is_ok(), "long message verification should succeed");
}

/// Test multiple independent sign/verify operations.
#[test]
fn multiple_signatures_independent() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message1 = b"message one";
    let message2 = b"message two";

    let sig1 = MlDsa44Backend::sign(&sk, message1).expect("signing should succeed");
    let sig2 = MlDsa44Backend::sign(&sk, message2).expect("signing should succeed");

    // Signatures should be different
    assert_ne!(
        sig1, sig2,
        "different messages should produce different signatures"
    );

    let backend = MlDsa44Backend::new();

    // Each signature should verify only its own message
    assert!(backend.verify_vote(1, &pk, message1, &sig1).is_ok());
    assert!(backend.verify_vote(1, &pk, message2, &sig2).is_ok());
    assert!(backend.verify_vote(1, &pk, message1, &sig2).is_err());
    assert!(backend.verify_vote(1, &pk, message2, &sig1).is_err());
}

// ============================================================================
// Verification failure tests
// ============================================================================

/// Test that verification fails for modified message.
#[test]
fn verify_fails_modified_message() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"original message";

    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    let modified = b"modified message";
    let result = backend.verify_vote(1, &pk, modified, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::InvalidSignature)),
        "modified message should be rejected"
    );
}

/// Test that verification fails for single-bit modified message.
#[test]
fn verify_fails_single_bit_message_change() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message".to_vec();

    let signature = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");

    let mut modified = message.clone();
    modified[0] ^= 0x01; // Flip one bit

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, &modified, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::InvalidSignature)),
        "single-bit change should be detected"
    );
}

/// Test that verification fails for modified signature.
#[test]
fn verify_fails_modified_signature() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message";

    let mut signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");
    signature[0] ^= 0xff;

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::InvalidSignature)),
        "modified signature should be rejected"
    );
}

/// Test that verification fails for single-bit modified signature.
#[test]
fn verify_fails_single_bit_signature_change() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message";

    let mut signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");
    // Flip one bit in the middle of the signature
    let mid = signature.len() / 2;
    signature[mid] ^= 0x01;

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::InvalidSignature)),
        "single-bit signature change should be detected"
    );
}

/// Test that verification fails with wrong public key.
#[test]
fn verify_fails_wrong_key() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let (wrong_pk, _) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message";

    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &wrong_pk, message, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::InvalidSignature)),
        "wrong key should be rejected"
    );

    // Correct key should work
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(result.is_ok(), "correct key should succeed");
}

// ============================================================================
// Malformed input tests
// ============================================================================

/// Test that malformed (short) public key is rejected.
#[test]
fn verify_rejects_short_public_key() {
    let backend = MlDsa44Backend::new();
    let short_pk = vec![0u8; 100];
    let message = b"test message";
    let signature = vec![0u8; ML_DSA_44_SIGNATURE_SIZE];

    let result = backend.verify_vote(1, &short_pk, message, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::MalformedSignature)),
        "short public key should be rejected as malformed"
    );
}

/// Test that malformed (long) public key is rejected.
#[test]
fn verify_rejects_long_public_key() {
    let backend = MlDsa44Backend::new();
    let long_pk = vec![0u8; ML_DSA_44_PUBLIC_KEY_SIZE + 100];
    let message = b"test message";
    let signature = vec![0u8; ML_DSA_44_SIGNATURE_SIZE];

    let result = backend.verify_vote(1, &long_pk, message, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::MalformedSignature)),
        "long public key should be rejected as malformed"
    );
}

/// Test that malformed (short) signature is rejected.
#[test]
fn verify_rejects_short_signature() {
    let (pk, _) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlDsa44Backend::new();
    let message = b"test message";
    let short_sig = vec![0u8; 100];

    let result = backend.verify_vote(1, &pk, message, &short_sig);
    assert!(
        matches!(result, Err(ConsensusSigError::MalformedSignature)),
        "short signature should be rejected as malformed"
    );
}

/// Test that malformed (long) signature is rejected.
#[test]
fn verify_rejects_long_signature() {
    let (pk, _) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlDsa44Backend::new();
    let message = b"test message";
    let long_sig = vec![0u8; ML_DSA_44_SIGNATURE_SIZE + 100];

    let result = backend.verify_vote(1, &pk, message, &long_sig);
    assert!(
        matches!(result, Err(ConsensusSigError::MalformedSignature)),
        "long signature should be rejected as malformed"
    );
}

/// Test that empty public key is rejected.
#[test]
fn verify_rejects_empty_public_key() {
    let backend = MlDsa44Backend::new();
    let empty_pk = vec![];
    let message = b"test message";
    let signature = vec![0u8; ML_DSA_44_SIGNATURE_SIZE];

    let result = backend.verify_vote(1, &empty_pk, message, &signature);
    assert!(
        matches!(result, Err(ConsensusSigError::MalformedSignature)),
        "empty public key should be rejected"
    );
}

/// Test that empty signature is rejected.
#[test]
fn verify_rejects_empty_signature() {
    let (pk, _) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlDsa44Backend::new();
    let message = b"test message";
    let empty_sig = vec![];

    let result = backend.verify_vote(1, &pk, message, &empty_sig);
    assert!(
        matches!(result, Err(ConsensusSigError::MalformedSignature)),
        "empty signature should be rejected"
    );
}

// ============================================================================
// ConsensusSigVerifier trait tests
// ============================================================================

/// Test that proposal verification works the same as vote verification.
#[test]
fn proposal_verification() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"proposal preimage";

    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();
    let result = backend.verify_proposal(1, &pk, message, &signature);
    assert!(result.is_ok(), "proposal verification should succeed");
}

/// Test that verify_vote and verify_proposal behave identically.
#[test]
fn vote_and_proposal_same_behavior() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"common preimage";

    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();

    // Both should succeed
    let vote_result = backend.verify_vote(1, &pk, message, &signature);
    let proposal_result = backend.verify_proposal(1, &pk, message, &signature);
    assert!(vote_result.is_ok());
    assert!(proposal_result.is_ok());

    // Both should fail for tampered signature
    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 0xff;
    let vote_result = backend.verify_vote(1, &pk, message, &bad_sig);
    let proposal_result = backend.verify_proposal(1, &pk, message, &bad_sig);
    assert!(matches!(
        vote_result,
        Err(ConsensusSigError::InvalidSignature)
    ));
    assert!(matches!(
        proposal_result,
        Err(ConsensusSigError::InvalidSignature)
    ));
}

/// Test that validator_id is ignored (as designed).
#[test]
fn validator_id_is_ignored() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message";
    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = MlDsa44Backend::new();

    // Different validator IDs should all work
    assert!(backend.verify_vote(0, &pk, message, &signature).is_ok());
    assert!(backend.verify_vote(1, &pk, message, &signature).is_ok());
    assert!(backend.verify_vote(100, &pk, message, &signature).is_ok());
    assert!(backend
        .verify_vote(u64::MAX, &pk, message, &signature)
        .is_ok());
}

// ============================================================================
// Backend properties tests
// ============================================================================

/// Test that backend is thread-safe (Send + Sync).
#[test]
fn backend_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MlDsa44Backend>();
}

/// Test that backend can be used from multiple threads.
#[test]
fn backend_multithreaded() {
    use std::sync::Arc;
    use std::thread;

    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test message";
    let signature = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    let backend = Arc::new(MlDsa44Backend::new());
    let pk = Arc::new(pk);
    let signature = Arc::new(signature);

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let backend = backend.clone();
            let pk = pk.clone();
            let signature = signature.clone();
            thread::spawn(move || {
                for _ in 0..10 {
                    let result = backend.verify_vote(i, &pk, message, &signature);
                    assert!(result.is_ok());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

/// Test Debug implementation.
#[test]
fn backend_debug() {
    let backend = MlDsa44Backend::new();
    let debug_str = format!("{:?}", backend);
    assert!(debug_str.contains("MlDsa44Backend"));
}

/// Test Clone implementation.
#[test]
#[allow(clippy::clone_on_copy)]
fn backend_clone() {
    let backend1 = MlDsa44Backend::new();
    let backend2 = backend1.clone();

    // Both should work identically
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test";
    let sig = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");

    assert!(backend1.verify_vote(1, &pk, message, &sig).is_ok());
    assert!(backend2.verify_vote(1, &pk, message, &sig).is_ok());
}

/// Test Default implementation.
#[test]
fn backend_default() {
    let backend: MlDsa44Backend = Default::default();
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = b"test";
    let sig = MlDsa44Backend::sign(&sk, message).expect("signing should succeed");
    assert!(backend.verify_vote(1, &pk, message, &sig).is_ok());
}
