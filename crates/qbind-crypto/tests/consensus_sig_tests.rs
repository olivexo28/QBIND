//! Tests for `ConsensusSigVerifier` trait and `ConsensusSigError` types.
//!
//! These tests verify the consensus signature verification interface using
//! a test-only SHA3-based verifier. The tests ensure that:
//! - Valid signatures are accepted
//! - Invalid signatures are rejected
//! - Wrong keys are rejected
//! - Error types display correctly

use sha3::{Digest, Sha3_256};

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};

// ============================================================================
// Test-only signature implementation
// ============================================================================

/// A test-only "toy" verifier using SHA3-256.
///
/// This verifier expects signatures to be:
/// `signature = SHA3-256(pk || preimage)`
///
/// **NOT FOR PRODUCTION** - this is only for testing the verification pipeline.
struct TestHashConsensusSigVerifier;

impl TestHashConsensusSigVerifier {
    /// Create a test signature for the given public key and preimage.
    ///
    /// `sig = SHA3-256(pk || preimage)`
    fn sign(pk: &[u8], preimage: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(pk);
        hasher.update(preimage);
        hasher.finalize().to_vec()
    }
}

impl ConsensusSigVerifier for TestHashConsensusSigVerifier {
    fn verify_vote(
        &self,
        _validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        let expected = Self::sign(pk, preimage);
        if signature == expected.as_slice() {
            Ok(())
        } else {
            Err(ConsensusSigError::InvalidSignature)
        }
    }

    fn verify_proposal(
        &self,
        _validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        let expected = Self::sign(pk, preimage);
        if signature == expected.as_slice() {
            Ok(())
        } else {
            Err(ConsensusSigError::InvalidSignature)
        }
    }
}

// ============================================================================
// Vote verification tests
// ============================================================================

/// Test that a valid signature is accepted for vote verification.
#[test]
fn hash_verifier_accepts_valid_vote_signature() {
    let verifier = TestHashConsensusSigVerifier;
    let pk = b"test-public-key";
    let preimage = b"test-preimage-data";
    let signature = TestHashConsensusSigVerifier::sign(pk, preimage);

    let result = verifier.verify_vote(1, pk, preimage, &signature);
    assert!(result.is_ok());
}

/// Test that a tampered signature is rejected for vote verification.
#[test]
fn hash_verifier_rejects_invalid_vote_signature() {
    let verifier = TestHashConsensusSigVerifier;
    let pk = b"test-public-key";
    let preimage = b"test-preimage-data";
    let mut signature = TestHashConsensusSigVerifier::sign(pk, preimage);
    // Tamper with the signature
    signature[0] ^= 0xff;

    let result = verifier.verify_vote(1, pk, preimage, &signature);
    assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
}

/// Test that verification fails when using the wrong public key for votes.
#[test]
fn hash_verifier_rejects_vote_with_wrong_key() {
    let verifier = TestHashConsensusSigVerifier;
    let pk = b"test-public-key";
    let wrong_pk = b"wrong-public-key";
    let preimage = b"test-preimage-data";
    let signature = TestHashConsensusSigVerifier::sign(pk, preimage);

    // Verify with wrong key
    let result = verifier.verify_vote(1, wrong_pk, preimage, &signature);
    assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
}

// ============================================================================
// Proposal verification tests
// ============================================================================

/// Test that a valid signature is accepted for proposal verification.
#[test]
fn hash_verifier_accepts_valid_proposal_signature() {
    let verifier = TestHashConsensusSigVerifier;
    let pk = b"test-public-key";
    let preimage = b"test-preimage-data";
    let signature = TestHashConsensusSigVerifier::sign(pk, preimage);

    let result = verifier.verify_proposal(1, pk, preimage, &signature);
    assert!(result.is_ok());
}

/// Test that a tampered signature is rejected for proposal verification.
#[test]
fn hash_verifier_rejects_invalid_proposal_signature() {
    let verifier = TestHashConsensusSigVerifier;
    let pk = b"test-public-key";
    let preimage = b"test-preimage-data";
    let mut signature = TestHashConsensusSigVerifier::sign(pk, preimage);
    // Tamper with the signature
    signature[0] ^= 0xff;

    let result = verifier.verify_proposal(1, pk, preimage, &signature);
    assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
}

/// Test that verification fails when using the wrong public key for proposals.
#[test]
fn hash_verifier_rejects_proposal_with_wrong_key() {
    let verifier = TestHashConsensusSigVerifier;
    let pk = b"test-public-key";
    let wrong_pk = b"wrong-public-key";
    let preimage = b"test-preimage-data";
    let signature = TestHashConsensusSigVerifier::sign(pk, preimage);

    // Verify with wrong key
    let result = verifier.verify_proposal(1, wrong_pk, preimage, &signature);
    assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
}

// ============================================================================
// Error type tests
// ============================================================================

/// Test that ConsensusSigError variants display correctly.
#[test]
fn consensus_sig_error_display() {
    let e1 = ConsensusSigError::MissingKey(42);
    assert!(format!("{}", e1).contains("42"));

    let e2 = ConsensusSigError::MalformedSignature;
    assert!(format!("{}", e2).contains("malformed"));

    let e3 = ConsensusSigError::InvalidSignature;
    assert!(format!("{}", e3).contains("invalid"));

    let e4 = ConsensusSigError::Other("custom error".to_string());
    assert!(format!("{}", e4).contains("custom error"));
}

/// Test that ConsensusSigError implements std::error::Error.
#[test]
fn consensus_sig_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ConsensusSigError::InvalidSignature);
    assert!(err.to_string().contains("invalid"));
}

// ============================================================================
// ConsensusSigSuiteId tests
// ============================================================================

/// Test ConsensusSigSuiteId basic operations.
#[test]
fn suite_id_basic_operations() {
    use qbind_crypto::{ConsensusSigSuiteId, SUITE_TOY_SHA3};

    // Test constructor
    let id = ConsensusSigSuiteId::new(42);
    assert_eq!(id.as_u16(), 42);

    // Test public field access
    let id2 = ConsensusSigSuiteId(100);
    assert_eq!(id2.0, 100);
    assert_eq!(id2.as_u16(), 100);

    // Test SUITE_TOY_SHA3 constant
    assert_eq!(SUITE_TOY_SHA3.as_u16(), 0);
}

/// Test ConsensusSigSuiteId equality and hashing.
#[test]
fn suite_id_equality_and_hash() {
    use qbind_crypto::ConsensusSigSuiteId;
    use std::collections::HashSet;

    let id1 = ConsensusSigSuiteId::new(1);
    let id2 = ConsensusSigSuiteId::new(2);
    let id3 = ConsensusSigSuiteId::new(1);

    assert_eq!(id1, id3);
    assert_ne!(id1, id2);

    // Test hash
    let mut set = HashSet::new();
    set.insert(id1);
    set.insert(id2);
    set.insert(id3);
    assert_eq!(set.len(), 2);
}

/// Test ConsensusSigSuiteId Display implementation.
#[test]
fn suite_id_display() {
    use qbind_crypto::{ConsensusSigSuiteId, SUITE_TOY_SHA3};

    let id = ConsensusSigSuiteId::new(42);
    assert_eq!(format!("{}", id), "suite_42");

    assert_eq!(format!("{}", SUITE_TOY_SHA3), "suite_0");
}

/// Test ConsensusSigSuiteId Default implementation.
#[test]
fn suite_id_default() {
    use qbind_crypto::ConsensusSigSuiteId;

    let id = ConsensusSigSuiteId::default();
    assert_eq!(id.as_u16(), 0);
}
