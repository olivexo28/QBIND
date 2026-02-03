//! Tests for `CryptoConsensusVerifier` metrics.
//!
//! These tests verify that the metrics counters are correctly incremented
//! for different verification outcomes (ok, missing_key, invalid_signature, other).

use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use qbind_consensus::verify::{ConsensusVerifier, VerificationError};
use qbind_consensus::{
    CryptoConsensusVerifier, ValidatorId, ValidatorKeyRegistry, ValidatorPublicKey,
};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

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
// Test helpers
// ============================================================================

/// Helper to create a Vote with a given signature.
fn make_vote_with_sig(height: u64, round: u64, signature: Vec<u8>) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature,
    }
}

/// Helper to create a BlockProposal with a given signature.
fn make_proposal_with_sig(height: u64, round: u64, signature: Vec<u8>) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature,
    }
}

/// Helper to sign a Vote using the test hash scheme.
fn sign_vote(pk: &[u8], vote: &Vote) -> Vec<u8> {
    let preimage = vote.signing_preimage();
    TestHashConsensusSigVerifier::sign(pk, &preimage)
}

/// Helper to sign a BlockProposal using the test hash scheme.
fn sign_proposal(pk: &[u8], proposal: &BlockProposal) -> Vec<u8> {
    let preimage = proposal.signing_preimage();
    TestHashConsensusSigVerifier::sign(pk, &preimage)
}

/// Build a simple registry with one validator.
fn build_registry_with_one_validator(id: u64, pk_bytes: Vec<u8>) -> ValidatorKeyRegistry {
    let mut registry = ValidatorKeyRegistry::new();
    registry.insert(ValidatorId::new(id), ValidatorPublicKey(pk_bytes));
    registry
}

// ============================================================================
// Metrics tests for vote verification
// ============================================================================

/// Test that a successful vote verification increments the "ok" counter.
#[test]
fn metrics_vote_ok_increments_on_success() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().vote_ok(), 0);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
    assert_eq!(verifier.metrics().vote_other(), 0);

    // Create and sign a valid vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok());

    // Check metrics
    assert_eq!(verifier.metrics().vote_ok(), 1);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
    assert_eq!(verifier.metrics().vote_other(), 0);
}

/// Test that a missing key vote verification increments the "missing_key" counter.
#[test]
fn metrics_vote_missing_key_increments_on_missing_key() {
    // Empty registry - no keys configured
    let registry = ValidatorKeyRegistry::new();
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().vote_missing_key(), 0);

    // Create a vote
    let vote = make_vote_with_sig(10, 5, vec![0u8; 32]);

    // Verify from unknown validator
    let result = verifier.verify_vote(ValidatorId::new(999), &vote);
    assert!(matches!(result, Err(VerificationError::MissingKey(_))));

    // Check metrics
    assert_eq!(verifier.metrics().vote_ok(), 0);
    assert_eq!(verifier.metrics().vote_missing_key(), 1);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
    assert_eq!(verifier.metrics().vote_other(), 0);
}

/// Test that an invalid signature vote verification increments the "invalid_signature" counter.
#[test]
fn metrics_vote_invalid_signature_increments_on_invalid_signature() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);

    // Create and sign a vote, then tamper with it
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);
    vote.signature[0] ^= 0xff; // Tamper

    // Verify
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(matches!(result, Err(VerificationError::InvalidSignature)));

    // Check metrics
    assert_eq!(verifier.metrics().vote_ok(), 0);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 1);
    assert_eq!(verifier.metrics().vote_other(), 0);
}

// ============================================================================
// Metrics tests for proposal verification
// ============================================================================

/// Test that a successful proposal verification increments the "ok" counter.
#[test]
fn metrics_proposal_ok_increments_on_success() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().proposal_ok(), 0);
    assert_eq!(verifier.metrics().proposal_missing_key(), 0);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);
    assert_eq!(verifier.metrics().proposal_other(), 0);

    // Create and sign a valid proposal
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(result.is_ok());

    // Check metrics
    assert_eq!(verifier.metrics().proposal_ok(), 1);
    assert_eq!(verifier.metrics().proposal_missing_key(), 0);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);
    assert_eq!(verifier.metrics().proposal_other(), 0);
}

/// Test that a missing key proposal verification increments the "missing_key" counter.
#[test]
fn metrics_proposal_missing_key_increments_on_missing_key() {
    // Empty registry - no keys configured
    let registry = ValidatorKeyRegistry::new();
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().proposal_missing_key(), 0);

    // Create a proposal
    let proposal = make_proposal_with_sig(10, 5, vec![0u8; 32]);

    // Verify from unknown validator
    let result = verifier.verify_proposal(ValidatorId::new(999), &proposal);
    assert!(matches!(result, Err(VerificationError::MissingKey(_))));

    // Check metrics
    assert_eq!(verifier.metrics().proposal_ok(), 0);
    assert_eq!(verifier.metrics().proposal_missing_key(), 1);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);
    assert_eq!(verifier.metrics().proposal_other(), 0);
}

/// Test that an invalid signature proposal verification increments the "invalid_signature" counter.
#[test]
fn metrics_proposal_invalid_signature_increments_on_invalid_signature() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);

    // Create and sign a proposal, then tamper with it
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);
    proposal.signature[0] ^= 0xff; // Tamper

    // Verify
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(matches!(result, Err(VerificationError::InvalidSignature)));

    // Check metrics
    assert_eq!(verifier.metrics().proposal_ok(), 0);
    assert_eq!(verifier.metrics().proposal_missing_key(), 0);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 1);
    assert_eq!(verifier.metrics().proposal_other(), 0);
}

// ============================================================================
// Mixed metrics tests
// ============================================================================

/// Test that multiple verifications correctly accumulate metrics.
#[test]
fn metrics_accumulate_correctly_across_multiple_verifications() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Perform multiple verifications of different kinds

    // 3 successful vote verifications
    for i in 0..3 {
        let mut vote = make_vote_with_sig(10, i, vec![]);
        vote.signature = sign_vote(&pk_bytes, &vote);
        let _ = verifier.verify_vote(ValidatorId::new(1), &vote);
    }

    // 2 failed vote verifications (missing key)
    for i in 0..2 {
        let vote = make_vote_with_sig(10, i, vec![0u8; 32]);
        let _ = verifier.verify_vote(ValidatorId::new(999), &vote);
    }

    // 1 failed vote verification (invalid signature)
    let mut vote = make_vote_with_sig(10, 0, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);
    vote.signature[0] ^= 0xff;
    let _ = verifier.verify_vote(ValidatorId::new(1), &vote);

    // 2 successful proposal verifications
    for i in 0..2 {
        let mut proposal = make_proposal_with_sig(10, i, vec![]);
        proposal.signature = sign_proposal(&pk_bytes, &proposal);
        let _ = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    }

    // 1 failed proposal verification (missing key)
    let proposal = make_proposal_with_sig(10, 0, vec![0u8; 32]);
    let _ = verifier.verify_proposal(ValidatorId::new(999), &proposal);

    // Check all metrics
    assert_eq!(verifier.metrics().vote_ok(), 3);
    assert_eq!(verifier.metrics().vote_missing_key(), 2);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 1);
    assert_eq!(verifier.metrics().vote_other(), 0);

    assert_eq!(verifier.metrics().proposal_ok(), 2);
    assert_eq!(verifier.metrics().proposal_missing_key(), 1);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);
    assert_eq!(verifier.metrics().proposal_other(), 0);
}

/// Test that metrics are accessible via the public API.
#[test]
fn metrics_accessible_via_public_api() {
    let registry = ValidatorKeyRegistry::new();
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Access metrics via the metrics() method
    let metrics = verifier.metrics();

    // All should start at zero
    assert_eq!(metrics.vote_ok(), 0);
    assert_eq!(metrics.vote_missing_key(), 0);
    assert_eq!(metrics.vote_invalid_signature(), 0);
    assert_eq!(metrics.vote_other(), 0);
    assert_eq!(metrics.proposal_ok(), 0);
    assert_eq!(metrics.proposal_missing_key(), 0);
    assert_eq!(metrics.proposal_invalid_signature(), 0);
    assert_eq!(metrics.proposal_other(), 0);
}
