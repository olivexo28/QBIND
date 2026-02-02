//! Integration tests for T131: ML-DSA-44 multi-suite verification.
//!
//! These tests verify that:
//! - ML-DSA-44 backend can be registered with `SimpleBackendRegistry`
//! - `MultiSuiteCryptoVerifier` correctly routes to ML-DSA-44 backend
//! - ML-DSA-44 and toy suite are independent (cross-suite verification fails)
//! - Per-suite metrics work with ML-DSA-44

use std::collections::HashMap;
use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use qbind_consensus::governed_key_registry::{
    ConsensusKeyGovernance, GovernedValidatorKeyRegistry,
};
use qbind_consensus::verify::{ConsensusVerifier, VerificationError};
use qbind_consensus::{
    ConsensusSigBackendRegistry, MultiSuiteCryptoVerifier, SimpleBackendRegistry, ValidatorId,
};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::{ConsensusSigSuiteId, MlDsa44Backend, SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Test-only toy signature implementation (for cross-suite testing)
// ============================================================================

/// A test-only "toy" verifier using SHA3-256.
///
/// This verifier expects signatures to be:
/// `signature = SHA3-256(pk || preimage)`
///
/// **NOT FOR PRODUCTION** - this is only for testing.
struct ToyHashVerifier;

impl ToyHashVerifier {
    fn sign(pk: &[u8], preimage: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(pk);
        hasher.update(preimage);
        hasher.finalize().to_vec()
    }
}

impl ConsensusSigVerifier for ToyHashVerifier {
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
// Test governance implementation
// ============================================================================

/// A test governance implementation with configurable suite IDs per validator.
#[derive(Debug, Default)]
struct TestSuiteGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl TestSuiteGovernance {
    fn new() -> Self {
        TestSuiteGovernance {
            keys: HashMap::new(),
        }
    }

    fn with_key(mut self, validator_id: u64, suite_id: ConsensusSigSuiteId, pk: Vec<u8>) -> Self {
        self.keys.insert(validator_id, (suite_id, pk));
        self
    }
}

impl ConsensusKeyGovernance for TestSuiteGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
}

// ============================================================================
// Test helpers
// ============================================================================

/// Create a Vote with the specified suite_id.
fn make_vote(height: u64, round: u64, suite_id: u16) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id,
        signature: vec![],
    }
}

/// Create a BlockProposal with the specified suite_id.
fn make_proposal(height: u64, round: u64, suite_id: u16) -> BlockProposal {
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
            suite_id,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// ML-DSA-44 Registration Tests
// ============================================================================

/// Test that ML-DSA-44 backend can be registered and used.
#[test]
fn ml_dsa_44_backend_registration() {
    let mut registry = SimpleBackendRegistry::new();

    // Register ML-DSA-44 backend for suite ID 100
    registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    // Backend should be retrievable
    let backend = registry.get_backend(SUITE_PQ_RESERVED_1);
    assert!(backend.is_some(), "ML-DSA-44 backend should be registered");
}

/// Test that both toy and ML-DSA-44 backends can coexist.
#[test]
fn toy_and_ml_dsa_44_coexist() {
    let mut registry = SimpleBackendRegistry::new();

    // Register both backends
    registry.register(SUITE_TOY_SHA3, Arc::new(ToyHashVerifier));
    registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    // Both should be retrievable
    assert!(registry.get_backend(SUITE_TOY_SHA3).is_some());
    assert!(registry.get_backend(SUITE_PQ_RESERVED_1).is_some());

    // Unknown suite should not be found
    let unknown = ConsensusSigSuiteId::new(999);
    assert!(registry.get_backend(unknown).is_none());
}

// ============================================================================
// Multi-Suite Verifier Tests
// ============================================================================

/// Test that MultiSuiteCryptoVerifier routes ML-DSA-44 signatures correctly.
#[test]
fn multi_suite_verifier_routes_ml_dsa_44() {
    // Generate ML-DSA-44 keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Create governance that assigns validator 1 to ML-DSA-44
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry with ML-DSA-44
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create and sign a vote using ML-DSA-44
    let mut vote = make_vote(10, 5, SUITE_PQ_RESERVED_1.as_u16());
    let preimage = vote.signing_preimage();
    vote.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");

    // Verification should succeed
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        result.is_ok(),
        "ML-DSA-44 verification should succeed: {:?}",
        result
    );

    // Metrics should be updated
    assert_eq!(verifier.metrics().vote_ok(), 1);
}

/// Test that MultiSuiteCryptoVerifier routes proposal verification correctly.
#[test]
fn multi_suite_verifier_ml_dsa_44_proposal() {
    // Generate ML-DSA-44 keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Create governance
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create and sign a proposal using ML-DSA-44
    let mut proposal = make_proposal(10, 5, SUITE_PQ_RESERVED_1.as_u16());
    let preimage = proposal.signing_preimage();
    proposal.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");

    // Verification should succeed
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(
        result.is_ok(),
        "ML-DSA-44 proposal verification should succeed: {:?}",
        result
    );

    // Metrics should be updated
    assert_eq!(verifier.metrics().proposal_ok(), 1);
}

// ============================================================================
// Cross-Suite Isolation Tests
// ============================================================================

/// Test that toy suite cannot verify ML-DSA-44 signatures.
#[test]
fn toy_cannot_verify_ml_dsa_44_signature() {
    // Generate ML-DSA-44 keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Create governance that assigns validator to toy suite (but with ML-DSA-44 key)
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_TOY_SHA3, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry with only toy suite
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_TOY_SHA3, Arc::new(ToyHashVerifier));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create vote with toy suite_id
    let mut vote = make_vote(10, 5, SUITE_TOY_SHA3.as_u16());

    // Sign with ML-DSA-44 (but toy verifier expects toy format)
    let preimage = vote.signing_preimage();
    vote.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");

    // Verification should fail because toy verifier can't verify ML-DSA-44 signature
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "toy suite should not verify ML-DSA-44 signature: {:?}",
        result
    );
}

/// Test that ML-DSA-44 cannot verify toy signatures.
#[test]
fn ml_dsa_44_cannot_verify_toy_signature() {
    // Generate toy keypair (just random bytes for the test)
    let toy_pk = b"toy-public-key".to_vec();

    // Create governance that assigns validator to ML-DSA-44 (but with toy key)
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, toy_pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry with only ML-DSA-44
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create vote with ML-DSA-44 suite_id
    let mut vote = make_vote(10, 5, SUITE_PQ_RESERVED_1.as_u16());

    // Sign with toy signer
    let preimage = vote.signing_preimage();
    vote.signature = ToyHashVerifier::sign(&toy_pk, &preimage);

    // Verification should fail because:
    // 1. Toy key is wrong size for ML-DSA-44 (will be rejected as malformed)
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        result.is_err(),
        "ML-DSA-44 should not verify toy signature: {:?}",
        result
    );
}

/// Test that validators with different suites are independent.
#[test]
fn different_validators_different_suites() {
    // Generate keys for both suites
    let (ml_dsa_pk, ml_dsa_sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let toy_pk = b"toy-validator-key".to_vec();

    // Create governance with different suites for different validators
    let governance = TestSuiteGovernance::new()
        .with_key(1, SUITE_PQ_RESERVED_1, ml_dsa_pk.clone())
        .with_key(2, SUITE_TOY_SHA3, toy_pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry with both suites
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_TOY_SHA3, Arc::new(ToyHashVerifier));
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Validator 1 signs with ML-DSA-44
    let mut vote1 = make_vote(10, 5, SUITE_PQ_RESERVED_1.as_u16());
    let preimage1 = vote1.signing_preimage();
    vote1.signature = MlDsa44Backend::sign(&ml_dsa_sk, &preimage1).expect("signing should succeed");

    // Validator 2 signs with toy suite
    let mut vote2 = make_vote(10, 5, SUITE_TOY_SHA3.as_u16());
    let preimage2 = vote2.signing_preimage();
    vote2.signature = ToyHashVerifier::sign(&toy_pk, &preimage2);

    // Both should verify with their respective backends
    assert!(
        verifier.verify_vote(ValidatorId::new(1), &vote1).is_ok(),
        "Validator 1 ML-DSA-44 vote should verify"
    );
    assert!(
        verifier.verify_vote(ValidatorId::new(2), &vote2).is_ok(),
        "Validator 2 toy vote should verify"
    );

    // Cross-verification should fail (wrong validator)
    // Note: This fails because wire suite_id doesn't match governance suite_id
    assert!(
        verifier.verify_vote(ValidatorId::new(2), &vote1).is_err(),
        "Vote1 (ML-DSA) should not verify as validator 2 (toy)"
    );
    assert!(
        verifier.verify_vote(ValidatorId::new(1), &vote2).is_err(),
        "Vote2 (toy) should not verify as validator 1 (ML-DSA)"
    );
}

// ============================================================================
// Suite Mismatch Tests
// ============================================================================

/// Test that wire suite_id must match governance suite_id.
#[test]
fn wire_suite_must_match_governance() {
    // Generate ML-DSA-44 keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Governance says validator 1 uses ML-DSA-44
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry with both suites
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_TOY_SHA3, Arc::new(ToyHashVerifier));
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create vote with wrong wire suite_id (toy instead of ML-DSA-44)
    let mut vote = make_vote(10, 5, SUITE_TOY_SHA3.as_u16()); // Wire says toy
    let preimage = vote.signing_preimage();
    vote.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");

    // Verification should fail with SuiteMismatch
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    match result {
        Err(VerificationError::SuiteMismatch { .. }) => {
            // Expected
        }
        other => panic!("Expected SuiteMismatch, got {:?}", other),
    }

    // Metrics should show suite mismatch
    assert_eq!(verifier.metrics().vote_suite_mismatch(), 1);
}

// ============================================================================
// Per-Suite Metrics Tests
// ============================================================================

/// Test that per-suite metrics are recorded for ML-DSA-44.
#[test]
fn per_suite_metrics_ml_dsa_44() {
    // Generate ML-DSA-44 keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Create governance
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Verify several votes
    for i in 0..5 {
        let mut vote = make_vote(10, i, SUITE_PQ_RESERVED_1.as_u16());
        let preimage = vote.signing_preimage();
        vote.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");

        let result = verifier.verify_vote(ValidatorId::new(1), &vote);
        assert!(result.is_ok());
    }

    // Verify a proposal
    let mut proposal = make_proposal(10, 0, SUITE_PQ_RESERVED_1.as_u16());
    let preimage = proposal.signing_preimage();
    proposal.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");
    assert!(verifier
        .verify_proposal(ValidatorId::new(1), &proposal)
        .is_ok());

    // Check per-suite metrics
    let per_suite = verifier.metrics().per_suite_metrics(SUITE_PQ_RESERVED_1);
    assert!(
        per_suite.is_some(),
        "per-suite metrics should exist for ML-DSA-44"
    );

    let (vote_count, proposal_count, _latency_buckets) = per_suite.unwrap();
    assert_eq!(vote_count, 5, "should have 5 vote verifications");
    assert_eq!(proposal_count, 1, "should have 1 proposal verification");
}

/// Test that metrics format includes ML-DSA-44 suite name.
#[test]
fn metrics_format_includes_ml_dsa_44_name() {
    // Generate ML-DSA-44 keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Create governance
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create backend registry
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Verify a vote to generate metrics
    let mut vote = make_vote(10, 0, SUITE_PQ_RESERVED_1.as_u16());
    let preimage = vote.signing_preimage();
    vote.signature = MlDsa44Backend::sign(&sk, &preimage).expect("signing should succeed");
    assert!(verifier.verify_vote(ValidatorId::new(1), &vote).is_ok());

    // Check metrics format includes ML-DSA-44 name
    let metrics_output = verifier.metrics().format_per_suite_metrics();
    assert!(
        metrics_output.contains("ml-dsa-44"),
        "metrics should include 'ml-dsa-44' suite name: {}",
        metrics_output
    );
}

// ============================================================================
// Backend Availability Tests
// ============================================================================

/// Test that missing backend produces appropriate error.
#[test]
fn missing_backend_returns_error() {
    // Generate ML-DSA-44 keypair
    let (pk, _) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");

    // Create governance that references ML-DSA-44
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_PQ_RESERVED_1, pk.clone());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create empty backend registry (no backends registered)
    let backend_registry = SimpleBackendRegistry::new();

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create vote with ML-DSA-44 suite_id
    let vote = make_vote(10, 0, SUITE_PQ_RESERVED_1.as_u16());

    // Verification should fail with "unsupported suite" error
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    match result {
        Err(VerificationError::Other(msg)) => {
            assert!(
                msg.contains("unsupported consensus signature suite"),
                "Error should mention unsupported suite: {}",
                msg
            );
        }
        other => panic!("Expected VerificationError::Other, got {:?}", other),
    }
}

/// Test that SUITE_PQ_RESERVED_1 equals suite ID 100.
#[test]
fn suite_pq_reserved_1_is_100() {
    assert_eq!(SUITE_PQ_RESERVED_1.as_u16(), 100);
}

/// Test that suite name is "ml-dsa-44" (not "ml-dsa-44-reserved").
#[test]
fn suite_name_is_ml_dsa_44() {
    use qbind_crypto::suite_name;
    assert_eq!(suite_name(SUITE_PQ_RESERVED_1), "ml-dsa-44");
}