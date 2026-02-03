//! Tests for T83: Wire vs governance suite mismatch detection.
//!
//! These tests verify that:
//! - Vote suite mismatch is detected and returns `VerificationError::SuiteMismatch`
//! - Proposal suite mismatch is detected and returns `VerificationError::SuiteMismatch`
//! - Happy path (matching suites) still succeeds
//! - Metrics correctly track suite mismatches
//!
//! # Test Design
//!
//! Tests are kept lightweight to avoid OOM issues on low-RAM machines.
//! They focus on the MultiSuiteCryptoVerifier directly rather than integration
//! with qbind-node.

use std::collections::HashMap;
use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use qbind_consensus::governed_key_registry::{
    ConsensusKeyGovernance, GovernedValidatorKeyRegistry,
};
use qbind_consensus::verify::{ConsensusVerifier, VerificationError};
use qbind_consensus::{MultiSuiteCryptoVerifier, SimpleBackendRegistry, ValidatorId};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::{ConsensusSigSuiteId, SUITE_TOY_SHA3};
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
// Test-only governance implementation
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

/// Helper to create a Vote with a specific suite_id on the wire.
fn make_vote_with_suite(height: u64, round: u64, wire_suite_id: u16, signature: Vec<u8>) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: wire_suite_id,
        signature,
    }
}

/// Helper to create a BlockProposal with a specific suite_id on the wire.
fn make_proposal_with_suite(
    height: u64,
    round: u64,
    wire_suite_id: u16,
    signature: Vec<u8>,
) -> BlockProposal {
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
            suite_id: wire_suite_id,
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

/// Create a MultiSuiteCryptoVerifier with given governance.
fn make_verifier(governance: TestSuiteGovernance) -> MultiSuiteCryptoVerifier {
    let key_provider: Arc<GovernedValidatorKeyRegistry<TestSuiteGovernance>> =
        Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Register backend for SUITE_TOY_SHA3 (value 0)
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry))
}

// ============================================================================
// Part D Tests: Suite mismatch detection
// ============================================================================

/// Test: Vote with wire suite != governance suite returns SuiteMismatch error.
#[test]
fn vote_suite_mismatch_returns_error() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    // Governance says validator 1 uses SUITE_TOY_SHA3 (0)
    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create a vote with wire suite_id = 999 (mismatch!)
    let mismatched_wire_suite: u16 = 999;
    let mut vote = make_vote_with_suite(10, 5, mismatched_wire_suite, vec![]);
    // Sign the vote (signature will be valid for the preimage with suite 999)
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify should fail with SuiteMismatch
    let result = verifier.verify_vote(ValidatorId::new(validator_id), &vote);

    match result {
        Err(VerificationError::SuiteMismatch {
            validator_id: vid,
            wire_suite,
            governance_suite,
        }) => {
            assert_eq!(vid, ValidatorId::new(validator_id));
            assert_eq!(wire_suite, ConsensusSigSuiteId::new(999));
            assert_eq!(governance_suite, SUITE_TOY_SHA3);
        }
        other => panic!("Expected SuiteMismatch error, got {:?}", other),
    }
}

/// Test: Proposal with wire suite != governance suite returns SuiteMismatch error.
#[test]
fn proposal_suite_mismatch_returns_error() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    // Governance says validator 1 uses SUITE_TOY_SHA3 (0)
    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create a proposal with wire suite_id = 999 (mismatch!)
    let mismatched_wire_suite: u16 = 999;
    let mut proposal = make_proposal_with_suite(10, 5, mismatched_wire_suite, vec![]);
    // Sign the proposal (signature will be valid for the preimage with suite 999)
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify should fail with SuiteMismatch
    let result = verifier.verify_proposal(ValidatorId::new(validator_id), &proposal);

    match result {
        Err(VerificationError::SuiteMismatch {
            validator_id: vid,
            wire_suite,
            governance_suite,
        }) => {
            assert_eq!(vid, ValidatorId::new(validator_id));
            assert_eq!(wire_suite, ConsensusSigSuiteId::new(999));
            assert_eq!(governance_suite, SUITE_TOY_SHA3);
        }
        other => panic!("Expected SuiteMismatch error, got {:?}", other),
    }
}

/// Test: Vote suite mismatch increments the suite_mismatch metric.
#[test]
fn vote_suite_mismatch_increments_metric() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Initial metric should be zero
    assert_eq!(verifier.metrics().vote_suite_mismatch(), 0);

    // Create mismatched vote
    let mut vote = make_vote_with_suite(10, 5, 999, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify (will fail with mismatch)
    let _ = verifier.verify_vote(ValidatorId::new(validator_id), &vote);

    // Metric should be incremented
    assert_eq!(verifier.metrics().vote_suite_mismatch(), 1);

    // Other metrics should be zero
    assert_eq!(verifier.metrics().vote_ok(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
}

/// Test: Proposal suite mismatch increments the suite_mismatch metric.
#[test]
fn proposal_suite_mismatch_increments_metric() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Initial metric should be zero
    assert_eq!(verifier.metrics().proposal_suite_mismatch(), 0);

    // Create mismatched proposal
    let mut proposal = make_proposal_with_suite(10, 5, 999, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify (will fail with mismatch)
    let _ = verifier.verify_proposal(ValidatorId::new(validator_id), &proposal);

    // Metric should be incremented
    assert_eq!(verifier.metrics().proposal_suite_mismatch(), 1);

    // Other metrics should be zero
    assert_eq!(verifier.metrics().proposal_ok(), 0);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);
}

/// Test: Vote with matching suite succeeds (happy path unchanged).
#[test]
fn vote_matching_suite_succeeds() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    // Governance says validator 1 uses SUITE_TOY_SHA3 (0)
    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create a vote with wire suite_id = 0 (matches governance)
    let mut vote = make_vote_with_suite(10, 5, SUITE_TOY_SHA3.as_u16(), vec![]);
    // Sign the vote
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify should succeed
    let result = verifier.verify_vote(ValidatorId::new(validator_id), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Metrics should show success
    assert_eq!(verifier.metrics().vote_ok(), 1);
    assert_eq!(verifier.metrics().vote_suite_mismatch(), 0);
}

/// Test: Proposal with matching suite succeeds (happy path unchanged).
#[test]
fn proposal_matching_suite_succeeds() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    // Governance says validator 1 uses SUITE_TOY_SHA3 (0)
    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create a proposal with wire suite_id = 0 (matches governance)
    let mut proposal = make_proposal_with_suite(10, 5, SUITE_TOY_SHA3.as_u16(), vec![]);
    // Sign the proposal
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify should succeed
    let result = verifier.verify_proposal(ValidatorId::new(validator_id), &proposal);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Metrics should show success
    assert_eq!(verifier.metrics().proposal_ok(), 1);
    assert_eq!(verifier.metrics().proposal_suite_mismatch(), 0);
}

/// Test: VerificationError::SuiteMismatch has correct Display impl.
#[test]
fn suite_mismatch_error_display() {
    let err = VerificationError::SuiteMismatch {
        validator_id: ValidatorId::new(42),
        wire_suite: ConsensusSigSuiteId::new(999),
        governance_suite: SUITE_TOY_SHA3,
    };

    let display_str = format!("{}", err);

    assert!(display_str.contains("suite mismatch"));
    assert!(display_str.contains("999"));
    assert!(display_str.contains("suite_0")); // SUITE_TOY_SHA3 displays as "suite_0"
}

/// Test: Multiple mismatches increment metrics correctly.
#[test]
fn multiple_mismatches_increment_metrics() {
    let pk_bytes = b"test-validator-key".to_vec();

    let governance = TestSuiteGovernance::new()
        .with_key(1, SUITE_TOY_SHA3, pk_bytes.clone())
        .with_key(2, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create two mismatched votes from different validators
    let mut vote1 = make_vote_with_suite(10, 5, 100, vec![]);
    vote1.signature = sign_vote(&pk_bytes, &vote1);

    let mut vote2 = make_vote_with_suite(11, 5, 200, vec![]);
    vote2.signature = sign_vote(&pk_bytes, &vote2);

    // Also create a mismatched proposal
    let mut proposal = make_proposal_with_suite(12, 5, 300, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify all (all will fail)
    let _ = verifier.verify_vote(ValidatorId::new(1), &vote1);
    let _ = verifier.verify_vote(ValidatorId::new(2), &vote2);
    let _ = verifier.verify_proposal(ValidatorId::new(1), &proposal);

    // Check metrics
    assert_eq!(verifier.metrics().vote_suite_mismatch(), 2);
    assert_eq!(verifier.metrics().proposal_suite_mismatch(), 1);
    assert_eq!(verifier.metrics().vote_ok(), 0);
    assert_eq!(verifier.metrics().proposal_ok(), 0);
}

// ============================================================================
// Part D Tests: Driver-level suite mismatch handling
// ============================================================================

use qbind_consensus::{
    ConsensusEngineDriver, ConsensusNetworkEvent, HotStuffDriver, HotStuffState,
    MockConsensusNetwork,
};

/// Test: Driver handles vote with suite mismatch without panicking.
///
/// When a vote has a wire suite_id that doesn't match governance, the driver
/// should reject the vote (increment rejected_invalid_signatures) and continue
/// without panicking.
#[test]
fn driver_handles_vote_suite_mismatch_gracefully() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    // Create governance that says validator uses SUITE_TOY_SHA3 (0)
    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create driver with verifier
    // T121: permissive driver is intentional here; test does not care about membership.
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine).with_verifier(Arc::new(verifier));
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Create a vote with mismatched wire suite_id = 999
    let mut vote = make_vote_with_suite(1, 0, 999, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(validator_id),
        vote,
    };

    // Driver should handle this without panicking
    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Vote should be rejected due to suite mismatch (counted as invalid signature)
    assert_eq!(driver.rejected_invalid_signatures(), 1);
    // Vote should NOT be counted as received
    assert_eq!(driver.votes_received(), 0);
    // No actions should be returned (rejected message)
    assert!(actions.is_empty(), "Expected no actions for rejected vote");
}

/// Test: Driver handles proposal with suite mismatch without panicking.
///
/// When a proposal has a wire suite_id that doesn't match governance, the driver
/// should reject the proposal (increment rejected_invalid_signatures) and continue
/// without panicking.
#[test]
fn driver_handles_proposal_suite_mismatch_gracefully() {
    let pk_bytes = b"test-validator-key".to_vec();
    let validator_id = 1u64;

    // Create governance that says validator uses SUITE_TOY_SHA3 (0)
    let governance =
        TestSuiteGovernance::new().with_key(validator_id, SUITE_TOY_SHA3, pk_bytes.clone());

    let verifier = make_verifier(governance);

    // Create driver with verifier
    // T121: permissive driver is intentional here; test does not care about membership.
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine).with_verifier(Arc::new(verifier));
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Create a proposal with mismatched wire suite_id = 888
    let mut proposal = make_proposal_with_suite(1, 0, 888, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    let event = ConsensusNetworkEvent::IncomingProposal {
        from: ValidatorId::new(validator_id),
        proposal,
    };

    // Driver should handle this without panicking
    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Proposal should be rejected due to suite mismatch (counted as invalid signature)
    assert_eq!(driver.rejected_invalid_signatures(), 1);
    // Proposal should NOT be counted as received
    assert_eq!(driver.proposals_received(), 0);
    // No actions should be returned (rejected message)
    assert!(
        actions.is_empty(),
        "Expected no actions for rejected proposal"
    );
}
