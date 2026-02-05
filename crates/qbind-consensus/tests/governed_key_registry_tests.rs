//! Integration tests for `GovernedValidatorKeyRegistry`.
//!
//! These tests verify that the `GovernedValidatorKeyRegistry` correctly:
//! - Provides keys from governance to `CryptoConsensusVerifier`
//! - Accepts valid vote and proposal signatures
//! - Rejects tampered signatures (InvalidSignature)
//! - Returns MissingKey when no key is configured
//!
//! The tests use a minimal test governance implementation and the
//! SHA3-based "toy" signature scheme for testing purposes.

use std::collections::HashMap;
use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use qbind_consensus::governed_key_registry::{
    ConsensusKeyGovernance, GovernedValidatorKeyRegistry,
};
use qbind_consensus::verify::{ConsensusVerifier, VerificationError};
use qbind_consensus::{CryptoConsensusVerifier, ValidatorId};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::{ConsensusSigSuiteId, SUITE_TOY_SHA3};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Test-only governance implementation
// ============================================================================

/// A minimal test governance implementation for testing `GovernedValidatorKeyRegistry`.
///
/// This fake governance simply stores a mapping from validator IDs to
/// consensus public keys (with suite ID), configurable via builder methods.
#[derive(Debug, Default)]
pub struct TestGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl TestGovernance {
    /// Create a new empty test governance.
    pub fn new() -> Self {
        TestGovernance {
            keys: HashMap::new(),
        }
    }

    /// Add a consensus key for a validator using the default test suite (SUITE_TOY_SHA3).
    pub fn with_key(mut self, validator_id: u64, pk: Vec<u8>) -> Self {
        self.keys.insert(validator_id, (SUITE_TOY_SHA3, pk));
        self
    }

    /// Add a consensus key for a validator with a specific suite ID.
    pub fn with_key_and_suite(
        mut self,
        validator_id: u64,
        suite_id: ConsensusSigSuiteId,
        pk: Vec<u8>,
    ) -> Self {
        self.keys.insert(validator_id, (suite_id, pk));
        self
    }
}

impl ConsensusKeyGovernance for TestGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
}

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

/// Build a CryptoConsensusVerifier using GovernedValidatorKeyRegistry.
fn build_governed_verifier(governance: TestGovernance) -> CryptoConsensusVerifier {
    let governed_registry: Arc<GovernedValidatorKeyRegistry<TestGovernance>> =
        Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));
    CryptoConsensusVerifier::with_key_provider(
        governed_registry,
        Arc::new(TestHashConsensusSigVerifier),
    )
}

// ============================================================================
// GovernedValidatorKeyRegistry unit tests
// ============================================================================

/// Test that GovernedValidatorKeyRegistry returns the expected pk bytes when a key is configured.
#[test]
fn governed_registry_returns_expected_key_bytes() {
    use qbind_consensus::key_registry::ValidatorKeyProvider;

    let pk = b"test-consensus-public-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk.clone());
    let registry = GovernedValidatorKeyRegistry::new(Arc::new(governance));

    let result = registry.get_key(ValidatorId::new(1));
    assert_eq!(result, Some(pk));
}

/// Test that GovernedValidatorKeyRegistry returns None when no key exists for the validator.
#[test]
fn governed_registry_returns_none_for_missing_key() {
    use qbind_consensus::key_registry::ValidatorKeyProvider;

    let governance = TestGovernance::new();
    let registry = GovernedValidatorKeyRegistry::new(Arc::new(governance));

    let result = registry.get_key(ValidatorId::new(999));
    assert!(result.is_none());
}

/// Test that GovernedValidatorKeyRegistry returns both suite ID and pk bytes via SuiteAwareValidatorKeyProvider.
#[test]
fn governed_registry_returns_suite_and_key() {
    use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;

    let pk = b"test-consensus-public-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk.clone());
    let registry = GovernedValidatorKeyRegistry::new(Arc::new(governance));

    let result = registry.get_suite_and_key(ValidatorId::new(1));
    assert_eq!(result, Some((SUITE_TOY_SHA3, pk)));
}

/// Test that SuiteAwareValidatorKeyProvider returns the correct suite ID when using with_key_and_suite.
#[test]
fn governed_registry_returns_custom_suite_id() {
    use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;

    let pk = b"test-key".to_vec();
    let custom_suite = ConsensusSigSuiteId::new(42);
    let governance = TestGovernance::new().with_key_and_suite(1, custom_suite, pk.clone());
    let registry = GovernedValidatorKeyRegistry::new(Arc::new(governance));

    let result = registry.get_suite_and_key(ValidatorId::new(1));
    assert_eq!(result, Some((custom_suite, pk)));
}

// ============================================================================
// Integration tests: GovernedValidatorKeyRegistry with CryptoConsensusVerifier
// ============================================================================

/// Test that GovernedValidatorKeyRegistry integrates correctly with CryptoConsensusVerifier
/// to verify a valid vote.
#[test]
fn governed_verifier_accepts_valid_vote() {
    let pk_bytes = b"validator-1-consensus-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // Create and sign a vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that GovernedValidatorKeyRegistry + CryptoConsensusVerifier rejects a tampered vote.
#[test]
fn governed_verifier_rejects_tampered_vote() {
    let pk_bytes = b"validator-1-consensus-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // Create and sign a vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Tamper with the signature
    vote.signature[0] ^= 0xff;

    // Verify should fail
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature, got {:?}",
        result
    );
}

/// Test that GovernedValidatorKeyRegistry + CryptoConsensusVerifier returns MissingKey
/// when no key is configured for the validator.
#[test]
fn governed_verifier_rejects_missing_key() {
    // Empty governance - no keys configured
    let governance = TestGovernance::new();
    let verifier = build_governed_verifier(governance);

    // Create a vote
    let vote = make_vote_with_sig(10, 5, vec![0u8; 32]);

    // Verify should fail with MissingKey
    let result = verifier.verify_vote(ValidatorId::new(999), &vote);
    assert!(
        matches!(result, Err(VerificationError::MissingKey(_))),
        "Expected MissingKey, got {:?}",
        result
    );
}

/// Test that GovernedValidatorKeyRegistry + CryptoConsensusVerifier accepts a valid proposal.
#[test]
fn governed_verifier_accepts_valid_proposal() {
    let pk_bytes = b"proposer-consensus-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // Create and sign a proposal
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that GovernedValidatorKeyRegistry + CryptoConsensusVerifier rejects a tampered proposal.
#[test]
fn governed_verifier_rejects_tampered_proposal() {
    let pk_bytes = b"proposer-consensus-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // Create and sign a proposal
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Tamper with the signature
    proposal.signature[0] ^= 0xff;

    // Verify should fail
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature, got {:?}",
        result
    );
}

/// Test that GovernedValidatorKeyRegistry + CryptoConsensusVerifier works with multiple validators.
#[test]
fn governed_verifier_with_multiple_validators() {
    let pk1 = b"validator-1-key".to_vec();
    let pk2 = b"validator-2-key".to_vec();
    let pk3 = b"validator-3-key".to_vec();

    let governance = TestGovernance::new()
        .with_key(1, pk1.clone())
        .with_key(2, pk2.clone())
        .with_key(3, pk3.clone());
    let verifier = build_governed_verifier(governance);

    // Create votes from each validator
    let mut vote1 = make_vote_with_sig(10, 0, vec![]);
    let mut vote2 = make_vote_with_sig(10, 0, vec![]);
    let mut vote3 = make_vote_with_sig(10, 0, vec![]);

    vote1.signature = sign_vote(&pk1, &vote1);
    vote2.signature = sign_vote(&pk2, &vote2);
    vote3.signature = sign_vote(&pk3, &vote3);

    // All should verify correctly
    assert!(verifier.verify_vote(ValidatorId::new(1), &vote1).is_ok());
    assert!(verifier.verify_vote(ValidatorId::new(2), &vote2).is_ok());
    assert!(verifier.verify_vote(ValidatorId::new(3), &vote3).is_ok());

    // Cross-verification should fail (InvalidSignature)
    assert!(
        matches!(
            verifier.verify_vote(ValidatorId::new(2), &vote1),
            Err(VerificationError::InvalidSignature)
        ),
        "Cross-verification should fail"
    );

    // Validator 4 has no key (MissingKey)
    let vote4 = make_vote_with_sig(10, 0, vec![0u8; 32]);
    assert!(
        matches!(
            verifier.verify_vote(ValidatorId::new(4), &vote4),
            Err(VerificationError::MissingKey(_))
        ),
        "Validator 4 has no key"
    );
}

// ============================================================================
// Integration tests: GovernedValidatorKeyRegistry with HotStuffDriver
// ============================================================================

/// Test that GovernedValidatorKeyRegistry integrates correctly with HotStuffDriver.
///
/// This test wires up a GovernedValidatorKeyRegistry into a CryptoConsensusVerifier,
/// then into a HotStuffDriver, and verifies that:
/// - Valid signatures are processed (incrementing votes_received)
/// - Invalid signatures are rejected (incrementing rejected_invalid_signatures)
#[test]
fn governed_verifier_integrates_with_hotstuff_driver() {
    use qbind_consensus::{
        ConsensusEngineDriver, ConsensusNetworkEvent, HotStuffDriver, HotStuffState,
        MockConsensusNetwork,
    };

    let pk_bytes = b"test-validator-public-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // Create a HotStuffDriver with the verifier
    // T121: permissive driver is intentional here; test does not care about membership.
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine).with_verifier(Arc::new(verifier));
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Test 1: Valid vote is accepted
    let mut valid_vote = make_vote_with_sig(1, 0, vec![]);
    valid_vote.signature = sign_vote(&pk_bytes, &valid_vote);
    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(1),
        vote: valid_vote,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();
    assert_eq!(driver.votes_received(), 1, "Valid vote should be counted");
    assert_eq!(
        driver.rejected_invalid_signatures(),
        0,
        "No rejections expected"
    );
    assert!(!actions.is_empty(), "Should return at least Noop action");

    // Test 2: Invalid (tampered) vote is rejected
    let mut invalid_vote = make_vote_with_sig(1, 1, vec![]);
    invalid_vote.signature = sign_vote(&pk_bytes, &invalid_vote);
    invalid_vote.signature[0] ^= 0xff; // Tamper with signature

    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(1),
        vote: invalid_vote,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();
    assert_eq!(
        driver.votes_received(),
        1,
        "Invalid vote should not be counted"
    );
    assert_eq!(
        driver.rejected_invalid_signatures(),
        1,
        "Tampered vote should be rejected"
    );
    assert!(actions.is_empty(), "No actions for rejected message");
}

/// Test that GovernedValidatorKeyRegistry rejects votes from validators not in governance
/// when integrated with HotStuffDriver.
#[test]
fn governed_verifier_rejects_unknown_validator_in_driver() {
    use qbind_consensus::{
        ConsensusEngineDriver, ConsensusNetworkEvent, HotStuffDriver, HotStuffState,
        MockConsensusNetwork,
    };

    // Only validator 1 has a key
    let pk_bytes = b"validator-1-pk".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // T121: permissive driver is intentional here; test does not care about membership.
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine).with_verifier(Arc::new(verifier));
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a vote claiming to be from validator 999 (not in governance)
    let mut vote = make_vote_with_sig(1, 0, vec![]);
    let unknown_pk = b"unknown-validator-pk".to_vec();
    vote.signature = sign_vote(&unknown_pk, &vote);

    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(999),
        vote,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();
    assert_eq!(
        driver.votes_received(),
        0,
        "Unknown validator vote should not be counted"
    );
    assert_eq!(
        driver.rejected_invalid_signatures(),
        1,
        "Unknown validator should be rejected"
    );
    assert!(actions.is_empty(), "No actions for rejected message");
}

/// Test GovernedValidatorKeyRegistry with proposals in HotStuffDriver.
#[test]
fn governed_verifier_handles_proposals_in_driver() {
    use qbind_consensus::{
        ConsensusEngineDriver, ConsensusNetworkEvent, HotStuffDriver, HotStuffState,
        MockConsensusNetwork,
    };

    let pk_bytes = b"proposer-public-key".to_vec();
    let governance = TestGovernance::new().with_key(1, pk_bytes.clone());
    let verifier = build_governed_verifier(governance);

    // T121: permissive driver is intentional here; test does not care about membership.
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine).with_verifier(Arc::new(verifier));
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Test 1: Valid proposal is accepted
    let mut valid_proposal = make_proposal_with_sig(1, 0, vec![]);
    valid_proposal.signature = sign_proposal(&pk_bytes, &valid_proposal);

    let event = ConsensusNetworkEvent::IncomingProposal {
        from: ValidatorId::new(1),
        proposal: Box::new(valid_proposal),
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();
    assert_eq!(
        driver.proposals_received(),
        1,
        "Valid proposal should be counted"
    );
    assert_eq!(
        driver.rejected_invalid_signatures(),
        0,
        "No rejections expected"
    );
    assert!(!actions.is_empty(), "Should return at least Noop action");

    // Test 2: Invalid proposal is rejected
    let mut invalid_proposal = make_proposal_with_sig(1, 1, vec![]);
    invalid_proposal.signature = sign_proposal(&pk_bytes, &invalid_proposal);
    invalid_proposal.signature[0] ^= 0xff; // Tamper

    let event = ConsensusNetworkEvent::IncomingProposal {
        from: ValidatorId::new(1),
        proposal: Box::new(invalid_proposal),
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();
    assert_eq!(
        driver.proposals_received(),
        1,
        "Invalid proposal should not be counted"
    );
    assert_eq!(
        driver.rejected_invalid_signatures(),
        1,
        "Tampered proposal should be rejected"
    );
    assert!(actions.is_empty(), "No actions for rejected message");
}
