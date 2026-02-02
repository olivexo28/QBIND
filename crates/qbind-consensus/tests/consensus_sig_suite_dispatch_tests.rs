//! Tests for per-suite consensus signature verifier dispatch.
//!
//! These tests verify that `MultiSuiteCryptoVerifier` correctly:
//! - Dispatches verification to the appropriate backend based on suite ID
//! - Returns `VerificationError::Other` when no backend is registered for a suite
//! - Records correct metrics and logs (including suite_id)
//!
//! The tests use a minimal test governance and the SHA3-based "toy" signature
//! scheme for testing purposes.

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
// Test-only governance implementation (suite-aware)
// ============================================================================

/// A minimal test governance implementation that returns (suite_id, pk_bytes).
#[derive(Debug, Default)]
pub struct TestSuiteGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl TestSuiteGovernance {
    /// Create a new empty test governance.
    pub fn new() -> Self {
        TestSuiteGovernance {
            keys: HashMap::new(),
        }
    }

    /// Add a consensus key for a validator with the specified suite ID.
    pub fn with_key(
        mut self,
        validator_id: u64,
        suite_id: ConsensusSigSuiteId,
        pk: Vec<u8>,
    ) -> Self {
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

/// Build a MultiSuiteCryptoVerifier with the given governance and backend registry.
fn build_multi_suite_verifier(
    governance: TestSuiteGovernance,
    registry: SimpleBackendRegistry,
) -> MultiSuiteCryptoVerifier {
    let key_provider: Arc<GovernedValidatorKeyRegistry<TestSuiteGovernance>> =
        Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));
    MultiSuiteCryptoVerifier::new(key_provider, Arc::new(registry))
}

// ============================================================================
// Per-suite dispatch tests
// ============================================================================

/// Test that MultiSuiteCryptoVerifier dispatches to the correct backend based on suite ID.
#[test]
fn multi_suite_verifier_dispatches_to_correct_backend() {
    // Setup: governance returns SUITE_TOY_SHA3 for validator 1
    let pk_bytes = b"validator-1-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_TOY_SHA3, pk_bytes.clone());

    // Backend registry maps SUITE_TOY_SHA3 to the test hash verifier
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create and sign a vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify should succeed
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Check metrics
    assert_eq!(verifier.metrics().vote_ok(), 1);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
    assert_eq!(verifier.metrics().vote_other(), 0);
}

/// Test that MultiSuiteCryptoVerifier accepts valid proposal signatures.
#[test]
fn multi_suite_verifier_accepts_valid_proposal() {
    let pk_bytes = b"proposer-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_TOY_SHA3, pk_bytes.clone());
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create and sign a proposal
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify should succeed
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Check metrics
    assert_eq!(verifier.metrics().proposal_ok(), 1);
}

/// Test that MultiSuiteCryptoVerifier rejects tampered signatures.
#[test]
fn multi_suite_verifier_rejects_tampered_signature() {
    let pk_bytes = b"validator-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_TOY_SHA3, pk_bytes.clone());
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create and sign a vote, then tamper with it
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);
    vote.signature[0] ^= 0xff; // Tamper

    // Verify should fail
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature, got {:?}",
        result
    );

    // Check metrics
    assert_eq!(verifier.metrics().vote_invalid_signature(), 1);
}

/// Test that MultiSuiteCryptoVerifier returns MissingKey when validator has no key.
#[test]
fn multi_suite_verifier_returns_missing_key() {
    // Empty governance - no keys
    let governance = TestSuiteGovernance::new();
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    let vote = make_vote_with_sig(10, 5, vec![0u8; 32]);
    let result = verifier.verify_vote(ValidatorId::new(999), &vote);

    assert!(
        matches!(result, Err(VerificationError::MissingKey(_))),
        "Expected MissingKey, got {:?}",
        result
    );

    // Check metrics
    assert_eq!(verifier.metrics().vote_missing_key(), 1);
}

// ============================================================================
// Missing backend tests
// ============================================================================

/// Test that MultiSuiteCryptoVerifier returns Other error when no backend for suite.
///
/// NOTE: As of T83, we first check wire suite_id vs governance suite_id.
/// To test the "backend not found" path, wire suite must match governance.
#[test]
fn multi_suite_verifier_returns_error_for_unsupported_suite() {
    // Governance returns an unknown suite ID
    let unknown_suite = ConsensusSigSuiteId::new(999);
    let pk_bytes = b"validator-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, unknown_suite, pk_bytes.clone());

    // Backend registry only knows SUITE_TOY_SHA3 (not suite 999)
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create a vote with wire suite_id = 999 (matching governance, but no backend)
    let vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 10,
        round: 5,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: unknown_suite.as_u16(), // Wire suite matches governance (999)
        signature: vec![0u8; 32],
    };

    // Verify should fail with Other error (backend not found)
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    match result {
        Err(VerificationError::Other(msg)) => {
            assert!(
                msg.contains("unsupported consensus signature suite"),
                "Expected 'unsupported consensus signature suite' in error, got: {}",
                msg
            );
        }
        other => panic!("Expected VerificationError::Other, got {:?}", other),
    }

    // Check metrics - should increment "other" counter
    assert_eq!(verifier.metrics().vote_other(), 1);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
}

/// Test that missing backend for proposal also returns Other error.
///
/// NOTE: As of T83, we first check wire suite_id vs governance suite_id.
/// To test the "backend not found" path, wire suite must match governance.
#[test]
fn multi_suite_verifier_returns_error_for_unsupported_suite_proposal() {
    let unknown_suite = ConsensusSigSuiteId::new(999);
    let pk_bytes = b"proposer-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, unknown_suite, pk_bytes.clone());
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create a proposal with wire suite_id = 999 (matching governance, but no backend)
    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 10,
            round: 5,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: unknown_suite.as_u16(), // Wire suite matches governance (999)
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![0u8; 32],
    };
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);

    match result {
        Err(VerificationError::Other(msg)) => {
            assert!(
                msg.contains("unsupported consensus signature suite"),
                "Expected 'unsupported consensus signature suite' in error, got: {}",
                msg
            );
        }
        other => panic!("Expected VerificationError::Other, got {:?}", other),
    }

    // Check metrics
    assert_eq!(verifier.metrics().proposal_other(), 1);
}

// ============================================================================
// Multiple validators with same suite
// ============================================================================

/// Test that multiple validators using the same suite work correctly.
#[test]
fn multi_suite_verifier_handles_multiple_validators_same_suite() {
    let pk1 = b"validator-1-key".to_vec();
    let pk2 = b"validator-2-key".to_vec();
    let pk3 = b"validator-3-key".to_vec();

    let governance = TestSuiteGovernance::new()
        .with_key(1, SUITE_TOY_SHA3, pk1.clone())
        .with_key(2, SUITE_TOY_SHA3, pk2.clone())
        .with_key(3, SUITE_TOY_SHA3, pk3.clone());

    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create and sign votes from each validator
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

    // Cross-verification should fail
    assert!(
        matches!(
            verifier.verify_vote(ValidatorId::new(2), &vote1),
            Err(VerificationError::InvalidSignature)
        ),
        "Cross-verification should fail"
    );

    // Check metrics
    assert_eq!(verifier.metrics().vote_ok(), 3);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 1);
}

// ============================================================================
// SimpleBackendRegistry tests
// ============================================================================

/// Test SimpleBackendRegistry basic operations.
#[test]
fn simple_backend_registry_basic_operations() {
    use qbind_consensus::ConsensusSigBackendRegistry;

    let mut registry = SimpleBackendRegistry::new();

    // Initially empty
    assert!(registry.get_backend(SUITE_TOY_SHA3).is_none());

    // Register a backend
    let backend: Arc<dyn ConsensusSigVerifier> = Arc::new(TestHashConsensusSigVerifier);
    registry.register(SUITE_TOY_SHA3, backend.clone());

    // Now it should be found
    assert!(registry.get_backend(SUITE_TOY_SHA3).is_some());

    // Unknown suite still returns None
    let unknown = ConsensusSigSuiteId::new(42);
    assert!(registry.get_backend(unknown).is_none());
}

/// Test SimpleBackendRegistry with_backend convenience constructor.
#[test]
fn simple_backend_registry_with_backend() {
    use qbind_consensus::ConsensusSigBackendRegistry;

    let registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    assert!(registry.get_backend(SUITE_TOY_SHA3).is_some());
}

/// Test that SimpleBackendRegistry is Debug.
#[test]
fn simple_backend_registry_is_debug() {
    let registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));
    let debug_str = format!("{:?}", registry);
    assert!(debug_str.contains("SimpleBackendRegistry"));
}

// ============================================================================
// MultiSuiteCryptoVerifier is Debug
// ============================================================================

/// Test that MultiSuiteCryptoVerifier is Debug.
#[test]
fn multi_suite_verifier_is_debug() {
    let governance = TestSuiteGovernance::new();
    let backend_registry = SimpleBackendRegistry::new();
    let verifier = build_multi_suite_verifier(governance, backend_registry);

    let debug_str = format!("{:?}", verifier);
    assert!(debug_str.contains("MultiSuiteCryptoVerifier"));
}

// ============================================================================
// T81: suite_id from wire format tests
// ============================================================================

/// Test that Vote with suite_id = SUITE_TOY_SHA3 and valid signature verifies successfully.
#[test]
fn vote_with_suite_toy_sha3_and_valid_signature_verifies() {
    let pk_bytes = b"validator-key-test".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, SUITE_TOY_SHA3, pk_bytes.clone());
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create a vote with suite_id = SUITE_TOY_SHA3 (value 0)
    let mut vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 10,
        round: 5,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: SUITE_TOY_SHA3.as_u16(),
        signature: vec![],
    };

    // Sign the vote with the correct key
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify should succeed
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Vote with suite_id = SUITE_TOY_SHA3 and valid signature should verify successfully, got {:?}", result);

    // Check metrics
    assert_eq!(verifier.metrics().vote_ok(), 1);
}

/// Test that a message with unknown suite_id (999) fails verification with a sensible error.
/// This tests the multi-suite dispatch error path when no backend is registered.
#[test]
fn message_with_unknown_suite_id_fails_verification() {
    // Governance says validator 1 uses unknown suite 999
    let unknown_suite_id = ConsensusSigSuiteId::new(999);
    let pk_bytes = b"validator-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, unknown_suite_id, pk_bytes.clone());

    // Backend registry only knows about SUITE_TOY_SHA3 (0)
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    // Create a vote (signature doesn't matter since we'll fail at backend lookup)
    let vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 10,
        round: 5,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: unknown_suite_id.as_u16(),
        signature: vec![0u8; 32],
    };

    // Verify should fail with an "unsupported consensus signature suite" error
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    match result {
        Err(VerificationError::Other(msg)) => {
            assert!(
                msg.contains("unsupported consensus signature suite"),
                "Expected 'unsupported consensus signature suite' error for unknown suite_id=999, got: {}",
                msg
            );
            assert!(
                msg.contains("999"),
                "Error message should mention the unknown suite ID 999, got: {}",
                msg
            );
        }
        other => panic!(
            "Expected VerificationError::Other for unknown suite_id, got {:?}",
            other
        ),
    }

    // Check metrics - should increment "other" counter
    assert_eq!(verifier.metrics().vote_other(), 1);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
}

/// Test that BlockProposal with unknown suite_id also fails verification.
#[test]
fn proposal_with_unknown_suite_id_fails_verification() {
    let unknown_suite_id = ConsensusSigSuiteId::new(999);
    let pk_bytes = b"proposer-key".to_vec();
    let governance = TestSuiteGovernance::new().with_key(1, unknown_suite_id, pk_bytes.clone());

    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = build_multi_suite_verifier(governance, backend_registry);

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 10,
            round: 5,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: unknown_suite_id.as_u16(),
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![0u8; 32],
    };

    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    match result {
        Err(VerificationError::Other(msg)) => {
            assert!(
                msg.contains("unsupported consensus signature suite"),
                "Expected 'unsupported consensus signature suite' error for proposal with unknown suite_id=999, got: {}",
                msg
            );
        }
        other => panic!(
            "Expected VerificationError::Other for proposal with unknown suite_id, got {:?}",
            other
        ),
    }

    // Check metrics
    assert_eq!(verifier.metrics().proposal_other(), 1);
}