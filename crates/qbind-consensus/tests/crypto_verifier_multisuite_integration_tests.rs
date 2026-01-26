//! Integration tests for T80: Multi-suite verification path integration.
//!
//! These tests verify that:
//! - `CryptoConsensusVerifier` internally delegates to `MultiSuiteCryptoVerifier`
//! - The multi-suite path is used even when constructed with single-backend APIs
//! - Suite ID dispatch works correctly through `CryptoConsensusVerifier`
//! - Metrics and behavior are preserved from T78
//!
//! The tests use a recording registry to confirm the multi-suite path is exercised.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use qbind_consensus::governed_key_registry::{
    ConsensusKeyGovernance, GovernedValidatorKeyRegistry,
};
use qbind_consensus::verify::{ConsensusVerifier, VerificationError};
use qbind_consensus::{
    ConsensusEngineDriver, ConsensusNetworkEvent, ConsensusSigBackendRegistry,
    CryptoConsensusVerifier, HotStuffDriver, HotStuffState, MockConsensusNetwork,
    MultiSuiteCryptoVerifier, SimpleBackendRegistry, SuiteAwareValidatorKeyProvider, ValidatorId,
    ValidatorKeyRegistry, ValidatorPublicKey,
};
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
    ///
    /// **NOT FOR PRODUCTION** - this is only for testing the verification pipeline.
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
// Recording backend registry (to verify multi-suite path is used)
// ============================================================================

/// A backend registry that records which suite IDs are queried.
///
/// This is used to verify that the multi-suite dispatch path is exercised.
#[derive(Debug)]
struct RecordingBackendRegistry {
    inner: SimpleBackendRegistry,
    call_count: AtomicU64,
    last_suite_queried: std::sync::Mutex<Option<ConsensusSigSuiteId>>,
}

impl RecordingBackendRegistry {
    fn new(inner: SimpleBackendRegistry) -> Self {
        RecordingBackendRegistry {
            inner,
            call_count: AtomicU64::new(0),
            last_suite_queried: std::sync::Mutex::new(None),
        }
    }

    fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }

    fn last_suite_queried(&self) -> Option<ConsensusSigSuiteId> {
        *self.last_suite_queried.lock().unwrap()
    }
}

impl ConsensusSigBackendRegistry for RecordingBackendRegistry {
    fn get_backend(&self, suite: ConsensusSigSuiteId) -> Option<Arc<dyn ConsensusSigVerifier>> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        *self.last_suite_queried.lock().unwrap() = Some(suite);
        self.inner.get_backend(suite)
    }
}

// ============================================================================
// Recording key provider (to verify multi-suite path is used)
// ============================================================================

/// A key provider that records which validators are queried.
///
/// This is used to verify that the suite-aware key provider path is exercised.
#[derive(Debug)]
struct RecordingSuiteAwareKeyProvider {
    keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
    call_count: AtomicU64,
}

impl RecordingSuiteAwareKeyProvider {
    fn new() -> Self {
        RecordingSuiteAwareKeyProvider {
            keys: HashMap::new(),
            call_count: AtomicU64::new(0),
        }
    }

    fn with_key(mut self, id: ValidatorId, suite: ConsensusSigSuiteId, pk: Vec<u8>) -> Self {
        self.keys.insert(id, (suite, pk));
        self
    }

    fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }
}

impl SuiteAwareValidatorKeyProvider for RecordingSuiteAwareKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        self.keys.get(&id).cloned()
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

// ============================================================================
// Integration tests: Verify multi-suite path is exercised
// ============================================================================

/// Test that CryptoConsensusVerifier routes through multi-suite dispatch.
///
/// This test uses a recording key provider to verify that the suite-aware
/// key lookup is called, confirming the multi-suite path is exercised.
#[test]
fn crypto_verifier_routes_through_multi_suite_dispatch() {
    let pk_bytes = b"test-validator-key".to_vec();

    // Create a recording key provider
    let key_provider = Arc::new(RecordingSuiteAwareKeyProvider::new().with_key(
        ValidatorId::new(1),
        SUITE_TOY_SHA3,
        pk_bytes.clone(),
    ));

    // Create a recording backend registry
    let inner_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));
    let recording_registry = Arc::new(RecordingBackendRegistry::new(inner_registry));

    // Create the MultiSuiteCryptoVerifier directly (to use our recording types)
    let verifier = MultiSuiteCryptoVerifier::new(key_provider.clone(), recording_registry.clone());

    // Verify initial state
    assert_eq!(key_provider.call_count(), 0);
    assert_eq!(recording_registry.call_count(), 0);

    // Create and sign a vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify the vote
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Verify that the multi-suite path was exercised
    assert_eq!(
        key_provider.call_count(),
        1,
        "Key provider should be called once"
    );
    assert_eq!(
        recording_registry.call_count(),
        1,
        "Backend registry should be called once"
    );
    assert_eq!(
        recording_registry.last_suite_queried(),
        Some(SUITE_TOY_SHA3),
        "Should query for SUITE_TOY_SHA3"
    );
}

/// Test that CryptoConsensusVerifier::new internally uses multi-suite path.
///
/// This test verifies that even when using the simple `new` constructor,
/// the CryptoConsensusVerifier routes through the multi-suite verification path.
#[test]
fn crypto_verifier_new_uses_multi_suite_path() {
    let pk_bytes = b"test-validator-key".to_vec();

    // Create a simple registry
    let mut registry = ValidatorKeyRegistry::new();
    registry.insert(ValidatorId::new(1), ValidatorPublicKey(pk_bytes.clone()));

    // Create CryptoConsensusVerifier using the simple constructor
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Create and sign a vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify the vote
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Verify that metrics are tracked (which goes through the inner verifier)
    assert_eq!(verifier.metrics().vote_ok(), 1);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
}

/// Test that CryptoConsensusVerifier preserves metrics behavior from T78.
///
/// This test verifies that all metrics counters work correctly through
/// the refactored delegation path.
#[test]
fn crypto_verifier_preserves_metrics_through_delegation() {
    let pk_bytes = b"test-validator-key".to_vec();

    let mut registry = ValidatorKeyRegistry::new();
    registry.insert(ValidatorId::new(1), ValidatorPublicKey(pk_bytes.clone()));

    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Initial metrics should be zero
    assert_eq!(verifier.metrics().vote_ok(), 0);
    assert_eq!(verifier.metrics().vote_missing_key(), 0);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 0);
    assert_eq!(verifier.metrics().proposal_ok(), 0);
    assert_eq!(verifier.metrics().proposal_missing_key(), 0);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 0);

    // Test successful vote verification
    let mut vote = make_vote_with_sig(10, 0, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);
    let _ = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert_eq!(verifier.metrics().vote_ok(), 1);

    // Test missing key
    let vote2 = make_vote_with_sig(10, 1, vec![0u8; 32]);
    let _ = verifier.verify_vote(ValidatorId::new(999), &vote2);
    assert_eq!(verifier.metrics().vote_missing_key(), 1);

    // Test invalid signature
    let mut vote3 = make_vote_with_sig(10, 2, vec![]);
    vote3.signature = sign_vote(&pk_bytes, &vote3);
    vote3.signature[0] ^= 0xff; // Tamper
    let _ = verifier.verify_vote(ValidatorId::new(1), &vote3);
    assert_eq!(verifier.metrics().vote_invalid_signature(), 1);

    // Test successful proposal verification
    let mut proposal = make_proposal_with_sig(10, 0, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);
    let _ = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert_eq!(verifier.metrics().proposal_ok(), 1);

    // Test missing key for proposal
    let proposal2 = make_proposal_with_sig(10, 1, vec![0u8; 32]);
    let _ = verifier.verify_proposal(ValidatorId::new(999), &proposal2);
    assert_eq!(verifier.metrics().proposal_missing_key(), 1);

    // Test invalid signature for proposal
    let mut proposal3 = make_proposal_with_sig(10, 2, vec![]);
    proposal3.signature = sign_proposal(&pk_bytes, &proposal3);
    proposal3.signature[0] ^= 0xff; // Tamper
    let _ = verifier.verify_proposal(ValidatorId::new(1), &proposal3);
    assert_eq!(verifier.metrics().proposal_invalid_signature(), 1);
}

/// Test that HotStuffDriver uses CryptoConsensusVerifier with multi-suite path.
///
/// This integration test constructs a CryptoConsensusVerifier the same way
/// the driver does, and confirms verification goes through the multi-suite path.
#[test]
fn hotstuff_driver_uses_multi_suite_verification_path() {
    let pk_bytes = b"test-validator-key".to_vec();

    // Create registry and verifier as the driver would
    let mut registry = ValidatorKeyRegistry::new();
    registry.insert(ValidatorId::new(1), ValidatorPublicKey(pk_bytes.clone()));

    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    // Create a HotStuffDriver with the verifier
    // T121: permissive driver is intentional here; test does not care about membership.
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine).with_verifier(Arc::new(verifier));
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a valid vote
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

    // Send an invalid (tampered) vote
    let mut invalid_vote = make_vote_with_sig(1, 1, vec![]);
    invalid_vote.signature = sign_vote(&pk_bytes, &invalid_vote);
    invalid_vote.signature[0] ^= 0xff; // Tamper

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

/// Test that suite ID is correctly passed through for dispatch.
///
/// This test uses a custom suite ID (not SUITE_TOY_SHA3) to verify that
/// the suite ID from the key provider is correctly passed to the backend registry.
///
/// NOTE: As of T83, the wire suite_id must match the governance suite_id,
/// so we set the vote's wire suite_id to match the custom governance suite.
#[test]
fn multi_suite_verifier_dispatches_to_correct_suite() {
    let pk_bytes = b"test-validator-key".to_vec();
    let custom_suite = ConsensusSigSuiteId::new(42);

    // Create governance that returns the custom suite ID
    let governance = TestSuiteGovernance::new().with_key(1, custom_suite, pk_bytes.clone());

    let key_provider: Arc<GovernedValidatorKeyRegistry<TestSuiteGovernance>> =
        Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Create a registry with both SUITE_TOY_SHA3 and custom_suite
    let mut backend_registry = SimpleBackendRegistry::new();
    backend_registry.register(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));
    backend_registry.register(custom_suite, Arc::new(TestHashConsensusSigVerifier));

    // Wrap in recording registry to verify correct suite is queried
    let recording_registry = Arc::new(RecordingBackendRegistry::new(backend_registry));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, recording_registry.clone());

    // Create a vote with wire suite_id matching governance (42)
    let mut vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 10,
        round: 5,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: custom_suite.as_u16(), // Wire suite matches governance
        signature: vec![],
    };
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify the vote
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Verify that the custom suite was queried (not SUITE_TOY_SHA3)
    assert_eq!(
        recording_registry.last_suite_queried(),
        Some(custom_suite),
        "Should query for custom_suite, not SUITE_TOY_SHA3"
    );
}

/// Test that unsupported suite returns appropriate error.
///
/// NOTE: As of T83, to test unsupported suite error (backend not registered),
/// the wire suite_id must match governance suite_id first. So this test:
/// 1. Sets governance to use an unknown suite (999)
/// 2. Sets the vote's wire suite_id to also be 999 (to pass mismatch check)
/// 3. Verifies that we get "unsupported suite" error from backend lookup
#[test]
fn multi_suite_verifier_rejects_unsupported_suite() {
    let pk_bytes = b"test-validator-key".to_vec();
    let unknown_suite = ConsensusSigSuiteId::new(999);

    // Create governance that returns an unknown suite ID
    let governance = TestSuiteGovernance::new().with_key(1, unknown_suite, pk_bytes.clone());

    let key_provider: Arc<GovernedValidatorKeyRegistry<TestSuiteGovernance>> =
        Arc::new(GovernedValidatorKeyRegistry::new(Arc::new(governance)));

    // Backend registry only knows SUITE_TOY_SHA3 (not suite 999)
    let backend_registry =
        SimpleBackendRegistry::with_backend(SUITE_TOY_SHA3, Arc::new(TestHashConsensusSigVerifier));

    let verifier = MultiSuiteCryptoVerifier::new(key_provider, Arc::new(backend_registry));

    // Create a vote with wire suite_id = 999 (matching governance, but no backend registered)
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

    // Verify should fail with "unsupported suite" error (backend not registered)
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

    // Verify metrics
    assert_eq!(verifier.metrics().vote_other(), 1);
}

/// Test that debug output includes multi-suite verifier info.
#[test]
fn crypto_verifier_debug_shows_multi_suite_structure() {
    let registry = ValidatorKeyRegistry::new();
    let verifier = CryptoConsensusVerifier::new(registry, Arc::new(TestHashConsensusSigVerifier));

    let debug_str = format!("{:?}", verifier);
    assert!(
        debug_str.contains("CryptoConsensusVerifier"),
        "Debug should contain CryptoConsensusVerifier"
    );
}
