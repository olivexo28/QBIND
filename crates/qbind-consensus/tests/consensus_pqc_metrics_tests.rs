//! Tests for per-suite PQC operation metrics (T120).
//!
//! These tests verify that the per-suite metrics counters are correctly
//! incremented for different signature suites during vote/proposal verification.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-consensus --test consensus_pqc_metrics_tests -- --test-threads=1
//! ```
//!
//! Note: `--test-threads=1` is recommended to avoid test interference when
//! multiple tests are modifying global test state, though these tests use
//! isolated verifier instances and should be thread-safe.

use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use qbind_consensus::verify::{ConsensusVerifier, VerificationError};
use qbind_consensus::{
    ConsensusSigBackendRegistry, MultiSuiteCryptoVerifier, SuiteAwareValidatorKeyProvider,
    ValidatorId, MAX_PER_SUITE_SLOTS,
};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigSuiteId, ConsensusSigVerifier};
use qbind_crypto::{suite_name, SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3};
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
// Test key provider and backend registry
// ============================================================================

/// A test key provider that maps validators to (suite_id, pk_bytes).
struct TestSuiteKeyProvider {
    entries: std::collections::HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl TestSuiteKeyProvider {
    fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    fn add_validator(&mut self, id: ValidatorId, suite_id: ConsensusSigSuiteId, pk: Vec<u8>) {
        self.entries.insert(id, (suite_id, pk));
    }
}

impl SuiteAwareValidatorKeyProvider for TestSuiteKeyProvider {
    fn get_suite_and_key(&self, validator: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.entries.get(&validator).cloned()
    }
}

impl std::fmt::Debug for TestSuiteKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestSuiteKeyProvider")
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// A test backend registry that returns the same verifier for any suite.
struct TestBackendRegistry {
    verifier: Arc<dyn ConsensusSigVerifier>,
}

impl TestBackendRegistry {
    fn new() -> Self {
        Self {
            verifier: Arc::new(TestHashConsensusSigVerifier),
        }
    }
}

impl ConsensusSigBackendRegistry for TestBackendRegistry {
    fn get_backend(&self, _suite_id: ConsensusSigSuiteId) -> Option<Arc<dyn ConsensusSigVerifier>> {
        Some(self.verifier.clone())
    }
}

impl std::fmt::Debug for TestBackendRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestBackendRegistry").finish()
    }
}

// ============================================================================
// Test helpers
// ============================================================================

/// Helper to create a Vote with a given signature and suite_id.
fn make_vote_with_sig_and_suite(
    height: u64,
    round: u64,
    signature: Vec<u8>,
    suite_id: u16,
) -> Vote {
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
        signature,
    }
}

/// Helper to create a BlockProposal with a given signature and suite_id.
fn make_proposal_with_sig_and_suite(
    height: u64,
    round: u64,
    signature: Vec<u8>,
    suite_id: u16,
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
            suite_id,
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
// Per-suite metrics tests
// ============================================================================

/// Test that per-suite vote metrics are correctly recorded for SUITE_TOY_SHA3.
#[test]
fn per_suite_vote_metrics_recorded_for_toy_suite() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let validator_id = ValidatorId::new(1);
    let suite_id = SUITE_TOY_SHA3;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_id, suite_id, pk_bytes.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Initial per-suite metrics should be empty
    assert!(verifier.metrics().per_suite_metrics(suite_id).is_none());

    // Create and sign a valid vote
    let mut vote = make_vote_with_sig_and_suite(10, 5, vec![], suite_id.as_u16());
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify - this should record per-suite metrics
    let result = verifier.verify_vote(validator_id, &vote);
    assert!(result.is_ok(), "vote verification should succeed");

    // Check per-suite metrics
    let (vote_count, proposal_count, _latency) = verifier
        .metrics()
        .per_suite_metrics(suite_id)
        .expect("per-suite metrics should exist for toy_sha3");
    assert_eq!(vote_count, 1, "vote count should be 1 for toy_sha3");
    assert_eq!(proposal_count, 0, "proposal count should be 0 for toy_sha3");
}

/// Test that per-suite proposal metrics are correctly recorded for SUITE_TOY_SHA3.
#[test]
fn per_suite_proposal_metrics_recorded_for_toy_suite() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let validator_id = ValidatorId::new(1);
    let suite_id = SUITE_TOY_SHA3;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_id, suite_id, pk_bytes.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Create and sign a valid proposal
    let mut proposal = make_proposal_with_sig_and_suite(10, 5, vec![], suite_id.as_u16());
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify - this should record per-suite metrics
    let result = verifier.verify_proposal(validator_id, &proposal);
    assert!(result.is_ok(), "proposal verification should succeed");

    // Check per-suite metrics
    let (vote_count, proposal_count, _latency) = verifier
        .metrics()
        .per_suite_metrics(suite_id)
        .expect("per-suite metrics should exist for toy_sha3");
    assert_eq!(vote_count, 0, "vote count should be 0 for toy_sha3");
    assert_eq!(proposal_count, 1, "proposal count should be 1 for toy_sha3");
}

/// Test that per-suite metrics work with multiple suites.
#[test]
fn per_suite_metrics_work_with_multiple_suites() {
    let pk_v1 = b"validator-1-pk".to_vec();
    let pk_v2 = b"validator-2-pk".to_vec();
    let validator_1 = ValidatorId::new(1);
    let validator_2 = ValidatorId::new(2);
    let suite_1 = SUITE_TOY_SHA3;
    let suite_2 = SUITE_PQ_RESERVED_1;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_1, suite_1, pk_v1.clone());
    key_provider.add_validator(validator_2, suite_2, pk_v2.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Send 3 votes for suite_1, 2 votes for suite_2
    for i in 0..3 {
        let mut vote = make_vote_with_sig_and_suite(10, i, vec![], suite_1.as_u16());
        vote.signature = sign_vote(&pk_v1, &vote);
        let _ = verifier.verify_vote(validator_1, &vote);
    }

    for i in 0..2 {
        let mut vote = make_vote_with_sig_and_suite(10, i, vec![], suite_2.as_u16());
        vote.signature = sign_vote(&pk_v2, &vote);
        let _ = verifier.verify_vote(validator_2, &vote);
    }

    // Check per-suite metrics for suite_1
    let (vote_count_1, proposal_count_1, _) = verifier
        .metrics()
        .per_suite_metrics(suite_1)
        .expect("per-suite metrics should exist for suite_1");
    assert_eq!(vote_count_1, 3, "vote count should be 3 for suite_1");
    assert_eq!(
        proposal_count_1, 0,
        "proposal count should be 0 for suite_1"
    );

    // Check per-suite metrics for suite_2
    let (vote_count_2, proposal_count_2, _) = verifier
        .metrics()
        .per_suite_metrics(suite_2)
        .expect("per-suite metrics should exist for suite_2");
    assert_eq!(vote_count_2, 2, "vote count should be 2 for suite_2");
    assert_eq!(
        proposal_count_2, 0,
        "proposal count should be 0 for suite_2"
    );
}

/// Test that per-suite latency buckets are recorded.
#[test]
fn per_suite_latency_buckets_recorded() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let validator_id = ValidatorId::new(1);
    let suite_id = SUITE_TOY_SHA3;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_id, suite_id, pk_bytes.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Verify multiple votes to populate latency buckets
    for i in 0..5 {
        let mut vote = make_vote_with_sig_and_suite(10, i, vec![], suite_id.as_u16());
        vote.signature = sign_vote(&pk_bytes, &vote);
        let _ = verifier.verify_vote(validator_id, &vote);
    }

    // Check latency buckets - should have at least some counts
    let (_, _, (under_1ms, to_10ms, to_100ms, over_100ms)) = verifier
        .metrics()
        .per_suite_metrics(suite_id)
        .expect("per-suite metrics should exist");

    let total_latency_count = under_1ms + to_10ms + to_100ms + over_100ms;
    assert_eq!(
        total_latency_count, 5,
        "total latency count should equal vote count"
    );
}

/// Test that all_per_suite_metrics returns all tracked suites.
#[test]
fn all_per_suite_metrics_returns_all_tracked() {
    let pk_v1 = b"validator-1-pk".to_vec();
    let pk_v2 = b"validator-2-pk".to_vec();
    let validator_1 = ValidatorId::new(1);
    let validator_2 = ValidatorId::new(2);
    let suite_1 = SUITE_TOY_SHA3;
    let suite_2 = SUITE_PQ_RESERVED_1;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_1, suite_1, pk_v1.clone());
    key_provider.add_validator(validator_2, suite_2, pk_v2.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Verify one vote for each suite
    let mut vote_1 = make_vote_with_sig_and_suite(10, 0, vec![], suite_1.as_u16());
    vote_1.signature = sign_vote(&pk_v1, &vote_1);
    let _ = verifier.verify_vote(validator_1, &vote_1);

    let mut vote_2 = make_vote_with_sig_and_suite(10, 1, vec![], suite_2.as_u16());
    vote_2.signature = sign_vote(&pk_v2, &vote_2);
    let _ = verifier.verify_vote(validator_2, &vote_2);

    // Get all per-suite metrics
    let all_metrics = verifier.metrics().all_per_suite_metrics();
    assert_eq!(all_metrics.len(), 2, "should have metrics for 2 suites");

    // Check that both suites are present
    let suite_ids: Vec<_> = all_metrics.iter().map(|(id, _, _, _)| *id).collect();
    assert!(suite_ids.contains(&suite_1), "suite_1 should be tracked");
    assert!(suite_ids.contains(&suite_2), "suite_2 should be tracked");
}

/// Test that format_per_suite_metrics produces Prometheus-style output.
#[test]
fn format_per_suite_metrics_produces_valid_output() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let validator_id = ValidatorId::new(1);
    let suite_id = SUITE_TOY_SHA3;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_id, suite_id, pk_bytes.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Verify some votes and proposals
    let mut vote = make_vote_with_sig_and_suite(10, 0, vec![], suite_id.as_u16());
    vote.signature = sign_vote(&pk_bytes, &vote);
    let _ = verifier.verify_vote(validator_id, &vote);

    let mut proposal = make_proposal_with_sig_and_suite(10, 0, vec![], suite_id.as_u16());
    proposal.signature = sign_proposal(&pk_bytes, &proposal);
    let _ = verifier.verify_proposal(validator_id, &proposal);

    // Format metrics
    let output = verifier.metrics().format_per_suite_metrics();

    // Check for expected labels
    let suite_name_str = suite_name(suite_id);
    assert!(
        output.contains(&format!("kind=\"vote\",suite=\"{}\"", suite_name_str)),
        "output should contain vote metrics for {}: {}",
        suite_name_str,
        output
    );
    assert!(
        output.contains(&format!("kind=\"proposal\",suite=\"{}\"", suite_name_str)),
        "output should contain proposal metrics for {}: {}",
        suite_name_str,
        output
    );
}

/// Test that per-suite metrics don't increment for failed verifications.
#[test]
fn per_suite_metrics_not_incremented_on_failure() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let validator_id = ValidatorId::new(1);
    let suite_id = SUITE_TOY_SHA3;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_id, suite_id, pk_bytes.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // First, verify a valid vote to create the metrics slot
    let mut valid_vote = make_vote_with_sig_and_suite(10, 0, vec![], suite_id.as_u16());
    valid_vote.signature = sign_vote(&pk_bytes, &valid_vote);
    let _ = verifier.verify_vote(validator_id, &valid_vote);

    // Get initial count
    let (initial_vote_count, _, _) = verifier
        .metrics()
        .per_suite_metrics(suite_id)
        .expect("metrics should exist");
    assert_eq!(initial_vote_count, 1);

    // Now try to verify with invalid signature (tampered)
    let mut invalid_vote = make_vote_with_sig_and_suite(10, 1, vec![], suite_id.as_u16());
    invalid_vote.signature = sign_vote(&pk_bytes, &invalid_vote);
    invalid_vote.signature[0] ^= 0xff; // Tamper

    let result = verifier.verify_vote(validator_id, &invalid_vote);
    assert!(matches!(result, Err(VerificationError::InvalidSignature)));

    // Per-suite metrics should NOT have incremented (only incremented on success)
    let (final_vote_count, _, _) = verifier
        .metrics()
        .per_suite_metrics(suite_id)
        .expect("metrics should exist");
    assert_eq!(
        final_vote_count, 1,
        "vote count should not increase on failure"
    );
}

/// Test that MAX_PER_SUITE_SLOTS bounds the number of tracked suites.
#[test]
fn max_per_suite_slots_bounds_tracking() {
    // This test creates more validators with distinct suites than MAX_PER_SUITE_SLOTS
    // to verify that the metrics don't panic and behave gracefully.

    let mut key_provider = TestSuiteKeyProvider::new();

    // Create MAX_PER_SUITE_SLOTS + 2 validators with distinct suite IDs
    for i in 0..(MAX_PER_SUITE_SLOTS + 2) {
        let validator_id = ValidatorId::new(i as u64);
        let suite_id = ConsensusSigSuiteId::new(i as u16);
        let pk = format!("validator-{}-pk", i).into_bytes();
        key_provider.add_validator(validator_id, suite_id, pk);
    }

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Verify one vote for each validator
    for i in 0..(MAX_PER_SUITE_SLOTS + 2) {
        let validator_id = ValidatorId::new(i as u64);
        let suite_id = ConsensusSigSuiteId::new(i as u16);
        let pk = format!("validator-{}-pk", i).into_bytes();

        let mut vote = make_vote_with_sig_and_suite(10, i as u64, vec![], suite_id.as_u16());
        vote.signature = sign_vote(&pk, &vote);

        // This should not panic even if we exceed MAX_PER_SUITE_SLOTS
        let _ = verifier.verify_vote(validator_id, &vote);
    }

    // Check that at most MAX_PER_SUITE_SLOTS suites are tracked
    let all_metrics = verifier.metrics().all_per_suite_metrics();
    assert!(
        all_metrics.len() <= MAX_PER_SUITE_SLOTS,
        "should track at most {} suites, got {}",
        MAX_PER_SUITE_SLOTS,
        all_metrics.len()
    );
}

/// Test that per-suite metrics increment correctly across multiple verifications.
#[test]
fn per_suite_metrics_accumulate_correctly() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let validator_id = ValidatorId::new(1);
    let suite_id = SUITE_TOY_SHA3;

    let mut key_provider = TestSuiteKeyProvider::new();
    key_provider.add_validator(validator_id, suite_id, pk_bytes.clone());

    let backend_registry = Arc::new(TestBackendRegistry::new());
    let verifier = MultiSuiteCryptoVerifier::new(Arc::new(key_provider), backend_registry);

    // Verify 10 votes and 5 proposals
    for i in 0..10 {
        let mut vote = make_vote_with_sig_and_suite(10, i, vec![], suite_id.as_u16());
        vote.signature = sign_vote(&pk_bytes, &vote);
        let _ = verifier.verify_vote(validator_id, &vote);
    }

    for i in 0..5 {
        let mut proposal = make_proposal_with_sig_and_suite(10, i, vec![], suite_id.as_u16());
        proposal.signature = sign_proposal(&pk_bytes, &proposal);
        let _ = verifier.verify_proposal(validator_id, &proposal);
    }

    // Check final counts
    let (vote_count, proposal_count, _) = verifier
        .metrics()
        .per_suite_metrics(suite_id)
        .expect("per-suite metrics should exist");
    assert_eq!(vote_count, 10, "vote count should be 10");
    assert_eq!(proposal_count, 5, "proposal count should be 5");
}
