//! T115: Epoch-level single-suite invariant tests.
//!
//! These tests verify that:
//! - Single-suite epochs are accepted.
//! - Mixed-suite epochs are rejected with `MixedSuitesInEpoch` error.
//! - The `epoch_suite_id()` helper correctly extracts the single suite ID.
//!
//! # Test Organization
//!
//! - Tests for the single-suite-per-epoch invariant enforcement.
//! - Tests for the `epoch_suite_id()` helper method.

use std::collections::HashMap;
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use qbind_consensus::{ConsensusValidatorSet, EpochState, ValidatorId, ValidatorSetEntry};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier, SUITE_TOY_SHA3};
use qbind_crypto::suite_catalog::{SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_node::startup_validation::{
    ConsensusStartupValidator, StartupValidationError, SuitePolicy, ValidatorEnumerator,
};
use qbind_node::storage::InMemoryConsensusStorage;

// ============================================================================
// Test-only implementations
// ============================================================================

/// A test governance implementation that supports enumeration.
#[derive(Debug, Default)]
struct TestEnumerableGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl TestEnumerableGovernance {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn with_validator(mut self, validator_id: u64, suite_id: ConsensusSigSuiteId) -> Self {
        self.keys.insert(
            validator_id,
            (
                suite_id,
                format!("pk-for-validator-{}", validator_id).into_bytes(),
            ),
        );
        self
    }
}

impl ConsensusKeyGovernance for TestEnumerableGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
}

impl ValidatorEnumerator for TestEnumerableGovernance {
    fn list_validators(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }
}

/// A test-only verifier that always succeeds.
struct NoopConsensusSigVerifier;

impl ConsensusSigVerifier for NoopConsensusSigVerifier {
    fn verify_vote(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Ok(())
    }

    fn verify_proposal(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Ok(())
    }
}

/// Helper to build a backend registry with specified suites.
fn build_backend_registry(suite_ids: Vec<ConsensusSigSuiteId>) -> SimpleBackendRegistry {
    let mut registry = SimpleBackendRegistry::new();
    for suite_id in suite_ids {
        registry.register(suite_id, Arc::new(NoopConsensusSigVerifier));
    }
    registry
}

/// Helper to create a 3-validator epoch state.
fn make_three_validator_epoch() -> EpochState {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(0),
            voting_power: 1,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 1,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 1,
        },
    ];
    let set = ConsensusValidatorSet::new(validators).expect("should create valid set");
    EpochState::genesis(set)
}

// ============================================================================
// T115: Single-Suite Epoch Accepted Tests
// ============================================================================

/// Test that a single-suite epoch is accepted (all validators use SUITE_TOY_SHA3).
#[test]
fn single_suite_epoch_accepted_toy_sha3() {
    let epoch_state = make_three_validator_epoch();

    // All validators use SUITE_TOY_SHA3
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_TOY_SHA3)
        .with_validator(2, SUITE_TOY_SHA3);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    // Epoch validation should succeed - single suite is valid
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        result.is_ok(),
        "Single-suite epoch should be accepted, got {:?}",
        result
    );
}

/// Test that a single-suite epoch is accepted (all validators use SUITE_PQ_RESERVED_1).
#[test]
fn single_suite_epoch_accepted_pq_suite() {
    let epoch_state = make_three_validator_epoch();

    // All validators use SUITE_PQ_RESERVED_1
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default()); // Prod policy accepts PQ suite

    // Epoch validation should succeed - single suite is valid
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        result.is_ok(),
        "Single-suite PQ epoch should be accepted, got {:?}",
        result
    );
}

// ============================================================================
// T115: Mixed-Suite Epoch Rejected Tests
// ============================================================================

/// Test that a mixed-suite epoch is rejected (validator 0 uses suite A, validator 1 uses suite B).
#[test]
fn mixed_suite_epoch_rejected() {
    let epoch_state = make_three_validator_epoch();

    // Mixed suites: validator 0 uses TOY_SHA3, others use PQ_RESERVED_1
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    // Epoch validation should fail with MixedSuitesInEpoch
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::MixedSuitesInEpoch { epoch_id, suites }) => {
            // Epoch ID should be genesis (0)
            assert_eq!(epoch_id.as_u64(), 0);
            // Should have 2 different suites
            assert_eq!(suites.len(), 2, "Expected 2 suites, got {:?}", suites);
            // The suites should contain both TOY_SHA3 and PQ_RESERVED_1
            assert!(
                suites.contains(&SUITE_TOY_SHA3) && suites.contains(&SUITE_PQ_RESERVED_1),
                "Expected SUITE_TOY_SHA3 and SUITE_PQ_RESERVED_1, got {:?}",
                suites
            );
        }
        other => panic!("Expected MixedSuitesInEpoch, got {:?}", other),
    }
}

/// Test that a mixed-suite epoch with three different suites is rejected.
#[test]
fn mixed_suite_epoch_three_suites_rejected() {
    let epoch_state = make_three_validator_epoch();

    // Each validator uses a different suite
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_PQ_RESERVED_2);

    let backend_registry = build_backend_registry(vec![
        SUITE_TOY_SHA3,
        SUITE_PQ_RESERVED_1,
        SUITE_PQ_RESERVED_2,
    ]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    // Epoch validation should fail with MixedSuitesInEpoch
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::MixedSuitesInEpoch { epoch_id, suites }) => {
            assert_eq!(epoch_id.as_u64(), 0);
            // Should have 3 different suites
            assert_eq!(suites.len(), 3, "Expected 3 suites, got {:?}", suites);
        }
        other => panic!("Expected MixedSuitesInEpoch, got {:?}", other),
    }
}

/// Test that mixed-suite epoch error message is descriptive.
#[test]
fn mixed_suite_epoch_error_message() {
    let epoch_state = make_three_validator_epoch();

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_TOY_SHA3);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    let result = validator.validate_epoch(&epoch_state, true);
    let err = result.expect_err("should fail with mixed suites");
    let msg = err.to_string();

    assert!(
        msg.contains("multiple signature suites"),
        "Error should mention multiple suites: {}",
        msg
    );
    assert!(
        msg.contains("single consensus signature suite"),
        "Error should mention single suite requirement: {}",
        msg
    );
}

/// Test that the mixed-suite check is done before individual validator policy checks.
/// This ensures that even if all suites are valid under policy, mixed suites are rejected.
#[test]
fn mixed_suite_rejected_even_with_valid_policy() {
    let epoch_state = make_three_validator_epoch();

    // Use two PQ suites that would both pass prod policy individually
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_2)
        .with_validator(2, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Should fail with MixedSuitesInEpoch, not pass because individual suites are valid
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::MixedSuitesInEpoch { .. }) => {
            // Expected - mixed suites rejected
        }
        other => panic!("Expected MixedSuitesInEpoch, got {:?}", other),
    }
}

// ============================================================================
// T115: epoch_suite_id() Helper Tests
// ============================================================================

/// Test that epoch_suite_id returns the single suite when all validators use the same suite.
#[test]
fn epoch_suite_id_single_suite() {
    let epoch_state = make_three_validator_epoch();

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_TOY_SHA3)
        .with_validator(2, SUITE_TOY_SHA3);

    let result = epoch_state.epoch_suite_id(&governance);
    assert!(result.is_ok(), "Should return Ok for single-suite epoch");
    assert_eq!(result.unwrap(), Some(SUITE_TOY_SHA3));
}

/// Test that epoch_suite_id returns error with mixed suites.
#[test]
fn epoch_suite_id_mixed_suites() {
    let epoch_state = make_three_validator_epoch();

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_TOY_SHA3);

    let result = epoch_state.epoch_suite_id(&governance);
    assert!(result.is_err(), "Should return Err for mixed-suite epoch");
    let suites = result.unwrap_err();
    assert_eq!(suites.len(), 2, "Should have 2 different suites");
}

/// Test that epoch_suite_id returns None when no validators have keys.
#[test]
fn epoch_suite_id_no_keys() {
    let epoch_state = make_three_validator_epoch();

    // Empty governance - no keys for any validator
    let governance = TestEnumerableGovernance::new();

    let result = epoch_state.epoch_suite_id(&governance);
    assert!(result.is_ok(), "Should return Ok when no keys");
    assert_eq!(result.unwrap(), None, "Should return None when no keys");
}

// ============================================================================
// No Panic Tests
// ============================================================================

/// Test that mixed-suite validation does not panic.
#[test]
fn mixed_suite_does_not_panic() {
    let epoch_state = make_three_validator_epoch();

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, ConsensusSigSuiteId::new(100))
        .with_validator(1, ConsensusSigSuiteId::new(200))
        .with_validator(2, ConsensusSigSuiteId::new(300));

    let backend_registry = build_backend_registry(vec![
        ConsensusSigSuiteId::new(100),
        ConsensusSigSuiteId::new(200),
        ConsensusSigSuiteId::new(300),
    ]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    // Should return an error, not panic
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(result.is_err(), "Should fail, not panic");
}
