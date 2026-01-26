//! Tests for epoch state integration with startup validation (T100).
//!
//! These tests verify that the startup validator correctly validates
//! epoch state against governance and backend registry.

use std::collections::HashMap;
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use qbind_consensus::{ConsensusValidatorSet, EpochId, EpochState, ValidatorId, ValidatorSetEntry};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier, SUITE_TOY_SHA3};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_node::startup_validation::{
    ConsensusStartupValidator, StartupValidationError, ValidatorEnumerator,
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

    fn with_validator(mut self, validator_id: u64, suite_id: u16) -> Self {
        self.keys.insert(
            validator_id,
            (
                ConsensusSigSuiteId::new(suite_id),
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
fn build_backend_registry(suite_ids: Vec<u16>) -> SimpleBackendRegistry {
    let mut registry = SimpleBackendRegistry::new();
    for suite_id in suite_ids {
        registry.register(
            ConsensusSigSuiteId::new(suite_id),
            Arc::new(NoopConsensusSigVerifier),
        );
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
// Epoch Validation Tests
// ============================================================================

/// Test that epoch validation passes when all validators have keys with known suites.
#[test]
fn epoch_validation_passes_with_complete_keys() {
    let epoch_state = make_three_validator_epoch();

    // Governance with keys for all 3 validators
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0);

    // Backend registry has suite 0
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_epoch(&epoch_state, false);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that epoch validation fails when a validator has no key.
#[test]
fn epoch_validation_fails_with_missing_key() {
    let epoch_state = make_three_validator_epoch();

    // Governance missing validator 1
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        // Missing validator 1
        .with_validator(2, 0);

    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_epoch(&epoch_state, false);

    match result {
        Err(StartupValidationError::MissingKeyForValidator(id)) => {
            assert_eq!(id, ValidatorId::new(1));
        }
        other => panic!("Expected MissingKeyForValidator(1), got {:?}", other),
    }
}

/// Test that epoch validation fails when a validator uses an unknown suite.
#[test]
fn epoch_validation_fails_with_unknown_suite() {
    let epoch_state = make_three_validator_epoch();

    // Governance with validator 1 using suite 99 (unknown)
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 99) // Unknown suite
        .with_validator(2, 0);

    // Backend registry only has suite 0
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_epoch(&epoch_state, false);

    match result {
        Err(StartupValidationError::UnknownSuiteForValidator {
            validator_id,
            suite_id,
        }) => {
            assert_eq!(validator_id, ValidatorId::new(1));
            assert_eq!(suite_id, 99);
        }
        other => panic!(
            "Expected UnknownSuiteForValidator for validator 1 with suite 99, got {:?}",
            other
        ),
    }
}

/// Test that strict epoch validation fails when governance has stray keys.
#[test]
fn epoch_validation_fails_with_stray_key() {
    let epoch_state = make_three_validator_epoch();

    // Governance has keys for validators 0, 1, 2, and also 99 (not in epoch)
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0)
        .with_validator(99, 0); // Stray key

    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    // With check_stray_keys = true
    let result = validator.validate_epoch(&epoch_state, true);

    match result {
        Err(StartupValidationError::StrayGovernanceKey(id)) => {
            assert_eq!(id, ValidatorId::new(99));
        }
        other => panic!("Expected StrayGovernanceKey(99), got {:?}", other),
    }
}

/// Test that strict epoch validation passes with exact match.
#[test]
fn epoch_validation_strict_passes_with_exact_match() {
    let epoch_state = make_three_validator_epoch();

    // Governance with exactly the epoch validators
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0);

    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    // With check_stray_keys = true
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test validate_with_epoch combines all validation.
#[test]
fn validate_with_epoch_passes_for_consistent_config() {
    let epoch_state = make_three_validator_epoch();

    // Governance with exactly the epoch validators
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0);

    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_with_epoch(&epoch_state);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test validate_with_epoch fails when epoch validation fails.
#[test]
fn validate_with_epoch_fails_when_epoch_has_missing_key() {
    let epoch_state = make_three_validator_epoch();

    // Governance missing validator 2
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0);
    // Missing validator 2

    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_with_epoch(&epoch_state);

    assert!(
        matches!(result, Err(StartupValidationError::MissingKeyForValidator(id)) if id == ValidatorId::new(2)),
        "Expected MissingKeyForValidator(2), got {:?}",
        result
    );
}

/// Test that epoch with different voting powers validates correctly.
#[test]
fn epoch_validation_with_weighted_validators() {
    // Create an epoch with weighted validators
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(10),
            voting_power: 100,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(20),
            voting_power: 200,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(30),
            voting_power: 300,
        },
    ];
    let set = ConsensusValidatorSet::new(validators).expect("should create valid set");
    let epoch_state = EpochState::new(EpochId::new(5), set);

    // Governance with keys for all validators using the same suite
    // Note: T115 requires single-suite-per-epoch, so all validators must use the same suite
    let governance = TestEnumerableGovernance::new()
        .with_validator(10, SUITE_TOY_SHA3.as_u16())
        .with_validator(20, SUITE_TOY_SHA3.as_u16())
        .with_validator(30, SUITE_TOY_SHA3.as_u16());

    // Backend registry has the single suite
    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3.as_u16()]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_epoch(&epoch_state, true);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);

    // Verify epoch properties
    assert_eq!(epoch_state.epoch_id(), EpochId::new(5));
    assert_eq!(epoch_state.total_voting_power(), 600);
}
