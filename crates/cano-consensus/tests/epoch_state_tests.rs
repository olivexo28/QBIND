//! Tests for epoch state types and validation (T100).
//!
//! These tests verify:
//! - EpochId basic operations
//! - EpochState creation and accessors
//! - Epoch + governance cross-check validation
//!   - Complete keys for a validator set → validation passes
//!   - Missing key for one validator → validation fails with MissingKey
//!   - Unknown suite id → validation fails with UnknownSuite
//!   - Stray key (governance key for non-epoch validator) → validation fails

use std::collections::HashMap;

use cano_consensus::governed_key_registry::ConsensusKeyGovernance;
use cano_consensus::{
    ConsensusValidatorSet, EpochId, EpochState, EpochValidationError, ValidatorId,
    ValidatorSetEntry,
};
use cano_crypto::ConsensusSigSuiteId;

// ============================================================================
// Test Governance Implementation
// ============================================================================

/// A test governance implementation that returns configurable keys for validators.
#[derive(Debug, Default)]
struct TestGovernance {
    /// Map from validator ID to (suite_id, pk_bytes).
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl TestGovernance {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a validator with a given suite ID.
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

    /// Get all validator IDs known to this governance.
    fn validator_ids(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }
}

impl ConsensusKeyGovernance for TestGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
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

/// Helper: a suite checker that accepts suite IDs 0 and 1.
fn accept_suites_0_and_1(suite_id: ConsensusSigSuiteId) -> bool {
    suite_id.as_u16() == 0 || suite_id.as_u16() == 1
}

/// Helper: a suite checker that accepts only suite ID 0.
fn accept_only_suite_0(suite_id: ConsensusSigSuiteId) -> bool {
    suite_id.as_u16() == 0
}

// ============================================================================
// EpochId Tests
// ============================================================================

#[test]
fn epoch_id_basic() {
    let epoch = EpochId::new(42);
    assert_eq!(epoch.as_u64(), 42);

    // Genesis
    assert_eq!(EpochId::GENESIS.as_u64(), 0);

    // From/Into
    let epoch2: EpochId = 100.into();
    assert_eq!(epoch2.as_u64(), 100);
    let raw: u64 = epoch2.into();
    assert_eq!(raw, 100);

    // Ordering
    assert!(EpochId::new(1) < EpochId::new(2));
    assert_eq!(EpochId::new(5), EpochId::new(5));
}

#[test]
fn epoch_id_display() {
    let epoch = EpochId::new(7);
    assert_eq!(format!("{}", epoch), "EpochId(7)");
}

// ============================================================================
// EpochState Tests
// ============================================================================

#[test]
fn epoch_state_creation() {
    let epoch_state = make_three_validator_epoch();

    assert_eq!(epoch_state.epoch_id(), EpochId::GENESIS);
    assert_eq!(epoch_state.len(), 3);
    assert_eq!(epoch_state.total_voting_power(), 3);
    assert!(!epoch_state.is_empty());
}

#[test]
fn epoch_state_get_and_contains() {
    let epoch_state = make_three_validator_epoch();

    // Contains
    assert!(epoch_state.contains(ValidatorId::new(0)));
    assert!(epoch_state.contains(ValidatorId::new(1)));
    assert!(epoch_state.contains(ValidatorId::new(2)));
    assert!(!epoch_state.contains(ValidatorId::new(99)));

    // Get
    let v0 = epoch_state
        .get(ValidatorId::new(0))
        .expect("should find validator 0");
    assert_eq!(v0.voting_power, 1);

    assert!(epoch_state.get(ValidatorId::new(99)).is_none());
}

#[test]
fn epoch_state_iter_and_validator_ids() {
    let epoch_state = make_three_validator_epoch();

    // Iter
    let entries: Vec<_> = epoch_state.iter().collect();
    assert_eq!(entries.len(), 3);

    // Validator IDs
    let ids = epoch_state.validator_ids();
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&ValidatorId::new(0)));
    assert!(ids.contains(&ValidatorId::new(1)));
    assert!(ids.contains(&ValidatorId::new(2)));
}

// ============================================================================
// Epoch + Governance Validation Tests
// ============================================================================

/// Test that validation passes when all validators have keys with known suites.
#[test]
fn epoch_validation_passes_with_complete_keys() {
    let epoch_state = make_three_validator_epoch();

    // Governance with keys for all 3 validators, all using suite 0
    let governance = TestGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0);

    let result = epoch_state.validate_with_governance(&governance, accept_suites_0_and_1);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that validation passes with different suites for different validators.
#[test]
fn epoch_validation_passes_with_multiple_suites() {
    let epoch_state = make_three_validator_epoch();

    // Governance with different suites
    let governance = TestGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 1)
        .with_validator(2, 0);

    let result = epoch_state.validate_with_governance(&governance, accept_suites_0_and_1);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that validation fails with MissingKey when a validator has no key.
#[test]
fn epoch_validation_fails_with_missing_key() {
    let epoch_state = make_three_validator_epoch();

    // Governance missing validator 1
    let governance = TestGovernance::new()
        .with_validator(0, 0)
        // Missing validator 1
        .with_validator(2, 0);

    let result = epoch_state.validate_with_governance(&governance, accept_suites_0_and_1);

    match result {
        Err(EpochValidationError::MissingKey(id)) => {
            assert_eq!(id, ValidatorId::new(1));
        }
        other => panic!("Expected MissingKey(1), got {:?}", other),
    }
}

/// Test that validation fails with UnknownSuite when a validator uses an unknown suite.
#[test]
fn epoch_validation_fails_with_unknown_suite() {
    let epoch_state = make_three_validator_epoch();

    // Governance with validator 1 using suite 99 (unknown)
    let governance = TestGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 99) // Unknown suite
        .with_validator(2, 0);

    let result = epoch_state.validate_with_governance(&governance, accept_only_suite_0);

    match result {
        Err(EpochValidationError::UnknownSuite {
            validator_id,
            suite_id,
        }) => {
            assert_eq!(validator_id, ValidatorId::new(1));
            assert_eq!(suite_id, 99);
        }
        other => panic!(
            "Expected UnknownSuite for validator 1 with suite 99, got {:?}",
            other
        ),
    }
}

/// Test that strict validation fails when governance has stray keys.
#[test]
fn epoch_validation_fails_with_stray_key() {
    let epoch_state = make_three_validator_epoch();

    // Governance has keys for validators 0, 1, 2, and also 99 (not in epoch)
    let governance = TestGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0)
        .with_validator(99, 0); // Stray key

    let gov_ids = governance.validator_ids();

    let result =
        epoch_state.validate_with_governance_strict(&governance, &gov_ids, accept_suites_0_and_1);

    match result {
        Err(EpochValidationError::StrayKey(id)) => {
            assert_eq!(id, ValidatorId::new(99));
        }
        other => panic!("Expected StrayKey(99), got {:?}", other),
    }
}

/// Test that strict validation passes when all keys match exactly.
#[test]
fn epoch_validation_strict_passes_with_exact_match() {
    let epoch_state = make_three_validator_epoch();

    // Governance with exactly the epoch validators
    let governance = TestGovernance::new()
        .with_validator(0, 0)
        .with_validator(1, 0)
        .with_validator(2, 0);

    let gov_ids = governance.validator_ids();

    let result =
        epoch_state.validate_with_governance_strict(&governance, &gov_ids, accept_suites_0_and_1);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that missing key is detected before stray key in strict validation.
#[test]
fn epoch_validation_strict_missing_key_before_stray() {
    let epoch_state = make_three_validator_epoch();

    // Governance missing validator 0 but has stray validator 99
    let governance = TestGovernance::new()
        // Missing validator 0
        .with_validator(1, 0)
        .with_validator(2, 0)
        .with_validator(99, 0); // Stray key

    let gov_ids = governance.validator_ids();

    let result =
        epoch_state.validate_with_governance_strict(&governance, &gov_ids, accept_suites_0_and_1);

    // Missing key should be detected first (before stray key check)
    assert!(
        matches!(result, Err(EpochValidationError::MissingKey(id)) if id == ValidatorId::new(0)),
        "Expected MissingKey(0), got {:?}",
        result
    );
}

// ============================================================================
// EpochValidationError Display Tests
// ============================================================================

#[test]
fn epoch_validation_error_display() {
    let err_missing = EpochValidationError::MissingKey(ValidatorId::new(42));
    assert!(err_missing.to_string().contains("42"));
    assert!(err_missing.to_string().contains("no consensus key"));

    let err_unknown = EpochValidationError::UnknownSuite {
        validator_id: ValidatorId::new(5),
        suite_id: 99,
    };
    assert!(err_unknown.to_string().contains("5"));
    assert!(err_unknown.to_string().contains("99"));

    let err_stray = EpochValidationError::StrayKey(ValidatorId::new(100));
    assert!(err_stray.to_string().contains("100"));
    assert!(err_stray.to_string().contains("not in the epoch set"));

    let err_other = EpochValidationError::Other("test error".to_string());
    assert!(err_other.to_string().contains("test error"));
}
