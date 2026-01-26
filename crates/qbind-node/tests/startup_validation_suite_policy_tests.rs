//! Tests for T111 Suite Policy & Startup Enforcement.
//!
//! These tests verify that `SuitePolicy` and `ConsensusStartupValidator` correctly:
//! - Allow toy suites under `dev_default()` policy.
//! - Reject toy suites under `prod_default()` policy.
//! - Enforce minimum security bits under `prod_default()` policy.
//! - Reject unknown suites regardless of policy.
//!
//! # Test Organization
//!
//! - `SuitePolicy` unit tests (basic API behavior).
//! - Integration tests for `ConsensusStartupValidator` with `SuitePolicy`.

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
// SuitePolicy Unit Tests
// ============================================================================

/// Test that SuitePolicy::dev_default() has expected values.
#[test]
fn suite_policy_dev_default_values() {
    let policy = SuitePolicy::dev_default();
    assert!(policy.allow_toy, "dev_default should allow toy suites");
    assert_eq!(
        policy.min_security_bits, None,
        "dev_default should have no min security bits"
    );
}

/// Test that SuitePolicy::prod_default() has expected values.
#[test]
fn suite_policy_prod_default_values() {
    let policy = SuitePolicy::prod_default();
    assert!(
        !policy.allow_toy,
        "prod_default should not allow toy suites"
    );
    assert_eq!(
        policy.min_security_bits,
        Some(128),
        "prod_default should require 128-bit security"
    );
}

/// Test SuitePolicy::new() custom policy.
#[test]
fn suite_policy_custom_values() {
    let policy = SuitePolicy::new(true, Some(256));
    assert!(policy.allow_toy);
    assert_eq!(policy.min_security_bits, Some(256));

    let policy2 = SuitePolicy::new(false, None);
    assert!(!policy2.allow_toy);
    assert_eq!(policy2.min_security_bits, None);
}

/// Test SuitePolicy::with_min_security_bits() builder method.
#[test]
fn suite_policy_with_min_security_bits() {
    let policy = SuitePolicy::dev_default().with_min_security_bits(192);
    assert!(policy.allow_toy);
    assert_eq!(policy.min_security_bits, Some(192));
}

/// Test that Default for SuitePolicy is dev_default.
#[test]
fn suite_policy_default_is_dev() {
    let policy: SuitePolicy = Default::default();
    assert_eq!(policy, SuitePolicy::dev_default());
}

/// Test that SuitePolicy implements Clone and PartialEq.
#[test]
fn suite_policy_clone_and_eq() {
    let policy1 = SuitePolicy::prod_default();
    let policy2 = policy1.clone();
    assert_eq!(policy1, policy2);

    let policy3 = SuitePolicy::dev_default();
    assert_ne!(policy1, policy3);
}

/// Test that SuitePolicy implements Debug.
#[test]
fn suite_policy_debug() {
    let policy = SuitePolicy::prod_default();
    let debug_str = format!("{:?}", policy);
    assert!(debug_str.contains("allow_toy"));
    assert!(debug_str.contains("min_security_bits"));
}

// ============================================================================
// Integration Tests: dev_default allows toy suite
// ============================================================================

/// Test that dev_default allows toy suite (SUITE_TOY_SHA3).
#[test]
fn dev_default_allows_toy_suite() {
    let epoch_state = make_three_validator_epoch();

    // Governance with all validators using SUITE_TOY_SHA3
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_TOY_SHA3)
        .with_validator(2, SUITE_TOY_SHA3);

    // Backend registry has SUITE_TOY_SHA3
    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    // Verify policy is dev_default
    assert!(validator.suite_policy().allow_toy);
    assert_eq!(validator.suite_policy().min_security_bits, None);

    // Epoch validation should succeed
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        result.is_ok(),
        "dev_default should allow toy suite, got {:?}",
        result
    );
}

/// Test that dev_default also works with validate_with_epoch.
#[test]
fn dev_default_allows_toy_suite_full_validation() {
    let epoch_state = make_three_validator_epoch();

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

    // Full validation should succeed
    let result = validator.validate_with_epoch(&epoch_state);
    assert!(
        result.is_ok(),
        "dev_default should allow toy suite in full validation, got {:?}",
        result
    );
}

// ============================================================================
// Integration Tests: prod_default rejects toy suite
// ============================================================================

/// Test that prod_default rejects toy suite (SUITE_TOY_SHA3).
#[test]
fn prod_default_rejects_toy_suite() {
    let epoch_state = make_three_validator_epoch();

    // Governance with all validators using SUITE_TOY_SHA3
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_TOY_SHA3)
        .with_validator(2, SUITE_TOY_SHA3);

    // Backend registry has SUITE_TOY_SHA3
    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Verify policy is prod_default
    assert!(!validator.suite_policy().allow_toy);
    assert_eq!(validator.suite_policy().min_security_bits, Some(128));

    // Epoch validation should fail with ToySuiteNotAllowed
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::ToySuiteNotAllowed {
            validator_id,
            suite_id,
            suite_name,
        }) => {
            // One of the validators should trigger the error
            assert!(
                validator_id == ValidatorId::new(0)
                    || validator_id == ValidatorId::new(1)
                    || validator_id == ValidatorId::new(2)
            );
            assert_eq!(suite_id, 0); // SUITE_TOY_SHA3 has id 0
            assert_eq!(suite_name, "toy-sha3");
        }
        other => panic!("Expected ToySuiteNotAllowed, got {:?}", other),
    }
}

/// Test that the error message for ToySuiteNotAllowed is descriptive.
#[test]
fn prod_default_toy_suite_error_message() {
    let epoch_state = make_three_validator_epoch();

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
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch(&epoch_state, true);
    let err = result.expect_err("should fail");
    let msg = err.to_string();

    assert!(
        msg.contains("toy suite"),
        "Error should mention 'toy suite': {}",
        msg
    );
    assert!(
        msg.contains("toy-sha3"),
        "Error should mention suite name: {}",
        msg
    );
    assert!(
        msg.contains("production policy"),
        "Error should mention production policy: {}",
        msg
    );
}

// ============================================================================
// Integration Tests: prod_default requires min security bits
// ============================================================================

/// Test that prod_default accepts a PQ suite with >= 128 bits security.
#[test]
fn prod_default_accepts_pq_suite_with_sufficient_security() {
    let epoch_state = make_three_validator_epoch();

    // Use SUITE_PQ_RESERVED_1 which has 128-bit security
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_PQ_RESERVED_1);

    // Backend registry has the PQ suite
    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Epoch validation should succeed
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        result.is_ok(),
        "prod_default should accept PQ suite with 128-bit security, got {:?}",
        result
    );
}

/// Test that prod_default accepts a PQ suite with > 128 bits security (256 bits).
#[test]
fn prod_default_accepts_pq_suite_with_extra_security() {
    let epoch_state = make_three_validator_epoch();

    // Use SUITE_PQ_RESERVED_2 which has 256-bit security
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_2)
        .with_validator(1, SUITE_PQ_RESERVED_2)
        .with_validator(2, SUITE_PQ_RESERVED_2);

    // Backend registry has the PQ suite
    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Epoch validation should succeed
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        result.is_ok(),
        "prod_default should accept PQ suite with 256-bit security, got {:?}",
        result
    );
}

/// Test that a policy requiring > 128 bits would reject 128-bit suite.
#[test]
fn custom_policy_rejects_insufficient_security_bits() {
    let epoch_state = make_three_validator_epoch();

    // Use SUITE_PQ_RESERVED_1 which has 128-bit security
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_1)
        .with_validator(2, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    // Custom policy requiring 192 bits
    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::new(false, Some(192)));

    // Epoch validation should fail with InsufficientSecurityBits
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::InsufficientSecurityBits {
            validator_id: _,
            suite_id,
            suite_name,
            actual_bits,
            required_bits,
        }) => {
            assert_eq!(suite_id, 100); // SUITE_PQ_RESERVED_1 has id 100
            assert_eq!(suite_name, "ml-dsa-44");
            assert_eq!(actual_bits, Some(128));
            assert_eq!(required_bits, 192);
        }
        other => panic!("Expected InsufficientSecurityBits, got {:?}", other),
    }
}

/// Test the error message for InsufficientSecurityBits.
#[test]
fn insufficient_security_bits_error_message() {
    let epoch_state = make_three_validator_epoch();

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
    .with_suite_policy(SuitePolicy::new(false, Some(256)));

    let result = validator.validate_epoch(&epoch_state, true);
    let err = result.expect_err("should fail");
    let msg = err.to_string();

    assert!(
        msg.contains("128"),
        "Error should mention actual bits: {}",
        msg
    );
    assert!(
        msg.contains("256"),
        "Error should mention required bits: {}",
        msg
    );
    assert!(
        msg.contains("ml-dsa-44"),
        "Error should mention suite name: {}",
        msg
    );
}

// ============================================================================
// Integration Tests: unknown suite triggers UnknownSuiteForValidator
// ============================================================================

/// Test that an unknown suite triggers UnknownSuiteForValidator under dev_default.
#[test]
fn unknown_suite_triggers_error_under_dev_policy() {
    let epoch_state = make_three_validator_epoch();

    // Use an unknown suite ID (65535 is not in KNOWN_CONSENSUS_SIG_SUITES)
    let unknown_suite = ConsensusSigSuiteId::new(65535);
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, unknown_suite)
        .with_validator(1, unknown_suite)
        .with_validator(2, unknown_suite);

    // Backend registry has the unknown suite (pretend it's registered)
    let backend_registry = build_backend_registry(vec![unknown_suite]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    // Epoch validation should fail with UnknownSuiteForValidator
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::UnknownSuiteForValidator {
            validator_id: _,
            suite_id,
        }) => {
            assert_eq!(suite_id, 65535);
        }
        other => panic!("Expected UnknownSuiteForValidator, got {:?}", other),
    }
}

/// Test that an unknown suite triggers UnknownSuiteForValidator under prod_default.
#[test]
fn unknown_suite_triggers_error_under_prod_policy() {
    let epoch_state = make_three_validator_epoch();

    // Use an unknown suite ID
    let unknown_suite = ConsensusSigSuiteId::new(999);
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, unknown_suite)
        .with_validator(1, unknown_suite)
        .with_validator(2, unknown_suite);

    let backend_registry = build_backend_registry(vec![unknown_suite]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Epoch validation should fail with UnknownSuiteForValidator
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::UnknownSuiteForValidator {
            validator_id: _,
            suite_id,
        }) => {
            assert_eq!(suite_id, 999);
        }
        other => panic!("Expected UnknownSuiteForValidator, got {:?}", other),
    }
}

/// Test the error message for UnknownSuiteForValidator.
#[test]
fn unknown_suite_error_message() {
    let epoch_state = make_three_validator_epoch();

    let unknown_suite = ConsensusSigSuiteId::new(12345);
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, unknown_suite)
        .with_validator(1, unknown_suite)
        .with_validator(2, unknown_suite);

    let backend_registry = build_backend_registry(vec![unknown_suite]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    let result = validator.validate_epoch(&epoch_state, true);
    let err = result.expect_err("should fail");
    let msg = err.to_string();

    assert!(
        msg.contains("12345"),
        "Error should mention suite ID: {}",
        msg
    );
    assert!(
        msg.contains("unknown"),
        "Error should mention 'unknown': {}",
        msg
    );
}

// ============================================================================
// Mixed Suite Tests (Updated for T115: Single-Suite-Per-Epoch Policy)
// ============================================================================

/// Test mixed suites: some validators use PQ, others use toy.
/// Under T115 single-suite-per-epoch policy, mixed suites are rejected.
/// This test was updated from pre-T115 behavior where dev_default allowed mixed suites.
#[test]
fn dev_default_rejects_mixed_suites_t115() {
    let epoch_state = make_three_validator_epoch();

    // Mixed suites: toy + PQ (this now fails under T115 policy)
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

    // T115: Mixed suites are now rejected even under dev_default
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::MixedSuitesInEpoch { epoch_id, suites }) => {
            assert_eq!(epoch_id.as_u64(), 0);
            assert_eq!(suites.len(), 3, "Should detect all 3 different suites");
        }
        other => panic!("Expected MixedSuitesInEpoch, got {:?}", other),
    }
}

/// Test mixed suites under prod_default: now fails with MixedSuitesInEpoch (T115).
/// Prior to T115, this would fail with ToySuiteNotAllowed. Now the single-suite-per-epoch
/// check happens first, so mixed suites are rejected before individual suite policy checks.
#[test]
fn prod_default_rejects_mixed_suites_t115() {
    let epoch_state = make_three_validator_epoch();

    // Mixed suites: toy + PQ
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
    .with_suite_policy(SuitePolicy::prod_default());

    // T115: Mixed suites are now rejected before individual suite checks
    let result = validator.validate_epoch(&epoch_state, true);
    match result {
        Err(StartupValidationError::MixedSuitesInEpoch { epoch_id, suites }) => {
            assert_eq!(epoch_id.as_u64(), 0);
            assert_eq!(suites.len(), 3, "Should detect all 3 different suites");
        }
        other => panic!("Expected MixedSuitesInEpoch (T115), got {:?}", other),
    }
}

// ============================================================================
// Default Policy Tests
// ============================================================================

/// Test that the default constructor uses dev_default policy.
#[test]
fn default_constructor_uses_dev_policy() {
    let governance = TestEnumerableGovernance::new().with_validator(0, SUITE_TOY_SHA3);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );
    // Note: NOT calling .with_suite_policy()

    // Default policy should be dev_default
    assert!(validator.suite_policy().allow_toy);
    assert_eq!(validator.suite_policy().min_security_bits, None);
}

/// Test that existing tests (without explicit policy) continue to work.
/// This ensures backward compatibility.
#[test]
fn backward_compatibility_with_existing_tests() {
    let epoch_state = make_three_validator_epoch();

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_TOY_SHA3)
        .with_validator(2, SUITE_TOY_SHA3);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3]);
    let storage = InMemoryConsensusStorage::new();

    // Create validator without explicit policy (should use dev_default)
    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    // Validation should succeed (backward compatible with existing tests)
    let result = validator.validate_with_epoch(&epoch_state);
    assert!(
        result.is_ok(),
        "Default policy should allow toy suites for backward compatibility, got {:?}",
        result
    );
}
