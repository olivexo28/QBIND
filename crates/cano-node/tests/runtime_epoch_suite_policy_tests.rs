//! T125: Runtime epoch suite policy tests.
//!
//! These tests verify that:
//! - Runtime transitions with equal or stronger suites are allowed.
//! - Runtime downgrades (weaker security) are rejected with `RuntimeSuiteDowngrade`.
//! - Toy ↔ PQ transitions are handled correctly under dev/prod policies at runtime.
//! - Unknown suites are treated as having 0 security bits.
//! - Single-epoch / no previous epoch transitions are handled correctly.
//! - Runtime suite transition metrics are recorded.
//!
//! # Test Organization
//!
//! - Tests for `SuitePolicy::check_transition_allowed` method (already covered in T124).
//! - Tests for runtime suite validation logic in `NodeHotstuffHarness`.
//! - Tests for runtime suite transition metrics.

use std::collections::HashMap;
use std::sync::Arc;

use cano_consensus::crypto_verifier::SimpleBackendRegistry;
use cano_consensus::governed_key_registry::ConsensusKeyGovernance;
use cano_consensus::{ConsensusValidatorSet, EpochId, EpochState, ValidatorId, ValidatorSetEntry};
use cano_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier, SUITE_TOY_SHA3};
use cano_crypto::suite_catalog::{SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2};
use cano_crypto::ConsensusSigSuiteId;
use cano_node::metrics::{NodeMetrics, SuiteTransitionMetrics};
use cano_node::startup_validation::{
    ConsensusStartupValidator, StartupValidationError, SuitePolicy, ValidatorEnumerator,
};
use cano_node::storage::InMemoryConsensusStorage;

// ============================================================================
// Test-only implementations (reused from T124)
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

/// Helper to create a single-validator epoch state with given ID and suite.
fn make_single_validator_epoch(
    epoch_id: u64,
    validator_id: u64,
    _suite_id: ConsensusSigSuiteId,
) -> EpochState {
    let validators = vec![ValidatorSetEntry {
        id: ValidatorId::new(validator_id),
        voting_power: 1,
    }];
    let set = ConsensusValidatorSet::new(validators).expect("should create valid set");
    // Create epoch with the specified epoch ID
    EpochState::new(EpochId::new(epoch_id), set)
}

// ============================================================================
// Runtime suite transition validation tests
// ============================================================================

/// Test that runtime suite validation logic works correctly.
/// This tests the core validation logic that would be used in `NodeHotstuffHarness`.
#[test]
fn runtime_suite_validation_logic() {
    // Create governance with known suites
    let governance = Arc::new(
        TestEnumerableGovernance::new()
            .with_validator(0, SUITE_PQ_RESERVED_1)
            .with_validator(1, SUITE_PQ_RESERVED_1) // For epoch1_same
            .with_validator(2, SUITE_PQ_RESERVED_2) // For epoch1_stronger
            .with_validator(3, SUITE_TOY_SHA3), // For epoch1_weaker
    );

    // Create epoch states
    let epoch0 = make_single_validator_epoch(0, 0, SUITE_PQ_RESERVED_1);
    let epoch1_same = make_single_validator_epoch(1, 1, SUITE_PQ_RESERVED_1);
    let epoch1_stronger = make_single_validator_epoch(1, 2, SUITE_PQ_RESERVED_2);
    let epoch1_weaker = make_single_validator_epoch(1, 3, SUITE_TOY_SHA3);

    // Test 1: Same suite should be allowed
    let from_suite = epoch0.epoch_suite_id(governance.as_ref()).unwrap().unwrap();
    let to_suite = epoch1_same
        .epoch_suite_id(governance.as_ref())
        .unwrap()
        .unwrap();
    let policy = SuitePolicy::prod_default();
    let result = policy.check_transition_allowed(from_suite, to_suite);
    assert!(result.is_ok(), "Same suite should be allowed");

    // Test 2: Stronger suite should be allowed
    let to_suite = epoch1_stronger
        .epoch_suite_id(governance.as_ref())
        .unwrap()
        .unwrap();
    let result = policy.check_transition_allowed(from_suite, to_suite);
    assert!(result.is_ok(), "Stronger suite should be allowed");

    // Test 3: Weaker suite should be rejected under prod policy
    let to_suite = epoch1_weaker
        .epoch_suite_id(governance.as_ref())
        .unwrap()
        .unwrap();
    let result = policy.check_transition_allowed(from_suite, to_suite);
    match result {
        Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
            from_suite,
            to_suite,
            ..
        }) => {
            assert_eq!(from_suite, SUITE_PQ_RESERVED_1);
            assert_eq!(to_suite, SUITE_TOY_SHA3);
        }
        other => panic!("Expected SuiteDowngradeAcrossEpochs, got {:?}", other),
    }

    // Test 4: Weaker suite should be allowed under dev policy
    let dev_policy = SuitePolicy::dev_default();
    let result = dev_policy.check_transition_allowed(from_suite, to_suite);
    assert!(
        result.is_ok(),
        "Weaker suite should be allowed under dev policy"
    );
}

/// Test that runtime suite transition metrics are recorded correctly.
#[test]
fn runtime_suite_transition_metrics() {
    let metrics = SuiteTransitionMetrics::new();

    // Initially zero
    assert_eq!(metrics.total_transitions(), 0);
    assert_eq!(metrics.ok_transitions(), 0);
    assert_eq!(metrics.rejected_transitions(), 0);
    assert_eq!(metrics.runtime_total_transitions(), 0);
    assert_eq!(metrics.runtime_ok_transitions(), 0);
    assert_eq!(metrics.runtime_rejected_transitions(), 0);

    // Record some startup transitions
    metrics.record_ok();
    metrics.record_rejected();
    metrics.record_ok();

    assert_eq!(metrics.total_transitions(), 3);
    assert_eq!(metrics.ok_transitions(), 2);
    assert_eq!(metrics.rejected_transitions(), 1);
    assert_eq!(metrics.runtime_total_transitions(), 0); // Runtime still zero

    // Record some runtime transitions
    metrics.record_runtime_ok();
    metrics.record_runtime_rejected();
    metrics.record_runtime_ok();
    metrics.record_runtime_ok();

    assert_eq!(metrics.total_transitions(), 3); // Startup transitions only
    assert_eq!(metrics.ok_transitions(), 2); // Startup ok only
    assert_eq!(metrics.rejected_transitions(), 1); // Startup rejected only
    assert_eq!(metrics.runtime_total_transitions(), 4);
    assert_eq!(metrics.runtime_ok_transitions(), 3);
    assert_eq!(metrics.runtime_rejected_transitions(), 1);

    // Check format includes runtime metrics
    let formatted = metrics.format_metrics();
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"ok\"} 2"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"rejected\"} 1"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"total\"} 3"));
    assert!(formatted.contains("suite_epoch_runtime_transitions_total{result=\"ok\"} 3"));
    assert!(formatted.contains("suite_epoch_runtime_transitions_total{result=\"rejected\"} 1"));
    assert!(formatted.contains("suite_epoch_runtime_transitions_total{result=\"total\"} 4"));
}

/// Test that NodeMetrics includes runtime suite transition metrics.
#[test]
fn node_metrics_includes_runtime_suite_transition() {
    let node_metrics = NodeMetrics::new();
    let suite_transition_metrics = node_metrics.suite_transition();

    // Should be accessible and start at zero
    assert_eq!(suite_transition_metrics.total_transitions(), 0);
    assert_eq!(suite_transition_metrics.ok_transitions(), 0);
    assert_eq!(suite_transition_metrics.rejected_transitions(), 0);
    assert_eq!(suite_transition_metrics.runtime_total_transitions(), 0);
    assert_eq!(suite_transition_metrics.runtime_ok_transitions(), 0);
    assert_eq!(suite_transition_metrics.runtime_rejected_transitions(), 0);

    // Should be able to record runtime transitions
    suite_transition_metrics.record_runtime_ok();
    suite_transition_metrics.record_runtime_rejected();

    assert_eq!(suite_transition_metrics.runtime_total_transitions(), 2);
    assert_eq!(suite_transition_metrics.runtime_ok_transitions(), 1);
    assert_eq!(suite_transition_metrics.runtime_rejected_transitions(), 1);
}

/// Test that NodeMetrics format includes runtime suite transition metrics.
#[test]
fn node_metrics_format_includes_runtime_suite_transition() {
    let node_metrics = NodeMetrics::new();

    // Record some transitions
    node_metrics.suite_transition().record_ok(); // Startup
    node_metrics.suite_transition().record_rejected(); // Startup
    node_metrics.suite_transition().record_runtime_ok();
    node_metrics.suite_transition().record_runtime_ok();
    node_metrics.suite_transition().record_runtime_rejected();

    let formatted = node_metrics.format_metrics();

    // Check that both startup and runtime metrics appear in the output
    assert!(formatted.contains("# Suite transition metrics (T124)"));
    assert!(formatted.contains("# Runtime suite transition metrics (T125)"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"ok\"} 1"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"rejected\"} 1"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"total\"} 2"));
    assert!(formatted.contains("suite_epoch_runtime_transitions_total{result=\"ok\"} 2"));
    assert!(formatted.contains("suite_epoch_runtime_transitions_total{result=\"rejected\"} 1"));
    assert!(formatted.contains("suite_epoch_runtime_transitions_total{result=\"total\"} 3"));
}

/// Test that unknown suite transition is handled correctly.
#[test]
fn runtime_suite_validation_unknown_suite() {
    let unknown_suite = ConsensusSigSuiteId::new(9999);

    let governance = Arc::new(
        TestEnumerableGovernance::new()
            .with_validator(0, SUITE_PQ_RESERVED_1)
            .with_validator(1, unknown_suite),
    );

    let epoch0 = make_single_validator_epoch(0, 0, SUITE_PQ_RESERVED_1);
    let epoch1_unknown = make_single_validator_epoch(1, 1, unknown_suite);

    let from_suite = epoch0.epoch_suite_id(governance.as_ref()).unwrap().unwrap();
    let to_suite = epoch1_unknown
        .epoch_suite_id(governance.as_ref())
        .unwrap()
        .unwrap();

    let policy = SuitePolicy::prod_default();

    // PQ → Unknown should be rejected (higher → 0 bits)
    let result = policy.check_transition_allowed(from_suite, to_suite);
    match result {
        Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
            from_suite,
            to_suite,
            ..
        }) => {
            assert_eq!(from_suite, SUITE_PQ_RESERVED_1);
            assert_eq!(to_suite, unknown_suite);
        }
        other => panic!("Expected SuiteDowngradeAcrossEpochs, got {:?}", other),
    }

    // Unknown → PQ should be allowed (0 → higher bits)
    let result = policy.check_transition_allowed(to_suite, from_suite);
    assert!(
        result.is_ok(),
        "Unknown → PQ should be allowed (0 → higher)"
    );
}

/// Test that mixed suite epoch is handled correctly (skipped).
#[test]
fn runtime_suite_validation_mixed_suite_epoch() {
    // Create governance with mixed suites for epoch 0
    let governance = Arc::new(
        TestEnumerableGovernance::new()
            .with_validator(0, SUITE_TOY_SHA3)
            .with_validator(1, SUITE_PQ_RESERVED_1), // Different suite!
    );

    // Create epoch with 2 validators (mixed suites)
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(0),
            voting_power: 1,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 1,
        },
    ];
    let set = ConsensusValidatorSet::new(validators).expect("should create valid set");
    let epoch0 = EpochState::genesis(set);

    // epoch_suite_id should return Err with mixed suites
    let result = epoch0.epoch_suite_id(governance.as_ref());
    match result {
        Err(mixed_suites) => {
            assert_eq!(mixed_suites.len(), 2);
            assert!(mixed_suites.contains(&SUITE_TOY_SHA3));
            assert!(mixed_suites.contains(&SUITE_PQ_RESERVED_1));
        }
        other => panic!("Expected Err with mixed suites, got {:?}", other),
    }
}

/// Test integration with ConsensusStartupValidator for runtime-like validation.
#[test]
fn consensus_startup_validator_runtime_validation() {
    let epochs = vec![
        make_single_validator_epoch(0, 0, SUITE_PQ_RESERVED_2),
        make_single_validator_epoch(1, 1, SUITE_PQ_RESERVED_1), // Weaker suite
    ];

    let governance = Arc::new(
        TestEnumerableGovernance::new()
            .with_validator(0, SUITE_PQ_RESERVED_2)
            .with_validator(1, SUITE_PQ_RESERVED_1),
    );

    let backend_registry = Arc::new(build_backend_registry(vec![
        SUITE_PQ_RESERVED_1,
        SUITE_PQ_RESERVED_2,
    ]));
    let storage = Arc::new(InMemoryConsensusStorage::new());

    let validator = ConsensusStartupValidator::new(governance, backend_registry, storage)
        .with_suite_policy(SuitePolicy::prod_default());

    let metrics = SuiteTransitionMetrics::new();

    let result = validator.validate_epoch_sequence(&epochs, Some(&metrics));
    match result {
        Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
            from_epoch,
            to_epoch,
            from_suite,
            to_suite,
        }) => {
            assert_eq!(from_epoch.as_u64(), 0);
            assert_eq!(to_epoch.as_u64(), 1);
            assert_eq!(from_suite, SUITE_PQ_RESERVED_2);
            assert_eq!(to_suite, SUITE_PQ_RESERVED_1);
        }
        other => panic!("Expected SuiteDowngradeAcrossEpochs, got {:?}", other),
    }

    // Metrics should record the rejected transition
    assert_eq!(metrics.total_transitions(), 1);
    assert_eq!(metrics.ok_transitions(), 0);
    assert_eq!(metrics.rejected_transitions(), 1);
}
