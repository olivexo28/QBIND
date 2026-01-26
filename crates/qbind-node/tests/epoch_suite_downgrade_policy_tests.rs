//! T124: Cross-epoch suite downgrade protection tests.
//!
//! These tests verify that:
//! - Allowed transitions (equal or stronger security) succeed.
//! - Downgrades (weaker security) are rejected with `SuiteDowngradeAcrossEpochs`.
//! - Toy ↔ PQ transitions are handled correctly under dev/prod policies.
//! - Unknown suites are treated as having 0 security bits.
//! - Single epoch or empty sequences succeed trivially.
//! - Metrics are recorded for transitions.
//!
//! # Test Organization
//!
//! - Tests for the `SuitePolicy::check_transition_allowed` method.
//! - Tests for `ConsensusStartupValidator::validate_epoch_sequence`.
//! - Tests for metrics recording (ok/rejected transitions).

use std::collections::HashMap;
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use qbind_consensus::{ConsensusValidatorSet, EpochId, EpochState, ValidatorId, ValidatorSetEntry};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier, SUITE_TOY_SHA3};
use qbind_crypto::suite_catalog::{SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_node::metrics::SuiteTransitionMetrics;
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

/// Helper to create a sequence of epochs with specified suites.
fn make_epoch_sequence(specs: Vec<(u64, u64, ConsensusSigSuiteId)>) -> Vec<EpochState> {
    specs
        .into_iter()
        .map(|(epoch_id, validator_id, suite_id)| {
            make_single_validator_epoch(epoch_id, validator_id, suite_id)
        })
        .collect()
}

// ============================================================================
// SuitePolicy::check_transition_allowed tests
// ============================================================================

/// Test that equal suite transition is allowed.
#[test]
fn suite_policy_equal_suite_allowed() {
    let policy = SuitePolicy::prod_default();

    // Same suite should always be allowed
    let result = policy.check_transition_allowed(SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_1);
    assert!(result.is_ok(), "Equal suite transition should be allowed");
}

/// Test that stronger suite transition is allowed.
#[test]
fn suite_policy_stronger_suite_allowed() {
    let policy = SuitePolicy::prod_default();

    // SUITE_PQ_RESERVED_2 has higher security bits than SUITE_PQ_RESERVED_1
    // (assuming PQ_RESERVED_2 has higher security bits)
    let result = policy.check_transition_allowed(SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2);
    assert!(
        result.is_ok(),
        "Stronger suite transition should be allowed"
    );
}

/// Test that weaker suite transition is rejected under prod policy.
#[test]
fn suite_policy_weaker_suite_rejected_prod() {
    let policy = SuitePolicy::prod_default();

    // SUITE_PQ_RESERVED_1 → SUITE_TOY_SHA3 is a downgrade
    let result = policy.check_transition_allowed(SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3);
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
}

/// Test that toy suite transition is allowed under dev policy.
#[test]
fn suite_policy_toy_suite_allowed_dev() {
    let policy = SuitePolicy::dev_default();

    // Toy suite transitions should be allowed in dev
    let result = policy.check_transition_allowed(SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1);
    assert!(result.is_ok(), "Toy → PQ should be allowed in dev");

    let result = policy.check_transition_allowed(SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3);
    assert!(result.is_ok(), "PQ → Toy should be allowed in dev");
}

/// Test that toy suite transition is rejected under prod policy.
#[test]
fn suite_policy_toy_suite_rejected_prod() {
    let policy = SuitePolicy::prod_default();

    // Toy suite transitions should be rejected in prod
    let result = policy.check_transition_allowed(SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1);
    match result {
        Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
            from_suite,
            to_suite,
            ..
        }) => {
            assert_eq!(from_suite, SUITE_TOY_SHA3);
            assert_eq!(to_suite, SUITE_PQ_RESERVED_1);
        }
        other => panic!("Expected SuiteDowngradeAcrossEpochs, got {:?}", other),
    }

    let result = policy.check_transition_allowed(SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3);
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
}

/// Test that unknown suite (security_bits = None) is treated as 0 bits.
#[test]
fn suite_policy_unknown_suite_treated_as_zero() {
    let policy = SuitePolicy::prod_default();

    // Create an unknown suite ID
    let unknown_suite = ConsensusSigSuiteId::new(9999);

    // Unknown → PQ should be allowed (0 → higher bits)
    let result = policy.check_transition_allowed(unknown_suite, SUITE_PQ_RESERVED_1);
    assert!(
        result.is_ok(),
        "Unknown → PQ should be allowed (0 → higher)"
    );

    // PQ → Unknown should be rejected (higher → 0)
    let result = policy.check_transition_allowed(SUITE_PQ_RESERVED_1, unknown_suite);
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
}

// ============================================================================
// ConsensusStartupValidator::validate_epoch_sequence tests
// ============================================================================

/// Test that single epoch sequence succeeds trivially.
#[test]
fn validate_epoch_sequence_single_epoch() {
    let epochs = make_epoch_sequence(vec![(0, 0, SUITE_PQ_RESERVED_1)]);

    let governance = TestEnumerableGovernance::new().with_validator(0, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(result.is_ok(), "Single epoch should succeed trivially");
}

/// Test that empty epoch sequence succeeds trivially.
#[test]
fn validate_epoch_sequence_empty() {
    let epochs = vec![];

    let governance = TestEnumerableGovernance::new();
    let backend_registry = build_backend_registry(vec![]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(
        result.is_ok(),
        "Empty epoch sequence should succeed trivially"
    );
}

/// Test that allowed transition (equal security) succeeds.
#[test]
fn validate_epoch_sequence_equal_security_allowed() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_1),
        (1, 1, SUITE_PQ_RESERVED_1), // Same suite
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(
        result.is_ok(),
        "Equal security transition should be allowed"
    );
}

/// Test that allowed transition (stronger security) succeeds.
#[test]
fn validate_epoch_sequence_stronger_security_allowed() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_1),
        (1, 1, SUITE_PQ_RESERVED_2), // Stronger suite
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_2);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(
        result.is_ok(),
        "Stronger security transition should be allowed"
    );
}

/// Test that downgrade (weaker security) is rejected.
#[test]
fn validate_epoch_sequence_downgrade_rejected() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_2),
        (1, 1, SUITE_PQ_RESERVED_1), // Weaker suite
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_2)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
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
}

/// Test that toy → PQ transition is allowed under dev policy.
#[test]
fn validate_epoch_sequence_toy_to_pq_allowed_dev() {
    let epochs = make_epoch_sequence(vec![(0, 0, SUITE_TOY_SHA3), (1, 1, SUITE_PQ_RESERVED_1)]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::dev_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(
        result.is_ok(),
        "Toy → PQ should be allowed under dev policy"
    );
}

/// Test that toy → PQ transition is rejected under prod policy.
#[test]
fn validate_epoch_sequence_toy_to_pq_rejected_prod() {
    let epochs = make_epoch_sequence(vec![(0, 0, SUITE_TOY_SHA3), (1, 1, SUITE_PQ_RESERVED_1)]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    match result {
        Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
            from_epoch,
            to_epoch,
            from_suite,
            to_suite,
        }) => {
            assert_eq!(from_epoch.as_u64(), 0);
            assert_eq!(to_epoch.as_u64(), 1);
            assert_eq!(from_suite, SUITE_TOY_SHA3);
            assert_eq!(to_suite, SUITE_PQ_RESERVED_1);
        }
        other => panic!("Expected SuiteDowngradeAcrossEpochs, got {:?}", other),
    }
}

/// Test that PQ → toy transition is rejected under prod policy.
#[test]
fn validate_epoch_sequence_pq_to_toy_rejected_prod() {
    let epochs = make_epoch_sequence(vec![(0, 0, SUITE_PQ_RESERVED_1), (1, 1, SUITE_TOY_SHA3)]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_TOY_SHA3);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    match result {
        Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
            from_epoch,
            to_epoch,
            from_suite,
            to_suite,
        }) => {
            assert_eq!(from_epoch.as_u64(), 0);
            assert_eq!(to_epoch.as_u64(), 1);
            assert_eq!(from_suite, SUITE_PQ_RESERVED_1);
            assert_eq!(to_suite, SUITE_TOY_SHA3);
        }
        other => panic!("Expected SuiteDowngradeAcrossEpochs, got {:?}", other),
    }
}

/// Test that gapped epoch IDs are handled correctly.
#[test]
fn validate_epoch_sequence_gapped_epoch_ids() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_1),
        (2, 1, SUITE_PQ_RESERVED_2), // Epoch 1 is missing
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_2);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(
        result.is_ok(),
        "Gapped epoch IDs should be handled (validates adjacent pairs)"
    );
}

/// Test that epoch with mixed suites is skipped (can't determine suite).
#[test]
fn validate_epoch_sequence_mixed_suite_epoch_skipped() {
    // Create a more complex epoch with mixed suites
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
    // epoch0 will have epoch ID 0 (genesis)

    let epoch1 = make_single_validator_epoch(1, 2, SUITE_PQ_RESERVED_2);

    let epochs = vec![epoch0, epoch1];

    // Governance has mixed suites for epoch 0
    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_TOY_SHA3)
        .with_validator(1, SUITE_PQ_RESERVED_1) // Different suite!
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

    // Should skip epoch 0 (mixed suites) and succeed
    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(result.is_ok(), "Mixed suite epoch should be skipped");
}

/// Test that unknown suite transition is handled correctly.
#[test]
fn validate_epoch_sequence_unknown_suite() {
    let unknown_suite = ConsensusSigSuiteId::new(9999);

    let epochs = make_epoch_sequence(vec![(0, 0, unknown_suite), (1, 1, SUITE_PQ_RESERVED_1)]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, unknown_suite)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    // Only register PQ suite, not the unknown one
    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Unknown → PQ should be allowed (0 → higher bits)
    let result = validator.validate_epoch_sequence(&epochs, None);
    assert!(result.is_ok(), "Unknown → PQ should be allowed");
}

// ============================================================================
// Metrics recording tests
// ============================================================================

/// Test that metrics record ok transitions.
#[test]
fn metrics_record_ok_transitions() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_1),
        (1, 1, SUITE_PQ_RESERVED_2), // Stronger suite
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_2);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let metrics = SuiteTransitionMetrics::new();

    let result = validator.validate_epoch_sequence(&epochs, Some(&metrics));
    assert!(result.is_ok(), "Transition should be allowed");

    assert_eq!(metrics.total_transitions(), 1, "Should record 1 transition");
    assert_eq!(metrics.ok_transitions(), 1, "Should record 1 ok transition");
    assert_eq!(
        metrics.rejected_transitions(),
        0,
        "Should record 0 rejected transitions"
    );
}

/// Test that metrics record rejected transitions.
#[test]
fn metrics_record_rejected_transitions() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_2),
        (1, 1, SUITE_PQ_RESERVED_1), // Weaker suite
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_2)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let metrics = SuiteTransitionMetrics::new();

    let result = validator.validate_epoch_sequence(&epochs, Some(&metrics));
    assert!(result.is_err(), "Transition should be rejected");

    assert_eq!(metrics.total_transitions(), 1, "Should record 1 transition");
    assert_eq!(
        metrics.ok_transitions(),
        0,
        "Should record 0 ok transitions"
    );
    assert_eq!(
        metrics.rejected_transitions(),
        1,
        "Should record 1 rejected transition"
    );
}

/// Test that metrics don't record equal suite transitions.
#[test]
fn metrics_no_record_equal_suite() {
    let epochs = make_epoch_sequence(vec![
        (0, 0, SUITE_PQ_RESERVED_1),
        (1, 1, SUITE_PQ_RESERVED_1), // Same suite
    ]);

    let governance = TestEnumerableGovernance::new()
        .with_validator(0, SUITE_PQ_RESERVED_1)
        .with_validator(1, SUITE_PQ_RESERVED_1);

    let backend_registry = build_backend_registry(vec![SUITE_PQ_RESERVED_1]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    let metrics = SuiteTransitionMetrics::new();

    let result = validator.validate_epoch_sequence(&epochs, Some(&metrics));
    assert!(result.is_ok(), "Equal suite should be allowed");

    assert_eq!(
        metrics.total_transitions(),
        0,
        "Should not record equal suite transition"
    );
    assert_eq!(
        metrics.ok_transitions(),
        0,
        "Should not record ok for equal suite"
    );
    assert_eq!(
        metrics.rejected_transitions(),
        0,
        "Should not record rejected for equal suite"
    );
}

/// Test that metrics format method works.
#[test]
fn metrics_format_method() {
    let metrics = SuiteTransitionMetrics::new();

    // Record some transitions
    metrics.record_ok();
    metrics.record_ok();
    metrics.record_rejected();

    let formatted = metrics.format_metrics();

    assert!(formatted.contains("suite_epoch_transitions_total{result=\"ok\"} 2"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"rejected\"} 1"));
    assert!(formatted.contains("suite_epoch_transitions_total{result=\"total\"} 3"));
}

// ============================================================================
// Integration with NodeMetrics tests
// ============================================================================

/// Test that NodeMetrics includes suite transition metrics.
#[test]
fn node_metrics_includes_suite_transition() {
    use qbind_node::metrics::NodeMetrics;

    let node_metrics = NodeMetrics::new();
    let suite_transition_metrics = node_metrics.suite_transition();

    // Should be accessible and start at zero
    assert_eq!(suite_transition_metrics.total_transitions(), 0);
    assert_eq!(suite_transition_metrics.ok_transitions(), 0);
    assert_eq!(suite_transition_metrics.rejected_transitions(), 0);

    // Should be able to record transitions
    suite_transition_metrics.record_ok();
    assert_eq!(suite_transition_metrics.total_transitions(), 1);
    assert_eq!(suite_transition_metrics.ok_transitions(), 1);
}

/// Test that NodeMetrics format includes suite transition metrics.
#[test]
fn node_metrics_format_includes_suite_transition() {
    use qbind_node::metrics::NodeMetrics;

    let node_metrics = NodeMetrics::new();

    // Record some transitions
    node_metrics.suite_transition().record_ok();
    node_metrics.suite_transition().record_rejected();

    let formatted = node_metrics.format_metrics();

    // Check that suite transition metrics appear in the output
    assert!(formatted.contains("suite_epoch_transitions_total"));
}
// Check that suite transition metrics appear in the output
