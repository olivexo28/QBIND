//! Tests for startup validation of consensus suites, backends, and storage.
//!
//! These tests verify that `ConsensusStartupValidator` correctly:
//! - Succeeds when all governance suites have registered backends.
//! - Fails with `MissingBackendForSuite` when some suites have no backend.
//! - Succeeds for fresh nodes with no persisted state.
//! - Fails when persisted storage uses unknown suite IDs.
//! - Succeeds when persisted storage uses known suite IDs.
//!
//! # Test Organization
//!
//! - Unit-style tests for validator logic (governance ↔ backends).
//! - Storage-related validation tests (persisted state ↔ backends).

use std::collections::HashMap;
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_node::startup_validation::{
    ConsensusStartupValidator, StartupValidationError, ValidatorEnumerator,
};
use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};

// ============================================================================
// Test-only implementations
// ============================================================================

/// A test governance implementation that supports enumeration.
///
/// Stores a mapping from validator IDs to (suite_id, pk_bytes).
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

/// A test-only verifier that always succeeds (used only for registry setup).
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

/// Helper to create a test block proposal with a given suite_id.
fn make_test_proposal(height: u64, suite_id: u16) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: height,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![1, 2, 3, 4],
    }
}

/// Helper to create a test QC with a given suite_id.
fn make_test_qc(height: u64, suite_id: u16) -> QuorumCertificate {
    QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id: [42u8; 32],
        suite_id,
        signer_bitmap: vec![0b00000111],
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
    }
}

/// Helper to build a simple backend registry with specified suites.
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

// ============================================================================
// Part B Tests: Governance suites ↔ backends validation
// ============================================================================

/// Test that validate() succeeds when all governance suites have backends.
#[test]
fn validate_succeeds_when_all_suites_have_backends() {
    // Governance with 3 validators, all using suite 0
    let governance = TestEnumerableGovernance::new()
        .with_validator(1, 0)
        .with_validator(2, 0)
        .with_validator(3, 0);

    // Backend registry has suite 0
    let backend_registry = build_backend_registry(vec![0]);

    // Storage is empty (fresh node)
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that validate() succeeds with multiple different suites.
#[test]
fn validate_succeeds_with_multiple_suites() {
    // Governance with validators using different suites
    let governance = TestEnumerableGovernance::new()
        .with_validator(1, 0)
        .with_validator(2, 1)
        .with_validator(3, 2);

    // Backend registry has all three suites
    let backend_registry = build_backend_registry(vec![0, 1, 2]);

    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that validate() fails with MissingBackendForSuite when a suite has no backend.
#[test]
fn validate_fails_when_single_suite_has_no_backend() {
    // Governance with validator using suite 42
    let governance = TestEnumerableGovernance::new().with_validator(1, 42);

    // Backend registry is empty
    let backend_registry = SimpleBackendRegistry::new();

    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        matches!(
            result,
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
            if suite_id == ConsensusSigSuiteId::new(42)
        ),
        "Expected MissingBackendForSuite(42), got {:?}",
        result
    );
}

/// Test that validate() fails with MissingBackendsForSuites when multiple suites have no backend.
#[test]
fn validate_fails_when_multiple_suites_have_no_backend() {
    // Governance with validators using suites 10 and 20
    let governance = TestEnumerableGovernance::new()
        .with_validator(1, 10)
        .with_validator(2, 20);

    // Backend registry has suite 0 only
    let backend_registry = build_backend_registry(vec![0]);

    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    match result {
        Err(StartupValidationError::MissingBackendsForSuites(suites)) => {
            assert_eq!(suites.len(), 2);
            let suite_values: Vec<u16> = suites.iter().map(|s| s.as_u16()).collect();
            assert!(suite_values.contains(&10), "Should contain suite 10");
            assert!(suite_values.contains(&20), "Should contain suite 20");
        }
        other => panic!("Expected MissingBackendsForSuites, got {:?}", other),
    }
}

/// Test that validate() fails correctly when some suites have backends and some don't.
#[test]
fn validate_fails_for_partial_backend_coverage() {
    // Governance with validators using suites 0, 1, and 2
    let governance = TestEnumerableGovernance::new()
        .with_validator(1, 0)
        .with_validator(2, 1)
        .with_validator(3, 2);

    // Backend registry only has suites 0 and 1
    let backend_registry = build_backend_registry(vec![0, 1]);

    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        matches!(
            result,
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
            if suite_id == ConsensusSigSuiteId::new(2)
        ),
        "Expected MissingBackendForSuite(2), got {:?}",
        result
    );
}

/// Test that validate() succeeds when governance has no validators.
#[test]
fn validate_succeeds_with_empty_governance() {
    // Empty governance
    let governance = TestEnumerableGovernance::new();

    // Backend registry with some suites (doesn't matter)
    let backend_registry = build_backend_registry(vec![0, 1, 2]);

    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        result.is_ok(),
        "Expected Ok with empty governance, got {:?}",
        result
    );
}

// ============================================================================
// Part C Tests: Storage-related validation
// ============================================================================

/// Test that validate() succeeds for fresh node with no persisted state.
#[test]
fn validate_succeeds_for_fresh_node() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(result.is_ok(), "Fresh node should validate successfully");
}

/// Test that validate() succeeds when persisted block uses a registered suite.
#[test]
fn validate_succeeds_when_persisted_block_uses_registered_suite() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    // Persist a block with suite_id = 0
    let block_id = [1u8; 32];
    let block = make_test_proposal(10, 0);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that validate() fails when persisted block uses an unregistered suite.
#[test]
fn validate_fails_when_persisted_block_uses_unregistered_suite() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    // Persist a block with suite_id = 99 (not registered)
    let block_id = [2u8; 32];
    let block = make_test_proposal(10, 99);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        matches!(
            result,
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
            if suite_id == ConsensusSigSuiteId::new(99)
        ),
        "Expected MissingBackendForSuite(99), got {:?}",
        result
    );
}

/// Test that validate() succeeds when both block and QC use registered suites.
#[test]
fn validate_succeeds_when_block_and_qc_use_registered_suites() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0, 1]);
    let storage = InMemoryConsensusStorage::new();

    // Persist a block with suite_id = 0 and QC with suite_id = 1
    let block_id = [3u8; 32];
    let block = make_test_proposal(10, 0);
    let qc = make_test_qc(10, 1);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_qc(&block_id, &qc).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that validate() fails when QC uses an unregistered suite.
#[test]
fn validate_fails_when_qc_uses_unregistered_suite() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    // Persist a block with suite_id = 0 and QC with suite_id = 88 (not registered)
    let block_id = [4u8; 32];
    let block = make_test_proposal(10, 0);
    let qc = make_test_qc(10, 88);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_qc(&block_id, &qc).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        matches!(
            result,
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
            if suite_id == ConsensusSigSuiteId::new(88)
        ),
        "Expected MissingBackendForSuite(88), got {:?}",
        result
    );
}

/// Test that validate() fails when last_committed block_id is not found in storage.
#[test]
fn validate_fails_when_last_committed_block_not_found() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    // Set last_committed but don't actually store the block
    let block_id = [5u8; 32];
    storage.put_last_committed(&block_id).unwrap();
    // NOTE: Intentionally NOT calling storage.put_block()

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        matches!(result, Err(StartupValidationError::StorageInconsistent(_))),
        "Expected StorageInconsistent, got {:?}",
        result
    );
}

/// Test that validate() checks embedded QC suite_id.
#[test]
fn validate_fails_when_embedded_qc_uses_unregistered_suite() {
    let governance = TestEnumerableGovernance::new().with_validator(1, 0);
    let backend_registry = build_backend_registry(vec![0]);
    let storage = InMemoryConsensusStorage::new();

    // Create a block with an embedded QC that uses suite_id = 77 (not registered)
    let block_id = [6u8; 32];
    let mut block = make_test_proposal(10, 0);
    block.qc = Some(make_test_qc(9, 77));
    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        matches!(
            result,
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
            if suite_id == ConsensusSigSuiteId::new(77)
        ),
        "Expected MissingBackendForSuite(77), got {:?}",
        result
    );
}

// ============================================================================
// Combined validation tests
// ============================================================================

/// Test that governance validation runs before storage validation.
/// If governance fails, storage isn't checked.
#[test]
fn governance_validation_runs_before_storage_validation() {
    // Governance references suite 100 (not registered)
    let governance = TestEnumerableGovernance::new().with_validator(1, 100);

    // Backend registry only has suite 0
    let backend_registry = build_backend_registry(vec![0]);

    let storage = InMemoryConsensusStorage::new();

    // Storage has a block with suite 200 (also not registered)
    // But governance validation should fail first
    let block_id = [7u8; 32];
    let block = make_test_proposal(10, 200);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();

    // Should fail on governance (suite 100), not storage (suite 200)
    assert!(
        matches!(
            result,
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
            if suite_id == ConsensusSigSuiteId::new(100)
        ),
        "Expected MissingBackendForSuite(100) from governance, got {:?}",
        result
    );
}

/// Test complete successful validation with both governance and storage.
#[test]
fn full_validation_succeeds_with_consistent_config() {
    // Governance with validators using suites 0 and 1
    let governance = TestEnumerableGovernance::new()
        .with_validator(1, 0)
        .with_validator(2, 1);

    // Backend registry has both suites
    let backend_registry = build_backend_registry(vec![0, 1]);

    let storage = InMemoryConsensusStorage::new();

    // Storage has a block with suite 0 and QC with suite 1
    let block_id = [8u8; 32];
    let block = make_test_proposal(10, 0);
    let qc = make_test_qc(10, 1);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_qc(&block_id, &qc).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let result = validator.validate();
    assert!(
        result.is_ok(),
        "Expected Ok for fully consistent config, got {:?}",
        result
    );
}

// ============================================================================
// Debug trait tests
// ============================================================================

/// Test that ConsensusStartupValidator implements Debug.
#[test]
fn startup_validator_is_debug() {
    let governance = TestEnumerableGovernance::new();
    let backend_registry = SimpleBackendRegistry::new();
    let storage = InMemoryConsensusStorage::new();

    let validator = ConsensusStartupValidator::new(
        Arc::new(governance),
        Arc::new(backend_registry),
        Arc::new(storage),
    );

    let debug_str = format!("{:?}", validator);
    assert!(debug_str.contains("ConsensusStartupValidator"));
}
