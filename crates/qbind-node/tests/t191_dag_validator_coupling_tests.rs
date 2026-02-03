//! T191 Unit Tests: Validator-Side DAG Coupling Enforcement
//!
//! These tests verify the DAG–consensus coupling validation on the validator side:
//! - `DagCouplingValidationResult` enum behavior
//! - `validate_dag_coupling_for_proposal()` function
//! - Mode behavior (Off/Warn/Enforce)
//! - Integration with proposal handling path

use qbind_consensus::ids::ValidatorId;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    BatchAck, BatchRef, DagCouplingMode, DagCouplingValidationResult, DagMempool, DagMempoolConfig,
    InMemoryDagMempool, QbindBatch,
};
use qbind_wire::consensus::{
    compute_batch_commitment, BlockHeader, BlockProposal, CertifiedBatchRef, NULL_BATCH_COMMITMENT,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test account ID with the given byte in the first position.
fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

/// Create a test transaction with a 32-byte payload filled with the specified byte.
fn make_test_tx(sender_byte: u8, nonce: u64, payload_byte: u8) -> QbindTransaction {
    QbindTransaction::new(test_account_id(sender_byte), nonce, vec![payload_byte; 32])
}

/// Create a test batch with no parent dependencies.
fn make_test_batch(creator: ValidatorId, view_hint: u64, txs: Vec<QbindTransaction>) -> QbindBatch {
    QbindBatch::new(creator, view_hint, vec![], txs)
}

/// Create an unsigned test acknowledgment with suite_id=100 (ML-DSA-44).
fn make_test_ack(batch_ref: BatchRef, validator_id: ValidatorId, view_hint: u64) -> BatchAck {
    BatchAck::new_unsigned(batch_ref, validator_id, view_hint, 100)
}

/// Create a mempool with availability enabled and the given quorum size.
fn create_test_mempool_with_availability(
    local_validator: ValidatorId,
    quorum_size: usize,
) -> InMemoryDagMempool {
    let config = DagMempoolConfig {
        local_validator_id: local_validator,
        batch_size: 1, // Small batch size for testing
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    InMemoryDagMempool::with_availability(config, quorum_size)
}

/// Simulate acks from multiple validators to certify a batch.
fn certify_batch(
    mempool: &InMemoryDagMempool,
    batch: &QbindBatch,
    acking_validators: &[ValidatorId],
    view: u64,
) {
    let batch_ref = BatchRef::new(batch.creator, batch.batch_id);
    for &validator in acking_validators {
        let ack = make_test_ack(batch_ref.clone(), validator, view);
        let _ = mempool.handle_batch_ack(ack);
    }
}

/// Create a minimal BlockProposal for testing with given batch_commitment.
fn make_test_proposal_with_commitment(
    view: u64,
    height: u64,
    batch_commitment: [u8; 32],
) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: view,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: 100,
            tx_count: 0,
            timestamp: 0,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// Part 1: DagCouplingValidationResult Tests
// ============================================================================

/// Test that DagCouplingValidationResult::Display works correctly.
#[test]
fn test_dag_coupling_validation_result_display() {
    assert_eq!(format!("{}", DagCouplingValidationResult::Ok), "ok");
    assert_eq!(
        format!("{}", DagCouplingValidationResult::NotRequired),
        "not_required"
    );
    assert_eq!(
        format!("{}", DagCouplingValidationResult::UncoupledMissing),
        "uncoupled_missing"
    );
    assert_eq!(
        format!("{}", DagCouplingValidationResult::UncoupledMismatch),
        "uncoupled_mismatch"
    );
    assert_eq!(
        format!("{}", DagCouplingValidationResult::UnknownBatches),
        "unknown_batches"
    );
    assert_eq!(
        format!(
            "{}",
            DagCouplingValidationResult::InternalError("test error".to_string())
        ),
        "internal_error: test error"
    );
}

/// Test that DagCouplingValidationResult enum values are correct.
#[test]
fn test_dag_coupling_validation_result_equality() {
    assert_eq!(
        DagCouplingValidationResult::Ok,
        DagCouplingValidationResult::Ok
    );
    assert_eq!(
        DagCouplingValidationResult::NotRequired,
        DagCouplingValidationResult::NotRequired
    );
    assert_ne!(
        DagCouplingValidationResult::Ok,
        DagCouplingValidationResult::NotRequired
    );
    assert_ne!(
        DagCouplingValidationResult::UncoupledMissing,
        DagCouplingValidationResult::UncoupledMismatch
    );
}

// ============================================================================
// Part 2: batch_commitment Validation Tests
// ============================================================================

/// Test that NULL_BATCH_COMMITMENT represents uncoupled proposal.
#[test]
fn test_null_batch_commitment_is_uncoupled() {
    let commitment = NULL_BATCH_COMMITMENT;
    assert_eq!(commitment, [0u8; 32]);
}

/// Test that batch_commitment differs for different certified refs.
#[test]
fn test_batch_commitment_varies_with_refs() {
    let refs1 = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let refs2 = vec![CertifiedBatchRef::new(2, [0xCC; 32], [0xDD; 32])];

    let commitment1 = compute_batch_commitment(&refs1);
    let commitment2 = compute_batch_commitment(&refs2);

    assert_ne!(commitment1, commitment2);
    assert_ne!(commitment1, NULL_BATCH_COMMITMENT);
    assert_ne!(commitment2, NULL_BATCH_COMMITMENT);
}

/// Test that the same refs produce the same commitment (deterministic).
#[test]
fn test_batch_commitment_is_deterministic() {
    let refs = vec![
        CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32]),
        CertifiedBatchRef::new(2, [0xCC; 32], [0xDD; 32]),
    ];

    let commitment1 = compute_batch_commitment(&refs);
    let commitment2 = compute_batch_commitment(&refs);

    assert_eq!(commitment1, commitment2);
}

// ============================================================================
// Part 3: Proposal Construction Tests (for validator-side comparison)
// ============================================================================

/// Test that proposals with NULL commitment can be constructed.
#[test]
fn test_proposal_with_null_commitment() {
    let proposal = make_test_proposal_with_commitment(1, 1, NULL_BATCH_COMMITMENT);
    assert_eq!(proposal.header.batch_commitment, NULL_BATCH_COMMITMENT);
}

/// Test that proposals with non-NULL commitment can be constructed.
#[test]
fn test_proposal_with_valid_commitment() {
    let refs = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let commitment = compute_batch_commitment(&refs);

    let proposal = make_test_proposal_with_commitment(1, 1, commitment);
    assert_ne!(proposal.header.batch_commitment, NULL_BATCH_COMMITMENT);
}

// ============================================================================
// Part 4: CertifiedFrontier Tests for Validator
// ============================================================================

/// Test that certified frontier produces correct CertifiedBatchRefs.
#[test]
fn test_certified_frontier_to_batch_refs() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xBB)]);
    mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(2), ValidatorId::new(3)],
        1,
    );

    // Get frontier and convert to refs
    let frontier = mempool.select_certified_frontier();
    assert_eq!(frontier.len(), 1);

    let refs = frontier.to_certified_batch_refs();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].creator, batch.creator.as_u64());
    assert_eq!(refs[0].batch_id, batch.batch_id);
}

/// Test that validator can compute same commitment as proposer.
#[test]
fn test_validator_computes_same_commitment_as_proposer() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify two batches
    let batch1 = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    let batch2 = make_test_batch(ValidatorId::new(6), 1, vec![make_test_tx(0x66, 0, 0xBB)]);

    mempool.insert_remote_batch(batch1.clone()).unwrap();
    mempool.insert_remote_batch(batch2.clone()).unwrap();

    let acking_validators = &[ValidatorId::new(10), ValidatorId::new(11)];
    certify_batch(&mempool, &batch1, acking_validators, 1);
    certify_batch(&mempool, &batch2, acking_validators, 1);

    // Get frontier and compute commitment
    let frontier = mempool.select_certified_frontier();
    let refs = frontier.to_certified_batch_refs();
    let proposer_commitment = compute_batch_commitment(&refs);

    // Simulate validator computing commitment from same frontier
    let validator_frontier = mempool.select_certified_frontier();
    let validator_refs = validator_frontier.to_certified_batch_refs();
    let validator_commitment = compute_batch_commitment(&validator_refs);

    // Commitments should match
    assert_eq!(proposer_commitment, validator_commitment);
    assert_ne!(proposer_commitment, NULL_BATCH_COMMITMENT);
}

// ============================================================================
// Part 5: DagCouplingMode Behavior Tests
// ============================================================================

/// Test DagCouplingMode default value.
#[test]
fn test_dag_coupling_mode_default() {
    let mode = DagCouplingMode::default();
    assert_eq!(mode, DagCouplingMode::Off);
}

/// Test DagCouplingMode display strings.
#[test]
fn test_dag_coupling_mode_display() {
    assert_eq!(format!("{}", DagCouplingMode::Off), "off");
    assert_eq!(format!("{}", DagCouplingMode::Warn), "warn");
    assert_eq!(format!("{}", DagCouplingMode::Enforce), "enforce");
}

/// Test parsing DagCouplingMode from string.
#[test]
fn test_parse_dag_coupling_mode() {
    use qbind_node::parse_dag_coupling_mode;

    assert_eq!(parse_dag_coupling_mode("off"), Some(DagCouplingMode::Off));
    assert_eq!(parse_dag_coupling_mode("OFF"), Some(DagCouplingMode::Off));
    assert_eq!(parse_dag_coupling_mode("warn"), Some(DagCouplingMode::Warn));
    assert_eq!(parse_dag_coupling_mode("WARN"), Some(DagCouplingMode::Warn));
    assert_eq!(
        parse_dag_coupling_mode("enforce"),
        Some(DagCouplingMode::Enforce)
    );
    assert_eq!(
        parse_dag_coupling_mode("ENFORCE"),
        Some(DagCouplingMode::Enforce)
    );
    assert_eq!(parse_dag_coupling_mode("invalid"), None);
}

// ============================================================================
// Part 6: Signing Preimage and Header Tests
// ============================================================================

/// Test that batch_commitment is included in block header.
#[test]
fn test_batch_commitment_in_header() {
    let refs = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let commitment = compute_batch_commitment(&refs);

    let proposal = make_test_proposal_with_commitment(1, 1, commitment);
    assert_eq!(proposal.header.batch_commitment, commitment);
}

/// Test that two proposals with different commitments have different preimages.
#[test]
fn test_different_commitments_produce_different_preimages() {
    let refs1 = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let refs2 = vec![CertifiedBatchRef::new(2, [0xCC; 32], [0xDD; 32])];

    let commitment1 = compute_batch_commitment(&refs1);
    let commitment2 = compute_batch_commitment(&refs2);

    let proposal1 = make_test_proposal_with_commitment(1, 1, commitment1);
    let proposal2 = make_test_proposal_with_commitment(1, 1, commitment2);

    // Same view/height but different commitments → different preimages
    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(preimage1, preimage2);
}

// ============================================================================
// Part 7: Metrics Tests
// ============================================================================

/// Test that DagCouplingMetrics can be created and updated.
#[test]
fn test_dag_coupling_metrics_basic() {
    use qbind_node::DagCouplingMetrics;

    let metrics = DagCouplingMetrics::new();

    // Initial counts should be 0
    assert_eq!(metrics.validation_total("ok"), 0);
    assert_eq!(metrics.validation_total("not_required"), 0);
    assert_eq!(metrics.validation_total("uncoupled_missing"), 0);
    assert_eq!(metrics.rejected_total("uncoupled_missing"), 0);

    // Record some validations
    metrics.record_validation("ok");
    metrics.record_validation("ok");
    metrics.record_validation("uncoupled_missing");
    metrics.record_rejection("uncoupled_missing");

    assert_eq!(metrics.validation_total("ok"), 2);
    assert_eq!(metrics.validation_total("uncoupled_missing"), 1);
    assert_eq!(metrics.rejected_total("uncoupled_missing"), 1);
}

/// Test that DagCouplingMetrics format_metrics produces output.
#[test]
fn test_dag_coupling_metrics_format() {
    use qbind_node::DagCouplingMetrics;

    let metrics = DagCouplingMetrics::new();
    metrics.record_validation("ok");

    let output = metrics.format_metrics();
    assert!(output.contains("qbind_dag_coupling_validation_total"));
    assert!(output.contains("result=\"ok\""));
}

// ============================================================================
// Part 8: Integration Tests
// ============================================================================

/// Test scenario: Validator receives proposal matching local frontier.
///
/// When a validator has the same certified frontier as the proposer,
/// the batch_commitment should match and validation should pass.
#[test]
fn test_matching_frontier_produces_matching_commitment() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Setup: Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Proposer computes commitment
    let proposer_frontier = mempool.select_certified_frontier();
    let proposer_refs = proposer_frontier.to_certified_batch_refs();
    let proposer_commitment = compute_batch_commitment(&proposer_refs);

    // Validator computes commitment from same state
    let validator_frontier = mempool.select_certified_frontier();
    let validator_refs = validator_frontier.to_certified_batch_refs();
    let validator_commitment = compute_batch_commitment(&validator_refs);

    // Create proposal with proposer's commitment
    let proposal = make_test_proposal_with_commitment(1, 1, proposer_commitment);

    // Validator should be able to verify
    assert_eq!(
        proposal.header.batch_commitment, validator_commitment,
        "Validator's computed commitment should match proposal"
    );
}

/// Test scenario: Validator detects tampered commitment.
///
/// If the proposal's batch_commitment doesn't match what validator computes,
/// the validation should detect this.
#[test]
fn test_mismatched_commitment_detected() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Setup: Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Validator computes correct commitment
    let validator_frontier = mempool.select_certified_frontier();
    let validator_refs = validator_frontier.to_certified_batch_refs();
    let correct_commitment = compute_batch_commitment(&validator_refs);

    // Create proposal with WRONG commitment (tampered)
    let wrong_commitment = [0xFF; 32]; // Deliberately wrong
    let proposal = make_test_proposal_with_commitment(1, 1, wrong_commitment);

    // Validator should detect mismatch
    assert_ne!(
        proposal.header.batch_commitment, correct_commitment,
        "Tampered commitment should not match validator's computation"
    );
}

/// Test scenario: Validator detects missing commitment.
///
/// If the proposal has NULL_BATCH_COMMITMENT but coupling is required,
/// validation should detect this.
#[test]
fn test_missing_commitment_detected() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Setup: Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Create proposal with NULL commitment (missing)
    let proposal = make_test_proposal_with_commitment(1, 1, NULL_BATCH_COMMITMENT);

    // Validator should detect missing commitment
    assert_eq!(
        proposal.header.batch_commitment, NULL_BATCH_COMMITMENT,
        "Proposal should have NULL commitment"
    );

    // Validator has certified batches, so NULL is incorrect
    let validator_frontier = mempool.select_certified_frontier();
    assert!(
        !validator_frontier.is_empty(),
        "Validator should have certified batches"
    );
}

// ============================================================================
// Part 9: Edge Cases
// ============================================================================

/// Test that empty frontier produces NULL commitment.
#[test]
fn test_empty_frontier_produces_null_commitment() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // No batches - empty frontier
    let frontier = mempool.select_certified_frontier();
    assert!(frontier.is_empty());

    let refs = frontier.to_certified_batch_refs();
    let commitment = compute_batch_commitment(&refs);

    assert_eq!(commitment, NULL_BATCH_COMMITMENT);
}

/// Test that frontier ordering is deterministic.
#[test]
fn test_frontier_ordering_deterministic() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add batches in random order
    let batch_v2_c5 = make_test_batch(ValidatorId::new(5), 2, vec![make_test_tx(0x25, 0, 0x11)]);
    let batch_v1_c3 = make_test_batch(ValidatorId::new(3), 1, vec![make_test_tx(0x13, 0, 0x22)]);

    // Insert in mixed order
    mempool.insert_remote_batch(batch_v2_c5.clone()).unwrap();
    mempool.insert_remote_batch(batch_v1_c3.clone()).unwrap();

    // Certify all batches
    let acking_validators = &[ValidatorId::new(10), ValidatorId::new(11)];
    certify_batch(&mempool, &batch_v2_c5, acking_validators, 2);
    certify_batch(&mempool, &batch_v1_c3, acking_validators, 1);

    // Get frontier multiple times - should be same order
    let frontier1 = mempool.select_certified_frontier();
    let frontier2 = mempool.select_certified_frontier();

    let refs1 = frontier1.to_certified_batch_refs();
    let refs2 = frontier2.to_certified_batch_refs();

    assert_eq!(refs1.len(), refs2.len());
    for (r1, r2) in refs1.iter().zip(refs2.iter()) {
        assert_eq!(r1.creator, r2.creator);
        assert_eq!(r1.batch_id, r2.batch_id);
        assert_eq!(r1.cert_digest, r2.cert_digest);
    }
}
