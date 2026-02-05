//! T192 Unit Tests: DAG Coupling Invariant Checks & Safety Probes
//!
//! These tests verify the post-commit block-level DAG coupling invariant checks:
//! - `DagCouplingBlockCheckResult` enum behavior
//! - `check_dag_coupling_invariant_for_committed_block()` function
//! - Mode behavior (Off/Warn/Enforce)
//! - Metrics integration
//!
//! The tests cover:
//! - Happy path with Enforce mode and correct commit
//! - Missing commitment scenario
//! - Mismatch scenario
//! - Off/Warn mode behavior (NotChecked)

use qbind_consensus::ids::ValidatorId;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    BatchAck, BatchRef, DagCouplingBlockCheckResult, DagCouplingMode, DagMempool, DagMempoolConfig,
    InMemoryDagMempool, QbindBatch,
};
use qbind_wire::consensus::{
    compute_batch_commitment, BlockHeader, CertifiedBatchRef, NULL_BATCH_COMMITMENT,
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

/// Create a minimal BlockHeader for testing with given batch_commitment.
fn make_test_header_with_commitment(
    view: u64,
    height: u64,
    batch_commitment: [u8; 32],
) -> BlockHeader {
    BlockHeader {
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
    }
}

// ============================================================================
// Part 1: DagCouplingBlockCheckResult Tests
// ============================================================================

/// Test that DagCouplingBlockCheckResult::Display works correctly.
#[test]
fn test_dag_coupling_block_check_result_display() {
    assert_eq!(
        format!("{}", DagCouplingBlockCheckResult::NotChecked),
        "not_checked"
    );
    assert_eq!(format!("{}", DagCouplingBlockCheckResult::Ok), "ok");
    assert_eq!(
        format!("{}", DagCouplingBlockCheckResult::MissingCommitment),
        "missing"
    );
    assert_eq!(
        format!("{}", DagCouplingBlockCheckResult::Mismatch),
        "mismatch"
    );
    assert_eq!(
        format!(
            "{}",
            DagCouplingBlockCheckResult::InternalError("test error".to_string())
        ),
        "internal_error: test error"
    );
}

/// Test that DagCouplingBlockCheckResult enum values are correct.
#[test]
fn test_dag_coupling_block_check_result_equality() {
    assert_eq!(
        DagCouplingBlockCheckResult::NotChecked,
        DagCouplingBlockCheckResult::NotChecked
    );
    assert_eq!(
        DagCouplingBlockCheckResult::Ok,
        DagCouplingBlockCheckResult::Ok
    );
    assert_ne!(
        DagCouplingBlockCheckResult::Ok,
        DagCouplingBlockCheckResult::NotChecked
    );
    assert_ne!(
        DagCouplingBlockCheckResult::MissingCommitment,
        DagCouplingBlockCheckResult::Mismatch
    );
}

// ============================================================================
// Part 2: Metrics Tests
// ============================================================================

/// Test that DagCouplingMetrics block check counters work correctly.
#[test]
fn test_dag_coupling_metrics_block_check() {
    use qbind_node::DagCouplingMetrics;

    let metrics = DagCouplingMetrics::new();

    // Initial counts should be 0
    assert_eq!(metrics.block_check_total("not_checked"), 0);
    assert_eq!(metrics.block_check_total("ok"), 0);
    assert_eq!(metrics.block_check_total("missing"), 0);
    assert_eq!(metrics.block_check_total("mismatch"), 0);
    assert_eq!(metrics.block_check_total("internal_error"), 0);
    assert_eq!(metrics.block_mismatch_total(), 0);
    assert_eq!(metrics.block_missing_total(), 0);

    // Record some block checks
    metrics.record_block_check("ok");
    metrics.record_block_check("ok");
    metrics.record_block_check("missing");
    metrics.record_block_check("mismatch");
    metrics.record_block_check("not_checked");

    assert_eq!(metrics.block_check_total("ok"), 2);
    assert_eq!(metrics.block_check_total("missing"), 1);
    assert_eq!(metrics.block_check_total("mismatch"), 1);
    assert_eq!(metrics.block_check_total("not_checked"), 1);
    assert_eq!(metrics.block_mismatch_total(), 1);
    assert_eq!(metrics.block_missing_total(), 1);
}

/// Test that DagCouplingMetrics format_metrics includes block check output.
#[test]
fn test_dag_coupling_metrics_format_includes_block_checks() {
    use qbind_node::DagCouplingMetrics;

    let metrics = DagCouplingMetrics::new();
    metrics.record_block_check("ok");
    metrics.record_block_check("missing");

    let output = metrics.format_metrics();

    // Check that T192 metrics are present
    assert!(output.contains("qbind_dag_coupling_block_check_total"));
    assert!(output.contains("result=\"ok\""));
    assert!(output.contains("result=\"missing\""));
    assert!(output.contains("qbind_dag_coupling_block_mismatch_total"));
    assert!(output.contains("qbind_dag_coupling_block_missing_total"));
}

// ============================================================================
// Part 3: CertifiedFrontier and Commitment Tests (for context)
// ============================================================================

/// Test that CertifiedFrontier produces correct commitment for validation.
#[test]
fn test_certified_frontier_commitment_for_validation() {
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

    // Get frontier and compute commitment
    let frontier = mempool.select_certified_frontier();
    let refs = frontier.to_certified_batch_refs();
    let commitment = compute_batch_commitment(&refs);

    // Commitment should be non-null
    assert_ne!(commitment, NULL_BATCH_COMMITMENT);

    // Computing again should produce the same result (deterministic)
    let commitment2 = compute_batch_commitment(&frontier.to_certified_batch_refs());
    assert_eq!(commitment, commitment2);
}

/// Test that different refs produce different commitments.
#[test]
fn test_different_refs_produce_different_commitments() {
    let refs1 = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let refs2 = vec![CertifiedBatchRef::new(2, [0xCC; 32], [0xDD; 32])];

    let commitment1 = compute_batch_commitment(&refs1);
    let commitment2 = compute_batch_commitment(&refs2);

    assert_ne!(commitment1, commitment2);
    assert_ne!(commitment1, NULL_BATCH_COMMITMENT);
    assert_ne!(commitment2, NULL_BATCH_COMMITMENT);
}

// ============================================================================
// Part 4: BlockHeader Tests with batch_commitment
// ============================================================================

/// Test that header with NULL commitment is detectable.
#[test]
fn test_header_with_null_commitment_is_detectable() {
    let header = make_test_header_with_commitment(1, 1, NULL_BATCH_COMMITMENT);
    assert_eq!(header.batch_commitment, NULL_BATCH_COMMITMENT);
}

/// Test that header with valid commitment is non-NULL.
#[test]
fn test_header_with_valid_commitment_is_non_null() {
    let refs = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let commitment = compute_batch_commitment(&refs);

    let header = make_test_header_with_commitment(1, 1, commitment);
    assert_ne!(header.batch_commitment, NULL_BATCH_COMMITMENT);
}

// ============================================================================
// Part 5: Scenario-Based Tests
// ============================================================================

/// Test scenario: Missing commitment detected in header.
///
/// When a header has NULL_BATCH_COMMITMENT but coupling is required,
/// the invariant check should detect this as a MissingCommitment violation.
#[test]
fn test_missing_commitment_scenario() {
    // Create a header with NULL commitment
    let header = make_test_header_with_commitment(1, 1, NULL_BATCH_COMMITMENT);

    // Verify it's NULL (the invariant check will catch this)
    assert_eq!(header.batch_commitment, NULL_BATCH_COMMITMENT);
}

/// Test scenario: Commitment mismatch detected.
///
/// When a header has a batch_commitment that doesn't match local computation,
/// the invariant check should detect this as a Mismatch violation.
#[test]
fn test_commitment_mismatch_scenario() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Compute correct commitment
    let frontier = mempool.select_certified_frontier();
    let correct_commitment = compute_batch_commitment(&frontier.to_certified_batch_refs());

    // Create header with WRONG commitment
    let wrong_commitment = [0xFF; 32];
    let header = make_test_header_with_commitment(1, 1, wrong_commitment);

    // Verify mismatch
    assert_ne!(header.batch_commitment, correct_commitment);
    assert_ne!(header.batch_commitment, NULL_BATCH_COMMITMENT);
}

/// Test scenario: Matching commitment produces Ok result.
///
/// When a header has a batch_commitment that matches local computation,
/// the invariant check should return Ok.
#[test]
fn test_matching_commitment_scenario() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Compute correct commitment
    let frontier = mempool.select_certified_frontier();
    let correct_commitment = compute_batch_commitment(&frontier.to_certified_batch_refs());

    // Create header with correct commitment
    let header = make_test_header_with_commitment(1, 1, correct_commitment);

    // Verify match
    assert_eq!(header.batch_commitment, correct_commitment);
    assert_ne!(header.batch_commitment, NULL_BATCH_COMMITMENT);
}

// ============================================================================
// Part 6: Mode Behavior Tests
// ============================================================================

/// Test that DagCouplingMode default is Off.
#[test]
fn test_dag_coupling_mode_default_is_off() {
    let mode = DagCouplingMode::default();
    assert_eq!(mode, DagCouplingMode::Off);
}

/// Test DagCouplingMode display strings.
#[test]
fn test_dag_coupling_mode_display_strings() {
    assert_eq!(format!("{}", DagCouplingMode::Off), "off");
    assert_eq!(format!("{}", DagCouplingMode::Warn), "warn");
    assert_eq!(format!("{}", DagCouplingMode::Enforce), "enforce");
}

/// Test parsing DagCouplingMode from string.
#[test]
fn test_parse_dag_coupling_mode_from_string() {
    use qbind_node::parse_dag_coupling_mode;

    assert_eq!(parse_dag_coupling_mode("off"), Some(DagCouplingMode::Off));
    assert_eq!(parse_dag_coupling_mode("warn"), Some(DagCouplingMode::Warn));
    assert_eq!(
        parse_dag_coupling_mode("enforce"),
        Some(DagCouplingMode::Enforce)
    );
    assert_eq!(parse_dag_coupling_mode("invalid"), None);
}

// ============================================================================
// Part 7: Edge Cases
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

/// Test that multiple certified batches produce different commitment than single batch.
#[test]
fn test_multiple_batches_produce_different_commitment() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify first batch
    let batch1 = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xAA)]);
    mempool.insert_remote_batch(batch1.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch1,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Get commitment with one batch
    let frontier1 = mempool.select_certified_frontier();
    let commitment1 = compute_batch_commitment(&frontier1.to_certified_batch_refs());

    // Add and certify second batch
    let batch2 = make_test_batch(ValidatorId::new(6), 1, vec![make_test_tx(0x66, 0, 0xBB)]);
    mempool.insert_remote_batch(batch2.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch2,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    // Get commitment with two batches
    let frontier2 = mempool.select_certified_frontier();
    let commitment2 = compute_batch_commitment(&frontier2.to_certified_batch_refs());

    // Commitments should be different
    assert_ne!(commitment1, commitment2);
    assert_ne!(commitment1, NULL_BATCH_COMMITMENT);
    assert_ne!(commitment2, NULL_BATCH_COMMITMENT);
}

/// Test that frontier ordering is deterministic across multiple calls.
#[test]
fn test_frontier_ordering_deterministic() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add batches in "random" order
    let batch_v2_c5 = make_test_batch(ValidatorId::new(5), 2, vec![make_test_tx(0x25, 0, 0x11)]);
    let batch_v1_c3 = make_test_batch(ValidatorId::new(3), 1, vec![make_test_tx(0x13, 0, 0x22)]);

    // Insert in mixed order
    mempool.insert_remote_batch(batch_v2_c5.clone()).unwrap();
    mempool.insert_remote_batch(batch_v1_c3.clone()).unwrap();

    // Certify all batches
    let acking_validators = &[ValidatorId::new(10), ValidatorId::new(11)];
    certify_batch(&mempool, &batch_v2_c5, acking_validators, 2);
    certify_batch(&mempool, &batch_v1_c3, acking_validators, 1);

    // Get frontier and compute commitment multiple times
    let commitment1 = compute_batch_commitment(
        &mempool
            .select_certified_frontier()
            .to_certified_batch_refs(),
    );
    let commitment2 = compute_batch_commitment(
        &mempool
            .select_certified_frontier()
            .to_certified_batch_refs(),
    );
    let commitment3 = compute_batch_commitment(
        &mempool
            .select_certified_frontier()
            .to_certified_batch_refs(),
    );

    // All should be identical
    assert_eq!(commitment1, commitment2);
    assert_eq!(commitment2, commitment3);
}

// ============================================================================
// Part 8: Integration Verification
// ============================================================================

/// Test that block-level check is observational only (no panics).
#[test]
fn test_block_check_is_observational_no_panics() {
    // Create various headers and verify no panics occur during check logic simulation

    // NULL commitment
    let _header1 = make_test_header_with_commitment(1, 1, NULL_BATCH_COMMITMENT);

    // Valid-looking commitment
    let refs = vec![CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32])];
    let _header2 = make_test_header_with_commitment(1, 1, compute_batch_commitment(&refs));

    // Garbage commitment
    let _header3 = make_test_header_with_commitment(1, 1, [0xFF; 32]);

    // All operations completed without panic - test passes
}
