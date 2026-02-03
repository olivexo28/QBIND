//! T190 Unit Tests: Proposer-Side DAG Coupling
//!
//! These tests verify the DAG–consensus coupling functionality on the proposer side:
//! - CertifiedFrontier creation and selection
//! - CertifiedFrontierEntry to CertifiedBatchRef conversion
//! - batch_commitment computation from certified batches
//! - Coupling mode behavior (Off/Warn/Enforce)
//! - Integration with proposer path

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    BatchAck, BatchRef, DagCouplingMode, DagMempool, DagMempoolConfig, DagMempoolMetrics,
    InMemoryDagMempool, QbindBatch,
};
use qbind_wire::consensus::{compute_batch_commitment, CertifiedBatchRef, NULL_BATCH_COMMITMENT};

// ============================================================================
// Test Helpers
// ============================================================================

fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_test_tx(sender_byte: u8, nonce: u64, payload_byte: u8) -> QbindTransaction {
    QbindTransaction::new(test_account_id(sender_byte), nonce, vec![payload_byte; 32])
}

fn make_test_batch(creator: ValidatorId, view_hint: u64, txs: Vec<QbindTransaction>) -> QbindBatch {
    QbindBatch::new(creator, view_hint, vec![], txs)
}

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

// ============================================================================
// Part 1: CertifiedFrontier Basic Tests
// ============================================================================

/// Test that an empty CertifiedFrontier is returned when availability is disabled.
#[test]
fn test_certified_frontier_empty_when_availability_disabled() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Add a batch
    let txs = vec![make_test_tx(0x11, 0, 0xAA)];
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    // Select certified frontier - should be empty since availability is disabled
    let frontier = mempool.select_certified_frontier();
    assert!(
        frontier.is_empty(),
        "Frontier should be empty when availability is disabled"
    );
}

/// Test that an empty CertifiedFrontier is returned when no batches are certified.
#[test]
fn test_certified_frontier_empty_when_no_certs() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add a batch
    let batch = make_test_batch(ValidatorId::new(1), 1, vec![make_test_tx(0x11, 0, 0xAA)]);
    mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");

    // Add only one ack (need 2 for quorum)
    let batch_ref = BatchRef::new(batch.creator, batch.batch_id);
    let ack = make_test_ack(batch_ref, ValidatorId::new(2), 1);
    mempool.handle_batch_ack(ack);

    // Select certified frontier - should be empty since quorum not reached
    let frontier = mempool.select_certified_frontier();
    assert!(
        frontier.is_empty(),
        "Frontier should be empty when no batches are certified"
    );
}

/// Test that certified batches appear in the frontier.
#[test]
fn test_certified_frontier_includes_certified_batches() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add a batch
    let batch = make_test_batch(ValidatorId::new(1), 1, vec![make_test_tx(0x11, 0, 0xAA)]);
    mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");

    // Certify it with 2 acks (meets quorum)
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(2), ValidatorId::new(3)],
        1,
    );

    // Select certified frontier - should include the batch
    let frontier = mempool.select_certified_frontier();
    assert_eq!(
        frontier.len(),
        1,
        "Frontier should have one certified batch"
    );
    assert_eq!(frontier.entries[0].batch.batch_id, batch.batch_id);
}

/// Test that fully committed batches are excluded from the frontier.
#[test]
fn test_certified_frontier_excludes_committed_batches() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add a batch with one transaction
    let tx = make_test_tx(0x11, 0, 0xAA);
    let batch = make_test_batch(ValidatorId::new(1), 1, vec![tx.clone()]);
    mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");

    // Certify it
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(2), ValidatorId::new(3)],
        1,
    );

    // Verify it's in the frontier
    let frontier = mempool.select_certified_frontier();
    assert_eq!(
        frontier.len(),
        1,
        "Frontier should have one batch before commit"
    );

    // Mark the transaction as committed
    mempool.mark_committed(&[tx]);

    // Now the frontier should be empty (batch is fully committed)
    let frontier_after = mempool.select_certified_frontier();
    assert!(
        frontier_after.is_empty(),
        "Frontier should be empty after batch is fully committed"
    );
}

// ============================================================================
// Part 2: CertifiedFrontierEntry and CertifiedBatchRef Tests
// ============================================================================

/// Test that CertifiedFrontierEntry correctly converts to CertifiedBatchRef.
#[test]
fn test_certified_frontier_entry_to_batch_ref() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 10, vec![make_test_tx(0x55, 0, 0xBB)]);
    mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(2), ValidatorId::new(3)],
        10,
    );

    // Get the frontier
    let frontier = mempool.select_certified_frontier();
    assert_eq!(frontier.len(), 1);

    // Convert to CertifiedBatchRef
    let entry = &frontier.entries[0];
    let cbr = entry.to_certified_batch_ref();

    // Verify fields
    assert_eq!(cbr.creator, batch.creator.as_u64());
    assert_eq!(cbr.batch_id, batch.batch_id);
    // cert_digest should be non-zero (it's the hash of the certificate)
    assert_ne!(cbr.cert_digest, [0u8; 32]);
}

/// Test that different certificates produce different cert_digests.
#[test]
fn test_different_certs_produce_different_digests() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add two batches from different creators
    let batch1 = make_test_batch(ValidatorId::new(5), 10, vec![make_test_tx(0x55, 0, 0xBB)]);
    let batch2 = make_test_batch(ValidatorId::new(6), 10, vec![make_test_tx(0x66, 0, 0xCC)]);

    mempool
        .insert_remote_batch(batch1.clone())
        .expect("insert should succeed");
    mempool
        .insert_remote_batch(batch2.clone())
        .expect("insert should succeed");

    // Certify both with different signers
    certify_batch(
        &mempool,
        &batch1,
        &[ValidatorId::new(2), ValidatorId::new(3)],
        10,
    );
    certify_batch(
        &mempool,
        &batch2,
        &[ValidatorId::new(3), ValidatorId::new(4)],
        10,
    );

    // Get the frontier
    let frontier = mempool.select_certified_frontier();
    assert_eq!(frontier.len(), 2);

    let refs = frontier.to_certified_batch_refs();
    assert_eq!(refs.len(), 2);

    // Cert digests should be different
    assert_ne!(refs[0].cert_digest, refs[1].cert_digest);
}

// ============================================================================
// Part 3: batch_commitment Computation Tests
// ============================================================================

/// Test that compute_batch_commitment returns NULL for empty refs.
#[test]
fn test_batch_commitment_null_for_empty() {
    let commitment = compute_batch_commitment(&[]);
    assert_eq!(commitment, NULL_BATCH_COMMITMENT);
}

/// Test that compute_batch_commitment produces non-null for non-empty refs.
#[test]
fn test_batch_commitment_non_null_for_refs() {
    let cbr = CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32]);
    let commitment = compute_batch_commitment(&[cbr]);
    assert_ne!(commitment, NULL_BATCH_COMMITMENT);
}

/// Test that different refs produce different commitments.
#[test]
fn test_batch_commitment_differs_for_different_refs() {
    let cbr1 = CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32]);
    let cbr2 = CertifiedBatchRef::new(2, [0xCC; 32], [0xDD; 32]);

    let commitment1 = compute_batch_commitment(&[cbr1.clone()]);
    let commitment2 = compute_batch_commitment(&[cbr2.clone()]);
    let commitment_both = compute_batch_commitment(&[cbr1, cbr2]);

    // All three should be different
    assert_ne!(commitment1, commitment2);
    assert_ne!(commitment1, commitment_both);
    assert_ne!(commitment2, commitment_both);
}

/// Test that order of refs affects commitment (commitment is order-sensitive).
#[test]
fn test_batch_commitment_order_sensitive() {
    let cbr1 = CertifiedBatchRef::new(1, [0xAA; 32], [0xBB; 32]);
    let cbr2 = CertifiedBatchRef::new(2, [0xCC; 32], [0xDD; 32]);

    let commitment_1_2 = compute_batch_commitment(&[cbr1.clone(), cbr2.clone()]);
    let commitment_2_1 = compute_batch_commitment(&[cbr2, cbr1]);

    // Different order should produce different commitment
    assert_ne!(commitment_1_2, commitment_2_1);
}

// ============================================================================
// Part 4: Frontier Ordering Tests
// ============================================================================

/// Test that frontier is sorted by (view_hint, creator, batch_id).
#[test]
fn test_frontier_deterministic_ordering() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add batches in random order (different views and creators)
    let batch_v2_c5 = make_test_batch(ValidatorId::new(5), 2, vec![make_test_tx(0x25, 0, 0x11)]);
    let batch_v1_c3 = make_test_batch(ValidatorId::new(3), 1, vec![make_test_tx(0x13, 0, 0x22)]);
    let batch_v1_c5 = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x15, 0, 0x33)]);
    let batch_v2_c3 = make_test_batch(ValidatorId::new(3), 2, vec![make_test_tx(0x23, 0, 0x44)]);

    // Insert in mixed order
    mempool.insert_remote_batch(batch_v2_c5.clone()).unwrap();
    mempool.insert_remote_batch(batch_v1_c3.clone()).unwrap();
    mempool.insert_remote_batch(batch_v1_c5.clone()).unwrap();
    mempool.insert_remote_batch(batch_v2_c3.clone()).unwrap();

    // Certify all batches
    let acking_validators = &[ValidatorId::new(10), ValidatorId::new(11)];
    certify_batch(&mempool, &batch_v2_c5, acking_validators, 2);
    certify_batch(&mempool, &batch_v1_c3, acking_validators, 1);
    certify_batch(&mempool, &batch_v1_c5, acking_validators, 1);
    certify_batch(&mempool, &batch_v2_c3, acking_validators, 2);

    // Get frontier - should be sorted by (view_hint, creator, batch_id)
    let frontier = mempool.select_certified_frontier();
    assert_eq!(frontier.len(), 4);

    // Expected order: v1_c3, v1_c5, v2_c3, v2_c5
    assert_eq!(frontier.entries[0].batch.view_hint, 1);
    assert_eq!(frontier.entries[0].batch.creator, ValidatorId::new(3));
    assert_eq!(frontier.entries[1].batch.view_hint, 1);
    assert_eq!(frontier.entries[1].batch.creator, ValidatorId::new(5));
    assert_eq!(frontier.entries[2].batch.view_hint, 2);
    assert_eq!(frontier.entries[2].batch.creator, ValidatorId::new(3));
    assert_eq!(frontier.entries[3].batch.view_hint, 2);
    assert_eq!(frontier.entries[3].batch.creator, ValidatorId::new(5));
}

// ============================================================================
// Part 5: flatten_txs Tests
// ============================================================================

/// Test that flatten_txs returns transactions from certified batches.
#[test]
fn test_flatten_txs_returns_batch_transactions() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add a batch with 2 transactions
    let tx1 = make_test_tx(0x11, 0, 0xAA);
    let tx2 = make_test_tx(0x22, 1, 0xBB);
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![tx1, tx2]);

    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    let frontier = mempool.select_certified_frontier();
    let txs = frontier.flatten_txs(100);

    assert_eq!(txs.len(), 2);
}

/// Test that flatten_txs respects max_txs limit.
#[test]
fn test_flatten_txs_respects_limit() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add a batch with 5 transactions
    let txs: Vec<_> = (0..5)
        .map(|i| make_test_tx(0x10 + i, i as u64, 0xAA))
        .collect();
    let batch = make_test_batch(ValidatorId::new(5), 1, txs);

    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
        1,
    );

    let frontier = mempool.select_certified_frontier();

    // Request only 3 txs
    let txs = frontier.flatten_txs(3);
    assert_eq!(txs.len(), 3);
}

/// Test that flatten_txs deduplicates transactions across batches.
#[test]
fn test_flatten_txs_deduplicates() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Same transaction (same sender + nonce)
    let tx_shared = make_test_tx(0x11, 0, 0xAA);

    // Two batches containing the same transaction
    let batch1 = make_test_batch(ValidatorId::new(5), 1, vec![tx_shared.clone()]);
    let batch2 = make_test_batch(ValidatorId::new(6), 1, vec![tx_shared.clone()]);

    mempool.insert_remote_batch(batch1.clone()).unwrap();
    mempool.insert_remote_batch(batch2.clone()).unwrap();

    let acking_validators = &[ValidatorId::new(10), ValidatorId::new(11)];
    certify_batch(&mempool, &batch1, acking_validators, 1);
    certify_batch(&mempool, &batch2, acking_validators, 1);

    let frontier = mempool.select_certified_frontier();
    assert_eq!(frontier.len(), 2, "Should have 2 certified batches");

    // Flatten should deduplicate
    let txs = frontier.flatten_txs(100);
    assert_eq!(txs.len(), 1, "Should have only 1 unique transaction");
}

// ============================================================================
// Part 6: DagCouplingMode Tests
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
// Part 7: Integration with CertifiedFrontier
// ============================================================================

/// Test that CertifiedFrontier total_tx_count is correct.
#[test]
fn test_certified_frontier_total_tx_count() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add two batches with 2 and 3 transactions
    let batch1 = make_test_batch(
        ValidatorId::new(5),
        1,
        vec![make_test_tx(0x11, 0, 0xAA), make_test_tx(0x12, 1, 0xBB)],
    );
    let batch2 = make_test_batch(
        ValidatorId::new(6),
        1,
        vec![
            make_test_tx(0x21, 0, 0xCC),
            make_test_tx(0x22, 1, 0xDD),
            make_test_tx(0x23, 2, 0xEE),
        ],
    );

    mempool.insert_remote_batch(batch1.clone()).unwrap();
    mempool.insert_remote_batch(batch2.clone()).unwrap();

    let acking_validators = &[ValidatorId::new(10), ValidatorId::new(11)];
    certify_batch(&mempool, &batch1, acking_validators, 1);
    certify_batch(&mempool, &batch2, acking_validators, 1);

    let frontier = mempool.select_certified_frontier();
    assert_eq!(frontier.len(), 2);
    assert_eq!(frontier.total_tx_count(), 5); // 2 + 3 = 5
}

/// Test that CertifiedFrontier can be used to compute batch_commitment.
#[test]
fn test_frontier_to_batch_commitment() {
    let mempool = create_test_mempool_with_availability(ValidatorId::new(1), 2);

    // Add and certify a batch
    let batch = make_test_batch(ValidatorId::new(5), 1, vec![make_test_tx(0x55, 0, 0xBB)]);
    mempool.insert_remote_batch(batch.clone()).unwrap();
    certify_batch(
        &mempool,
        &batch,
        &[ValidatorId::new(10), ValidatorId::new(11)],
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

// ============================================================================
// Part 8: Metrics Tests
// ============================================================================

/// Test that certified_frontier_select_total metric is incremented.
#[test]
fn test_certified_frontier_select_metric() {
    let metrics = Arc::new(DagMempoolMetrics::new());
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 1,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };

    let mempool = InMemoryDagMempool::with_availability(config, 2).with_metrics(metrics.clone());

    // Initial count should be 0
    assert_eq!(metrics.certified_frontier_select_total(), 0);

    // Select certified frontier (even if empty)
    let _ = mempool.select_certified_frontier();

    // Count should be incremented
    assert_eq!(metrics.certified_frontier_select_total(), 1);

    // Select again
    let _ = mempool.select_certified_frontier();
    assert_eq!(metrics.certified_frontier_select_total(), 2);
}
