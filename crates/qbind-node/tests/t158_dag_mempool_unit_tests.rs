//! T158 Integration Tests: DAG Mempool Unit Tests
//!
//! These tests verify the DAG mempool functionality:
//! - Batch creation and insertion
//! - DAG invariants (no cycles, consistent children mapping)
//! - Frontier selection and deterministic ordering
//! - Commit cleanup behavior

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    compute_batch_id, compute_tx_id, BatchRef, DagMempool, DagMempoolConfig, DagMempoolMetrics,
    InMemoryDagMempool, QbindBatch,
};

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

// ============================================================================
// Part 1: Batch Creation & Insertion Tests
// ============================================================================

/// Test that inserting local transactions creates batches with unique IDs.
#[test]
fn test_batch_creation_with_unique_ids() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 2, // Small batch size for testing
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert 4 transactions - should create 2 batches
    let txs = vec![
        make_test_tx(0xAA, 0, 0x11),
        make_test_tx(0xAA, 1, 0x22),
        make_test_tx(0xAA, 2, 0x33),
        make_test_tx(0xAA, 3, 0x44),
    ];
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    let stats = mempool.stats();
    assert_eq!(stats.num_batches, 2, "should have created 2 batches");
    assert_eq!(stats.pending_txs, 0, "no pending txs (all batched)");
}

/// Test that batch IDs are consistent with compute_batch_id.
#[test]
fn test_batch_id_consistency() {
    let creator = ValidatorId::new(42);
    let view_hint = 10;
    let parents = vec![BatchRef::new(ValidatorId::new(0), [0xBB; 32])];
    let txs = vec![make_test_tx(0xCC, 0, 0x55)];

    // Create batch manually
    let batch = QbindBatch::new(creator, view_hint, parents.clone(), txs.clone());

    // Verify batch_id matches manual computation
    let expected_id = compute_batch_id(creator, view_hint, &parents, &txs);
    assert_eq!(
        batch.batch_id, expected_id,
        "batch_id should match compute_batch_id"
    );
}

/// Test that parents are set correctly when creating successive batches.
#[test]
fn test_batch_parent_references() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 2,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // First batch (no parents)
    mempool
        .insert_local_txs(vec![
            make_test_tx(0xDD, 0, 0x10),
            make_test_tx(0xDD, 1, 0x20),
        ])
        .expect("insert should succeed");

    let stats1 = mempool.stats();
    assert_eq!(stats1.num_batches, 1, "should have 1 batch");
    assert_eq!(stats1.num_edges, 0, "first batch has no parents");

    // Second batch (should reference first)
    mempool
        .insert_local_txs(vec![
            make_test_tx(0xDD, 2, 0x30),
            make_test_tx(0xDD, 3, 0x40),
        ])
        .expect("insert should succeed");

    let stats2 = mempool.stats();
    assert_eq!(stats2.num_batches, 2, "should have 2 batches");
    assert!(
        stats2.num_edges > 0,
        "second batch should have parent edges"
    );
}

// ============================================================================
// Part 2: DAG Invariants Tests
// ============================================================================

/// Test that remote batches are inserted correctly and children mapping is maintained.
#[test]
fn test_remote_batch_insertion_and_children_mapping() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Create and insert first batch (no parents)
    let batch1 = QbindBatch::new(
        ValidatorId::new(2),
        0,
        vec![],
        vec![make_test_tx(0xEE, 0, 0x11)],
    );
    let batch1_id = batch1.batch_id;

    mempool
        .insert_remote_batch(batch1)
        .expect("remote batch insert should succeed");

    // Create second batch with first as parent
    let batch2 = QbindBatch::new(
        ValidatorId::new(3),
        1,
        vec![BatchRef::new(ValidatorId::new(2), batch1_id)],
        vec![make_test_tx(0xFF, 0, 0x22)],
    );

    mempool
        .insert_remote_batch(batch2)
        .expect("remote batch insert should succeed");

    let stats = mempool.stats();
    assert_eq!(stats.num_batches, 2, "should have 2 batches");
    assert_eq!(stats.num_edges, 1, "should have 1 parent edge");
}

/// Test that duplicate batch insertion is handled gracefully (idempotent).
#[test]
fn test_duplicate_batch_insertion() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    let batch = QbindBatch::new(
        ValidatorId::new(2),
        0,
        vec![],
        vec![make_test_tx(0xAA, 0, 0x11)],
    );

    // Insert the same batch twice
    mempool
        .insert_remote_batch(batch.clone())
        .expect("first insert should succeed");
    mempool
        .insert_remote_batch(batch)
        .expect("duplicate insert should succeed (idempotent)");

    let stats = mempool.stats();
    assert_eq!(stats.num_batches, 1, "should still have only 1 batch");
}

/// Test DAG structure with multiple validators.
#[test]
fn test_dag_with_multiple_validators() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Validator 2 creates batch
    let batch_v2 = QbindBatch::new(
        ValidatorId::new(2),
        0,
        vec![],
        vec![make_test_tx(0xAA, 0, 0x10)],
    );
    let batch_v2_id = batch_v2.batch_id;

    // Validator 3 creates batch
    let batch_v3 = QbindBatch::new(
        ValidatorId::new(3),
        0,
        vec![],
        vec![make_test_tx(0xBB, 0, 0x20)],
    );
    let batch_v3_id = batch_v3.batch_id;

    mempool.insert_remote_batch(batch_v2).unwrap();
    mempool.insert_remote_batch(batch_v3).unwrap();

    // Validator 4 creates batch referencing both
    let batch_v4 = QbindBatch::new(
        ValidatorId::new(4),
        1,
        vec![
            BatchRef::new(ValidatorId::new(2), batch_v2_id),
            BatchRef::new(ValidatorId::new(3), batch_v3_id),
        ],
        vec![make_test_tx(0xCC, 0, 0x30)],
    );

    mempool.insert_remote_batch(batch_v4).unwrap();

    let stats = mempool.stats();
    assert_eq!(stats.num_batches, 3, "should have 3 batches");
    assert_eq!(stats.num_edges, 2, "should have 2 edges from v4's batch");
}

// ============================================================================
// Part 3: Frontier Selection Tests
// ============================================================================

/// Test that frontier selection returns transactions in deterministic order.
#[test]
fn test_frontier_selection_deterministic() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100, // Large batch size to keep txs pending
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert 5 transactions
    let txs: Vec<_> = (0..5)
        .map(|i| make_test_tx(0xDD, i as u64, i as u8))
        .collect();
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    // Select multiple times and verify determinism
    let selected1 = mempool.select_frontier_txs(3);
    let selected2 = mempool.select_frontier_txs(3);
    let selected3 = mempool.select_frontier_txs(3);

    assert_eq!(selected1, selected2, "selection should be deterministic");
    assert_eq!(selected2, selected3, "selection should be deterministic");
    assert_eq!(selected1.len(), 3, "should select 3 txs");
}

/// Test that committed transactions are not returned in future selections.
#[test]
fn test_frontier_excludes_committed_txs() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert 5 transactions
    let txs: Vec<_> = (0..5)
        .map(|i| make_test_tx(0xEE, i as u64, i as u8))
        .collect();
    mempool
        .insert_local_txs(txs.clone())
        .expect("insert should succeed");

    // Mark first 2 as committed
    mempool.mark_committed(&txs[0..2]);

    // Select should not include committed
    let selected = mempool.select_frontier_txs(10);
    assert_eq!(selected.len(), 3, "should have 3 uncommitted txs");

    // Verify nonces start from 2
    for tx in &selected {
        assert!(tx.nonce >= 2, "committed txs should not be selected");
    }
}

/// Test that max_txs limit is respected in frontier selection.
#[test]
fn test_frontier_respects_max_txs() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert 10 transactions
    let txs: Vec<_> = (0..10)
        .map(|i| make_test_tx(0xFF, i as u64, i as u8))
        .collect();
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    // Select with different limits
    let selected_3 = mempool.select_frontier_txs(3);
    let selected_5 = mempool.select_frontier_txs(5);
    let selected_all = mempool.select_frontier_txs(100);

    assert_eq!(selected_3.len(), 3, "should select exactly 3");
    assert_eq!(selected_5.len(), 5, "should select exactly 5");
    assert_eq!(selected_all.len(), 10, "should select all 10");
}

// ============================================================================
// Part 4: Commit Cleanup Tests
// ============================================================================

/// Test that mark_committed updates internal state correctly.
#[test]
fn test_mark_committed_updates_state() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 2,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert 4 transactions (creates 2 batches)
    let txs: Vec<_> = (0..4)
        .map(|i| make_test_tx(0xAA, i as u64, i as u8))
        .collect();
    mempool
        .insert_local_txs(txs.clone())
        .expect("insert should succeed");

    let stats_before = mempool.stats();
    assert_eq!(stats_before.num_batches, 2);
    assert_eq!(stats_before.committed_txs, 0);

    // Mark all transactions as committed
    mempool.mark_committed(&txs);

    let stats_after = mempool.stats();
    assert_eq!(stats_after.committed_txs, 4, "should have 4 committed txs");
}

/// Test that pending transactions are cleaned up after commit.
#[test]
fn test_commit_cleans_pending_txs() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100, // Large batch size to keep txs pending
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert 5 transactions (all pending)
    let txs: Vec<_> = (0..5)
        .map(|i| make_test_tx(0xBB, i as u64, i as u8))
        .collect();
    mempool
        .insert_local_txs(txs.clone())
        .expect("insert should succeed");

    let stats_before = mempool.stats();
    assert_eq!(stats_before.pending_txs, 5, "all txs should be pending");

    // Mark all as committed
    mempool.mark_committed(&txs);

    let stats_after = mempool.stats();
    assert_eq!(stats_after.pending_txs, 0, "pending should be cleaned up");
}

// ============================================================================
// Part 5: Metrics Tests
// ============================================================================

/// Test that metrics track batches correctly.
#[test]
fn test_dag_mempool_metrics_tracking() {
    let metrics = Arc::new(DagMempoolMetrics::new());
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 2,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config).with_metrics(metrics.clone());

    // Insert transactions that create a batch
    let txs = vec![make_test_tx(0xCC, 0, 0x10), make_test_tx(0xCC, 1, 0x20)];
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    // Check metrics
    assert_eq!(metrics.batches_total(), 1, "should track 1 batch");
    assert!(metrics.txs_total() >= 2, "should track at least 2 txs");
}

/// Test that frontier selection increments metrics.
#[test]
fn test_frontier_selection_metrics() {
    let metrics = Arc::new(DagMempoolMetrics::new());
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config).with_metrics(metrics.clone());

    // Insert some transactions
    let txs = vec![make_test_tx(0xDD, 0, 0x10), make_test_tx(0xDD, 1, 0x20)];
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    // Select frontier multiple times
    let _ = mempool.select_frontier_txs(10);
    let _ = mempool.select_frontier_txs(10);

    // Check metrics
    assert_eq!(
        metrics.frontier_select_total(),
        2,
        "should track 2 selections"
    );
    assert!(
        metrics.frontier_txs_selected_total() > 0,
        "should track selected txs"
    );
}

/// Test metrics format output contains expected fields.
#[test]
fn test_dag_mempool_metrics_format() {
    let metrics = DagMempoolMetrics::new();
    metrics.inc_batches_total();
    metrics.inc_batches_total();
    metrics.inc_edges_total(5);
    metrics.inc_txs_total(10);
    metrics.inc_frontier_select_total();
    metrics.inc_frontier_txs_selected_total(3);

    let output = metrics.format_metrics();

    // Check expected metric lines
    assert!(
        output.contains("qbind_dag_batches_total 2"),
        "should include batches_total"
    );
    assert!(
        output.contains("qbind_dag_edges_total 5"),
        "should include edges_total"
    );
    assert!(
        output.contains("qbind_dag_txs_total 10"),
        "should include txs_total"
    );
    assert!(
        output.contains("qbind_dag_frontier_select_total 1"),
        "should include frontier_select_total"
    );
    assert!(
        output.contains("qbind_dag_frontier_txs_selected_total 3"),
        "should include frontier_txs_selected_total"
    );
}

// ============================================================================
// Part 6: Sign/Verify Tests
// ============================================================================

/// Test batch signing and verification round-trip with ML-DSA-44.
#[test]
fn test_batch_sign_verify_roundtrip() {
    // Generate a keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

    // Create a batch
    let creator = ValidatorId::new(42);
    let mut batch = QbindBatch::new(
        creator,
        5,
        vec![BatchRef::new(ValidatorId::new(1), [0xAA; 32])],
        vec![make_test_tx(0xBB, 0, 0x11), make_test_tx(0xCC, 1, 0x22)],
    );

    // Sign it
    batch.sign(&sk).expect("signing should succeed");
    assert!(batch.is_signed(), "batch should be signed");

    // Verify with correct public key
    batch
        .verify_signature(&pk_bytes)
        .expect("verification should succeed");
}

/// Test that verification fails with wrong public key.
#[test]
fn test_batch_verify_fails_with_wrong_key() {
    // Generate two keypairs
    let (_pk1_bytes, sk1) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let (pk2_bytes, _sk2) = MlDsa44Backend::generate_keypair().expect("keygen failed");

    // Create and sign a batch with sk1
    let creator = ValidatorId::new(42);
    let mut batch = QbindBatch::new(creator, 5, vec![], vec![make_test_tx(0xDD, 0, 0x33)]);
    batch.sign(&sk1).expect("signing should succeed");

    // Verify with wrong public key (pk2)
    let result = batch.verify_signature(&pk2_bytes);
    assert!(result.is_err(), "verification should fail with wrong key");
}

// ============================================================================
// Part 7: Transaction Deduplication Tests
// ============================================================================

/// Test that duplicate transactions are filtered on insertion.
#[test]
fn test_transaction_deduplication() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    let tx = make_test_tx(0xEE, 0, 0x11);

    // Insert same transaction twice
    mempool
        .insert_local_txs(vec![tx.clone()])
        .expect("first insert should succeed");
    mempool
        .insert_local_txs(vec![tx])
        .expect("duplicate insert should succeed");

    let stats = mempool.stats();
    assert_eq!(stats.pending_txs, 1, "duplicate should be filtered");
}

/// Test that tx_id computation is consistent.
#[test]
fn test_tx_id_consistency() {
    let tx = make_test_tx(0xFF, 42, 0x77);

    let id1 = compute_tx_id(&tx);
    let id2 = compute_tx_id(&tx);

    assert_eq!(id1, id2, "tx_id should be consistent");
}

// ============================================================================
// Part 8: Capacity Limits Tests
// ============================================================================

/// Test that mempool rejects when at capacity.
#[test]
fn test_mempool_capacity_limit() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 100, // Large batch size so txs stay pending
        max_batches: 100,
        max_pending_txs: 5, // Very small limit
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_config(config);

    // Insert up to limit
    let txs: Vec<_> = (0..5)
        .map(|i| make_test_tx(0xAA, i as u64, i as u8))
        .collect();
    mempool
        .insert_local_txs(txs)
        .expect("insert should succeed");

    // Try to insert more - should fail
    let result = mempool.insert_local_txs(vec![make_test_tx(0xBB, 0, 0x99)]);
    assert!(result.is_err(), "should reject when full");
}
