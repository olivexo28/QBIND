//! Integration tests for storage latency metrics (T107).
//!
//! These tests verify that:
//! - Storage metrics increment on RocksDB writes
//! - Latency buckets are populated correctly
//! - Metrics are available via `NodeMetrics`

use std::sync::Arc;

use qbind_node::metrics::{NodeMetrics, StorageOp};
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};

use tempfile::TempDir;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test BlockProposal with specified height and suite_id.
fn make_test_proposal(height: u64, suite_id: u16) -> BlockProposal {
    let mut parent = [0u8; 32];
    parent[0..8].copy_from_slice(&(height.saturating_sub(1)).to_le_bytes());

    let mut payload_hash = [0u8; 32];
    payload_hash[0..8].copy_from_slice(&height.to_le_bytes());

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: height,
            parent_block_id: parent,
            payload_hash,
            proposer_index: 0,
            suite_id,
            tx_count: 0,
            timestamp: 1704067200 + height,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![0xAB, 0xCD],
    }
}

/// Create a test QuorumCertificate with specified height and suite_id.
fn make_test_qc(height: u64, suite_id: u16) -> QuorumCertificate {
    let mut block_id = [0u8; 32];
    block_id[0..8].copy_from_slice(&height.to_le_bytes());

    QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id,
        signer_bitmap: vec![0b00000111],
        signatures: vec![vec![1, 2, 3]],
    }
}

/// Create a unique block_id for testing.
fn make_block_id(seed: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0..8].copy_from_slice(&seed.to_le_bytes());
    id
}

// ============================================================================
// Storage Metrics Tests
// ============================================================================

#[test]
fn rocksdb_storage_with_metrics_records_put_block() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    let block_id = make_block_id(1);
    let block = make_test_proposal(10, 42);

    // Verify metrics are zero before operation
    assert_eq!(metrics.storage().op_count(StorageOp::PutBlock), 0);

    // Perform the operation
    storage
        .put_block(&block_id, &block)
        .expect("put_block failed");

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::PutBlock), 1);
    // Fast operations should typically be in the <1ms or 1-10ms bucket
    let (b1, b10, b100, over) = metrics.storage().op_buckets(StorageOp::PutBlock);
    assert_eq!(
        b1 + b10 + b100 + over,
        1,
        "One bucket should be incremented"
    );
    // For a simple put, we expect it to be in one of the faster buckets
    assert!(
        b1 > 0 || b10 > 0,
        "Fast storage operation should be in <1ms or 1-10ms bucket"
    );
}

#[test]
fn rocksdb_storage_with_metrics_records_put_qc() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    let block_id = make_block_id(2);
    let qc = make_test_qc(10, 42);

    // Perform the operation
    storage.put_qc(&block_id, &qc).expect("put_qc failed");

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::PutQc), 1);
}

#[test]
fn rocksdb_storage_with_metrics_records_put_last_committed() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    let block_id = make_block_id(3);

    // Perform the operation
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed failed");

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::PutLastCommitted), 1);
}

#[test]
fn rocksdb_storage_with_metrics_records_put_current_epoch() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    // Perform the operation
    storage
        .put_current_epoch(42)
        .expect("put_current_epoch failed");

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::PutCurrentEpoch), 1);
}

#[test]
fn rocksdb_storage_with_metrics_records_get_block() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    let block_id = make_block_id(4);

    // Perform a get (even if nothing is there)
    let _ = storage.get_block(&block_id);

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::GetBlock), 1);
}

#[test]
fn rocksdb_storage_with_metrics_records_get_qc() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    let block_id = make_block_id(5);

    // Perform a get (even if nothing is there)
    let _ = storage.get_qc(&block_id);

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::GetQc), 1);
}

#[test]
fn rocksdb_storage_with_metrics_records_get_last_committed() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    // Perform a get (even if nothing is there)
    let _ = storage.get_last_committed();

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::GetLastCommitted), 1);
}

#[test]
fn rocksdb_storage_with_metrics_records_get_current_epoch() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    // Perform a get (even if nothing is there)
    let _ = storage.get_current_epoch();

    // Verify metrics were incremented
    assert_eq!(metrics.storage().op_count(StorageOp::GetCurrentEpoch), 1);
}

#[test]
fn rocksdb_storage_with_metrics_multiple_operations() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let metrics = Arc::new(NodeMetrics::new());
    let storage = RocksDbConsensusStorage::open(&db_path)
        .expect("Failed to open database")
        .with_metrics(metrics.clone());

    // Perform multiple operations
    for i in 0..5u64 {
        let block_id = make_block_id(i);
        let block = make_test_proposal(i, 42);
        let qc = make_test_qc(i, 42);

        storage
            .put_block(&block_id, &block)
            .expect("put_block failed");
        storage.put_qc(&block_id, &qc).expect("put_qc failed");
        storage
            .put_last_committed(&block_id)
            .expect("put_last_committed failed");

        let _ = storage.get_block(&block_id);
        let _ = storage.get_qc(&block_id);
    }

    // Verify metrics were incremented correctly
    assert_eq!(metrics.storage().op_count(StorageOp::PutBlock), 5);
    assert_eq!(metrics.storage().op_count(StorageOp::PutQc), 5);
    assert_eq!(metrics.storage().op_count(StorageOp::PutLastCommitted), 5);
    assert_eq!(metrics.storage().op_count(StorageOp::GetBlock), 5);
    assert_eq!(metrics.storage().op_count(StorageOp::GetQc), 5);
}

#[test]
fn rocksdb_storage_without_metrics_works() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    // Open without metrics
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let block_id = make_block_id(1);
    let block = make_test_proposal(10, 42);

    // Operations should still work
    storage
        .put_block(&block_id, &block)
        .expect("put_block failed");
    let retrieved = storage.get_block(&block_id).expect("get_block failed");
    assert!(retrieved.is_some());
}

#[test]
fn storage_metrics_format_in_node_metrics() {
    let metrics = NodeMetrics::new();

    // Record some operations
    metrics
        .storage()
        .record(StorageOp::PutBlock, std::time::Duration::from_millis(5));
    metrics
        .storage()
        .record(StorageOp::GetBlock, std::time::Duration::from_micros(500));

    let output = metrics.format_metrics();

    // Verify storage metrics are included in the output
    assert!(output.contains("# Storage operation latency metrics (T107)"));
    assert!(output.contains("eezo_storage_op_duration_ms_count{op=\"put_block\"} 1"));
    assert!(output.contains("eezo_storage_op_duration_ms_count{op=\"get_block\"} 1"));
}
