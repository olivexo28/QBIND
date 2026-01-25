//! Tests for RocksDB-backed consensus storage.
//!
//! These tests verify:
//! - Block storage roundtrip (including suite_id preservation)
//! - QC storage roundtrip (including suite_id preservation)
//! - Last committed block_id roundtrip
//! - Non-existent key handling

use cano_node::storage::{ConsensusStorage, RocksDbConsensusStorage};
use cano_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};

use tempfile::TempDir;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test BlockProposal with specified height and suite_id.
fn make_test_proposal(height: u64, suite_id: u16, proposer_index: u16) -> BlockProposal {
    // Create a parent_block_id that varies with height for uniqueness
    let mut parent = [0u8; 32];
    parent[0..8].copy_from_slice(&(height.saturating_sub(1)).to_le_bytes());

    // Create a payload hash that varies with proposer
    let mut payload_hash = [0u8; 32];
    payload_hash[0..2].copy_from_slice(&proposer_index.to_le_bytes());
    payload_hash[2..10].copy_from_slice(&height.to_le_bytes());

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: height,
            parent_block_id: parent,
            payload_hash,
            proposer_index,
            suite_id,
            tx_count: 2,
            timestamp: 1704067200 + height, // Unique timestamp per height
            payload_kind: cano_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![
            vec![1, 2, 3, 4],    // Dummy tx 1
            vec![5, 6, 7, 8, 9], // Dummy tx 2
        ],
        signature: vec![0xAB, 0xCD, 0xEF],
    }
}

/// Create a test BlockProposal with an embedded QC.
fn make_test_proposal_with_qc(
    height: u64,
    header_suite_id: u16,
    qc_suite_id: u16,
) -> BlockProposal {
    let mut proposal = make_test_proposal(height, header_suite_id, 0);
    proposal.qc = Some(make_test_qc(height - 1, qc_suite_id));
    proposal
}

/// Create a test QuorumCertificate with specified height and suite_id.
fn make_test_qc(height: u64, suite_id: u16) -> QuorumCertificate {
    // Create a block_id that varies with height
    let mut block_id = [0u8; 32];
    block_id[0..8].copy_from_slice(&height.to_le_bytes());
    // suite_id is u16 (2 bytes), copy to correct slice length
    block_id[8..10].copy_from_slice(&suite_id.to_le_bytes());

    QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id,
        signer_bitmap: vec![0b00001111], // 4 signers
        signatures: vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ],
    }
}

/// Create a unique block_id for testing.
fn make_block_id(seed: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0..8].copy_from_slice(&seed.to_le_bytes());
    id[24..32].copy_from_slice(&seed.to_le_bytes());
    id
}

// ============================================================================
// RocksDB Storage Tests
// ============================================================================

#[test]
fn rocksdb_storage_open_creates_db() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let storage = RocksDbConsensusStorage::open(&db_path);
    assert!(storage.is_ok(), "Should be able to open new database");

    // Check that the directory was created
    assert!(db_path.exists(), "Database directory should exist");
}

#[test]
fn rocksdb_storage_put_get_block_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let block_id = make_block_id(1);
    let block = make_test_proposal(10, 42, 5);

    // Store the block
    storage
        .put_block(&block_id, &block)
        .expect("put_block failed");

    // Retrieve and verify
    let retrieved = storage.get_block(&block_id).expect("get_block failed");
    assert!(retrieved.is_some(), "Block should be found");

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.header.height, 10);
    assert_eq!(retrieved.header.suite_id, 42, "suite_id must be preserved");
    assert_eq!(retrieved.header.proposer_index, 5);
    assert_eq!(retrieved.txs.len(), 2);
    assert_eq!(retrieved.signature, vec![0xAB, 0xCD, 0xEF]);
}

#[test]
fn rocksdb_storage_put_get_block_with_non_default_suite_id() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Test with various suite_id values
    for suite_id in [0, 1, 42, 999, 65535_u16] {
        let block_id = make_block_id(suite_id as u64);
        let block = make_test_proposal(100, suite_id, 0);

        storage
            .put_block(&block_id, &block)
            .expect("put_block failed");

        let retrieved = storage
            .get_block(&block_id)
            .expect("get_block failed")
            .unwrap();
        assert_eq!(
            retrieved.header.suite_id, suite_id,
            "suite_id {} must roundtrip correctly",
            suite_id
        );
    }
}

#[test]
fn rocksdb_storage_put_get_block_with_embedded_qc() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let block_id = make_block_id(100);
    let block = make_test_proposal_with_qc(20, 111, 222);

    storage
        .put_block(&block_id, &block)
        .expect("put_block failed");

    let retrieved = storage
        .get_block(&block_id)
        .expect("get_block failed")
        .unwrap();
    assert_eq!(
        retrieved.header.suite_id, 111,
        "Header suite_id must be preserved"
    );

    let qc = retrieved.qc.expect("QC should be present");
    assert_eq!(qc.suite_id, 222, "QC suite_id must be preserved");
    assert_eq!(qc.height, 19);
}

#[test]
fn rocksdb_storage_put_get_qc_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let block_id = make_block_id(200);
    let qc = make_test_qc(50, 123);

    storage.put_qc(&block_id, &qc).expect("put_qc failed");

    let retrieved = storage.get_qc(&block_id).expect("get_qc failed");
    assert!(retrieved.is_some(), "QC should be found");

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.height, 50);
    assert_eq!(retrieved.suite_id, 123, "suite_id must be preserved");
    assert_eq!(retrieved.signatures.len(), 4);
}

#[test]
fn rocksdb_storage_put_get_qc_with_various_suite_ids() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    for suite_id in [0, 1, 42, 999, 65535_u16] {
        let block_id = make_block_id(300 + suite_id as u64);
        let qc = make_test_qc(100, suite_id);

        storage.put_qc(&block_id, &qc).expect("put_qc failed");

        let retrieved = storage.get_qc(&block_id).expect("get_qc failed").unwrap();
        assert_eq!(
            retrieved.suite_id, suite_id,
            "QC suite_id {} must roundtrip correctly",
            suite_id
        );
    }
}

#[test]
fn rocksdb_storage_last_committed_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Initially None
    let initial = storage
        .get_last_committed()
        .expect("get_last_committed failed");
    assert!(
        initial.is_none(),
        "Fresh database should have no last_committed"
    );

    // Set it
    let block_id = make_block_id(999);
    storage
        .put_last_committed(&block_id)
        .expect("put_last_committed failed");

    // Retrieve and verify
    let retrieved = storage
        .get_last_committed()
        .expect("get_last_committed failed");
    assert!(retrieved.is_some(), "Should have last_committed after put");
    assert_eq!(retrieved.unwrap(), block_id);

    // Update it
    let new_block_id = make_block_id(1000);
    storage
        .put_last_committed(&new_block_id)
        .expect("put_last_committed failed");

    let updated = storage
        .get_last_committed()
        .expect("get_last_committed failed");
    assert_eq!(
        updated.unwrap(),
        new_block_id,
        "last_committed should be updated"
    );
}

#[test]
fn rocksdb_storage_get_nonexistent_returns_none() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let block_id = make_block_id(12345);

    assert!(storage
        .get_block(&block_id)
        .expect("get_block failed")
        .is_none());
    assert!(storage.get_qc(&block_id).expect("get_qc failed").is_none());
}

#[test]
fn rocksdb_storage_block_and_qc_keys_do_not_collide() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Use the same block_id for both block and QC
    let block_id = make_block_id(42);
    let block = make_test_proposal(10, 100, 0);
    let qc = make_test_qc(10, 200);

    storage
        .put_block(&block_id, &block)
        .expect("put_block failed");
    storage.put_qc(&block_id, &qc).expect("put_qc failed");

    // Retrieve both and verify they are distinct
    let retrieved_block = storage
        .get_block(&block_id)
        .expect("get_block failed")
        .unwrap();
    let retrieved_qc = storage.get_qc(&block_id).expect("get_qc failed").unwrap();

    assert_eq!(
        retrieved_block.header.suite_id, 100,
        "Block must have its own suite_id"
    );
    assert_eq!(retrieved_qc.suite_id, 200, "QC must have its own suite_id");
}

#[test]
fn rocksdb_storage_persists_across_reopen() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");

    let block_id = make_block_id(777);
    let block = make_test_proposal(30, 42, 1);
    let qc = make_test_qc(29, 43);
    let last_committed = make_block_id(778);

    // Open, write, close
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");
        storage
            .put_block(&block_id, &block)
            .expect("put_block failed");
        storage.put_qc(&block_id, &qc).expect("put_qc failed");
        storage
            .put_last_committed(&last_committed)
            .expect("put_last_committed failed");
    }

    // Reopen and verify persistence
    {
        let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to reopen database");

        let retrieved_block = storage
            .get_block(&block_id)
            .expect("get_block failed")
            .unwrap();
        assert_eq!(retrieved_block.header.height, 30);
        assert_eq!(retrieved_block.header.suite_id, 42, "suite_id must persist");

        let retrieved_qc = storage.get_qc(&block_id).expect("get_qc failed").unwrap();
        assert_eq!(retrieved_qc.height, 29);
        assert_eq!(retrieved_qc.suite_id, 43, "QC suite_id must persist");

        let retrieved_last = storage
            .get_last_committed()
            .expect("get_last_committed failed")
            .unwrap();
        assert_eq!(
            retrieved_last, last_committed,
            "last_committed must persist"
        );
    }
}

#[test]
fn rocksdb_storage_multiple_blocks_and_qcs() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    // Store multiple blocks and QCs
    for i in 0..10_u64 {
        let block_id = make_block_id(i);
        let block = make_test_proposal(i, (i * 10) as u16, (i % 3) as u16);
        let qc = make_test_qc(i, ((i + 1) * 10) as u16);

        storage
            .put_block(&block_id, &block)
            .expect("put_block failed");
        storage.put_qc(&block_id, &qc).expect("put_qc failed");
    }

    // Verify all of them
    for i in 0..10_u64 {
        let block_id = make_block_id(i);

        let block = storage
            .get_block(&block_id)
            .expect("get_block failed")
            .unwrap();
        assert_eq!(block.header.height, i);
        assert_eq!(block.header.suite_id, (i * 10) as u16);

        let qc = storage.get_qc(&block_id).expect("get_qc failed").unwrap();
        assert_eq!(qc.height, i);
        assert_eq!(qc.suite_id, ((i + 1) * 10) as u16);
    }
}

#[test]
fn rocksdb_storage_overwrite_block() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbConsensusStorage::open(&db_path).expect("Failed to open database");

    let block_id = make_block_id(888);

    // Store original
    let block1 = make_test_proposal(10, 100, 0);
    storage
        .put_block(&block_id, &block1)
        .expect("put_block failed");

    // Overwrite with different suite_id
    let block2 = make_test_proposal(10, 200, 0);
    storage
        .put_block(&block_id, &block2)
        .expect("put_block failed");

    // Should retrieve the newer one
    let retrieved = storage
        .get_block(&block_id)
        .expect("get_block failed")
        .unwrap();
    assert_eq!(retrieved.header.suite_id, 200, "Overwrite should work");
}
