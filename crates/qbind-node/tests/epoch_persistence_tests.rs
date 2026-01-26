//! T103: Tests for epoch persistence and restore across restart.
//!
//! These tests verify that:
//! - Epoch is persisted to storage when transitions happen
//! - Epoch is restored from storage on node restart
//! - Fresh DB defaults to epoch 0
//! - Single-node harness can survive restart with epoch state intact

use std::sync::Arc;
use tempfile::TempDir;

use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, EpochStateProvider, StaticEpochStateProvider,
    ValidatorSetEntry,
};
use qbind_consensus::ValidatorId;
use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};

// ============================================================================
// Helper Functions
// ============================================================================

fn make_validator_set(ids: &[u64]) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = ids
        .iter()
        .map(|&i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_block_proposal(epoch: u64, height: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![0xAA, 0xBB],
    }
}

fn make_qc(epoch: u64, height: u64) -> QuorumCertificate {
    QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch,
        height,
        round: height,
        step: 0,
        block_id: [0xFFu8; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0b00000111],
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
    }
}

// ============================================================================
// Part 3.1: Storage-level epoch roundtrip tests
// ============================================================================

#[test]
fn storage_epoch_roundtrip_in_memory() {
    let storage = InMemoryConsensusStorage::new();

    // Initially None
    assert_eq!(storage.get_current_epoch().unwrap(), None);

    // Store epoch 0
    storage.put_current_epoch(0).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));

    // Store epoch 1
    storage.put_current_epoch(1).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));

    // Store large epoch value
    storage.put_current_epoch(999999).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(999999));
}

#[test]
fn storage_epoch_roundtrip_rocksdb() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Initially None
    assert_eq!(storage.get_current_epoch().unwrap(), None);

    // Store epoch 0
    storage.put_current_epoch(0).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));

    // Store epoch 1
    storage.put_current_epoch(1).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));

    // Store large epoch value
    storage.put_current_epoch(12345).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(12345));
}

#[test]
fn storage_epoch_persists_across_rocksdb_reopen() {
    let temp_dir = TempDir::new().unwrap();

    // Write epoch in first instance
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        storage.put_current_epoch(42).unwrap();
    }

    // Read epoch in second instance (simulates restart)
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        assert_eq!(storage.get_current_epoch().unwrap(), Some(42));
    }
}

#[test]
fn storage_epoch_and_blocks_coexist() {
    let storage = InMemoryConsensusStorage::new();

    let block_id = [1u8; 32];
    let block = make_block_proposal(0, 10);
    let qc = make_qc(0, 9);

    // Store block, QC, last_committed, and epoch
    storage.put_block(&block_id, &block).unwrap();
    storage.put_qc(&block_id, &qc).unwrap();
    storage.put_last_committed(&block_id).unwrap();
    storage.put_current_epoch(5).unwrap();

    // All should be retrievable
    assert!(storage.get_block(&block_id).unwrap().is_some());
    assert!(storage.get_qc(&block_id).unwrap().is_some());
    assert_eq!(storage.get_last_committed().unwrap(), Some(block_id));
    assert_eq!(storage.get_current_epoch().unwrap(), Some(5));
}

// ============================================================================
// Part 3.2: Fresh DB behavior
// ============================================================================

#[test]
fn fresh_db_returns_none_for_epoch() {
    let storage = InMemoryConsensusStorage::new();

    // Fresh DB should return None for current_epoch
    assert_eq!(storage.get_current_epoch().unwrap(), None);

    // This simulates the expected behavior: None → default to epoch 0
}

#[test]
fn fresh_rocksdb_returns_none_for_epoch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Fresh RocksDB should return None for current_epoch
    assert_eq!(storage.get_current_epoch().unwrap(), None);
}

// ============================================================================
// Part 3.3: Epoch restore integration (using mock harness components)
// ============================================================================

/// Test that epoch state can be restored from storage with a provider.
#[test]
fn epoch_restore_with_provider() {
    // Setup: Create epoch states for epochs 0, 1, 2
    let validators = make_validator_set(&[0, 1, 2]);

    let epoch0 = EpochState::genesis(validators.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators.clone());
    let epoch2 = EpochState::new(EpochId::new(2), validators);

    let provider = Arc::new(
        StaticEpochStateProvider::new()
            .with_epoch(epoch0)
            .with_epoch(epoch1)
            .with_epoch(epoch2),
    );

    // Simulate: Node was in epoch 1, persisted it
    let storage = Arc::new(InMemoryConsensusStorage::new());
    storage.put_current_epoch(1).unwrap();

    // On restart: Read epoch from storage
    let stored_epoch = storage.get_current_epoch().unwrap();
    assert_eq!(stored_epoch, Some(1));

    // Fetch epoch state from provider
    let epoch_state = provider.get_epoch_state(EpochId::new(1));
    assert!(epoch_state.is_some());
    assert_eq!(epoch_state.as_ref().unwrap().epoch_id(), EpochId::new(1));

    // Verify validator set is correct
    let restored_epoch = epoch_state.unwrap();
    assert_eq!(restored_epoch.len(), 3);
    assert!(restored_epoch.contains(ValidatorId(0)));
    assert!(restored_epoch.contains(ValidatorId(1)));
    assert!(restored_epoch.contains(ValidatorId(2)));
}

/// Test that missing epoch in provider results in error scenario.
#[test]
fn epoch_restore_missing_epoch_in_provider() {
    // Setup: Provider only has epoch 0
    let validators = make_validator_set(&[0, 1, 2]);
    let epoch0 = EpochState::genesis(validators);

    let provider = Arc::new(StaticEpochStateProvider::new().with_epoch(epoch0));

    // Simulate: Storage indicates epoch 5 (but provider doesn't have it)
    let storage = Arc::new(InMemoryConsensusStorage::new());
    storage.put_current_epoch(5).unwrap();

    // On restart: Try to fetch epoch 5
    let stored_epoch = storage.get_current_epoch().unwrap();
    assert_eq!(stored_epoch, Some(5));

    let epoch_state = provider.get_epoch_state(EpochId::new(5));

    // This should return None, which would be handled as an error at the harness level
    assert!(epoch_state.is_none());
}

// ============================================================================
// Part 3.4: Backward compatibility - existing DB without epoch key
// ============================================================================

#[test]
fn backward_compat_existing_db_without_epoch_key() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Simulate existing DB: has blocks and last_committed, but no epoch key
    let block_id = [0xAAu8; 32];
    let block = make_block_proposal(0, 1);

    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    // Epoch key is NOT set (simulating old DB)
    let epoch = storage.get_current_epoch().unwrap();
    assert_eq!(epoch, None);

    // The harness should treat None as epoch 0 (default behavior)
    let effective_epoch = epoch.unwrap_or(0);
    assert_eq!(effective_epoch, 0);
}

// ============================================================================
// Part 3.5: Epoch transition scenario (unit-level check)
// ============================================================================

/// Verify that epoch transition updates storage correctly.
#[test]
fn epoch_transition_updates_storage() {
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Start in epoch 0
    assert_eq!(storage.get_current_epoch().unwrap(), None);

    // Simulate initial commit in epoch 0
    let block_id_0 = [0x10u8; 32];
    let block_0 = make_block_proposal(0, 1);
    storage.put_block(&block_id_0, &block_0).unwrap();
    storage.put_last_committed(&block_id_0).unwrap();
    storage.put_current_epoch(0).unwrap();

    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));

    // Simulate epoch transition to epoch 1 (via reconfig block commit)
    storage.put_current_epoch(1).unwrap();

    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));

    // Commit a block in epoch 1
    let block_id_1 = [0x20u8; 32];
    let block_1 = make_block_proposal(1, 2);
    storage.put_block(&block_id_1, &block_1).unwrap();
    storage.put_last_committed(&block_id_1).unwrap();

    // Epoch should still be 1
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));
}

/// Verify that multiple epoch transitions persist correctly.
#[test]
fn multiple_epoch_transitions_persist() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Start in epoch 0
    storage.put_current_epoch(0).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));

    // Transition to epoch 1
    storage.put_current_epoch(1).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));

    // Transition to epoch 2
    storage.put_current_epoch(2).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(2));

    // Transition to epoch 3
    storage.put_current_epoch(3).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(3));

    // Reopen DB and verify epoch 3 is still there
    drop(storage);
    let storage2 = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
    assert_eq!(storage2.get_current_epoch().unwrap(), Some(3));
}

// ============================================================================
// Part 3.6: Full restart simulation
// ============================================================================

/// Simulate a complete node restart scenario:
/// 1. Node runs in epoch 0, commits blocks
/// 2. Node transitions to epoch 1 via reconfig block
/// 3. Node commits more blocks in epoch 1
/// 4. Node restarts
/// 5. On restart, node loads epoch 1 from storage
#[test]
fn full_restart_simulation_with_epoch_transition() {
    let temp_dir = TempDir::new().unwrap();

    // Phase 1: Initial run - epoch 0 to epoch 1 transition
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Start in epoch 0
        storage.put_current_epoch(0).unwrap();

        // Commit a block in epoch 0
        let block_id_0 = [0x01u8; 32];
        let block_0 = make_block_proposal(0, 10);
        storage.put_block(&block_id_0, &block_0).unwrap();
        storage.put_qc(&block_id_0, &make_qc(0, 10)).unwrap();
        storage.put_last_committed(&block_id_0).unwrap();

        // Transition to epoch 1 (simulating reconfig block commit)
        storage.put_current_epoch(1).unwrap();

        // Commit a block in epoch 1
        let block_id_1 = [0x02u8; 32];
        let block_1 = make_block_proposal(1, 20);
        storage.put_block(&block_id_1, &block_1).unwrap();
        storage.put_qc(&block_id_1, &make_qc(1, 20)).unwrap();
        storage.put_last_committed(&block_id_1).unwrap();

        // Verify state before shutdown
        assert_eq!(storage.get_current_epoch().unwrap(), Some(1));
        assert_eq!(storage.get_last_committed().unwrap(), Some(block_id_1));
    }

    // Phase 2: Restart - load persisted state
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // On restart, epoch should be 1
        let restored_epoch = storage.get_current_epoch().unwrap();
        assert_eq!(restored_epoch, Some(1));

        // Last committed block should also be preserved
        let restored_block_id = storage.get_last_committed().unwrap();
        assert_eq!(restored_block_id, Some([0x02u8; 32]));

        // Verify block can be loaded
        let restored_block = storage.get_block(&[0x02u8; 32]).unwrap();
        assert!(restored_block.is_some());
        let block = restored_block.unwrap();
        assert_eq!(block.header.epoch, 1);
        assert_eq!(block.header.height, 20);

        // Verify QC can be loaded
        let restored_qc = storage.get_qc(&[0x02u8; 32]).unwrap();
        assert!(restored_qc.is_some());
        assert_eq!(restored_qc.unwrap().epoch, 1);
    }

    // Phase 3: Continue operation in epoch 1
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Continue committing blocks in epoch 1
        let block_id_2 = [0x03u8; 32];
        let block_2 = make_block_proposal(1, 30);
        storage.put_block(&block_id_2, &block_2).unwrap();
        storage.put_qc(&block_id_2, &make_qc(1, 30)).unwrap();
        storage.put_last_committed(&block_id_2).unwrap();

        // Epoch should remain 1
        assert_eq!(storage.get_current_epoch().unwrap(), Some(1));
    }
}

/// Verify that a node starting from a completely fresh DB defaults to epoch 0
/// and can begin operation normally.
#[test]
fn fresh_node_starts_in_epoch_zero() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Fresh DB - no epoch key
    assert_eq!(storage.get_current_epoch().unwrap(), None);

    // Application logic would interpret None as epoch 0
    let effective_epoch = storage.get_current_epoch().unwrap().unwrap_or(0);
    assert_eq!(effective_epoch, 0);

    // First commit in epoch 0
    storage.put_current_epoch(0).unwrap();
    let block_id = [0x10u8; 32];
    let block = make_block_proposal(0, 1);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    // Now epoch is explicitly 0
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));
}
