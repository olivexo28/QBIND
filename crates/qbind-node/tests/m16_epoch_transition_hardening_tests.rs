//! M16: Epoch Transition Hardening Tests
//!
//! These tests verify that epoch transitions are atomic and crash-safe:
//! 1. All epoch-boundary writes commit together in a single RocksDB WriteBatch
//! 2. In-memory transition happens only after durable commit succeeds
//! 3. After any crash/restart, node loads self-consistent epoch state
//! 4. Incomplete transitions are detected and cause fail-closed behavior
//!
//! This closes Spec Gap 2.6 by eliminating crash windows where:
//! - validator set changes are partially applied
//! - slashing/jail eligibility and validator set diverge after restart
//! - "next epoch" markers advance without fully persisting required state

use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

use qbind_node::storage::{
    ConsensusStorage, EpochTransitionBatch, EpochTransitionMarker, RocksDbConsensusStorage,
    StorageError,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};
use qbind_wire::PAYLOAD_KIND_RECONFIG;

// ============================================================================
// Helper Functions
// ============================================================================

fn make_reconfig_proposal(height: u64, current_epoch: u64, next_epoch: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: current_epoch,
            height,
            round: height,
            parent_block_id: [0u8; 32],
            payload_hash: [1u8; 32],
            proposer_index: 0,
            suite_id: 0x0301,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: PAYLOAD_KIND_RECONFIG,
            next_epoch,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![1, 2, 3, 4],
    }
}

fn make_qc(height: u64, epoch: u64, block_id: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id: 0x0301,
        signer_bitmap: vec![0b00000111],
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
    }
}

fn make_block_id(seed: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = seed;
    id[31] = seed;
    id
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ============================================================================
// Test A: Atomic Epoch Transition Batch Success
// ============================================================================

/// M16.A1: Verify that atomic epoch transition batch commits all writes together.
#[test]
fn m16_a1_atomic_epoch_transition_commits_all_writes() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Set up initial state
    storage.put_current_epoch(0).unwrap();

    let block_id = make_block_id(42);
    let block = make_reconfig_proposal(100, 0, 1);
    let qc = make_qc(100, 0, block_id);

    // Create the atomic batch
    let mut batch = EpochTransitionBatch::new(1, 0, block_id);
    batch.set_block(block_id, block.clone());
    batch.set_qc(block_id, qc.clone());
    batch.set_update_last_committed(true);

    // Apply the atomic transition
    storage.apply_epoch_transition_atomic(batch).unwrap();

    // Verify all writes were applied
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));
    assert_eq!(storage.get_last_committed().unwrap(), Some(block_id));

    let stored_block = storage.get_block(&block_id).unwrap();
    assert!(stored_block.is_some());
    assert_eq!(stored_block.unwrap().header.height, 100);

    let stored_qc = storage.get_qc(&block_id).unwrap();
    assert!(stored_qc.is_some());
    assert_eq!(stored_qc.unwrap().height, 100);

    // Verify no incomplete transition marker
    let marker = storage.check_for_incomplete_epoch_transition().unwrap();
    assert!(marker.is_none());
}

/// M16.A2: Verify that atomic epoch transition survives restart.
#[test]
fn m16_a2_atomic_epoch_transition_survives_restart() {
    let temp_dir = TempDir::new().unwrap();

    let block_id = make_block_id(55);
    let block = make_reconfig_proposal(200, 1, 2);
    let qc = make_qc(200, 1, block_id);

    // First "run": apply atomic transition
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        storage.put_current_epoch(1).unwrap();

        let mut batch = EpochTransitionBatch::new(2, 1, block_id);
        batch.set_block(block_id, block);
        batch.set_qc(block_id, qc);
        batch.set_update_last_committed(true);

        storage.apply_epoch_transition_atomic(batch).unwrap();
    }

    // "Restart": reopen and verify all state
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Verify epoch consistency check passes
        storage.verify_epoch_consistency_on_startup().unwrap();

        // Verify all state is consistent
        assert_eq!(storage.get_current_epoch().unwrap(), Some(2));
        assert_eq!(storage.get_last_committed().unwrap(), Some(block_id));
        assert!(storage.get_block(&block_id).unwrap().is_some());
        assert!(storage.get_qc(&block_id).unwrap().is_some());
    }
}

// ============================================================================
// Test B: Failure Injection - No Partial State
// ============================================================================

/// M16.B1: Verify that injected write failure leaves no partial state.
#[test]
fn m16_b1_injected_write_failure_leaves_no_partial_state() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Set up initial state
    storage.put_current_epoch(0).unwrap();
    let initial_block_id = make_block_id(1);
    storage.put_last_committed(&initial_block_id).unwrap();

    let block_id = make_block_id(99);
    let block = make_reconfig_proposal(300, 0, 1);
    let qc = make_qc(300, 0, block_id);

    // Enable failure injection
    storage.set_inject_write_failure(true);

    // Create the atomic batch
    let mut batch = EpochTransitionBatch::new(1, 0, block_id);
    batch.set_block(block_id, block);
    batch.set_qc(block_id, qc);
    batch.set_update_last_committed(true);

    // Attempt the atomic transition - should fail
    let result = storage.apply_epoch_transition_atomic(batch);
    assert!(result.is_err());

    // Disable failure injection for subsequent reads
    storage.set_inject_write_failure(false);

    // Verify NO partial state was written
    assert_eq!(
        storage.get_current_epoch().unwrap(),
        Some(0),
        "Epoch should remain at 0 after failed transition"
    );
    assert_eq!(
        storage.get_last_committed().unwrap(),
        Some(initial_block_id),
        "Last committed should remain unchanged"
    );
    assert!(
        storage.get_block(&block_id).unwrap().is_none(),
        "Block should not be written"
    );
    assert!(
        storage.get_qc(&block_id).unwrap().is_none(),
        "QC should not be written"
    );
}

/// M16.B2: Verify that failed transition is invisible after restart.
#[test]
fn m16_b2_failed_transition_invisible_after_restart() {
    let temp_dir = TempDir::new().unwrap();
    let block_id = make_block_id(77);

    // First "run": set up initial state and attempt failed transition
    {
        let mut storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        storage.put_current_epoch(5).unwrap();
        let initial_block_id = make_block_id(10);
        storage.put_last_committed(&initial_block_id).unwrap();

        // Enable failure injection
        storage.set_inject_write_failure(true);

        let block = make_reconfig_proposal(400, 5, 6);
        let mut batch = EpochTransitionBatch::new(6, 5, block_id);
        batch.set_block(block_id, block);
        batch.set_update_last_committed(true);

        // Attempt and fail
        let result = storage.apply_epoch_transition_atomic(batch);
        assert!(result.is_err());
    }

    // "Restart": verify state is fully consistent at epoch 5
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Epoch consistency check should pass (no marker, old epoch intact)
        storage.verify_epoch_consistency_on_startup().unwrap();

        assert_eq!(storage.get_current_epoch().unwrap(), Some(5));
        assert_eq!(storage.get_last_committed().unwrap(), Some(make_block_id(10)));
        assert!(storage.get_block(&block_id).unwrap().is_none());
    }
}

// ============================================================================
// Test C: Epoch, Validator Set, Governance Activation Consistency
// ============================================================================

/// M16.C1: Verify epoch ID is atomically updated.
#[test]
fn m16_c1_epoch_id_atomically_updated() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Set initial epoch
    storage.put_current_epoch(10).unwrap();

    let block_id = make_block_id(88);
    let block = make_reconfig_proposal(500, 10, 11);

    let mut batch = EpochTransitionBatch::new(11, 10, block_id);
    batch.set_block(block_id, block);
    batch.set_update_last_committed(true);

    storage.apply_epoch_transition_atomic(batch).unwrap();

    // Verify epoch transition was atomic
    assert_eq!(storage.get_current_epoch().unwrap(), Some(11));
}

/// M16.C2: Verify multiple sequential transitions remain consistent.
#[test]
fn m16_c2_multiple_sequential_transitions_consistent() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    storage.put_current_epoch(0).unwrap();

    // Transition through epochs 1, 2, 3
    for epoch in 1..=3 {
        let block_id = make_block_id(epoch as u8);
        let block = make_reconfig_proposal(epoch * 100, epoch - 1, epoch);

        let mut batch = EpochTransitionBatch::new(epoch, epoch - 1, block_id);
        batch.set_block(block_id, block);
        batch.set_update_last_committed(true);

        storage.apply_epoch_transition_atomic(batch).unwrap();

        // Verify after each transition
        assert_eq!(storage.get_current_epoch().unwrap(), Some(epoch));
        assert_eq!(storage.get_last_committed().unwrap(), Some(block_id));
    }

    // Final verification
    assert_eq!(storage.get_current_epoch().unwrap(), Some(3));
    storage.verify_epoch_consistency_on_startup().unwrap();
}

// ============================================================================
// Test D: Recovery Logic - Detect Incomplete Transitions
// ============================================================================

/// M16.D1: Verify incomplete transition marker is detected on startup.
#[test]
fn m16_d1_incomplete_transition_detected_on_startup() {
    let temp_dir = TempDir::new().unwrap();

    let block_id = make_block_id(123);

    // First "run": write marker but don't complete transition (simulating crash)
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        storage.put_current_epoch(7).unwrap();

        // Write the transition marker (simulates start of transition)
        let marker = EpochTransitionMarker {
            target_epoch: 8,
            previous_epoch: 7,
            started_at_ms: current_time_ms(),
            reconfig_block_id: block_id,
        };
        storage.write_epoch_transition_marker(&marker).unwrap();

        // Simulate crash - don't call apply_epoch_transition_atomic
    }

    // "Restart": detect incomplete transition
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Check for incomplete transition marker
        let marker = storage.check_for_incomplete_epoch_transition().unwrap();
        assert!(marker.is_some());
        let marker = marker.unwrap();
        assert_eq!(marker.target_epoch, 8);
        assert_eq!(marker.previous_epoch, 7);
        assert_eq!(marker.reconfig_block_id, block_id);

        // Verify consistency check fails
        let result = storage.verify_epoch_consistency_on_startup();
        assert!(result.is_err());

        match result {
            Err(StorageError::IncompleteEpochTransition { epoch, details }) => {
                assert_eq!(epoch, 8);
                assert!(details.contains("epoch transition marker found"));
            }
            _ => panic!("Expected IncompleteEpochTransition error"),
        }
    }
}

/// M16.D2: Verify successful transition clears the marker.
#[test]
fn m16_d2_successful_transition_clears_marker() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    let block_id = make_block_id(200);
    storage.put_current_epoch(15).unwrap();

    // Write marker first (simulates the pre-transition state)
    let marker = EpochTransitionMarker {
        target_epoch: 16,
        previous_epoch: 15,
        started_at_ms: current_time_ms(),
        reconfig_block_id: block_id,
    };
    storage.write_epoch_transition_marker(&marker).unwrap();

    // Verify marker exists
    assert!(storage.check_for_incomplete_epoch_transition().unwrap().is_some());

    // Now apply the atomic transition (which clears the marker)
    let block = make_reconfig_proposal(1500, 15, 16);
    let mut batch = EpochTransitionBatch::new(16, 15, block_id);
    batch.set_block(block_id, block);
    batch.set_update_last_committed(true);

    storage.apply_epoch_transition_atomic(batch).unwrap();

    // Verify marker is cleared
    assert!(storage.check_for_incomplete_epoch_transition().unwrap().is_none());

    // Verify consistency check passes
    storage.verify_epoch_consistency_on_startup().unwrap();
}

/// M16.D3: Verify marker with mismatch causes fail-closed.
#[test]
fn m16_d3_marker_mismatch_causes_fail_closed() {
    let temp_dir = TempDir::new().unwrap();

    // First "run": write marker for epoch 20, but only advance epoch to 19
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        storage.put_current_epoch(19).unwrap();

        // Write marker for a future transition that never happened
        let marker = EpochTransitionMarker {
            target_epoch: 20,
            previous_epoch: 19,
            started_at_ms: current_time_ms(),
            reconfig_block_id: make_block_id(255),
        };
        storage.write_epoch_transition_marker(&marker).unwrap();

        // Simulate crash without completing transition
    }

    // "Restart": should fail-closed
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Current epoch is 19, but marker says we were transitioning to 20
        assert_eq!(storage.get_current_epoch().unwrap(), Some(19));

        // Consistency check should fail
        let result = storage.verify_epoch_consistency_on_startup();
        assert!(result.is_err());
    }
}

// ============================================================================
// Test E: Edge Cases
// ============================================================================

/// M16.E1: Verify fresh database has no incomplete transition.
#[test]
fn m16_e1_fresh_database_no_incomplete_transition() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Fresh DB should have no marker
    assert!(storage.check_for_incomplete_epoch_transition().unwrap().is_none());

    // Consistency check should pass
    storage.verify_epoch_consistency_on_startup().unwrap();
}

/// M16.E2: Verify transition with no block/QC still updates epoch atomically.
#[test]
fn m16_e2_transition_without_block_qc_updates_epoch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    storage.put_current_epoch(100).unwrap();

    // Minimal batch - just epoch update
    let batch = EpochTransitionBatch::new(101, 100, make_block_id(1));

    storage.apply_epoch_transition_atomic(batch).unwrap();

    assert_eq!(storage.get_current_epoch().unwrap(), Some(101));
    storage.verify_epoch_consistency_on_startup().unwrap();
}

/// M16.E3: Verify error type contains useful diagnostic info.
#[test]
fn m16_e3_error_contains_diagnostic_info() {
    let error = StorageError::IncompleteEpochTransition {
        epoch: 42,
        details: "test details".to_string(),
    };

    let display = format!("{}", error);
    assert!(display.contains("42"));
    assert!(display.contains("test details"));
    assert!(display.contains("FATAL"));
    assert!(display.contains("incomplete epoch transition"));
}

/// M16.E4: Verify test-only clear marker method works.
#[test]
fn m16_e4_test_clear_marker_method() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Write a marker
    let marker = EpochTransitionMarker {
        target_epoch: 5,
        previous_epoch: 4,
        started_at_ms: current_time_ms(),
        reconfig_block_id: make_block_id(50),
    };
    storage.write_epoch_transition_marker(&marker).unwrap();

    // Verify marker exists
    assert!(storage.check_for_incomplete_epoch_transition().unwrap().is_some());

    // Clear it using test helper
    storage.clear_epoch_transition_marker().unwrap();

    // Verify marker is gone
    assert!(storage.check_for_incomplete_epoch_transition().unwrap().is_none());
}

// ============================================================================
// Test F: Concurrent/Interleaved Operations
// ============================================================================

/// M16.F1: Verify normal operations after successful transition.
#[test]
fn m16_f1_normal_operations_after_transition() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    storage.put_current_epoch(0).unwrap();

    // Apply atomic transition
    let block_id = make_block_id(1);
    let block = make_reconfig_proposal(100, 0, 1);
    let mut batch = EpochTransitionBatch::new(1, 0, block_id);
    batch.set_block(block_id, block);
    batch.set_update_last_committed(true);

    storage.apply_epoch_transition_atomic(batch).unwrap();

    // Normal operations should work
    let normal_block_id = make_block_id(2);
    let normal_block = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 1,
            height: 101,
            round: 101,
            parent_block_id: block_id,
            payload_hash: [2u8; 32],
            proposer_index: 0,
            suite_id: 0x0301,
            tx_count: 0,
            timestamp: 1234567891,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![5, 6, 7, 8],
    };

    storage.put_block(&normal_block_id, &normal_block).unwrap();
    storage.put_last_committed(&normal_block_id).unwrap();

    // Verify
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));
    assert_eq!(storage.get_last_committed().unwrap(), Some(normal_block_id));
    assert!(storage.get_block(&normal_block_id).unwrap().is_some());
}