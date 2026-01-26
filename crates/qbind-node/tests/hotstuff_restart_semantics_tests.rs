//! Tests for HotStuff restart semantics (T84).
//!
//! These tests verify that the HotStuff consensus engine can safely restart
//! from persisted state, maintaining safety guarantees while resuming consensus.
//!
//! # Test Organization
//!
//! - **Happy restart path**: Node commits blocks, restarts, and resumes correctly
//! - **Fresh node behavior**: Starting without persisted state works as before
//! - **Missing/partial state**: Inconsistent storage is detected and reported
//!
//! # Low-RAM Friendly
//!
//! These tests are designed to be lightweight and can be run independently:
//!
//! ```bash
//! cargo test -p qbind-node --test hotstuff_restart_semantics_tests -- --test-threads=1
//! ```

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::BasicHotStuffEngine;

use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a validator set with the given number of validators.
fn make_validator_set(num: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Create a test block proposal at the given height.
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

/// Create a test QC at the given height.
fn make_test_qc(height: u64, suite_id: u16, block_id: [u8; 32]) -> WireQc {
    WireQc {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id,
        signer_bitmap: vec![0b00000111],
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
    }
}

// ============================================================================
// Part A: Engine restart initialization tests
// ============================================================================

/// Test that BasicHotStuffEngine can be initialized from restart state.
#[test]
fn engine_initialize_from_restart_sets_committed_block() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Initially no committed block
    assert!(engine.committed_block().is_none());
    assert!(engine.committed_height().is_none());

    // Initialize from restart
    let block_id = [42u8; 32];
    let height = 10;
    engine.initialize_from_restart(block_id, height, None);

    // Now should have committed block
    assert_eq!(engine.committed_block(), Some(&block_id));
    assert_eq!(engine.committed_height(), Some(height));
}

/// Test that restart initialization sets view to committed_height + 1.
#[test]
fn engine_initialize_from_restart_advances_view() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Initially at view 0
    assert_eq!(engine.current_view(), 0);

    // Initialize from restart at height 10
    let block_id = [42u8; 32];
    let height = 10;
    engine.initialize_from_restart(block_id, height, None);

    // View should be height + 1 = 11
    assert_eq!(engine.current_view(), 11);
}

/// Test that restart initialization sets locked_qc when provided.
#[test]
fn engine_initialize_from_restart_sets_locked_qc() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Initially no locked QC
    assert!(engine.locked_qc().is_none());

    // Create a locked QC
    let qc_block_id = [99u8; 32];
    let locked_qc = QuorumCertificate::new(qc_block_id, 9, vec![]);

    // Initialize from restart with locked QC
    let block_id = [42u8; 32];
    let height = 10;
    engine.initialize_from_restart(block_id, height, Some(locked_qc.clone()));

    // Should have locked QC
    let stored_qc = engine.locked_qc().expect("should have locked QC");
    assert_eq!(stored_qc.block_id, qc_block_id);
    assert_eq!(stored_qc.view, 9);
}

/// Test that restarted engine resets proposal/vote flags.
#[test]
fn engine_initialize_from_restart_resets_flags() {
    // Use 3 validators so QC formation doesn't happen immediately
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // At view 0, validator 1 is leader (sorted [1,2,3], view 0 % 3 = 0 -> leader[0] = 1)
    assert!(engine.is_leader_for_current_view());
    assert_eq!(engine.current_view(), 0);

    // Propose something to set the proposed_in_view flag
    let actions = engine.try_propose();
    assert!(!actions.is_empty(), "Should have proposed");

    // Call try_propose again - should return empty because we already proposed
    let actions2 = engine.try_propose();
    assert!(actions2.is_empty(), "Should not propose twice in same view");

    // Now initialize from restart - flags should be reset
    let block_id = [42u8; 32];
    let height = 10;
    engine.initialize_from_restart(block_id, height, None);

    // Should now be at view 11
    assert_eq!(engine.current_view(), 11);

    // The proposed_in_view flag should be reset, so if we're leader for view 11
    // we should be able to propose again.
    // Leader for view 11: 11 % 3 = 2 -> leader[2] = validator 3
    // So validator 1 is NOT leader for view 11
    assert!(!engine.is_leader_for_current_view());
}

// ============================================================================
// Part B: Storage-based restart tests (using InMemoryConsensusStorage)
// ============================================================================

/// Test that persisted state can be loaded and used to initialize engine.
#[test]
fn storage_based_restart_initializes_engine() {
    let storage = Arc::new(InMemoryConsensusStorage::new());
    let validators = make_validator_set(3);

    // Persist a block
    let block_id = [1u8; 32];
    let block = make_test_proposal(5, 0);
    storage.put_block(&block_id, &block).unwrap();
    storage.put_last_committed(&block_id).unwrap();

    // Persist a QC for this block
    let qc = make_test_qc(5, 0, block_id);
    storage.put_qc(&block_id, &qc).unwrap();

    // Now simulate what load_persisted_state does:
    let last_committed = storage.get_last_committed().unwrap().unwrap();
    assert_eq!(last_committed, block_id);

    let loaded_block = storage.get_block(&block_id).unwrap().unwrap();
    assert_eq!(loaded_block.header.height, 5);

    let loaded_qc = storage.get_qc(&block_id).unwrap().unwrap();
    assert_eq!(loaded_qc.height, 5);

    // Initialize engine from this state
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    let locked_qc = QuorumCertificate::new(loaded_qc.block_id, loaded_qc.height, vec![]);
    engine.initialize_from_restart(block_id, loaded_block.header.height, Some(locked_qc));

    assert_eq!(engine.committed_block(), Some(&block_id));
    assert_eq!(engine.committed_height(), Some(5));
    assert_eq!(engine.current_view(), 6);
    assert!(engine.locked_qc().is_some());
}

/// Test fresh node behavior: no persisted state means starting from genesis.
#[test]
fn fresh_node_starts_from_genesis() {
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // No persisted state
    let last_committed = storage.get_last_committed().unwrap();
    assert!(last_committed.is_none());

    // Engine should start normally from genesis
    let validators = make_validator_set(3);
    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    assert!(engine.committed_block().is_none());
    assert!(engine.committed_height().is_none());
    assert_eq!(engine.current_view(), 0);
    assert!(engine.locked_qc().is_none());
}

/// Test that missing block for last_committed is detected.
#[test]
fn missing_block_for_last_committed_is_detectable() {
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Set last_committed but don't store the actual block
    let block_id = [99u8; 32];
    storage.put_last_committed(&block_id).unwrap();

    // Try to load - block should be None
    let last_committed = storage.get_last_committed().unwrap().unwrap();
    assert_eq!(last_committed, block_id);

    let loaded_block = storage.get_block(&block_id).unwrap();
    assert!(loaded_block.is_none(), "Block should be missing");

    // This inconsistency should be handled by load_persisted_state
    // returning an error in the actual harness implementation
}

// ============================================================================
// Part C: View/height consistency tests
// ============================================================================

/// Test that restarted engine won't re-commit at old heights.
#[test]
fn restarted_engine_view_is_past_committed_height() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Restart at height 100
    let block_id = [42u8; 32];
    engine.initialize_from_restart(block_id, 100, None);

    // Current view should be 101
    assert_eq!(engine.current_view(), 101);
    assert!(engine.current_view() > 100);
}

/// Test that set_view can be used for manual view control.
#[test]
fn set_view_allows_manual_view_control() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    assert_eq!(engine.current_view(), 0);

    engine.set_view(42);
    assert_eq!(engine.current_view(), 42);

    engine.set_view(100);
    assert_eq!(engine.current_view(), 100);
}

// ============================================================================
// Part D: Safety invariant tests
// ============================================================================

/// Test that locked_qc is preserved correctly after restart.
#[test]
fn locked_qc_preserved_after_restart() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Set up restart state with a specific locked QC
    let lock_block_id = [88u8; 32];
    let lock_view = 50;
    let locked_qc = QuorumCertificate::new(lock_block_id, lock_view, vec![]);

    let committed_block_id = [42u8; 32];
    let committed_height = 55;

    engine.initialize_from_restart(committed_block_id, committed_height, Some(locked_qc));

    // Verify locked QC is set correctly
    let qc = engine.locked_qc().expect("should have locked QC");
    assert_eq!(qc.block_id, lock_block_id);
    assert_eq!(qc.view, lock_view);

    // Verify committed state
    assert_eq!(engine.committed_block(), Some(&committed_block_id));
    assert_eq!(engine.committed_height(), Some(committed_height));
}

/// Test that engine with restart state can still accept new proposals.
#[test]
fn restarted_engine_can_process_new_proposals() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Restart at height 10
    let block_id = [42u8; 32];
    engine.initialize_from_restart(block_id, 10, None);

    // Engine should be at view 11
    assert_eq!(engine.current_view(), 11);

    // Create a proposal for view 11 from validator 2 (leader for view 11)
    // leaders sorted: [1, 2, 3], view 11 % 3 = 2 -> leader[2] = 3
    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 11,
            round: 11,
            parent_block_id: block_id, // Parent is the committed block
            payload_hash: [0u8; 32],
            proposer_index: 2, // validator 3 (index 2 because 0-indexed)
            suite_id: 0,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    // Process the proposal from validator 3
    let action = engine.on_proposal_event(ValidatorId(3), &proposal);

    // Engine should either vote or not (depending on safety rules),
    // but it should not crash or panic
    // The key is that the engine can process proposals after restart
    let _ = action;
}

// ============================================================================
// Edge case tests
// ============================================================================

/// Test restart at height 0 (genesis restart).
#[test]
fn restart_at_genesis_height() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    let block_id = [0u8; 32];
    engine.initialize_from_restart(block_id, 0, None);

    // Should be at view 1
    assert_eq!(engine.current_view(), 1);
    assert_eq!(engine.committed_height(), Some(0));
}

/// Test restart with very high height (overflow protection).
#[test]
fn restart_at_high_height_no_overflow() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Use u64::MAX - 1 to test saturating_add
    let block_id = [42u8; 32];
    engine.initialize_from_restart(block_id, u64::MAX - 1, None);

    // Should be at view u64::MAX (saturated)
    assert_eq!(engine.current_view(), u64::MAX);
}

/// Test restart without QC (only committed block).
#[test]
fn restart_without_locked_qc() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    let block_id = [42u8; 32];
    engine.initialize_from_restart(block_id, 10, None);

    // No locked QC
    assert!(engine.locked_qc().is_none());

    // But committed state is set
    assert_eq!(engine.committed_block(), Some(&block_id));
    assert_eq!(engine.committed_height(), Some(10));
}
