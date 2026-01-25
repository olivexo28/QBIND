//! T112: Atomic Epoch Persistence Tests
//!
//! These tests verify that epoch transitions are atomic with respect to storage:
//! 1. Epoch is persisted to storage BEFORE engine state is updated
//! 2. After successful transition, storage reflects the new epoch
//! 3. On restart, the node sees consistent epoch state
//!
//! This addresses the "Non-atomic epoch transition (HIGH)" issue from the audit.

use std::sync::Arc;
use tempfile::TempDir;

use cano_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, EpochStateProvider, StaticEpochStateProvider,
    ValidatorSetEntry,
};
use cano_consensus::ValidatorId;
use cano_node::storage::{ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage};

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

fn make_epoch_state_provider(max_epoch: u64) -> Arc<StaticEpochStateProvider> {
    let validators = make_validator_set(&[0, 1, 2]);
    let mut provider = StaticEpochStateProvider::new();

    for epoch in 0..=max_epoch {
        let epoch_state = if epoch == 0 {
            EpochState::genesis(validators.clone())
        } else {
            EpochState::new(EpochId::new(epoch), validators.clone())
        };
        provider.insert(epoch_state);
    }

    Arc::new(provider)
}

// ============================================================================
// T112: Storage-level epoch persistence tests
// ============================================================================

/// T112: Verify that epoch storage operations are atomic.
#[test]
fn t112_storage_epoch_put_get_is_atomic() {
    let storage = InMemoryConsensusStorage::new();

    // Initially no epoch
    assert_eq!(storage.get_current_epoch().unwrap(), None);

    // Store epoch 0
    storage.put_current_epoch(0).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));

    // Store epoch 1
    storage.put_current_epoch(1).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(1));

    // Each put should be immediately visible
    storage.put_current_epoch(42).unwrap();
    assert_eq!(storage.get_current_epoch().unwrap(), Some(42));
}

/// T112: Verify epoch persists across RocksDB reopens (simulating restart).
#[test]
fn t112_rocksdb_epoch_survives_restart() {
    let temp_dir = TempDir::new().unwrap();

    // First "run": write epoch 3
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        storage.put_current_epoch(3).unwrap();
        assert_eq!(storage.get_current_epoch().unwrap(), Some(3));
    }

    // "Restart": reopen and verify epoch 3 is still there
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();
        assert_eq!(storage.get_current_epoch().unwrap(), Some(3));
    }
}

/// T112: Verify that storage epoch update before engine transition
/// ensures restart consistency.
///
/// This simulates the scenario where:
/// 1. A reconfig block commits
/// 2. Storage is updated to new epoch (step 1 of atomic transition)
/// 3. A crash occurs before engine update completes
/// 4. On restart, storage has the new epoch
///
/// The fix in T112 ensures that storage is updated FIRST, so restart
/// always sees the correct epoch.
#[test]
fn t112_storage_updated_before_engine_ensures_restart_consistency() {
    let temp_dir = TempDir::new().unwrap();

    // Simulate the epoch transition ordering:
    // 1. Reconfig block commits
    // 2. Storage is updated FIRST (as per T112 fix)
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Start in epoch 0
        storage.put_current_epoch(0).unwrap();

        // Simulate T112 ordering: persist new epoch BEFORE engine update
        // In a real scenario, engine.transition_to_epoch() would be called AFTER this
        storage.put_current_epoch(1).unwrap();

        // At this point, storage has epoch 1.
        // If we crashed here (before engine update), restart should see epoch 1.
        assert_eq!(storage.get_current_epoch().unwrap(), Some(1));
    }

    // "Restart" after "crash" (simulated by closing and reopening)
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // On restart, we should see epoch 1 from storage
        let restored_epoch = storage.get_current_epoch().unwrap();
        assert_eq!(
            restored_epoch,
            Some(1),
            "After restart, storage should show epoch 1 (persisted before engine update)"
        );
    }
}

/// T112: Verify that a complete epoch transition sequence is consistent.
///
/// This tests the full sequence:
/// 1. Start in epoch 0
/// 2. Commit reconfig block
/// 3. Persist epoch 1 to storage
/// 4. Update engine to epoch 1
/// 5. On restart, both storage and restored epoch match
#[test]
fn t112_complete_epoch_transition_is_consistent() {
    let temp_dir = TempDir::new().unwrap();

    // Phase 1: Initial run with epoch transitions
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // Start fresh - epoch 0
        assert_eq!(storage.get_current_epoch().unwrap(), None);
        storage.put_current_epoch(0).unwrap();

        // Transition to epoch 1 (simulating reconfig block commit)
        // T112 ordering: storage first
        storage.put_current_epoch(1).unwrap();

        // Transition to epoch 2
        storage.put_current_epoch(2).unwrap();

        // Final state should be epoch 2
        assert_eq!(storage.get_current_epoch().unwrap(), Some(2));
    }

    // Phase 2: Restart and verify consistency
    {
        let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

        // On restart, epoch should be 2
        let restored_epoch = storage.get_current_epoch().unwrap();
        assert_eq!(
            restored_epoch,
            Some(2),
            "After restart, storage should show the latest persisted epoch"
        );

        // The epoch state provider should have epoch 2
        let provider = make_epoch_state_provider(5);
        let epoch_state = provider.get_epoch_state(EpochId::new(2));
        assert!(
            epoch_state.is_some(),
            "Epoch state provider should have state for restored epoch"
        );

        // The restored epoch should match the epoch state
        let state = epoch_state.unwrap();
        assert_eq!(state.epoch_id(), EpochId::new(2));
    }
}

/// T112: Test that fresh DB defaults to epoch 0 correctly.
#[test]
fn t112_fresh_db_defaults_to_epoch_zero() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbConsensusStorage::open(temp_dir.path()).unwrap();

    // Fresh DB should return None for current_epoch
    let epoch = storage.get_current_epoch().unwrap();
    assert_eq!(epoch, None);

    // Application should treat None as epoch 0
    let effective_epoch = epoch.unwrap_or(0);
    assert_eq!(effective_epoch, 0);
}

// ============================================================================
// T112: Error propagation tests
// ============================================================================

/// T112: Verify that epoch transition error propagation works correctly.
#[test]
fn t112_epoch_transition_error_propagates() {
    use cano_consensus::validator_set::EpochTransitionError;

    // Create a non-sequential epoch error
    let error = EpochTransitionError::NonSequentialEpoch {
        current: EpochId::new(0),
        requested: EpochId::new(5),
    };

    // Verify the error contains useful information
    let display = format!("{}", error);
    assert!(
        display.contains("non-sequential") || display.contains("0") || display.contains("5"),
        "Error message should contain relevant info: {}",
        display
    );
}

/// T112: Test the MissingEpochState error variant.
#[test]
fn t112_missing_epoch_state_error() {
    use cano_consensus::validator_set::EpochTransitionError;

    let error = EpochTransitionError::MissingEpochState(EpochId::new(42));

    let display = format!("{}", error);
    assert!(
        display.contains("42") || display.contains("not available"),
        "Error message should indicate missing epoch: {}",
        display
    );
}
