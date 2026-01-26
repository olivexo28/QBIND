//! T112: Atomic Epoch Transition & Non-Panic Epoch Validation Tests
//!
//! These tests verify the fixes for T112:
//! 1. Non-panic on invalid epoch transitions (returns errors instead of panics)
//! 2. Sequential epoch validation returns proper errors
//! 3. Happy-path transitions still work correctly

use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochTransitionError, ValidatorSetEntry,
};
use qbind_consensus::ValidatorId;

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

// ============================================================================
// T112 Part 1: Non-panic epoch transition tests
// ============================================================================

/// T112: Verify that non-sequential epoch transitions return an error (not panic).
///
/// Previously, epoch transitions might use assert_eq! which would panic.
/// This test verifies that invalid transitions return a proper error.
#[test]
fn t112_non_sequential_transition_returns_error_not_panic() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators2 = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Start at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Try to skip to epoch 2 (should return error, NOT panic)
    let result = engine.transition_to_epoch(EpochId::new(2), validators2);

    // Verify we get an error (not a panic)
    assert!(
        result.is_err(),
        "non-sequential transition should return Err"
    );

    // Verify the error is the right type
    match result.unwrap_err() {
        EpochTransitionError::NonSequentialEpoch { current, requested } => {
            assert_eq!(current, EpochId::new(0));
            assert_eq!(requested, EpochId::new(2));
        }
        other => panic!("Expected NonSequentialEpoch error, got: {:?}", other),
    }

    // Verify epoch is unchanged
    assert_eq!(engine.current_epoch(), 0);
}

/// T112: Verify that trying to stay at the same epoch returns an error.
#[test]
fn t112_same_epoch_transition_returns_error_not_panic() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators0_copy = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Start at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Try to "transition" to epoch 0 (same epoch - should fail)
    let result = engine.transition_to_epoch(EpochId::new(0), validators0_copy);

    // Verify we get an error (not a panic)
    assert!(result.is_err(), "same-epoch transition should return Err");

    // Verify the error indicates non-sequential (0 -> 0 is not 0 -> 1)
    match result.unwrap_err() {
        EpochTransitionError::NonSequentialEpoch { current, requested } => {
            assert_eq!(current, EpochId::new(0));
            assert_eq!(requested, EpochId::new(0));
        }
        other => panic!("Expected NonSequentialEpoch error, got: {:?}", other),
    }

    // Verify epoch is unchanged
    assert_eq!(engine.current_epoch(), 0);
}

/// T112: Verify that backward epoch transitions return an error.
#[test]
fn t112_backward_epoch_transition_returns_error_not_panic() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[1, 2, 3]);
    let validators_back = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // First, transition to epoch 1 (valid)
    let result = engine.transition_to_epoch(EpochId::new(1), validators1);
    assert!(result.is_ok());
    assert_eq!(engine.current_epoch(), 1);

    // Now try to go back to epoch 0 (should fail)
    let result = engine.transition_to_epoch(EpochId::new(0), validators_back);

    // Verify we get an error (not a panic)
    assert!(result.is_err(), "backward transition should return Err");

    match result.unwrap_err() {
        EpochTransitionError::NonSequentialEpoch { current, requested } => {
            assert_eq!(current, EpochId::new(1));
            assert_eq!(requested, EpochId::new(0));
        }
        other => panic!("Expected NonSequentialEpoch error, got: {:?}", other),
    }

    // Verify epoch is unchanged (still 1)
    assert_eq!(engine.current_epoch(), 1);
}

// ============================================================================
// T112 Part 2: Happy-path transitions still work
// ============================================================================

/// T112: Verify that valid sequential epoch transitions work correctly.
#[test]
fn t112_valid_sequential_transition_succeeds() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[4, 5, 6]); // Different validators

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Start at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Transition to epoch 1 (valid: 0 -> 1)
    let result = engine.transition_to_epoch(EpochId::new(1), validators1);
    assert!(result.is_ok(), "valid sequential transition should succeed");

    // Verify epoch is now 1
    assert_eq!(engine.current_epoch(), 1);

    // Verify leader set was updated
    assert_eq!(engine.leader_for_view(0), ValidatorId(4));
}

/// T112: Verify multiple sequential transitions work correctly.
#[test]
fn t112_multiple_sequential_transitions_succeed() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[4, 5, 6]);
    let validators2 = make_validator_set(&[7, 8, 9]);
    let validators3 = make_validator_set(&[10, 11, 12]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Transition 0 -> 1
    assert!(engine
        .transition_to_epoch(EpochId::new(1), validators1)
        .is_ok());
    assert_eq!(engine.current_epoch(), 1);
    assert_eq!(engine.leader_for_view(0), ValidatorId(4));

    // Transition 1 -> 2
    assert!(engine
        .transition_to_epoch(EpochId::new(2), validators2)
        .is_ok());
    assert_eq!(engine.current_epoch(), 2);
    assert_eq!(engine.leader_for_view(0), ValidatorId(7));

    // Transition 2 -> 3
    assert!(engine
        .transition_to_epoch(EpochId::new(3), validators3)
        .is_ok());
    assert_eq!(engine.current_epoch(), 3);
    assert_eq!(engine.leader_for_view(0), ValidatorId(10));
}

/// T112: Verify that epoch transition preserves view state.
#[test]
fn t112_epoch_transition_preserves_view() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Advance to view 5
    for _ in 0..5 {
        engine.advance_view();
    }
    assert_eq!(engine.current_view(), 5);

    // Transition to epoch 1
    assert!(engine
        .transition_to_epoch(EpochId::new(1), validators1)
        .is_ok());

    // View should be unchanged
    assert_eq!(engine.current_view(), 5);
    assert_eq!(engine.current_epoch(), 1);
}

// ============================================================================
// T112 Part 3: Error type verification
// ============================================================================

/// T112: Verify EpochTransitionError implements Display properly.
#[test]
fn t112_epoch_transition_error_has_display() {
    let error = EpochTransitionError::NonSequentialEpoch {
        current: EpochId::new(0),
        requested: EpochId::new(2),
    };

    let display = format!("{}", error);
    assert!(display.contains("non-sequential"));
    assert!(display.contains("0") || display.contains("current"));
    assert!(display.contains("2") || display.contains("requested"));
}

/// T112: Verify EpochTransitionError implements std::error::Error.
#[test]
fn t112_epoch_transition_error_is_std_error() {
    let error: Box<dyn std::error::Error> = Box::new(EpochTransitionError::NonSequentialEpoch {
        current: EpochId::new(0),
        requested: EpochId::new(2),
    });

    // Just verify it can be used as a std::error::Error
    let _ = error.to_string();
}
