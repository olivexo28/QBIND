//! T213: Key Rotation Hooks v0 integration tests.
//!
//! These tests verify the key rotation primitives as specified in T213:
//! - KeyRotationEvent application
//! - Dual-key validity during grace period
//! - Rotation commitment after grace period
//! - No overlapping rotations
//! - Emergency rotation uses same mechanics as scheduled

use qbind_consensus::key_rotation::{
    advance_epoch_for_rotation, apply_key_rotation_event, KeyRole, KeyRotationError,
    KeyRotationEvent, KeyRotationKind, KeyRotationRegistry,
};

// Helper to create test public keys
fn test_pk(n: u8) -> Vec<u8> {
    vec![n; 32]
}

// ============================================================================
// Test: Apply rotation event basic (T213 §2.5)
// ============================================================================

#[test]
fn test_apply_rotation_event_basic() {
    // T213 §2.5: Single validator, scheduled rotation, grace_epochs = 2
    // Verify state after applying event.

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    let event = KeyRotationEvent::scheduled(
        1,                  // validator_id
        KeyRole::Consensus, // key_role
        test_pk(2),         // new_public_key
        100,                // effective_epoch
        2,                  // grace_epochs
    );

    let current_epoch = 99;
    let result = registry.apply_rotation_event(&event, current_epoch);
    assert!(result.is_ok(), "rotation event should be applied successfully");

    // Verify the state after applying
    let state = registry
        .get_key_state(1, KeyRole::Consensus)
        .expect("validator should exist");

    // Should be in rotating state
    assert!(state.is_rotating(), "validator should be in rotation");

    // Current key unchanged
    assert_eq!(
        state.current_key,
        test_pk(1),
        "current key should not change yet"
    );

    // Pending key set correctly
    let pending = state.next_key.as_ref().expect("pending key should exist");
    assert_eq!(pending.key, test_pk(2), "pending key should be new key");
    assert_eq!(
        pending.grace_start_epoch, 100,
        "grace should start at effective_epoch"
    );
    assert_eq!(
        pending.grace_end_epoch, 102,
        "grace should end at effective + grace_epochs"
    );
    assert_eq!(
        pending.kind,
        KeyRotationKind::Scheduled,
        "kind should be Scheduled"
    );
}

// ============================================================================
// Test: Dual-key validity during grace period (T213 §2.5)
// ============================================================================

#[test]
fn test_dual_key_validity_during_grace() {
    // T213 §2.5: For epochs [E, E+2], signatures under both old and new key are accepted.

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);
    registry.apply_rotation_event(&event, 99).unwrap();

    // Before grace period starts (epoch 99)
    // Old key valid, new key NOT valid
    assert!(
        registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 99),
        "old key should be valid before grace period"
    );
    assert!(
        !registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 99),
        "new key should NOT be valid before grace period"
    );

    // During grace period (epochs 100, 101, 102)
    for epoch in [100, 101, 102] {
        assert!(
            registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), epoch),
            "old key should be valid during grace period (epoch {})",
            epoch
        );
        assert!(
            registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), epoch),
            "new key should be valid during grace period (epoch {})",
            epoch
        );
    }

    // After grace period (epoch 103) - before commit
    // Old key still valid (it's still current), new key no longer in grace
    assert!(
        registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 103),
        "old key should still be valid after grace period (still current)"
    );
    assert!(
        !registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 103),
        "new key should NOT be valid after grace period (before commit)"
    );
}

// ============================================================================
// Test: Rotation commits after grace period (T213 §2.5)
// ============================================================================

#[test]
fn test_rotation_commits_after_grace() {
    // T213 §2.5: After calling advance_epoch_for_rotation with epoch > grace_end_epoch:
    // - old key no longer accepted
    // - new key is the sole current_key

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);
    registry.apply_rotation_event(&event, 99).unwrap();

    // Grace period ends at epoch 102 (inclusive)
    // Calling advance_epoch at 102 should NOT commit yet
    let committed = advance_epoch_for_rotation(&mut registry, 102);
    assert!(committed.is_empty(), "should not commit at grace_end_epoch");

    // Verify still rotating
    let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
    assert!(state.is_rotating(), "should still be rotating at epoch 102");
    assert_eq!(state.current_key, test_pk(1), "old key still current");

    // Calling advance_epoch at 103 should commit
    let committed = advance_epoch_for_rotation(&mut registry, 103);
    assert_eq!(committed.len(), 1, "should commit one rotation");
    assert!(
        committed.contains(&(1, KeyRole::Consensus)),
        "committed list should contain validator 1"
    );

    // Verify rotation committed
    let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
    assert!(!state.is_rotating(), "should no longer be rotating");
    assert_eq!(state.current_key, test_pk(2), "new key should be current");
    assert!(state.next_key.is_none(), "pending key should be cleared");

    // Now only the new key is valid
    assert!(
        registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 103),
        "new key should be valid after commit"
    );
    // Old key is no longer valid (it's not the current key anymore)
    assert!(
        !registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 103),
        "old key should NOT be valid after commit"
    );
}

// ============================================================================
// Test: No overlapping rotations (T213 §2.5)
// ============================================================================

#[test]
fn test_no_overlapping_rotations() {
    // T213 §2.5: Applying a second event while next_key is Some returns error.

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    // First rotation
    let event1 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);
    assert!(
        registry.apply_rotation_event(&event1, 99).is_ok(),
        "first rotation should succeed"
    );

    // Second rotation should fail
    let event2 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(3), 101, 2);
    let result = registry.apply_rotation_event(&event2, 99);

    match result {
        Err(KeyRotationError::RotationAlreadyInProgress {
            validator_id,
            key_role,
            existing_grace_end,
        }) => {
            assert_eq!(validator_id, 1);
            assert_eq!(key_role, KeyRole::Consensus);
            assert_eq!(existing_grace_end, 102); // 100 + 2
        }
        _ => panic!("expected RotationAlreadyInProgress error, got {:?}", result),
    }
}

// ============================================================================
// Test: Emergency rotation uses same hooks (T213 §2.5)
// ============================================================================

#[test]
fn test_emergency_rotation_uses_same_hooks() {
    // T213 §2.5: KeyRotationKind::Emergency still uses the same mechanics;
    // this is tag-only for now.

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    // Emergency rotation
    let event = KeyRotationEvent::emergency(1, KeyRole::Consensus, test_pk(2), 100, 1);
    assert!(
        registry.apply_rotation_event(&event, 99).is_ok(),
        "emergency rotation should succeed"
    );

    // Check the kind is Emergency
    let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
    let pending = state.next_key.as_ref().unwrap();
    assert_eq!(
        pending.kind,
        KeyRotationKind::Emergency,
        "kind should be Emergency"
    );

    // Same dual-key validity behavior
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 100));
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 100));
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 101));
    assert!(!registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 102));

    // Same commit behavior
    let committed = advance_epoch_for_rotation(&mut registry, 102);
    assert_eq!(committed.len(), 1);

    let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
    assert_eq!(state.current_key, test_pk(2));
}

// ============================================================================
// Test: Large epoch numbers (overflow checks) (T213 §2.5 edge cases)
// ============================================================================

#[test]
fn test_large_epoch_numbers_overflow() {
    // T213 §2.5: Large epoch numbers (overflow checks)

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    // Event with epoch near u64::MAX
    let event = KeyRotationEvent::scheduled(
        1,
        KeyRole::Consensus,
        test_pk(2),
        u64::MAX - 1, // effective_epoch
        10,           // grace_epochs (would overflow without saturation)
    );

    // Should use saturating arithmetic
    assert_eq!(
        event.grace_end_epoch(),
        u64::MAX,
        "grace_end should saturate to u64::MAX"
    );

    // Application should succeed
    assert!(
        registry
            .apply_rotation_event(&event, u64::MAX - 1)
            .is_ok(),
        "rotation with large epochs should succeed"
    );

    // Verify key validity at large epochs
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), u64::MAX));
}

// ============================================================================
// Test: Grace epochs = 0 (immediate switch) (T213 §2.5 edge cases)
// ============================================================================

#[test]
fn test_grace_epochs_zero_immediate_switch() {
    // T213 §2.5: grace_epochs = 0 (decide behaviour; simplest: treat as immediate
    // switch at effective_epoch, document it and test it).

    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));

    // grace_epochs = 0 means grace period is [100, 100] (single epoch)
    let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 0);
    registry.apply_rotation_event(&event, 100).unwrap();

    // At effective epoch: both keys valid (grace period is exactly this epoch)
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 100));
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 100));

    // Next epoch: new key no longer in grace (101 > 100), old key still current
    assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 101));
    assert!(!registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 101));

    // Advance to epoch 101: should commit
    let committed = advance_epoch_for_rotation(&mut registry, 101);
    assert_eq!(committed.len(), 1);

    // Now new key is current
    let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
    assert_eq!(state.current_key, test_pk(2));
}

// ============================================================================
// Test: Multiple validators with staggered rotations
// ============================================================================

#[test]
fn test_multiple_validators_staggered_rotations() {
    let mut registry = KeyRotationRegistry::new();

    // Register 3 validators
    registry.register_key(1, KeyRole::Consensus, test_pk(1));
    registry.register_key(2, KeyRole::Consensus, test_pk(2));
    registry.register_key(3, KeyRole::Consensus, test_pk(3));

    // Staggered rotations with different effective epochs and grace periods
    let event1 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(11), 100, 2); // ends 102
    let event2 = KeyRotationEvent::scheduled(2, KeyRole::Consensus, test_pk(12), 100, 3); // ends 103
    let event3 = KeyRotationEvent::scheduled(3, KeyRole::Consensus, test_pk(13), 101, 4); // ends 105

    registry.apply_rotation_event(&event1, 99).unwrap();
    registry.apply_rotation_event(&event2, 99).unwrap();
    registry.apply_rotation_event(&event3, 100).unwrap();

    // At epoch 102: all still rotating
    let committed = advance_epoch_for_rotation(&mut registry, 102);
    assert!(committed.is_empty());

    // At epoch 103: validator 1 commits
    let committed = advance_epoch_for_rotation(&mut registry, 103);
    assert_eq!(committed.len(), 1);
    assert!(committed.contains(&(1, KeyRole::Consensus)));

    // At epoch 104: validator 2 commits
    let committed = advance_epoch_for_rotation(&mut registry, 104);
    assert_eq!(committed.len(), 1);
    assert!(committed.contains(&(2, KeyRole::Consensus)));

    // At epoch 106: validator 3 commits
    let committed = advance_epoch_for_rotation(&mut registry, 106);
    assert_eq!(committed.len(), 1);
    assert!(committed.contains(&(3, KeyRole::Consensus)));

    // Verify all rotated
    assert_eq!(
        registry
            .get_key_state(1, KeyRole::Consensus)
            .unwrap()
            .current_key,
        test_pk(11)
    );
    assert_eq!(
        registry
            .get_key_state(2, KeyRole::Consensus)
            .unwrap()
            .current_key,
        test_pk(12)
    );
    assert_eq!(
        registry
            .get_key_state(3, KeyRole::Consensus)
            .unwrap()
            .current_key,
        test_pk(13)
    );
}

// ============================================================================
// Test: Apply rotation with validator set validation
// ============================================================================

#[test]
fn test_apply_rotation_with_validator_set_validation() {
    let mut registry = KeyRotationRegistry::new();
    registry.register_key(1, KeyRole::Consensus, test_pk(1));
    registry.register_key(2, KeyRole::Consensus, test_pk(2));

    let validator_ids: Vec<u64> = vec![1, 2, 3]; // validator 3 in set but no key yet

    // Valid rotation for validator in set
    let event1 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(11), 100, 2);
    assert!(apply_key_rotation_event(
        &mut registry,
        validator_ids.iter().copied(),
        &event1,
        99
    )
    .is_ok());

    // Invalid rotation for validator NOT in set
    let event2 = KeyRotationEvent::scheduled(99, KeyRole::Consensus, test_pk(99), 100, 2);
    match apply_key_rotation_event(&mut registry, validator_ids.iter().copied(), &event2, 99) {
        Err(KeyRotationError::ValidatorNotFound(99)) => (),
        other => panic!("expected ValidatorNotFound(99), got {:?}", other),
    }
}

// ============================================================================
// Test: Rotation for different key roles
// ============================================================================

#[test]
fn test_rotation_for_different_key_roles() {
    let mut registry = KeyRotationRegistry::new();

    // Same validator, different key roles
    registry.register_key(1, KeyRole::Consensus, test_pk(1));
    registry.register_key(1, KeyRole::BatchSigning, test_pk(2));
    registry.register_key(1, KeyRole::P2pIdentity, test_pk(3));

    // Rotate each role independently
    let event_consensus =
        KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(11), 100, 2);
    let event_batch =
        KeyRotationEvent::scheduled(1, KeyRole::BatchSigning, test_pk(12), 100, 3);
    let event_p2p =
        KeyRotationEvent::scheduled(1, KeyRole::P2pIdentity, test_pk(13), 100, 4);

    registry.apply_rotation_event(&event_consensus, 99).unwrap();
    registry.apply_rotation_event(&event_batch, 99).unwrap();
    registry.apply_rotation_event(&event_p2p, 99).unwrap();

    // All three rotating independently
    assert!(registry.get_key_state(1, KeyRole::Consensus).unwrap().is_rotating());
    assert!(registry.get_key_state(1, KeyRole::BatchSigning).unwrap().is_rotating());
    assert!(registry.get_key_state(1, KeyRole::P2pIdentity).unwrap().is_rotating());

    // Commit consensus first (ends at 102)
    advance_epoch_for_rotation(&mut registry, 103);
    assert!(!registry.get_key_state(1, KeyRole::Consensus).unwrap().is_rotating());
    assert!(registry.get_key_state(1, KeyRole::BatchSigning).unwrap().is_rotating());
    assert!(registry.get_key_state(1, KeyRole::P2pIdentity).unwrap().is_rotating());

    // Commit batch (ends at 103)
    advance_epoch_for_rotation(&mut registry, 104);
    assert!(!registry.get_key_state(1, KeyRole::BatchSigning).unwrap().is_rotating());
    assert!(registry.get_key_state(1, KeyRole::P2pIdentity).unwrap().is_rotating());

    // Commit p2p (ends at 104)
    advance_epoch_for_rotation(&mut registry, 105);
    assert!(!registry.get_key_state(1, KeyRole::P2pIdentity).unwrap().is_rotating());
}