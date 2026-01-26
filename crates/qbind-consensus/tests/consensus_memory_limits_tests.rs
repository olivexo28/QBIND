//! Tests for consensus memory limits (T118).
//!
//! These tests verify that the VoteAccumulator and HotStuffStateEngine
//! properly enforce memory limits to prevent unbounded growth under
//! adversarial conditions.
//!
//! Key scenarios covered:
//! - Bounded number of tracked views
//! - Bounded votes per (view, block_id) pair
//! - Adversarial spam with default limits
//! - Safety: no invalid QCs are formed when limits cause vote drops

use qbind_consensus::{
    ConsensusLimitsConfig, ConsensusValidatorSet, HotStuffStateEngine, QcValidationError,
    ValidatorId, ValidatorSetEntry, VoteAccumulator,
};

// ============================================================================
// Helper functions
// ============================================================================

/// Create a simple validator set with the given number of validators.
/// Each validator has voting power 1, so quorum = ceil(2*n/3).
fn make_validator_set(num_validators: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (0..num_validators)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Create a block ID from a seed value.
fn make_block_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// ============================================================================
// Test: Bounded number of views
// ============================================================================

/// Test that VoteAccumulator never tracks more than max_tracked_views.
/// Older views should be evicted when the limit is exceeded.
#[test]
fn vote_accumulator_bounded_views_evicts_oldest() {
    // Configure with a small limit: max 3 views
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(3, 256);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(4);
    let block_id = make_block_id(0xAA);

    // Add votes for views 10, 20, 30 (all should be tracked)
    acc.on_vote(&validators, ValidatorId(0), 10, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(0), 20, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(0), 30, &block_id)
        .unwrap();

    assert_eq!(acc.tracked_view_count(), 3);
    assert_eq!(acc.vote_count(10, &block_id), 1);
    assert_eq!(acc.vote_count(20, &block_id), 1);
    assert_eq!(acc.vote_count(30, &block_id), 1);
    assert_eq!(acc.evicted_views(), 0);

    // Add a vote for view 40 - this should evict view 10 (oldest)
    acc.on_vote(&validators, ValidatorId(0), 40, &block_id)
        .unwrap();

    assert_eq!(acc.tracked_view_count(), 3);
    assert_eq!(acc.vote_count(10, &block_id), 0); // Evicted
    assert_eq!(acc.vote_count(20, &block_id), 1);
    assert_eq!(acc.vote_count(30, &block_id), 1);
    assert_eq!(acc.vote_count(40, &block_id), 1);
    assert_eq!(acc.evicted_views(), 1);

    // Add votes for views 50, 60 - should evict 20, 30
    acc.on_vote(&validators, ValidatorId(0), 50, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(0), 60, &block_id)
        .unwrap();

    assert_eq!(acc.tracked_view_count(), 3);
    assert_eq!(acc.vote_count(20, &block_id), 0); // Evicted
    assert_eq!(acc.vote_count(30, &block_id), 0); // Evicted
    assert_eq!(acc.vote_count(40, &block_id), 1);
    assert_eq!(acc.vote_count(50, &block_id), 1);
    assert_eq!(acc.vote_count(60, &block_id), 1);
    assert_eq!(acc.evicted_views(), 3);
}

/// Test that adding votes to an existing view does not cause eviction.
#[test]
fn vote_accumulator_existing_view_no_eviction() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(3, 256);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(4);
    let block_id = make_block_id(0xBB);

    // Fill up to the limit
    acc.on_vote(&validators, ValidatorId(0), 10, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(0), 20, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(0), 30, &block_id)
        .unwrap();

    assert_eq!(acc.tracked_view_count(), 3);

    // Add more votes to existing views - no eviction should occur
    acc.on_vote(&validators, ValidatorId(1), 10, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), 20, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(3), 30, &block_id)
        .unwrap();

    assert_eq!(acc.tracked_view_count(), 3);
    assert_eq!(acc.vote_count(10, &block_id), 2);
    assert_eq!(acc.vote_count(20, &block_id), 2);
    assert_eq!(acc.vote_count(30, &block_id), 2);
    assert_eq!(acc.evicted_views(), 0);
}

/// Test that QC formation still works correctly after view eviction.
#[test]
fn vote_accumulator_qc_formation_after_eviction() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(2, 256);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    // 4 validators, need 3 for quorum
    let validators = make_validator_set(4);
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    // Add votes for view 10, reaching quorum
    acc.on_vote(&validators, ValidatorId(0), 10, &block_a)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), 10, &block_a)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), 10, &block_a)
        .unwrap();

    // Should have a QC for view 10
    let qc = acc.maybe_qc_for(&validators, 10, &block_a).unwrap();
    assert!(qc.is_some());

    // Add votes for view 20
    acc.on_vote(&validators, ValidatorId(0), 20, &block_b)
        .unwrap();

    // View 10 should be evicted when we add view 30
    acc.on_vote(&validators, ValidatorId(0), 30, &block_b)
        .unwrap();

    // View 10 is evicted, but we should still be able to add votes to views 20 and 30
    assert_eq!(acc.tracked_view_count(), 2);
    assert_eq!(acc.vote_count(10, &block_a), 0); // Evicted

    // Build up quorum for view 20
    acc.on_vote(&validators, ValidatorId(1), 20, &block_b)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), 20, &block_b)
        .unwrap();

    // Should have QC for view 20
    let qc = acc.maybe_qc_for(&validators, 20, &block_b).unwrap();
    assert!(qc.is_some());
    let qc = qc.unwrap();
    assert_eq!(qc.view, 20);
    assert_eq!(qc.block_id, block_b);
}

// ============================================================================
// Test: Bounded votes per view
// ============================================================================

/// Test that max_votes_per_view is enforced.
#[test]
fn vote_accumulator_bounded_votes_per_view() {
    // Allow only 4 votes per (view, block_id)
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(128, 4);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    // Create a validator set with more validators than the limit
    let validators = make_validator_set(10);
    let block_id = make_block_id(0xCC);
    let view = 100;

    // Add 4 votes - all should succeed
    for i in 0..4 {
        let result = acc.on_vote(&validators, ValidatorId(i), view, &block_id);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be new vote
    }

    assert_eq!(acc.vote_count(view, &block_id), 4);
    assert_eq!(acc.dropped_votes(), 0);

    // Try to add a 5th vote - should be dropped
    let result = acc.on_vote(&validators, ValidatorId(4), view, &block_id);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Was dropped

    assert_eq!(acc.vote_count(view, &block_id), 4);
    assert_eq!(acc.dropped_votes(), 1);

    // Try to add more votes - all should be dropped
    for i in 5..10 {
        let result = acc.on_vote(&validators, ValidatorId(i), view, &block_id);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    assert_eq!(acc.vote_count(view, &block_id), 4);
    assert_eq!(acc.dropped_votes(), 6);
}

/// Test that duplicate votes don't count as dropped.
#[test]
fn vote_accumulator_duplicate_not_dropped() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(128, 4);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(10);
    let block_id = make_block_id(0xDD);
    let view = 200;

    // Fill to the limit
    for i in 0..4 {
        acc.on_vote(&validators, ValidatorId(i), view, &block_id)
            .unwrap();
    }

    // Duplicate votes should return false but not increment dropped_votes
    let result = acc.on_vote(&validators, ValidatorId(0), view, &block_id);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Duplicate
    assert_eq!(acc.dropped_votes(), 0); // Not dropped, just duplicate
}

/// Test that different (view, block_id) pairs have independent limits.
#[test]
fn vote_accumulator_independent_limits_per_entry() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(128, 3);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(6);
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let view = 100;

    // Fill block_a to limit
    acc.on_vote(&validators, ValidatorId(0), view, &block_a)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view, &block_a)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), view, &block_a)
        .unwrap();

    // block_b should still accept votes
    let result = acc.on_vote(&validators, ValidatorId(0), view, &block_b);
    assert!(result.is_ok());
    assert!(result.unwrap()); // New vote accepted

    acc.on_vote(&validators, ValidatorId(1), view, &block_b)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), view, &block_b)
        .unwrap();

    assert_eq!(acc.vote_count(view, &block_a), 3);
    assert_eq!(acc.vote_count(view, &block_b), 3);
}

/// Test that QC formation fails gracefully when votes are dropped.
#[test]
fn vote_accumulator_no_qc_when_votes_dropped() {
    // Only allow 2 votes per entry, but need 3 for quorum (4 validators)
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(128, 2);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(4); // Need 3 for quorum
    let block_id = make_block_id(0xEE);
    let view = 300;

    // Add 2 votes (at the limit)
    acc.on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view, &block_id)
        .unwrap();

    // Try to add a 3rd vote - gets dropped
    let result = acc.on_vote(&validators, ValidatorId(2), view, &block_id);
    assert!(!result.unwrap()); // Dropped

    // We should NOT have a QC because only 2 votes are retained
    let qc = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    assert!(qc.is_none());

    assert_eq!(acc.vote_count(view, &block_id), 2);
    assert_eq!(acc.dropped_votes(), 1);
}

// ============================================================================
// Test: Adversarial spam scenario
// ============================================================================

/// Simulate an adversarial spam scenario with many views and validators.
/// Verify that memory limits are respected and no panics occur.
#[test]
fn vote_accumulator_adversarial_spam_default_limits() {
    let limits = ConsensusLimitsConfig::default();
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(100);

    // Simulate spam: many different views with many different blocks
    for view in 0..500u64 {
        for block_seed in 0..5u8 {
            let block_id = make_block_id(block_seed);
            for validator_idx in 0..10u64 {
                let _ = acc.on_vote(&validators, ValidatorId(validator_idx), view, &block_id);
            }
        }
    }

    // Verify limits are respected
    assert!(acc.tracked_view_count() <= limits.max_tracked_views);

    // With 500 views and limit of 128, we should have evicted some
    assert!(acc.evicted_views() > 0);

    // No panics occurred (implicit)
}

/// Test spam with very restrictive limits.
#[test]
fn vote_accumulator_adversarial_spam_restrictive_limits() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(5, 3);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(20);

    // Heavy spam
    for view in 0..100u64 {
        let block_id = make_block_id((view % 10) as u8);
        for validator_idx in 0..20u64 {
            let _ = acc.on_vote(&validators, ValidatorId(validator_idx), view, &block_id);
        }
    }

    // Verify limits are strictly respected
    assert!(acc.tracked_view_count() <= 5);
    assert!(acc.evicted_views() > 0);
    assert!(acc.dropped_votes() > 0);
}

// ============================================================================
// Test: HotStuffStateEngine with limits
// ============================================================================

/// Test that HotStuffStateEngine properly uses limits.
#[test]
fn hotstuff_engine_with_custom_limits() {
    let validators = make_validator_set(4);
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(3, 10);

    let engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    assert_eq!(engine.limits().max_tracked_views, 3);
    assert_eq!(engine.limits().max_votes_per_view, 10);
    assert_eq!(engine.dropped_votes(), 0);
    assert_eq!(engine.evicted_views(), 0);
}

/// Test that HotStuffStateEngine tracks dropped votes and evicted views.
#[test]
fn hotstuff_engine_tracks_limit_metrics() {
    let validators = make_validator_set(10);
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(2, 3);

    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators.clone(), limits);

    let block_id = make_block_id(0xFF);

    // Add votes for view 10
    engine.on_vote(ValidatorId(0), 10, &block_id).unwrap();
    engine.on_vote(ValidatorId(1), 10, &block_id).unwrap();
    engine.on_vote(ValidatorId(2), 10, &block_id).unwrap();
    // 4th vote should be dropped
    engine.on_vote(ValidatorId(3), 10, &block_id).unwrap();

    assert_eq!(engine.dropped_votes(), 1);

    // Add votes for views 20 and 30 to trigger eviction of view 10
    engine.on_vote(ValidatorId(0), 20, &block_id).unwrap();
    engine.on_vote(ValidatorId(0), 30, &block_id).unwrap();

    assert_eq!(engine.evicted_views(), 1);
}

/// Test that update_validators preserves limits configuration.
#[test]
fn hotstuff_engine_update_validators_preserves_limits() {
    let validators1 = make_validator_set(4);
    let validators2 = make_validator_set(6);
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(5, 20);

    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators1, limits);

    // Update validators
    engine.update_validators(validators2);

    // Limits should be preserved
    assert_eq!(engine.limits().max_tracked_views, 5);
    assert_eq!(engine.limits().max_votes_per_view, 20);
}

// ============================================================================
// Test: Safety - no invalid QCs
// ============================================================================

/// Test that no invalid QC is ever formed, even under limit pressure.
#[test]
fn safety_no_invalid_qc_under_pressure() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(2, 2);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    // Need 3 for quorum with 4 validators
    let validators = make_validator_set(4);

    // Try many combinations, ensuring no invalid QC is formed
    for view in 0..50u64 {
        let block_id = make_block_id((view % 5) as u8);

        for validator in 0..4u64 {
            let _ = acc.on_vote(&validators, ValidatorId(validator), view, &block_id);
        }

        // Check if a QC can be formed
        let qc_result = acc.maybe_qc_for(&validators, view, &block_id);

        // If a QC is returned, it must be valid
        if let Ok(Some(qc)) = qc_result {
            // Validate the QC
            let validation_result = qc.validate(&validators);
            assert!(
                validation_result.is_ok(),
                "QC validation failed for view {}: {:?}",
                view,
                validation_result
            );
        }
    }
}

/// Test that non-member votes are still rejected even with limits.
#[test]
fn non_member_votes_rejected_with_limits() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(10, 10);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(4);
    let block_id = make_block_id(0xAA);
    let view = 100;

    // Non-member vote should still return an error, not be silently dropped
    let result = acc.on_vote(&validators, ValidatorId(99), view, &block_id);
    assert!(matches!(
        result,
        Err(QcValidationError::NonMemberSigner(ValidatorId(99)))
    ));

    // Vote count should be 0
    assert_eq!(acc.vote_count(view, &block_id), 0);
    // This shouldn't count as a dropped vote (it was rejected)
    assert_eq!(acc.dropped_votes(), 0);
}

// ============================================================================
// Test: Config defaults
// ============================================================================

/// Test that default configuration has reasonable values.
#[test]
fn config_defaults_are_reasonable() {
    let config = ConsensusLimitsConfig::default();

    // Defaults should be conservative but not tiny
    assert!(
        config.max_tracked_views >= 64,
        "max_tracked_views too small"
    );
    assert!(
        config.max_tracked_views <= 1024,
        "max_tracked_views too large"
    );

    assert!(
        config.max_votes_per_view >= 100,
        "max_votes_per_view too small"
    );
    assert!(
        config.max_votes_per_view <= 1024,
        "max_votes_per_view too large"
    );
}

/// Test that VoteAccumulator::new() uses default limits.
#[test]
fn vote_accumulator_new_uses_defaults() {
    let acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();
    let defaults = ConsensusLimitsConfig::default();

    assert_eq!(acc.limits().max_tracked_views, defaults.max_tracked_views);
    assert_eq!(acc.limits().max_votes_per_view, defaults.max_votes_per_view);
}

/// Test that HotStuffStateEngine::new() uses default limits.
#[test]
fn hotstuff_engine_new_uses_defaults() {
    let validators = make_validator_set(4);
    let engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);
    let defaults = ConsensusLimitsConfig::default();

    assert_eq!(
        engine.limits().max_tracked_views,
        defaults.max_tracked_views
    );
    assert_eq!(
        engine.limits().max_votes_per_view,
        defaults.max_votes_per_view
    );
}

// ============================================================================
// Test: Entry count tracking
// ============================================================================

/// Test that entry_count() works correctly.
#[test]
fn vote_accumulator_entry_count() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(10, 10);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(4);

    // No entries initially
    assert_eq!(acc.entry_count(), 0);

    // Add vote for (view=10, block_a)
    let block_a = make_block_id(0xAA);
    acc.on_vote(&validators, ValidatorId(0), 10, &block_a)
        .unwrap();
    assert_eq!(acc.entry_count(), 1);

    // Add vote for (view=10, block_b) - different block, same view
    let block_b = make_block_id(0xBB);
    acc.on_vote(&validators, ValidatorId(0), 10, &block_b)
        .unwrap();
    assert_eq!(acc.entry_count(), 2);

    // Add vote for (view=20, block_a) - same block, different view
    acc.on_vote(&validators, ValidatorId(0), 20, &block_a)
        .unwrap();
    assert_eq!(acc.entry_count(), 3);

    // Adding to existing entry doesn't increase count
    acc.on_vote(&validators, ValidatorId(1), 10, &block_a)
        .unwrap();
    assert_eq!(acc.entry_count(), 3);
}

/// Test that remove_entry updates tracked views correctly.
#[test]
fn vote_accumulator_remove_entry_updates_tracked_views() {
    let limits = ConsensusLimitsConfig::new_vote_accumulator_limits(10, 10);
    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::with_limits(limits);

    let validators = make_validator_set(4);
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    // Add entries for view 10 with two different blocks
    acc.on_vote(&validators, ValidatorId(0), 10, &block_a)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(0), 10, &block_b)
        .unwrap();

    assert_eq!(acc.tracked_view_count(), 1);
    assert_eq!(acc.entry_count(), 2);

    // Remove one entry - view should still be tracked
    acc.remove_entry(10, &block_a);
    assert_eq!(acc.tracked_view_count(), 1);
    assert_eq!(acc.entry_count(), 1);

    // Remove the other entry - view should be removed
    acc.remove_entry(10, &block_b);
    assert_eq!(acc.tracked_view_count(), 0);
    assert_eq!(acc.entry_count(), 0);
}
