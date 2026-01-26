//! Tests for per-validator equivocation recording in BasicHotStuffEngine (T129).
//!
//! These tests verify that the ValidatorEquivocationRecorder trait is correctly
//! wired into the BasicHotStuffEngine and that equivocation events are properly
//! recorded during consensus operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;

use qbind_consensus::{
    BasicHotStuffEngine, ConsensusValidatorSet, NoopValidatorEquivocationRecorder,
    ValidatorEquivocationRecorder, ValidatorId, ValidatorSetEntry,
};
use qbind_wire::consensus::Vote;

// ============================================================================
// Test Equivocation Recorder
// ============================================================================

/// Per-validator counters for testing.
#[derive(Debug, Default)]
struct TestEquivocationCounters {
    equivocations_total: AtomicU64,
    equivocating: AtomicU64,
}

/// A test implementation of ValidatorEquivocationRecorder that tracks all events.
#[derive(Debug, Default)]
struct TestEquivocationRecorder {
    validators: RwLock<HashMap<ValidatorId, TestEquivocationCounters>>,
}

impl ValidatorEquivocationRecorder for TestEquivocationRecorder {
    fn on_validator_equivocation(&self, validator_id: ValidatorId, _view: u64) {
        let mut validators = self.validators.write().unwrap();
        let counters = validators.entry(validator_id).or_default();
        counters.equivocations_total.fetch_add(1, Ordering::Relaxed);
        counters.equivocating.store(1, Ordering::Relaxed);
    }
}

impl TestEquivocationRecorder {
    fn equivocations_total(&self, validator_id: ValidatorId) -> u64 {
        let validators = self.validators.read().unwrap();
        validators
            .get(&validator_id)
            .map(|c| c.equivocations_total.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn is_equivocating(&self, validator_id: ValidatorId) -> bool {
        let validators = self.validators.read().unwrap();
        validators
            .get(&validator_id)
            .map(|c| c.equivocating.load(Ordering::Relaxed) == 1)
            .unwrap_or(false)
    }

    fn tracked_validators(&self) -> usize {
        self.validators.read().unwrap().len()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Create a validator set with `num` validators, each with `vp` voting power.
fn make_validator_set(num: u64, vp: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: vp,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Create a vote message.
fn make_vote(validator_id: ValidatorId, view: u64, block_id: [u8; 32]) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: view,
        round: view,
        step: 0,
        block_id,
        validator_index: validator_id.0 as u16,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![],
    }
}

/// Create a different block ID for testing equivocation.
fn make_block_id(seed: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = seed;
    id
}

// ============================================================================
// Tests: Basic Equivocation Recorder Functionality
// ============================================================================

#[test]
fn noop_equivocation_recorder_does_not_panic() {
    let recorder = NoopValidatorEquivocationRecorder;
    recorder.on_validator_equivocation(ValidatorId(1), 0);
    recorder.on_validator_equivocation(ValidatorId(2), 100);
}

#[test]
fn noop_equivocation_recorder_is_send_sync_debug() {
    fn assert_send_sync_debug<T: Send + Sync + std::fmt::Debug>() {}
    assert_send_sync_debug::<NoopValidatorEquivocationRecorder>();
}

#[test]
fn test_recorder_tracks_equivocations() {
    let recorder = TestEquivocationRecorder::default();

    recorder.on_validator_equivocation(ValidatorId(1), 0);
    recorder.on_validator_equivocation(ValidatorId(2), 0);
    recorder.on_validator_equivocation(ValidatorId(1), 1);

    assert_eq!(recorder.equivocations_total(ValidatorId(1)), 2);
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 1);
    assert!(recorder.is_equivocating(ValidatorId(1)));
    assert!(recorder.is_equivocating(ValidatorId(2)));
    assert_eq!(recorder.tracked_validators(), 2);
}

// ============================================================================
// Tests: Engine Integration - Equivocation Detection
// ============================================================================

#[test]
fn equivocation_detected_when_same_validator_votes_for_different_blocks() {
    // Need at least 2 validators for proper test
    let validators = make_validator_set(2, 1);
    let recorder = Arc::new(TestEquivocationRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_equivocation_recorder(recorder.clone());

    // Register a block first (needed for vote accumulation)
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    engine.state_mut().register_block(block_a, 0, None, None);
    engine.state_mut().register_block(block_b, 0, None, None);

    // Validator 2 votes for block A
    let vote_a = make_vote(ValidatorId(2), 0, block_a);
    let result_a = engine.on_vote_event(ValidatorId(2), &vote_a);
    assert!(result_a.is_ok());

    // No equivocation yet
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 0);

    // Validator 2 votes for block B (same view, different block = equivocation!)
    let vote_b = make_vote(ValidatorId(2), 0, block_b);
    let result_b = engine.on_vote_event(ValidatorId(2), &vote_b);
    assert!(result_b.is_ok()); // Returns Ok(None) for equivocating vote

    // Equivocation should be detected
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 1);
    assert!(recorder.is_equivocating(ValidatorId(2)));
}

#[test]
fn duplicate_vote_same_block_not_counted_as_equivocation() {
    let validators = make_validator_set(2, 1);
    let recorder = Arc::new(TestEquivocationRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_equivocation_recorder(recorder.clone());

    let block_a = make_block_id(0xAA);
    engine.state_mut().register_block(block_a, 0, None, None);

    // Validator 2 votes for block A twice
    let vote_1 = make_vote(ValidatorId(2), 0, block_a);
    let vote_2 = make_vote(ValidatorId(2), 0, block_a);

    let _ = engine.on_vote_event(ValidatorId(2), &vote_1);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_2);

    // No equivocation (same block = duplicate, not equivocation)
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 0);
    assert!(!recorder.is_equivocating(ValidatorId(2)));
}

#[test]
fn votes_in_different_views_not_equivocation() {
    let validators = make_validator_set(2, 1);
    let recorder = Arc::new(TestEquivocationRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_equivocation_recorder(recorder.clone());

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    engine.state_mut().register_block(block_a, 0, None, None);
    engine.state_mut().register_block(block_b, 1, None, None);

    // Validator 2 votes for block A in view 0
    let vote_view_0 = make_vote(ValidatorId(2), 0, block_a);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_view_0);

    // Validator 2 votes for block B in view 1 (different view, allowed)
    let vote_view_1 = make_vote(ValidatorId(2), 1, block_b);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_view_1);

    // No equivocation (different views)
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 0);
}

#[test]
fn multiple_equivocations_from_same_validator() {
    let validators = make_validator_set(3, 1);
    let recorder = Arc::new(TestEquivocationRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_equivocation_recorder(recorder.clone());

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);

    engine.state_mut().register_block(block_a, 0, None, None);
    engine.state_mut().register_block(block_b, 0, None, None);
    engine.state_mut().register_block(block_c, 0, None, None);

    // Validator 2 votes for A
    let vote_a = make_vote(ValidatorId(2), 0, block_a);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_a);
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 0);

    // Validator 2 votes for B (first equivocation)
    let vote_b = make_vote(ValidatorId(2), 0, block_b);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_b);
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 1);

    // Validator 2 votes for C (second equivocation)
    let vote_c = make_vote(ValidatorId(2), 0, block_c);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_c);
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 2);
}

#[test]
fn equivocation_recorder_set_after_construction() {
    let validators = make_validator_set(2, 1);
    let recorder = Arc::new(TestEquivocationRecorder::default());

    // Create engine WITHOUT recorder
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    engine.state_mut().register_block(block_a, 0, None, None);
    engine.state_mut().register_block(block_b, 0, None, None);

    // First equivocation without recorder
    let vote_a = make_vote(ValidatorId(2), 0, block_a);
    let vote_b = make_vote(ValidatorId(2), 0, block_b);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_a);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_b);

    // Recorder doesn't see equivocation (not attached yet)
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 0);

    // Now set the recorder
    engine.set_equivocation_recorder(recorder.clone());

    // Equivocation in view 1
    let block_c = make_block_id(0xCC);
    let block_d = make_block_id(0xDD);
    engine.state_mut().register_block(block_c, 1, None, None);
    engine.state_mut().register_block(block_d, 1, None, None);

    let vote_c = make_vote(ValidatorId(2), 1, block_c);
    let vote_d = make_vote(ValidatorId(2), 1, block_d);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_c);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_d);

    // Now recorder sees equivocation
    assert_eq!(recorder.equivocations_total(ValidatorId(2)), 1);
}

#[test]
fn equivocating_vote_does_not_record_valid_vote_metrics() {
    use qbind_consensus::ValidatorVoteRecorder;

    // Test recorder for vote metrics
    #[derive(Debug, Default)]
    struct TestVoteRecorder {
        vote_count: AtomicU64,
    }

    impl ValidatorVoteRecorder for TestVoteRecorder {
        fn on_validator_vote(&self, _validator_id: ValidatorId, _view: u64) {
            self.vote_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    let validators = make_validator_set(2, 1);
    let equivocation_recorder = Arc::new(TestEquivocationRecorder::default());
    let vote_recorder = Arc::new(TestVoteRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_equivocation_recorder(equivocation_recorder.clone())
            .with_validator_vote_recorder(vote_recorder.clone());

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    engine.state_mut().register_block(block_a, 0, None, None);
    engine.state_mut().register_block(block_b, 0, None, None);

    // First vote (valid) - should record vote
    let vote_a = make_vote(ValidatorId(2), 0, block_a);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_a);
    assert_eq!(vote_recorder.vote_count.load(Ordering::Relaxed), 1);

    // Equivocating vote - should NOT record as valid vote
    let vote_b = make_vote(ValidatorId(2), 0, block_b);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_b);

    // Vote counter should still be 1 (equivocating vote not counted)
    assert_eq!(vote_recorder.vote_count.load(Ordering::Relaxed), 1);
    // But equivocation was recorded
    assert_eq!(equivocation_recorder.equivocations_total(ValidatorId(2)), 1);
}
