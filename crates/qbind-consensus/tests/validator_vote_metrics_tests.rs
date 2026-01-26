//! Tests for per-validator vote metrics (T128).
//!
//! These tests verify that the ValidatorVoteRecorder trait is correctly
//! wired into the BasicHotStuffEngine and that per-validator metrics are
//! recorded properly during consensus operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;

use qbind_consensus::{
    BasicHotStuffEngine, ConsensusValidatorSet, NoopValidatorVoteRecorder, ValidatorId,
    ValidatorSetEntry, ValidatorVoteRecorder,
};
use qbind_wire::consensus::Vote;

// ============================================================================
// Test Validator Vote Recorder
// ============================================================================

/// Per-validator counters for testing.
#[derive(Debug, Default)]
struct TestValidatorCounters {
    votes_total: AtomicU64,
    last_vote_view: AtomicU64,
}

/// A test implementation of ValidatorVoteRecorder that tracks all events.
#[derive(Debug, Default)]
struct TestValidatorVoteRecorder {
    validators: RwLock<HashMap<ValidatorId, TestValidatorCounters>>,
}

impl ValidatorVoteRecorder for TestValidatorVoteRecorder {
    fn on_validator_vote(&self, validator_id: ValidatorId, view: u64) {
        let mut validators = self.validators.write().unwrap();
        let counters = validators.entry(validator_id).or_default();
        counters.votes_total.fetch_add(1, Ordering::Relaxed);

        // Update last_vote_view monotonically
        loop {
            let current = counters.last_vote_view.load(Ordering::Relaxed);
            if view <= current {
                break;
            }
            match counters.last_vote_view.compare_exchange_weak(
                current,
                view,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }
}

impl TestValidatorVoteRecorder {
    fn votes_total(&self, validator_id: ValidatorId) -> u64 {
        let validators = self.validators.read().unwrap();
        validators
            .get(&validator_id)
            .map(|c| c.votes_total.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn last_vote_view(&self, validator_id: ValidatorId) -> u64 {
        let validators = self.validators.read().unwrap();
        validators
            .get(&validator_id)
            .map(|c| c.last_vote_view.load(Ordering::Relaxed))
            .unwrap_or(0)
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

// ============================================================================
// Tests: Basic Validator Vote Recorder Functionality
// ============================================================================

#[test]
fn noop_validator_vote_recorder_does_not_panic() {
    let recorder = NoopValidatorVoteRecorder;
    recorder.on_validator_vote(ValidatorId(1), 0);
    recorder.on_validator_vote(ValidatorId(2), 100);
}

#[test]
fn noop_validator_vote_recorder_is_send_sync_debug() {
    fn assert_send_sync_debug<T: Send + Sync + std::fmt::Debug>() {}
    assert_send_sync_debug::<NoopValidatorVoteRecorder>();
}

#[test]
fn test_recorder_tracks_multiple_validators() {
    let recorder = TestValidatorVoteRecorder::default();

    recorder.on_validator_vote(ValidatorId(1), 0);
    recorder.on_validator_vote(ValidatorId(2), 0);
    recorder.on_validator_vote(ValidatorId(1), 1);
    recorder.on_validator_vote(ValidatorId(3), 2);

    assert_eq!(recorder.votes_total(ValidatorId(1)), 2);
    assert_eq!(recorder.votes_total(ValidatorId(2)), 1);
    assert_eq!(recorder.votes_total(ValidatorId(3)), 1);
    assert_eq!(recorder.tracked_validators(), 3);
}

#[test]
fn test_recorder_updates_last_vote_view_monotonically() {
    let recorder = TestValidatorVoteRecorder::default();

    // Increasing views should update
    recorder.on_validator_vote(ValidatorId(1), 0);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 0);

    recorder.on_validator_vote(ValidatorId(1), 5);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 5);

    recorder.on_validator_vote(ValidatorId(1), 10);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 10);

    // Lower view should NOT update (monotonic)
    recorder.on_validator_vote(ValidatorId(1), 3);
    assert_eq!(
        recorder.last_vote_view(ValidatorId(1)),
        10,
        "Lower view should not update"
    );

    // But votes_total should still increment
    assert_eq!(recorder.votes_total(ValidatorId(1)), 4);
}

// ============================================================================
// Tests: Engine Integration - Per-Validator Vote Recording
// ============================================================================

#[test]
fn single_node_records_self_vote_per_validator() {
    // Single-node setup: node is always leader
    let validators = make_validator_set(1, 1);
    let recorder = Arc::new(TestValidatorVoteRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_validator_vote_recorder(recorder.clone());

    // Initial state: no votes recorded
    assert_eq!(recorder.votes_total(ValidatorId(1)), 0);

    // First leader step: propose and self-vote
    let _actions = engine.on_leader_step();

    // Should record self-vote
    assert_eq!(recorder.votes_total(ValidatorId(1)), 1);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 0);

    // Second leader step (view 1)
    let _actions2 = engine.on_leader_step();

    assert_eq!(recorder.votes_total(ValidatorId(1)), 2);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 1);
}

#[test]
fn two_node_records_votes_from_both_validators() {
    // Two-node setup
    let validators = make_validator_set(2, 1);
    let recorder = Arc::new(TestValidatorVoteRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_validator_vote_recorder(recorder.clone());

    // Node 1 is leader at view 0, produces proposal and self-vote
    let actions = engine.on_leader_step();
    assert!(!actions.is_empty());

    // Extract block_id from the proposal
    let block_id = match &actions[0] {
        qbind_consensus::ConsensusEngineAction::BroadcastProposal(proposal) => {
            let mut id = [0u8; 32];
            let proposer_bytes = ValidatorId(1).0.to_le_bytes();
            id[..8].copy_from_slice(&proposer_bytes);
            let view_bytes = 0u64.to_le_bytes();
            id[8..16].copy_from_slice(&view_bytes);
            id[16..32].copy_from_slice(&proposal.header.parent_block_id[..16]);
            id
        }
        _ => panic!("Expected BroadcastProposal"),
    };

    // After leader step: only node 1's self-vote recorded
    assert_eq!(recorder.votes_total(ValidatorId(1)), 1);
    assert_eq!(recorder.votes_total(ValidatorId(2)), 0);

    // Simulate receiving node 2's vote
    let vote_from_2 = make_vote(ValidatorId(2), 0, block_id);
    let result = engine.on_vote_event(ValidatorId(2), &vote_from_2);
    assert!(result.is_ok());

    // Now both validators should have votes recorded
    assert_eq!(recorder.votes_total(ValidatorId(1)), 1);
    assert_eq!(recorder.votes_total(ValidatorId(2)), 1);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 0);
    assert_eq!(recorder.last_vote_view(ValidatorId(2)), 0);
}

#[test]
fn wrong_epoch_vote_not_recorded_per_validator() {
    let validators = make_validator_set(2, 1);
    let recorder = Arc::new(TestValidatorVoteRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_validator_vote_recorder(recorder.clone());

    // Create a vote with wrong epoch
    let mut wrong_epoch_vote = make_vote(ValidatorId(2), 0, [0u8; 32]);
    wrong_epoch_vote.epoch = 999; // Wrong epoch

    let result = engine.on_vote_event(ValidatorId(2), &wrong_epoch_vote);

    // Vote should be rejected
    assert!(result.is_err());

    // No vote should be recorded for validator 2 (rejected before recording)
    assert_eq!(recorder.votes_total(ValidatorId(2)), 0);
}

#[test]
fn validator_vote_recorder_set_after_construction() {
    let validators = make_validator_set(1, 1);
    let recorder = Arc::new(TestValidatorVoteRecorder::default());

    // Create engine WITHOUT recorder
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // First leader step without recorder
    let _actions = engine.on_leader_step();
    assert_eq!(
        recorder.votes_total(ValidatorId(1)),
        0,
        "No recording without recorder"
    );

    // Now set the recorder
    engine.set_validator_vote_recorder(recorder.clone());

    // Second leader step with recorder
    let _actions2 = engine.on_leader_step();
    assert_eq!(recorder.votes_total(ValidatorId(1)), 1);
}

#[test]
fn last_vote_view_is_updated_monotonically_in_engine() {
    let validators = make_validator_set(1, 1);
    let recorder = Arc::new(TestValidatorVoteRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_validator_vote_recorder(recorder.clone());

    // Run through several views
    for _ in 0..5 {
        let _actions = engine.on_leader_step();
    }

    // last_vote_view should be the highest view seen
    assert_eq!(recorder.votes_total(ValidatorId(1)), 5);
    assert_eq!(recorder.last_vote_view(ValidatorId(1)), 4); // Views 0-4
}

#[test]
fn multiple_votes_from_same_validator_in_different_views() {
    // Use 3 validators so node 1 is leader at views 0 and 3
    let validators = make_validator_set(3, 1);
    let recorder = Arc::new(TestValidatorVoteRecorder::default());

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone())
            .with_validator_vote_recorder(recorder.clone());

    // Leader proposes at view 0
    let actions = engine.on_leader_step();
    assert!(
        !actions.is_empty(),
        "Leader should produce proposal at view 0"
    );
    let block_id_0 = extract_block_id(&actions);

    // Validator 2 votes for view 0
    let vote_v0_from_2 = make_vote(ValidatorId(2), 0, block_id_0);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_v0_from_2);

    // Validator 3 votes for view 0 - this should form QC
    let vote_v0_from_3 = make_vote(ValidatorId(3), 0, block_id_0);
    let _ = engine.on_vote_event(ValidatorId(3), &vote_v0_from_3);

    // Now at view 1. Node 2 is leader. Advance manually to view 3 where node 1 is leader again
    engine.advance_view(); // view 1 -> 2
    engine.advance_view(); // view 2 -> 3

    // Leader proposes at view 3 (node 1 is leader again since 3 % 3 == 0)
    let actions = engine.on_leader_step();
    assert!(
        !actions.is_empty(),
        "Leader should produce proposal at view 3"
    );
    let block_id_3 = extract_block_id(&actions);

    // Validator 2 votes for view 3
    let vote_v3_from_2 = make_vote(ValidatorId(2), 3, block_id_3);
    let _ = engine.on_vote_event(ValidatorId(2), &vote_v3_from_2);

    // Validator 2 should have 2 votes recorded (view 0 and view 3)
    assert_eq!(recorder.votes_total(ValidatorId(2)), 2);
    assert_eq!(recorder.last_vote_view(ValidatorId(2)), 3);
}

// Helper to extract block_id from actions
fn extract_block_id(actions: &[qbind_consensus::ConsensusEngineAction<ValidatorId>]) -> [u8; 32] {
    match &actions[0] {
        qbind_consensus::ConsensusEngineAction::BroadcastProposal(proposal) => {
            let proposer_id = proposal.header.proposer_index as u64;
            let view = proposal.header.height;
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&proposer_id.to_le_bytes());
            id[8..16].copy_from_slice(&view.to_le_bytes());
            id[16..32].copy_from_slice(&proposal.header.parent_block_id[..16]);
            id
        }
        _ => panic!("Expected BroadcastProposal"),
    }
}
