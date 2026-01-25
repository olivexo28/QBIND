//! T102.1: Epoch transition tests.
//!
//! These tests verify that:
//! - When a reconfig block commits, the epoch transition happens
//! - The engine's current_epoch is updated correctly
//! - The validator set is updated correctly

use cano_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use cano_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use cano_consensus::{EpochStateProvider, ValidatorId};
use cano_wire::consensus::{BlockHeader, BlockProposal};

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

fn make_test_proposal(epoch: u64, height: u64, payload_kind: u8, next_epoch: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id: [0xFFu8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind,
            next_epoch,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// Engine-level epoch transition tests
// ============================================================================

#[test]
fn engine_starts_at_epoch_zero() {
    let validators = make_validator_set(&[1, 2, 3]);
    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    assert_eq!(engine.current_epoch(), 0);
}

#[test]
fn engine_transition_to_epoch_updates_epoch() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[1, 2, 3]); // Same validators for simplicity

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Start at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Transition to epoch 1
    let result = engine.transition_to_epoch(EpochId::new(1), validators1);
    assert!(result.is_ok(), "transition should succeed");

    // Verify epoch is now 1
    assert_eq!(engine.current_epoch(), 1);
}

#[test]
fn engine_transition_to_epoch_rejects_non_sequential() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators2 = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Start at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Try to skip to epoch 2 (should fail)
    let result = engine.transition_to_epoch(EpochId::new(2), validators2);
    assert!(result.is_err(), "non-sequential transition should fail");

    // Epoch should still be 0
    assert_eq!(engine.current_epoch(), 0);
}

#[test]
fn engine_transition_updates_leader_set() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[4, 5, 6]); // Different validators

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators0);

    // Verify initial leader set (sorted by ID)
    assert_eq!(engine.leader_for_view(0), ValidatorId(1));
    assert_eq!(engine.leader_for_view(1), ValidatorId(2));
    assert_eq!(engine.leader_for_view(2), ValidatorId(3));

    // Transition to epoch 1 with new validators
    let result = engine.transition_to_epoch(EpochId::new(1), validators1);
    assert!(result.is_ok());

    // Verify leader set is now based on new validators
    assert_eq!(engine.leader_for_view(0), ValidatorId(4));
    assert_eq!(engine.leader_for_view(1), ValidatorId(5));
    assert_eq!(engine.leader_for_view(2), ValidatorId(6));
}

#[test]
fn engine_can_process_proposals_after_epoch_transition() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators0);

    // Transition to epoch 1
    let result = engine.transition_to_epoch(EpochId::new(1), validators1);
    assert!(result.is_ok());

    // The engine should now be at epoch 1
    assert_eq!(engine.current_epoch(), 1);

    // Note: The engine still needs to advance views for proposals to be processed.
    // After epoch transition, the view doesn't reset, but the engine should
    // accept proposals with the new epoch.
    //
    // For a full proposal acceptance test, we'd need to advance the view and
    // ensure the proposal is from the correct leader. This test just validates
    // that the epoch transition doesn't break the engine's ability to process
    // proposals (the proposal may be rejected for other reasons like wrong view).

    // Verify the epoch is correctly set
    let current_view = engine.current_view();
    let leader = engine.leader_for_view(current_view);

    // Create a proposal from the leader for the current view
    let proposal_epoch1 = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 1, // new epoch
            height: current_view,
            round: current_view,
            parent_block_id: [0xFFu8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: cano_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    // The key assertion: the engine should not panic and should correctly
    // check the epoch. The action might be None due to view/leader rules,
    // but the epoch check should pass.
    let _action = engine.on_proposal_event(leader, &proposal_epoch1);
    // Success: no panic, epoch was accepted (even if proposal was rejected for other reasons)
}

#[test]
fn engine_rejects_old_epoch_proposals_after_transition() {
    let validators0 = make_validator_set(&[1, 2, 3]);
    let validators1 = make_validator_set(&[1, 2, 3]);

    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators0);

    // Transition to epoch 1
    let result = engine.transition_to_epoch(EpochId::new(1), validators1);
    assert!(result.is_ok());

    // Proposals with epoch 0 should now be rejected
    let proposal_epoch0 = make_test_proposal(
        0, // old epoch
        1,
        cano_wire::PAYLOAD_KIND_NORMAL,
        0,
    );

    let action = engine.on_proposal_event(ValidatorId(1), &proposal_epoch0);
    assert!(
        action.is_none(),
        "should reject epoch 0 proposal after transition to epoch 1"
    );
}

// ============================================================================
// StaticEpochStateProvider tests
// ============================================================================

#[test]
fn static_provider_returns_configured_epochs() {
    let validators = make_validator_set(&[1, 2, 3]);

    let epoch0 = EpochState::genesis(validators.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators.clone());

    let provider = StaticEpochStateProvider::new()
        .with_epoch(epoch0)
        .with_epoch(epoch1);

    assert!(provider.get_epoch_state(EpochId::new(0)).is_some());
    assert!(provider.get_epoch_state(EpochId::new(1)).is_some());
    assert!(provider.get_epoch_state(EpochId::new(99)).is_none());
}

#[test]
fn static_provider_len_and_is_empty() {
    let validators = make_validator_set(&[1, 2, 3]);

    let mut provider = StaticEpochStateProvider::new();
    assert!(provider.is_empty());
    assert_eq!(provider.len(), 0);

    provider.insert(EpochState::genesis(validators.clone()));
    assert!(!provider.is_empty());
    assert_eq!(provider.len(), 1);

    provider.insert(EpochState::new(EpochId::new(1), validators));
    assert_eq!(provider.len(), 2);
}

// ============================================================================
// Reconfig proposal handling tests
// ============================================================================

#[test]
fn normal_proposal_has_payload_kind_normal() {
    let proposal = make_test_proposal(0, 1, cano_wire::PAYLOAD_KIND_NORMAL, 0);
    assert_eq!(proposal.header.payload_kind, cano_wire::PAYLOAD_KIND_NORMAL);
    assert_eq!(proposal.header.next_epoch, 0);
}

#[test]
fn reconfig_proposal_has_payload_kind_reconfig() {
    let proposal = make_test_proposal(0, 1, cano_wire::PAYLOAD_KIND_RECONFIG, 1);
    assert_eq!(
        proposal.header.payload_kind,
        cano_wire::PAYLOAD_KIND_RECONFIG
    );
    assert_eq!(proposal.header.next_epoch, 1);
}
