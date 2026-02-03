//! T101: Epoch validation tests for BasicHotStuffEngine.
//!
//! These tests verify that:
//! - Votes with wrong epoch are rejected
//! - Proposals with wrong epoch are rejected
//! - Same-epoch votes and proposals are accepted

use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::ValidatorId;
use qbind_consensus::{ConsensusVerifyError, QcValidationError};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

fn make_validator_set(num: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_test_vote(epoch: u64, height: u64, round: u64) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![],
    }
}

fn make_test_proposal(epoch: u64, height: u64, round: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round,
            parent_block_id: [0xFFu8; 32], // "no parent" sentinel
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// Vote epoch validation tests
// ============================================================================

#[test]
fn vote_with_correct_epoch_is_accepted() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Engine starts at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Vote with epoch 0 should be accepted (no error, though may not form QC)
    let vote = make_test_vote(0, 0, 0);
    let result = engine.on_vote_event(ValidatorId(2), &vote);
    assert!(
        result.is_ok(),
        "Vote with matching epoch should be accepted"
    );
}

#[test]
fn vote_with_wrong_epoch_is_rejected() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Engine is at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Vote with epoch 1 should be rejected
    let vote = make_test_vote(1, 0, 0);
    let result = engine.on_vote_event(ValidatorId(2), &vote);

    assert!(result.is_err(), "Vote with wrong epoch should be rejected");
    let err = result.unwrap_err();
    match err {
        QcValidationError::Verify(ConsensusVerifyError::WrongEpoch { expected, actual }) => {
            assert_eq!(expected, 0);
            assert_eq!(actual, 1);
        }
        _ => panic!("Expected WrongEpoch error, got {:?}", err),
    }
}

#[test]
fn vote_with_wrong_epoch_after_set_is_rejected() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Set epoch to 5
    engine.set_current_epoch(5);
    assert_eq!(engine.current_epoch(), 5);

    // Vote with epoch 0 should now be rejected
    let vote = make_test_vote(0, 0, 0);
    let result = engine.on_vote_event(ValidatorId(2), &vote);

    assert!(result.is_err(), "Vote with wrong epoch should be rejected");
    match result.unwrap_err() {
        QcValidationError::Verify(ConsensusVerifyError::WrongEpoch { expected, actual }) => {
            assert_eq!(expected, 5);
            assert_eq!(actual, 0);
        }
        _ => panic!("Expected WrongEpoch error"),
    }

    // Vote with epoch 5 should be accepted
    let vote5 = make_test_vote(5, 0, 0);
    let result5 = engine.on_vote_event(ValidatorId(2), &vote5);
    assert!(
        result5.is_ok(),
        "Vote with matching epoch should be accepted"
    );
}

// ============================================================================
// Proposal epoch validation tests
// ============================================================================

#[test]
fn proposal_with_wrong_epoch_returns_none() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Engine is at epoch 0
    assert_eq!(engine.current_epoch(), 0);

    // Proposal with epoch 1 should be rejected (returns None)
    let proposal = make_test_proposal(1, 0, 0);
    let action = engine.on_proposal_event(ValidatorId(1), &proposal);

    assert!(
        action.is_none(),
        "Proposal with wrong epoch should return None"
    );
}

#[test]
fn proposal_with_correct_epoch_is_processed() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators);

    // Engine is at epoch 0, node is validator 2, leader for view 0 is validator 1
    assert_eq!(engine.current_epoch(), 0);

    // Proposal with epoch 0 from leader (validator 1) should be processed
    let proposal = make_test_proposal(0, 0, 0);
    let action = engine.on_proposal_event(ValidatorId(1), &proposal);

    // If we're validator 2 (not leader) and proposal is from leader, we should vote
    assert!(
        action.is_some(),
        "Proposal with correct epoch from leader should be processed"
    );
}

// ============================================================================
// Epoch getter/setter tests
// ============================================================================

#[test]
fn engine_starts_at_epoch_zero() {
    let validators = make_validator_set(3);
    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    assert_eq!(engine.current_epoch(), 0);
}

#[test]
fn set_current_epoch_updates_epoch() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    engine.set_current_epoch(42);
    assert_eq!(engine.current_epoch(), 42);

    engine.set_current_epoch(100);
    assert_eq!(engine.current_epoch(), 100);
}

#[test]
fn verify_epoch_returns_ok_for_matching_epoch() {
    let validators = make_validator_set(3);
    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    assert!(engine.verify_epoch(0).is_ok());
}

#[test]
fn verify_epoch_returns_error_for_mismatched_epoch() {
    let validators = make_validator_set(3);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);
    engine.set_current_epoch(5);

    let result = engine.verify_epoch(0);
    assert!(result.is_err());
    match result.unwrap_err() {
        ConsensusVerifyError::WrongEpoch { expected, actual } => {
            assert_eq!(expected, 5);
            assert_eq!(actual, 0);
        }
        _ => panic!("Expected WrongEpoch error"),
    }
}
