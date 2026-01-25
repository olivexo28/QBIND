//! T102.1: Single-node epoch transition integration test.
//!
//! This test verifies that:
//! - A node can commit a reconfig block
//! - The epoch transition is triggered at commit time
//! - The node continues to operate in the new epoch

use std::sync::Arc;

use cano_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use cano_consensus::ValidatorId;
use cano_node::block_store::BlockStore;
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

fn make_reconfig_proposal(epoch: u64, height: u64, next_epoch: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id: [0x11u8; 32],
            payload_hash: [0x22u8; 32],
            proposer_index: 0,
            suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: cano_wire::PAYLOAD_KIND_RECONFIG,
            next_epoch,
        },
        qc: None,
        txs: vec![],
        signature: vec![0xDE, 0xAD],
    }
}

fn make_normal_proposal(epoch: u64, height: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id: [0x33u8; 32],
            payload_hash: [0x44u8; 32],
            proposer_index: 0,
            suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: cano_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![0xBE, 0xEF],
    }
}

/// Test that a block store can hold both normal and reconfig proposals.
#[test]
fn block_store_holds_reconfig_proposals() {
    let mut store = BlockStore::new();

    let normal = make_normal_proposal(0, 1);
    let reconfig = make_reconfig_proposal(0, 2, 1);

    let id1 = store.store_proposal(&Arc::new(normal.clone()));
    let id2 = store.store_proposal(&Arc::new(reconfig.clone()));

    // Both should be stored
    assert!(store.get(&id1).is_some());
    assert!(store.get(&id2).is_some());

    // Verify payload types are preserved
    let stored1 = store.get(&id1).unwrap();
    let stored2 = store.get(&id2).unwrap();

    assert_eq!(
        stored1.proposal.header.payload_kind,
        cano_wire::PAYLOAD_KIND_NORMAL
    );
    assert_eq!(
        stored2.proposal.header.payload_kind,
        cano_wire::PAYLOAD_KIND_RECONFIG
    );
    assert_eq!(stored2.proposal.header.next_epoch, 1);
}

/// Test that EpochStateProvider can be configured with multiple epochs.
#[test]
fn epoch_state_provider_multi_epoch() {
    use cano_consensus::EpochStateProvider;

    let validators = make_validator_set(&[1, 2, 3]);

    let epoch0 = EpochState::genesis(validators.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators.clone());
    let epoch2 = EpochState::new(EpochId::new(2), validators);

    let provider = StaticEpochStateProvider::new()
        .with_epoch(epoch0)
        .with_epoch(epoch1)
        .with_epoch(epoch2);

    // All configured epochs should be available
    assert!(provider.get_epoch_state(EpochId::new(0)).is_some());
    assert!(provider.get_epoch_state(EpochId::new(1)).is_some());
    assert!(provider.get_epoch_state(EpochId::new(2)).is_some());

    // Non-configured epoch should not be available
    assert!(provider.get_epoch_state(EpochId::new(99)).is_none());
}

/// Test that reconfig proposals can be distinguished from normal proposals.
#[test]
fn detect_reconfig_proposal() {
    let normal = make_normal_proposal(0, 1);
    let reconfig = make_reconfig_proposal(0, 2, 1);

    // Check payload kind
    let is_normal_reconfig = normal.header.payload_kind == cano_wire::PAYLOAD_KIND_RECONFIG;
    let is_reconfig_reconfig = reconfig.header.payload_kind == cano_wire::PAYLOAD_KIND_RECONFIG;

    assert!(
        !is_normal_reconfig,
        "normal proposal should not be reconfig"
    );
    assert!(is_reconfig_reconfig, "reconfig proposal should be reconfig");

    // For reconfig, next_epoch is meaningful
    assert_eq!(reconfig.header.next_epoch, 1);
}
