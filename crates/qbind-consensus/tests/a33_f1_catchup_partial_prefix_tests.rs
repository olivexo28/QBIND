use qbind_consensus::basic_hotstuff_engine::{RestoreCatchupBlock, RestoreCatchupError};
use qbind_consensus::{
    BasicHotStuffEngine, ConsensusValidatorSet, QcValidationError, QuorumCertificate, ValidatorId,
    ValidatorSetEntry,
};

type BlockId = [u8; 32];
const ANCHOR: BlockId = [0x44; 32];

#[derive(Debug, PartialEq, Eq)]
struct BlockObservation {
    id: BlockId,
    view: u64,
    height: u64,
    parent: Option<BlockId>,
    justify_qc: Option<QuorumCertificate<BlockId>>,
    own_qc: Option<QuorumCertificate<BlockId>>,
    verified: bool,
    evidence_charge: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    blocks: Vec<BlockObservation>,
    votes: Vec<usize>,
    lock: Option<QuorumCertificate<BlockId>>,
    committed: Option<BlockId>,
    height: Option<u64>,
    commits: Vec<(BlockId, u64, u64)>,
    view: u64,
    block_count: usize,
    evicted_blocks: u64,
    retained_bytes: u64,
}

fn normalized(qc: &QuorumCertificate<BlockId>) -> QuorumCertificate<BlockId> {
    let mut qc = qc.clone();
    qc.signers.sort_by_key(|signer| signer.0);
    qc
}

fn observe(
    engine: &BasicHotStuffEngine<BlockId>,
    inputs: &[RestoreCatchupBlock<BlockId>],
) -> Observation {
    let mut blocks: Vec<_> = engine
        .state()
        .blocks_iter()
        .map(|block| BlockObservation {
            id: block.id,
            view: block.view,
            height: block.height,
            parent: block.parent_id,
            justify_qc: block.justify_qc.as_ref().map(normalized),
            own_qc: block.own_qc.as_ref().map(normalized),
            verified: block.verified_justification.is_some(),
            evidence_charge: block.verified_justification_charge,
        })
        .collect();
    blocks.sort_by_key(|block| block.id);
    Observation {
        blocks,
        votes: inputs
            .iter()
            .map(|block| engine.state().vote_count(block.view, &block.block_id))
            .collect::<Vec<_>>(),
        lock: engine.locked_qc().map(normalized),
        committed: engine.committed_block().copied(),
        height: engine.committed_height(),
        commits: engine
            .commit_log()
            .iter()
            .map(|entry| (entry.block_id, entry.view, entry.height))
            .collect(),
        view: engine.current_view(),
        block_count: engine.state().block_count(),
        evicted_blocks: engine.state().evicted_blocks(),
        retained_bytes: engine.state().retained_evidence_bytes(),
    }
}

fn fixture() -> (
    BasicHotStuffEngine<BlockId>,
    Vec<RestoreCatchupBlock<BlockId>>,
) {
    let validators = ConsensusValidatorSet::new(
        (0..4)
            .map(|id| ValidatorSetEntry {
                id: ValidatorId(id),
                voting_power: 1,
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mut engine = BasicHotStuffEngine::new(ValidatorId(2), validators);
    engine.initialize_from_snapshot_baseline(ANCHOR, 10);
    let mut parent = ANCHOR;
    let blocks = (11..=15)
        .map(|height| {
            let proposer = engine.leader_for_view(height);
            let mut block_id = [0; 32];
            block_id[..8].copy_from_slice(&proposer.0.to_le_bytes());
            block_id[8..16].copy_from_slice(&height.to_le_bytes());
            block_id[16..].copy_from_slice(&parent[..16]);
            let block = RestoreCatchupBlock {
                height,
                view: height,
                parent_block_id: parent,
                block_id,
                proposer,
                qc_signers: vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
            };
            parent = block_id;
            block
        })
        .collect();
    (engine, blocks)
}

fn invalid_qc() -> RestoreCatchupError<BlockId> {
    RestoreCatchupError::InvalidQc(QcValidationError::NonMemberSigner(ValidatorId(99)))
}

#[test]
fn valid_prefix_then_invalid_qc_retains_prefix_effects_without_final_view_advance() {
    let (mut engine, mut blocks) = fixture();
    let before = observe(&engine, &blocks);
    assert_eq!(before.block_count, 1);
    assert_eq!(before.height, Some(10));
    assert_eq!(before.committed, Some(ANCHOR));
    assert_eq!(before.view, 11);
    assert_eq!(before.votes, vec![0; 5]);
    assert!(before.lock.is_none());
    assert!(before.commits.is_empty());

    blocks[4].qc_signers.push(ValidatorId(99));
    assert_eq!(
        engine.apply_restore_catchup_blocks(&blocks),
        Err(invalid_qc())
    );
    let after = observe(&engine, &blocks);
    assert_ne!(after, before);
    assert_eq!(after.votes, vec![3, 3, 3, 3, 0]);
    assert_eq!(after.block_count, 5);
    assert_eq!(after.lock.as_ref().unwrap().block_id, blocks[3].block_id);
    assert_eq!(after.lock.as_ref().unwrap().view, 14);
    assert_eq!(after.height, Some(12));
    assert_eq!(after.committed, Some(blocks[1].block_id));
    assert_eq!(
        after.commits,
        vec![(blocks[0].block_id, 11, 11), (blocks[1].block_id, 12, 12)]
    );
    assert_eq!(after.view, before.view);
    assert_eq!(after.evicted_blocks, 0);
    assert_eq!(after.retained_bytes, 0);
    assert!(engine.state().get_block(&blocks[4].block_id).is_none());
    for block in &blocks[..4] {
        let retained = engine.state().get_block(&block.block_id).unwrap();
        assert_eq!(
            retained.own_qc.as_ref().map(normalized),
            Some(QuorumCertificate::new(
                block.block_id,
                block.view,
                vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
            ))
        );
        assert!(retained.verified_justification.is_none());
        assert_eq!(retained.verified_justification_charge, 0);
    }

    let (mut prefix_only, valid_blocks) = fixture();
    assert_eq!(
        prefix_only.apply_restore_catchup_blocks(&valid_blocks[..4]),
        Ok(4)
    );
    let mut expected = observe(&prefix_only, &valid_blocks);
    assert_eq!(expected.view, 15);
    // Error returns before the end-of-batch view update; compare the other observations.
    expected.view = before.view;
    assert_eq!(after, expected);
}

#[test]
fn invalid_first_qc_leaves_the_same_observations_unchanged() {
    let (mut engine, mut blocks) = fixture();
    blocks[0].qc_signers.push(ValidatorId(99));
    let before = observe(&engine, &blocks);
    assert_eq!(
        engine.apply_restore_catchup_blocks(&blocks),
        Err(invalid_qc())
    );
    assert_eq!(observe(&engine, &blocks), before);
}

#[test]
fn valid_suffix_records_all_votes_qcs_commits_and_final_view_advance() {
    let (mut engine, blocks) = fixture();
    let before = observe(&engine, &blocks);
    assert_eq!(engine.apply_restore_catchup_blocks(&blocks), Ok(5));
    let after = observe(&engine, &blocks);
    assert_ne!(after, before);
    assert_eq!(after.votes, vec![3; 5]);
    assert_eq!(after.block_count, 6);
    assert_eq!(after.lock.as_ref().unwrap().block_id, blocks[4].block_id);
    assert_eq!(after.lock.as_ref().unwrap().view, 15);
    assert_eq!(after.height, Some(13));
    assert_eq!(after.committed, Some(blocks[2].block_id));
    assert_eq!(
        after.commits,
        blocks[..3]
            .iter()
            .map(|block| (block.block_id, block.view, block.height))
            .collect::<Vec<_>>()
    );
    assert_eq!(after.view, 16);
    assert_eq!(after.evicted_blocks, 0);
    assert_eq!(after.retained_bytes, 0);
    for block in &after.blocks {
        assert_eq!(block.own_qc.is_some(), block.id != ANCHOR);
        assert!(!block.verified);
        assert_eq!(block.evidence_charge, 0);
    }
}
