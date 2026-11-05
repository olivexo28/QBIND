use qbind_consensus::basic_hotstuff_engine::RestoreCatchupBlock;
use qbind_consensus::{
    BasicHotStuffEngine, ConsensusLimitsConfig, ConsensusValidatorSet, HotStuffStateEngine,
    QuorumCertificate, ValidatorId, ValidatorSetEntry,
};

fn validators() -> ConsensusValidatorSet {
    ConsensusValidatorSet::new(
        (0..4)
            .map(|id| ValidatorSetEntry {
                id: ValidatorId(id),
                voting_power: 1,
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn state(capacity: usize) -> HotStuffStateEngine<[u8; 32]> {
    HotStuffStateEngine::with_limits(
        validators(),
        ConsensusLimitsConfig {
            max_pending_blocks: capacity,
            ..Default::default()
        },
    )
}

fn certify(state: &mut HotStuffStateEngine<[u8; 32]>, id: [u8; 32], view: u64) {
    for signer in 0..3 {
        state.on_vote(ValidatorId(signer), view, &id).unwrap();
    }
    assert!(state.get_block(&id).unwrap().own_qc.is_some());
}

fn cycle_registration(multi: bool, own_qc: bool) {
    let mut state = state(if multi { 3 } else { 2 });
    let a = [1; 32];
    let b = [2; 32];
    let root = [3; 32];
    let outside = [4; 32];
    state.register_block(a, 1, Some(if multi { b } else { a }), None);
    if multi {
        state.register_block(b, 2, Some(a), None);
    }
    state.register_block(root, 0, None, None);
    if own_qc {
        certify(&mut state, a, 1);
        // Isolate the own-QC walk: the lock's ancestry is complete and disjoint.
        state.set_locked_qc(QuorumCertificate::new(root, 0, vec![]));
    } else {
        state.set_locked_qc(QuorumCertificate::new(a, 1, vec![]));
    }
    let before = state.block_count();
    assert!(!state.can_admit_block_slot(&outside));
    assert_eq!(state.block_count(), before);
    assert_eq!(state.evicted_blocks(), 0);
    state.register_block(outside, 3, Some(a), None);
    assert_eq!(state.block_count(), before + 1);
    assert!(state.get_block(&outside).unwrap().own_qc.is_none());
    assert!(state.get_block(&a).is_some());
    assert!(state.get_block(&root).is_some());
    assert_eq!(state.evicted_blocks(), 0);
}

#[test]
fn locked_self_cycle_outside_candidate() {
    cycle_registration(false, false);
}

#[test]
fn locked_multi_cycle_outside_candidate() {
    cycle_registration(true, false);
}

#[test]
fn own_qc_self_cycle_outside_candidate() {
    cycle_registration(false, true);
}

#[test]
fn own_qc_multi_cycle_outside_candidate() {
    cycle_registration(true, true);
}

#[test]
fn complete_acyclic_protected_ancestors_and_unrelated_eviction() {
    for own_qc in [false, true] {
        let mut state = state(4);
        state.register_block([1; 32], 0, None, None);
        state.register_block([2; 32], 1, Some([1; 32]), None);
        state.register_block([3; 32], 2, Some([2; 32]), None);
        state.register_block([4; 32], 0, None, None);
        if own_qc {
            certify(&mut state, [3; 32], 2);
            state.set_locked_qc(QuorumCertificate::new([4; 32], 0, vec![]));
        } else {
            state.set_locked_qc(QuorumCertificate::new([3; 32], 2, vec![]));
        }
        assert_eq!(state.can_admit_block_slot(&[5; 32]), !own_qc);
        state.register_block([5; 32], 3, Some([3; 32]), None);
        for id in 1..=3 {
            assert!(state.get_block(&[id; 32]).is_some());
        }
        assert_eq!(state.evicted_blocks(), 1);
        // Own-QC case protects root 4 too, so legacy eviction removes candidate 5.
        assert_eq!(state.get_block(&[4; 32]).is_some(), own_qc);
        assert_eq!(state.get_block(&[5; 32]).is_some(), !own_qc);
    }
}

#[test]
fn missing_protected_parent_or_lock_is_indeterminate() {
    for own_qc in [false, true] {
        let mut state = state(2);
        state.register_block([1; 32], 1, Some([99; 32]), None);
        state.register_block([2; 32], 0, None, None);
        if own_qc {
            certify(&mut state, [1; 32], 1);
            state.set_locked_qc(QuorumCertificate::new([2; 32], 0, vec![]));
        } else {
            state.set_locked_qc(QuorumCertificate::new([1; 32], 1, vec![]));
        }
        assert!(!state.can_admit_block_slot(&[3; 32]));
        state.register_block([3; 32], 2, None, None);
        assert_eq!(state.block_count(), 3);
        assert_eq!(state.evicted_blocks(), 0);
    }
    let mut absent_lock = state(1);
    absent_lock.register_block([1; 32], 0, None, None);
    absent_lock.set_locked_qc(QuorumCertificate::new([99; 32], 1, vec![]));
    assert!(!absent_lock.can_admit_block_slot(&[2; 32]));
    absent_lock.register_block([2; 32], 2, None, None);
    assert_eq!(absent_lock.block_count(), 2);
    assert_eq!(absent_lock.evicted_blocks(), 0);
}

#[test]
fn unprotected_missing_parent_and_no_lock_keep_legacy_behavior() {
    let mut state = state(1);
    state.register_block([1; 32], 1, Some([99; 32]), None);
    assert_eq!(state.get_block(&[1; 32]).unwrap().height, 0);
    assert!(state.can_admit_block_slot(&[2; 32]));
    state.register_block([2; 32], 2, None, None);
    assert!(state.get_block(&[1; 32]).is_none());
    assert_eq!(state.evicted_blocks(), 1);
}

#[test]
fn committed_height_protection_is_unchanged() {
    let mut state = state(1);
    state.initialize_from_snapshot_baseline([1; 32], 5, 5);
    assert!(!state.can_admit_block_slot(&[2; 32]));
    state.register_block([2; 32], 6, Some([1; 32]), None);
    assert!(state.get_block(&[1; 32]).is_some());
    assert!(state.get_block(&[2; 32]).is_none());
    assert_eq!(state.committed_height(), Some(5));
}

fn catchup_witness(capacity: usize) {
    let mut engine = BasicHotStuffEngine::with_state_limits(
        ValidatorId(0),
        validators(),
        ConsensusLimitsConfig {
            max_pending_blocks: capacity,
            ..Default::default()
        },
    );
    let mut anchor = [0; 32];
    anchor[..8].copy_from_slice(&engine.leader_for_view(2).0.to_le_bytes());
    anchor[8..16].copy_from_slice(&2u64.to_le_bytes());
    let prefix: [u8; 16] = anchor[..16].try_into().unwrap();
    anchor[16..].copy_from_slice(&prefix);
    engine.initialize_from_snapshot_baseline(anchor, 1);
    let mut parent = anchor;
    let mut blocks = Vec::new();
    for height in 2..=(capacity as u64 + 2) {
        let proposer = engine.leader_for_view(height);
        let mut block_id = [0; 32];
        block_id[..8].copy_from_slice(&proposer.0.to_le_bytes());
        block_id[8..16].copy_from_slice(&height.to_le_bytes());
        block_id[16..].copy_from_slice(&parent[..16]);
        blocks.push(RestoreCatchupBlock {
            height,
            view: height,
            parent_block_id: parent,
            block_id,
            proposer,
            qc_signers: vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
        });
        parent = block_id;
    }
    assert_eq!(blocks[0].block_id, anchor);
    assert_eq!(
        engine.apply_restore_catchup_blocks(&blocks).unwrap(),
        capacity + 1
    );
    assert_eq!(engine.state().block_count(), capacity + 1);
    assert_eq!(engine.state().evicted_blocks(), 0);
    assert_eq!(engine.locked_qc().unwrap().block_id, parent);
    assert_eq!(engine.committed_height(), Some(capacity as u64));
    assert_eq!(engine.state().retained_evidence_bytes(), 0);
}

#[test]
fn registration_before_vote_catchup_witness_scaled() {
    catchup_witness(4);
}

#[test]
fn registration_before_vote_catchup_witness_default_capacity() {
    catchup_witness(4096);
}
