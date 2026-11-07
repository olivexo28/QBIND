use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::verify_quorum_certificate_with_domain;
use qbind_consensus::{
    BasicHotStuffEngine, BoundedSafetyOutcome, ConsensusEngineAction, ConsensusLimitsConfig,
    ConsensusValidatorSet, HotStuffStateEngine, QuorumCertificate, SafetyBranch, SafetyDecision,
    SafetyDecisionGate, SafetyDecisionObserver, SafetyDecisionView, SafetyGateRefusal, ValidatorId,
    ValidatorSetEntry, VerifiedQuorumCertificate,
};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

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

fn assert_read_only_decision(
    state: &HotStuffStateEngine<[u8; 32]>,
    candidate: [u8; 32],
    expected: SafetyDecision,
) {
    let before = format!("{state:?}");
    assert_eq!(state.safety_decision(&candidate), expected);
    assert_eq!(
        state.is_safe_to_vote_on_block(&candidate),
        matches!(expected, SafetyDecision::Safe(_))
    );
    assert_eq!(format!("{state:?}"), before);
}

fn cycle_state(multi: bool) -> HotStuffStateEngine<[u8; 32]> {
    let mut state = state(16);
    state.register_block(
        [1; 32],
        1,
        Some(if multi { [2; 32] } else { [1; 32] }),
        None,
    );
    if multi {
        state.register_block([2; 32], 2, Some([1; 32]), None);
    }
    state.register_block([3; 32], 3, Some([1; 32]), None);
    state.register_block([9; 32], 0, None, None);
    state.set_locked_qc(QuorumCertificate::new([9; 32], 10, vec![]));
    state
}

#[test]
fn state_self_cycle_outside_candidate() {
    assert_read_only_decision(&cycle_state(false), [3; 32], SafetyDecision::Unsafe);
}

#[test]
fn state_multi_cycle_outside_candidate() {
    assert_read_only_decision(&cycle_state(true), [3; 32], SafetyDecision::Unsafe);
}

#[test]
fn acyclic_positive_negative_and_exact_retained_boundary() {
    // The lock is the final visited node: N retained nodes, N-1 transitions.
    for n in [1u8, 2, 16] {
        let mut state = state(0);
        state.set_locked_qc(QuorumCertificate::new([99; 32], 50, vec![]));
        for id in 1..=n {
            state.register_block(
                [id; 32],
                u64::from(id),
                (id > 1).then(|| [id - 1; 32]),
                None,
            );
        }
        // Indeterminate protected ancestry keeps legacy insertion over capacity.
        assert_eq!(state.block_count(), usize::from(n));
        state.set_locked_qc(QuorumCertificate::new([1; 32], 50, vec![]));
        assert_read_only_decision(
            &state,
            [n; 32],
            SafetyDecision::Safe(SafetyBranch::Ancestry),
        );
        assert_eq!(
            state.bounded_safety_decision(&[n; 32], usize::from(n - 1)),
            BoundedSafetyOutcome::SafeAncestry {
                hops: usize::from(n - 1)
            }
        );
        if n > 1 {
            assert_eq!(
                state.bounded_safety_decision(&[n; 32], usize::from(n - 2)),
                BoundedSafetyOutcome::BoundExhausted
            );
        }
        state.set_locked_qc(QuorumCertificate::new([99; 32], 50, vec![]));
        assert_read_only_decision(&state, [n; 32], SafetyDecision::Unsafe);
    }
}

#[test]
fn missing_candidate_parent_and_retained_lock_refuse() {
    let mut state = state(16);
    state.set_locked_qc(QuorumCertificate::new([9; 32], 10, vec![]));
    assert_read_only_decision(&state, [3; 32], SafetyDecision::Unsafe);
    state.register_block([3; 32], 3, Some([8; 32]), None);
    assert_read_only_decision(&state, [3; 32], SafetyDecision::Unsafe);
    // Even the lock's ID as a missing parent is not proof: lookup must succeed.
    state.register_block([3; 32], 3, Some([9; 32]), None);
    assert_read_only_decision(&state, [3; 32], SafetyDecision::Unsafe);
    state.register_block([9; 32], 0, None, None);
    assert_read_only_decision(
        &state,
        [3; 32],
        SafetyDecision::Safe(SafetyBranch::Ancestry),
    );
}

#[test]
fn existing_short_circuits_and_cycle_containing_lock_are_preserved() {
    let mut state = cycle_state(true);
    state.set_locked_qc(QuorumCertificate::new([2; 32], 10, vec![]));
    assert_read_only_decision(
        &state,
        [3; 32],
        SafetyDecision::Safe(SafetyBranch::Ancestry),
    );
    // View sufficiency remains an independent OR branch, even with absent lock.
    state.set_locked_qc(QuorumCertificate::new([99; 32], 10, vec![]));
    for view in [9, 10, 11] {
        state.register_block(
            [3; 32],
            3,
            Some([1; 32]),
            Some(QuorumCertificate::new([8; 32], view, vec![])),
        );
        assert_read_only_decision(
            &state,
            [3; 32],
            if view < 10 {
                SafetyDecision::Unsafe
            } else {
                SafetyDecision::Safe(SafetyBranch::ViewSufficiency)
            },
        );
    }
    let mut no_lock = state_with_cycle_no_lock();
    assert_read_only_decision(
        &no_lock,
        [1; 32],
        SafetyDecision::Safe(SafetyBranch::NoLock),
    );
    no_lock.register_block([3; 32], 3, Some([99; 32]), None);
    for candidate in [[3; 32], [99; 32]] {
        assert_read_only_decision(
            &no_lock,
            candidate,
            SafetyDecision::Safe(SafetyBranch::NoLock),
        );
    }
}

fn state_with_cycle_no_lock() -> HotStuffStateEngine<[u8; 32]> {
    let mut state = state(16);
    state.register_block([1; 32], 1, Some([1; 32]), None);
    state
}

fn proposal(view: u64, parent: [u8; 32], proposer: ValidatorId) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: view,
            round: view,
            parent_block_id: parent,
            payload_hash: [0; 32],
            proposer_index: proposer.0 as u16,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

fn candidate_id(proposal: &BlockProposal, proposer: ValidatorId) -> [u8; 32] {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&proposer.0.to_le_bytes());
    id[8..16].copy_from_slice(&proposal.header.height.to_le_bytes());
    id[16..].copy_from_slice(&proposal.header.parent_block_id[..16]);
    id
}

#[derive(Default)]
struct Hooks {
    calls: usize,
}

impl SafetyDecisionObserver<[u8; 32]> for Hooks {
    fn observe(&mut self, _: &SafetyDecisionView<'_, [u8; 32]>) {
        self.calls += 1;
    }
}

impl SafetyDecisionGate<[u8; 32]> for Hooks {
    fn evaluate(&mut self, _: &SafetyDecisionView<'_, [u8; 32]>) -> Result<(), SafetyGateRefusal> {
        self.calls += 1;
        Ok(())
    }
}

fn proposal_cycle(multi: bool) {
    for route in 0..3 {
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), validators());
        *engine.state_mut() = cycle_state(multi);
        let lock = engine.locked_qc().unwrap().clone();
        let before_commit = engine.committed_height();
        let before_evictions = engine.state().evicted_blocks();
        let mut hooks = Hooks::default();
        let view = 20;
        let leader = engine.leader_for_view(view);
        let p = proposal(view, [1; 32], leader);
        let id = candidate_id(&p, leader);
        let prior_nodes: Vec<_> = engine
            .state()
            .blocks_iter()
            .map(|node| (node.id, format!("{node:?}")))
            .collect();
        let action = match route {
            0 => engine.on_proposal_event(leader, &p),
            1 => engine.on_proposal_event_observed(leader, &p, &mut hooks),
            _ => engine
                .on_proposal_event_gated(leader, &p, &mut hooks)
                .unwrap(),
        };
        assert!(action.is_none());
        assert_eq!(hooks.calls, 0);
        assert_eq!(engine.current_view(), view); // Earlier advancement is not rolled back.
        let candidate = engine.state().get_block(&id).unwrap();
        assert_eq!(candidate.parent_id, Some([1; 32]));
        assert!(candidate.own_qc.is_none());
        assert_eq!(engine.state().vote_count(view, &id), 0);
        for (id, before) in &prior_nodes {
            assert_eq!(
                format!("{:?}", engine.state().get_block(id).unwrap()),
                *before
            );
        }
        assert_eq!(engine.state().block_count(), prior_nodes.len() + 1);
        assert_eq!(engine.locked_qc(), Some(&lock));
        assert_eq!(engine.committed_height(), before_commit);
        assert_eq!(engine.state().evicted_blocks(), before_evictions);
        assert_eq!(engine.state().retained_evidence_bytes(), 0);
        // Registration is the only state-engine effect; a repeat must do no more.
        let after = format!("{:?}", engine.state());
        assert!(engine.on_proposal_event(leader, &p).is_none());
        assert_eq!(format!("{:?}", engine.state()), after);
        // The same view can still vote on a proven extension: latch not consumed.
        let good = proposal(view, lock.block_id, leader);
        assert!(matches!(
            engine.on_proposal_event(leader, &good),
            Some(ConsensusEngineAction::BroadcastVote(_))
        ));
        let good_id = candidate_id(&good, leader);
        assert_eq!(engine.state().vote_count(view, &good_id), 1);
        assert_eq!(engine.locked_qc(), Some(&lock)); // One of four votes is not a QC.
        assert!(engine.on_proposal_event(leader, &good).is_none());
    }
}

#[test]
fn proposal_self_cycle_outside_candidate() {
    proposal_cycle(false);
}

#[test]
fn proposal_multi_cycle_outside_candidate() {
    proposal_cycle(true);
}

#[test]
fn proposal_missing_ancestry_refusal_and_acyclic_retry() {
    let mut engine = BasicHotStuffEngine::new(ValidatorId(0), validators());
    engine
        .state_mut()
        .set_locked_qc(QuorumCertificate::new([9; 32], 10, vec![]));
    let leader = engine.leader_for_view(20);
    let p = proposal(20, [9; 32], leader);
    assert!(engine.on_proposal_event(leader, &p).is_none());
    let id = candidate_id(&p, leader);
    assert_eq!(engine.state().vote_count(20, &id), 0);
    assert_eq!(engine.current_view(), 20);
    engine.state_mut().register_block([9; 32], 0, None, None);
    assert!(matches!(
        engine.on_proposal_event(leader, &p),
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
}

#[derive(Debug)]
struct TestKeys(Vec<Vec<u8>>);

impl SuiteAwareValidatorKeyProvider for TestKeys {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.0
            .get(id.0 as usize)
            .map(|key| (SUITE_PQ_RESERVED_1, key.clone()))
    }
}

fn verified_qc() -> Arc<VerifiedQuorumCertificate> {
    let domain = ProposalVoteSigningDomainV2::try_new(ChainId(1), 1, [9; 32], [8; 32]).unwrap();
    let mut keys = TestKeys(Vec::new());
    let mut qc = WireQc {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 0,
        round: 0,
        step: 1,
        block_id: [1; 32],
        suite_id: 100,
        signer_bitmap: vec![0b111],
        signatures: Vec::new(),
    };
    for index in 0..4 {
        let (pk, sk) = MlDsa44Backend::generate_keypair().unwrap();
        keys.0.push(pk);
        if index < 3 {
            let vote = Vote {
                version: qc.version,
                chain_id: qc.chain_id,
                epoch: qc.epoch,
                height: qc.height,
                round: qc.round,
                step: qc.step,
                block_id: qc.block_id,
                validator_index: index,
                suite_id: qc.suite_id,
                signature: vec![],
            };
            qc.signatures
                .push(MlDsa44Backend::sign(&sk, &domain.vote_preimage(&vote)).unwrap());
        }
    }
    let registry =
        SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend));
    Arc::new(
        verify_quorum_certificate_with_domain(&qc, &domain, 0, &validators(), &keys, &registry)
            .unwrap(),
    )
}

#[test]
fn verified_refusal_retains_exact_evidence_and_earlier_effects() {
    let evidence = verified_qc();
    for multi in [false, true] {
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), validators());
        *engine.state_mut() = cycle_state(multi);
        engine
            .state_mut()
            .register_block_with_verified_justification(
                [1; 32],
                1,
                Some(if multi { [2; 32] } else { [1; 32] }),
                Arc::clone(&evidence),
            )
            .unwrap();
        let original = format!("{:?}", engine.state().get_block(&[1; 32]).unwrap());
        let old_charge = engine.state().retained_evidence_bytes();
        let lock = engine.locked_qc().unwrap().clone();
        let leader = engine.leader_for_view(20);
        let mut p = proposal(20, [1; 32], leader);
        p.qc = Some(evidence.certificate().clone());
        let id = candidate_id(&p, leader);
        assert!(engine
            .on_verified_proposal_event(leader, &p, Arc::clone(&evidence))
            .unwrap()
            .is_none());
        assert_eq!(engine.current_view(), 20);
        assert_eq!(engine.locked_qc(), Some(&lock));
        assert_eq!(engine.committed_height(), None);
        assert_eq!(engine.state().evicted_blocks(), 0);
        let candidate = engine.state().get_block(&id).unwrap();
        assert_eq!(engine.state().vote_count(20, &id), 0);
        assert!(candidate.own_qc.is_none());
        assert!(Arc::ptr_eq(
            candidate.verified_justification.as_ref().unwrap(),
            &evidence
        ));
        assert_eq!(
            format!("{:?}", engine.state().get_block(&[1; 32]).unwrap()),
            original
        );
        assert!(Arc::ptr_eq(
            engine
                .state()
                .get_block(&[1; 32])
                .unwrap()
                .verified_justification
                .as_ref()
                .unwrap(),
            &evidence
        ));
        assert_eq!(
            engine.state().retained_evidence_bytes(),
            old_charge + evidence.retained_byte_size().unwrap()
        );
        let after = format!("{:?}", engine.state());
        assert_read_only_decision(engine.state(), id, SafetyDecision::Unsafe);
        assert!(engine
            .on_verified_proposal_event(leader, &p, Arc::clone(&evidence))
            .unwrap()
            .is_none());
        assert_eq!(format!("{:?}", engine.state()), after);
    }
}
