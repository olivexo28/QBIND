use qbind_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet, LeaderCaptureInput,
    LeaderProposalGate, LeaderProposalRouteResult, LeaderRouteLimits, SafetyGateRefusal,
    ValidatorId, vote_accumulator::ConsensusLimitsConfig,
};
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc};

fn validators(count: u64) -> ConsensusValidatorSet {
    ConsensusValidatorSet::new(
        (1..=count)
            .map(|id| ValidatorSetEntry {
                id: ValidatorId::new(id),
                voting_power: 1,
            }),
    )
    .expect("valid validator set")
}

fn genesis_proposal() -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 0,
            round: 0,
            parent_block_id: [0xff; 32],
            payload_hash: [0; 32],
            proposer_index: 1,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0; 32],
        },
        qc: None,
        txs: Vec::new(),
        signature: Vec::new(),
    }
}

struct AcceptGate {
    calls: usize,
    max_signers: usize,
}

impl LeaderProposalGate<()> for AcceptGate {
    fn route_limits(&self) -> LeaderRouteLimits {
        LeaderRouteLimits::new(self.max_signers)
    }

    fn capture_l0(&mut self, input: &LeaderCaptureInput<'_>) -> Result<(), SafetyGateRefusal> {
        self.calls += 1;
        let context = input.context();
        assert_eq!(input.proposal().header.parent_block_id, *context.parent_block_id());
        assert_eq!(input.proposal().header.height, context.origin_view());
        assert_eq!(context.justification().unwrap().block_id, *context.parent_block_id());
        Ok(())
    }
}

fn engine_with_l0(count: u64) -> BasicHotStuffEngine<[u8; 32]> {
    let mut engine = BasicHotStuffEngine::new(ValidatorId::new(1), validators(count));
    let action = engine
        .on_proposal_event(ValidatorId::new(1), &genesis_proposal())
        .expect("genesis proposal accepted");
    assert!(matches!(action, ConsensusEngineAction::BroadcastVote(_)));
    if count > 1 {
        let base_vote = match action {
            ConsensusEngineAction::BroadcastVote(vote) => vote,
            _ => unreachable!(),
        };
        let quorum = (2 * count).div_ceil(3);
        for id in 2..=quorum {
            let mut vote = base_vote.clone();
            vote.validator_index = id as u16;
            engine
                .on_vote_event(ValidatorId::new(id), &vote)
                .expect("additional validator vote accepted");
        }
    }
    engine.advance_view();
    for _ in 0..count {
        if engine.is_leader_for_current_view() {
            break;
        }
        engine.advance_view();
    }
    engine
}

fn candidate_for_current_locked_view(engine: &BasicHotStuffEngine<[u8; 32]>) -> [u8; 32] {
    let parent = engine.locked_qc().expect("L0 lock").block_id;
    let mut candidate = [0; 32];
    candidate[..8].copy_from_slice(&engine.local_id().as_u64().to_le_bytes());
    candidate[8..16].copy_from_slice(&engine.current_view().to_le_bytes());
    candidate[16..].copy_from_slice(&parent[..16]);
    candidate
}

#[test]
fn leader_route_returns_same_invocation_proposal_vote_and_advances_after_single_validator_qc() {
    let mut engine = engine_with_l0(1);
    let origin_view = engine.current_view();
    let parent = engine.locked_qc().expect("L0 lock").block_id;
    let mut gate = AcceptGate {
        calls: 0,
        max_signers: 4,
    };

    let decided = match engine.try_propose_gated_owning(&mut gate) {
        LeaderProposalRouteResult::Decided(decided) => decided,
        _ => panic!("leader route should decide"),
    };

    assert_eq!(gate.calls, 1);
    assert_eq!(decided.proposal().header.height, origin_view);
    assert_eq!(decided.proposal().header.parent_block_id, parent);
    assert_eq!(decided.proposal().header.proposer_index, 1);
    assert_eq!(decided.vote().height, origin_view);
    let mut expected_id = [0; 32];
    expected_id[..8].copy_from_slice(&1u64.to_le_bytes());
    expected_id[8..16].copy_from_slice(&origin_view.to_le_bytes());
    expected_id[16..].copy_from_slice(&parent[..16]);
    assert_eq!(decided.vote().block_id, expected_id);
    assert!(decided.effects().candidate_registered);
    assert!(decided.effects().accumulator_inserted);
    assert!(decided.effects().qc_formed);
    assert!(decided.effects().qc_processed);
    assert!(decided.effects().qc_processing_succeeded);
    assert!(decided.effects().view_advanced);
    assert_eq!(engine.current_view(), origin_view + 1);
}

#[test]
fn leader_route_refuses_nonleader_without_calling_capture_gate() {
    let mut engine = engine_with_l0(2);
    while engine.is_leader_for_current_view() {
        engine.advance_view();
    }
    assert!(!engine.is_leader_for_current_view());
    let mut gate = AcceptGate {
        calls: 0,
        max_signers: 4,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut gate),
        LeaderProposalRouteResult::Refused(qbind_consensus::LeaderRouteRefusal::NonLeader)
    ));
    assert_eq!(gate.calls, 0);
}

#[test]
fn already_voted_refusal_is_distinct_from_already_proposed() {
    let mut engine = engine_with_l0(4);
    assert!(engine.is_leader_for_current_view());
    let view = engine.current_view();
    let locked = engine.locked_qc().expect("L0 lock").clone();
    let mut inbound = genesis_proposal();
    inbound.header.height = view;
    inbound.header.round = view;
    inbound.header.parent_block_id = locked.block_id;
    inbound.header.proposer_index = 1;
    inbound.qc = Some(WireQc {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: locked.view,
        round: locked.view,
        step: 0,
        block_id: locked.block_id,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: Vec::new(),
        signatures: Vec::new(),
    });
    let action = engine
        .on_proposal_event(ValidatorId::new(1), &inbound);
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "expected inbound self-vote, got {action:?}"
    );
    let mut gate = AcceptGate {
        calls: 0,
        max_signers: 4,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut gate),
        LeaderProposalRouteResult::Refused(qbind_consensus::LeaderRouteRefusal::AlreadyVoted)
    ));
    assert_eq!(gate.calls, 0);
}

#[test]
fn same_candidate_vote_history_refuses_before_capture() {
    let mut engine = engine_with_l0(4);
    let view = engine.current_view();
    let candidate = candidate_for_current_locked_view(&engine);
    assert!(engine
        .state_mut()
        .on_vote(ValidatorId::new(1), view, &candidate)
        .expect("pre-existing same-candidate vote is recorded")
        .is_none());
    let mut gate = AcceptGate {
        calls: 0,
        max_signers: 4,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut gate),
        LeaderProposalRouteResult::Refused(
            qbind_consensus::LeaderRouteRefusal::PriorSameCandidateVote
        )
    ));
    assert_eq!(gate.calls, 0);
}

#[test]
fn conflicting_vote_history_refuses_before_capture() {
    let mut engine = engine_with_l0(4);
    let view = engine.current_view();
    assert!(engine
        .state_mut()
        .on_vote(ValidatorId::new(1), view, &[0x55; 32])
        .expect("conflicting vote history is recorded")
        .is_none());
    let mut gate = AcceptGate {
        calls: 0,
        max_signers: 4,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut gate),
        LeaderProposalRouteResult::Refused(
            qbind_consensus::LeaderRouteRefusal::ConflictingVoteHistory
        )
    ));
    assert_eq!(gate.calls, 0);
}

#[test]
fn zero_signer_capacity_refuses_before_capture_and_can_retry() {
    let mut engine = engine_with_l0(1);
    let mut rejecting_gate = AcceptGate {
        calls: 0,
        max_signers: 0,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut rejecting_gate),
        LeaderProposalRouteResult::Refused(
            qbind_consensus::LeaderRouteRefusal::SignerBoundExceeded
        )
    ));
    assert_eq!(rejecting_gate.calls, 0);
    let mut accepting_gate = AcceptGate {
        calls: 0,
        max_signers: 1,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut accepting_gate),
        LeaderProposalRouteResult::Decided(_)
    ));
    assert_eq!(accepting_gate.calls, 1);
}

#[test]
fn full_block_capacity_refuses_without_replacing_the_locked_block() {
    let limits = ConsensusLimitsConfig::new(128, 256, 1, 16_384);
    let mut engine = BasicHotStuffEngine::with_state_limits(
        ValidatorId::new(1),
        validators(1),
        limits,
    );
    let action = engine
        .on_proposal_event(ValidatorId::new(1), &genesis_proposal())
        .expect("genesis accepted");
    assert!(matches!(action, ConsensusEngineAction::BroadcastVote(_)));
    let locked = engine.locked_qc().expect("genesis QC").block_id;
    engine.advance_view();
    let mut gate = AcceptGate {
        calls: 0,
        max_signers: 1,
    };
    assert!(matches!(
        engine.try_propose_gated_owning(&mut gate),
        LeaderProposalRouteResult::Refused(qbind_consensus::LeaderRouteRefusal::BlockCapacity)
    ));
    assert_eq!(gate.calls, 0);
    assert_eq!(engine.state().block_count(), 1);
    assert!(engine.state().get_block(&locked).is_some());
}
