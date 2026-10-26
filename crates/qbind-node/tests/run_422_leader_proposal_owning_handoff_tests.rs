#![cfg(feature = "test-utils")]

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{
    InjectFault, SafetyBackend, SafetyBackendPolicy, TryLockDomainOutcome,
};
use qbind_node::safety_record_store::decision_capture::{
    AncestryKind, EntrypointKind, LeaderOwnerRefusal, MetaBranch, PreparedDecisionInputLimits,
};
use qbind_node::safety_record_store::owner::{
    clear_capture_interval_hook, make_locked_qc, set_capture_interval_hook, PublishResult,
    SafetyRecordOwner,
};
use qbind_node::safety_record_store::prepared::{
    pin_charge_bytes, registry_cell_charge_bytes, GenerationIdentity,
};
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::WireQc;
use qbind_node::safety_record_store::record::ValidatedRecord;
use qbind_node::safety_record_store::validate::FixtureCommittedHistory;
use qbind_wire::consensus::{BlockHeader, BlockProposal};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const QC_SUITE: u16 = 7;
const TIMEOUT_SUITE: u8 = 100;

fn context(n: u64) -> PinnedSafetyContext {
    PinnedSafetyContext {
        network_genesis_id: [1; 32],
        authority_context_ref: [2; 32],
        chain_id: 1,
        epoch: 0,
        qc_suite_id: QC_SUITE,
        timeout_suite_id: TIMEOUT_SUITE,
        s_sig: 8,
        validators: (0..n).map(|id| (ValidatorId::new(id), 1)).collect(),
        require_height_equals_round: false,
    }
}

fn proposal() -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 0,
            round: 0,
            parent_block_id: [0xff; 32],
            payload_hash: [0; 32],
            proposer_index: 0,
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

fn engine_with_lock(n: u64) -> (BasicHotStuffEngine<[u8; 32]>, [u8; 32]) {
    let validators = ConsensusValidatorSet::new(
        (0..n)
            .map(|id| ValidatorSetEntry {
                id: ValidatorId::new(id),
                voting_power: 1,
            }),
    )
    .unwrap();
    let mut engine = BasicHotStuffEngine::new(ValidatorId::new(0), validators);
    let action = engine
        .on_proposal_event(ValidatorId::new(0), &proposal())
        .expect("proposal produces local vote");
    if n > 1 {
        let base_vote = match action {
            ConsensusEngineAction::BroadcastVote(vote) => vote,
            _ => panic!("expected local vote"),
        };
        let quorum = (2 * n).div_ceil(3);
        for id in 1..quorum {
            let mut vote = base_vote.clone();
            vote.validator_index = id as u16;
            engine
                .on_vote_event(ValidatorId::new(id), &vote)
                .expect("additional validator vote accepted");
        }
    }
    let l0 = engine.locked_qc().expect("L0 QC").block_id;
    for _ in 0..=n {
        if engine.current_view() > 0 && engine.is_leader_for_current_view() {
            break;
        }
        engine.advance_view();
    }
    (engine, l0)
}

fn engine_with_full_candidate_accumulator(
    l0: [u8; 32],
) -> (BasicHotStuffEngine<[u8; 32]>, [u8; 32]) {
    let validators = ConsensusValidatorSet::new(
        (0..4).map(|id| ValidatorSetEntry {
            id: ValidatorId::new(id),
            voting_power: 1,
        }),
    )
    .unwrap();
    let limits = qbind_consensus::vote_accumulator::ConsensusLimitsConfig::new(
        128, 2, 128, 16_384,
    );
    let mut engine =
        BasicHotStuffEngine::with_state_limits(ValidatorId::new(0), validators, limits);
    engine
        .state_mut()
        .set_locked_qc(qbind_consensus::QuorumCertificate::new(
            l0,
            0,
            vec![ValidatorId::new(0)],
        ));
    let mut candidate = [0; 32];
    candidate[..8].copy_from_slice(&0u64.to_le_bytes());
    candidate[8..16].copy_from_slice(&0u64.to_le_bytes());
    candidate[16..].copy_from_slice(&l0[..16]);
    for id in [1, 2] {
        assert!(engine
            .state_mut()
            .on_vote(ValidatorId::new(id), 0, &candidate)
            .expect("fixture vote accepted")
            .is_none());
    }
    (engine, candidate)
}

fn owner_with_locked_context(
    path: &std::path::Path,
    ctx: &PinnedSafetyContext,
    l0: [u8; 32],
) -> SafetyRecordOwner {
    let backend = SafetyBackend::open_or_initialize(
        path,
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .expect("backend opens");
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).expect("owner attaches");
    owner.initialize(true).expect("backend initializes");
    let mut signer_bitmap = vec![0; (ctx.validators.len() + 7) / 8];
    for signer in 0..ctx.validators.len() {
        signer_bitmap[signer / 8] |= 1 << (signer % 8);
    }
    let qc = WireQc {
        version: 1,
        chain_id: ctx.chain_id,
        epoch: ctx.epoch,
        height: 0,
        round: 0,
        step: 0,
        block_id: l0,
        suite_id: ctx.qc_suite_id,
        signer_bitmap,
        signatures: (0..ctx.validators.len())
            .map(|_| vec![0xab; ctx.s_sig])
            .collect(),
    };
    let locked = make_locked_qc(ctx, l0, 0, qc, None).expect("Locked record");
    match owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>) {
        PublishResult::DurableAcknowledged { new_revision: 1 } => {}
        other => panic!("Locked publication failed: {other:?}"),
    }
    owner
}

fn assert_ledgers_within_caps(owner: &SafetyRecordOwner) -> (u128, u128) {
    let backend = owner.backend_for_test();
    let operational = backend.accounting_current();
    let aggregate = backend.accounting_aggregate_current();
    assert!(operational <= backend.accounting_cap().unwrap());
    assert!(aggregate <= backend.accounting_aggregate_cap().unwrap());
    (operational, aggregate)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ledgers {
    operational: u128,
    aggregate: u128,
    operational_cap: Option<u128>,
    aggregate_cap: Option<u128>,
}

fn ledgers(owner: &SafetyRecordOwner) -> Ledgers {
    let backend = owner.backend_for_test();
    Ledgers {
        operational: backend.accounting_current(),
        aggregate: backend.accounting_aggregate_current(),
        operational_cap: backend.accounting_cap(),
        aggregate_cap: backend.accounting_aggregate_cap(),
    }
}

fn assert_ledgers_unchanged(owner: &SafetyRecordOwner, expected: Ledgers) {
    assert_eq!(ledgers(owner), expected, "operational/aggregate ledgers changed");
}

fn execute_leader_route(
    owner: &SafetyRecordOwner,
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    limits: &PreparedDecisionInputLimits,
    revision: u64,
    proof: ValidatedRecord,
) -> qbind_node::safety_record_store::decision_capture::LeaderOwnerOutcome {
    let mut proof = Some(proof);
    let admission = owner
        .prepare_leader_route(limits, revision, proof.as_ref().unwrap())
        .unwrap_or_else(|reason| panic!("leader route preparation refused: {reason:?}"));
    admission.propose_and_capture(engine, &mut proof)
}

fn proof_identity(
    proof: &ValidatedRecord,
) -> ([u8; 32], u64, Option<GenerationIdentity>, Option<u64>) {
    (
        *proof.origin_context_digest(),
        proof.publication_revision(),
        GenerationIdentity::from_retained(proof.retained()),
        proof.recovery_backend_incarnation(),
    )
}

fn assert_proof_unchanged(
    proof: &ValidatedRecord,
    bytes: &[u8],
    identity: ([u8; 32], u64, Option<GenerationIdentity>, Option<u64>),
) {
    assert!(
        proof.encoded() == bytes && proof_identity(proof) == identity,
        "returned proof bytes/provenance changed [redacted]"
    );
}

#[test]
fn accepted_route_keeps_exact_pair_and_preserves_origin_view_without_qc() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    engine
        .set_pending_reconfig_next_epoch(2)
        .expect("valid reconfiguration intent");
    let backend = owner.backend_for_test();
    let proof_free = (
        backend.accounting_current(),
        backend.accounting_aggregate_current(),
        backend.accounting_cap(),
        backend.accounting_aggregate_cap(),
    );
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let charge_report = owner
        .leader_route_charge_report_for_test(&limits)
        .unwrap();
    let proof_held = ledgers(&owner);
    assert!(proof_held.operational > proof_free.0);
    assert!(proof_held.aggregate > proof_free.1);
    assert_eq!(
        backend
            .prepared_registry_for_test()
            .map(|registry| registry.lock().unwrap().occupied())
            .unwrap_or(0),
        0
    );
    let outcome = execute_leader_route(&owner, &mut engine, &limits, 1, proof);
    let decided = outcome
        .decided_envelope()
        .unwrap_or_else(|| panic!("leader route refused: {:?}", outcome.refusal()));
    let proposal = decided.proposal();
    let vote = decided.vote();
    assert_eq!(proposal.header.parent_block_id, l0);
    assert_eq!(proposal.header.payload_kind, qbind_wire::PAYLOAD_KIND_RECONFIG);
    assert_eq!(proposal.header.next_epoch, 2);
    assert_eq!(vote.block_id, decided.payload().meta().candidate_id().to_owned());
    assert_eq!(vote.height, decided.payload().meta().origin_view());
    assert_eq!(decided.payload().meta().safety_branch(), MetaBranch::ViewSufficiency);
    assert_eq!(decided.payload().meta().entrypoint(), EntrypointKind::LeaderLogical);
    assert_eq!(decided.payload().ancestry().kind(), AncestryKind::NotApplicable);
    assert!(decided.effects().accumulator_inserted);
    assert!(!decided.effects().qc_formed);
    assert!(!decided.effects().qc_processed);
    assert!(decided.effects().qc_processing_succeeded);
    assert!(!decided.effects().view_advanced);
    assert_eq!(engine.pending_reconfig_next_epoch(), None);
    assert_eq!(engine.current_view(), vote.height);
    let route_charge = outcome.route_charge();
    assert_eq!(route_charge, charge_report.selected);
    let registry = backend
        .prepared_registry_for_test()
        .expect("capture installed prepared registry");
    let retained = registry
        .lock()
        .unwrap()
        .inspect(decided.payload().pin().handle())
        .expect("live prepared pin is registered");
    let new_generation_charge =
        retained.generation_core_charge + retained.generation_control_charge;
    let live = ledgers(&owner);
    assert_eq!(
        live,
        Ledgers {
            operational: proof_free.0
                + route_charge
                + registry_cell_charge_bytes()
                + pin_charge_bytes()
                + new_generation_charge,
            aggregate: proof_free.1
                + route_charge
                + registry_cell_charge_bytes()
                + pin_charge_bytes()
                + new_generation_charge,
            operational_cap: proof_free.2,
            aggregate_cap: proof_free.3,
        },
        "cold live successful result identity [redacted]"
    );
    assert_eq!(
        backend
            .prepared_registry_for_test()
            .unwrap()
            .lock()
            .unwrap()
            .occupied(),
        1
    );
    drop(outcome);
    assert!(route_charge > 0);
    assert_eq!(
        backend
            .prepared_registry_for_test()
            .unwrap()
            .lock()
            .unwrap()
            .occupied(),
        0
    );
    assert!(backend.accounting_current() > 0, "standing registry remains charged");
    assert_eq!(
        backend.accounting_current(),
        proof_free.0 + registry_cell_charge_bytes()
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        proof_free.1 + registry_cell_charge_bytes()
    );
}

#[test]
fn owner_single_validator_qc_advances_to_l1_while_pin_retains_l0_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let mut ctx = context(2);
    ctx.validators[0].1 = 2;
    let validators = ConsensusValidatorSet::new([
        ValidatorSetEntry {
            id: ValidatorId::new(0),
            voting_power: 2,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 1,
        },
    ])
    .unwrap();
    let mut engine = BasicHotStuffEngine::new(ValidatorId::new(0), validators);
    assert!(matches!(
        engine
            .on_proposal_event(ValidatorId::new(0), &proposal())
            .expect("weighted local vote forms genesis QC"),
        ConsensusEngineAction::BroadcastVote(_)
    ));
    let l0 = engine.locked_qc().expect("genesis QC").block_id;
    engine.advance_view();
    for _ in 0..2 {
        if engine.is_leader_for_current_view() {
            break;
        }
        engine.advance_view();
    }
    assert!(engine.is_leader_for_current_view());
    let origin_view = engine.current_view();
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let charge_report = owner
        .leader_route_charge_report_for_test(&limits)
        .unwrap();
    let x = ledgers(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let outcome = execute_leader_route(&owner, &mut engine, &limits, 1, proof);
    assert_eq!(outcome.route_charge(), charge_report.selected);
    let decided = outcome.decided_envelope().unwrap_or_else(|| {
        panic!(
            "owner single-validator route refused: {:?}",
            outcome.refusal()
        )
    });
    assert_eq!(decided.payload().meta().origin_view(), origin_view);
    assert_eq!(decided.proposal().header.height, origin_view);
    assert_eq!(decided.vote().height, origin_view);
    assert!(decided.effects().accumulator_inserted);
    assert!(decided.effects().qc_formed);
    assert!(decided.effects().qc_processed);
    assert!(decided.effects().qc_processing_succeeded);
    assert!(decided.effects().view_advanced);
    assert_eq!(engine.current_view(), origin_view + 1);
    assert_eq!(
        owner
            .backend_for_test()
            .prepared_registry_for_test()
            .unwrap()
            .lock()
            .unwrap()
            .occupied_identities_for_test(),
        vec![GenerationIdentity {
            lock_block_id: l0,
            lock_view: 0,
        }],
        "retained pin remains tied to original L0 after L1 advancement"
    );
    let pin = decided.payload().pin();
    let registry = owner.backend_for_test().prepared_registry_for_test().unwrap();
    let retained = registry
        .lock()
        .unwrap()
        .inspect(pin.handle())
        .expect("L0 pin remains registered");
    let route = outcome.route_charge();
    let generation = retained.generation_core_charge + retained.generation_control_charge;
    assert_eq!(
        ledgers(&owner),
        Ledgers {
            operational: x.operational
                + route
                + registry_cell_charge_bytes()
                + pin_charge_bytes()
                + generation,
            aggregate: x.aggregate
                + route
                + registry_cell_charge_bytes()
                + pin_charge_bytes()
                + generation,
            ..x
        },
        "single-validator live success exact ledger identity [redacted]"
    );
}

#[test]
fn no_qc_vote_is_accepted_once_and_repeat_is_refused_without_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let outcome = execute_leader_route(&owner, &mut engine, &limits, 1, proof);
    let decided = outcome.decided_envelope().expect("first self-vote accepted");
    assert!(decided.effects().accumulator_inserted);
    assert!(!decided.effects().qc_formed);
    assert!(!decided.effects().view_advanced);
    assert_eq!(decided.vote().block_id, *decided.payload().meta().candidate_id());
    drop(outcome);

    engine
        .set_pending_reconfig_next_epoch(2)
        .expect("valid reconfiguration intent");
    let proof_free = ledgers(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("second O3 proof");
    let original = proof.encoded().to_vec();
    let original_identity = proof_identity(&proof);
    let proof_held = ledgers(&owner);
    let second = execute_leader_route(&owner, &mut engine, &limits, 1, proof);
    let second_live = ledgers(&owner);
    let route = second.route_charge();
    assert_eq!(
        second_live,
        Ledgers {
            operational: proof_held.operational + route,
            aggregate: proof_held.aggregate + route,
            ..proof_held
        },
        "repeated-call refusal retains proof and R [redacted]"
    );
    assert!(matches!(
        second.refusal(),
        Some(LeaderOwnerRefusal::Engine(
            qbind_consensus::LeaderRouteRefusal::AlreadyProposed
        ))
    ));
    assert_eq!(engine.pending_reconfig_next_epoch(), Some(2));
    let proof = second.into_proof().expect("AlreadyProposed returns the intact proof");
    assert_proof_unchanged(&proof, &original, original_identity);
    assert_eq!(ledgers(&owner), proof_held);
    drop(proof);
    assert_ledgers_unchanged(&owner, proof_free);
}

#[test]
fn stale_revision_refusal_returns_proof_for_successful_retry() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let original = proof.encoded().to_vec();
    let original_identity = proof_identity(&proof);
    let proof_held = ledgers(&owner);
    let mut proof = Some(proof);
    let admission = owner
        .prepare_leader_route(&limits, 2, proof.as_ref().unwrap())
        .expect("route reservation admitted before stale revision check");
    let route = owner
        .leader_route_charge_report_for_test(&limits)
        .unwrap()
        .selected;
    let refused = admission.propose_and_capture(&mut engine, &mut proof);
    assert_eq!(
        ledgers(&owner),
        Ledgers {
            operational: proof_held.operational + route,
            aggregate: proof_held.aggregate + route,
            ..proof_held
        },
        "stale refusal retains proof and R [redacted]"
    );
    assert!(matches!(
        refused.refusal(),
        Some(LeaderOwnerRefusal::Capture(
            qbind_node::safety_record_store::decision_capture::LeaderCaptureRefusal::Capture(
                qbind_node::safety_record_store::prepared::CaptureRefusal::StaleRevision { .. }
            )
        ))
    ));
    let proof = refused.into_proof().expect("stale refusal preserves proof");
    assert_proof_unchanged(&proof, &original, original_identity);
    assert_ledgers_unchanged(&owner, proof_held);

    let retried = execute_leader_route(&owner, &mut engine, &limits, 1, proof);
    assert!(retried.decided_envelope().is_some());
}

#[test]
fn captured_pin_is_released_on_real_post_capture_accumulator_capacity_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let l0 = [0x6a; 32];
    let (mut engine, candidate) = engine_with_full_candidate_accumulator(l0);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    engine
        .set_pending_reconfig_next_epoch(2)
        .expect("valid reconfiguration intent");
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let x = ledgers(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let proof_held = ledgers(&owner);
    let route = owner
        .leader_route_charge_report_for_test(&limits)
        .unwrap()
        .selected;
    let mut proof = Some(proof);
    let admission = owner
        .prepare_leader_route(&limits, 1, proof.as_ref().unwrap())
        .expect("route admission");
    let outcome = admission.propose_and_capture(&mut engine, &mut proof);
    assert!(outcome.decided_envelope().is_none());
    match outcome.refusal().expect("typed post-capture refusal") {
        LeaderOwnerRefusal::PostCapture(diagnostic) => {
            assert!(matches!(
                diagnostic.reason,
                qbind_consensus::LeaderRouteRefusal::VoteNotAccepted(
                    qbind_consensus::LeaderVoteRefusal::CapacityDropped
                )
            ));
            assert!(diagnostic.effects.candidate_registered);
            assert!(diagnostic.effects.proposed_flag_set);
            assert!(diagnostic.effects.vote_history_recorded);
            assert!(diagnostic.effects.voted_flag_set);
            assert!(diagnostic.effects.accumulator_capacity_dropped);
            assert!(!diagnostic.effects.accumulator_inserted);
            assert!(!diagnostic.effects.qc_formed);
            assert!(!diagnostic.effects.qc_processed);
            assert!(!diagnostic.effects.qc_processing_succeeded);
            assert!(!diagnostic.effects.view_advanced);
        }
        other => panic!("unexpected post-capture result: {other:?}"),
    }
    assert_eq!(engine.current_view(), 0);
    assert_eq!(engine.pending_reconfig_next_epoch(), Some(2));
    assert!(engine.state().get_block(&candidate).is_some());
    assert_eq!(
        owner
            .backend_for_test()
            .prepared_registry_for_test()
            .map(|registry| registry.lock().unwrap().occupied())
            .unwrap_or(0),
        0,
        "captured pin was released during owner cleanup"
    );
    let live = ledgers(&owner);
    assert_eq!(
        live,
        Ledgers {
            operational: x.operational + route + registry_cell_charge_bytes(),
            aggregate: x.aggregate + route + registry_cell_charge_bytes(),
            operational_cap: x.operational_cap,
            aggregate_cap: x.aggregate_cap,
        },
        "post-capture cleanup retains only X, R, and standing registry [redacted]"
    );
    assert_eq!(proof_held.operational - x.operational, proof_held.aggregate - x.aggregate);
    assert!(
        outcome.into_proof().is_none(),
        "post-capture failure fabricates no proof"
    );
    assert_ledgers_unchanged(
        &owner,
        Ledgers {
            operational: x.operational + registry_cell_charge_bytes(),
            aggregate: x.aggregate + registry_cell_charge_bytes(),
            ..x
        },
    );
}

#[test]
fn engine_lock_and_retained_proof_correspondence_refusal_is_pre_registration() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, _) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, [0x77; 32]);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let original = proof.encoded().to_vec();
    let original_identity = proof_identity(&proof);
    let proof_held = ledgers(&owner);
    let mut proof = Some(proof);
    let admission = owner
        .prepare_leader_route(&limits, 1, proof.as_ref().unwrap())
        .expect("route reservation admitted before engine/proof correspondence");
    let route = owner
        .leader_route_charge_report_for_test(&limits)
        .unwrap()
        .selected;
    let before_view = engine.current_view();
    let outcome = admission.propose_and_capture(&mut engine, &mut proof);
    assert_eq!(
        ledgers(&owner),
        Ledgers {
            operational: proof_held.operational + route,
            aggregate: proof_held.aggregate + route,
            ..proof_held
        },
        "correspondence refusal retains proof and R [redacted]"
    );
    assert!(matches!(
        outcome.refusal(),
        Some(LeaderOwnerRefusal::Capture(
            qbind_node::safety_record_store::decision_capture::LeaderCaptureRefusal::Correspondence(
                qbind_node::safety_record_store::decision_capture::CorrespondenceRefusal::LockBlockMismatch
            )
        ))
    ));
    assert_eq!(engine.current_view(), before_view);
    assert_eq!(engine.state().block_count(), 1);
    let proof = outcome
        .into_proof()
        .expect("correspondence refusal preserves proof");
    assert_proof_unchanged(&proof, &original, original_identity);
    assert_ledgers_unchanged(&owner, proof_held);
}

#[test]
fn route_admission_refusal_preserves_proof_and_pressure_relief_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof_free = ledgers(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let original = proof.encoded().to_vec();
    let original_identity = proof_identity(&proof);
    let backend = owner.backend_for_test();
    let with_proof = ledgers(&owner);
    let available = (backend.accounting_cap().unwrap() - backend.accounting_current())
        .min(
            backend.accounting_aggregate_cap().unwrap()
                - backend.accounting_aggregate_current(),
        );
    assert!(available > 0, "fixture has route admission headroom");
    let pressure = backend
        .reserve_standing_for_test(available)
        .expect("pressure consumes the remaining admission headroom");
    let pressured = ledgers(&owner);
    let mut proof = Some(proof);
    let refusal = owner.prepare_leader_route(&limits, 1, proof.as_ref().unwrap());
    assert!(matches!(
        refusal,
        Err(qbind_node::safety_record_store::decision_capture::LeaderRoutePreparationRefusal::RouteAdmission(_))
    ));
    assert_ledgers_unchanged(&owner, pressured);
    assert_proof_unchanged(
        proof.as_ref().unwrap(),
        &original,
        original_identity,
    );
    drop(pressure);
    assert_ledgers_unchanged(&owner, with_proof);

    let admission = owner
        .prepare_leader_route(&limits, 1, proof.as_ref().unwrap())
        .expect("pressure relief permits admission");
    let retried = admission.propose_and_capture(&mut engine, &mut proof);
    let decided = retried
        .decided_envelope()
        .expect("pressure-relieved route succeeds");
    let registry = owner.backend_for_test().prepared_registry_for_test().unwrap();
    let retained = registry
        .lock()
        .unwrap()
        .inspect(decided.payload().pin().handle())
        .expect("retry pin remains registered");
    let generation = retained.generation_core_charge + retained.generation_control_charge;
    assert_eq!(
        ledgers(&owner),
        Ledgers {
            operational: proof_free.operational
                + retried.route_charge()
                + registry_cell_charge_bytes()
                + pin_charge_bytes()
                + generation,
            aggregate: proof_free.aggregate
                + retried.route_charge()
                + registry_cell_charge_bytes()
                + pin_charge_bytes()
                + generation,
            ..proof_free
        },
        "relieved retry exact live-result identity [redacted]"
    );
}

#[test]
fn recovery_required_precheck_returns_the_unconsumed_proof() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (_engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let original = proof.encoded().to_vec();
    let original_identity = proof_identity(&proof);
    let locked_qc = WireQc {
        version: 1,
        chain_id: ctx.chain_id,
        epoch: ctx.epoch,
        height: 1,
        round: 1,
        step: 0,
        block_id: [0x99; 32],
        suite_id: ctx.qc_suite_id,
        signer_bitmap: vec![0x0f],
        signatures: (0..ctx.validators.len())
            .map(|_| vec![0xab; ctx.s_sig])
            .collect(),
    };
    let next = make_locked_qc(&ctx, [0x99; 32], 1, locked_qc, None)
        .expect("second Locked record");
    let backend = owner.backend_for_test();
    backend.set_inject(InjectFault::UncertainAfterWrite);
    assert!(matches!(
        owner.publish_locked(next, 1, None::<&FixtureCommittedHistory>),
        PublishResult::UncertainDurable
    ));
    backend.set_inject(InjectFault::None);
    assert!(owner.recovery_required());

    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let before = ledgers(&owner);
    let refusal = owner.prepare_leader_route(&limits, 2, &proof);
    assert!(matches!(
        refusal,
        Err(qbind_node::safety_record_store::decision_capture::LeaderRoutePreparationRefusal::Capture(
            qbind_node::safety_record_store::decision_capture::LeaderCaptureRefusal::Precheck(
                qbind_node::safety_record_store::prepared::CaptureRefusal::RecoveryRequired
            )
        ))
    ));
    assert_ledgers_unchanged(&owner, before);
    assert_proof_unchanged(&proof, &original, original_identity);
}

#[test]
fn effective_policy_refusal_preserves_proof_without_constructing_route_result() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (_engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let original = proof.encoded().to_vec();
    let original_identity = proof_identity(&proof);
    let wrong_limits = PreparedDecisionInputLimits::from_pinned(&context(3)).unwrap();
    let before = ledgers(&owner);
    assert!(matches!(
        owner.prepare_leader_route(&wrong_limits, 1, &proof),
        Err(qbind_node::safety_record_store::decision_capture::LeaderRoutePreparationRefusal::Capture(
            qbind_node::safety_record_store::decision_capture::LeaderCaptureRefusal::EffectivePolicyMismatch
        ))
    ));
    assert_ledgers_unchanged(&owner, before);
    assert_proof_unchanged(&proof, &original, original_identity);
}

#[test]
fn capture_interval_holds_the_same_domain_until_the_leader_engine_returns() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let release_rx = Arc::new(Mutex::new(release_rx));
    let release_rx_hook = Arc::clone(&release_rx);
    let observed = Arc::new(Mutex::new(None));
    let observed_thread = Arc::clone(&observed);
    std::thread::scope(|scope| {
        let observer_owner = &owner;
        let observer = scope.spawn(move || {
            entered_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("capture hook entered");
            let result = match observer_owner
                .backend_for_test()
                .try_lock_domain_for_test()
            {
                TryLockDomainOutcome::WouldBlock => "would-block",
                TryLockDomainOutcome::Acquired(guard) => {
                    drop(guard);
                    "acquired"
                }
                TryLockDomainOutcome::Poisoned => "poisoned",
            };
            *observed_thread.lock().unwrap() = Some(result);
            release_tx.send(()).expect("release owner");
        });
        set_capture_interval_hook(move || {
            entered_tx.send(()).expect("notify observer");
            release_rx_hook
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect("bounded observer release");
        });
        let outcome =
            execute_leader_route(&owner, &mut engine, &limits, 1, proof);
        clear_capture_interval_hook();
        observer.join().expect("observer joins");
        assert!(outcome.decided_envelope().is_some());
        assert_eq!(*observed.lock().unwrap(), Some("would-block"));
        assert_ledgers_within_caps(&owner);
        drop(outcome);
        match owner.backend_for_test().try_lock_domain_for_test() {
            TryLockDomainOutcome::Acquired(guard) => drop(guard),
            other => panic!("domain should be available after engine return: {other:?}"),
        }
    });
}

#[test]
fn reused_registry_and_shared_generation_add_only_the_new_pin_and_route() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(10);
    let (mut first_engine, l0) = engine_with_lock(10);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let backend = owner.backend_for_test();
    let proof_free = ledgers(&owner);

    let first_proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("first O3 proof");
    let first = execute_leader_route(&owner, &mut first_engine, &limits, 1, first_proof);
    assert!(first.decided_envelope().is_some());
    assert_ledgers_within_caps(&owner);
    let first_route = first.route_charge();

    let (mut second_engine, _) = engine_with_lock(10);
    let baseline = ledgers(&owner);
    let second_proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("second O3 proof");
    let with_proof = ledgers(&owner);
    assert!(with_proof.operational > baseline.operational);
    assert!(with_proof.aggregate > baseline.aggregate);
    assert_eq!(with_proof.operational_cap, baseline.operational_cap);
    assert_eq!(with_proof.aggregate_cap, baseline.aggregate_cap);
    let second = execute_leader_route(&owner, &mut second_engine, &limits, 1, second_proof);
    assert!(
        second.decided_envelope().is_some(),
        "second capture refused: {:?}",
        second.refusal()
    );
    let second_route = second.route_charge();
    assert_eq!(
        ledgers(&owner),
        Ledgers {
            operational: baseline.operational + second_route + pin_charge_bytes(),
            aggregate: baseline.aggregate + second_route + pin_charge_bytes(),
            ..baseline
        }
    );
    assert_eq!(
        backend
            .prepared_registry_for_test()
            .unwrap()
            .lock()
            .unwrap()
            .occupied(),
        2
    );

    drop(second);
    assert_ledgers_unchanged(&owner, baseline);
    assert!(first_route > 0);
    drop(first);
    assert_ledgers_unchanged(
        &owner,
        Ledgers {
            operational: proof_free.operational + registry_cell_charge_bytes(),
            aggregate: proof_free.aggregate + registry_cell_charge_bytes(),
            ..proof_free
        },
    );
    let accounting_observer = owner.leader_accounting_observer_for_test();
    drop(owner);
    assert_eq!(accounting_observer.current(), 0);
    assert_eq!(accounting_observer.aggregate().current(), 0);
}
