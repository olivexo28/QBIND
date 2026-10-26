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
use qbind_node::safety_record_store::prepared::{pin_charge_bytes, registry_cell_charge_bytes};
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::WireQc;
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
    );
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let route_baseline = (
        backend.accounting_current(),
        backend.accounting_aggregate_current(),
    );
    assert_eq!(
        backend
            .prepared_registry_for_test()
            .map(|registry| registry.lock().unwrap().occupied())
            .unwrap_or(0),
        0
    );
    let outcome = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
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
    assert!(decided.effects().qc_processed);
    assert!(!decided.effects().view_advanced);
    assert_eq!(engine.pending_reconfig_next_epoch(), None);
    assert_eq!(engine.current_view(), vote.height);
    let route_charge = outcome.route_charge().expect("route reservation remains live");
    let live = assert_ledgers_within_caps(&owner);
    assert!(live.0 > route_baseline.0);
    assert!(live.1 > route_baseline.1);
    assert!(backend.accounting_current() > route_baseline.0);
    assert!(backend.accounting_aggregate_current() > route_baseline.1);
    assert!(backend.accounting_current() <= backend.accounting_cap().unwrap());
    assert!(backend.accounting_aggregate_current() <= backend.accounting_aggregate_cap().unwrap());
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
fn no_qc_vote_is_accepted_once_and_repeat_is_refused_without_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let outcome = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
    let decided = outcome.decided_envelope().expect("first self-vote accepted");
    assert!(decided.effects().accumulator_inserted);
    assert!(!decided.effects().qc_formed);
    assert!(!decided.effects().view_advanced);
    assert_eq!(decided.vote().block_id, *decided.payload().meta().candidate_id());
    drop(outcome);

    engine
        .set_pending_reconfig_next_epoch(2)
        .expect("valid reconfiguration intent");
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("second O3 proof");
    let second = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
    assert_ledgers_within_caps(&owner);
    assert!(matches!(
        second.refusal(),
        Some(LeaderOwnerRefusal::Engine(
            qbind_consensus::LeaderRouteRefusal::AlreadyProposed
        ))
    ));
    assert_eq!(engine.pending_reconfig_next_epoch(), Some(2));
    assert!(second.into_proof().is_some());
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
    let refused = owner.propose_and_capture_leader_owned(&mut engine, &limits, 2, proof);
    assert_ledgers_within_caps(&owner);
    assert!(matches!(
        refused.refusal(),
        Some(LeaderOwnerRefusal::Capture(
            qbind_node::safety_record_store::decision_capture::LeaderCaptureRefusal::Capture(
                qbind_node::safety_record_store::prepared::CaptureRefusal::StaleRevision { .. }
            )
        ))
    ));
    let proof = refused.into_proof().expect("stale refusal preserves proof");
    assert_eq!(proof.encoded(), original);

    let retried = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
    assert!(retried.decided_envelope().is_some());
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
    let before_view = engine.current_view();
    let outcome = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
    assert_ledgers_within_caps(&owner);
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
    assert!(outcome.into_proof().is_some());
}

#[test]
fn route_admission_refusal_preserves_proof_and_pressure_relief_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let limits = PreparedDecisionInputLimits::from_pinned(&ctx).unwrap();
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let original = proof.encoded().to_vec();
    let backend = owner.backend_for_test();
    let available = (backend.accounting_cap().unwrap() - backend.accounting_current())
        .min(
            backend.accounting_aggregate_cap().unwrap()
                - backend.accounting_aggregate_current(),
        );
    assert!(available > 0, "fixture has route admission headroom");
    let pressure = backend
        .reserve_standing_for_test(available)
        .expect("pressure consumes the remaining admission headroom");
    let refused = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
    assert_ledgers_within_caps(&owner);
    assert!(matches!(
        refused.refusal(),
        Some(LeaderOwnerRefusal::RouteAdmission(_))
    ));
    let proof = refused.into_proof().expect("route admission preserves proof");
    assert_eq!(proof.encoded(), original);
    drop(pressure);

    let retried = owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
    assert!(retried.decided_envelope().is_some());
}

#[test]
fn recovery_required_precheck_returns_the_unconsumed_proof() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(4);
    let (mut engine, l0) = engine_with_lock(4);
    let owner = owner_with_locked_context(dir.path(), &ctx, l0);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
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
    let outcome = owner.propose_and_capture_leader_owned(&mut engine, &limits, 2, proof);
    assert_ledgers_within_caps(&owner);
    assert!(matches!(
        outcome.refusal(),
        Some(LeaderOwnerRefusal::Capture(
            qbind_node::safety_record_store::decision_capture::LeaderCaptureRefusal::Precheck(
                qbind_node::safety_record_store::prepared::CaptureRefusal::RecoveryRequired
            )
        ))
    ));
    assert!(outcome.into_proof().is_some());
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
            owner.propose_and_capture_leader_owned(&mut engine, &limits, 1, proof);
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
    let proof_free = (
        backend.accounting_current(),
        backend.accounting_aggregate_current(),
    );

    let first_proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("first O3 proof");
    let first = owner.propose_and_capture_leader_owned(
        &mut first_engine,
        &limits,
        1,
        first_proof,
    );
    assert!(first.decided_envelope().is_some());
    assert_ledgers_within_caps(&owner);
    let first_route = first.route_charge().unwrap();

    let (mut second_engine, _) = engine_with_lock(10);
    let baseline = (
        backend.accounting_current(),
        backend.accounting_aggregate_current(),
    );
    let second_proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("second O3 proof");
    let with_proof = (
        backend.accounting_current(),
        backend.accounting_aggregate_current(),
    );
    let second = owner.propose_and_capture_leader_owned(
        &mut second_engine,
        &limits,
        1,
        second_proof,
    );
    assert!(
        second.decided_envelope().is_some(),
        "second capture refused: {:?}",
        second.refusal()
    );
    assert_ledgers_within_caps(&owner);
    let second_route = second.route_charge().unwrap();
    assert_eq!(
        backend.accounting_current(),
        baseline.0 + second_route + pin_charge_bytes()
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        baseline.1 + second_route + pin_charge_bytes()
    );
    assert!(with_proof.0 > baseline.0);
    assert!(with_proof.1 > baseline.1);
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
    assert_eq!(backend.accounting_current(), baseline.0);
    assert_eq!(backend.accounting_aggregate_current(), baseline.1);
    assert!(first_route > 0);
    drop(first);
    assert_eq!(
        backend.accounting_current(),
        proof_free.0 + registry_cell_charge_bytes()
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        proof_free.1 + registry_cell_charge_bytes()
    );
}
