//! RUN 422 §13.6 — Isolated non-consuming retained-decision observation
//! (ISOLATED). These tests exercise
//! [`SafetyRecordOwner::observe_retained_decision`]: a read-only route that
//! borrows a retained [`qbind_consensus::DecidedVote`] envelope and its exact
//! proposal, validates the current durable restriction under one serialization
//! domain acquisition, verifies the pin's provenance and candidate
//! correspondence, and performs a BOUNDED safe-voting re-evaluation. Nothing is
//! consumed, re-ingested, signed, or published; the original envelope, its
//! `Vote`, and its pin are preserved, and the result is a `Copy` diagnostic
//! describing only the checked state.
//!
//! The whole target is gated behind `test-utils` (it uses the `test-utils`-gated
//! seams `backend_for_test`, `prepared_registry_for_test`) and carries no
//! production caller. Activation remains DISABLED.

#![cfg(feature = "test-utils")]

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{
    BasicHotStuffEngine, BoundedSafetyOutcome, ConsensusEngineAction, ConsensusValidatorSet,
    DecidedVote,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{SafetyBackend, SafetyBackendPolicy};
use qbind_node::safety_record_store::decision_capture::{
    OwnedDecisionOutcome, OwningCapturePayload, PreparedDecisionInputLimits,
};
use qbind_node::safety_record_store::owner::{make_locked_qc, PublishResult, SafetyRecordOwner};
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::WireQc as StoreWireQc;
use qbind_node::safety_record_store::validate::FixtureCommittedHistory;
use qbind_node::safety_record_store::{
    ProvenanceRefusal, RetainedDecisionBlocked, RetainedDecisionObservation, RetainedDecisionReject,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as EngineWireQc};

// ===========================================================================
// Fixtures (mirrors of the owning-capture binding test fixtures; labelled
// constructed test fixtures, not production inputs)
// ===========================================================================

const QC_SUITE: u16 = 7;
const TIMEOUT_SUITE: u8 = 100;
const S_SIG: usize = 8;
const CHAIN_ID: u32 = 42;
const EPOCH: u64 = 7;

fn ctx_n(n: u64) -> PinnedSafetyContext {
    let validators = (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect();
    PinnedSafetyContext {
        network_genesis_id: [1u8; 32],
        authority_context_ref: [2u8; 32],
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        qc_suite_id: QC_SUITE,
        timeout_suite_id: TIMEOUT_SUITE,
        s_sig: S_SIG,
        validators,
        require_height_equals_round: false,
    }
}

fn valid_wire_qc(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> StoreWireQc {
    let n = ctx.n() as u64;
    let mut bitmap = vec![0u8; ((n + 7) / 8).max(1) as usize];
    let mut signatures = Vec::new();
    for i in 0..n {
        bitmap[(i / 8) as usize] |= 1 << (i % 8);
        signatures.push(vec![0xABu8; S_SIG]);
    }
    signatures.shrink_to_fit();
    StoreWireQc {
        version: 1,
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        height: view,
        round: view,
        step: 0,
        block_id,
        suite_id: QC_SUITE,
        signer_bitmap: bitmap,
        signatures,
    }
}

fn open_enabled(dir: &std::path::Path) -> SafetyBackend {
    SafetyBackend::open_or_initialize(
        dir,
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .expect("enabled devnet backend opens")
}

fn init_owner(dir: &std::path::Path, ctx: &PinnedSafetyContext) -> SafetyRecordOwner {
    let backend = open_enabled(dir);
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).expect("attach");
    owner.initialize(true).expect("O1 initialize");
    owner
}

/// Publish one Locked restriction (lock = `block`/`view`) and return the new
/// authoritative revision.
fn publish_qc(
    owner: &SafetyRecordOwner,
    ctx: &PinnedSafetyContext,
    block: [u8; 32],
    view: u64,
    expected: u64,
) -> u64 {
    let qc = valid_wire_qc(ctx, block, view);
    let l = make_locked_qc(ctx, block, view, qc, None).unwrap();
    match owner.publish_locked(l, expected, None::<&FixtureCommittedHistory>) {
        PublishResult::DurableAcknowledged { new_revision } => new_revision,
        other => panic!("expected DurableAcknowledged, got {other:?}"),
    }
}

fn engine_validator_set(num: u64) -> ConsensusValidatorSet {
    let entries = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 1,
        })
        .collect::<Vec<_>>();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_proposal(view: u64, parent_block_id: [u8; 32], proposer_index: u16) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: view,
            round: view,
            parent_block_id,
            payload_hash: [0u8; 32],
            proposer_index,
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

fn logical_qc(block_id: [u8; 32], height: u64) -> EngineWireQc {
    EngineWireQc {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![],
        signatures: vec![],
    }
}

/// A single-validator engine locked at view 0, advanced to view 1, plus a safe
/// view-1 proposal (ViewSufficiency branch) and the engine's L0 lock id.
fn engine_locked_and_safe_view1() -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal, [u8; 32]) {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId::new(1), engine_validator_set(1));
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let a0 = engine.on_proposal_event(ValidatorId::new(1), &p0);
    assert!(matches!(a0, Some(ConsensusEngineAction::BroadcastVote(_))));
    let l0_block = engine.locked_qc().expect("L0 lock").block_id;
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));
    (engine, p1, l0_block)
}

/// Init an owner and publish the L0 restriction; return it with the
/// authoritative revision after that publication (the current durable revision,
/// since capture writes no durable record).
fn owner_with_matching_proof(
    dir: &std::path::Path,
    ctx: &PinnedSafetyContext,
    l0_block: [u8; 32],
) -> (SafetyRecordOwner, u64) {
    let owner = init_owner(dir, ctx);
    let rev = publish_qc(&owner, ctx, l0_block, 0, 0);
    (owner, rev)
}

fn limits(ctx: &PinnedSafetyContext) -> PreparedDecisionInputLimits {
    PreparedDecisionInputLimits::from_pinned(ctx).expect("pinned context yields a valid policy")
}

fn registry_occupied(owner: &SafetyRecordOwner) -> usize {
    match owner.backend_for_test().prepared_registry_for_test() {
        Some(reg) => reg.lock().unwrap().occupied(),
        None => 0,
    }
}

/// Capture a retained decision for `p1` and return (owner, engine, decided,
/// proposal, limits, engine-post-capture lock (block, view), durable revision).
fn capture_decision(
    dir: &std::path::Path,
    ctx: &PinnedSafetyContext,
) -> (
    SafetyRecordOwner,
    BasicHotStuffEngine<[u8; 32]>,
    DecidedVote<OwningCapturePayload>,
    BlockProposal,
    PreparedDecisionInputLimits,
    ([u8; 32], u64),
    u64,
) {
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let (owner, rev) = owner_with_matching_proof(dir, ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(ctx);
    let decided = match owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
    {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };
    let lk = engine.locked_qc().expect("post-capture lock");
    let engine_lock = (lk.block_id, lk.view);
    (owner, engine, decided, p1, lim, engine_lock, rev)
}

// ===========================================================================
// Bounded consensus query (direct) — isolated deterministic outcomes.
// Constructed fixtures: a single-validator engine driven over a parent chain.
// ===========================================================================

/// Build a four-block parent chain p0<-p1<-p2<-p3 (single validator) and return
/// the engine plus the derived block ids (id0..id3). Each self-vote raises the
/// lock to the voted block, so after p3 the engine lock is `id3`.
fn built_chain() -> (BasicHotStuffEngine<[u8; 32]>, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId::new(1), engine_validator_set(1));
    let p0 = make_proposal(0, [0xFF; 32], 1);
    engine.on_proposal_event(ValidatorId::new(1), &p0);
    let id0 = engine.locked_qc().unwrap().block_id;
    let id_of = |view: u64, parent: [u8; 32]| {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&1u64.to_le_bytes());
        id[8..16].copy_from_slice(&view.to_le_bytes());
        id[16..32].copy_from_slice(&parent[..16]);
        id
    };
    let id1 = id_of(1, id0);
    let id2 = id_of(2, id1);
    let id3 = id_of(3, id2);
    engine.advance_view();
    let mut p1 = make_proposal(1, id0, 1);
    p1.qc = Some(logical_qc(id0, 0));
    engine.on_proposal_event(ValidatorId::new(1), &p1);
    engine.advance_view();
    engine.on_proposal_event(ValidatorId::new(1), &make_proposal(2, id1, 1));
    engine.advance_view();
    engine.on_proposal_event(ValidatorId::new(1), &make_proposal(3, id2, 1));
    (engine, id0, id1, id2, id3)
}

#[test]
fn bounded_query_safe_no_lock_before_any_proposal() {
    // CONSTRUCTED FIXTURE: a fresh engine has no lock; every candidate is safe.
    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId::new(1), engine_validator_set(1));
    assert!(engine.locked_qc().is_none());
    assert_eq!(
        engine.state().bounded_safety_decision(&[0x11; 32], 8),
        BoundedSafetyOutcome::SafeNoLock
    );
}

#[test]
fn bounded_query_candidate_is_lock_zero_hops() {
    // CONSTRUCTED FIXTURE: the tip `id3` is the lock → 0-hop ancestry success.
    let (engine, _id0, _id1, _id2, id3) = built_chain();
    assert_eq!(engine.locked_qc().unwrap().block_id, id3);
    for h in 0..4 {
        assert_eq!(
            engine.state().bounded_safety_decision(&id3, h),
            BoundedSafetyOutcome::SafeAncestry { hops: 0 },
            "candidate == lock is 0 hops at bound {h}"
        );
    }
}

#[test]
fn bounded_query_over_bound_is_exhausted_then_finite() {
    // CONSTRUCTED FIXTURE: `id2` is NOT the lock (the lock `id3` is its
    // descendant, never reached by walking ancestors). Under a hop bound shorter
    // than the walk to genesis the query refuses with a finite `BoundExhausted`;
    // once the bound exceeds the chain length the walk terminates at the
    // parent-less genesis with `NoParentLink`. This demonstrates both the exact
    // bound cutoff and finite multi-hop traversal (the same hop cap bounds any
    // shape, including a cycle).
    let (engine, _id0, _id1, id2, _id3) = built_chain();
    assert_eq!(
        engine.state().bounded_safety_decision(&id2, 0),
        BoundedSafetyOutcome::BoundExhausted
    );
    assert_eq!(
        engine.state().bounded_safety_decision(&id2, 2),
        BoundedSafetyOutcome::BoundExhausted,
        "walk id2->id1->id0 hits the bound at hop 2"
    );
    assert_eq!(
        engine.state().bounded_safety_decision(&id2, 3),
        BoundedSafetyOutcome::NoParentLink,
        "with slack the finite walk reaches parent-less genesis"
    );
}

#[test]
fn bounded_query_candidate_absent() {
    // CONSTRUCTED FIXTURE: an id the engine never registered.
    let (engine, _id0, _id1, _id2, _id3) = built_chain();
    assert_eq!(
        engine.state().bounded_safety_decision(&[0x77; 32], 5),
        BoundedSafetyOutcome::CandidateAbsent
    );
}

// ===========================================================================
// Owner-controlled observation route — full scenarios.
// ===========================================================================

#[test]
fn observe_exact_proposal_success_revalidated() {
    // Capture p1; publish the current durable restriction so it matches the
    // post-capture engine lock; observe the exact proposal → revalidated with a
    // 0-hop ancestry outcome (candidate == lock). The original envelope, Vote,
    // and pin are preserved, and the registry still retains the ORIGINAL L0
    // identity (lock_view 0) despite the restriction advancing to view 1.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    assert_eq!(lv, 1);
    let l0_identity = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry installed")
        .lock()
        .unwrap()
        .occupied_identities_for_test();
    assert_eq!(l0_identity.len(), 1);
    assert_eq!(l0_identity[0].lock_view, 0, "captured generation retains L0 view");

    publish_qc(&owner, &ctx, lb, lv, rev);
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Revalidated(BoundedSafetyOutcome::SafeAncestry { hops: 0 })
    );

    // Preservation: the envelope's Vote and the pin survive unchanged.
    assert_eq!(decided.vote().height, 1);
    assert_eq!(registry_occupied(&owner), 1, "pin preserved");
    let after = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .unwrap()
        .lock()
        .unwrap()
        .occupied_identities_for_test();
    assert_eq!(after, l0_identity, "original L0 evidence preserved");
}

#[test]
fn observe_engine_durable_disagreement_inconclusive() {
    // Capture but do NOT republish: the durable restriction stays at L0
    // (l0_block/view0) while the engine self-vote raised the lock to view1.
    // The route blocks conservatively — distinct from recovery-required.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, _lk, _rev) = capture_decision(dir.path(), &ctx);
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Inconclusive(
            RetainedDecisionBlocked::EngineDurableDisagreement
        )
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved on inconclusive");
}

#[test]
fn observe_substituted_proposal_commitment_mismatch() {
    // Republish so the durable matches the engine lock (reaching the commitment
    // check), then observe a DIFFERENT proposal: its recomputed commitment does
    // not match the retained binding → substitution refused.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, _p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    publish_qc(&owner, &ctx, lb, lv, rev);
    let mut substitute = make_proposal(1, [0x55; 32], 1);
    substitute.qc = Some(logical_qc([0x55; 32], 0));
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &substitute,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Rejected(RetainedDecisionReject::CommitmentMismatch)
    );
}

#[test]
fn observe_effective_policy_mismatch_rejected() {
    // Owner pinned to ctx_n(4); observe with limits derived from ctx_n(2). The
    // effective-limits binding refuses before the domain is even acquired.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, _lim, _lk, _rev) = capture_decision(dir.path(), &ctx);
    let foreign_limits = limits(&ctx_n(2));
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &foreign_limits,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Rejected(RetainedDecisionReject::EffectivePolicyMismatch)
    );
}

#[test]
fn observe_bootstrap_unresolved_inconclusive() {
    // A second owner that only initialized (durable = BootstrapNoLock) observes
    // the first owner's decided envelope. The Locked-only route leaves bootstrap
    // explicitly unresolved.
    let ctx = ctx_n(4);
    let dir_a = tempfile::tempdir().unwrap();
    let (_owner_a, engine, decided, p1, lim, _lk, _rev) = capture_decision(dir_a.path(), &ctx);
    let dir_b = tempfile::tempdir().unwrap();
    let owner_b = init_owner(dir_b.path(), &ctx);
    let obs = owner_b.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Inconclusive(RetainedDecisionBlocked::BootstrapUnresolved)
    );
}

#[test]
fn observe_missing_provenance_rejected() {
    // A second owner that PUBLISHED a Locked restriction but never captured has
    // no installed registry: the pin's provenance lookup refuses `Missing`.
    let ctx = ctx_n(4);
    let dir_a = tempfile::tempdir().unwrap();
    let (_owner_a, engine, decided, p1, lim, (lb, lv), _rev) = capture_decision(dir_a.path(), &ctx);
    let dir_b = tempfile::tempdir().unwrap();
    let owner_b = init_owner(dir_b.path(), &ctx);
    // Publish B's own Locked (matching the engine lock so correspondence would
    // pass) so the route reaches the provenance step on B's empty registry.
    publish_qc(&owner_b, &ctx, lb, lv, 0);
    let obs = owner_b.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Rejected(RetainedDecisionReject::Provenance(
            ProvenanceRefusal::Missing
        ))
    );
}

#[test]
fn observe_foreign_provenance_rejected() {
    // Two independent backends draw distinct ownership incarnations. Owner B
    // (its own capture installs a registry under B's incarnation) observes A's
    // decided envelope, whose pin handle was minted under A's incarnation → the
    // registry lookup refuses `Foreign`.
    let ctx = ctx_n(4);
    let dir_a = tempfile::tempdir().unwrap();
    let (_owner_a, engine_a, decided_a, p1_a, lim, _lk, _rev) = capture_decision(dir_a.path(), &ctx);
    let dir_b = tempfile::tempdir().unwrap();
    let (owner_b, _engine_b, _decided_b, _p1_b, _lim_b, _lk_b, _rev_b) =
        capture_decision(dir_b.path(), &ctx);
    let obs = owner_b.observe_retained_decision(
        &engine_a,
        &decided_a,
        &p1_a,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Rejected(RetainedDecisionReject::Provenance(
            ProvenanceRefusal::Foreign
        ))
    );
}

#[test]
fn observe_evidence_unavailable_inconclusive() {
    // Corrupt the stored record after capture; the held-guard loader reads but
    // fails to decode/validate it → evidence unavailable (a validation failure,
    // not an admission failure).
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, _lk, _rev) = capture_decision(dir.path(), &ctx);
    owner
        .debug_overwrite_record_for_test(&[0u8; 8])
        .expect("overwrite record");
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    match obs {
        RetainedDecisionObservation::Inconclusive(RetainedDecisionBlocked::EvidenceUnavailable(
            _,
        )) => {}
        other => panic!("expected EvidenceUnavailable, got {other:?}"),
    }
}

#[test]
fn observe_loader_admission_inconclusive() {
    // Exhaust the shared aggregate budget with a standing reservation so the
    // loader's covering holder reservation is refused → admission inconclusive.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, _lk, _rev) = capture_decision(dir.path(), &ctx);
    let cap = owner
        .backend_for_test()
        .accounting_aggregate_cap()
        .expect("enabled backend has an aggregate cap");
    let current = owner.backend_for_test().accounting_aggregate_current();
    let standing = owner
        .backend_for_test()
        .reserve_standing_for_test(cap - current)
        .expect("reserve the whole remaining budget");
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Inconclusive(RetainedDecisionBlocked::Admission)
    );
    drop(standing);
    // After the budget frees, the same observation revalidates (republish first).
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across admission refusal");
}