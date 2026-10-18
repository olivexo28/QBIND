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
    DecidedVote, HotStuffStateEngine, QuorumCertificate as EngineQc,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{
    InjectFault, SafetyBackend, SafetyBackendPolicy, TryLockDomainOutcome,
};
use qbind_node::safety_record_store::decision_capture::{
    LoaderDiagnostic, OwnedDecisionOutcome, OwningCapturePayload, PreparedDecisionInputLimits,
    ProjectionMismatch,
};
use qbind_node::safety_record_store::owner::{
    clear_observation_working_set_hook, make_locked_qc, set_observation_working_set_hook,
    PublishResult, SafetyRecordOwner,
};
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::{CommittedAnchor, WireQc as StoreWireQc};
use qbind_node::safety_record_store::validate::FixtureCommittedHistory;
use qbind_node::safety_record_store::{
    ProvenanceRefusal, RetainedDecisionBlocked, RetainedDecisionObservation, RetainedDecisionReject,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as EngineWireQc};
use std::sync::mpsc;
use std::time::Duration;

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

// ---------------------------------------------------------------------------
// Direct state-engine fixtures (RUN 422 §13.6). These drive
// `HotStuffStateEngine::bounded_safety_decision` through the PUBLIC state APIs
// (`register_block`, `set_locked_qc`) rather than self-voting proposal events,
// so a block's parent chain, its `justify_qc` view, and the pinned lock can be
// arranged EXACTLY — including the view-sufficiency short-circuit, an exact
// 64-hop reach, a parent-absent chain, and a genuine cyclic parent graph that
// cannot be produced by ordinary self-voting. These are LABELLED direct state
// fixtures (constructed, not engine-decision-derived): they prove the bounded
// query's branch/hop behaviour, not a production decision.
// ---------------------------------------------------------------------------

/// A fresh single-validator state engine with no lock and no blocks.
fn direct_engine() -> HotStuffStateEngine<[u8; 32]> {
    HotStuffStateEngine::<[u8; 32]>::new(engine_validator_set(1))
}

/// A distinct 32-byte block id derived from an index (first 8 bytes LE + a tag),
/// so a long chain yields unambiguous, non-colliding ids.
fn chain_id(i: u64) -> [u8; 32] {
    let mut id = [0xC0u8; 32];
    id[..8].copy_from_slice(&i.to_le_bytes());
    id
}

#[test]
fn bounded_query_view_sufficiency_short_circuits() {
    // DIRECT STATE FIXTURE: the candidate carries a `justify_qc` whose view is
    // >= the locked view, so the query returns `SafeViewSufficiency` WITHOUT
    // walking ancestry. To PROVE the short-circuit, the candidate's parent is a
    // block that was never registered: a walk would return `ParentAbsent`, so
    // observing `SafeViewSufficiency` (even at `max_hops == 0`) establishes the
    // walk was not taken.
    let mut engine = direct_engine();
    let lock = chain_id(0);
    engine.register_block(lock, 5, None, None);
    engine.set_locked_qc(EngineQc::new(lock, 5, vec![]));

    let candidate = chain_id(100);
    let missing_parent = chain_id(999); // never registered
    let justify = EngineQc::new(chain_id(50), 5, vec![]); // justify.view == locked.view
    engine.register_block(candidate, 6, Some(missing_parent), Some(justify));

    for h in [0usize, 1, 8] {
        assert_eq!(
            engine.bounded_safety_decision(&candidate, h),
            BoundedSafetyOutcome::SafeViewSufficiency,
            "justify.view >= locked.view short-circuits before any walk at bound {h}"
        );
    }
}

#[test]
fn bounded_query_positive_multi_hop_ancestry() {
    // DIRECT STATE FIXTURE: a parent chain lock(L0) <- b1 <- b2 <- b3, candidate
    // b3 is exactly three parent transitions above the lock. No block carries a
    // justify_qc, so the view-sufficiency short-circuit never applies and the
    // bounded walk runs. The exact hop count is reported; one hop short refuses.
    let mut engine = direct_engine();
    let l0 = chain_id(0);
    let b1 = chain_id(1);
    let b2 = chain_id(2);
    let b3 = chain_id(3);
    engine.register_block(l0, 0, None, None);
    engine.register_block(b1, 1, Some(l0), None);
    engine.register_block(b2, 2, Some(b1), None);
    engine.register_block(b3, 3, Some(b2), None);
    engine.set_locked_qc(EngineQc::new(l0, 0, vec![]));

    assert_eq!(
        engine.bounded_safety_decision(&b3, 2),
        BoundedSafetyOutcome::BoundExhausted,
        "two hops cannot reach a three-hop ancestor"
    );
    assert_eq!(
        engine.bounded_safety_decision(&b3, 3),
        BoundedSafetyOutcome::SafeAncestry { hops: 3 },
        "exact bound reaches the lock on the third parent transition"
    );
    assert_eq!(
        engine.bounded_safety_decision(&b3, 9),
        BoundedSafetyOutcome::SafeAncestry { hops: 3 },
        "a larger bound still reports the exact hop count"
    );
}

#[test]
fn bounded_query_exactly_64_reaches_and_65_refused() {
    // DIRECT STATE FIXTURE: two chains at the production ancestry bound
    // (`max_ancestry_hops() == 64`). Chain A places the candidate exactly 64
    // parent transitions above the lock → reached at the cap. Chain B places it
    // 65 transitions above → refused (65 required, 64 permitted).
    let bound = limits(&ctx_n(4)).max_ancestry_hops();
    assert_eq!(bound, 64, "the pinned production ancestry bound is 64");

    // Chain A: lock = chain_id(0), b_i parent b_{i-1}, candidate = b_64.
    let mut a = direct_engine();
    a.register_block(chain_id(0), 0, None, None);
    for i in 1..=64u64 {
        a.register_block(chain_id(i), i, Some(chain_id(i - 1)), None);
    }
    a.set_locked_qc(EngineQc::new(chain_id(0), 0, vec![]));
    assert_eq!(
        a.bounded_safety_decision(&chain_id(64), bound),
        BoundedSafetyOutcome::SafeAncestry { hops: 64 },
        "exactly 64 transitions reach the lock at the cap"
    );

    // Chain B: candidate = b_65, 65 transitions above the lock.
    let mut b = direct_engine();
    b.register_block(chain_id(0), 0, None, None);
    for i in 1..=65u64 {
        b.register_block(chain_id(i), i, Some(chain_id(i - 1)), None);
    }
    b.set_locked_qc(EngineQc::new(chain_id(0), 0, vec![]));
    assert_eq!(
        b.bounded_safety_decision(&chain_id(65), bound),
        BoundedSafetyOutcome::BoundExhausted,
        "65 required transitions are refused at the 64-hop cap"
    );
}

#[test]
fn bounded_query_parent_absent() {
    // DIRECT STATE FIXTURE: a registered candidate whose parent link references a
    // block absent from the engine, with the lock elsewhere → the walk reaches an
    // unavailable ancestor and reports `ParentAbsent` (distinct from
    // `CandidateAbsent`, where the candidate itself is unregistered).
    let mut engine = direct_engine();
    let lock = chain_id(0);
    engine.register_block(lock, 0, None, None);
    engine.set_locked_qc(EngineQc::new(lock, 0, vec![]));

    let candidate = chain_id(10);
    let missing_parent = chain_id(999); // never registered
    engine.register_block(candidate, 1, Some(missing_parent), None);
    assert_eq!(
        engine.bounded_safety_decision(&candidate, 5),
        BoundedSafetyOutcome::ParentAbsent
    );
}

#[test]
fn bounded_query_cyclic_fixture_terminates_at_cap() {
    // DIRECT STATE FIXTURE: a genuine cyclic parent graph a -> b -> a with the
    // lock `z` deliberately OFF the cycle. The bounded walk from `a` can never
    // reach `z`; it must terminate FINITELY at `BoundExhausted` once `max_hops`
    // transitions are taken (the test returning at all proves termination — the
    // unbounded walk is never invoked).
    let mut engine = direct_engine();
    let a = chain_id(1);
    let b = chain_id(2);
    let z = chain_id(0); // the lock: never on the a<->b cycle
    engine.register_block(a, 1, Some(b), None); // a -> b
    engine.register_block(b, 2, Some(a), None); // b -> a (closes the cycle)
    engine.set_locked_qc(EngineQc::new(z, 0, vec![]));

    for cap in [0usize, 1, 5, 64] {
        assert_eq!(
            engine.bounded_safety_decision(&a, cap),
            BoundedSafetyOutcome::BoundExhausted,
            "the cyclic walk terminates at the cap {cap} without looping"
        );
    }
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
    let (owner, engine, decided, p1, lim, _lk, rev) = capture_decision(dir.path(), &ctx);
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
    // After the budget frees, EXECUTE the promised retry with the SAME envelope
    // and proposal. Republish so the durable matches the (view-1) engine lock,
    // then re-observe: the identical call now revalidates (0-hop ancestry), and
    // the pin is preserved across both the refusal and the successful retry.
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across admission refusal");
    let lk = engine.locked_qc().expect("post-capture lock");
    publish_qc(&owner, &ctx, lk.block_id, lk.view, rev);
    let retry = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        retry,
        RetainedDecisionObservation::Revalidated(BoundedSafetyOutcome::SafeAncestry { hops: 0 }),
        "the same envelope/proposal revalidates once the budget frees"
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across the successful retry");
}

// ===========================================================================
// Owner-route observation evidence (RUN 422 §13.6, part 3).
//
// Focused cases that EXECUTE the new observation route (NOT the capture route):
// a registered-candidate projection mismatch, a recovery-required refusal, a
// missing required committed-history refusal, loader- vs working-set-phase
// admission refusals demonstrated SEPARATELY (the working-set phase isolated via
// one narrowly scoped, test-only phase hook because the loader peak otherwise
// dominates static pressure), exact operational AND aggregate baselines after a
// success and a refusal with the original envelope/Vote/pin preserved, and a
// bounded coordination handshake proving publication is excluded during the
// observation and an eligible publication succeeds after release.
// ===========================================================================

#[test]
fn observe_registered_candidate_projection_mismatch_rejected() {
    // Capture p1 and republish so the durable matches the engine lock, so the
    // observation reaches the projection check (9c). Then OVERWRITE the
    // registered candidate node with a wrong view: the commitment (9a) and fixed
    // metadata (9b) still match the unchanged proposal, so the mismatch surfaces
    // precisely as a registered-candidate projection refusal (CandidateView).
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, mut engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    publish_qc(&owner, &ctx, lb, lv, rev);
    // The registered candidate id equals the post-capture locked block id; rewrite
    // its node view (the locked_qc view is unchanged, so correspondence still
    // holds and the projection check runs).
    engine
        .state_mut()
        .register_block(lb, lv + 100, Some([0xAB; 32]), None);
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Rejected(RetainedDecisionReject::Projection(
            ProjectionMismatch::CandidateView
        ))
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across a rejection");
}

#[test]
fn observe_recovery_required_inconclusive() {
    // Latch an actual recovery-required backend state with an uncertain durable
    // write, THEN observe: the recovery-required gate (step 3) blocks before any
    // loader/working-set work — distinct from an engine/durable disagreement.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    owner
        .backend_for_test()
        .set_inject(InjectFault::UncertainAfterWrite);
    // Latch recovery with an eligible (view-advancing) uncertain publication. The
    // recovery gate (step 3) short-circuits before any correspondence check, so
    // the durable lock need not match the engine lock here.
    let qc = valid_wire_qc(&ctx, lb, lv + 1);
    let latch = owner.publish_locked(
        make_locked_qc(&ctx, lb, lv + 1, qc, None).unwrap(),
        rev,
        None::<&FixtureCommittedHistory>,
    );
    assert!(
        matches!(latch, PublishResult::UncertainDurable),
        "expected an uncertain durable outcome, got {latch:?}"
    );
    assert!(owner.backend_for_test().recovery_required(), "recovery latched");
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Inconclusive(RetainedDecisionBlocked::RecoveryRequired)
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across a refusal");
}

#[test]
fn observe_missing_committed_history_inconclusive() {
    // Publish an anchored Locked restriction WITH the required independent
    // committed history, then observe supplying NO history: the held-guard loader
    // requires the independent input for the anchored record and declines →
    // evidence unavailable (missing independent committed history), NOT an
    // admission failure.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    let anchor = CommittedAnchor {
        block_id: lb,
        height: lv,
    };
    let qc = valid_wire_qc(&ctx, lb, lv);
    let anchored = make_locked_qc(&ctx, lb, lv, qc, Some(anchor)).unwrap();
    let history = FixtureCommittedHistory::new().with(lb, lv);
    match owner.publish_locked(anchored, rev, Some(&history)) {
        PublishResult::DurableAcknowledged { .. } => {}
        other => panic!("expected the anchored publication to be acknowledged, got {other:?}"),
    }
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Inconclusive(RetainedDecisionBlocked::EvidenceUnavailable(
            LoaderDiagnostic::MissingIndependentHistory
        ))
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across a refusal");
}

#[test]
fn observe_working_set_phase_admission_inconclusive() {
    // Admission refusal at the OBSERVATION WORKING-SET phase, demonstrated
    // SEPARATELY from the loader phase. Static pressure alone cannot isolate this
    // phase: to pass the loader its transient O3 scratch peak (larger than the
    // working set) must fit, which then also leaves room for the smaller working
    // set. So a single narrowly scoped, test-only phase hook applies the pressure
    // AFTER the loader succeeds and BEFORE the working-set reservation: it fills
    // the remaining operational budget so ONLY the working-set admission fails.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    publish_qc(&owner, &ctx, lb, lv, rev);

    let acct = owner.backend_for_test().accounting_handle_for_test();
    let stash: std::sync::Arc<
        std::sync::Mutex<Option<qbind_node::safety_record_store::accounting::Reservation>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let hook_acct = acct.clone();
    let hook_stash = std::sync::Arc::clone(&stash);
    set_observation_working_set_hook(move || {
        // The loader's covering holder reservation is already charged here; fill
        // the tighter of the operational and aggregate remaining budgets so the
        // following working-set reserve (which admits against BOTH) is refused —
        // while the loader peak comfortably fit moments earlier.
        let op_rem = hook_acct
            .cap()
            .map(|c| c.saturating_sub(hook_acct.current()));
        let agg_rem = hook_acct
            .aggregate()
            .cap()
            .map(|c| c.saturating_sub(hook_acct.aggregate().current()));
        let fill = match (op_rem, agg_rem) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => 0,
        };
        if let Ok(r) = hook_acct.reserve(fill) {
            *hook_stash.lock().unwrap() = Some(r);
        }
    });
    let obs = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    clear_observation_working_set_hook();
    assert!(
        stash.lock().unwrap().is_some(),
        "the phase hook actually applied working-set-phase pressure"
    );
    assert_eq!(
        obs,
        RetainedDecisionObservation::Inconclusive(RetainedDecisionBlocked::Admission),
        "the working-set admission was refused after a successful loader phase"
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved across a refusal");

    // Release the working-set-phase pressure and retry with the SAME envelope and
    // proposal: the identical call now revalidates (the loader was never the
    // blocker here).
    *stash.lock().unwrap() = None;
    let retry = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        retry,
        RetainedDecisionObservation::Revalidated(BoundedSafetyOutcome::SafeAncestry { hops: 0 }),
        "the same envelope/proposal revalidates once the working-set budget frees"
    );
}

#[test]
fn observe_success_and_refusal_restore_exact_baselines() {
    // After BOTH a successful observation and a refusal, the exact operational AND
    // aggregate charged totals return to their pre-call baselines, and the
    // original envelope stays live: its complete Vote and its pin provenance (the
    // registry's retained generation identity) are byte-for-byte preserved.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    publish_qc(&owner, &ctx, lb, lv, rev);

    let backend = owner.backend_for_test();
    let vote_before = decided.vote().clone();
    let identities_before = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry installed")
        .lock()
        .unwrap()
        .occupied_identities_for_test();
    let op_before = backend.accounting_current();
    let agg_before = backend.accounting_aggregate_current();

    // Success path: a full revalidation that admits and releases the whole
    // working set.
    let ok = owner.observe_retained_decision(
        &engine,
        &decided,
        &p1,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        ok,
        RetainedDecisionObservation::Revalidated(BoundedSafetyOutcome::SafeAncestry { hops: 0 })
    );
    assert_eq!(
        backend.accounting_current(),
        op_before,
        "operational baseline restored after success"
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        agg_before,
        "aggregate baseline restored after success"
    );

    // Refusal path on the SAME still-live envelope: a substituted proposal fails
    // the commitment check (a rejection after the working set is admitted), and
    // the working set is still fully released.
    let mut substituted = p1.clone();
    substituted.header.payload_hash = [0x7E; 32];
    let refused = owner.observe_retained_decision(
        &engine,
        &decided,
        &substituted,
        &lim,
        None::<&FixtureCommittedHistory>,
    );
    assert_eq!(
        refused,
        RetainedDecisionObservation::Rejected(RetainedDecisionReject::CommitmentMismatch)
    );
    assert_eq!(
        backend.accounting_current(),
        op_before,
        "operational baseline restored after refusal"
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        agg_before,
        "aggregate baseline restored after refusal"
    );

    // The original envelope is still live and unchanged: complete Vote equality
    // and identical retained pin provenance.
    assert_eq!(decided.vote(), &vote_before, "complete Vote preserved");
    let identities_after = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .unwrap()
        .lock()
        .unwrap()
        .occupied_identities_for_test();
    assert_eq!(
        identities_after, identities_before,
        "original pin provenance preserved"
    );
    assert_eq!(registry_occupied(&owner), 1, "pin preserved");
}

// ---------------------------------------------------------------------------
// Bounded coordination for the observation route (RUN 422 §13.6, part 3).
// Mirrors the capture-route handshake helpers but drives the OBSERVATION route
// via its own working-set phase hook, so this is NOT capture-route evidence.
// ---------------------------------------------------------------------------

/// Upper bound on every cross-thread wait. Not a synchronization sleep:
/// coordination is driven by channel signals. The bound only ensures a stuck
/// handshake fails within it instead of hanging.
const COORD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DomainObservation {
    WouldBlock,
    Acquired,
    Poisoned,
}

fn classify_try_lock(outcome: TryLockDomainOutcome<'_>) -> DomainObservation {
    match outcome {
        TryLockDomainOutcome::WouldBlock => DomainObservation::WouldBlock,
        TryLockDomainOutcome::Acquired(_g) => DomainObservation::Acquired,
        TryLockDomainOutcome::Poisoned => DomainObservation::Poisoned,
    }
}

/// The four explicitly recorded legs of the bounded two-way handshake. An
/// observation is credited as evidence of the paused phase ONLY when
/// [`HandshakeLegs::fully_completed`] holds; a silent timeout or dropped endpoint
/// produces a DISTINCT, recorded failure rather than being accepted.
#[derive(Clone, Copy, Default, Debug)]
struct HandshakeLegs {
    owner_entry_signalled: Option<bool>,
    owner_release_received: Option<bool>,
    observer_entry_received: Option<bool>,
    observer_release_acked: Option<bool>,
}

impl HandshakeLegs {
    fn fully_completed(&self) -> bool {
        self.owner_entry_signalled == Some(true)
            && self.owner_release_received == Some(true)
            && self.observer_entry_received == Some(true)
            && self.observer_release_acked == Some(true)
    }
}

/// Owner-side coordination handle, used INSIDE the working-set hook (bound
/// `Fn() + Send + Sync + 'static`), so the single-consumer endpoints are wrapped
/// in `Mutex`. The hook only signals and waits and never panics.
struct OwnerHookCoord {
    entry_tx: std::sync::Mutex<mpsc::Sender<()>>,
    release_rx: std::sync::Mutex<mpsc::Receiver<()>>,
    legs: std::sync::Arc<std::sync::Mutex<HandshakeLegs>>,
}

impl OwnerHookCoord {
    fn signal_entry_and_await_release(&self) {
        let sent = self.entry_tx.lock().unwrap().send(()).is_ok();
        self.legs.lock().unwrap().owner_entry_signalled = Some(sent);
        let released = self
            .release_rx
            .lock()
            .unwrap()
            .recv_timeout(COORD_TIMEOUT)
            .is_ok();
        self.legs.lock().unwrap().owner_release_received = Some(released);
    }
}

/// Observer-side coordination handle, owned by the single observer thread.
struct ObserverCoord {
    entry_rx: mpsc::Receiver<()>,
    release_tx: mpsc::Sender<()>,
    legs: std::sync::Arc<std::sync::Mutex<HandshakeLegs>>,
}

impl ObserverCoord {
    fn await_entry(&self) -> bool {
        let got = self.entry_rx.recv_timeout(COORD_TIMEOUT).is_ok();
        self.legs.lock().unwrap().observer_entry_received = Some(got);
        got
    }

    fn ack_release(&self) {
        let acked = self.release_tx.send(()).is_ok();
        self.legs.lock().unwrap().observer_release_acked = Some(acked);
    }
}

fn make_handshake() -> (
    OwnerHookCoord,
    ObserverCoord,
    std::sync::Arc<std::sync::Mutex<HandshakeLegs>>,
) {
    let (entry_tx, entry_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let legs = std::sync::Arc::new(std::sync::Mutex::new(HandshakeLegs::default()));
    let owner = OwnerHookCoord {
        entry_tx: std::sync::Mutex::new(entry_tx),
        release_rx: std::sync::Mutex::new(release_rx),
        legs: std::sync::Arc::clone(&legs),
    };
    let observer = ObserverCoord {
        entry_rx,
        release_tx,
        legs: std::sync::Arc::clone(&legs),
    };
    (owner, observer, legs)
}

#[test]
fn observe_excludes_publication_until_release() {
    // The observation route holds the single serialization domain across the whole
    // operation. While it pauses at the working-set phase (guard held), a
    // competing non-blocking acquisition observes `WouldBlock` — so a publication
    // (which must take the SAME domain) is excluded. After release the route
    // revalidates and an eligible publication succeeds. The bounded handshake MUST
    // complete on every leg before the observation is credited.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (owner, engine, decided, p1, lim, (lb, lv), rev) = capture_decision(dir.path(), &ctx);
    let rev2 = publish_qc(&owner, &ctx, lb, lv, rev);

    let (owner_coord, observer_coord, legs) = make_handshake();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<DomainObservation>));
    let observed_obs = std::sync::Arc::clone(&observed);

    std::thread::scope(|scope| {
        let obs_owner = &owner;
        let observer = scope.spawn(move || {
            // Only classify after a SUCCESSFUL bounded entry handshake.
            if observer_coord.await_entry() {
                *observed_obs.lock().unwrap() = Some(classify_try_lock(
                    obs_owner.backend_for_test().try_lock_domain_for_test(),
                ));
            }
            observer_coord.ack_release();
        });

        set_observation_working_set_hook(move || owner_coord.signal_entry_and_await_release());
        let outcome = owner.observe_retained_decision(
            &engine,
            &decided,
            &p1,
            &lim,
            None::<&FixtureCommittedHistory>,
        );
        clear_observation_working_set_hook();

        observer.join().expect("observer thread");

        let final_legs = *legs.lock().unwrap();
        assert!(
            final_legs.fully_completed(),
            "the bounded entry/release handshake completed on both sides: {final_legs:?}"
        );
        assert_eq!(
            *observed.lock().unwrap(),
            Some(DomainObservation::WouldBlock),
            "publication is excluded (contention observed) while the observation held the domain"
        );
        assert_eq!(
            outcome,
            RetainedDecisionObservation::Revalidated(BoundedSafetyOutcome::SafeAncestry {
                hops: 0
            }),
            "the observation completes after release"
        );
        assert_eq!(registry_occupied(&owner), 1, "pin preserved across the observation");

        // After release, an ELIGIBLE (view-advancing) publication succeeds (the
        // domain is free and progress resumes).
        match owner.publish_locked(
            make_locked_qc(&ctx, lb, lv + 1, valid_wire_qc(&ctx, lb, lv + 1), None).unwrap(),
            rev2,
            None::<&FixtureCommittedHistory>,
        ) {
            PublishResult::DurableAcknowledged { .. } => {}
            other => panic!("expected an eligible publication to succeed, got {other:?}"),
        }
    });
}