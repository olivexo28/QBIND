//! RUN 422 §13.6 — Owner-controlled decision/capture binding (ISOLATED).
//!
//! These tests exercise the owner-controlled route
//! [`SafetyRecordOwner::decide_and_capture_owned`]: the owner acquires the
//! backend serialization domain, invokes the existing owning engine entrypoint,
//! the real safety decision runs under L0, correspondence / projection /
//! input-policy / ancestry checks and the capture run under that SAME held
//! guard, the existing self-vote may raise L1, and the existing closed
//! `DecidedVote<OwningCapturePayload>` envelope is produced.
//!
//! The route authenticates nothing: the proposal commitment and ancestry
//! binding are a *volatile decision association*, not a certificate check. The
//! whole target is gated behind `test-utils` (it uses the `test-utils`-gated
//! observation seams `backend_for_test`, `accounting_current`,
//! `reserve_standing_for_test`, `prepared_registry_for_test`,
//! `try_lock_domain_for_test`, `set_capture_interval_hook`) and carries no
//! production caller. Activation remains DISABLED.

#![cfg(feature = "test-utils")]

use std::sync::mpsc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{
    SafetyBackend, SafetyBackendPolicy, TryLockDomainOutcome,
};
use qbind_node::safety_record_store::decision_capture::{
    OwnedCaptureRefusal, OwnedDecisionOutcome, PreparedDecisionInputLimits,
};
use qbind_node::safety_record_store::owner::{
    clear_capture_interval_hook, make_locked_qc, set_capture_interval_hook, PublishResult,
    SafetyRecordOwner,
};
use qbind_node::safety_record_store::prepared::CaptureRefusal;
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::WireQc as StoreWireQc;
use qbind_node::safety_record_store::validate::FixtureCommittedHistory;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as EngineWireQc};

// ===========================================================================
// Fixtures (mirrors of the owning-handoff node test fixtures)
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

/// Publish one Locked restriction and return the new authoritative revision.
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

fn op_current(owner: &SafetyRecordOwner) -> u128 {
    owner.backend_for_test().accounting_current()
}

fn registry_occupied(owner: &SafetyRecordOwner) -> usize {
    match owner.backend_for_test().prepared_registry_for_test() {
        Some(reg) => reg.lock().unwrap().occupied(),
        None => 0,
    }
}

fn limits(ctx: &PinnedSafetyContext) -> PreparedDecisionInputLimits {
    PreparedDecisionInputLimits::from_pinned(ctx).expect("pinned context yields a valid policy")
}

// ===========================================================================
// Consensus helpers
// ===========================================================================

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

/// A single-validator engine locked at view 0, advanced to view 1, together with
/// a safe view-1 proposal (ViewSufficiency branch) and the engine's L0 lock id.
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

/// Mint a Locked proof whose retained lock matches the engine's L0 lock, so the
/// owner-route correspondence check accepts it. Returns (owner, proof, limits).
fn owner_with_matching_proof(
    dir: &std::path::Path,
    ctx: &PinnedSafetyContext,
    l0_block: [u8; 32],
) -> SafetyRecordOwner {
    let owner = init_owner(dir, ctx);
    // Lock block id = engine L0 block, lock view 0 -> revision 1.
    publish_qc(&owner, ctx, l0_block, 0, 0);
    owner
}

// ===========================================================================
// 1. Real L0 decision/capture -> same-event self-vote L1; retain original L0.
// ===========================================================================

#[test]
fn owner_route_decides_l0_captures_and_self_votes_l1() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);

    let decided = match outcome {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };

    // The real self-vote raised L1 AFTER the L0 decision/capture; the engine's
    // own live lock is now view 1, while the captured payload retains the L0
    // association (lock view 0) that drove the decision.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(1),
        "self-vote raised L1"
    );
    assert_eq!(
        registry_occupied(&owner),
        1,
        "the envelope owns one live pin"
    );
    assert!(
        op_current(&owner) > baseline,
        "pin + reservations charged while owned"
    );

    // The envelope carries the engine's own unsigned self-vote (read-only).
    assert_eq!(decided.vote().height, 1);
    assert_eq!(decided.vote().signature.capacity(), 0, "unsigned self-vote");

    drop(decided);
    assert_eq!(registry_occupied(&owner), 0, "abandoning frees the slot");
}

// ===========================================================================
// 2. Engine L0 lock vs current durable restriction mismatch -> refusal, proof
//    returned intact, no self-vote.
// ===========================================================================

#[test]
fn lock_mismatch_refuses_with_proof_returned_and_no_self_vote() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, _l0_block) = engine_locked_and_safe_view1();
    let owner = init_owner(dir.path(), &ctx);
    // Publish a DIFFERENT durable lock than the engine's L0 (block [9;32]@5).
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);

    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: _returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::Correspondence(_)),
                "expected a correspondence refusal, got {reason:?}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // No self-vote raised L1; the engine's live lock is still L0 (view 0).
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no self-vote on refusal"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on refusal");
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");
}

// ===========================================================================
// 3. Projection mismatch (via the test-only mismatched-input seam) -> refusal,
//    proof returned, no capture. The engine decides on the real proposal while
//    the gate projects a substituted proposal; this is NOT a production API.
// ===========================================================================

#[test]
fn projection_mismatch_via_seam_refuses_with_proof_returned() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Gate projects a proposal whose candidate view / id disagree with the
    // engine's actual decision (height 2 vs the engine's view-1 decision).
    let mut mismatched = p1.clone();
    mismatched.header.height = 2;
    mismatched.header.round = 2;

    let outcome = owner.decide_and_capture_owned_projection_seam(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &mismatched,
        &lim,
        1,
        proof,
    );

    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: _returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::Projection(_)),
                "expected a projection refusal, got {reason:?}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    assert_eq!(
        registry_occupied(&owner),
        0,
        "no capture on projection refusal"
    );
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");
}

// ===========================================================================
// 4. Proof return on pre-consumption exits: owner-precheck BootstrapUnresolved
//    (no durable lock yet) returns the intact proof before the engine call.
// ===========================================================================

#[test]
fn bootstrap_unresolved_precheck_returns_proof_before_engine() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, _l0) = engine_locked_and_safe_view1();
    let owner = init_owner(dir.path(), &ctx);
    // No publish_qc: the authoritative restriction is BootstrapNoLock.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 0, proof);
    match outcome {
        OwnedDecisionOutcome::Refused { proof: _p, reason } => {
            assert!(
                matches!(
                    reason,
                    OwnedCaptureRefusal::Precheck(CaptureRefusal::BootstrapUnresolved)
                ),
                "expected BootstrapUnresolved precheck, got {reason:?}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // The engine was never consulted: still at L0 view 0.
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(0));
}

// ===========================================================================
// 5. Scratch/envelope admission refusal: with headroom reduced below the
//    required charge, the route refuses WITHOUT a dependent self-vote or
//    envelope, returns the proof, restores capacity, and a subsequent attempt
//    (headroom restored) succeeds.
// ===========================================================================

#[test]
fn admission_refusal_then_admissible_retry() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let lim = limits(&ctx);

    // Read the proof FIRST (its O3 holder charge is now live), then starve the
    // remaining headroom so the route's first ADDITIONAL reservation (the
    // transient hashing/traversal scratch) is refused — without disturbing the
    // already-held proof.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let backend = owner.backend_for_test();
    let op_headroom =
        backend.accounting_cap().expect("operational ceiling") - backend.accounting_current();
    let agg_headroom = backend
        .accounting_aggregate_cap()
        .expect("aggregate ceiling")
        - backend.accounting_aggregate_current();
    let headroom = op_headroom.min(agg_headroom);
    // Leave only 8 bytes: far below the route's fixed scratch charge.
    let standing = backend
        .reserve_standing_for_test(headroom - 8)
        .expect("reserve standing to starve the route");

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
    match outcome {
        OwnedDecisionOutcome::Refused { proof: _p, reason } => {
            assert!(
                matches!(
                    reason,
                    OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_))
                ),
                "expected an admission refusal, got {reason:?}"
            );
        }
        other => panic!("expected admission Refused, got {other:?}"),
    }
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no dependent self-vote"
    );
    assert_eq!(
        registry_occupied(&owner),
        0,
        "no envelope/pin on admission refusal"
    );

    // Restore capacity; the route is admissible on retry.
    drop(standing);
    let proof2 = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let retry =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof2);
    let decided = match retry {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected admissible retry to Decide, got {other:?}"),
    };
    assert_eq!(decided.vote().height, 1);
    assert_eq!(registry_occupied(&owner), 1, "retry captured one pin");
    drop(decided);
}

// ===========================================================================
// 6. Ordinary pins and envelopes share the SAME existing two-slot population:
//    an ordinary capture + an owner-route envelope fill both slots; a third
//    refuses RegistryFull with the proof intact.
// ===========================================================================

#[test]
fn envelope_shares_the_two_existing_prepared_slots() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let lim = limits(&ctx);

    // Slot 1: an ordinary capture.
    let proof_a = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let _ordinary = owner
        .capture_prepared_decision(proof_a, 1)
        .expect("ordinary capture takes slot 1");
    assert_eq!(registry_occupied(&owner), 1);

    // Slot 2: an owner-route envelope.
    let proof_b = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let _decided = match owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &lim,
        1,
        proof_b,
    ) {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };
    assert_eq!(registry_occupied(&owner), 2, "both existing slots occupied");

    // A third capture refuses RegistryFull, proof intact — no new multiplicity.
    let proof_c = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    match owner.capture_prepared_decision(proof_c, 1) {
        Err((_proof, CaptureRefusal::RegistryFull)) => {}
        other => panic!("expected RegistryFull with proof returned, got {other:?}"),
    }
    assert_eq!(registry_occupied(&owner), 2, "refusal consumed no slot");
}

// ===========================================================================
// 7. Complete outgoing Vote parity: all ten fields match the engine's own
//    ungated self-vote, and the carried signature has zero capacity.
// ===========================================================================

#[test]
fn outgoing_vote_parity_all_ten_fields_and_zero_signature_capacity() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();

    // Reference engine (ungated) produces the canonical self-vote.
    let (mut ref_engine, ref_p1, _l0_ref) = engine_locked_and_safe_view1();
    let ref_action = ref_engine.on_proposal_event(ValidatorId::new(1), &ref_p1);
    let ref_vote = match ref_action {
        Some(ConsensusEngineAction::BroadcastVote(v)) => v,
        other => panic!("reference engine must self-vote, got {other:?}"),
    };

    // Owner-route engine produces the SAME self-vote inside the envelope.
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let decided =
        match owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
        {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("expected Decided, got {other:?}"),
        };
    let got = decided.vote();

    assert_eq!(got.version, ref_vote.version, "field 1: version");
    assert_eq!(got.chain_id, ref_vote.chain_id, "field 2: chain_id");
    assert_eq!(got.epoch, ref_vote.epoch, "field 3: epoch");
    assert_eq!(got.height, ref_vote.height, "field 4: height");
    assert_eq!(got.round, ref_vote.round, "field 5: round");
    assert_eq!(got.step, ref_vote.step, "field 6: step");
    assert_eq!(got.block_id, ref_vote.block_id, "field 7: block_id");
    assert_eq!(
        got.validator_index, ref_vote.validator_index,
        "field 8: validator_index"
    );
    assert_eq!(got.suite_id, ref_vote.suite_id, "field 9: suite_id");
    assert_eq!(
        got.signature, ref_vote.signature,
        "field 10: signature bytes"
    );
    assert_eq!(
        got.signature.capacity(),
        0,
        "unsigned: zero signature capacity"
    );
}

// ===========================================================================
// 8. Abandonment, standing-registry baseline and final teardown.
// ===========================================================================

#[test]
fn abandonment_restores_baseline_leaving_only_standing_registry() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let decided =
        match owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
        {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("expected Decided, got {other:?}"),
        };
    let occupied_charge = op_current(&owner);
    assert!(
        occupied_charge > baseline,
        "pin + envelope reservation charged"
    );

    // Abandonment: covered objects destroyed before their covering reservations
    // release; the lazily installed registry cell persists as a standing charge.
    drop(decided);
    let after = op_current(&owner);
    assert_eq!(registry_occupied(&owner), 0, "slot freed");
    assert!(after >= baseline, "charges did not underflow the baseline");
    assert!(after < occupied_charge, "pin + envelope + scratch released");
}

// ===========================================================================
// 9. Required-ancestry not-applicable branch: a ViewSufficiency decision records
//    the not-applicable ancestry without a walk and still captures.
// ===========================================================================

#[test]
fn view_sufficiency_records_not_applicable_ancestry() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    // engine_locked_and_safe_view1 yields a ViewSufficiency decision (justify
    // view 0 >= locked view 0): no ancestry walk is required.
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
    assert!(
        matches!(outcome, OwnedDecisionOutcome::Decided(_)),
        "ViewSufficiency captures with not-applicable ancestry"
    );
    assert_eq!(registry_occupied(&owner), 1);
}

// ===========================================================================
// 10. Serialization: an observer against the SAME domain sees `WouldBlock` while
//     the owner is paused holding the guard at the pre-ingestion semantic point,
//     then `Acquired` after normal release (publication progress). Bounded
//     coordination (channels), no timing sleeps.
// ===========================================================================

#[test]
fn owner_route_holds_domain_until_release_observed_as_would_block() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Coordination: the hook signals "paused, guard held" and waits for release.
    // The hook bound requires `Send + Sync`, so the endpoints it uses are wrapped
    // in a `Mutex` (both `Sender`/`Receiver` are `Send`).
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let release_rx = std::sync::Mutex::new(release_rx);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            // Wait until the owner is paused inside the capture interval holding
            // the domain guard.
            entered_rx.recv().expect("owner signals it is paused");
            // Same-domain non-blocking acquisition must observe contention, not
            // poisoning: the owner holds the guard and has not panicked.
            match obs.backend_for_test().try_lock_domain_for_test() {
                TryLockDomainOutcome::WouldBlock => {}
                other => panic!("expected WouldBlock while owner holds the guard, got {other:?}"),
            }
            // Let the owner complete and release the guard.
            release_tx.send(()).expect("release the owner");
        });

        // Owner thread: install the one-shot pause hook, then run the route.
        set_capture_interval_hook(move || {
            entered_tx
                .lock()
                .unwrap()
                .send(())
                .expect("announce paused");
            release_rx.lock().unwrap().recv().expect("await release");
        });
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_capture_interval_hook();
        assert!(
            matches!(outcome, OwnedDecisionOutcome::Decided(_)),
            "route completes after release"
        );

        observer.join().expect("observer thread");

        // The capture committed under the guard: the envelope (still alive here)
        // owns one live pin.
        assert_eq!(
            registry_occupied(&owner),
            1,
            "the capture committed under the guard"
        );

        // After normal release, a late acquisition now succeeds (publication can
        // make progress); restore it immediately, byte-identically.
        match owner.backend_for_test().try_lock_domain_for_test() {
            TryLockDomainOutcome::Acquired(_g) => {}
            other => panic!("expected Acquired after release, got {other:?}"),
        }
    });
}
