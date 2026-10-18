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
use std::time::Duration;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{
    SafetyBackend, SafetyBackendPolicy, TryLockDomainOutcome,
};
use qbind_node::safety_record_store::decision_capture::{
    covering_charge_for_test, scratch_charge_for_test, OwnedCaptureRefusal, OwnedDecisionOutcome,
    PreparedDecisionInputLimits, ProjectionMismatch,
};
use qbind_node::safety_record_store::owner::{
    clear_binding_phase_hook, clear_capture_interval_hook, clear_pre_ingestion_hook,
    make_locked_qc, set_binding_phase_hook, set_capture_interval_hook, set_pre_ingestion_hook,
    PublishResult, SafetyRecordOwner,
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
// Bounded coordination (§2)
// ===========================================================================

/// Upper bound on every cross-thread wait in the serialization observation
/// tests. It is NOT a synchronization sleep: coordination is driven by actual
/// channel signals (the owner's hook announces its pause; the observer announces
/// release). The bound exists only so that an early owner refusal, a missing
/// hook invocation, an observer failure, or an assertion failure can never leave
/// a scoped thread waiting indefinitely — a stuck test fails within the bound
/// instead of hanging. It is generous relative to the microseconds a real
/// hand-off takes.
const COORD_TIMEOUT: Duration = Duration::from_secs(30);

/// Classification of a non-blocking same-domain acquisition that does NOT retain
/// an acquired guard: any `Acquired` guard is dropped at the match arm, so the
/// classification never itself holds the serialization domain. This distinguishes
/// contention (`WouldBlock`), successful acquisition, and poisoning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DomainObservation {
    WouldBlock,
    Acquired,
    Poisoned,
}

fn classify_try_lock(outcome: TryLockDomainOutcome<'_>) -> DomainObservation {
    match outcome {
        TryLockDomainOutcome::WouldBlock => DomainObservation::WouldBlock,
        // Drop the acquired guard immediately: the classification must never
        // retain the domain it is merely observing.
        TryLockDomainOutcome::Acquired(_g) => DomainObservation::Acquired,
        TryLockDomainOutcome::Poisoned => DomainObservation::Poisoned,
    }
}

// ===========================================================================
// Returned-proof preservation (§3/§4)
// ===========================================================================

/// A read-only fingerprint of a [`ValidatedRecord`]'s externally observable
/// identity, taken BEFORE an owner-route call so the SAME returned proof can be
/// shown to be preserved — its original validated bytes, its publication
/// revision, and its originating pinned-context provenance digest. This compares
/// the ACTUAL returned proof (not a fresh `read_validate`) against the snapshot.
#[derive(Clone, PartialEq, Eq, Debug)]
struct ProofFingerprint {
    encoded: Vec<u8>,
    revision: u64,
    origin: [u8; 32],
}

fn fingerprint(proof: &qbind_node::safety_record_store::ValidatedRecord) -> ProofFingerprint {
    ProofFingerprint {
        encoded: proof.encoded().to_vec(),
        revision: proof.publication_revision(),
        origin: *proof.origin_context_digest(),
    }
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
// 2. Engine L0 lock vs sealed-proof retained restriction mismatch -> a GATE
//    `Correspondence` refusal (produced INSIDE the fallible owning gate AFTER a
//    safe engine decision, NOT an ordinary pre-gate engine rejection), with the
//    SAME proof returned intact and no self-vote. The distinct ordinary
//    pre-gate rejection is covered separately by
//    `ordinary_engine_rejection_refuses_with_proof_and_no_self_vote`.
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
    let before = fingerprint(&proof);
    let lim = limits(&ctx);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);

    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: returned,
            reason,
        } => {
            // This is a GATE correspondence refusal (raised inside the owning
            // gate after the engine decided safe), NOT an ordinary engine
            // rejection taken before the gate was consulted.
            assert!(
                matches!(reason, OwnedCaptureRefusal::Correspondence(_)),
                "expected a gate correspondence refusal, got {reason:?}"
            );
            // The SAME returned proof is preserved byte-for-byte (bytes, revision,
            // provenance), not a re-read substitute.
            assert_eq!(
                fingerprint(&returned),
                before,
                "the returned proof is the intact original"
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

    // Coordination: the hook signals "paused, guard held" and waits for release
    // under a BOUNDED wait. The observer records its non-blocking acquisition
    // classification into a shared slot and ALWAYS releases the owner — even on an
    // unexpected observation or a timeout — so neither the scoped observer nor the
    // owner's hook can wait indefinitely. The hook bound requires `Send + Sync`,
    // so the endpoints it uses are wrapped in a `Mutex` (both `Sender`/`Receiver`
    // are `Send`).
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<DomainObservation>));
    let observed_obs = std::sync::Arc::clone(&observed);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            // Bounded wait until the owner is paused inside the capture interval
            // holding the domain guard; never block forever.
            let entered = entered_rx.recv_timeout(COORD_TIMEOUT);
            // On a successful signal, classify the same-domain non-blocking
            // acquisition (contention vs acquisition vs poisoning) WITHOUT holding
            // any acquired guard. Record it; assert later, outside the hook.
            if entered.is_ok() {
                *observed_obs.lock().unwrap() =
                    Some(classify_try_lock(obs.backend_for_test().try_lock_domain_for_test()));
            }
            // ALWAYS release the owner so its bounded hook wait completes, even if
            // we observed nothing (timeout/disconnect).
            let _ = release_tx.send(());
        });

        // Owner thread: install the one-shot pause hook, then run the route. The
        // hook never panics (so a failed hand-off cannot poison the held domain
        // guard) and waits only under the bounded timeout.
        set_capture_interval_hook(move || {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = release_rx.lock().unwrap().recv_timeout(COORD_TIMEOUT);
        });
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_capture_interval_hook();

        observer.join().expect("observer thread");

        // Assertions OUTSIDE the hook critical section: a failure here cannot
        // leave a thread waiting or poison the domain.
        assert_eq!(
            *observed.lock().unwrap(),
            Some(DomainObservation::WouldBlock),
            "same-domain acquisition observed contention (not poisoning) while the \
             owner held the guard at the capture interval"
        );
        assert!(
            matches!(outcome, OwnedDecisionOutcome::Decided(_)),
            "route completes after release"
        );

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

// ===========================================================================
// 11. §2 — Bind the effective input policy to the owner's pinned context. A
//     policy constructed for a LARGER validator set carries a relaxed
//     QC-signature-count cap; the owner route must refuse it (typed,
//     allocation-free) BEFORE the engine decision, so no dependent self-vote
//     occurs. The correctly bounded owner-derived policy is then accepted.
// ===========================================================================

#[test]
fn owner_route_rejects_policy_built_for_larger_validator_set() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);

    // N=8 policy relaxes the QC-signature-count cap to 8; the owner's pinned N=4
    // caps it at 4. The larger policy must not be admitted by the owner route.
    let larger = limits(&ctx_n(8));
    assert_eq!(larger.max_qc_sig_count(), 8, "larger policy admits 8 signatures");
    assert_eq!(limits(&ctx).max_qc_sig_count(), 4, "owner-derived caps at 4");

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &larger, 1, proof);
    match outcome {
        OwnedDecisionOutcome::Refused { proof: _p, reason } => assert!(
            matches!(reason, OwnedCaptureRefusal::EffectivePolicyMismatch),
            "expected EffectivePolicyMismatch, got {reason:?}"
        ),
        other => panic!("expected Refused, got {other:?}"),
    }
    // The larger policy's four-plus-signature cap was never exercised: the engine
    // was never consulted (still L0 view 0), so no dependent self-vote occurred.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no self-vote on policy refusal"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on policy refusal");
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");

    // Correctly bounded case: the owner-derived N=4 policy is accepted.
    let proof2 = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let decided = match owner
        .decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof2)
    {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided with owner-derived policy, got {other:?}"),
    };
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote on accept");
    assert_eq!(registry_occupied(&owner), 1);
    drop(decided);
}

// ===========================================================================
// 12. §4 — The header-to-originating-proposer projection check. The engine
//     derives the candidate id from the originating `from`, not from
//     `header.proposer_index`, so changing ONLY the header's proposer identity
//     must be caught by the projection check (not the candidate-id check), with
//     the proof returned intact and no dependent self-vote. The matching header
//     succeeds.
// ===========================================================================

#[test]
fn header_proposer_index_mismatch_refuses_projection() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);
    let lim = limits(&ctx);

    // Change ONLY the header's proposer identity (2 != originating proposer 1).
    let mut mismatched = p1.clone();
    mismatched.header.proposer_index = 2;

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let outcome = owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &mismatched,
        &lim,
        1,
        proof,
    );
    match outcome {
        OwnedDecisionOutcome::Refused { proof: _p, reason } => assert!(
            matches!(
                reason,
                OwnedCaptureRefusal::Projection(ProjectionMismatch::Proposer)
            ),
            "expected Projection(Proposer), got {reason:?}"
        ),
        other => panic!("expected Refused, got {other:?}"),
    }
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no dependent self-vote on projection refusal"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on projection refusal");
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");

    // The matching header (proposer_index == originating proposer 1) succeeds on
    // the still-unvoted engine.
    let proof2 = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let decided = match owner
        .decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof2)
    {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided for matching header, got {other:?}"),
    };
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote on accept");
    drop(decided);
}

// ===========================================================================
// 13. §3 — Admission-before-construction: the additional `covering` (envelope/
//     data) reservation is admitted BEFORE the binding values it covers. A
//     discriminating observation reads the accounting occupancy at the binding
//     phase (an observer thread, while the owner is paused holding the guard) and
//     confirms the occupancy already includes BOTH `covering` and `scratch` — the
//     reservation overlap that only holds when `covering` was admitted first. The
//     reviewed order (covering admitted AFTER the bindings) would show only
//     `scratch` at this phase.
// ===========================================================================

#[test]
fn binding_phase_reservation_overlaps_covering() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Occupancy with the proof held, before the route runs (the registry is still
    // unallocated and is only created during capture, AFTER this binding phase).
    let before = op_current(&owner);
    let covering = covering_charge_for_test().expect("covering charge");
    let scratch = scratch_charge_for_test();

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    let snapshot = std::sync::Arc::new(std::sync::Mutex::new(None::<u128>));
    let snapshot_obs = std::sync::Arc::clone(&snapshot);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            // Bounded wait for the binding-phase signal; never block forever.
            if entered_rx.recv_timeout(COORD_TIMEOUT).is_ok() {
                // Accounting is a SEPARATE mutex from the serialization domain, so
                // this read does not contend with the held domain guard.
                let occ = obs.backend_for_test().accounting_current();
                *snapshot_obs.lock().unwrap() = Some(occ);
            }
            // ALWAYS release the owner so its bounded hook wait completes.
            let _ = release_tx.send(());
        });

        set_binding_phase_hook(move || {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = release_rx.lock().unwrap().recv_timeout(COORD_TIMEOUT);
        });
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_binding_phase_hook();
        observer.join().expect("observer thread");
        assert!(
            matches!(outcome, OwnedDecisionOutcome::Decided(_)),
            "route completes after the binding-phase observation"
        );
    });

    let occ = snapshot.lock().unwrap().expect("binding-phase occupancy recorded");
    assert_eq!(
        occ,
        before + covering + scratch,
        "covering and scratch overlap at the binding phase: covering was admitted \
         BEFORE the covered binding values (the corrected admission order)"
    );
}

// ===========================================================================
// 14. §3 — Continuous coverage on every refusal: the envelope (covering)
//     admission refusal, the scratch admission refusal, and the capture refusal
//     each destroy the covered objects before releasing their covering
//     reservations, returning the proof intact and the charges exactly to the
//     starved baseline, with no dependent self-vote.
// ===========================================================================

#[test]
fn covering_scratch_and_capture_refusals_restore_baseline() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let lim = limits(&ctx);
    let covering = covering_charge_for_test().expect("covering charge");

    // --- envelope (covering) admission refusal: leave < covering ------------
    {
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        let backend = owner.backend_for_test();
        let op_headroom =
            backend.accounting_cap().expect("op ceiling") - backend.accounting_current();
        let agg_headroom = backend
            .accounting_aggregate_cap()
            .expect("agg ceiling")
            - backend.accounting_aggregate_current();
        let headroom = op_headroom.min(agg_headroom);
        // Leave covering-1 bytes: the FIRST reservation (covering) is refused.
        let standing = backend
            .reserve_standing_for_test(headroom - (covering - 1))
            .expect("starve below covering");
        let starved = op_current(&owner);
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        assert!(
            matches!(
                outcome,
                OwnedDecisionOutcome::Refused {
                    reason: OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_)),
                    ..
                }
            ),
            "expected a covering admission refusal"
        );
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote");
        assert_eq!(registry_occupied(&owner), 0);
        assert_eq!(op_current(&owner), starved, "covering released, baseline restored");
        drop(standing);
    }

    // --- scratch admission refusal: leave exactly covering ------------------
    {
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        let backend = owner.backend_for_test();
        let op_headroom =
            backend.accounting_cap().expect("op ceiling") - backend.accounting_current();
        let agg_headroom = backend
            .accounting_aggregate_cap()
            .expect("agg ceiling")
            - backend.accounting_aggregate_current();
        let headroom = op_headroom.min(agg_headroom);
        // Leave exactly covering bytes: covering succeeds, then scratch is refused.
        let standing = backend
            .reserve_standing_for_test(headroom - covering)
            .expect("starve to exactly covering");
        let starved = op_current(&owner);
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        assert!(
            matches!(
                outcome,
                OwnedDecisionOutcome::Refused {
                    reason: OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_)),
                    ..
                }
            ),
            "expected a scratch admission refusal"
        );
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote");
        assert_eq!(registry_occupied(&owner), 0);
        assert_eq!(
            op_current(&owner),
            starved,
            "covering + scratch released, baseline restored"
        );
        drop(standing);
    }

    // --- capture refusal (stale expected revision): covering + scratch admitted,
    //     bindings computed, then the capture conversion refuses; covered objects
    //     destroyed before the reservations release ----------------------------
    {
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        let baseline = op_current(&owner);
        // expected revision 2 disagrees with the current authoritative revision 1.
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 2, proof);
        assert!(
            matches!(
                outcome,
                OwnedDecisionOutcome::Refused {
                    reason: OwnedCaptureRefusal::Capture(CaptureRefusal::StaleRevision { .. }),
                    ..
                }
            ),
            "expected a stale-revision capture refusal"
        );
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote");
        assert_eq!(registry_occupied(&owner), 0);
        assert_eq!(
            op_current(&owner),
            baseline,
            "covering + scratch released on capture refusal, baseline restored"
        );
    }
}

// ===========================================================================
// 15. §5 — The pre-ingestion serialization observation point. A competing,
//     non-blocking same-domain acquisition observes `WouldBlock` (contention,
//     not poisoning) at the fixed semantic boundary immediately BEFORE the owner
//     invokes the engine ingestion, establishing that the owner held the one
//     serialization domain before ingestion. After normal release the route
//     completes and an actual eligible publication succeeds (publication
//     completion, not mere lock availability).
// ===========================================================================

#[test]
fn pre_ingestion_hook_observes_would_block_before_ingestion() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<DomainObservation>));
    let observed_obs = std::sync::Arc::clone(&observed);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            // Bounded wait for the pre-ingestion pause; never block forever.
            if entered_rx.recv_timeout(COORD_TIMEOUT).is_ok() {
                // Same-domain non-blocking acquisition: contention, not poisoning.
                // Classified without retaining any acquired guard.
                *observed_obs.lock().unwrap() =
                    Some(classify_try_lock(obs.backend_for_test().try_lock_domain_for_test()));
            }
            // ALWAYS release the owner so its bounded hook wait completes.
            let _ = release_tx.send(());
        });

        // Install the pre-ingestion hook (fires strictly BEFORE the engine call).
        // It never panics and waits only under the bounded timeout.
        set_pre_ingestion_hook(move || {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = release_rx.lock().unwrap().recv_timeout(COORD_TIMEOUT);
        });
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_pre_ingestion_hook();
        observer.join().expect("observer thread");

        // Assert the observation OUTSIDE the hook critical section.
        assert_eq!(
            *observed.lock().unwrap(),
            Some(DomainObservation::WouldBlock),
            "same-domain acquisition observed contention (not poisoning) before ingestion"
        );
        let decided = match outcome {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("route completes after release, got {other:?}"),
        };

        // The self-vote ran AFTER the pre-ingestion point, raising L1.
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "ingestion ran after release");
        drop(decided);
    });

    // After the route released the domain, perform an ACTUAL eligible publication
    // (not merely a successful try_lock) and assert it completes, advancing the
    // authoritative revision from 1 to 2.
    let new_rev = publish_qc(&owner, &ctx, [0x5Au8; 32], 2, 1);
    assert_eq!(new_rev, 2, "publication completed after normal release");
}

// ===========================================================================
// 16. §6 Retained L0 — after the real self-vote raises the engine to L1, the
//     ACTUAL captured generation identity still carries the L0 lock (view 0,
//     block = the engine's L0 lock), established by inspecting the retained
//     generation's provenance, not by registry occupancy alone.
// ===========================================================================

#[test]
fn captured_generation_retains_l0_provenance_after_self_vote_l1() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let decided = match owner
        .decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
    {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };
    // The engine's own live lock advanced to L1 via the self-vote.
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote raised L1");

    // The captured generation's provenance is still L0: inspect the actual
    // retained identity (not merely the occupancy count).
    let reg = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry allocated by the capture");
    let identities = reg.lock().unwrap().occupied_identities_for_test();
    assert_eq!(identities.len(), 1, "exactly one captured generation");
    assert_eq!(
        identities[0].lock_view, 0,
        "captured generation retains the L0 lock view despite the engine at L1"
    );
    assert_eq!(
        identities[0].lock_block_id, l0_block,
        "captured generation retains the L0 lock block id"
    );

    drop(decided);
    assert_eq!(registry_occupied(&owner), 0, "abandoning frees the slot");
}
// ===========================================================================
// 17. §4 — Owner-route OrdinaryEngineRejection: an ACTUAL engine rejection taken
//     BEFORE the gate is consulted. The engine decides it is NOT safe to vote on
//     a conflicting-fork proposal (no justify QC, parent unregistered), so the
//     fallible owning gate — and therefore every correspondence / projection /
//     ancestry check — is never reached. The owner/proof is otherwise admissible
//     (durable lock matches L0, policy derived from the pinned context). The SAME
//     proof is returned intact, no dependent self-vote or capture occurs, and the
//     charges return exactly to baseline. This is distinct from the gate
//     `Correspondence` refusal in
//     `lock_mismatch_refuses_with_proof_returned_and_no_self_vote`.
// ===========================================================================

#[test]
fn ordinary_engine_rejection_refuses_with_proof_and_no_self_vote() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    // Engine locked at L0 (view 0). Build a CONFLICTING candidate: no justify QC
    // (so the view-sufficiency short-circuit cannot apply) whose parent is an
    // unregistered block (so the ancestry walk cannot reach the lock) -> the
    // engine's safety predicate returns Unsafe BEFORE the gate is consulted.
    let (mut engine, _safe_p1, l0_block) = engine_locked_and_safe_view1();
    let mut conflicting = make_proposal(1, [0x77u8; 32], 1);
    conflicting.qc = None;
    // Admissible owner/proof: the durable lock matches the engine L0 and the
    // policy is owner-derived. Correspondence WOULD pass, but the engine rejects
    // first so the gate is never reached.
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    let lim = limits(&ctx);

    let outcome = owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &conflicting,
        &lim,
        1,
        proof,
    );
    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::OrdinaryEngineRejection),
                "expected an ordinary pre-gate engine rejection, got {reason:?}"
            );
            assert_eq!(
                fingerprint(&returned),
                before,
                "the same proof is returned intact"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // The engine was consulted but rejected before the gate: no self-vote (still
    // L0 view 0), no capture, and the charges return exactly to baseline.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no dependent self-vote on an ordinary engine rejection"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on ordinary rejection");
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");
}

// ===========================================================================
// 18. §4 — Owner-route MissingCandidate: the existing engine missing-candidate
//     path, reached through existing configuration (`max_pending_blocks == 0`)
//     and the owner entrypoint. Under that block-slot pressure the just-
//     registered candidate is immediately evicted, and a `NoLock` engine decision
//     (the engine itself holds no lock) succeeds WITHOUT a candidate lookup; the
//     owning gate then finds the required decision-view candidate absent and
//     refuses `MissingCandidate` BEFORE any self-vote. The owner still holds a
//     durable restriction (so the provenance precheck passes) and an admissible
//     policy; the SAME proof is returned intact, no capture occurs, and the
//     charges return exactly to baseline. This is an engine missing-candidate
//     refusal, kept distinct from a storage bootstrap refusal.
// ===========================================================================

#[test]
fn missing_candidate_refuses_with_proof_and_no_self_vote() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    // Fresh engine with NO lock and `max_pending_blocks == 0`: the candidate is
    // evicted on registration and the decision is `NoLock` (no candidate lookup).
    let limits_cfg = qbind_consensus::ConsensusLimitsConfig {
        max_pending_blocks: 0,
        ..Default::default()
    };
    let mut engine: BasicHotStuffEngine<[u8; 32]> = BasicHotStuffEngine::with_state_limits(
        ValidatorId::new(1),
        engine_validator_set(1),
        limits_cfg,
    );
    let p = make_proposal(0, [0xFFu8; 32], 1);
    // Owner holds a durable restriction so the provenance precheck passes; the
    // engine lock is absent, but correspondence is never reached.
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [0x42u8; 32], 3, 0);
    let baseline = op_current(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    let lim = limits(&ctx);

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p, &lim, 1, proof);
    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::MissingCandidate),
                "expected a missing-candidate refusal, got {reason:?}"
            );
            assert_eq!(
                fingerprint(&returned),
                before,
                "the same proof is returned intact"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // The engine held no lock to begin with, so there is nothing to self-vote
    // into; no capture occurs and the charges return exactly to baseline.
    assert!(
        engine.locked_qc().is_none(),
        "engine remains unlocked; no self-vote"
    );
    assert_eq!(
        registry_occupied(&owner),
        0,
        "no capture on missing-candidate refusal"
    );
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");
}
