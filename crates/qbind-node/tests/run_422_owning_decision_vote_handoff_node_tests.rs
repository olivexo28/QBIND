//! Run 422 §13.6 — node-side evidence for the isolated, opt-in **owning**
//! decision-to-vote handoff: the node gate captures a `PreparedPin` **inside**
//! `evaluate_owning` (via the existing
//! [`SafetyRecordOwner::capture_prepared_decision`]) and hands back a
//! `HandoffPayload { pin, extra_reservation }` that the consensus engine
//! transports — unexamined — across its self-vote into the closed
//! [`DecidedVote`] envelope.
//!
//! These tests drive the ACTUAL engine entrypoint
//! ([`BasicHotStuffEngine::on_proposal_event_gated_owning`]) against a real
//! `SafetyRecordOwner`, to establish that:
//!
//! - **Same-invocation ownership:** the pin is captured within the gate call
//!   and the returned envelope owns a live pin whose registry entry is
//!   occupied; abandoning the envelope frees the slot and releases every charge.
//! - **Two-slot exhaustion (shared):** an envelope capture consumes **one of the
//!   two existing** prepared slots; with one ordinary pin outstanding a handoff
//!   takes the second, and a further capture (ordinary or handoff) refuses with
//!   `RegistryFull` and the proof returned intact — the envelope adds no new
//!   multiplicity.
//! - **Refusal cleanup:** a forced capture refusal releases the extra
//!   reservation (operational `current()` returns to its pre-gate value) and the
//!   capture API returns the proof intact (it captures successfully afterward).
//! - **No double charge:** the embedded pin is covered by its own reservation,
//!   so `extra_charge == size_of::<DecidedVote<HandoffPayload>>() -
//!   size_of::<PreparedPin>()`, and the admitted operational total equals an
//!   ordinary capture's charges **plus** the extra — the pin is counted once.
//!
//! Scope (per the brief): this establishes **same-invocation ownership/
//! association only** — no engine-decision↔generation correspondence,
//! verification, freshness, or authorization. Accepted storage stays CLOSED;
//! §13.6 correspondence remains INCOMPLETE; activation DISABLED; public DevNet
//! NO-GO.

use std::mem::size_of;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet, DecidedVote,
    GatedSelfVoteRefusal, OwningSafetyDecisionGate, SafetyDecisionView, SafetyGateRefusal,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::accounting::{
    prepared_generation_charge, prepared_holder_control_charge, Reservation,
};
use qbind_node::safety_record_store::backend::{SafetyBackend, SafetyBackendPolicy};
use qbind_node::safety_record_store::owner::{make_locked_qc, PublishResult, SafetyRecordOwner};
use qbind_node::safety_record_store::prepared::{
    generation_backing_struct_size_bytes, pin_charge_bytes, registry_cell_charge_bytes,
    CaptureRefusal, PreparedPin,
};
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::{ValidatedRecord, WireQc as StoreWireQc};
use qbind_node::safety_record_store::validate::FixtureCommittedHistory;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as EngineWireQc};

// ===========================================================================
// Node-side payload and gate under test
// ===========================================================================

/// The node-side owning payload. `pin` is declared FIRST and the trailing
/// `extra_reservation` LAST, so Rust's declaration-order drop destroys the pin
/// (freeing its registry entry and, on the last share, its generation charge)
/// **before** the extra reservation is released — no live object is uncharged
/// across the release.
///
/// `#[allow(dead_code)]`: both fields exist purely for their ordered RAII `Drop`
/// (the pin releases its registry slot/charges; the reservation releases last);
/// they are never read.
#[allow(dead_code)]
struct HandoffPayload {
    /// Occupies one of the registry's two existing slots; covered by its own
    /// inline `_pin_reservation`.
    pin: PreparedPin,
    /// Covers the envelope/control bytes OUTSIDE the embedded pin. Declared last
    /// so it releases only after the pin is destroyed.
    extra_reservation: Reservation,
}

/// The exact extra bytes the handoff must reserve: the whole envelope minus the
/// embedded pin (which its own `_pin_reservation` already covers). Verified by
/// `size_of`, not a hand-estimated number.
fn extra_charge_bytes() -> u128 {
    (size_of::<DecidedVote<HandoffPayload>>() - size_of::<PreparedPin>()) as u128
}

/// A node gate that, inside `evaluate_owning`, reserves the extra envelope bytes
/// (fail-fast) and then captures a `PreparedPin` via the existing capture API,
/// returning the combined `HandoffPayload`. On refusal it releases the extra
/// reservation and retains the returned proof intact. It never panics.
struct NodeCapturingGate<'o> {
    owner: &'o SafetyRecordOwner,
    proof: Option<ValidatedRecord>,
    expected_revision: u64,
    extra_charge: u128,
    calls: usize,
    last_refusal: Option<CaptureRefusal>,
    returned_proof: Option<ValidatedRecord>,
}

impl<'o> NodeCapturingGate<'o> {
    fn new(owner: &'o SafetyRecordOwner, proof: ValidatedRecord, expected_revision: u64) -> Self {
        Self {
            owner,
            proof: Some(proof),
            expected_revision,
            extra_charge: extra_charge_bytes(),
            calls: 0,
            last_refusal: None,
            returned_proof: None,
        }
    }
}

impl OwningSafetyDecisionGate<[u8; 32], HandoffPayload> for NodeCapturingGate<'_> {
    fn evaluate_owning(
        &mut self,
        _decision: &SafetyDecisionView<'_, [u8; 32]>,
    ) -> Result<HandoffPayload, SafetyGateRefusal> {
        self.calls += 1;
        // Step 1: reserve the extra envelope bytes FIRST (cheap, fail-fast). On
        // refusal there is no capture and no self-vote.
        let extra_reservation = match self
            .owner
            .backend_for_test()
            .reserve_standing_for_test(self.extra_charge)
        {
            Ok(r) => r,
            Err(_) => return Err(SafetyGateRefusal),
        };
        // Step 2: capture via the existing API (acquires the serialization
        // domain INTERNALLY — never taken externally here).
        let proof = self.proof.take().expect("gate was handed a proof");
        match self
            .owner
            .capture_prepared_decision(proof, self.expected_revision)
        {
            Ok(pin) => Ok(HandoffPayload {
                pin,
                extra_reservation,
            }),
            Err((proof, refusal)) => {
                // Release the extra reservation; retain the proof intact (the
                // capture API already left the standing registry behavior and
                // returned the proof unconsumed).
                drop(extra_reservation);
                self.last_refusal = Some(refusal);
                self.returned_proof = Some(proof);
                Err(SafetyGateRefusal)
            }
        }
    }
}

// ===========================================================================
// Storage helpers (subset mirrored from the prepared-generation spike)
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

/// Publish one QC-derived restriction and return the new authoritative revision.
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

/// The number of occupied registry slots. The registry is installed lazily on
/// the first successful capture; before that it is absent and occupancy is 0.
/// Acquires the domain lock itself; must not be called while a capture holds the
/// domain guard.
fn registry_occupied(owner: &SafetyRecordOwner) -> usize {
    match owner.backend_for_test().prepared_registry_for_test() {
        Some(reg) => reg.lock().unwrap().occupied(),
        None => 0,
    }
}

// ===========================================================================
// Consensus helpers (mirrors of the gate/observer spike helpers)
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

/// Single-validator engine locked at view 0, advanced to view 1, with a safe
/// view-1 proposal that self-votes when admitted.
fn engine_and_safe_view1_proposal() -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal) {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId::new(1), engine_validator_set(1));
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let a0 = engine.on_proposal_event(ValidatorId::new(1), &p0);
    assert!(matches!(a0, Some(ConsensusEngineAction::BroadcastVote(_))));
    let l0_block = engine.locked_qc().expect("L0").block_id;
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));
    (engine, p1)
}

// ===========================================================================
// 1. Same-invocation ownership: the pin is captured in-gate and the returned
//    envelope owns a live pin whose registry entry is occupied; abandonment
//    frees the slot and releases every charge.
// ===========================================================================

#[test]
fn same_invocation_ownership_captures_pin_in_gate() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // -> revision 1
    let baseline = op_current(&owner);

    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let mut gate = NodeCapturingGate::new(&owner, proof, 1);

    let decided = engine
        .on_proposal_event_gated_owning(ValidatorId::new(1), &p1, &mut gate)
        .expect("allowing owning gate yields Ok")
        .expect("safe proposal yields a decided vote");

    // Captured within THIS gate call; L0 observed before the self-vote raised L1.
    assert_eq!(gate.calls, 1, "gate consulted exactly once");
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote raised L1");

    // The returned envelope owns a live pin: exactly one registry slot occupied.
    assert_eq!(registry_occupied(&owner), 1, "the envelope owns one live pin");
    assert!(
        op_current(&owner) > baseline,
        "the admitted pin + extra reservation are charged while owned"
    );
    // The envelope carries the engine's own self-vote (read-only).
    assert_eq!(decided.vote().height, 1);
    assert_eq!(
        decided.vote().signature.capacity(),
        0,
        "the carried vote is the existing unsigned self-vote"
    );

    // Abandonment destroys the pin (frees the slot) then releases the extra
    // reservation; the pin, generation, and extra charges are released. The
    // lazily installed registry cell persists (a standing per-backend charge).
    drop(decided);
    assert_eq!(registry_occupied(&owner), 0, "abandoning frees the slot");
    assert_eq!(
        op_current(&owner),
        baseline + registry_cell_charge_bytes(),
        "pin + generation + extra released; only the standing registry cell remains"
    );
}

// ===========================================================================
// 2. Two-slot exhaustion shared by ordinary pins and envelopes: a handoff takes
//    one of the two existing slots; a further capture hits RegistryFull with the
//    proof returned intact.
// ===========================================================================

#[test]
fn envelope_shares_the_two_existing_prepared_slots() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // -> revision 1

    // One ordinary outstanding pin takes the FIRST slot.
    let proof_a = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let _ordinary = owner
        .capture_prepared_decision(proof_a, 1)
        .expect("ordinary capture takes slot 1");
    assert_eq!(registry_occupied(&owner), 1);

    // A handoff capture takes the SECOND (last) slot through the envelope path.
    let proof_b = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let mut gate = NodeCapturingGate::new(&owner, proof_b, 1);
    let _decided = engine
        .on_proposal_event_gated_owning(ValidatorId::new(1), &p1, &mut gate)
        .expect("owning gate Ok")
        .expect("handoff takes slot 2");
    assert_eq!(gate.calls, 1);
    assert_eq!(registry_occupied(&owner), 2, "both existing slots now occupied");

    // A further capture (ordinary here) refuses with RegistryFull, proof intact —
    // the envelope added no new multiplicity.
    let proof_c = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    match owner.capture_prepared_decision(proof_c, 1) {
        Err((_proof, CaptureRefusal::RegistryFull)) => {}
        other => panic!("expected RegistryFull with proof returned, got {other:?}"),
    }
    assert_eq!(registry_occupied(&owner), 2, "refusal consumed no slot");
}

// ===========================================================================
// 3. Refusal cleanup: a forced capture refusal releases the extra reservation
//    and returns the proof intact (it captures successfully afterward); no
//    self-vote, no lock transition.
// ===========================================================================

#[test]
fn capture_refusal_releases_extra_reservation_and_keeps_proof_intact() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // -> revision 1

    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    // `pre_eval` includes the proof's own standing charge but NOT the extra.
    let pre_eval = op_current(&owner);

    let (mut engine, p1) = engine_and_safe_view1_proposal();
    // Force a StaleRevision refusal by expecting a wrong authoritative revision.
    let mut gate = NodeCapturingGate::new(&owner, proof, 999);

    let refusal = match engine.on_proposal_event_gated_owning(ValidatorId::new(1), &p1, &mut gate) {
        Err(r) => r,
        Ok(_) => panic!("a capture refusal must surface as Err, not a decided vote"),
    };
    assert_eq!(gate.calls, 1);
    assert_eq!(refusal, GatedSelfVoteRefusal::GateRejected(SafetyGateRefusal));
    assert!(
        matches!(gate.last_refusal, Some(CaptureRefusal::StaleRevision { .. })),
        "the underlying capture refusal was StaleRevision, got {:?}",
        gate.last_refusal
    );

    // The extra reservation was released; the proof's standing charge is retained.
    assert_eq!(
        op_current(&owner),
        pre_eval,
        "the extra reservation was released on the refusal path"
    );
    // No self-vote / lock transition occurred (still at L0 = view 0).
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(0));
    assert_eq!(registry_occupied(&owner), 0, "no slot consumed on refusal");

    // The returned proof is intact: capturing it with the correct revision now
    // succeeds.
    let proof = gate.returned_proof.take().expect("proof returned intact");
    let _pin = owner
        .capture_prepared_decision(proof, 1)
        .expect("the returned proof captures with the correct revision");
    assert_eq!(registry_occupied(&owner), 1);
}

// ===========================================================================
// 4. No double charge: the embedded pin is covered by its own reservation; the
//    extra charge is exactly the envelope minus the pin, and the admitted total
//    equals an ordinary capture's charges plus the extra (pin counted once).
// ===========================================================================

#[test]
fn embedded_pin_is_not_charged_twice() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // -> revision 1
    let baseline = op_current(&owner);
    assert_eq!(baseline, 0, "no live operational holders at baseline");

    // The exact per-object charges for this generation.
    let proof_ref = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let core = prepared_generation_charge(&ctx, proof_ref.retained()).unwrap();
    let control = prepared_holder_control_charge(generation_backing_struct_size_bytes()).unwrap();
    let registry = registry_cell_charge_bytes();
    let pin = pin_charge_bytes();

    // Reference: an ORDINARY capture of the generation (no envelope/extra).
    let pin_ref = owner
        .capture_prepared_decision(proof_ref, 1)
        .expect("ordinary reference capture");
    let ordinary_op = op_current(&owner);
    assert_eq!(
        ordinary_op,
        core + control + registry + pin,
        "ordinary capture charges exactly core + control + registry + pin"
    );
    drop(pin_ref);
    // The registry cell is a standing per-backend charge and persists.
    assert_eq!(
        op_current(&owner),
        registry,
        "only the standing registry cell remains after the reference pin drops"
    );
    assert_eq!(registry_occupied(&owner), 0);

    // The disjoint-coverage charge: envelope total minus the embedded pin.
    let extra_charge = extra_charge_bytes();
    assert_eq!(
        extra_charge,
        (size_of::<DecidedVote<HandoffPayload>>() - size_of::<PreparedPin>()) as u128,
        "extra_charge is the envelope minus the embedded pin"
    );

    // A handoff capture of an EQUAL generation.
    let proof_h = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let mut gate = NodeCapturingGate::new(&owner, proof_h, 1);
    let decided = engine
        .on_proposal_event_gated_owning(ValidatorId::new(1), &p1, &mut gate)
        .expect("owning gate Ok")
        .expect("handoff decided");
    let handoff_op = op_current(&owner);

    // The embedded pin contributes exactly ONCE: the handoff total is the
    // ordinary capture's charges plus the disjoint extra, not the pin doubled.
    assert_eq!(
        handoff_op,
        core + control + registry + pin + extra_charge,
        "handoff total = core + control + registry + pin + extra"
    );
    assert_eq!(
        handoff_op,
        ordinary_op + extra_charge,
        "operational total = ordinary pin charges + extra (pin counted once)"
    );

    drop(decided);
    assert_eq!(
        op_current(&owner),
        registry,
        "pin + generation + extra released; only the standing registry cell remains"
    );
}

// ===========================================================================
// 5. Extra-byte reservation exhausted BEFORE capture: the in-gate extra
//    reservation (taken first, fail-fast) is driven to refuse by standing
//    pressure, so the capture API is never reached. There is no capture, no
//    envelope, and no dependent self-vote; the operational and aggregate charges
//    return to their pre-attempt values; removing the pressure and retrying the
//    SAME proposal votes successfully — the vote opportunity was preserved. The
//    temporary pressure charge is kept distinct from the intentionally retained
//    standing registry charge.
// ===========================================================================

#[test]
fn extra_reservation_exhaustion_before_capture_preserves_vote_opportunity() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // -> revision 1

    // Baseline BEFORE the proof is read: no live operational holders. The proof's
    // standing charge is released when the retry capture consumes it, so the final
    // post-abandonment total is measured against this proof-free baseline.
    let baseline = op_current(&owner);

    // The proof is held by the gate; the extra-reservation refusal returns it
    // intact (the capture API is never reached), so it stays available for retry.
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let extra = extra_charge_bytes();

    // Compute the headroom under the TIGHTER of the operational sub-ledger and
    // the shared aggregate ceilings (the in-gate `reserve` must satisfy both),
    // then reserve standing pressure that leaves strictly `extra - 1` bytes — so
    // the gate's first-step extra reservation of `extra` bytes cannot fit.
    let backend = owner.backend_for_test();
    let op_headroom = backend.accounting_cap().expect("operational ceiling bound")
        - backend.accounting_current();
    let agg_headroom = backend
        .accounting_aggregate_cap()
        .expect("aggregate ceiling bound")
        - backend.accounting_aggregate_current();
    let headroom = op_headroom.min(agg_headroom);
    assert!(
        headroom >= extra,
        "fixture must start with room for the extra charge (headroom {headroom}, extra {extra})"
    );
    let pressure = backend
        .reserve_standing_for_test(headroom - (extra - 1))
        .expect("pressure reservation fits under both ceilings");

    // Pre-attempt snapshot (pressure applied, proof held): both running totals.
    let pre_op = op_current(&owner);
    let pre_agg = backend.accounting_aggregate_current();
    assert_eq!(registry_occupied(&owner), 0, "no capture yet");

    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let mut gate = NodeCapturingGate::new(&owner, proof, 1);

    // The in-gate extra reservation cannot fit => refusal strictly before any
    // capture.
    let refusal = match engine.on_proposal_event_gated_owning(ValidatorId::new(1), &p1, &mut gate) {
        Err(r) => r,
        Ok(_) => panic!("extra-reservation exhaustion must surface as Err, not a decided vote"),
    };
    assert_eq!(gate.calls, 1, "gate consulted exactly once");
    assert_eq!(refusal, GatedSelfVoteRefusal::GateRejected(SafetyGateRefusal));

    // No capture, no envelope, no dependent self-vote. The capture API was never
    // even reached, so no registry cell was installed and the proof was never
    // taken from the gate (no capture refusal was recorded).
    assert_eq!(registry_occupied(&owner), 0, "the exhausted attempt captured nothing");
    assert!(
        backend.prepared_registry_for_test().is_none(),
        "no registry installed: capture never ran"
    );
    assert!(
        gate.last_refusal.is_none(),
        "capture was never attempted (the extra reservation refused first)"
    );
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote => lock stays at L0");
    assert_eq!(engine.current_view(), 1, "view unchanged by the refusal");

    // Operational and aggregate charges returned to their pre-attempt values: the
    // failed extra reservation disturbed neither running total.
    assert_eq!(
        op_current(&owner),
        pre_op,
        "operational charge returned to its pre-attempt value"
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        pre_agg,
        "aggregate charge returned to its pre-attempt value"
    );

    // Remove the (temporary) pressure and retry the SAME proposal with the SAME
    // gate (its proof is still held): the opportunity was preserved, so the retry
    // captures and self-votes.
    drop(pressure);
    let retry = engine
        .on_proposal_event_gated_owning(ValidatorId::new(1), &p1, &mut gate)
        .expect("retry is admissible once pressure is removed")
        .expect("retry yields a decided vote");
    assert_eq!(gate.calls, 2, "gate consulted again on the retry");
    assert_eq!(retry.vote().height, 1, "the retry carries the view-1 self-vote");
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(1),
        "the retry self-vote raised the lock to L1 (view 1)"
    );
    assert_eq!(registry_occupied(&owner), 1, "the retry owns one live pin");

    // Abandonment releases the pin + generation + extra (the temporary charges);
    // only the intentionally retained standing registry cell — installed by the
    // successful retry capture — remains, distinct from the released pressure.
    drop(retry);
    assert_eq!(registry_occupied(&owner), 0, "abandoning frees the slot");
    assert_eq!(
        op_current(&owner),
        baseline + registry_cell_charge_bytes(),
        "only the standing registry cell remains; all temporary charges released"
    );
}