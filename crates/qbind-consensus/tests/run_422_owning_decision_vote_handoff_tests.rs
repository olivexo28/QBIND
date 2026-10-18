//! Run 422 §13.6 — real-engine evidence for the isolated, opt-in **owning**
//! decision-to-vote handoff
//! ([`BasicHotStuffEngine::on_proposal_event_gated_owning`] +
//! [`OwningSafetyDecisionGate`] + the closed [`DecidedVote`] envelope).
//!
//! These tests drive the ACTUAL engine control flow (not a test-authored
//! consumer model) to establish that:
//!
//! - an ALLOWING owning gate produces its opaque payload **inside** the gate
//!   call — at the real safe-voting decision, with the lock in effect (L0)
//!   before the same-event self-vote raises it (L1) — and the engine returns a
//!   closed [`DecidedVote`] that owns both the emitted `Vote` and that payload;
//! - the carried `Vote` is **field-for-field identical** to the one the
//!   non-owning gated route emits for the same proposal, with `signature`
//!   capacity 0 (the existing unsigned self-vote);
//! - a REFUSING owning gate yields `Err`, casts no self-vote, drives no lock
//!   transition, and produces **no payload** at all;
//! - **abandoning** (dropping) an un-consumed `DecidedVote` destroys the
//!   payload's covered data **before** the reservation the payload declares
//!   last — the declaration-order drop discipline the node-side pin/reservation
//!   relies on; the reversed field order would release the reservation first.
//!
//! What this does NOT establish (per the brief): any node-side binder, durable
//! correspondence, production caller, signing integration, or the D10
//! prerequisite. The handoff establishes **same-invocation ownership/association
//! only** — no authorization, correspondence, verification, or permission to
//! sign. Accepted storage stays CLOSED; §13.6 correspondence remains
//! INCOMPLETE; activation DISABLED; public DevNet NO-GO.

use std::sync::{Arc, Mutex};

use qbind_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet, GatedSelfVoteRefusal,
    OwningSafetyDecisionGate, SafetyBranch, SafetyDecisionView, SafetyGateRefusal, ValidatorId,
};
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc};

// ===========================================================================
// Helpers (mirrors of the gate spike's helpers)
// ===========================================================================

fn validator_set(num: u64) -> ConsensusValidatorSet {
    let entries = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
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

fn logical_qc(block_id: [u8; 32], height: u64) -> WireQc {
    WireQc {
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

/// Drive a single-validator engine through one accepted proposal at view 0 so
/// its self-vote forms a QC and establishes the lock L0 (the view-0 block).
fn engine_locked_at_view0() -> (BasicHotStuffEngine<[u8; 32]>, [u8; 32]) {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validator_set(1));
    assert!(engine.locked_qc().is_none(), "no lock initially");

    let p0 = make_proposal(0, [0xFF; 32], 1);
    let action = engine.on_proposal_event(ValidatorId(1), &p0);
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "view-0 self-vote should broadcast"
    );
    let locked = engine
        .locked_qc()
        .expect("lock L0 established by self-vote");
    assert_eq!(locked.view, 0, "L0 is the view-0 block");
    let l0_block = locked.block_id;
    (engine, l0_block)
}

/// Prepare a single-validator engine locked at view 0 and advanced to view 1,
/// together with a safe view-1 proposal that will self-vote when admitted.
fn engine_and_safe_view1_proposal() -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal) {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));
    (engine, p1)
}

// ===========================================================================
// Drop-logging test payload
// ===========================================================================

type DropLog = Arc<Mutex<Vec<&'static str>>>;

/// A token that records its own destruction into a shared ordered log.
struct DropMarker {
    tag: &'static str,
    log: DropLog,
}

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.log.lock().unwrap().push(self.tag);
    }
}

/// Test analogue of the node-side `HandoffPayload`: covered data declared
/// FIRST, the "reservation" declared LAST so it releases only after the data it
/// covers is destroyed (mirrors `PreparedPin` then `extra_reservation`).
#[allow(dead_code)] // fields exist solely for their ordered Drop
struct TestHandoff {
    /// Stands in for the covered pin/data; declared first => dropped first.
    covered: DropMarker,
    /// Stands in for the trailing reservation; declared last => dropped last.
    reservation: DropMarker,
}

/// Deliberately WRONG field order (reservation before covered data): used to
/// show the ordered log would release the reservation BEFORE the data it covers
/// — the failure mode the chosen declaration order avoids.
#[allow(dead_code)] // fields exist solely for their ordered Drop
struct WrongOrderHandoff {
    reservation: DropMarker,
    covered: DropMarker,
}

// ===========================================================================
// Owning gate under test
// ===========================================================================

/// An owning gate that, on allow, produces a `TestHandoff` whose tokens log
/// their destruction order, and records the decision scalars it was handed. It
/// never panics; a refusal is an `Err`, and on refusal it produces NO payload.
struct OwningTestGate {
    reject: bool,
    log: DropLog,
    calls: usize,
    branch: Option<SafetyBranch>,
    locked_view: Option<u64>,
    locked_block_id: Option<[u8; 32]>,
    candidate_view: Option<u64>,
    origin_view: Option<u64>,
}

impl OwningTestGate {
    fn allowing(log: DropLog) -> Self {
        Self {
            reject: false,
            log,
            calls: 0,
            branch: None,
            locked_view: None,
            locked_block_id: None,
            candidate_view: None,
            origin_view: None,
        }
    }
    fn rejecting(log: DropLog) -> Self {
        Self {
            reject: true,
            ..Self::allowing(log)
        }
    }
}

impl OwningSafetyDecisionGate<[u8; 32], TestHandoff> for OwningTestGate {
    fn evaluate_owning(
        &mut self,
        d: &SafetyDecisionView<'_, [u8; 32]>,
    ) -> Result<TestHandoff, SafetyGateRefusal> {
        self.calls += 1;
        self.branch = Some(d.branch());
        self.locked_view = d.locked_view();
        self.locked_block_id = d.locked_block_id().copied();
        self.candidate_view = Some(d.candidate_view());
        self.origin_view = Some(d.origin_view());
        if self.reject {
            // Refusal: produce NO payload (the `?`-less early return means no
            // `TestHandoff` tokens are ever constructed).
            return Err(SafetyGateRefusal);
        }
        Ok(TestHandoff {
            covered: DropMarker {
                tag: "covered",
                log: Arc::clone(&self.log),
            },
            reservation: DropMarker {
                tag: "reservation",
                log: Arc::clone(&self.log),
            },
        })
    }
}

// ===========================================================================
// 1. Same-invocation ownership: the payload is produced inside the gate call,
//    at L0 before the self-vote raises L1, and the engine returns a live
//    envelope owning both the Vote and the payload.
// ===========================================================================

#[test]
fn same_invocation_ownership_sees_l0_before_self_vote_raises_l1() {
    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let log: DropLog = Arc::new(Mutex::new(Vec::new()));
    let mut gate = OwningTestGate::allowing(Arc::clone(&log));

    let decided = engine
        .on_proposal_event_gated_owning(ValidatorId(1), &p1, &mut gate)
        .expect("allowing owning gate yields Ok")
        .expect("a safe proposal yields a decided vote");

    // Produced within THIS gate call.
    assert_eq!(gate.calls, 1, "owning gate consulted exactly once");
    // The gate observed the L0 lock (view 0), NOT the L1 the self-vote formed.
    assert_eq!(gate.locked_view, Some(0), "gate saw L0 (view 0)");
    assert_eq!(gate.branch, Some(SafetyBranch::ViewSufficiency));
    assert_eq!(gate.candidate_view, Some(1));
    assert_eq!(gate.origin_view, Some(1));

    // The envelope owns a live payload: nothing has dropped yet.
    assert!(
        log.lock().unwrap().is_empty(),
        "the payload is still owned/live inside the returned envelope"
    );
    // The envelope exposes its own emitted self-vote (read-only).
    assert_eq!(decided.vote().height, 1, "envelope carries the view-1 vote");

    // Post-decision the engine has already been raised to L1 (view 1): reading
    // the lock AFTER the event could not have established L0.
    let post = engine.locked_qc().expect("lock present after self-vote");
    assert_eq!(post.view, 1, "self-vote raised the lock to L1 (view 1)");

    // Dropping the envelope now releases the owned payload.
    drop(decided);
    assert_eq!(
        *log.lock().unwrap(),
        vec!["covered", "reservation"],
        "abandoning the envelope destroys the payload"
    );
}

// ===========================================================================
// 2. Complete Vote association: the carried Vote equals field-for-field the
//    Vote the non-owning gated route emits for the same proposal.
// ===========================================================================

#[test]
fn carried_vote_matches_non_owning_route_field_for_field() {
    // Non-owning gated route (allowing) over identical inputs.
    let (mut plain, p_plain) = engine_and_safe_view1_proposal();
    let mut plain_gate = AllowPlainGate::default();
    let plain_vote = match plain
        .on_proposal_event_gated(ValidatorId(1), &p_plain, &mut plain_gate)
        .expect("allowing gate yields Ok")
    {
        Some(ConsensusEngineAction::BroadcastVote(v)) => v,
        other => panic!("expected BroadcastVote, got {other:?}"),
    };

    // Owning route over identical inputs.
    let (mut owning, p_owning) = engine_and_safe_view1_proposal();
    let log: DropLog = Arc::new(Mutex::new(Vec::new()));
    let mut owning_gate = OwningTestGate::allowing(log);
    let decided = owning
        .on_proposal_event_gated_owning(ValidatorId(1), &p_owning, &mut owning_gate)
        .expect("allowing owning gate yields Ok")
        .expect("safe proposal yields a decided vote");

    assert_eq!(
        decided.vote(),
        &plain_vote,
        "the owning route changes no field of the emitted Vote"
    );
    assert_eq!(
        decided.vote().signature.capacity(),
        0,
        "the carried vote is the existing unsigned self-vote (signature capacity 0)"
    );
}

/// A plain allowing gate for the non-owning comparison route.
#[derive(Default)]
struct AllowPlainGate;
impl qbind_consensus::SafetyDecisionGate<[u8; 32]> for AllowPlainGate {
    fn evaluate(&mut self, _d: &SafetyDecisionView<'_, [u8; 32]>) -> Result<(), SafetyGateRefusal> {
        Ok(())
    }
}

// ===========================================================================
// 3. Refusal: no self-vote, no lock transition, and NO payload produced.
// ===========================================================================

#[test]
fn owning_refusal_casts_no_vote_and_produces_no_payload() {
    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let log: DropLog = Arc::new(Mutex::new(Vec::new()));
    let mut reject = OwningTestGate::rejecting(Arc::clone(&log));

    let refusal = match engine.on_proposal_event_gated_owning(ValidatorId(1), &p1, &mut reject) {
        Err(r) => r,
        Ok(_) => panic!("refusing owning gate must yield Err, not a decided vote"),
    };
    assert_eq!(reject.calls, 1, "gate consulted exactly once");
    assert_eq!(
        refusal,
        GatedSelfVoteRefusal::GateRejected(SafetyGateRefusal)
    );
    assert_eq!(
        reject.branch,
        Some(SafetyBranch::ViewSufficiency),
        "gate saw the branch that actually decided safety"
    );

    // No payload was ever constructed (nothing dropped because nothing built).
    assert!(
        log.lock().unwrap().is_empty(),
        "a refusing gate produces no payload tokens at all"
    );
    // No vote-derived mutation: the lock stays at L0 (view 0).
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "refusal casts no vote => lock unchanged at L0"
    );
    assert_eq!(engine.current_view(), 1, "view unchanged by the refusal");

    // The refusal did NOT consume the vote opportunity: an admissible retry
    // (same view, now allowing) still votes and yields a payload.
    let mut allow = OwningTestGate::allowing(Arc::clone(&log));
    let retry = engine
        .on_proposal_event_gated_owning(ValidatorId(1), &p1, &mut allow)
        .expect("retry is admissible")
        .expect("retry yields a decided vote");
    assert_eq!(retry.vote().height, 1);
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(1),
        "the retry self-vote raised the lock to L1 (view 1)"
    );
}

// ===========================================================================
// 4. Ordinary pre-decision rejection: the gate is never consulted, so there is
//    neither a payload nor a vote (Ok(None)).
// ===========================================================================

#[test]
fn ordinary_rejection_returns_none_without_consulting_owning_gate() {
    // A fresh engine at view 0 that has ALREADY voted: a second proposal for
    // the same view is an ordinary rejection reached before the decision.
    let (mut engine, _l0) = engine_locked_at_view0();
    let log: DropLog = Arc::new(Mutex::new(Vec::new()));
    let mut gate = OwningTestGate::allowing(Arc::clone(&log));

    // Re-submit a view-0 proposal: engine already voted in view 0.
    let p0b = make_proposal(0, [0xAB; 32], 1);
    let result = engine
        .on_proposal_event_gated_owning(ValidatorId(1), &p0b, &mut gate)
        .expect("ordinary rejection is Ok(None), not an Err");
    assert!(result.is_none(), "no decided vote for an ordinary rejection");
    assert_eq!(gate.calls, 0, "owning gate not consulted before the decision");
    assert!(
        log.lock().unwrap().is_empty(),
        "no payload produced for an ordinary rejection"
    );
}

// ===========================================================================
// 5. Abandonment / destruction order: dropping an un-consumed envelope destroys
//    covered data BEFORE the trailing reservation; the reversed field order
//    would release the reservation first.
// ===========================================================================

#[test]
fn abandoning_envelope_destroys_covered_data_before_reservation() {
    let (mut engine, p1) = engine_and_safe_view1_proposal();
    let log: DropLog = Arc::new(Mutex::new(Vec::new()));
    let mut gate = OwningTestGate::allowing(Arc::clone(&log));

    let decided = engine
        .on_proposal_event_gated_owning(ValidatorId(1), &p1, &mut gate)
        .expect("allowing owning gate yields Ok")
        .expect("safe proposal yields a decided vote");

    // Abandon without consuming.
    drop(decided);

    assert_eq!(
        *log.lock().unwrap(),
        vec!["covered", "reservation"],
        "covered data is destroyed before the trailing reservation releases"
    );
}

#[test]
fn reversed_field_order_would_release_reservation_first() {
    // This documents the failure mode the chosen `TestHandoff`/`HandoffPayload`
    // field order avoids: declaring the reservation first drops it BEFORE the
    // data it covers.
    let log: DropLog = Arc::new(Mutex::new(Vec::new()));
    let wrong = WrongOrderHandoff {
        reservation: DropMarker {
            tag: "reservation",
            log: Arc::clone(&log),
        },
        covered: DropMarker {
            tag: "covered",
            log: Arc::clone(&log),
        },
    };
    drop(wrong);
    assert_eq!(
        *log.lock().unwrap(),
        vec!["reservation", "covered"],
        "reversed field order wrongly releases the reservation before the data"
    );
}
