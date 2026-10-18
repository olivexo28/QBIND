//! Run 422 §13.6 — focused evidence for the two read-only `SafetyDecisionView`
//! queries added as consensus-side correspondence prerequisites:
//!
//! - [`SafetyDecisionView::candidate_justify_block_id`] — the borrowed
//!   justification block id read directly from the candidate's own logical
//!   justification;
//! - [`SafetyDecisionView::ancestry_relation_to_lock`] — a bounded, typed
//!   classification of the candidate↔lock parent relationship.
//!
//! The cases in THIS file are driven through the ACTUAL engine control flow
//! ([`BasicHotStuffEngine::on_proposal_event_observed`]): the view they inspect
//! is the one the engine built at the instant it decided it was safe to vote,
//! under the L0 lock, before the same-event self-vote raised L1. They establish:
//!
//! - the justification id is present/absent exactly as the candidate carries a
//!   justification;
//! - a `ViewSufficiency` decision (whose predicate short-circuited and walked NO
//!   ancestry) can still be *inspected* for its parent relationship — reaching
//!   the lock directly, running off a missing parent link, or off an absent
//!   referenced block — WITHOUT forcing the predicate into an ancestry walk;
//! - the explicit no-lock result on the `NoLock` boundary;
//! - inspecting the view changes neither the emitted `Vote` nor the resulting
//!   engine state (parity against an un-observed run).
//!
//! Graph shapes the natural engine control flow does not produce
//! (candidate-is-lock, deep multi-hop under a pinned older lock, and bounded
//! termination on a cyclic parent graph) are covered by CONSTRUCTED internal
//! fixtures in the in-crate unit tests of `basic_hotstuff_engine.rs`; those are
//! labeled there as constructed fixtures, not executed engine decisions.
//!
//! What this does NOT establish (per the brief): any engine↔durable-record
//! correspondence, owner session, bound capture, or binding accounting. These
//! are read-only inspection interfaces only.

use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{
    AncestryRelation, BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet,
    SafetyBranch, SafetyDecisionObserver, SafetyDecisionView, ValidatorId,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc};

// ===========================================================================
// Helpers (mirrors of the sibling observer-spike test helpers).
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

/// A minimal logical (legacy) wire QC referencing `block_id` at `height`. Only
/// `block_id` and `height` are read by the legacy ingestion path.
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

/// Observer that records, from the ACTUAL engine-built view, the outputs of the
/// two new read-only queries. It copies scalars/ids only; it retains no borrow
/// and clones no certificate.
#[derive(Default)]
struct Recording {
    calls: usize,
    branch: Option<SafetyBranch>,
    candidate_id: Option<[u8; 32]>,
    locked_block_id: Option<[u8; 32]>,
    justify_block_id: Option<[u8; 32]>,
    /// `ancestry_relation_to_lock(h)` for `h` in `0..=5` (index == bound).
    relations: Vec<AncestryRelation>,
}

impl SafetyDecisionObserver<[u8; 32]> for Recording {
    fn observe(&mut self, d: &SafetyDecisionView<'_, [u8; 32]>) {
        self.calls += 1;
        self.branch = Some(d.branch());
        self.candidate_id = Some(*d.candidate_id());
        self.locked_block_id = d.locked_block_id().copied();
        self.justify_block_id = d.candidate_justify_block_id().copied();
        self.relations = (0..=5).map(|h| d.ancestry_relation_to_lock(h)).collect();
    }
}

/// Drive a single-validator engine through one accepted view-0 proposal so its
/// self-vote forms a QC and establishes the lock L0 (= the view-0 block).
/// Returns the engine and the locked (L0) block id.
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

// ===========================================================================
// 1. No lock, no justification: justify id absent; relation is NoLock.
//    (Executed engine decision: the view-0 NoLock boundary.)
// ===========================================================================

#[test]
fn no_lock_boundary_reports_no_justify_id_and_no_lock_relation() {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validator_set(1));

    // View-0 proposal: no justification QC, and no lock is in effect yet.
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p0, &mut rec);

    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "view-0 proposal self-votes under NoLock"
    );
    assert_eq!(rec.calls, 1);
    assert_eq!(rec.branch, Some(SafetyBranch::NoLock));
    // Justification id is absent because the candidate carries no justification.
    assert_eq!(rec.justify_block_id, None);
    // With no lock in effect, every bound yields the explicit NoLock outcome.
    for (bound, rel) in rec.relations.iter().enumerate() {
        assert_eq!(
            *rel,
            AncestryRelation::NoLock,
            "bound {bound} must report NoLock when no lock is in effect"
        );
    }
}

// ===========================================================================
// 2. ViewSufficiency decision inspected for DIRECT ancestry to the lock.
//    Justify id present. Exact-bound success at hop 1; zero-bound exhaustion.
//    (Executed engine decision; the predicate short-circuited, yet the OPTIONAL
//     query still walks the parent link.)
// ===========================================================================

#[test]
fn view_sufficiency_direct_ancestry_and_justify_id_present() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);

    // View-1 proposal whose parent IS the lock block and whose justify view
    // (0) >= locked view (0) => ViewSufficiency (ancestry NOT walked by the
    // predicate).
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);

    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "view-1 proposal is safe and self-votes"
    );
    assert_eq!(rec.calls, 1);
    assert_eq!(rec.branch, Some(SafetyBranch::ViewSufficiency));
    // Justification id is present and equals the referenced (lock) block.
    assert_eq!(rec.justify_block_id, Some(l0_block));
    assert_eq!(rec.locked_block_id, Some(l0_block));

    // The candidate is not the lock, so zero hops exhausts the bound...
    assert_eq!(rec.relations[0], AncestryRelation::BoundExhausted);
    // ...and exactly one parent transition reaches the lock (exact-bound
    // success), as does any larger bound.
    assert_eq!(rec.relations[1], AncestryRelation::ReachedLock { hops: 1 });
    assert_eq!(rec.relations[2], AncestryRelation::ReachedLock { hops: 1 });
    assert_eq!(rec.relations[5], AncestryRelation::ReachedLock { hops: 1 });
}

// ===========================================================================
// 3. ViewSufficiency decision whose candidate references an ABSENT parent
//    block: inspection reports ParentAbsent (never "reached lock").
// ===========================================================================

#[test]
fn view_sufficiency_inspection_reports_absent_parent_block() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // Parent id is a real (non-sentinel) id that was never registered. Justify
    // view sufficiency admits the vote without an ancestry walk.
    let unregistered_parent = [0x22u8; 32];
    assert_ne!(unregistered_parent, l0_block);
    let mut p1 = make_proposal(1, unregistered_parent, 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);
    assert!(matches!(
        action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
    assert_eq!(rec.branch, Some(SafetyBranch::ViewSufficiency));
    // Candidate != lock; its parent is referenced but absent from the engine.
    assert_eq!(rec.relations[0], AncestryRelation::BoundExhausted);
    for bound in 1..=5usize {
        assert_eq!(
            rec.relations[bound],
            AncestryRelation::ParentAbsent,
            "bound {bound}: an absent referenced parent must not be proved ancestry"
        );
    }
}

// ===========================================================================
// 4. ViewSufficiency decision whose candidate has NO parent link (sentinel):
//    inspection reports NoParentLink (never "reached lock").
// ===========================================================================

#[test]
fn view_sufficiency_inspection_reports_missing_parent_link() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // Sentinel parent => the candidate node has parent_id == None.
    let mut p1 = make_proposal(1, [0xFF; 32], 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);
    assert!(matches!(
        action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
    assert_eq!(rec.branch, Some(SafetyBranch::ViewSufficiency));
    // Candidate != lock and has no parent link to follow.
    assert_eq!(rec.relations[0], AncestryRelation::BoundExhausted);
    for bound in 1..=5usize {
        assert_eq!(
            rec.relations[bound],
            AncestryRelation::NoParentLink,
            "bound {bound}: a missing parent link must not be proved ancestry"
        );
    }
}

// ===========================================================================
// 5. Inspecting the view changes neither the emitted Vote nor the engine state.
//    Parity: an observed run equals an un-observed run.
// ===========================================================================

#[test]
fn inspection_does_not_alter_vote_or_engine_state() {
    // Observed run.
    let (mut observed, l0_block) = engine_locked_at_view0();
    observed.advance_view();
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));
    let mut rec = Recording::default();
    let observed_action = observed.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);
    assert_eq!(rec.calls, 1, "the view was actually inspected");

    // Un-observed run from identical setup.
    let (mut plain, l0_block2) = engine_locked_at_view0();
    plain.advance_view();
    assert_eq!(l0_block, l0_block2, "identical setup");
    let mut p1b = make_proposal(1, l0_block2, 1);
    p1b.qc = Some(logical_qc(l0_block2, 0));
    let plain_action = plain.on_proposal_event(ValidatorId(1), &p1b);

    // Same emitted action (a self-vote in both).
    assert!(matches!(
        observed_action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
    assert!(matches!(
        plain_action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));

    // Same resulting lock state (the same-event self-vote raised L1 identically).
    let o_lock = observed.locked_qc().expect("lock after vote");
    let p_lock = plain.locked_qc().expect("lock after vote");
    assert_eq!(o_lock.view, p_lock.view);
    assert_eq!(o_lock.block_id, p_lock.block_id);
    assert_eq!(observed.current_view(), plain.current_view());
}
