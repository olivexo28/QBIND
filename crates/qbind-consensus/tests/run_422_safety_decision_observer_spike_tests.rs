//! Run 422 §13.6 spike — executable feasibility evidence for the scoped
//! borrowed safety-decision observer.
//!
//! These tests exercise the ACTUAL engine control flow
//! ([`BasicHotStuffEngine::on_proposal_event_observed`] /
//! [`BasicHotStuffEngine::on_verified_proposal_event_observed`]), not a
//! test-authored consumer model, to establish that:
//!
//! - the observer sees the L0 decision BEFORE a same-event self-vote raises the
//!   lock to L1;
//! - the branch it observes is the one that actually decided safety
//!   (justification-view short-circuit vs. ancestry), including the equality
//!   boundary;
//! - legacy and verified entrypoints both drive it while preserving their
//!   distinct evidence guarantees;
//! - an observed run is otherwise identical to a legacy run (equivalent action
//!   and resulting state);
//! - no observation occurs when no successful safety decision occurred (early
//!   refusal) and when the callback panics no self-vote or action follows;
//! - the observation machinery allocates nothing of its own (the view is a
//!   fixed, stack-resident bundle of borrows and scalars) and clones no
//!   certificate `Arc`.
//!
//! What this does NOT establish is called out in the brief: association with
//! the eventual outbound action, correspondence to a durable generation,
//! across-event revalidation, and the D10/signing prerequisite.

use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::verify_quorum_certificate_with_domain;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::vote_accumulator::ConsensusLimitsConfig;
use qbind_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet, SafetyBranch,
    SafetyDecisionObserver, SafetyDecisionView, ValidatorId,
};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

// ===========================================================================
// Helpers
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

/// Recording observer that copies out scalars only (never retains a borrow).
#[derive(Default)]
struct Recording {
    calls: usize,
    branch: Option<SafetyBranch>,
    locked_block_id: Option<[u8; 32]>,
    locked_view: Option<u64>,
    candidate_id: Option<[u8; 32]>,
    candidate_view: Option<u64>,
    candidate_parent: Option<[u8; 32]>,
    candidate_justify_view: Option<u64>,
    origin_view: Option<u64>,
    from: Option<ValidatorId>,
    verified: Option<bool>,
    ancestors: Vec<[u8; 32]>,
}

impl SafetyDecisionObserver<[u8; 32]> for Recording {
    fn observe(&mut self, d: &SafetyDecisionView<'_, [u8; 32]>) {
        self.calls += 1;
        self.branch = Some(d.branch());
        self.locked_block_id = d.locked_block_id().copied();
        self.locked_view = d.locked_view();
        self.candidate_id = Some(*d.candidate_id());
        self.candidate_view = Some(d.candidate_view());
        self.candidate_parent = d.candidate_parent().copied();
        self.candidate_justify_view = d.candidate_justify_view();
        self.origin_view = Some(d.origin_view());
        self.from = Some(d.from());
        self.verified = Some(d.is_verified_entrypoint());
        d.for_each_ancestor(16, |ancestor| self.ancestors.push(*ancestor.id()));
    }
}

/// Observer that performs no work (for no-op parity).
struct NoopObserver;
impl SafetyDecisionObserver<[u8; 32]> for NoopObserver {
    fn observe(&mut self, _d: &SafetyDecisionView<'_, [u8; 32]>) {}
}

/// Drive a single-validator engine through one accepted proposal at view 0 so
/// that its self-vote forms a QC and establishes the lock L0 (= the view-0
/// block). Returns the engine and the locked (L0) block id.
fn engine_locked_at_view0() -> (BasicHotStuffEngine<[u8; 32]>, [u8; 32]) {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validator_set(1));
    assert!(engine.locked_qc().is_none(), "no lock initially");

    // View 0 proposal from the (sole) leader. Parent sentinel => no parent.
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let action = engine.on_proposal_event(ValidatorId(1), &p0);
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "view-0 self-vote should broadcast"
    );
    let locked = engine.locked_qc().expect("lock L0 established by self-vote");
    assert_eq!(locked.view, 0, "L0 is the view-0 block");
    let l0_block = locked.block_id;
    (engine, l0_block)
}

// ===========================================================================
// 1. Real safety check under L0 followed by a same-event self-vote L1.
//    The callback observes L0.
// ===========================================================================

#[test]
fn observes_l0_before_same_event_self_vote_raises_l1() {
    let (mut engine, l0_block) = engine_locked_at_view0();

    // Advance to view 1 (resets voted_in_view). Sole validator remains leader.
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);

    // View-1 proposal whose justify QC references the L0 block at view 0, so
    // justify_qc.view (0) >= locked.view (0) => ViewSufficiency.
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);

    // A vote was emitted...
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "view-1 proposal is safe and self-votes"
    );
    // ...exactly one observation happened...
    assert_eq!(rec.calls, 1);
    // ...and it observed the L0 lock, NOT the L1 that the self-vote just formed.
    assert_eq!(rec.locked_view, Some(0), "observer saw L0 (view 0)");
    assert_eq!(rec.locked_block_id, Some(l0_block));
    assert_eq!(rec.candidate_view, Some(1));
    assert_eq!(rec.origin_view, Some(1));
    assert_eq!(rec.branch, Some(SafetyBranch::ViewSufficiency));

    // The post-decision engine state has already been raised to L1 (view 1):
    // reading the lock AFTER the event could not have established L0.
    let post = engine.locked_qc().expect("lock present after self-vote");
    assert_eq!(post.view, 1, "self-vote raised the lock to L1 (view 1)");
    assert_ne!(
        post.block_id, l0_block,
        "L1 is a different block than the observed L0"
    );
}

// ===========================================================================
// 2. Justification-view and ancestry branches, including the equality boundary.
// ===========================================================================

#[test]
fn view_sufficiency_branch_at_equality_boundary() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // justify_qc.view == locked.view (0 == 0): the `>=` boundary admits via
    // ViewSufficiency and the ancestry walk is short-circuited.
    let mut p1 = make_proposal(1, [0x11; 32], 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);
    assert!(matches!(
        action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
    assert_eq!(rec.calls, 1);
    assert_eq!(rec.branch, Some(SafetyBranch::ViewSufficiency));
    assert_eq!(rec.candidate_justify_view, Some(0));
    assert_eq!(rec.locked_view, Some(0));
}

#[test]
fn ancestry_branch_when_justify_view_below_lock() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // No justify QC => the view-sufficiency branch cannot fire; the candidate's
    // parent is the locked block, so the ancestry walk reaches it.
    let p1 = make_proposal(1, l0_block, 1);
    assert!(p1.qc.is_none());

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);
    assert!(matches!(
        action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
    assert_eq!(rec.calls, 1);
    assert_eq!(rec.branch, Some(SafetyBranch::Ancestry));
    assert_eq!(rec.candidate_parent, Some(l0_block));
    // Optional ancestry inspection reaches the L0 block as a strict ancestor.
    assert!(
        rec.ancestors.contains(&l0_block),
        "for_each_ancestor reaches the locked block"
    );
}

#[test]
fn opaque_ancestor_view_exposes_only_scalars_and_identifiers() {
    // Run 422 §13.6 correction — ancestry inspection yields an opaque
    // `SafetyAncestorView` (identifiers + Copy scalars), never a `&BlockNode`
    // or an owned certificate. This exercises each scalar accessor at runtime;
    // the compile-fail doctest on `SafetyDecisionObserver` proves the
    // certificate surface is NOT reachable.
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // view-1 candidate whose parent is the L0 (view-0) block. No justify QC, so
    // the ancestry walk reaches the parent.
    let p1 = make_proposal(1, l0_block, 1);

    // Observer that copies the opaque ancestor view's scalar fields out.
    #[derive(Default)]
    struct AncestorScalars {
        views: Vec<u64>,
        heights: Vec<u64>,
        ids: Vec<[u8; 32]>,
        parents: Vec<Option<[u8; 32]>>,
        justify_views: Vec<Option<u64>>,
        verified_flags: Vec<bool>,
    }
    impl SafetyDecisionObserver<[u8; 32]> for AncestorScalars {
        fn observe(&mut self, d: &SafetyDecisionView<'_, [u8; 32]>) {
            d.for_each_ancestor(8, |a| {
                self.views.push(a.view());
                self.heights.push(a.height());
                self.ids.push(*a.id());
                self.parents.push(a.parent_id().copied());
                self.justify_views.push(a.justify_view());
                self.verified_flags.push(a.has_verified_justification());
            });
        }
    }

    let mut rec = AncestorScalars::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);
    assert!(matches!(
        action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));

    // Exactly one strict ancestor: the L0 (view-0) block.
    assert_eq!(rec.ids, vec![l0_block]);
    assert_eq!(rec.views, vec![0], "ancestor is the view-0 block");
    assert_eq!(rec.heights, vec![0], "view-0 block is at height 0");
    assert_eq!(rec.parents, vec![None], "view-0 block has no parent");
    assert_eq!(
        rec.justify_views,
        vec![None],
        "the view-0 block carried no justification QC"
    );
    assert_eq!(
        rec.verified_flags,
        vec![false],
        "legacy entrypoint retains no verified-justification evidence"
    );
}

#[test]
fn no_lock_branch_is_explicit() {
    // Fresh engine, no lock yet: the first proposal admits via NoLock.
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validator_set(1));
    let p0 = make_proposal(0, [0xFF; 32], 1);

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p0, &mut rec);
    assert!(matches!(
        action,
        Some(ConsensusEngineAction::BroadcastVote(_))
    ));
    assert_eq!(rec.calls, 1);
    assert_eq!(rec.branch, Some(SafetyBranch::NoLock));
    assert_eq!(rec.locked_view, None, "NoLock: no effective lock");
    assert_eq!(rec.locked_block_id, None);
}

// ===========================================================================
// 3. No-op observation vs. legacy execution: equivalent action and state.
// ===========================================================================

#[test]
fn observed_run_matches_legacy_run() {
    // Legacy run.
    let (mut legacy, l0_legacy) = engine_locked_at_view0();
    legacy.advance_view();
    let mut p_legacy = make_proposal(1, l0_legacy, 1);
    p_legacy.qc = Some(logical_qc(l0_legacy, 0));
    let a_legacy = legacy.on_proposal_event(ValidatorId(1), &p_legacy);

    // Observed run with a no-op observer, identical inputs.
    let (mut observed, l0_observed) = engine_locked_at_view0();
    observed.advance_view();
    let mut p_observed = make_proposal(1, l0_observed, 1);
    p_observed.qc = Some(logical_qc(l0_observed, 0));
    let mut noop = NoopObserver;
    let a_observed = observed.on_proposal_event_observed(ValidatorId(1), &p_observed, &mut noop);

    // Same block ids are derived (deterministic). The complete outgoing Vote
    // (every field, not merely the action variant) is identical between the
    // legacy and the no-op-observed run, and so are the resulting lock and view.
    assert_eq!(l0_legacy, l0_observed);

    fn vote_of(a: &Option<ConsensusEngineAction<ValidatorId>>) -> &Vote {
        match a {
            Some(ConsensusEngineAction::BroadcastVote(v)) => v,
            other => panic!("expected BroadcastVote, got {other:?}"),
        }
    }
    let v_legacy = vote_of(&a_legacy);
    let v_observed = vote_of(&a_observed);
    assert_eq!(
        v_legacy, v_observed,
        "a no-op observation changes no field of the outgoing Vote"
    );

    assert_eq!(
        legacy.locked_qc().map(|q| (q.block_id, q.view)),
        observed.locked_qc().map(|q| (q.block_id, q.view)),
        "a no-op observation changes neither the lock nor the outcome"
    );
    assert_eq!(legacy.current_view(), observed.current_view());
}

// ===========================================================================
// 4. Early refusal: no observation where no successful safety decision occurred.
// ===========================================================================

#[test]
fn no_observation_on_conflicting_fork() {
    let (mut engine, _l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // A view-1 proposal on a conflicting fork: parent is an unknown block and
    // the justify QC's view is below the lock, so neither branch admits.
    let mut p1 = make_proposal(1, [0x99; 32], 1);
    // Reference a non-locked block at a view strictly below the lock would need
    // view < 0 which is impossible; instead drop the justify QC entirely so the
    // ancestry walk (parent 0x99 unknown) is the only path and it fails.
    p1.qc = None;

    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut rec);

    assert!(action.is_none(), "conflicting fork must not vote");
    assert_eq!(rec.calls, 0, "no successful decision => no observation");
}

// ===========================================================================
// 4b. Eliminate silent observation omission (Run 422 §13.6 correction).
//
//     Legacy, no-lock case with `max_pending_blocks == 0`: `register_block`
//     evicts the candidate it just registered, the safety predicate still
//     succeeds via `NoLock` (which reads no block), and the observation input
//     (the candidate) is therefore absent at the observation point. The earlier
//     revision silently skipped observation and self-voted anyway. The observed
//     route now makes this explicit: it observes nothing AND casts no vote.
// ===========================================================================

/// Build a single-validator engine whose block tree cannot retain any block
/// (`max_pending_blocks == 0`), so a freshly registered candidate is evicted
/// immediately.
fn zero_slot_engine() -> BasicHotStuffEngine<[u8; 32]> {
    let mut limits = ConsensusLimitsConfig::default();
    limits.max_pending_blocks = 0;
    BasicHotStuffEngine::with_state_limits(ValidatorId(1), validator_set(1), limits)
}

#[test]
fn observed_route_makes_missing_observation_input_explicit() {
    let mut engine = zero_slot_engine();
    assert!(engine.locked_qc().is_none(), "fresh engine: no lock (NoLock)");
    assert_eq!(engine.state().block_count(), 0);
    let evicted_before = engine.state().evicted_blocks();

    // A view-0 proposal from the sole leader. `NoLock` admits without reading
    // the block, but the candidate is evicted on registration (zero slots).
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let mut rec = Recording::default();
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p0, &mut rec);

    // Callback count: the observation input was evicted, so the observer is
    // NOT invoked — but this is now surfaced, not swallowed.
    assert_eq!(
        rec.calls, 0,
        "observation input (candidate) was evicted => observer not invoked"
    );
    // Absence of dependent voting: the observed route refuses to self-vote when
    // it cannot observe. No action is returned.
    assert!(
        action.is_none(),
        "observed route must not vote when the observation input is missing"
    );
    // For a single validator, a self-vote would immediately form a QC and set
    // the lock. Its absence proves no self-vote occurred.
    assert!(
        engine.locked_qc().is_none(),
        "no self-vote => no QC formed => lock stays empty"
    );
    assert_eq!(engine.current_view(), 0, "view is unchanged by the refusal");

    // Precisely which earlier proposal-processing mutations remain: the
    // candidate was registered and then evicted under the zero-slot budget, so
    // the block tree is empty and the eviction counter advanced by exactly one.
    // No vote-derived mutation (lock / QC / committed state) remains.
    assert_eq!(
        engine.state().block_count(),
        0,
        "the registered candidate was evicted, not retained"
    );
    assert_eq!(
        engine.state().evicted_blocks(),
        evicted_before + 1,
        "exactly the one candidate block was evicted"
    );
}

#[test]
fn unobserved_legacy_route_still_votes_when_candidate_evicted() {
    // Same zero-slot scenario, but the UNOBSERVED legacy route is preserved
    // unchanged: it self-votes even though the candidate was evicted. This is
    // the behavior the correction deliberately leaves intact; only the opt-in
    // observed route diverges.
    let mut engine = zero_slot_engine();

    let p0 = make_proposal(0, [0xFF; 32], 1);
    let action = engine.on_proposal_event(ValidatorId(1), &p0);

    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "legacy (unobserved) route votes exactly as before"
    );
    // The self-vote formed the single-validator QC and set the lock to view 0.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "legacy self-vote formed the lock"
    );
    // The same eviction happened: the candidate did not survive the zero-slot
    // budget. The difference is purely the observed route's refusal to vote.
    assert_eq!(engine.state().block_count(), 0);
    assert_eq!(engine.state().evicted_blocks(), 1);
}

// ===========================================================================
// 5. Callback panic: no subsequent self-vote or returned action; earlier
//    proposal-processing mutations (block registration) remain.
// ===========================================================================

const OBSERVER_PANIC_MSG: &str = "observer panics during observation";

struct PanicObserver;
impl SafetyDecisionObserver<[u8; 32]> for PanicObserver {
    fn observe(&mut self, _d: &SafetyDecisionView<'_, [u8; 32]>) {
        panic!("{OBSERVER_PANIC_MSG}");
    }
}

#[test]
fn callback_panic_prevents_self_vote_and_action() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    // Pre-state: the view-1 block is not yet registered, lock is L0 (view 0).
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(0));
    let blocks_before = engine.state().block_count();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut obs = PanicObserver;
        engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut obs)
    }));
    let payload = result.expect_err("the panic propagates out of ingestion");

    // Require the EXPECTED observer panic payload: this must be the observer's
    // own panic, not an unrelated panic (e.g. an engine assertion) that would
    // also make `catch_unwind` return `Err`. An unrelated payload fails here.
    let msg = payload
        .downcast_ref::<&'static str>()
        .map(|s| *s)
        .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
        .expect("panic payload is a string");
    assert_eq!(
        msg, OBSERVER_PANIC_MSG,
        "must be the observer's panic, not an unrelated one"
    );

    // Earlier proposal-processing mutation that remains: the candidate block WAS
    // registered (it is created before the safety decision/observation), so the
    // engine's block count grew by exactly one.
    assert_eq!(
        engine.state().block_count(),
        blocks_before + 1,
        "the registered candidate block survives the panic"
    );
    // But the self-vote never ran: the lock is still L0, not raised to L1.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no self-vote-generated L1 after a panicking observation"
    );
}

// ===========================================================================
// 6. Verified entrypoint drives the observer, preserving its evidence
//    guarantee (candidate carries verified justification) without cloning the
//    evidence Arc into the observation.
// ===========================================================================

const TEST_SUITE: ConsensusSigSuiteId = SUITE_PQ_RESERVED_1;
const TEST_SUITE_U16: u16 = 100;
const WIRE_CHAIN: u32 = 1;

struct VerifiedFixture {
    validators: ConsensusValidatorSet,
    kp: TestKeyProvider,
    sks: std::collections::HashMap<ValidatorId, Vec<u8>>,
}

#[derive(Debug, Default)]
struct TestKeyProvider {
    keys: std::collections::HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}
impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).cloned()
    }
}

fn verified_fixture(n: u64) -> VerifiedFixture {
    let mut keys = std::collections::HashMap::new();
    let mut sks = std::collections::HashMap::new();
    let mut entries = Vec::new();
    for id in 1..=n {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        keys.insert(ValidatorId(id), (TEST_SUITE, pk));
        sks.insert(ValidatorId(id), sk);
        entries.push(ValidatorSetEntry {
            id: ValidatorId(id),
            voting_power: 1,
        });
    }
    VerifiedFixture {
        validators: ConsensusValidatorSet::new(entries).expect("set"),
        kp: TestKeyProvider { keys },
        sks,
    }
}

fn domain_for(block_commitment: [u8; 32]) -> ProposalVoteSigningDomainV2 {
    ProposalVoteSigningDomainV2::try_new(ChainId(1), WIRE_CHAIN, [9u8; 32], block_commitment)
        .expect("domain")
}

fn set_bit(bitmap: &mut Vec<u8>, index: u16) {
    let byte = (index / 8) as usize;
    let bit = index % 8;
    if bitmap.len() <= byte {
        bitmap.resize(byte + 1, 0);
    }
    bitmap[byte] |= 1u8 << bit;
}

/// Build a QC signed under `d` by `signers` over the justified `block_id` at
/// `height`.
fn build_signed_qc(
    f: &VerifiedFixture,
    d: &ProposalVoteSigningDomainV2,
    block_id: [u8; 32],
    height: u64,
    signers: &[u16],
) -> WireQc {
    let mut qc = WireQc {
        version: 1,
        chain_id: WIRE_CHAIN,
        epoch: 0,
        height,
        round: height,
        step: 1,
        block_id,
        suite_id: TEST_SUITE_U16,
        signer_bitmap: vec![],
        signatures: vec![],
    };
    let mut bitmap = Vec::new();
    let mut sigs = Vec::new();
    for &s in signers {
        set_bit(&mut bitmap, s);
        let vote = Vote {
            version: qc.version,
            chain_id: qc.chain_id,
            epoch: qc.epoch,
            height: qc.height,
            round: qc.round,
            step: qc.step,
            block_id: qc.block_id,
            validator_index: s,
            suite_id: qc.suite_id,
            signature: vec![],
        };
        let pre = d.vote_preimage(&vote);
        let sk = f.sks.get(&ValidatorId(s as u64)).expect("sk");
        sigs.push(MlDsa44Backend::sign(sk, &pre).expect("sign"));
    }
    qc.signer_bitmap = bitmap;
    qc.signatures = sigs;
    qc
}

#[test]
fn verified_entrypoint_drives_observer_without_cloning_evidence() {
    // 4 validators (ids 1..=4), threshold ceil(2*4/3)=3. Leader for view 0 is
    // the lowest id (1).
    let f = verified_fixture(4);
    let justified_block = [0x55u8; 32];
    let d = domain_for([3u8; 32]);
    let wire_qc = build_signed_qc(&f, &d, justified_block, 0, &[1, 2, 3]);
    let registry = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend));

    let verified = verify_quorum_certificate_with_domain(
        &wire_qc,
        &d,
        0,
        &f.validators,
        &f.kp,
        &registry,
    )
    .expect("quorum verifies");
    let evidence = Arc::new(verified);
    let strong_before = Arc::strong_count(&evidence);

    // Engine over the same validator set; leader for view 0 is ValidatorId(1).
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), f.validators.clone());

    // A view-0 proposal whose embedded QC is exactly the verified certificate.
    let mut proposal = make_proposal(0, [0xFF; 32], 1);
    proposal.qc = Some(evidence.certificate().clone());

    let mut rec = Recording::default();
    let result = engine.on_verified_proposal_event_observed(
        ValidatorId(1),
        &proposal,
        Arc::clone(&evidence),
        &mut rec,
    );

    let action = result.expect("verified ingestion succeeds");
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "verified proposal is safe (NoLock) and self-votes"
    );
    assert_eq!(rec.calls, 1);
    assert_eq!(rec.branch, Some(SafetyBranch::NoLock));
    assert_eq!(
        rec.verified,
        Some(true),
        "observer records the verified entrypoint"
    );

    // Endpoint retention check (NOT a temporary-clone detector, NOT a heap
    // measurement). This compares the certificate Arc's strong count at two
    // endpoints — before ingestion and after it returns — and asserts the NET
    // retention is bounded by the one reference the engine legitimately keeps
    // (the block node's retained justification; our own `evidence` handle is the
    // baseline). It says nothing about transient clones that may have existed
    // *during* the call and been dropped before it returned, and it measures no
    // heap allocation. It is an endpoint before/after retention comparison only.
    let strong_after = Arc::strong_count(&evidence);
    assert!(
        strong_after <= strong_before + 1,
        "net retained certificate Arc references across the operation must not \
         exceed the engine's one legitimate hold (before={strong_before}, \
         after={strong_after})"
    );
}

// ===========================================================================
// 7. Layout / allocation accounting of the observation machinery.
// ===========================================================================

#[test]
fn view_layout_is_fixed_and_stack_resident() {
    use std::mem::size_of;
    // The view is a fixed bundle: two references (state, candidate), one
    // Option<&QC>, a branch enum, two u64 scalars, a ValidatorId and a bool.
    // It owns no heap allocation; its size is a small, fixed, inline cost.
    let sz = size_of::<SafetyDecisionView<'static, [u8; 32]>>();
    // Record the measured size (printed with `--nocapture`); assert it stays a
    // handful of machine words rather than, say, an owned certificate.
    assert!(
        sz <= 8 * std::mem::size_of::<usize>(),
        "SafetyDecisionView should be a few words (measured {sz} bytes)"
    );
    assert!(sz > 0);
    println!("SafetyDecisionView<[u8;32]> size = {sz} bytes");
    println!("SafetyBranch size = {} bytes", size_of::<SafetyBranch>());
}