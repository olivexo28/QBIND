//! Run 422 §13.6 — real-engine evidence for the isolated, opt-in **fallible
//! safety-decision gate**.
//!
//! These tests drive the ACTUAL engine control flow
//! ([`BasicHotStuffEngine::on_proposal_event_gated`] /
//! [`BasicHotStuffEngine::on_verified_proposal_event_gated`]), not a
//! test-authored consumer model, to establish that:
//!
//! - an ALLOWING gate yields a byte-identical outgoing `Vote` and resulting
//!   state to the corresponding existing (unobserved) route;
//! - a REJECTING gate casts no self-vote and emits no `Vote`, and a subsequent
//!   admissible retry still votes — the refusal does not consume the vote
//!   opportunity (`voted_in_view` is left unset);
//! - the gate sees the L0 lock BEFORE an allowed same-event self-vote raises it
//!   to L1;
//! - an unsafe proposal is an ORDINARY rejection (`Ok(None)`, gate not
//!   consulted), while a missing decision-view candidate is a typed
//!   `MissingCandidate` refusal (gate not consulted);
//! - the legacy and verified gated entrypoints keep their distinct pre-checks
//!   (the verified route rejects a missing/!matching embedded QC with
//!   `GatedVerifiedProposalError::Ingest` BEFORE the gate; the legacy route does
//!   not require an embedded QC at all);
//! - a future-view refusal leaves exactly the permitted earlier view/
//!   registration mutations and NO vote-derived mutation.
//!
//! What this does NOT establish (per the brief): any node-side binder, action/
//! pin pairing, durable correspondence, production caller, signing integration,
//! or the D10 prerequisite. The gate establishes no authorization, durable
//! correspondence, or permission to sign.

use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::verify_quorum_certificate_with_domain;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::vote_accumulator::ConsensusLimitsConfig;
use qbind_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet, GatedSelfVoteRefusal,
    GatedVerifiedProposalError, SafetyBranch, SafetyDecisionGate, SafetyDecisionView,
    SafetyGateRefusal, ValidatorId, VerifiedProposalIngestError,
};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

// ===========================================================================
// Helpers (mirrors of the observer spike's helpers)
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

/// A minimal logical (legacy) wire QC referencing `block_id` at `height`.
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

/// Fallible gate that records the decision scalars it is handed and either
/// allows or refuses the dependent self-vote. It copies scalars out only and
/// never panics (refusal is `Err`, never a panic).
#[derive(Default)]
struct CountingGate {
    reject: bool,
    calls: usize,
    branch: Option<SafetyBranch>,
    locked_view: Option<u64>,
    locked_block_id: Option<[u8; 32]>,
    candidate_id: Option<[u8; 32]>,
    candidate_view: Option<u64>,
    origin_view: Option<u64>,
    from: Option<ValidatorId>,
    verified: Option<bool>,
}

impl CountingGate {
    fn allowing() -> Self {
        CountingGate {
            reject: false,
            ..Default::default()
        }
    }
    fn rejecting() -> Self {
        CountingGate {
            reject: true,
            ..Default::default()
        }
    }
}

impl SafetyDecisionGate<[u8; 32]> for CountingGate {
    fn evaluate(&mut self, d: &SafetyDecisionView<'_, [u8; 32]>) -> Result<(), SafetyGateRefusal> {
        self.calls += 1;
        self.branch = Some(d.branch());
        self.locked_view = d.locked_view();
        self.locked_block_id = d.locked_block_id().copied();
        self.candidate_id = Some(*d.candidate_id());
        self.candidate_view = Some(d.candidate_view());
        self.origin_view = Some(d.origin_view());
        self.from = Some(d.from());
        self.verified = Some(d.is_verified_entrypoint());
        if self.reject {
            Err(SafetyGateRefusal)
        } else {
            Ok(())
        }
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

/// Single-validator engine whose block tree cannot retain any block
/// (`max_pending_blocks == 0`), so a freshly registered candidate is evicted
/// immediately.
fn zero_slot_engine() -> BasicHotStuffEngine<[u8; 32]> {
    let limits = ConsensusLimitsConfig {
        max_pending_blocks: 0,
        ..Default::default()
    };
    BasicHotStuffEngine::with_state_limits(ValidatorId(1), validator_set(1), limits)
}

fn vote_of(a: &Option<ConsensusEngineAction<ValidatorId>>) -> &Vote {
    match a {
        Some(ConsensusEngineAction::BroadcastVote(v)) => v,
        other => panic!("expected BroadcastVote, got {other:?}"),
    }
}

// ===========================================================================
// 1. Allowing gate: exact outgoing Vote and resulting state match the existing
//    (unobserved) route.
// ===========================================================================

#[test]
fn allowing_gate_matches_existing_route() {
    // Existing unobserved route.
    let (mut legacy, l0_legacy) = engine_locked_at_view0();
    legacy.advance_view();
    let mut p_legacy = make_proposal(1, l0_legacy, 1);
    p_legacy.qc = Some(logical_qc(l0_legacy, 0));
    let a_legacy = legacy.on_proposal_event(ValidatorId(1), &p_legacy);

    // Gated route with an allowing gate, identical inputs.
    let (mut gated, l0_gated) = engine_locked_at_view0();
    gated.advance_view();
    let mut p_gated = make_proposal(1, l0_gated, 1);
    p_gated.qc = Some(logical_qc(l0_gated, 0));
    let mut gate = CountingGate::allowing();
    let a_gated = gated
        .on_proposal_event_gated(ValidatorId(1), &p_gated, &mut gate)
        .expect("allowing gate yields Ok");

    assert_eq!(l0_legacy, l0_gated);
    assert_eq!(gate.calls, 1, "gate consulted exactly once");

    // Field-by-field Vote equality, not merely the action variant.
    assert_eq!(
        vote_of(&a_legacy),
        vote_of(&a_gated),
        "an allowing gate changes no field of the outgoing Vote"
    );
    // Resulting lock and view are identical.
    assert_eq!(
        legacy.locked_qc().map(|q| (q.block_id, q.view)),
        gated.locked_qc().map(|q| (q.block_id, q.view)),
        "an allowing gate changes neither the lock nor the outcome"
    );
    assert_eq!(legacy.current_view(), gated.current_view());
}

// ===========================================================================
// 2. Rejecting gate: no self-vote or outgoing Vote; a subsequent admissible
//    retry still votes (the refusal did not consume the vote opportunity).
// ===========================================================================

#[test]
fn rejecting_gate_casts_no_vote_and_leaves_opportunity() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);

    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    // Reject: the gate declines at the real (ViewSufficiency) decision.
    let mut reject = CountingGate::rejecting();
    let refusal = engine
        .on_proposal_event_gated(ValidatorId(1), &p1, &mut reject)
        .expect_err("rejecting gate yields Err");
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

    // No vote-derived mutation: the lock stays at L0 (view 0). If a self-vote
    // had been cast, the single-validator QC would have raised the lock to L1.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "refusal casts no vote => lock unchanged at L0"
    );
    assert_eq!(engine.current_view(), 1, "view unchanged by the refusal");

    // The refusal did NOT consume the vote opportunity: a subsequent admissible
    // retry (same view, now with an allowing gate) still votes.
    let mut allow = CountingGate::allowing();
    let retry = engine
        .on_proposal_event_gated(ValidatorId(1), &p1, &mut allow)
        .expect("retry is admissible");
    assert_eq!(allow.calls, 1);
    assert!(
        matches!(retry, Some(ConsensusEngineAction::BroadcastVote(_))),
        "admissible retry still votes after an earlier refusal"
    );
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(1),
        "the retry self-vote raised the lock to L1 (view 1)"
    );
}

// ===========================================================================
// 3. Same-event L0 -> L1: the gate sees L0 before an allowed self-vote raises
//    L1.
// ===========================================================================

#[test]
fn gate_sees_l0_before_allowed_self_vote_raises_l1() {
    let (mut engine, l0_block) = engine_locked_at_view0();
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);

    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));

    let mut gate = CountingGate::allowing();
    let action = engine
        .on_proposal_event_gated(ValidatorId(1), &p1, &mut gate)
        .expect("allowing gate yields Ok");

    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "view-1 proposal is safe and self-votes"
    );
    assert_eq!(gate.calls, 1);
    // The gate observed the L0 lock (view 0), NOT the L1 the self-vote formed.
    assert_eq!(gate.locked_view, Some(0), "gate saw L0 (view 0)");
    assert_eq!(gate.locked_block_id, Some(l0_block));
    assert_eq!(gate.candidate_view, Some(1));
    assert_eq!(gate.origin_view, Some(1));
    assert_eq!(gate.branch, Some(SafetyBranch::ViewSufficiency));

    // Post-decision the engine has already been raised to L1 (view 1): reading
    // the lock AFTER the event could not have established L0.
    let post = engine.locked_qc().expect("lock present after self-vote");
    assert_eq!(post.view, 1, "self-vote raised the lock to L1 (view 1)");
}

// ===========================================================================
// 4. Unsafe proposal is an ordinary rejection (gate not consulted); a missing
//    decision-view candidate is a typed MissingCandidate refusal.
// ===========================================================================

#[test]
fn unsafe_proposal_is_ordinary_rejection_not_gate_refusal() {
    let (mut engine, _l0_block) = engine_locked_at_view0();
    engine.advance_view();

    // Conflicting fork: unknown parent and no justify QC => neither safety
    // branch admits => Unsafe (a decision before the gate is reached).
    let mut p1 = make_proposal(1, [0x99; 32], 1);
    p1.qc = None;

    let mut gate = CountingGate::rejecting();
    let result = engine.on_proposal_event_gated(ValidatorId(1), &p1, &mut gate);

    // Ordinary rejection: Ok(None), NOT a gate refusal, and the gate is never
    // consulted (no successful safety decision occurred).
    assert!(
        matches!(result, Ok(None)),
        "unsafe proposal is an ordinary rejection (Ok(None)), not a gate refusal"
    );
    assert_eq!(
        gate.calls, 0,
        "no successful decision => gate not consulted"
    );
}

#[test]
fn missing_candidate_is_typed_refusal_gate_not_consulted() {
    let mut engine = zero_slot_engine();
    assert!(
        engine.locked_qc().is_none(),
        "fresh engine: no lock (NoLock)"
    );
    let evicted_before = engine.state().evicted_blocks();

    // NoLock admits without reading the block, but the candidate is evicted on
    // registration (zero slots), so the decision-view candidate is absent.
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let mut gate = CountingGate::allowing();
    let refusal = engine
        .on_proposal_event_gated(ValidatorId(1), &p0, &mut gate)
        .expect_err("missing candidate yields a typed refusal");

    assert_eq!(refusal, GatedSelfVoteRefusal::MissingCandidate);
    assert_eq!(
        gate.calls, 0,
        "candidate absent => the gate is not consulted at all"
    );
    // No vote-derived mutation: a single-validator self-vote would have formed a
    // QC and set the lock.
    assert!(
        engine.locked_qc().is_none(),
        "no self-vote => no QC => lock stays empty"
    );
    assert_eq!(engine.current_view(), 0, "view unchanged by the refusal");

    // Permitted earlier mutations precisely: the candidate was registered and
    // then evicted under the zero-slot budget; nothing else changed.
    assert_eq!(
        engine.state().block_count(),
        0,
        "candidate evicted, not retained"
    );
    assert_eq!(
        engine.state().evicted_blocks(),
        evicted_before + 1,
        "exactly the one candidate block was evicted"
    );

    // The legacy (ungated) route is preserved: it still votes in this same
    // zero-slot scenario (only the gated route refuses).
    let mut legacy = zero_slot_engine();
    let legacy_action = legacy.on_proposal_event(ValidatorId(1), &make_proposal(0, [0xFF; 32], 1));
    assert!(
        matches!(legacy_action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "legacy (ungated) route votes exactly as before"
    );
    assert_eq!(legacy.locked_qc().map(|q| q.view), Some(0));
}

// ===========================================================================
// 5. Legacy and verified gated entrypoints retain their distinct checks.
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
fn verified_gated_enforces_prechecks_before_gate() {
    let f = verified_fixture(4);
    let justified_block = [0x55u8; 32];
    let d = domain_for([3u8; 32]);
    let wire_qc = build_signed_qc(&f, &d, justified_block, 0, &[1, 2, 3]);
    let registry = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend));
    let verified =
        verify_quorum_certificate_with_domain(&wire_qc, &d, 0, &f.validators, &f.kp, &registry)
            .expect("quorum verifies");
    let evidence = Arc::new(verified);

    // (a) A proposal with NO embedded QC: the verified pre-check rejects it with
    // a distinct Ingest error BEFORE the gate is consulted.
    {
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), f.validators.clone());
        let proposal = make_proposal(0, [0xFF; 32], 1); // qc = None
        let mut gate = CountingGate::allowing();
        let err = engine
            .on_verified_proposal_event_gated(
                ValidatorId(1),
                &proposal,
                Arc::clone(&evidence),
                &mut gate,
            )
            .expect_err("missing embedded QC is rejected");
        assert_eq!(
            err,
            GatedVerifiedProposalError::Ingest(VerifiedProposalIngestError::MissingEmbeddedQc)
        );
        assert_eq!(gate.calls, 0, "pre-check rejects before the gate");
    }

    // (b) Happy verified path with an allowing gate: the gate is consulted once
    // at the real decision (NoLock) and records the verified entrypoint.
    {
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), f.validators.clone());
        let mut proposal = make_proposal(0, [0xFF; 32], 1);
        proposal.qc = Some(evidence.certificate().clone());
        let mut gate = CountingGate::allowing();
        let action = gate_verified_ok(&mut engine, &proposal, &evidence, &mut gate);
        assert!(
            matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
            "verified proposal is safe (NoLock) and self-votes"
        );
        assert_eq!(gate.calls, 1);
        assert_eq!(gate.branch, Some(SafetyBranch::NoLock));
        assert_eq!(
            gate.verified,
            Some(true),
            "gate records the verified entrypoint"
        );
    }

    // (c) The LEGACY gated route does not require an embedded QC at all: the
    // very same QC-less proposal votes through the legacy gated entrypoint. This
    // contrasts the distinct pre-check regimes of the two routes.
    {
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), f.validators.clone());
        let proposal = make_proposal(0, [0xFF; 32], 1); // qc = None
        let mut gate = CountingGate::allowing();
        let action = engine
            .on_proposal_event_gated(ValidatorId(1), &proposal, &mut gate)
            .expect("legacy gated route does not require an embedded QC");
        assert!(
            matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
            "legacy gated route votes without an embedded QC"
        );
        assert_eq!(gate.calls, 1);
        assert_eq!(
            gate.verified,
            Some(false),
            "legacy entrypoint is not verified"
        );
    }
}

/// Helper to keep the verified happy-path borrow of `evidence` tidy.
fn gate_verified_ok(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    proposal: &BlockProposal,
    evidence: &Arc<qbind_consensus::qc_verify_domain::VerifiedQuorumCertificate>,
    gate: &mut CountingGate,
) -> Option<ConsensusEngineAction<ValidatorId>> {
    engine
        .on_verified_proposal_event_gated(ValidatorId(1), proposal, Arc::clone(evidence), gate)
        .expect("verified ingestion succeeds")
}

// ===========================================================================
// 6. Future-view refusal: assert the permitted earlier view/registration
//    mutations precisely, and NO vote-derived mutation.
// ===========================================================================

#[test]
fn future_view_refusal_preserves_only_permitted_mutations() {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validator_set(1));
    assert_eq!(engine.current_view(), 0);
    assert!(engine.locked_qc().is_none());
    assert_eq!(engine.state().block_count(), 0);

    // A proposal for a FUTURE view (5). Ingestion advances the engine's view to
    // 5 and resets per-view flags, then registers the block, before reaching the
    // safety decision. The gate then refuses at the NoLock decision.
    let p5 = make_proposal(5, [0xFF; 32], 1);
    let mut reject = CountingGate::rejecting();
    let refusal = engine
        .on_proposal_event_gated(ValidatorId(1), &p5, &mut reject)
        .expect_err("rejecting gate yields Err");

    assert_eq!(
        refusal,
        GatedSelfVoteRefusal::GateRejected(SafetyGateRefusal)
    );
    assert_eq!(reject.calls, 1, "gate consulted once at the real decision");
    assert_eq!(reject.branch, Some(SafetyBranch::NoLock));
    assert_eq!(reject.origin_view, Some(5), "gate saw the originating view");

    // PERMITTED earlier mutations (precisely): the view was advanced to the
    // future view, and the candidate block was registered and retained (default
    // slots). These happen BEFORE the decision and are explicitly preserved.
    assert_eq!(engine.current_view(), 5, "view advanced to the future view");
    assert_eq!(
        engine.state().block_count(),
        1,
        "the candidate block was registered and retained"
    );

    // NO vote-derived mutation: no self-vote, no QC, no lock transition.
    assert!(
        engine.locked_qc().is_none(),
        "refusal => no self-vote => no lock transition"
    );

    // The vote opportunity for view 5 is intact: an allowing retry still votes.
    let mut allow = CountingGate::allowing();
    let retry = engine
        .on_proposal_event_gated(ValidatorId(1), &p5, &mut allow)
        .expect("retry is admissible");
    assert!(
        matches!(retry, Some(ConsensusEngineAction::BroadcastVote(_))),
        "the earlier refusal left the view-5 vote opportunity intact"
    );
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(5),
        "the retry self-vote formed the lock at view 5"
    );
}