//! Run 422 — real-engine evidence for CONSTRUCTION-TIME outgoing Vote-suite
//! selection ([`BasicHotStuffEngine::with_state_limits_and_vote_suite`] and the
//! private `vote_suite_id` field it installs).
//!
//! These tests drive the ACTUAL engine control flow (leader step and the shared
//! proposal-ingestion body via the legacy, observed, gated, gated-owning, and
//! verified routes) to establish that:
//!
//! - every EXISTING constructor (`new`, `with_state_limits`) still stamps the
//!   default suite (`DEFAULT_CONSENSUS_SUITE_ID` == 0) on BOTH outgoing Vote
//!   paths — the leader's own Vote and the follower self-vote;
//! - the new `with_state_limits_and_vote_suite` constructor stamps the EXPLICIT
//!   selected value on both outgoing Vote paths, while leaving every other Vote
//!   field, the proposal HEADER suite, and the embedded QC suite unchanged;
//! - the selected suite is carried into the closed owning [`DecidedVote`]
//!   envelope on the real engine emission path, with the remaining Vote fields
//!   field-for-field identical to the default route's vote;
//! - shared ingestion behaviour (safety decision, self-vote, lock transition)
//!   is preserved across legacy, observed, gated, and verified routes with the
//!   selected suite in effect.
//!
//! This is OUTGOING-VOTE METADATA ONLY. Selecting a suite establishes no key
//! availability, backend support, verification, authorization, or permission to
//! sign; it is a pure message-metadata change on the engine's own votes. The
//! downstream node-side four-way (Vote, signer, key, backend) suite agreement is
//! NOT exercised here and remains the node composition's responsibility.

use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::verify_quorum_certificate_with_domain;
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::vote_accumulator::ConsensusLimitsConfig;
use qbind_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet, DecidedVote,
    OwningSafetyDecisionGate, SafetyDecisionObserver, SafetyDecisionGate, SafetyDecisionView,
    SafetyGateRefusal, ValidatorId,
};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

// The explicit non-default selection exercised throughout: suite 100
// (ML-DSA-44 / SUITE_PQ_RESERVED_1 as a raw wire id). Metadata only.
const SELECTED_SUITE: u16 = 100;
const WIRE_CHAIN: u32 = 1;

// ===========================================================================
// Shared helpers
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
            // The proposal HEADER suite is independent of the engine's outgoing
            // Vote-suite selection and must stay at the default.
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

/// Default engine built via `new`.
fn default_engine(n: u64) -> BasicHotStuffEngine<[u8; 32]> {
    BasicHotStuffEngine::new(ValidatorId(1), validator_set(n))
}

/// Default engine built via `with_state_limits` (default limits).
fn default_limits_engine(n: u64) -> BasicHotStuffEngine<[u8; 32]> {
    BasicHotStuffEngine::with_state_limits(
        ValidatorId(1),
        validator_set(n),
        ConsensusLimitsConfig::default(),
    )
}

/// Engine built via the new constructor selecting `SELECTED_SUITE`.
fn suite_selected_engine(n: u64) -> BasicHotStuffEngine<[u8; 32]> {
    BasicHotStuffEngine::with_state_limits_and_vote_suite(
        ValidatorId(1),
        validator_set(n),
        ConsensusLimitsConfig::default(),
        SELECTED_SUITE,
    )
}

/// Drive a single-validator engine through one accepted view-0 proposal so its
/// self-vote forms a QC and locks L0; return the emitted follower self-vote.
fn ingest_view0_selfvote(engine: &mut BasicHotStuffEngine<[u8; 32]>) -> Vote {
    let p0 = make_proposal(0, [0xFF; 32], 1);
    match engine.on_proposal_event(ValidatorId(1), &p0) {
        Some(ConsensusEngineAction::BroadcastVote(v)) => v,
        other => panic!("expected a broadcast self-vote, got {other:?}"),
    }
}

/// Drive the leader step of a single-validator engine and return ONLY the
/// leader's own broadcast Vote (the first of propose's two actions is the
/// proposal; the second is the leader vote).
fn leader_vote(engine: &mut BasicHotStuffEngine<[u8; 32]>) -> Vote {
    let actions = engine.try_propose();
    let mut found = None;
    for a in actions {
        if let ConsensusEngineAction::BroadcastVote(v) = a {
            found = Some(v);
        }
    }
    found.expect("leader step must broadcast the leader's own vote")
}

// ===========================================================================
// 1. Existing constructors keep the default suite on BOTH outgoing Vote paths.
// ===========================================================================

#[test]
fn new_constructor_defaults_both_outgoing_vote_paths_to_suite_zero() {
    // Follower self-vote path (shared ingestion body).
    let mut e = default_engine(1);
    let self_vote = ingest_view0_selfvote(&mut e);
    assert_eq!(
        self_vote.suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "follower self-vote keeps the default suite under `new`"
    );

    // Leader's own Vote path (leader step).
    let mut e2 = default_engine(1);
    let lv = leader_vote(&mut e2);
    assert_eq!(
        lv.suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "leader's own vote keeps the default suite under `new`"
    );
}

#[test]
fn with_state_limits_defaults_both_outgoing_vote_paths_to_suite_zero() {
    let mut e = default_limits_engine(1);
    let self_vote = ingest_view0_selfvote(&mut e);
    assert_eq!(
        self_vote.suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "follower self-vote keeps the default suite under `with_state_limits`"
    );

    let mut e2 = default_limits_engine(1);
    let lv = leader_vote(&mut e2);
    assert_eq!(
        lv.suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "leader's own vote keeps the default suite under `with_state_limits`"
    );
}

// ===========================================================================
// 2. Explicit selection stamps the chosen suite on BOTH outgoing Vote paths.
// ===========================================================================

#[test]
fn selected_suite_is_stamped_on_both_outgoing_vote_paths() {
    let mut e = suite_selected_engine(1);
    let self_vote = ingest_view0_selfvote(&mut e);
    assert_eq!(
        self_vote.suite_id, SELECTED_SUITE,
        "follower self-vote carries the selected suite"
    );

    let mut e2 = suite_selected_engine(1);
    let lv = leader_vote(&mut e2);
    assert_eq!(
        lv.suite_id, SELECTED_SUITE,
        "leader's own vote carries the selected suite"
    );
}

// ===========================================================================
// 3. Selection changes ONLY the Vote suite: every other field matches the
//    default route's vote, and proposal-header/embedded-QC suites are unchanged.
// ===========================================================================

#[test]
fn selection_changes_only_vote_suite_and_leaves_header_and_qc_untouched() {
    // Two engines, identical inputs, differing only in outgoing Vote suite.
    let mut def = default_engine(1);
    let mut sel = suite_selected_engine(1);

    let def_vote = ingest_view0_selfvote(&mut def);
    let sel_vote = ingest_view0_selfvote(&mut sel);

    // The ONLY difference is `suite_id`.
    assert_eq!(def_vote.suite_id, qbind_wire::DEFAULT_CONSENSUS_SUITE_ID);
    assert_eq!(sel_vote.suite_id, SELECTED_SUITE);

    // Reduce the selected vote to the default suite and require FULL equality:
    // proves no other field (version/chain_id/epoch/height/round/step/block_id/
    // validator_index/signature) was perturbed by selection.
    let mut normalized = sel_vote.clone();
    normalized.suite_id = def_vote.suite_id;
    assert_eq!(
        normalized, def_vote,
        "selection perturbs ONLY the Vote suite_id; all other fields are identical"
    );
    assert_eq!(sel_vote.signature.capacity(), 0, "self-vote stays unsigned");

    // The proposal header and embedded QC suites are governed by their own
    // fields, which the engine leaves at the default on the leader step.
    let mut leader_engine = suite_selected_engine(1);
    let actions = leader_engine.try_propose();
    let mut proposal: Option<BlockProposal> = None;
    for a in actions {
        if let ConsensusEngineAction::BroadcastProposal(p) = a {
            proposal = Some(*p);
        }
    }
    let proposal = proposal.expect("leader step broadcasts a proposal");
    assert_eq!(
        proposal.header.suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "proposal header suite is NOT affected by outgoing Vote-suite selection"
    );
    // (The genesis leader proposal carries no justify QC; the embedded-QC suite
    // field, when present, is likewise independent — it is stamped at the
    // default and never read from `vote_suite_id`.)
    assert!(
        proposal.qc.is_none(),
        "the genesis leader proposal has no embedded QC to perturb"
    );
}

// ===========================================================================
// 4. The owning envelope (DecidedVote) carries the selected-suite self-vote.
// ===========================================================================

/// Minimal allowing owning gate that produces a trivial `()` payload at the
/// real decision, strictly before the self-vote. Metadata/ownership only.
struct AllowUnit;
impl OwningSafetyDecisionGate<[u8; 32], ()> for AllowUnit {
    fn evaluate_owning(
        &mut self,
        _d: &SafetyDecisionView<'_, [u8; 32]>,
    ) -> Result<(), SafetyGateRefusal> {
        Ok(())
    }
}

/// Lock a single-validator engine at L0, advance to view 1, and return a safe
/// view-1 proposal that will self-vote when admitted.
fn engine_and_safe_view1_proposal(
    mut engine: BasicHotStuffEngine<[u8; 32]>,
) -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal) {
    let _ = ingest_view0_selfvote(&mut engine);
    let l0 = engine.locked_qc().expect("L0 lock").block_id;
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);
    let mut p1 = make_proposal(1, l0, 1);
    p1.qc = Some(logical_qc(l0, 0));
    (engine, p1)
}

#[test]
fn owning_envelope_carries_selected_suite_with_other_fields_matching_default() {
    // Default engine: the DecidedVote carries a suite-0 vote.
    let (mut def_engine, def_p1) = engine_and_safe_view1_proposal(default_engine(1));
    let mut def_gate = AllowUnit;
    let def_decided: DecidedVote<()> = def_engine
        .on_proposal_event_gated_owning(ValidatorId(1), &def_p1, &mut def_gate)
        .expect("no refusal")
        .expect("owning gate allows => DecidedVote");
    assert_eq!(
        def_decided.vote().suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "default engine's owning envelope carries a suite-0 vote"
    );

    // Selected engine: the DecidedVote carries a suite-100 vote; all other
    // fields are identical to the default envelope's vote.
    let (mut sel_engine, sel_p1) = engine_and_safe_view1_proposal(suite_selected_engine(1));
    let mut sel_gate = AllowUnit;
    let sel_decided: DecidedVote<()> = sel_engine
        .on_proposal_event_gated_owning(ValidatorId(1), &sel_p1, &mut sel_gate)
        .expect("no refusal")
        .expect("owning gate allows => DecidedVote");
    assert_eq!(
        sel_decided.vote().suite_id,
        SELECTED_SUITE,
        "selected engine's owning envelope carries the selected-suite vote"
    );

    let mut normalized = sel_decided.vote().clone();
    normalized.suite_id = def_decided.vote().suite_id;
    assert_eq!(
        &normalized,
        def_decided.vote(),
        "the owning envelope's vote differs from the default ONLY in suite_id"
    );
}

// ===========================================================================
// 5. Shared ingestion behaviour preserved across routes with selection active.
// ===========================================================================

/// Observer that records the single observed decision's lock view.
struct RecordingObserver {
    calls: usize,
    locked_view: Option<u64>,
}
impl SafetyDecisionObserver<[u8; 32]> for RecordingObserver {
    fn observe(&mut self, d: &SafetyDecisionView<'_, [u8; 32]>) {
        self.calls += 1;
        self.locked_view = d.locked_view();
    }
}

/// Allowing plain gate (veto-only) for the gated route.
struct AllowGate {
    calls: usize,
}
impl SafetyDecisionGate<[u8; 32]> for AllowGate {
    fn evaluate(&mut self, _d: &SafetyDecisionView<'_, [u8; 32]>) -> Result<(), SafetyGateRefusal> {
        self.calls += 1;
        Ok(())
    }
}

#[test]
fn observed_and_gated_routes_preserve_behaviour_and_stamp_selected_suite() {
    // Observed route: the self-vote still broadcasts and carries the selected
    // suite; the observer fires once at the real decision (lock L0 in effect).
    let (mut engine, p1) = engine_and_safe_view1_proposal(suite_selected_engine(1));
    let mut obs = RecordingObserver {
        calls: 0,
        locked_view: None,
    };
    let action = engine.on_proposal_event_observed(ValidatorId(1), &p1, &mut obs);
    match action {
        Some(ConsensusEngineAction::BroadcastVote(v)) => {
            assert_eq!(v.suite_id, SELECTED_SUITE, "observed route stamps selection");
            assert_eq!(v.height, 1);
        }
        other => panic!("expected observed self-vote, got {other:?}"),
    }
    assert_eq!(obs.calls, 1, "observer fires exactly once at the decision");
    assert_eq!(
        obs.locked_view,
        Some(0),
        "the observed decision sees L0 before the self-vote raises the lock"
    );

    // Gated route: an allowing gate yields the same outgoing self-vote with the
    // selected suite, and the gate is consulted exactly once.
    let (mut engine2, p1b) = engine_and_safe_view1_proposal(suite_selected_engine(1));
    let mut gate = AllowGate { calls: 0 };
    let action = engine2
        .on_proposal_event_gated(ValidatorId(1), &p1b, &mut gate)
        .expect("allowing gate does not refuse");
    match action {
        Some(ConsensusEngineAction::BroadcastVote(v)) => {
            assert_eq!(v.suite_id, SELECTED_SUITE, "gated route stamps selection");
        }
        other => panic!("expected gated self-vote, got {other:?}"),
    }
    assert_eq!(gate.calls, 1, "gate consulted exactly once");
    assert_eq!(
        engine2.locked_qc().map(|q| q.view),
        Some(1),
        "a single view-1 self-vote at n=1 forms a QC and raises the lock to L1",
    );
}

// ===========================================================================
// 6. Verified route: shared ingestion still self-votes with the selected suite,
//    and retains the verified entrypoint distinction.
// ===========================================================================

#[derive(Debug, Default)]
struct TestKeyProvider {
    keys: std::collections::HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}
impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).cloned()
    }
}

struct VerifiedFixture {
    validators: ConsensusValidatorSet,
    kp: TestKeyProvider,
    sks: std::collections::HashMap<ValidatorId, Vec<u8>>,
}

fn verified_fixture(n: u64) -> VerifiedFixture {
    let mut keys = std::collections::HashMap::new();
    let mut sks = std::collections::HashMap::new();
    let mut entries = Vec::new();
    for id in 1..=n {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        keys.insert(ValidatorId(id), (SUITE_PQ_RESERVED_1, pk));
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
        suite_id: SELECTED_SUITE,
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
fn verified_route_self_votes_with_selected_suite_and_marks_verified_entrypoint() {
    let f = verified_fixture(4);
    let justified_block = [0x55u8; 32];
    let d = domain_for([3u8; 32]);
    let wire_qc = build_signed_qc(&f, &d, justified_block, 0, &[1, 2, 3]);
    let registry = SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend));
    let verified =
        verify_quorum_certificate_with_domain(&wire_qc, &d, 0, &f.validators, &f.kp, &registry)
            .expect("quorum verifies");
    let evidence = Arc::new(verified);

    // A suite-selected engine processes a verified proposal at view 0; the
    // shared ingestion body self-votes and the outgoing vote carries the
    // selected suite. The observer confirms the verified entrypoint.
    let mut engine = BasicHotStuffEngine::with_state_limits_and_vote_suite(
        ValidatorId(1),
        f.validators.clone(),
        ConsensusLimitsConfig::default(),
        SELECTED_SUITE,
    );
    let mut proposal = make_proposal(0, [0xFF; 32], 1);
    proposal.qc = Some(evidence.certificate().clone());

    struct VerifiedObserver {
        verified_entrypoint: Option<bool>,
    }
    impl SafetyDecisionObserver<[u8; 32]> for VerifiedObserver {
        fn observe(&mut self, d: &SafetyDecisionView<'_, [u8; 32]>) {
            self.verified_entrypoint = Some(d.is_verified_entrypoint());
        }
    }
    let mut obs = VerifiedObserver {
        verified_entrypoint: None,
    };

    let action = engine
        .on_verified_proposal_event_observed(
            ValidatorId(1),
            &proposal,
            Arc::clone(&evidence),
            &mut obs,
        )
        .expect("verified pre-checks pass");
    match action {
        Some(ConsensusEngineAction::BroadcastVote(v)) => {
            assert_eq!(
                v.suite_id, SELECTED_SUITE,
                "verified route stamps the selected outgoing Vote suite"
            );
            assert_eq!(v.height, 0);
        }
        other => panic!("expected verified self-vote, got {other:?}"),
    }
    assert_eq!(
        obs.verified_entrypoint,
        Some(true),
        "the verified entrypoint distinction is preserved under selection"
    );
}