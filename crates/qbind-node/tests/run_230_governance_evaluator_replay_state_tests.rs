//! Run 230 — source/test governance evaluator **replay and freshness state
//! boundary** tests.
//!
//! Source/test only. Run 230 captures **no** release-binary evidence;
//! release-binary replay/freshness evidence is deferred to **Run 231**. These
//! tests prove that the typed, pure replay/freshness state boundary
//! ([`classify_evaluator_replay_freshness`] /
//! [`evaluate_evaluator_replay_freshness`]) distinguishes fresh / not-yet-
//! effective / expired / stale / replay / already-consumed / superseded /
//! wrong-binding / unavailable states before any mutation, that the
//! DevNet/TestNet [`FixtureReplayStateStore`] records a consumed decision only
//! on an explicit consume call (read-only validation never consumes), that the
//! production / MainNet readers are callable but unavailable / fail-closed, and
//! that MainNet peer-driven apply remains refused even when the state is fresh.
//!
//! Coverage: A1–A16, R1–R32, deterministic digest tests, first-seen / replay /
//! already-consumed / superseded, effective/expiry epoch, read-only-does-not-
//! consume, explicit-consume-marks-consumed, production/MainNet unavailable,
//! no-mutation, MainNet refusal, and compatibility with the Run 228 / 226 /
//! 224 / 222 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_230.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_peer_context::{
    GovernanceEvaluatorPeerContext, PeerEvaluatorContextSurface,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    classify_evaluator_replay_freshness, consumed_decision_digest, evaluate_evaluator_replay_freshness,
    freshness_transcript_digest, gate_evaluator_replay_freshness,
    local_operator_cannot_satisfy_replay_state_policy,
    mainnet_peer_driven_apply_remains_refused_under_replay_state,
    peer_majority_cannot_satisfy_replay_state_policy,
    policy_change_action_remains_unsupported_under_replay_state, replay_observation_digest,
    replay_state_key_digest, validator_set_rotation_remains_unsupported_under_replay_state,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, FixtureReplayStateStore,
    GovernanceEvaluatorReplayStateReader, GovernanceEvaluatorReplayStateWriter,
    MainnetReplayStateReader, PreviouslySeenState, ProductionReplayStateReader,
    ReplayFreshnessState, ReplayStateGateOutcome, ReplayStatePolicy, SeenDecisionRecord,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 / 228 corpora).
// ===========================================================================

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const GOV_PROOF: &str = "governance-proof-digest-bbbbbbbbbbbbbbbb";
const NONCE: &str = "replay-nonce-cccccccccccccccccccccccccc";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SOURCE_ID: &str = "decision-source-0001";
const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const TRANSCRIPT_DIGEST: &str = "evaluator-transcript-digest-iiiiiiiiiiii";
const COMMIT: &str = "response-commitment-eeeeeeeeeeeeeeeeeeee";

const EFFECTIVE: u64 = 100;
const EXPIRY: u64 = 200;
const SEQUENCE: u64 = 7;

// ===========================================================================
// Run 222 evaluator material
// ===========================================================================

fn ev_identity(env: TrustBundleEnvironment) -> DecisionSourceIdentity {
    DecisionSourceIdentity {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        source_kind: EvaluatorSourceKind::FixtureDecisionSource,
        source_id: SOURCE_ID.to_string(),
        governance_class: GovernanceExecutionClass::FixtureGovernance,
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        environment: env,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        freshness_replay_window: 200,
    }
}

fn ev_request(identity: &DecisionSourceIdentity) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: "governance-execution-input-digest-jjjj".to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn ev_response(request: &EvaluatorRequest) -> EvaluatorResponse {
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: SEQUENCE,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: EFFECTIVE,
        response_expiry_epoch: EXPIRY,
        emergency_flag: false,
        response_commitment: COMMIT.to_string(),
    }
}

// ===========================================================================
// Run 230 input + expectations builders
// ===========================================================================

fn expectations(
    env: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
) -> EvaluatorReplayFreshnessExpectations {
    let identity = ev_identity(env);
    let request = ev_request(&identity);
    let response = ev_response(&request);
    EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
    )
}

fn input_with(
    env: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
    current_canonical_epoch: u64,
    previously_seen: PreviouslySeenState,
) -> EvaluatorReplayFreshnessInput {
    let identity = ev_identity(env);
    let request = ev_request(&identity);
    let response = ev_response(&request);
    EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
        current_canonical_epoch,
        previously_seen,
    )
}

/// Default DevNet first-seen, mutating-but-not-peer-driven surface, canonical
/// epoch in the middle of the freshness window.
fn devnet_fresh_input() -> EvaluatorReplayFreshnessInput {
    input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    )
}

fn devnet_exp() -> EvaluatorReplayFreshnessExpectations {
    expectations(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}

// ===========================================================================
// Accepted scenarios A1–A16
// ===========================================================================

#[test]
fn a1_devnet_fixture_accepts_first_seen_fresh() {
    let store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let mut input = devnet_fresh_input();
    input.previously_seen = store.read_for(&input);
    assert_eq!(input.previously_seen, PreviouslySeenState::FirstSeen);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::ProceedFresh
    );
}

#[test]
fn a2_testnet_fixture_accepts_first_seen_fresh() {
    let store = FixtureReplayStateStore::new(TrustBundleEnvironment::Testnet);
    let exp = expectations(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let mut input = input_with(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    );
    input.previously_seen = store.read_for(&input);
    assert_eq!(input.previously_seen, PreviouslySeenState::FirstSeen);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::ProceedFresh
    );
}

#[test]
fn a3_fresh_but_not_yet_effective_is_deferred() {
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        50, // before effective (100)
        PreviouslySeenState::FirstSeen,
    );
    let outcome = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
    assert_eq!(outcome, EvaluatorReplayFreshnessOutcome::ProceedDeferred);
    // A deferral is NOT an approval for mutation.
    assert!(!outcome.authorizes_mutation());
    assert!(outcome.is_deferred());
    assert_eq!(
        classify_evaluator_replay_freshness(&input, &devnet_exp()),
        ReplayFreshnessState::FreshButNotYetEffective
    );
}

#[test]
fn a4_decision_at_effective_epoch_is_fresh() {
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE, // exactly at effective
        PreviouslySeenState::FirstSeen,
    );
    let outcome = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
    assert_eq!(outcome, EvaluatorReplayFreshnessOutcome::ProceedFresh);
    assert!(outcome.authorizes_mutation());
}

#[test]
fn a5_decision_before_expiry_is_fresh() {
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EXPIRY - 1, // last fresh epoch
        PreviouslySeenState::FirstSeen,
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::ProceedFresh
    );
}

#[test]
fn a6_replay_state_key_digest_deterministic() {
    let input = devnet_fresh_input();
    assert_eq!(replay_state_key_digest(&input), replay_state_key_digest(&input));
}

#[test]
fn a7_replay_observation_digest_deterministic() {
    let input = devnet_fresh_input();
    assert_eq!(
        replay_observation_digest(&input, 1, 150),
        replay_observation_digest(&input, 1, 150)
    );
    assert_ne!(
        replay_observation_digest(&input, 1, 150),
        replay_observation_digest(&input, 2, 150)
    );
}

#[test]
fn a8_consumed_decision_digest_deterministic() {
    let input = devnet_fresh_input();
    assert_eq!(
        consumed_decision_digest(&input, 150),
        consumed_decision_digest(&input, 150)
    );
    assert_ne!(
        consumed_decision_digest(&input, 150),
        consumed_decision_digest(&input, 151)
    );
}

#[test]
fn a9_freshness_transcript_digest_deterministic() {
    let input = devnet_fresh_input();
    assert_eq!(
        freshness_transcript_digest(&input, ReplayFreshnessState::Fresh),
        freshness_transcript_digest(&input, ReplayFreshnessState::Fresh)
    );
    assert_ne!(
        freshness_transcript_digest(&input, ReplayFreshnessState::Fresh),
        freshness_transcript_digest(&input, ReplayFreshnessState::Expired)
    );
}

#[test]
fn a10_replay_state_key_binds_all_required_fields() {
    let base = devnet_fresh_input();
    let base_key = replay_state_key_digest(&base);

    // Each of the 12 bound fields changes the key digest.
    let mut m = base.clone();
    m.environment = TrustBundleEnvironment::Testnet;
    assert_ne!(replay_state_key_digest(&m), base_key, "environment");

    let mut m = base.clone();
    m.chain_id = "other-chain".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "chain_id");

    let mut m = base.clone();
    m.genesis_hash = "other-genesis".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "genesis_hash");

    let mut m = base.clone();
    m.evaluator_source_identity_digest = "other-src".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "source identity");

    let mut m = base.clone();
    m.evaluator_request_digest = "other-req".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "request digest");

    let mut m = base.clone();
    m.evaluator_response_digest = "other-resp".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "response digest");

    let mut m = base.clone();
    m.proposal_id = "other-proposal".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "proposal id");

    let mut m = base.clone();
    m.decision_id = "other-decision".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "decision id");

    let mut m = base.clone();
    m.lifecycle_action = LocalLifecycleAction::Revoke;
    assert_ne!(replay_state_key_digest(&m), base_key, "lifecycle action");

    let mut m = base.clone();
    m.candidate_digest = "other-candidate".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "candidate digest");

    let mut m = base.clone();
    m.authority_domain_sequence = SEQUENCE + 1;
    assert_ne!(replay_state_key_digest(&m), base_key, "sequence");

    let mut m = base.clone();
    m.replay_nonce = "other-nonce".to_string();
    assert_ne!(replay_state_key_digest(&m), base_key, "replay nonce");
}

#[test]
fn a11_fixture_writer_records_consumed_only_after_explicit_consume() {
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let input = devnet_fresh_input();
    let key = replay_state_key_digest(&input);

    // Record an observation: present but NOT consumed.
    store.record_for(&input);
    assert!(!store.is_consumed(&key));

    // Explicit consume marks consumed.
    assert!(store.consume_for(&input));
    assert!(store.is_consumed(&key));
}

#[test]
fn a12_read_only_validation_does_not_mark_consumed() {
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let input = devnet_fresh_input();
    let key = replay_state_key_digest(&input);
    store.record_for(&input);

    // Many reads must never mark consumed.
    for _ in 0..5 {
        let _ = store.read_for(&input);
        let _ = store.read_previous_state(&key);
    }
    assert!(!store.is_consumed(&key));
}

#[test]
fn a13_production_reader_callable_returns_unavailable() {
    let reader = ProductionReplayStateReader;
    let mut input = devnet_fresh_input();
    input.previously_seen = reader.read_previous_state(&replay_state_key_digest(&input));
    assert_eq!(input.previously_seen, PreviouslySeenState::ProductionUnavailable);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedProductionUnavailable
    );
}

#[test]
fn a14_mainnet_reader_callable_returns_unavailable() {
    let reader = MainnetReplayStateReader;
    // Use a non-peer-driven surface so the MainNet *peer-driven* guard does not
    // mask the reader-unavailable path.
    let exp = expectations(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let mut input = input_with(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    );
    input.previously_seen = reader.read_previous_state(&replay_state_key_digest(&input));
    assert_eq!(input.previously_seen, PreviouslySeenState::MainNetUnavailable);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable
    );
}

#[test]
fn a15_run224_compatible_when_policy_disabled() {
    // When the replay-state policy is Disabled the boundary is NOT wired, so
    // the Run 224 integration layer behaves exactly as before.
    let input = devnet_fresh_input();
    let gate = gate_evaluator_replay_freshness(ReplayStatePolicy::Disabled, &input, &devnet_exp());
    assert_eq!(gate, ReplayStateGateOutcome::NotWired);
    assert!(gate.is_not_wired());

    // A wired fixture policy does evaluate.
    let wired =
        gate_evaluator_replay_freshness(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(
        wired,
        ReplayStateGateOutcome::Evaluated(EvaluatorReplayFreshnessOutcome::ProceedFresh)
    );
}

#[test]
fn a16_run228_peer_context_compatible_when_policy_disabled() {
    // A Run 228 peer evaluator context is unchanged; deriving a replay input
    // that references its bound digests and gating with Disabled is NotWired.
    let peer = GovernanceEvaluatorPeerContext::absent(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
    );
    // The peer context's own digest remains stable/usable.
    assert_eq!(peer.context_digest(), peer.context_digest());

    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LiveInbound0x05,
        150,
        PreviouslySeenState::FirstSeen,
    );
    let exp = expectations(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LiveInbound0x05,
    );
    assert_eq!(
        gate_evaluator_replay_freshness(ReplayStatePolicy::Disabled, &input, &exp),
        ReplayStateGateOutcome::NotWired
    );
}

// ===========================================================================
// Rejection scenarios R1–R32
// ===========================================================================

fn seen_record(key: &str) -> SeenDecisionRecord {
    SeenDecisionRecord {
        state_key_digest: key.to_string(),
        replay_nonce: NONCE.to_string(),
        recorded_sequence: SEQUENCE,
        recorded_effective_epoch: EFFECTIVE,
        recorded_expiry_epoch: EXPIRY,
        observation_count: 1,
        consumed: false,
        superseded: false,
    }
}

#[test]
fn r1_expired_rejected() {
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EXPIRY, // at/after expiry
        PreviouslySeenState::FirstSeen,
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedExpired(ReplayFreshnessState::Expired)
    );
}

#[test]
fn r2_stale_rejected() {
    // Degenerate window: expiry <= effective. Build matching expectations.
    let mut input = devnet_fresh_input();
    input.effective_epoch = 200;
    input.expiry_epoch = 100;
    let mut exp = devnet_exp();
    exp.expected_effective_epoch = 200;
    exp.expected_expiry_epoch = 100;
    assert_eq!(
        classify_evaluator_replay_freshness(&input, &exp),
        ReplayFreshnessState::Stale
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::FailClosedExpired(ReplayFreshnessState::Stale)
    );
}

#[test]
fn r3_replay_rejected() {
    let key = replay_state_key_digest(&devnet_fresh_input());
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::Seen(seen_record(&key)),
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedReplay
    );
}

#[test]
fn r4_already_consumed_rejected() {
    let key = replay_state_key_digest(&devnet_fresh_input());
    let mut record = seen_record(&key);
    record.consumed = true;
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::Seen(record),
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed
    );
}

#[test]
fn r5_superseded_rejected() {
    let key = replay_state_key_digest(&devnet_fresh_input());
    let mut record = seen_record(&key);
    record.superseded = true;
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::Seen(record),
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedSuperseded
    );
}

#[test]
fn r5b_higher_recorded_sequence_is_superseded() {
    let key = replay_state_key_digest(&devnet_fresh_input());
    let mut record = seen_record(&key);
    record.recorded_sequence = SEQUENCE + 1; // a newer decision exists
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::Seen(record),
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedSuperseded
    );
}

/// Helper: assert a single-field mutation is rejected as a wrong binding with
/// the expected classified state.
fn assert_wrong_binding(
    mutate: impl FnOnce(&mut EvaluatorReplayFreshnessInput),
    expected_state: ReplayFreshnessState,
) {
    let mut input = devnet_fresh_input();
    mutate(&mut input);
    let outcome = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
    match outcome {
        EvaluatorReplayFreshnessOutcome::FailClosedWrongBinding { state, .. } => {
            assert_eq!(state, expected_state);
        }
        other => panic!("expected wrong-binding {:?}, got {:?}", expected_state, other),
    }
}

#[test]
fn r6_wrong_effective_epoch_rejected() {
    assert_wrong_binding(|i| i.effective_epoch = 101, ReplayFreshnessState::WrongEpoch);
}

#[test]
fn r7_wrong_expiry_epoch_rejected() {
    assert_wrong_binding(|i| i.expiry_epoch = 201, ReplayFreshnessState::WrongEpoch);
}

#[test]
fn r8_wrong_environment_rejected() {
    assert_wrong_binding(
        |i| i.environment = TrustBundleEnvironment::Testnet,
        ReplayFreshnessState::WrongEnvironment,
    );
}

#[test]
fn r9_wrong_chain_rejected() {
    assert_wrong_binding(
        |i| i.chain_id = "wrong-chain".to_string(),
        ReplayFreshnessState::WrongChain,
    );
}

#[test]
fn r10_wrong_genesis_rejected() {
    assert_wrong_binding(
        |i| i.genesis_hash = "wrong-genesis".to_string(),
        ReplayFreshnessState::WrongGenesis,
    );
}

#[test]
fn r11_wrong_surface_rejected() {
    assert_wrong_binding(
        |i| i.validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck,
        ReplayFreshnessState::WrongSurface,
    );
}

#[test]
fn r12_wrong_source_identity_digest_rejected() {
    assert_wrong_binding(
        |i| i.evaluator_source_identity_digest = "wrong-src".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r13_wrong_request_digest_rejected() {
    assert_wrong_binding(
        |i| i.evaluator_request_digest = "wrong-req".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r14_wrong_response_digest_rejected() {
    assert_wrong_binding(
        |i| i.evaluator_response_digest = "wrong-resp".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r15_wrong_transcript_digest_rejected() {
    assert_wrong_binding(
        |i| i.evaluator_transcript_digest = "wrong-transcript".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r16_wrong_proposal_id_rejected() {
    assert_wrong_binding(
        |i| i.proposal_id = "wrong-proposal".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r17_wrong_decision_id_rejected() {
    assert_wrong_binding(
        |i| i.decision_id = "wrong-decision".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r18_wrong_lifecycle_action_rejected() {
    assert_wrong_binding(
        |i| i.lifecycle_action = LocalLifecycleAction::Revoke,
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r19_wrong_candidate_digest_rejected() {
    assert_wrong_binding(
        |i| i.candidate_digest = "wrong-candidate".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r20_wrong_authority_domain_sequence_rejected() {
    assert_wrong_binding(
        |i| i.authority_domain_sequence = SEQUENCE + 9,
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r21_wrong_replay_nonce_rejected() {
    assert_wrong_binding(
        |i| i.replay_nonce = "wrong-nonce".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r22_malformed_state_rejected() {
    // Empty mandatory field is structurally malformed.
    assert_wrong_binding(
        |i| i.replay_nonce = String::new(),
        ReplayFreshnessState::MalformedState,
    );
}

#[test]
fn r23_state_unavailable_rejected() {
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::Unavailable,
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedStateUnavailable
    );
}

#[test]
fn r24_production_state_unavailable_rejected() {
    let input = input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::ProductionUnavailable,
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        EvaluatorReplayFreshnessOutcome::FailClosedProductionUnavailable
    );
}

#[test]
fn r25_mainnet_state_unavailable_rejected() {
    let exp = expectations(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = input_with(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::MainNetUnavailable,
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable
    );
}

#[test]
fn r26_local_operator_cannot_satisfy_replay_state_policy() {
    assert!(local_operator_cannot_satisfy_replay_state_policy());
}

#[test]
fn r27_peer_majority_cannot_satisfy_replay_state_policy() {
    assert!(peer_majority_cannot_satisfy_replay_state_policy());
}

#[test]
fn r28_validator_set_rotation_unsupported() {
    assert!(validator_set_rotation_remains_unsupported_under_replay_state());
}

#[test]
fn r29_policy_change_action_unsupported() {
    assert!(policy_change_action_remains_unsupported_under_replay_state());
}

#[test]
fn r30_validation_only_rejection_writes_no_marker_no_sequence() {
    // A validation-only rejection (wrong binding) must not record anything in
    // the fixture store: the boundary is pure and the store is untouched.
    let store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let mut input = devnet_fresh_input();
    input.chain_id = "wrong-chain".to_string();
    let outcome = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
    assert!(outcome.is_fail_closed());
    // No write happened: the store is still empty (no marker / no sequence).
    assert!(store.is_empty());
}

#[test]
fn r31_mutating_rejection_produces_no_mutation() {
    // Every fail-closed outcome leaves no mutation authorized (no Run 070, no
    // live trust swap, no session eviction, no sequence write, no marker write
    // — none can happen because nothing authorizes mutation).
    let cases = [
        evaluate_evaluator_replay_freshness(
            &input_with(
                TrustBundleEnvironment::Devnet,
                GovernanceExecutionRuntimeSurface::ReloadApply,
                EXPIRY,
                PreviouslySeenState::FirstSeen,
            ),
            &devnet_exp(),
        ),
        evaluate_evaluator_replay_freshness(
            &input_with(
                TrustBundleEnvironment::Devnet,
                GovernanceExecutionRuntimeSurface::ReloadApply,
                150,
                PreviouslySeenState::Unavailable,
            ),
            &devnet_exp(),
        ),
    ];
    for outcome in cases {
        assert!(outcome.is_fail_closed());
        assert!(!outcome.authorizes_mutation());
        assert!(outcome.no_mutation());
    }
}

#[test]
fn r32_mainnet_peer_driven_apply_refused_even_when_fresh() {
    // A peer-driven drain surface on a MainNet trust domain is refused before
    // any freshness reasoning — even with a first-seen, in-window decision.
    let exp = expectations(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input = input_with(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        150, // squarely within the freshness window
        PreviouslySeenState::FirstSeen,
    );
    let outcome = evaluate_evaluator_replay_freshness(&input, &exp);
    assert_eq!(
        outcome,
        EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable
    );
    assert!(!outcome.authorizes_mutation());
    assert!(mainnet_peer_driven_apply_remains_refused_under_replay_state(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// First-seen → observe → replay → consume lifecycle (fixture store)
// ===========================================================================

#[test]
fn fixture_lifecycle_first_seen_then_replay_then_consumed() {
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let base = devnet_fresh_input();
    let exp = devnet_exp();

    // 1. First-seen → fresh.
    let mut input = base.clone();
    input.previously_seen = store.read_for(&input);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::ProceedFresh
    );

    // 2. Observe it, then re-present → replay.
    store.record_for(&base);
    let mut input = base.clone();
    input.previously_seen = store.read_for(&input);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::FailClosedReplay
    );

    // 3. Explicit consume, then re-present → already consumed.
    assert!(store.consume_for(&base));
    let mut input = base.clone();
    input.previously_seen = store.read_for(&input);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed
    );
}

#[test]
fn fixture_store_rejects_mainnet_environment() {
    // A DevNet/TestNet fixture store can never serve a MainNet environment.
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let input = input_with(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    );
    assert_eq!(store.read_for(&input), PreviouslySeenState::Unavailable);
    store.record_for(&input);
    assert!(store.is_empty());
}

#[test]
fn production_and_mainnet_writers_never_record() {
    let key = replay_state_key_digest(&devnet_fresh_input());

    let mut prod = ProductionReplayStateReader;
    prod.record_observation(&key, NONCE, SEQUENCE);
    assert!(!prod.mark_consumed(&key));

    let mut main = MainnetReplayStateReader;
    main.record_observation(&key, NONCE, SEQUENCE);
    assert!(!main.mark_consumed(&key));
}