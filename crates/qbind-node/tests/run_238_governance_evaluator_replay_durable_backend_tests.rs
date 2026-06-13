//! Run 238 — source/test governance evaluator **durable replay state backend
//! boundary** tests.
//!
//! Source/test only. Run 238 captures **no** release-binary evidence;
//! release-binary durable-backend evidence is deferred to **Run 239**. These
//! tests prove that the typed, pure durable backend contract
//! ([`observe_decision_if_absent`] / [`read_decision_state`] /
//! [`mark_consumed_after_success`] / [`compare_and_mark_consumed`]) models
//! observed / consumed / replayed / superseded states, restart durability
//! through an explicit fixture snapshot (never a file format), atomic
//! compare-and-mark-consumed, crash-window classification, fail-closed
//! production / MainNet backends, and unconditional MainNet peer-driven apply
//! refusal.
//!
//! Coverage: A1–A22, R1–R37, deterministic digest tests, restart snapshot
//! tests, observed/fresh/deferred/expired/stale/consumed/replay/superseded
//! tests, crash-window classification tests, compare-and-mark-consumed atomicity
//! tests, read-only-validation-does-not-consume tests, production/MainNet
//! unavailable tests, no-mutation tests, MainNet refusal tests, and
//! compatibility with the Run 236 / 234 / 232 / 230 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_238.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_consume_runtime_integration::{
    consume_integrated_as_after_success_only_post_mutation_step,
    fresh_required_before_mutation_authorization_under_consume_runtime,
};
use qbind_node::pqc_governance_evaluator_replay_durable_backend::{
    classify_crash_window, compare_and_mark_consumed, crash_window_transcript_digest,
    durable_backend_key_digest, durable_consume_only_after_successful_mutation,
    durable_operation_transcript_digest, durable_record_digest,
    local_operator_cannot_satisfy_durable_backend_policy,
    mainnet_peer_driven_apply_remains_refused_under_durable_backend, mark_consumed_after_success,
    no_rocksdb_file_schema_migration_change_under_durable_backend, observe_decision_if_absent,
    peer_majority_cannot_satisfy_durable_backend_policy,
    policy_change_action_remains_unsupported_under_durable_backend,
    production_mainnet_durable_backend_remains_unavailable, read_decision_state,
    restart_durability_is_fixture_snapshot_only,
    validator_set_rotation_remains_unsupported_under_durable_backend, CrashWindow,
    CrashWindowObservation, DurableBackendDecisionExpectations, DurableBackendDecisionInput,
    DurableBackendKind, DurableConsumeOutcome, DurableMutationCompletion, DurableBackendOutcome,
    DurableRecordState, FixtureDurableReplayBackend,
    GovernanceEvaluatorReplayDurableBackendReader, MainnetDurableReplayBackend,
    ProductionDurableReplayBackend,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, replay_state_key_digest,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, PreviouslySeenState,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 230 / 234 corpora).
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

const SEQUENCE: u64 = 7;

// ===========================================================================
// Run 222 evaluator material (epoch-parametrized)
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

fn ev_request(identity: &DecisionSourceIdentity, effective: u64, expiry: u64) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: "governance-execution-input-digest-jjjj".to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        effective_epoch: effective,
        expiry_epoch: expiry,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn ev_response(request: &EvaluatorRequest, effective: u64, expiry: u64) -> EvaluatorResponse {
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: SEQUENCE,
        effective_epoch: effective,
        expiry_epoch: expiry,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: effective,
        response_expiry_epoch: expiry,
        emergency_flag: false,
        response_commitment: COMMIT.to_string(),
    }
}

// ===========================================================================
// Run 230 freshness input / Run 238 durable input + expectations builders
// ===========================================================================

fn fresh_in(
    env: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    effective: u64,
    expiry: u64,
    canonical: u64,
) -> EvaluatorReplayFreshnessInput {
    let identity = ev_identity(env);
    let request = ev_request(&identity, effective, expiry);
    let response = ev_response(&request, effective, expiry);
    EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        vs,
        canonical,
        PreviouslySeenState::FirstSeen,
    )
}

fn di(
    env: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    effective: u64,
    expiry: u64,
    canonical: u64,
) -> (
    DurableBackendDecisionInput,
    DurableBackendDecisionExpectations,
) {
    let f = fresh_in(env, vs, effective, expiry, canonical);
    (
        DurableBackendDecisionInput::from_freshness_input(&f, ms),
        DurableBackendDecisionExpectations::from_freshness_input(&f, ms),
    )
}

/// Standard fresh DevNet decision (effective 100, expiry 200, canonical 150).
fn fresh_devnet() -> (
    DurableBackendDecisionInput,
    DurableBackendDecisionExpectations,
) {
    di(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    )
}

fn key_of(input: &DurableBackendDecisionInput) -> String {
    durable_backend_key_digest(input)
}

// ===========================================================================
// A — accepted scenarios A1–A22
// ===========================================================================

#[test]
fn a1_first_seen_devnet_records_observed_fresh() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let outcome =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(outcome, DurableBackendOutcome::ProceedFirstSeen);
    assert_eq!(
        backend.read_durable_state(&key_of(&input)),
        DurableRecordState::ObservedFresh
    );
}

#[test]
fn a2_first_seen_testnet_records_observed_fresh() {
    let (input, exp) = di(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    );
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Testnet);
    let outcome =
        observe_decision_if_absent(DurableBackendKind::FixtureTestNet, &input, &exp, &mut backend);
    assert_eq!(outcome, DurableBackendOutcome::ProceedFirstSeen);
    assert_eq!(
        backend.read_durable_state(&key_of(&input)),
        DurableRecordState::ObservedFresh
    );
}

#[test]
fn a3_known_fresh_reads_proceed_known_fresh() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let outcome = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(outcome, DurableBackendOutcome::ProceedKnownFresh);
    assert!(outcome.authorizes_proceed());
}

#[test]
fn a4_not_yet_effective_is_deferred_and_not_mutation_approval() {
    let (input, exp) = di(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        50, // canonical < effective
    );
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let observe =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(observe, DurableBackendOutcome::ProceedDeferred);
    assert!(observe.is_deferred());
    assert!(!observe.authorizes_proceed());
    assert_eq!(
        backend.read_durable_state(&key_of(&input)),
        DurableRecordState::ObservedDeferred
    );
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::ProceedDeferred);
}

#[test]
fn a5_expired_is_fail_closed_expired() {
    let (input, exp) = di(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        250, // canonical >= expiry
    );
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let observe =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(observe, DurableBackendOutcome::FailClosedExpired);
    assert!(observe.is_fail_closed());
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedExpired);
}

#[test]
fn a6_stale_is_fail_closed_stale() {
    let (input, exp) = di(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        200,
        100, // degenerate window: expiry <= effective
        150,
    );
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let observe =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(observe, DurableBackendOutcome::FailClosedStale);
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedStale);
}

#[test]
fn a7_explicit_consume_after_success_marks_consumed() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let outcome = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::ConsumedAfterSuccess);
    assert!(backend.is_consumed(&key_of(&input)));
}

#[test]
fn a8_same_decision_after_consume_reads_consumed_fail_closed() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedConsumed);
    let observe_again =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(observe_again, DurableBackendOutcome::FailClosedConsumed);
}

#[test]
fn a9_read_only_validation_does_not_mark_consumed() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    for _ in 0..3 {
        let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
        assert_eq!(read, DurableBackendOutcome::ProceedKnownFresh);
    }
    assert!(!backend.is_consumed(&key_of(&input)));
}

#[test]
fn a10_observe_only_survives_restart_snapshot() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let snapshot = backend.restart_snapshot();
    assert_eq!(snapshot.len(), 1);
    let restarted = FixtureDurableReplayBackend::from_snapshot(snapshot);
    assert!(restarted.contains(&key_of(&input)));
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &restarted);
    assert_eq!(read, DurableBackendOutcome::ProceedKnownFresh);
    assert!(!restarted.is_consumed(&key_of(&input)));
}

#[test]
fn a11_consumed_state_survives_restart_snapshot() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    let restarted = FixtureDurableReplayBackend::from_snapshot(backend.restart_snapshot());
    assert!(restarted.is_consumed(&key_of(&input)));
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &restarted);
    assert_eq!(read, DurableBackendOutcome::FailClosedConsumed);
}

#[test]
fn a12_rollback_after_observe_does_not_mark_consumed() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let outcome = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::RolledBack,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedRolledBack);
    assert!(!backend.is_consumed(&key_of(&input)));
}

#[test]
fn a13_apply_failed_after_observe_does_not_mark_consumed() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let outcome = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::ApplyFailed,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedApplyFailed);
    assert!(!backend.is_consumed(&key_of(&input)));
}

#[test]
fn a14_after_mutation_before_consume_window_is_typed_and_not_silently_approved() {
    let obs = CrashWindowObservation {
        backend_kind: DurableBackendKind::FixtureDevNet,
        observed: true,
        mutation_attempted: true,
        mutation_succeeded: true,
        rolled_back: false,
        apply_failed: false,
        consumed: false,
    };
    let window = classify_crash_window(&obs);
    assert_eq!(window, CrashWindow::AfterMutationBeforeConsume);
    assert!(window.is_after_mutation_before_consume());
    assert!(window.requires_fail_closed_recovery());
}

#[test]
fn a15_after_consume_window_reads_consumed_fail_closed_for_repeat() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    let obs = CrashWindowObservation {
        backend_kind: DurableBackendKind::FixtureDevNet,
        observed: true,
        mutation_attempted: true,
        mutation_succeeded: true,
        rolled_back: false,
        apply_failed: false,
        consumed: true,
    };
    assert_eq!(classify_crash_window(&obs), CrashWindow::AfterConsume);
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedConsumed);
}

#[test]
fn a16_durable_backend_key_digest_is_deterministic() {
    let (input, _) = fresh_devnet();
    assert_eq!(durable_backend_key_digest(&input), durable_backend_key_digest(&input));
    let mut other = input.clone();
    other.replay_nonce = "different-nonce".to_string();
    assert_ne!(durable_backend_key_digest(&input), durable_backend_key_digest(&other));
}

#[test]
fn a17_durable_record_digest_is_deterministic() {
    let (input, _) = fresh_devnet();
    let a = durable_record_digest(&input, DurableRecordState::ObservedFresh, 1);
    let b = durable_record_digest(&input, DurableRecordState::ObservedFresh, 1);
    assert_eq!(a, b);
    let c = durable_record_digest(&input, DurableRecordState::Consumed, 1);
    assert_ne!(a, c);
}

#[test]
fn a18_durable_operation_transcript_digest_is_deterministic() {
    let (input, _) = fresh_devnet();
    let a = durable_operation_transcript_digest(&input, "observe", "proceed-first-seen");
    let b = durable_operation_transcript_digest(&input, "observe", "proceed-first-seen");
    assert_eq!(a, b);
    let c = durable_operation_transcript_digest(&input, "observe", "fail-closed-replay");
    assert_ne!(a, c);
}

#[test]
fn a19_crash_window_transcript_digest_is_deterministic() {
    let (input, _) = fresh_devnet();
    let obs = CrashWindowObservation {
        backend_kind: DurableBackendKind::FixtureDevNet,
        observed: true,
        mutation_attempted: true,
        mutation_succeeded: true,
        rolled_back: false,
        apply_failed: false,
        consumed: false,
    };
    let a = crash_window_transcript_digest(&input, &obs, CrashWindow::AfterMutationBeforeConsume);
    let b = crash_window_transcript_digest(&input, &obs, CrashWindow::AfterMutationBeforeConsume);
    assert_eq!(a, b);
    let c = crash_window_transcript_digest(&input, &obs, CrashWindow::AfterConsume);
    assert_ne!(a, c);
}

#[test]
fn a20_production_durable_backend_callable_fails_closed_unavailable() {
    let (input, exp) = di(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    );
    let mut backend = ProductionDurableReplayBackend;
    assert_eq!(
        read_decision_state(DurableBackendKind::Production, &input, &exp, &backend),
        DurableBackendOutcome::FailClosedProductionUnavailable
    );
    assert_eq!(
        observe_decision_if_absent(DurableBackendKind::Production, &input, &exp, &mut backend),
        DurableBackendOutcome::FailClosedProductionUnavailable
    );
    assert_eq!(
        mark_consumed_after_success(
            DurableBackendKind::Production,
            &input,
            &exp,
            DurableMutationCompletion::AppliedSuccessfully,
            &mut backend,
        ),
        DurableConsumeOutcome::FailClosedProductionUnavailable
    );
    assert!(production_mainnet_durable_backend_remains_unavailable());
}

#[test]
fn a21_mainnet_durable_backend_callable_fails_closed_unavailable() {
    let (input, exp) = di(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    );
    let mut backend = MainnetDurableReplayBackend;
    assert_eq!(
        read_decision_state(DurableBackendKind::MainNet, &input, &exp, &backend),
        DurableBackendOutcome::FailClosedMainNetUnavailable
    );
    assert_eq!(
        observe_decision_if_absent(DurableBackendKind::MainNet, &input, &exp, &mut backend),
        DurableBackendOutcome::FailClosedMainNetUnavailable
    );
    assert_eq!(
        mark_consumed_after_success(
            DurableBackendKind::MainNet,
            &input,
            &exp,
            DurableMutationCompletion::AppliedSuccessfully,
            &mut backend,
        ),
        DurableConsumeOutcome::FailClosedMainNetUnavailable
    );
}

#[test]
fn a22_run236_consume_runtime_integration_remains_compatible_when_durable_not_wired() {
    // Run 238 adds the durable backend boundary as an independent module. Not
    // wiring it leaves the Run 236 consume runtime integration invariants intact.
    assert!(consume_integrated_as_after_success_only_post_mutation_step());
    assert!(fresh_required_before_mutation_authorization_under_consume_runtime());
    // And the durable key composes from the same Run 230 replay-state key.
    let f = fresh_in(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    );
    let input = DurableBackendDecisionInput::from_freshness_input(
        &f,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    assert_eq!(input.replay_state_key_digest, replay_state_key_digest(&f));
}

// ===========================================================================
// R — rejection scenarios R1–R37
// ===========================================================================

/// Observe a tampered input against canonical expectations and assert the
/// boundary fails closed malformed without recording anything.
fn assert_wrong_binding_rejected(mut tamper: impl FnMut(&mut DurableBackendDecisionInput)) {
    let (mut input, exp) = fresh_devnet();
    tamper(&mut input);
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let outcome =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(outcome, DurableBackendOutcome::FailClosedMalformedRecord);
    assert!(backend.is_empty());
}

#[test]
fn r1_wrong_replay_state_key_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.replay_state_key_digest = "wrong".to_string());
}

#[test]
fn r2_wrong_source_identity_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.evaluator_source_identity_digest = "wrong".to_string());
}

#[test]
fn r3_wrong_request_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.evaluator_request_digest = "wrong".to_string());
}

#[test]
fn r4_wrong_response_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.evaluator_response_digest = "wrong".to_string());
}

#[test]
fn r5_wrong_transcript_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.evaluator_transcript_digest = "wrong".to_string());
}

#[test]
fn r6_wrong_decision_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.governance_execution_decision_digest = "wrong".to_string());
}

#[test]
fn r7_wrong_proposal_id_rejected() {
    assert_wrong_binding_rejected(|i| i.proposal_id = "wrong".to_string());
}

#[test]
fn r8_wrong_decision_id_rejected() {
    assert_wrong_binding_rejected(|i| i.decision_id = "wrong".to_string());
}

#[test]
fn r9_wrong_lifecycle_action_rejected() {
    assert_wrong_binding_rejected(|i| i.lifecycle_action = LocalLifecycleAction::Retire);
}

#[test]
fn r10_wrong_candidate_digest_rejected() {
    assert_wrong_binding_rejected(|i| i.candidate_digest = "wrong".to_string());
}

#[test]
fn r11_wrong_authority_domain_sequence_rejected() {
    assert_wrong_binding_rejected(|i| i.authority_domain_sequence = 999);
}

#[test]
fn r12_wrong_effective_epoch_rejected() {
    assert_wrong_binding_rejected(|i| i.effective_epoch = 999);
}

#[test]
fn r13_wrong_expiry_epoch_rejected() {
    assert_wrong_binding_rejected(|i| i.expiry_epoch = 999);
}

#[test]
fn r14_wrong_replay_nonce_rejected() {
    assert_wrong_binding_rejected(|i| i.replay_nonce = "wrong".to_string());
}

#[test]
fn r15_wrong_environment_rejected() {
    assert_wrong_binding_rejected(|i| i.environment = TrustBundleEnvironment::Testnet);
}

#[test]
fn r16_wrong_chain_rejected() {
    assert_wrong_binding_rejected(|i| i.chain_id = "wrong".to_string());
}

#[test]
fn r17_wrong_genesis_rejected() {
    assert_wrong_binding_rejected(|i| i.genesis_hash = "wrong".to_string());
}

#[test]
fn r18_wrong_validation_surface_rejected() {
    assert_wrong_binding_rejected(|i| {
        i.validation_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn r19_wrong_mutation_surface_rejected() {
    assert_wrong_binding_rejected(|i| {
        i.mutation_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn r20_malformed_backend_record_rejected() {
    assert_wrong_binding_rejected(|i| i.replay_nonce = String::new());
}

#[test]
fn r21_replay_detected_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let again =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(again, DurableBackendOutcome::FailClosedReplay);
}

#[test]
fn r22_consumed_decision_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    let again =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(again, DurableBackendOutcome::FailClosedConsumed);
}

#[test]
fn r23_superseded_decision_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert!(backend.mark_superseded(&key_of(&input)));
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedSuperseded);
    let observe =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(observe, DurableBackendOutcome::FailClosedSuperseded);
}

#[test]
fn r24_backend_unavailable_rejected() {
    // A fixture kind on a MainNet environment has no available backend.
    let (input, exp) = di(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    );
    let backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let read = read_decision_state(DurableBackendKind::FixtureDevNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedBackendUnavailable);
}

#[test]
fn r25_production_backend_unavailable_rejected() {
    let (input, exp) = fresh_devnet();
    let backend = ProductionDurableReplayBackend;
    let read = read_decision_state(DurableBackendKind::Production, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedProductionUnavailable);
}

#[test]
fn r26_mainnet_backend_unavailable_refused_rejected() {
    let (input, exp) = di(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    );
    let backend = MainnetDurableReplayBackend;
    let read = read_decision_state(DurableBackendKind::MainNet, &input, &exp, &backend);
    assert_eq!(read, DurableBackendOutcome::FailClosedMainNetUnavailable);
}

#[test]
fn r27_compare_and_mark_consumed_wrong_expected_state_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    // Current state is ObservedFresh; expect ObservedDeferred -> rejected.
    let outcome = compare_and_mark_consumed(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableRecordState::ObservedDeferred,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedWrongExpectedState);
    assert!(!backend.is_consumed(&key_of(&input)));
    // The correct expected state succeeds atomically.
    let ok = compare_and_mark_consumed(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableRecordState::ObservedFresh,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    assert_eq!(ok, DurableConsumeOutcome::ConsumedAfterSuccess);
    assert!(backend.is_consumed(&key_of(&input)));
}

#[test]
fn r28_consume_before_observe_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let outcome = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedNotObserved);
    assert!(backend.is_empty());
}

#[test]
fn r29_consume_before_successful_mutation_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    for completion in [
        DurableMutationCompletion::NotAttempted,
        DurableMutationCompletion::AuthorizedButNotApplied,
    ] {
        let outcome = mark_consumed_after_success(
            DurableBackendKind::FixtureDevNet,
            &input,
            &exp,
            completion,
            &mut backend,
        );
        assert_eq!(outcome, DurableConsumeOutcome::RejectedNotSuccessfulMutation);
    }
    assert!(!backend.is_consumed(&key_of(&input)));
}

#[test]
fn r30_consume_after_failed_apply_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let outcome = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::ApplyFailed,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedApplyFailed);
    assert!(!backend.is_consumed(&key_of(&input)));
}

#[test]
fn r31_consume_after_rollback_rejected() {
    let (input, exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    let outcome = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &input,
        &exp,
        DurableMutationCompletion::RolledBack,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedRolledBack);
    assert!(!backend.is_consumed(&key_of(&input)));
}

#[test]
fn r32_local_operator_cannot_satisfy_durable_backend_policy() {
    assert!(local_operator_cannot_satisfy_durable_backend_policy());
}

#[test]
fn r33_peer_majority_cannot_satisfy_durable_backend_policy() {
    assert!(peer_majority_cannot_satisfy_durable_backend_policy());
}

#[test]
fn r34_validator_set_rotation_unsupported_rejected() {
    assert!(validator_set_rotation_remains_unsupported_under_durable_backend());
}

#[test]
fn r35_policy_change_action_unsupported_rejected() {
    assert!(policy_change_action_remains_unsupported_under_durable_backend());
}

#[test]
fn r36_rejection_produces_no_mutation() {
    // A malformed observe records nothing (no sequence/marker write modeled).
    let (mut input, exp) = fresh_devnet();
    input.replay_nonce = "tampered".to_string();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let outcome =
        observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    assert_eq!(outcome, DurableBackendOutcome::FailClosedMalformedRecord);
    assert!(backend.is_empty());

    // A rejected consume after a legitimate observe leaves the record unconsumed.
    let (good, good_exp) = fresh_devnet();
    let mut backend2 = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(
        DurableBackendKind::FixtureDevNet,
        &good,
        &good_exp,
        &mut backend2,
    );
    let rejected = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &good,
        &good_exp,
        DurableMutationCompletion::ApplyFailed,
        &mut backend2,
    );
    assert!(rejected.no_consume());
    assert!(!backend2.is_consumed(&key_of(&good)));
}

#[test]
fn r37_mainnet_peer_driven_apply_refused_even_when_fixture_says_fresh() {
    // The DevNet fixture has the decision observed fresh.
    let (devnet_input, devnet_exp) = fresh_devnet();
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    observe_decision_if_absent(
        DurableBackendKind::FixtureDevNet,
        &devnet_input,
        &devnet_exp,
        &mut backend,
    );
    assert_eq!(
        read_decision_state(
            DurableBackendKind::FixtureDevNet,
            &devnet_input,
            &devnet_exp,
            &backend
        ),
        DurableBackendOutcome::ProceedKnownFresh
    );

    // A MainNet peer-driven apply variant is refused regardless.
    let (mn_input, mn_exp) = di(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        100,
        200,
        150,
    );
    let mut mn_backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let observe = observe_decision_if_absent(
        DurableBackendKind::FixtureDevNet,
        &mn_input,
        &mn_exp,
        &mut mn_backend,
    );
    assert_eq!(observe, DurableBackendOutcome::FailClosedMainNetUnavailable);
    let consume = mark_consumed_after_success(
        DurableBackendKind::FixtureDevNet,
        &mn_input,
        &mn_exp,
        DurableMutationCompletion::AppliedSuccessfully,
        &mut mn_backend,
    );
    assert_eq!(consume, DurableConsumeOutcome::FailClosedMainNetUnavailable);
    assert!(mainnet_peer_driven_apply_remains_refused_under_durable_backend(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// Crash-window classification — full coverage
// ===========================================================================

fn base_obs(kind: DurableBackendKind) -> CrashWindowObservation {
    CrashWindowObservation {
        backend_kind: kind,
        observed: false,
        mutation_attempted: false,
        mutation_succeeded: false,
        rolled_back: false,
        apply_failed: false,
        consumed: false,
    }
}

#[test]
fn crash_window_before_observe() {
    let obs = base_obs(DurableBackendKind::FixtureDevNet);
    assert_eq!(classify_crash_window(&obs), CrashWindow::BeforeObserve);
}

#[test]
fn crash_window_after_observe_before_mutation() {
    let mut obs = base_obs(DurableBackendKind::FixtureDevNet);
    obs.observed = true;
    assert_eq!(
        classify_crash_window(&obs),
        CrashWindow::AfterObserveBeforeMutation
    );
}

#[test]
fn crash_window_after_consume() {
    let mut obs = base_obs(DurableBackendKind::FixtureDevNet);
    obs.observed = true;
    obs.mutation_attempted = true;
    obs.mutation_succeeded = true;
    obs.consumed = true;
    assert_eq!(classify_crash_window(&obs), CrashWindow::AfterConsume);
    assert!(!classify_crash_window(&obs).requires_fail_closed_recovery());
}

#[test]
fn crash_window_rollback_after_observe() {
    let mut obs = base_obs(DurableBackendKind::FixtureDevNet);
    obs.observed = true;
    obs.mutation_attempted = true;
    obs.rolled_back = true;
    assert_eq!(classify_crash_window(&obs), CrashWindow::RollbackAfterObserve);
}

#[test]
fn crash_window_apply_failed_after_observe() {
    let mut obs = base_obs(DurableBackendKind::FixtureDevNet);
    obs.observed = true;
    obs.mutation_attempted = true;
    obs.apply_failed = true;
    assert_eq!(
        classify_crash_window(&obs),
        CrashWindow::ApplyFailedAfterObserve
    );
}

#[test]
fn crash_window_unknown() {
    let mut obs = base_obs(DurableBackendKind::FixtureDevNet);
    obs.observed = true;
    obs.mutation_attempted = true; // attempted but no terminal status
    assert_eq!(classify_crash_window(&obs), CrashWindow::UnknownCrashWindow);
}

#[test]
fn crash_window_production_and_mainnet_unavailable() {
    let mut prod = base_obs(DurableBackendKind::Production);
    prod.observed = true;
    prod.consumed = true;
    assert_eq!(
        classify_crash_window(&prod),
        CrashWindow::ProductionCrashWindowUnavailable
    );
    let mut mn = base_obs(DurableBackendKind::MainNet);
    mn.observed = true;
    mn.consumed = true;
    assert_eq!(
        classify_crash_window(&mn),
        CrashWindow::MainNetCrashWindowUnavailable
    );
}

// ===========================================================================
// Compatibility with Runs 236 / 234 / 232 / 230 + non-implementation invariants
// ===========================================================================

#[test]
fn compat_run230_freshness_boundary_unchanged() {
    // Run 230 still classifies a fresh first-seen decision as ProceedFresh.
    let identity = ev_identity(TrustBundleEnvironment::Devnet);
    let request = ev_request(&identity, 100, 200);
    let response = ev_response(&request, 100, 200);
    let input = EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    );
    let exp = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    assert_eq!(
        evaluate_evaluator_replay_freshness(&input, &exp),
        EvaluatorReplayFreshnessOutcome::ProceedFresh
    );
}

#[test]
fn non_implementation_invariants_hold() {
    assert!(durable_consume_only_after_successful_mutation());
    assert!(restart_durability_is_fixture_snapshot_only());
    assert!(no_rocksdb_file_schema_migration_change_under_durable_backend());
    assert!(production_mainnet_durable_backend_remains_unavailable());
}
