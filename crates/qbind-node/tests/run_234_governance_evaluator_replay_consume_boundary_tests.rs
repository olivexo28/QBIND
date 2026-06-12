//! Run 234 — source/test governance evaluator **post-mutation replay consume
//! boundary** tests.
//!
//! Source/test only. Run 234 captures **no** release-binary evidence;
//! release-binary consume-boundary evidence is deferred to **Run 235**. These
//! tests prove that the typed, pure post-mutation consume boundary
//! ([`evaluate_post_mutation_consume`] / [`perform_post_mutation_consume`])
//! separates pre-mutation freshness validation, mutation authorization,
//! successful mutation completion, and an explicit replay-state consume after
//! success only: consume is authorized **only** after
//! [`MutationCompletionStatus::AppliedSuccessfully`], a deferral / validation-only
//! / authorized-but-not-applied / failed-apply / rolled-back / unsupported-surface
//! / MainNet-refused outcome never consumes, the DevNet/TestNet fixture writer
//! records consumed only on an explicit after-success call, the production /
//! MainNet consume writers are callable but unavailable / fail-closed, and
//! MainNet peer-driven apply remains refused and never consumes.
//!
//! Coverage: A1–A18, R1–R33, deterministic digest tests, consume-after-success-
//! only, validation-only never consumes, failed/rolled-back never consumes,
//! fixture consume updates state only after explicit success, production/MainNet
//! consume unavailable, non-mutation, MainNet refusal, and compatibility with the
//! Run 233 / 232 / 231 / 230 / 228 / 226 / 224 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_234.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_consume_boundary::{
    consume_authorization_digest, consume_only_after_successful_mutation,
    consume_transcript_digest, deferred_is_never_consumed, evaluate_post_mutation_consume,
    local_operator_cannot_satisfy_consume_policy,
    mainnet_peer_driven_apply_remains_refused_under_consume_boundary,
    peer_majority_cannot_satisfy_consume_policy, perform_post_mutation_consume,
    policy_change_action_remains_unsupported_under_consume_boundary,
    post_mutation_consume_record_digest, production_mainnet_consume_remains_unavailable,
    surface_is_validation_only, validation_only_is_never_consumed,
    validator_set_rotation_remains_unsupported_under_consume_boundary, ConsumeBoundaryOutcome,
    MutationAuthorizationOutcome, MutationCompletionStatus, PostMutationConsumeExpectations,
    PostMutationConsumeInput,
};
use qbind_node::pqc_governance_evaluator_replay_runtime_integration::{
    integrate_governance_evaluator_replay_runtime,
    GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, replay_state_key_digest,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, FixtureReplayStateStore,
    GovernanceEvaluatorReplayStateReader, GovernanceEvaluatorReplayStateWriter,
    MainnetReplayStateReader, PreviouslySeenState, ProductionReplayStateReader, ReplayStatePolicy,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorExpectations, EvaluatorPolicy, EvaluatorRequest,
    EvaluatorResponse, EvaluatorSourceKind, FixtureGovernanceExecutionEvaluatorInterface,
    ProductionGovernanceExecutionEvaluator, EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::GovernanceEvaluatorRuntimeIntegrationContext;
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadWire,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceQuorumThreshold,
    GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_governance_execution_policy::GovernanceExecutionPolicy;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 / 230 / 232 corpora).
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
const CANONICAL: u64 = 150;

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
// Run 230 freshness input / Run 234 consume input + expectations builders
// ===========================================================================

fn freshness_input(
    env: TrustBundleEnvironment,
    validation_surface: GovernanceExecutionRuntimeSurface,
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
        validation_surface,
        CANONICAL,
        previously_seen,
    )
}

fn consume_input(
    env: TrustBundleEnvironment,
    validation_surface: GovernanceExecutionRuntimeSurface,
    mutation_surface: GovernanceExecutionRuntimeSurface,
    auth: MutationAuthorizationOutcome,
    completion: MutationCompletionStatus,
) -> PostMutationConsumeInput {
    let fresh = freshness_input(env, validation_surface, PreviouslySeenState::FirstSeen);
    PostMutationConsumeInput::from_freshness_input(&fresh, mutation_surface, auth, completion)
}

fn consume_exp(
    env: TrustBundleEnvironment,
    validation_surface: GovernanceExecutionRuntimeSurface,
    mutation_surface: GovernanceExecutionRuntimeSurface,
) -> PostMutationConsumeExpectations {
    let fresh = freshness_input(env, validation_surface, PreviouslySeenState::FirstSeen);
    PostMutationConsumeExpectations::from_freshness_input(&fresh, mutation_surface)
}

/// DevNet, mutating ReloadApply surface, authorized-fresh, applied-successfully:
/// the consume-eligible happy path with a wired DevNet fixture policy.
fn devnet_success_input() -> PostMutationConsumeInput {
    consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    )
}

fn devnet_exp() -> PostMutationConsumeExpectations {
    consume_exp(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}

// ===========================================================================
// A — accepted scenarios A1–A18
// ===========================================================================

#[test]
fn a1_legacy_bypass_does_not_consume() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::LegacyBypass,
        MutationCompletionStatus::NotAttempted,
    );
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeLegacyBypass);
    assert!(!outcome.authorizes_consume());
    assert!(outcome.no_consume());
}

#[test]
fn a2_deferred_does_not_consume() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::Deferred,
        MutationCompletionStatus::NotAttempted,
    );
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeDeferred);
    assert!(outcome.no_consume());
}

#[test]
fn a3_validation_only_success_does_not_consume() {
    let exp = consume_exp(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
    );
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::ValidationOnly,
    );
    let outcome = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp);
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeValidationOnly);
}

#[test]
fn a4_authorized_but_not_applied_does_not_consume() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AuthorizedButNotApplied,
    );
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeBeforeApply);
}

#[test]
fn a5_apply_failed_does_not_consume() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::ApplyFailed,
    );
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeApplyFailed);
}

#[test]
fn a6_rolled_back_does_not_consume() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::RolledBack,
    );
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeRolledBack);
}

#[test]
fn a7_unsupported_surface_does_not_consume() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::UnsupportedSurface,
    );
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeUnsupportedSurface);
}

#[test]
fn a8_mainnet_refused_does_not_consume() {
    let exp = consume_exp(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input = consume_input(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    let outcome = evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp);
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused);
    assert!(mainnet_peer_driven_apply_remains_refused_under_consume_boundary(
        TrustBundleEnvironment::Mainnet
    ));
}

#[test]
fn a9_devnet_fixture_consume_only_after_applied_successfully() {
    let input = devnet_success_input();
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert_eq!(outcome, ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess);
    assert!(outcome.authorizes_consume());
}

#[test]
fn a10_testnet_fixture_consume_only_after_applied_successfully() {
    let exp = consume_exp(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = consume_input(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    let outcome = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureTestNet, &input, &exp);
    assert_eq!(outcome, ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess);
}

#[test]
fn a11_after_fixture_consume_run230_classifies_already_consumed() {
    let env = TrustBundleEnvironment::Devnet;
    let mut store = FixtureReplayStateStore::new(env);

    // Record an observation (pre-mutation), then validate read-only: still fresh.
    let mut fresh = freshness_input(
        env,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        PreviouslySeenState::FirstSeen,
    );
    store.record_for(&fresh);
    fresh.previously_seen = store.read_for(&fresh);
    let exp230 = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &ev_identity(env),
        &ev_request(&ev_identity(env)),
        &ev_response(&ev_request(&ev_identity(env))),
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );

    // Now perform the post-mutation consume after a successful mutation.
    let input = devnet_success_input();
    let outcome = perform_post_mutation_consume(
        ReplayStatePolicy::FixtureDevNet,
        &input,
        &devnet_exp(),
        &mut store,
    );
    assert_eq!(outcome, ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess);
    assert!(store.is_consumed(&input.replay_state_key_digest));

    // Re-validating through the Run 230 state now classifies already-consumed.
    let mut after = freshness_input(
        env,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        PreviouslySeenState::FirstSeen,
    );
    after.previously_seen = store.read_for(&after);
    assert_eq!(
        evaluate_evaluator_replay_freshness(&after, &exp230),
        EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed
    );
}

#[test]
fn a12_consume_authorization_digest_is_deterministic() {
    let input = devnet_success_input();
    assert_eq!(
        consume_authorization_digest(&input),
        consume_authorization_digest(&input)
    );
    // A second structurally-identical input produces the same digest.
    let twin = devnet_success_input();
    assert_eq!(
        consume_authorization_digest(&input),
        consume_authorization_digest(&twin)
    );
}

#[test]
fn a13_consume_transcript_digest_is_deterministic() {
    let input = devnet_success_input();
    let outcome = ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess;
    assert_eq!(
        consume_transcript_digest(&input, &outcome),
        consume_transcript_digest(&input, &outcome)
    );
    // A different resolved outcome produces a different transcript digest.
    assert_ne!(
        consume_transcript_digest(&input, &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess),
        consume_transcript_digest(&input, &ConsumeBoundaryOutcome::DoNotConsumeBeforeApply)
    );
}

#[test]
fn a14_post_mutation_consume_record_digest_is_deterministic() {
    let input = devnet_success_input();
    assert_eq!(
        post_mutation_consume_record_digest(&input, 150),
        post_mutation_consume_record_digest(&input, 150)
    );
    // A different consumed epoch produces a different record digest.
    assert_ne!(
        post_mutation_consume_record_digest(&input, 150),
        post_mutation_consume_record_digest(&input, 151)
    );
}

#[test]
fn a15_consume_binding_includes_every_required_field() {
    // Each A15 binding field, when changed, changes the consume authorization
    // digest — proving the binding includes it.
    let base = devnet_success_input();
    let base_digest = consume_authorization_digest(&base);

    let mut mutators: Vec<Box<dyn Fn(&mut PostMutationConsumeInput)>> = Vec::new();
    mutators.push(Box::new(|i| i.replay_state_key_digest = "x".to_string()));
    mutators.push(Box::new(|i| i.evaluator_request_digest = "x".to_string()));
    mutators.push(Box::new(|i| i.evaluator_response_digest = "x".to_string()));
    mutators.push(Box::new(|i| i.governance_execution_decision_digest = "x".to_string()));
    mutators.push(Box::new(|i| i.lifecycle_action = LocalLifecycleAction::Revoke));
    mutators.push(Box::new(|i| i.candidate_digest = "x".to_string()));
    mutators.push(Box::new(|i| i.authority_domain_sequence += 1));
    mutators.push(Box::new(|i| i.replay_nonce = "x".to_string()));
    mutators.push(Box::new(|i| i.environment = TrustBundleEnvironment::Testnet));
    mutators.push(Box::new(|i| i.chain_id = "x".to_string()));
    mutators.push(Box::new(|i| i.genesis_hash = "x".to_string()));
    mutators.push(Box::new(|i| {
        i.validation_surface = GovernanceExecutionRuntimeSurface::Sighup
    }));
    mutators.push(Box::new(|i| {
        i.mutation_surface = GovernanceExecutionRuntimeSurface::Sighup
    }));
    mutators.push(Box::new(|i| {
        i.mutation_completion_status = MutationCompletionStatus::ApplyFailed
    }));

    for mutate in &mutators {
        let mut altered = base.clone();
        mutate(&mut altered);
        assert_ne!(
            base_digest,
            consume_authorization_digest(&altered),
            "a bound A15 field did not affect the consume authorization digest"
        );
    }
}

#[test]
fn a16_production_consume_writer_is_callable_and_fails_closed() {
    let exp = consume_exp(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    let outcome = evaluate_post_mutation_consume(ReplayStatePolicy::Production, &input, &exp);
    assert_eq!(
        outcome,
        ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable
    );
    // The production writer is callable but always fails closed.
    let mut writer = ProductionReplayStateReader;
    assert!(!writer.mark_consumed(&input.replay_state_key_digest));
    let performed =
        perform_post_mutation_consume(ReplayStatePolicy::Production, &input, &exp, &mut writer);
    assert_eq!(
        performed,
        ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable
    );
}

#[test]
fn a17_mainnet_consume_writer_is_callable_and_fails_closed() {
    // Non-peer-driven MainNet surface so the MainNet-refusal guard does not
    // pre-empt the consume-policy unavailability path.
    let exp = consume_exp(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = consume_input(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    let outcome = evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp);
    assert_eq!(
        outcome,
        ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable
    );
    // The MainNet writer is callable but always fails closed.
    let mut writer = MainnetReplayStateReader;
    assert!(!writer.mark_consumed(&input.replay_state_key_digest));
    let performed =
        perform_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp, &mut writer);
    assert_eq!(
        performed,
        ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable
    );
}

#[test]
fn a18_run232_remains_compatible_when_consume_boundary_not_wired() {
    // The Run 232 replay/freshness runtime integration runs unchanged and still
    // authorizes a fresh mutate; its outcome projects into the consume boundary's
    // authorization view.
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run();
    assert!(matches!(
        outcome,
        GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. }
    ));
    assert_eq!(
        MutationAuthorizationOutcome::from_replay_runtime_outcome(&outcome),
        MutationAuthorizationOutcome::AuthorizedFresh
    );

    // The other Run 232 outcome variants project to non-authorizing views.
    assert_eq!(
        MutationAuthorizationOutcome::from_replay_runtime_outcome(
            &GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass
        ),
        MutationAuthorizationOutcome::LegacyBypass
    );
    assert_eq!(
        MutationAuthorizationOutcome::from_replay_runtime_outcome(
            &GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred
        ),
        MutationAuthorizationOutcome::Deferred
    );
    assert_eq!(
        MutationAuthorizationOutcome::from_replay_runtime_outcome(
            &GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
        ),
        MutationAuthorizationOutcome::MainNetRefused
    );
}

// ===========================================================================
// R — rejection scenarios R1–R33
// ===========================================================================

/// Build a consume-eligible DevNet input (authorized-fresh, applied-successfully,
/// mutating surfaces) so a single wrong binding field is the only reason a
/// consume is refused.
fn wrong_binding_base() -> PostMutationConsumeInput {
    devnet_success_input()
}

fn assert_wrong_binding(input: &PostMutationConsumeInput) {
    let outcome =
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, input, &devnet_exp());
    assert!(
        matches!(outcome, ConsumeBoundaryOutcome::FailClosedWrongBinding { .. }),
        "expected FailClosedWrongBinding, got {:?}",
        outcome
    );
    assert!(outcome.is_fail_closed());
    assert!(outcome.no_consume());
}

#[test]
fn r1_wrong_replay_state_key_digest_rejected() {
    let mut input = wrong_binding_base();
    input.replay_state_key_digest = "wrong-key".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r2_wrong_source_identity_digest_rejected() {
    let mut input = wrong_binding_base();
    input.evaluator_source_identity_digest = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r3_wrong_request_digest_rejected() {
    let mut input = wrong_binding_base();
    input.evaluator_request_digest = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r4_wrong_response_digest_rejected() {
    let mut input = wrong_binding_base();
    input.evaluator_response_digest = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r5_wrong_transcript_digest_rejected() {
    let mut input = wrong_binding_base();
    input.evaluator_transcript_digest = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r6_wrong_decision_digest_rejected() {
    let mut input = wrong_binding_base();
    input.governance_execution_decision_digest = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r7_wrong_proposal_id_rejected() {
    let mut input = wrong_binding_base();
    input.proposal_id = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r8_wrong_decision_id_rejected() {
    let mut input = wrong_binding_base();
    input.decision_id = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r9_wrong_lifecycle_action_rejected() {
    let mut input = wrong_binding_base();
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    assert_wrong_binding(&input);
}

#[test]
fn r10_wrong_candidate_digest_rejected() {
    let mut input = wrong_binding_base();
    input.candidate_digest = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r11_wrong_authority_domain_sequence_rejected() {
    let mut input = wrong_binding_base();
    input.authority_domain_sequence = SEQUENCE + 1;
    assert_wrong_binding(&input);
}

#[test]
fn r12_wrong_effective_epoch_rejected() {
    let mut input = wrong_binding_base();
    input.effective_epoch = EFFECTIVE + 1;
    assert_wrong_binding(&input);
}

#[test]
fn r13_wrong_expiry_epoch_rejected() {
    let mut input = wrong_binding_base();
    input.expiry_epoch = EXPIRY + 1;
    assert_wrong_binding(&input);
}

#[test]
fn r14_wrong_replay_nonce_rejected() {
    let mut input = wrong_binding_base();
    input.replay_nonce = "wrong".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r15_wrong_environment_rejected() {
    // Wrong environment relative to the DevNet expectations (still non-mainnet
    // so the binding mismatch — not the MainNet guard — is exercised).
    let mut input = wrong_binding_base();
    input.environment = TrustBundleEnvironment::Testnet;
    assert_wrong_binding(&input);
}

#[test]
fn r16_wrong_chain_rejected() {
    let mut input = wrong_binding_base();
    input.chain_id = "wrong-chain".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r17_wrong_genesis_rejected() {
    let mut input = wrong_binding_base();
    input.genesis_hash = "wrong-genesis".to_string();
    assert_wrong_binding(&input);
}

#[test]
fn r18_wrong_validation_surface_rejected() {
    let mut input = wrong_binding_base();
    // A different, still-mutating surface so the validation-only short-circuit
    // does not pre-empt the binding mismatch.
    input.validation_surface = GovernanceExecutionRuntimeSurface::Sighup;
    assert_wrong_binding(&input);
}

#[test]
fn r19_wrong_mutation_surface_rejected() {
    let mut input = wrong_binding_base();
    input.mutation_surface = GovernanceExecutionRuntimeSurface::Sighup;
    assert_wrong_binding(&input);
}

#[test]
fn r20_consume_before_apply_rejected() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::NotAttempted,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp()),
        ConsumeBoundaryOutcome::DoNotConsumeBeforeApply
    );
}

#[test]
fn r21_consume_after_failed_apply_rejected() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::ApplyFailed,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp()),
        ConsumeBoundaryOutcome::DoNotConsumeApplyFailed
    );
}

#[test]
fn r22_consume_after_rollback_rejected() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::RolledBack,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp()),
        ConsumeBoundaryOutcome::DoNotConsumeRolledBack
    );
}

#[test]
fn r23_consume_on_validation_only_surface_rejected() {
    let exp = consume_exp(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
    );
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp),
        ConsumeBoundaryOutcome::DoNotConsumeValidationOnly
    );
}

#[test]
fn r24_consume_on_unsupported_surface_rejected() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::UnsupportedSurface,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp()),
        ConsumeBoundaryOutcome::DoNotConsumeUnsupportedSurface
    );
}

#[test]
fn r25_production_consume_unavailable_rejected() {
    let input = consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::Production, &input, &devnet_exp()),
        ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable
    );
    assert!(production_mainnet_consume_remains_unavailable());
}

#[test]
fn r26_mainnet_consume_unavailable_rejected() {
    let exp = consume_exp(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = consume_input(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp),
        ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable
    );
}

#[test]
fn r27_local_operator_cannot_satisfy_consume_policy() {
    assert!(local_operator_cannot_satisfy_consume_policy());
}

#[test]
fn r28_peer_majority_cannot_satisfy_consume_policy() {
    assert!(peer_majority_cannot_satisfy_consume_policy());
}

#[test]
fn r29_validator_set_rotation_unsupported_rejected() {
    assert!(validator_set_rotation_remains_unsupported_under_consume_boundary());
}

#[test]
fn r30_policy_change_action_unsupported_rejected() {
    assert!(policy_change_action_remains_unsupported_under_consume_boundary());
}

#[test]
fn r31_malformed_consume_state_rejected() {
    let mut input = wrong_binding_base();
    input.replay_state_key_digest = String::new();
    assert!(!input.is_well_formed());
    assert_wrong_binding(&input);
}

#[test]
fn r32_consume_rejection_is_non_mutating() {
    // A rejection performed against a fixture store records no consume and no
    // observation: no Run 070 call, no live trust swap, no session eviction, no
    // sequence write, and no marker write.
    let env = TrustBundleEnvironment::Devnet;
    let mut store = FixtureReplayStateStore::new(env);
    assert!(store.is_empty());

    // Authorized-fresh but apply failed: must not consume.
    let input = consume_input(
        env,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::ApplyFailed,
    );
    let outcome = perform_post_mutation_consume(
        ReplayStatePolicy::FixtureDevNet,
        &input,
        &devnet_exp(),
        &mut store,
    );
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeApplyFailed);
    // The store recorded nothing — the rejection never wrote.
    assert!(store.is_empty());
    assert!(!store.is_consumed(&input.replay_state_key_digest));
}

#[test]
fn r33_mainnet_peer_driven_apply_refused_does_not_consume_even_if_fresh() {
    // A MainNet peer-driven drain surface with an authorized-fresh, applied
    // decision and a wired MainNet policy still refuses and never consumes.
    let exp = consume_exp(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input = consume_input(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let outcome =
        perform_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp, &mut store);
    assert_eq!(outcome, ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused);
    assert!(store.is_empty());
}

// ===========================================================================
// Focused invariant coverage
// ===========================================================================

#[test]
fn consume_after_success_only_across_every_completion_status() {
    // Only AppliedSuccessfully (with a wired fixture policy) consumes; every
    // other completion status resolves to a non-consume.
    for completion in [
        MutationCompletionStatus::NotAttempted,
        MutationCompletionStatus::AuthorizedButNotApplied,
        MutationCompletionStatus::AppliedSuccessfully,
        MutationCompletionStatus::ApplyFailed,
        MutationCompletionStatus::RolledBack,
        MutationCompletionStatus::ValidationOnly,
        MutationCompletionStatus::UnsupportedSurface,
        MutationCompletionStatus::MainNetRefused,
    ] {
        let input = consume_input(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            MutationAuthorizationOutcome::AuthorizedFresh,
            completion,
        );
        let outcome =
            evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        if completion == MutationCompletionStatus::AppliedSuccessfully {
            assert!(outcome.authorizes_consume());
        } else {
            assert!(outcome.no_consume(), "{:?} unexpectedly consumed", completion);
        }
    }
    assert!(consume_only_after_successful_mutation());
}

#[test]
fn validation_only_surfaces_never_consume() {
    for surface in [
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        GovernanceExecutionRuntimeSurface::LiveInbound0x05,
    ] {
        assert!(surface_is_validation_only(surface));
        let exp = consume_exp(TrustBundleEnvironment::Devnet, surface, surface);
        let input = consume_input(
            TrustBundleEnvironment::Devnet,
            surface,
            surface,
            MutationAuthorizationOutcome::AuthorizedFresh,
            MutationCompletionStatus::AppliedSuccessfully,
        );
        assert_eq!(
            evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp),
            ConsumeBoundaryOutcome::DoNotConsumeValidationOnly
        );
    }
    assert!(validation_only_is_never_consumed());
}

#[test]
fn failed_and_rolled_back_mutations_never_consume() {
    for completion in [
        MutationCompletionStatus::ApplyFailed,
        MutationCompletionStatus::RolledBack,
    ] {
        let input = consume_input(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            MutationAuthorizationOutcome::AuthorizedFresh,
            completion,
        );
        assert!(
            evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp())
                .no_consume()
        );
    }
    assert!(deferred_is_never_consumed());
}

#[test]
fn fixture_consume_updates_state_only_after_explicit_success_call() {
    let env = TrustBundleEnvironment::Devnet;
    let mut store = FixtureReplayStateStore::new(env);
    let input = devnet_success_input();

    // Record an observation; before the explicit consume call the decision is
    // not consumed.
    let fresh = freshness_input(
        env,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        PreviouslySeenState::FirstSeen,
    );
    store.record_for(&fresh);
    assert!(!store.is_consumed(&input.replay_state_key_digest));

    // Read-only evaluation never consumes.
    let _ = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    assert!(!store.is_consumed(&input.replay_state_key_digest));

    // The explicit after-success perform call marks consumed.
    let outcome = perform_post_mutation_consume(
        ReplayStatePolicy::FixtureDevNet,
        &input,
        &devnet_exp(),
        &mut store,
    );
    assert_eq!(outcome, ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess);
    assert!(store.is_consumed(&input.replay_state_key_digest));
}

#[test]
fn fixture_consume_without_prior_observation_fails_closed() {
    // The fixture writer can only mark a recorded decision consumed; an
    // after-success consume with no prior observation fails closed unavailable.
    let env = TrustBundleEnvironment::Devnet;
    let mut store = FixtureReplayStateStore::new(env);
    let input = devnet_success_input();
    let outcome = perform_post_mutation_consume(
        ReplayStatePolicy::FixtureDevNet,
        &input,
        &devnet_exp(),
        &mut store,
    );
    assert_eq!(outcome, ConsumeBoundaryOutcome::FailClosedConsumeUnavailable);
    assert!(!store.is_consumed(&input.replay_state_key_digest));
}

#[test]
fn disabled_policy_consume_fails_closed_unavailable() {
    let input = devnet_success_input();
    assert_eq!(
        evaluate_post_mutation_consume(ReplayStatePolicy::Disabled, &input, &devnet_exp()),
        ConsumeBoundaryOutcome::FailClosedConsumeUnavailable
    );
}

#[test]
fn run230_state_key_matches_consume_binding() {
    // The consume input references exactly the Run 230 replay state key digest,
    // proving the consume binding composes with the Run 230 / 232 layers.
    let fresh = freshness_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        PreviouslySeenState::FirstSeen,
    );
    let input = devnet_success_input();
    assert_eq!(input.replay_state_key_digest, replay_state_key_digest(&fresh));
}

// ===========================================================================
// A18 support — full Run 232 integration fixture (compatibility check)
// ===========================================================================

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

fn rotate_input(env: TrustBundleEnvironment) -> GovernanceExecutionInput {
    GovernanceExecutionInput {
        execution_version: GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
        environment: env,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        governance_class: GovernanceExecutionClass::FixtureGovernance,
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        current_signing_key_fingerprint: "curcurcurcurcurcurcurcurcurcurcurcurcurc".to_string(),
        candidate_signing_key_fingerprint: "candcandcandcandcandcandcandcandcandcand".to_string(),
        revoked_signing_key_fingerprint: None,
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
    }
}

fn rotate_decision() -> GovernanceExecutionDecision {
    GovernanceExecutionDecision {
        execution_version: GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_authority_root_fingerprint: ROOT_FP.to_string(),
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_sequence: SEQUENCE,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        decision_commitment: "decision-commitment-eeeeeeeeeeeeeeeeeeee".to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        emergency_flag: false,
        replay_nonce: NONCE.to_string(),
    }
}

fn rotate_gov_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    GovernanceExecutionExpectations {
        expected_environment: env,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_governance_action: GovernanceAction::Rotate,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_effective_epoch: EFFECTIVE,
        expected_replay_nonce: NONCE.to_string(),
        now_epoch: CANONICAL,
    }
}

fn available_from(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    GovernanceExecutionLoadStatus::Available(wire.to_parts().expect("wire converts to parts"))
}

fn ev_request_with_digest(
    identity: &DecisionSourceIdentity,
    input_digest: &str,
) -> EvaluatorRequest {
    let mut request = ev_request(identity);
    request.governance_execution_input_digest = input_digest.to_string();
    request
}

fn ev_expectations(env: TrustBundleEnvironment, input_digest: &str) -> EvaluatorExpectations {
    EvaluatorExpectations {
        expected_evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        expected_environment: env,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_governance_action: GovernanceAction::Rotate,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_effective_epoch: EFFECTIVE,
        expected_expiry_epoch: EXPIRY,
        expected_replay_nonce: NONCE.to_string(),
        expected_governance_execution_input_digest: input_digest.to_string(),
        now_epoch: CANONICAL,
    }
}

struct Fixture {
    arming: GovernanceExecutionRuntimeArmingConfig,
    surface: GovernanceExecutionRuntimeSurface,
    td: AuthorityTrustDomain,
    load: GovernanceExecutionLoadStatus,
    gov_exp: GovernanceExecutionExpectations,
    identity: DecisionSourceIdentity,
    request: EvaluatorRequest,
    response: EvaluatorResponse,
    ev_exp: EvaluatorExpectations,
    ev_policy: EvaluatorPolicy,
    peer_driven: bool,
    replay_policy: ReplayStatePolicy,
    replay_input: EvaluatorReplayFreshnessInput,
    replay_exp: EvaluatorReplayFreshnessExpectations,
}

impl Fixture {
    fn context<'a, E: ProductionGovernanceExecutionEvaluator>(
        &'a self,
        evaluator: &'a E,
    ) -> GovernanceEvaluatorReplayRuntimeIntegrationContext<'a, E> {
        GovernanceEvaluatorReplayRuntimeIntegrationContext {
            integration: GovernanceEvaluatorRuntimeIntegrationContext {
                arming: &self.arming,
                surface: self.surface,
                trust_domain: &self.td,
                load_status: &self.load,
                governance_execution_expectations: &self.gov_exp,
                evaluator,
                identity: &self.identity,
                request: &self.request,
                response: &self.response,
                evaluator_expectations: &self.ev_exp,
                evaluator_policy: self.ev_policy,
                is_peer_driven_apply_preflight: self.peer_driven,
            },
            replay_policy: self.replay_policy,
            replay_input: &self.replay_input,
            replay_expectations: &self.replay_exp,
        }
    }

    fn run(&self) -> GovernanceEvaluatorReplayRuntimeOutcome {
        integrate_governance_evaluator_replay_runtime(
            &self.context(&FixtureGovernanceExecutionEvaluatorInterface),
        )
    }
}

fn rotate_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env);
    let request = ev_request_with_digest(&identity, &input_digest);
    let response = ev_response(&request);
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;

    let replay_exp = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity, &request, &response, TRANSCRIPT_DIGEST, DECISION_DIGEST, env, CHAIN, GENESIS,
        surface,
    );
    let replay_input = EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );

    Fixture {
        arming: GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        surface,
        td: trust_domain(env),
        load: available_from(&input, &decision),
        gov_exp: rotate_gov_expectations(env),
        ev_exp: ev_expectations(env, &input_digest),
        identity,
        request,
        response,
        ev_policy: EvaluatorPolicy::FixtureDecisionSourceAllowed,
        peer_driven: false,
        replay_policy: ReplayStatePolicy::FixtureDevNet,
        replay_input,
        replay_exp,
    }
}