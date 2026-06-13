//! Run 236 — source/test governance evaluator **replay consume runtime
//! integration** tests.
//!
//! Source/test only. Run 236 captures **no** release-binary evidence;
//! release-binary consume-runtime-integration evidence is deferred to **Run
//! 237**. These tests prove that the composed integration
//! ([`integrate_replay_consume_runtime`]) ties the Run 234 post-mutation consume
//! boundary into the Run 232 replay/freshness runtime path as a modeled
//! after-success-only post-mutation step: replay/freshness is validated and a
//! mutation is authorized only on fresh (Run 232 → Run 230), the mutation
//! completion status is modeled, and a consume happens **only** after a modeled
//! `AppliedSuccessfully` mutation in a wired DevNet/TestNet fixture. Deferred,
//! validation-only, before-apply, failed-apply, rolled-back, unsupported-surface,
//! and MainNet-refused outcomes never consume; production/MainNet consume remains
//! unavailable/fail-closed; and MainNet peer-driven apply remains refused and
//! never consumes even when the replay state is fresh and the mutation completion
//! is modeled successful.
//!
//! Coverage: A1–A17, R1–R35, ordering (consume only after successful mutation
//! completion), no-consume for deferred / validation-only / failed / rolled-back
//! / unsupported / MainNet-refused, fixture consume updates state only after
//! success, production/MainNet consume unavailable, non-mutation, MainNet
//! refusal, and compatibility with the Run 235 / 234 / 233 / 232 / 231 / 230 /
//! 228 / 226 / 224 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_236.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_consume_boundary::{
    local_operator_cannot_satisfy_consume_policy, peer_majority_cannot_satisfy_consume_policy,
    MutationAuthorizationOutcome, MutationCompletionStatus, PostMutationConsumeExpectations,
    PostMutationConsumeInput,
};
use qbind_node::pqc_governance_evaluator_replay_consume_runtime_integration::{
    consume_integrated_as_after_success_only_post_mutation_step,
    deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime,
    fresh_required_before_mutation_authorization_under_consume_runtime,
    integrate_replay_consume_runtime,
    mainnet_peer_driven_apply_remains_refused_under_consume_runtime,
    policy_change_action_remains_unsupported_under_consume_runtime,
    production_mainnet_consume_remains_unavailable_under_consume_runtime,
    validator_set_rotation_remains_unsupported_under_consume_runtime,
    wire_replay_consume_runtime_callsite, ReplayConsumeRuntimeIntegrationInput,
    ReplayConsumeRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_runtime_integration::{
    integrate_governance_evaluator_replay_runtime,
    GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput, FixtureReplayStateStore,
    MainnetReplayStateReader, PreviouslySeenState, ProductionReplayStateReader, ReplayStatePolicy,
    SeenDecisionRecord,
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
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionPolicy,
    GovernanceQuorumThreshold, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 / 230 / 232 / 234 corpora).
// ===========================================================================

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CUR_KEY: &str = "curcurcurcurcurcurcurcurcurcurcurcurcurc";
const CAND_KEY: &str = "candcandcandcandcandcandcandcandcandcand";
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
// Run 211 governance-execution carrier material (drives Run 220 consumption)
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
        current_signing_key_fingerprint: CUR_KEY.to_string(),
        candidate_signing_key_fingerprint: CAND_KEY.to_string(),
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

fn ev_request(identity: &DecisionSourceIdentity, input_digest: &str) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: input_digest.to_string(),
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

// ===========================================================================
// Owned-material fixture bundle (Run 232 context + Run 234 consume layer)
// ===========================================================================

/// Owns every layer's material for one composed Run 236 round-trip so a test can
/// mutate any field and then borrow it into the integration input.
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
    consume_input: PostMutationConsumeInput,
    consume_exp: PostMutationConsumeExpectations,
    consume_policy: ReplayStatePolicy,
}

impl Fixture {
    fn replay_context<'a, E: ProductionGovernanceExecutionEvaluator>(
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

    /// Run the composed Run 236 integration against `store`, using the default
    /// fixture evaluator.
    fn run(&self, store: &mut FixtureReplayStateStore) -> ReplayConsumeRuntimeOutcome {
        let evaluator = FixtureGovernanceExecutionEvaluatorInterface;
        let replay_ctx = self.replay_context(&evaluator);
        let input = ReplayConsumeRuntimeIntegrationInput {
            replay_runtime: &replay_ctx,
            consume_input: &self.consume_input,
            consume_expectations: &self.consume_exp,
            consume_policy: self.consume_policy,
        };
        integrate_replay_consume_runtime(&input, store)
    }
}

/// A fully-consistent fixture-rotate composed integration on `env` that, with
/// the default fixture evaluator, a wired fixture replay policy, a first-seen
/// fresh replay state, a mutating (non-peer-driven) ReloadApply surface, and the
/// given consume mutation surface + completion status, reaches the Run 232
/// `ProceedFresh` gate before the consume boundary.
fn rotate_fixture(
    env: TrustBundleEnvironment,
    mutation_surface: GovernanceExecutionRuntimeSurface,
    completion: MutationCompletionStatus,
    consume_policy: ReplayStatePolicy,
) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env);
    let request = ev_request(&identity, &input_digest);
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

    let consume_input = PostMutationConsumeInput::from_freshness_input(
        &replay_input,
        mutation_surface,
        MutationAuthorizationOutcome::AuthorizedFresh,
        completion,
    );
    let consume_exp =
        PostMutationConsumeExpectations::from_freshness_input(&replay_input, mutation_surface);

    let replay_policy = match env {
        TrustBundleEnvironment::Testnet => ReplayStatePolicy::FixtureTestNet,
        _ => ReplayStatePolicy::FixtureDevNet,
    };

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
        replay_policy,
        replay_input,
        replay_exp,
        consume_input,
        consume_exp,
        consume_policy,
    }
}

/// The consume-eligible DevNet happy-path fixture: ReloadApply mutation surface,
/// applied-successfully completion, wired DevNet fixture consume policy.
fn devnet_success_fixture() -> Fixture {
    rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::FixtureDevNet,
    )
}

/// A fresh store with the fixture's decision already observed (so the fixture
/// writer can mark it consumed after a successful mutation).
fn store_with_observation(fx: &Fixture) -> FixtureReplayStateStore {
    let mut store = FixtureReplayStateStore::new(match fx.consume_policy {
        ReplayStatePolicy::FixtureTestNet => TrustBundleEnvironment::Testnet,
        _ => TrustBundleEnvironment::Devnet,
    });
    store.record_for(&fx.replay_input);
    store
}

// ===========================================================================
// A — accepted scenarios A1–A17
// ===========================================================================

// A1. legacy bypass produces no consume.
#[test]
fn a1_legacy_bypass_no_consume() {
    let mut fx = devnet_success_fixture();
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ProceedLegacyBypassNoConsume
    );
    assert!(outcome.no_consume());
    // No consume happened: the observation remains unconsumed.
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A2. deferred replay/freshness produces no consume and no mutation
// authorization.
#[test]
fn a2_deferred_no_consume_no_authorization() {
    let mut fx = devnet_success_fixture();
    // Canonical epoch before the effective epoch: fresh-but-not-yet-effective.
    fx.replay_input.current_canonical_epoch = 50;
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(outcome, ReplayConsumeRuntimeOutcome::ProceedDeferredNoConsume);
    assert!(outcome.no_consume());
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A3. validation-only fresh decision produces no consume.
#[test]
fn a3_validation_only_no_consume() {
    // Run 232 still authorizes a fresh mutate (ReloadApply), but the consume
    // mutation surface is validation-only.
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ProceedValidationOnlyNoConsume
    );
    assert!(outcome.no_consume());
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A4. fresh decision authorizes mutation but does not consume before apply.
#[test]
fn a4_fresh_authorizes_mutation_no_consume_before_apply() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::NotAttempted,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ProceedFreshMutationAuthorized
    );
    assert!(outcome.is_proceed());
    assert!(outcome.no_consume());
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A5. fresh decision plus AppliedSuccessfully consumes in DevNet fixture only.
#[test]
fn a5_devnet_fresh_applied_consumes_fixture() {
    let fx = devnet_success_fixture();
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess
    );
    assert!(outcome.authorizes_consume());
    assert!(store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A6. fresh decision plus AppliedSuccessfully consumes in TestNet fixture only.
#[test]
fn a6_testnet_fresh_applied_consumes_fixture() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::FixtureTestNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess
    );
    assert!(store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A7. after fixture consume, same decision validates as already-consumed /
// fail-closed through Run 230 state.
#[test]
fn a7_after_consume_run230_classifies_already_consumed() {
    let fx = devnet_success_fixture();
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess
    );
    assert!(store.is_consumed(&fx.consume_input.replay_state_key_digest));

    // Re-validating the same decision through the composed integration now
    // fails closed: the Run 230 state classifies it already-consumed before any
    // mutation authorization.
    let mut fx2 = devnet_success_fixture();
    fx2.replay_input.previously_seen = store.read_for(&fx2.replay_input);
    let outcome2 = fx2.run(&mut store);
    assert!(
        matches!(
            outcome2,
            ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)
        ),
        "{:?}",
        outcome2
    );
    assert!(outcome2.no_consume());
}

// A8. read-only validation path never consumes.
#[test]
fn a8_read_only_validation_never_consumes() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        MutationCompletionStatus::ValidationOnly,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert!(outcome.no_consume());
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A9. failed apply never consumes.
#[test]
fn a9_failed_apply_never_consumes() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::ApplyFailed,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(outcome, ReplayConsumeRuntimeOutcome::DoNotConsumeApplyFailed);
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A10. rollback never consumes.
#[test]
fn a10_rollback_never_consumes() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::RolledBack,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(outcome, ReplayConsumeRuntimeOutcome::DoNotConsumeRolledBack);
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A11. unsupported surface never consumes.
#[test]
fn a11_unsupported_surface_never_consumes() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::UnsupportedSurface,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::DoNotConsumeUnsupportedSurface
    );
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// A12. MainNet refused never consumes.
#[test]
fn a12_mainnet_refused_never_consumes() {
    let outcome = mainnet_peer_driven_fixture_outcome();
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(outcome.no_consume());
    assert!(mainnet_peer_driven_apply_remains_refused_under_consume_runtime(
        TrustBundleEnvironment::Mainnet
    ));
}

// A13. production consume writer path is reached and fails closed unavailable.
#[test]
fn a13_production_consume_unavailable() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::Production,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ProductionConsumeUnavailable
    );
    // The production writer never marks consumed.
    let mut prod = ProductionReplayStateReader;
    let prod_input = ReplayConsumeRuntimeIntegrationInput {
        replay_runtime: &fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface),
        consume_input: &fx.consume_input,
        consume_expectations: &fx.consume_exp,
        consume_policy: ReplayStatePolicy::Production,
    };
    assert_eq!(
        integrate_replay_consume_runtime(&prod_input, &mut prod),
        ReplayConsumeRuntimeOutcome::ProductionConsumeUnavailable
    );
}

// A14. MainNet consume writer path is reached and fails closed
// unavailable/refused.
#[test]
fn a14_mainnet_consume_unavailable() {
    // DevNet-bound fresh decision, MainNet consume writer selector: the consume
    // writer path is reached and fails closed (no MainNet peer-driven surface, so
    // the unconditional refusal guard does not pre-empt it).
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::MainNet,
    );
    let mut mainnet = MainnetReplayStateReader;
    let input = ReplayConsumeRuntimeIntegrationInput {
        replay_runtime: &fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface),
        consume_input: &fx.consume_input,
        consume_expectations: &fx.consume_exp,
        consume_policy: ReplayStatePolicy::MainNet,
    };
    assert_eq!(
        integrate_replay_consume_runtime(&input, &mut mainnet),
        ReplayConsumeRuntimeOutcome::MainNetConsumeUnavailable
    );
}

/// Build a MainNet peer-driven-drain fixture and run it (used by A12/A15/R35).
fn mainnet_peer_driven_fixture_outcome() -> ReplayConsumeRuntimeOutcome {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::MainNet,
    );
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_exp.expected_validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_input.previously_seen = PreviouslySeenState::FirstSeen;
    // Rebuild the consume layer to match the peer-driven validation surface.
    fx.consume_input = PostMutationConsumeInput::from_freshness_input(
        &fx.replay_input,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    fx.consume_exp = PostMutationConsumeExpectations::from_freshness_input(
        &fx.replay_input,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    fx.run(&mut store)
}

// A15. MainNet peer-driven apply remains refused even when replay state is fresh
// and mutation completion is modeled successful.
#[test]
fn a15_mainnet_peer_driven_refused_even_when_fresh_and_applied() {
    let outcome = mainnet_peer_driven_fixture_outcome();
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
}

// A16. Run 232 replay/freshness runtime integration remains compatible.
#[test]
fn a16_run232_remains_compatible() {
    let fx = devnet_success_fixture();
    let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
    // Run 232, run standalone, still authorizes a fresh mutate.
    let replay_outcome = integrate_governance_evaluator_replay_runtime(&replay_ctx);
    assert!(matches!(
        replay_outcome,
        GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. }
    ));
    // And it projects into the consume authorization view.
    assert_eq!(
        MutationAuthorizationOutcome::from_replay_runtime_outcome(&replay_outcome),
        MutationAuthorizationOutcome::AuthorizedFresh
    );
}

// A17. Run 234 consume boundary remains compatible (the consume layer drives the
// composed outcome on the after-success path).
#[test]
fn a17_run234_consume_boundary_remains_compatible() {
    let fx = devnet_success_fixture();
    let mut store = store_with_observation(&fx);
    // The composed integration honours the Run 234 after-success-only contract.
    assert_eq!(
        fx.run(&mut store),
        ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess
    );
    assert!(consume_integrated_as_after_success_only_post_mutation_step());
}

// ===========================================================================
// R — rejection scenarios R1–R35
// ===========================================================================

/// Assert that a replay-side perturbation fails closed before consume (a Run 232
/// replay-runtime fail-closed), performing no consume.
fn assert_replay_runtime_fail_closed(mutate: impl FnOnce(&mut Fixture)) {
    let mut fx = devnet_success_fixture();
    mutate(&mut fx);
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert!(
        matches!(
            outcome,
            ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)
        ),
        "expected ReplayRuntimeFailClosed, got {:?}",
        outcome
    );
    assert!(outcome.is_fail_closed());
    assert!(outcome.no_consume());
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

/// Assert that a consume-side perturbation fails closed on the consume binding
/// (a Run 234 consume fail-closed), performing no consume.
fn assert_consume_fail_closed(mutate: impl FnOnce(&mut Fixture)) {
    let mut fx = devnet_success_fixture();
    mutate(&mut fx);
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert!(
        matches!(outcome, ReplayConsumeRuntimeOutcome::ConsumeFailClosed { .. }),
        "expected ConsumeFailClosed, got {:?}",
        outcome
    );
    assert!(outcome.no_consume());
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// R1. expired decision rejected before consume.
#[test]
fn r1_expired_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.current_canonical_epoch = EXPIRY + 50);
}

// R2. stale decision rejected before consume.
#[test]
fn r2_stale_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.effective_epoch = 200;
        fx.replay_input.expiry_epoch = 100;
        fx.replay_exp.expected_effective_epoch = 200;
        fx.replay_exp.expected_expiry_epoch = 100;
    });
}

fn seen_record(consumed: bool, superseded: bool) -> PreviouslySeenState {
    PreviouslySeenState::Seen(SeenDecisionRecord {
        state_key_digest: "k".to_string(),
        replay_nonce: NONCE.to_string(),
        recorded_sequence: SEQUENCE,
        recorded_effective_epoch: EFFECTIVE,
        recorded_expiry_epoch: EXPIRY,
        observation_count: 1,
        consumed,
        superseded,
    })
}

// R3. replayed decision rejected before consume.
#[test]
fn r3_replayed_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.previously_seen = seen_record(false, false));
}

// R4. already-consumed decision rejected before consume.
#[test]
fn r4_already_consumed_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.previously_seen = seen_record(true, false));
}

// R5. superseded decision rejected before consume.
#[test]
fn r5_superseded_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.previously_seen = seen_record(false, true));
}

// R6. wrong environment rejected before consume.
#[test]
fn r6_wrong_environment_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.environment = TrustBundleEnvironment::Testnet
    });
}

// R7. wrong chain rejected before consume.
#[test]
fn r7_wrong_chain_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.chain_id = "wrong-chain".to_string());
}

// R8. wrong genesis rejected before consume.
#[test]
fn r8_wrong_genesis_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.genesis_hash = "wrong-genesis".to_string());
}

// R9. wrong validation surface rejected before consume.
#[test]
fn r9_wrong_validation_surface_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck
    });
}

// R10. wrong mutation surface rejected before consume (consume-binding).
#[test]
fn r10_wrong_mutation_surface_rejected_before_consume() {
    assert_consume_fail_closed(|fx| {
        fx.consume_input.mutation_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

// R11. wrong source identity digest rejected before consume.
#[test]
fn r11_wrong_source_identity_digest_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.evaluator_source_identity_digest = "wrong".to_string()
    });
}

// R12. wrong request digest rejected before consume.
#[test]
fn r12_wrong_request_digest_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.evaluator_request_digest = "wrong".to_string()
    });
}

// R13. wrong response digest rejected before consume.
#[test]
fn r13_wrong_response_digest_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.evaluator_response_digest = "wrong".to_string()
    });
}

// R14. wrong transcript digest rejected before consume.
#[test]
fn r14_wrong_transcript_digest_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.evaluator_transcript_digest = "wrong".to_string()
    });
}

// R15. wrong proposal id rejected before consume.
#[test]
fn r15_wrong_proposal_id_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.proposal_id = "wrong".to_string());
}

// R16. wrong decision id rejected before consume.
#[test]
fn r16_wrong_decision_id_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.decision_id = "wrong".to_string());
}

// R17. wrong lifecycle action rejected before consume.
#[test]
fn r17_wrong_lifecycle_action_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.lifecycle_action = LocalLifecycleAction::Revoke
    });
}

// R18. wrong candidate digest rejected before consume.
#[test]
fn r18_wrong_candidate_digest_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.candidate_digest = "wrong".to_string());
}

// R19. wrong authority-domain sequence rejected before consume.
#[test]
fn r19_wrong_authority_domain_sequence_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.authority_domain_sequence = SEQUENCE + 1);
}

// R20. wrong replay nonce rejected before consume.
#[test]
fn r20_wrong_replay_nonce_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| fx.replay_input.replay_nonce = "wrong".to_string());
}

// R21. malformed replay state rejected before consume.
#[test]
fn r21_malformed_replay_state_rejected_before_consume() {
    assert_replay_runtime_fail_closed(|fx| {
        fx.replay_input.evaluator_request_digest = String::new()
    });
}

// R22. malformed consume state rejected.
#[test]
fn r22_malformed_consume_state_rejected() {
    assert_consume_fail_closed(|fx| fx.consume_input.replay_state_key_digest = String::new());
}

// R23. consume attempted before apply rejected.
#[test]
fn r23_consume_before_apply_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AuthorizedButNotApplied,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(outcome, ReplayConsumeRuntimeOutcome::DoNotConsumeBeforeApply);
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// R24. consume attempted after failed apply rejected.
#[test]
fn r24_consume_after_failed_apply_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::ApplyFailed,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    assert_eq!(
        fx.run(&mut store),
        ReplayConsumeRuntimeOutcome::DoNotConsumeApplyFailed
    );
}

// R25. consume attempted after rollback rejected.
#[test]
fn r25_consume_after_rollback_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::RolledBack,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    assert_eq!(
        fx.run(&mut store),
        ReplayConsumeRuntimeOutcome::DoNotConsumeRolledBack
    );
}

// R26. consume attempted on validation-only surface rejected.
#[test]
fn r26_consume_on_validation_only_surface_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::ProceedValidationOnlyNoConsume
    );
    assert!(outcome.no_consume());
}

// R27. consume attempted on unsupported surface rejected.
#[test]
fn r27_consume_on_unsupported_surface_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::UnsupportedSurface,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    assert_eq!(
        fx.run(&mut store),
        ReplayConsumeRuntimeOutcome::DoNotConsumeUnsupportedSurface
    );
}

// R28. production consume unavailable rejected.
#[test]
fn r28_production_consume_unavailable_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::Production,
    );
    let mut store = store_with_observation(&fx);
    assert_eq!(
        fx.run(&mut store),
        ReplayConsumeRuntimeOutcome::ProductionConsumeUnavailable
    );
    assert!(production_mainnet_consume_remains_unavailable_under_consume_runtime());
}

// R29. MainNet consume unavailable/refused rejected.
#[test]
fn r29_mainnet_consume_unavailable_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::MainNet,
    );
    let mut store = store_with_observation(&fx);
    assert_eq!(
        fx.run(&mut store),
        ReplayConsumeRuntimeOutcome::MainNetConsumeUnavailable
    );
}

// R30. local operator cannot satisfy consume policy.
#[test]
fn r30_local_operator_cannot_satisfy_consume_policy() {
    assert!(local_operator_cannot_satisfy_consume_policy());
}

// R31. peer majority cannot satisfy consume policy.
#[test]
fn r31_peer_majority_cannot_satisfy_consume_policy() {
    assert!(peer_majority_cannot_satisfy_consume_policy());
}

// R32. validator-set rotation unsupported rejected.
#[test]
fn r32_validator_set_rotation_unsupported_rejected() {
    assert!(validator_set_rotation_remains_unsupported_under_consume_runtime());
}

// R33. policy-change action unsupported rejected.
#[test]
fn r33_policy_change_action_unsupported_rejected() {
    assert!(policy_change_action_remains_unsupported_under_consume_runtime());
}

// R34. rejection produces no Run 070 call, no live trust swap, no session
// eviction, no sequence write, and no marker write (non-mutating).
#[test]
fn r34_rejection_is_non_mutating() {
    // A failed-apply rejection performed against a fixture store with a prior
    // observation records no consume: the writer is never invoked on a
    // non-consume path.
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::ApplyFailed,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store = store_with_observation(&fx);
    let outcome = fx.run(&mut store);
    assert_eq!(outcome, ReplayConsumeRuntimeOutcome::DoNotConsumeApplyFailed);
    assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));

    // A replay-side rejection against an empty store records nothing at all.
    let mut fx2 = devnet_success_fixture();
    fx2.replay_input.current_canonical_epoch = EXPIRY + 50;
    let mut empty = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let outcome2 = fx2.run(&mut empty);
    assert!(matches!(
        outcome2,
        ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)
    ));
    assert!(empty.is_empty());
}

// R35. MainNet peer-driven apply remains refused and does not consume even if
// replay state is fresh.
#[test]
fn r35_mainnet_peer_driven_refused_does_not_consume_even_if_fresh() {
    let outcome = mainnet_peer_driven_fixture_outcome();
    assert_eq!(
        outcome,
        ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(outcome.no_consume());
}

// ===========================================================================
// Focused invariant coverage
// ===========================================================================

// Ordering: consume happens only after a modeled successful mutation completion.
#[test]
fn consume_only_after_successful_mutation_completion() {
    for completion in [
        MutationCompletionStatus::NotAttempted,
        MutationCompletionStatus::AuthorizedButNotApplied,
        MutationCompletionStatus::AppliedSuccessfully,
        MutationCompletionStatus::ApplyFailed,
        MutationCompletionStatus::RolledBack,
        MutationCompletionStatus::ValidationOnly,
        MutationCompletionStatus::UnsupportedSurface,
    ] {
        let fx = rotate_fixture(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            completion,
            ReplayStatePolicy::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let outcome = fx.run(&mut store);
        if completion == MutationCompletionStatus::AppliedSuccessfully {
            assert!(outcome.authorizes_consume(), "{:?}", completion);
            assert!(store.is_consumed(&fx.consume_input.replay_state_key_digest));
        } else {
            assert!(outcome.no_consume(), "{:?} unexpectedly consumed", completion);
            assert!(!store.is_consumed(&fx.consume_input.replay_state_key_digest));
        }
    }
    assert!(fresh_required_before_mutation_authorization_under_consume_runtime());
    assert!(deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime());
}

// Fixture consume updates state only after success: an after-success consume with
// no prior observation fails closed unavailable and records nothing.
#[test]
fn fixture_consume_without_prior_observation_fails_closed() {
    let fx = devnet_success_fixture();
    let mut empty = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let outcome = fx.run(&mut empty);
    assert!(
        matches!(outcome, ReplayConsumeRuntimeOutcome::ConsumeFailClosed { .. }),
        "{:?}",
        outcome
    );
    assert!(!empty.is_consumed(&fx.consume_input.replay_state_key_digest));
}

// The call-site wiring surfaces a proceed for the consume path and a fail-closed
// for a non-proceed outcome.
#[test]
fn callsite_wiring_partitions_proceed_and_fail_closed() {
    // Proceed (successful consume).
    let fx = devnet_success_fixture();
    let mut store = store_with_observation(&fx);
    let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
    let input = ReplayConsumeRuntimeIntegrationInput {
        replay_runtime: &replay_ctx,
        consume_input: &fx.consume_input,
        consume_expectations: &fx.consume_exp,
        consume_policy: fx.consume_policy,
    };
    assert!(wire_replay_consume_runtime_callsite(&input, &mut store).is_ok());

    // Fail-closed (failed apply).
    let fx2 = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::ApplyFailed,
        ReplayStatePolicy::FixtureDevNet,
    );
    let mut store2 = store_with_observation(&fx2);
    let replay_ctx2 = fx2.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
    let input2 = ReplayConsumeRuntimeIntegrationInput {
        replay_runtime: &replay_ctx2,
        consume_input: &fx2.consume_input,
        consume_expectations: &fx2.consume_exp,
        consume_policy: fx2.consume_policy,
    };
    let err = wire_replay_consume_runtime_callsite(&input2, &mut store2).unwrap_err();
    assert_eq!(
        err.outcome,
        ReplayConsumeRuntimeOutcome::DoNotConsumeApplyFailed
    );
    assert_eq!(err.surface, GovernanceExecutionRuntimeSurface::ReloadApply);
}

// Typed-input accessors expose the modeled surfaces / environment / chain /
// genesis.
#[test]
fn typed_input_accessors_expose_bound_fields() {
    let fx = devnet_success_fixture();
    let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
    let input = ReplayConsumeRuntimeIntegrationInput {
        replay_runtime: &replay_ctx,
        consume_input: &fx.consume_input,
        consume_expectations: &fx.consume_exp,
        consume_policy: fx.consume_policy,
    };
    assert_eq!(
        input.mutation_surface(),
        GovernanceExecutionRuntimeSurface::ReloadApply
    );
    assert_eq!(
        input.mutation_completion_status(),
        MutationCompletionStatus::AppliedSuccessfully
    );
    assert_eq!(
        input.validation_surface(),
        GovernanceExecutionRuntimeSurface::ReloadApply
    );
    assert_eq!(input.environment(), TrustBundleEnvironment::Devnet);
    assert_eq!(input.chain_id(), CHAIN);
    assert_eq!(input.genesis_hash(), GENESIS);
}
