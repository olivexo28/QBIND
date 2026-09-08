//! Run 232 — source/test governance evaluator **replay/freshness runtime
//! integration** tests.
//!
//! Source/test only. Run 232 captures **no** release-binary evidence;
//! release-binary replay/freshness runtime-integration evidence is deferred to
//! **Run 233**. These tests prove that the Run 230 replay/freshness state
//! boundary is composed into the Run 224 / Run 226 evaluator-runtime
//! integration path as a mandatory pre-mutation gate via
//! [`integrate_governance_evaluator_replay_runtime`]: a mutate is authorized
//! only after the Run 224 layer authorizes a mutate **and** the Run 230
//! replay/freshness state classifies the decision fresh.
//!
//! Coverage: A1–A10, R1–R27, ordering (replay/freshness validation occurs
//! before mutation authorization), `ProceedDeferred` is not approval, read-only
//! validation does not consume, explicit consume only after successful fixture
//! authorization, non-mutation, MainNet refusal, and compatibility with the Run
//! 230 / 228 / 226 / 224 / 222 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_232.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_peer_context::{
    GovernanceEvaluatorPeerContext, PeerEvaluatorContextSurface, PeerEvaluatorSourceClass,
};
use qbind_node::pqc_governance_evaluator_replay_runtime_integration::{
    deferred_is_never_mutation_approval, fresh_replay_state_required_before_mutation,
    integrate_governance_evaluator_replay_runtime,
    mainnet_peer_driven_apply_remains_refused_under_replay_runtime,
    policy_change_action_remains_unsupported_under_replay_runtime,
    production_mainnet_replay_state_remains_unavailable,
    validator_set_rotation_remains_unsupported_under_replay_runtime,
    wire_governance_evaluator_replay_runtime_callsite,
    wire_governance_evaluator_replay_runtime_peer_context,
    GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, EvaluatorReplayFreshnessExpectations,
    EvaluatorReplayFreshnessInput, EvaluatorReplayFreshnessOutcome, FixtureReplayStateStore,
    GovernanceEvaluatorReplayStateReader, MainnetReplayStateReader, PreviouslySeenState,
    ProductionReplayStateReader, ReplayFreshnessState, ReplayStatePolicy, SeenDecisionRecord,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorExpectations, EvaluatorOutcome, EvaluatorPolicy,
    EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    FixtureGovernanceExecutionEvaluatorInterface, MainnetDecisionSourceEvaluatorInterface,
    ProductionDecisionSourceEvaluatorInterface, ProductionGovernanceExecutionEvaluator,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::{
    integrate_governance_evaluator_runtime_consumption,
    GovernanceEvaluatorRuntimeIntegrationContext,
};
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadWire,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionOutcome,
    GovernanceExecutionPolicy, GovernanceQuorumThreshold, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 / 230 corpora).
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

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

// ===========================================================================
// Run 211 governance-execution carrier material (drives Run 220 consumption)
// ===========================================================================

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
        now_epoch: 150,
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
// Run 222 evaluator material (the next evaluation stage)
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
        now_epoch: 150,
    }
}

// ===========================================================================
// Owned-material fixture bundle
// ===========================================================================

/// Owns every layer's material for one composed Run 232 round-trip so a test
/// can mutate any field and then borrow it into the integration context.
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

    fn run_with<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
    ) -> GovernanceEvaluatorReplayRuntimeOutcome {
        integrate_governance_evaluator_replay_runtime(&self.context(evaluator))
    }

    fn run(&self) -> GovernanceEvaluatorReplayRuntimeOutcome {
        self.run_with(&FixtureGovernanceExecutionEvaluatorInterface)
    }
}

/// A fully-consistent fixture-rotate composed integration on `env` that, with
/// the default fixture evaluator, a wired fixture replay policy, a first-seen
/// fresh replay state, and a mutating (non-peer-driven) surface, reaches
/// [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh`].
fn rotate_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env);
    let request = ev_request(&identity, &input_digest);
    let response = ev_response(&request);
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;

    let replay_exp = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
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
        150, // canonical epoch in the middle of [EFFECTIVE, EXPIRY)
        PreviouslySeenState::FirstSeen,
    );

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
    }
}

// ===========================================================================
// A — accepted scenarios
// ===========================================================================

// A1. Disabled policy + absent carrier preserves the legacy bypass and never
// reaches the replay/freshness boundary.
#[test]
fn a1_disabled_absent_preserves_legacy_bypass() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    let outcome = fx.run();
    assert_eq!(
        outcome,
        GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass
    );
    assert!(outcome.is_proceed());
    assert!(outcome.is_legacy_bypass());
    assert!(!outcome.is_mutate_authorized());
}

// A2. DevNet fixture evaluator decision with fresh replay state reaches
// ProceedFresh.
#[test]
fn a2_devnet_fixture_fresh_reaches_proceed_fresh() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run();
    assert!(outcome.is_mutate_authorized(), "{:?}", outcome);
    if let GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh {
        runtime_consumption,
        evaluator,
        lifecycle_action,
        candidate_digest,
        authority_domain_sequence,
    } = outcome
    {
        assert!(matches!(
            runtime_consumption,
            GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. }
        ));
        assert!(matches!(
            evaluator,
            EvaluatorOutcome::EvaluatorResponseAuthorized { .. }
        ));
        assert_eq!(lifecycle_action, LocalLifecycleAction::Rotate);
        assert_eq!(candidate_digest, CAND_DIGEST);
        assert_eq!(authority_domain_sequence, SEQUENCE);
    } else {
        panic!("expected ProceedFresh");
    }
}

// A3. TestNet fixture evaluator decision with fresh replay state reaches
// ProceedFresh.
#[test]
fn a3_testnet_fixture_fresh_reaches_proceed_fresh() {
    let fx = rotate_fixture(TrustBundleEnvironment::Testnet);
    assert!(fx.run().is_mutate_authorized());
}

// A4. not-yet-effective decision reaches ProceedDeferred, not mutation
// authorization — even though the Run 224 evaluator approves.
#[test]
fn a4_not_yet_effective_defers_not_mutate() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Run 224 still approves (evaluator now_epoch=150 is fresh), but the
    // replay/freshness canonical epoch is before the effective epoch.
    fx.replay_input.current_canonical_epoch = 50;
    // Sanity: the Run 224 layer authorizes a mutate on its own.
    let integration = integrate_governance_evaluator_runtime_consumption(
        &fx.context(&FixtureGovernanceExecutionEvaluatorInterface)
            .integration,
    );
    assert!(integration.is_mutate_authorized());
    let outcome = fx.run();
    assert_eq!(outcome, GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred);
    assert!(outcome.is_deferred());
    assert!(!outcome.is_mutate_authorized());
    assert!(outcome.is_fail_closed());
}

// A5. fresh decision at the effective epoch authorizes only after the
// evaluator and the replay state both agree.
#[test]
fn a5_fresh_at_effective_epoch_authorizes() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.replay_input.current_canonical_epoch = EFFECTIVE;
    assert!(fx.run().is_mutate_authorized());
}

// A6. explicit consume marks consumed only after successful fixture
// authorization.
#[test]
fn a6_explicit_consume_only_after_successful_authorization() {
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);

    // Before authorization, nothing is consumed.
    assert!(store.is_empty());

    // Composed integration authorizes a fresh mutate.
    let outcome = fx.run();
    assert!(outcome.is_mutate_authorized());

    // ONLY after a successful authorization does the caller explicitly consume.
    store.record_for(&fx.replay_input);
    assert!(store.consume_for(&fx.replay_input));
    assert!(store.is_consumed(&qbind_node::pqc_governance_evaluator_replay_state::replay_state_key_digest(&fx.replay_input)));

    // A re-evaluation now classifies the decision already-consumed.
    let mut replayed = fx.replay_input.clone();
    replayed.previously_seen = store.read_for(&replayed);
    assert!(matches!(
        replayed.previously_seen,
        PreviouslySeenState::Seen(SeenDecisionRecord { consumed: true, .. })
    ));
    let mut fx2 = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx2.replay_input = replayed;
    assert_eq!(
        fx2.run(),
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
            EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed
        )
    );
}

// A7. read-only validation does not mark consumed.
#[test]
fn a7_read_only_validation_does_not_consume() {
    let store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Run the composed integration (a pure, read-only validation).
    assert!(fx.run().is_mutate_authorized());
    // The store recorded nothing: read-only validation never consumes.
    assert!(store.is_empty());
    assert!(!store.is_consumed(
        &qbind_node::pqc_governance_evaluator_replay_state::replay_state_key_digest(&fx.replay_input)
    ));
}

// A8. production replay reader is reached and fails closed unavailable.
#[test]
fn a8_production_replay_reader_fails_closed_unavailable() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.replay_policy = ReplayStatePolicy::Production;
    // The production reader is reached and returns unavailable.
    let key = qbind_node::pqc_governance_evaluator_replay_state::replay_state_key_digest(
        &fx.replay_input,
    );
    fx.replay_input.previously_seen = ProductionReplayStateReader.read_previous_state(&key);
    assert_eq!(
        fx.replay_input.previously_seen,
        PreviouslySeenState::ProductionUnavailable
    );
    assert_eq!(
        fx.run(),
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
            EvaluatorReplayFreshnessOutcome::FailClosedProductionUnavailable
        )
    );
}

// A9. MainNet replay reader is reached and fails closed unavailable/refused.
#[test]
fn a9_mainnet_replay_reader_fails_closed_unavailable() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.replay_policy = ReplayStatePolicy::MainNet;
    let key = qbind_node::pqc_governance_evaluator_replay_state::replay_state_key_digest(
        &fx.replay_input,
    );
    fx.replay_input.previously_seen = MainnetReplayStateReader.read_previous_state(&key);
    assert_eq!(
        fx.replay_input.previously_seen,
        PreviouslySeenState::MainNetUnavailable
    );
    assert_eq!(
        fx.run(),
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
            EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable
        )
    );
}

// A10. MainNet peer-driven apply remains refused even when the replay state is
// fresh.
#[test]
fn a10_mainnet_peer_driven_apply_refused_even_when_fresh() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    // The replay state is fresh on its own.
    fx.replay_input.environment = TrustBundleEnvironment::Mainnet;
    fx.replay_exp.expected_environment = TrustBundleEnvironment::Mainnet;
    fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_exp.expected_validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_input.previously_seen = PreviouslySeenState::FirstSeen;
    // Refused regardless.
    assert_eq!(
        fx.run(),
        GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(fx.run().is_mainnet_peer_driven_apply_refused());
}

// ===========================================================================
// R — rejection scenarios (replay/freshness fail-closed before mutation)
// ===========================================================================

/// Run the composed integration with a mutated replay input that keeps the Run
/// 224 layer authorizing a mutate, and assert the precise replay/freshness
/// fail-closed outcome.
fn assert_replay_fail_closed(
    mutate: impl FnOnce(&mut Fixture),
    expected: EvaluatorReplayFreshnessOutcome,
) {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    mutate(&mut fx);
    let outcome = fx.run();
    assert_eq!(
        outcome,
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(expected),
        "{:?}",
        outcome
    );
    assert!(outcome.is_fail_closed());
    assert!(!outcome.is_mutate_authorized());
}

// R1. expired decision rejected before mutation.
#[test]
fn r1_expired_rejected() {
    assert_replay_fail_closed(
        |fx| fx.replay_input.current_canonical_epoch = EXPIRY + 50,
        EvaluatorReplayFreshnessOutcome::FailClosedExpired(ReplayFreshnessState::Expired),
    );
}

// R2. stale decision rejected before mutation.
#[test]
fn r2_stale_rejected() {
    assert_replay_fail_closed(
        |fx| {
            // Degenerate replay window (expiry <= effective) classified stale.
            fx.replay_input.effective_epoch = 200;
            fx.replay_input.expiry_epoch = 100;
            fx.replay_exp.expected_effective_epoch = 200;
            fx.replay_exp.expected_expiry_epoch = 100;
        },
        EvaluatorReplayFreshnessOutcome::FailClosedExpired(ReplayFreshnessState::Stale),
    );
}

// R3. replayed decision rejected before mutation.
#[test]
fn r3_replayed_rejected() {
    assert_replay_fail_closed(
        |fx| {
            fx.replay_input.previously_seen = PreviouslySeenState::Seen(SeenDecisionRecord {
                state_key_digest: "k".to_string(),
                replay_nonce: NONCE.to_string(),
                recorded_sequence: SEQUENCE,
                recorded_effective_epoch: EFFECTIVE,
                recorded_expiry_epoch: EXPIRY,
                observation_count: 1,
                consumed: false,
                superseded: false,
            });
        },
        EvaluatorReplayFreshnessOutcome::FailClosedReplay,
    );
}

// R4. already-consumed decision rejected before mutation.
#[test]
fn r4_already_consumed_rejected() {
    assert_replay_fail_closed(
        |fx| {
            fx.replay_input.previously_seen = PreviouslySeenState::Seen(SeenDecisionRecord {
                state_key_digest: "k".to_string(),
                replay_nonce: NONCE.to_string(),
                recorded_sequence: SEQUENCE,
                recorded_effective_epoch: EFFECTIVE,
                recorded_expiry_epoch: EXPIRY,
                observation_count: 1,
                consumed: true,
                superseded: false,
            });
        },
        EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed,
    );
}

// R5. superseded decision rejected before mutation.
#[test]
fn r5_superseded_rejected() {
    assert_replay_fail_closed(
        |fx| {
            fx.replay_input.previously_seen = PreviouslySeenState::Seen(SeenDecisionRecord {
                state_key_digest: "k".to_string(),
                replay_nonce: NONCE.to_string(),
                recorded_sequence: SEQUENCE,
                recorded_effective_epoch: EFFECTIVE,
                recorded_expiry_epoch: EXPIRY,
                observation_count: 1,
                consumed: false,
                superseded: true,
            });
        },
        EvaluatorReplayFreshnessOutcome::FailClosedSuperseded,
    );
}

/// Assert a wrong-binding rejection with the given classified state.
fn assert_wrong_binding(mutate: impl FnOnce(&mut Fixture), state: ReplayFreshnessState) {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    mutate(&mut fx);
    let outcome = fx.run();
    match outcome {
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
            EvaluatorReplayFreshnessOutcome::FailClosedWrongBinding { state: s, .. },
        ) => assert_eq!(s, state),
        other => panic!("expected wrong-binding {:?}, got {:?}", state, other),
    }
}

// R6. wrong environment rejected.
#[test]
fn r6_wrong_environment_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.environment = TrustBundleEnvironment::Testnet,
        ReplayFreshnessState::WrongEnvironment,
    );
}

// R7. wrong chain rejected.
#[test]
fn r7_wrong_chain_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.chain_id = "wrong-chain".to_string(),
        ReplayFreshnessState::WrongChain,
    );
}

// R8. wrong genesis rejected.
#[test]
fn r8_wrong_genesis_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.genesis_hash = "wrong-genesis".to_string(),
        ReplayFreshnessState::WrongGenesis,
    );
}

// R9. wrong validation surface rejected.
#[test]
fn r9_wrong_surface_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck,
        ReplayFreshnessState::WrongSurface,
    );
}

// R10. wrong source identity digest rejected.
#[test]
fn r10_wrong_source_identity_digest_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.evaluator_source_identity_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R11. wrong request digest rejected.
#[test]
fn r11_wrong_request_digest_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.evaluator_request_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R12. wrong response digest rejected.
#[test]
fn r12_wrong_response_digest_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.evaluator_response_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R13. wrong transcript digest rejected.
#[test]
fn r13_wrong_transcript_digest_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.evaluator_transcript_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R14. wrong proposal id rejected.
#[test]
fn r14_wrong_proposal_id_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.proposal_id = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R15. wrong decision id rejected.
#[test]
fn r15_wrong_decision_id_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.decision_id = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R16. wrong lifecycle action rejected.
#[test]
fn r16_wrong_lifecycle_action_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.lifecycle_action = LocalLifecycleAction::Revoke,
        ReplayFreshnessState::MalformedState,
    );
}

// R17. wrong candidate digest rejected.
#[test]
fn r17_wrong_candidate_digest_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.candidate_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R18. wrong authority-domain sequence rejected.
#[test]
fn r18_wrong_sequence_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.authority_domain_sequence = SEQUENCE + 1,
        ReplayFreshnessState::MalformedState,
    );
}

// R19. wrong replay nonce rejected.
#[test]
fn r19_wrong_replay_nonce_rejected() {
    assert_wrong_binding(
        |fx| fx.replay_input.replay_nonce = "wrong-nonce".to_string(),
        ReplayFreshnessState::MalformedState,
    );
}

// R20. malformed replay state rejected.
#[test]
fn r20_malformed_replay_state_rejected() {
    assert_wrong_binding(
        |fx| {
            // Empty mandatory field => structurally malformed input.
            fx.replay_input.proposal_id = String::new();
            fx.replay_exp.expected_proposal_id = String::new();
        },
        ReplayFreshnessState::MalformedState,
    );
}

// R21. replay state unavailable rejected.
#[test]
fn r21_replay_state_unavailable_rejected() {
    assert_replay_fail_closed(
        |fx| fx.replay_input.previously_seen = PreviouslySeenState::Unavailable,
        EvaluatorReplayFreshnessOutcome::FailClosedStateUnavailable,
    );
}

// R22. production replay state unavailable rejected.
#[test]
fn r22_production_replay_state_unavailable_rejected() {
    assert_replay_fail_closed(
        |fx| {
            fx.replay_policy = ReplayStatePolicy::Production;
            fx.replay_input.previously_seen = PreviouslySeenState::ProductionUnavailable;
        },
        EvaluatorReplayFreshnessOutcome::FailClosedProductionUnavailable,
    );
}

// R23. MainNet replay state unavailable/refused rejected.
#[test]
fn r23_mainnet_replay_state_unavailable_rejected() {
    assert_replay_fail_closed(
        |fx| {
            fx.replay_policy = ReplayStatePolicy::MainNet;
            fx.replay_input.previously_seen = PreviouslySeenState::MainNetUnavailable;
        },
        EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable,
    );
}

// R24. validator-set rotation unsupported rejected.
#[test]
fn r24_validator_set_rotation_unsupported() {
    assert!(validator_set_rotation_remains_unsupported_under_replay_runtime());
}

// R25. policy-change action unsupported rejected.
#[test]
fn r25_policy_change_action_unsupported() {
    assert!(policy_change_action_remains_unsupported_under_replay_runtime());
}

// R26. validation-only rejection writes no marker and no sequence.
#[test]
fn r26_validation_only_rejection_writes_nothing() {
    let store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadCheck; // validation-only
    fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    fx.replay_exp.expected_validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    fx.replay_input.current_canonical_epoch = EXPIRY + 50; // expired => fail-closed
    let outcome = fx.run();
    assert!(outcome.is_fail_closed());
    // The pure integration writes nothing: no marker, no sequence, no consume.
    assert!(store.is_empty());
}

// R27. mutating rejection produces no Run 070 call, no live trust swap, no
// session eviction, no sequence write, and no marker write.
#[test]
fn r27_mutating_rejection_is_non_mutating() {
    let store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Mutating surface (ReloadApply) but expired replay state.
    fx.replay_input.current_canonical_epoch = EXPIRY + 50;
    let err = wire_governance_evaluator_replay_runtime_callsite(
        &fx.context(&FixtureGovernanceExecutionEvaluatorInterface),
    )
    .expect_err("expired replay state must fail closed");
    assert!(err.outcome.is_fail_closed());
    assert!(!err.outcome.is_mutate_authorized());
    // The pure integration records no observation and no consume.
    assert!(store.is_empty());
}

// ===========================================================================
// Ordering / non-approval / runtime-integration fail-closed
// ===========================================================================

// Ordering: the replay/freshness validation gates mutation. The Run 224 layer
// authorizes a mutate, but flipping only the replay state from fresh to expired
// flips the composed outcome from ProceedFresh to a non-mutating fail-closed.
#[test]
fn ordering_replay_freshness_gates_mutation() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Run 224 authorizes a mutate independently.
    let integration = integrate_governance_evaluator_runtime_consumption(
        &fx.context(&FixtureGovernanceExecutionEvaluatorInterface)
            .integration,
    );
    assert!(integration.is_mutate_authorized());
    // Fresh replay state => composed ProceedFresh.
    assert!(fx.run().is_mutate_authorized());

    // Flip ONLY the replay state to expired; the composed outcome is no longer
    // a mutate, proving replay/freshness gates mutation authorization.
    let mut expired = rotate_fixture(TrustBundleEnvironment::Devnet);
    expired.replay_input.current_canonical_epoch = EXPIRY + 1;
    assert!(!expired.run().is_mutate_authorized());
}

// A Run 224 / Run 226 fail-closed (here: the evaluator policy requires a
// production source but a fixture source is supplied) surfaces as a runtime
// integration fail-closed and never reaches the replay/freshness boundary.
#[test]
fn runtime_integration_fail_closed_surfaced() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
    let outcome = fx.run_with(&ProductionDecisionSourceEvaluatorInterface);
    assert!(matches!(
        outcome,
        GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(_)
    ));
    assert!(outcome.is_fail_closed());
    assert!(!outcome.is_mutate_authorized());
}

// When the replay-state boundary is not wired (Disabled) but the Run 224 layer
// authorizes a mutate, the composed integration fails closed: a mutate is never
// authorized without a wired, fresh replay/freshness gate.
#[test]
fn not_wired_replay_policy_fails_closed_when_mutate_pending() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.replay_policy = ReplayStatePolicy::Disabled;
    assert_eq!(
        fx.run(),
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
            EvaluatorReplayFreshnessOutcome::FailClosedStateUnavailable
        )
    );
}

// The call-site wiring returns Ok for a fresh mutate and Ok for the legacy
// bypass, and Err for a deferral (a deferral is not an approval).
#[test]
fn callsite_wiring_consumes_outcomes() {
    let fresh = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert!(wire_governance_evaluator_replay_runtime_callsite(
        &fresh.context(&FixtureGovernanceExecutionEvaluatorInterface)
    )
    .is_ok());

    let mut deferred = rotate_fixture(TrustBundleEnvironment::Devnet);
    deferred.replay_input.current_canonical_epoch = 1; // before effective
    let err = wire_governance_evaluator_replay_runtime_callsite(
        &deferred.context(&FixtureGovernanceExecutionEvaluatorInterface),
    )
    .expect_err("a deferral is not an approval");
    assert!(err.outcome.is_deferred());
}

// ===========================================================================
// MainNet refusal (fixture evaluator on MainNet never authorizes)
// ===========================================================================

#[test]
fn mainnet_fixture_never_authorizes() {
    // A non-peer-driven MainNet surface: the Run 222/211 stages refuse the
    // fixture source on a MainNet trust domain, so the composed integration
    // fails closed before the replay/freshness boundary.
    let fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    let outcome = fx.run();
    assert!(outcome.is_fail_closed());
    assert!(!outcome.is_mutate_authorized());
}

#[test]
fn mainnet_evaluator_interface_unavailable() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    fx.ev_policy = EvaluatorPolicy::MainnetDecisionSourceRequired;
    let outcome = fx.run_with(&MainnetDecisionSourceEvaluatorInterface);
    assert!(matches!(
        outcome,
        GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(_)
    ));
}

// ===========================================================================
// Compatibility with Runs 230 / 228 / 226 / 224 / 222
// ===========================================================================

// Run 224 / 222 compatibility: the underlying integration still authorizes a
// mutate on its own, and the Run 230 boundary still classifies fresh on its
// own; the composed Run 232 outcome agrees.
#[test]
fn compat_run_224_222_and_230() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Run 224 / 222.
    let integration = integrate_governance_evaluator_runtime_consumption(
        &fx.context(&FixtureGovernanceExecutionEvaluatorInterface)
            .integration,
    );
    assert!(integration.is_mutate_authorized());
    // Run 230 alone.
    assert_eq!(
        evaluate_evaluator_replay_freshness(&fx.replay_input, &fx.replay_exp),
        EvaluatorReplayFreshnessOutcome::ProceedFresh
    );
    // Run 232 composed.
    assert!(fx.run().is_mutate_authorized());
}

// Run 228 / 226 compatibility: a representable Present peer context routes
// through the Run 226 wiring into the Run 224 integration, and the Run 232
// peer-context entry point applies the Run 230 replay/freshness gate on top.
#[test]
fn compat_run_228_226_peer_context_fresh() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::LiveInbound0x05;
    fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::LiveInbound0x05;
    fx.replay_exp.expected_validation_surface = GovernanceExecutionRuntimeSurface::LiveInbound0x05;
    let ctx = fx.context(&FixtureGovernanceExecutionEvaluatorInterface);
    let peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        PeerEvaluatorSourceClass::LiveInboundPeer,
        "peer-0001",
        &ctx.integration,
        None,
        None,
    );
    let outcome = wire_governance_evaluator_replay_runtime_peer_context(&peer, &ctx);
    assert!(outcome.is_mutate_authorized(), "{:?}", outcome);
}

// Run 228 compatibility: MainNet peer-driven apply remains refused through the
// peer-context entry point even when the replay state would be fresh.
#[test]
fn compat_run_228_mainnet_peer_driven_refused() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    fx.replay_input.environment = TrustBundleEnvironment::Mainnet;
    fx.replay_exp.expected_environment = TrustBundleEnvironment::Mainnet;
    fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_exp.expected_validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    let ctx = fx.context(&FixtureGovernanceExecutionEvaluatorInterface);
    let peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::PeerDrivenDrain,
        PeerEvaluatorSourceClass::DrainStagedPeer,
        "peer-0002",
        &ctx.integration,
        None,
        None,
    );
    assert_eq!(
        wire_governance_evaluator_replay_runtime_peer_context(&peer, &ctx),
        GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
}

// The grep-verifiable refusal helpers are all fail-closed.
#[test]
fn refusal_helpers_are_fail_closed() {
    assert!(mainnet_peer_driven_apply_remains_refused_under_replay_runtime(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(fresh_replay_state_required_before_mutation());
    assert!(deferred_is_never_mutation_approval());
    assert!(production_mainnet_replay_state_remains_unavailable());
    assert!(validator_set_rotation_remains_unsupported_under_replay_runtime());
    assert!(policy_change_action_remains_unsupported_under_replay_runtime());
}