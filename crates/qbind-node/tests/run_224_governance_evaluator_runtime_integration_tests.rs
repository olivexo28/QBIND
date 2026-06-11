//! Run 224 — source/test governance evaluator-runtime integration tests.
//!
//! Source/test only. Run 224 captures **no** release-binary evidence;
//! release-binary evaluator-runtime integration evidence is deferred to
//! **Run 225**. These tests prove that the Run 222 evaluator interface is
//! composed into the Run 220 runtime-consumption pipeline at the
//! source/test level via
//! [`integrate_governance_evaluator_runtime_consumption`], preserving the
//! documented ordering (selector resolution -> sidecar/load-status
//! derivation -> runtime consumption -> evaluator request construction ->
//! evaluator evaluation -> governance execution decision validation ->
//! lifecycle/governance/custody checks -> mutation only after all checks
//! pass).
//!
//! Coverage: A1–A12, R1–R30, ordering (evaluator evaluation happens before
//! any mutation authorization), deterministic digest binding, non-mutation
//! (the integration is a pure function), MainNet refusal, and compatibility
//! with the Run 220 runtime consumption and the Run 222 evaluator
//! interface.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_224.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_evaluator::{
    local_operator_cannot_satisfy_evaluator_policy,
    mainnet_peer_driven_apply_remains_refused_under_evaluator,
    peer_majority_cannot_satisfy_evaluator_policy,
    validator_set_rotation_remains_unsupported_under_evaluator, DecisionSourceIdentity,
    EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface, EvaluatorExpectations,
    EvaluatorOutcome, EvaluatorPolicy, EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    FixtureGovernanceExecutionEvaluatorInterface, MainnetDecisionSourceEvaluatorInterface,
    OnChainDecisionSourceEvaluatorInterface, ProductionDecisionSourceEvaluatorInterface,
    ProductionGovernanceExecutionEvaluator, EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::{
    integrate_governance_evaluator_runtime_consumption,
    integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value,
    GovernanceEvaluatorRuntimeIntegrationContext, GovernanceEvaluatorRuntimeIntegrationOutcome,
};
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadCarryingDecisionOutcome,
    GovernanceExecutionPayloadParseError, GovernanceExecutionPayloadWire,
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
// Shared constants (mirror the Run 220 / Run 222 corpora so the runtime
// consumption material and the evaluator material bind to the same trust
// domain, proposal/decision identity, candidate digest, and replay nonce).
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
const COMMIT: &str = "response-commitment-eeeeeeeeeeeeeeeeeeee";

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
        authority_domain_sequence: 7,
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        effective_epoch: 100,
        expiry_epoch: 200,
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
        authorized_sequence: 7,
        effective_epoch: 100,
        expiry_epoch: 200,
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
        expected_authority_domain_sequence: 7,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_effective_epoch: 100,
        expected_replay_nonce: NONCE.to_string(),
        now_epoch: 150,
    }
}

fn revoke_input(env: TrustBundleEnvironment) -> GovernanceExecutionInput {
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::Revoke;
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    input.revoked_signing_key_fingerprint = Some(CUR_KEY.to_string());
    input
}

fn revoke_decision() -> GovernanceExecutionDecision {
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::Revoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    decision
}

fn revoke_gov_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_gov_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    exp
}

fn emergency_input(env: TrustBundleEnvironment) -> GovernanceExecutionInput {
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::EmergencyCouncilFixture;
    input.governance_action = GovernanceAction::EmergencyRevoke;
    input.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    input.emergency_flag = true;
    input.revoked_signing_key_fingerprint = Some(CUR_KEY.to_string());
    input
}

fn emergency_decision() -> GovernanceExecutionDecision {
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::EmergencyRevoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    decision.emergency_flag = true;
    decision.issuer_authority_class = GovernanceAuthorityClass::EmergencyCouncil;
    decision
}

fn emergency_gov_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_gov_expectations(env);
    exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    exp
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

fn ev_identity(
    env: TrustBundleEnvironment,
    kind: EvaluatorSourceKind,
) -> DecisionSourceIdentity {
    let (governance_class, issuer) = match kind {
        EvaluatorSourceKind::EmergencyCouncilFixtureSource => (
            GovernanceExecutionClass::EmergencyCouncilFixture,
            GovernanceAuthorityClass::EmergencyCouncil,
        ),
        _ => (
            GovernanceExecutionClass::FixtureGovernance,
            GovernanceAuthorityClass::GenesisBound,
        ),
    };
    DecisionSourceIdentity {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        source_kind: kind,
        source_id: SOURCE_ID.to_string(),
        governance_class,
        issuer_authority_class: issuer,
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

fn ev_request(
    identity: &DecisionSourceIdentity,
    input_digest: &str,
    governance_action: GovernanceAction,
    lifecycle_action: LocalLifecycleAction,
    emergency: bool,
) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: input_digest.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action,
        lifecycle_action,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: 7,
        effective_epoch: 100,
        expiry_epoch: 200,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: emergency,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn ev_response(
    request: &EvaluatorRequest,
    governance_action: GovernanceAction,
    lifecycle_action: LocalLifecycleAction,
    emergency: bool,
) -> EvaluatorResponse {
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: governance_action,
        authorized_lifecycle_action: lifecycle_action,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: 7,
        effective_epoch: 100,
        expiry_epoch: 200,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: 100,
        response_expiry_epoch: 200,
        emergency_flag: emergency,
        response_commitment: COMMIT.to_string(),
    }
}

fn ev_expectations(
    env: TrustBundleEnvironment,
    input_digest: &str,
    governance_action: GovernanceAction,
    lifecycle_action: LocalLifecycleAction,
) -> EvaluatorExpectations {
    EvaluatorExpectations {
        expected_evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        expected_environment: env,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_governance_action: governance_action,
        expected_lifecycle_action: lifecycle_action,
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: 7,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_effective_epoch: 100,
        expected_expiry_epoch: 200,
        expected_replay_nonce: NONCE.to_string(),
        expected_governance_execution_input_digest: input_digest.to_string(),
        now_epoch: 150,
    }
}

// ===========================================================================
// Owned-material fixture bundle
// ===========================================================================

/// Owns every layer's material for one integration round-trip so a test can
/// mutate any field and then borrow it into the integration context.
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
}

impl Fixture {
    fn run_with<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
    ) -> GovernanceEvaluatorRuntimeIntegrationOutcome {
        let ctx = GovernanceEvaluatorRuntimeIntegrationContext {
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
        };
        integrate_governance_evaluator_runtime_consumption(&ctx)
    }

    fn run(&self) -> GovernanceEvaluatorRuntimeIntegrationOutcome {
        self.run_with(&FixtureGovernanceExecutionEvaluatorInterface)
    }
}

/// A fully-consistent fixture-rotate integration on `env` that, with the
/// default fixture evaluator, reaches [`GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate`].
fn rotate_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env, EvaluatorSourceKind::FixtureDecisionSource);
    let request = ev_request(
        &identity,
        &input_digest,
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
        false,
    );
    let response = ev_response(
        &request,
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
        false,
    );
    Fixture {
        arming: GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        td: trust_domain(env),
        load: available_from(&input, &decision),
        gov_exp: rotate_gov_expectations(env),
        ev_exp: ev_expectations(
            env,
            &input_digest,
            GovernanceAction::Rotate,
            LocalLifecycleAction::Rotate,
        ),
        identity,
        request,
        response,
        ev_policy: EvaluatorPolicy::FixtureDecisionSourceAllowed,
        peer_driven: false,
    }
}

fn revoke_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = revoke_input(env);
    let decision = revoke_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env, EvaluatorSourceKind::FixtureDecisionSource);
    let request = ev_request(
        &identity,
        &input_digest,
        GovernanceAction::Revoke,
        LocalLifecycleAction::Revoke,
        false,
    );
    let response = ev_response(
        &request,
        GovernanceAction::Revoke,
        LocalLifecycleAction::Revoke,
        false,
    );
    Fixture {
        arming: GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        td: trust_domain(env),
        load: available_from(&input, &decision),
        gov_exp: revoke_gov_expectations(env),
        ev_exp: ev_expectations(
            env,
            &input_digest,
            GovernanceAction::Revoke,
            LocalLifecycleAction::Revoke,
        ),
        identity,
        request,
        response,
        ev_policy: EvaluatorPolicy::FixtureDecisionSourceAllowed,
        peer_driven: false,
    }
}

fn emergency_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = emergency_input(env);
    let decision = emergency_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env, EvaluatorSourceKind::EmergencyCouncilFixtureSource);
    let request = ev_request(
        &identity,
        &input_digest,
        GovernanceAction::EmergencyRevoke,
        LocalLifecycleAction::EmergencyRevoke,
        true,
    );
    let response = ev_response(
        &request,
        GovernanceAction::EmergencyRevoke,
        LocalLifecycleAction::EmergencyRevoke,
        true,
    );
    Fixture {
        arming: GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        ),
        surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        td: trust_domain(env),
        load: available_from(&input, &decision),
        gov_exp: emergency_gov_expectations(env),
        ev_exp: ev_expectations(
            env,
            &input_digest,
            GovernanceAction::EmergencyRevoke,
            LocalLifecycleAction::EmergencyRevoke,
        ),
        identity,
        request,
        response,
        ev_policy: EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed,
        peer_driven: false,
    }
}

// ===========================================================================
// A — accepted scenarios
// ===========================================================================

// A1. Disabled policy with absent governance-execution carrier preserves the
// legacy `ProceedLegacyBypass` (Run 214 compatibility) and never reaches the
// evaluator.
#[test]
fn a1_disabled_absent_preserves_legacy_bypass() {
    let env = TrustBundleEnvironment::Devnet;
    let mut fx = rotate_fixture(env);
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    let outcome = fx.run();
    assert_eq!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass
    );
    assert!(outcome.is_proceed());
    assert!(outcome.is_legacy_bypass());
    assert!(!outcome.is_mutate_authorized());
}

// A2. DevNet fixture runtime consumption calls the fixture evaluator and
// accepts the matching evaluator response.
#[test]
fn a2_devnet_fixture_runtime_consumption_calls_evaluator_and_accepts() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run();
    assert!(outcome.is_mutate_authorized(), "{:?}", outcome);
    if let GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate {
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
        assert_eq!(authority_domain_sequence, 7);
    } else {
        panic!("expected ProceedMutate");
    }
}

// A3. TestNet fixture runtime consumption calls the fixture evaluator and
// accepts the matching evaluator response.
#[test]
fn a3_testnet_fixture_runtime_consumption_calls_evaluator_and_accepts() {
    let fx = rotate_fixture(TrustBundleEnvironment::Testnet);
    assert!(fx.run().is_mutate_authorized());
}

// A4. explicit emergency fixture runtime consumption calls the emergency
// evaluator and accepts only an explicit emergency action.
#[test]
fn a4_emergency_fixture_accepts_only_explicit_emergency_action() {
    let env = TrustBundleEnvironment::Devnet;
    let fx = emergency_fixture(env);
    let outcome = fx.run_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
    assert!(outcome.is_mutate_authorized(), "{:?}", outcome);

    // A non-emergency action under the emergency policy is refused.
    let mut non_emergency = emergency_fixture(env);
    non_emergency.request.emergency_flag = false;
    non_emergency.response.emergency_flag = false;
    let rejected =
        non_emergency.run_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
    assert!(!rejected.is_mutate_authorized());
}

// A5. evaluator request digest binds the governance-execution payload digest,
// proposal id, decision id, lifecycle action, candidate digest, sequence,
// epoch, expiry, replay nonce, and source identity.
#[test]
fn a5_request_digest_binds_every_field() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let base = fx.request.request_digest();
    assert_eq!(base, fx.request.request_digest(), "deterministic");

    let mut perturbed = fx.request.clone();
    perturbed.proposal_id = "other".to_string();
    assert_ne!(base, perturbed.request_digest());
    let mut perturbed = fx.request.clone();
    perturbed.candidate_digest = "other".to_string();
    assert_ne!(base, perturbed.request_digest());
    let mut perturbed = fx.request.clone();
    perturbed.authority_domain_sequence = 999;
    assert_ne!(base, perturbed.request_digest());
    let mut perturbed = fx.request.clone();
    perturbed.replay_nonce = "other".to_string();
    assert_ne!(base, perturbed.request_digest());
    let mut perturbed = fx.request.clone();
    perturbed.decision_source_identity_digest = "other".to_string();
    assert_ne!(base, perturbed.request_digest());
    let mut perturbed = fx.request.clone();
    perturbed.governance_execution_input_digest = "other".to_string();
    assert_ne!(base, perturbed.request_digest());
}

// A6. evaluator response digest binds the request digest, decision digest,
// action, candidate digest, sequence, epoch, expiry, and replay nonce.
#[test]
fn a6_response_digest_binds_every_field() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let base = fx.response.response_digest();
    assert_eq!(base, fx.response.response_digest(), "deterministic");

    let mut perturbed = fx.response.clone();
    perturbed.request_digest = "other".to_string();
    assert_ne!(base, perturbed.response_digest());
    let mut perturbed = fx.response.clone();
    perturbed.decision_digest = "other".to_string();
    assert_ne!(base, perturbed.response_digest());
    let mut perturbed = fx.response.clone();
    perturbed.authorized_candidate_digest = "other".to_string();
    assert_ne!(base, perturbed.response_digest());
    let mut perturbed = fx.response.clone();
    perturbed.authorized_authority_domain_sequence = 999;
    assert_ne!(base, perturbed.response_digest());
    let mut perturbed = fx.response.clone();
    perturbed.replay_nonce = "other".to_string();
    assert_ne!(base, perturbed.response_digest());
}

// A7. rotate action accepted only when runtime consumption, evaluator
// response, governance execution decision, candidate digest, and sequence all
// match.
#[test]
fn a7_rotate_accepted_only_when_all_match() {
    let env = TrustBundleEnvironment::Devnet;
    assert!(rotate_fixture(env).run().is_mutate_authorized());

    // Mismatched candidate digest in the evaluator response breaks the match.
    let mut fx = rotate_fixture(env);
    fx.response.authorized_candidate_digest = "different-candidate".to_string();
    assert!(!fx.run().is_mutate_authorized());

    // Mismatched sequence in the evaluator response breaks the match.
    let mut fx = rotate_fixture(env);
    fx.response.authorized_authority_domain_sequence = 8;
    assert!(!fx.run().is_mutate_authorized());
}

// A8. revoke action accepted only when runtime consumption, evaluator
// response, governance execution decision, revoked/candidate material, and
// sequence all match.
#[test]
fn a8_revoke_accepted_only_when_all_match() {
    let env = TrustBundleEnvironment::Devnet;
    assert!(revoke_fixture(env).run().is_mutate_authorized());

    let mut fx = revoke_fixture(env);
    fx.response.authorized_authority_domain_sequence = 9;
    assert!(!fx.run().is_mutate_authorized());
}

// A9. production evaluator path is reached and fails closed as unavailable.
#[test]
fn a9_production_evaluator_reached_fails_closed_unavailable() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run_with(&ProductionDecisionSourceEvaluatorInterface);
    assert!(matches!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
            EvaluatorOutcome::ProductionDecisionSourceUnavailable
        )
    ));
    assert!(!outcome.is_mutate_authorized());
}

// A10. on-chain evaluator path is reached and fails closed as unavailable.
#[test]
fn a10_onchain_evaluator_reached_fails_closed_unavailable() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run_with(&OnChainDecisionSourceEvaluatorInterface);
    assert!(matches!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
            EvaluatorOutcome::OnChainDecisionSourceUnavailable
        )
    ));
}

// A11. MainNet evaluator path is reached and fails closed / refused.
#[test]
fn a11_mainnet_evaluator_reached_fails_closed_unavailable() {
    // Use a non-MainNet trust domain so the runtime-consumption carrier
    // accepts and the integration reaches the MainNet evaluator interface,
    // which fails closed as unavailable.
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run_with(&MainnetDecisionSourceEvaluatorInterface);
    assert!(matches!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
            EvaluatorOutcome::MainnetDecisionSourceUnavailable
        )
    ));
}

// A12. MainNet peer-driven apply remains refused even with fixture evaluator
// approval.
#[test]
fn a12_mainnet_peer_driven_apply_refused_even_with_fixture_approval() {
    let env = TrustBundleEnvironment::Mainnet;
    let mut fx = rotate_fixture(env);
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    let outcome = fx.run();
    assert_eq!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(!outcome.is_mutate_authorized());
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
}

// ===========================================================================
// R — rejection scenarios (all non-mutating)
// ===========================================================================

// R1. missing governance-execution material rejected when evaluator policy
// requires it.
#[test]
fn r1_missing_material_required_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.load = GovernanceExecutionLoadStatus::Absent; // carrier missing
    let outcome = fx.run();
    assert!(matches!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::RuntimeConsumptionFailClosed(
            GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent { .. }
        )
    ));
    assert!(!outcome.is_mutate_authorized());
}

// R2. malformed governance-execution material rejected.
#[test]
fn r2_malformed_material_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.load = GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
        error: "broken".to_string(),
    });
    let outcome = fx.run();
    assert!(matches!(
        outcome,
        GovernanceEvaluatorRuntimeIntegrationOutcome::RuntimeConsumptionFailClosed(
            GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload(_)
        )
    ));
}

/// Assert that an integration outcome is an `EvaluatorRejected` carrying the
/// expected evaluator outcome predicate, and is non-mutating.
fn assert_evaluator_rejected(
    outcome: &GovernanceEvaluatorRuntimeIntegrationOutcome,
    pred: impl Fn(&EvaluatorOutcome) -> bool,
) {
    assert!(!outcome.is_mutate_authorized(), "{:?}", outcome);
    match outcome {
        GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(o) => {
            assert!(pred(o), "unexpected evaluator outcome: {:?}", o)
        }
        other => panic!("expected EvaluatorRejected, got {:?}", other),
    }
}

// R3. wrong evaluator source rejected.
#[test]
fn r3_wrong_evaluator_source_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Identity presents the emergency-council source kind, but the policy is
    // plain fixture-allowed -> source/kind policy mismatch.
    fx.identity.source_kind = EvaluatorSourceKind::EmergencyCouncilFixtureSource;
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::SourceKindPolicyMismatch { .. })
    });
}

// R4. wrong environment rejected.
#[test]
fn r4_wrong_environment_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_environment = TrustBundleEnvironment::Testnet;
    fx.identity.environment = TrustBundleEnvironment::Testnet;
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongEnvironment { .. })
    });
}

// R5. wrong chain rejected.
#[test]
fn r5_wrong_chain_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.identity.chain_id = "other-chain".to_string();
    fx.ev_exp.expected_chain_id = "other-chain".to_string();
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| matches!(o, EvaluatorOutcome::WrongChain { .. }));
}

// R6. wrong genesis rejected.
#[test]
fn r6_wrong_genesis_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.identity.genesis_hash = "other-genesis".to_string();
    fx.ev_exp.expected_genesis_hash = "other-genesis".to_string();
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongGenesis { .. })
    });
}

// R7. wrong authority root rejected.
#[test]
fn r7_wrong_authority_root_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.identity.authority_root_fingerprint = "other-root".to_string();
    fx.ev_exp.expected_authority_root_fingerprint = "other-root".to_string();
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongAuthorityRoot { .. })
    });
}

// R8. wrong governance proof digest rejected.
#[test]
fn r8_wrong_governance_proof_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.identity.governance_proof_digest = "other-gov-proof".to_string();
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongGovernanceProofDigest { .. })
    });
}

// R9. wrong on-chain proof digest rejected.
#[test]
fn r9_wrong_onchain_proof_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
    // identity.on_chain_proof_digest stays None -> mismatch.
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongOnChainProofDigest { .. })
    });
}

// R10. wrong custody attestation digest rejected.
#[test]
fn r10_wrong_custody_attestation_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongCustodyAttestationDigest { .. })
    });
}

// R11. wrong proposal id rejected.
#[test]
fn r11_wrong_proposal_id_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_proposal_id = "other-proposal".to_string();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongProposalId { .. })
    });
}

// R12. wrong decision id rejected.
#[test]
fn r12_wrong_decision_id_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_decision_id = "other-decision".to_string();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongDecisionId { .. })
    });
}

// R13. wrong lifecycle action rejected.
#[test]
fn r13_wrong_lifecycle_action_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongLifecycleAction { .. })
    });
}

// R14. wrong candidate digest rejected.
#[test]
fn r14_wrong_candidate_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_candidate_digest = "other-candidate".to_string();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongCandidateDigest { .. })
    });
}

// R15. wrong authority-domain sequence rejected.
#[test]
fn r15_wrong_sequence_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_authority_domain_sequence = 8;
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::WrongAuthorityDomainSequence { .. })
    });
}

// R16. expired evaluator request rejected.
#[test]
fn r16_expired_request_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.now_epoch = 250; // past the [100, 200) enactment window
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::ExpiredDecision { .. })
    });
}

// R17. stale/replayed evaluator request rejected.
#[test]
fn r17_stale_or_replayed_request_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_replay_nonce = "fresh-nonce".to_string();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::StaleOrReplayedDecision)
    });
}

// R18. quorum/threshold insufficient rejected.
#[test]
fn r18_quorum_insufficient_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.request.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::QuorumThresholdInsufficient { .. })
    });
}

// R19. emergency action not authorized rejected.
#[test]
fn r19_emergency_action_not_authorized_rejected() {
    // A plain-fixture policy with an emergency-flagged request is refused.
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.request.emergency_flag = true;
    fx.response.request_digest = fx.request.request_digest();
    fx.response.emergency_flag = true;
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::EmergencyActionNotAuthorized)
    });
}

// R20. validator-set rotation unsupported rejected.
#[test]
fn r20_validator_set_rotation_unsupported_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // The carrier remains a valid rotate; the evaluator request asks for an
    // unsupported validator-set rotation -> evaluator rejects.
    fx.request.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::ValidatorSetRotationUnsupported)
    });
    assert!(validator_set_rotation_remains_unsupported_under_evaluator());
}

// R21. policy-change action unsupported rejected.
#[test]
fn r21_policy_change_action_unsupported_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.request.governance_action = GovernanceAction::PolicyChangeRequest;
    fx.response.request_digest = fx.request.request_digest();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::PolicyChangeActionUnsupported)
    });
}

// R22. production evaluator unavailable rejected.
#[test]
fn r22_production_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run_with(&ProductionDecisionSourceEvaluatorInterface);
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::ProductionDecisionSourceUnavailable)
    });
}

// R23. on-chain evaluator unavailable rejected.
#[test]
fn r23_onchain_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run_with(&OnChainDecisionSourceEvaluatorInterface);
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::OnChainDecisionSourceUnavailable)
    });
}

// R24. MainNet evaluator unavailable/refused rejected.
#[test]
fn r24_mainnet_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    let outcome = fx.run_with(&MainnetDecisionSourceEvaluatorInterface);
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::MainnetDecisionSourceUnavailable)
    });
}

// R25. local operator cannot satisfy evaluator policy.
#[test]
fn r25_local_operator_cannot_satisfy_evaluator_policy() {
    assert!(local_operator_cannot_satisfy_evaluator_policy());
    // A production-required evaluator policy fails closed in the integration
    // regardless of any local-operator-supplied fixture material.
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
    assert!(!fx.run().is_mutate_authorized());
}

// R26. peer majority cannot satisfy evaluator policy.
#[test]
fn r26_peer_majority_cannot_satisfy_evaluator_policy() {
    assert!(peer_majority_cannot_satisfy_evaluator_policy());
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::MainnetDecisionSourceRequired;
    assert!(!fx.run().is_mutate_authorized());
}

// R27. evaluator valid but governance execution decision invalid rejected.
#[test]
fn r27_evaluator_valid_but_governance_decision_invalid_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // The evaluator material stays fully valid, but the carrier's Run 211
    // decision is invalid (wrong authorized sequence) so the Run 220 runtime
    // consumption rejects at the Callsite stage.
    let mut fx = rotate_fixture(env);
    let mut decision = rotate_decision();
    decision.authorized_sequence = 999; // mismatched -> Run 211 rejects
    fx.load = available_from(&rotate_input(env), &decision);
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::GovernanceExecutionDecisionInvalid { .. })
    });
}

// R28. governance execution decision valid but evaluator response invalid
// rejected.
#[test]
fn r28_governance_decision_valid_but_evaluator_response_invalid_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    // Carrier (Run 211) stays valid; the evaluator response commitment is the
    // explicit invalid sentinel.
    fx.response.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| {
        matches!(o, EvaluatorOutcome::InvalidResponseCommitment)
    });
}

// R29. validation-only rejection writes no marker and no sequence.
#[test]
fn r29_validation_only_rejection_is_non_mutating_and_pure() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadCheck; // validation-only
    fx.ev_exp.expected_candidate_digest = "other".to_string(); // force reject
    let first = fx.run();
    let second = fx.run();
    assert!(!first.is_mutate_authorized());
    assert_eq!(first, second, "integration is pure / repeatable");
}

// R30. mutating rejection produces no Run 070 call, no live trust swap, no
// session eviction, no sequence write, and no marker write.
#[test]
fn r30_mutating_rejection_is_non_mutating_and_pure() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadApply; // mutating surface
    fx.response.approved = false; // force evaluator response reject
    let first = fx.run();
    let second = fx.run();
    assert!(!first.is_mutate_authorized());
    assert!(first.is_fail_closed());
    assert_eq!(first, second, "integration is pure / repeatable");
}

// ===========================================================================
// Ordering, MainNet, sidecar derivation, and compatibility
// ===========================================================================

// Ordering: evaluator evaluation happens before any mutation authorization.
// A valid carrier + valid evaluator produces ProceedMutate; flipping either
// the runtime-consumption stage OR the evaluator stage to reject removes the
// mutation authorization — proving both stages gate mutation.
#[test]
fn ordering_both_stages_gate_mutation() {
    let env = TrustBundleEnvironment::Devnet;
    assert!(rotate_fixture(env).run().is_mutate_authorized());

    // Flip ONLY the evaluator stage to reject (carrier still valid).
    let mut ev_only = rotate_fixture(env);
    ev_only.response.approved = false;
    assert!(!ev_only.run().is_mutate_authorized());

    // Flip ONLY the runtime-consumption stage to reject (evaluator valid):
    // an absent carrier under a requiring policy fails closed before the
    // evaluator can authorize mutation.
    let mut rc_only = rotate_fixture(env);
    rc_only.load = GovernanceExecutionLoadStatus::Absent;
    let outcome = rc_only.run();
    assert!(!outcome.is_mutate_authorized());
    assert!(outcome.is_fail_closed());
}

// MainNet fixture sources are refused even off the peer-driven path: the
// underlying Run 211 / Run 222 stages refuse fixture material on MainNet.
#[test]
fn mainnet_fixture_runtime_consumption_refused() {
    let fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    assert!(!fx.run().is_mutate_authorized());
    assert!(mainnet_peer_driven_apply_remains_refused_under_evaluator(
        TrustBundleEnvironment::Mainnet
    ));
}

// MainNet peer-driven apply refused even when the evaluator would approve a
// fixture decision (explicit flag guard, any surface).
#[test]
fn mainnet_peer_driven_apply_refused_explicit_flag() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    fx.peer_driven = true;
    assert_eq!(
        fx.run(),
        GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused
    );
}

// Sidecar/load-status derivation: the convenience wrapper derives the Run 213
// load status from an in-memory sidecar JSON value and reaches the same
// ProceedMutate decision as the explicit-load-status entry point.
#[test]
fn sidecar_value_derivation_reaches_proceed_mutate() {
    let env = TrustBundleEnvironment::Devnet;
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let sidecar = serde_json::json!({
        "schema_version": 2,
        "governance_execution": serde_json::to_value(&wire).expect("wire serializes"),
    });

    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let td = trust_domain(env);
    let gov_exp = rotate_gov_expectations(env);
    let identity = ev_identity(env, EvaluatorSourceKind::FixtureDecisionSource);
    let request = ev_request(
        &identity,
        &input_digest,
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
        false,
    );
    let response = ev_response(
        &request,
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
        false,
    );
    let ev_exp = ev_expectations(
        env,
        &input_digest,
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
    );

    let outcome = integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value(
        &arming,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        &td,
        Some(&sidecar),
        &gov_exp,
        &FixtureGovernanceExecutionEvaluatorInterface,
        &identity,
        &request,
        &response,
        &ev_exp,
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
        false,
    );
    assert!(outcome.is_mutate_authorized(), "{:?}", outcome);

    // A `None` sidecar (no operator sidecar) under a requiring policy is
    // Absent -> fail closed.
    let none_outcome =
        integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value(
            &arming,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            &td,
            None,
            &gov_exp,
            &FixtureGovernanceExecutionEvaluatorInterface,
            &identity,
            &request,
            &response,
            &ev_exp,
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            false,
        );
    assert!(!none_outcome.is_mutate_authorized());
}

// Compatibility with Run 220: the integration reaches ProceedMutate across
// every representable runtime surface (except the MainNet-refused peer-driven
// drain, which is exercised separately) under a valid fixture round-trip.
#[test]
fn compat_run220_all_surfaces_reach_proceed_mutate() {
    let env = TrustBundleEnvironment::Devnet;
    for surface in GovernanceExecutionRuntimeSurface::ALL {
        let mut fx = rotate_fixture(env);
        fx.surface = surface;
        let outcome = fx.run();
        assert!(
            outcome.is_mutate_authorized(),
            "surface {:?} did not reach ProceedMutate: {:?}",
            surface,
            outcome
        );
    }
}

// Compatibility with Run 222: the integration delegates the evaluator stage
// to the Run 222 evaluator interface unchanged — disabled evaluator policy
// fails closed for a present fixture carrier.
#[test]
fn compat_run222_disabled_evaluator_policy_fails_closed() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::Disabled;
    let outcome = fx.run();
    assert_evaluator_rejected(&outcome, |o| matches!(o, EvaluatorOutcome::EvaluatorDisabled));
}
