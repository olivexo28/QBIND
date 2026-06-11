//! Run 226 — source/test governance evaluator runtime call-site wiring tests.
//!
//! Source/test only. Run 226 captures **no** release-binary evidence;
//! release-binary call-site wiring evidence is deferred to **Run 227**. Run
//! 226 does **not** implement a real governance execution engine, a real
//! on-chain governance proof verifier, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, a real KMS/HSM
//! backend, or a real RemoteSigner backend.
//!
//! These tests prove that the representable long-running runtime call sites
//! now route runtime consumption **through** the Run 224 governance evaluator
//! integration layer via the Run 226 call-site wiring entry points
//! ([`wire_governance_evaluator_runtime_callsite`] and
//! [`wire_governance_evaluator_runtime_callsite_without_evaluator_context`]),
//! consuming the [`GovernanceEvaluatorRuntimeIntegrationOutcome`] (never
//! discarding it), preserving the default Disabled legacy bypass, keeping
//! production/on-chain/MainNet evaluators unavailable/fail-closed, keeping
//! fixture/emergency-fixture evaluators non-production, failing closed
//! before any mutation on rejection, and keeping MainNet peer-driven apply
//! refused.
//!
//! Coverage: A1–A17 (where representable), R1–R31, source reachability from
//! the binary call-site entry point into the integration layer, proof that
//! `ProceedMutate` is the only mutation-authorizing outcome, ordering,
//! deterministic digest binding, default Disabled compatibility, MainNet
//! refusal, and compatibility with Runs 220 / 222 / 224.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_226.md`.

use std::sync::Mutex;

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_evaluator::{
    mainnet_peer_driven_apply_remains_refused_under_evaluator,
    validator_set_rotation_remains_unsupported_under_evaluator, DecisionSourceIdentity,
    EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface, EvaluatorExpectations,
    EvaluatorOutcome, EvaluatorPolicy, EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    FixtureGovernanceExecutionEvaluatorInterface, MainnetDecisionSourceEvaluatorInterface,
    OnChainDecisionSourceEvaluatorInterface, ProductionDecisionSourceEvaluatorInterface,
    ProductionGovernanceExecutionEvaluator, EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::{
    wire_governance_evaluator_runtime_callsite,
    wire_governance_evaluator_runtime_callsite_without_evaluator_context,
    GovernanceEvaluatorRuntimeCallsiteFailClosed, GovernanceEvaluatorRuntimeIntegrationContext,
    GovernanceEvaluatorRuntimeIntegrationOutcome,
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
use qbind_node::pqc_governance_execution_policy_surface::{
    GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
    GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / Run 222 / Run 224 corpora).
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

fn ev_identity(env: TrustBundleEnvironment, kind: EvaluatorSourceKind) -> DecisionSourceIdentity {
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
// Owned-material fixture bundle — drives the Run 226 *call-site* wiring entry.
// ===========================================================================

/// Owns every layer's material for one call-site round-trip so a test can
/// mutate any field and then borrow it into the integration context that the
/// Run 226 call-site wiring entry point consumes.
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

type CallsiteResult =
    Result<GovernanceEvaluatorRuntimeIntegrationOutcome, GovernanceEvaluatorRuntimeCallsiteFailClosed>;

impl Fixture {
    /// Route this fixture through the Run 226 call-site wiring entry point
    /// using the supplied evaluator (the entry the representable call sites
    /// invoke). The result is consumed, never discarded.
    fn callsite_with<E: ProductionGovernanceExecutionEvaluator>(&self, evaluator: &E) -> CallsiteResult {
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
        wire_governance_evaluator_runtime_callsite(&ctx)
    }

    fn callsite(&self) -> CallsiteResult {
        self.callsite_with(&FixtureGovernanceExecutionEvaluatorInterface)
    }

    /// `true` iff the call-site wiring authorized a mutation (`ProceedMutate`).
    fn is_mutate_authorized(&self) -> bool {
        matches!(
            self.callsite(),
            Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate { .. })
        )
    }
}

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
// Result assertion helpers
// ===========================================================================

/// Assert the call-site wiring proceeded as the legacy bypass.
fn assert_legacy_bypass(result: &CallsiteResult) {
    match result {
        Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass) => {}
        other => panic!("expected Ok(ProceedLegacyBypass), got {:?}", other),
    }
}

/// Assert the call-site wiring authorized a mutation (`ProceedMutate`).
fn assert_proceed_mutate(result: &CallsiteResult) {
    match result {
        Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate { .. }) => {}
        other => panic!("expected Ok(ProceedMutate), got {:?}", other),
    }
}

/// Assert the call-site wiring failed closed carrying an `EvaluatorRejected`
/// outcome matching the predicate. A fail-closed `Err` never authorizes a
/// mutation (its outcome is not `ProceedMutate`).
fn assert_evaluator_rejected(result: &CallsiteResult, pred: impl Fn(&EvaluatorOutcome) -> bool) {
    match result {
        Err(fc) => {
            assert!(
                !fc.outcome.is_mutate_authorized(),
                "fail-closed must not authorize mutation: {:?}",
                fc
            );
            match &fc.outcome {
                GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(o) => {
                    assert!(pred(o), "unexpected evaluator outcome: {:?}", o)
                }
                other => panic!("expected EvaluatorRejected, got {:?}", other),
            }
        }
        Ok(o) => panic!("expected Err(EvaluatorRejected), got Ok({:?})", o),
    }
}

/// Assert the call-site wiring failed closed carrying a
/// `RuntimeConsumptionFailClosed` outcome matching the predicate.
fn assert_runtime_fail_closed(
    result: &CallsiteResult,
    pred: impl Fn(&GovernanceExecutionPayloadCarryingDecisionOutcome) -> bool,
) {
    match result {
        Err(fc) => match &fc.outcome {
            GovernanceEvaluatorRuntimeIntegrationOutcome::RuntimeConsumptionFailClosed(o) => {
                assert!(pred(o), "unexpected runtime-consumption outcome: {:?}", o)
            }
            other => panic!("expected RuntimeConsumptionFailClosed, got {:?}", other),
        },
        Ok(o) => panic!("expected Err(RuntimeConsumptionFailClosed), got Ok({:?})", o),
    }
}

/// Assert the call-site wiring did not authorize a mutation (any `Err`, or an
/// `Ok(ProceedLegacyBypass)` — never `Ok(ProceedMutate)`).
fn assert_no_mutation(result: &CallsiteResult) {
    if let Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate { .. }) = result {
        panic!("unexpected mutation authorization: {:?}", result);
    }
}

// ===========================================================================
// A — accepted scenarios (default Disabled legacy bypass on each surface)
// ===========================================================================

// A1. reload-check default Disabled + absent carrier preserves the legacy
// bypass.
#[test]
fn a1_reload_check_disabled_absent_preserves_legacy_bypass() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    assert_legacy_bypass(&fx.callsite());
}

// A2. reload-apply default Disabled + absent carrier preserves legacy
// behavior.
#[test]
fn a2_reload_apply_disabled_absent_preserves_legacy_bypass() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    assert_legacy_bypass(&fx.callsite());
}

// A3. startup `--p2p-trust-bundle` default Disabled + absent carrier preserves
// legacy behavior.
#[test]
fn a3_startup_p2p_trust_bundle_disabled_absent_preserves_legacy_bypass() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    assert_legacy_bypass(&fx.callsite());
}

// A4. SIGHUP default Disabled + absent carrier preserves legacy behavior.
#[test]
fn a4_sighup_disabled_absent_preserves_legacy_bypass() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::Sighup;
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    assert_legacy_bypass(&fx.callsite());
}

// A5. local peer-candidate-check default Disabled + absent carrier preserves
// legacy behavior.
#[test]
fn a5_local_peer_candidate_check_disabled_absent_preserves_legacy_bypass() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck;
    fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    fx.load = GovernanceExecutionLoadStatus::Absent;
    assert_legacy_bypass(&fx.callsite());
}

// A6. reload-check with DevNet fixture policy and a valid sidecar routes
// through the integration and accepts only when runtime consumption and the
// evaluator both agree.
#[test]
fn a6_reload_check_devnet_fixture_routes_through_integration() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    assert_proceed_mutate(&fx.callsite());

    // Flip ONLY the evaluator response: acceptance is withdrawn.
    let mut ev_only = rotate_fixture(TrustBundleEnvironment::Devnet);
    ev_only.surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    ev_only.response.approved = false;
    assert_no_mutation(&ev_only.callsite());
}

// A7. reload-apply with DevNet fixture policy and a valid sidecar routes
// through the integration and accepts only when both agree.
#[test]
fn a7_reload_apply_devnet_fixture_routes_through_integration() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_proceed_mutate(&fx.callsite());

    let mut rc_only = rotate_fixture(TrustBundleEnvironment::Devnet);
    rc_only.load = GovernanceExecutionLoadStatus::Absent; // runtime consumption rejects
    assert_no_mutation(&rc_only.callsite());
}

// A8. SIGHUP with DevNet fixture policy and a valid sidecar routes through the
// integration where representable.
#[test]
fn a8_sighup_devnet_fixture_routes_through_integration() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::Sighup;
    assert_proceed_mutate(&fx.callsite());
}

// A9. local peer-candidate-check with TestNet fixture policy and a valid
// sidecar routes through the integration where representable.
#[test]
fn a9_local_peer_candidate_check_testnet_fixture_routes_through_integration() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Testnet);
    fx.surface = GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck;
    assert_proceed_mutate(&fx.callsite());
}

// A10. explicit emergency fixture policy accepts only an explicit emergency
// action.
#[test]
fn a10_emergency_fixture_accepts_only_explicit_emergency_action() {
    let env = TrustBundleEnvironment::Devnet;
    let fx = emergency_fixture(env);
    assert_proceed_mutate(&fx.callsite_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface));

    let mut non_emergency = emergency_fixture(env);
    non_emergency.request.emergency_flag = false;
    non_emergency.response.emergency_flag = false;
    assert_no_mutation(
        &non_emergency.callsite_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface),
    );
}

// A11. production evaluator path is reached from runtime call-site integration
// and fails closed as unavailable.
#[test]
fn a11_production_evaluator_reached_fails_closed_unavailable() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_evaluator_rejected(
        &fx.callsite_with(&ProductionDecisionSourceEvaluatorInterface),
        |o| matches!(o, EvaluatorOutcome::ProductionDecisionSourceUnavailable),
    );
}

// A12. on-chain evaluator path is reached from runtime call-site integration
// and fails closed as unavailable.
#[test]
fn a12_onchain_evaluator_reached_fails_closed_unavailable() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_evaluator_rejected(
        &fx.callsite_with(&OnChainDecisionSourceEvaluatorInterface),
        |o| matches!(o, EvaluatorOutcome::OnChainDecisionSourceUnavailable),
    );
}

// A13. MainNet evaluator path is reached from runtime call-site integration
// and fails closed / refused.
#[test]
fn a13_mainnet_evaluator_reached_fails_closed_unavailable() {
    // Non-MainNet trust domain so runtime consumption accepts and the
    // integration reaches the MainNet evaluator interface (unavailable).
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_evaluator_rejected(
        &fx.callsite_with(&MainnetDecisionSourceEvaluatorInterface),
        |o| matches!(o, EvaluatorOutcome::MainnetDecisionSourceUnavailable),
    );
}

// A14. CLI-over-env precedence is preserved through call-site integration.
#[test]
fn a14_cli_over_env_precedence_preserved_through_callsite() {
    let _g = env_guard();
    // env says Disabled, CLI says fixture-governance-allowed -> CLI wins.
    std::env::set_var(
        QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
        GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
    );
    let arming = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some(
        GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
    ))
    .expect("valid selector");
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
    std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV);

    // The CLI-resolved arming drives a valid fixture round-trip to
    // ProceedMutate through the call-site wiring.
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.arming = arming;
    assert_proceed_mutate(&fx.callsite());
}

// A15. invalid selector fails closed before mutation.
#[test]
fn a15_invalid_selector_fails_closed_before_mutation() {
    // An unknown CLI selector value is a typed parse error: the runtime
    // arming config is never constructed with a downgraded policy, so the
    // selector resolution itself fails closed before any call-site mutation.
    let result = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("not-a-real-policy"));
    assert!(result.is_err(), "invalid selector must fail closed");
}

// A16. live inbound `0x05` limitation: a present-but-invalid candidate is not
// propagated/staged/applied (the call-site wiring never authorizes a mutation)
// and the limitation is documented in the Run 226 evidence.
#[test]
fn a16_live_inbound_0x05_invalid_candidate_not_applied() {
    // A valid fixture round-trip is representable at source/test level.
    let mut valid = rotate_fixture(TrustBundleEnvironment::Devnet);
    valid.surface = GovernanceExecutionRuntimeSurface::LiveInbound0x05;
    assert_proceed_mutate(&valid.callsite());

    // An invalid (malformed) candidate fails closed -> not applied.
    let mut invalid = rotate_fixture(TrustBundleEnvironment::Devnet);
    invalid.surface = GovernanceExecutionRuntimeSurface::LiveInbound0x05;
    invalid.load = GovernanceExecutionLoadStatus::Malformed(
        GovernanceExecutionPayloadParseError::Json {
            error: "broken-live-0x05".to_string(),
        },
    );
    assert_no_mutation(&invalid.callsite());
}

// A17. peer-driven drain limitation: MainNet peer-driven apply remains
// refused.
#[test]
fn a17_peer_driven_drain_mainnet_refused() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    match fx.callsite() {
        Err(fc) => {
            assert!(fc.is_mainnet_peer_driven_apply_refused());
            assert_eq!(
                fc.outcome,
                GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused
            );
        }
        Ok(o) => panic!("expected MainNet peer-driven apply refused, got Ok({:?})", o),
    }
}

// ===========================================================================
// R — rejection scenarios (all non-mutating, all fail closed before mutation)
// ===========================================================================

// R1. missing governance-execution material rejected when explicit evaluator
// policy requires it.
#[test]
fn r1_missing_material_required_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.load = GovernanceExecutionLoadStatus::Absent;
    assert_runtime_fail_closed(&fx.callsite(), |o| {
        matches!(
            o,
            GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent { .. }
        )
    });
}

// R2. malformed governance-execution material rejected.
#[test]
fn r2_malformed_material_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.load = GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
        error: "broken".to_string(),
    });
    assert_runtime_fail_closed(&fx.callsite(), |o| {
        matches!(
            o,
            GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload(_)
        )
    });
}

// R3. wrong evaluator source rejected.
#[test]
fn r3_wrong_evaluator_source_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.identity.source_kind = EvaluatorSourceKind::EmergencyCouncilFixtureSource;
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    assert_evaluator_rejected(&fx.callsite(), |o| {
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
    assert_evaluator_rejected(&fx.callsite(), |o| {
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
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongChain { .. })
    });
}

// R6. wrong genesis rejected.
#[test]
fn r6_wrong_genesis_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.identity.genesis_hash = "other-genesis".to_string();
    fx.ev_exp.expected_genesis_hash = "other-genesis".to_string();
    fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
    fx.response.request_digest = fx.request.request_digest();
    assert_evaluator_rejected(&fx.callsite(), |o| {
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
    assert_evaluator_rejected(&fx.callsite(), |o| {
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
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongGovernanceProofDigest { .. })
    });
}

// R9. wrong on-chain proof digest rejected.
#[test]
fn r9_wrong_onchain_proof_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongOnChainProofDigest { .. })
    });
}

// R10. wrong custody attestation digest rejected.
#[test]
fn r10_wrong_custody_attestation_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongCustodyAttestationDigest { .. })
    });
}

// R11. wrong proposal id rejected.
#[test]
fn r11_wrong_proposal_id_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_proposal_id = "other-proposal".to_string();
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongProposalId { .. })
    });
}

// R12. wrong decision id rejected.
#[test]
fn r12_wrong_decision_id_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_decision_id = "other-decision".to_string();
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongDecisionId { .. })
    });
}

// R13. wrong lifecycle action rejected.
#[test]
fn r13_wrong_lifecycle_action_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongLifecycleAction { .. })
    });
}

// R14. wrong candidate digest rejected.
#[test]
fn r14_wrong_candidate_digest_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_candidate_digest = "other-candidate".to_string();
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongCandidateDigest { .. })
    });
}

// R15. wrong authority-domain sequence rejected.
#[test]
fn r15_wrong_sequence_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_authority_domain_sequence = 8;
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::WrongAuthorityDomainSequence { .. })
    });
}

// R16. expired evaluator request rejected.
#[test]
fn r16_expired_request_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.now_epoch = 250;
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::ExpiredDecision { .. })
    });
}

// R17. stale/replayed evaluator request rejected.
#[test]
fn r17_stale_or_replayed_request_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_exp.expected_replay_nonce = "fresh-nonce".to_string();
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::StaleOrReplayedDecision)
    });
}

// R18. quorum/threshold insufficient rejected.
#[test]
fn r18_quorum_insufficient_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.request.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
    fx.response.request_digest = fx.request.request_digest();
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::QuorumThresholdInsufficient { .. })
    });
}

// R19. emergency action not authorized rejected.
#[test]
fn r19_emergency_action_not_authorized_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.request.emergency_flag = true;
    fx.response.request_digest = fx.request.request_digest();
    fx.response.emergency_flag = true;
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::EmergencyActionNotAuthorized)
    });
}

// R20. validator-set rotation unsupported rejected.
#[test]
fn r20_validator_set_rotation_unsupported_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.request.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    fx.response.request_digest = fx.request.request_digest();
    assert_evaluator_rejected(&fx.callsite(), |o| {
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
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::PolicyChangeActionUnsupported)
    });
}

// R22. production evaluator unavailable rejected.
#[test]
fn r22_production_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_evaluator_rejected(
        &fx.callsite_with(&ProductionDecisionSourceEvaluatorInterface),
        |o| matches!(o, EvaluatorOutcome::ProductionDecisionSourceUnavailable),
    );
}

// R23. on-chain evaluator unavailable rejected.
#[test]
fn r23_onchain_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_evaluator_rejected(
        &fx.callsite_with(&OnChainDecisionSourceEvaluatorInterface),
        |o| matches!(o, EvaluatorOutcome::OnChainDecisionSourceUnavailable),
    );
}

// R24. MainNet evaluator unavailable/refused rejected.
#[test]
fn r24_mainnet_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert_evaluator_rejected(
        &fx.callsite_with(&MainnetDecisionSourceEvaluatorInterface),
        |o| matches!(o, EvaluatorOutcome::MainnetDecisionSourceUnavailable),
    );
}

// R25. local operator cannot satisfy evaluator policy.
#[test]
fn r25_local_operator_cannot_satisfy_evaluator_policy() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
    assert_no_mutation(&fx.callsite());
}

// R26. peer majority cannot satisfy evaluator policy.
#[test]
fn r26_peer_majority_cannot_satisfy_evaluator_policy() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::MainnetDecisionSourceRequired;
    assert_no_mutation(&fx.callsite());
}

// R27. evaluator valid but governance execution decision invalid rejected.
#[test]
fn r27_evaluator_valid_but_governance_decision_invalid_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut fx = rotate_fixture(env);
    let mut decision = rotate_decision();
    decision.authorized_sequence = 999; // Run 211 rejects the carrier
    fx.load = available_from(&rotate_input(env), &decision);
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::GovernanceExecutionDecisionInvalid { .. })
    });
}

// R28. governance execution decision valid but evaluator response invalid
// rejected.
#[test]
fn r28_governance_decision_valid_but_evaluator_response_invalid_rejected() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.response.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::InvalidResponseCommitment)
    });
}

// R29. validation-only rejection writes no marker and no sequence (the
// call-site wiring is pure / repeatable and never authorizes a mutation).
#[test]
fn r29_validation_only_rejection_is_non_mutating_and_pure() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    fx.ev_exp.expected_candidate_digest = "other".to_string();
    let first = fx.callsite();
    let second = fx.callsite();
    assert_no_mutation(&first);
    assert_eq!(first, second, "call-site wiring is pure / repeatable");
}

// R30. mutating rejection produces no Run 070 call, no live trust swap, no
// session eviction, no sequence write, and no marker write.
#[test]
fn r30_mutating_rejection_is_non_mutating_and_pure() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    fx.response.approved = false;
    let first = fx.callsite();
    let second = fx.callsite();
    assert_no_mutation(&first);
    assert!(first.is_err(), "mutating-surface rejection must fail closed");
    assert_eq!(first, second, "call-site wiring is pure / repeatable");
}

// R31. MainNet peer-driven apply remains refused even with fixture evaluator
// approval.
#[test]
fn r31_mainnet_peer_driven_apply_refused_even_with_fixture_approval() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    match fx.callsite() {
        Err(fc) => assert!(fc.is_mainnet_peer_driven_apply_refused()),
        Ok(o) => panic!("expected MainNet peer-driven apply refused, got Ok({:?})", o),
    }
    assert!(mainnet_peer_driven_apply_remains_refused_under_evaluator(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// Source reachability + invariant proofs
// ===========================================================================

// Source reachability: the binary marker-decision call-site entry point
// (`wire_governance_evaluator_runtime_callsite_without_evaluator_context`)
// routes every representable runtime surface through the Run 224 integration
// layer. The default Disabled + absent carrier proceeds as the legacy bypass;
// a present carrier fails closed before mutation.
#[test]
fn callsite_without_evaluator_context_reaches_integration_on_all_surfaces() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let gov_exp = rotate_gov_expectations(env);
    let disabled = GovernanceExecutionRuntimeArmingConfig::disabled();
    for surface in GovernanceExecutionRuntimeSurface::ALL {
        // Default Disabled + absent -> legacy bypass.
        let bypass = wire_governance_evaluator_runtime_callsite_without_evaluator_context(
            &disabled,
            surface,
            &td,
            &gov_exp,
            &GovernanceExecutionLoadStatus::Absent,
            matches!(surface, GovernanceExecutionRuntimeSurface::PeerDrivenDrain),
        );
        assert_eq!(
            bypass,
            Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass),
            "surface {:?} should bypass under Disabled+absent",
            surface
        );
    }
}

// The binary call-site entry fails closed for a present carrier (it cannot
// bind a real evaluator context, so a present carrier reaches the unavailable
// production evaluator and never authorizes a mutation).
#[test]
fn callsite_without_evaluator_context_present_carrier_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let gov_exp = rotate_gov_expectations(env);
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let load = available_from(&rotate_input(env), &rotate_decision());
    let result = wire_governance_evaluator_runtime_callsite_without_evaluator_context(
        &arming,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        &td,
        &gov_exp,
        &load,
        false,
    );
    match result {
        Err(fc) => assert!(!fc.outcome.is_mutate_authorized()),
        Ok(o) => panic!("present carrier must fail closed, got Ok({:?})", o),
    }
}

// The binary call-site entry refuses MainNet peer-driven apply.
#[test]
fn callsite_without_evaluator_context_mainnet_peer_driven_refused() {
    let env = TrustBundleEnvironment::Mainnet;
    let td = trust_domain(env);
    let gov_exp = rotate_gov_expectations(env);
    let arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    let result = wire_governance_evaluator_runtime_callsite_without_evaluator_context(
        &arming,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        &td,
        &gov_exp,
        &GovernanceExecutionLoadStatus::Absent,
        true,
    );
    match result {
        Err(fc) => assert!(fc.is_mainnet_peer_driven_apply_refused()),
        Ok(o) => panic!("MainNet peer-driven apply must be refused, got Ok({:?})", o),
    }
}

// Proof that `GovernanceEvaluatorRuntimeIntegrationOutcome` is consumed, not
// discarded: a `ProceedMutate` carries the composed runtime-consumption and
// evaluator outcomes through the call-site wiring.
#[test]
fn integration_outcome_is_consumed_not_discarded() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    match fx.callsite() {
        Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate {
            runtime_consumption,
            evaluator,
            lifecycle_action,
            candidate_digest,
            authority_domain_sequence,
        }) => {
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
        }
        other => panic!("expected ProceedMutate, got {:?}", other),
    }
}

// Proof that `ProceedMutate` is the only mutation-authorizing integration
// outcome; every other variant fails closed before mutation.
#[test]
fn proceed_mutate_is_the_only_mutation_authorizing_outcome() {
    use GovernanceEvaluatorRuntimeIntegrationOutcome as O;
    assert!(O::ProceedMutate {
        runtime_consumption: GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            proposal_id: PROPOSAL.to_string(),
            decision_id: DECISION.to_string(),
            lifecycle_action: LocalLifecycleAction::Rotate,
            environment: TrustBundleEnvironment::Devnet,
        },
        evaluator: EvaluatorOutcome::EvaluatorResponseAuthorized {
            lifecycle_action: LocalLifecycleAction::Rotate,
            candidate_digest: CAND_DIGEST.to_string(),
            authority_domain_sequence: 7,
        },
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: 7,
    }
    .is_mutate_authorized());

    assert!(!O::ProceedLegacyBypass.is_mutate_authorized());
    assert!(!O::MainNetPeerDrivenApplyRefused.is_mutate_authorized());
    assert!(
        !O::EvaluatorRejected(EvaluatorOutcome::ProductionDecisionSourceUnavailable)
            .is_mutate_authorized()
    );
    assert!(!O::RuntimeConsumptionFailClosed(
        GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused
    )
    .is_mutate_authorized());
}

// The three fail-closed integration outcomes all surface as `Err` from the
// call-site wiring (RuntimeConsumptionFailClosed, EvaluatorRejected,
// MainNetPeerDrivenApplyRefused).
#[test]
fn fail_closed_outcomes_surface_as_callsite_errors() {
    // RuntimeConsumptionFailClosed (required-but-absent).
    let mut rc = rotate_fixture(TrustBundleEnvironment::Devnet);
    rc.load = GovernanceExecutionLoadStatus::Absent;
    assert!(rc.callsite().is_err());

    // EvaluatorRejected (production evaluator unavailable).
    let ev = rotate_fixture(TrustBundleEnvironment::Devnet);
    assert!(ev
        .callsite_with(&ProductionDecisionSourceEvaluatorInterface)
        .is_err());

    // MainNetPeerDrivenApplyRefused.
    let mut mn = rotate_fixture(TrustBundleEnvironment::Mainnet);
    mn.peer_driven = true;
    assert!(mn.callsite().is_err());
}

// Ordering: both the runtime-consumption stage and the evaluator stage gate
// mutation through the call-site wiring.
#[test]
fn ordering_both_stages_gate_mutation_through_callsite() {
    let env = TrustBundleEnvironment::Devnet;
    assert_proceed_mutate(&rotate_fixture(env).callsite());

    let mut ev_only = rotate_fixture(env);
    ev_only.response.approved = false;
    assert_no_mutation(&ev_only.callsite());

    let mut rc_only = rotate_fixture(env);
    rc_only.load = GovernanceExecutionLoadStatus::Absent;
    assert_no_mutation(&rc_only.callsite());
}

// Deterministic evaluator request/response digest binding is preserved across
// the call-site wiring (the digests bind the bound fields).
#[test]
fn deterministic_request_response_digest_binding() {
    let fx = rotate_fixture(TrustBundleEnvironment::Devnet);

    let req = fx.request.request_digest();
    assert_eq!(req, fx.request.request_digest(), "request digest deterministic");
    let mut perturbed = fx.request.clone();
    perturbed.candidate_digest = "other".to_string();
    assert_ne!(req, perturbed.request_digest());

    let resp = fx.response.response_digest();
    assert_eq!(resp, fx.response.response_digest(), "response digest deterministic");
    let mut perturbed = fx.response.clone();
    perturbed.authorized_authority_domain_sequence = 999;
    assert_ne!(resp, perturbed.response_digest());
}

// MainNet fixture material is refused on the call-site wiring even off the
// peer-driven path.
#[test]
fn mainnet_fixture_callsite_refused() {
    let fx = rotate_fixture(TrustBundleEnvironment::Mainnet);
    assert_no_mutation(&fx.callsite());
}

// Compatibility with Run 220 / 224: every representable surface reaches
// ProceedMutate under a valid fixture round-trip through the call-site wiring
// (except the MainNet-refused peer-driven drain, exercised separately).
#[test]
fn compat_run220_run224_all_surfaces_reach_proceed_mutate() {
    let env = TrustBundleEnvironment::Devnet;
    for surface in GovernanceExecutionRuntimeSurface::ALL {
        let mut fx = rotate_fixture(env);
        fx.surface = surface;
        assert_proceed_mutate(&fx.callsite());
    }
}

// Compatibility with Run 222: the call-site wiring delegates the evaluator
// stage to the Run 222 evaluator interface unchanged — a Disabled evaluator
// policy fails closed for a present fixture carrier.
#[test]
fn compat_run222_disabled_evaluator_policy_fails_closed() {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    fx.ev_policy = EvaluatorPolicy::Disabled;
    assert_evaluator_rejected(&fx.callsite(), |o| {
        matches!(o, EvaluatorOutcome::EvaluatorDisabled)
    });
}

// ===========================================================================
// env serialization guard (A14 mutates the process environment)
// ===========================================================================

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}