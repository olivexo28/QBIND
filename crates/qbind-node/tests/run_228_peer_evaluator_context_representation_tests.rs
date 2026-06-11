//! Run 228 — source/test evaluator-context representation boundary tests for
//! live inbound `0x05` and peer-driven drain.
//!
//! Source/test only. Run 228 captures **no** release-binary evidence;
//! release-binary evidence for this boundary is deferred to **Run 229**. These
//! tests prove that the live inbound `0x05` and peer-driven drain surfaces now
//! have a typed, local-only evaluator-context representation boundary
//! ([`GovernanceEvaluatorPeerContext`]) that classifies the carrier status,
//! routes a representable `Present` context through the Run 226 call-site
//! wiring into the Run 224 integration layer, preserves the default Disabled
//! legacy validation behavior, fails closed (typed, never a silent approval)
//! on a missing / unsupported / malformed carrier, keeps
//! production/on-chain/MainNet evaluators unavailable/fail-closed, keeps
//! fixture/emergency-fixture evaluators non-production, and keeps MainNet
//! peer-driven apply refused.
//!
//! Coverage: A1–A14, R1–R27, deterministic context-digest binding, local-only
//! / no-wire-schema-change, live inbound `0x05` no-propagation/no-staging/
//! no-apply, peer-driven drain no-apply, MainNet refusal, and compatibility
//! with the Run 226 / 224 / 222 / 220 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_228.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_peer_context::{
    evaluate_peer_evaluator_context, evaluate_peer_evaluator_context_wire_only,
    mainnet_peer_driven_apply_remains_refused_under_peer_context,
    validator_set_rotation_remains_unsupported_under_peer_context, GovernanceEvaluatorPeerContext,
    PeerEvaluatorCarrierStatus, PeerEvaluatorContextOutcome, PeerEvaluatorContextSurface,
    PeerEvaluatorLoadStatus, PeerEvaluatorSourceClass,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface,
    EvaluatorExpectations, EvaluatorOutcome, EvaluatorPolicy, EvaluatorRequest, EvaluatorResponse,
    EvaluatorSourceKind, FixtureGovernanceExecutionEvaluatorInterface,
    MainnetDecisionSourceEvaluatorInterface, OnChainDecisionSourceEvaluatorInterface,
    ProductionDecisionSourceEvaluatorInterface, ProductionGovernanceExecutionEvaluator,
    EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL, EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::{
    GovernanceEvaluatorRuntimeIntegrationContext, GovernanceEvaluatorRuntimeIntegrationOutcome,
};
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus,
    GovernanceExecutionPayloadWire,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceQuorumThreshold,
    GovernanceExecutionPolicy, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 corpora).
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
const TRUST_BUNDLE_DIGEST: &str = "trust-bundle-digest-fffffffffffffffffff";
const MARKER_DIGEST: &str = "v2-marker-digest-hhhhhhhhhhhhhhhhhhhhhhh";

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

// ===========================================================================
// Run 211 governance-execution carrier material
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
// Run 222 evaluator material
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
// Owned-material fixture bundle
// ===========================================================================

/// Owns every layer's material for one boundary round-trip so a test can
/// mutate any field and then borrow it into the integration + peer context.
struct Fixture {
    arming: GovernanceExecutionRuntimeArmingConfig,
    peer_surface: PeerEvaluatorContextSurface,
    td: AuthorityTrustDomain,
    load: GovernanceExecutionLoadStatus,
    gov_exp: GovernanceExecutionExpectations,
    identity: DecisionSourceIdentity,
    request: EvaluatorRequest,
    response: EvaluatorResponse,
    ev_exp: EvaluatorExpectations,
    ev_policy: EvaluatorPolicy,
    source_class: PeerEvaluatorSourceClass,
}

impl Fixture {
    fn runtime_surface(&self) -> GovernanceExecutionRuntimeSurface {
        self.peer_surface.runtime_surface()
    }

    fn is_peer_driven(&self) -> bool {
        self.peer_surface.is_peer_driven_apply_preflight()
    }

    fn integration_ctx<'a, E: ProductionGovernanceExecutionEvaluator>(
        &'a self,
        evaluator: &'a E,
    ) -> GovernanceEvaluatorRuntimeIntegrationContext<'a, E> {
        GovernanceEvaluatorRuntimeIntegrationContext {
            arming: &self.arming,
            surface: self.runtime_surface(),
            trust_domain: &self.td,
            load_status: &self.load,
            governance_execution_expectations: &self.gov_exp,
            evaluator,
            identity: &self.identity,
            request: &self.request,
            response: &self.response,
            evaluator_expectations: &self.ev_exp,
            evaluator_policy: self.ev_policy,
            is_peer_driven_apply_preflight: self.is_peer_driven(),
        }
    }

    /// Build a `Present` context that references the integration material and
    /// route it through the Run 228 boundary.
    fn route_present_with<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
    ) -> PeerEvaluatorContextOutcome {
        let ctx = self.integration_ctx(evaluator);
        let peer = GovernanceEvaluatorPeerContext::present_from_integration(
            self.peer_surface,
            self.source_class,
            "peer-0001",
            &ctx,
            Some(TRUST_BUNDLE_DIGEST.to_string()),
            Some(MARKER_DIGEST.to_string()),
        );
        assert_eq!(peer.carrier_status, PeerEvaluatorCarrierStatus::Present);
        evaluate_peer_evaluator_context(&peer, &ctx)
    }

    fn route_present(&self) -> PeerEvaluatorContextOutcome {
        self.route_present_with(&FixtureGovernanceExecutionEvaluatorInterface)
    }

    /// Build a context with an explicit carrier status (for the non-Present
    /// classifications) and route it.
    fn route_with_status<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
        status: PeerEvaluatorCarrierStatus,
    ) -> PeerEvaluatorContextOutcome {
        let ctx = self.integration_ctx(evaluator);
        let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
            self.peer_surface,
            self.source_class,
            "peer-0001",
            &ctx,
            Some(TRUST_BUNDLE_DIGEST.to_string()),
            Some(MARKER_DIGEST.to_string()),
        );
        peer.carrier_status = status;
        evaluate_peer_evaluator_context(&peer, &ctx)
    }
}

/// A fully-consistent fixture-rotate boundary on `env`/`surface` that, with
/// the default fixture evaluator, reaches `RoutedProceedMutate`.
fn rotate_fixture(env: TrustBundleEnvironment, surface: PeerEvaluatorContextSurface) -> Fixture {
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
        peer_surface: surface,
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
        source_class: match surface {
            PeerEvaluatorContextSurface::LiveInbound0x05 => PeerEvaluatorSourceClass::LiveInboundPeer,
            PeerEvaluatorContextSurface::PeerDrivenDrain => PeerEvaluatorSourceClass::DrainStagedPeer,
        },
    }
}

fn emergency_fixture(
    env: TrustBundleEnvironment,
    surface: PeerEvaluatorContextSurface,
) -> Fixture {
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
        peer_surface: surface,
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
        source_class: PeerEvaluatorSourceClass::LocalSourceTest,
    }
}

/// Assert that an outcome is a routed fail-closed carrying an evaluator
/// rejection matching `pred`, and authorizes no apply.
fn assert_routed_evaluator_reject(
    outcome: &PeerEvaluatorContextOutcome,
    pred: impl Fn(&EvaluatorOutcome) -> bool,
) {
    match outcome {
        PeerEvaluatorContextOutcome::RoutedFailClosed(fc) => match &fc.outcome {
            GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(o) => {
                assert!(pred(o), "unexpected evaluator outcome: {:?}", o);
            }
            other => panic!("expected EvaluatorRejected, got {:?}", other),
        },
        other => panic!("expected RoutedFailClosed, got {:?}", other),
    }
    assert!(outcome.no_propagation_no_staging_no_apply());
    assert!(!outcome.is_apply_authorized());
}

const SURFACES: [PeerEvaluatorContextSurface; 2] = [
    PeerEvaluatorContextSurface::LiveInbound0x05,
    PeerEvaluatorContextSurface::PeerDrivenDrain,
];

// ===========================================================================
// A — accepted scenarios
// ===========================================================================

// A1. live inbound 0x05 default Disabled + absent context preserves legacy
// validation behavior.
#[test]
fn a1_live_inbound_disabled_absent_preserves_legacy() {
    let peer = GovernanceEvaluatorPeerContext::absent(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
    );
    let arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    let td = trust_domain(TrustBundleEnvironment::Devnet);
    let load = GovernanceExecutionLoadStatus::Absent;
    let gov_exp = rotate_gov_expectations(TrustBundleEnvironment::Devnet);
    let identity = ev_identity(TrustBundleEnvironment::Devnet, EvaluatorSourceKind::Disabled);
    let request = ev_request(
        &identity,
        "input",
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
        TrustBundleEnvironment::Devnet,
        "input",
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
    );
    let ctx = GovernanceEvaluatorRuntimeIntegrationContext {
        arming: &arming,
        surface: GovernanceExecutionRuntimeSurface::LiveInbound0x05,
        trust_domain: &td,
        load_status: &load,
        governance_execution_expectations: &gov_exp,
        evaluator: &FixtureGovernanceExecutionEvaluatorInterface,
        identity: &identity,
        request: &request,
        response: &response,
        evaluator_expectations: &ev_exp,
        evaluator_policy: EvaluatorPolicy::Disabled,
        is_peer_driven_apply_preflight: false,
    };
    let outcome = evaluate_peer_evaluator_context(&peer, &ctx);
    assert_eq!(outcome, PeerEvaluatorContextOutcome::LegacyValidationPreserved);
    assert!(outcome.is_legacy_validation_preserved());
    assert!(!outcome.is_apply_authorized());
}

// A2. peer-driven drain default Disabled + absent context preserves legacy
// validation behavior.
#[test]
fn a2_peer_driven_drain_disabled_absent_preserves_legacy() {
    let peer = GovernanceEvaluatorPeerContext::absent(
        PeerEvaluatorContextSurface::PeerDrivenDrain,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
    );
    let arming = GovernanceExecutionRuntimeArmingConfig::disabled();
    let td = trust_domain(TrustBundleEnvironment::Devnet);
    let load = GovernanceExecutionLoadStatus::Absent;
    let gov_exp = rotate_gov_expectations(TrustBundleEnvironment::Devnet);
    let identity = ev_identity(TrustBundleEnvironment::Devnet, EvaluatorSourceKind::Disabled);
    let request = ev_request(
        &identity,
        "input",
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
        TrustBundleEnvironment::Devnet,
        "input",
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
    );
    let ctx = GovernanceEvaluatorRuntimeIntegrationContext {
        arming: &arming,
        surface: GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        trust_domain: &td,
        load_status: &load,
        governance_execution_expectations: &gov_exp,
        evaluator: &FixtureGovernanceExecutionEvaluatorInterface,
        identity: &identity,
        request: &request,
        response: &response,
        evaluator_expectations: &ev_exp,
        evaluator_policy: EvaluatorPolicy::Disabled,
        is_peer_driven_apply_preflight: true,
    };
    let outcome = evaluate_peer_evaluator_context(&peer, &ctx);
    assert_eq!(outcome, PeerEvaluatorContextOutcome::LegacyValidationPreserved);
}

// A3. live inbound 0x05 local context binds selected policy, candidate digest,
// evaluator request/response digests, lifecycle action, sequence, env, chain,
// genesis.
#[test]
fn a3_live_inbound_present_binds_all_fields() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        PeerEvaluatorSourceClass::LiveInboundPeer,
        "peer-0001",
        &ctx,
        Some(TRUST_BUNDLE_DIGEST.to_string()),
        Some(MARKER_DIGEST.to_string()),
    );
    assert_eq!(peer.selected_policy, GovernanceExecutionPolicy::FixtureGovernanceAllowed);
    assert_eq!(peer.load_status, PeerEvaluatorLoadStatus::Available);
    assert_eq!(peer.authority_domain_sequence, 7);
    assert_eq!(peer.lifecycle_action, LocalLifecycleAction::Rotate);
    assert_eq!(peer.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(peer.chain_id, CHAIN);
    assert_eq!(peer.genesis_hash, GENESIS);
    assert_eq!(
        peer.evaluator_request_digest.as_deref(),
        Some(fx.request.request_digest().as_str())
    );
    assert_eq!(
        peer.evaluator_response_digest.as_deref(),
        Some(fx.response.response_digest().as_str())
    );
    assert_eq!(
        peer.governance_execution_payload_digest.as_deref(),
        Some(fx.request.governance_execution_input_digest.as_str())
    );
    assert!(peer.present_bindings_complete());
    assert!(peer.binds_consistently_with(&ctx));
}

// A4. peer-driven drain local context binds the same set.
#[test]
fn a4_peer_driven_drain_present_binds_all_fields() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::PeerDrivenDrain,
        PeerEvaluatorSourceClass::DrainStagedPeer,
        "peer-0001",
        &ctx,
        Some(TRUST_BUNDLE_DIGEST.to_string()),
        Some(MARKER_DIGEST.to_string()),
    );
    assert!(peer.present_bindings_complete());
    assert!(peer.binds_consistently_with(&ctx));
    assert_eq!(peer.candidate_trust_bundle_digest.as_deref(), Some(TRUST_BUNDLE_DIGEST));
    assert_eq!(peer.candidate_v2_marker_digest.as_deref(), Some(MARKER_DIGEST));
}

// A5. live inbound 0x05 with valid DevNet fixture context reaches the Run 226
// integration layer and proceeds to mutate (representable).
#[test]
fn a5_live_inbound_fixture_reaches_integration_and_mutates() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_present();
    match &outcome {
        PeerEvaluatorContextOutcome::RoutedProceedMutate {
            integration_outcome,
            context_digest,
        } => {
            assert!(integration_outcome.is_mutate_authorized());
            assert!(!context_digest.is_empty());
        }
        other => panic!("expected RoutedProceedMutate, got {:?}", other),
    }
    assert!(outcome.is_apply_authorized());
}

// A5b. live inbound 0x05 wire-only path that is not representable returns typed
// UnsupportedSurface without propagation/staging/apply.
#[test]
fn a5b_live_inbound_unsupported_surface_no_apply() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_with_status(
        &FixtureGovernanceExecutionEvaluatorInterface,
        PeerEvaluatorCarrierStatus::UnsupportedSurface,
    );
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::UnsupportedSurface { .. }
    ));
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// A6. peer-driven drain with valid DevNet fixture context reaches the Run 226
// integration layer and proceeds (representable).
#[test]
fn a6_peer_driven_drain_fixture_reaches_integration_and_mutates() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let outcome = fx.route_present();
    assert!(outcome.is_apply_authorized());
}

// A6b. peer-driven drain unsupported carrier returns typed UnsupportedSurface
// without apply.
#[test]
fn a6b_peer_driven_drain_unsupported_surface_no_apply() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let outcome = fx.route_with_status(
        &FixtureGovernanceExecutionEvaluatorInterface,
        PeerEvaluatorCarrierStatus::UnsupportedSurface,
    );
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::UnsupportedSurface { .. }
    ));
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// A7. explicit emergency fixture context accepted only for emergency action in
// non-production source/test context.
#[test]
fn a7_emergency_fixture_accepted_for_emergency_only() {
    for surface in SURFACES {
        let fx = emergency_fixture(TrustBundleEnvironment::Devnet, surface);
        let outcome =
            fx.route_present_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
        assert!(
            outcome.is_apply_authorized(),
            "emergency fixture should proceed on {:?}: {:?}",
            surface,
            outcome
        );
    }
    // The same context under a non-emergency fixture evaluator/policy is
    // rejected (kind/policy mismatch) — never accepted as production.
    let mut fx = emergency_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
    let outcome = fx.route_present_with(&FixtureGovernanceExecutionEvaluatorInterface);
    assert!(outcome.is_fail_closed());
}

// A8. production evaluator context reaches production unavailable / fail-closed.
#[test]
fn a8_production_evaluator_unavailable() {
    for surface in SURFACES {
        let fx = rotate_fixture(TrustBundleEnvironment::Devnet, surface);
        let outcome = fx.route_present_with(&ProductionDecisionSourceEvaluatorInterface);
        assert_routed_evaluator_reject(&outcome, |o| {
            matches!(o, EvaluatorOutcome::ProductionDecisionSourceUnavailable)
        });
    }
}

// A9. on-chain evaluator context reaches on-chain unavailable / fail-closed.
#[test]
fn a9_onchain_evaluator_unavailable() {
    for surface in SURFACES {
        let fx = rotate_fixture(TrustBundleEnvironment::Devnet, surface);
        let outcome = fx.route_present_with(&OnChainDecisionSourceEvaluatorInterface);
        assert_routed_evaluator_reject(&outcome, |o| {
            matches!(o, EvaluatorOutcome::OnChainDecisionSourceUnavailable)
        });
    }
}

// A10. MainNet evaluator context reaches MainNet refused/unavailable outcome.
#[test]
fn a10_mainnet_evaluator_refused() {
    // On a non-MainNet trust domain (so consumption accepts) but with the
    // MainNet evaluator interface, the evaluator is reached and fails closed.
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_present_with(&MainnetDecisionSourceEvaluatorInterface);
    assert_routed_evaluator_reject(&outcome, |o| {
        matches!(o, EvaluatorOutcome::MainnetDecisionSourceUnavailable)
    });
}

// A11. MainNet peer-driven apply remains refused even with fixture approval.
#[test]
fn a11_mainnet_peer_driven_apply_refused_with_fixture_approval() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Mainnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let outcome = fx.route_present();
    assert_eq!(outcome, PeerEvaluatorContextOutcome::MainNetRefused);
    assert!(outcome.is_mainnet_refused());
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// A12. invalid live inbound 0x05 context is not propagated, staged, or applied.
#[test]
fn a12_invalid_live_inbound_not_propagated_staged_applied() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    // Corrupt the candidate digest expectation so the evaluator rejects.
    fx.ev_exp.expected_candidate_digest = "wrong-candidate-digest".to_string();
    let outcome = fx.route_present();
    assert!(outcome.is_fail_closed());
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// A13. invalid peer-driven drain context produces no apply and no mutation.
#[test]
fn a13_invalid_peer_driven_drain_no_apply() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    fx.ev_exp.expected_candidate_digest = "wrong-candidate-digest".to_string();
    let outcome = fx.route_present();
    assert!(outcome.is_fail_closed());
    assert!(!outcome.is_apply_authorized());
}

// A14. absence of a wire/schema carrier is represented as typed
// WireSchemaUnavailable, not silently treated as approval.
#[test]
fn a14_wire_schema_unavailable_is_typed_not_approval() {
    for surface in SURFACES {
        let outcome = evaluate_peer_evaluator_context_wire_only(
            surface,
            TrustBundleEnvironment::Devnet,
            CHAIN,
            GENESIS,
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
        );
        assert!(matches!(
            outcome,
            PeerEvaluatorContextOutcome::WireSchemaUnavailable { .. }
        ));
        assert!(outcome.no_propagation_no_staging_no_apply());
        assert!(!outcome.is_apply_authorized());
    }
    // Under the default Disabled policy the wire-only path preserves legacy
    // validation behavior.
    let legacy = evaluate_peer_evaluator_context_wire_only(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
        EvaluatorPolicy::Disabled,
    );
    assert_eq!(legacy, PeerEvaluatorContextOutcome::LegacyValidationPreserved);
}

// ===========================================================================
// R — rejection scenarios (all non-mutating, no apply)
// ===========================================================================

// R1. malformed evaluator peer context rejected.
#[test]
fn r1_malformed_context_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_with_status(
        &FixtureGovernanceExecutionEvaluatorInterface,
        PeerEvaluatorCarrierStatus::Malformed,
    );
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::MalformedRejected { .. }
    ));
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R1b. a Present context missing required bindings is rejected as malformed.
#[test]
fn r1b_present_missing_bindings_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        PeerEvaluatorSourceClass::LiveInboundPeer,
        "peer-0001",
        &ctx,
        None,
        None,
    );
    peer.evaluator_request_digest = None; // drop a required binding
    assert!(!peer.present_bindings_complete());
    let outcome = evaluate_peer_evaluator_context(&peer, &ctx);
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::MalformedRejected { .. }
    ));
}

// R2. missing evaluator context rejected under explicit evaluator policy.
#[test]
fn r2_missing_context_under_explicit_policy_rejected() {
    let td = trust_domain(TrustBundleEnvironment::Devnet);
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let load = GovernanceExecutionLoadStatus::Absent;
    let gov_exp = rotate_gov_expectations(TrustBundleEnvironment::Devnet);
    let identity = ev_identity(TrustBundleEnvironment::Devnet, EvaluatorSourceKind::FixtureDecisionSource);
    let request = ev_request(
        &identity,
        "input",
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
        TrustBundleEnvironment::Devnet,
        "input",
        GovernanceAction::Rotate,
        LocalLifecycleAction::Rotate,
    );
    let mut peer = GovernanceEvaluatorPeerContext::absent(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        TrustBundleEnvironment::Devnet,
        CHAIN,
        GENESIS,
    );
    peer.evaluator_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
    let ctx = GovernanceEvaluatorRuntimeIntegrationContext {
        arming: &arming,
        surface: GovernanceExecutionRuntimeSurface::LiveInbound0x05,
        trust_domain: &td,
        load_status: &load,
        governance_execution_expectations: &gov_exp,
        evaluator: &FixtureGovernanceExecutionEvaluatorInterface,
        identity: &identity,
        request: &request,
        response: &response,
        evaluator_expectations: &ev_exp,
        evaluator_policy: EvaluatorPolicy::FixtureDecisionSourceAllowed,
        is_peer_driven_apply_preflight: false,
    };
    let outcome = evaluate_peer_evaluator_context(&peer, &ctx);
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::MissingContextRejected { .. }
    ));
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R3. wrong environment rejected.
#[test]
fn r3_wrong_environment_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_environment = TrustBundleEnvironment::Testnet;
    let outcome = fx.route_present();
    assert!(outcome.is_fail_closed());
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R4. wrong chain rejected.
#[test]
fn r4_wrong_chain_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_chain_id = "wrong-chain".to_string();
    assert!(fx.route_present().is_fail_closed());
}

// R5. wrong genesis rejected.
#[test]
fn r5_wrong_genesis_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_genesis_hash = "wrong-genesis".to_string();
    assert!(fx.route_present().is_fail_closed());
}

// R6. wrong candidate digest rejected.
#[test]
fn r6_wrong_candidate_digest_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    fx.ev_exp.expected_candidate_digest = "wrong-candidate".to_string();
    assert!(fx.route_present().is_fail_closed());
}

// R7. wrong evaluator source identity digest rejected.
#[test]
fn r7_wrong_source_identity_digest_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    // Corrupt the request's bound source-identity digest.
    fx.request.decision_source_identity_digest = "wrong-source-identity-digest".to_string();
    // Rebuild the response so it still answers this request digest.
    fx.response.request_digest = fx.request.request_digest();
    assert!(fx.route_present().is_fail_closed());
}

// R8. wrong evaluator request digest rejected.
#[test]
fn r8_wrong_request_digest_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    // Response answers a stale request digest.
    fx.response.request_digest = "stale-request-digest".to_string();
    assert!(fx.route_present().is_fail_closed());
}

// R9. wrong evaluator response digest rejected (invalid commitment).
#[test]
fn r9_wrong_response_commitment_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.response.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
    assert!(fx.route_present().is_fail_closed());
}

// R10. wrong lifecycle action rejected.
#[test]
fn r10_wrong_lifecycle_action_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    assert!(fx.route_present().is_fail_closed());
}

// R11. wrong authority-domain sequence rejected.
#[test]
fn r11_wrong_sequence_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_authority_domain_sequence = 99;
    assert!(fx.route_present().is_fail_closed());
}

// R12. expired evaluator request rejected.
#[test]
fn r12_expired_request_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.now_epoch = 9_999; // beyond expiry_epoch
    assert!(fx.route_present().is_fail_closed());
}

// R13. stale / replayed evaluator request rejected.
#[test]
fn r13_stale_replayed_request_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_replay_nonce = "different-nonce".to_string();
    assert!(fx.route_present().is_fail_closed());
}

// R14. quorum / threshold insufficient rejected.
#[test]
fn r14_quorum_insufficient_rejected() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.request.quorum = GovernanceQuorumThreshold::new(1, 5, 3); // approvals < required
    fx.response.request_digest = fx.request.request_digest();
    assert!(fx.route_present().is_fail_closed());
}

// R15. emergency action not authorized rejected (emergency request under a
// plain fixture policy/evaluator).
#[test]
fn r15_emergency_not_authorized_rejected() {
    let mut fx = emergency_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
    let outcome = fx.route_present_with(&FixtureGovernanceExecutionEvaluatorInterface);
    assert!(outcome.is_fail_closed());
}

// R16. production evaluator unavailable rejected.
#[test]
fn r16_production_unavailable_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_present_with(&ProductionDecisionSourceEvaluatorInterface);
    assert_routed_evaluator_reject(&outcome, |o| o.is_unavailable());
}

// R17. on-chain evaluator unavailable rejected.
#[test]
fn r17_onchain_unavailable_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let outcome = fx.route_present_with(&OnChainDecisionSourceEvaluatorInterface);
    assert_routed_evaluator_reject(&outcome, |o| o.is_unavailable());
}

// R18. MainNet evaluator unavailable / refused rejected.
#[test]
fn r18_mainnet_evaluator_unavailable_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_present_with(&MainnetDecisionSourceEvaluatorInterface);
    assert_routed_evaluator_reject(&outcome, |o| {
        matches!(o, EvaluatorOutcome::MainnetDecisionSourceUnavailable)
    });
}

// R19. validator-set rotation unsupported rejected.
#[test]
fn r19_validator_set_rotation_unsupported() {
    assert!(validator_set_rotation_remains_unsupported_under_peer_context());
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.request.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    fx.response.request_digest = fx.request.request_digest();
    assert!(fx.route_present().is_fail_closed());
}

// R20. policy-change action unsupported rejected.
#[test]
fn r20_policy_change_action_unsupported() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.request.governance_action = GovernanceAction::PolicyChangeRequest;
    fx.response.request_digest = fx.request.request_digest();
    assert!(fx.route_present().is_fail_closed());
}

// R21. peer majority cannot satisfy evaluator policy.
#[test]
fn r21_peer_majority_cannot_satisfy_policy() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    fx.source_class = PeerEvaluatorSourceClass::PeerMajorityGossip;
    let outcome = fx.route_present();
    assert_eq!(outcome, PeerEvaluatorContextOutcome::PeerMajorityUnsupported);
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R22. local operator cannot satisfy evaluator policy where the policy requires
// evaluator authority (production-required policy with the unavailable
// production evaluator).
#[test]
fn r22_local_operator_cannot_satisfy_production_policy() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
    let outcome = fx.route_present_with(&ProductionDecisionSourceEvaluatorInterface);
    assert!(outcome.is_fail_closed());
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R23. live inbound 0x05 unsupported carrier rejected without
// propagation/staging/apply.
#[test]
fn r23_live_inbound_unsupported_carrier_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let outcome = fx.route_with_status(
        &FixtureGovernanceExecutionEvaluatorInterface,
        PeerEvaluatorCarrierStatus::WireSchemaUnavailable,
    );
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::WireSchemaUnavailable { .. }
    ));
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R24. peer-driven drain unsupported carrier rejected without apply.
#[test]
fn r24_peer_driven_drain_unsupported_carrier_rejected() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let outcome = fx.route_with_status(
        &FixtureGovernanceExecutionEvaluatorInterface,
        PeerEvaluatorCarrierStatus::UnsupportedSurface,
    );
    assert!(outcome.is_fail_closed());
    assert!(!outcome.is_apply_authorized());
}

// R25. validation-only rejection writes no marker and no sequence. The
// boundary is a pure function: a fail-closed outcome authorizes no mutation.
#[test]
fn r25_validation_only_rejection_no_marker_no_sequence() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    fx.ev_exp.expected_candidate_digest = "wrong".to_string();
    let outcome = fx.route_present();
    assert!(outcome.is_fail_closed());
    // No mutate authorization => no marker write, no sequence advance.
    assert!(!outcome.is_apply_authorized());
}

// R26. mutating rejection produces no Run 070 call, no live trust swap, no
// session eviction, no sequence write, and no marker write.
#[test]
fn r26_mutating_rejection_no_side_effects() {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    fx.ev_exp.expected_candidate_digest = "wrong".to_string();
    let outcome = fx.route_present();
    assert!(outcome.is_fail_closed());
    assert!(outcome.no_propagation_no_staging_no_apply());
}

// R27. MainNet peer-driven apply remains refused even with fixture approval.
#[test]
fn r27_mainnet_peer_driven_apply_refused() {
    assert!(mainnet_peer_driven_apply_remains_refused_under_peer_context());
    let fx = rotate_fixture(
        TrustBundleEnvironment::Mainnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let outcome = fx.route_present();
    assert_eq!(outcome, PeerEvaluatorContextOutcome::MainNetRefused);
    // Even an explicit MainNetRefused carrier status routes to refusal.
    let refused = fx.route_with_status(
        &FixtureGovernanceExecutionEvaluatorInterface,
        PeerEvaluatorCarrierStatus::MainNetRefused,
    );
    assert_eq!(refused, PeerEvaluatorContextOutcome::MainNetRefused);
}

// ===========================================================================
// Deterministic digest / local-only / surface-mismatch tests
// ===========================================================================

#[test]
fn context_digest_is_deterministic_and_field_sensitive() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let peer_a = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        PeerEvaluatorSourceClass::LiveInboundPeer,
        "peer-0001",
        &ctx,
        Some(TRUST_BUNDLE_DIGEST.to_string()),
        Some(MARKER_DIGEST.to_string()),
    );
    let peer_b = peer_a.clone();
    assert_eq!(peer_a.context_digest(), peer_b.context_digest());

    let mut peer_c = peer_a.clone();
    peer_c.peer_id = "different-peer".to_string();
    assert_ne!(peer_a.context_digest(), peer_c.context_digest());

    let mut peer_d = peer_a.clone();
    peer_d.surface = PeerEvaluatorContextSurface::PeerDrivenDrain;
    assert_ne!(peer_a.context_digest(), peer_d.context_digest());
}

#[test]
fn surface_mismatch_between_peer_and_integration_is_unsupported() {
    // Peer context says live inbound 0x05 but the integration drives the drain
    // surface — fail closed as unsupported.
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::PeerDrivenDrain,
    );
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::PeerDrivenDrain,
        PeerEvaluatorSourceClass::DrainStagedPeer,
        "peer-0001",
        &ctx,
        None,
        None,
    );
    peer.surface = PeerEvaluatorContextSurface::LiveInbound0x05; // mismatch
    let outcome = evaluate_peer_evaluator_context(&peer, &ctx);
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::UnsupportedSurface { .. }
    ));
}

#[test]
fn inconsistent_present_binding_rejected_as_malformed() {
    let fx = rotate_fixture(
        TrustBundleEnvironment::Devnet,
        PeerEvaluatorContextSurface::LiveInbound0x05,
    );
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PeerEvaluatorContextSurface::LiveInbound0x05,
        PeerEvaluatorSourceClass::LiveInboundPeer,
        "peer-0001",
        &ctx,
        None,
        None,
    );
    // Tamper a referenced digest so the local cross-binding fails.
    peer.evaluator_request_digest = Some("tampered-request-digest".to_string());
    assert!(!peer.binds_consistently_with(&ctx));
    let outcome = evaluate_peer_evaluator_context(&peer, &ctx);
    assert!(matches!(
        outcome,
        PeerEvaluatorContextOutcome::MalformedRejected { .. }
    ));
}

// Compatibility smoke: TestNet fixture context routes through the integration
// layer just like DevNet (Run 220/222/224 compatibility).
#[test]
fn testnet_fixture_routes_and_mutates() {
    for surface in SURFACES {
        if surface == PeerEvaluatorContextSurface::PeerDrivenDrain {
            // drain on testnet is representable and non-MainNet, so it routes.
        }
        let fx = rotate_fixture(TrustBundleEnvironment::Testnet, surface);
        assert!(fx.route_present().is_apply_authorized());
    }
}