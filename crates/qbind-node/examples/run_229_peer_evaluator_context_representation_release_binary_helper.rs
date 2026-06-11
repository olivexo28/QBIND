//! Run 229 — release-built helper for the Run 228 governance evaluator
//! **peer evaluator-context representation boundary**
//! (`crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`).
//!
//! Where Run 226 landed the call-site wiring and Run 227 proved it in release
//! mode, Run 228 added a typed, local-only evaluator-context representation
//! boundary ([`GovernanceEvaluatorPeerContext`]) for the two previously-limited
//! surfaces — the live inbound `0x05` peer-candidate validation surface and the
//! peer-driven drain validation surface — with the carrier taxonomy
//! (`Absent`, `Present`, `Malformed`, `UnsupportedSurface`,
//! `WireSchemaUnavailable`, `PeerMajorityUnsupported`, `MainNetRefused`). Run
//! 228 captured no release-binary evidence; Run 229 is that release-binary
//! evidence.
//!
//! This helper drives the A1–A18 / R1–R27 matrix from `task/RUN_229_TASK.txt`
//! through the **release-built** Run 228 peer evaluator-context symbols,
//! proving that:
//!
//! * the default Disabled + absent-carrier path preserves legacy validation
//!   behavior on both surfaces (`LegacyValidationPreserved`);
//! * a `Present` local context binds selected policy, candidate digest,
//!   evaluator request/response/source digests, lifecycle action, sequence,
//!   environment, chain id, and genesis hash, and routes through the Run 226
//!   call-site wiring into the Run 224 integration layer;
//! * only the routed `RoutedProceedMutate` authorizes apply;
//! * every other carrier status is a typed fail-closed (never an approval) —
//!   in particular `WireSchemaUnavailable` is fail-closed, not approval;
//! * invalid live inbound `0x05` contexts are not propagated, staged, or
//!   applied; invalid peer-driven drain contexts are not applied;
//! * production / on-chain / MainNet evaluators are reached and fail closed as
//!   unavailable;
//! * MainNet peer-driven apply remains refused even with a fixture approval;
//! * peer-majority gossip can never satisfy an evaluator policy;
//! * validator-set rotation remains unsupported.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, on-chain proof verifier, KMS/HSM, or RemoteSigner
//! backend. The boundary is a pure function (no marker write, no sequence
//! write, no live trust swap, no session eviction, no Run 070 call). MainNet
//! peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadCarryingDecisionOutcome,
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
// Shared constants (mirror the Run 220 / 222 / 224 / 226 / 228 corpora so the
// runtime-consumption material and the evaluator material bind to the same
// trust domain, proposal/decision identity, candidate digest, replay nonce).
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
// Owned-material fixture bundle (mirrors the Run 228 test fixture)
// ===========================================================================

/// Owns every layer's material for one boundary round-trip so a scenario can
/// mutate any field and then borrow it into the integration + peer context
/// routed through the Run 228 peer evaluator-context boundary.
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
            PeerEvaluatorContextSurface::LiveInbound0x05 => {
                PeerEvaluatorSourceClass::LiveInboundPeer
            }
            PeerEvaluatorContextSurface::PeerDrivenDrain => {
                PeerEvaluatorSourceClass::DrainStagedPeer
            }
        },
    }
}

fn emergency_fixture(env: TrustBundleEnvironment, surface: PeerEvaluatorContextSurface) -> Fixture {
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

// ===========================================================================
// Stable outcome tags
// ===========================================================================

/// Stable tag for the typed Run 222 evaluator outcome.
fn outcome_tag(o: &EvaluatorOutcome) -> &'static str {
    use EvaluatorOutcome as O;
    match o {
        O::FixtureDecisionSourceAccepted { .. } => "accept:FixtureDecisionSourceAccepted",
        O::EmergencyFixtureAccepted { .. } => "accept:EmergencyFixtureAccepted",
        O::EvaluatorResponseAuthorized { .. } => "accept:EvaluatorResponseAuthorized",
        O::EvaluatorDisabled => "reject:EvaluatorDisabled",
        O::ProductionDecisionSourceUnavailable => "reject:ProductionDecisionSourceUnavailable",
        O::OnChainDecisionSourceUnavailable => "reject:OnChainDecisionSourceUnavailable",
        O::MainnetDecisionSourceUnavailable => "reject:MainnetDecisionSourceUnavailable",
        O::FixtureRejectedUnderProductionPolicy { .. } => {
            "reject:FixtureRejectedUnderProductionPolicy"
        }
        O::EmergencyFixtureRejectedUnderProductionPolicy { .. } => {
            "reject:EmergencyFixtureRejectedUnderProductionPolicy"
        }
        O::SourceKindPolicyMismatch { .. } => "reject:SourceKindPolicyMismatch",
        O::UnknownSourceRejected { .. } => "reject:UnknownSourceRejected",
        O::FixtureRejectedForMainNet => "reject:FixtureRejectedForMainNet",
        O::WrongEnvironment { .. } => "reject:WrongEnvironment",
        O::WrongChain { .. } => "reject:WrongChain",
        O::WrongGenesis { .. } => "reject:WrongGenesis",
        O::WrongAuthorityRoot { .. } => "reject:WrongAuthorityRoot",
        O::WrongGovernanceProofDigest { .. } => "reject:WrongGovernanceProofDigest",
        O::WrongOnChainProofDigest { .. } => "reject:WrongOnChainProofDigest",
        O::WrongCustodyAttestationDigest { .. } => "reject:WrongCustodyAttestationDigest",
        O::WrongProposalId { .. } => "reject:WrongProposalId",
        O::WrongDecisionId { .. } => "reject:WrongDecisionId",
        O::WrongLifecycleAction { .. } => "reject:WrongLifecycleAction",
        O::WrongCandidateDigest { .. } => "reject:WrongCandidateDigest",
        O::WrongAuthorityDomainSequence { .. } => "reject:WrongAuthorityDomainSequence",
        O::WrongEffectiveEpoch { .. } => "reject:WrongEffectiveEpoch",
        O::ExpiredDecision { .. } => "reject:ExpiredDecision",
        O::StaleOrReplayedDecision => "reject:StaleOrReplayedDecision",
        O::QuorumThresholdInsufficient { .. } => "reject:QuorumThresholdInsufficient",
        O::EmergencyActionNotAuthorized => "reject:EmergencyActionNotAuthorized",
        O::ValidatorSetRotationUnsupported => "reject:ValidatorSetRotationUnsupported",
        O::PolicyChangeActionUnsupported => "reject:PolicyChangeActionUnsupported",
        O::MalformedSourceIdentity { .. } => "reject:MalformedSourceIdentity",
        O::MalformedEvaluatorRequest { .. } => "reject:MalformedEvaluatorRequest",
        O::MalformedEvaluatorResponse { .. } => "reject:MalformedEvaluatorResponse",
        O::UnsupportedEvaluatorVersion { .. } => "reject:UnsupportedEvaluatorVersion",
        O::InvalidResponseCommitment => "reject:InvalidResponseCommitment",
        O::EvaluatorResponseRejected => "reject:EvaluatorResponseRejected",
        O::GovernanceExecutionDecisionInvalid { .. } => "reject:GovernanceExecutionDecisionInvalid",
        O::EvaluatorResponseInvalid { .. } => "reject:EvaluatorResponseInvalid",
        O::LocalOperatorCannotSatisfyEvaluatorPolicy => {
            "reject:LocalOperatorCannotSatisfyEvaluatorPolicy"
        }
        O::PeerMajorityCannotSatisfyEvaluatorPolicy => {
            "reject:PeerMajorityCannotSatisfyEvaluatorPolicy"
        }
    }
}

/// Stable tag for the Run 213 carrier outcome surfaced by a runtime-consumption
/// fail-closed.
fn carrier_tag(o: &GovernanceExecutionPayloadCarryingDecisionOutcome) -> &'static str {
    use GovernanceExecutionPayloadCarryingDecisionOutcome as C;
    match o {
        C::MalformedGovernanceExecutionPayload(_) => "MalformedGovernanceExecutionPayload",
        C::GovernanceExecutionRequiredButAbsent { .. } => "GovernanceExecutionRequiredButAbsent",
        C::NoGovernanceExecutionSupplied => "NoGovernanceExecutionSupplied",
        C::MainNetPeerDrivenApplyRefused => "MainNetPeerDrivenApplyRefused",
        C::Callsite(_) => "Callsite",
    }
}

/// Stable tag for the underlying Run 224 integration outcome.
fn itag(o: &GovernanceEvaluatorRuntimeIntegrationOutcome) -> String {
    use GovernanceEvaluatorRuntimeIntegrationOutcome as I;
    match o {
        I::ProceedLegacyBypass => "proceed:LegacyBypass".to_string(),
        I::ProceedMutate { .. } => "proceed:Mutate".to_string(),
        I::RuntimeConsumptionFailClosed(c) => {
            format!("reject:RuntimeConsumptionFailClosed:{}", carrier_tag(c))
        }
        I::EvaluatorRejected(e) => format!("reject:Evaluator:{}", outcome_tag(e)),
        I::MainNetPeerDrivenApplyRefused => "reject:MainNetPeerDrivenApplyRefused".to_string(),
    }
}

/// Stable tag for a Run 228 peer evaluator-context outcome. Every variant
/// other than `legacy-validation-preserved` and `routed-proceed-mutate` is a
/// typed fail-closed (never an approval).
fn ptag(o: &PeerEvaluatorContextOutcome) -> String {
    use PeerEvaluatorContextOutcome as P;
    match o {
        P::LegacyValidationPreserved => "legacy-validation-preserved".to_string(),
        P::RoutedProceedMutate { .. } => "routed-proceed-mutate".to_string(),
        P::RoutedFailClosed(fc) => format!("routed-fail-closed:{}", itag(&fc.outcome)),
        P::UnsupportedSurface { .. } => "unsupported-surface".to_string(),
        P::WireSchemaUnavailable { .. } => "wire-schema-unavailable".to_string(),
        P::MalformedRejected { .. } => "malformed-rejected".to_string(),
        P::MissingContextRejected { .. } => "missing-context-rejected".to_string(),
        P::PeerMajorityUnsupported => "peer-majority-unsupported".to_string(),
        P::MainNetRefused => "mainnet-refused".to_string(),
    }
}

fn is_apply(o: &PeerEvaluatorContextOutcome) -> bool {
    o.is_apply_authorized()
}

fn no_apply(o: &PeerEvaluatorContextOutcome) -> bool {
    o.no_propagation_no_staging_no_apply()
}

// ===========================================================================
// Output table helper
// ===========================================================================

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

struct Table {
    name: &'static str,
    rows: String,
    expected: String,
    actual: String,
    pass: u64,
    fail: u64,
}
impl Table {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            rows: String::new(),
            expected: String::new(),
            actual: String::new(),
            pass: 0,
            fail: 0,
        }
    }
    fn check(&mut self, id: &str, expected: &str, actual: &str) {
        let ok = expected == actual;
        self.pass += ok as u64;
        self.fail += (!ok) as u64;
        self.rows.push_str(&format!(
            "{id}\t{}\texpected={expected}\tactual={actual}\n",
            if ok { "PASS" } else { "FAIL" }
        ));
        self.expected.push_str(&format!("{id}\t{expected}\n"));
        self.actual.push_str(&format!("{id}\t{actual}\n"));
    }
    fn assert_true(&mut self, id: &str, ok: bool, detail: &str) {
        self.check(id, "true", if ok { "true" } else { "false" });
        if !detail.is_empty() {
            self.rows.push_str(&format!("\t# {id}: {detail}\n"));
        }
    }
    /// Assert that a fail-closed outcome authorizes no apply and leaves no
    /// propagation/staging/apply (the boundary is pure).
    fn assert_fail_closed(&mut self, id: &str, o: &PeerEvaluatorContextOutcome) {
        self.assert_true(&format!("{id}.is-fail-closed"), o.is_fail_closed(), "");
        self.assert_true(&format!("{id}.not-apply"), !is_apply(o), "");
        self.assert_true(&format!("{id}.no-prop-no-stage-no-apply"), no_apply(o), "");
    }
    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

// ===========================================================================
// A — accepted / compatible scenarios (A1–A18) routed through the Run 228
// peer evaluator-context boundary.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use PeerEvaluatorContextSurface as PS;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — live inbound 0x05 default Disabled + absent carrier preserves legacy
    // validation behavior.
    {
        let o = evaluate_peer_evaluator_context_wire_only(
            PS::LiveInbound0x05,
            Env::Devnet,
            CHAIN,
            GENESIS,
            EvaluatorPolicy::Disabled,
        );
        t.check("A1.live-0x05-disabled-absent", "legacy-validation-preserved", &ptag(&o));
        t.assert_true("A1.is-legacy", o.is_legacy_validation_preserved(), "");
        t.assert_true("A1.not-apply", !is_apply(&o), "");
    }
    // A2 — peer-driven drain default Disabled + absent carrier preserves legacy
    // validation behavior.
    {
        let o = evaluate_peer_evaluator_context_wire_only(
            PS::PeerDrivenDrain,
            Env::Devnet,
            CHAIN,
            GENESIS,
            EvaluatorPolicy::Disabled,
        );
        t.check("A2.peer-drain-disabled-absent", "legacy-validation-preserved", &ptag(&o));
    }
    // A3 — live inbound 0x05 local Present context binds every required field.
    {
        let fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
        let peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PS::LiveInbound0x05,
            PeerEvaluatorSourceClass::LiveInboundPeer,
            "peer-0001",
            &ctx,
            Some(TRUST_BUNDLE_DIGEST.to_string()),
            Some(MARKER_DIGEST.to_string()),
        );
        t.check(
            "A3.selected-policy",
            "FixtureGovernanceAllowed",
            &format!("{:?}", peer.selected_policy),
        );
        t.check("A3.load-status", "available", peer.load_status.tag());
        t.check("A3.sequence", "7", &peer.authority_domain_sequence.to_string());
        t.check("A3.lifecycle", "Rotate", &format!("{:?}", peer.lifecycle_action));
        t.check("A3.environment", "devnet", &peer.environment.to_string());
        t.check("A3.chain-id", CHAIN, &peer.chain_id);
        t.check("A3.genesis", GENESIS, &peer.genesis_hash);
        t.check(
            "A3.request-digest",
            fx.request.request_digest().as_str(),
            peer.evaluator_request_digest.as_deref().unwrap_or(""),
        );
        t.check(
            "A3.response-digest",
            fx.response.response_digest().as_str(),
            peer.evaluator_response_digest.as_deref().unwrap_or(""),
        );
        t.check(
            "A3.source-identity-digest",
            fx.identity.source_identity_digest().as_str(),
            peer.evaluator_source_identity_digest.as_deref().unwrap_or(""),
        );
        t.check(
            "A3.payload-digest",
            fx.request.governance_execution_input_digest.as_str(),
            peer.governance_execution_payload_digest.as_deref().unwrap_or(""),
        );
        t.check(
            "A3.candidate-trust-bundle-digest",
            TRUST_BUNDLE_DIGEST,
            peer.candidate_trust_bundle_digest.as_deref().unwrap_or(""),
        );
        t.check(
            "A3.candidate-v2-marker-digest",
            MARKER_DIGEST,
            peer.candidate_v2_marker_digest.as_deref().unwrap_or(""),
        );
        t.assert_true("A3.bindings-complete", peer.present_bindings_complete(), "");
        t.assert_true("A3.binds-consistently", peer.binds_consistently_with(&ctx), "");
    }
    // A4 — peer-driven drain local Present context binds the same set.
    {
        let fx = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain);
        let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
        let peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PS::PeerDrivenDrain,
            PeerEvaluatorSourceClass::DrainStagedPeer,
            "peer-0001",
            &ctx,
            Some(TRUST_BUNDLE_DIGEST.to_string()),
            Some(MARKER_DIGEST.to_string()),
        );
        t.assert_true("A4.bindings-complete", peer.present_bindings_complete(), "");
        t.assert_true("A4.binds-consistently", peer.binds_consistently_with(&ctx), "");
        t.check("A4.carrier-present", "present", peer.carrier_status.tag());
    }
    // A5 — live inbound 0x05 valid fixture Present context routes to Run 226
    // integration and proceeds to mutate (representable).
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_present();
        t.check("A5.live-0x05-routes-mutate", "routed-proceed-mutate", &ptag(&o));
        t.assert_true("A5.apply-authorized", is_apply(&o), "");
        match &o {
            PeerEvaluatorContextOutcome::RoutedProceedMutate {
                integration_outcome,
                context_digest,
            } => {
                t.assert_true("A5.integration-mutate", integration_outcome.is_mutate_authorized(), "");
                t.assert_true("A5.context-digest-nonempty", !context_digest.is_empty(), "");
            }
            other => t.assert_true("A5.shape", false, &format!("{other:?}")),
        }
        // Not representable -> typed UnsupportedSurface without apply.
        let unsup = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::UnsupportedSurface,
        );
        t.check("A5.live-0x05-unsupported", "unsupported-surface", &ptag(&unsup));
        t.assert_true("A5.unsupported-no-apply", no_apply(&unsup), "");
    }
    // A6 — peer-driven drain valid fixture Present context routes and proceeds.
    {
        let o = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain).route_present();
        t.check("A6.peer-drain-routes-mutate", "routed-proceed-mutate", &ptag(&o));
        t.assert_true("A6.apply-authorized", is_apply(&o), "");
        let unsup = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::UnsupportedSurface,
        );
        t.check("A6.peer-drain-unsupported", "unsupported-surface", &ptag(&unsup));
        t.assert_true("A6.unsupported-no-apply", no_apply(&unsup), "");
    }
    // A7 — explicit emergency fixture context accepted only for explicit
    // emergency action in non-production source/test context.
    {
        for (id, surface) in [
            ("A7.live-0x05", PS::LiveInbound0x05),
            ("A7.peer-drain", PS::PeerDrivenDrain),
        ] {
            let o = emergency_fixture(Env::Devnet, surface)
                .route_present_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
            t.check(&format!("{id}-emergency-accept"), "routed-proceed-mutate", &ptag(&o));
        }
        // The same context under a non-emergency fixture evaluator/policy is
        // rejected (kind/policy mismatch) — never accepted as production.
        let mut fx = emergency_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
        let rej = fx.route_present_with(&FixtureGovernanceExecutionEvaluatorInterface);
        t.assert_true("A7.non-emergency-fail-closed", rej.is_fail_closed(), "");
    }
    // A8 — production evaluator context reaches production unavailable.
    {
        for (id, surface) in [
            ("A8.live-0x05", PS::LiveInbound0x05),
            ("A8.peer-drain", PS::PeerDrivenDrain),
        ] {
            let o = rotate_fixture(Env::Devnet, surface)
                .route_present_with(&ProductionDecisionSourceEvaluatorInterface);
            t.check(
                &format!("{id}-production-unavailable"),
                "routed-fail-closed:reject:Evaluator:reject:ProductionDecisionSourceUnavailable",
                &ptag(&o),
            );
            t.assert_true(&format!("{id}.no-apply"), no_apply(&o), "");
        }
    }
    // A9 — on-chain evaluator context reaches on-chain unavailable.
    {
        for (id, surface) in [
            ("A9.live-0x05", PS::LiveInbound0x05),
            ("A9.peer-drain", PS::PeerDrivenDrain),
        ] {
            let o = rotate_fixture(Env::Devnet, surface)
                .route_present_with(&OnChainDecisionSourceEvaluatorInterface);
            t.check(
                &format!("{id}-onchain-unavailable"),
                "routed-fail-closed:reject:Evaluator:reject:OnChainDecisionSourceUnavailable",
                &ptag(&o),
            );
        }
    }
    // A10 — MainNet evaluator context reaches MainNet unavailable/refused (on a
    // non-MainNet domain so consumption accepts and the evaluator is reached).
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05)
            .route_present_with(&MainnetDecisionSourceEvaluatorInterface);
        t.check(
            "A10.mainnet-evaluator-unavailable",
            "routed-fail-closed:reject:Evaluator:reject:MainnetDecisionSourceUnavailable",
            &ptag(&o),
        );
    }
    // A11 — MainNet peer-driven apply remains refused even with fixture
    // approval.
    {
        let o = rotate_fixture(Env::Mainnet, PS::PeerDrivenDrain).route_present();
        t.check("A11.mainnet-peer-driven-refused", "mainnet-refused", &ptag(&o));
        t.assert_true("A11.is-mainnet-refused", o.is_mainnet_refused(), "");
        t.assert_true("A11.no-apply", no_apply(&o), "");
    }
    // A12 — invalid live inbound 0x05 context is not propagated, staged, or
    // applied.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_candidate_digest = "wrong-candidate-digest".to_string();
        let o = fx.route_present();
        t.assert_fail_closed("A12", &o);
    }
    // A13 — invalid peer-driven drain context produces no apply.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain);
        fx.ev_exp.expected_candidate_digest = "wrong-candidate-digest".to_string();
        let o = fx.route_present();
        t.assert_fail_closed("A13", &o);
    }
    // A14 — absence of a wire/schema carrier is typed WireSchemaUnavailable,
    // not approval.
    {
        for (id, surface) in [
            ("A14.live-0x05", PS::LiveInbound0x05),
            ("A14.peer-drain", PS::PeerDrivenDrain),
        ] {
            let o = evaluate_peer_evaluator_context_wire_only(
                surface,
                Env::Devnet,
                CHAIN,
                GENESIS,
                EvaluatorPolicy::FixtureDecisionSourceAllowed,
            );
            t.check(&format!("{id}-wire-schema-unavailable"), "wire-schema-unavailable", &ptag(&o));
            t.assert_true(&format!("{id}.not-apply"), !is_apply(&o), "");
            t.assert_true(&format!("{id}.no-apply"), no_apply(&o), "");
        }
    }
    // A15 — every carrier-taxonomy status is release-evidenced.
    {
        // Absent (under explicit policy -> missing-context-rejected).
        let mut absent_fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        absent_fx.ev_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
        let absent = absent_fx.route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::Absent,
        );
        t.check("A15.absent", "missing-context-rejected", &ptag(&absent));
        // Present (routes to mutate).
        let present = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_present();
        t.check("A15.present", "routed-proceed-mutate", &ptag(&present));
        // Malformed.
        let malformed = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::Malformed,
        );
        t.check("A15.malformed", "malformed-rejected", &ptag(&malformed));
        // UnsupportedSurface.
        let unsupported = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::UnsupportedSurface,
        );
        t.check("A15.unsupported-surface", "unsupported-surface", &ptag(&unsupported));
        // WireSchemaUnavailable.
        let wire = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::WireSchemaUnavailable,
        );
        t.check("A15.wire-schema-unavailable", "wire-schema-unavailable", &ptag(&wire));
        // PeerMajorityUnsupported.
        let pm = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::PeerMajorityUnsupported,
        );
        t.check("A15.peer-majority-unsupported", "peer-majority-unsupported", &ptag(&pm));
        // MainNetRefused.
        let mn = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::MainNetRefused,
        );
        t.check("A15.mainnet-refused", "mainnet-refused", &ptag(&mn));
        // Every non-Present status is fail-closed / not approval.
        for (id, o) in [
            ("A15.absent", &absent),
            ("A15.malformed", &malformed),
            ("A15.unsupported-surface", &unsupported),
            ("A15.wire-schema-unavailable", &wire),
            ("A15.peer-majority-unsupported", &pm),
            ("A15.mainnet-refused", &mn),
        ] {
            t.assert_true(&format!("{id}.not-apply"), !is_apply(o), "");
        }
    }
    // A16 — Run 227 call-site wiring release behavior remains compatible: a
    // routed Present context surfaces the same composed integration outcome the
    // call-site wiring produces (mutate here; production-unavailable below).
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_present();
        match &o {
            PeerEvaluatorContextOutcome::RoutedProceedMutate { integration_outcome, .. } => {
                t.check("A16.integration-outcome", "proceed:Mutate", &itag(integration_outcome));
            }
            other => t.assert_true("A16.shape", false, &format!("{other:?}")),
        }
        let prod = rotate_fixture(Env::Devnet, PS::LiveInbound0x05)
            .route_present_with(&ProductionDecisionSourceEvaluatorInterface);
        match &prod {
            PeerEvaluatorContextOutcome::RoutedFailClosed(fc) => {
                t.check(
                    "A16.production-integration-outcome",
                    "reject:Evaluator:reject:ProductionDecisionSourceUnavailable",
                    &itag(&fc.outcome),
                );
            }
            other => t.assert_true("A16.production-shape", false, &format!("{other:?}")),
        }
    }
    // A17 — Run 225 integration release behavior remains compatible: TestNet
    // fixture context routes through the integration layer like DevNet.
    {
        for (id, surface) in [
            ("A17.live-0x05", PS::LiveInbound0x05),
            ("A17.peer-drain", PS::PeerDrivenDrain),
        ] {
            let o = rotate_fixture(Env::Testnet, surface).route_present();
            t.check(&format!("{id}-testnet-routes-mutate"), "routed-proceed-mutate", &ptag(&o));
            t.assert_true(&format!("{id}.apply"), is_apply(&o), "");
        }
    }
    // A18 — Run 223 evaluator-interface release behavior remains compatible: a
    // Disabled evaluator policy fails closed for a present fixture carrier;
    // production / on-chain / MainNet evaluators are callable but fail closed.
    {
        let mut disabled_ev = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        disabled_ev.ev_policy = EvaluatorPolicy::Disabled;
        let o = disabled_ev.route_present();
        t.check(
            "A18.disabled-evaluator",
            "routed-fail-closed:reject:Evaluator:reject:EvaluatorDisabled",
            &ptag(&o),
        );
    }
    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R27); all non-mutating, no apply.
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use PeerEvaluatorContextSurface as PS;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1 — malformed evaluator peer context rejected.
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::Malformed,
        );
        t.check("R1.malformed", "malformed-rejected", &ptag(&o));
        t.assert_fail_closed("R1", &o);
    }
    // R1b — a Present context missing required bindings is malformed.
    {
        let fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
        let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PS::LiveInbound0x05,
            PeerEvaluatorSourceClass::LiveInboundPeer,
            "peer-0001",
            &ctx,
            None,
            None,
        );
        peer.evaluator_request_digest = None;
        t.assert_true("R1b.bindings-incomplete", !peer.present_bindings_complete(), "");
        let o = evaluate_peer_evaluator_context(&peer, &ctx);
        t.check("R1b.missing-binding-malformed", "malformed-rejected", &ptag(&o));
    }
    // R2 — missing evaluator context rejected under explicit evaluator policy.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
        let o = fx.route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::Absent,
        );
        t.check("R2.missing-under-explicit", "missing-context-rejected", &ptag(&o));
        t.assert_fail_closed("R2", &o);
    }
    // R3 — wrong environment rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_environment = Env::Testnet;
        let o = fx.route_present();
        t.assert_true("R3.wrong-environment", o.is_fail_closed(), "");
        t.assert_fail_closed("R3", &o);
    }
    // R4 — wrong chain rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_chain_id = "wrong-chain".to_string();
        t.assert_true("R4.wrong-chain", fx.route_present().is_fail_closed(), "");
    }
    // R5 — wrong genesis rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_genesis_hash = "wrong-genesis".to_string();
        t.assert_true("R5.wrong-genesis", fx.route_present().is_fail_closed(), "");
    }
    // R6 — wrong candidate digest rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain);
        fx.ev_exp.expected_candidate_digest = "wrong-candidate".to_string();
        t.assert_true("R6.wrong-candidate", fx.route_present().is_fail_closed(), "");
    }
    // R7 — wrong evaluator source identity digest rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.request.decision_source_identity_digest = "wrong-source-identity-digest".to_string();
        fx.response.request_digest = fx.request.request_digest();
        t.assert_true("R7.wrong-source-identity", fx.route_present().is_fail_closed(), "");
    }
    // R8 — wrong evaluator request digest rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.response.request_digest = "stale-request-digest".to_string();
        t.assert_true("R8.wrong-request-digest", fx.route_present().is_fail_closed(), "");
    }
    // R9 — wrong evaluator response digest rejected (invalid commitment).
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.response.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
        t.assert_true("R9.wrong-response-commitment", fx.route_present().is_fail_closed(), "");
    }
    // R10 — wrong lifecycle action rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
        t.assert_true("R10.wrong-lifecycle", fx.route_present().is_fail_closed(), "");
    }
    // R11 — wrong authority-domain sequence rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_authority_domain_sequence = 99;
        t.assert_true("R11.wrong-sequence", fx.route_present().is_fail_closed(), "");
    }
    // R12 — expired evaluator request rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.now_epoch = 9_999;
        t.assert_true("R12.expired", fx.route_present().is_fail_closed(), "");
    }
    // R13 — stale / replayed evaluator request rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_replay_nonce = "different-nonce".to_string();
        t.assert_true("R13.stale-replayed", fx.route_present().is_fail_closed(), "");
    }
    // R14 — quorum / threshold insufficient rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.request.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
        fx.response.request_digest = fx.request.request_digest();
        t.assert_true("R14.quorum-insufficient", fx.route_present().is_fail_closed(), "");
    }
    // R15 — emergency action not authorized rejected.
    {
        let mut fx = emergency_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_policy = EvaluatorPolicy::FixtureDecisionSourceAllowed;
        let o = fx.route_present_with(&FixtureGovernanceExecutionEvaluatorInterface);
        t.assert_true("R15.emergency-not-authorized", o.is_fail_closed(), "");
    }
    // R16 — production evaluator unavailable rejected.
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05)
            .route_present_with(&ProductionDecisionSourceEvaluatorInterface);
        t.check(
            "R16.production-unavailable",
            "routed-fail-closed:reject:Evaluator:reject:ProductionDecisionSourceUnavailable",
            &ptag(&o),
        );
    }
    // R17 — on-chain evaluator unavailable rejected.
    {
        let o = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain)
            .route_present_with(&OnChainDecisionSourceEvaluatorInterface);
        t.check(
            "R17.onchain-unavailable",
            "routed-fail-closed:reject:Evaluator:reject:OnChainDecisionSourceUnavailable",
            &ptag(&o),
        );
    }
    // R18 — MainNet evaluator unavailable / refused rejected.
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05)
            .route_present_with(&MainnetDecisionSourceEvaluatorInterface);
        t.check(
            "R18.mainnet-unavailable",
            "routed-fail-closed:reject:Evaluator:reject:MainnetDecisionSourceUnavailable",
            &ptag(&o),
        );
    }
    // R19 — validator-set rotation unsupported rejected.
    {
        t.assert_true(
            "R19.helper-unsupported",
            validator_set_rotation_remains_unsupported_under_peer_context(),
            "",
        );
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.request.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        fx.response.request_digest = fx.request.request_digest();
        t.assert_true("R19.validator-set-rotation", fx.route_present().is_fail_closed(), "");
    }
    // R20 — policy-change action unsupported rejected.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.request.governance_action = GovernanceAction::PolicyChangeRequest;
        fx.response.request_digest = fx.request.request_digest();
        t.assert_true("R20.policy-change", fx.route_present().is_fail_closed(), "");
    }
    // R21 — peer majority cannot satisfy evaluator policy.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain);
        fx.source_class = PeerEvaluatorSourceClass::PeerMajorityGossip;
        let o = fx.route_present();
        t.check("R21.peer-majority", "peer-majority-unsupported", &ptag(&o));
        t.assert_fail_closed("R21", &o);
    }
    // R22 — local operator cannot satisfy evaluator policy where the policy
    // requires evaluator authority (production-required + unavailable
    // production evaluator).
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
        let o = fx.route_present_with(&ProductionDecisionSourceEvaluatorInterface);
        t.assert_true("R22.local-operator-cannot-satisfy", o.is_fail_closed(), "");
        t.assert_fail_closed("R22", &o);
    }
    // R23 — live inbound 0x05 unsupported carrier rejected without
    // propagation/staging/apply.
    {
        let o = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::WireSchemaUnavailable,
        );
        t.check("R23.live-0x05-unsupported", "wire-schema-unavailable", &ptag(&o));
        t.assert_fail_closed("R23", &o);
    }
    // R24 — peer-driven drain unsupported carrier rejected without apply.
    {
        let o = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::UnsupportedSurface,
        );
        t.check("R24.peer-drain-unsupported", "unsupported-surface", &ptag(&o));
        t.assert_fail_closed("R24", &o);
    }
    // R25 — validation-only rejection (live inbound 0x05) authorizes no
    // mutation and is pure/repeatable.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        fx.ev_exp.expected_candidate_digest = "wrong".to_string();
        let first = fx.route_present();
        let second = fx.route_present();
        t.assert_true("R25.not-apply", !is_apply(&first), "");
        t.assert_true("R25.fail-closed", first.is_fail_closed(), "");
        t.assert_true("R25.pure-repeatable", ptag(&first) == ptag(&second), "");
    }
    // R26 — mutating-surface rejection (peer-driven drain) produces no apply
    // and is pure/repeatable.
    {
        let mut fx = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain);
        fx.ev_exp.expected_candidate_digest = "wrong".to_string();
        let first = fx.route_present();
        let second = fx.route_present();
        t.assert_true("R26.not-apply", !is_apply(&first), "");
        t.assert_true("R26.fail-closed", first.is_fail_closed(), "");
        t.assert_true("R26.pure-repeatable", ptag(&first) == ptag(&second), "");
    }
    // R27 — MainNet peer-driven apply remains refused even with fixture
    // approval.
    {
        t.assert_true(
            "R27.helper-refused",
            mainnet_peer_driven_apply_remains_refused_under_peer_context(),
            "",
        );
        let o = rotate_fixture(Env::Mainnet, PS::PeerDrivenDrain).route_present();
        t.check("R27.mainnet-peer-driven-refused", "mainnet-refused", &ptag(&o));
        t.assert_true("R27.not-apply", !is_apply(&o), "");
        // Even an explicit MainNetRefused carrier status routes to refusal.
        let explicit = rotate_fixture(Env::Mainnet, PS::PeerDrivenDrain).route_with_status(
            &FixtureGovernanceExecutionEvaluatorInterface,
            PeerEvaluatorCarrierStatus::MainNetRefused,
        );
        t.check("R27.explicit-mainnet-refused", "mainnet-refused", &ptag(&explicit));
    }
    t.finish(out)
}

// ===========================================================================
// Reachability / carrier-taxonomy table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use PeerEvaluatorContextSurface as PS;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // Surface -> runtime surface mapping is reachable and correct.
    t.check(
        "K.live-0x05-runtime-surface",
        "live-inbound-0x05",
        PS::LiveInbound0x05.runtime_surface().tag(),
    );
    t.check(
        "K.peer-drain-runtime-surface",
        "peer-driven-drain",
        PS::PeerDrivenDrain.runtime_surface().tag(),
    );
    t.assert_true(
        "K.peer-drain-is-preflight",
        PS::PeerDrivenDrain.is_peer_driven_apply_preflight(),
        "",
    );
    t.assert_true(
        "K.live-0x05-not-preflight",
        !PS::LiveInbound0x05.is_peer_driven_apply_preflight(),
        "",
    );

    // Carrier-status tags are reachable.
    for (status, tag) in [
        (PeerEvaluatorCarrierStatus::Absent, "absent"),
        (PeerEvaluatorCarrierStatus::Present, "present"),
        (PeerEvaluatorCarrierStatus::Malformed, "malformed"),
        (PeerEvaluatorCarrierStatus::UnsupportedSurface, "unsupported-surface"),
        (PeerEvaluatorCarrierStatus::WireSchemaUnavailable, "wire-schema-unavailable"),
        (PeerEvaluatorCarrierStatus::PeerMajorityUnsupported, "peer-majority-unsupported"),
        (PeerEvaluatorCarrierStatus::MainNetRefused, "mainnet-refused"),
    ] {
        t.check(&format!("K.carrier-{tag}"), tag, status.tag());
    }
    t.assert_true(
        "K.present-is-present",
        PeerEvaluatorCarrierStatus::Present.is_present(),
        "",
    );
    t.assert_true(
        "K.absent-not-present",
        !PeerEvaluatorCarrierStatus::Absent.is_present(),
        "",
    );

    // Source-class tags + peer-majority predicate reachable.
    for (class, tag) in [
        (PeerEvaluatorSourceClass::LiveInboundPeer, "live-inbound-peer"),
        (PeerEvaluatorSourceClass::DrainStagedPeer, "drain-staged-peer"),
        (PeerEvaluatorSourceClass::LocalSourceTest, "local-source-test"),
        (PeerEvaluatorSourceClass::PeerMajorityGossip, "peer-majority-gossip"),
    ] {
        t.check(&format!("K.source-{tag}"), tag, class.tag());
    }
    t.assert_true(
        "K.peer-majority-gossip-is-majority",
        PeerEvaluatorSourceClass::PeerMajorityGossip.is_peer_majority(),
        "",
    );

    // Load-status mirror reachable.
    for (ls, tag) in [
        (PeerEvaluatorLoadStatus::Absent, "absent"),
        (PeerEvaluatorLoadStatus::Available, "available"),
        (PeerEvaluatorLoadStatus::Malformed, "malformed"),
    ] {
        t.check(&format!("K.load-{tag}"), tag, ls.tag());
    }

    // Outcome predicate partitioning is reachable and correct.
    let mutate = rotate_fixture(Env::Devnet, PS::LiveInbound0x05).route_present();
    t.assert_true("O.mutate-apply", mutate.is_apply_authorized(), "");
    t.assert_true("O.mutate-not-fail-closed", !mutate.is_fail_closed(), "");
    let legacy = evaluate_peer_evaluator_context_wire_only(
        PS::LiveInbound0x05,
        Env::Devnet,
        CHAIN,
        GENESIS,
        EvaluatorPolicy::Disabled,
    );
    t.assert_true("O.legacy-is-legacy", legacy.is_legacy_validation_preserved(), "");
    t.assert_true("O.legacy-not-apply", !legacy.is_apply_authorized(), "");
    let refused = rotate_fixture(Env::Mainnet, PS::PeerDrivenDrain).route_present();
    t.assert_true("O.refused-mainnet", refused.is_mainnet_refused(), "");
    t.assert_true("O.refused-fail-closed", refused.is_fail_closed(), "");
    t.assert_true("O.refused-no-apply", refused.no_propagation_no_staging_no_apply(), "");

    // Surface mismatch between peer and integration is unsupported.
    {
        let fx = rotate_fixture(Env::Devnet, PS::PeerDrivenDrain);
        let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
        let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PS::PeerDrivenDrain,
            PeerEvaluatorSourceClass::DrainStagedPeer,
            "peer-0001",
            &ctx,
            None,
            None,
        );
        peer.surface = PS::LiveInbound0x05;
        let o = evaluate_peer_evaluator_context(&peer, &ctx);
        t.check("M.surface-mismatch-unsupported", "unsupported-surface", &ptag(&o));
    }

    // Inconsistent Present binding is malformed.
    {
        let fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
        let mut peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PS::LiveInbound0x05,
            PeerEvaluatorSourceClass::LiveInboundPeer,
            "peer-0001",
            &ctx,
            None,
            None,
        );
        peer.evaluator_request_digest = Some("tampered-request-digest".to_string());
        t.assert_true("M.inconsistent-binding", !peer.binds_consistently_with(&ctx), "");
        let o = evaluate_peer_evaluator_context(&peer, &ctx);
        t.check("M.inconsistent-malformed", "malformed-rejected", &ptag(&o));
    }

    // Deterministic context digest.
    {
        let fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
        let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
        let a = GovernanceEvaluatorPeerContext::present_from_integration(
            PS::LiveInbound0x05,
            PeerEvaluatorSourceClass::LiveInboundPeer,
            "peer-0001",
            &ctx,
            Some(TRUST_BUNDLE_DIGEST.to_string()),
            Some(MARKER_DIGEST.to_string()),
        );
        let b = a.clone();
        t.assert_true("D.digest-deterministic", a.context_digest() == b.context_digest(), "");
        let mut c = a.clone();
        c.peer_id = "different-peer".to_string();
        t.assert_true("D.digest-field-sensitive", a.context_digest() != c.context_digest(), "");
    }

    // Explicit fail-closed helper symbols reachable.
    t.assert_true(
        "H.validator-set-rotation-unsupported",
        validator_set_rotation_remains_unsupported_under_peer_context(),
        "",
    );
    t.assert_true(
        "H.mainnet-peer-driven-refused",
        mainnet_peer_driven_apply_remains_refused_under_peer_context(),
        "",
    );

    t.finish(out)
}

// ===========================================================================
// Fixture dump
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use PeerEvaluatorContextSurface as PS;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let fx = rotate_fixture(Env::Devnet, PS::LiveInbound0x05);
    let ctx = fx.integration_ctx(&FixtureGovernanceExecutionEvaluatorInterface);
    let peer = GovernanceEvaluatorPeerContext::present_from_integration(
        PS::LiveInbound0x05,
        PeerEvaluatorSourceClass::LiveInboundPeer,
        "peer-0001",
        &ctx,
        Some(TRUST_BUNDLE_DIGEST.to_string()),
        Some(MARKER_DIGEST.to_string()),
    );

    write_file(&dir.join("peer_context.txt"), &format!("{peer:#?}\n"));
    write_file(&dir.join("context_digest.txt"), &format!("{}\n", peer.context_digest()));
    write_file(
        &dir.join("source_identity_digest.txt"),
        &format!("{}\n", fx.identity.source_identity_digest()),
    );
    write_file(&dir.join("request_digest.txt"), &format!("{}\n", fx.request.request_digest()));
    write_file(&dir.join("response_digest.txt"), &format!("{}\n", fx.response.response_digest()));
    write_file(
        &dir.join("governance_execution_input_digest.txt"),
        &format!("{}\n", fx.request.governance_execution_input_digest),
    );

    // Routed mutate outcome.
    write_file(&dir.join("routed_mutate_outcome.txt"), &format!("{:#?}\n", fx.route_present()));

    // MainNet peer-driven refusal outcome.
    let mn = rotate_fixture(Env::Mainnet, PS::PeerDrivenDrain);
    write_file(&dir.join("mainnet_refused_outcome.txt"), &format!("{:#?}\n", mn.route_present()));

    // Carrier taxonomy outcome inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_peer_context\n");
    for entry in [
        "entry\tevaluate_peer_evaluator_context",
        "entry\tevaluate_peer_evaluator_context_wire_only",
        "type\tGovernanceEvaluatorPeerContext",
        "type\tPeerEvaluatorContextSurface",
        "type\tPeerEvaluatorCarrierStatus",
        "type\tPeerEvaluatorSourceClass",
        "type\tPeerEvaluatorLoadStatus",
        "type\tPeerEvaluatorContextOutcome",
        "carrier\tAbsent",
        "carrier\tPresent",
        "carrier\tMalformed",
        "carrier\tUnsupportedSurface",
        "carrier\tWireSchemaUnavailable",
        "carrier\tPeerMajorityUnsupported",
        "carrier\tMainNetRefused",
        "composed\tRun226:wire_governance_evaluator_runtime_callsite",
        "composed\tRun224:GovernanceEvaluatorRuntimeIntegrationContext",
        "composed\tRun222:ProductionGovernanceExecutionEvaluator",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_peer_context",
        "guard\tvalidator_set_rotation_remains_unsupported_under_peer_context",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("peer_context_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_229_peer_evaluator_context_representation_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from("run_229_peer_evaluator_context_representation_release_binary_helper\nscope: Run 228 governance evaluator peer evaluator-context representation boundary (pqc_governance_evaluator_peer_context: GovernanceEvaluatorPeerContext, evaluate_peer_evaluator_context, evaluate_peer_evaluator_context_wire_only, carrier taxonomy Absent/Present/Malformed/UnsupportedSurface/WireSchemaUnavailable/PeerMajorityUnsupported/MainNetRefused) exercised through release-built library symbols (release binary)\nnote: fixture-only; routes a representable Present context through the Run 226 call-site wiring into the Run 224 integration layer (composing Run 220 runtime consumption + Run 222 evaluator interface + Run 211 decision validation + Run 213 payload material); pure (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); default Disabled + absent legacy validation preserved; missing/unsupported/malformed carrier under explicit evaluator policy is typed fail-closed; WireSchemaUnavailable is fail-closed (NOT approval); invalid live inbound 0x05 not propagated/staged/applied; invalid peer-driven drain not applied; production/on-chain/MainNet evaluators unavailable/fail-closed; MainNet peer-driven apply remains refused; validator-set rotation unsupported\n\n");
    for (name, f) in tables {
        let (p, fcnt) = f(&out_dir);
        total_pass += p;
        total_fail += fcnt;
        summary.push_str(&format!("table {name}: pass={p} fail={fcnt}\n"));
    }
    run_fixture_dump(&out_dir);
    summary.push_str(&format!(
        "\ntotal_pass: {total_pass}\ntotal_fail: {total_fail}\nverdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}