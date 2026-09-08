//! Run 227 — release-built helper for the Run 226 governance evaluator
//! runtime **call-site wiring**
//! (`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`).
//!
//! Where Run 224 landed the pure integration layer and Run 225 proved it in
//! release mode, Run 226 added the call-site wiring entry points
//! ([`wire_governance_evaluator_runtime_callsite`] and
//! [`wire_governance_evaluator_runtime_callsite_without_evaluator_context`])
//! and routed the representable Run 220 runtime call sites
//! (`consume_run_220_governance_execution_runtime_outcome` in `main.rs` and
//! `consume_run_220_sighup_governance_execution_marker_decision` in
//! `pqc_live_trust_reload.rs`) through the integration layer. Run 226 captured
//! no release-binary evidence; Run 227 is that release-binary evidence.
//!
//! This helper drives the A1–A23 / R1–R31 matrix from `task/RUN_227_TASK.txt`
//! through the **release-built** Run 226 call-site wiring symbols, proving that:
//!
//! * representable runtime call sites consume a
//!   [`GovernanceEvaluatorRuntimeIntegrationOutcome`] through the wiring (the
//!   outcome is never discarded — the `Ok`/`Err` discipline of the wiring is
//!   asserted against the underlying integration outcome);
//! * the default Disabled + absent-carrier legacy bypass is preserved
//!   (`Ok(ProceedLegacyBypass)`) at every binary call-site surface via
//!   [`wire_governance_evaluator_runtime_callsite_without_evaluator_context`];
//! * a present governance-execution carrier without an evaluator context fails
//!   closed before mutation (`Err`, never `Ok(ProceedMutate)`);
//! * `ProceedMutate` is the only mutation-authorizing outcome and is produced
//!   only when both the Run 220 runtime-consumption stage and the Run 222
//!   evaluator stage agree;
//! * the production / on-chain / MainNet evaluator paths are reached from the
//!   call-site wiring and fail closed as unavailable;
//! * MainNet peer-driven apply remains refused
//!   (`Err(.. MainNetPeerDrivenApplyRefused)`);
//! * the live inbound `0x05` and peer-driven drain limitations are evidenced
//!   honestly (only the Disabled + absent-carrier legacy bypass is `Ok` at
//!   those binary call sites; a present carrier always fails closed).
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, on-chain proof verifier, KMS/HSM, or RemoteSigner
//! backend. The wiring is pure (no marker write, no sequence write, no live
//! trust swap, no session eviction, no Run 070 call). MainNet peer-driven
//! apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
// Shared constants (mirror the Run 220 / Run 222 / Run 224 / Run 226 corpora
// so the runtime-consumption material and the evaluator material bind to the
// same trust domain, proposal/decision identity, candidate digest, replay
// nonce).
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
// Owned-material fixture bundle (mirrors the Run 226 test fixture)
// ===========================================================================

type CallsiteResult =
    Result<GovernanceEvaluatorRuntimeIntegrationOutcome, GovernanceEvaluatorRuntimeCallsiteFailClosed>;

/// Owns every layer's material for one call-site round-trip so a scenario can
/// mutate any field and then borrow it into the integration context routed
/// through the Run 226 call-site wiring.
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
    fn context<'a, E: ProductionGovernanceExecutionEvaluator>(
        &'a self,
        evaluator: &'a E,
    ) -> GovernanceEvaluatorRuntimeIntegrationContext<'a, E> {
        GovernanceEvaluatorRuntimeIntegrationContext {
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
        }
    }

    /// Route this fixture through the Run 226 call-site wiring entry point
    /// (`wire_governance_evaluator_runtime_callsite`) with the supplied
    /// evaluator. The result is consumed, never discarded.
    fn callsite_with<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
    ) -> CallsiteResult {
        wire_governance_evaluator_runtime_callsite(&self.context(evaluator))
    }

    fn callsite(&self) -> CallsiteResult {
        self.callsite_with(&FixtureGovernanceExecutionEvaluatorInterface)
    }

    /// Drive the same fixture through the raw Run 224 integration entry point
    /// (used only to prove the call-site wiring agrees with the integration
    /// outcome — Run 225 release-behavior compatibility).
    fn integrate_with<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
    ) -> GovernanceEvaluatorRuntimeIntegrationOutcome {
        integrate_governance_evaluator_runtime_consumption(&self.context(evaluator))
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

/// Stable tag for the integration outcome.
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

/// Borrow the underlying integration outcome from a call-site wiring result,
/// regardless of `Ok`/`Err` (the wiring consumes — never discards — it).
fn result_outcome(r: &CallsiteResult) -> &GovernanceEvaluatorRuntimeIntegrationOutcome {
    match r {
        Ok(o) => o,
        Err(fc) => &fc.outcome,
    }
}

/// Stable tag for a call-site wiring result. The `Ok`/`Err` discipline is
/// verified separately by [`assert_result_discipline`].
fn rtag(r: &CallsiteResult) -> String {
    itag(result_outcome(r))
}

fn is_mutate(r: &CallsiteResult) -> bool {
    result_outcome(r).is_mutate_authorized()
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
    /// Assert the call-site wiring `Ok`/`Err` discipline: a proceed outcome is
    /// `Ok`, every fail-closed outcome is `Err` and carries the originating
    /// surface plus a non-empty operator reason and never authorizes mutation.
    fn assert_result_discipline(&mut self, id: &str, r: &CallsiteResult) {
        let outcome = result_outcome(r);
        let proceed = outcome.is_proceed();
        self.check(
            &format!("{id}.discipline-ok-iff-proceed"),
            &proceed.to_string(),
            &r.is_ok().to_string(),
        );
        if let Err(fc) = r {
            self.assert_true(
                &format!("{id}.err-not-mutate"),
                !fc.outcome.is_mutate_authorized(),
                "",
            );
            self.assert_true(&format!("{id}.err-reason-nonempty"), !fc.reason.is_empty(), "");
        }
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
// A — accepted / compatible scenarios (A1–A23) routed through the call-site
// wiring (`wire_governance_evaluator_runtime_callsite` and
// `wire_governance_evaluator_runtime_callsite_without_evaluator_context`).
// ===========================================================================

/// Drive the binary call-site entry (`..._without_evaluator_context`) on a
/// surface under the given arming/load, returning the wiring result.
fn callsite_no_ctx(
    arming: &GovernanceExecutionRuntimeArmingConfig,
    surface: GovernanceExecutionRuntimeSurface,
    td: &AuthorityTrustDomain,
    gov_exp: &GovernanceExecutionExpectations,
    load: &GovernanceExecutionLoadStatus,
    peer_driven: bool,
) -> CallsiteResult {
    wire_governance_evaluator_runtime_callsite_without_evaluator_context(
        arming, surface, td, gov_exp, load, peer_driven,
    )
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");
    let disabled = GovernanceExecutionRuntimeArmingConfig::disabled();

    // A1–A5 — default Disabled + absent carrier produces ProceedLegacyBypass at
    // each binary call-site surface, via the binary call-site wiring entry
    // (`..._without_evaluator_context`).
    let bypass_surfaces = [
        ("A1.reload-check", S::ReloadCheck),
        ("A2.reload-apply", S::ReloadApply),
        ("A3.startup-p2p-trust-bundle", S::StartupP2pTrustBundle),
        ("A4.sighup", S::Sighup),
        ("A5.local-peer-candidate-check", S::LocalPeerCandidateCheck),
    ];
    for (id, surface) in bypass_surfaces {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let gov_exp = rotate_gov_expectations(env);
        let r = callsite_no_ctx(
            &disabled,
            surface,
            &td,
            &gov_exp,
            &GovernanceExecutionLoadStatus::Absent,
            false,
        );
        t.check(id, "proceed:LegacyBypass", &rtag(&r));
        t.assert_result_discipline(id, &r);
    }

    // A6 — reload-check with DevNet fixture policy + valid sidecar routes
    // through integration and accepts only when both stages agree.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.surface = S::ReloadCheck;
        let r = fx.callsite();
        t.check("A6.reload-check-accept", "proceed:Mutate", &rtag(&r));
        t.assert_result_discipline("A6", &r);
    }
    // A7 — reload-apply with DevNet fixture policy + valid sidecar.
    {
        let fx = rotate_fixture(Env::Devnet); // ReloadApply by default
        let r = fx.callsite();
        t.check("A7.reload-apply-accept", "proceed:Mutate", &rtag(&r));
        t.assert_result_discipline("A7", &r);
        // accepts only when both agree: flip evaluator stage -> not mutate.
        let mut ev_only = rotate_fixture(Env::Devnet);
        ev_only.response.approved = false;
        t.assert_true("A7.evaluator-flip-not-mutate", !is_mutate(&ev_only.callsite()), "");
    }
    // A8 — SIGHUP with DevNet fixture policy + valid sidecar routes through
    // integration where representable (full evaluator context).
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.surface = S::Sighup;
        let r = fx.callsite();
        t.check("A8.sighup-accept", "proceed:Mutate", &rtag(&r));
        t.assert_result_discipline("A8", &r);
    }
    // A9 — local peer-candidate-check with TestNet fixture policy + valid
    // sidecar routes through integration where representable.
    {
        let mut fx = rotate_fixture(Env::Testnet);
        fx.surface = S::LocalPeerCandidateCheck;
        let r = fx.callsite();
        t.check("A9.local-peer-candidate-accept", "proceed:Mutate", &rtag(&r));
        t.assert_result_discipline("A9", &r);
    }
    // A9b — revoke round-trip also reaches ProceedMutate through the wiring
    // (Run 220/222/211 revoke material binds the same trust domain/sequence).
    {
        let r = revoke_fixture(Env::Devnet).callsite();
        t.check("A9b.revoke-accept", "proceed:Mutate", &rtag(&r));
        t.assert_result_discipline("A9b", &r);
        let mut bad_seq = revoke_fixture(Env::Devnet);
        bad_seq.response.authorized_authority_domain_sequence = 9;
        t.assert_true("A9b.wrong-sequence-not-mutate", !is_mutate(&bad_seq.callsite()), "");
    }
    // A10 — explicit emergency fixture accepts only an explicit emergency
    // action.
    {
        let env = Env::Devnet;
        let r = emergency_fixture(env)
            .callsite_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
        t.check("A10.emergency-accept", "proceed:Mutate", &rtag(&r));
        t.assert_result_discipline("A10", &r);
        let mut non_emergency = emergency_fixture(env);
        non_emergency.request.emergency_flag = false;
        non_emergency.response.emergency_flag = false;
        non_emergency.response.request_digest = non_emergency.request.request_digest();
        let rej = non_emergency
            .callsite_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
        t.assert_true("A10.non-emergency-refused", !is_mutate(&rej), "");
    }
    // A11 — production evaluator path reached from call-site integration and
    // fails closed as unavailable.
    {
        let r = rotate_fixture(Env::Devnet).callsite_with(&ProductionDecisionSourceEvaluatorInterface);
        t.check(
            "A11.production-unavailable",
            "reject:Evaluator:reject:ProductionDecisionSourceUnavailable",
            &rtag(&r),
        );
        t.assert_result_discipline("A11", &r);
    }
    // A12 — on-chain evaluator path reached and fails closed as unavailable.
    {
        let r = rotate_fixture(Env::Devnet).callsite_with(&OnChainDecisionSourceEvaluatorInterface);
        t.check(
            "A12.onchain-unavailable",
            "reject:Evaluator:reject:OnChainDecisionSourceUnavailable",
            &rtag(&r),
        );
        t.assert_result_discipline("A12", &r);
    }
    // A13 — MainNet evaluator path reached and fails closed/refused (DevNet
    // domain so runtime consumption accepts and the wiring reaches the
    // evaluator).
    {
        let r = rotate_fixture(Env::Devnet).callsite_with(&MainnetDecisionSourceEvaluatorInterface);
        t.check(
            "A13.mainnet-unavailable",
            "reject:Evaluator:reject:MainnetDecisionSourceUnavailable",
            &rtag(&r),
        );
        t.assert_result_discipline("A13", &r);
    }
    // A14 — CLI-over-env precedence is preserved through call-site integration.
    {
        // env says disabled; CLI says fixture-governance-allowed -> CLI wins.
        env::set_var(
            QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
            GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
        );
        let cli = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .expect("valid CLI selector resolves");
        t.check(
            "A14.cli-wins-over-env",
            "FixtureGovernanceAllowed",
            &format!("{:?}", cli.governance_execution_policy()),
        );
        // env consulted when CLI absent.
        let env_only = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None)
            .expect("env selector resolves");
        t.check(
            "A14.env-when-cli-absent",
            "Disabled",
            &format!("{:?}", env_only.governance_execution_policy()),
        );
        env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV);
        // Drive the CLI-resolved policy through the call-site wiring.
        let env2 = Env::Devnet;
        let mut fx = rotate_fixture(env2);
        fx.arming = cli;
        t.assert_true("A14.cli-resolved-reaches-mutate", is_mutate(&fx.callsite()), "");
    }
    // A15 — invalid selector fails closed before mutation.
    {
        let bad = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("bogus-policy"));
        t.assert_true("A15.invalid-selector-err", bad.is_err(), "");
    }
    // A16 — live inbound 0x05 limitation evidenced honestly: only the Disabled
    // + absent legacy bypass is Ok at the binary call site; a present carrier
    // (invalid or not yet bindable) fails closed and is never staged/applied.
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let gov_exp = rotate_gov_expectations(env);
        let bypass = callsite_no_ctx(
            &disabled,
            S::LiveInbound0x05,
            &td,
            &gov_exp,
            &GovernanceExecutionLoadStatus::Absent,
            false,
        );
        t.check("A16.live-0x05-bypass", "proceed:LegacyBypass", &rtag(&bypass));
        let armed = GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let present = callsite_no_ctx(
            &armed,
            S::LiveInbound0x05,
            &td,
            &gov_exp,
            &available_from(&rotate_input(env), &rotate_decision()),
            false,
        );
        t.assert_true("A16.live-0x05-present-fail-closed", present.is_err(), "");
        t.assert_true("A16.live-0x05-present-not-mutate", !is_mutate(&present), "");
    }
    // A17 — peer-driven drain limitation evidenced honestly; MainNet
    // peer-driven apply remains refused.
    {
        // DevNet peer-driven drain bypass under Disabled + absent.
        let env = Env::Devnet;
        let td = trust_domain(env);
        let gov_exp = rotate_gov_expectations(env);
        let bypass = callsite_no_ctx(
            &disabled,
            S::PeerDrivenDrain,
            &td,
            &gov_exp,
            &GovernanceExecutionLoadStatus::Absent,
            false,
        );
        t.check("A17.peer-drain-bypass", "proceed:LegacyBypass", &rtag(&bypass));
        // MainNet peer-driven apply preflight refused.
        let mn_env = Env::Mainnet;
        let mn_td = trust_domain(mn_env);
        let mn_exp = rotate_gov_expectations(mn_env);
        let refused = callsite_no_ctx(
            &disabled,
            S::PeerDrivenDrain,
            &mn_td,
            &mn_exp,
            &GovernanceExecutionLoadStatus::Absent,
            true,
        );
        t.check(
            "A17.mainnet-peer-driven-refused",
            "reject:MainNetPeerDrivenApplyRefused",
            &rtag(&refused),
        );
        match &refused {
            Err(fc) => t.assert_true("A17.refused-typed", fc.is_mainnet_peer_driven_apply_refused(), ""),
            Ok(_) => t.assert_true("A17.refused-typed", false, "expected Err"),
        }
    }
    // A18 — GovernanceEvaluatorRuntimeIntegrationOutcome is consumed, not
    // discarded: a ProceedMutate carries the composed runtime-consumption and
    // evaluator outcomes through the wiring.
    {
        match rotate_fixture(Env::Devnet).callsite() {
            Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate {
                runtime_consumption,
                evaluator,
                lifecycle_action,
                candidate_digest,
                authority_domain_sequence,
            }) => {
                t.assert_true(
                    "A18.runtime-fixture-accepted",
                    matches!(
                        runtime_consumption,
                        GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. }
                    ),
                    "",
                );
                t.assert_true(
                    "A18.evaluator-authorized",
                    matches!(evaluator, EvaluatorOutcome::EvaluatorResponseAuthorized { .. }),
                    "",
                );
                t.check("A18.lifecycle", "Rotate", &format!("{lifecycle_action:?}"));
                t.check("A18.candidate", CAND_DIGEST, &candidate_digest);
                t.check("A18.sequence", "7", &authority_domain_sequence.to_string());
            }
            other => t.assert_true("A18.proceed-mutate-shape", false, &format!("{other:?}")),
        }
    }
    // A19 — ProceedMutate is the only mutation-authorizing integration outcome.
    {
        use GovernanceEvaluatorRuntimeIntegrationOutcome as O;
        t.assert_true("A19.mutate-authorizes", rotate_fixture(Env::Devnet).callsite().map_or(false, |o| o.is_mutate_authorized()), "");
        t.assert_true("A19.bypass-not-mutate", !O::ProceedLegacyBypass.is_mutate_authorized(), "");
        t.assert_true("A19.refused-not-mutate", !O::MainNetPeerDrivenApplyRefused.is_mutate_authorized(), "");
        t.assert_true(
            "A19.evaluator-rejected-not-mutate",
            !O::EvaluatorRejected(EvaluatorOutcome::ProductionDecisionSourceUnavailable)
                .is_mutate_authorized(),
            "",
        );
    }
    // A20 — RuntimeConsumptionFailClosed, EvaluatorRejected, and
    // MainNetPeerDrivenApplyRefused all surface as Err (fail closed before
    // mutation) from the call-site wiring.
    {
        let mut rc = rotate_fixture(Env::Devnet);
        rc.load = GovernanceExecutionLoadStatus::Absent;
        t.assert_true("A20.runtime-consumption-err", rc.callsite().is_err(), "");
        let ev = rotate_fixture(Env::Devnet);
        t.assert_true(
            "A20.evaluator-rejected-err",
            ev.callsite_with(&ProductionDecisionSourceEvaluatorInterface).is_err(),
            "",
        );
        let mut mn = rotate_fixture(Env::Mainnet);
        mn.surface = S::PeerDrivenDrain;
        mn.peer_driven = true;
        t.assert_true("A20.mainnet-refused-err", mn.callsite().is_err(), "");
    }
    // A21 — Run 221 runtime-consumption compatibility: every representable
    // surface reaches ProceedMutate through the wiring under a valid fixture
    // round-trip (the MainNet peer-driven drain is exercised in A17).
    {
        let env = Env::Devnet;
        for surface in GovernanceExecutionRuntimeSurface::ALL {
            let mut fx = rotate_fixture(env);
            fx.surface = surface;
            t.assert_true(
                &format!("A21.surface-{surface:?}-mutate"),
                is_mutate(&fx.callsite()),
                "",
            );
        }
    }
    // A22 — Run 223 evaluator-interface compatibility: a Disabled evaluator
    // policy fails closed for a present fixture carrier; production / on-chain /
    // MainNet evaluators are callable but fail closed as unavailable.
    {
        let env = Env::Devnet;
        let mut disabled_ev = rotate_fixture(env);
        disabled_ev.ev_policy = EvaluatorPolicy::Disabled;
        t.check(
            "A22.disabled-evaluator",
            "reject:Evaluator:reject:EvaluatorDisabled",
            &rtag(&disabled_ev.callsite()),
        );
        t.assert_true(
            "A22.production-unavailable",
            matches!(
                result_outcome(&rotate_fixture(env).callsite_with(&ProductionDecisionSourceEvaluatorInterface)),
                GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
                    EvaluatorOutcome::ProductionDecisionSourceUnavailable
                )
            ),
            "",
        );
    }
    // A23 — Run 225 integration-layer compatibility: the call-site wiring
    // outcome equals the raw integration outcome for representative cases
    // (proceed-mutate, legacy-bypass, evaluator-rejected, mainnet-refused).
    {
        let env = Env::Devnet;
        // ProceedMutate.
        let fx = rotate_fixture(env);
        t.assert_true(
            "A23.mutate-matches-integration",
            result_outcome(&fx.callsite()) == &fx.integrate_with(&FixtureGovernanceExecutionEvaluatorInterface),
            "",
        );
        // EvaluatorRejected.
        let fx = rotate_fixture(env);
        t.assert_true(
            "A23.evaluator-matches-integration",
            result_outcome(&fx.callsite_with(&ProductionDecisionSourceEvaluatorInterface))
                == &fx.integrate_with(&ProductionDecisionSourceEvaluatorInterface),
            "",
        );
        // MainNetPeerDrivenApplyRefused.
        let mut mn = rotate_fixture(Env::Mainnet);
        mn.surface = S::PeerDrivenDrain;
        mn.peer_driven = true;
        t.assert_true(
            "A23.mainnet-matches-integration",
            result_outcome(&mn.callsite()) == &mn.integrate_with(&FixtureGovernanceExecutionEvaluatorInterface),
            "",
        );
    }
    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R31); all non-mutating, all surfacing as Err
// from the call-site wiring (except where they are the legacy bypass).
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;

    // R1 — missing material rejected when evaluator policy requires it.
    {
        let mut fx = rotate_fixture(env);
        fx.load = GovernanceExecutionLoadStatus::Absent;
        let r = fx.callsite();
        t.check(
            "R1.required-absent",
            "reject:RuntimeConsumptionFailClosed:GovernanceExecutionRequiredButAbsent",
            &rtag(&r),
        );
        t.assert_result_discipline("R1", &r);
    }
    // R2 — malformed material rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.load = GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
            error: "broken".to_string(),
        });
        let r = fx.callsite();
        t.check(
            "R2.malformed",
            "reject:RuntimeConsumptionFailClosed:MalformedGovernanceExecutionPayload",
            &rtag(&r),
        );
        t.assert_result_discipline("R2", &r);
    }
    // R3 — wrong evaluator source rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.source_kind = EvaluatorSourceKind::EmergencyCouncilFixtureSource;
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R3.wrong-source", "reject:Evaluator:reject:SourceKindPolicyMismatch", &rtag(&fx.callsite()));
    }
    // R4 — wrong environment rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_environment = Env::Testnet;
        fx.identity.environment = Env::Testnet;
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R4.wrong-environment", "reject:Evaluator:reject:WrongEnvironment", &rtag(&fx.callsite()));
    }
    // R5 — wrong chain rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.chain_id = "other-chain".to_string();
        fx.ev_exp.expected_chain_id = "other-chain".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R5.wrong-chain", "reject:Evaluator:reject:WrongChain", &rtag(&fx.callsite()));
    }
    // R6 — wrong genesis rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.genesis_hash = "other-genesis".to_string();
        fx.ev_exp.expected_genesis_hash = "other-genesis".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R6.wrong-genesis", "reject:Evaluator:reject:WrongGenesis", &rtag(&fx.callsite()));
    }
    // R7 — wrong authority root rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.authority_root_fingerprint = "other-root".to_string();
        fx.ev_exp.expected_authority_root_fingerprint = "other-root".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R7.wrong-authority-root", "reject:Evaluator:reject:WrongAuthorityRoot", &rtag(&fx.callsite()));
    }
    // R8 — wrong governance proof digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.governance_proof_digest = "other-gov-proof".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R8.wrong-gov-proof", "reject:Evaluator:reject:WrongGovernanceProofDigest", &rtag(&fx.callsite()));
    }
    // R9 — wrong on-chain proof digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
        t.check("R9.wrong-onchain-proof", "reject:Evaluator:reject:WrongOnChainProofDigest", &rtag(&fx.callsite()));
    }
    // R10 — wrong custody attestation digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
        t.check("R10.wrong-custody", "reject:Evaluator:reject:WrongCustodyAttestationDigest", &rtag(&fx.callsite()));
    }
    // R11 — wrong proposal id rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_proposal_id = "other-proposal".to_string();
        t.check("R11.wrong-proposal", "reject:Evaluator:reject:WrongProposalId", &rtag(&fx.callsite()));
    }
    // R12 — wrong decision id rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_decision_id = "other-decision".to_string();
        t.check("R12.wrong-decision", "reject:Evaluator:reject:WrongDecisionId", &rtag(&fx.callsite()));
    }
    // R13 — wrong lifecycle action rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
        t.check("R13.wrong-lifecycle", "reject:Evaluator:reject:WrongLifecycleAction", &rtag(&fx.callsite()));
    }
    // R14 — wrong candidate digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_candidate_digest = "other-candidate".to_string();
        t.check("R14.wrong-candidate", "reject:Evaluator:reject:WrongCandidateDigest", &rtag(&fx.callsite()));
    }
    // R15 — wrong authority-domain sequence rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_authority_domain_sequence = 8;
        t.check("R15.wrong-sequence", "reject:Evaluator:reject:WrongAuthorityDomainSequence", &rtag(&fx.callsite()));
    }
    // R16 — expired evaluator request rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.now_epoch = 250;
        t.check("R16.expired", "reject:Evaluator:reject:ExpiredDecision", &rtag(&fx.callsite()));
    }
    // R17 — stale/replayed evaluator request rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_replay_nonce = "fresh-nonce".to_string();
        t.check("R17.stale-replayed", "reject:Evaluator:reject:StaleOrReplayedDecision", &rtag(&fx.callsite()));
    }
    // R18 — quorum/threshold insufficient rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
        fx.response.request_digest = fx.request.request_digest();
        t.check("R18.quorum-insufficient", "reject:Evaluator:reject:QuorumThresholdInsufficient", &rtag(&fx.callsite()));
    }
    // R19 — emergency action not authorized rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.emergency_flag = true;
        fx.response.request_digest = fx.request.request_digest();
        fx.response.emergency_flag = true;
        t.check("R19.emergency-not-authorized", "reject:Evaluator:reject:EmergencyActionNotAuthorized", &rtag(&fx.callsite()));
    }
    // R20 — validator-set rotation unsupported rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        fx.response.request_digest = fx.request.request_digest();
        t.check("R20.validator-set-rotation", "reject:Evaluator:reject:ValidatorSetRotationUnsupported", &rtag(&fx.callsite()));
        t.assert_true("R20.helper-unsupported", validator_set_rotation_remains_unsupported_under_evaluator(), "");
    }
    // R21 — policy-change action unsupported rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.governance_action = GovernanceAction::PolicyChangeRequest;
        fx.response.request_digest = fx.request.request_digest();
        t.check("R21.policy-change", "reject:Evaluator:reject:PolicyChangeActionUnsupported", &rtag(&fx.callsite()));
    }
    // R22 — production evaluator unavailable rejected.
    {
        let r = rotate_fixture(env).callsite_with(&ProductionDecisionSourceEvaluatorInterface);
        t.check("R22.production-unavailable", "reject:Evaluator:reject:ProductionDecisionSourceUnavailable", &rtag(&r));
    }
    // R23 — on-chain evaluator unavailable rejected.
    {
        let r = rotate_fixture(env).callsite_with(&OnChainDecisionSourceEvaluatorInterface);
        t.check("R23.onchain-unavailable", "reject:Evaluator:reject:OnChainDecisionSourceUnavailable", &rtag(&r));
    }
    // R24 — MainNet evaluator unavailable/refused rejected.
    {
        let r = rotate_fixture(env).callsite_with(&MainnetDecisionSourceEvaluatorInterface);
        t.check("R24.mainnet-unavailable", "reject:Evaluator:reject:MainnetDecisionSourceUnavailable", &rtag(&r));
    }
    // R25 — local operator cannot satisfy evaluator policy.
    {
        t.assert_true("R25.local-operator-cannot-satisfy", local_operator_cannot_satisfy_evaluator_policy(), "");
        let mut fx = rotate_fixture(env);
        fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
        t.assert_true("R25.production-required-not-mutate", !is_mutate(&fx.callsite()), "");
    }
    // R26 — peer majority cannot satisfy evaluator policy.
    {
        t.assert_true("R26.peer-majority-cannot-satisfy", peer_majority_cannot_satisfy_evaluator_policy(), "");
        let mut fx = rotate_fixture(env);
        fx.ev_policy = EvaluatorPolicy::MainnetDecisionSourceRequired;
        t.assert_true("R26.mainnet-required-not-mutate", !is_mutate(&fx.callsite()), "");
    }
    // R27 — evaluator valid but governance execution decision invalid rejected.
    {
        let mut fx = rotate_fixture(env);
        let mut decision = rotate_decision();
        decision.authorized_sequence = 999; // mismatched -> Run 211 rejects
        fx.load = available_from(&rotate_input(env), &decision);
        t.check("R27.governance-decision-invalid", "reject:Evaluator:reject:GovernanceExecutionDecisionInvalid", &rtag(&fx.callsite()));
    }
    // R28 — governance execution decision valid but evaluator response invalid.
    {
        let mut fx = rotate_fixture(env);
        fx.response.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
        t.check("R28.response-invalid", "reject:Evaluator:reject:InvalidResponseCommitment", &rtag(&fx.callsite()));
    }
    // R29 — validation-only rejection writes no marker and no sequence
    // (pure/repeatable through the call-site wiring).
    {
        let mut fx = rotate_fixture(env);
        fx.surface = S::ReloadCheck; // validation-only
        fx.ev_exp.expected_candidate_digest = "other".to_string(); // force reject
        let first = fx.callsite();
        let second = fx.callsite();
        t.assert_true("R29.not-mutate", !is_mutate(&first), "");
        t.assert_true("R29.is-err", first.is_err(), "");
        t.assert_true("R29.pure-repeatable", result_outcome(&first) == result_outcome(&second), "");
    }
    // R30 — mutating rejection produces no mutation (pure/repeatable through
    // the call-site wiring).
    {
        let mut fx = rotate_fixture(env);
        fx.surface = S::ReloadApply; // mutating surface
        fx.response.approved = false; // force evaluator response reject
        let first = fx.callsite();
        let second = fx.callsite();
        t.assert_true("R30.not-mutate", !is_mutate(&first), "");
        t.assert_true("R30.fail-closed", first.is_err(), "");
        t.assert_true("R30.pure-repeatable", result_outcome(&first) == result_outcome(&second), "");
    }
    // R31 — MainNet peer-driven apply remains refused even with fixture
    // evaluator approval.
    {
        let mut fx = rotate_fixture(Env::Mainnet);
        fx.surface = S::PeerDrivenDrain;
        fx.peer_driven = true;
        let r = fx.callsite();
        t.check("R31.mainnet-peer-driven-refused", "reject:MainNetPeerDrivenApplyRefused", &rtag(&r));
        t.assert_true("R31.is-err", r.is_err(), "");
        t.assert_true("R31.not-mutate", !is_mutate(&r), "");
    }
    t.finish(out)
}

// ===========================================================================
// Reachability table — the Run 226 call-site wiring symbols and the binary
// call-site entry without an evaluator context.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");
    let env = Env::Devnet;

    // The full-context call-site wiring entry reaches ProceedMutate.
    let explicit = rotate_fixture(env).callsite();
    t.check("K.full-ctx-wiring-mutate", "proceed:Mutate", &rtag(&explicit));
    t.assert_true("K.full-ctx-wiring-ok", explicit.is_ok(), "");

    // The binary call-site entry (`..._without_evaluator_context`) reaches the
    // integration layer on every representable surface: Disabled + absent ->
    // legacy bypass.
    {
        let td = trust_domain(env);
        let gov_exp = rotate_gov_expectations(env);
        let disabled = GovernanceExecutionRuntimeArmingConfig::disabled();
        for surface in GovernanceExecutionRuntimeSurface::ALL {
            let r = callsite_no_ctx(
                &disabled,
                surface,
                &td,
                &gov_exp,
                &GovernanceExecutionLoadStatus::Absent,
                matches!(surface, S::PeerDrivenDrain),
            );
            // The MainNet path is not driven here (DevNet domain), so every
            // surface bypasses under Disabled + absent.
            t.check(
                &format!("K.no-ctx-{surface:?}-bypass"),
                "proceed:LegacyBypass",
                &rtag(&r),
            );
        }
        // A present carrier at the binary call site fails closed (the entry
        // cannot bind a real evaluator context).
        let present = callsite_no_ctx(
            &GovernanceExecutionRuntimeArmingConfig::with_policy(
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            ),
            S::ReloadApply,
            &td,
            &gov_exp,
            &available_from(&rotate_input(env), &rotate_decision()),
            false,
        );
        t.assert_true("K.no-ctx-present-fail-closed", present.is_err(), "");
        t.assert_true("K.no-ctx-present-not-mutate", !is_mutate(&present), "");
    }

    // Outcome predicate partitioning is reachable and correct.
    let bypass = GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass;
    t.assert_true("O.bypass-is-proceed", bypass.is_proceed(), "");
    t.assert_true("O.bypass-is-legacy", bypass.is_legacy_bypass(), "");
    t.assert_true("O.bypass-not-mutate", !bypass.is_mutate_authorized(), "");
    t.assert_true("O.bypass-not-fail-closed", !bypass.is_fail_closed(), "");
    let refused = GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused;
    t.assert_true("O.refused-fail-closed", refused.is_fail_closed(), "");
    t.assert_true("O.refused-is-refused", refused.is_mainnet_peer_driven_apply_refused(), "");
    t.assert_true("O.refused-not-mutate", !refused.is_mutate_authorized(), "");

    // The typed call-site fail-closed carries surface + reason and refuses
    // MainNet peer-driven apply.
    {
        let mut mn = rotate_fixture(Env::Mainnet);
        mn.surface = S::PeerDrivenDrain;
        mn.peer_driven = true;
        match mn.callsite() {
            Err(fc) => {
                t.check("F.fail-closed-surface", "peer-driven-drain", fc.surface.tag());
                t.assert_true("F.fail-closed-reason-nonempty", !fc.reason.is_empty(), "");
                t.assert_true("F.fail-closed-mainnet-refused", fc.is_mainnet_peer_driven_apply_refused(), "");
            }
            Ok(o) => t.assert_true("F.fail-closed-shape", false, &format!("{o:?}")),
        }
    }

    // Explicit fail-closed helper symbols reachable.
    t.assert_true("H.validator-set-rotation-unsupported", validator_set_rotation_remains_unsupported_under_evaluator(), "");
    t.assert_true("H.mainnet-refused-helper", mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Mainnet), "");
    t.assert_true("H.mainnet-refused-devnet-false", !mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Devnet), "");
    t.assert_true("H.local-operator-cannot-satisfy", local_operator_cannot_satisfy_evaluator_policy(), "");
    t.assert_true("H.peer-majority-cannot-satisfy", peer_majority_cannot_satisfy_evaluator_policy(), "");

    // MainNet fixture runtime consumption is refused off the peer-driven path
    // through the wiring as well.
    t.assert_true("M.mainnet-fixture-not-mutate", !is_mutate(&rotate_fixture(Env::Mainnet).callsite()), "");

    t.finish(out)
}

// ===========================================================================
// Fixture dump
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let env = TrustBundleEnvironment::Devnet;
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
    write_file(&dir.join("governance_execution_input.txt"), &format!("{input:#?}\n"));
    write_file(&dir.join("governance_execution_decision.txt"), &format!("{decision:#?}\n"));
    write_file(&dir.join("decision_source_identity.txt"), &format!("{identity:#?}\n"));
    write_file(&dir.join("evaluator_request.txt"), &format!("{request:#?}\n"));
    write_file(&dir.join("evaluator_response.txt"), &format!("{response:#?}\n"));
    write_file(&dir.join("governance_execution_input_digest.txt"), &format!("{input_digest}\n"));
    write_file(&dir.join("source_identity_digest.txt"), &format!("{}\n", identity.source_identity_digest()));
    write_file(&dir.join("request_digest.txt"), &format!("{}\n", request.request_digest()));
    write_file(&dir.join("response_digest.txt"), &format!("{}\n", response.response_digest()));

    // Capture the call-site wiring ProceedMutate outcome (authorized fields).
    let outcome = rotate_fixture(env).callsite();
    write_file(&dir.join("callsite_outcome.txt"), &format!("{outcome:#?}\n"));

    // Capture a typed call-site fail-closed (MainNet peer-driven apply).
    let mut mn = rotate_fixture(TrustBundleEnvironment::Mainnet);
    mn.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    mn.peer_driven = true;
    write_file(&dir.join("callsite_fail_closed.txt"), &format!("{:#?}\n", mn.callsite()));

    // Call-site wiring inventory — typed symbols the release binary exposes.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_execution_evaluator_runtime_integration\n");
    for entry in [
        "entry\twire_governance_evaluator_runtime_callsite",
        "entry\twire_governance_evaluator_runtime_callsite_without_evaluator_context",
        "type\tGovernanceEvaluatorRuntimeCallsiteFailClosed",
        "type\tGovernanceEvaluatorRuntimeIntegrationContext",
        "type\tGovernanceEvaluatorRuntimeIntegrationOutcome",
        "outcome\tProceedLegacyBypass",
        "outcome\tProceedMutate",
        "outcome\tRuntimeConsumptionFailClosed",
        "outcome\tEvaluatorRejected",
        "outcome\tMainNetPeerDrivenApplyRefused",
        "composed\tRun224:integrate_governance_evaluator_runtime_consumption",
        "composed\tRun220:GovernanceExecutionRuntimeArmingConfig::consume_surface",
        "composed\tRun222:ProductionGovernanceExecutionEvaluator",
        "composed\tRun211:GovernanceExecutionExpectations",
        "composed\tRun213:GovernanceExecutionLoadStatus",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("callsite_wiring_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper <OUT_DIR>");
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
    let mut summary = String::from("run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper\nscope: Run 226 governance evaluator runtime call-site wiring (wire_governance_evaluator_runtime_callsite / wire_governance_evaluator_runtime_callsite_without_evaluator_context, GovernanceEvaluatorRuntimeCallsiteFailClosed) exercised through release-built library symbols (release binary)\nnote: fixture-only; routes the representable runtime call sites through the Run 224 integration layer (composing Run 220 runtime consumption + Run 222 evaluator interface + Run 211 decision validation + Run 213 payload material); pure (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); the integration outcome is consumed, not discarded; default Disabled legacy bypass preserved; present carrier without evaluator context fails closed; production/on-chain/MainNet evaluators unavailable/fail-closed; MainNet peer-driven apply remains refused\n\n");
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