//! Run 225 — release-built helper for the Run 224 governance evaluator
//! runtime **integration** layer
//! (`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`).
//!
//! Where Run 224 landed the source/test integration layer that composes Run
//! 220 runtime consumption, the Run 222 evaluator request/response/interface,
//! Run 211 governance execution decision validation, and Run 213 payload
//! material into a single pure entry point
//! (`integrate_governance_evaluator_runtime_consumption` /
//! `..._from_optional_sidecar_value`, the
//! `GovernanceEvaluatorRuntimeIntegrationContext` input bundle, and the typed
//! `GovernanceEvaluatorRuntimeIntegrationOutcome`), Run 225 proves that the
//! **release-built** code exposes and exercises that integration layer: it
//! drives the full A1–A15 / R1–R30 matrix from `task/RUN_225_TASK.txt`
//! through the production library symbols, records the deterministic
//! evaluator source/request/response digests and the governance-execution
//! payload digest, confirms the ordering (selector resolution →
//! sidecar/load-status derivation → runtime consumption → evaluator request
//! construction → evaluator evaluation → governance execution decision
//! validation → mutation only after all required checks pass), and confirms
//! the production/on-chain/MainNet evaluators remain unavailable/fail-closed,
//! the default legacy bypass is preserved, and MainNet peer-driven apply
//! remains refused.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real
//! governance execution engine, on-chain proof verifier, KMS/HSM, or
//! RemoteSigner backend. The integration layer is pure (no marker write, no
//! sequence write, no live trust swap, no session eviction, no Run 070
//! call). MainNet peer-driven apply remains refused.

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
// Shared constants (mirror the Run 220 / Run 222 / Run 224 corpora so the
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
// Owned-material fixture bundle (mirrors the Run 224 test fixture)
// ===========================================================================

/// Owns every layer's material for one integration round-trip so a scenario
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
    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

// ===========================================================================
// A — accepted / compatible scenarios (A1–A15)
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — disabled policy + absent carrier produces ProceedLegacyBypass.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
        fx.load = GovernanceExecutionLoadStatus::Absent;
        let o = fx.run();
        t.check("A1.disabled-absent", "proceed:LegacyBypass", &itag(&o));
        t.assert_true("A1.is-proceed", o.is_proceed(), "");
        t.assert_true("A1.is-legacy-bypass", o.is_legacy_bypass(), "");
        t.assert_true("A1.not-mutate", !o.is_mutate_authorized(), "");
    }
    // A2 — DevNet fixture runtime consumption + matching evaluator -> ProceedMutate.
    {
        let o = rotate_fixture(Env::Devnet).run();
        t.check("A2.devnet-fixture", "proceed:Mutate", &itag(&o));
        t.assert_true("A2.is-mutate", o.is_mutate_authorized(), "");
        if let GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate {
            runtime_consumption,
            evaluator,
            lifecycle_action,
            candidate_digest,
            authority_domain_sequence,
        } = o
        {
            t.assert_true(
                "A2.runtime-fixture-accepted",
                matches!(
                    runtime_consumption,
                    GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. }
                ),
                "",
            );
            t.assert_true(
                "A2.evaluator-authorized",
                matches!(evaluator, EvaluatorOutcome::EvaluatorResponseAuthorized { .. }),
                "",
            );
            t.check("A2.lifecycle", "Rotate", &format!("{lifecycle_action:?}"));
            t.check("A2.candidate", CAND_DIGEST, &candidate_digest);
            t.check("A2.sequence", "7", &authority_domain_sequence.to_string());
        } else {
            t.assert_true("A2.proceed-mutate-shape", false, "expected ProceedMutate");
        }
    }
    // A3 — TestNet fixture runtime consumption + matching evaluator -> ProceedMutate.
    {
        let o = rotate_fixture(Env::Testnet).run();
        t.check("A3.testnet-fixture", "proceed:Mutate", &itag(&o));
    }
    // A4 — explicit emergency fixture accepts only an explicit emergency action.
    {
        let env = Env::Devnet;
        let o = emergency_fixture(env)
            .run_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
        t.check("A4.emergency-accepted", "proceed:Mutate", &itag(&o));
        let mut non_emergency = emergency_fixture(env);
        non_emergency.request.emergency_flag = false;
        non_emergency.response.emergency_flag = false;
        non_emergency.response.request_digest = non_emergency.request.request_digest();
        let rej =
            non_emergency.run_with(&EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface);
        t.assert_true("A4.non-emergency-refused", !rej.is_mutate_authorized(), "");
    }
    // A5 — evaluator request digest binds every enumerated field.
    {
        let fx = rotate_fixture(Env::Devnet);
        let base = fx.request.request_digest();
        t.assert_true("A5.deterministic", base == fx.request.request_digest(), "");
        let mutate = |f: &dyn Fn(&mut EvaluatorRequest)| {
            let mut r = fx.request.clone();
            f(&mut r);
            r.request_digest()
        };
        let fields: [(&str, &dyn Fn(&mut EvaluatorRequest)); 10] = [
            ("input_digest", &|r: &mut EvaluatorRequest| r.governance_execution_input_digest = "x".to_string()),
            ("proposal_id", &|r: &mut EvaluatorRequest| r.proposal_id = "x".to_string()),
            ("decision_id", &|r: &mut EvaluatorRequest| r.decision_id = "x".to_string()),
            ("lifecycle_action", &|r: &mut EvaluatorRequest| r.lifecycle_action = LocalLifecycleAction::Revoke),
            ("candidate_digest", &|r: &mut EvaluatorRequest| r.candidate_digest = "x".to_string()),
            ("sequence", &|r: &mut EvaluatorRequest| r.authority_domain_sequence = 999),
            ("effective_epoch", &|r: &mut EvaluatorRequest| r.effective_epoch = 5),
            ("expiry_epoch", &|r: &mut EvaluatorRequest| r.expiry_epoch = 5),
            ("replay_nonce", &|r: &mut EvaluatorRequest| r.replay_nonce = "x".to_string()),
            ("source_identity", &|r: &mut EvaluatorRequest| r.decision_source_identity_digest = "x".to_string()),
        ];
        for (name, f) in fields {
            t.assert_true(&format!("A5.binds-{name}"), base != mutate(f), "");
        }
    }
    // A6 — evaluator response digest binds every enumerated field.
    {
        let fx = rotate_fixture(Env::Devnet);
        let base = fx.response.response_digest();
        t.assert_true("A6.deterministic", base == fx.response.response_digest(), "");
        let mutate = |f: &dyn Fn(&mut EvaluatorResponse)| {
            let mut r = fx.response.clone();
            f(&mut r);
            r.response_digest()
        };
        let fields: [(&str, &dyn Fn(&mut EvaluatorResponse)); 8] = [
            ("request_digest", &|r: &mut EvaluatorResponse| r.request_digest = "x".to_string()),
            ("decision_digest", &|r: &mut EvaluatorResponse| r.decision_digest = "x".to_string()),
            ("action", &|r: &mut EvaluatorResponse| r.authorized_lifecycle_action = LocalLifecycleAction::Revoke),
            ("candidate_digest", &|r: &mut EvaluatorResponse| r.authorized_candidate_digest = "x".to_string()),
            ("sequence", &|r: &mut EvaluatorResponse| r.authorized_authority_domain_sequence = 999),
            ("effective_epoch", &|r: &mut EvaluatorResponse| r.effective_epoch = 5),
            ("expiry_epoch", &|r: &mut EvaluatorResponse| r.expiry_epoch = 5),
            ("replay_nonce", &|r: &mut EvaluatorResponse| r.replay_nonce = "x".to_string()),
        ];
        for (name, f) in fields {
            t.assert_true(&format!("A6.binds-{name}"), base != mutate(f), "");
        }
    }
    // A7 — rotate accepted only when runtime consumption, evaluator response,
    // governance decision, candidate digest, and sequence all match.
    {
        let env = Env::Devnet;
        t.check("A7.rotate-all-match", "proceed:Mutate", &itag(&rotate_fixture(env).run()));
        let mut bad_cand = rotate_fixture(env);
        bad_cand.response.authorized_candidate_digest = "different-candidate".to_string();
        t.assert_true("A7.wrong-candidate-not-mutate", !bad_cand.run().is_mutate_authorized(), "");
        let mut bad_seq = rotate_fixture(env);
        bad_seq.response.authorized_authority_domain_sequence = 8;
        t.assert_true("A7.wrong-sequence-not-mutate", !bad_seq.run().is_mutate_authorized(), "");
    }
    // A8 — revoke accepted only when runtime consumption, evaluator response,
    // governance decision, revoked/candidate material, and sequence all match.
    {
        let env = Env::Devnet;
        t.check("A8.revoke-all-match", "proceed:Mutate", &itag(&revoke_fixture(env).run()));
        let mut bad_seq = revoke_fixture(env);
        bad_seq.response.authorized_authority_domain_sequence = 9;
        t.assert_true("A8.wrong-sequence-not-mutate", !bad_seq.run().is_mutate_authorized(), "");
    }
    // A9 — production evaluator path reached and fails closed as unavailable.
    {
        let o = rotate_fixture(Env::Devnet).run_with(&ProductionDecisionSourceEvaluatorInterface);
        t.check(
            "A9.production-unavailable",
            "reject:Evaluator:reject:ProductionDecisionSourceUnavailable",
            &itag(&o),
        );
        t.assert_true("A9.not-mutate", !o.is_mutate_authorized(), "");
    }
    // A10 — on-chain evaluator path reached and fails closed as unavailable.
    {
        let o = rotate_fixture(Env::Devnet).run_with(&OnChainDecisionSourceEvaluatorInterface);
        t.check(
            "A10.onchain-unavailable",
            "reject:Evaluator:reject:OnChainDecisionSourceUnavailable",
            &itag(&o),
        );
    }
    // A11 — MainNet evaluator path reached and fails closed (DevNet domain so
    // runtime consumption accepts and the integration reaches the evaluator).
    {
        let o = rotate_fixture(Env::Devnet).run_with(&MainnetDecisionSourceEvaluatorInterface);
        t.check(
            "A11.mainnet-unavailable",
            "reject:Evaluator:reject:MainnetDecisionSourceUnavailable",
            &itag(&o),
        );
    }
    // A12 — MainNet peer-driven apply refused even with fixture approval.
    {
        let mut fx = rotate_fixture(Env::Mainnet);
        fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
        fx.peer_driven = true;
        let o = fx.run();
        t.check("A12.mainnet-peer-driven-refused", "reject:MainNetPeerDrivenApplyRefused", &itag(&o));
        t.assert_true("A12.is-refused", o.is_mainnet_peer_driven_apply_refused(), "");
        t.assert_true("A12.not-mutate", !o.is_mutate_authorized(), "");
    }
    // A13 — integration ordering: both stages gate mutation.
    {
        let env = Env::Devnet;
        t.check("A13.both-valid-mutate", "proceed:Mutate", &itag(&rotate_fixture(env).run()));
        // Flip ONLY the evaluator stage to reject (carrier still valid).
        let mut ev_only = rotate_fixture(env);
        ev_only.response.approved = false;
        t.assert_true("A13.evaluator-only-reject", !ev_only.run().is_mutate_authorized(), "");
        // Flip ONLY the runtime-consumption stage to reject (evaluator valid).
        let mut rc_only = rotate_fixture(env);
        rc_only.load = GovernanceExecutionLoadStatus::Absent;
        let rc = rc_only.run();
        t.assert_true("A13.runtime-only-reject", !rc.is_mutate_authorized(), "");
        t.assert_true("A13.runtime-only-fail-closed", rc.is_fail_closed(), "");
    }
    // A14 — Run 221 runtime-consumption compatibility: every surface reaches
    // ProceedMutate under a valid fixture round-trip (except the MainNet-refused
    // peer-driven drain, exercised in A12).
    {
        let env = Env::Devnet;
        for surface in GovernanceExecutionRuntimeSurface::ALL {
            let mut fx = rotate_fixture(env);
            fx.surface = surface;
            t.assert_true(
                &format!("A14.surface-{surface:?}-mutate"),
                fx.run().is_mutate_authorized(),
                "",
            );
        }
    }
    // A15 — Run 223 evaluator-interface compatibility: disabled evaluator
    // policy fails closed for a present fixture carrier; the production /
    // on-chain / MainNet evaluators are callable but fail closed as unavailable.
    {
        let env = Env::Devnet;
        let mut disabled = rotate_fixture(env);
        disabled.ev_policy = EvaluatorPolicy::Disabled;
        let o = disabled.run();
        t.check("A15.disabled-evaluator", "reject:Evaluator:reject:EvaluatorDisabled", &itag(&o));
        t.assert_true(
            "A15.production-unavailable",
            matches!(
                rotate_fixture(env).run_with(&ProductionDecisionSourceEvaluatorInterface),
                GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
                    EvaluatorOutcome::ProductionDecisionSourceUnavailable
                )
            ),
            "",
        );
    }
    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R30); all non-mutating
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;

    // R1 — missing material rejected when evaluator policy requires it.
    {
        let mut fx = rotate_fixture(env);
        fx.load = GovernanceExecutionLoadStatus::Absent;
        let o = fx.run();
        t.check(
            "R1.required-absent",
            "reject:RuntimeConsumptionFailClosed:GovernanceExecutionRequiredButAbsent",
            &itag(&o),
        );
        t.assert_true("R1.not-mutate", !o.is_mutate_authorized(), "");
    }
    // R2 — malformed material rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.load = GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
            error: "broken".to_string(),
        });
        t.check(
            "R2.malformed",
            "reject:RuntimeConsumptionFailClosed:MalformedGovernanceExecutionPayload",
            &itag(&fx.run()),
        );
    }
    // R3 — wrong evaluator source rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.source_kind = EvaluatorSourceKind::EmergencyCouncilFixtureSource;
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R3.wrong-source", "reject:Evaluator:reject:SourceKindPolicyMismatch", &itag(&fx.run()));
    }
    // R4 — wrong environment rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_environment = Env::Testnet;
        fx.identity.environment = Env::Testnet;
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R4.wrong-environment", "reject:Evaluator:reject:WrongEnvironment", &itag(&fx.run()));
    }
    // R5 — wrong chain rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.chain_id = "other-chain".to_string();
        fx.ev_exp.expected_chain_id = "other-chain".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R5.wrong-chain", "reject:Evaluator:reject:WrongChain", &itag(&fx.run()));
    }
    // R6 — wrong genesis rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.genesis_hash = "other-genesis".to_string();
        fx.ev_exp.expected_genesis_hash = "other-genesis".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R6.wrong-genesis", "reject:Evaluator:reject:WrongGenesis", &itag(&fx.run()));
    }
    // R7 — wrong authority root rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.authority_root_fingerprint = "other-root".to_string();
        fx.ev_exp.expected_authority_root_fingerprint = "other-root".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R7.wrong-authority-root", "reject:Evaluator:reject:WrongAuthorityRoot", &itag(&fx.run()));
    }
    // R8 — wrong governance proof digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.identity.governance_proof_digest = "other-gov-proof".to_string();
        fx.request.decision_source_identity_digest = fx.identity.source_identity_digest();
        fx.response.request_digest = fx.request.request_digest();
        t.check("R8.wrong-gov-proof", "reject:Evaluator:reject:WrongGovernanceProofDigest", &itag(&fx.run()));
    }
    // R9 — wrong on-chain proof digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
        t.check("R9.wrong-onchain-proof", "reject:Evaluator:reject:WrongOnChainProofDigest", &itag(&fx.run()));
    }
    // R10 — wrong custody attestation digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
        t.check("R10.wrong-custody", "reject:Evaluator:reject:WrongCustodyAttestationDigest", &itag(&fx.run()));
    }
    // R11 — wrong proposal id rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_proposal_id = "other-proposal".to_string();
        t.check("R11.wrong-proposal", "reject:Evaluator:reject:WrongProposalId", &itag(&fx.run()));
    }
    // R12 — wrong decision id rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_decision_id = "other-decision".to_string();
        t.check("R12.wrong-decision", "reject:Evaluator:reject:WrongDecisionId", &itag(&fx.run()));
    }
    // R13 — wrong lifecycle action rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
        t.check("R13.wrong-lifecycle", "reject:Evaluator:reject:WrongLifecycleAction", &itag(&fx.run()));
    }
    // R14 — wrong candidate digest rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_candidate_digest = "other-candidate".to_string();
        t.check("R14.wrong-candidate", "reject:Evaluator:reject:WrongCandidateDigest", &itag(&fx.run()));
    }
    // R15 — wrong authority-domain sequence rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_authority_domain_sequence = 8;
        t.check("R15.wrong-sequence", "reject:Evaluator:reject:WrongAuthorityDomainSequence", &itag(&fx.run()));
    }
    // R16 — expired evaluator request rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.now_epoch = 250;
        t.check("R16.expired", "reject:Evaluator:reject:ExpiredDecision", &itag(&fx.run()));
    }
    // R17 — stale/replayed evaluator request rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.ev_exp.expected_replay_nonce = "fresh-nonce".to_string();
        t.check("R17.stale-replayed", "reject:Evaluator:reject:StaleOrReplayedDecision", &itag(&fx.run()));
    }
    // R18 — quorum/threshold insufficient rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
        fx.response.request_digest = fx.request.request_digest();
        t.check("R18.quorum-insufficient", "reject:Evaluator:reject:QuorumThresholdInsufficient", &itag(&fx.run()));
    }
    // R19 — emergency action not authorized rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.emergency_flag = true;
        fx.response.request_digest = fx.request.request_digest();
        fx.response.emergency_flag = true;
        t.check("R19.emergency-not-authorized", "reject:Evaluator:reject:EmergencyActionNotAuthorized", &itag(&fx.run()));
    }
    // R20 — validator-set rotation unsupported rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        fx.response.request_digest = fx.request.request_digest();
        t.check("R20.validator-set-rotation", "reject:Evaluator:reject:ValidatorSetRotationUnsupported", &itag(&fx.run()));
        t.assert_true("R20.helper-unsupported", validator_set_rotation_remains_unsupported_under_evaluator(), "");
    }
    // R21 — policy-change action unsupported rejected.
    {
        let mut fx = rotate_fixture(env);
        fx.request.governance_action = GovernanceAction::PolicyChangeRequest;
        fx.response.request_digest = fx.request.request_digest();
        t.check("R21.policy-change", "reject:Evaluator:reject:PolicyChangeActionUnsupported", &itag(&fx.run()));
    }
    // R22 — production evaluator unavailable rejected.
    {
        let o = rotate_fixture(env).run_with(&ProductionDecisionSourceEvaluatorInterface);
        t.check("R22.production-unavailable", "reject:Evaluator:reject:ProductionDecisionSourceUnavailable", &itag(&o));
    }
    // R23 — on-chain evaluator unavailable rejected.
    {
        let o = rotate_fixture(env).run_with(&OnChainDecisionSourceEvaluatorInterface);
        t.check("R23.onchain-unavailable", "reject:Evaluator:reject:OnChainDecisionSourceUnavailable", &itag(&o));
    }
    // R24 — MainNet evaluator unavailable/refused rejected.
    {
        let o = rotate_fixture(env).run_with(&MainnetDecisionSourceEvaluatorInterface);
        t.check("R24.mainnet-unavailable", "reject:Evaluator:reject:MainnetDecisionSourceUnavailable", &itag(&o));
    }
    // R25 — local operator cannot satisfy evaluator policy.
    {
        t.assert_true("R25.local-operator-cannot-satisfy", local_operator_cannot_satisfy_evaluator_policy(), "");
        let mut fx = rotate_fixture(env);
        fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
        t.assert_true("R25.production-required-not-mutate", !fx.run().is_mutate_authorized(), "");
    }
    // R26 — peer majority cannot satisfy evaluator policy.
    {
        t.assert_true("R26.peer-majority-cannot-satisfy", peer_majority_cannot_satisfy_evaluator_policy(), "");
        let mut fx = rotate_fixture(env);
        fx.ev_policy = EvaluatorPolicy::MainnetDecisionSourceRequired;
        t.assert_true("R26.mainnet-required-not-mutate", !fx.run().is_mutate_authorized(), "");
    }
    // R27 — evaluator valid but governance execution decision invalid rejected.
    {
        let mut fx = rotate_fixture(env);
        let mut decision = rotate_decision();
        decision.authorized_sequence = 999; // mismatched -> Run 211 rejects
        fx.load = available_from(&rotate_input(env), &decision);
        t.check("R27.governance-decision-invalid", "reject:Evaluator:reject:GovernanceExecutionDecisionInvalid", &itag(&fx.run()));
    }
    // R28 — governance execution decision valid but evaluator response invalid.
    {
        let mut fx = rotate_fixture(env);
        fx.response.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
        t.check("R28.response-invalid", "reject:Evaluator:reject:InvalidResponseCommitment", &itag(&fx.run()));
    }
    // R29 — validation-only rejection writes no marker and no sequence (pure/repeatable).
    {
        let mut fx = rotate_fixture(env);
        fx.surface = GovernanceExecutionRuntimeSurface::ReloadCheck; // validation-only
        fx.ev_exp.expected_candidate_digest = "other".to_string(); // force reject
        let first = fx.run();
        let second = fx.run();
        t.assert_true("R29.not-mutate", !first.is_mutate_authorized(), "");
        t.assert_true("R29.pure-repeatable", first == second, "");
    }
    // R30 — mutating rejection produces no mutation (pure/repeatable).
    {
        let mut fx = rotate_fixture(env);
        fx.surface = GovernanceExecutionRuntimeSurface::ReloadApply; // mutating surface
        fx.response.approved = false; // force evaluator response reject
        let first = fx.run();
        let second = fx.run();
        t.assert_true("R30.not-mutate", !first.is_mutate_authorized(), "");
        t.assert_true("R30.fail-closed", first.is_fail_closed(), "");
        t.assert_true("R30.pure-repeatable", first == second, "");
    }
    t.finish(out)
}

// ===========================================================================
// Reachability table
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");
    let env = Env::Devnet;

    // The two integration entry points are reachable and agree.
    let explicit = rotate_fixture(env).run();
    t.check("K.explicit-entry-mutate", "proceed:Mutate", &itag(&explicit));

    // Sidecar-derivation convenience wrapper reaches the same ProceedMutate.
    {
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
        let some_outcome =
            integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value(
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
        t.check("K.sidecar-some-mutate", "proceed:Mutate", &itag(&some_outcome));
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
        t.assert_true("K.sidecar-none-not-mutate", !none_outcome.is_mutate_authorized(), "");
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

    // Explicit fail-closed helper symbols reachable.
    t.assert_true("H.validator-set-rotation-unsupported", validator_set_rotation_remains_unsupported_under_evaluator(), "");
    t.assert_true("H.mainnet-refused-helper", mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Mainnet), "");
    t.assert_true("H.mainnet-refused-devnet-false", !mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Devnet), "");
    t.assert_true("H.local-operator-cannot-satisfy", local_operator_cannot_satisfy_evaluator_policy(), "");
    t.assert_true("H.peer-majority-cannot-satisfy", peer_majority_cannot_satisfy_evaluator_policy(), "");

    // MainNet fixture runtime consumption is refused off the peer-driven path.
    t.assert_true("M.mainnet-fixture-not-mutate", !rotate_fixture(Env::Mainnet).run().is_mutate_authorized(), "");

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

    // Capture the ProceedMutate integration outcome (authorized fields).
    let outcome = rotate_fixture(env).run();
    write_file(&dir.join("integration_outcome.txt"), &format!("{outcome:#?}\n"));

    // Integration-layer inventory — typed symbols the release binary exposes.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_execution_evaluator_runtime_integration\n");
    for entry in [
        "entry\tintegrate_governance_evaluator_runtime_consumption",
        "entry\tintegrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value",
        "type\tGovernanceEvaluatorRuntimeIntegrationContext",
        "type\tGovernanceEvaluatorRuntimeIntegrationOutcome",
        "outcome\tProceedLegacyBypass",
        "outcome\tProceedMutate",
        "outcome\tRuntimeConsumptionFailClosed",
        "outcome\tEvaluatorRejected",
        "outcome\tMainNetPeerDrivenApplyRefused",
        "composed\tRun220:GovernanceExecutionRuntimeArmingConfig::consume_surface",
        "composed\tRun222:ProductionGovernanceExecutionEvaluator",
        "composed\tRun211:GovernanceExecutionExpectations",
        "composed\tRun213:GovernanceExecutionLoadStatus",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("integration_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_225_governance_evaluator_runtime_integration_release_binary_helper <OUT_DIR>");
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
    let mut summary = String::from("run_225_governance_evaluator_runtime_integration_release_binary_helper\nscope: Run 224 governance evaluator runtime integration layer (integrate_governance_evaluator_runtime_consumption / ..._from_optional_sidecar_value, GovernanceEvaluatorRuntimeIntegrationContext, GovernanceEvaluatorRuntimeIntegrationOutcome) exercised through release-built library symbols (release binary)\nnote: fixture-only; composes Run 220 runtime consumption + Run 222 evaluator interface + Run 211 decision validation + Run 213 payload material; pure (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); production/on-chain/MainNet evaluators unavailable/fail-closed; MainNet peer-driven apply remains refused\n\n");
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
