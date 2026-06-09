//! Run 223 — release-built helper for the Run 222 production governance
//! execution **evaluator interface** boundary
//! (`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`).
//!
//! Where Run 222 landed the typed evaluator interface at the source/test
//! level (the `ProductionGovernanceExecutionEvaluator` trait, the
//! `EvaluatorSourceKind` / `EvaluatorPolicy` selectors, the
//! `DecisionSourceIdentity` / `EvaluatorRequest` / `EvaluatorResponse`
//! records, the deterministic domain-separated digest helpers, the typed
//! `EvaluatorOutcome`, and `evaluate_governance_evaluator_with_peer_driven_guard`),
//! Run 223 proves that the **release-built** code exposes and exercises
//! that interface: it drives the full A1–A18 / R1–R40 matrix from
//! `task/RUN_223_TASK.txt` through the production library symbols, records
//! the deterministic source/request/response/transcript digests, and
//! confirms the fixture/emergency fixture acceptance, the
//! production/on-chain/MainNet unavailable fail-closed behaviour, and the
//! MainNet peer-driven apply refusal guard.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real
//! governance execution engine, on-chain proof verifier, KMS/HSM, or
//! RemoteSigner backend. The evaluator module is pure (no marker write, no
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
    evaluate_governance_decision_source, evaluate_governance_evaluator_with_peer_driven_guard,
    evaluator_transcript_digest, local_operator_cannot_satisfy_evaluator_policy,
    mainnet_peer_driven_apply_remains_refused_under_evaluator,
    peer_majority_cannot_satisfy_evaluator_policy,
    validator_set_rotation_remains_unsupported_under_evaluator, verify_governance_evaluator_response,
    DecisionSourceIdentity, EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface,
    EvaluatorComposedOutcome, EvaluatorExpectations, EvaluatorOutcome, EvaluatorPolicy,
    EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    FixtureGovernanceExecutionEvaluatorInterface, MainnetDecisionSourceEvaluatorInterface,
    OnChainDecisionSourceEvaluatorInterface, ProductionDecisionSourceEvaluatorInterface,
    ProductionGovernanceExecutionEvaluator, EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const GOV_PROOF: &str = "governance-proof-digest-bbbbbbbbbbbbbbbb";
const NONCE: &str = "replay-nonce-cccccccccccccccccccccccccc";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SOURCE_ID: &str = "decision-source-0001";
const INPUT_DIGEST: &str = "governance-execution-input-digest-ffffffff";
const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const COMMIT: &str = "response-commitment-eeeeeeeeeeeeeeeeeeee";

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

fn rotate_identity(env: TrustBundleEnvironment) -> DecisionSourceIdentity {
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

fn rotate_request(env: TrustBundleEnvironment) -> EvaluatorRequest {
    let identity = rotate_identity(env);
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: INPUT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: 7,
        effective_epoch: 100,
        expiry_epoch: 200,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn rotate_response(env: TrustBundleEnvironment) -> EvaluatorResponse {
    let request = rotate_request(env);
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: 7,
        effective_epoch: 100,
        expiry_epoch: 200,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: 100,
        response_expiry_epoch: 200,
        emergency_flag: false,
        response_commitment: COMMIT.to_string(),
    }
}

fn rotate_expectations(env: TrustBundleEnvironment) -> EvaluatorExpectations {
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
        expected_authority_domain_sequence: 7,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_effective_epoch: 100,
        expected_expiry_epoch: 200,
        expected_replay_nonce: NONCE.to_string(),
        expected_governance_execution_input_digest: INPUT_DIGEST.to_string(),
        now_epoch: 150,
    }
}

// --- revoke fixtures ---

fn revoke_request(env: TrustBundleEnvironment) -> EvaluatorRequest {
    let mut req = rotate_request(env);
    req.governance_action = GovernanceAction::Revoke;
    req.lifecycle_action = LocalLifecycleAction::Revoke;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    req
}
fn revoke_response(env: TrustBundleEnvironment) -> EvaluatorResponse {
    let request = revoke_request(env);
    let mut resp = rotate_response(env);
    resp.authorized_governance_action = GovernanceAction::Revoke;
    resp.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    resp.request_digest = request.request_digest();
    resp
}
fn revoke_expectations(env: TrustBundleEnvironment) -> EvaluatorExpectations {
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    exp
}

// --- emergency-council fixtures ---

fn emergency_identity(env: TrustBundleEnvironment) -> DecisionSourceIdentity {
    let mut id = rotate_identity(env);
    id.source_kind = EvaluatorSourceKind::EmergencyCouncilFixtureSource;
    id.governance_class = GovernanceExecutionClass::EmergencyCouncilFixture;
    id.issuer_authority_class = GovernanceAuthorityClass::EmergencyCouncil;
    id
}
fn emergency_request(env: TrustBundleEnvironment) -> EvaluatorRequest {
    let identity = emergency_identity(env);
    let mut req = rotate_request(env);
    req.governance_action = GovernanceAction::EmergencyRevoke;
    req.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    req.emergency_flag = true;
    req.decision_source_identity_digest = identity.source_identity_digest();
    req
}
fn emergency_response(env: TrustBundleEnvironment) -> EvaluatorResponse {
    let request = emergency_request(env);
    let mut resp = rotate_response(env);
    resp.request_digest = request.request_digest();
    resp.authorized_governance_action = GovernanceAction::EmergencyRevoke;
    resp.authorized_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    resp.emergency_flag = true;
    resp
}
fn emergency_expectations(env: TrustBundleEnvironment) -> EvaluatorExpectations {
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    exp
}

/// Stable tag for the typed evaluator outcome.
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

/// Stable tag for the composed (peer-driven guard) outcome.
fn composed_tag(c: &EvaluatorComposedOutcome) -> String {
    match c {
        EvaluatorComposedOutcome::Accepted(o) => format!("accepted:{}", outcome_tag(o)),
        EvaluatorComposedOutcome::Rejected(o) => format!("rejected:{}", outcome_tag(o)),
        EvaluatorComposedOutcome::MainNetPeerDrivenApplyRefused => {
            "MainNetPeerDrivenApplyRefused".to_string()
        }
    }
}

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

/// Drive `evaluate_governance_decision_source` for the given inputs.
fn src(
    policy: EvaluatorPolicy,
    identity: &DecisionSourceIdentity,
    request: &EvaluatorRequest,
    expectations: &EvaluatorExpectations,
    env: TrustBundleEnvironment,
) -> EvaluatorOutcome {
    evaluate_governance_decision_source(identity, request, expectations, &trust_domain(env), policy)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — fixture accepts DevNet under explicit fixture policy.
    {
        let env = Env::Devnet;
        let o = src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            env,
        );
        t.check("A1.fixture-devnet", "accept:FixtureDecisionSourceAccepted", outcome_tag(&o));
        t.assert_true("A1.is-accept", o.is_accept(), "");
    }
    // A2 — fixture accepts TestNet under explicit fixture policy.
    {
        let env = Env::Testnet;
        let o = src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            env,
        );
        t.check("A2.fixture-testnet", "accept:FixtureDecisionSourceAccepted", outcome_tag(&o));
    }
    // A3 — emergency fixture accepts explicit emergency decision/policy.
    {
        let env = Env::Devnet;
        let o = src(
            EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed,
            &emergency_identity(env),
            &emergency_request(env),
            &emergency_expectations(env),
            env,
        );
        t.check("A3.emergency-fixture", "accept:EmergencyFixtureAccepted", outcome_tag(&o));
    }
    // A4 — source-identity digest deterministic + binding.
    {
        let env = Env::Devnet;
        let id = rotate_identity(env);
        t.assert_true("A4.digest-stable", id.source_identity_digest() == id.source_identity_digest(), "");
        let mut other = rotate_identity(env);
        other.source_id = "different".to_string();
        t.assert_true("A4.digest-binds", id.source_identity_digest() != other.source_identity_digest(), "");
    }
    // A5 — request digest deterministic + binding.
    {
        let env = Env::Devnet;
        let req = rotate_request(env);
        t.assert_true("A5.digest-stable", req.request_digest() == req.request_digest(), "");
        let mut other = rotate_request(env);
        other.proposal_id = "proposal-9999".to_string();
        t.assert_true("A5.digest-binds", req.request_digest() != other.request_digest(), "");
    }
    // A6 — response digest deterministic + binding.
    {
        let env = Env::Devnet;
        let resp = rotate_response(env);
        t.assert_true("A6.digest-stable", resp.response_digest() == resp.response_digest(), "");
        let mut other = rotate_response(env);
        other.authorized_authority_domain_sequence = 99;
        t.assert_true("A6.digest-binds", resp.response_digest() != other.response_digest(), "");
    }
    // A7 — transcript digest deterministic + binding.
    {
        let env = Env::Devnet;
        let id = rotate_identity(env);
        let req = rotate_request(env);
        let resp = rotate_response(env);
        let d1 = evaluator_transcript_digest(
            &id.source_identity_digest(),
            &req.request_digest(),
            &resp.response_digest(),
        );
        let d2 = evaluator_transcript_digest(
            &id.source_identity_digest(),
            &req.request_digest(),
            &resp.response_digest(),
        );
        t.assert_true("A7.digest-stable", d1 == d2, "");
        let d3 = evaluator_transcript_digest("a", &req.request_digest(), &resp.response_digest());
        t.assert_true("A7.digest-binds", d1 != d3, "");
    }
    // A8 — request binds every enumerated field (each mutation changes digest).
    {
        let env = Env::Devnet;
        let base = rotate_request(env).request_digest();
        let mutate = |f: &dyn Fn(&mut EvaluatorRequest)| {
            let mut r = rotate_request(env);
            f(&mut r);
            r.request_digest()
        };
        let fields: [(&str, &dyn Fn(&mut EvaluatorRequest)); 9] = [
            ("proposal_id", &|r: &mut EvaluatorRequest| r.proposal_id = "x".to_string()),
            ("decision_id", &|r: &mut EvaluatorRequest| r.decision_id = "x".to_string()),
            ("lifecycle_action", &|r: &mut EvaluatorRequest| r.lifecycle_action = LocalLifecycleAction::Revoke),
            ("candidate_digest", &|r: &mut EvaluatorRequest| r.candidate_digest = "x".to_string()),
            ("authority_domain_sequence", &|r: &mut EvaluatorRequest| r.authority_domain_sequence = 999),
            ("effective_epoch", &|r: &mut EvaluatorRequest| r.effective_epoch = 5),
            ("expiry_epoch", &|r: &mut EvaluatorRequest| r.expiry_epoch = 5),
            ("replay_nonce", &|r: &mut EvaluatorRequest| r.replay_nonce = "x".to_string()),
            ("source_identity_digest", &|r: &mut EvaluatorRequest| r.decision_source_identity_digest = "x".to_string()),
        ];
        for (name, f) in fields {
            t.assert_true(&format!("A8.binds-{name}"), base != mutate(f), "");
        }
    }
    // A9 — response binds every enumerated field.
    {
        let env = Env::Devnet;
        let base = rotate_response(env).response_digest();
        let mutate = |f: &dyn Fn(&mut EvaluatorResponse)| {
            let mut r = rotate_response(env);
            f(&mut r);
            r.response_digest()
        };
        let fields: [(&str, &dyn Fn(&mut EvaluatorResponse)); 8] = [
            ("request_digest", &|r: &mut EvaluatorResponse| r.request_digest = "x".to_string()),
            ("decision_digest", &|r: &mut EvaluatorResponse| r.decision_digest = "x".to_string()),
            ("authorized_lifecycle_action", &|r: &mut EvaluatorResponse| r.authorized_lifecycle_action = LocalLifecycleAction::Revoke),
            ("authorized_candidate_digest", &|r: &mut EvaluatorResponse| r.authorized_candidate_digest = "x".to_string()),
            ("authorized_sequence", &|r: &mut EvaluatorResponse| r.authorized_authority_domain_sequence = 999),
            ("effective_epoch", &|r: &mut EvaluatorResponse| r.effective_epoch = 5),
            ("expiry_epoch", &|r: &mut EvaluatorResponse| r.expiry_epoch = 5),
            ("replay_nonce", &|r: &mut EvaluatorResponse| r.replay_nonce = "x".to_string()),
        ];
        for (name, f) in fields {
            t.assert_true(&format!("A9.binds-{name}"), base != mutate(f), "");
        }
    }
    // A10 — rotate authorization only with matching candidate digest + sequence.
    {
        let env = Env::Devnet;
        let ok = verify_governance_evaluator_response(
            &rotate_response(env),
            &rotate_request(env),
            &rotate_expectations(env),
        );
        t.check("A10.rotate-authorized", "accept:EvaluatorResponseAuthorized", outcome_tag(&ok));
        let mut resp = rotate_response(env);
        resp.authorized_candidate_digest = "mismatch".to_string();
        resp.request_digest = rotate_request(env).request_digest();
        let bad = verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env));
        t.check("A10.rotate-wrong-candidate", "reject:WrongCandidateDigest", outcome_tag(&bad));
    }
    // A11 — revoke authorization only with matching material + sequence.
    {
        let env = Env::Devnet;
        let ok = verify_governance_evaluator_response(
            &revoke_response(env),
            &revoke_request(env),
            &revoke_expectations(env),
        );
        t.check("A11.revoke-authorized", "accept:EvaluatorResponseAuthorized", outcome_tag(&ok));
        let mut resp = revoke_response(env);
        resp.authorized_authority_domain_sequence = 99;
        resp.request_digest = revoke_request(env).request_digest();
        let bad = verify_governance_evaluator_response(&resp, &revoke_request(env), &revoke_expectations(env));
        t.check("A11.revoke-wrong-sequence", "reject:WrongAuthorityDomainSequence", outcome_tag(&bad));
    }
    // A12 — emergency revoke only under explicit emergency fixture policy.
    {
        let env = Env::Devnet;
        let ok = src(
            EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed,
            &emergency_identity(env),
            &emergency_request(env),
            &emergency_expectations(env),
            env,
        );
        t.check("A12.emergency-accepted", "accept:EmergencyFixtureAccepted", outcome_tag(&ok));
        let auth = verify_governance_evaluator_response(
            &emergency_response(env),
            &emergency_request(env),
            &emergency_expectations(env),
        );
        t.check("A12.emergency-authorized", "accept:EvaluatorResponseAuthorized", outcome_tag(&auth));
        let mismatch = src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &emergency_identity(env),
            &emergency_request(env),
            &emergency_expectations(env),
            env,
        );
        t.check("A12.emergency-under-plain-fixture", "reject:SourceKindPolicyMismatch", outcome_tag(&mismatch));
    }
    // A13 — production evaluator boundary callable, typed unavailable.
    {
        let env = Env::Devnet;
        let ev = ProductionDecisionSourceEvaluatorInterface;
        let o = ev.evaluate_governance_decision_source(
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            &trust_domain(env),
            EvaluatorPolicy::ProductionDecisionSourceRequired,
        );
        t.check("A13.production-unavailable", "reject:ProductionDecisionSourceUnavailable", outcome_tag(&o));
        t.assert_true("A13.is-unavailable", o.is_unavailable(), "");
        t.assert_true(
            "A13.source-kind",
            ev.source_kind() == EvaluatorSourceKind::ProductionDecisionSourceUnavailable,
            "",
        );
    }
    // A14 — on-chain evaluator boundary callable, typed unavailable.
    {
        let env = Env::Devnet;
        let ev = OnChainDecisionSourceEvaluatorInterface;
        let o = ev.evaluate_governance_decision_source(
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            &trust_domain(env),
            EvaluatorPolicy::ProductionDecisionSourceRequired,
        );
        t.check("A14.onchain-unavailable", "reject:OnChainDecisionSourceUnavailable", outcome_tag(&o));
        t.assert_true("A14.is-unavailable", o.is_unavailable(), "");
    }
    // A15 — MainNet evaluator boundary callable, typed unavailable/refusal.
    {
        let env = Env::Mainnet;
        let ev = MainnetDecisionSourceEvaluatorInterface;
        let o = ev.evaluate_governance_decision_source(
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            &trust_domain(env),
            EvaluatorPolicy::MainnetDecisionSourceRequired,
        );
        t.check("A15.mainnet-unavailable", "reject:MainnetDecisionSourceUnavailable", outcome_tag(&o));
        t.assert_true("A15.is-unavailable", o.is_unavailable(), "");
    }
    // A16 — Run 220 runtime-consumption compatibility: Disabled policy inert.
    {
        let env = Env::Devnet;
        let o = src(
            EvaluatorPolicy::Disabled,
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            env,
        );
        t.check("A16.disabled-inert", "reject:EvaluatorDisabled", outcome_tag(&o));
    }
    // A17 — peer-driven guard preserves MainNet refusal even when fixture would approve.
    {
        let env = Env::Mainnet;
        let c = evaluate_governance_evaluator_with_peer_driven_guard(
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_response(env),
            &rotate_expectations(env),
            &trust_domain(env),
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            true,
        );
        t.check("A17.mainnet-refused", "MainNetPeerDrivenApplyRefused", &composed_tag(&c));
        t.assert_true("A17.is-reject", c.is_reject(), "");
        // Non-MainNet round-trip accepts through the guard.
        let env = Env::Devnet;
        let ok = evaluate_governance_evaluator_with_peer_driven_guard(
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_response(env),
            &rotate_expectations(env),
            &trust_domain(env),
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            false,
        );
        t.check("A17.devnet-accepted", "accepted:accept:EvaluatorResponseAuthorized", &composed_tag(&ok));
    }
    // A18 — evaluator interface remains pure: repeated calls equal, inputs unchanged.
    {
        let env = Env::Devnet;
        let id = rotate_identity(env);
        let req = rotate_request(env);
        let exp = rotate_expectations(env);
        let id_before = id.clone();
        let req_before = req.clone();
        let o1 = evaluate_governance_decision_source(&id, &req, &exp, &trust_domain(env), EvaluatorPolicy::FixtureDecisionSourceAllowed);
        let o2 = evaluate_governance_decision_source(&id, &req, &exp, &trust_domain(env), EvaluatorPolicy::FixtureDecisionSourceAllowed);
        t.assert_true("A18.pure-repeatable", o1 == o2, "");
        t.assert_true("A18.inputs-unchanged", id == id_before && req == req_before, "");
    }
    t.finish(out)
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;

    // R1 — disabled policy rejected.
    t.check(
        "R1.disabled",
        "reject:EvaluatorDisabled",
        outcome_tag(&src(EvaluatorPolicy::Disabled, &rotate_identity(env), &rotate_request(env), &rotate_expectations(env), env)),
    );
    // R2 — fixture rejected under production-required.
    t.check(
        "R2.fixture-production-required",
        "reject:FixtureRejectedUnderProductionPolicy",
        outcome_tag(&src(EvaluatorPolicy::ProductionDecisionSourceRequired, &rotate_identity(env), &rotate_request(env), &rotate_expectations(env), env)),
    );
    // R3 — emergency fixture rejected under production-required.
    t.check(
        "R3.emergency-production-required",
        "reject:EmergencyFixtureRejectedUnderProductionPolicy",
        outcome_tag(&src(EvaluatorPolicy::ProductionDecisionSourceRequired, &emergency_identity(env), &emergency_request(env), &emergency_expectations(env), env)),
    );
    // R4 — fixture rejected under MainNet-required.
    t.check(
        "R4.fixture-mainnet-required",
        "reject:FixtureRejectedUnderProductionPolicy",
        outcome_tag(&src(EvaluatorPolicy::MainnetDecisionSourceRequired, &rotate_identity(env), &rotate_request(env), &rotate_expectations(env), env)),
    );
    // R5 — production evaluator rejected as unavailable (fixture policy).
    {
        let mut id = rotate_identity(env);
        id.source_kind = EvaluatorSourceKind::ProductionDecisionSourceUnavailable;
        t.check("R5.production-unavailable", "reject:ProductionDecisionSourceUnavailable", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R6 — on-chain unavailable.
    {
        let mut id = rotate_identity(env);
        id.source_kind = EvaluatorSourceKind::OnChainDecisionSourceUnavailable;
        t.check("R6.onchain-unavailable", "reject:OnChainDecisionSourceUnavailable", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R7 — MainNet unavailable.
    {
        let mut id = rotate_identity(env);
        id.source_kind = EvaluatorSourceKind::MainnetDecisionSourceUnavailable;
        t.check("R7.mainnet-unavailable", "reject:MainnetDecisionSourceUnavailable", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R8 — unknown source rejected.
    {
        let mut id = rotate_identity(env);
        id.source_kind = EvaluatorSourceKind::Unknown;
        t.check("R8.unknown-source", "reject:UnknownSourceRejected", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R9 — wrong environment.
    {
        let mut id = rotate_identity(env);
        id.environment = Env::Testnet;
        t.check("R9.wrong-environment", "reject:WrongEnvironment", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R10 — wrong chain.
    {
        let mut id = rotate_identity(env);
        id.chain_id = "other-chain".to_string();
        t.check("R10.wrong-chain", "reject:WrongChain", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R11 — wrong genesis.
    {
        let mut id = rotate_identity(env);
        id.genesis_hash = "other-genesis".to_string();
        t.check("R11.wrong-genesis", "reject:WrongGenesis", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R12 — wrong authority root (re-bind identity digest so root check fires).
    {
        let mut id = rotate_identity(env);
        id.authority_root_fingerprint = "other-root".to_string();
        let mut req = rotate_request(env);
        req.decision_source_identity_digest = id.source_identity_digest();
        t.check("R12.wrong-authority-root", "reject:WrongAuthorityRoot", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &req, &rotate_expectations(env), env)));
    }
    // R13 — wrong governance proof digest.
    {
        let mut id = rotate_identity(env);
        id.governance_proof_digest = "other-proof".to_string();
        let mut req = rotate_request(env);
        req.decision_source_identity_digest = id.source_identity_digest();
        t.check("R13.wrong-governance-proof", "reject:WrongGovernanceProofDigest", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &req, &rotate_expectations(env), env)));
    }
    // R14 — wrong on-chain proof digest.
    {
        let mut id = rotate_identity(env);
        id.on_chain_proof_digest = Some("unexpected-onchain".to_string());
        let mut req = rotate_request(env);
        req.decision_source_identity_digest = id.source_identity_digest();
        t.check("R14.wrong-onchain-proof", "reject:WrongOnChainProofDigest", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &req, &rotate_expectations(env), env)));
    }
    // R15 — wrong custody attestation digest.
    {
        let mut id = rotate_identity(env);
        id.custody_attestation_digest = Some("unexpected-custody".to_string());
        let mut req = rotate_request(env);
        req.decision_source_identity_digest = id.source_identity_digest();
        t.check("R15.wrong-custody-attestation", "reject:WrongCustodyAttestationDigest", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &req, &rotate_expectations(env), env)));
    }
    // R16 — wrong proposal id.
    {
        let mut req = rotate_request(env);
        req.proposal_id = "other-proposal".to_string();
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R16.wrong-proposal-id", "reject:WrongProposalId", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R17 — wrong decision id.
    {
        let mut req = rotate_request(env);
        req.decision_id = "other-decision".to_string();
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R17.wrong-decision-id", "reject:WrongDecisionId", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R18 — wrong lifecycle action.
    {
        let mut req = rotate_request(env);
        req.governance_action = GovernanceAction::Retire;
        req.lifecycle_action = LocalLifecycleAction::Retire;
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R18.wrong-lifecycle-action", "reject:WrongLifecycleAction", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R19 — wrong candidate digest.
    {
        let mut req = rotate_request(env);
        req.candidate_digest = "other-candidate".to_string();
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R19.wrong-candidate-digest", "reject:WrongCandidateDigest", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R20 — wrong authority-domain sequence.
    {
        let mut req = rotate_request(env);
        req.authority_domain_sequence = 999;
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R20.wrong-sequence", "reject:WrongAuthorityDomainSequence", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R21 — wrong effective epoch.
    {
        let mut req = rotate_request(env);
        req.effective_epoch = 50;
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R21.wrong-effective-epoch", "reject:WrongEffectiveEpoch", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R22 — expired decision.
    {
        let mut exp = rotate_expectations(env);
        exp.now_epoch = 250;
        t.check("R22.expired-decision", "reject:ExpiredDecision", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &rotate_request(env), &exp, env)));
    }
    // R23 — stale/replayed decision.
    {
        let mut req = rotate_request(env);
        req.replay_nonce = "stale-nonce".to_string();
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R23.stale-replayed", "reject:StaleOrReplayedDecision", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R24 — quorum/threshold insufficient.
    {
        let mut req = rotate_request(env);
        req.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R24.quorum-insufficient", "reject:QuorumThresholdInsufficient", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R25 — emergency action not authorized (emergency action under plain fixture policy).
    {
        let mut req = rotate_request(env);
        req.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
        req.governance_action = GovernanceAction::EmergencyRevoke;
        req.emergency_flag = true;
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        let mut exp = rotate_expectations(env);
        exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
        exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
        t.check("R25.emergency-not-authorized", "reject:EmergencyActionNotAuthorized", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &exp, env)));
    }
    // R26 — validator-set rotation unsupported.
    {
        let mut req = rotate_request(env);
        req.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R26.validator-set-rotation", "reject:ValidatorSetRotationUnsupported", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R27 — policy-change action unsupported.
    {
        let mut req = rotate_request(env);
        req.governance_action = GovernanceAction::PolicyChangeRequest;
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R27.policy-change", "reject:PolicyChangeActionUnsupported", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R28 — malformed source identity.
    {
        let mut id = rotate_identity(env);
        id.source_id = String::new();
        let mut req = rotate_request(env);
        req.decision_source_identity_digest = id.source_identity_digest();
        t.check("R28.malformed-source-identity", "reject:MalformedSourceIdentity", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &req, &rotate_expectations(env), env)));
    }
    // R29 — malformed evaluator request.
    {
        let mut req = rotate_request(env);
        req.replay_nonce = String::new();
        req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
        t.check("R29.malformed-request", "reject:MalformedEvaluatorRequest", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &rotate_identity(env), &req, &rotate_expectations(env), env)));
    }
    // R30 — malformed evaluator response.
    {
        let mut resp = rotate_response(env);
        resp.evaluator_source_id = String::new();
        t.check("R30.malformed-response", "reject:MalformedEvaluatorResponse", outcome_tag(&verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env))));
    }
    // R31 — unsupported evaluator version.
    {
        let mut id = rotate_identity(env);
        id.evaluator_version = 99;
        let mut req = rotate_request(env);
        req.decision_source_identity_digest = id.source_identity_digest();
        t.check("R31.unsupported-version", "reject:UnsupportedEvaluatorVersion", outcome_tag(&src(EvaluatorPolicy::FixtureDecisionSourceAllowed, &id, &req, &rotate_expectations(env), env)));
    }
    // R32 — invalid response commitment.
    {
        let mut resp = rotate_response(env);
        resp.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
        t.check("R32.invalid-commitment", "reject:InvalidResponseCommitment", outcome_tag(&verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env))));
    }
    // R33 — local operator cannot satisfy evaluator policy.
    t.assert_true("R33.local-operator-cannot-satisfy", local_operator_cannot_satisfy_evaluator_policy(), "");
    // R34 — peer majority cannot satisfy evaluator policy.
    t.assert_true("R34.peer-majority-cannot-satisfy", peer_majority_cannot_satisfy_evaluator_policy(), "");
    // R35 — evaluator valid but governance execution decision invalid (response action disagrees).
    {
        let mut resp = rotate_response(env);
        resp.authorized_lifecycle_action = LocalLifecycleAction::Retire;
        resp.request_digest = rotate_request(env).request_digest();
        t.check("R35.governance-decision-invalid", "reject:WrongLifecycleAction", outcome_tag(&verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env))));
    }
    // R36 — governance valid but evaluator response invalid (response does not bind request digest).
    {
        let mut resp = rotate_response(env);
        resp.request_digest = "not-the-request-digest".to_string();
        t.check("R36.response-invalid", "reject:MalformedEvaluatorResponse", outcome_tag(&verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env))));
    }
    // R37 — lifecycle+proof+custody valid but production evaluator unavailable.
    {
        let mut id = rotate_identity(env);
        id.source_kind = EvaluatorSourceKind::ProductionDecisionSourceUnavailable;
        t.check("R37.production-unavailable-required", "reject:ProductionDecisionSourceUnavailable", outcome_tag(&src(EvaluatorPolicy::ProductionDecisionSourceRequired, &id, &rotate_request(env), &rotate_expectations(env), env)));
    }
    // R38 — validation-only rejection remains non-mutating (inputs unchanged).
    {
        let id = rotate_identity(env);
        let req = rotate_request(env);
        let exp = rotate_expectations(env);
        let id_before = id.clone();
        let req_before = req.clone();
        let _ = evaluate_governance_decision_source(&id, &req, &exp, &trust_domain(env), EvaluatorPolicy::Disabled);
        t.assert_true("R38.inputs-unchanged", id == id_before && req == req_before, "");
    }
    // R39 — mutating rejection produces no mutation (composed guard rejects, no APIs).
    {
        let c = evaluate_governance_evaluator_with_peer_driven_guard(
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_response(env),
            &rotate_expectations(env),
            &trust_domain(env),
            EvaluatorPolicy::Disabled,
            false,
        );
        t.check("R39.composed-rejected", "rejected:reject:EvaluatorDisabled", &composed_tag(&c));
        t.assert_true("R39.is-reject", c.is_reject(), "");
    }
    // R40 — MainNet peer-driven apply refused even with fixture approval.
    {
        let menv = Env::Mainnet;
        let c = evaluate_governance_evaluator_with_peer_driven_guard(
            &rotate_identity(menv),
            &rotate_request(menv),
            &rotate_response(menv),
            &rotate_expectations(menv),
            &trust_domain(menv),
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            true,
        );
        t.check("R40.mainnet-refused", "MainNetPeerDrivenApplyRefused", &composed_tag(&c));
        t.assert_true("R40.helper-refuses", mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Mainnet), "");
    }
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");
    let env = Env::Devnet;

    // Source kind / policy tags reachable.
    t.assert_true("K.fixture-is-fixture", EvaluatorSourceKind::FixtureDecisionSource.is_fixture(), "");
    t.assert_true("K.emergency-is-fixture", EvaluatorSourceKind::EmergencyCouncilFixtureSource.is_fixture(), "");
    t.assert_true("K.production-is-unavailable", EvaluatorSourceKind::ProductionDecisionSourceUnavailable.is_production_unavailable(), "");
    t.assert_true("P.production-requires-source", EvaluatorPolicy::ProductionDecisionSourceRequired.requires_production_source(), "");
    t.assert_true("P.fixture-allowed-source", EvaluatorPolicy::FixtureDecisionSourceAllowed.allowed_fixture_source() == Some(EvaluatorSourceKind::FixtureDecisionSource), "");

    // Trait implementations reachable; each presents its kind.
    let fixture = FixtureGovernanceExecutionEvaluatorInterface;
    let emergency = EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface;
    t.assert_true("T.fixture-kind", fixture.source_kind() == EvaluatorSourceKind::FixtureDecisionSource, "");
    t.assert_true("T.emergency-kind", emergency.source_kind() == EvaluatorSourceKind::EmergencyCouncilFixtureSource, "");
    t.assert_true("T.production-kind", ProductionDecisionSourceEvaluatorInterface.source_kind() == EvaluatorSourceKind::ProductionDecisionSourceUnavailable, "");
    t.assert_true("T.onchain-kind", OnChainDecisionSourceEvaluatorInterface.source_kind() == EvaluatorSourceKind::OnChainDecisionSourceUnavailable, "");
    t.assert_true("T.mainnet-kind", MainnetDecisionSourceEvaluatorInterface.source_kind() == EvaluatorSourceKind::MainnetDecisionSourceUnavailable, "");

    // Fixture trait verify path reaches authorize.
    let auth = fixture.verify_governance_evaluator_response(&rotate_response(env), &rotate_request(env), &rotate_expectations(env));
    t.check("T.fixture-verify-authorized", "accept:EvaluatorResponseAuthorized", outcome_tag(&auth));

    // Deterministic digest helpers reachable and non-empty.
    let id = rotate_identity(env);
    let req = rotate_request(env);
    let resp = rotate_response(env);
    t.assert_true("D.source-identity-digest", !id.source_identity_digest().is_empty(), "");
    t.assert_true("D.request-digest", !req.request_digest().is_empty(), "");
    t.assert_true("D.response-digest", !resp.response_digest().is_empty(), "");
    t.assert_true(
        "D.transcript-digest",
        !evaluator_transcript_digest(&id.source_identity_digest(), &req.request_digest(), &resp.response_digest()).is_empty(),
        "",
    );

    // Explicit fail-closed helper symbols reachable.
    t.assert_true("H.validator-set-rotation-unsupported", validator_set_rotation_remains_unsupported_under_evaluator(), "");
    t.assert_true("H.mainnet-refused-helper", mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Mainnet), "");
    t.assert_true("H.mainnet-refused-helper-devnet-false", !mainnet_peer_driven_apply_remains_refused_under_evaluator(Env::Devnet), "");
    t.assert_true("H.local-operator-cannot-satisfy", local_operator_cannot_satisfy_evaluator_policy(), "");
    t.assert_true("H.peer-majority-cannot-satisfy", peer_majority_cannot_satisfy_evaluator_policy(), "");

    t.finish(out)
}

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let env = TrustBundleEnvironment::Devnet;
    let id = rotate_identity(env);
    let req = rotate_request(env);
    let resp = rotate_response(env);
    write_file(&dir.join("decision_source_identity.txt"), &format!("{id:#?}\n"));
    write_file(&dir.join("evaluator_request.txt"), &format!("{req:#?}\n"));
    write_file(&dir.join("evaluator_response.txt"), &format!("{resp:#?}\n"));
    write_file(&dir.join("evaluator_expectations.txt"), &format!("{:#?}\n", rotate_expectations(env)));
    write_file(&dir.join("source_identity_digest.txt"), &format!("{}\n", id.source_identity_digest()));
    write_file(&dir.join("request_digest.txt"), &format!("{}\n", req.request_digest()));
    write_file(&dir.join("response_digest.txt"), &format!("{}\n", resp.response_digest()));
    write_file(
        &dir.join("transcript_digest.txt"),
        &format!(
            "{}\n",
            evaluator_transcript_digest(&id.source_identity_digest(), &req.request_digest(), &resp.response_digest())
        ),
    );
    // Evaluator interface inventory — typed symbols the release binary exposes.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_execution_evaluator\n");
    inv.push_str(&format!("supported_version\t{}\n", EVALUATOR_SUPPORTED_VERSION));
    for k in [
        EvaluatorSourceKind::Disabled,
        EvaluatorSourceKind::FixtureDecisionSource,
        EvaluatorSourceKind::EmergencyCouncilFixtureSource,
        EvaluatorSourceKind::OnChainDecisionSourceUnavailable,
        EvaluatorSourceKind::ProductionDecisionSourceUnavailable,
        EvaluatorSourceKind::MainnetDecisionSourceUnavailable,
        EvaluatorSourceKind::Unknown,
    ] {
        inv.push_str(&format!("source_kind\t{}\n", k.tag()));
    }
    for p in [
        EvaluatorPolicy::Disabled,
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
        EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed,
        EvaluatorPolicy::ProductionDecisionSourceRequired,
        EvaluatorPolicy::MainnetDecisionSourceRequired,
    ] {
        inv.push_str(&format!("policy\t{}\n", p.tag()));
    }
    for ev in [
        "FixtureGovernanceExecutionEvaluatorInterface",
        "EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface",
        "ProductionDecisionSourceEvaluatorInterface",
        "OnChainDecisionSourceEvaluatorInterface",
        "MainnetDecisionSourceEvaluatorInterface",
    ] {
        inv.push_str(&format!("evaluator_impl\t{ev}\n"));
    }
    for helper in [
        "source_identity_digest",
        "request_digest",
        "response_digest",
        "evaluator_transcript_digest",
        "evaluate_governance_decision_source",
        "verify_governance_evaluator_response",
        "evaluate_governance_evaluator_with_peer_driven_guard",
    ] {
        inv.push_str(&format!("helper\t{helper}\n"));
    }
    write_file(&dir.join("evaluator_interface_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_223_governance_execution_evaluator_release_binary_helper <OUT_DIR>");
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
    let mut summary = String::from("run_223_governance_execution_evaluator_release_binary_helper\nscope: Run 222 production governance execution evaluator interface boundary (ProductionGovernanceExecutionEvaluator trait / EvaluatorSourceKind / EvaluatorPolicy / DecisionSourceIdentity / EvaluatorRequest / EvaluatorResponse / deterministic digest helpers / EvaluatorOutcome / evaluate_governance_evaluator_with_peer_driven_guard) exercised through release-built library symbols (release binary)\nnote: fixture-only; no real governance execution engine/on-chain verifier/KMS-HSM/RemoteSigner; pure (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); MainNet peer-driven apply remains refused\n\n");
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
