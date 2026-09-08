//! Run 212 — release-built helper that exercises the Run 211 **governance
//! execution policy boundary**
//! ([`qbind_node::pqc_governance_execution_policy`]) **in release mode**
//! through the production library symbols.
//!
//! Per `task/RUN_212_TASK.txt`, Run 212 is the release-binary evidence run
//! for the Run 211 source/test governance execution policy boundary. This
//! helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, or
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond what Runs 070, 130–211 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every governance-execution evaluator, digest helper, composition
//!   helper, and fail-closed helper exercised here is a pure function
//!   returning an owned typed outcome;
//! * does NOT open any P2P socket and performs no network or backend I/O;
//! * does NOT implement any real governance execution engine, real
//!   on-chain governance proof verifier, real KMS/HSM backend, real
//!   RemoteSigner backend, or validator-set rotation; production / on-chain
//!   / MainNet governance execution always fails closed as unavailable;
//! * never elevates the DevNet/TestNet fixture governance execution into
//!   MainNet production governance (MainNet peer-driven apply always
//!   refuses at the typed boundary);
//! * exists alongside (and does NOT replace) the Run 211 source/test target
//!   `crates/qbind-node/tests/run_211_governance_execution_policy_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. fixture governance execution accepted under the explicit fixture
//!    policy on DevNet/TestNet (evidence-only);
//! 2. emergency council fixture execution accepted only under the explicit
//!    emergency fixture policy;
//! 3. production / on-chain / MainNet governance execution remains
//!    unavailable/fail-closed;
//! 4. governance input/decision/transcript/policy digests are
//!    deterministic and domain-bound;
//! 5. governance execution authorizes a lifecycle action only when the
//!    action, candidate digest, and sequence all match;
//! 6. validator-set rotation and policy-change actions remain unsupported;
//! 7. rejected governance-execution cases produce no mutation (pure,
//!    repeat-stable, owned outcomes);
//! 8. MainNet peer-driven apply remains refused even with fixture approval;
//! 9. no real governance execution engine / on-chain proof verifier /
//!    KMS-HSM backend / RemoteSigner backend / validator-set rotation is
//!    claimed.
//!
//! Usage:
//! ```text
//! run_212_governance_execution_policy_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_policy::{
    evaluate_governance_execution_policy, evaluate_governance_execution_with_peer_driven_guard,
    governance_execution_policy_digest, governance_execution_transcript_digest,
    local_operator_cannot_satisfy_governance_execution,
    mainnet_peer_driven_apply_remains_refused_under_governance_execution,
    peer_majority_cannot_satisfy_governance_execution, validator_set_rotation_remains_unsupported,
    FixtureGovernanceExecutionEvaluator, GovernanceAction, GovernanceExecutionClass,
    GovernanceExecutionComposedOutcome, GovernanceExecutionDecision, GovernanceExecutionEvaluator,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionOutcome,
    GovernanceExecutionPolicy, GovernanceQuorumThreshold, MainnetGovernanceExecutionEvaluator,
    OnChainGovernanceExecutionEvaluator, ProductionGovernanceExecutionEvaluator,
    GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 211 source/test fixtures
// so the typed governance-execution semantics carry over end-to-end in release
// mode.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 211 source/test corpus exactly.
// ---------------------------------------------------------------------------

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

/// A standard accepted-path input for the Rotate action.
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

/// A standard accepted-path decision matching [`rotate_input`].
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

/// Standard expectations matching [`rotate_input`] / [`rotate_decision`].
fn rotate_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
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

/// Emergency-revoke input under the emergency fixture policy.
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

fn emergency_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    exp
}

/// A revoke input/decision/expectations triple under the fixture policy.
fn revoke_triple(
    env: TrustBundleEnvironment,
) -> (
    GovernanceExecutionInput,
    GovernanceExecutionDecision,
    GovernanceExecutionExpectations,
) {
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::Revoke;
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::Revoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    (input, decision, exp)
}

// ---------------------------------------------------------------------------
// Typed-outcome tagging — short, stable strings for the evidence tables.
// ---------------------------------------------------------------------------

fn outcome_tag(outcome: &GovernanceExecutionOutcome) -> &'static str {
    use GovernanceExecutionOutcome as O;
    match outcome {
        O::FixtureGovernanceAccepted { .. } => "accept:FixtureGovernanceAccepted",
        O::EmergencyCouncilFixtureAccepted { .. } => "accept:EmergencyCouncilFixtureAccepted",
        O::GovernanceExecutionDisabled => "reject:GovernanceExecutionDisabled",
        O::FixtureRejectedProductionRequired => "reject:FixtureRejectedProductionRequired",
        O::FixtureRejectedMainnetRequired => "reject:FixtureRejectedMainnetRequired",
        O::EmergencyFixtureRejectedProductionRequired => {
            "reject:EmergencyFixtureRejectedProductionRequired"
        }
        O::EmergencyFixtureRejectedMainnetRequired => {
            "reject:EmergencyFixtureRejectedMainnetRequired"
        }
        O::ProductionGovernanceUnavailable => "reject:ProductionGovernanceUnavailable",
        O::OnChainGovernanceUnavailable => "reject:OnChainGovernanceUnavailable",
        O::MainNetGovernanceUnavailable => "reject:MainNetGovernanceUnavailable",
        O::GovernanceClassPolicyMismatch { .. } => "reject:GovernanceClassPolicyMismatch",
        O::UnknownGovernanceClassRejected { .. } => "reject:UnknownGovernanceClassRejected",
        O::FixtureRejectedForMainNet => "reject:FixtureRejectedForMainNet",
        O::WrongEnvironment { .. } => "reject:WrongEnvironment",
        O::WrongChain { .. } => "reject:WrongChain",
        O::WrongGenesis { .. } => "reject:WrongGenesis",
        O::WrongAuthorityRoot { .. } => "reject:WrongAuthorityRoot",
        O::WrongLifecycleAction { .. } => "reject:WrongLifecycleAction",
        O::WrongCandidateDigest { .. } => "reject:WrongCandidateDigest",
        O::WrongAuthorityDomainSequence { .. } => "reject:WrongAuthorityDomainSequence",
        O::WrongGovernanceProofDigest { .. } => "reject:WrongGovernanceProofDigest",
        O::WrongOnChainProofDigest { .. } => "reject:WrongOnChainProofDigest",
        O::WrongCustodyAttestationDigest { .. } => "reject:WrongCustodyAttestationDigest",
        O::WrongProposalId { .. } => "reject:WrongProposalId",
        O::WrongDecisionId { .. } => "reject:WrongDecisionId",
        O::WrongEffectiveEpoch { .. } => "reject:WrongEffectiveEpoch",
        O::ExpiredDecision { .. } => "reject:ExpiredDecision",
        O::StaleOrReplayedDecision => "reject:StaleOrReplayedDecision",
        O::QuorumThresholdInsufficient { .. } => "reject:QuorumThresholdInsufficient",
        O::EmergencyActionNotAuthorized => "reject:EmergencyActionNotAuthorized",
        O::ValidatorSetRotationUnsupported => "reject:ValidatorSetRotationUnsupported",
        O::PolicyChangeActionUnsupported => "reject:PolicyChangeActionUnsupported",
        O::GovernanceDecisionRejected => "reject:GovernanceDecisionRejected",
        O::MalformedExecutionInput { .. } => "reject:MalformedExecutionInput",
        O::MalformedExecutionDecision { .. } => "reject:MalformedExecutionDecision",
        O::UnsupportedGovernanceExecutionVersion { .. } => {
            "reject:UnsupportedGovernanceExecutionVersion"
        }
        O::LocalOperatorCannotSatisfyGovernanceExecution => {
            "reject:LocalOperatorCannotSatisfyGovernanceExecution"
        }
        O::PeerMajorityCannotSatisfyGovernanceExecution => {
            "reject:PeerMajorityCannotSatisfyGovernanceExecution"
        }
    }
}

fn composed_tag(outcome: &GovernanceExecutionComposedOutcome) -> String {
    use GovernanceExecutionComposedOutcome as C;
    match outcome {
        C::Accepted(o) => format!("accepted:{}", outcome_tag(o)),
        C::Rejected(o) => format!("rejected:{}", outcome_tag(o)),
        C::MainNetPeerDrivenApplyRefused => "MainNetPeerDrivenApplyRefused".to_string(),
    }
}

/// Convenience: evaluate under the fixture policy on the given env.
fn eval_fixture(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
    exp: &GovernanceExecutionExpectations,
    env: TrustBundleEnvironment,
) -> GovernanceExecutionOutcome {
    evaluate_governance_execution_policy(
        input,
        decision,
        exp,
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    )
}

// ---------------------------------------------------------------------------
// Evidence writing helpers
// ---------------------------------------------------------------------------

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("create dir {parent:?}: {e}"));
    }
    let mut f = fs::File::create(path).unwrap_or_else(|e| panic!("create {path:?}: {e}"));
    f.write_all(contents.as_bytes())
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

/// A small table recorder that accumulates `name<TAB>PASS|FAIL<TAB>detail`
/// rows plus an `expected`/`actual` ledger and writes them under `out`.
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
        Table {
            name,
            rows: String::new(),
            expected: String::new(),
            actual: String::new(),
            pass: 0,
            fail: 0,
        }
    }

    /// Record an equality check on a typed-outcome tag.
    fn check(&mut self, id: &str, expected: &str, actual: &str) {
        let ok = expected == actual;
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        self.rows.push_str(&format!(
            "{}\t{}\texpected={}\tactual={}\n",
            id,
            if ok { "PASS" } else { "FAIL" },
            expected,
            actual
        ));
        self.expected.push_str(&format!("{}\t{}\n", id, expected));
        self.actual.push_str(&format!("{}\t{}\n", id, actual));
    }

    /// Record a boolean assertion.
    fn assert_true(&mut self, id: &str, ok: bool, detail: &str) {
        self.check(id, "true", if ok { "true" } else { "false" });
        if !detail.is_empty() {
            self.rows.push_str(&format!("\t# {}: {}\n", id, detail));
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

// ---------------------------------------------------------------------------
// Table 1 — accepted / compatible cases (A1..A16).
// ---------------------------------------------------------------------------

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — fixture governance accepted under fixture policy on DevNet.
    {
        let env = Env::Devnet;
        let outcome = eval_fixture(&rotate_input(env), &rotate_decision(), &rotate_expectations(env), env);
        t.check("A1.fixture-devnet", "accept:FixtureGovernanceAccepted", outcome_tag(&outcome));
    }

    // A2 — fixture governance accepted under fixture policy on TestNet.
    {
        let env = Env::Testnet;
        let outcome = eval_fixture(&rotate_input(env), &rotate_decision(), &rotate_expectations(env), env);
        t.check("A2.fixture-testnet", "accept:FixtureGovernanceAccepted", outcome_tag(&outcome));
    }

    // A3 — emergency council fixture accepted under emergency fixture policy.
    {
        let env = Env::Devnet;
        let outcome = evaluate_governance_execution_policy(
            &emergency_input(env),
            &emergency_decision(),
            &emergency_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        );
        t.check(
            "A3.emergency-devnet",
            "accept:EmergencyCouncilFixtureAccepted",
            outcome_tag(&outcome),
        );
    }

    // A4 — governance execution input digest deterministic + domain-bound.
    {
        let env = Env::Devnet;
        let a = rotate_input(env).input_digest();
        let b = rotate_input(env).input_digest();
        let mut c = rotate_input(env);
        c.proposal_id = "different".to_string();
        t.assert_true("A4.input-digest-deterministic", a == b && a != c.input_digest(), "");
    }

    // A5 — governance execution decision digest deterministic + domain-bound.
    {
        let a = rotate_decision().decision_digest();
        let b = rotate_decision().decision_digest();
        let mut c = rotate_decision();
        c.authorized_sequence = 8;
        t.assert_true("A5.decision-digest-deterministic", a == b && a != c.decision_digest(), "");
    }

    // A6 — governance execution transcript digest deterministic + bound.
    {
        let env = Env::Devnet;
        let input = rotate_input(env);
        let decision = rotate_decision();
        let t1 =
            governance_execution_transcript_digest(&input.input_digest(), &decision.decision_digest());
        let t2 =
            governance_execution_transcript_digest(&input.input_digest(), &decision.decision_digest());
        let mut other = rotate_input(env);
        other.replay_nonce = "other-nonce".to_string();
        let t3 = governance_execution_transcript_digest(
            &other.input_digest(),
            &decision.decision_digest(),
        );
        t.assert_true("A6.transcript-digest-deterministic", t1 == t2 && t1 != t3, "");
    }

    // A7 — governance policy digest deterministic (optional helper, implemented).
    {
        let d1 = governance_execution_policy_digest(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance,
        );
        let d2 = governance_execution_policy_digest(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance,
        );
        let d3 = governance_execution_policy_digest(
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
            GovernanceExecutionClass::EmergencyCouncilFixture,
        );
        t.assert_true("A7.policy-digest-deterministic", d1 == d2 && d1 != d3, "");
    }

    // A8 — input binds the full tuple: mutating any bound field changes the
    // input digest (environment, chain, genesis, proposal id, decision id,
    // authority root, lifecycle action, candidate digest, sequence, governance
    // proof digest, effective epoch, expiry epoch, replay nonce).
    {
        let env = Env::Devnet;
        let base = rotate_input(env).input_digest();
        let mutators: Vec<Box<dyn Fn(&mut GovernanceExecutionInput)>> = vec![
            Box::new(|i| i.environment = Env::Testnet),
            Box::new(|i| i.chain_id = "x".to_string()),
            Box::new(|i| i.genesis_hash = "x".to_string()),
            Box::new(|i| i.proposal_id = "x".to_string()),
            Box::new(|i| i.decision_id = "x".to_string()),
            Box::new(|i| i.authority_root_fingerprint = "x".to_string()),
            Box::new(|i| i.lifecycle_action = LocalLifecycleAction::Revoke),
            Box::new(|i| i.candidate_digest = "x".to_string()),
            Box::new(|i| i.authority_domain_sequence = 99),
            Box::new(|i| i.governance_proof_digest = "x".to_string()),
            Box::new(|i| i.effective_epoch = 1),
            Box::new(|i| i.expiry_epoch = 9999),
            Box::new(|i| i.replay_nonce = "x".to_string()),
        ];
        let mut all_changed = true;
        for m in mutators {
            let mut i = rotate_input(env);
            m(&mut i);
            all_changed &= base != i.input_digest();
        }
        t.assert_true("A8.input-binds-full-tuple", all_changed, "");
    }

    // A9 — decision binds the full tuple.
    {
        let base = rotate_decision().decision_digest();
        let mutators: Vec<Box<dyn Fn(&mut GovernanceExecutionDecision)>> = vec![
            Box::new(|d| d.proposal_id = "x".to_string()),
            Box::new(|d| d.decision_id = "x".to_string()),
            Box::new(|d| d.approved = false),
            Box::new(|d| d.authorized_lifecycle_action = LocalLifecycleAction::Revoke),
            Box::new(|d| d.authorized_authority_root_fingerprint = "x".to_string()),
            Box::new(|d| d.authorized_candidate_digest = "x".to_string()),
            Box::new(|d| d.authorized_sequence = 99),
            Box::new(|d| d.effective_epoch = 1),
            Box::new(|d| d.expiry_epoch = 9999),
            Box::new(|d| d.emergency_flag = true),
            Box::new(|d| d.replay_nonce = "x".to_string()),
        ];
        let mut all_changed = true;
        for m in mutators {
            let mut d = rotate_decision();
            m(&mut d);
            all_changed &= base != d.decision_digest();
        }
        t.assert_true("A9.decision-binds-full-tuple", all_changed, "");
    }

    // A10 — lifecycle rotate authorized only when the decision authorizes rotate.
    {
        let env = Env::Devnet;
        let ok = eval_fixture(&rotate_input(env), &rotate_decision(), &rotate_expectations(env), env);
        let mut decision = rotate_decision();
        decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
        decision.authorized_governance_action = GovernanceAction::Revoke;
        let bad = eval_fixture(&rotate_input(env), &decision, &rotate_expectations(env), env);
        t.check("A10.rotate-accepted", "accept:FixtureGovernanceAccepted", outcome_tag(&ok));
        t.check("A10.rotate-mismatch", "reject:WrongLifecycleAction", outcome_tag(&bad));
    }

    // A11 — lifecycle revoke authorized only when the decision authorizes revoke.
    {
        let env = Env::Devnet;
        let (input, decision, exp) = revoke_triple(env);
        let outcome = eval_fixture(&input, &decision, &exp, env);
        t.check("A11.revoke-accepted", "accept:FixtureGovernanceAccepted", outcome_tag(&outcome));
    }

    // A12 — emergency revoke accepted only under the explicit emergency fixture
    // policy; the plain fixture policy refuses the emergency class.
    {
        let env = Env::Devnet;
        let ok = evaluate_governance_execution_policy(
            &emergency_input(env),
            &emergency_decision(),
            &emergency_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        );
        let bad = eval_fixture(&emergency_input(env), &emergency_decision(), &emergency_expectations(env), env);
        t.check("A12.emergency-accepted", "accept:EmergencyCouncilFixtureAccepted", outcome_tag(&ok));
        t.check("A12.emergency-under-fixture", "reject:GovernanceClassPolicyMismatch", outcome_tag(&bad));
    }

    // A13 — production governance boundary callable, returns typed unavailable.
    {
        let env = Env::Devnet;
        let evaluator = ProductionGovernanceExecutionEvaluator;
        let outcome = evaluator.evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("A13.production-unavailable", "reject:ProductionGovernanceUnavailable", outcome_tag(&outcome));
        t.assert_true("A13.is-unavailable", outcome.is_unavailable(), "");
    }

    // A14 — on-chain governance boundary callable, returns typed unavailable.
    {
        let env = Env::Devnet;
        let evaluator = OnChainGovernanceExecutionEvaluator;
        let outcome = evaluator.evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("A14.onchain-unavailable", "reject:OnChainGovernanceUnavailable", outcome_tag(&outcome));
        t.assert_true("A14.is-unavailable", outcome.is_unavailable(), "");
    }

    // A15 — GenesisBound / EmergencyCouncil / OnChainGovernance proof-carrier
    // behavior unchanged when governance execution policy is Disabled: carrying
    // optional on-chain / custody-attestation digests still returns Disabled.
    {
        let env = Env::Devnet;
        for issuer in [
            GovernanceAuthorityClass::GenesisBound,
            GovernanceAuthorityClass::EmergencyCouncil,
            GovernanceAuthorityClass::OnChainGovernance,
        ] {
            let mut input = rotate_input(env);
            input.on_chain_proof_digest = Some("onchain-digest".to_string());
            input.custody_attestation_digest = Some("custody-attestation-digest".to_string());
            let mut decision = rotate_decision();
            decision.issuer_authority_class = issuer;
            let outcome = evaluate_governance_execution_policy(
                &input,
                &decision,
                &rotate_expectations(env),
                &trust_domain(env),
                GovernanceExecutionPolicy::Disabled,
            );
            t.check(
                &format!("A15.disabled-inert-{issuer:?}"),
                "reject:GovernanceExecutionDisabled",
                outcome_tag(&outcome),
            );
        }
    }

    // A16 — custody / RemoteSigner / KMS-HSM / custody-attestation paths remain
    // compatible when governance execution policy is Disabled: bound optional
    // digests do not flip the inert Disabled outcome.
    {
        let env = Env::Devnet;
        let mut input = rotate_input(env);
        input.custody_attestation_digest = Some("kms-hsm-remote-signer-attestation".to_string());
        input.on_chain_proof_digest = Some("onchain-proof".to_string());
        let outcome = evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::Disabled,
        );
        t.check("A16.custody-signer-compat", "reject:GovernanceExecutionDisabled", outcome_tag(&outcome));
    }

    // Extra — the fixture evaluator trait accepts on DevNet and reports its class.
    {
        let env = Env::Devnet;
        let evaluator = FixtureGovernanceExecutionEvaluator;
        let outcome = evaluator.evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.assert_true(
            "X.fixture-evaluator-trait",
            outcome.is_accept()
                && evaluator.class() == GovernanceExecutionClass::FixtureGovernance,
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — rejection cases (R1..R38).
// ---------------------------------------------------------------------------

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;

    // R1 — governance execution rejected under Disabled policy.
    {
        let outcome = evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::Disabled,
        );
        t.check("R1.disabled", "reject:GovernanceExecutionDisabled", outcome_tag(&outcome));
    }

    // R2 — fixture governance rejected under ProductionGovernanceRequired.
    {
        let outcome = evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("R2.fixture-production-required", "reject:FixtureRejectedProductionRequired", outcome_tag(&outcome));
    }

    // R3 — emergency fixture rejected under ProductionGovernanceRequired.
    {
        let outcome = evaluate_governance_execution_policy(
            &emergency_input(env),
            &emergency_decision(),
            &emergency_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check(
            "R3.emergency-production-required",
            "reject:EmergencyFixtureRejectedProductionRequired",
            outcome_tag(&outcome),
        );
    }

    // R4 — fixture governance rejected under MainnetGovernanceRequired.
    {
        let outcome = evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        );
        t.check("R4.fixture-mainnet-required", "reject:FixtureRejectedMainnetRequired", outcome_tag(&outcome));
    }

    // R5 — production governance rejected as unavailable.
    {
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R5.production-unavailable", "reject:ProductionGovernanceUnavailable", outcome_tag(&outcome));
    }

    // R6 — on-chain governance rejected as unavailable.
    {
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::OnChainGovernanceUnavailable;
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R6.onchain-unavailable", "reject:OnChainGovernanceUnavailable", outcome_tag(&outcome));
    }

    // R7 — MainNet governance rejected as unavailable (class + MainNet evaluator).
    {
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::MainnetGovernanceUnavailable;
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R7.mainnet-unavailable", "reject:MainNetGovernanceUnavailable", outcome_tag(&outcome));
        let evaluator = MainnetGovernanceExecutionEvaluator;
        let placeholder = evaluator.evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        );
        t.check("R7.mainnet-evaluator", "reject:MainNetGovernanceUnavailable", outcome_tag(&placeholder));
    }

    // R8 — unknown governance class rejected.
    {
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::Unknown;
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R8.unknown-class", "reject:UnknownGovernanceClassRejected", outcome_tag(&outcome));
    }

    // R9..R21 — wrong-binding rejections. Each mutates one bound field.
    let wrong_input_cases: &[(&str, &str, fn(&mut GovernanceExecutionInput, &mut GovernanceExecutionExpectations))] = &[
        ("R9.wrong-environment", "reject:WrongEnvironment", |i, _e| {
            i.environment = TrustBundleEnvironment::Testnet;
        }),
        ("R10.wrong-chain", "reject:WrongChain", |i, _e| {
            i.chain_id = "wrong-chain".to_string();
        }),
        ("R11.wrong-genesis", "reject:WrongGenesis", |i, _e| {
            i.genesis_hash = "wrong-genesis".to_string();
        }),
        ("R12.wrong-authority-root", "reject:WrongAuthorityRoot", |i, _e| {
            i.authority_root_fingerprint = "wrong-root".to_string();
        }),
        ("R13.wrong-lifecycle-action", "reject:WrongLifecycleAction", |i, _e| {
            i.lifecycle_action = LocalLifecycleAction::Retire;
        }),
        ("R14.wrong-candidate-digest", "reject:WrongCandidateDigest", |i, _e| {
            i.candidate_digest = "wrong-candidate".to_string();
        }),
        ("R15.wrong-sequence", "reject:WrongAuthorityDomainSequence", |i, _e| {
            i.authority_domain_sequence = 99;
        }),
        ("R16.wrong-governance-proof", "reject:WrongGovernanceProofDigest", |i, _e| {
            i.governance_proof_digest = "wrong-proof".to_string();
        }),
        ("R17.wrong-onchain-proof", "reject:WrongOnChainProofDigest", |i, e| {
            i.on_chain_proof_digest = Some("wrong-onchain".to_string());
            e.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
        }),
        ("R18.wrong-custody-attestation", "reject:WrongCustodyAttestationDigest", |i, e| {
            i.custody_attestation_digest = Some("wrong-custody".to_string());
            e.expected_custody_attestation_digest = Some("expected-custody".to_string());
        }),
        ("R19.wrong-proposal-id", "reject:WrongProposalId", |i, _e| {
            i.proposal_id = "wrong-proposal".to_string();
        }),
        ("R20.wrong-decision-id", "reject:WrongDecisionId", |i, _e| {
            i.decision_id = "wrong-decision".to_string();
        }),
        ("R21.wrong-effective-epoch", "reject:WrongEffectiveEpoch", |i, _e| {
            i.effective_epoch = 101;
        }),
    ];
    for (id, expected, mutate) in wrong_input_cases {
        let mut input = rotate_input(env);
        let mut exp = rotate_expectations(env);
        mutate(&mut input, &mut exp);
        let outcome = eval_fixture(&input, &rotate_decision(), &exp, env);
        t.check(id, expected, outcome_tag(&outcome));
    }

    // R22 — expired decision rejected.
    {
        let mut exp = rotate_expectations(env);
        exp.now_epoch = 250; // past expiry_epoch (200)
        let outcome = eval_fixture(&rotate_input(env), &rotate_decision(), &exp, env);
        t.check("R22.expired-decision", "reject:ExpiredDecision", outcome_tag(&outcome));
    }

    // R23 — stale / replayed decision rejected.
    {
        let mut input = rotate_input(env);
        input.replay_nonce = "stale-nonce".to_string();
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R23.stale-replayed", "reject:StaleOrReplayedDecision", outcome_tag(&outcome));
    }

    // R24 — quorum threshold insufficient rejected.
    {
        let mut input = rotate_input(env);
        input.quorum = GovernanceQuorumThreshold::new(2, 5, 3);
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R24.quorum-insufficient", "reject:QuorumThresholdInsufficient", outcome_tag(&outcome));
    }

    // R25 — emergency action not authorized rejected.
    {
        let mut decision = emergency_decision();
        decision.emergency_flag = false;
        let outcome = evaluate_governance_execution_policy(
            &emergency_input(env),
            &decision,
            &emergency_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        );
        t.check("R25.emergency-not-authorized", "reject:EmergencyActionNotAuthorized", outcome_tag(&outcome));
    }

    // R26 — validator-set rotation unsupported rejected.
    {
        let mut input = rotate_input(env);
        input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R26.validator-set-rotation", "reject:ValidatorSetRotationUnsupported", outcome_tag(&outcome));
        t.assert_true("R26.helper", validator_set_rotation_remains_unsupported(), "");
    }

    // R27 — policy-change action unsupported rejected (all four placeholders).
    {
        let mut all_ok = true;
        for action in [
            GovernanceAction::PolicyChangeRequest,
            GovernanceAction::CustodyPolicyChangeRequest,
            GovernanceAction::RemoteSignerPolicyChangeRequest,
            GovernanceAction::CustodyAttestationPolicyChangeRequest,
        ] {
            let mut input = rotate_input(env);
            input.governance_action = action;
            let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
            all_ok &= matches!(outcome, GovernanceExecutionOutcome::PolicyChangeActionUnsupported);
        }
        t.assert_true("R27.policy-change-unsupported", all_ok, "");
    }

    // R28 — malformed governance execution input rejected.
    {
        let mut input = rotate_input(env);
        input.proposal_id = String::new();
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R28.malformed-input", "reject:MalformedExecutionInput", outcome_tag(&outcome));
    }

    // R29 — malformed governance execution decision rejected.
    {
        let mut decision = rotate_decision();
        decision.decision_commitment = GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL.to_string();
        let outcome = eval_fixture(&rotate_input(env), &decision, &rotate_expectations(env), env);
        t.check("R29.malformed-decision", "reject:MalformedExecutionDecision", outcome_tag(&outcome));
    }

    // R30 — unsupported governance execution version rejected.
    {
        let mut input = rotate_input(env);
        input.execution_version = 99;
        let outcome = eval_fixture(&input, &rotate_decision(), &rotate_expectations(env), env);
        t.check("R30.unsupported-version", "reject:UnsupportedGovernanceExecutionVersion", outcome_tag(&outcome));
    }

    // R31 — local operator cannot satisfy governance execution.
    {
        t.assert_true("R31.local-operator", local_operator_cannot_satisfy_governance_execution(), "");
    }

    // R32 — peer majority cannot satisfy governance execution.
    {
        t.assert_true("R32.peer-majority", peer_majority_cannot_satisfy_governance_execution(), "");
    }

    // R33 — governance valid but lifecycle action mismatch rejected (input
    // requests Revoke, decision authorizes Rotate).
    {
        let mut input = rotate_input(env);
        input.governance_action = GovernanceAction::Revoke;
        input.lifecycle_action = LocalLifecycleAction::Revoke;
        let mut exp = rotate_expectations(env);
        exp.expected_governance_action = GovernanceAction::Revoke;
        exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
        let outcome = eval_fixture(&input, &rotate_decision(), &exp, env);
        t.check("R33.lifecycle-action-mismatch", "reject:WrongLifecycleAction", outcome_tag(&outcome));
    }

    // R34 — lifecycle valid but governance decision invalid (not approved).
    {
        let mut decision = rotate_decision();
        decision.approved = false;
        let outcome = eval_fixture(&rotate_input(env), &decision, &rotate_expectations(env), env);
        t.check("R34.decision-not-approved", "reject:GovernanceDecisionRejected", outcome_tag(&outcome));
    }

    // R35 — lifecycle + governance proof + custody valid but production
    // governance execution unavailable rejected.
    {
        let mut input = rotate_input(env);
        input.custody_attestation_digest = Some("custody-attestation-digest".to_string());
        let outcome = evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("R35.production-unavailable-with-valid", "reject:FixtureRejectedProductionRequired", outcome_tag(&outcome));
        t.assert_true("R35.is-reject", outcome.is_reject(), "");
    }

    // R36 — validation-only rejection remains non-mutating: repeated evaluation
    // yields identical results and the input digest is unchanged.
    {
        let input = rotate_input(env);
        let decision = rotate_decision();
        let exp = rotate_expectations(env);
        let td = trust_domain(env);
        let before = input.input_digest();
        let o1 = evaluate_governance_execution_policy(
            &input,
            &decision,
            &exp,
            &td,
            GovernanceExecutionPolicy::Disabled,
        );
        let o2 = evaluate_governance_execution_policy(
            &input,
            &decision,
            &exp,
            &td,
            GovernanceExecutionPolicy::Disabled,
        );
        t.assert_true(
            "R36.validation-only-non-mutating",
            o1 == o2 && before == input.input_digest(),
            "",
        );
    }

    // R37 — mutating preflight rejection produces no Run 070 call, no live trust
    // swap, no session eviction, no sequence write, no marker write. The
    // composition guard performs no I/O and returns a value type; a rejected
    // preflight cannot mutate.
    {
        let mut decision = rotate_decision();
        decision.approved = false;
        let composed = evaluate_governance_execution_with_peer_driven_guard(
            &rotate_input(env),
            &decision,
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            true,
        );
        t.check(
            "R37.mutating-preflight-rejected",
            "rejected:reject:GovernanceDecisionRejected",
            &composed_tag(&composed),
        );
    }

    // R38 — MainNet peer-driven apply remains refused even with fixture approval.
    {
        let menv = Env::Mainnet;
        let composed = evaluate_governance_execution_with_peer_driven_guard(
            &rotate_input(menv),
            &rotate_decision(),
            &rotate_expectations(menv),
            &trust_domain(menv),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            true,
        );
        t.check("R38.mainnet-peer-driven-refused", "MainNetPeerDrivenApplyRefused", &composed_tag(&composed));
        t.assert_true(
            "R38.helper",
            mainnet_peer_driven_apply_remains_refused_under_governance_execution(Env::Mainnet),
            "",
        );
        // A non-peer-driven fixture path on a MainNet trust domain is still
        // refused as fixture-for-mainnet.
        let direct = evaluate_governance_execution_policy(
            &rotate_input(menv),
            &rotate_decision(),
            &rotate_expectations(menv),
            &trust_domain(menv),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R38.fixture-for-mainnet", "reject:FixtureRejectedForMainNet", outcome_tag(&direct));
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 3 — determinism + composition reachability + MainNet refusal helpers.
// ---------------------------------------------------------------------------

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // Determinism — repeated digests are byte-identical across repeats.
    {
        let env = Env::Devnet;
        let input = rotate_input(env);
        let decision = rotate_decision();
        let mut idig = String::new();
        let mut ddig = String::new();
        let mut tdig = String::new();
        let mut pdig = String::new();
        let mut stable = true;
        for i in 0..8 {
            let id = input.input_digest();
            let dd = decision.decision_digest();
            let td = governance_execution_transcript_digest(&id, &dd);
            let pd = governance_execution_policy_digest(
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
                GovernanceExecutionClass::FixtureGovernance,
            );
            if i == 0 {
                idig = id;
                ddig = dd;
                tdig = td;
                pdig = pd;
            } else {
                stable &= idig == id && ddig == dd && tdig == td && pdig == pd;
            }
        }
        t.assert_true("D1.digests-stable", stable, "");
    }

    // Composition guard accepts a non-peer-driven fixture path on DevNet.
    {
        let env = Env::Devnet;
        let composed = evaluate_governance_execution_with_peer_driven_guard(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            false,
        );
        t.assert_true("C1.guard-accepts-non-peer-devnet", composed.is_accept(), "");
    }

    // Composition guard accepts a peer-driven fixture path on DevNet (only
    // MainNet peer-driven apply is refused).
    {
        let env = Env::Devnet;
        let composed = evaluate_governance_execution_with_peer_driven_guard(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            true,
        );
        t.assert_true("C2.guard-accepts-peer-devnet", composed.is_accept(), "");
    }

    // MainNet refusal helper returns true only on MainNet.
    {
        t.assert_true(
            "M1.mainnet-refused",
            mainnet_peer_driven_apply_remains_refused_under_governance_execution(Env::Mainnet),
            "",
        );
        t.assert_true(
            "M2.devnet-not-refused",
            !mainnet_peer_driven_apply_remains_refused_under_governance_execution(Env::Devnet),
            "",
        );
        t.assert_true(
            "M3.testnet-not-refused",
            !mainnet_peer_driven_apply_remains_refused_under_governance_execution(Env::Testnet),
            "",
        );
    }

    // Fail-closed helpers are grep-verifiable named symbols.
    {
        t.assert_true(
            "F1.fail-closed-helpers",
            local_operator_cannot_satisfy_governance_execution()
                && peer_majority_cannot_satisfy_governance_execution()
                && validator_set_rotation_remains_unsupported(),
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — canonical input/decision/expectations + digests + policy tags.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let env = TrustBundleEnvironment::Devnet;
    let input = rotate_input(env);
    let decision = rotate_decision();

    let input_digest = input.input_digest();
    let decision_digest = decision.decision_digest();
    let transcript_digest = governance_execution_transcript_digest(&input_digest, &decision_digest);

    // Canonical governance-execution input fixture (debug rendering — Run 211
    // input/decision/expectations are not wire types and carry no serde
    // surface; the helper records their debug form + digests).
    write_file(&dir.join("governance_execution_input.txt"), &format!("{input:#?}\n"));
    write_file(&dir.join("governance_execution_decision.txt"), &format!("{decision:#?}\n"));
    write_file(
        &dir.join("governance_execution_expectations.txt"),
        &format!("{:#?}\n", rotate_expectations(env)),
    );

    write_file(&dir.join("input_digest.txt"), &format!("{input_digest}\n"));
    write_file(&dir.join("decision_digest.txt"), &format!("{decision_digest}\n"));
    write_file(&dir.join("transcript_digest.txt"), &format!("{transcript_digest}\n"));

    // Per-policy / per-class policy digests.
    let mut policy = String::new();
    for (p, c) in [
        (
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance,
        ),
        (
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
            GovernanceExecutionClass::EmergencyCouncilFixture,
        ),
        (
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
        ),
        (
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
        ),
        (
            GovernanceExecutionPolicy::Disabled,
            GovernanceExecutionClass::Disabled,
        ),
    ] {
        policy.push_str(&format!(
            "policy\t{}\tclass\t{}\tpolicy_digest\t{}\n",
            p.tag(),
            c.tag(),
            governance_execution_policy_digest(p, c)
        ));
    }
    write_file(&dir.join("policy_digests.txt"), &policy);

    // Canonical action / class / policy tag tables.
    let mut tags = String::new();
    for a in [
        GovernanceAction::AuthoritySigningKeyInitialActivation,
        GovernanceAction::Rotate,
        GovernanceAction::Retire,
        GovernanceAction::Revoke,
        GovernanceAction::EmergencyRevoke,
        GovernanceAction::PolicyChangeRequest,
        GovernanceAction::CustodyPolicyChangeRequest,
        GovernanceAction::RemoteSignerPolicyChangeRequest,
        GovernanceAction::CustodyAttestationPolicyChangeRequest,
        GovernanceAction::ValidatorSetRotationRequest,
        GovernanceAction::Unknown,
    ] {
        tags.push_str(&format!("action\t{}\t{:?}\n", a.tag(), a));
    }
    write_file(&dir.join("action_tags.txt"), &tags);
}

fn main() {
    let mut args = env::args().skip(1);
    let out_dir = match args.next() {
        Some(a) => PathBuf::from(a),
        None => {
            eprintln!(
                "usage: run_212_governance_execution_policy_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("create out dir {out_dir:?}: {e}"));

    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("reachability", run_reachability_table),
    ];

    let mut total_pass = 0u64;
    let mut total_fail = 0u64;
    let mut summary = String::new();
    summary.push_str("run_212_governance_execution_policy_release_binary_helper\n");
    summary.push_str(
        "scope: Run 211 governance execution policy boundary (pure evaluators, digest helpers, composition + fail-closed helpers) exercised in release mode through the production library symbols\n",
    );
    summary.push_str(
        "note: fixture-only; no real governance execution engine; no real on-chain governance proof verifier; no real KMS/HSM/RemoteSigner backend; no validator-set rotation; no live trust mutation; no P2P socket; production / on-chain / MainNet governance execution fails closed as unavailable; MainNet peer-driven apply remains refused\n\n",
    );
    for (name, f) in tables {
        let (pass, fail) = f(&out_dir);
        total_pass += pass;
        total_fail += fail;
        summary.push_str(&format!("table {name}: pass={pass} fail={fail}\n"));
    }

    run_fixture_dump(&out_dir);

    summary.push_str(&format!("\ntotal_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };
    summary.push_str(&format!("verdict: {verdict}\n"));
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if total_fail != 0 {
        std::process::exit(1);
    }
}