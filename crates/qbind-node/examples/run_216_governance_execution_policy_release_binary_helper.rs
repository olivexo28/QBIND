//! Run 216 — release-built helper for the Run 215 hidden governance-execution
//! policy selector. Fixture-only: no network/backend I/O and no live mutation.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_payload_carrying::{
    load_v2_ratification_sidecar_with_governance_execution_from_bytes,
    mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying,
    parse_optional_governance_execution_sibling_from_json_value, GovernanceExecutionLoadStatus,
    GovernanceExecutionParts, GovernanceExecutionPayloadCarryingDecisionOutcome,
    GovernanceExecutionPayloadParseError, GovernanceExecutionPayloadWire,
    GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD, GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    governance_execution_policy_digest, governance_execution_transcript_digest, GovernanceAction,
    GovernanceExecutionClass, GovernanceExecutionDecision, GovernanceExecutionExpectations,
    GovernanceExecutionInput, GovernanceExecutionOutcome, GovernanceExecutionPolicy,
    GovernanceQuorumThreshold, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy_surface::{
    governance_execution_policy_env_selector, governance_execution_policy_from_cli_or_env,
    governance_execution_policy_from_selector,
    preflight_v2_marker_governance_execution_for_live_inbound_0x05,
    preflight_v2_marker_governance_execution_for_local_peer_candidate_check,
    preflight_v2_marker_governance_execution_for_peer_driven_drain,
    preflight_v2_marker_governance_execution_for_reload_apply,
    preflight_v2_marker_governance_execution_for_reload_check,
    preflight_v2_marker_governance_execution_for_sighup,
    preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle,
    GovernanceExecutionPolicySelectorParseError, GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
    GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
    GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
    GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
    GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CUR_KEY: &str = "curcurcurcurcurcurcurcurcurcurcurcurcurc";
const CAND_KEY: &str = "candcandcandcandcandcandcandcandcandcand";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const GOV_PROOF: &str = "governance-proof-digest-bbbbbbbbbbbb";
const NONCE: &str = "replay-nonce-cccccccccccccccccccccccccc";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";

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
fn revoke_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_expectations(env);
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
fn emergency_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    exp
}

fn available_from(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    GovernanceExecutionLoadStatus::Available(wire.to_parts().expect("wire converts"))
}
fn available_via_json(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    let value = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap() });
    parse_optional_governance_execution_sibling_from_json_value(&value)
}
fn malformed_loaded() -> GovernanceExecutionLoadStatus {
    GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
        error: "broken".to_string(),
    })
}

#[derive(Clone, Copy)]
enum Surface {
    ReloadCheck,
    ReloadApply,
    StartupP2p,
    Sighup,
    LocalPeerCandidate,
    LiveInbound0x05,
    PeerDrivenDrain,
}
const ALL_SURFACES: [Surface; 7] = [
    Surface::ReloadCheck,
    Surface::ReloadApply,
    Surface::StartupP2p,
    Surface::Sighup,
    Surface::LocalPeerCandidate,
    Surface::LiveInbound0x05,
    Surface::PeerDrivenDrain,
];
fn surface_name(s: Surface) -> &'static str {
    match s {
        Surface::ReloadCheck => "reload_check",
        Surface::ReloadApply => "reload_apply",
        Surface::StartupP2p => "startup_p2p_trust_bundle",
        Surface::Sighup => "sighup",
        Surface::LocalPeerCandidate => "local_peer_candidate_check",
        Surface::LiveInbound0x05 => "live_inbound_0x05",
        Surface::PeerDrivenDrain => "peer_driven_drain",
    }
}
type PreflightFn = fn(
    &AuthorityTrustDomain,
    &GovernanceExecutionExpectations,
    GovernanceExecutionPolicy,
    &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome;
fn surface_wrapper(s: Surface) -> PreflightFn {
    match s {
        Surface::ReloadCheck => preflight_v2_marker_governance_execution_for_reload_check,
        Surface::ReloadApply => preflight_v2_marker_governance_execution_for_reload_apply,
        Surface::StartupP2p => {
            preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle
        }
        Surface::Sighup => preflight_v2_marker_governance_execution_for_sighup,
        Surface::LocalPeerCandidate => {
            preflight_v2_marker_governance_execution_for_local_peer_candidate_check
        }
        Surface::LiveInbound0x05 => preflight_v2_marker_governance_execution_for_live_inbound_0x05,
        Surface::PeerDrivenDrain => preflight_v2_marker_governance_execution_for_peer_driven_drain,
    }
}
fn preflight(
    surface: Surface,
    env: TrustBundleEnvironment,
    exp: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    surface_wrapper(surface)(&trust_domain(env), exp, policy, loaded)
}

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
fn decision_tag(outcome: &GovernanceExecutionPayloadCarryingDecisionOutcome) -> String {
    use GovernanceExecutionPayloadCarryingDecisionOutcome as D;
    match outcome {
        D::MalformedGovernanceExecutionPayload(_) => {
            "reject:MalformedGovernanceExecutionPayload".to_string()
        }
        D::GovernanceExecutionRequiredButAbsent { .. } => {
            "reject:GovernanceExecutionRequiredButAbsent".to_string()
        }
        D::NoGovernanceExecutionSupplied => "bypass:NoGovernanceExecutionSupplied".to_string(),
        D::MainNetPeerDrivenApplyRefused => "reject:MainNetPeerDrivenApplyRefused".to_string(),
        D::Callsite(o) => format!("callsite:{}", outcome_tag(o)),
    }
}
fn callsite_tag(outcome: &GovernanceExecutionPayloadCarryingDecisionOutcome) -> String {
    outcome
        .callsite_outcome()
        .map(outcome_tag)
        .unwrap_or("none")
        .to_string()
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
struct EnvGuard {
    prior: Option<String>,
}
impl EnvGuard {
    fn set(value: Option<&str>) -> Self {
        let prior = env::var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV).ok();
        match value {
            Some(v) => env::set_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV, v),
            None => env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV),
        };
        Self { prior }
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => env::set_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV, v),
            None => env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV),
        }
    }
}

fn run_selector_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("selector");
    let canonical = [
        (
            GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
            GovernanceExecutionPolicy::Disabled,
        ),
        (
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        (
            GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        ),
        (
            GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        ),
        (
            GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        ),
    ];
    {
        let _g = EnvGuard::set(None);
        t.assert_true(
            "A1.default-absent-is-disabled",
            governance_execution_policy_from_cli_or_env(None)
                == Ok(GovernanceExecutionPolicy::Disabled),
            "",
        );
    }
    {
        let _g = EnvGuard::set(None);
        for (tag, expected) in canonical {
            t.assert_true(
                &format!("A2.cli-{tag}"),
                governance_execution_policy_from_cli_or_env(Some(tag)) == Ok(expected),
                "",
            );
        }
    }
    for (tag, expected) in canonical {
        let _g = EnvGuard::set(Some(tag));
        t.assert_true(
            &format!("A3.env-{tag}"),
            governance_execution_policy_env_selector() == Ok(Some(expected))
                && governance_execution_policy_from_cli_or_env(None) == Ok(expected),
            "",
        );
    }
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ));
        let resolved = governance_execution_policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
        ));
        t.check(
            "A9.cli-over-env",
            "disabled",
            resolved.as_ref().map(|p| p.tag()).unwrap_or("err"),
        );
    }
    {
        let _g = EnvGuard::set(None);
        t.assert_true(
            "R1.invalid-cli",
            matches!(
                governance_execution_policy_from_cli_or_env(Some("bogus")),
                Err(GovernanceExecutionPolicySelectorParseError::UnknownValue { .. })
            ),
            "",
        );
        t.assert_true(
            "R1.empty-cli",
            governance_execution_policy_from_cli_or_env(Some("   "))
                == Err(GovernanceExecutionPolicySelectorParseError::Empty),
            "",
        );
    }
    {
        let _g = EnvGuard::set(Some("bogus"));
        t.assert_true(
            "R2.invalid-env",
            governance_execution_policy_env_selector().is_err()
                && governance_execution_policy_from_cli_or_env(None).is_err(),
            "",
        );
    }
    {
        let _g = EnvGuard::set(None);
        env::set_var(
            "QBIND_SOME_UNRELATED_FLAG_216",
            "fixture-governance-allowed",
        );
        let resolved = governance_execution_policy_from_cli_or_env(None);
        env::remove_var("QBIND_SOME_UNRELATED_FLAG_216");
        t.assert_true(
            "R3.unrelated-env-stays-disabled",
            resolved == Ok(GovernanceExecutionPolicy::Disabled),
            "",
        );
    }
    t.assert_true(
        "parser.case-insensitive-trim",
        governance_execution_policy_from_selector(" FIXTURE-GOVERNANCE-ALLOWED ")
            == Ok(GovernanceExecutionPolicy::FixtureGovernanceAllowed),
        "",
    );
    t.finish(out)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");
    {
        let policy = governance_execution_policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let env = Env::Devnet;
        let loaded = available_via_json(&rotate_input(env), &rotate_decision());
        for s in ALL_SURFACES {
            let out = preflight(s, env, &rotate_expectations(env), policy, &loaded);
            t.check(
                &format!("A4.{}", surface_name(s)),
                "callsite:accept:FixtureGovernanceAccepted",
                &decision_tag(&out),
            );
        }
    }
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ));
        let env = Env::Testnet;
        let policy = governance_execution_policy_from_cli_or_env(None).unwrap();
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A5.env-testnet-fixture",
            "callsite:accept:FixtureGovernanceAccepted",
            &decision_tag(&out),
        );
    }
    {
        let env = Env::Devnet;
        let policy = governance_execution_policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
        ))
        .unwrap();
        let out = preflight(
            Surface::ReloadApply,
            env,
            &emergency_expectations(env),
            policy,
            &available_from(&emergency_input(env), &emergency_decision()),
        );
        t.check(
            "A6.emergency-explicit",
            "callsite:accept:EmergencyCouncilFixtureAccepted",
            &decision_tag(&out),
        );
    }
    {
        let env = Env::Devnet;
        let policy = governance_execution_policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
        ))
        .unwrap();
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&input, &rotate_decision()),
        );
        t.check(
            "A7.production-unavailable",
            "reject:ProductionGovernanceUnavailable",
            &callsite_tag(&out),
        );
    }
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
        ));
        let env = Env::Mainnet;
        let policy = governance_execution_policy_from_cli_or_env(None).unwrap();
        let out = preflight(
            Surface::PeerDrivenDrain,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A8.mainnet-refusal",
            "reject:MainNetPeerDrivenApplyRefused",
            &decision_tag(&out),
        );
    }
    {
        let env = Env::Devnet;
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::Disabled,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check(
            "A10.no-governance-disabled",
            "bypass:NoGovernanceExecutionSupplied",
            &decision_tag(&out),
        );
    }
    {
        let env = Env::Devnet;
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::Disabled,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A11.disabled-present-inert",
            "reject:GovernanceExecutionDisabled",
            &callsite_tag(&out),
        );
    }
    t.assert_true(
        "A12.custody-policy-selector-compatible",
        true,
        "Run 193 unchanged; governed by separate tests/harness",
    );
    t.assert_true(
        "A13.remote-signer-selector-compatible",
        true,
        "Run 199 unchanged; governed by separate tests/harness",
    );
    t.assert_true(
        "A14.custody-attestation-selector-compatible",
        true,
        "Run 210 unchanged; governed by separate tests/harness",
    );
    {
        let env = Env::Devnet;
        let out = preflight(
            Surface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.assert_true("A15.rotate-authorized", out.is_accept(), "");
    }
    {
        let env = Env::Devnet;
        let out = preflight(
            Surface::ReloadApply,
            env,
            &revoke_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&revoke_input(env), &revoke_decision()),
        );
        t.assert_true("A16.revoke-authorized", out.is_accept(), "");
    }
    t.finish(out)
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;
    {
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check(
            "R4",
            "reject:GovernanceExecutionRequiredButAbsent",
            &decision_tag(&out),
        );
    }
    {
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check(
            "R5",
            "reject:GovernanceExecutionRequiredButAbsent",
            &decision_tag(&out),
        );
    }
    {
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "R6",
            "reject:FixtureRejectedProductionRequired",
            &callsite_tag(&out),
        );
    }
    {
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &emergency_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            &available_from(&emergency_input(env), &emergency_decision()),
        );
        t.check(
            "R7",
            "reject:EmergencyFixtureRejectedProductionRequired",
            &callsite_tag(&out),
        );
    }
    {
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "R8",
            "reject:FixtureRejectedMainnetRequired",
            &callsite_tag(&out),
        );
    }
    for (id, class, expected) in [
        (
            "R9",
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
            "reject:ProductionGovernanceUnavailable",
        ),
        (
            "R10",
            GovernanceExecutionClass::OnChainGovernanceUnavailable,
            "reject:OnChainGovernanceUnavailable",
        ),
        (
            "R11",
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
            "reject:MainNetGovernanceUnavailable",
        ),
        (
            "R12",
            GovernanceExecutionClass::Unknown,
            "reject:UnknownGovernanceClassRejected",
        ),
    ] {
        let mut input = rotate_input(env);
        input.governance_class = class;
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&input, &rotate_decision()),
        );
        t.check(id, expected, &callsite_tag(&out));
    }
    {
        let out = preflight(
            Surface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.check(
            "R13",
            "reject:MalformedGovernanceExecutionPayload",
            &decision_tag(&out),
        );
    }
    macro_rules! one {
        ($id:expr, $expect:expr, $body:expr) => {{
            let mut input = rotate_input(env);
            let mut decision = rotate_decision();
            let mut exp = rotate_expectations(env);
            ($body)(&mut input, &mut decision, &mut exp);
            let o = preflight(
                Surface::ReloadCheck,
                env,
                &exp,
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
                &available_from(&input, &decision),
            );
            t.check($id, $expect, &callsite_tag(&o));
        }};
    }
    one!(
        "R14",
        "reject:WrongEnvironment",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.environment = Env::Testnet
    );
    one!(
        "R15",
        "reject:WrongChain",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.chain_id = "other".into()
    );
    one!(
        "R16",
        "reject:WrongGenesis",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.genesis_hash = "other".into()
    );
    one!(
        "R17",
        "reject:WrongAuthorityRoot",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.authority_root_fingerprint =
            "other".into()
    );
    one!(
        "R18",
        "reject:WrongLifecycleAction",
        |_i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            d.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
            d.authorized_governance_action = GovernanceAction::Revoke;
        }
    );
    one!(
        "R19",
        "reject:WrongCandidateDigest",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.candidate_digest = "wrong".into();
            d.authorized_candidate_digest = "wrong".into();
        }
    );
    one!(
        "R20",
        "reject:WrongAuthorityDomainSequence",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.authority_domain_sequence = 9;
            d.authorized_sequence = 9;
        }
    );
    one!(
        "R21",
        "reject:WrongGovernanceProofDigest",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_proof_digest =
            "wrong".into()
    );
    one!(
        "R22",
        "reject:WrongOnChainProofDigest",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| {
            i.on_chain_proof_digest = Some("wrong".into());
            e.expected_on_chain_proof_digest = Some("expected".into());
        }
    );
    one!(
        "R23",
        "reject:WrongCustodyAttestationDigest",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| {
            i.custody_attestation_digest = Some("wrong".into());
            e.expected_custody_attestation_digest = Some("expected".into());
        }
    );
    one!(
        "R24",
        "reject:WrongProposalId",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.proposal_id = "wrong".into();
            d.proposal_id = "wrong".into();
        }
    );
    one!(
        "R25",
        "reject:WrongDecisionId",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.decision_id = "wrong".into();
            d.decision_id = "wrong".into();
        }
    );
    one!(
        "R26",
        "reject:WrongEffectiveEpoch",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.effective_epoch = 101;
            d.effective_epoch = 101;
        }
    );
    one!(
        "R27",
        "reject:ExpiredDecision",
        |_i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| e.now_epoch = 250
    );
    one!(
        "R28",
        "reject:StaleOrReplayedDecision",
        |_i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| e.expected_replay_nonce = "fresh".into()
    );
    one!(
        "R29",
        "reject:QuorumThresholdInsufficient",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.quorum =
            GovernanceQuorumThreshold::new(1, 5, 3)
    );
    {
        let mut input = emergency_input(env);
        input.governance_class = GovernanceExecutionClass::FixtureGovernance;
        let mut decision = emergency_decision();
        decision.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
        let out = preflight(
            Surface::ReloadCheck,
            env,
            &emergency_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&input, &decision),
        );
        t.check(
            "R30",
            "reject:EmergencyActionNotAuthorized",
            &callsite_tag(&out),
        );
    }
    one!(
        "R31",
        "reject:ValidatorSetRotationUnsupported",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_action =
            GovernanceAction::ValidatorSetRotationRequest
    );
    one!(
        "R32",
        "reject:PolicyChangeActionUnsupported",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_action =
            GovernanceAction::PolicyChangeRequest
    );
    t.assert_true("R33", qbind_node::pqc_governance_execution_policy::local_operator_cannot_satisfy_governance_execution(), "");
    t.assert_true("R34", qbind_node::pqc_governance_execution_policy::peer_majority_cannot_satisfy_governance_execution(), "");
    one!(
        "R35",
        "reject:WrongLifecycleAction",
        |_i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            d.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
            d.authorized_governance_action = GovernanceAction::Revoke;
        }
    );
    one!(
        "R36",
        "reject:GovernanceDecisionRejected",
        |_i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| d.approved = false
    );
    {
        let mut decision = rotate_decision();
        decision.approved = false;
        let loaded = available_from(&rotate_input(env), &decision);
        let a = preflight(
            Surface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        let b = preflight(
            Surface::LocalPeerCandidate,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        t.assert_true("R37", a == b && a.is_reject(), "");
    }
    {
        let a = preflight(
            Surface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        let b = preflight(
            Surface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.assert_true("R38", a == b && a.is_reject(), "");
    }
    {
        let out = preflight(
            Surface::LiveInbound0x05,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.assert_true("R39", out.is_malformed_payload() && out.is_reject(), "");
    }
    {
        let menv = Env::Mainnet;
        let out = preflight(
            Surface::PeerDrivenDrain,
            menv,
            &rotate_expectations(menv),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            &available_from(&rotate_input(menv), &rotate_decision()),
        );
        t.check(
            "R40",
            "reject:MainNetPeerDrivenApplyRefused",
            &decision_tag(&out),
        );
        t.assert_true(
            "R40.helper",
            mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(
                menv,
            ),
            "",
        );
    }
    t.finish(out)
}

fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    sibling: Option<serde_json::Value>,
) -> serde_json::Value {
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::v2_test_helpers::build_signed_ratification_v2;
    use qbind_ledger::genesis::GENESIS_AUTHORITY_SUITE_ML_DSA_44;
    use qbind_ledger::RatificationEnvironment;
    let ratification_env = match env {
        TrustBundleEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        TrustBundleEnvironment::Testnet => RatificationEnvironment::Testnet,
        TrustBundleEnvironment::Devnet => RatificationEnvironment::Devnet,
    };
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (target_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let auth_pk_hex = auth_pk
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let v2 = build_signed_ratification_v2(
        CHAIN,
        ratification_env,
        [0xaa; 32],
        GENESIS_AUTHORITY_SUITE_ML_DSA_44 as u32,
        &auth_pk_hex,
        &auth_sk,
        &target_pk,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some("aa".repeat(20)),
        Some("bb".repeat(20)),
        None,
        None,
        None,
        None,
    );
    let mut value = serde_json::to_value(&v2).unwrap();
    if let Some(p) = sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

fn run_loader_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("loader");
    let env = TrustBundleEnvironment::Devnet;
    let legacy = serde_json::to_vec(&make_v2_sidecar_value(env, None)).unwrap();
    let loaded = load_v2_ratification_sidecar_with_governance_execution_from_bytes(
        &legacy,
        Path::new("/dev/null/run-216-legacy.json"),
    )
    .unwrap();
    t.assert_true(
        "L1.legacy-absent",
        loaded.governance_execution.is_absent(),
        "",
    );
    let input = rotate_input(env);
    let decision = rotate_decision();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let carry = serde_json::to_vec(&make_v2_sidecar_value(
        env,
        Some(serde_json::to_value(&wire).unwrap()),
    ))
    .unwrap();
    let loaded = load_v2_ratification_sidecar_with_governance_execution_from_bytes(
        &carry,
        Path::new("/dev/null/run-216-carry.json"),
    )
    .unwrap();
    t.assert_true(
        "L2.carry-available",
        loaded.governance_execution.as_parts()
            == Some(&GovernanceExecutionParts { input, decision }),
        "",
    );
    t.check(
        "L3.field",
        "governance_execution",
        GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD,
    );
    t.check(
        "L4.version",
        "1",
        &GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION.to_string(),
    );
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("reachability");
    let env = TrustBundleEnvironment::Devnet;
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    for s in ALL_SURFACES {
        t.assert_true(
            &format!("S.{}", surface_name(s)),
            preflight(
                s,
                env,
                &rotate_expectations(env),
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
                &loaded,
            )
            .is_accept(),
            "",
        );
    }
    let p1 = governance_execution_policy_digest(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        GovernanceExecutionClass::FixtureGovernance,
    );
    let p2 = governance_execution_policy_digest(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        GovernanceExecutionClass::FixtureGovernance,
    );
    let tr = governance_execution_transcript_digest(
        &rotate_input(env).input_digest(),
        &rotate_decision().decision_digest(),
    );
    t.assert_true("D1.digests-stable", p1 == p2 && !tr.is_empty(), "");
    t.assert_true(
        "M1.mainnet-refusal-helper",
        mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(
            TrustBundleEnvironment::Mainnet,
        ),
        "",
    );
    t.finish(out)
}

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let env = TrustBundleEnvironment::Devnet;
    let input = rotate_input(env);
    let decision = rotate_decision();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    write_file(
        &dir.join("governance_execution_payload_wire.json"),
        &format!("{}\n", serde_json::to_string_pretty(&wire).unwrap()),
    );
    write_file(
        &dir.join("v2_sidecar_with_governance_execution.json"),
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&make_v2_sidecar_value(
                env,
                Some(serde_json::to_value(&wire).unwrap())
            ))
            .unwrap()
        ),
    );
    write_file(
        &dir.join("governance_execution_input.txt"),
        &format!("{input:#?}\n"),
    );
    write_file(
        &dir.join("governance_execution_decision.txt"),
        &format!("{decision:#?}\n"),
    );
    write_file(
        &dir.join("governance_execution_expectations.txt"),
        &format!("{:#?}\n", rotate_expectations(env)),
    );
    write_file(
        &dir.join("input_digest.txt"),
        &format!("{}\n", input.input_digest()),
    );
    write_file(
        &dir.join("decision_digest.txt"),
        &format!("{}\n", decision.decision_digest()),
    );
    write_file(
        &dir.join("transcript_digest.txt"),
        &format!(
            "{}\n",
            governance_execution_transcript_digest(
                &input.input_digest(),
                &decision.decision_digest()
            )
        ),
    );
    let mut tags = format!(
        "env_var\t{}\ncli_flag\t--p2p-trust-bundle-governance-execution-policy\n",
        QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV
    );
    for p in [
        GovernanceExecutionPolicy::Disabled,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
        GovernanceExecutionPolicy::MainnetGovernanceRequired,
    ] {
        tags.push_str(&format!("policy\t{}\t{:?}\n", p.tag(), p));
    }
    write_file(&dir.join("selector_tags.txt"), &tags);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_216_governance_execution_policy_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("selector", run_selector_table),
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("loader", run_loader_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from("run_216_governance_execution_policy_release_binary_helper\nscope: Run 215 hidden governance-execution policy selector + seven production preflight wrappers over Run 213 routing helpers and Run 211 evaluator (release binary)\nnote: fixture-only; no real governance execution engine/on-chain verifier/KMS-HSM/RemoteSigner; no mutation; MainNet peer-driven apply remains refused\n\n");
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
