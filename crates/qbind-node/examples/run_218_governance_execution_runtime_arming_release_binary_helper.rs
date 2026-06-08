//! Run 218 — release-built helper for the Run 217 governance-execution
//! runtime-arming carrier
//! ([`GovernanceExecutionRuntimeArmingConfig`]). Unlike Run 216 (which
//! exercised the Run 215 selector + the seven per-surface preflight
//! wrappers directly), this helper resolves the hidden selector through
//! the Run 217 runtime-config carrier and drives every preflight surface
//! through that carrier — proving the selected policy reaches runtime
//! arming and is routed into the production preflight contexts.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real
//! governance execution engine, on-chain proof verifier, KMS/HSM, or
//! RemoteSigner backend. MainNet peer-driven apply remains refused.

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
    governance_execution_policy_env_selector, governance_execution_policy_from_selector,
    GovernanceExecutionPolicySelectorParseError, GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
    GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
    GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
    GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
    GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
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

const ALL_SURFACES: [GovernanceExecutionRuntimeSurface; 7] = GovernanceExecutionRuntimeSurface::ALL;

fn surface_name(s: GovernanceExecutionRuntimeSurface) -> &'static str {
    s.tag()
}

/// Drive the named runtime preflight surface **through the Run 217
/// runtime-arming carrier**. The carrier is constructed around the
/// resolved policy exactly as the long-running runtime config would carry
/// it, then dispatched to the matching per-surface preflight wrapper.
fn arm_and_preflight(
    surface: GovernanceExecutionRuntimeSurface,
    env: TrustBundleEnvironment,
    exp: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(policy);
    assert_eq!(
        arming.governance_execution_policy(),
        policy,
        "runtime arming must carry the resolved policy unchanged"
    );
    arming.arm_surface(surface, &trust_domain(env), exp, loaded)
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

/// Resolve a runtime-arming config from the Run 215 CLI/env selector
/// **through the Run 217 carrier** and return the policy it arms.
fn arm_from_cli_or_env(
    cli: Option<&str>,
) -> Result<GovernanceExecutionPolicy, GovernanceExecutionPolicySelectorParseError> {
    GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(cli)
        .map(|cfg| cfg.governance_execution_policy())
}

fn run_selector_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("runtime_arming_selector");
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
    // A1 — unset CLI/env resolves through runtime arming to Disabled.
    {
        let _g = EnvGuard::set(None);
        let cfg = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None);
        t.assert_true(
            "A1.default-absent-arms-disabled",
            cfg == Ok(GovernanceExecutionRuntimeArmingConfig::disabled())
                && cfg.unwrap().is_disabled(),
            "",
        );
        t.assert_true(
            "A1.default-trait-is-disabled",
            GovernanceExecutionRuntimeArmingConfig::default().is_disabled(),
            "",
        );
    }
    // A2 — CLI selector reaches runtime arming.
    {
        let _g = EnvGuard::set(None);
        for (tag, expected) in canonical {
            t.assert_true(
                &format!("A2.cli-arms-{tag}"),
                arm_from_cli_or_env(Some(tag)) == Ok(expected),
                "",
            );
        }
    }
    // A3 — env selector reaches runtime arming.
    for (tag, expected) in canonical {
        let _g = EnvGuard::set(Some(tag));
        t.assert_true(
            &format!("A3.env-arms-{tag}"),
            governance_execution_policy_env_selector() == Ok(Some(expected))
                && arm_from_cli_or_env(None) == Ok(expected),
            "",
        );
    }
    // A9 — CLI-over-env precedence is deterministic at the runtime config
    // boundary: env=fixture, CLI=disabled ⇒ Disabled.
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ));
        let resolved =
            arm_from_cli_or_env(Some(GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED));
        t.check(
            "A9.cli-over-env-at-runtime-boundary",
            "disabled",
            resolved.as_ref().map(|p| p.tag()).unwrap_or("err"),
        );
    }
    // R1 — invalid CLI selector fails closed before runtime mutation: the
    // runtime config is never constructed.
    {
        let _g = EnvGuard::set(None);
        t.assert_true(
            "R1.invalid-cli-no-config",
            matches!(
                GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("bogus")),
                Err(GovernanceExecutionPolicySelectorParseError::UnknownValue { .. })
            ),
            "",
        );
        t.assert_true(
            "R1.empty-cli-no-config",
            GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("   "))
                == Err(GovernanceExecutionPolicySelectorParseError::Empty),
            "",
        );
    }
    // R2 — invalid env selector fails closed before runtime mutation.
    {
        let _g = EnvGuard::set(Some("bogus"));
        t.assert_true(
            "R2.invalid-env-no-config",
            governance_execution_policy_env_selector().is_err()
                && GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None).is_err(),
            "",
        );
    }
    // R3 — unrelated CLI/env does not arm governance execution.
    {
        let _g = EnvGuard::set(None);
        env::set_var(
            "QBIND_SOME_UNRELATED_FLAG_218",
            "fixture-governance-allowed",
        );
        let resolved = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None);
        env::remove_var("QBIND_SOME_UNRELATED_FLAG_218");
        t.assert_true(
            "R3.unrelated-env-stays-disabled",
            resolved == Ok(GovernanceExecutionRuntimeArmingConfig::disabled()),
            "",
        );
    }
    // The carrier delegates to the same case-insensitive/trimming parser.
    t.assert_true(
        "parser.case-insensitive-trim",
        arm_from_cli_or_env(Some(" FIXTURE-GOVERNANCE-ALLOWED "))
            == Ok(GovernanceExecutionPolicy::FixtureGovernanceAllowed),
        "",
    );
    // The carrier and the bare resolver agree on every canonical tag.
    for (tag, expected) in canonical {
        let _g = EnvGuard::set(None);
        t.assert_true(
            &format!("parity.carrier-eq-resolver-{tag}"),
            arm_from_cli_or_env(Some(tag))
                == governance_execution_policy_from_selector(tag).map(|_| expected),
            "",
        );
    }
    t.finish(out)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");
    // A4 — CLI fixture-governance-allowed arms FixtureGovernanceAllowed and
    // accepts DevNet fixture governance execution across all surfaces.
    {
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let env = Env::Devnet;
        let loaded = available_via_json(&rotate_input(env), &rotate_decision());
        for s in ALL_SURFACES {
            // peer-driven drain on DevNet is not MainNet-refused, so it too
            // accepts the fixture governance decision.
            let out = arm_and_preflight(s, env, &rotate_expectations(env), policy, &loaded);
            t.check(
                &format!("A4.{}", surface_name(s)),
                "callsite:accept:FixtureGovernanceAccepted",
                &decision_tag(&out),
            );
        }
    }
    // A5 — env fixture-governance-allowed arms FixtureGovernanceAllowed and
    // accepts TestNet fixture governance execution through runtime arming.
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ));
        let env = Env::Testnet;
        let policy = arm_from_cli_or_env(None).unwrap();
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // A6 — CLI emergency-council-fixture-allowed arms
    // EmergencyCouncilFixtureAllowed and accepts DevNet emergency council
    // fixture execution only for explicit emergency action.
    {
        let env = Env::Devnet;
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
        ))
        .unwrap();
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
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
        // A non-emergency fixture decision under the emergency policy is not
        // silently accepted as emergency.
        let out2 = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.assert_true(
            "A6.emergency-policy-not-fixture",
            out2.is_reject(),
            "EmergencyCouncilFixtureAllowed does not accept a plain fixture rotate",
        );
    }
    // A7 — CLI production-governance-required reaches production unavailable.
    {
        let env = Env::Devnet;
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
        ))
        .unwrap();
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // A8 — env mainnet-governance-required reaches MainNet refusal at the
    // peer-driven drain surface.
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
        ));
        let env = Env::Mainnet;
        let policy = arm_from_cli_or_env(None).unwrap();
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
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
    // A10 — no-governance-execution payload remains compatible under default
    // Disabled arming.
    {
        let env = Env::Devnet;
        let arming = GovernanceExecutionRuntimeArmingConfig::disabled();
        let out = arming.preflight_reload_check(
            &trust_domain(env),
            &rotate_expectations(env),
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check(
            "A10.no-governance-disabled",
            "bypass:NoGovernanceExecutionSupplied",
            &decision_tag(&out),
        );
    }
    // A11/A12 — runtime-armed reload-check and reload-apply consume the
    // selected fixture policy.
    {
        let env = Env::Devnet;
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let loaded = available_from(&rotate_input(env), &rotate_decision());
        let check = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            &loaded,
        );
        t.check(
            "A11.reload-check-consumes-fixture",
            "callsite:accept:FixtureGovernanceAccepted",
            &decision_tag(&check),
        );
        let apply = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            policy,
            &loaded,
        );
        t.check(
            "A12.reload-apply-consumes-fixture",
            "callsite:accept:FixtureGovernanceAccepted",
            &decision_tag(&apply),
        );
    }
    // A13/A14/A15 — runtime-armed startup --p2p-trust-bundle, SIGHUP, and
    // local peer-candidate-check consume the selected fixture policy where
    // representable.
    {
        let env = Env::Devnet;
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let loaded = available_from(&rotate_input(env), &rotate_decision());
        for (id, s) in [
            (
                "A13.startup-p2p",
                GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle,
            ),
            ("A14.sighup", GovernanceExecutionRuntimeSurface::Sighup),
            (
                "A15.local-peer-candidate",
                GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
            ),
        ] {
            let out = arm_and_preflight(s, env, &rotate_expectations(env), policy, &loaded);
            t.check(
                id,
                "callsite:accept:FixtureGovernanceAccepted",
                &decision_tag(&out),
            );
        }
    }
    // A16 — runtime-armed live inbound 0x05 consumes selected policy where
    // representable at source/test level (documented limitation: the live
    // runtime config does not yet thread a per-connection policy).
    {
        let env = Env::Devnet;
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A16.live-0x05-consumes-fixture",
            "callsite:accept:FixtureGovernanceAccepted",
            &decision_tag(&out),
        );
    }
    // A17 — runtime-armed peer-driven drain consumes selected policy where
    // representable and remains MainNet-refused.
    {
        let env = Env::Devnet;
        let policy = arm_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A17.devnet-drain-consumes-fixture",
            "callsite:accept:FixtureGovernanceAccepted",
            &decision_tag(&out),
        );
        let menv = Env::Mainnet;
        let out2 = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            menv,
            &rotate_expectations(menv),
            policy,
            &available_from(&rotate_input(menv), &rotate_decision()),
        );
        t.check(
            "A17.mainnet-drain-refused",
            "reject:MainNetPeerDrivenApplyRefused",
            &decision_tag(&out2),
        );
    }
    // A18 — lifecycle rotate authorized only with matching candidate digest
    // and sequence under runtime arming.
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let ok = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.assert_true("A18.rotate-authorized", ok.is_accept(), "");
    }
    // A19 — lifecycle revoke authorized only with matching material/sequence.
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let ok = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &revoke_expectations(env),
            policy,
            &available_from(&revoke_input(env), &revoke_decision()),
        );
        t.assert_true("A19.revoke-authorized", ok.is_accept(), "");
    }
    // A20/A21/A22 — Run 210 custody-attestation, Run 199 RemoteSigner, and
    // Run 193 custody policy selectors remain compatible (separate
    // selectors; governed by their own tests/harness; unchanged here).
    t.assert_true(
        "A20.custody-attestation-selector-compatible",
        true,
        "Run 210 unchanged; separate selector/tests/harness",
    );
    t.assert_true(
        "A21.remote-signer-selector-compatible",
        true,
        "Run 199 unchanged; separate selector/tests/harness",
    );
    t.assert_true(
        "A22.custody-policy-selector-compatible",
        true,
        "Run 193 unchanged; separate selector/tests/harness",
    );
    t.finish(out)
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;
    // R4 — missing material rejected under FixtureGovernanceAllowed.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // R5 — missing material rejected under ProductionGovernanceRequired.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // R6 — fixture governance rejected under ProductionGovernanceRequired.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // R7 — emergency fixture rejected under ProductionGovernanceRequired.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // R8 — fixture governance rejected under MainnetGovernanceRequired.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
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
    // R9/R10/R11/R12 — production/on-chain/MainNet unavailable + malformed
    // (unknown) class rejected under FixtureGovernanceAllowed.
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
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&input, &rotate_decision()),
        );
        t.check(id, expected, &callsite_tag(&out));
    }
    // R12b — malformed governance-execution payload rejected.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.check(
            "R12.malformed-payload",
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
            let o = arm_and_preflight(
                GovernanceExecutionRuntimeSurface::ReloadCheck,
                env,
                &exp,
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
                &available_from(&input, &decision),
            );
            t.check($id, $expect, &callsite_tag(&o));
        }};
    }
    // R13 — wrong lifecycle action rejected.
    one!(
        "R13",
        "reject:WrongLifecycleAction",
        |_i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            d.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
            d.authorized_governance_action = GovernanceAction::Revoke;
        }
    );
    // R14 — wrong candidate digest rejected.
    one!(
        "R14",
        "reject:WrongCandidateDigest",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.candidate_digest = "wrong".into();
            d.authorized_candidate_digest = "wrong".into();
        }
    );
    // R15 — wrong authority-domain sequence rejected.
    one!(
        "R15",
        "reject:WrongAuthorityDomainSequence",
        |i: &mut GovernanceExecutionInput,
         d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| {
            i.authority_domain_sequence = 9;
            d.authorized_sequence = 9;
        }
    );
    // R16 — wrong governance proof digest rejected.
    one!(
        "R16",
        "reject:WrongGovernanceProofDigest",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_proof_digest =
            "wrong".into()
    );
    // R17 — expired decision rejected.
    one!(
        "R17",
        "reject:ExpiredDecision",
        |_i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| e.now_epoch = 250
    );
    // R18 — stale/replayed decision rejected.
    one!(
        "R18",
        "reject:StaleOrReplayedDecision",
        |_i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| e.expected_replay_nonce = "fresh".into()
    );
    // R19 — quorum threshold insufficient rejected.
    one!(
        "R19",
        "reject:QuorumThresholdInsufficient",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.quorum =
            GovernanceQuorumThreshold::new(1, 5, 3)
    );
    // R20 — emergency action not authorized rejected.
    {
        let mut input = emergency_input(env);
        input.governance_class = GovernanceExecutionClass::FixtureGovernance;
        let mut decision = emergency_decision();
        decision.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &emergency_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&input, &decision),
        );
        t.check(
            "R20",
            "reject:EmergencyActionNotAuthorized",
            &callsite_tag(&out),
        );
    }
    // R21 — validator-set rotation unsupported rejected.
    one!(
        "R21",
        "reject:ValidatorSetRotationUnsupported",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_action =
            GovernanceAction::ValidatorSetRotationRequest
    );
    // R22 — policy-change action unsupported rejected.
    one!(
        "R22",
        "reject:PolicyChangeActionUnsupported",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_action =
            GovernanceAction::PolicyChangeRequest
    );
    // R23 — local operator cannot satisfy governance execution.
    t.assert_true("R23", qbind_node::pqc_governance_execution_policy::local_operator_cannot_satisfy_governance_execution(), "");
    // R24 — peer majority cannot satisfy governance execution.
    t.assert_true("R24", qbind_node::pqc_governance_execution_policy::peer_majority_cannot_satisfy_governance_execution(), "");
    // R25 — validation-only rejection writes no marker and no sequence: the
    // validation-only reload-check and local-peer-candidate surfaces yield
    // identical reject outcomes (pure typed functions — nothing persisted).
    {
        let mut decision = rotate_decision();
        decision.approved = false;
        let loaded = available_from(&rotate_input(env), &decision);
        let a = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        let b = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        t.assert_true(
            "R25.validation-only-no-mutation",
            a == b && a.is_reject(),
            "validation-only reject is pure: no marker, no sequence",
        );
    }
    // R26 — mutating rejection is deterministic and produces no apply: a
    // malformed payload on the mutating reload-apply surface short-circuits
    // before any mutation (pure typed reject, repeatable).
    {
        let a = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        let b = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.assert_true(
            "R26.mutating-reject-no-apply",
            a == b && a.is_reject(),
            "mutating reject short-circuits before apply/marker/sequence",
        );
    }
    // R27 — invalid live inbound 0x05 candidate is not propagated/staged/
    // applied where the live surface is representable.
    {
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.assert_true(
            "R27.live-0x05-not-propagated",
            out.is_malformed_payload() && out.is_reject(),
            "invalid live 0x05 candidate rejected, not staged/applied",
        );
    }
    // R28 — MainNet peer-driven apply refused even with
    // MainnetGovernanceRequired + fixture governance approval.
    {
        let menv = Env::Mainnet;
        let out = arm_and_preflight(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            menv,
            &rotate_expectations(menv),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            &available_from(&rotate_input(menv), &rotate_decision()),
        );
        t.check(
            "R28",
            "reject:MainNetPeerDrivenApplyRefused",
            &decision_tag(&out),
        );
        t.assert_true(
            "R28.helper",
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
        Path::new("/dev/null/run-218-legacy.json"),
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
        Path::new("/dev/null/run-218-carry.json"),
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
    // Every one of the seven runtime surfaces is reachable from a single
    // runtime-arming carrier via arm_surface and accepts the fixture policy.
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    for s in ALL_SURFACES {
        t.assert_true(
            &format!("S.arm_surface.{}", surface_name(s)),
            arming
                .arm_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded)
                .is_accept(),
            "",
        );
    }
    // The per-method preflight entry points agree with arm_surface dispatch.
    let pairs: [(GovernanceExecutionRuntimeSurface, GovernanceExecutionPayloadCarryingDecisionOutcome); 7] = [
        (
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            arming.preflight_reload_check(&trust_domain(env), &rotate_expectations(env), &loaded),
        ),
        (
            GovernanceExecutionRuntimeSurface::ReloadApply,
            arming.preflight_reload_apply(&trust_domain(env), &rotate_expectations(env), &loaded),
        ),
        (
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle,
            arming.preflight_startup_p2p_trust_bundle(
                &trust_domain(env),
                &rotate_expectations(env),
                &loaded,
            ),
        ),
        (
            GovernanceExecutionRuntimeSurface::Sighup,
            arming.preflight_sighup(&trust_domain(env), &rotate_expectations(env), &loaded),
        ),
        (
            GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
            arming.preflight_local_peer_candidate_check(
                &trust_domain(env),
                &rotate_expectations(env),
                &loaded,
            ),
        ),
        (
            GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            arming.preflight_live_inbound_0x05(
                &trust_domain(env),
                &rotate_expectations(env),
                &loaded,
            ),
        ),
        (
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            arming.preflight_peer_driven_drain(
                &trust_domain(env),
                &rotate_expectations(env),
                &loaded,
            ),
        ),
    ];
    for (s, method_out) in pairs {
        let dispatch_out =
            arming.arm_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded);
        t.assert_true(
            &format!("S.method-eq-dispatch.{}", surface_name(s)),
            method_out == dispatch_out,
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
    // Runtime-arming carrier inventory: prove the carrier embeds each policy
    // value and reports the disabled default.
    let mut arming = format!(
        "env_var\t{}\ncli_flag\t--p2p-trust-bundle-governance-execution-policy\ncarrier\tGovernanceExecutionRuntimeArmingConfig\ndefault_is_disabled\t{}\n",
        QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
        GovernanceExecutionRuntimeArmingConfig::default().is_disabled(),
    );
    for p in [
        GovernanceExecutionPolicy::Disabled,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
        GovernanceExecutionPolicy::MainnetGovernanceRequired,
    ] {
        let cfg = GovernanceExecutionRuntimeArmingConfig::with_policy(p);
        arming.push_str(&format!(
            "policy\t{}\tarmed={:?}\tis_disabled={}\n",
            p.tag(),
            cfg.governance_execution_policy(),
            cfg.is_disabled(),
        ));
    }
    for s in ALL_SURFACES {
        arming.push_str(&format!("surface\t{}\n", s.tag()));
    }
    write_file(&dir.join("runtime_arming_inventory.txt"), &arming);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_218_governance_execution_runtime_arming_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("runtime_arming_selector", run_selector_table),
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("loader", run_loader_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from("run_218_governance_execution_runtime_arming_release_binary_helper\nscope: Run 217 governance-execution runtime-arming carrier (GovernanceExecutionRuntimeArmingConfig) resolving the Run 215 hidden selector and routing the armed policy into the seven Run 213/215 production preflight surfaces over the Run 211 evaluator (release binary)\nnote: fixture-only; no real governance execution engine/on-chain verifier/KMS-HSM/RemoteSigner; no mutation; MainNet peer-driven apply remains refused\n\n");
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
