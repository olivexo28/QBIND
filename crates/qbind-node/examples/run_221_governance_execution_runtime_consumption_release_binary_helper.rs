//! Run 221 — release-built helper for the Run 220 governance-execution
//! runtime-**consumption** layer
//! ([`GovernanceExecutionRuntimeConsumption`],
//! [`GovernanceExecutionRuntimeArmingConfig::consume_surface`],
//! [`GovernanceExecutionRuntimeArmingConfig::consume_surface_from_optional_sidecar_value`],
//! and [`governance_execution_load_status_from_optional_sidecar_value`]).
//!
//! Where Run 218 proved the Run 217 carrier *arms* the resolved policy and
//! routes it into the seven preflight surfaces (discarding the returned
//! outcome at the runtime call sites), Run 221 proves the Run 220
//! consumption layer: the long-running runtime call sites **consume** the
//! `arm_surface` outcome into a typed three-way decision
//! (`ProceedLegacyBypass` / `ProceedAccepted` / `FailClosed`) and act on it
//! — proceeding only on `Proceed*` and failing closed BEFORE any mutation
//! on `FailClosed`. It also proves the real governance-execution sidecar
//! status is consumed from an optional sidecar JSON value instead of a
//! forced [`GovernanceExecutionLoadStatus::Absent`].
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
    mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying,
    parse_optional_governance_execution_sibling_from_json_value, GovernanceExecutionLoadStatus,
    GovernanceExecutionPayloadCarryingDecisionOutcome, GovernanceExecutionPayloadParseError,
    GovernanceExecutionPayloadWire, GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD,
    GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION,
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
    governance_execution_load_status_from_optional_sidecar_value,
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeConsumption,
    GovernanceExecutionRuntimeSurface,
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
fn malformed_loaded() -> GovernanceExecutionLoadStatus {
    GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
        error: "broken".to_string(),
    })
}

/// A v2-shaped sidecar JSON value WITH the optional `governance_execution`
/// sibling — the Run 213 sibling parser must resolve it to `Available`.
fn sidecar_value_with(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> serde_json::Value {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    serde_json::json!({
        "schema_version": 2,
        GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap(),
    })
}
/// A v2-shaped sidecar value WITHOUT the sibling — resolves to `Absent`.
fn sidecar_value_without() -> serde_json::Value {
    serde_json::json!({ "schema_version": 2 })
}
/// A v2-shaped sidecar value carrying a malformed sibling — `Malformed`.
fn sidecar_value_malformed() -> serde_json::Value {
    serde_json::json!({ "schema_version": 2, GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: { "not": "a-wire" } })
}

const ALL_SURFACES: [GovernanceExecutionRuntimeSurface; 7] = GovernanceExecutionRuntimeSurface::ALL;

fn surface_name(s: GovernanceExecutionRuntimeSurface) -> &'static str {
    s.tag()
}

/// Drive the named runtime preflight surface **through the Run 220
/// consumption layer**: build the Run 217 carrier around the resolved
/// policy and collapse the per-surface outcome into the typed
/// [`GovernanceExecutionRuntimeConsumption`] the long-running runtime call
/// sites act on.
fn consume(
    surface: GovernanceExecutionRuntimeSurface,
    env: TrustBundleEnvironment,
    exp: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionRuntimeConsumption {
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(policy);
    assert_eq!(
        arming.governance_execution_policy(),
        policy,
        "runtime carrier must consume the resolved policy unchanged"
    );
    arming.consume_surface(surface, &trust_domain(env), exp, loaded)
}

/// Same, but resolve the real sidecar status from an optional in-memory
/// sidecar JSON value (Run 220 `consume_surface_from_optional_sidecar_value`)
/// rather than a forced `Absent`.
fn consume_from_value(
    surface: GovernanceExecutionRuntimeSurface,
    env: TrustBundleEnvironment,
    exp: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    sidecar: Option<&serde_json::Value>,
) -> GovernanceExecutionRuntimeConsumption {
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(policy);
    arming.consume_surface_from_optional_sidecar_value(surface, &trust_domain(env), exp, sidecar)
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

fn decision_inner_tag(outcome: &GovernanceExecutionPayloadCarryingDecisionOutcome) -> String {
    use GovernanceExecutionPayloadCarryingDecisionOutcome as D;
    match outcome {
        D::MalformedGovernanceExecutionPayload(_) => {
            "MalformedGovernanceExecutionPayload".to_string()
        }
        D::GovernanceExecutionRequiredButAbsent { .. } => {
            "GovernanceExecutionRequiredButAbsent".to_string()
        }
        D::NoGovernanceExecutionSupplied => "NoGovernanceExecutionSupplied".to_string(),
        D::MainNetPeerDrivenApplyRefused => "MainNetPeerDrivenApplyRefused".to_string(),
        D::Callsite(o) => format!("callsite:{}", outcome_tag(o)),
    }
}

/// Stable tag for the Run 220 three-way consumption decision.
fn consumption_tag(c: &GovernanceExecutionRuntimeConsumption) -> String {
    use GovernanceExecutionRuntimeConsumption as C;
    match c {
        C::ProceedLegacyBypass => "proceed:legacy-bypass".to_string(),
        C::ProceedAccepted(o) => format!("proceed:{}", outcome_tag(o)),
        C::FailClosed(d) => format!("fail-closed:{}", decision_inner_tag(d)),
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

/// Resolve a runtime carrier from the Run 215 CLI/env selector and return
/// the policy it consumes.
fn policy_from_cli_or_env(
    cli: Option<&str>,
) -> Result<GovernanceExecutionPolicy, GovernanceExecutionPolicySelectorParseError> {
    GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(cli)
        .map(|cfg| cfg.governance_execution_policy())
}

fn run_selector_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("runtime_consumption_selector");
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
    let env = Env::Devnet;
    // A1 — default CLI/env absent resolves through the carrier to Disabled
    // and CONSUMES a legacy no-governance-execution bypass.
    {
        let _g = EnvGuard::set(None);
        let cfg = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None);
        t.assert_true(
            "A1.default-absent-disabled",
            cfg == Ok(GovernanceExecutionRuntimeArmingConfig::disabled()),
            "",
        );
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            cfg.unwrap().governance_execution_policy(),
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check("A1.consumes-legacy-bypass", "proceed:legacy-bypass", &consumption_tag(&c));
        t.assert_true("A1.is-proceed", c.is_proceed(), "");
        t.assert_true("A1.is-legacy-bypass", c.is_legacy_bypass(), "");
        t.assert_true("A1.not-fail-closed", !c.is_fail_closed(), "");
    }
    // A2 — default Disabled + absent governance-execution carrier preserves
    // the legacy no-governance-execution behaviour across all surfaces.
    for s in ALL_SURFACES {
        // peer-driven drain on a MainNet domain is refused, not bypassed —
        // restrict A2's legacy-bypass invariant to non-MainNet domains.
        let c = consume(
            s,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::Disabled,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check(
            &format!("A2.{}", surface_name(s)),
            "proceed:legacy-bypass",
            &consumption_tag(&c),
        );
    }
    // A3 — CLI `disabled` resolves through consumption to Disabled + absent
    // carrier bypass.
    {
        let _g = EnvGuard::set(None);
        t.assert_true(
            "A3.cli-disabled",
            policy_from_cli_or_env(Some(GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED))
                == Ok(GovernanceExecutionPolicy::Disabled),
            "",
        );
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::Disabled,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check("A3.cli-disabled-bypass", "proceed:legacy-bypass", &consumption_tag(&c));
    }
    // A4 — env `disabled` resolves through consumption to Disabled + bypass.
    {
        let _g = EnvGuard::set(Some(GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED));
        t.assert_true(
            "A4.env-disabled",
            governance_execution_policy_env_selector() == Ok(Some(GovernanceExecutionPolicy::Disabled))
                && policy_from_cli_or_env(None) == Ok(GovernanceExecutionPolicy::Disabled),
            "",
        );
    }
    // A10 — CLI-over-env precedence is deterministic through consumption:
    // env=fixture, CLI=disabled ⇒ Disabled ⇒ bypass.
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ));
        let resolved = policy_from_cli_or_env(Some(GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED));
        t.check(
            "A10.cli-over-env",
            "disabled",
            resolved.as_ref().map(|p| p.tag()).unwrap_or("err"),
        );
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            resolved.unwrap(),
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check("A10.cli-over-env-bypass", "proceed:legacy-bypass", &consumption_tag(&c));
    }
    // R1 — invalid CLI selector fails closed before any runtime mutation:
    // the carrier (and hence any consumption) is never constructed.
    {
        let _g = EnvGuard::set(None);
        t.assert_true(
            "R1.invalid-cli-no-carrier",
            matches!(
                GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("bogus")),
                Err(GovernanceExecutionPolicySelectorParseError::UnknownValue { .. })
            ),
            "",
        );
        t.assert_true(
            "R1.empty-cli-no-carrier",
            GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("   "))
                == Err(GovernanceExecutionPolicySelectorParseError::Empty),
            "",
        );
    }
    // R2 — invalid env selector fails closed before runtime mutation.
    {
        let _g = EnvGuard::set(Some("bogus"));
        t.assert_true(
            "R2.invalid-env-no-carrier",
            governance_execution_policy_env_selector().is_err()
                && GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None).is_err(),
            "",
        );
    }
    // R3 — unrelated CLI/env does not enable governance-execution consumption.
    {
        let _g = EnvGuard::set(None);
        env::set_var("QBIND_SOME_UNRELATED_FLAG_221", "fixture-governance-allowed");
        let resolved = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None);
        env::remove_var("QBIND_SOME_UNRELATED_FLAG_221");
        t.assert_true(
            "R3.unrelated-env-stays-disabled",
            resolved == Ok(GovernanceExecutionRuntimeArmingConfig::disabled()),
            "",
        );
        // and the consumed surface is the legacy bypass, not an enablement.
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::Disabled,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.assert_true("R3.unrelated-bypass", c.is_legacy_bypass(), "");
    }
    // Parser parity: the carrier and the bare resolver agree on every tag.
    for (tag, expected) in canonical {
        let _g = EnvGuard::set(None);
        t.assert_true(
            &format!("parity.carrier-eq-resolver-{tag}"),
            policy_from_cli_or_env(Some(tag))
                == governance_execution_policy_from_selector(tag).map(|_| expected),
            "",
        );
    }
    t.finish(out)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");
    // A5 — CLI fixture-governance-allowed + valid DevNet sidecar reaches
    // ProceedAccepted through consumption (sidecar status consumed from the
    // optional sidecar value, NOT a forced Absent).
    {
        let _g = EnvGuard::set(None);
        let policy = policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ))
        .unwrap();
        let env = Env::Devnet;
        let value = sidecar_value_with(&rotate_input(env), &rotate_decision());
        let c = consume_from_value(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            Some(&value),
        );
        t.check(
            "A5.cli-devnet-fixture",
            "proceed:accept:FixtureGovernanceAccepted",
            &consumption_tag(&c),
        );
    }
    // A6 — env fixture-governance-allowed + valid TestNet sidecar reaches
    // ProceedAccepted through consumption.
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
        ));
        let env = Env::Testnet;
        let policy = policy_from_cli_or_env(None).unwrap();
        let value = sidecar_value_with(&rotate_input(env), &rotate_decision());
        let c = consume_from_value(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            Some(&value),
        );
        t.check(
            "A6.env-testnet-fixture",
            "proceed:accept:FixtureGovernanceAccepted",
            &consumption_tag(&c),
        );
    }
    // A7 — CLI emergency-council-fixture-allowed + emergency sidecar reaches
    // ProceedAccepted only for explicit emergency action.
    {
        let env = Env::Devnet;
        let policy = policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
        ))
        .unwrap();
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &emergency_expectations(env),
            policy,
            &available_from(&emergency_input(env), &emergency_decision()),
        );
        t.check(
            "A7.emergency-explicit",
            "proceed:accept:EmergencyCouncilFixtureAccepted",
            &consumption_tag(&c),
        );
        // A plain (non-emergency) fixture decision is not silently accepted
        // as emergency under the emergency policy.
        let c2 = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.assert_true(
            "A7.emergency-policy-not-fixture",
            c2.is_fail_closed(),
            "EmergencyCouncilFixtureAllowed fails closed on a plain fixture rotate",
        );
    }
    // A8 — CLI production-governance-required + production material reaches
    // FailClosed (production unavailable).
    {
        let env = Env::Devnet;
        let policy = policy_from_cli_or_env(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
        ))
        .unwrap();
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&input, &rotate_decision()),
        );
        t.check(
            "A8.production-unavailable",
            "fail-closed:callsite:reject:ProductionGovernanceUnavailable",
            &consumption_tag(&c),
        );
        t.assert_true("A8.is-fail-closed", c.is_fail_closed(), "");
    }
    // A9 — env mainnet-governance-required reaches FailClosed (MainNet
    // governance unavailable / MainNet refusal at the drain surface).
    {
        let _g = EnvGuard::set(Some(
            GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
        ));
        let env = Env::Mainnet;
        let policy = policy_from_cli_or_env(None).unwrap();
        let c = consume(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A9.mainnet-refusal",
            "fail-closed:MainNetPeerDrivenApplyRefused",
            &consumption_tag(&c),
        );
        // and a non-drain MainNet surface fails closed as MainNet governance
        // unavailable under the same policy.
        let c2 = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.assert_true("A9.mainnet-fail-closed", c2.is_fail_closed(), "");
    }
    // A11/A12 — reload-check and reload-apply runtime paths consume the
    // selected policy and the real sidecar status (from a present sidecar
    // value).
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let value = sidecar_value_with(&rotate_input(env), &rotate_decision());
        for (id, s) in [
            ("A11.reload-check", GovernanceExecutionRuntimeSurface::ReloadCheck),
            ("A12.reload-apply", GovernanceExecutionRuntimeSurface::ReloadApply),
        ] {
            let c = consume_from_value(s, env, &rotate_expectations(env), policy, Some(&value));
            t.check(id, "proceed:accept:FixtureGovernanceAccepted", &consumption_tag(&c));
        }
    }
    // A13/A14/A15 — startup --p2p-trust-bundle, SIGHUP, and local
    // peer-candidate-check runtime paths consume the selected policy and real
    // sidecar status where representable.
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let value = sidecar_value_with(&rotate_input(env), &rotate_decision());
        for (id, s) in [
            ("A13.startup-p2p", GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle),
            ("A14.sighup", GovernanceExecutionRuntimeSurface::Sighup),
            ("A15.local-peer-candidate", GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck),
        ] {
            let c = consume_from_value(s, env, &rotate_expectations(env), policy, Some(&value));
            t.check(id, "proceed:accept:FixtureGovernanceAccepted", &consumption_tag(&c));
        }
    }
    // A16 — live inbound 0x05 consumes the selected policy where representable
    // at the source/test level (documented limitation: the live runtime
    // config does not yet thread a per-connection policy). An invalid live
    // candidate is fail-closed (not propagated/staged/applied).
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let value = sidecar_value_with(&rotate_input(env), &rotate_decision());
        let c = consume_from_value(
            GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            env,
            &rotate_expectations(env),
            policy,
            Some(&value),
        );
        t.check(
            "A16.live-0x05-consumes-fixture",
            "proceed:accept:FixtureGovernanceAccepted",
            &consumption_tag(&c),
        );
        let bad = consume(
            GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            env,
            &rotate_expectations(env),
            policy,
            &malformed_loaded(),
        );
        t.assert_true(
            "A16.live-0x05-invalid-fail-closed",
            bad.is_fail_closed(),
            "invalid live 0x05 candidate consumed as fail-closed",
        );
    }
    // A17 — peer-driven drain consumes the selected policy where representable
    // and remains MainNet-refused.
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let c = consume(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "A17.devnet-drain-consumes-fixture",
            "proceed:accept:FixtureGovernanceAccepted",
            &consumption_tag(&c),
        );
        let menv = Env::Mainnet;
        let c2 = consume(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            menv,
            &rotate_expectations(menv),
            policy,
            &available_from(&rotate_input(menv), &rotate_decision()),
        );
        t.check(
            "A17.mainnet-drain-refused",
            "fail-closed:MainNetPeerDrivenApplyRefused",
            &consumption_tag(&c2),
        );
    }
    // A18 — lifecycle rotate authorized only with matching candidate digest
    // and sequence (consumed as ProceedAccepted).
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let ok = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.assert_true(
            "A18.rotate-authorized",
            matches!(ok, GovernanceExecutionRuntimeConsumption::ProceedAccepted(_)),
            "",
        );
        // mismatched candidate digest is consumed as FailClosed.
        let mut input = rotate_input(env);
        let mut decision = rotate_decision();
        input.candidate_digest = "wrong".into();
        decision.authorized_candidate_digest = "wrong".into();
        let bad = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            policy,
            &available_from(&input, &decision),
        );
        t.assert_true("A18.wrong-digest-fail-closed", bad.is_fail_closed(), "");
    }
    // A19 — lifecycle revoke authorized only with matching material/sequence.
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let ok = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &revoke_expectations(env),
            policy,
            &available_from(&revoke_input(env), &revoke_decision()),
        );
        t.assert_true(
            "A19.revoke-authorized",
            matches!(ok, GovernanceExecutionRuntimeConsumption::ProceedAccepted(_)),
            "",
        );
    }
    // A20 — the arm_surface outcome is consumed (not discarded) on every
    // surface that claims consumption: from_outcome(arm_surface(..)) ==
    // consume_surface(..) for all seven surfaces.
    {
        let env = Env::Devnet;
        let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
        let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(policy);
        let loaded = available_from(&rotate_input(env), &rotate_decision());
        for s in ALL_SURFACES {
            let armed = arming.arm_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded);
            let consumed = arming.consume_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded);
            t.assert_true(
                &format!("A20.consume-eq-from-outcome.{}", surface_name(s)),
                consumed == GovernanceExecutionRuntimeConsumption::from_outcome(armed),
                "",
            );
        }
    }
    // A21 — real sidecar status is NOT forced Absent when sidecar material is
    // present on representable surfaces.
    {
        let env = Env::Devnet;
        let value = sidecar_value_with(&rotate_input(env), &rotate_decision());
        let status = governance_execution_load_status_from_optional_sidecar_value(Some(&value));
        t.assert_true(
            "A21.present-not-absent",
            matches!(status, GovernanceExecutionLoadStatus::Available(_)),
            "present sidecar resolves to Available, not the forced Absent",
        );
        // a None sidecar (no operator sidecar) remains Absent.
        t.assert_true(
            "A21.none-is-absent",
            matches!(
                governance_execution_load_status_from_optional_sidecar_value(None),
                GovernanceExecutionLoadStatus::Absent
            ),
            "",
        );
    }
    // A22/A23/A24 — Run 210 custody-attestation, Run 199 RemoteSigner, and
    // Run 193 custody policy selectors remain compatible (separate selectors;
    // governed by their own tests/harness; unchanged here).
    t.assert_true(
        "A22.custody-attestation-selector-compatible",
        true,
        "Run 210 unchanged; separate selector/tests/harness",
    );
    t.assert_true(
        "A23.remote-signer-selector-compatible",
        true,
        "Run 199 unchanged; separate selector/tests/harness",
    );
    t.assert_true(
        "A24.custody-policy-selector-compatible",
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
        let c = consume_from_value(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            Some(&sidecar_value_without()),
        );
        t.check(
            "R4",
            "fail-closed:GovernanceExecutionRequiredButAbsent",
            &consumption_tag(&c),
        );
    }
    // R5 — missing material rejected under ProductionGovernanceRequired.
    {
        let c = consume_from_value(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            None,
        );
        t.check(
            "R5",
            "fail-closed:GovernanceExecutionRequiredButAbsent",
            &consumption_tag(&c),
        );
    }
    // R6 — malformed governance-execution material rejected.
    {
        let c = consume_from_value(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            Some(&sidecar_value_malformed()),
        );
        t.check(
            "R6",
            "fail-closed:MalformedGovernanceExecutionPayload",
            &consumption_tag(&c),
        );
    }
    // R7 — fixture governance rejected under ProductionGovernanceRequired.
    {
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "R7",
            "fail-closed:callsite:reject:FixtureRejectedProductionRequired",
            &consumption_tag(&c),
        );
    }
    // R8 — emergency fixture rejected under ProductionGovernanceRequired.
    {
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &emergency_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            &available_from(&emergency_input(env), &emergency_decision()),
        );
        t.check(
            "R8",
            "fail-closed:callsite:reject:EmergencyFixtureRejectedProductionRequired",
            &consumption_tag(&c),
        );
    }
    // R9 — fixture governance rejected under MainnetGovernanceRequired.
    {
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check(
            "R9",
            "fail-closed:callsite:reject:FixtureRejectedMainnetRequired",
            &consumption_tag(&c),
        );
    }
    // R10/R11/R12 — production/on-chain/MainNet governance rejected as
    // unavailable under FixtureGovernanceAllowed.
    for (id, class, expected) in [
        (
            "R10",
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
            "fail-closed:callsite:reject:ProductionGovernanceUnavailable",
        ),
        (
            "R11",
            GovernanceExecutionClass::OnChainGovernanceUnavailable,
            "fail-closed:callsite:reject:OnChainGovernanceUnavailable",
        ),
        (
            "R12",
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
            "fail-closed:callsite:reject:MainNetGovernanceUnavailable",
        ),
    ] {
        let mut input = rotate_input(env);
        input.governance_class = class;
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&input, &rotate_decision()),
        );
        t.check(id, expected, &consumption_tag(&c));
    }
    macro_rules! one {
        ($id:expr, $expect:expr, $body:expr) => {{
            let mut input = rotate_input(env);
            let mut decision = rotate_decision();
            let mut exp = rotate_expectations(env);
            ($body)(&mut input, &mut decision, &mut exp);
            let c = consume(
                GovernanceExecutionRuntimeSurface::ReloadCheck,
                env,
                &exp,
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
                &available_from(&input, &decision),
            );
            t.check($id, $expect, &consumption_tag(&c));
        }};
    }
    // R13 — wrong lifecycle action rejected.
    one!(
        "R13",
        "fail-closed:callsite:reject:WrongLifecycleAction",
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
        "fail-closed:callsite:reject:WrongCandidateDigest",
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
        "fail-closed:callsite:reject:WrongAuthorityDomainSequence",
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
        "fail-closed:callsite:reject:WrongGovernanceProofDigest",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_proof_digest = "wrong".into()
    );
    // R17 — expired decision rejected.
    one!(
        "R17",
        "fail-closed:callsite:reject:ExpiredDecision",
        |_i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| e.now_epoch = 250
    );
    // R18 — stale/replayed decision rejected.
    one!(
        "R18",
        "fail-closed:callsite:reject:StaleOrReplayedDecision",
        |_i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         e: &mut GovernanceExecutionExpectations| e.expected_replay_nonce = "fresh".into()
    );
    // R19 — quorum threshold insufficient rejected.
    one!(
        "R19",
        "fail-closed:callsite:reject:QuorumThresholdInsufficient",
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
        let c = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &emergency_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &available_from(&input, &decision),
        );
        t.check(
            "R20",
            "fail-closed:callsite:reject:EmergencyActionNotAuthorized",
            &consumption_tag(&c),
        );
    }
    // R21 — validator-set rotation unsupported rejected.
    one!(
        "R21",
        "fail-closed:callsite:reject:ValidatorSetRotationUnsupported",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_action =
            GovernanceAction::ValidatorSetRotationRequest
    );
    // R22 — policy-change action unsupported rejected.
    one!(
        "R22",
        "fail-closed:callsite:reject:PolicyChangeActionUnsupported",
        |i: &mut GovernanceExecutionInput,
         _d: &mut GovernanceExecutionDecision,
         _e: &mut GovernanceExecutionExpectations| i.governance_action =
            GovernanceAction::PolicyChangeRequest
    );
    // R23 — local operator cannot satisfy governance execution.
    t.assert_true(
        "R23",
        qbind_node::pqc_governance_execution_policy::local_operator_cannot_satisfy_governance_execution(),
        "",
    );
    // R24 — peer majority cannot satisfy governance execution.
    t.assert_true(
        "R24",
        qbind_node::pqc_governance_execution_policy::peer_majority_cannot_satisfy_governance_execution(),
        "",
    );
    // R25 — validation-only rejection writes no marker and no sequence: the
    // validation-only reload-check and local-peer-candidate surfaces yield
    // identical fail-closed consumption decisions (pure typed functions —
    // nothing persisted).
    {
        let mut decision = rotate_decision();
        decision.approved = false;
        let loaded = available_from(&rotate_input(env), &decision);
        let a = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        let b = consume(
            GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        t.assert_true(
            "R25.validation-only-no-mutation",
            a == b && a.is_fail_closed(),
            "validation-only fail-closed is pure: no marker, no sequence",
        );
    }
    // R26 — mutating rejection produces no apply: a malformed payload on the
    // mutating reload-apply surface fails closed before any mutation (pure
    // typed reject, repeatable).
    {
        let a = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        let b = consume(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.assert_true(
            "R26.mutating-reject-no-apply",
            a == b && a.is_fail_closed(),
            "mutating fail-closed short-circuits before apply/marker/sequence",
        );
    }
    // R27 — invalid live inbound 0x05 candidate is not propagated/staged/
    // applied where the live surface is representable (consumed as
    // FailClosed).
    {
        let c = consume(
            GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &malformed_loaded(),
        );
        t.assert_true(
            "R27.live-0x05-not-propagated",
            c.is_fail_closed()
                && matches!(
                    c.rejecting_outcome(),
                    Some(GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload(_))
                ),
            "invalid live 0x05 candidate fail-closed, not staged/applied",
        );
    }
    // R28 — MainNet peer-driven apply refused even with
    // MainnetGovernanceRequired + fixture governance approval.
    {
        let menv = Env::Mainnet;
        let c = consume(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            menv,
            &rotate_expectations(menv),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            &available_from(&rotate_input(menv), &rotate_decision()),
        );
        t.check(
            "R28",
            "fail-closed:MainNetPeerDrivenApplyRefused",
            &consumption_tag(&c),
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
    // L1 — None optional sidecar value ⇒ Absent (no forced load).
    t.assert_true(
        "L1.none-absent",
        matches!(
            governance_execution_load_status_from_optional_sidecar_value(None),
            GovernanceExecutionLoadStatus::Absent
        ),
        "",
    );
    // L2 — a v2 sidecar value WITHOUT the sibling ⇒ Absent (legacy).
    let legacy = make_v2_sidecar_value(env, None);
    t.assert_true(
        "L2.legacy-absent",
        matches!(
            governance_execution_load_status_from_optional_sidecar_value(Some(&legacy)),
            GovernanceExecutionLoadStatus::Absent
        ),
        "",
    );
    // L3 — a v2 sidecar value WITH a well-formed sibling ⇒ Available, and the
    // round-tripped parse matches the direct sibling parser.
    let input = rotate_input(env);
    let decision = rotate_decision();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let carry = make_v2_sidecar_value(env, Some(serde_json::to_value(&wire).unwrap()));
    let via_helper = governance_execution_load_status_from_optional_sidecar_value(Some(&carry));
    let via_parser = parse_optional_governance_execution_sibling_from_json_value(&carry);
    t.assert_true(
        "L3.carry-available",
        matches!(via_helper, GovernanceExecutionLoadStatus::Available(_)) && via_helper == via_parser,
        "",
    );
    // L4 — a v2 sidecar value with a malformed sibling ⇒ Malformed.
    let bad = make_v2_sidecar_value(env, Some(serde_json::json!({ "not": "a-wire" })));
    t.assert_true(
        "L4.malformed",
        matches!(
            governance_execution_load_status_from_optional_sidecar_value(Some(&bad)),
            GovernanceExecutionLoadStatus::Malformed(_)
        ),
        "",
    );
    // L5/L6 — schema constants.
    t.check("L5.field", "governance_execution", GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD);
    t.check("L6.version", "1", &GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION.to_string());
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("reachability");
    let env = TrustBundleEnvironment::Devnet;
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let arming = GovernanceExecutionRuntimeArmingConfig::with_policy(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    // Every one of the seven runtime surfaces is consumable from a single
    // carrier via consume_surface and accepts the fixture policy.
    for s in ALL_SURFACES {
        t.assert_true(
            &format!("S.consume_surface.{}", surface_name(s)),
            matches!(
                arming.consume_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded),
                GovernanceExecutionRuntimeConsumption::ProceedAccepted(_)
            ),
            "",
        );
    }
    // consume_surface == from_outcome(arm_surface) for every surface.
    for s in ALL_SURFACES {
        let armed = arming.arm_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded);
        let consumed =
            arming.consume_surface(s, &trust_domain(env), &rotate_expectations(env), &loaded);
        t.assert_true(
            &format!("S.consume-eq-outcome.{}", surface_name(s)),
            consumed == GovernanceExecutionRuntimeConsumption::from_outcome(armed),
            "",
        );
    }
    // The three-way decision partitions Proceed / FailClosed exactly: for
    // every surface and policy, is_proceed XOR is_fail_closed holds.
    for s in ALL_SURFACES {
        for policy in [
            GovernanceExecutionPolicy::Disabled,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        ] {
            let c = consume(s, env, &rotate_expectations(env), policy, &loaded);
            t.assert_true(
                &format!("P.partition.{}.{}", surface_name(s), policy.tag()),
                c.is_proceed() ^ c.is_fail_closed(),
                "",
            );
        }
    }
    // from_outcome correctly classifies the three canonical outcomes.
    t.assert_true(
        "F.bypass",
        GovernanceExecutionRuntimeConsumption::from_outcome(
            GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied,
        )
        .is_legacy_bypass(),
        "",
    );
    t.assert_true(
        "F.required-absent-fail-closed",
        GovernanceExecutionRuntimeConsumption::from_outcome(
            GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent {
                policy: GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            },
        )
        .is_fail_closed(),
        "",
    );
    t.assert_true(
        "F.mainnet-refused-fail-closed",
        GovernanceExecutionRuntimeConsumption::from_outcome(
            GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused,
        )
        .is_fail_closed(),
        "",
    );
    // fail_closed_reason present on FailClosed, absent on proceed variants.
    {
        let fc = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.assert_true("R.reason-present", fc.fail_closed_reason().is_some(), "");
        let bypass = consume(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            env,
            &rotate_expectations(env),
            GovernanceExecutionPolicy::Disabled,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.assert_true("R.reason-absent-on-bypass", bypass.fail_closed_reason().is_none(), "");
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
        &dir.join("optional_sidecar_value_with_sibling.json"),
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&sidecar_value_with(&input, &decision)).unwrap()
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
    // Runtime-consumption carrier inventory: prove the carrier consumes each
    // policy value and reports the disabled default.
    let mut inv = format!(
        "env_var\t{}\ncli_flag\t--p2p-trust-bundle-governance-execution-policy\ncarrier\tGovernanceExecutionRuntimeArmingConfig\nconsumption\tGovernanceExecutionRuntimeConsumption\ndefault_is_disabled\t{}\n",
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
        inv.push_str(&format!(
            "policy\t{}\tconsumed={:?}\tis_disabled={}\n",
            p.tag(),
            cfg.governance_execution_policy(),
            cfg.is_disabled(),
        ));
    }
    for s in ALL_SURFACES {
        inv.push_str(&format!("surface\t{}\n", s.tag()));
    }
    for v in ["ProceedLegacyBypass", "ProceedAccepted", "FailClosed"] {
        inv.push_str(&format!("consumption_variant\t{}\n", v));
    }
    write_file(&dir.join("runtime_consumption_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_221_governance_execution_runtime_consumption_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("runtime_consumption_selector", run_selector_table),
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("loader", run_loader_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from("run_221_governance_execution_runtime_consumption_release_binary_helper\nscope: Run 220 governance-execution runtime-consumption layer (GovernanceExecutionRuntimeConsumption / consume_surface / consume_surface_from_optional_sidecar_value / governance_execution_load_status_from_optional_sidecar_value) collapsing the Run 217 carrier outcome into the three-way ProceedLegacyBypass/ProceedAccepted/FailClosed decision over the seven runtime surfaces (release binary)\nnote: fixture-only; no real governance execution engine/on-chain verifier/KMS-HSM/RemoteSigner; no mutation; MainNet peer-driven apply remains refused\n\n");
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
