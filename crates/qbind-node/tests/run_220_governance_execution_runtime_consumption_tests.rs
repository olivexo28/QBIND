//! Run 220 — source/test long-running governance-execution runtime
//! **consumption** wiring tests.
//!
//! Source/test only. Run 220 captures **no** release-binary evidence;
//! release-binary governance-execution runtime-consumption evidence is
//! deferred to **Run 221**. Run 217 wired the resolved
//! [`GovernanceExecutionPolicy`] into the seven per-surface preflight
//! wrappers, but the long-running runtime call sites **discarded** the
//! returned outcome (`let _outcome = arming.arm_surface(..)`) and forced
//! [`GovernanceExecutionLoadStatus::Absent`]. Run 220 closes that gap at the
//! source/test level by collapsing the per-surface outcome into a typed
//! [`GovernanceExecutionRuntimeConsumption`] via
//! [`GovernanceExecutionRuntimeArmingConfig::consume_surface`] /
//! [`GovernanceExecutionRuntimeArmingConfig::consume_surface_from_optional_sidecar_value`],
//! and asserting that:
//!
//! * the runtime config **consumes** the selected policy (default / CLI /
//!   env / CLI-over-env / invalid fail-closed);
//! * the runtime config **consumes** real governance-execution sidecar
//!   status (Absent / Available / Malformed) from an optional sidecar JSON
//!   value where representable — no longer a forced `Absent`;
//! * the `arm_surface` outcome is consumed, not discarded (the consumption
//!   decision partitions Proceed / FailClosed exactly);
//! * the Run 213 payload routing reaches the Run 211 evaluator under the
//!   consumed policy;
//! * the A1–A17 accepted scenarios and R1–R28 rejection scenarios from
//!   `task/RUN_220_TASK.txt` hold at the runtime-consumption layer;
//! * validation-only and mutating rejection surfaces never mutate (the
//!   consumption is pure / repeatable);
//! * MainNet peer-driven apply remains refused;
//! * compatibility with the Run 214 governance-execution payload path, the
//!   Run 210 custody-attestation selector, the Run 199 RemoteSigner
//!   selector, and the Run 193 custody selector holds.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_220.md`.

use std::sync::{Mutex, OnceLock};

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadParseError,
    GovernanceExecutionPayloadWire,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionOutcome,
    GovernanceExecutionPolicy, GovernanceQuorumThreshold, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy_surface::{
    GovernanceExecutionPolicySelectorParseError,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    governance_execution_load_status_from_optional_sidecar_value,
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeConsumption,
    GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Env-var serialization (selector tests mutate the process env)
// ===========================================================================

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    prior: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(value: Option<&str>) -> Self {
        let lock = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV).ok();
        match value {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV),
        }
        EnvGuard { prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV),
        }
    }
}

// ===========================================================================
// Shared fixtures (mirror the Run 213 / Run 215 / Run 217 corpus)
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
    GovernanceExecutionLoadStatus::Available(wire.to_parts().expect("wire converts to parts"))
}

fn malformed_loaded() -> GovernanceExecutionLoadStatus {
    GovernanceExecutionLoadStatus::Malformed(GovernanceExecutionPayloadParseError::Json {
        error: "broken".to_string(),
    })
}

/// Build an in-memory sidecar JSON value carrying a well-formed Run 213
/// `governance_execution` sibling — used to prove the runtime path consumes
/// REAL sidecar status (Available), not a forced `Absent`.
fn sidecar_value_with_governance_execution(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> serde_json::Value {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    serde_json::json!({
        "schema_version": 2,
        "governance_execution": serde_json::to_value(&wire).expect("wire serializes"),
    })
}

/// A v2 sidecar value WITHOUT the optional `governance_execution` sibling —
/// must parse to `Absent` (legacy no-governance-execution payload).
fn sidecar_value_without_governance_execution() -> serde_json::Value {
    serde_json::json!({ "schema_version": 2 })
}

/// A v2 sidecar value carrying a malformed `governance_execution` sibling —
/// must parse to `Malformed`.
fn sidecar_value_with_malformed_governance_execution() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 2,
        "governance_execution": { "not": "a-valid-wire" },
    })
}

fn arming_from_cli(cli: Option<&str>) -> GovernanceExecutionRuntimeArmingConfig {
    GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(cli)
        .expect("selector resolves to a runtime-arming config")
}

// ===========================================================================
// Selector → consumed runtime config (default / CLI / env / CLI-over-env)
// ===========================================================================

// A1 / A15. default CLI/env absent resolves to Disabled through the runtime
// config and CONSUMES a legacy no-governance-execution bypass (Run 214
// compatibility) — the runtime path proceeds unchanged.
#[test]
fn a1_a15_default_consumes_legacy_bypass() {
    let _g = EnvGuard::set(None);
    let arming = arming_from_cli(None);
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::Disabled
    );

    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let consumption = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        &td,
        &exp,
        &GovernanceExecutionLoadStatus::Absent,
    );
    assert!(consumption.is_proceed());
    assert!(consumption.is_legacy_bypass());
    assert!(!consumption.is_fail_closed());
}

// A10. CLI-over-env precedence is preserved through the consumed runtime
// config.
#[test]
fn a10_cli_over_env_precedence_preserved() {
    let _g = EnvGuard::set(Some("fixture-governance-allowed"));
    let arming = arming_from_cli(Some("disabled"));
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::Disabled
    );
}

// Selector CLI / env reach the consumed runtime config.
#[test]
fn selector_cli_and_env_reach_consumed_config() {
    {
        let _g = EnvGuard::set(None);
        assert_eq!(
            arming_from_cli(Some("fixture-governance-allowed")).governance_execution_policy(),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed
        );
    }
    {
        let _g = EnvGuard::set(Some("emergency-council-fixture-allowed"));
        assert_eq!(
            arming_from_cli(None).governance_execution_policy(),
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed
        );
    }
}

// A11 / R1. invalid CLI selector fails closed BEFORE the runtime config is
// constructed (never silently downgraded to Disabled).
#[test]
fn a11_r1_invalid_cli_selector_fails_closed_before_config() {
    let _g = EnvGuard::set(None);
    let err =
        GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("totally-bogus")).unwrap_err();
    assert!(matches!(
        err,
        GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
    ));
}

// R1b. empty CLI selector fails closed.
#[test]
fn r1b_empty_cli_selector_fails_closed() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("   ")).unwrap_err(),
        GovernanceExecutionPolicySelectorParseError::Empty
    );
}

// R2. invalid env selector fails closed.
#[test]
fn r2_invalid_env_selector_fails_closed() {
    let _g = EnvGuard::set(Some("nope"));
    assert!(matches!(
        GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None).unwrap_err(),
        GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
    ));
}

// R3. unrelated env does not arm/consume governance execution.
#[test]
fn r3_unrelated_env_does_not_arm() {
    let _g = EnvGuard::set(None);
    std::env::set_var("QBIND_SOME_UNRELATED_FLAG_220", "fixture-governance-allowed");
    assert!(arming_from_cli(None).is_disabled());
    std::env::remove_var("QBIND_SOME_UNRELATED_FLAG_220");
}

// ===========================================================================
// Accepted scenarios A2–A9 / A12–A14 through the consumed runtime config
// ===========================================================================

// A2 / A3. reload-check consumes selected fixture policy and ACCEPTS DevNet
// / TestNet governance-execution material (proceed-accepted).
#[test]
fn a2_a3_reload_check_consumes_and_accepts_fixture() {
    for env in [TrustBundleEnvironment::Devnet, TrustBundleEnvironment::Testnet] {
        let _g = EnvGuard::set(None);
        let arming = arming_from_cli(Some("fixture-governance-allowed"));
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let loaded = available_from(&rotate_input(env), &rotate_decision());
        let consumption = arming.consume_surface(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            &td,
            &exp,
            &loaded,
        );
        assert!(consumption.is_proceed());
        assert!(matches!(
            consumption,
            GovernanceExecutionRuntimeConsumption::ProceedAccepted(
                GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. }
            )
        ));
    }
}

// A4. reload-apply consumes selected fixture policy and accepts DevNet
// fixture material (mutating surface, proceed-accepted).
#[test]
fn a4_reload_apply_consumes_and_accepts() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let consumption =
        arming.consume_surface(GovernanceExecutionRuntimeSurface::ReloadApply, &td, &exp, &loaded);
    assert!(consumption.is_proceed());
}

// A5 / A6 / A7. startup / SIGHUP / local peer-candidate-check consume the
// selected fixture policy and proceed-accept.
#[test]
fn a5_a6_a7_surfaces_consume_and_accept() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    for surface in [
        GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle,
        GovernanceExecutionRuntimeSurface::Sighup,
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
    ] {
        assert!(
            arming
                .consume_surface(surface, &td, &exp, &loaded)
                .is_proceed(),
            "surface {} should consume-accept",
            surface.tag()
        );
    }
}

// A8. live inbound `0x05` consumes the selected policy where representable.
#[test]
fn a8_live_inbound_0x05_consumes_policy() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(arming
        .consume_surface(GovernanceExecutionRuntimeSurface::LiveInbound0x05, &td, &exp, &loaded)
        .is_proceed());
}

// A9 / A13 / R28. peer-driven drain consumes the policy and remains MainNet
// refused unconditionally (fail-closed).
#[test]
fn a9_a13_r28_peer_driven_drain_mainnet_refused() {
    let _g = EnvGuard::set(None);
    let arming = arming_from_cli(Some("fixture-governance-allowed"));

    // Non-MainNet proceeds under fixture policy.
    let dev = TrustBundleEnvironment::Devnet;
    assert!(arming
        .consume_surface(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            &trust_domain(dev),
            &rotate_expectations(dev),
            &available_from(&rotate_input(dev), &rotate_decision()),
        )
        .is_proceed());

    // MainNet refused — fail closed, with the precise reason.
    let main = TrustBundleEnvironment::Mainnet;
    let consumption = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        &trust_domain(main),
        &rotate_expectations(main),
        &available_from(&rotate_input(main), &rotate_decision()),
    );
    assert!(consumption.is_fail_closed());
    assert!(consumption
        .rejecting_outcome()
        .unwrap()
        .is_mainnet_peer_driven_apply_refused());
}

// A12. production-governance-required reaches the production-unavailable
// outcome and fails closed.
#[test]
fn a12_production_required_consumes_unavailable_fail_closed() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("production-governance-required"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
    let loaded = available_from(&input, &rotate_decision());
    let consumption =
        arming.consume_surface(GovernanceExecutionRuntimeSurface::ReloadCheck, &td, &exp, &loaded);
    assert!(consumption.is_fail_closed());
    assert_eq!(
        consumption.rejecting_outcome().unwrap().callsite_outcome(),
        Some(&GovernanceExecutionOutcome::ProductionGovernanceUnavailable)
    );
}

// A14. emergency-council-fixture-allowed only consume-accepts an explicit
// emergency action.
#[test]
fn a14_emergency_council_only_accepts_emergency() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("emergency-council-fixture-allowed"));
    let td = trust_domain(env);

    let accepted = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        &td,
        &emergency_expectations(env),
        &available_from(&emergency_input(env), &emergency_decision()),
    );
    assert!(matches!(
        accepted,
        GovernanceExecutionRuntimeConsumption::ProceedAccepted(
            GovernanceExecutionOutcome::EmergencyCouncilFixtureAccepted { .. }
        )
    ));

    let rejected = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        &td,
        &rotate_expectations(env),
        &available_from(&rotate_input(env), &rotate_decision()),
    );
    assert!(rejected.is_fail_closed());
}

// Revoke action consume-accepted.
#[test]
fn revoke_action_consume_accepted() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let consumption = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadApply,
        &trust_domain(env),
        &revoke_expectations(env),
        &available_from(&revoke_input(env), &revoke_decision()),
    );
    assert!(consumption.is_proceed());
}

// ===========================================================================
// A16 — `arm_surface` outcome consumed, not discarded
// ===========================================================================

// A16. every consumption decision partitions the outcome space: a proceed
// decision is NOT a fail-closed decision and vice-versa. No outcome is
// silently dropped.
#[test]
fn a16_arm_surface_outcome_is_consumed_not_discarded() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);

    // Accept → proceed-accepted (consumed).
    let accept = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        &td,
        &exp,
        &available_from(&rotate_input(env), &rotate_decision()),
    );
    assert!(accept.is_proceed() ^ accept.is_fail_closed());
    assert!(accept.is_proceed());

    // Reject → fail-closed (consumed, with a reason).
    let reject = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        &td,
        &exp,
        &malformed_loaded(),
    );
    assert!(reject.is_proceed() ^ reject.is_fail_closed());
    assert!(reject.is_fail_closed());
    assert!(reject.fail_closed_reason().is_some());
}

// ===========================================================================
// A17 — real sidecar status consumed (NO forced Absent)
// ===========================================================================

// A17 / regression. an optional sidecar JSON value carrying a well-formed
// `governance_execution` sibling is consumed as REAL `Available` status
// (not a forced `Absent`); absent sibling → `Absent`; malformed sibling →
// `Malformed`.
#[test]
fn a17_real_sidecar_status_consumed_not_forced_absent() {
    let env = TrustBundleEnvironment::Devnet;

    // Present, well-formed sibling → Available (NOT Absent).
    let present = sidecar_value_with_governance_execution(&rotate_input(env), &rotate_decision());
    assert!(matches!(
        governance_execution_load_status_from_optional_sidecar_value(Some(&present)),
        GovernanceExecutionLoadStatus::Available(_)
    ));

    // Absent sibling → Absent.
    let absent = sidecar_value_without_governance_execution();
    assert!(matches!(
        governance_execution_load_status_from_optional_sidecar_value(Some(&absent)),
        GovernanceExecutionLoadStatus::Absent
    ));

    // Malformed sibling → Malformed.
    let malformed = sidecar_value_with_malformed_governance_execution();
    assert!(matches!(
        governance_execution_load_status_from_optional_sidecar_value(Some(&malformed)),
        GovernanceExecutionLoadStatus::Malformed(_)
    ));

    // No sidecar at all → Absent.
    assert!(matches!(
        governance_execution_load_status_from_optional_sidecar_value(None),
        GovernanceExecutionLoadStatus::Absent
    ));
}

// A17b. the consume-from-optional-sidecar-value path routes the REAL parsed
// status through the consumed policy: a present valid sibling under a
// fixture policy proceed-accepts; a malformed sibling fails closed.
#[test]
fn a17b_consume_from_optional_sidecar_value_routes_real_status() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);

    let present = sidecar_value_with_governance_execution(&rotate_input(env), &rotate_decision());
    assert!(arming
        .consume_surface_from_optional_sidecar_value(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            &td,
            &exp,
            Some(&present),
        )
        .is_proceed());

    let malformed = sidecar_value_with_malformed_governance_execution();
    assert!(arming
        .consume_surface_from_optional_sidecar_value(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            &td,
            &exp,
            Some(&malformed),
        )
        .is_fail_closed());

    // Absent sidecar under Disabled is a legacy bypass.
    let disabled = GovernanceExecutionRuntimeArmingConfig::disabled();
    assert!(disabled
        .consume_surface_from_optional_sidecar_value(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            &td,
            &exp,
            None,
        )
        .is_legacy_bypass());
}

// ===========================================================================
// Source reachability — consumed config reaches all seven surfaces and the
// Run 211 evaluator
// ===========================================================================

#[test]
fn consumed_config_reaches_all_seven_surfaces() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    for surface in GovernanceExecutionRuntimeSurface::ALL {
        // Every non-MainNet surface proceeds on valid fixture material.
        assert!(
            arming.consume_surface(surface, &td, &exp, &loaded).is_proceed(),
            "surface {} should consume-proceed",
            surface.tag()
        );
    }
}

#[test]
fn payload_routing_reaches_run_211_evaluator_under_consumed_policy() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let consumption = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        &trust_domain(env),
        &rotate_expectations(env),
        &available_from(&rotate_input(env), &rotate_decision()),
    );
    assert!(matches!(
        consumption,
        GovernanceExecutionRuntimeConsumption::ProceedAccepted(_)
    ));
}

// ===========================================================================
// Rejection scenarios R4–R27 through the consumed config
// ===========================================================================

// R4 / R5. missing material fails closed under FixtureGovernanceAllowed /
// ProductionGovernanceRequired.
#[test]
fn r4_r5_absent_material_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    for policy in ["fixture-governance-allowed", "production-governance-required"] {
        let _g = EnvGuard::set(None);
        let arming = arming_from_cli(Some(policy));
        let consumption = arming.consume_surface(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            &trust_domain(env),
            &rotate_expectations(env),
            &GovernanceExecutionLoadStatus::Absent,
        );
        assert!(consumption.is_fail_closed());
        assert!(consumption
            .rejecting_outcome()
            .unwrap()
            .is_required_but_absent());
    }
}

// R6. malformed material fails closed.
#[test]
fn r6_malformed_material_fails_closed() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let consumption = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadApply,
        &trust_domain(env),
        &rotate_expectations(env),
        &malformed_loaded(),
    );
    assert!(consumption.is_fail_closed());
    assert!(consumption
        .rejecting_outcome()
        .unwrap()
        .is_malformed_payload());
}

// R7 / R8 / R9. fixture & emergency rejected under production/mainnet
// required.
#[test]
fn r7_r8_r9_fixture_emergency_rejected_under_required() {
    let env = TrustBundleEnvironment::Devnet;
    // R7: fixture under production-required.
    {
        let _g = EnvGuard::set(None);
        let arming = arming_from_cli(Some("production-governance-required"));
        assert_eq!(
            arming
                .consume_surface(
                    GovernanceExecutionRuntimeSurface::ReloadCheck,
                    &trust_domain(env),
                    &rotate_expectations(env),
                    &available_from(&rotate_input(env), &rotate_decision()),
                )
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
        );
    }
    // R8: emergency fixture under production-required.
    {
        let _g = EnvGuard::set(None);
        let arming = arming_from_cli(Some("production-governance-required"));
        assert_eq!(
            arming
                .consume_surface(
                    GovernanceExecutionRuntimeSurface::ReloadCheck,
                    &trust_domain(env),
                    &emergency_expectations(env),
                    &available_from(&emergency_input(env), &emergency_decision()),
                )
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::EmergencyFixtureRejectedProductionRequired)
        );
    }
    // R9: fixture under mainnet-required.
    {
        let _g = EnvGuard::set(None);
        let arming = arming_from_cli(Some("mainnet-governance-required"));
        assert_eq!(
            arming
                .consume_surface(
                    GovernanceExecutionRuntimeSurface::ReloadCheck,
                    &trust_domain(env),
                    &rotate_expectations(env),
                    &available_from(&rotate_input(env), &rotate_decision()),
                )
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::FixtureRejectedMainnetRequired)
        );
    }
}

// R10 / R11 / R12. production / on-chain / MainNet governance unavailable.
#[test]
fn r10_r11_r12_production_onchain_mainnet_unavailable() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let cases = [
        (
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
            GovernanceExecutionOutcome::ProductionGovernanceUnavailable,
        ),
        (
            GovernanceExecutionClass::OnChainGovernanceUnavailable,
            GovernanceExecutionOutcome::OnChainGovernanceUnavailable,
        ),
        (
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
            GovernanceExecutionOutcome::MainNetGovernanceUnavailable,
        ),
    ];
    for (class, expected) in cases {
        let mut input = rotate_input(env);
        input.governance_class = class;
        let consumption = arming.consume_surface(
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            &td,
            &exp,
            &available_from(&input, &rotate_decision()),
        );
        assert!(consumption.is_fail_closed());
        assert_eq!(
            consumption.rejecting_outcome().unwrap().callsite_outcome(),
            Some(&expected)
        );
    }
}

// R13–R22. evaluator-level rejections all fail closed through consumption.
#[test]
fn r13_to_r22_evaluator_rejections_fail_closed() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);

    let consume = |exp: &GovernanceExecutionExpectations, loaded: &GovernanceExecutionLoadStatus| {
        arming.consume_surface(GovernanceExecutionRuntimeSurface::ReloadCheck, &td, exp, loaded)
    };

    // R13 wrong lifecycle action.
    {
        let mut d = rotate_decision();
        d.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
        d.authorized_governance_action = GovernanceAction::Revoke;
        assert!(matches!(
            consume(&rotate_expectations(env), &available_from(&rotate_input(env), &d))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(GovernanceExecutionOutcome::WrongLifecycleAction { .. })
        ));
    }
    // R14 wrong candidate digest.
    {
        let mut input = rotate_input(env);
        input.candidate_digest = "different".to_string();
        let mut d = rotate_decision();
        d.authorized_candidate_digest = "different".to_string();
        assert!(matches!(
            consume(&rotate_expectations(env), &available_from(&input, &d))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(GovernanceExecutionOutcome::WrongCandidateDigest { .. })
        ));
    }
    // R15 wrong sequence.
    {
        let mut input = rotate_input(env);
        input.authority_domain_sequence = 9;
        let mut d = rotate_decision();
        d.authorized_sequence = 9;
        assert!(matches!(
            consume(&rotate_expectations(env), &available_from(&input, &d))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(GovernanceExecutionOutcome::WrongAuthorityDomainSequence { .. })
        ));
    }
    // R16 wrong governance proof digest.
    {
        let mut input = rotate_input(env);
        input.governance_proof_digest = "wrong".to_string();
        assert!(matches!(
            consume(&rotate_expectations(env), &available_from(&input, &rotate_decision()))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(GovernanceExecutionOutcome::WrongGovernanceProofDigest { .. })
        ));
    }
    // R17 expired decision.
    {
        let mut exp = rotate_expectations(env);
        exp.now_epoch = 250;
        assert!(matches!(
            consume(&exp, &available_from(&rotate_input(env), &rotate_decision()))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(GovernanceExecutionOutcome::ExpiredDecision { .. })
        ));
    }
    // R18 stale/replayed.
    {
        let mut exp = rotate_expectations(env);
        exp.expected_replay_nonce = "fresh".to_string();
        assert_eq!(
            consume(&exp, &available_from(&rotate_input(env), &rotate_decision()))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::StaleOrReplayedDecision)
        );
    }
    // R19 quorum insufficient.
    {
        let mut input = rotate_input(env);
        input.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
        assert!(matches!(
            consume(&rotate_expectations(env), &available_from(&input, &rotate_decision()))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(GovernanceExecutionOutcome::QuorumThresholdInsufficient { .. })
        ));
    }
    // R20 emergency action not authorized.
    {
        let mut input = emergency_input(env);
        input.governance_class = GovernanceExecutionClass::FixtureGovernance;
        let mut d = emergency_decision();
        d.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
        assert_eq!(
            consume(&emergency_expectations(env), &available_from(&input, &d))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::EmergencyActionNotAuthorized)
        );
    }
    // R21 validator-set rotation unsupported.
    {
        let mut input = rotate_input(env);
        input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        assert_eq!(
            consume(&rotate_expectations(env), &available_from(&input, &rotate_decision()))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::ValidatorSetRotationUnsupported)
        );
    }
    // R22 policy-change action unsupported.
    {
        let mut input = rotate_input(env);
        input.governance_action = GovernanceAction::PolicyChangeRequest;
        assert_eq!(
            consume(&rotate_expectations(env), &available_from(&input, &rotate_decision()))
                .rejecting_outcome()
                .unwrap()
                .callsite_outcome(),
            Some(&GovernanceExecutionOutcome::PolicyChangeActionUnsupported)
        );
    }
}

// R23 / R24. local operator & peer majority cannot satisfy governance
// execution — production-required fails closed with fixture material.
#[test]
fn r23_r24_local_and_peer_cannot_satisfy() {
    use qbind_node::pqc_governance_execution_policy::{
        local_operator_cannot_satisfy_governance_execution,
        peer_majority_cannot_satisfy_governance_execution,
    };
    assert!(local_operator_cannot_satisfy_governance_execution());
    assert!(peer_majority_cannot_satisfy_governance_execution());

    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("production-governance-required"));
    assert_eq!(
        arming
            .consume_surface(
                GovernanceExecutionRuntimeSurface::ReloadCheck,
                &trust_domain(env),
                &rotate_expectations(env),
                &available_from(&rotate_input(env), &rotate_decision()),
            )
            .rejecting_outcome()
            .unwrap()
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R25. validation-only rejection is pure / repeatable (no marker, no
// sequence — the consumption is a pure function).
#[test]
fn r25_validation_only_rejection_is_pure() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut decision = rotate_decision();
    decision.approved = false;
    let loaded = available_from(&rotate_input(env), &decision);
    let a = arming.consume_surface(GovernanceExecutionRuntimeSurface::ReloadCheck, &td, &exp, &loaded);
    let b = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
        &td,
        &exp,
        &loaded,
    );
    assert!(a.is_fail_closed());
    assert_eq!(a, b);
}

// R26. mutating rejection is pure / repeatable.
#[test]
fn r26_mutating_rejection_is_pure() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let a = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadApply,
        &td,
        &exp,
        &malformed_loaded(),
    );
    let b = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::ReloadApply,
        &td,
        &exp,
        &malformed_loaded(),
    );
    assert!(a.is_fail_closed());
    assert_eq!(a, b);
}

// R27. invalid live inbound `0x05` candidate is not propagated/staged/
// applied — the consumption short-circuits to fail-closed.
#[test]
fn r27_invalid_live_0x05_fails_closed() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let consumption = arming.consume_surface(
        GovernanceExecutionRuntimeSurface::LiveInbound0x05,
        &trust_domain(env),
        &rotate_expectations(env),
        &malformed_loaded(),
    );
    assert!(consumption.is_fail_closed());
    assert!(consumption
        .rejecting_outcome()
        .unwrap()
        .is_malformed_payload());
}

// ===========================================================================
// Compatibility with sibling Run selectors (Run 214 / 210 / 199 / 193)
// ===========================================================================

#[test]
fn compatibility_with_sibling_run_selectors() {
    {
        let _g = EnvGuard::set(None);
        assert_eq!(
            qbind_node::pqc_authority_custody_policy_surface::authority_custody_policy_from_cli_or_env(
                None
            )
            .unwrap(),
            qbind_node::pqc_authority_custody::AuthorityCustodyPolicy::Disabled
        );
        assert_eq!(
            qbind_node::pqc_remote_signer_policy_surface::remote_signer_policy_from_cli_or_env(None)
                .unwrap(),
            qbind_node::pqc_remote_authority_signer::RemoteSignerPolicy::Disabled
        );
        assert_eq!(
            qbind_node::pqc_custody_attestation_policy_surface::custody_attestation_policy_from_cli_or_env(
                None
            )
            .unwrap(),
            qbind_node::pqc_custody_attestation_verifier::CustodyAttestationPolicy::Disabled
        );
    }
    {
        let _g2 = EnvGuard::set(Some("fixture-governance-allowed"));
        assert_eq!(
            arming_from_cli(None).governance_execution_policy(),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed
        );
    }
}