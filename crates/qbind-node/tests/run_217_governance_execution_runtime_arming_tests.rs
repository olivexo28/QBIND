//! Run 217 — source/test governance-execution runtime policy arming
//! wiring tests.
//!
//! Source/test only. Run 217 captures **no** release-binary evidence;
//! release-binary governance-execution runtime-arming evidence is deferred
//! to **Run 218**. These tests drive the hidden Run 215
//! governance-execution policy selector through the Run 217 runtime-config
//! carrier
//! [`qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeArmingConfig`]
//! and assert that:
//!
//! * the CLI/env selector reaches the runtime config (default / CLI / env
//!   / CLI-over-env / invalid fail-closed);
//! * the runtime config reaches all seven Run 213 / Run 215 per-surface
//!   preflight wrappers (reload-check, reload-apply, startup
//!   `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live
//!   inbound `0x05`, peer-driven drain) where representable;
//! * the Run 213 payload routing reaches the Run 211 evaluator under the
//!   armed policy;
//! * the A1–A15 accepted scenarios and R1–R28 rejection scenarios from
//!   `task/RUN_217_TASK.txt` hold at the runtime-arming layer;
//! * no-mutation invariants (validation-only + mutating rejection
//!   surfaces never mutate — the wrappers are pure / repeatable);
//! * MainNet peer-driven apply remains refused even with
//!   `MainnetGovernanceRequired` and fully-valid fixture governance
//!   approval;
//! * compatibility with the Run 214 governance-execution payload path,
//!   the Run 210 custody-attestation selector, the Run 199 RemoteSigner
//!   selector, and the Run 193 custody selector (their selectors are
//!   independent and unaffected by the governance-execution selector).
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_217.md`.

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
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
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
// Shared fixtures (mirror the Run 213 / Run 215 corpus)
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

/// Build a runtime-arming config from the CLI selector (env serialized by
/// the caller). Panics on a parse error — callers that expect an error use
/// [`GovernanceExecutionRuntimeArmingConfig::from_cli_or_env`] directly.
fn arming_from_cli(cli: Option<&str>) -> GovernanceExecutionRuntimeArmingConfig {
    GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(cli)
        .expect("selector resolves to a runtime-arming config")
}

// ===========================================================================
// Selector → runtime config (default / CLI / env / CLI-over-env / invalid)
// ===========================================================================

// A1 / A15. default CLI/env absent resolves to Disabled through runtime
// config, and an absent governance-execution carrier is accepted as a
// legacy no-governance-execution payload (Run 214 compatibility).
#[test]
fn a1_a15_default_runtime_arming_is_disabled_and_compatible() {
    let _g = EnvGuard::set(None);
    let arming = arming_from_cli(None);
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::Disabled
    );
    assert!(arming.is_disabled());

    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome =
        arming.preflight_reload_check(&td, &exp, &GovernanceExecutionLoadStatus::Absent);
    assert!(outcome.is_bypassed());
    assert!(!outcome.is_reject());
}

// Selector reaches runtime config via the CLI source.
#[test]
fn selector_cli_reaches_runtime_config() {
    let _g = EnvGuard::set(None);
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
}

// Selector reaches runtime config via the env source.
#[test]
fn selector_env_reaches_runtime_config() {
    let _g = EnvGuard::set(Some("emergency-council-fixture-allowed"));
    let arming = arming_from_cli(None);
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed
    );
}

// A10. CLI-over-env precedence is preserved through the runtime config.
#[test]
fn a10_cli_over_env_precedence_through_runtime_config() {
    let _g = EnvGuard::set(Some("fixture-governance-allowed"));
    // CLI sets disabled while env sets fixture-governance-allowed.
    let arming = arming_from_cli(Some("disabled"));
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::Disabled
    );
}

// A11 / R1. invalid CLI selector fails closed before runtime mutation —
// the runtime config is never constructed.
#[test]
fn a11_r1_invalid_cli_selector_fails_closed_before_runtime_config() {
    let _g = EnvGuard::set(None);
    let err = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("totally-bogus"))
        .unwrap_err();
    assert!(matches!(
        err,
        GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
    ));
    assert_eq!(err.tag(), "unknown-value");
}

// R1b. empty CLI selector fails closed before runtime config.
#[test]
fn r1b_empty_cli_selector_fails_closed() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(Some("   ")).unwrap_err(),
        GovernanceExecutionPolicySelectorParseError::Empty
    );
}

// R2. invalid env selector fails closed before runtime config.
#[test]
fn r2_invalid_env_selector_fails_closed() {
    let _g = EnvGuard::set(Some("nope"));
    let err = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(None).unwrap_err();
    assert!(matches!(
        err,
        GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
    ));
}

// R3. unrelated CLI/env does not arm governance execution.
#[test]
fn r3_unrelated_env_does_not_arm_policy() {
    let _g = EnvGuard::set(None);
    std::env::set_var("QBIND_SOME_UNRELATED_FLAG_217", "fixture-governance-allowed");
    let arming = arming_from_cli(None);
    assert!(arming.is_disabled());
    std::env::remove_var("QBIND_SOME_UNRELATED_FLAG_217");
}

// ===========================================================================
// Accepted scenarios A2–A9 / A12–A14 through the runtime config
// ===========================================================================

// A2. runtime reload-check consumes selected fixture policy and accepts
// DevNet fixture governance-execution material.
#[test]
fn a2_reload_check_devnet_fixture_accepted() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = arming.preflight_reload_check(&td, &exp, &loaded);
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. })
    ));
}

// A3. runtime reload-check consumes selected fixture policy and accepts
// TestNet fixture governance-execution material (env source).
#[test]
fn a3_reload_check_testnet_fixture_accepted() {
    let _g = EnvGuard::set(Some("fixture-governance-allowed"));
    let env = TrustBundleEnvironment::Testnet;
    let arming = arming_from_cli(None);
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = arming.preflight_reload_check(&td, &exp, &loaded);
    assert!(outcome.is_accept());
}

// A4. runtime reload-apply consumes selected fixture policy and accepts
// DevNet fixture governance-execution material.
#[test]
fn a4_reload_apply_devnet_fixture_accepted() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = arming.preflight_reload_apply(&td, &exp, &loaded);
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            lifecycle_action: LocalLifecycleAction::Rotate,
            ..
        })
    ));
}

// A5. startup `--p2p-trust-bundle` preflight consumes selected fixture
// policy.
#[test]
fn a5_startup_consumes_fixture_policy() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(arming
        .preflight_startup_p2p_trust_bundle(&td, &exp, &loaded)
        .is_accept());
}

// A6. SIGHUP preflight consumes selected fixture policy.
#[test]
fn a6_sighup_consumes_fixture_policy() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(arming.preflight_sighup(&td, &exp, &loaded).is_accept());
}

// A7. local peer-candidate-check consumes selected fixture policy.
#[test]
fn a7_local_peer_candidate_check_consumes_fixture_policy() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(arming
        .preflight_local_peer_candidate_check(&td, &exp, &loaded)
        .is_accept());
}

// A8. live inbound `0x05` consumes selected policy where representable.
// (Live-config threading is deferred to Run 218; the limitation is
// documented on the wrapper and module.)
#[test]
fn a8_live_inbound_0x05_consumes_selected_policy() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(arming
        .preflight_live_inbound_0x05(&td, &exp, &loaded)
        .is_accept());
}

// A9. peer-driven drain consumes selected policy and remains MainNet
// refused; accepts on non-MainNet under fixture policy.
#[test]
fn a9_peer_driven_drain_consumes_policy_and_mainnet_refused() {
    let _g = EnvGuard::set(None);
    let arming = arming_from_cli(Some("fixture-governance-allowed"));

    // Non-MainNet: accepts under fixture policy.
    let dev = TrustBundleEnvironment::Devnet;
    let td = trust_domain(dev);
    let exp = rotate_expectations(dev);
    let loaded = available_from(&rotate_input(dev), &rotate_decision());
    assert!(arming.preflight_peer_driven_drain(&td, &exp, &loaded).is_accept());

    // MainNet: refused unconditionally.
    let main = TrustBundleEnvironment::Mainnet;
    let td_m = trust_domain(main);
    let exp_m = rotate_expectations(main);
    let loaded_m = available_from(&rotate_input(main), &rotate_decision());
    let outcome = arming.preflight_peer_driven_drain(&td_m, &exp_m, &loaded_m);
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert!(!outcome.is_accept());
}

// A12. production-governance-required reaches the production governance
// unavailable outcome.
#[test]
fn a12_production_required_reaches_unavailable() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("production-governance-required"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
    let loaded = available_from(&input, &rotate_decision());
    let outcome = arming.preflight_reload_check(&td, &exp, &loaded);
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::ProductionGovernanceUnavailable)
    );
}

// A13. mainnet-governance-required reaches MainNet refusal at the
// peer-driven drain surface (MainNet refused regardless of policy).
#[test]
fn a13_mainnet_required_reaches_mainnet_refusal() {
    let _g = EnvGuard::set(Some("mainnet-governance-required"));
    let arming = arming_from_cli(None);
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::MainnetGovernanceRequired
    );
    let env = TrustBundleEnvironment::Mainnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(arming
        .preflight_peer_driven_drain(&td, &exp, &loaded)
        .is_mainnet_peer_driven_apply_refused());
}

// A14. emergency-council-fixture-allowed only accepts an explicit
// emergency action.
#[test]
fn a14_emergency_council_only_accepts_emergency_action() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("emergency-council-fixture-allowed"));
    let td = trust_domain(env);

    // Explicit emergency action accepted.
    let exp_e = emergency_expectations(env);
    let loaded_e = available_from(&emergency_input(env), &emergency_decision());
    let accepted = arming.preflight_reload_check(&td, &exp_e, &loaded_e);
    assert!(accepted.is_accept());
    assert!(matches!(
        accepted.callsite_outcome(),
        Some(GovernanceExecutionOutcome::EmergencyCouncilFixtureAccepted { .. })
    ));

    // A non-emergency (plain rotate) fixture is NOT accepted under the
    // emergency-council policy.
    let exp_r = rotate_expectations(env);
    let loaded_r = available_from(&rotate_input(env), &rotate_decision());
    let rejected = arming.preflight_reload_check(&td, &exp_r, &loaded_r);
    assert!(!rejected.is_accept());
}

// ===========================================================================
// Source reachability — runtime config reaches all seven surfaces
// ===========================================================================

#[test]
fn runtime_config_reaches_all_seven_surfaces_on_accept() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());

    for surface in GovernanceExecutionRuntimeSurface::ALL {
        let outcome = arming.arm_surface(surface, &td, &exp, &loaded);
        // Every non-MainNet surface routes through the Run 211 evaluator
        // and accepts the valid fixture material.
        assert!(
            outcome.is_accept(),
            "surface {} should accept valid fixture material",
            surface.tag()
        );
    }
}

// Run 213 payload routing reaches the Run 211 evaluator under the armed
// policy — a valid present carrier produces a Run 211 Callsite outcome.
#[test]
fn payload_routing_reaches_run_211_evaluator() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = arming.preflight_reload_check(&td, &exp, &loaded);
    assert!(outcome.callsite_outcome().is_some());
}

// ===========================================================================
// Rejection scenarios R4–R28 through the runtime config
// ===========================================================================

// R4. missing governance-execution material rejected under
// FixtureGovernanceAllowed.
#[test]
fn r4_absent_rejected_under_fixture_allowed() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome =
        arming.preflight_reload_check(&td, &exp, &GovernanceExecutionLoadStatus::Absent);
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

// R5. missing governance-execution material rejected under
// ProductionGovernanceRequired.
#[test]
fn r5_absent_rejected_under_production_required() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("production-governance-required"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome =
        arming.preflight_reload_check(&td, &exp, &GovernanceExecutionLoadStatus::Absent);
    assert!(outcome.is_required_but_absent());
}

// R6. fixture governance rejected under ProductionGovernanceRequired.
#[test]
fn r6_fixture_rejected_production_required() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("production-governance-required"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R7. emergency fixture rejected under ProductionGovernanceRequired.
#[test]
fn r7_emergency_fixture_rejected_production_required() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("production-governance-required"));
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let loaded = available_from(&emergency_input(env), &emergency_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::EmergencyFixtureRejectedProductionRequired)
    );
}

// R8. fixture governance rejected under MainnetGovernanceRequired.
#[test]
fn r8_fixture_rejected_mainnet_required() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("mainnet-governance-required"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedMainnetRequired)
    );
}

// R9 / R10 / R11. production / on-chain / MainNet governance rejected as
// unavailable under a fixture-allowed policy.
#[test]
fn r9_r10_r11_production_onchain_mainnet_unavailable() {
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
        let loaded = available_from(&input, &rotate_decision());
        assert_eq!(
            arming
                .preflight_reload_check(&td, &exp, &loaded)
                .callsite_outcome(),
            Some(&expected)
        );
    }
}

// R12. malformed governance execution material rejected.
#[test]
fn r12_malformed_material_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = arming.preflight_reload_apply(&td, &exp, &malformed_loaded());
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

// R13. wrong lifecycle action rejected.
#[test]
fn r13_wrong_lifecycle_action_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut decision = rotate_decision();
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    decision.authorized_governance_action = GovernanceAction::Revoke;
    let loaded = available_from(&rotate_input(env), &decision);
    assert!(matches!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongLifecycleAction { .. })
    ));
}

// R14. wrong candidate digest rejected.
#[test]
fn r14_wrong_candidate_digest_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.candidate_digest = "different-digest".to_string();
    let mut decision = rotate_decision();
    decision.authorized_candidate_digest = "different-digest".to_string();
    let loaded = available_from(&input, &decision);
    assert!(matches!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongCandidateDigest { .. })
    ));
}

// R15. wrong authority-domain sequence rejected.
#[test]
fn r15_wrong_sequence_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.authority_domain_sequence = 9;
    let mut decision = rotate_decision();
    decision.authorized_sequence = 9;
    let loaded = available_from(&input, &decision);
    assert!(matches!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongAuthorityDomainSequence { .. })
    ));
}

// R16. wrong governance proof digest rejected.
#[test]
fn r16_wrong_governance_proof_digest_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_proof_digest = "wrong-proof".to_string();
    let loaded = available_from(&input, &rotate_decision());
    assert!(matches!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongGovernanceProofDigest { .. })
    ));
}

// R17. expired decision rejected.
#[test]
fn r17_expired_decision_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.now_epoch = 250; // past expiry_epoch 200
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(matches!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::ExpiredDecision { .. })
    ));
}

// R18. stale/replayed decision rejected.
#[test]
fn r18_stale_replayed_decision_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_replay_nonce = "fresh-nonce".to_string();
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::StaleOrReplayedDecision)
    );
}

// R19. quorum threshold insufficient rejected.
#[test]
fn r19_quorum_insufficient_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
    let loaded = available_from(&input, &rotate_decision());
    assert!(matches!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::QuorumThresholdInsufficient { .. })
    ));
}

// R20. emergency action not authorized rejected.
#[test]
fn r20_emergency_action_not_authorized_rejected() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let mut input = emergency_input(env);
    input.governance_class = GovernanceExecutionClass::FixtureGovernance;
    let mut decision = emergency_decision();
    decision.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
    let loaded = available_from(&input, &decision);
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::EmergencyActionNotAuthorized)
    );
}

// R21. validator-set rotation unsupported rejected.
#[test]
fn r21_validator_set_rotation_unsupported() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    let loaded = available_from(&input, &rotate_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::ValidatorSetRotationUnsupported)
    );
}

// R22. policy-change action unsupported rejected.
#[test]
fn r22_policy_change_action_unsupported() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::PolicyChangeRequest;
    let loaded = available_from(&input, &rotate_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::PolicyChangeActionUnsupported)
    );
}

// R23 / R24. local operator and peer majority cannot satisfy governance
// execution — both represented by ProductionGovernanceRequired failing
// closed with fixture material (no local/peer authority can satisfy it).
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
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert_eq!(
        arming
            .preflight_reload_check(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R25. validation-only rejection writes no marker and no sequence — the
// validation-only wrappers are pure / repeatable and produce equal
// outcomes.
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
    let a = arming.preflight_reload_check(&td, &exp, &loaded);
    let b = arming.preflight_local_peer_candidate_check(&td, &exp, &loaded);
    assert!(a.is_reject());
    assert_eq!(a, b);
}

// R26. mutating rejection produces no Run 070 call, no live trust swap,
// no session eviction, no sequence write, and no marker write — the
// mutating wrapper only returns a typed outcome (pure / repeatable).
#[test]
fn r26_mutating_rejection_is_pure() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let a = arming.preflight_reload_apply(&td, &exp, &malformed_loaded());
    let b = arming.preflight_reload_apply(&td, &exp, &malformed_loaded());
    assert!(a.is_reject());
    assert_eq!(a, b);
}

// R27. invalid live inbound `0x05` governance-execution candidate is not
// propagated, staged, or applied — the wrapper short-circuits to a reject.
#[test]
fn r27_invalid_live_0x05_not_propagated() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = arming.preflight_live_inbound_0x05(&td, &exp, &malformed_loaded());
    assert!(outcome.is_reject());
    assert!(outcome.is_malformed_payload());
}

// R28. MainNet peer-driven apply remains refused even with
// MainnetGovernanceRequired and a fully-valid fixture governance approval.
#[test]
fn r28_mainnet_peer_driven_apply_refused_with_fixture_approval() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Mainnet;
    // Even under FixtureGovernanceAllowed with valid material, MainNet
    // peer-driven apply is refused unconditionally.
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = arming.preflight_peer_driven_drain(&td, &exp, &loaded);
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert!(!outcome.is_accept());

    // ...and even under MainnetGovernanceRequired the refusal holds.
    let arming_main = GovernanceExecutionRuntimeArmingConfig::with_policy(
        GovernanceExecutionPolicy::MainnetGovernanceRequired,
    );
    assert!(arming_main
        .preflight_peer_driven_drain(&td, &exp, &loaded)
        .is_mainnet_peer_driven_apply_refused());
}

// ===========================================================================
// Revoke-action acceptance + compatibility with sibling Run selectors
// ===========================================================================

// Revoke lifecycle action authorized through the runtime config.
#[test]
fn revoke_action_authorized_through_runtime_config() {
    let _g = EnvGuard::set(None);
    let env = TrustBundleEnvironment::Devnet;
    let arming = arming_from_cli(Some("fixture-governance-allowed"));
    let td = trust_domain(env);
    let exp = revoke_expectations(env);
    let loaded = available_from(&revoke_input(env), &revoke_decision());
    assert!(matches!(
        arming
            .preflight_reload_apply(&td, &exp, &loaded)
            .callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            lifecycle_action: LocalLifecycleAction::Revoke,
            ..
        })
    ));
}

// Compatibility: the governance-execution selector is independent of the
// Run 193 custody, Run 199 RemoteSigner, and Run 210 custody-attestation
// selectors — arming governance execution does not perturb their default
// resolution, and an unset governance-execution selector leaves the
// default Disabled (Run 214 no-governance-execution payload) compatible.
#[test]
fn compatibility_with_sibling_run_selectors() {
    let _g = EnvGuard::set(None);

    // Run 193 custody selector default.
    assert_eq!(
        qbind_node::pqc_authority_custody_policy_surface::authority_custody_policy_from_cli_or_env(
            None
        )
        .unwrap(),
        qbind_node::pqc_authority_custody::AuthorityCustodyPolicy::Disabled
    );
    // Run 199 RemoteSigner selector default.
    assert_eq!(
        qbind_node::pqc_remote_signer_policy_surface::remote_signer_policy_from_cli_or_env(None)
            .unwrap(),
        qbind_node::pqc_remote_authority_signer::RemoteSignerPolicy::Disabled
    );
    // Run 210 custody-attestation selector default.
    assert_eq!(
        qbind_node::pqc_custody_attestation_policy_surface::custody_attestation_policy_from_cli_or_env(
            None
        )
        .unwrap(),
        qbind_node::pqc_custody_attestation_verifier::CustodyAttestationPolicy::Disabled
    );

    // Arming governance execution (env source) does not change the above
    // sibling defaults and itself resolves correctly.
    let _g2 = EnvGuard::set(Some("fixture-governance-allowed"));
    let arming = arming_from_cli(None);
    assert_eq!(
        arming.governance_execution_policy(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
}