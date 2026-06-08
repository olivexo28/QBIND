//! Run 215 — source/test hidden governance-execution policy selector and
//! production preflight integration tests.
//!
//! Source/test only. Run 215 does **not** capture release-binary
//! evidence; release-binary governance-execution-policy selector
//! evidence is deferred to **Run 216**. The tests cover:
//!
//! * selector parsing + precedence (default / CLI / env / CLI-over-env /
//!   invalid value fail-closed) for
//!   [`governance_execution_policy_from_selector`],
//!   [`governance_execution_policy_env_selector`], and
//!   [`governance_execution_policy_from_cli_or_env`];
//! * the A1–A16 / R1–R40 matrix from `task/RUN_215_TASK.txt` where
//!   representable at the selector + production-context preflight layer;
//! * source reachability (the selected policy reaches all seven Run 215
//!   per-surface preflight wrappers and through them the Run 213/211
//!   evaluator);
//! * action authorization (rotate / revoke / emergency-revoke / wrong
//!   action fail-closed);
//! * no-mutation invariants (validation-only + mutating rejection
//!   surfaces never mutate);
//! * MainNet refusal invariants.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_215.md`.

use std::sync::{Mutex, OnceLock};

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
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
    governance_execution_policy_env_selector, governance_execution_policy_from_cli_or_env,
    governance_execution_policy_from_selector,
    preflight_v2_marker_governance_execution_for_live_inbound_0x05,
    preflight_v2_marker_governance_execution_for_local_peer_candidate_check,
    preflight_v2_marker_governance_execution_for_peer_driven_drain,
    preflight_v2_marker_governance_execution_for_reload_apply,
    preflight_v2_marker_governance_execution_for_reload_check,
    preflight_v2_marker_governance_execution_for_sighup,
    preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle,
    GovernanceExecutionPolicySelectorParseError,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV,
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
// Shared fixtures (mirror the Run 213 corpus)
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

/// Build a `GovernanceExecutionLoadStatus::Available` from a wire payload
/// round-trip (input + decision -> wire -> parts).
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

// ===========================================================================
// Selector parsing + precedence
// ===========================================================================

#[test]
fn selector_parses_all_canonical_tags() {
    assert_eq!(
        governance_execution_policy_from_selector("disabled").unwrap(),
        GovernanceExecutionPolicy::Disabled
    );
    assert_eq!(
        governance_execution_policy_from_selector("fixture-governance-allowed").unwrap(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
    assert_eq!(
        governance_execution_policy_from_selector("emergency-council-fixture-allowed").unwrap(),
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed
    );
    assert_eq!(
        governance_execution_policy_from_selector("production-governance-required").unwrap(),
        GovernanceExecutionPolicy::ProductionGovernanceRequired
    );
    assert_eq!(
        governance_execution_policy_from_selector("mainnet-governance-required").unwrap(),
        GovernanceExecutionPolicy::MainnetGovernanceRequired
    );
}

#[test]
fn selector_is_case_insensitive_and_trims() {
    assert_eq!(
        governance_execution_policy_from_selector("  FIXTURE-GOVERNANCE-ALLOWED ").unwrap(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
}

// Selector default: both sources absent => Disabled.
#[test]
fn selector_default_is_disabled_when_both_absent() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        governance_execution_policy_from_cli_or_env(None).unwrap(),
        GovernanceExecutionPolicy::Disabled
    );
    assert_eq!(governance_execution_policy_env_selector().unwrap(), None);
}

// Selector CLI: CLI value selects the policy.
#[test]
fn selector_cli_selects_policy() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        governance_execution_policy_from_cli_or_env(Some("fixture-governance-allowed")).unwrap(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
}

// Selector env: env value selects the policy.
#[test]
fn selector_env_selects_policy() {
    let _g = EnvGuard::set(Some("fixture-governance-allowed"));
    assert_eq!(
        governance_execution_policy_env_selector().unwrap(),
        Some(GovernanceExecutionPolicy::FixtureGovernanceAllowed)
    );
    assert_eq!(
        governance_execution_policy_from_cli_or_env(None).unwrap(),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
    );
}

// A7. CLI-over-env precedence is deterministic.
#[test]
fn a7_cli_over_env_precedence_is_deterministic() {
    let _g = EnvGuard::set(Some("fixture-governance-allowed"));
    // CLI sets disabled while env sets fixture-governance-allowed.
    assert_eq!(
        governance_execution_policy_from_cli_or_env(Some("disabled")).unwrap(),
        GovernanceExecutionPolicy::Disabled
    );
}

// ===========================================================================
// Accepted scenarios
// ===========================================================================

// A1. default selector absent => Disabled; old no-governance-execution
//     payload accepted (bypass) where it was accepted before.
// A8. no-governance-execution payload remains compatible under default
//     Disabled.
#[test]
fn a1_a8_absent_payload_compatible_under_disabled() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::Disabled,
        &GovernanceExecutionLoadStatus::Absent,
    );
    assert_eq!(
        outcome,
        GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied
    );
    assert!(outcome.is_bypassed());
    assert!(!outcome.is_reject());
}

// A2. CLI fixture-governance-allowed; DevNet fixture governance accepted
//     under production-context path.
#[test]
fn a2_cli_fixture_devnet_accepted() {
    let env = TrustBundleEnvironment::Devnet;
    let policy =
        governance_execution_policy_from_cli_or_env(Some("fixture-governance-allowed")).unwrap();
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome =
        preflight_v2_marker_governance_execution_for_reload_check(&td, &exp, policy, &loaded);
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. })
    ));
}

// A3. env fixture-governance-allowed; TestNet fixture governance accepted.
#[test]
fn a3_env_fixture_testnet_accepted() {
    let _g = EnvGuard::set(Some("fixture-governance-allowed"));
    let env = TrustBundleEnvironment::Testnet;
    let policy = governance_execution_policy_from_cli_or_env(None).unwrap();
    assert_eq!(policy, GovernanceExecutionPolicy::FixtureGovernanceAllowed);
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome =
        preflight_v2_marker_governance_execution_for_reload_apply(&td, &exp, policy, &loaded);
    assert!(outcome.is_accept());
}

// A4. CLI emergency-council-fixture-allowed; DevNet emergency council
//     fixture execution accepted only for explicit emergency action.
#[test]
fn a4_cli_emergency_devnet_accepted() {
    let env = TrustBundleEnvironment::Devnet;
    let policy =
        governance_execution_policy_from_cli_or_env(Some("emergency-council-fixture-allowed"))
            .unwrap();
    assert_eq!(
        policy,
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed
    );
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let loaded = available_from(&emergency_input(env), &emergency_decision());
    let outcome =
        preflight_v2_marker_governance_execution_for_reload_check(&td, &exp, policy, &loaded);
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::EmergencyCouncilFixtureAccepted { .. })
    ));
}

// A5. CLI production-governance-required; production governance material
//     reaches evaluator and fails closed as unavailable.
#[test]
fn a5_cli_production_required_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let policy =
        governance_execution_policy_from_cli_or_env(Some("production-governance-required")).unwrap();
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
    let loaded = available_from(&input, &rotate_decision());
    let outcome =
        preflight_v2_marker_governance_execution_for_reload_check(&td, &exp, policy, &loaded);
    assert!(outcome.is_reject());
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::ProductionGovernanceUnavailable)
    );
}

// A6. env mainnet-governance-required; MainNet refusal outcome reached.
#[test]
fn a6_env_mainnet_required_refusal() {
    let _g = EnvGuard::set(Some("mainnet-governance-required"));
    let policy = governance_execution_policy_from_cli_or_env(None).unwrap();
    assert_eq!(policy, GovernanceExecutionPolicy::MainnetGovernanceRequired);
    // Peer-driven drain on MainNet remains refused regardless.
    let env = TrustBundleEnvironment::Mainnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome =
        preflight_v2_marker_governance_execution_for_peer_driven_drain(&td, &exp, policy, &loaded);
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
}

// A9. GenesisBound/EmergencyCouncil/OnChainGovernance proof-carrier
//     behavior unchanged when policy is Disabled (carried material is not
//     evaluated; absent material bypasses).
#[test]
fn a9_proof_carrier_unchanged_under_disabled() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    // Present fixture material under Disabled fails closed as disabled,
    // never accepted — i.e. the carrier never enables anything.
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::Disabled,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::GovernanceExecutionDisabled)
    );
}

// A13. mutating DevNet fixture governance under FixtureGovernanceAllowed
//      preflight accepts when lifecycle/governance/sequence all pass.
#[test]
fn a13_mutating_devnet_fixture_accepted() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(outcome.is_accept());
}

// A14. lifecycle rotate action authorized only with matching action,
//      candidate digest, and sequence.
#[test]
fn a14_rotate_action_authorized() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_apply(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            lifecycle_action: LocalLifecycleAction::Rotate,
            ..
        })
    ));
}

// A15. lifecycle revoke action authorized only with matching
//      candidate/revoked-key material and sequence.
#[test]
fn a15_revoke_action_authorized() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = revoke_expectations(env);
    let loaded = available_from(&revoke_input(env), &revoke_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_apply(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            lifecycle_action: LocalLifecycleAction::Revoke,
            ..
        })
    ));
}

// A16. live inbound 0x05 receives the selected policy through its Run 215
//      preflight wrapper. (Live-config threading is deferred to Run 216;
//      the limitation is documented on the wrapper.)
#[test]
fn a16_live_inbound_0x05_receives_selected_policy() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_live_inbound_0x05(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(outcome.is_accept());
}

// ===========================================================================
// Source reachability — selected policy reaches all seven surfaces
// ===========================================================================

#[test]
fn all_seven_surfaces_reach_evaluator_on_accept() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let policy = GovernanceExecutionPolicy::FixtureGovernanceAllowed;
    let loaded = available_from(&rotate_input(env), &rotate_decision());

    assert!(
        preflight_v2_marker_governance_execution_for_reload_check(&td, &exp, policy, &loaded)
            .is_accept()
    );
    assert!(
        preflight_v2_marker_governance_execution_for_reload_apply(&td, &exp, policy, &loaded)
            .is_accept()
    );
    assert!(
        preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle(
            &td, &exp, policy, &loaded
        )
        .is_accept()
    );
    assert!(
        preflight_v2_marker_governance_execution_for_sighup(&td, &exp, policy, &loaded).is_accept()
    );
    assert!(
        preflight_v2_marker_governance_execution_for_local_peer_candidate_check(
            &td, &exp, policy, &loaded
        )
        .is_accept()
    );
    assert!(
        preflight_v2_marker_governance_execution_for_live_inbound_0x05(&td, &exp, policy, &loaded)
            .is_accept()
    );
    // 7th surface: peer-driven drain accepts on non-MainNet.
    assert!(
        preflight_v2_marker_governance_execution_for_peer_driven_drain(&td, &exp, policy, &loaded)
            .is_accept()
    );
}

// ===========================================================================
// Rejection scenarios
// ===========================================================================

// R1. invalid CLI selector value rejected with typed parse error.
#[test]
fn r1_invalid_cli_selector_typed_error() {
    let err = governance_execution_policy_from_cli_or_env(Some("totally-bogus")).unwrap_err();
    assert!(matches!(
        err,
        GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
    ));
    assert_eq!(err.tag(), "unknown-value");
}

// R1b. empty CLI selector value rejected with typed Empty error.
#[test]
fn r1b_empty_cli_selector_typed_error() {
    assert_eq!(
        governance_execution_policy_from_cli_or_env(Some("   ")).unwrap_err(),
        GovernanceExecutionPolicySelectorParseError::Empty
    );
}

// R2. invalid env selector value rejected with typed parse error.
#[test]
fn r2_invalid_env_selector_typed_error() {
    let _g = EnvGuard::set(Some("nope"));
    let err = governance_execution_policy_env_selector().unwrap_err();
    assert!(matches!(
        err,
        GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
    ));
    assert!(governance_execution_policy_from_cli_or_env(None).is_err());
}

// R3. unrelated CLI/env does not enable governance execution policy.
#[test]
fn r3_unrelated_env_does_not_enable_policy() {
    let _g = EnvGuard::set(None);
    std::env::set_var("QBIND_SOME_UNRELATED_FLAG", "fixture-governance-allowed");
    assert_eq!(
        governance_execution_policy_from_cli_or_env(None).unwrap(),
        GovernanceExecutionPolicy::Disabled
    );
    std::env::remove_var("QBIND_SOME_UNRELATED_FLAG");
}

// R4. no-governance-execution payload rejected under
//     FixtureGovernanceAllowed (required but absent).
#[test]
fn r4_absent_rejected_under_fixture_allowed() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &GovernanceExecutionLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

// R5. no-governance-execution payload rejected under
//     ProductionGovernanceRequired.
#[test]
fn r5_absent_rejected_under_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
        &GovernanceExecutionLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
}

// R6. fixture governance rejected under ProductionGovernanceRequired.
#[test]
fn r6_fixture_rejected_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R7. emergency fixture rejected under ProductionGovernanceRequired.
#[test]
fn r7_emergency_fixture_rejected_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let loaded = available_from(&emergency_input(env), &emergency_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::EmergencyFixtureRejectedProductionRequired)
    );
}

// R8. fixture governance rejected under MainnetGovernanceRequired.
#[test]
fn r8_fixture_rejected_mainnet_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::MainnetGovernanceRequired,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedMainnetRequired)
    );
}

// R9/R10/R11. production / on-chain / MainNet governance rejected as
//             unavailable under a fixture-allowed policy.
#[test]
fn r9_r10_r11_production_onchain_mainnet_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
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
        let outcome = preflight_v2_marker_governance_execution_for_reload_check(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            &loaded,
        );
        assert_eq!(outcome.callsite_outcome(), Some(&expected));
    }
}

// R12. unknown governance class rejected.
#[test]
fn r12_unknown_class_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::Unknown;
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::UnknownGovernanceClassRejected { .. })
    ));
}

// R13. malformed governance execution material rejected.
#[test]
fn r13_malformed_material_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = preflight_v2_marker_governance_execution_for_reload_apply(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &malformed_loaded(),
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

// R14. wrong environment rejected.
#[test]
fn r14_wrong_environment_rejected() {
    let td = trust_domain(TrustBundleEnvironment::Devnet);
    let exp = rotate_expectations(TrustBundleEnvironment::Devnet);
    // Input declares a different environment than the trust domain.
    let input = rotate_input(TrustBundleEnvironment::Testnet);
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongEnvironment { .. })
    ));
}

// R15. wrong chain rejected.
#[test]
fn r15_wrong_chain_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.chain_id = "other-chain".to_string();
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongChain { .. })
    ));
}

// R16. wrong genesis rejected.
#[test]
fn r16_wrong_genesis_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.genesis_hash = "other-genesis".to_string();
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongGenesis { .. })
    ));
}

// R17. wrong authority root rejected.
#[test]
fn r17_wrong_authority_root_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.authority_root_fingerprint = "wrong-root".to_string();
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongAuthorityRoot { .. })
    ));
}

// R18/R35. wrong lifecycle action rejected (governance valid but
//          lifecycle action mismatch).
#[test]
fn r18_r35_wrong_lifecycle_action_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut decision = rotate_decision();
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    decision.authorized_governance_action = GovernanceAction::Revoke;
    let loaded = available_from(&rotate_input(env), &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongLifecycleAction { .. })
    ));
}

// R19. wrong candidate digest rejected.
#[test]
fn r19_wrong_candidate_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.candidate_digest = "different-digest".to_string();
    let mut decision = rotate_decision();
    decision.authorized_candidate_digest = "different-digest".to_string();
    let loaded = available_from(&input, &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongCandidateDigest { .. })
    ));
}

// R20. wrong authority-domain sequence rejected.
#[test]
fn r20_wrong_sequence_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.authority_domain_sequence = 9;
    let mut decision = rotate_decision();
    decision.authorized_sequence = 9;
    let loaded = available_from(&input, &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongAuthorityDomainSequence { .. })
    ));
}

// R21. wrong governance proof digest rejected.
#[test]
fn r21_wrong_governance_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_proof_digest = "wrong-proof".to_string();
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongGovernanceProofDigest { .. })
    ));
}

// R22. wrong on-chain proof digest rejected.
#[test]
fn r22_wrong_onchain_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
    let mut input = rotate_input(env);
    input.on_chain_proof_digest = Some("wrong-onchain".to_string());
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongOnChainProofDigest { .. })
    ));
}

// R23. wrong custody attestation digest rejected.
#[test]
fn r23_wrong_custody_attestation_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
    let mut input = rotate_input(env);
    input.custody_attestation_digest = Some("wrong-custody".to_string());
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongCustodyAttestationDigest { .. })
    ));
}

// R24. wrong proposal id rejected.
#[test]
fn r24_wrong_proposal_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.proposal_id = "wrong-proposal".to_string();
    let mut decision = rotate_decision();
    decision.proposal_id = "wrong-proposal".to_string();
    let loaded = available_from(&input, &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongProposalId { .. })
    ));
}

// R25. wrong decision id rejected.
#[test]
fn r25_wrong_decision_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.decision_id = "wrong-decision".to_string();
    let mut decision = rotate_decision();
    decision.decision_id = "wrong-decision".to_string();
    let loaded = available_from(&input, &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongDecisionId { .. })
    ));
}

// R26. wrong effective epoch rejected.
#[test]
fn r26_wrong_effective_epoch_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.effective_epoch = 101;
    let mut decision = rotate_decision();
    decision.effective_epoch = 101;
    let loaded = available_from(&input, &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::WrongEffectiveEpoch { .. })
    ));
}

// R27. expired decision rejected.
#[test]
fn r27_expired_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.now_epoch = 250; // past expiry_epoch 200
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::ExpiredDecision { .. })
    ));
}

// R28. stale/replayed decision rejected.
#[test]
fn r28_stale_replayed_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_replay_nonce = "fresh-nonce".to_string();
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::StaleOrReplayedDecision)
    );
}

// R29. quorum threshold insufficient rejected.
#[test]
fn r29_quorum_insufficient_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::QuorumThresholdInsufficient { .. })
    ));
}

// R30. emergency action not authorized rejected.
#[test]
fn r30_emergency_action_not_authorized_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    // Emergency action carried under the non-emergency fixture class/policy.
    let mut input = emergency_input(env);
    input.governance_class = GovernanceExecutionClass::FixtureGovernance;
    let mut decision = emergency_decision();
    decision.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
    let loaded = available_from(&input, &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::EmergencyActionNotAuthorized)
    );
}

// R31. validator-set rotation unsupported rejected.
#[test]
fn r31_validator_set_rotation_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::ValidatorSetRotationUnsupported)
    );
}

// R32. policy-change action unsupported rejected.
#[test]
fn r32_policy_change_action_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::PolicyChangeRequest;
    let loaded = available_from(&input, &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::PolicyChangeActionUnsupported)
    );
}

// R33. local operator cannot satisfy governance execution.
// R34. peer majority / gossip count cannot satisfy governance execution.
//      Both are represented by ProductionGovernanceRequired failing closed
//      with fixture material (no local/peer authority can satisfy it).
#[test]
fn r33_r34_local_and_peer_cannot_satisfy() {
    use qbind_node::pqc_governance_execution_policy::{
        local_operator_cannot_satisfy_governance_execution,
        peer_majority_cannot_satisfy_governance_execution,
    };
    assert!(local_operator_cannot_satisfy_governance_execution());
    assert!(peer_majority_cannot_satisfy_governance_execution());

    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R36. lifecycle valid but governance decision invalid rejected.
#[test]
fn r36_governance_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut decision = rotate_decision();
    decision.approved = false;
    let loaded = available_from(&rotate_input(env), &decision);
    let outcome = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::GovernanceDecisionRejected)
    );
}

// R37. validation-only rejection writes no marker and no sequence — the
//      routing helpers return data values only and are pure / equal.
#[test]
fn r37_validation_only_rejection_is_pure() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let mut decision = rotate_decision();
    decision.approved = false;
    let loaded = available_from(&rotate_input(env), &decision);
    let a = preflight_v2_marker_governance_execution_for_reload_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    let b = preflight_v2_marker_governance_execution_for_local_peer_candidate_check(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(a.is_reject());
    assert_eq!(a, b);
}

// R38. mutating rejection produces no Run 070 call, no live trust swap,
//      no sequence write, no marker write — the wrapper only returns a
//      typed outcome (pure / repeatable).
#[test]
fn r38_mutating_rejection_is_pure() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let a = preflight_v2_marker_governance_execution_for_reload_apply(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &malformed_loaded(),
    );
    let b = preflight_v2_marker_governance_execution_for_reload_apply(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &malformed_loaded(),
    );
    assert!(a.is_reject());
    assert_eq!(a, b);
}

// R39. invalid live inbound 0x05 governance-execution candidate is not
//      propagated, staged, or applied — the wrapper short-circuits to a
//      reject outcome.
#[test]
fn r39_invalid_live_0x05_not_propagated() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let outcome = preflight_v2_marker_governance_execution_for_live_inbound_0x05(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &malformed_loaded(),
    );
    assert!(outcome.is_reject());
    assert!(outcome.is_malformed_payload());
}

// R40. MainNet peer-driven apply remains refused even with
//      MainnetGovernanceRequired and a fully-valid fixture governance
//      approval.
#[test]
fn r40_mainnet_peer_driven_apply_refused_with_fixture_approval() {
    let env = TrustBundleEnvironment::Mainnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    // Even under FixtureGovernanceAllowed with valid material, MainNet
    // peer-driven apply is refused unconditionally.
    let outcome = preflight_v2_marker_governance_execution_for_peer_driven_drain(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        &loaded,
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert!(!outcome.is_accept());
}