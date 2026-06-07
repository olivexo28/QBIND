//! Run 211 — source/test governance execution policy boundary
//! integration tests.
//!
//! Source/test only. Run 211 does **not** capture release-binary
//! evidence; release-binary governance execution policy-boundary evidence
//! is deferred to **Run 212**. The tests cover:
//!
//! * the full A1–A15 / R1–R38 matrix from `task/RUN_211_TASK.txt`;
//! * input / decision / transcript canonical digest determinism and
//!   domain-binding;
//! * proposal / decision binding;
//! * action authorization (rotate / revoke);
//! * emergency action separation;
//! * fixture-vs-production governance separation;
//! * production / on-chain / MainNet governance unavailable fail-closed
//!   paths;
//! * malformed input / decision fail-closed paths;
//! * the no-I/O guarantee for the production governance path (the tests
//!   construct only data values and call only pure evaluators / pure
//!   trait methods);
//! * the no-mutation guarantee (validation-only surfaces never mutate);
//! * MainNet refusal invariants;
//! * compatibility with the Run 159 lifecycle, Run 163 governance proof,
//!   Run 178 OnChainGovernance, Run 188 custody, Run 194 RemoteSigner,
//!   Run 203 KMS/HSM, and Run 205 custody-attestation paths (bound only
//!   as opaque digests).
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_211.md`.

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

// ===========================================================================
// Shared fixtures
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

/// A standard accepted-path input for the Rotate action on DevNet.
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

// ===========================================================================
// A — accepted scenarios
// ===========================================================================

#[test]
fn a1_fixture_governance_accepted_devnet() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome,
        GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            lifecycle_action: LocalLifecycleAction::Rotate,
            environment: TrustBundleEnvironment::Devnet,
            ..
        }
    ));
}

#[test]
fn a2_fixture_governance_accepted_testnet() {
    let env = TrustBundleEnvironment::Testnet;
    let outcome = evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    assert!(outcome.is_accept());
}

#[test]
fn a3_emergency_council_fixture_accepted_devnet() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_execution_policy(
        &emergency_input(env),
        &emergency_decision(),
        &emergency_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
    );
    assert!(matches!(
        outcome,
        GovernanceExecutionOutcome::EmergencyCouncilFixtureAccepted { .. }
    ));
}

#[test]
fn a4_input_digest_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let a = rotate_input(env);
    let b = rotate_input(env);
    assert_eq!(a.input_digest(), b.input_digest());
    let mut c = rotate_input(env);
    c.proposal_id = "different".to_string();
    assert_ne!(a.input_digest(), c.input_digest());
}

#[test]
fn a5_decision_digest_deterministic() {
    let a = rotate_decision();
    let b = rotate_decision();
    assert_eq!(a.decision_digest(), b.decision_digest());
    let mut c = rotate_decision();
    c.authorized_sequence = 8;
    assert_ne!(a.decision_digest(), c.decision_digest());
}

#[test]
fn a6_transcript_digest_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let input = rotate_input(env);
    let decision = rotate_decision();
    let t1 = governance_execution_transcript_digest(&input.input_digest(), &decision.decision_digest());
    let t2 = governance_execution_transcript_digest(&input.input_digest(), &decision.decision_digest());
    assert_eq!(t1, t2);
    // Different input changes transcript.
    let mut other = rotate_input(env);
    other.replay_nonce = "other-nonce".to_string();
    let t3 = governance_execution_transcript_digest(&other.input_digest(), &decision.decision_digest());
    assert_ne!(t1, t3);
    // Policy digest determinism (optional helper).
    assert_eq!(
        governance_execution_policy_digest(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance
        ),
        governance_execution_policy_digest(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance
        )
    );
}

#[test]
fn a7_input_binds_full_tuple() {
    // Mutating any bound field changes the input digest.
    let env = TrustBundleEnvironment::Devnet;
    let base = rotate_input(env).input_digest();
    let mutators: Vec<Box<dyn Fn(&mut GovernanceExecutionInput)>> = vec![
        Box::new(|i| i.environment = TrustBundleEnvironment::Testnet),
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
    for m in mutators {
        let mut i = rotate_input(env);
        m(&mut i);
        assert_ne!(base, i.input_digest());
    }
}

#[test]
fn a8_decision_binds_full_tuple() {
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
    for m in mutators {
        let mut d = rotate_decision();
        m(&mut d);
        assert_ne!(base, d.decision_digest());
    }
}

#[test]
fn a9_rotate_authorized_only_when_decision_authorizes_rotate() {
    let env = TrustBundleEnvironment::Devnet;
    // Authorized rotate -> accept.
    assert!(evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    )
    .is_accept());
    // Decision authorizes a different action -> reject.
    let mut decision = rotate_decision();
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    decision.authorized_governance_action = GovernanceAction::Revoke;
    let outcome = evaluate_governance_execution_policy(
        &rotate_input(env),
        &decision,
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    assert!(matches!(
        outcome,
        GovernanceExecutionOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn a10_revoke_authorized_only_when_decision_authorizes_revoke() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::Revoke;
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::Revoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    assert!(evaluate_governance_execution_policy(
        &input,
        &decision,
        &exp,
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    )
    .is_accept());
}

#[test]
fn a11_emergency_revoke_accepted_only_under_emergency_policy() {
    let env = TrustBundleEnvironment::Devnet;
    // Accepted under emergency policy.
    assert!(evaluate_governance_execution_policy(
        &emergency_input(env),
        &emergency_decision(),
        &emergency_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
    )
    .is_accept());
    // Emergency class under the plain fixture policy -> class/policy
    // mismatch (the emergency class is not the fixture policy's class).
    let outcome = evaluate_governance_execution_policy(
        &emergency_input(env),
        &emergency_decision(),
        &emergency_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    assert!(matches!(
        outcome,
        GovernanceExecutionOutcome::GovernanceClassPolicyMismatch { .. }
    ));
}

#[test]
fn a12_production_boundary_callable_returns_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let evaluator = ProductionGovernanceExecutionEvaluator;
    let outcome = evaluator.evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    assert_eq!(
        outcome,
        GovernanceExecutionOutcome::ProductionGovernanceUnavailable
    );
    assert!(outcome.is_unavailable());
}

#[test]
fn a13_onchain_boundary_callable_returns_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let evaluator = OnChainGovernanceExecutionEvaluator;
    let outcome = evaluator.evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    assert_eq!(
        outcome,
        GovernanceExecutionOutcome::OnChainGovernanceUnavailable
    );
    assert!(outcome.is_unavailable());
}

#[test]
fn a14_disabled_policy_is_inert_default() {
    // When the policy is Disabled, the evaluator returns Disabled and
    // never inspects any binding — existing proof-carrier behavior is
    // unchanged.
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(GovernanceExecutionPolicy::default(), GovernanceExecutionPolicy::Disabled);
    let outcome = evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::Disabled,
    );
    assert_eq!(outcome, GovernanceExecutionOutcome::GovernanceExecutionDisabled);
}

#[test]
fn a15_disabled_compatible_with_bound_custody_and_signer_digests() {
    // Carrying optional on-chain / custody-attestation digests under the
    // Disabled policy still returns Disabled (boundary stays inert).
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.on_chain_proof_digest = Some("onchain-digest".to_string());
    input.custody_attestation_digest = Some("custody-attestation-digest".to_string());
    let outcome = evaluate_governance_execution_policy(
        &input,
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::Disabled,
    );
    assert_eq!(outcome, GovernanceExecutionOutcome::GovernanceExecutionDisabled);
}

// ===========================================================================
// R — rejection scenarios
// ===========================================================================

#[test]
fn r1_rejected_under_disabled_policy() {
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::Disabled,
        ),
        GovernanceExecutionOutcome::GovernanceExecutionDisabled
    );
}

#[test]
fn r2_fixture_rejected_under_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        ),
        GovernanceExecutionOutcome::FixtureRejectedProductionRequired
    );
}

#[test]
fn r3_emergency_fixture_rejected_under_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(
        evaluate_governance_execution_policy(
            &emergency_input(env),
            &emergency_decision(),
            &emergency_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        ),
        GovernanceExecutionOutcome::EmergencyFixtureRejectedProductionRequired
    );
}

#[test]
fn r4_fixture_rejected_under_mainnet_required() {
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        ),
        GovernanceExecutionOutcome::FixtureRejectedMainnetRequired
    );
}

#[test]
fn r5_production_rejected_as_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
    assert_eq!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::ProductionGovernanceUnavailable
    );
}

#[test]
fn r6_onchain_rejected_as_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::OnChainGovernanceUnavailable;
    assert_eq!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::OnChainGovernanceUnavailable
    );
}

#[test]
fn r7_mainnet_governance_rejected_as_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::MainnetGovernanceUnavailable;
    assert_eq!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::MainNetGovernanceUnavailable
    );
    // The MainNet evaluator placeholder also fails closed.
    let evaluator = MainnetGovernanceExecutionEvaluator;
    assert_eq!(
        evaluator.evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        ),
        GovernanceExecutionOutcome::MainNetGovernanceUnavailable
    );
}

#[test]
fn r8_unknown_governance_class_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::Unknown;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::UnknownGovernanceClassRejected { .. }
    ));
}

#[test]
fn r9_wrong_environment_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.environment = TrustBundleEnvironment::Testnet;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r10_wrong_chain_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.chain_id = "wrong-chain".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongChain { .. }
    ));
}

#[test]
fn r11_wrong_genesis_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.genesis_hash = "wrong-genesis".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r12_wrong_authority_root_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.authority_root_fingerprint = "wrong-root".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r13_wrong_lifecycle_action_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // Input lifecycle action does not match its governance action mapping.
    let mut input = rotate_input(env);
    input.lifecycle_action = LocalLifecycleAction::Retire;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r14_wrong_candidate_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.candidate_digest = "wrong-candidate".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r15_wrong_sequence_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.authority_domain_sequence = 99;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r16_wrong_governance_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_proof_digest = "wrong-proof".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongGovernanceProofDigest { .. }
    ));
}

#[test]
fn r17_wrong_onchain_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.on_chain_proof_digest = Some("wrong-onchain".to_string());
    let mut exp = rotate_expectations(env);
    exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &exp,
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongOnChainProofDigest { .. }
    ));
}

#[test]
fn r18_wrong_custody_attestation_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.custody_attestation_digest = Some("wrong-custody".to_string());
    let mut exp = rotate_expectations(env);
    exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &exp,
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongCustodyAttestationDigest { .. }
    ));
}

#[test]
fn r19_wrong_proposal_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.proposal_id = "wrong-proposal".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongProposalId { .. }
    ));
}

#[test]
fn r20_wrong_decision_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.decision_id = "wrong-decision".to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongDecisionId { .. }
    ));
}

#[test]
fn r21_wrong_effective_epoch_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.effective_epoch = 101;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongEffectiveEpoch { .. }
    ));
}

#[test]
fn r22_expired_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut exp = rotate_expectations(env);
    exp.now_epoch = 250; // past expiry_epoch (200)
    assert!(matches!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &exp,
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::ExpiredDecision { .. }
    ));
}

#[test]
fn r23_stale_replayed_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.replay_nonce = "stale-nonce".to_string();
    assert_eq!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::StaleOrReplayedDecision
    );
}

#[test]
fn r24_quorum_threshold_insufficient_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.quorum = GovernanceQuorumThreshold::new(2, 5, 3);
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::QuorumThresholdInsufficient { .. }
    ));
}

#[test]
fn r25_emergency_action_not_authorized_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // Emergency input/decision but the decision does not flag emergency.
    let mut decision = emergency_decision();
    decision.emergency_flag = false;
    assert_eq!(
        evaluate_governance_execution_policy(
            &emergency_input(env),
            &decision,
            &emergency_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        ),
        GovernanceExecutionOutcome::EmergencyActionNotAuthorized
    );
}

#[test]
fn r26_validator_set_rotation_unsupported_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    assert_eq!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::ValidatorSetRotationUnsupported
    );
    assert!(validator_set_rotation_remains_unsupported());
}

#[test]
fn r27_policy_change_action_unsupported_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    for action in [
        GovernanceAction::PolicyChangeRequest,
        GovernanceAction::CustodyPolicyChangeRequest,
        GovernanceAction::RemoteSignerPolicyChangeRequest,
        GovernanceAction::CustodyAttestationPolicyChangeRequest,
    ] {
        let mut input = rotate_input(env);
        input.governance_action = action;
        assert_eq!(
            evaluate_governance_execution_policy(
                &input,
                &rotate_decision(),
                &rotate_expectations(env),
                &trust_domain(env),
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            ),
            GovernanceExecutionOutcome::PolicyChangeActionUnsupported
        );
    }
}

#[test]
fn r28_malformed_input_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.proposal_id = String::new();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::MalformedExecutionInput { .. }
    ));
}

#[test]
fn r29_malformed_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut decision = rotate_decision();
    decision.decision_commitment = GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL.to_string();
    assert!(matches!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &decision,
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::MalformedExecutionDecision { .. }
    ));
}

#[test]
fn r30_unsupported_version_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.execution_version = 99;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::UnsupportedGovernanceExecutionVersion { .. }
    ));
}

#[test]
fn r31_local_operator_cannot_satisfy_governance_execution() {
    assert!(local_operator_cannot_satisfy_governance_execution());
}

#[test]
fn r32_peer_majority_cannot_satisfy_governance_execution() {
    assert!(peer_majority_cannot_satisfy_governance_execution());
}

#[test]
fn r33_governance_valid_but_lifecycle_action_mismatch_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // The decision authorizes Rotate, the input requests Revoke (a
    // self-consistent Revoke request), but the decision does not authorize
    // Revoke -> action mismatch.
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::Revoke;
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    assert!(matches!(
        evaluate_governance_execution_policy(
            &input,
            &rotate_decision(),
            &exp,
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r34_lifecycle_valid_but_governance_decision_invalid_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // The decision is not approved.
    let mut decision = rotate_decision();
    decision.approved = false;
    assert_eq!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &decision,
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::GovernanceDecisionRejected
    );
}

#[test]
fn r35_valid_lifecycle_governance_custody_but_production_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // Lifecycle + governance proof + custody all bound and consistent, but
    // the production governance policy fails closed as unavailable.
    let mut input = rotate_input(env);
    input.custody_attestation_digest = Some("custody-attestation-digest".to_string());
    let outcome = evaluate_governance_execution_policy(
        &input,
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    assert!(outcome.is_reject());
    assert_eq!(outcome, GovernanceExecutionOutcome::FixtureRejectedProductionRequired);
}

#[test]
fn r36_validation_only_rejection_is_non_mutating() {
    // The evaluator borrows immutably and returns a value type. Calling it
    // twice on the same inputs yields identical results and cannot mutate
    // its inputs.
    let env = TrustBundleEnvironment::Devnet;
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
    assert_eq!(o1, o2);
    assert_eq!(before, input.input_digest());
}

#[test]
fn r37_mutating_preflight_rejection_produces_no_mutation() {
    // The composition guard performs no I/O and returns a value type; a
    // rejected preflight cannot write a marker/sequence or swap trust.
    let env = TrustBundleEnvironment::Devnet;
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
    assert!(matches!(
        composed,
        GovernanceExecutionComposedOutcome::Rejected(GovernanceExecutionOutcome::GovernanceDecisionRejected)
    ));
}

#[test]
fn r38_mainnet_peer_driven_apply_refused_even_with_fixture_approval() {
    let env = TrustBundleEnvironment::Mainnet;
    // Even if the fixture decision would otherwise be valid, MainNet
    // peer-driven apply is refused up front.
    let composed = evaluate_governance_execution_with_peer_driven_guard(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        true,
    );
    assert_eq!(
        composed,
        GovernanceExecutionComposedOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(mainnet_peer_driven_apply_remains_refused_under_governance_execution(
        TrustBundleEnvironment::Mainnet
    ));
    // A non-peer-driven fixture path on MainNet trust domain is still
    // refused as fixture-for-mainnet.
    assert_eq!(
        evaluate_governance_execution_policy(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            &trust_domain(env),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        GovernanceExecutionOutcome::FixtureRejectedForMainNet
    );
}

// ===========================================================================
// Extra: fixture evaluator trait + no-mutation under accept
// ===========================================================================

#[test]
fn fixture_evaluator_trait_accepts_devnet() {
    let env = TrustBundleEnvironment::Devnet;
    let evaluator = FixtureGovernanceExecutionEvaluator;
    assert_eq!(evaluator.class(), GovernanceExecutionClass::FixtureGovernance);
    let outcome = evaluator.evaluate_governance_execution_policy(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    assert!(outcome.is_accept());
}

#[test]
fn peer_driven_guard_accepts_non_peer_devnet() {
    let env = TrustBundleEnvironment::Devnet;
    let composed = evaluate_governance_execution_with_peer_driven_guard(
        &rotate_input(env),
        &rotate_decision(),
        &rotate_expectations(env),
        &trust_domain(env),
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        false,
    );
    assert!(composed.is_accept());
}