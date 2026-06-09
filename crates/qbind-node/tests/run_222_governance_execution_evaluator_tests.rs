//! Run 222 — source/test production governance execution evaluator
//! interface boundary integration tests.
//!
//! Source/test only. Run 222 does **not** capture release-binary
//! evidence; release-binary evaluator-interface evidence is deferred to
//! **Run 223**. The tests cover:
//!
//! * the full A1–A16 / R1–R40 matrix from `task/RUN_222_TASK.txt`;
//! * source-identity / request / response / transcript canonical digest
//!   determinism and domain-binding;
//! * source / request / response field binding;
//! * rotate / revoke / emergency action authorization;
//! * fixture-vs-production evaluator separation;
//! * production / on-chain / MainNet decision-source unavailable
//!   fail-closed paths;
//! * malformed source-identity / request / response fail-closed paths;
//! * the no-I/O guarantee for the production / on-chain / MainNet
//!   evaluator paths (the tests construct only data values and call only
//!   pure evaluators / pure trait methods);
//! * the no-mutation guarantee (validation-only surfaces never mutate);
//! * MainNet refusal invariants;
//! * compatibility with the Run 211 governance-execution policy boundary,
//!   the Run 213 payload material, and the Run 220 runtime consumption.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_222.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_evaluator::{
    evaluate_governance_decision_source, evaluate_governance_evaluator_with_peer_driven_guard,
    evaluator_transcript_digest, local_operator_cannot_satisfy_evaluator_policy,
    mainnet_peer_driven_apply_remains_refused_under_evaluator,
    peer_majority_cannot_satisfy_evaluator_policy, validator_set_rotation_remains_unsupported_under_evaluator,
    verify_governance_evaluator_response, DecisionSourceIdentity,
    EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface, EvaluatorComposedOutcome,
    EvaluatorExpectations, EvaluatorOutcome, EvaluatorPolicy, EvaluatorRequest, EvaluatorResponse,
    EvaluatorSourceKind, FixtureGovernanceExecutionEvaluatorInterface,
    MainnetDecisionSourceEvaluatorInterface, OnChainDecisionSourceEvaluatorInterface,
    ProductionDecisionSourceEvaluatorInterface, ProductionGovernanceExecutionEvaluator,
    EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL, EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
// ===========================================================================

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

/// A fixture decision-source identity on `env` for the Rotate action.
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

/// A rotate request bound to [`rotate_identity`].
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

/// A rotate response bound to [`rotate_request`].
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

// ===========================================================================
// A — accepted scenarios
// ===========================================================================

#[test]
fn a1_fixture_decision_source_accepted_devnet() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_decision_source(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
    );
    assert!(matches!(
        outcome,
        EvaluatorOutcome::FixtureDecisionSourceAccepted { .. }
    ));
    assert!(outcome.is_accept());
}

#[test]
fn a2_fixture_decision_source_accepted_testnet() {
    let env = TrustBundleEnvironment::Testnet;
    let outcome = evaluate_governance_decision_source(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
    );
    assert!(matches!(
        outcome,
        EvaluatorOutcome::FixtureDecisionSourceAccepted {
            environment: TrustBundleEnvironment::Testnet,
            ..
        }
    ));
}

#[test]
fn a3_emergency_fixture_accepted() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_decision_source(
        &emergency_identity(env),
        &emergency_request(env),
        &emergency_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed,
    );
    assert!(matches!(
        outcome,
        EvaluatorOutcome::EmergencyFixtureAccepted { .. }
    ));
}

#[test]
fn a4_source_identity_digest_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let id = rotate_identity(env);
    assert_eq!(id.source_identity_digest(), id.source_identity_digest());
    let mut other = rotate_identity(env);
    other.source_id = "different-source".to_string();
    assert_ne!(id.source_identity_digest(), other.source_identity_digest());
}

#[test]
fn a5_request_digest_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let req = rotate_request(env);
    assert_eq!(req.request_digest(), req.request_digest());
    let mut other = rotate_request(env);
    other.proposal_id = "proposal-9999".to_string();
    assert_ne!(req.request_digest(), other.request_digest());
}

#[test]
fn a6_response_digest_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let resp = rotate_response(env);
    assert_eq!(resp.response_digest(), resp.response_digest());
    let mut other = rotate_response(env);
    other.authorized_authority_domain_sequence = 99;
    assert_ne!(resp.response_digest(), other.response_digest());
}

#[test]
fn a7_transcript_digest_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let id = rotate_identity(env);
    let req = rotate_request(env);
    let resp = rotate_response(env);
    let t1 = evaluator_transcript_digest(
        &id.source_identity_digest(),
        &req.request_digest(),
        &resp.response_digest(),
    );
    let t2 = evaluator_transcript_digest(
        &id.source_identity_digest(),
        &req.request_digest(),
        &resp.response_digest(),
    );
    assert_eq!(t1, t2);
    let t3 = evaluator_transcript_digest("a", &req.request_digest(), &resp.response_digest());
    assert_ne!(t1, t3);
}

#[test]
fn a8_request_binds_identity_fields() {
    // Changing any bound request field changes the request digest.
    let env = TrustBundleEnvironment::Devnet;
    let base = rotate_request(env).request_digest();
    let mutate = |f: &dyn Fn(&mut EvaluatorRequest)| {
        let mut r = rotate_request(env);
        f(&mut r);
        r.request_digest()
    };
    assert_ne!(base, mutate(&|r| r.proposal_id = "x".to_string()));
    assert_ne!(base, mutate(&|r| r.decision_id = "x".to_string()));
    assert_ne!(
        base,
        mutate(&|r| r.lifecycle_action = LocalLifecycleAction::Revoke)
    );
    assert_ne!(base, mutate(&|r| r.candidate_digest = "x".to_string()));
    assert_ne!(base, mutate(&|r| r.authority_domain_sequence = 999));
    assert_ne!(base, mutate(&|r| r.effective_epoch = 5));
    assert_ne!(base, mutate(&|r| r.expiry_epoch = 5));
    assert_ne!(base, mutate(&|r| r.replay_nonce = "x".to_string()));
    assert_ne!(
        base,
        mutate(&|r| r.decision_source_identity_digest = "x".to_string())
    );
}

#[test]
fn a9_response_binds_request_fields() {
    let env = TrustBundleEnvironment::Devnet;
    let base = rotate_response(env).response_digest();
    let mutate = |f: &dyn Fn(&mut EvaluatorResponse)| {
        let mut r = rotate_response(env);
        f(&mut r);
        r.response_digest()
    };
    assert_ne!(base, mutate(&|r| r.request_digest = "x".to_string()));
    assert_ne!(base, mutate(&|r| r.decision_digest = "x".to_string()));
    assert_ne!(
        base,
        mutate(&|r| r.authorized_lifecycle_action = LocalLifecycleAction::Revoke)
    );
    assert_ne!(
        base,
        mutate(&|r| r.authorized_candidate_digest = "x".to_string())
    );
    assert_ne!(
        base,
        mutate(&|r| r.authorized_authority_domain_sequence = 999)
    );
    assert_ne!(base, mutate(&|r| r.effective_epoch = 5));
    assert_ne!(base, mutate(&|r| r.expiry_epoch = 5));
    assert_ne!(base, mutate(&|r| r.replay_nonce = "x".to_string()));
}

#[test]
fn a10_rotate_authorization_requires_matching_candidate_and_sequence() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = verify_governance_evaluator_response(
        &rotate_response(env),
        &rotate_request(env),
        &rotate_expectations(env),
    );
    assert!(matches!(
        outcome,
        EvaluatorOutcome::EvaluatorResponseAuthorized {
            lifecycle_action: LocalLifecycleAction::Rotate,
            ..
        }
    ));
    // Mismatched candidate digest is not authorized.
    let mut resp = rotate_response(env);
    resp.authorized_candidate_digest = "mismatch".to_string();
    resp.request_digest = rotate_request(env).request_digest();
    let bad = verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env));
    assert!(matches!(bad, EvaluatorOutcome::WrongCandidateDigest { .. }));
}

#[test]
fn a11_revoke_authorization_requires_matching_material() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.governance_action = GovernanceAction::Revoke;
    req.lifecycle_action = LocalLifecycleAction::Revoke;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    let mut resp = rotate_response(env);
    resp.authorized_governance_action = GovernanceAction::Revoke;
    resp.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    resp.request_digest = req.request_digest();
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;

    let outcome = verify_governance_evaluator_response(&resp, &req, &exp);
    assert!(matches!(
        outcome,
        EvaluatorOutcome::EvaluatorResponseAuthorized {
            lifecycle_action: LocalLifecycleAction::Revoke,
            ..
        }
    ));
    // Wrong sequence is rejected.
    let mut resp2 = resp.clone();
    resp2.authorized_authority_domain_sequence = 99;
    resp2.request_digest = req.request_digest();
    let bad = verify_governance_evaluator_response(&resp2, &req, &exp);
    assert!(matches!(
        bad,
        EvaluatorOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn a12_emergency_revoke_only_under_emergency_policy() {
    let env = TrustBundleEnvironment::Devnet;
    // Accepted under emergency policy.
    let ok = evaluate_governance_decision_source(
        &emergency_identity(env),
        &emergency_request(env),
        &emergency_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed,
    );
    assert!(matches!(ok, EvaluatorOutcome::EmergencyFixtureAccepted { .. }));
    // The emergency response verifies and authorizes the emergency revoke.
    let resp_outcome = verify_governance_evaluator_response(
        &emergency_response(env),
        &emergency_request(env),
        &emergency_expectations(env),
    );
    assert!(matches!(
        resp_outcome,
        EvaluatorOutcome::EvaluatorResponseAuthorized {
            lifecycle_action: LocalLifecycleAction::EmergencyRevoke,
            ..
        }
    ));
    // Emergency source under the plain fixture policy is a kind mismatch.
    let mismatch = evaluate_governance_decision_source(
        &emergency_identity(env),
        &emergency_request(env),
        &emergency_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
    );
    assert!(matches!(
        mismatch,
        EvaluatorOutcome::SourceKindPolicyMismatch { .. }
    ));
}

#[test]
fn a13_production_evaluator_callable_returns_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let ev = ProductionDecisionSourceEvaluatorInterface;
    let outcome = ev.evaluate_governance_decision_source(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::ProductionDecisionSourceRequired,
    );
    assert_eq!(outcome, EvaluatorOutcome::ProductionDecisionSourceUnavailable);
    assert!(outcome.is_unavailable());
}

#[test]
fn a14_onchain_evaluator_callable_returns_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let ev = OnChainDecisionSourceEvaluatorInterface;
    let outcome = ev.evaluate_governance_decision_source(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::ProductionDecisionSourceRequired,
    );
    assert_eq!(outcome, EvaluatorOutcome::OnChainDecisionSourceUnavailable);
}

#[test]
fn a15_mainnet_evaluator_callable_returns_unavailable() {
    let env = TrustBundleEnvironment::Mainnet;
    let ev = MainnetDecisionSourceEvaluatorInterface;
    let outcome = ev.evaluate_governance_decision_source(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::MainnetDecisionSourceRequired,
    );
    assert_eq!(outcome, EvaluatorOutcome::MainnetDecisionSourceUnavailable);
}

#[test]
fn a16_disabled_policy_remains_inert_for_runtime_consumption() {
    // Under the Disabled evaluator policy every source is inert
    // (fail-closed disabled), so Run 220 runtime-consumption behaviour
    // remains unchanged: the evaluator never authorizes anything.
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_decision_source(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::Disabled,
    );
    assert_eq!(outcome, EvaluatorOutcome::EvaluatorDisabled);
}

// ===========================================================================
// R — rejection scenarios
// ===========================================================================

fn src(
    policy: EvaluatorPolicy,
    identity: &DecisionSourceIdentity,
    request: &EvaluatorRequest,
    expectations: &EvaluatorExpectations,
    env: TrustBundleEnvironment,
) -> EvaluatorOutcome {
    evaluate_governance_decision_source(identity, request, expectations, &trust_domain(env), policy)
}

#[test]
fn r1_disabled_policy_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(
        src(
            EvaluatorPolicy::Disabled,
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::EvaluatorDisabled
    );
}

#[test]
fn r2_fixture_rejected_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    assert!(matches!(
        src(
            EvaluatorPolicy::ProductionDecisionSourceRequired,
            &rotate_identity(env),
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::FixtureRejectedUnderProductionPolicy { .. }
    ));
}

#[test]
fn r3_emergency_fixture_rejected_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    assert!(matches!(
        src(
            EvaluatorPolicy::ProductionDecisionSourceRequired,
            &emergency_identity(env),
            &emergency_request(env),
            &emergency_expectations(env),
            env
        ),
        EvaluatorOutcome::EmergencyFixtureRejectedUnderProductionPolicy { .. }
    ));
}

#[test]
fn r4_fixture_rejected_mainnet_required() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = src(
        EvaluatorPolicy::MainnetDecisionSourceRequired,
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_expectations(env),
        env,
    );
    assert!(matches!(
        outcome,
        EvaluatorOutcome::FixtureRejectedUnderProductionPolicy {
            policy_tag: "mainnet-decision-source-required"
        }
    ));
}

#[test]
fn r5_production_evaluator_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.source_kind = EvaluatorSourceKind::ProductionDecisionSourceUnavailable;
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::ProductionDecisionSourceUnavailable
    );
}

#[test]
fn r6_onchain_evaluator_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.source_kind = EvaluatorSourceKind::OnChainDecisionSourceUnavailable;
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::OnChainDecisionSourceUnavailable
    );
}

#[test]
fn r7_mainnet_evaluator_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.source_kind = EvaluatorSourceKind::MainnetDecisionSourceUnavailable;
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::MainnetDecisionSourceUnavailable
    );
}

#[test]
fn r8_unknown_source_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.source_kind = EvaluatorSourceKind::Unknown;
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::UnknownSourceRejected { .. }
    ));
}

#[test]
fn r9_wrong_environment_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.environment = TrustBundleEnvironment::Testnet;
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r10_wrong_chain_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.chain_id = "other-chain".to_string();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongChain { .. }
    ));
}

#[test]
fn r11_wrong_genesis_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.genesis_hash = "other-genesis".to_string();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r12_wrong_authority_root_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.authority_root_fingerprint = "other-root".to_string();
    // Re-bind the request identity digest so the wrong-root check is what fires.
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r13_wrong_governance_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.governance_proof_digest = "other-proof".to_string();
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongGovernanceProofDigest { .. }
    ));
}

#[test]
fn r14_wrong_onchain_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.on_chain_proof_digest = Some("unexpected-onchain".to_string());
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongOnChainProofDigest { .. }
    ));
}

#[test]
fn r15_wrong_custody_attestation_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.custody_attestation_digest = Some("unexpected-custody".to_string());
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongCustodyAttestationDigest { .. }
    ));
}

#[test]
fn r16_wrong_proposal_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.proposal_id = "other-proposal".to_string();
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongProposalId { .. }
    ));
}

#[test]
fn r17_wrong_decision_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.decision_id = "other-decision".to_string();
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongDecisionId { .. }
    ));
}

#[test]
fn r18_wrong_lifecycle_action_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.governance_action = GovernanceAction::Retire;
    req.lifecycle_action = LocalLifecycleAction::Retire;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    // Expectations still want Rotate.
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r19_wrong_candidate_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.candidate_digest = "other-candidate".to_string();
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r20_wrong_sequence_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.authority_domain_sequence = 999;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r21_wrong_effective_epoch_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.effective_epoch = 50;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::WrongEffectiveEpoch { .. }
    ));
}

#[test]
fn r22_expired_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut exp = rotate_expectations(env);
    exp.now_epoch = 250; // beyond expiry 200
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &rotate_request(env),
            &exp,
            env
        ),
        EvaluatorOutcome::ExpiredDecision { .. }
    ));
}

#[test]
fn r23_stale_or_replayed_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.replay_nonce = "stale-nonce".to_string();
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::StaleOrReplayedDecision
    );
}

#[test]
fn r24_quorum_threshold_insufficient_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::QuorumThresholdInsufficient { .. }
    ));
}

#[test]
fn r25_emergency_action_not_authorized_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // Emergency action under the plain fixture policy: emergency flag set,
    // but the kind would be a mismatch first, so use a fixture source with
    // an emergency lifecycle action to trigger the emergency separation.
    let mut req = rotate_request(env);
    req.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    req.governance_action = GovernanceAction::EmergencyRevoke;
    req.emergency_flag = true;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    let mut exp = rotate_expectations(env);
    exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &exp,
            env
        ),
        EvaluatorOutcome::EmergencyActionNotAuthorized
    );
}

#[test]
fn r26_validator_set_rotation_unsupported_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::ValidatorSetRotationUnsupported
    );
}

#[test]
fn r27_policy_change_action_unsupported_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.governance_action = GovernanceAction::PolicyChangeRequest;
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert_eq!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::PolicyChangeActionUnsupported
    );
}

#[test]
fn r28_malformed_source_identity_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.source_id = String::new();
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::MalformedSourceIdentity { .. }
    ));
}

#[test]
fn r29_malformed_evaluator_request_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut req = rotate_request(env);
    req.replay_nonce = String::new();
    req.decision_source_identity_digest = rotate_identity(env).source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &rotate_identity(env),
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::MalformedEvaluatorRequest { .. }
    ));
}

#[test]
fn r30_malformed_evaluator_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut resp = rotate_response(env);
    resp.evaluator_source_id = String::new();
    let outcome =
        verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env));
    assert!(matches!(
        outcome,
        EvaluatorOutcome::MalformedEvaluatorResponse { .. }
    ));
}

#[test]
fn r31_unsupported_evaluator_version_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.evaluator_version = 99;
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    assert!(matches!(
        src(
            EvaluatorPolicy::FixtureDecisionSourceAllowed,
            &id,
            &req,
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::UnsupportedEvaluatorVersion { .. }
    ));
}

#[test]
fn r32_invalid_response_commitment_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut resp = rotate_response(env);
    resp.response_commitment = EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL.to_string();
    let outcome =
        verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env));
    assert_eq!(outcome, EvaluatorOutcome::InvalidResponseCommitment);
}

#[test]
fn r33_local_operator_cannot_satisfy_evaluator_policy() {
    assert!(local_operator_cannot_satisfy_evaluator_policy());
}

#[test]
fn r34_peer_majority_cannot_satisfy_evaluator_policy() {
    assert!(peer_majority_cannot_satisfy_evaluator_policy());
}

#[test]
fn r35_evaluator_valid_but_governance_decision_invalid_rejected() {
    // The decision source is valid but the response's authorized lifecycle
    // action disagrees with the governance execution decision (request).
    let env = TrustBundleEnvironment::Devnet;
    let mut resp = rotate_response(env);
    resp.authorized_lifecycle_action = LocalLifecycleAction::Retire;
    resp.request_digest = rotate_request(env).request_digest();
    let outcome =
        verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env));
    assert!(matches!(outcome, EvaluatorOutcome::WrongLifecycleAction { .. }));
}

#[test]
fn r36_governance_valid_but_evaluator_response_invalid_rejected() {
    // The request (governance execution material) is valid, but the
    // response does not bind the request digest.
    let env = TrustBundleEnvironment::Devnet;
    let mut resp = rotate_response(env);
    resp.request_digest = "not-the-request-digest".to_string();
    let outcome =
        verify_governance_evaluator_response(&resp, &rotate_request(env), &rotate_expectations(env));
    assert!(matches!(
        outcome,
        EvaluatorOutcome::MalformedEvaluatorResponse { .. }
    ));
}

#[test]
fn r37_lifecycle_proof_custody_valid_but_production_unavailable_rejected() {
    // Even with otherwise-valid lifecycle/proof/custody material, a
    // production-required policy fails closed as unavailable for a
    // production source.
    let env = TrustBundleEnvironment::Devnet;
    let mut id = rotate_identity(env);
    id.source_kind = EvaluatorSourceKind::ProductionDecisionSourceUnavailable;
    assert_eq!(
        src(
            EvaluatorPolicy::ProductionDecisionSourceRequired,
            &id,
            &rotate_request(env),
            &rotate_expectations(env),
            env
        ),
        EvaluatorOutcome::ProductionDecisionSourceUnavailable
    );
}

#[test]
fn r38_validation_only_rejection_is_non_mutating() {
    // The evaluator is a pure function returning a typed value; a rejected
    // evaluation leaves all inputs untouched (no &mut anywhere). We assert
    // the inputs are unchanged after a rejecting call.
    let env = TrustBundleEnvironment::Devnet;
    let id = rotate_identity(env);
    let req = rotate_request(env);
    let exp = rotate_expectations(env);
    let id_before = id.clone();
    let req_before = req.clone();
    let _ = evaluate_governance_decision_source(
        &id,
        &req,
        &exp,
        &trust_domain(env),
        EvaluatorPolicy::Disabled,
    );
    assert_eq!(id, id_before);
    assert_eq!(req, req_before);
}

#[test]
fn r39_mutating_rejection_produces_no_mutation() {
    // The composed guard never mutates: a rejected composed outcome carries
    // the typed reject and performs no Run 070 call / trust swap / eviction
    // / sequence write / marker write (the module has no such APIs).
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_evaluator_with_peer_driven_guard(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_response(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::Disabled,
        false,
    );
    assert!(matches!(
        outcome,
        EvaluatorComposedOutcome::Rejected(EvaluatorOutcome::EvaluatorDisabled)
    ));
    assert!(outcome.is_reject());
}

#[test]
fn r40_mainnet_peer_driven_apply_refused_even_with_fixture_approval() {
    let env = TrustBundleEnvironment::Mainnet;
    let outcome = evaluate_governance_evaluator_with_peer_driven_guard(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_response(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
        true,
    );
    assert_eq!(outcome, EvaluatorComposedOutcome::MainNetPeerDrivenApplyRefused);
    assert!(mainnet_peer_driven_apply_remains_refused_under_evaluator(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// Separation / invariant tests
// ===========================================================================

#[test]
fn fixture_source_rejected_for_mainnet_trust_domain() {
    let env = TrustBundleEnvironment::Mainnet;
    let mut id = rotate_identity(env);
    id.environment = TrustBundleEnvironment::Mainnet;
    let mut req = rotate_request(env);
    req.decision_source_identity_digest = id.source_identity_digest();
    let mut exp = rotate_expectations(env);
    exp.expected_environment = TrustBundleEnvironment::Mainnet;
    let outcome = evaluate_governance_decision_source(
        &id,
        &req,
        &exp,
        &trust_domain(env),
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
    );
    assert_eq!(outcome, EvaluatorOutcome::FixtureRejectedForMainNet);
}

#[test]
fn validator_set_rotation_remains_unsupported_invariant() {
    assert!(validator_set_rotation_remains_unsupported_under_evaluator());
}

#[test]
fn fixture_and_emergency_evaluators_present_distinct_kinds() {
    let fixture = FixtureGovernanceExecutionEvaluatorInterface;
    let emergency = EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface;
    assert_eq!(
        fixture.source_kind(),
        EvaluatorSourceKind::FixtureDecisionSource
    );
    assert_eq!(
        emergency.source_kind(),
        EvaluatorSourceKind::EmergencyCouncilFixtureSource
    );
}

#[test]
fn full_round_trip_accepts_via_composed_guard() {
    let env = TrustBundleEnvironment::Devnet;
    let outcome = evaluate_governance_evaluator_with_peer_driven_guard(
        &rotate_identity(env),
        &rotate_request(env),
        &rotate_response(env),
        &rotate_expectations(env),
        &trust_domain(env),
        EvaluatorPolicy::FixtureDecisionSourceAllowed,
        false,
    );
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome,
        EvaluatorComposedOutcome::Accepted(EvaluatorOutcome::EvaluatorResponseAuthorized { .. })
    ));
}
