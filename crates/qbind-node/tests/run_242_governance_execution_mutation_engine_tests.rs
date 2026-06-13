//! Run 242 — source/test governance **execution mutation-engine boundary**
//! tests.
//!
//! Source/test only. Run 242 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the typed
//! mutation-engine boundary ([`evaluate_governance_mutation_engine`]) makes the
//! hand-off of an already-authorized governance evaluator decision to a future
//! mutation executor explicit and typed: MainNet peer-driven apply is refused
//! before any mutation attempt, a legacy bypass performs no mutation, a binding
//! mismatch is rejected before apply and never reaches the executor, a read-only
//! validation surface never mutates, validator-set rotation and policy-change
//! actions are unsupported, production / MainNet engine kinds are reachable but
//! unavailable, a DevNet/TestNet fixture mutation can report typed
//! success/failure/rollback/ambiguous, and the mutation outcome projects into the
//! Run 240 durable runtime's mutation-completion semantics so a durable consume
//! can only follow a modeled successful mutation.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_242.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_evaluator_replay_durable_backend::DurableMutationCompletion;
use qbind_node::pqc_governance_execution_mutation_engine::{
    evaluate_governance_mutation_engine, local_operator_cannot_satisfy_mutation_engine_authority,
    mainnet_peer_driven_apply_refused_by_mutation_engine,
    mutation_engine_rejection_is_non_mutating,
    mutation_failure_never_consumes_durable_replay_state,
    mutation_rollback_never_consumes_durable_replay_state,
    mutation_success_is_required_before_durable_consume,
    no_rocksdb_file_schema_migration_change_under_mutation_engine,
    peer_majority_cannot_satisfy_mutation_engine_authority,
    policy_change_unsupported_by_mutation_engine,
    production_mainnet_mutation_engine_unavailable,
    project_mutation_outcome_to_durable_completion, recover_governance_mutation_window,
    validator_set_rotation_unsupported_by_mutation_engine,
    wire_governance_mutation_engine_callsite, AuthorizedMutationRequest, FixtureMutationExecutor,
    GovernanceMutationAction, GovernanceMutationCandidate, GovernanceMutationEngineExpectations,
    GovernanceMutationEngineInput, GovernanceMutationEngineKind, GovernanceMutationEnvironmentBinding,
    GovernanceMutationExecutor, GovernanceMutationOutcome, GovernanceMutationPolicy,
    GovernanceMutationRuntimeBinding, GovernanceMutationSurface, MainNetMutationExecutor,
    MutationEngineDurableProjection, MutationExecutionResult, MutationWindow,
    MutationWindowObservation, ProductionMutationExecutor,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants
// ===========================================================================

const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SEQUENCE: u64 = 7;

// ===========================================================================
// Owned-context builder
// ===========================================================================

struct Ctx {
    candidate: GovernanceMutationCandidate,
    env: GovernanceMutationEnvironmentBinding,
    runtime: GovernanceMutationRuntimeBinding,
    expectations: GovernanceMutationEngineExpectations,
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    action: GovernanceMutationAction,
) -> Ctx {
    let candidate = GovernanceMutationCandidate {
        decision_digest: DECISION_DIGEST.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_domain_sequence: SEQUENCE,
        lifecycle_action: LocalLifecycleAction::Rotate,
        action,
    };
    let env = GovernanceMutationEnvironmentBinding {
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let runtime = GovernanceMutationRuntimeBinding {
        governance_surface: ms,
        mutation_surface: GovernanceMutationSurface {
            validation_surface: vs,
            mutation_surface: ms,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let expectations = GovernanceMutationEngineExpectations {
        expected_decision_digest: DECISION_DIGEST.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
    };
    Ctx {
        candidate,
        env,
        runtime,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        kind: GovernanceMutationEngineKind,
        policy: GovernanceMutationPolicy,
    ) -> GovernanceMutationEngineInput<'_> {
        GovernanceMutationEngineInput {
            engine_kind: kind,
            policy,
            candidate: &self.candidate,
            environment_binding: &self.env,
            runtime_binding: &self.runtime,
        }
    }
}

/// Standard fresh DevNet mutating apply context.
fn devnet_mutating() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn testnet_mutating() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn devnet_validation() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn devnet_exec(result: MutationExecutionResult) -> FixtureMutationExecutor {
    FixtureMutationExecutor::new(TrustBundleEnvironment::Devnet, result)
}

// ===========================================================================
// A — accepted / compatible
// ===========================================================================

#[test]
fn a1_disabled_policy_preserves_legacy_bypass_no_mutation() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::Disabled,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::ProceedLegacyBypassNoMutation);
    assert_eq!(exec.attempts(), 0, "legacy bypass never invokes the executor");
    assert!(outcome.is_legacy_bypass());
    assert!(outcome.no_consume());
}

#[test]
fn a1b_disabled_engine_kind_preserves_legacy_bypass() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::Disabled,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::ProceedLegacyBypassNoMutation);
    assert_eq!(exec.attempts(), 0);
}

#[test]
fn a2_devnet_fixture_mutation_success() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationAppliedSuccessfully);
    assert_eq!(exec.attempts(), 1);
    assert!(outcome.is_applied_successfully());
}

#[test]
fn a3_testnet_fixture_mutation_success() {
    let c = testnet_mutating();
    let mut exec = FixtureMutationExecutor::new(
        TrustBundleEnvironment::Testnet,
        MutationExecutionResult::AppliedSuccessfully,
    );
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureTestNet,
            GovernanceMutationPolicy::FixtureTestNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationAppliedSuccessfully);
    assert_eq!(exec.attempts(), 1);
}

#[test]
fn a4_mutation_success_composes_into_durable_consume_after_success() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    let projection = project_mutation_outcome_to_durable_completion(&outcome);
    assert_eq!(
        projection,
        MutationEngineDurableProjection::DurableCompletion(
            DurableMutationCompletion::AppliedSuccessfully
        )
    );
    assert!(projection.authorizes_durable_consume());
}

#[test]
fn a5_read_only_validation_never_mutates() {
    let c = devnet_validation();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert!(matches!(
        outcome,
        GovernanceMutationOutcome::MutationRejectedBeforeApply { .. }
    ));
    assert_eq!(exec.attempts(), 0, "validation surface never reaches the executor");
    let projection = project_mutation_outcome_to_durable_completion(&outcome);
    assert!(!projection.authorizes_durable_consume());
}

#[test]
fn a6_failed_apply_never_consumes() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::ApplyFailed);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationApplyFailed);
    assert!(outcome.no_consume());
    let projection = project_mutation_outcome_to_durable_completion(&outcome);
    assert_eq!(
        projection,
        MutationEngineDurableProjection::DurableCompletion(DurableMutationCompletion::ApplyFailed)
    );
    assert!(!projection.authorizes_durable_consume());
}

#[test]
fn a7_rollback_never_consumes() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::RolledBack);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationRolledBack);
    let projection = project_mutation_outcome_to_durable_completion(&outcome);
    assert_eq!(
        projection,
        MutationEngineDurableProjection::DurableCompletion(DurableMutationCompletion::RolledBack)
    );
    assert!(!projection.authorizes_durable_consume());
}

#[test]
fn a8_authorized_not_applied_does_not_consume() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AuthorizedNotApplied);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationAuthorized);
    assert!(outcome.is_authorized_not_applied());
    let projection = project_mutation_outcome_to_durable_completion(&outcome);
    assert_eq!(
        projection,
        MutationEngineDurableProjection::DurableCompletion(
            DurableMutationCompletion::AuthorizedButNotApplied
        )
    );
    assert!(!projection.authorizes_durable_consume());
}

#[test]
fn a9_ambiguous_after_authorization_window_fails_closed() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AmbiguousAfterAuthorization);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationAmbiguousFailClosed);
    assert!(outcome.is_fail_closed());
    let projection = project_mutation_outcome_to_durable_completion(&outcome);
    assert!(matches!(
        projection,
        MutationEngineDurableProjection::FailClosedBeforeDurable(_)
    ));
}

#[test]
fn a10_production_mutation_path_reachable_but_unavailable() {
    let c = devnet_mutating();
    let mut exec = ProductionMutationExecutor;
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::ProductionUnavailable,
            GovernanceMutationPolicy::Production,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::ProductionMutationUnavailable);
    assert!(outcome.executor_must_not_run());
    assert!(matches!(
        project_mutation_outcome_to_durable_completion(&outcome),
        MutationEngineDurableProjection::FailClosedBeforeDurable(_)
    ));
}

#[test]
fn a11_mainnet_mutation_path_reachable_but_unavailable() {
    // MainNet non-peer-driven mutating surface: reachable but unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    );
    let mut exec = MainNetMutationExecutor;
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::MainNetUnavailable,
            GovernanceMutationPolicy::MainNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MainNetMutationUnavailable);
    assert!(outcome.executor_must_not_run());
}

#[test]
fn a12_mainnet_peer_driven_apply_refused_before_mutation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    );
    // Even if a fixture executor would "succeed", the refusal happens first.
    let mut exec = FixtureMutationExecutor::new(
        TrustBundleEnvironment::Mainnet,
        MutationExecutionResult::AppliedSuccessfully,
    );
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(
        outcome,
        GovernanceMutationOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(exec.attempts(), 0, "refusal happens before any mutation attempt");
}

#[test]
fn a13_validator_set_rotation_unsupported() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::ValidatorSetRotation,
    );
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(
        outcome,
        GovernanceMutationOutcome::ValidatorSetRotationUnsupported
    );
    assert_eq!(exec.attempts(), 0);
}

#[test]
fn a14_policy_change_action_unsupported() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::PolicyChange,
    );
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::PolicyChangeUnsupported);
    assert_eq!(exec.attempts(), 0);
}

#[test]
fn a15_callsite_wiring_ok_on_success_err_on_fail_closed() {
    // Success -> Ok.
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let ok = wire_governance_mutation_engine_callsite(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert!(ok.is_ok());

    // Apply failed -> Err.
    let mut exec2 = devnet_exec(MutationExecutionResult::ApplyFailed);
    let err = wire_governance_mutation_engine_callsite(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec2,
    );
    let fc = err.expect_err("apply-failed must fail closed at the call site");
    assert!(fc.reason.contains("No Run 070 apply"));
    assert!(fc.reason.contains("no durable consume"));
}

// ===========================================================================
// R — rejected (binding mismatches never reach the executor)
// ===========================================================================

fn assert_rejected_before_apply(mutate: impl FnOnce(&mut GovernanceMutationEngineExpectations)) {
    let c = devnet_mutating();
    let mut exp = c.expectations.clone();
    mutate(&mut exp);
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &exp,
        &mut exec,
    );
    assert!(
        matches!(
            outcome,
            GovernanceMutationOutcome::MutationRejectedBeforeApply { .. }
        ),
        "expected rejected-before-apply, got {:?}",
        outcome
    );
    assert_eq!(exec.attempts(), 0, "rejected path never reaches the executor");
    assert!(outcome.executor_must_not_run());
    assert!(matches!(
        project_mutation_outcome_to_durable_completion(&outcome),
        MutationEngineDurableProjection::FailClosedBeforeDurable(_)
    ));
}

#[test]
fn r1_wrong_environment_rejected() {
    assert_rejected_before_apply(|e| e.expected_environment = TrustBundleEnvironment::Testnet);
}

#[test]
fn r2_wrong_chain_rejected() {
    assert_rejected_before_apply(|e| e.expected_chain_id = "qbind-other".to_string());
}

#[test]
fn r3_wrong_genesis_rejected() {
    assert_rejected_before_apply(|e| e.expected_genesis_hash = "other-genesis".to_string());
}

#[test]
fn r4_wrong_governance_surface_rejected() {
    assert_rejected_before_apply(|e| {
        e.expected_governance_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn r5_wrong_mutation_surface_rejected() {
    assert_rejected_before_apply(|e| {
        e.expected_mutation_surface = GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle
    });
}

#[test]
fn r6_wrong_candidate_digest_rejected() {
    assert_rejected_before_apply(|e| e.expected_candidate_digest = "other-candidate".to_string());
}

#[test]
fn r7_wrong_decision_digest_rejected() {
    assert_rejected_before_apply(|e| e.expected_decision_digest = "other-decision".to_string());
}

#[test]
fn r8_wrong_proposal_id_rejected() {
    assert_rejected_before_apply(|e| e.expected_proposal_id = "proposal-9999".to_string());
}

#[test]
fn r9_wrong_decision_id_rejected() {
    assert_rejected_before_apply(|e| e.expected_decision_id = "decision-9999".to_string());
}

#[test]
fn r10_wrong_authority_domain_sequence_rejected() {
    assert_rejected_before_apply(|e| e.expected_authority_domain_sequence = 999);
}

#[test]
fn r11_wrong_lifecycle_action_rejected() {
    assert_rejected_before_apply(|e| e.expected_lifecycle_action = LocalLifecycleAction::Revoke);
}

#[test]
fn r12_malformed_candidate_rejected() {
    let mut c = devnet_mutating();
    c.candidate.candidate_digest = String::new();
    let mut exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert!(matches!(
        outcome,
        GovernanceMutationOutcome::MutationRejectedBeforeApply { .. }
    ));
    assert_eq!(exec.attempts(), 0);
}

#[test]
fn r13_consume_after_failed_apply_never_authorized() {
    // The projection of a failed apply never authorizes a durable consume.
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::ApplyFailed);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert!(!project_mutation_outcome_to_durable_completion(&outcome).authorizes_durable_consume());
}

#[test]
fn r14_consume_after_rollback_never_authorized() {
    let c = devnet_mutating();
    let mut exec = devnet_exec(MutationExecutionResult::RolledBack);
    let outcome = evaluate_governance_mutation_engine(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &c.expectations,
        &mut exec,
    );
    assert!(!project_mutation_outcome_to_durable_completion(&outcome).authorizes_durable_consume());
}

#[test]
fn r15_local_operator_and_peer_majority_cannot_satisfy_authority() {
    assert!(local_operator_cannot_satisfy_mutation_engine_authority());
    assert!(peer_majority_cannot_satisfy_mutation_engine_authority());
}

// ===========================================================================
// Recovery — mutation-window classification fails closed
// ===========================================================================

#[test]
fn recovery_ambiguous_after_apply_before_report_fails_closed() {
    let c = devnet_mutating();
    let exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let observation = MutationWindowObservation {
        authorized: true,
        apply_attempted: true,
        completion_reported: false,
    };
    let outcome = recover_governance_mutation_window(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &observation,
        &exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::MutationAmbiguousFailClosed);
}

#[test]
fn recovery_before_authorization_rejected_before_apply() {
    let c = devnet_mutating();
    let exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    let observation = MutationWindowObservation {
        authorized: false,
        apply_attempted: false,
        completion_reported: false,
    };
    let outcome = recover_governance_mutation_window(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &observation,
        &exec,
    );
    assert!(matches!(
        outcome,
        GovernanceMutationOutcome::MutationRejectedBeforeApply { .. }
    ));
}

#[test]
fn recovery_mainnet_peer_driven_refused_before_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    );
    let exec = FixtureMutationExecutor::new(
        TrustBundleEnvironment::Mainnet,
        MutationExecutionResult::AppliedSuccessfully,
    );
    let observation = MutationWindowObservation {
        authorized: true,
        apply_attempted: true,
        completion_reported: true,
    };
    let outcome = recover_governance_mutation_window(
        &c.input(
            GovernanceMutationEngineKind::FixtureDevNet,
            GovernanceMutationPolicy::FixtureDevNet,
        ),
        &observation,
        &exec,
    );
    assert_eq!(
        outcome,
        GovernanceMutationOutcome::MainNetPeerDrivenApplyRefused
    );
}

#[test]
fn recovery_production_unavailable() {
    let c = devnet_mutating();
    let exec = ProductionMutationExecutor;
    let observation = MutationWindowObservation {
        authorized: true,
        apply_attempted: true,
        completion_reported: false,
    };
    let outcome = recover_governance_mutation_window(
        &c.input(
            GovernanceMutationEngineKind::ProductionUnavailable,
            GovernanceMutationPolicy::Production,
        ),
        &observation,
        &exec,
    );
    assert_eq!(outcome, GovernanceMutationOutcome::ProductionMutationUnavailable);
}

// ===========================================================================
// Executor trait direct behavior
// ===========================================================================

#[test]
fn fixture_executor_window_classification() {
    let exec = devnet_exec(MutationExecutionResult::AppliedSuccessfully);
    assert_eq!(
        exec.recover_mutation_window(&MutationWindowObservation {
            authorized: false,
            apply_attempted: false,
            completion_reported: false,
        }),
        MutationWindow::BeforeAuthorization
    );
    assert_eq!(
        exec.recover_mutation_window(&MutationWindowObservation {
            authorized: true,
            apply_attempted: false,
            completion_reported: false,
        }),
        MutationWindow::AfterAuthorizationBeforeApply
    );
    assert_eq!(
        exec.recover_mutation_window(&MutationWindowObservation {
            authorized: true,
            apply_attempted: true,
            completion_reported: false,
        }),
        MutationWindow::AfterApplyBeforeReport
    );
    assert_eq!(
        exec.recover_mutation_window(&MutationWindowObservation {
            authorized: true,
            apply_attempted: true,
            completion_reported: true,
        }),
        MutationWindow::AfterReport
    );
}

#[test]
fn production_and_mainnet_executors_unavailable() {
    let cand = GovernanceMutationCandidate {
        decision_digest: DECISION_DIGEST.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_domain_sequence: SEQUENCE,
        lifecycle_action: LocalLifecycleAction::Rotate,
        action: GovernanceMutationAction::ApplyAuthorizedCandidate,
    };
    let env = GovernanceMutationEnvironmentBinding {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let rt = GovernanceMutationRuntimeBinding {
        governance_surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        mutation_surface: GovernanceMutationSurface {
            validation_surface: GovernanceExecutionRuntimeSurface::ReloadApply,
            mutation_surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let request = AuthorizedMutationRequest {
        engine_kind: GovernanceMutationEngineKind::ProductionUnavailable,
        candidate: &cand,
        environment_binding: &env,
        runtime_binding: &rt,
    };
    let mut prod = ProductionMutationExecutor;
    assert_eq!(
        prod.execute_authorized_mutation(&request),
        MutationExecutionResult::Unavailable
    );
    let mut main = MainNetMutationExecutor;
    assert_eq!(
        main.execute_authorized_mutation(&request),
        MutationExecutionResult::Unavailable
    );
}

// ===========================================================================
// Invariant helpers (grep-verifiable)
// ===========================================================================

#[test]
fn invariant_helpers_are_fail_closed() {
    assert!(mutation_engine_rejection_is_non_mutating());
    assert!(mutation_success_is_required_before_durable_consume());
    assert!(mutation_failure_never_consumes_durable_replay_state());
    assert!(mutation_rollback_never_consumes_durable_replay_state());
    assert!(production_mainnet_mutation_engine_unavailable());
    assert!(mainnet_peer_driven_apply_refused_by_mutation_engine(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!mainnet_peer_driven_apply_refused_by_mutation_engine(
        TrustBundleEnvironment::Devnet
    ));
    assert!(no_rocksdb_file_schema_migration_change_under_mutation_engine());
    assert!(validator_set_rotation_unsupported_by_mutation_engine());
    assert!(policy_change_unsupported_by_mutation_engine());
}
