//! Run 244 — source/test governance **modeled trust-state mutation applier
//! boundary** tests.
//!
//! Source/test only. Run 244 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! trust-state mutation applier boundary
//! ([`evaluate_modeled_trust_mutation`]) snapshots a modeled in-memory trust
//! state, applies a modeled trust-state update, reports
//! success/failure/rollback/ambiguous windows, and projects the result back into
//! the Run 242 mutation-engine outcome and the Run 240 durable completion
//! semantics so a durable consume can only follow a modeled successful apply.
//!
//! Every rejected path is non-mutating: no Run 070 call, no `LivePqcTrustState`
//! mutation, no real trust swap, no session eviction, no sequence write, no
//! marker write, no durable consume, and no applier invocation where the
//! rejection happens before apply.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_244.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_evaluator_replay_durable_backend::DurableMutationCompletion;
use qbind_node::pqc_governance_execution_mutation_engine::{
    GovernanceMutationOutcome, MutationEngineDurableProjection,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_trust_mutation_applier::{
    evaluate_modeled_trust_mutation, local_operator_cannot_satisfy_modeled_trust_applier_authority,
    mainnet_peer_driven_apply_refused_by_modeled_trust_applier,
    map_modeled_outcome_to_mutation_engine_outcome,
    modeled_outcome_authorizes_durable_consume,
    modeled_trust_applier_ambiguous_window_fails_closed,
    modeled_trust_applier_failure_never_consumes,
    modeled_trust_applier_never_calls_run_070,
    modeled_trust_applier_never_mutates_live_pqc_trust_state,
    modeled_trust_applier_no_rocksdb_file_schema_migration_change,
    modeled_trust_applier_rejection_is_non_mutating,
    modeled_trust_applier_rollback_never_consumes,
    modeled_trust_applier_success_required_before_durable_consume,
    peer_majority_cannot_satisfy_modeled_trust_applier_authority,
    policy_change_unsupported_by_modeled_trust_applier,
    production_mainnet_modeled_trust_applier_unavailable,
    project_modeled_outcome_to_durable_completion, recover_modeled_trust_mutation,
    validator_set_rotation_unsupported_by_modeled_trust_applier, FixtureModeledTrustMutationApplier,
    MainNetModeledTrustMutationApplier, ModeledApplierFault, ModeledGovernanceTrustMutation,
    ModeledGovernanceTrustMutationApplier, ModeledGovernanceTrustMutationApplierKind,
    ModeledGovernanceTrustMutationEnvironmentBinding, ModeledGovernanceTrustMutationExpectations,
    ModeledGovernanceTrustMutationInput, ModeledGovernanceTrustMutationPolicy,
    ModeledGovernanceTrustMutationRuntimeBinding, ModeledGovernanceTrustMutationSurface,
    ModeledGovernanceTrustRoot, ModeledGovernanceTrustState, ModeledTrustMutationAction,
    ModeledTrustMutationOutcome, ModeledTrustMutationWindowObservation, ModeledTrustRootStatus,
    ProductionModeledTrustMutationApplier,
};
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
const ROOT: &str = "modeled-trust-root-A";

// ===========================================================================
// Owned-context builder
// ===========================================================================

struct Ctx {
    mutation: ModeledGovernanceTrustMutation,
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    expectations: ModeledGovernanceTrustMutationExpectations,
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    action: ModeledTrustMutationAction,
    root_id: &str,
) -> Ctx {
    let mutation = ModeledGovernanceTrustMutation {
        action,
        root_id: root_id.to_string(),
        decision_digest: DECISION_DIGEST.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_domain_sequence: SEQUENCE,
        lifecycle_action: LocalLifecycleAction::Rotate,
    };
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let runtime = ModeledGovernanceTrustMutationRuntimeBinding {
        governance_surface: ms,
        mutation_surface: ModeledGovernanceTrustMutationSurface {
            validation_surface: vs,
            mutation_surface: ms,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let expectations = ModeledGovernanceTrustMutationExpectations {
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
        mutation,
        env,
        runtime,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        policy: ModeledGovernanceTrustMutationPolicy,
        applier_kind: ModeledGovernanceTrustMutationApplierKind,
    ) -> ModeledGovernanceTrustMutationInput<'_> {
        ModeledGovernanceTrustMutationInput {
            applier_kind,
            policy,
            mutation: &self.mutation,
            environment_binding: &self.env,
            runtime_binding: &self.runtime,
        }
    }
}

/// A modeled trust state seeded with one active root.
fn state_with_active_root() -> ModeledGovernanceTrustState {
    ModeledGovernanceTrustState::with_roots(vec![ModeledGovernanceTrustRoot::active(ROOT)])
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_policy_preserves_legacy_bypass_no_modeled_mutation() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::Disabled,
        ModeledGovernanceTrustMutationApplierKind::Disabled,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationNotAttempted);
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty(), "legacy bypass performs no modeled mutation");
    assert!(outcome.no_consume());
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::ProceedLegacyBypassNoMutation
    );
}

#[test]
fn devnet_fixture_add_root_succeeds_only_in_modeled_state() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert!(state.contains_active(ROOT));
    assert_eq!(state.len(), 1);
    assert_eq!(applier.attempts(), 1);
    assert!(modeled_outcome_authorizes_durable_consume(&outcome));
}

#[test]
fn testnet_fixture_add_root_succeeds_only_in_modeled_state() {
    let c = ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureTestNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureTestNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Testnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert!(state.contains_active(ROOT));
    assert_eq!(applier.attempts(), 1);
}

#[test]
fn fixture_retire_root_succeeds_in_modeled_state_only() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::RetireTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert_eq!(state.status_of(ROOT), Some(ModeledTrustRootStatus::Retired));
}

#[test]
fn fixture_revoke_root_succeeds_in_modeled_state_only() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::RevokeTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert_eq!(state.status_of(ROOT), Some(ModeledTrustRootStatus::Revoked));
}

#[test]
fn fixture_emergency_revoke_root_succeeds_in_modeled_state_only() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::EmergencyRevokeTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert_eq!(
        state.status_of(ROOT),
        Some(ModeledTrustRootStatus::EmergencyRevoked)
    );
}

#[test]
fn fixture_noop_succeeds_without_state_drift() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::Noop,
        "",
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = state_with_active_root();
    let before = state.clone();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert_eq!(state, before, "noop performs no modeled state drift");
}

#[test]
fn applied_success_maps_to_mutation_applied_successfully() {
    let outcome = ModeledTrustMutationOutcome::ModeledMutationApplied;
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::MutationAppliedSuccessfully
    );
}

#[test]
fn applied_success_projects_to_consume_eligible_durable_completion() {
    let outcome = ModeledTrustMutationOutcome::ModeledMutationApplied;
    let projection = project_modeled_outcome_to_durable_completion(&outcome);
    assert_eq!(
        projection,
        MutationEngineDurableProjection::DurableCompletion(
            DurableMutationCompletion::AppliedSuccessfully
        )
    );
    assert!(projection.authorizes_durable_consume());
}

#[test]
fn duplicate_root_handled_idempotently_under_explicit_typed_outcome() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    // Idempotent: explicit applied outcome, no duplicate root added.
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert_eq!(state.len(), 1, "duplicate add is idempotent");
}

// ===========================================================================
// Production / MainNet reachable-but-unavailable
// ===========================================================================

#[test]
fn production_modeled_applier_reachable_but_unavailable() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let mut exp = c.expectations.clone();
    exp.expected_environment = TrustBundleEnvironment::Mainnet;
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::Production,
        ModeledGovernanceTrustMutationApplierKind::ProductionUnavailable,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = ProductionModeledTrustMutationApplier;
    let outcome = evaluate_modeled_trust_mutation(&input, &exp, &mut state, &mut applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable
    );
    assert!(outcome.applier_must_not_run());
    assert!(state.is_empty());
    assert!(outcome.no_consume());
}

#[test]
fn mainnet_modeled_applier_reachable_but_unavailable() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let mut exp = c.expectations.clone();
    exp.expected_environment = TrustBundleEnvironment::Mainnet;
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::MainNet,
        ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = MainNetModeledTrustMutationApplier;
    let outcome = evaluate_modeled_trust_mutation(&input, &exp, &mut state, &mut applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable
    );
    assert!(state.is_empty());
    assert!(outcome.no_consume());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_snapshot_and_applier_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::MainNet,
        ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Mainnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(applier.attempts(), 0, "refused before applier invocation");
    assert!(state.is_empty());
}

#[test]
fn validator_set_rotation_unsupported() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::ValidatorSetRotationUnsupported,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ValidatorSetRotationUnsupported
    );
    assert_eq!(applier.attempts(), 0);
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::ValidatorSetRotationUnsupported
    );
}

#[test]
fn policy_change_unsupported() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::PolicyChangeUnsupported,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::PolicyChangeUnsupported);
    assert_eq!(applier.attempts(), 0);
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::PolicyChangeUnsupported
    );
}

// ===========================================================================
// Rejected-before-snapshot matrix (binding mismatches never invoke the applier)
// ===========================================================================

fn assert_rejected_before_snapshot(mutate_exp: impl Fn(&mut ModeledGovernanceTrustMutationExpectations)) {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let mut exp = c.expectations.clone();
    mutate_exp(&mut exp);
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &exp, &mut state, &mut applier);
    assert!(
        matches!(
            outcome,
            ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }
        ),
        "expected rejected-before-snapshot, got {:?}",
        outcome
    );
    assert_eq!(applier.attempts(), 0, "rejected-before-snapshot never invokes applier");
    assert!(state.is_empty());
    assert!(outcome.no_consume());
    assert!(outcome.applier_must_not_run());
}

#[test]
fn wrong_environment_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_environment = TrustBundleEnvironment::Testnet);
}

#[test]
fn wrong_chain_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_chain_id = "qbind-other".to_string());
}

#[test]
fn wrong_genesis_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_genesis_hash = "other-genesis".to_string());
}

#[test]
fn wrong_governance_surface_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| {
        e.expected_governance_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| {
        e.expected_mutation_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_candidate_digest = "other-candidate".to_string());
}

#[test]
fn wrong_decision_digest_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_decision_digest = "other-decision".to_string());
}

#[test]
fn wrong_proposal_id_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_proposal_id = "proposal-9999".to_string());
}

#[test]
fn wrong_decision_id_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_decision_id = "decision-9999".to_string());
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_snapshot() {
    assert_rejected_before_snapshot(|e| e.expected_authority_domain_sequence = 999);
}

#[test]
fn malformed_modeled_mutation_rejected_before_snapshot() {
    let mut c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    // Empty root id on an action that requires one is malformed.
    c.mutation.root_id = String::new();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }
    ));
    assert_eq!(applier.attempts(), 0);
}

#[test]
fn wrong_governance_surface_validation_only_rejected_before_snapshot() {
    // A read-only validation surface never mutates.
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }
    ));
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty());
}

// ===========================================================================
// Rejected-before-apply matrix (applier snapshots then rejects)
// ===========================================================================

#[test]
fn retiring_missing_root_rejected_before_apply() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::RetireTrustRoot,
        "absent-root",
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let before = state.clone();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply { .. }
    ));
    // The applier was invoked (it snapshotted) but the modeled state is unchanged.
    assert_eq!(applier.attempts(), 1);
    assert_eq!(state, before, "rejected-before-apply leaves modeled state unchanged");
    assert!(outcome.no_consume());
    assert!(matches!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::MutationRejectedBeforeApply { .. }
    ));
}

#[test]
fn revoking_missing_root_rejected_before_apply() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::RevokeTrustRoot,
        "absent-root",
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply { .. }
    ));
    assert_eq!(applier.attempts(), 1);
    assert!(state.is_empty());
    assert!(outcome.no_consume());
}

// ===========================================================================
// Apply-failure / rollback / fatal / ambiguous matrix
// ===========================================================================

#[test]
fn apply_failure_before_mutation_never_consumes() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::ApplyFailedBeforeMutation,
    );
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplyFailed);
    assert!(state.is_empty(), "apply failure leaves modeled state unchanged");
    assert!(outcome.no_consume());
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::MutationApplyFailed
    );
}

#[test]
fn apply_failure_rolls_back_modeled_state_and_never_consumes() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let before = state.clone();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::ApplyFailedRolledBack,
    );
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationRolledBack);
    assert_eq!(state, before, "rollback restores the pre-apply modeled state");
    assert!(outcome.no_consume());
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::MutationRolledBack
    );
}

#[test]
fn rollback_failure_is_fatal_fail_closed_and_never_consumes() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::RollbackFailedFatal,
    );
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal
    );
    assert!(outcome.no_consume());
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::MutationAmbiguousFailClosed
    );
}

#[test]
fn ambiguous_window_fails_closed_and_never_consumes() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::AmbiguousAfterApply,
    );
    let outcome = evaluate_modeled_trust_mutation(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed
    );
    assert!(outcome.no_consume());
    assert_eq!(
        map_modeled_outcome_to_mutation_engine_outcome(&outcome),
        GovernanceMutationOutcome::MutationAmbiguousFailClosed
    );
}

// ===========================================================================
// Non-success outcomes never consume (durable projection)
// ===========================================================================

#[test]
fn non_success_outcomes_never_authorize_durable_consume() {
    let outcomes = [
        ModeledTrustMutationOutcome::ModeledMutationNotAttempted,
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot {
            reason: "x".to_string(),
        },
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply {
            reason: "x".to_string(),
        },
        ModeledTrustMutationOutcome::ModeledMutationApplyFailed,
        ModeledTrustMutationOutcome::ModeledMutationRolledBack,
        ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal,
        ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed,
        ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable,
        ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable,
        ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused,
        ModeledTrustMutationOutcome::ValidatorSetRotationUnsupported,
        ModeledTrustMutationOutcome::PolicyChangeUnsupported,
    ];
    for o in &outcomes {
        assert!(
            !modeled_outcome_authorizes_durable_consume(o),
            "{:?} must never authorize durable consume",
            o
        );
        assert!(o.no_consume());
    }
    // Only the applied success authorizes a durable consume.
    assert!(modeled_outcome_authorizes_durable_consume(
        &ModeledTrustMutationOutcome::ModeledMutationApplied
    ));
}

// ===========================================================================
// Recovery / crash-window matrix
// ===========================================================================

fn devnet_input_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    )
}

#[test]
fn recovery_before_snapshot_recovers_as_not_attempted() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let obs = ModeledTrustMutationWindowObservation::default();
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationNotAttempted);
    assert!(outcome.no_consume());
}

#[test]
fn recovery_after_snapshot_before_apply_rolls_back_no_consume() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        ..Default::default()
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationRolledBack);
    assert!(outcome.no_consume());
}

#[test]
fn recovery_after_apply_before_report_fails_closed() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        ..Default::default()
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_after_report_success_recovers_as_applied() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        completion_reported: true,
        success_reported: true,
        rollback_failed: false,
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
    assert!(modeled_outcome_authorizes_durable_consume(&outcome));
}

#[test]
fn recovery_after_report_ambiguous_fails_closed() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        completion_reported: true,
        success_reported: false,
        rollback_failed: false,
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_rollback_failed_is_fatal() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        rollback_failed: true,
        ..Default::default()
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_production_classification_unavailable() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::Production,
        ModeledGovernanceTrustMutationApplierKind::ProductionUnavailable,
    );
    let applier = ProductionModeledTrustMutationApplier;
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        completion_reported: true,
        success_reported: true,
        rollback_failed: false,
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_mainnet_classification_unavailable() {
    let c = devnet_input_ctx();
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::MainNet,
        ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable,
    );
    let applier = MainNetModeledTrustMutationApplier;
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        completion_reported: true,
        success_reported: true,
        rollback_failed: false,
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_mainnet_peer_driven_refusal_precedes_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.input(
        ModeledGovernanceTrustMutationPolicy::MainNet,
        ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable,
    );
    let applier = MainNetModeledTrustMutationApplier;
    let obs = ModeledTrustMutationWindowObservation {
        snapshotted: true,
        applied: true,
        completion_reported: true,
        success_reported: true,
        rollback_failed: false,
    };
    let outcome = recover_modeled_trust_mutation(&input, &obs, &applier);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused
    );
}

// ===========================================================================
// Invariant helpers
// ===========================================================================

#[test]
fn invariant_helpers_are_fail_closed() {
    assert!(modeled_trust_applier_rejection_is_non_mutating());
    assert!(modeled_trust_applier_never_calls_run_070());
    assert!(modeled_trust_applier_never_mutates_live_pqc_trust_state());
    assert!(modeled_trust_applier_success_required_before_durable_consume());
    assert!(modeled_trust_applier_failure_never_consumes());
    assert!(modeled_trust_applier_rollback_never_consumes());
    assert!(modeled_trust_applier_ambiguous_window_fails_closed());
    assert!(production_mainnet_modeled_trust_applier_unavailable());
    assert!(mainnet_peer_driven_apply_refused_by_modeled_trust_applier(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!mainnet_peer_driven_apply_refused_by_modeled_trust_applier(
        TrustBundleEnvironment::Devnet
    ));
    assert!(validator_set_rotation_unsupported_by_modeled_trust_applier());
    assert!(policy_change_unsupported_by_modeled_trust_applier());
    assert!(modeled_trust_applier_no_rocksdb_file_schema_migration_change());
    assert!(local_operator_cannot_satisfy_modeled_trust_applier_authority());
    assert!(peer_majority_cannot_satisfy_modeled_trust_applier_authority());
}

#[test]
fn local_operator_and_peer_majority_cannot_satisfy_mainnet_authority() {
    // A MainNet modeled applier is always unavailable regardless of any local
    // operator key or peer-majority count.
    assert!(local_operator_cannot_satisfy_modeled_trust_applier_authority());
    assert!(peer_majority_cannot_satisfy_modeled_trust_applier_authority());
    let mut state = ModeledGovernanceTrustState::new();
    let request_kind = ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable;
    assert!(request_kind.is_unavailable());
    let mut applier = MainNetModeledTrustMutationApplier;
    let mutation = ModeledGovernanceTrustMutation {
        action: ModeledTrustMutationAction::AddTrustRoot,
        root_id: ROOT.to_string(),
        decision_digest: DECISION_DIGEST.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_domain_sequence: SEQUENCE,
        lifecycle_action: LocalLifecycleAction::Rotate,
    };
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: TrustBundleEnvironment::Mainnet,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let rt = ModeledGovernanceTrustMutationRuntimeBinding {
        governance_surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        mutation_surface: ModeledGovernanceTrustMutationSurface {
            validation_surface: GovernanceExecutionRuntimeSurface::ReloadApply,
            mutation_surface: GovernanceExecutionRuntimeSurface::ReloadApply,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let request = qbind_node::pqc_governance_modeled_trust_mutation_applier::ModeledTrustMutationRequest {
        applier_kind: request_kind,
        mutation: &mutation,
        environment_binding: &env,
        runtime_binding: &rt,
    };
    let outcome = applier.apply_modeled_mutation(&mut state, &request);
    assert_eq!(
        outcome,
        ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable
    );
    assert!(state.is_empty());
}