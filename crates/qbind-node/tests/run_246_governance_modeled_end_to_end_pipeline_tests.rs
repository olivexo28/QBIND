//! Run 246 — source/test governance **modeled end-to-end pipeline** tests.
//!
//! Source/test only. Run 246 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! end-to-end governance pipeline
//! ([`run_modeled_end_to_end_pipeline`]) composes the Run 226 evaluator
//! call-site, Run 240 durable replay observation, Run 242 mutation-engine, and
//! Run 244 modeled applier boundaries so that a durable consume is authorized
//! end-to-end **only** after a modeled successful applier outcome.
//!
//! Every rejected path is non-mutating and non-consuming: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no durable consume, and no applier invocation
//! where the rejection happens before the applier stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_246.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_execution_mutation_engine::GovernanceMutationOutcome;
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_end_to_end_pipeline::{
    modeled_end_to_end_pipeline_ambiguous_window_fails_closed,
    modeled_end_to_end_pipeline_applier_success_required_before_consume,
    modeled_end_to_end_pipeline_failed_apply_never_consumes,
    modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority,
    modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first,
    modeled_end_to_end_pipeline_never_calls_run_070,
    modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state,
    modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change,
    modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_end_to_end_pipeline_policy_change_unsupported,
    modeled_end_to_end_pipeline_production_mainnet_unavailable,
    modeled_end_to_end_pipeline_rejection_is_non_mutating,
    modeled_end_to_end_pipeline_rollback_never_consumes,
    modeled_end_to_end_pipeline_success_required_before_durable_consume,
    modeled_end_to_end_pipeline_validator_set_rotation_unsupported,
    recover_modeled_end_to_end_pipeline_window, run_modeled_end_to_end_pipeline,
    DefaultGovernanceModeledEndToEndPipelineExecutor, DurableReplayObservation,
    EvaluatorCallsiteAuthorization, GovernanceModeledEndToEndPipelineExecutor,
    GovernanceModeledEndToEndPipelineInput, GovernanceModeledEndToEndPipelineOutcome,
    GovernanceModeledEndToEndPipelinePolicy,
};
use qbind_node::pqc_governance_modeled_trust_mutation_applier::{
    FixtureModeledTrustMutationApplier, MainNetModeledTrustMutationApplier, ModeledApplierFault,
    ModeledGovernanceTrustMutation, ModeledGovernanceTrustMutationApplierKind,
    ModeledGovernanceTrustMutationEnvironmentBinding, ModeledGovernanceTrustMutationExpectations,
    ModeledGovernanceTrustMutationInput, ModeledGovernanceTrustMutationPolicy,
    ModeledGovernanceTrustMutationRuntimeBinding, ModeledGovernanceTrustMutationSurface,
    ModeledGovernanceTrustRoot, ModeledGovernanceTrustState, ModeledTrustMutationAction,
    ModeledTrustMutationOutcome, ProductionModeledTrustMutationApplier,
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
    fn modeled_input(
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

    fn pipeline_input(
        &self,
        policy: GovernanceModeledEndToEndPipelinePolicy,
        evaluator: EvaluatorCallsiteAuthorization,
        replay: DurableReplayObservation,
        modeled_policy: ModeledGovernanceTrustMutationPolicy,
        applier_kind: ModeledGovernanceTrustMutationApplierKind,
    ) -> GovernanceModeledEndToEndPipelineInput<'_> {
        GovernanceModeledEndToEndPipelineInput {
            policy,
            evaluator_authorization: evaluator,
            replay_observation: replay,
            modeled_input: self.modeled_input(modeled_policy, applier_kind),
        }
    }
}

/// A DevNet mutating-surface context for the given action.
fn devnet_ctx(action: ModeledTrustMutationAction) -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        action,
        ROOT,
    )
}

fn state_with_active_root() -> ModeledGovernanceTrustState {
    ModeledGovernanceTrustState::with_roots(vec![ModeledGovernanceTrustRoot::active(ROOT)])
}

/// The canonical "everything agrees" success input parameters.
fn happy_devnet(
    c: &Ctx,
) -> GovernanceModeledEndToEndPipelineInput<'_> {
    c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    )
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_pipeline_policy_preserves_legacy_bypass_no_mutation_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::disabled(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ProceedLegacyBypassNoMutation
    );
    assert!(decision.outcome.no_consume());
    assert!(!decision.authorizes_durable_consume());
    assert!(!decision.applier_invoked());
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty());
}

#[test]
fn disabled_evaluator_callsite_preserves_legacy_bypass_no_mutation_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::LegacyBypass,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ProceedLegacyBypassNoMutation
    );
    assert!(!decision.applier_invoked());
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty());
}

#[test]
fn devnet_fixture_add_root_success_authorizes_durable_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
    );
    assert!(decision.authorizes_durable_consume());
    assert!(decision.durable_consume_decision.authorized);
    assert!(decision.applier_invoked());
    assert_eq!(applier.attempts(), 1);
    assert!(state.contains_active(ROOT));
    // Mutation-engine stage projected the modeled success.
    assert_eq!(
        decision.mutation_engine.unwrap().outcome,
        GovernanceMutationOutcome::MutationAppliedSuccessfully
    );
}

#[test]
fn testnet_fixture_add_root_success_authorizes_durable_consume() {
    let c = ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureTestNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureTestNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Testnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
    );
    assert!(decision.authorizes_durable_consume());
    assert!(state.contains_active(ROOT));
}

#[test]
fn modeled_retire_root_success_authorizes_consume_only_after_success() {
    let c = devnet_ctx(ModeledTrustMutationAction::RetireTrustRoot);
    let input = happy_devnet(&c);
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
    );
    assert!(decision.authorizes_durable_consume());
}

#[test]
fn modeled_revoke_root_success_authorizes_consume_only_after_success() {
    let c = devnet_ctx(ModeledTrustMutationAction::RevokeTrustRoot);
    let input = happy_devnet(&c);
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(decision.authorizes_durable_consume());
}

#[test]
fn modeled_emergency_revoke_root_success_authorizes_consume_only_after_success() {
    let c = devnet_ctx(ModeledTrustMutationAction::EmergencyRevokeTrustRoot);
    let input = happy_devnet(&c);
    let mut state = state_with_active_root();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(decision.authorizes_durable_consume());
}

#[test]
fn modeled_noop_success_authorizes_consume_with_no_state_drift() {
    let c = devnet_ctx(ModeledTrustMutationAction::Noop);
    // Noop does not require a root id; clear it to make the binding well-formed.
    let mut c = c;
    c.mutation.root_id = String::new();
    let input = happy_devnet(&c);
    let mut state = state_with_active_root();
    let before = state.len();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
    );
    assert!(decision.authorizes_durable_consume());
    assert_eq!(state.len(), before, "noop produces no modeled state drift");
}

#[test]
fn production_pipeline_path_reachable_but_unavailable_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::Production,
        ModeledGovernanceTrustMutationApplierKind::ProductionUnavailable,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = ProductionModeledTrustMutationApplier::default();
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ProductionUnavailableNoConsume
    );
    assert!(decision.outcome.no_consume());
    assert!(!decision.applier_invoked());
}

#[test]
fn mainnet_pipeline_path_reachable_but_unavailable_no_consume() {
    // A mutating (non-peer-driven) MainNet surface reaches the applier-kind
    // routing and fails closed as unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::MainNet,
        ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = MainNetModeledTrustMutationApplier::default();
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::MainNetUnavailableNoConsume
    );
    assert!(decision.outcome.no_consume());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_replay_snapshot_and_applier() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    // Even with a fresh replay observation and a fixture applier, MainNet
    // peer-driven apply is refused first.
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume
    );
    assert!(decision.outcome.is_mainnet_peer_driven_apply_refused());
    assert!(!decision.applier_invoked());
    assert_eq!(applier.attempts(), 0, "no applier invocation, no snapshot");
    assert!(decision.mutation_engine.is_none(), "stopped before mutation engine");
    assert!(state.is_empty());
}

#[test]
fn validator_set_rotation_unsupported_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::ValidatorSetRotationUnsupported);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ValidatorSetRotationUnsupportedNoConsume
    );
    assert!(!decision.applier_invoked());
    assert_eq!(applier.attempts(), 0);
}

#[test]
fn policy_change_unsupported_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::PolicyChangeUnsupported);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::PolicyChangeUnsupportedNoConsume
    );
    assert!(!decision.applier_invoked());
}

// ===========================================================================
// Rejected / fail-closed matrix
// ===========================================================================

#[test]
fn evaluator_rejection_before_replay_no_mutation_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Rejected {
            reason: "evaluator rejected".to_string(),
        },
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay { .. }
    ));
    assert!(decision.outcome.no_consume());
    assert!(decision.mutation_engine.is_none());
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty());
}

/// Helper: drive a single binding-mismatch mutation that should reject at the
/// mutation-engine gate (before the applier) and assert non-mutating no-consume.
fn assert_mutation_engine_rejected(mut c: Ctx, mutate: impl FnOnce(&mut Ctx)) {
    mutate(&mut c);
    let input = happy_devnet(&c);
    let mut state = state_with_active_root();
    let before = state.len();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(
        matches!(
            decision.outcome,
            GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier { .. }
        ),
        "expected mutation-engine rejection, got {:?}",
        decision.outcome.tag()
    );
    assert!(decision.outcome.no_consume());
    assert!(!decision.applier_invoked());
    assert_eq!(applier.attempts(), 0, "no applier invocation, no snapshot");
    assert_eq!(state.len(), before, "binding rejection is non-mutating");
}

#[test]
fn wrong_environment_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.env.environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.env.chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.env.genesis_hash = "genesis-wrong".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.mutation.candidate_digest = "candidate-wrong".to_string();
    });
}

#[test]
fn wrong_decision_digest_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.mutation.decision_digest = "decision-wrong".to_string();
    });
}

#[test]
fn wrong_proposal_id_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.mutation.proposal_id = "proposal-wrong".to_string();
    });
}

#[test]
fn wrong_decision_id_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.mutation.decision_id = "decision-id-wrong".to_string();
    });
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.mutation.authority_domain_sequence = 99;
        c.runtime.authority_domain_sequence = 99;
    });
}

#[test]
fn wrong_lifecycle_action_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        c.mutation.lifecycle_action = LocalLifecycleAction::Retire;
    });
}

#[test]
fn malformed_modeled_mutation_rejected_before_snapshot_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    assert_mutation_engine_rejected(c, |c| {
        // AddTrustRoot requires a root id; empty it to malform the mutation.
        c.mutation.root_id = String::new();
    });
}

#[test]
fn read_only_validation_surface_rejected_before_snapshot_no_consume() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeSnapshot { .. }
    ));
    assert!(decision.outcome.no_consume());
    assert!(!decision.applier_invoked());
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty());
}

#[test]
fn stale_durable_replay_state_cannot_reach_mutation_or_consume() {
    assert_replay_rejection(
        DurableReplayObservation::StaleOrExpired,
        GovernanceModeledEndToEndPipelineOutcome::ReplayStaleOrExpiredNoConsume,
    );
}

#[test]
fn consumed_durable_replay_state_cannot_reach_mutation_or_consume() {
    assert_replay_rejection(
        DurableReplayObservation::Consumed,
        GovernanceModeledEndToEndPipelineOutcome::ReplayConsumedNoConsume,
    );
}

#[test]
fn superseded_durable_replay_state_cannot_reach_mutation_or_consume() {
    assert_replay_rejection(
        DurableReplayObservation::Superseded,
        GovernanceModeledEndToEndPipelineOutcome::ReplaySupersededNoConsume,
    );
}

#[test]
fn backend_unavailable_cannot_reach_mutation_or_consume() {
    assert_replay_rejection(
        DurableReplayObservation::BackendUnavailable,
        GovernanceModeledEndToEndPipelineOutcome::BackendUnavailableNoConsume,
    );
}

#[test]
fn deferred_or_read_only_replay_cannot_reach_mutation_or_consume() {
    assert_replay_rejection(
        DurableReplayObservation::DeferredOrReadOnly,
        GovernanceModeledEndToEndPipelineOutcome::DurableReplayRejectedBeforeMutation,
    );
}

/// Helper: a fresh evaluator authorization but a rejecting replay observation
/// must never reach the mutation engine, the applier, or a consume.
fn assert_replay_rejection(
    replay: DurableReplayObservation,
    expected: GovernanceModeledEndToEndPipelineOutcome,
) {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        replay,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(decision.outcome, expected);
    assert!(decision.outcome.no_consume());
    assert!(decision.mutation_engine.is_none(), "stopped before mutation engine");
    assert_eq!(applier.attempts(), 0);
    assert!(state.is_empty());
}

#[test]
fn consume_before_modeled_applier_success_is_rejected_apply_failed() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::ApplyFailedBeforeMutation,
    );
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierApplyFailedNoConsume
    );
    assert!(decision.outcome.no_consume());
    assert!(decision.applier_invoked());
    assert!(state.is_empty(), "apply-failed-before-mutation is non-mutating");
}

#[test]
fn consume_after_modeled_rollback_is_rejected() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::ApplyFailedRolledBack,
    );
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume
    );
    assert!(decision.outcome.no_consume());
    assert!(state.is_empty(), "rollback restores the snapshot");
}

#[test]
fn consume_after_rollback_failed_is_rejected_fatal() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::RollbackFailedFatal,
    );
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRollbackFailedFatalNoConsume
    );
    assert!(decision.outcome.no_consume());
}

#[test]
fn consume_after_ambiguous_window_is_rejected() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::AmbiguousAfterApply,
    );
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume
    );
    assert!(decision.outcome.no_consume());
}

#[test]
fn retiring_missing_root_rejects_before_apply_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::RetireTrustRoot);
    let input = happy_devnet(&c);
    // Empty modeled state — the target root is absent.
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply { .. }
    ));
    assert!(decision.outcome.no_consume());
    assert!(decision.applier_invoked(), "applier snapshotted before rejecting");
    assert!(state.is_empty(), "rejected-before-apply is non-mutating");
}

#[test]
fn revoking_missing_root_rejects_before_apply_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::RevokeTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(matches!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply { .. }
    ));
    assert!(decision.outcome.no_consume());
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

#[test]
fn recovery_after_report_success_authorizes_durable_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let outcome = recover_modeled_end_to_end_pipeline_window(
        &input,
        &ModeledTrustMutationOutcome::ModeledMutationApplied,
    );
    assert_eq!(
        outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
    );
}

#[test]
fn recovery_after_snapshot_before_apply_rolls_back_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let outcome = recover_modeled_end_to_end_pipeline_window(
        &input,
        &ModeledTrustMutationOutcome::ModeledMutationRolledBack,
    );
    assert_eq!(
        outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_ambiguous_window_fails_closed_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let outcome = recover_modeled_end_to_end_pipeline_window(
        &input,
        &ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed,
    );
    assert_eq!(
        outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_rollback_failed_window_is_fatal_no_consume() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let outcome = recover_modeled_end_to_end_pipeline_window(
        &input,
        &ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal,
    );
    assert_eq!(
        outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRollbackFailedFatalNoConsume
    );
}

#[test]
fn recovery_mainnet_peer_driven_apply_refusal_precedes_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input = happy_devnet(&c);
    // Even a recovered "applied" success is refused for a MainNet peer-driven
    // surface.
    let outcome = recover_modeled_end_to_end_pipeline_window(
        &input,
        &ModeledTrustMutationOutcome::ModeledMutationApplied,
    );
    assert_eq!(
        outcome,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_modeled_applier_applied_success_reaches_consume_authorized() {
    // A fresh evaluator + fresh durable replay + mutation-engine authorization
    // are all present, but the modeled apply fails: no consume.
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledApplierFault::ApplyFailedBeforeMutation,
    );
    let decision = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert!(!decision.authorizes_durable_consume());
    // The durable projection stage reflects the non-consuming completion.
    assert!(!decision
        .durable_projection
        .unwrap()
        .projection
        .authorizes_durable_consume());
}

#[test]
fn evaluator_success_alone_does_not_consume() {
    // Evaluator authorized, but durable replay only deferred: no consume.
    assert_replay_rejection(
        DurableReplayObservation::DeferredOrReadOnly,
        GovernanceModeledEndToEndPipelineOutcome::DurableReplayRejectedBeforeMutation,
    );
}

#[test]
fn executor_trait_matches_free_function() {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
    let exec = DefaultGovernanceModeledEndToEndPipelineExecutor;
    let decision = exec.run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
    assert_eq!(
        decision.outcome,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
    );
}

// ===========================================================================
// Invariant helpers
// ===========================================================================

#[test]
fn invariant_helpers_hold() {
    assert!(modeled_end_to_end_pipeline_rejection_is_non_mutating());
    assert!(modeled_end_to_end_pipeline_never_calls_run_070());
    assert!(modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state());
    assert!(modeled_end_to_end_pipeline_success_required_before_durable_consume());
    assert!(modeled_end_to_end_pipeline_applier_success_required_before_consume());
    assert!(modeled_end_to_end_pipeline_failed_apply_never_consumes());
    assert!(modeled_end_to_end_pipeline_rollback_never_consumes());
    assert!(modeled_end_to_end_pipeline_ambiguous_window_fails_closed());
    assert!(modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(modeled_end_to_end_pipeline_production_mainnet_unavailable());
    assert!(modeled_end_to_end_pipeline_validator_set_rotation_unsupported());
    assert!(modeled_end_to_end_pipeline_policy_change_unsupported());
    assert!(modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change());
    assert!(modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority());
    assert!(modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority());
}
