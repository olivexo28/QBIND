//! Run 252 — source/test governance **modeled durable-completion finalization
//! projection** tests.
//!
//! Source/test only. Run 252 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! durable-completion finalization projection
//! ([`evaluate_modeled_durable_completion_finalization_projection`]) records a
//! modeled in-memory finalization **only** when the Run 250 reporter recorded a
//! completion report, and that every other reporter outcome, every finalization
//! record failure, rollback, rollback-failure, ambiguous finalization window,
//! every production / MainNet unavailable / unsupported path, and every rejected
//! binding fails closed with no finalization.
//!
//! Every rejected path is non-mutating and non-finalizing: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no durable completion, and no finalizer
//! invocation where the rejection happens before the finalizer stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_252.md`.

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_completion_finalization_projection::{
    evaluate_modeled_durable_completion_finalization_projection,
    finalization_outcome_authorizes_modeled_durable_completion,
    finalization_outcome_projects_to_durable_completion,
    modeled_finalization_ambiguous_window_fails_closed,
    modeled_finalization_completion_report_required_before_finalization,
    modeled_finalization_failed_record_never_finalizes,
    modeled_finalization_local_operator_cannot_satisfy_mainnet_authority,
    modeled_finalization_mainnet_peer_driven_apply_refused_first,
    modeled_finalization_never_calls_run_070,
    modeled_finalization_never_mutates_live_pqc_trust_state,
    modeled_finalization_never_writes_sequence_or_marker,
    modeled_finalization_no_rocksdb_file_schema_migration_change,
    modeled_finalization_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_finalization_pipeline_success_required_before_finalization,
    modeled_finalization_policy_change_unsupported,
    modeled_finalization_production_mainnet_unavailable,
    modeled_finalization_record_required_before_durable_completion,
    modeled_finalization_rejection_is_non_mutating,
    modeled_finalization_rollback_never_finalizes,
    modeled_finalization_sink_receipt_required_before_finalization,
    modeled_finalization_validator_set_rotation_unsupported,
    project_completion_reporter_outcome_to_finalization_intent,
    recover_modeled_durable_completion_finalization_window,
    DurableCompletionFinalizationIntent, FixtureModeledDurableCompletionFinalizer,
    GovernanceModeledDurableCompletionFinalizationExpectations,
    GovernanceModeledDurableCompletionFinalizationInput,
    GovernanceModeledDurableCompletionFinalizationOutcome,
    GovernanceModeledDurableCompletionFinalizationPolicy,
    GovernanceModeledDurableCompletionFinalizationRecord,
    GovernanceModeledDurableCompletionFinalizer,
    MainNetModeledDurableCompletionFinalizer, ModeledDurableCompletionFinalizationFault,
    ModeledDurableCompletionFinalizationLedger, ModeledDurableCompletionFinalizationWindow,
    ModeledDurableCompletionFinalizerKind, ProductionModeledDurableCompletionFinalizer,
};
use qbind_node::pqc_governance_modeled_durable_consume_completion_reporter::GovernanceModeledDurableConsumeCompletionReporterOutcome;
use qbind_node::pqc_governance_modeled_durable_consume_projection_sink::GovernanceModeledDurableConsumeSinkOutcome;
use qbind_node::pqc_governance_modeled_end_to_end_pipeline::{
    DurableReplayObservation, GovernanceModeledEndToEndPipelineOutcome,
};
use qbind_node::pqc_governance_modeled_trust_mutation_applier::{
    ModeledGovernanceTrustMutationEnvironmentBinding, ModeledGovernanceTrustMutationRuntimeBinding,
    ModeledGovernanceTrustMutationSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants
// ===========================================================================

const FINALIZATION_ID: &str = "durable-completion-finalization-0001";
const FINALIZATION_DIGEST: &str = "finalization-digest-ffffffffffffffffffff";
const REPORT_DIGEST: &str = "completion-report-digest-cccccccccccccccc";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
const SINK_DIGEST: &str = "sink-decision-digest-ssssssssssssssssssss";
const REPORTER_DIGEST: &str = "reporter-decision-digest-eeeeeeeeeeeeeeee";
const PIPELINE_DIGEST: &str = "modeled-pipeline-decision-digest-pppppppp";
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
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    finalization: GovernanceModeledDurableCompletionFinalizationRecord,
    expectations: GovernanceModeledDurableCompletionFinalizationExpectations,
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
) -> Ctx {
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
    let finalization = GovernanceModeledDurableCompletionFinalizationRecord {
        finalization_id: FINALIZATION_ID.to_string(),
        finalization_digest: FINALIZATION_DIGEST.to_string(),
        report_digest: REPORT_DIGEST.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        sink_decision_digest: SINK_DIGEST.to_string(),
        reporter_decision_digest: REPORTER_DIGEST.to_string(),
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableCompletionFinalizationExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_finalization_digest: FINALIZATION_DIGEST.to_string(),
        expected_report_digest: REPORT_DIGEST.to_string(),
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_reporter_decision_digest: REPORTER_DIGEST.to_string(),
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        finalization,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        policy: GovernanceModeledDurableCompletionFinalizationPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
    ) -> GovernanceModeledDurableCompletionFinalizationInput {
        GovernanceModeledDurableCompletionFinalizationInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            finalization: self.finalization.clone(),
        }
    }

    /// The canonical "reporter recorded a completion report" wired input.
    fn recorded(&self) -> GovernanceModeledDurableCompletionFinalizationInput {
        self.input(
            GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        )
    }
}

/// A DevNet mutating-surface context.
fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}

fn devnet_finalizer() -> FixtureModeledDurableCompletionFinalizer {
    FixtureModeledDurableCompletionFinalizer::new(TrustBundleEnvironment::Devnet)
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_finalization_policy_preserves_legacy_bypass_no_finalization_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::finalization_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization
    );
    assert!(outcome.no_finalization());
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_reporter_policy_preserves_legacy_bypass_never_invokes_finalizer() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::reporter_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization
    );
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_sink_policy_preserves_legacy_bypass_never_invokes_finalizer() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::sink_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization
    );
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_pipeline_policy_preserves_legacy_bypass_never_invokes_finalizer() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::pipeline_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization
    );
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_evaluator_callsite_preserves_legacy_bypass_never_invokes_finalizer() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::evaluator_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization
    );
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn devnet_reporter_recorded_records_one_modeled_finalization() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
    assert!(outcome.authorizes_modeled_durable_completion());
    assert!(outcome.projects_to_durable_completion());
    assert_eq!(finalizer.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(FINALIZATION_ID));
}

#[test]
fn testnet_reporter_recorded_records_one_modeled_finalization() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer =
        FixtureModeledDurableCompletionFinalizer::new(TrustBundleEnvironment::Testnet);
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
    assert_eq!(
        finalizer.kind(),
        ModeledDurableCompletionFinalizerKind::FixtureTestNet
    );
    assert_eq!(ledger.len(), 1);
}

/// Helper: drive a recorded-report input whose modeled action is reflected by a
/// distinct candidate digest, and assert exactly one finalization is recorded only
/// after the reporter recorded a completion report.
fn assert_action_records_finalization(candidate_digest: &str) {
    let mut c = devnet_ctx();
    c.finalization.candidate_digest = candidate_digest.to_string();
    c.expectations.expected_candidate_digest = candidate_digest.to_string();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
    assert_eq!(finalizer.invocations(), 1);
    assert_eq!(ledger.len(), 1);
}

#[test]
fn modeled_add_root_records_finalization_only_after_completion_report_record() {
    assert_action_records_finalization("candidate-add-root-aaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn modeled_retire_root_records_finalization_only_after_completion_report_record() {
    assert_action_records_finalization("candidate-retire-root-bbbbbbbbbbbbbbbb");
}

#[test]
fn modeled_revoke_root_records_finalization_only_after_completion_report_record() {
    assert_action_records_finalization("candidate-revoke-root-cccccccccccccccc");
}

#[test]
fn modeled_emergency_revoke_root_records_finalization_only_after_completion_report_record() {
    assert_action_records_finalization("candidate-emergency-revoke-dddddddddddd");
}

#[test]
fn modeled_noop_records_finalization_only_under_explicit_success_and_recorded_report() {
    assert_action_records_finalization("candidate-noop-eeeeeeeeeeeeeeeeeeeeeeee");
}

#[test]
fn duplicate_identical_finalization_is_idempotent_no_second_finalization() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let first = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
    let second = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent
    );
    // Idempotent: no new finalization, but it still projects to durable completion.
    assert!(!second.authorizes_modeled_durable_completion());
    assert!(second.projects_to_durable_completion());
    assert_eq!(ledger.len(), 1, "no second finalization recorded");
}

#[test]
fn production_finalizer_reachable_but_unavailable_records_no_finalization() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = ProductionModeledDurableCompletionFinalizer::default();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ProductionFinalizerUnavailableNoFinalization
    );
    assert!(outcome.no_finalization());
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_finalizer_reachable_but_unavailable_records_no_finalization() {
    // A mutating (non-peer-driven) MainNet surface reaches the finalizer and fails
    // closed as unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = MainNetModeledDurableCompletionFinalizer::default();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetFinalizerUnavailableNoFinalization
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_pipeline_sink_reporter_and_finalizer() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    // Even with a reporter-recorded binding, MainNet peer-driven apply is refused
    // first.
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(finalizer.invocations(), 0, "no finalizer invocation");
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_unsupported_records_no_finalization() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ValidatorSetRotationUnsupportedNoCompletion,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ValidatorSetRotationUnsupportedNoFinalization
    );
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn policy_change_unsupported_records_no_finalization() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::PolicyChangeUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PolicyChangeUnsupportedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::PolicyChangeUnsupportedNoCompletion,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::PolicyChangeUnsupportedNoFinalization
    );
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — reporter outcomes never authorize a finalization
// ===========================================================================

/// Helper: a non-recording reporter outcome must never invoke the finalizer and
/// must record no finalization.
fn assert_reporter_no_finalization(
    reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
    expected: GovernanceModeledDurableCompletionFinalizationOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(outcome, expected, "reporter outcome projected wrong");
    assert!(outcome.no_finalization());
    assert_eq!(
        finalizer.invocations(),
        0,
        "no finalizer invocation before finalizer stage"
    );
    assert!(ledger.is_empty());
}

#[test]
fn reporter_legacy_bypass_maps_to_legacy_bypass_no_finalization() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport,
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization,
    );
}

#[test]
fn reporter_rejected_before_sink_maps_to_rejected_before_reporter() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::RejectedBeforeSinkNoCompletionReport,
        GovernanceModeledDurableCompletionFinalizationOutcome::RejectedBeforeReporterNoFinalization,
    );
}

#[test]
fn reporter_sink_did_not_record_maps_to_reporter_did_not_record() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
}

#[test]
fn reporter_rejected_before_record_maps_to_reporter_did_not_record() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
}

#[test]
fn reporter_record_failure_maps_to_reporter_did_not_record() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecordFailedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
}

#[test]
fn reporter_rollback_maps_to_reporter_did_not_record() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRolledBackNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
}

#[test]
fn reporter_rollback_failed_maps_to_reporter_did_not_record() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRollbackFailedFatalNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
}

#[test]
fn reporter_ambiguous_window_maps_to_reporter_did_not_record() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportAmbiguousFailClosedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
}

#[test]
fn reporter_production_unavailable_maps_to_production_finalizer_unavailable() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ProductionReporterUnavailableNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::ProductionFinalizerUnavailableNoFinalization,
    );
}

#[test]
fn reporter_mainnet_unavailable_maps_to_mainnet_finalizer_unavailable() {
    assert_reporter_no_finalization(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetReporterUnavailableNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetFinalizerUnavailableNoFinalization,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — pipeline-level rejections (reporter never recorded)
// ===========================================================================

/// Helper: a non-success pipeline outcome carries a non-recording sink + reporter
/// outcome and must never invoke the finalizer and record no finalization.
fn assert_pipeline_no_finalization(pipeline: GovernanceModeledEndToEndPipelineOutcome) {
    let c = devnet_ctx();
    // A non-success pipeline never reaches the reporter-recorded outcome.
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        pipeline,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
    assert!(outcome.no_finalization());
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn evaluator_rejection_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay {
            reason: "evaluator rejected".to_string(),
        },
    );
}

#[test]
fn callsite_rejection_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier {
            reason: "binding mismatch".to_string(),
        },
    );
}

#[test]
fn durable_replay_stale_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ReplayStaleOrExpiredNoConsume,
    );
}

#[test]
fn durable_replay_consumed_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ReplayConsumedNoConsume,
    );
}

#[test]
fn durable_replay_superseded_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ReplaySupersededNoConsume,
    );
}

#[test]
fn durable_replay_backend_unavailable_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::BackendUnavailableNoConsume,
    );
}

#[test]
fn mutation_engine_rejection_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeSnapshot {
            reason: "read-only validation surface".to_string(),
        },
    );
}

#[test]
fn modeled_applier_rejected_before_apply_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply {
            reason: "missing root".to_string(),
        },
    );
}

#[test]
fn modeled_apply_failure_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierApplyFailedNoConsume,
    );
}

#[test]
fn modeled_rollback_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume,
    );
}

#[test]
fn modeled_rollback_failed_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRollbackFailedFatalNoConsume,
    );
}

#[test]
fn modeled_ambiguous_window_produces_no_finalizer_intent_no_finalization() {
    assert_pipeline_no_finalization(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — sink-level rejections (reporter never recorded)
// ===========================================================================

/// Helper: a non-recording sink outcome carries the matching non-recording
/// reporter outcome and must never invoke the finalizer and record no finalization.
fn assert_sink_no_finalization(sink: GovernanceModeledDurableConsumeSinkOutcome) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
    assert!(outcome.no_finalization());
    assert_eq!(finalizer.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn sink_did_not_record_receipt_produces_no_finalization() {
    assert_sink_no_finalization(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord,
    );
}

#[test]
fn sink_record_failure_produces_no_finalization() {
    assert_sink_no_finalization(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume,
    );
}

#[test]
fn sink_rollback_produces_no_finalization() {
    assert_sink_no_finalization(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume,
    );
}

#[test]
fn sink_rollback_failed_produces_no_finalization() {
    assert_sink_no_finalization(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume,
    );
}

#[test]
fn sink_ambiguous_window_produces_no_finalization() {
    assert_sink_no_finalization(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — finalization record failures (finalizer IS invoked)
// ===========================================================================

/// Helper: drive a reporter-recorded input against a faulting fixture finalizer.
fn assert_record_fault(
    fault: ModeledDurableCompletionFinalizationFault,
    expected: GovernanceModeledDurableCompletionFinalizationOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = FixtureModeledDurableCompletionFinalizer::with_fault(
        TrustBundleEnvironment::Devnet,
        fault,
    );
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_finalization());
    assert_eq!(finalizer.invocations(), 1, "finalizer was invoked");
    assert!(ledger.is_empty(), "no finalization recorded on a fault");
}

#[test]
fn finalization_record_failure_does_not_finalize() {
    assert_record_fault(
        ModeledDurableCompletionFinalizationFault::RecordFailedNoFinalization,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRecordFailedNoFinalization,
    );
}

#[test]
fn finalization_rollback_success_does_not_finalize() {
    assert_record_fault(
        ModeledDurableCompletionFinalizationFault::RolledBackNoFinalization,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRolledBackNoFinalization,
    );
}

#[test]
fn finalization_rollback_failure_is_fatal_does_not_finalize() {
    assert_record_fault(
        ModeledDurableCompletionFinalizationFault::RollbackFailedFatal,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRollbackFailedFatalNoFinalization,
    );
}

#[test]
fn finalization_ambiguous_window_fails_closed_does_not_finalize() {
    assert_record_fault(
        ModeledDurableCompletionFinalizationFault::AmbiguousAfterRecord,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionAmbiguousFailClosedNoFinalization,
    );
}

#[test]
fn same_finalization_id_different_digest_is_equivocation_no_second_finalization() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let first = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );

    // Same finalization id, different finalization digest — equivocation.
    // Expectations must be updated to accept the new digest so the rejection is the
    // equivocation gate, not the identity gate.
    let mut c2 = devnet_ctx();
    c2.finalization.finalization_digest = "finalization-digest-DIFFERENT".to_string();
    c2.expectations.expected_finalization_digest = "finalization-digest-DIFFERENT".to_string();
    let input2 = c2.recorded();
    let second = evaluate_modeled_durable_completion_finalization_projection(
        &input2,
        &c2.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord
    );
    assert!(second.no_finalization());
    assert_eq!(ledger.len(), 1, "no second finalization recorded");
}

#[test]
fn duplicate_completion_report_without_prior_finalization_does_not_create_new() {
    // A CompletionReportDuplicateIdempotent reporter outcome may only match an
    // already-recorded finalization; with an empty ledger it must not create a new
    // finalization by itself.
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportDuplicateIdempotent,
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord
    );
    assert!(outcome.no_finalization());
    assert!(
        ledger.is_empty(),
        "no finalization created from a duplicate completion report"
    );
}

#[test]
fn duplicate_completion_report_with_matching_prior_finalization_is_idempotent() {
    let c = devnet_ctx();
    // First, record a finalization via a recorded completion report.
    let recorded = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let first = evaluate_modeled_durable_completion_finalization_projection(
        &recorded,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
    // Now a duplicate-idempotent completion report matches the existing
    // finalization.
    let dup = c.input(
        GovernanceModeledDurableCompletionFinalizationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportDuplicateIdempotent,
    );
    let second = evaluate_modeled_durable_completion_finalization_projection(
        &dup,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent
    );
    assert!(second.projects_to_durable_completion());
    assert_eq!(ledger.len(), 1, "no second finalization recorded");
}

// ===========================================================================
// Rejected before finalizer invocation — environment / surface binding
// ===========================================================================

/// Helper: a binding mismatch must reject before the finalizer is invoked.
fn assert_binding_rejected(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::RejectedBeforeReporterNoFinalization
    );
    assert!(outcome.no_finalization());
    assert_eq!(
        finalizer.invocations(),
        0,
        "no finalizer invocation before finalizer stage"
    );
    assert!(ledger.is_empty());
}

#[test]
fn wrong_environment_rejected_before_finalizer_invocation() {
    assert_binding_rejected(|c| {
        c.env.environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_finalizer_invocation() {
    assert_binding_rejected(|c| {
        c.env.chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_finalizer_invocation() {
    assert_binding_rejected(|c| {
        c.env.genesis_hash = "genesis-wrong".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_finalizer_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_finalizer_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
    });
}

// ===========================================================================
// Rejected before record — finalization identity (finalizer IS invoked)
// ===========================================================================

/// Helper: a finalization-identity mismatch must reject before record (finalizer
/// invoked).
fn assert_finalization_rejected_before_record(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord
    );
    assert!(outcome.no_finalization());
    assert_eq!(
        finalizer.invocations(),
        1,
        "finalizer invoked but rejected before record"
    );
    assert!(ledger.is_empty(), "no finalization recorded");
}

#[test]
fn wrong_finalization_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.finalization_digest = "finalization-digest-wrong".to_string();
    });
}

#[test]
fn wrong_completion_report_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.report_digest = "report-digest-wrong".to_string();
    });
}

#[test]
fn wrong_receipt_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.receipt_digest = "receipt-digest-wrong".to_string();
    });
}

#[test]
fn wrong_sink_decision_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.sink_decision_digest = "sink-digest-wrong".to_string();
    });
}

#[test]
fn wrong_reporter_decision_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.reporter_decision_digest = "reporter-digest-wrong".to_string();
    });
}

#[test]
fn wrong_pipeline_decision_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.pipeline_decision_digest = "pipeline-digest-wrong".to_string();
    });
}

#[test]
fn wrong_proposal_id_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.proposal_id = "proposal-wrong".to_string();
    });
}

#[test]
fn wrong_decision_id_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.decision_id = "decision-wrong".to_string();
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.candidate_digest = "candidate-wrong".to_string();
    });
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.authority_domain_sequence = 99;
    });
}

#[test]
fn malformed_finalization_rejected_before_record() {
    assert_finalization_rejected_before_record(|c| {
        c.finalization.finalization_id = String::new();
    });
}

// ===========================================================================
// MainNet authority cannot be satisfied locally
// ===========================================================================

#[test]
fn local_operator_key_cannot_satisfy_mainnet_authority() {
    assert!(modeled_finalization_local_operator_cannot_satisfy_mainnet_authority());
}

#[test]
fn peer_majority_cannot_satisfy_mainnet_authority() {
    assert!(modeled_finalization_peer_majority_cannot_satisfy_mainnet_authority());
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recover(
    window: ModeledDurableCompletionFinalizationWindow,
    finalization: Option<&GovernanceModeledDurableCompletionFinalizationRecord>,
) -> GovernanceModeledDurableCompletionFinalizationOutcome {
    let c = devnet_ctx();
    let input = c.recorded();
    recover_modeled_durable_completion_finalization_window(
        &input,
        window,
        ModeledDurableCompletionFinalizerKind::FixtureDevNet,
        finalization,
        &c.expectations,
    )
}

#[test]
fn recovery_before_pipeline_window_fails_closed_no_finalization() {
    let outcome = recover(ModeledDurableCompletionFinalizationWindow::BeforePipeline, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
    assert!(outcome.no_finalization());
}

#[test]
fn recovery_after_pipeline_success_before_sink_intent_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterPipelineSuccessBeforeSinkIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
}

#[test]
fn recovery_after_sink_intent_before_receipt_record_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterSinkIntentBeforeReceiptRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
}

#[test]
fn recovery_after_receipt_record_before_report_intent_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterReceiptRecordBeforeReportIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
}

#[test]
fn recovery_after_report_intent_before_report_record_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterReportIntentBeforeReportRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization
    );
}

#[test]
fn recovery_after_report_record_before_finalization_intent_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterReportRecordBeforeFinalizationIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_finalization_intent_before_finalization_record_fails_closed_no_durable_completion()
{
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationIntentBeforeFinalizationRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_finalization_record_before_success_without_finalization_fails_closed() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationRecordBeforeFinalizationSuccess,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_finalization_record_before_success_with_matching_finalization_recovers() {
    let c = devnet_ctx();
    let finalization = c.finalization.clone();
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationRecordBeforeFinalizationSuccess,
        Some(&finalization),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
    assert!(outcome.projects_to_durable_completion());
}

#[test]
fn recovery_after_finalization_success_recovers_durable_completion_finalized() {
    let c = devnet_ctx();
    let finalization = c.finalization.clone();
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationSuccess,
        Some(&finalization),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized
    );
}

#[test]
fn recovery_after_finalization_ambiguous_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationAmbiguous,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionAmbiguousFailClosedNoFinalization
    );
    assert!(outcome.no_finalization());
}

#[test]
fn recovery_finalization_record_failed_window_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::FinalizationRecordFailed,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRecordFailedNoFinalization
    );
}

#[test]
fn recovery_rollback_completed_window_fails_closed_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::RollbackCompleted,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRolledBackNoFinalization
    );
}

#[test]
fn recovery_rollback_failed_window_is_fatal_no_finalization() {
    let outcome = recover(
        ModeledDurableCompletionFinalizationWindow::RollbackFailed,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRollbackFailedFatalNoFinalization
    );
}

#[test]
fn recovery_unknown_window_fails_closed_no_finalization() {
    let outcome = recover(ModeledDurableCompletionFinalizationWindow::Unknown, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionAmbiguousFailClosedNoFinalization
    );
    assert!(outcome.no_finalization());
}

#[test]
fn recovery_production_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_modeled_durable_completion_finalization_window(
        &input,
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationSuccess,
        ModeledDurableCompletionFinalizerKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::ProductionFinalizerUnavailableNoFinalization
    );
}

#[test]
fn recovery_mainnet_classification_unavailable() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.recorded();
    let outcome = recover_modeled_durable_completion_finalization_window(
        &input,
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationSuccess,
        ModeledDurableCompletionFinalizerKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetFinalizerUnavailableNoFinalization
    );
}

#[test]
fn recovery_mainnet_peer_driven_apply_refusal_precedes_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input = c.recorded();
    let finalization = c.finalization.clone();
    let outcome = recover_modeled_durable_completion_finalization_window(
        &input,
        ModeledDurableCompletionFinalizationWindow::AfterFinalizationSuccess,
        ModeledDurableCompletionFinalizerKind::FixtureDevNet,
        Some(&finalization),
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_completion_report_recorded_creates_finalization_intent() {
    let intent = project_completion_reporter_outcome_to_finalization_intent(
        &GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
    );
    assert_eq!(intent, DurableCompletionFinalizationIntent::CreateIntent);
    assert!(intent.creates_intent());
}

#[test]
fn duplicate_idempotent_reporter_outcome_projects_to_idempotent_only() {
    let intent = project_completion_reporter_outcome_to_finalization_intent(
        &GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportDuplicateIdempotent,
    );
    assert_eq!(intent, DurableCompletionFinalizationIntent::IdempotentOnly);
    assert!(!intent.creates_intent());
}

#[test]
fn non_recording_reporter_outcomes_create_no_finalization_intent() {
    for reporter in [
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::RejectedBeforeSinkNoCompletionReport,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecordFailedNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRolledBackNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRollbackFailedFatalNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportAmbiguousFailClosedNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ProductionReporterUnavailableNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetReporterUnavailableNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ValidatorSetRotationUnsupportedNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::PolicyChangeUnsupportedNoCompletion,
    ] {
        let intent = project_completion_reporter_outcome_to_finalization_intent(&reporter);
        assert!(
            !intent.creates_intent(),
            "reporter outcome {} must not create a finalization intent",
            reporter.tag()
        );
    }
}

#[test]
fn only_durable_completion_finalized_authorizes_modeled_durable_completion() {
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    assert!(finalization_outcome_authorizes_modeled_durable_completion(
        &Final::DurableCompletionFinalized
    ));
    // Every other outcome does not authorize a new modeled durable completion.
    for outcome in [
        Final::LegacyBypassNoFinalization,
        Final::ReporterDidNotRecordCompletionNoFinalization,
        Final::RejectedBeforeReporterNoFinalization,
        Final::DurableCompletionDuplicateIdempotent,
        Final::DurableCompletionRejectedBeforeRecord,
        Final::DurableCompletionRecordFailedNoFinalization,
        Final::DurableCompletionRolledBackNoFinalization,
        Final::DurableCompletionRollbackFailedFatalNoFinalization,
        Final::DurableCompletionAmbiguousFailClosedNoFinalization,
        Final::ProductionFinalizerUnavailableNoFinalization,
        Final::MainNetFinalizerUnavailableNoFinalization,
        Final::MainNetPeerDrivenApplyRefusedNoFinalization,
        Final::ValidatorSetRotationUnsupportedNoFinalization,
        Final::PolicyChangeUnsupportedNoFinalization,
    ] {
        assert!(
            !finalization_outcome_authorizes_modeled_durable_completion(&outcome),
            "{} must not authorize a modeled durable completion",
            outcome.tag()
        );
    }
}

#[test]
fn no_finalization_outcomes_do_not_project_to_durable_completion() {
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    for outcome in [
        Final::LegacyBypassNoFinalization,
        Final::ReporterDidNotRecordCompletionNoFinalization,
        Final::RejectedBeforeReporterNoFinalization,
        Final::DurableCompletionRejectedBeforeRecord,
        Final::DurableCompletionRecordFailedNoFinalization,
        Final::DurableCompletionRolledBackNoFinalization,
        Final::DurableCompletionRollbackFailedFatalNoFinalization,
        Final::DurableCompletionAmbiguousFailClosedNoFinalization,
        Final::ProductionFinalizerUnavailableNoFinalization,
        Final::MainNetFinalizerUnavailableNoFinalization,
        Final::MainNetPeerDrivenApplyRefusedNoFinalization,
        Final::ValidatorSetRotationUnsupportedNoFinalization,
        Final::PolicyChangeUnsupportedNoFinalization,
    ] {
        assert!(
            !finalization_outcome_projects_to_durable_completion(&outcome),
            "{} must not project to durable completion",
            outcome.tag()
        );
        assert!(outcome.no_finalization());
    }
    // Finalized and idempotent-duplicate both project to durable completion.
    assert!(finalization_outcome_projects_to_durable_completion(
        &Final::DurableCompletionFinalized
    ));
    assert!(finalization_outcome_projects_to_durable_completion(
        &Final::DurableCompletionDuplicateIdempotent
    ));
}

// ===========================================================================
// Stage-ordering cases
// ===========================================================================

#[test]
fn rejection_before_finalizer_stage_leaves_invocation_count_zero() {
    // A binding mismatch (before the finalizer stage) leaves the finalizer
    // invocation count at zero.
    let mut c = devnet_ctx();
    c.env.environment = TrustBundleEnvironment::Testnet;
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let _ = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(finalizer.invocations(), 0);
}

#[test]
fn finalization_record_failure_does_not_invalidate_reporter_but_does_not_finalize() {
    // A finalization record failure leaves the reporter-recorded binding untouched
    // but does not authorize durable completion finality.
    let c = devnet_ctx();
    let input = c.recorded();
    assert_eq!(
        input.reporter_binding,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        "reporter still says recorded"
    );
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = FixtureModeledDurableCompletionFinalizer::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledDurableCompletionFinalizationFault::RecordFailedNoFinalization,
    );
    let outcome = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert!(outcome.no_finalization());
    assert!(ledger.is_empty());
}

#[test]
fn ledger_snapshot_restore_models_rollback_with_no_drift() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    // Record one finalization.
    let _ = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    let snap = ledger.snapshot();
    assert_eq!(snap.len(), 1);
    assert!(!snap.is_empty());
    // A rollback restores the snapshot exactly.
    let mut ledger2 = ModeledDurableCompletionFinalizationLedger::new();
    ledger2.restore(&snap);
    assert_eq!(ledger2.len(), 1);
    assert!(ledger2.contains(FINALIZATION_ID));
}

// ===========================================================================
// Finalization-ledger cases
// ===========================================================================

#[test]
fn one_valid_finalization_inserts_exactly_one_ledger_record() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableCompletionFinalizationLedger::new();
    let mut finalizer = devnet_finalizer();
    let _ = evaluate_modeled_durable_completion_finalization_projection(
        &input,
        &c.expectations,
        &mut finalizer,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.records().len(), 1);
    assert_eq!(ledger.records()[0].finalization_id, FINALIZATION_ID);
}

// ===========================================================================
// Invariant helpers
// ===========================================================================

#[test]
fn invariant_helpers_hold() {
    assert!(modeled_finalization_rejection_is_non_mutating());
    assert!(modeled_finalization_never_calls_run_070());
    assert!(modeled_finalization_never_mutates_live_pqc_trust_state());
    assert!(modeled_finalization_never_writes_sequence_or_marker());
    assert!(modeled_finalization_no_rocksdb_file_schema_migration_change());
    assert!(modeled_finalization_pipeline_success_required_before_finalization());
    assert!(modeled_finalization_sink_receipt_required_before_finalization());
    assert!(modeled_finalization_completion_report_required_before_finalization());
    assert!(modeled_finalization_record_required_before_durable_completion());
    assert!(modeled_finalization_failed_record_never_finalizes());
    assert!(modeled_finalization_rollback_never_finalizes());
    assert!(modeled_finalization_ambiguous_window_fails_closed());
    assert!(modeled_finalization_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!modeled_finalization_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(modeled_finalization_production_mainnet_unavailable());
    assert!(modeled_finalization_validator_set_rotation_unsupported());
    assert!(modeled_finalization_policy_change_unsupported());
    assert!(modeled_finalization_local_operator_cannot_satisfy_mainnet_authority());
    assert!(modeled_finalization_peer_majority_cannot_satisfy_mainnet_authority());
}