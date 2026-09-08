//! Run 250 — source/test governance **modeled durable-consume receipt-acknowledgement /
//! completion reporter** tests.
//!
//! Source/test only. Run 250 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! durable-consume completion reporter
//! ([`evaluate_modeled_durable_consume_completion_reporter`]) records a modeled
//! in-memory completion report **only** when the Run 248 sink recorded a consume
//! receipt, and that every other sink outcome, every report record failure,
//! rollback, rollback-failure, ambiguous acknowledgement window, every production
//! / MainNet unavailable / unsupported path, and every rejected binding fails
//! closed with no acknowledgement and no completion.
//!
//! Every rejected path is non-mutating and non-completing: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no durable consume, and no reporter invocation
//! where the rejection happens before the reporter stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_250.md`.

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_consume_completion_reporter::{
    completion_reporter_outcome_authorizes_modeled_completion,
    completion_reporter_outcome_projects_to_durable_completion,
    evaluate_modeled_durable_consume_completion_reporter,
    modeled_completion_reporter_ambiguous_window_fails_closed,
    modeled_completion_reporter_failed_record_never_completes,
    modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority,
    modeled_completion_reporter_mainnet_peer_driven_apply_refused_first,
    modeled_completion_reporter_never_calls_run_070,
    modeled_completion_reporter_never_mutates_live_pqc_trust_state,
    modeled_completion_reporter_never_writes_sequence_or_marker,
    modeled_completion_reporter_no_rocksdb_file_schema_migration_change,
    modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_completion_reporter_pipeline_success_required_before_report,
    modeled_completion_reporter_policy_change_unsupported,
    modeled_completion_reporter_production_mainnet_unavailable,
    modeled_completion_reporter_rejection_is_non_mutating,
    modeled_completion_reporter_report_record_required_before_completion,
    modeled_completion_reporter_rollback_never_completes,
    modeled_completion_reporter_sink_receipt_required_before_report,
    modeled_completion_reporter_validator_set_rotation_unsupported,
    project_sink_outcome_to_completion_report_intent,
    recover_modeled_durable_consume_completion_reporter_window, CompletionReportIntent,
    FixtureModeledDurableConsumeCompletionReporter, GovernanceModeledDurableConsumeCompletionReport,
    GovernanceModeledDurableConsumeCompletionReporter,
    GovernanceModeledDurableConsumeCompletionReporterExpectations,
    GovernanceModeledDurableConsumeCompletionReporterInput,
    GovernanceModeledDurableConsumeCompletionReporterOutcome,
    GovernanceModeledDurableConsumeCompletionReporterPolicy,
    MainNetModeledDurableConsumeCompletionReporter, ModeledCompletionReportFault,
    ModeledDurableConsumeCompletionReportLedger, ModeledDurableConsumeCompletionReporterKind,
    ModeledDurableConsumeCompletionReportWindow,
    ProductionModeledDurableConsumeCompletionReporter,
};
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

const REPORT_ID: &str = "completion-report-0001";
const REPORT_DIGEST: &str = "completion-report-digest-cccccccccccccccc";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
const SINK_DIGEST: &str = "sink-decision-digest-ssssssssssssssssssss";
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
    report: GovernanceModeledDurableConsumeCompletionReport,
    expectations: GovernanceModeledDurableConsumeCompletionReporterExpectations,
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
    let report = GovernanceModeledDurableConsumeCompletionReport {
        report_id: REPORT_ID.to_string(),
        report_digest: REPORT_DIGEST.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        sink_decision_digest: SINK_DIGEST.to_string(),
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableConsumeCompletionReporterExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_report_digest: REPORT_DIGEST.to_string(),
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        report,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        policy: GovernanceModeledDurableConsumeCompletionReporterPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
    ) -> GovernanceModeledDurableConsumeCompletionReporterInput {
        GovernanceModeledDurableConsumeCompletionReporterInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            report: self.report.clone(),
        }
    }

    /// The canonical "sink recorded a receipt" wired input.
    fn recorded(&self) -> GovernanceModeledDurableConsumeCompletionReporterInput {
        self.input(
            GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
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

fn devnet_reporter() -> FixtureModeledDurableConsumeCompletionReporter {
    FixtureModeledDurableConsumeCompletionReporter::new(TrustBundleEnvironment::Devnet)
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_reporter_policy_preserves_legacy_bypass_no_completion_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::reporter_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport
    );
    assert!(outcome.no_completion());
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_sink_policy_preserves_legacy_bypass_never_invokes_reporter() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::sink_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport
    );
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_pipeline_policy_preserves_legacy_bypass_never_invokes_reporter() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::pipeline_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport
    );
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_evaluator_callsite_preserves_legacy_bypass_never_invokes_reporter() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::evaluator_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport
    );
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn devnet_sink_receipt_recorded_records_one_modeled_completion_report() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
    assert!(outcome.authorizes_modeled_completion());
    assert!(outcome.projects_to_durable_completion());
    assert_eq!(reporter.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(REPORT_ID));
}

#[test]
fn testnet_sink_receipt_recorded_records_one_modeled_completion_report() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter =
        FixtureModeledDurableConsumeCompletionReporter::new(TrustBundleEnvironment::Testnet);
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
    assert_eq!(
        reporter.kind(),
        ModeledDurableConsumeCompletionReporterKind::FixtureTestNet
    );
    assert_eq!(ledger.len(), 1);
}

/// Helper: drive a recorded-receipt input whose modeled action is reflected by a
/// distinct candidate digest, and assert exactly one completion report is
/// recorded only after sink receipt record.
fn assert_action_records_completion(candidate_digest: &str) {
    let mut c = devnet_ctx();
    c.report.candidate_digest = candidate_digest.to_string();
    c.expectations.expected_candidate_digest = candidate_digest.to_string();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
    assert_eq!(reporter.invocations(), 1);
    assert_eq!(ledger.len(), 1);
}

#[test]
fn modeled_add_root_records_completion_only_after_sink_receipt_record() {
    assert_action_records_completion("candidate-add-root-aaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn modeled_retire_root_records_completion_only_after_sink_receipt_record() {
    assert_action_records_completion("candidate-retire-root-bbbbbbbbbbbbbbbb");
}

#[test]
fn modeled_revoke_root_records_completion_only_after_sink_receipt_record() {
    assert_action_records_completion("candidate-revoke-root-cccccccccccccccc");
}

#[test]
fn modeled_emergency_revoke_root_records_completion_only_after_sink_receipt_record() {
    assert_action_records_completion("candidate-emergency-revoke-dddddddddddd");
}

#[test]
fn modeled_noop_records_completion_only_under_explicit_success_and_recorded_receipt() {
    assert_action_records_completion("candidate-noop-eeeeeeeeeeeeeeeeeeeeeeee");
}

#[test]
fn duplicate_identical_completion_report_is_idempotent_no_second_report() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let first = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
    let second = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportDuplicateIdempotent
    );
    // Idempotent: no new report, but it still projects to durable completion.
    assert!(!second.authorizes_modeled_completion());
    assert!(second.projects_to_durable_completion());
    assert_eq!(ledger.len(), 1, "no second completion report recorded");
}

#[test]
fn production_reporter_reachable_but_unavailable_records_no_completion() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = ProductionModeledDurableConsumeCompletionReporter::default();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ProductionReporterUnavailableNoCompletion
    );
    assert!(outcome.no_completion());
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_reporter_reachable_but_unavailable_records_no_completion() {
    // A mutating (non-peer-driven) MainNet surface reaches the reporter and fails
    // closed as unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = MainNetModeledDurableConsumeCompletionReporter::default();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetReporterUnavailableNoCompletion
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_pipeline_sink_and_reporter() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    // Even with a sink-recorded binding, MainNet peer-driven apply is refused
    // first.
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(reporter.invocations(), 0, "no reporter invocation");
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_unsupported_records_no_completion() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ValidatorSetRotationUnsupportedNoConsume,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ValidatorSetRotationUnsupportedNoCompletion
    );
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn policy_change_unsupported_records_no_completion() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::PolicyChangeUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PolicyChangeUnsupportedNoConsume,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::PolicyChangeUnsupportedNoCompletion
    );
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — sink outcomes never authorize a report
// ===========================================================================

/// Helper: a non-recording sink outcome must never invoke the reporter and must
/// record no completion report.
fn assert_sink_no_completion(
    sink: GovernanceModeledDurableConsumeSinkOutcome,
    expected: GovernanceModeledDurableConsumeCompletionReporterOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(outcome, expected, "sink outcome projected wrong");
    assert!(outcome.no_completion());
    assert_eq!(
        reporter.invocations(),
        0,
        "no reporter invocation before reporter stage"
    );
    assert!(ledger.is_empty());
}

#[test]
fn sink_legacy_bypass_maps_to_legacy_bypass_no_completion() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::LegacyBypassNoCompletionReport,
    );
}

#[test]
fn sink_rejected_before_pipeline_maps_to_rejected_before_sink() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::RejectedBeforePipelineNoReceipt,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::RejectedBeforeSinkNoCompletionReport,
    );
}

#[test]
fn sink_pipeline_did_not_authorize_maps_to_sink_did_not_record() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
}

#[test]
fn sink_rejected_before_record_maps_to_sink_did_not_record() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
}

#[test]
fn sink_record_failure_maps_to_sink_did_not_record() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
}

#[test]
fn sink_rollback_maps_to_sink_did_not_record() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
}

#[test]
fn sink_rollback_failed_maps_to_sink_did_not_record() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
}

#[test]
fn sink_ambiguous_window_maps_to_sink_did_not_record() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
    );
}

#[test]
fn sink_production_unavailable_maps_to_production_reporter_unavailable() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::ProductionSinkUnavailableNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ProductionReporterUnavailableNoCompletion,
    );
}

#[test]
fn sink_mainnet_unavailable_maps_to_mainnet_reporter_unavailable() {
    assert_sink_no_completion(
        GovernanceModeledDurableConsumeSinkOutcome::MainNetSinkUnavailableNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetReporterUnavailableNoCompletion,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — pipeline-level rejections (sink never recorded)
// ===========================================================================

/// Helper: a non-success pipeline outcome carries a non-recording sink outcome and
/// must never invoke the reporter and record no completion report.
fn assert_pipeline_no_completion(pipeline: GovernanceModeledEndToEndPipelineOutcome) {
    let c = devnet_ctx();
    // A non-success pipeline never reaches the sink-recorded outcome.
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        pipeline,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport
    );
    assert!(outcome.no_completion());
    assert_eq!(reporter.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn evaluator_rejection_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay {
            reason: "evaluator rejected".to_string(),
        },
    );
}

#[test]
fn callsite_rejection_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier {
            reason: "binding mismatch".to_string(),
        },
    );
}

#[test]
fn durable_replay_stale_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ReplayStaleOrExpiredNoConsume,
    );
}

#[test]
fn durable_replay_consumed_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ReplayConsumedNoConsume,
    );
}

#[test]
fn durable_replay_superseded_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ReplaySupersededNoConsume,
    );
}

#[test]
fn durable_replay_backend_unavailable_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::BackendUnavailableNoConsume,
    );
}

#[test]
fn mutation_engine_rejection_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeSnapshot {
            reason: "read-only validation surface".to_string(),
        },
    );
}

#[test]
fn modeled_applier_rejected_before_apply_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply {
            reason: "missing root".to_string(),
        },
    );
}

#[test]
fn modeled_apply_failure_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierApplyFailedNoConsume,
    );
}

#[test]
fn modeled_rollback_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume,
    );
}

#[test]
fn modeled_rollback_failed_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRollbackFailedFatalNoConsume,
    );
}

#[test]
fn modeled_ambiguous_window_produces_no_reporter_intent_no_completion() {
    assert_pipeline_no_completion(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — report record failures (reporter IS invoked)
// ===========================================================================

/// Helper: drive a sink-recorded input against a faulting fixture reporter.
fn assert_record_fault(
    fault: ModeledCompletionReportFault,
    expected: GovernanceModeledDurableConsumeCompletionReporterOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = FixtureModeledDurableConsumeCompletionReporter::with_fault(
        TrustBundleEnvironment::Devnet,
        fault,
    );
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_completion());
    assert_eq!(reporter.invocations(), 1, "reporter was invoked");
    assert!(ledger.is_empty(), "no completion report recorded on a fault");
}

#[test]
fn report_record_failure_does_not_complete() {
    assert_record_fault(
        ModeledCompletionReportFault::RecordFailedNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecordFailedNoCompletion,
    );
}

#[test]
fn report_rollback_success_does_not_complete() {
    assert_record_fault(
        ModeledCompletionReportFault::RolledBackNoCompletion,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRolledBackNoCompletion,
    );
}

#[test]
fn report_rollback_failure_is_fatal_does_not_complete() {
    assert_record_fault(
        ModeledCompletionReportFault::RollbackFailedFatal,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRollbackFailedFatalNoCompletion,
    );
}

#[test]
fn report_ambiguous_window_fails_closed_does_not_complete() {
    assert_record_fault(
        ModeledCompletionReportFault::AmbiguousAfterRecord,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportAmbiguousFailClosedNoCompletion,
    );
}

#[test]
fn same_report_id_different_digest_is_equivocation_no_second_report() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let first = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );

    // Same report id, different report digest — equivocation. Expectations must be
    // updated to accept the new digest so the rejection is the equivocation gate,
    // not the identity gate.
    let mut c2 = devnet_ctx();
    c2.report.report_digest = "completion-report-digest-DIFFERENT".to_string();
    c2.expectations.expected_report_digest = "completion-report-digest-DIFFERENT".to_string();
    let input2 = c2.recorded();
    let second = evaluate_modeled_durable_consume_completion_reporter(
        &input2,
        &c2.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord
    );
    assert!(second.no_completion());
    assert_eq!(ledger.len(), 1, "no second completion report recorded");
}

#[test]
fn duplicate_sink_receipt_without_prior_report_does_not_create_new_completion() {
    // A ConsumeReceiptDuplicateIdempotent sink outcome may only match an
    // already-recorded completion report; with an empty ledger it must not create
    // a new completion report by itself.
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent,
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord
    );
    assert!(outcome.no_completion());
    assert!(ledger.is_empty(), "no completion report created from a duplicate");
}

#[test]
fn duplicate_sink_receipt_with_matching_prior_report_is_idempotent() {
    let c = devnet_ctx();
    // First, record a completion report via a recorded sink receipt.
    let recorded = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let first = evaluate_modeled_durable_consume_completion_reporter(
        &recorded,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
    // Now a duplicate-idempotent sink receipt matches the existing report.
    let dup = c.input(
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent,
    );
    let second = evaluate_modeled_durable_consume_completion_reporter(
        &dup,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportDuplicateIdempotent
    );
    assert!(second.projects_to_durable_completion());
    assert_eq!(ledger.len(), 1, "no second completion report recorded");
}

// ===========================================================================
// Rejected before reporter invocation — environment / surface binding
// ===========================================================================

/// Helper: a binding mismatch must reject before the reporter is invoked.
fn assert_binding_rejected(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::RejectedBeforeSinkNoCompletionReport
    );
    assert!(outcome.no_completion());
    assert_eq!(
        reporter.invocations(),
        0,
        "no reporter invocation before reporter stage"
    );
    assert!(ledger.is_empty());
}

#[test]
fn wrong_environment_rejected_before_reporter_invocation() {
    assert_binding_rejected(|c| {
        c.env.environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_reporter_invocation() {
    assert_binding_rejected(|c| {
        c.env.chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_reporter_invocation() {
    assert_binding_rejected(|c| {
        c.env.genesis_hash = "genesis-wrong".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_reporter_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_reporter_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
    });
}

// ===========================================================================
// Rejected before record — report identity (reporter IS invoked)
// ===========================================================================

/// Helper: a report-identity mismatch must reject before record (reporter
/// invoked).
fn assert_report_rejected_before_record(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord
    );
    assert!(outcome.no_completion());
    assert_eq!(
        reporter.invocations(),
        1,
        "reporter invoked but rejected before record"
    );
    assert!(ledger.is_empty(), "no completion report recorded");
}

#[test]
fn wrong_report_digest_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.report_digest = "report-digest-wrong".to_string();
    });
}

#[test]
fn wrong_receipt_digest_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.receipt_digest = "receipt-digest-wrong".to_string();
    });
}

#[test]
fn wrong_sink_decision_digest_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.sink_decision_digest = "sink-digest-wrong".to_string();
    });
}

#[test]
fn wrong_pipeline_decision_digest_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.pipeline_decision_digest = "pipeline-digest-wrong".to_string();
    });
}

#[test]
fn wrong_proposal_id_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.proposal_id = "proposal-wrong".to_string();
    });
}

#[test]
fn wrong_decision_id_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.decision_id = "decision-wrong".to_string();
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.candidate_digest = "candidate-wrong".to_string();
    });
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.authority_domain_sequence = 99;
    });
}

#[test]
fn malformed_completion_report_rejected_before_record() {
    assert_report_rejected_before_record(|c| {
        c.report.report_id = String::new();
    });
}

// ===========================================================================
// MainNet authority cannot be satisfied locally
// ===========================================================================

#[test]
fn local_operator_key_cannot_satisfy_mainnet_authority() {
    assert!(modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority());
}

#[test]
fn peer_majority_cannot_satisfy_mainnet_authority() {
    assert!(modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority());
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recover(
    window: ModeledDurableConsumeCompletionReportWindow,
    report: Option<&GovernanceModeledDurableConsumeCompletionReport>,
) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
    let c = devnet_ctx();
    let input = c.recorded();
    recover_modeled_durable_consume_completion_reporter_window(
        &input,
        window,
        ModeledDurableConsumeCompletionReporterKind::FixtureDevNet,
        report,
        &c.expectations,
    )
}

#[test]
fn recovery_before_pipeline_window_fails_closed_no_report() {
    let outcome = recover(ModeledDurableConsumeCompletionReportWindow::BeforePipeline, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport
    );
    assert!(outcome.no_completion());
}

#[test]
fn recovery_after_pipeline_success_before_sink_intent_fails_closed_no_report() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterPipelineSuccessBeforeSinkIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport
    );
}

#[test]
fn recovery_after_sink_intent_before_receipt_record_fails_closed_no_report() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterSinkIntentBeforeReceiptRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport
    );
}

#[test]
fn recovery_after_receipt_record_before_report_intent_fails_closed_no_report() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterReceiptRecordBeforeReportIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_report_intent_before_report_record_fails_closed_no_completion() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterReportIntentBeforeReportRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_report_record_before_success_without_report_fails_closed() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterReportRecordBeforeReportSuccess,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_report_record_before_success_with_matching_report_recovers() {
    let c = devnet_ctx();
    let report = c.report.clone();
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterReportRecordBeforeReportSuccess,
        Some(&report),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
    assert!(outcome.projects_to_durable_completion());
}

#[test]
fn recovery_after_report_success_recovers_completion_reported() {
    let c = devnet_ctx();
    let report = c.report.clone();
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterReportSuccess,
        Some(&report),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded
    );
}

#[test]
fn recovery_after_report_ambiguous_fails_closed_no_completion() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::AfterReportAmbiguous,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportAmbiguousFailClosedNoCompletion
    );
    assert!(outcome.no_completion());
}

#[test]
fn recovery_report_record_failed_window_fails_closed_no_completion() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::ReportRecordFailed,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecordFailedNoCompletion
    );
}

#[test]
fn recovery_rollback_completed_window_fails_closed_no_completion() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::RollbackCompleted,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRolledBackNoCompletion
    );
}

#[test]
fn recovery_rollback_failed_window_is_fatal_no_completion() {
    let outcome = recover(
        ModeledDurableConsumeCompletionReportWindow::RollbackFailed,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRollbackFailedFatalNoCompletion
    );
}

#[test]
fn recovery_unknown_window_fails_closed_no_completion() {
    let outcome = recover(ModeledDurableConsumeCompletionReportWindow::Unknown, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportAmbiguousFailClosedNoCompletion
    );
    assert!(outcome.no_completion());
}

#[test]
fn recovery_production_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_modeled_durable_consume_completion_reporter_window(
        &input,
        ModeledDurableConsumeCompletionReportWindow::AfterReportSuccess,
        ModeledDurableConsumeCompletionReporterKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ProductionReporterUnavailableNoCompletion
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
    let outcome = recover_modeled_durable_consume_completion_reporter_window(
        &input,
        ModeledDurableConsumeCompletionReportWindow::AfterReportSuccess,
        ModeledDurableConsumeCompletionReporterKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetReporterUnavailableNoCompletion
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
    let report = c.report.clone();
    let outcome = recover_modeled_durable_consume_completion_reporter_window(
        &input,
        ModeledDurableConsumeCompletionReportWindow::AfterReportSuccess,
        ModeledDurableConsumeCompletionReporterKind::FixtureDevNet,
        Some(&report),
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_sink_receipt_recorded_creates_completion_report_intent() {
    let intent = project_sink_outcome_to_completion_report_intent(
        &GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
    );
    assert_eq!(intent, CompletionReportIntent::CreateIntent);
    assert!(intent.creates_intent());
}

#[test]
fn duplicate_idempotent_sink_outcome_projects_to_idempotent_only() {
    let intent = project_sink_outcome_to_completion_report_intent(
        &GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent,
    );
    assert_eq!(intent, CompletionReportIntent::IdempotentOnly);
    assert!(!intent.creates_intent());
}

#[test]
fn non_recording_sink_outcomes_create_no_completion_report_intent() {
    for sink in [
        GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt,
        GovernanceModeledDurableConsumeSinkOutcome::RejectedBeforePipelineNoReceipt,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ProductionSinkUnavailableNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetSinkUnavailableNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PolicyChangeUnsupportedNoConsume,
    ] {
        let intent = project_sink_outcome_to_completion_report_intent(&sink);
        assert!(
            !intent.creates_intent(),
            "sink outcome {} must not create a completion-report intent",
            sink.tag()
        );
    }
}

#[test]
fn only_completion_report_recorded_authorizes_modeled_completion() {
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    assert!(completion_reporter_outcome_authorizes_modeled_completion(
        &Report::CompletionReportRecorded
    ));
    // Every other outcome does not authorize a new modeled completion.
    for outcome in [
        Report::LegacyBypassNoCompletionReport,
        Report::RejectedBeforeSinkNoCompletionReport,
        Report::SinkDidNotRecordReceiptNoCompletionReport,
        Report::CompletionReportDuplicateIdempotent,
        Report::CompletionReportRejectedBeforeRecord,
        Report::CompletionReportRecordFailedNoCompletion,
        Report::CompletionReportRolledBackNoCompletion,
        Report::CompletionReportRollbackFailedFatalNoCompletion,
        Report::CompletionReportAmbiguousFailClosedNoCompletion,
        Report::ProductionReporterUnavailableNoCompletion,
        Report::MainNetReporterUnavailableNoCompletion,
        Report::MainNetPeerDrivenApplyRefusedNoCompletion,
        Report::ValidatorSetRotationUnsupportedNoCompletion,
        Report::PolicyChangeUnsupportedNoCompletion,
    ] {
        assert!(
            !completion_reporter_outcome_authorizes_modeled_completion(&outcome),
            "{} must not authorize a modeled completion",
            outcome.tag()
        );
    }
}

#[test]
fn no_completion_outcomes_do_not_project_to_durable_completion() {
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    for outcome in [
        Report::LegacyBypassNoCompletionReport,
        Report::RejectedBeforeSinkNoCompletionReport,
        Report::SinkDidNotRecordReceiptNoCompletionReport,
        Report::CompletionReportRejectedBeforeRecord,
        Report::CompletionReportRecordFailedNoCompletion,
        Report::CompletionReportRolledBackNoCompletion,
        Report::CompletionReportRollbackFailedFatalNoCompletion,
        Report::CompletionReportAmbiguousFailClosedNoCompletion,
        Report::ProductionReporterUnavailableNoCompletion,
        Report::MainNetReporterUnavailableNoCompletion,
        Report::MainNetPeerDrivenApplyRefusedNoCompletion,
        Report::ValidatorSetRotationUnsupportedNoCompletion,
        Report::PolicyChangeUnsupportedNoCompletion,
    ] {
        assert!(
            !completion_reporter_outcome_projects_to_durable_completion(&outcome),
            "{} must not project to durable completion",
            outcome.tag()
        );
        assert!(outcome.no_completion());
    }
    // Recorded and idempotent-duplicate both project to durable completion.
    assert!(completion_reporter_outcome_projects_to_durable_completion(
        &Report::CompletionReportRecorded
    ));
    assert!(completion_reporter_outcome_projects_to_durable_completion(
        &Report::CompletionReportDuplicateIdempotent
    ));
}

// ===========================================================================
// Stage-ordering cases
// ===========================================================================

#[test]
fn rejection_before_reporter_stage_leaves_invocation_count_zero() {
    // A binding mismatch (before the reporter stage) leaves the reporter
    // invocation count at zero.
    let mut c = devnet_ctx();
    c.env.environment = TrustBundleEnvironment::Testnet;
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let _ = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(reporter.invocations(), 0);
}

#[test]
fn report_record_failure_does_not_invalidate_sink_but_does_not_complete() {
    // A report record failure leaves the sink-recorded binding untouched but does
    // not authorize completion.
    let c = devnet_ctx();
    let input = c.recorded();
    assert_eq!(
        input.sink_binding,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        "sink still says recorded"
    );
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = FixtureModeledDurableConsumeCompletionReporter::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledCompletionReportFault::RecordFailedNoCompletion,
    );
    let outcome = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert!(outcome.no_completion());
    assert!(ledger.is_empty());
}

#[test]
fn ledger_snapshot_restore_models_rollback_with_no_drift() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    // Record one completion report.
    let _ = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    let snap = ledger.snapshot();
    assert_eq!(snap.len(), 1);
    assert!(!snap.is_empty());
    // A rollback restores the snapshot exactly.
    let mut ledger2 = ModeledDurableConsumeCompletionReportLedger::new();
    ledger2.restore(&snap);
    assert_eq!(ledger2.len(), 1);
    assert!(ledger2.contains(REPORT_ID));
}

// ===========================================================================
// Completion-report ledger cases
// ===========================================================================

#[test]
fn one_valid_completion_report_inserts_exactly_one_ledger_record() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let _ = evaluate_modeled_durable_consume_completion_reporter(
        &input,
        &c.expectations,
        &mut reporter,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.records().len(), 1);
    assert_eq!(ledger.records()[0].report_id, REPORT_ID);
}

// ===========================================================================
// Invariant helpers
// ===========================================================================

#[test]
fn invariant_helpers_hold() {
    assert!(modeled_completion_reporter_rejection_is_non_mutating());
    assert!(modeled_completion_reporter_never_calls_run_070());
    assert!(modeled_completion_reporter_never_mutates_live_pqc_trust_state());
    assert!(modeled_completion_reporter_never_writes_sequence_or_marker());
    assert!(modeled_completion_reporter_no_rocksdb_file_schema_migration_change());
    assert!(modeled_completion_reporter_pipeline_success_required_before_report());
    assert!(modeled_completion_reporter_sink_receipt_required_before_report());
    assert!(modeled_completion_reporter_report_record_required_before_completion());
    assert!(modeled_completion_reporter_failed_record_never_completes());
    assert!(modeled_completion_reporter_rollback_never_completes());
    assert!(modeled_completion_reporter_ambiguous_window_fails_closed());
    assert!(modeled_completion_reporter_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!modeled_completion_reporter_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(modeled_completion_reporter_production_mainnet_unavailable());
    assert!(modeled_completion_reporter_validator_set_rotation_unsupported());
    assert!(modeled_completion_reporter_policy_change_unsupported());
    assert!(modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority());
    assert!(modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority());
}