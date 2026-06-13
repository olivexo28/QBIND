//! Run 248 — source/test governance **modeled durable-consume projection sink**
//! tests.
//!
//! Source/test only. Run 248 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! durable-consume projection sink
//! ([`evaluate_modeled_durable_consume_projection_sink`]) records a modeled
//! in-memory consume receipt **only** when the Run 246 pipeline authorized
//! consume, and that every other pipeline outcome, every sink record failure,
//! rollback, rollback-failure, ambiguous receipt window, every production /
//! MainNet unavailable / unsupported path, and every rejected binding fails
//! closed with no receipt and no consume.
//!
//! Every rejected path is non-mutating and non-consuming: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no durable consume, and no sink invocation
//! where the rejection happens before the sink stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_248.md`.

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_consume_projection_sink::{
    evaluate_modeled_durable_consume_projection_sink,
    modeled_consume_sink_ambiguous_window_fails_closed,
    modeled_consume_sink_failed_record_never_consumes,
    modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority,
    modeled_consume_sink_mainnet_peer_driven_apply_refused_first,
    modeled_consume_sink_never_calls_run_070,
    modeled_consume_sink_never_mutates_live_pqc_trust_state,
    modeled_consume_sink_never_writes_sequence_or_marker,
    modeled_consume_sink_no_rocksdb_file_schema_migration_change,
    modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_consume_sink_pipeline_success_required_before_receipt,
    modeled_consume_sink_policy_change_unsupported,
    modeled_consume_sink_production_mainnet_unavailable,
    modeled_consume_sink_receipt_record_required_before_consume,
    modeled_consume_sink_rejection_is_non_mutating, modeled_consume_sink_rollback_never_consumes,
    modeled_consume_sink_validator_set_rotation_unsupported,
    project_pipeline_outcome_to_consume_sink_intent,
    recover_modeled_durable_consume_projection_sink_window,
    sink_outcome_authorizes_modeled_consume_receipt, sink_outcome_projects_to_durable_completion,
    ConsumeSinkIntent, FixtureModeledDurableConsumeProjectionSink,
    GovernanceModeledDurableConsumeProjectionSink, GovernanceModeledDurableConsumeSinkExpectations,
    GovernanceModeledDurableConsumeSinkInput, GovernanceModeledDurableConsumeSinkOutcome,
    GovernanceModeledDurableConsumeSinkPolicy, GovernanceModeledDurableConsumeSinkReceipt,
    MainNetModeledDurableConsumeProjectionSink, ModeledConsumeSinkFault,
    ModeledDurableConsumeReceiptLedger, ModeledDurableConsumeReceiptWindow,
    ModeledDurableConsumeSinkKind, ProductionModeledDurableConsumeProjectionSink,
};
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

const RECEIPT_ID: &str = "consume-receipt-0001";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
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
    receipt: GovernanceModeledDurableConsumeSinkReceipt,
    expectations: GovernanceModeledDurableConsumeSinkExpectations,
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
    let receipt = GovernanceModeledDurableConsumeSinkReceipt {
        receipt_id: RECEIPT_ID.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableConsumeSinkExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        receipt,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        policy: GovernanceModeledDurableConsumeSinkPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
    ) -> GovernanceModeledDurableConsumeSinkInput {
        GovernanceModeledDurableConsumeSinkInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            receipt: self.receipt.clone(),
        }
    }

    /// The canonical "pipeline authorized consume" wired input.
    fn authorized(&self) -> GovernanceModeledDurableConsumeSinkInput {
        self.input(
            GovernanceModeledDurableConsumeSinkPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
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

fn devnet_sink() -> FixtureModeledDurableConsumeProjectionSink {
    FixtureModeledDurableConsumeProjectionSink::new(TrustBundleEnvironment::Devnet)
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_sink_policy_preserves_legacy_bypass_no_receipt_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeSinkPolicy::sink_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
    );
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt
    );
    assert!(outcome.no_consume());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_pipeline_policy_preserves_legacy_bypass_never_invokes_sink() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeSinkPolicy::pipeline_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
    );
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_evaluator_callsite_preserves_legacy_bypass_never_invokes_sink() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeSinkPolicy::evaluator_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
    );
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn devnet_pipeline_success_records_one_modeled_receipt() {
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    );
    assert!(outcome.authorizes_modeled_consume_receipt());
    assert!(outcome.projects_to_durable_completion());
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(RECEIPT_ID));
}

#[test]
fn testnet_pipeline_success_records_one_modeled_receipt() {
    let c = testnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = FixtureModeledDurableConsumeProjectionSink::new(TrustBundleEnvironment::Testnet);
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    );
    assert_eq!(sink.kind(), ModeledDurableConsumeSinkKind::FixtureTestNet);
    assert_eq!(ledger.len(), 1);
}

#[test]
fn duplicate_identical_receipt_is_idempotent_no_second_receipt() {
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let first = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    );
    let second = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent
    );
    // Idempotent: no new receipt, but it still projects to durable completion.
    assert!(!second.authorizes_modeled_consume_receipt());
    assert!(second.projects_to_durable_completion());
    assert_eq!(ledger.len(), 1, "no second receipt recorded");
}

#[test]
fn production_sink_reachable_but_unavailable_records_no_receipt() {
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = ProductionModeledDurableConsumeProjectionSink::default();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ProductionSinkUnavailableNoConsume
    );
    assert!(outcome.no_consume());
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_sink_reachable_but_unavailable_records_no_receipt() {
    // A mutating (non-peer-driven) MainNet surface reaches the sink and fails
    // closed as unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = MainNetModeledDurableConsumeProjectionSink::default();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetSinkUnavailableNoConsume
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_pipeline_and_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    // Even with a pipeline-authorized binding, MainNet peer-driven apply is
    // refused first.
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0, "no sink invocation");
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_unsupported_records_no_receipt() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeSinkPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ValidatorSetRotationUnsupportedNoConsume,
    );
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ValidatorSetRotationUnsupportedNoConsume
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn policy_change_unsupported_records_no_receipt() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeSinkPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::PolicyChangeUnsupportedNoConsume,
    );
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::PolicyChangeUnsupportedNoConsume
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — pipeline outcomes never authorize a receipt
// ===========================================================================

/// Helper: a non-success pipeline outcome must never invoke the sink and must
/// record no receipt.
fn assert_pipeline_no_receipt(
    pipeline: GovernanceModeledEndToEndPipelineOutcome,
    expected: GovernanceModeledDurableConsumeSinkOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableConsumeSinkPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        pipeline,
    );
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected, "pipeline outcome projected wrong");
    assert!(outcome.no_consume());
    assert_eq!(sink.invocations(), 0, "no sink invocation before sink stage");
    assert!(ledger.is_empty());
}

#[test]
fn evaluator_rejection_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay {
            reason: "evaluator rejected".to_string(),
        },
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn callsite_rejection_produces_no_sink_intent_no_receipt() {
    // The mutation-engine binding gate (a call-site rejection) yields no intent.
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier {
            reason: "binding mismatch".to_string(),
        },
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn durable_replay_stale_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ReplayStaleOrExpiredNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn durable_replay_consumed_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ReplayConsumedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn durable_replay_superseded_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ReplaySupersededNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn durable_replay_backend_unavailable_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::BackendUnavailableNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn durable_replay_rejected_before_mutation_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::DurableReplayRejectedBeforeMutation,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn mutation_engine_rejection_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeSnapshot {
            reason: "read-only validation surface".to_string(),
        },
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn modeled_applier_rejected_before_apply_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply {
            reason: "missing root".to_string(),
        },
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn modeled_apply_failure_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierApplyFailedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn modeled_rollback_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn modeled_rollback_failed_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRollbackFailedFatalNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn modeled_ambiguous_window_produces_no_sink_intent_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
    );
}

#[test]
fn pipeline_production_unavailable_maps_to_production_sink_unavailable() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ProductionUnavailableNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ProductionSinkUnavailableNoConsume,
    );
}

#[test]
fn pipeline_mainnet_unavailable_maps_to_mainnet_sink_unavailable() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::MainNetUnavailableNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetSinkUnavailableNoConsume,
    );
}

#[test]
fn pipeline_legacy_bypass_maps_to_legacy_bypass_no_receipt() {
    assert_pipeline_no_receipt(
        GovernanceModeledEndToEndPipelineOutcome::ProceedLegacyBypassNoMutation,
        GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — sink record failures (sink IS invoked)
// ===========================================================================

/// Helper: drive a pipeline-authorized input against a faulting fixture sink.
fn assert_record_fault(
    fault: ModeledConsumeSinkFault,
    expected: GovernanceModeledDurableConsumeSinkOutcome,
) {
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink =
        FixtureModeledDurableConsumeProjectionSink::with_fault(TrustBundleEnvironment::Devnet, fault);
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_consume());
    assert_eq!(sink.invocations(), 1, "sink was invoked");
    assert!(ledger.is_empty(), "no receipt recorded on a fault");
}

#[test]
fn sink_record_failure_does_not_consume() {
    assert_record_fault(
        ModeledConsumeSinkFault::RecordFailedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume,
    );
}

#[test]
fn sink_rollback_success_does_not_consume() {
    assert_record_fault(
        ModeledConsumeSinkFault::RolledBackNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume,
    );
}

#[test]
fn sink_rollback_failure_is_fatal_does_not_consume() {
    assert_record_fault(
        ModeledConsumeSinkFault::RollbackFailedFatal,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume,
    );
}

#[test]
fn sink_ambiguous_window_fails_closed_does_not_consume() {
    assert_record_fault(
        ModeledConsumeSinkFault::AmbiguousAfterRecord,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume,
    );
}

#[test]
fn same_receipt_id_different_digest_is_equivocation_no_second_receipt() {
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let first = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    );

    // Same receipt id, different receipt digest — equivocation. Expectations must
    // be updated to accept the new digest so the rejection is the equivocation
    // gate, not the identity gate.
    let mut c2 = devnet_ctx();
    c2.receipt.receipt_digest = "consume-receipt-digest-DIFFERENT".to_string();
    c2.expectations.expected_receipt_digest = "consume-receipt-digest-DIFFERENT".to_string();
    let input2 = c2.authorized();
    let second = evaluate_modeled_durable_consume_projection_sink(
        &input2,
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord
    );
    assert!(second.no_consume());
    assert_eq!(ledger.len(), 1, "no second receipt recorded");
}

// ===========================================================================
// Rejected before sink invocation — environment / surface binding
// ===========================================================================

/// Helper: a binding mismatch must reject before the sink is invoked.
fn assert_binding_rejected(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::RejectedBeforePipelineNoReceipt
    );
    assert!(outcome.no_consume());
    assert_eq!(sink.invocations(), 0, "no sink invocation before sink stage");
    assert!(ledger.is_empty());
}

#[test]
fn wrong_environment_rejected_before_sink_invocation() {
    assert_binding_rejected(|c| {
        c.env.environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_sink_invocation() {
    assert_binding_rejected(|c| {
        c.env.chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_sink_invocation() {
    assert_binding_rejected(|c| {
        c.env.genesis_hash = "genesis-wrong".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_sink_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_sink_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
    });
}

// ===========================================================================
// Rejected before record — receipt identity (sink IS invoked)
// ===========================================================================

/// Helper: a receipt-identity mismatch must reject before record (sink invoked).
fn assert_receipt_rejected_before_record(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord
    );
    assert!(outcome.no_consume());
    assert_eq!(sink.invocations(), 1, "sink invoked but rejected before record");
    assert!(ledger.is_empty(), "no receipt recorded");
}

#[test]
fn wrong_receipt_digest_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.receipt_digest = "receipt-digest-wrong".to_string();
    });
}

#[test]
fn wrong_pipeline_decision_digest_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.pipeline_decision_digest = "pipeline-digest-wrong".to_string();
    });
}

#[test]
fn wrong_proposal_id_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.proposal_id = "proposal-wrong".to_string();
    });
}

#[test]
fn wrong_decision_id_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.decision_id = "decision-wrong".to_string();
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.candidate_digest = "candidate-wrong".to_string();
    });
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.authority_domain_sequence = 99;
    });
}

#[test]
fn malformed_receipt_rejected_before_record() {
    assert_receipt_rejected_before_record(|c| {
        c.receipt.receipt_id = String::new();
    });
}

// ===========================================================================
// MainNet authority cannot be satisfied locally
// ===========================================================================

#[test]
fn local_operator_key_cannot_satisfy_mainnet_authority() {
    assert!(modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority());
}

#[test]
fn peer_majority_cannot_satisfy_mainnet_authority() {
    assert!(modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority());
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recover(
    window: ModeledDurableConsumeReceiptWindow,
    report: Option<&GovernanceModeledDurableConsumeSinkReceipt>,
) -> GovernanceModeledDurableConsumeSinkOutcome {
    let c = devnet_ctx();
    let input = c.authorized();
    recover_modeled_durable_consume_projection_sink_window(
        &input,
        window,
        ModeledDurableConsumeSinkKind::FixtureDevNet,
        report,
        &c.expectations,
    )
}

#[test]
fn recovery_before_pipeline_window_fails_closed_no_receipt() {
    let outcome = recover(ModeledDurableConsumeReceiptWindow::BeforePipeline, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_after_pipeline_success_before_sink_intent_fails_closed_no_receipt() {
    let outcome = recover(
        ModeledDurableConsumeReceiptWindow::AfterPipelineSuccessBeforeSinkIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt
    );
}

#[test]
fn recovery_after_sink_intent_before_record_fails_closed_no_receipt() {
    let outcome = recover(
        ModeledDurableConsumeReceiptWindow::AfterSinkIntentBeforeRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_after_record_before_report_without_report_fails_closed() {
    let outcome = recover(
        ModeledDurableConsumeReceiptWindow::AfterRecordBeforeReport,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_record_before_report_with_matching_report_recovers_recorded() {
    let c = devnet_ctx();
    let report = c.receipt.clone();
    let outcome = recover(
        ModeledDurableConsumeReceiptWindow::AfterRecordBeforeReport,
        Some(&report),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    );
    assert!(outcome.projects_to_durable_completion());
}

#[test]
fn recovery_after_report_success_recovers_recorded() {
    let c = devnet_ctx();
    let report = c.receipt.clone();
    let outcome = recover(
        ModeledDurableConsumeReceiptWindow::AfterReportSuccess,
        Some(&report),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    );
}

#[test]
fn recovery_after_report_ambiguous_fails_closed_no_consume() {
    let outcome = recover(
        ModeledDurableConsumeReceiptWindow::AfterReportAmbiguous,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_record_failed_window_fails_closed_no_consume() {
    let outcome = recover(ModeledDurableConsumeReceiptWindow::RecordFailed, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume
    );
}

#[test]
fn recovery_rollback_completed_window_fails_closed_no_consume() {
    let outcome = recover(ModeledDurableConsumeReceiptWindow::RollbackCompleted, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume
    );
}

#[test]
fn recovery_rollback_failed_window_is_fatal_no_consume() {
    let outcome = recover(ModeledDurableConsumeReceiptWindow::RollbackFailed, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume
    );
}

#[test]
fn recovery_unknown_window_fails_closed_no_consume() {
    let outcome = recover(ModeledDurableConsumeReceiptWindow::Unknown, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume
    );
    assert!(outcome.no_consume());
}

#[test]
fn recovery_production_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.authorized();
    let outcome = recover_modeled_durable_consume_projection_sink_window(
        &input,
        ModeledDurableConsumeReceiptWindow::AfterReportSuccess,
        ModeledDurableConsumeSinkKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::ProductionSinkUnavailableNoConsume
    );
}

#[test]
fn recovery_mainnet_classification_unavailable() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.authorized();
    let outcome = recover_modeled_durable_consume_projection_sink_window(
        &input,
        ModeledDurableConsumeReceiptWindow::AfterReportSuccess,
        ModeledDurableConsumeSinkKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetSinkUnavailableNoConsume
    );
}

#[test]
fn recovery_mainnet_peer_driven_apply_refusal_precedes_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input = c.authorized();
    let report = c.receipt.clone();
    let outcome = recover_modeled_durable_consume_projection_sink_window(
        &input,
        ModeledDurableConsumeReceiptWindow::AfterReportSuccess,
        ModeledDurableConsumeSinkKind::FixtureDevNet,
        Some(&report),
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_pipeline_consume_authorized_creates_sink_intent() {
    let intent = project_pipeline_outcome_to_consume_sink_intent(
        &GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
    );
    assert_eq!(intent, ConsumeSinkIntent::CreateIntent);
    assert!(intent.creates_intent());
}

#[test]
fn non_success_pipeline_outcomes_create_no_sink_intent() {
    for pipeline in [
        GovernanceModeledEndToEndPipelineOutcome::ProceedLegacyBypassNoMutation,
        GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay {
            reason: "x".to_string(),
        },
        GovernanceModeledEndToEndPipelineOutcome::DurableReplayRejectedBeforeMutation,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierApplyFailedNoConsume,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume,
        GovernanceModeledEndToEndPipelineOutcome::ProductionUnavailableNoConsume,
        GovernanceModeledEndToEndPipelineOutcome::MainNetUnavailableNoConsume,
        GovernanceModeledEndToEndPipelineOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledEndToEndPipelineOutcome::PolicyChangeUnsupportedNoConsume,
    ] {
        let intent = project_pipeline_outcome_to_consume_sink_intent(&pipeline);
        assert!(
            !intent.creates_intent(),
            "outcome {:?} must not create a sink intent",
            pipeline.tag()
        );
    }
}

#[test]
fn only_consume_receipt_recorded_authorizes_modeled_receipt() {
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    assert!(sink_outcome_authorizes_modeled_consume_receipt(
        &Sink::ConsumeReceiptRecorded
    ));
    // Every other outcome does not authorize a new modeled receipt.
    for outcome in [
        Sink::LegacyBypassNoReceipt,
        Sink::RejectedBeforePipelineNoReceipt,
        Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        Sink::ConsumeReceiptDuplicateIdempotent,
        Sink::ConsumeReceiptRejectedBeforeRecord,
        Sink::ConsumeReceiptRecordFailedNoConsume,
        Sink::ConsumeReceiptRolledBackNoConsume,
        Sink::ConsumeReceiptRollbackFailedFatalNoConsume,
        Sink::ConsumeReceiptAmbiguousFailClosedNoConsume,
        Sink::ProductionSinkUnavailableNoConsume,
        Sink::MainNetSinkUnavailableNoConsume,
        Sink::MainNetPeerDrivenApplyRefusedNoConsume,
        Sink::ValidatorSetRotationUnsupportedNoConsume,
        Sink::PolicyChangeUnsupportedNoConsume,
    ] {
        assert!(
            !sink_outcome_authorizes_modeled_consume_receipt(&outcome),
            "{} must not authorize a modeled receipt",
            outcome.tag()
        );
    }
}

#[test]
fn no_receipt_outcomes_do_not_project_to_durable_completion() {
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    for outcome in [
        Sink::LegacyBypassNoReceipt,
        Sink::RejectedBeforePipelineNoReceipt,
        Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        Sink::ConsumeReceiptRejectedBeforeRecord,
        Sink::ConsumeReceiptRecordFailedNoConsume,
        Sink::ConsumeReceiptRolledBackNoConsume,
        Sink::ConsumeReceiptRollbackFailedFatalNoConsume,
        Sink::ConsumeReceiptAmbiguousFailClosedNoConsume,
        Sink::ProductionSinkUnavailableNoConsume,
        Sink::MainNetSinkUnavailableNoConsume,
        Sink::MainNetPeerDrivenApplyRefusedNoConsume,
        Sink::ValidatorSetRotationUnsupportedNoConsume,
        Sink::PolicyChangeUnsupportedNoConsume,
    ] {
        assert!(
            !sink_outcome_projects_to_durable_completion(&outcome),
            "{} must not project to durable completion",
            outcome.tag()
        );
        assert!(outcome.no_consume());
    }
    // Recorded and idempotent-duplicate both project to durable completion.
    assert!(sink_outcome_projects_to_durable_completion(
        &Sink::ConsumeReceiptRecorded
    ));
    assert!(sink_outcome_projects_to_durable_completion(
        &Sink::ConsumeReceiptDuplicateIdempotent
    ));
}

// ===========================================================================
// Stage-ordering cases
// ===========================================================================

#[test]
fn rejection_before_sink_stage_leaves_invocation_count_zero() {
    // A binding mismatch (before the sink stage) leaves the sink invocation count
    // at zero.
    let mut c = devnet_ctx();
    c.env.environment = TrustBundleEnvironment::Testnet;
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let _ = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(sink.invocations(), 0);
}

#[test]
fn sink_record_failure_does_not_invalidate_pipeline_but_does_not_consume() {
    // A sink record failure leaves the pipeline-authorized binding untouched but
    // does not authorize consume.
    let c = devnet_ctx();
    let input = c.authorized();
    assert!(input
        .pipeline_binding
        .authorizes_durable_consume(), "pipeline still says authorized");
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = FixtureModeledDurableConsumeProjectionSink::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledConsumeSinkFault::RecordFailedNoConsume,
    );
    let outcome = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert!(outcome.no_consume());
    assert!(ledger.is_empty());
}

#[test]
fn ledger_snapshot_restore_models_rollback_with_no_drift() {
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    // Record one receipt.
    let _ = evaluate_modeled_durable_consume_projection_sink(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    let snap = ledger.snapshot();
    assert_eq!(snap.len(), 1);
    assert!(!snap.is_empty());
    // A rollback restores the snapshot exactly.
    let mut ledger2 = ModeledDurableConsumeReceiptLedger::new();
    ledger2.restore(&snap);
    assert_eq!(ledger2.len(), 1);
    assert!(ledger2.contains(RECEIPT_ID));
}

// ===========================================================================
// Invariant helpers
// ===========================================================================

#[test]
fn invariant_helpers_hold() {
    assert!(modeled_consume_sink_rejection_is_non_mutating());
    assert!(modeled_consume_sink_never_calls_run_070());
    assert!(modeled_consume_sink_never_mutates_live_pqc_trust_state());
    assert!(modeled_consume_sink_never_writes_sequence_or_marker());
    assert!(modeled_consume_sink_no_rocksdb_file_schema_migration_change());
    assert!(modeled_consume_sink_pipeline_success_required_before_receipt());
    assert!(modeled_consume_sink_receipt_record_required_before_consume());
    assert!(modeled_consume_sink_failed_record_never_consumes());
    assert!(modeled_consume_sink_rollback_never_consumes());
    assert!(modeled_consume_sink_ambiguous_window_fails_closed());
    assert!(modeled_consume_sink_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!modeled_consume_sink_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(modeled_consume_sink_production_mainnet_unavailable());
    assert!(modeled_consume_sink_validator_set_rotation_unsupported());
    assert!(modeled_consume_sink_policy_change_unsupported());
    assert!(modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority());
    assert!(modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority());
}
