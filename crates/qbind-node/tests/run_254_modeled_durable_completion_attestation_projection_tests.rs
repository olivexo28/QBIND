//! Run 254 — source/test governance **modeled durable-completion finalization
//! attestation projection** tests.
//!
//! Source/test only. Run 254 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! durable-completion attestation projection
//! ([`evaluate_modeled_durable_completion_attestation_projection`]) records a
//! modeled in-memory attestation **only** when the Run 252 finalizer recorded a
//! durable-completion finalization, and that every other finalization outcome,
//! every attestation record failure, rollback, rollback-failure, ambiguous
//! attestation window, every production / MainNet unavailable / unsupported path,
//! and every rejected binding fails closed with no attestation.
//!
//! Every rejected path is non-mutating and non-attesting: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no durable completion / audit write, and no
//! attestor invocation where the rejection happens before the attestor stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_254.md`.

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_completion_attestation_projection::{
    attestation_outcome_authorizes_modeled_attestation,
    attestation_outcome_projects_to_durable_completion_attested,
    evaluate_modeled_durable_completion_attestation_projection,
    modeled_attestation_ambiguous_window_fails_closed,
    modeled_attestation_completion_report_required_before_attestation,
    modeled_attestation_failed_record_never_attests,
    modeled_attestation_finalization_required_before_attestation,
    modeled_attestation_local_operator_cannot_satisfy_mainnet_authority,
    modeled_attestation_mainnet_peer_driven_apply_refused_first,
    modeled_attestation_never_calls_run_070,
    modeled_attestation_never_mutates_live_pqc_trust_state,
    modeled_attestation_never_writes_sequence_or_marker,
    modeled_attestation_no_rocksdb_file_schema_migration_change,
    modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_attestation_pipeline_success_required_before_attestation,
    modeled_attestation_policy_change_unsupported,
    modeled_attestation_production_mainnet_unavailable,
    modeled_attestation_record_required_before_durable_completion_attested,
    modeled_attestation_rejection_is_non_mutating,
    modeled_attestation_rollback_never_attests,
    modeled_attestation_sink_receipt_required_before_attestation,
    modeled_attestation_validator_set_rotation_unsupported,
    project_finalization_outcome_to_attestation_intent,
    recover_modeled_durable_completion_attestation_window,
    DurableCompletionAttestationIntent, FixtureModeledDurableCompletionAttestor,
    GovernanceModeledDurableCompletionAttestationExpectations,
    GovernanceModeledDurableCompletionAttestationInput,
    GovernanceModeledDurableCompletionAttestationOutcome,
    GovernanceModeledDurableCompletionAttestationPolicy,
    GovernanceModeledDurableCompletionAttestationRecord,
    GovernanceModeledDurableCompletionAttestor, MainNetModeledDurableCompletionAttestor,
    ModeledDurableCompletionAttestationFault, ModeledDurableCompletionAttestationLedger,
    ModeledDurableCompletionAttestationWindow, ModeledDurableCompletionAttestorKind,
    ProductionModeledDurableCompletionAttestor,
};
use qbind_node::pqc_governance_modeled_durable_completion_finalization_projection::GovernanceModeledDurableCompletionFinalizationOutcome;
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

const ATTESTATION_ID: &str = "durable-completion-attestation-0001";
const ATTESTATION_DIGEST: &str = "attestation-digest-tttttttttttttttttttt";
const FINALIZATION_DIGEST: &str = "finalization-digest-ffffffffffffffffffff";
const REPORT_DIGEST: &str = "completion-report-digest-cccccccccccccccc";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
const SINK_DIGEST: &str = "sink-decision-digest-ssssssssssssssssssss";
const REPORTER_DIGEST: &str = "reporter-decision-digest-eeeeeeeeeeeeeeee";
const FINALIZATION_DECISION_DIGEST: &str = "finalization-decision-digest-llllllllll";
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
    attestation: GovernanceModeledDurableCompletionAttestationRecord,
    expectations: GovernanceModeledDurableCompletionAttestationExpectations,
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
    let attestation = GovernanceModeledDurableCompletionAttestationRecord {
        attestation_id: ATTESTATION_ID.to_string(),
        attestation_digest: ATTESTATION_DIGEST.to_string(),
        finalization_digest: FINALIZATION_DIGEST.to_string(),
        report_digest: REPORT_DIGEST.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        sink_decision_digest: SINK_DIGEST.to_string(),
        reporter_decision_digest: REPORTER_DIGEST.to_string(),
        finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableCompletionAttestationExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_attestation_digest: ATTESTATION_DIGEST.to_string(),
        expected_finalization_digest: FINALIZATION_DIGEST.to_string(),
        expected_report_digest: REPORT_DIGEST.to_string(),
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_reporter_decision_digest: REPORTER_DIGEST.to_string(),
        expected_finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        attestation,
        expectations,
    }
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: GovernanceModeledDurableCompletionAttestationPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
    ) -> GovernanceModeledDurableCompletionAttestationInput {
        GovernanceModeledDurableCompletionAttestationInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            finalization_binding: finalization,
            attestation: self.attestation.clone(),
        }
    }

    /// The canonical "finalizer recorded a finalization" wired input.
    fn finalized(&self) -> GovernanceModeledDurableCompletionAttestationInput {
        self.input(
            GovernanceModeledDurableCompletionAttestationPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
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

fn devnet_attestor() -> FixtureModeledDurableCompletionAttestor {
    FixtureModeledDurableCompletionAttestor::new(TrustBundleEnvironment::Devnet)
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_attestation_policy_preserves_legacy_bypass_no_attestation_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::attestation_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation
    );
    assert!(outcome.no_attestation());
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_finalization_policy_preserves_legacy_bypass_never_invokes_attestor() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::finalization_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_reporter_policy_preserves_legacy_bypass_never_invokes_attestor() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::reporter_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_sink_policy_preserves_legacy_bypass_never_invokes_attestor() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::sink_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_pipeline_policy_preserves_legacy_bypass_never_invokes_attestor() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::pipeline_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_evaluator_callsite_preserves_legacy_bypass_never_invokes_attestor() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::evaluator_disabled(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn devnet_finalized_records_one_modeled_attestation() {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
    assert!(outcome.authorizes_modeled_durable_completion_attestation());
    assert!(outcome.projects_to_durable_completion_attested());
    assert_eq!(attestor.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(ATTESTATION_ID));
}

#[test]
fn testnet_finalized_records_one_modeled_attestation() {
    let c = testnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor =
        FixtureModeledDurableCompletionAttestor::new(TrustBundleEnvironment::Testnet);
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
    assert_eq!(
        attestor.kind(),
        ModeledDurableCompletionAttestorKind::FixtureTestNet
    );
    assert_eq!(ledger.len(), 1);
}

/// Helper: drive a finalized input whose modeled action is reflected by a distinct
/// candidate digest, and assert exactly one attestation is recorded only after the
/// finalizer recorded a finalization.
fn assert_action_records_attestation(candidate_digest: &str) {
    let mut c = devnet_ctx();
    c.attestation.candidate_digest = candidate_digest.to_string();
    c.expectations.expected_candidate_digest = candidate_digest.to_string();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
    assert_eq!(attestor.invocations(), 1);
    assert_eq!(ledger.len(), 1);
}

#[test]
fn modeled_add_root_records_attestation_only_after_finalization_record() {
    assert_action_records_attestation("candidate-add-root-aaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn modeled_retire_root_records_attestation_only_after_finalization_record() {
    assert_action_records_attestation("candidate-retire-root-bbbbbbbbbbbbbbbb");
}

#[test]
fn modeled_revoke_root_records_attestation_only_after_finalization_record() {
    assert_action_records_attestation("candidate-revoke-root-cccccccccccccccc");
}

#[test]
fn modeled_emergency_revoke_root_records_attestation_only_after_finalization_record() {
    assert_action_records_attestation("candidate-emergency-revoke-dddddddddddd");
}

#[test]
fn modeled_noop_records_attestation_only_under_explicit_success_and_recorded_finalization() {
    assert_action_records_attestation("candidate-noop-eeeeeeeeeeeeeeeeeeeeeeee");
}

#[test]
fn duplicate_identical_attestation_is_idempotent_no_second_attestation() {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let first = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
    let second = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationDuplicateIdempotent
    );
    // Idempotent: no new attestation, but it still projects to durable completion
    // attestation.
    assert!(!second.authorizes_modeled_durable_completion_attestation());
    assert!(second.projects_to_durable_completion_attested());
    assert_eq!(ledger.len(), 1, "no second attestation recorded");
}

#[test]
fn production_attestor_reachable_but_unavailable_records_no_attestation() {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = ProductionModeledDurableCompletionAttestor::default();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::ProductionAttestorUnavailableNoAttestation
    );
    assert!(outcome.no_attestation());
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_attestor_reachable_but_unavailable_records_no_attestation() {
    // A mutating (non-peer-driven) MainNet surface reaches the attestor and fails
    // closed as unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = MainNetModeledDurableCompletionAttestor::default();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetAttestorUnavailableNoAttestation
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_pipeline_sink_reporter_finalizer_and_attestor() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    // Even with a finalized binding, MainNet peer-driven apply is refused first.
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(attestor.invocations(), 0, "no attestor invocation");
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_unsupported_records_no_attestation() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::ValidatorSetRotationUnsupportedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ValidatorSetRotationUnsupportedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::ValidatorSetRotationUnsupportedNoFinalization,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::ValidatorSetRotationUnsupportedNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn policy_change_unsupported_records_no_attestation() {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::PolicyChangeUnsupportedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::PolicyChangeUnsupportedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::PolicyChangeUnsupportedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::PolicyChangeUnsupportedNoFinalization,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::PolicyChangeUnsupportedNoAttestation
    );
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — finalization outcomes never authorize an attestation
// ===========================================================================

/// Helper: a non-finalizing finalization outcome must never invoke the attestor
/// and must record no attestation.
fn assert_finalization_no_attestation(
    finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
    expected: GovernanceModeledDurableCompletionAttestationOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        finalization,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(outcome, expected, "finalization outcome projected wrong");
    assert!(outcome.no_attestation());
    assert_eq!(
        attestor.invocations(),
        0,
        "no attestor invocation before attestor stage"
    );
    assert!(ledger.is_empty());
}

#[test]
fn finalization_legacy_bypass_maps_to_legacy_bypass_no_attestation() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::LegacyBypassNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation,
    );
}

#[test]
fn finalization_rejected_before_reporter_maps_to_rejected_before_finalization() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::RejectedBeforeReporterNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::RejectedBeforeFinalizationNoAttestation,
    );
}

#[test]
fn finalization_reporter_did_not_record_maps_to_finalization_did_not_finalize() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
    );
}

#[test]
fn finalization_rejected_before_record_maps_to_finalization_did_not_finalize() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRejectedBeforeRecord,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
    );
}

#[test]
fn finalization_record_failure_maps_to_finalization_did_not_finalize() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRecordFailedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
    );
}

#[test]
fn finalization_rollback_maps_to_finalization_did_not_finalize() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRolledBackNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
    );
}

#[test]
fn finalization_rollback_failed_maps_to_finalization_did_not_finalize() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionRollbackFailedFatalNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
    );
}

#[test]
fn finalization_ambiguous_window_maps_to_finalization_did_not_finalize() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionAmbiguousFailClosedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
    );
}

#[test]
fn finalization_production_unavailable_maps_to_production_attestor_unavailable() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::ProductionFinalizerUnavailableNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::ProductionAttestorUnavailableNoAttestation,
    );
}

#[test]
fn finalization_mainnet_unavailable_maps_to_mainnet_attestor_unavailable() {
    assert_finalization_no_attestation(
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetFinalizerUnavailableNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetAttestorUnavailableNoAttestation,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — pipeline-level rejections (finalizer never recorded)
// ===========================================================================

/// Helper: a non-success pipeline outcome carries non-recording sink + reporter +
/// finalization outcomes and must never invoke the attestor and record no
/// attestation.
fn assert_pipeline_no_attestation(pipeline: GovernanceModeledEndToEndPipelineOutcome) {
    let c = devnet_ctx();
    // A non-success pipeline never reaches the finalized outcome.
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        pipeline,
        GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
    assert!(outcome.no_attestation());
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn evaluator_rejection_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay {
            reason: "evaluator rejected".to_string(),
        },
    );
}

#[test]
fn callsite_rejection_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier {
            reason: "binding mismatch".to_string(),
        },
    );
}

#[test]
fn durable_replay_stale_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ReplayStaleOrExpiredNoConsume,
    );
}

#[test]
fn durable_replay_consumed_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ReplayConsumedNoConsume,
    );
}

#[test]
fn durable_replay_superseded_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ReplaySupersededNoConsume,
    );
}

#[test]
fn durable_replay_backend_unavailable_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::BackendUnavailableNoConsume,
    );
}

#[test]
fn mutation_engine_rejection_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeSnapshot {
            reason: "read-only validation surface".to_string(),
        },
    );
}

#[test]
fn modeled_applier_rejected_before_apply_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply {
            reason: "missing root".to_string(),
        },
    );
}

#[test]
fn modeled_apply_failure_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierApplyFailedNoConsume,
    );
}

#[test]
fn modeled_rollback_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRolledBackNoConsume,
    );
}

#[test]
fn modeled_rollback_failed_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRollbackFailedFatalNoConsume,
    );
}

#[test]
fn modeled_ambiguous_window_produces_no_attestor_intent_no_attestation() {
    assert_pipeline_no_attestation(
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAmbiguousFailClosedNoConsume,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — sink-level rejections (finalizer never recorded)
// ===========================================================================

/// Helper: a non-recording sink outcome carries non-recording reporter +
/// finalization outcomes and must never invoke the attestor and record no
/// attestation.
fn assert_sink_no_attestation(sink: GovernanceModeledDurableConsumeSinkOutcome) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
    assert!(outcome.no_attestation());
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn sink_did_not_record_receipt_produces_no_attestation() {
    assert_sink_no_attestation(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord,
    );
}

#[test]
fn sink_record_failure_produces_no_attestation() {
    assert_sink_no_attestation(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume,
    );
}

#[test]
fn sink_rollback_produces_no_attestation() {
    assert_sink_no_attestation(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume,
    );
}

#[test]
fn sink_rollback_failed_produces_no_attestation() {
    assert_sink_no_attestation(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume,
    );
}

#[test]
fn sink_ambiguous_window_produces_no_attestation() {
    assert_sink_no_attestation(
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — reporter-level rejections (finalizer never recorded)
// ===========================================================================

/// Helper: a non-recording reporter outcome carries a non-finalizing finalization
/// outcome and must never invoke the attestor and record no attestation.
fn assert_reporter_no_attestation(
    reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter,
        GovernanceModeledDurableCompletionFinalizationOutcome::ReporterDidNotRecordCompletionNoFinalization,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
    assert!(outcome.no_attestation());
    assert_eq!(attestor.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn reporter_did_not_record_completion_produces_no_attestation() {
    assert_reporter_no_attestation(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRejectedBeforeRecord,
    );
}

#[test]
fn reporter_record_failure_produces_no_attestation() {
    assert_reporter_no_attestation(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecordFailedNoCompletion,
    );
}

#[test]
fn reporter_rollback_produces_no_attestation() {
    assert_reporter_no_attestation(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRolledBackNoCompletion,
    );
}

#[test]
fn reporter_rollback_failed_produces_no_attestation() {
    assert_reporter_no_attestation(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRollbackFailedFatalNoCompletion,
    );
}

#[test]
fn reporter_ambiguous_window_produces_no_attestation() {
    assert_reporter_no_attestation(
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportAmbiguousFailClosedNoCompletion,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — attestation record failures (attestor IS invoked)
// ===========================================================================

/// Helper: drive a finalized input against a faulting fixture attestor.
fn assert_record_fault(
    fault: ModeledDurableCompletionAttestationFault,
    expected: GovernanceModeledDurableCompletionAttestationOutcome,
) {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor =
        FixtureModeledDurableCompletionAttestor::with_fault(TrustBundleEnvironment::Devnet, fault);
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_attestation());
    assert_eq!(attestor.invocations(), 1, "attestor was invoked");
    assert!(ledger.is_empty(), "no attestation recorded on a fault");
}

#[test]
fn attestation_record_failure_does_not_attest() {
    assert_record_fault(
        ModeledDurableCompletionAttestationFault::RecordFailedNoAttestation,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRecordFailedNoAttestation,
    );
}

#[test]
fn attestation_rollback_success_does_not_attest() {
    assert_record_fault(
        ModeledDurableCompletionAttestationFault::RolledBackNoAttestation,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRolledBackNoAttestation,
    );
}

#[test]
fn attestation_rollback_failure_is_fatal_does_not_attest() {
    assert_record_fault(
        ModeledDurableCompletionAttestationFault::RollbackFailedFatal,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
    );
}

#[test]
fn attestation_ambiguous_window_fails_closed_does_not_attest() {
    assert_record_fault(
        ModeledDurableCompletionAttestationFault::AmbiguousAfterRecord,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
    );
}

#[test]
fn same_attestation_id_different_digest_is_equivocation_no_second_attestation() {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let first = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );

    // Same attestation id, different attestation digest — equivocation.
    // Expectations must be updated to accept the new digest so the rejection is the
    // equivocation gate, not the identity gate.
    let mut c2 = devnet_ctx();
    c2.attestation.attestation_digest = "attestation-digest-DIFFERENT".to_string();
    c2.expectations.expected_attestation_digest = "attestation-digest-DIFFERENT".to_string();
    let input2 = c2.finalized();
    let second = evaluate_modeled_durable_completion_attestation_projection(
        &input2,
        &c2.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRejectedBeforeRecord
    );
    assert!(second.no_attestation());
    assert_eq!(ledger.len(), 1, "no second attestation recorded");
}

#[test]
fn duplicate_finalization_without_prior_attestation_does_not_create_new() {
    // A DurableCompletionDuplicateIdempotent finalization outcome may only match an
    // already-recorded attestation; with an empty ledger it must not create a new
    // attestation by itself.
    let c = devnet_ctx();
    let input = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRejectedBeforeRecord
    );
    assert!(outcome.no_attestation());
    assert!(
        ledger.is_empty(),
        "no attestation created from a duplicate finalization"
    );
}

#[test]
fn duplicate_finalization_with_matching_prior_attestation_is_idempotent() {
    let c = devnet_ctx();
    // First, record an attestation via a finalized finalization.
    let finalized = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let first = evaluate_modeled_durable_completion_attestation_projection(
        &finalized,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        first,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
    // Now a duplicate-idempotent finalization matches the existing attestation.
    let dup = c.input(
        GovernanceModeledDurableCompletionAttestationPolicy::wired(),
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent,
    );
    let second = evaluate_modeled_durable_completion_attestation_projection(
        &dup,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        second,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationDuplicateIdempotent
    );
    assert!(second.projects_to_durable_completion_attested());
    assert_eq!(ledger.len(), 1, "no second attestation recorded");
}

// ===========================================================================
// Rejected before attestor invocation — environment / surface binding
// ===========================================================================

/// Helper: a binding mismatch must reject before the attestor is invoked.
fn assert_binding_rejected(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::RejectedBeforeFinalizationNoAttestation
    );
    assert!(outcome.no_attestation());
    assert_eq!(
        attestor.invocations(),
        0,
        "no attestor invocation before attestor stage"
    );
    assert!(ledger.is_empty());
}

#[test]
fn wrong_environment_rejected_before_attestor_invocation() {
    assert_binding_rejected(|c| {
        c.env.environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_attestor_invocation() {
    assert_binding_rejected(|c| {
        c.env.chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_attestor_invocation() {
    assert_binding_rejected(|c| {
        c.env.genesis_hash = "genesis-wrong".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_attestor_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_attestor_invocation() {
    assert_binding_rejected(|c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
    });
}

// ===========================================================================
// Rejected before record — attestation identity (attestor IS invoked)
// ===========================================================================

/// Helper: an attestation-identity mismatch must reject before record (attestor
/// invoked).
fn assert_attestation_rejected_before_record(mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRejectedBeforeRecord
    );
    assert!(outcome.no_attestation());
    assert_eq!(
        attestor.invocations(),
        1,
        "attestor invoked but rejected before record"
    );
    assert!(ledger.is_empty(), "no attestation recorded");
}

#[test]
fn wrong_attestation_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.attestation_digest = "attestation-digest-wrong".to_string();
    });
}

#[test]
fn wrong_finalization_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.finalization_digest = "finalization-digest-wrong".to_string();
    });
}

#[test]
fn wrong_completion_report_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.report_digest = "report-digest-wrong".to_string();
    });
}

#[test]
fn wrong_receipt_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.receipt_digest = "receipt-digest-wrong".to_string();
    });
}

#[test]
fn wrong_sink_decision_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.sink_decision_digest = "sink-digest-wrong".to_string();
    });
}

#[test]
fn wrong_reporter_decision_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.reporter_decision_digest = "reporter-digest-wrong".to_string();
    });
}

#[test]
fn wrong_finalization_decision_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.finalization_decision_digest = "finalization-decision-wrong".to_string();
    });
}

#[test]
fn wrong_pipeline_decision_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.pipeline_decision_digest = "pipeline-digest-wrong".to_string();
    });
}

#[test]
fn wrong_proposal_id_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.proposal_id = "proposal-wrong".to_string();
    });
}

#[test]
fn wrong_decision_id_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.decision_id = "decision-wrong".to_string();
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.candidate_digest = "candidate-wrong".to_string();
    });
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.authority_domain_sequence = 99;
    });
}

#[test]
fn malformed_attestation_rejected_before_record() {
    assert_attestation_rejected_before_record(|c| {
        c.attestation.attestation_id = String::new();
    });
}

// ===========================================================================
// MainNet authority cannot be satisfied locally
// ===========================================================================

#[test]
fn local_operator_key_cannot_satisfy_mainnet_authority() {
    assert!(modeled_attestation_local_operator_cannot_satisfy_mainnet_authority());
}

#[test]
fn peer_majority_cannot_satisfy_mainnet_authority() {
    assert!(modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority());
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recover(
    window: ModeledDurableCompletionAttestationWindow,
    attestation: Option<&GovernanceModeledDurableCompletionAttestationRecord>,
) -> GovernanceModeledDurableCompletionAttestationOutcome {
    let c = devnet_ctx();
    let input = c.finalized();
    recover_modeled_durable_completion_attestation_window(
        &input,
        window,
        ModeledDurableCompletionAttestorKind::FixtureDevNet,
        attestation,
        &c.expectations,
    )
}

#[test]
fn recovery_before_pipeline_window_fails_closed_no_attestation() {
    let outcome = recover(ModeledDurableCompletionAttestationWindow::BeforePipeline, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
    assert!(outcome.no_attestation());
}

#[test]
fn recovery_after_pipeline_success_before_sink_intent_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterPipelineSuccessBeforeSinkIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
}

#[test]
fn recovery_after_sink_intent_before_receipt_record_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterSinkIntentBeforeReceiptRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
}

#[test]
fn recovery_after_receipt_record_before_report_intent_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterReceiptRecordBeforeReportIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
}

#[test]
fn recovery_after_report_intent_before_report_record_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterReportIntentBeforeReportRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
}

#[test]
fn recovery_after_report_record_before_finalization_intent_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterReportRecordBeforeFinalizationIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
}

#[test]
fn recovery_after_finalization_intent_before_finalization_record_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterFinalizationIntentBeforeFinalizationRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation
    );
}

#[test]
fn recovery_after_finalization_record_before_attestation_intent_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterFinalizationRecordBeforeAttestationIntent,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_attestation_intent_before_attestation_record_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterAttestationIntentBeforeAttestationRecord,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_attestation_record_before_success_without_attestation_fails_closed() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterAttestationRecordBeforeAttestationSuccess,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRejectedBeforeRecord
    );
}

#[test]
fn recovery_after_attestation_record_before_success_with_matching_attestation_recovers() {
    let c = devnet_ctx();
    let attestation = c.attestation.clone();
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterAttestationRecordBeforeAttestationSuccess,
        Some(&attestation),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
    assert!(outcome.projects_to_durable_completion_attested());
}

#[test]
fn recovery_after_attestation_success_recovers_durable_completion_attested() {
    let c = devnet_ctx();
    let attestation = c.attestation.clone();
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterAttestationSuccess,
        Some(&attestation),
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested
    );
}

#[test]
fn recovery_after_attestation_ambiguous_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AfterAttestationAmbiguous,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationAmbiguousFailClosedNoAttestation
    );
    assert!(outcome.no_attestation());
}

#[test]
fn recovery_attestation_record_failed_window_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::AttestationRecordFailed,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRecordFailedNoAttestation
    );
}

#[test]
fn recovery_rollback_completed_window_fails_closed_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::RollbackCompleted,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRolledBackNoAttestation
    );
}

#[test]
fn recovery_rollback_failed_window_is_fatal_no_attestation() {
    let outcome = recover(
        ModeledDurableCompletionAttestationWindow::RollbackFailed,
        None,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationRollbackFailedFatalNoAttestation
    );
}

#[test]
fn recovery_unknown_window_fails_closed_no_attestation() {
    let outcome = recover(ModeledDurableCompletionAttestationWindow::Unknown, None);
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationAmbiguousFailClosedNoAttestation
    );
    assert!(outcome.no_attestation());
}

#[test]
fn recovery_production_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.finalized();
    let outcome = recover_modeled_durable_completion_attestation_window(
        &input,
        ModeledDurableCompletionAttestationWindow::AfterAttestationSuccess,
        ModeledDurableCompletionAttestorKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::ProductionAttestorUnavailableNoAttestation
    );
}

#[test]
fn recovery_mainnet_classification_unavailable() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let input = c.finalized();
    let outcome = recover_modeled_durable_completion_attestation_window(
        &input,
        ModeledDurableCompletionAttestationWindow::AfterAttestationSuccess,
        ModeledDurableCompletionAttestorKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetAttestorUnavailableNoAttestation
    );
}

#[test]
fn recovery_mainnet_peer_driven_apply_refusal_precedes_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input = c.finalized();
    let attestation = c.attestation.clone();
    let outcome = recover_modeled_durable_completion_attestation_window(
        &input,
        ModeledDurableCompletionAttestationWindow::AfterAttestationSuccess,
        ModeledDurableCompletionAttestorKind::FixtureDevNet,
        Some(&attestation),
        &c.expectations,
    );
    assert_eq!(
        outcome,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_durable_completion_finalized_creates_attestation_intent() {
    let intent = project_finalization_outcome_to_attestation_intent(
        &GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
    );
    assert_eq!(intent, DurableCompletionAttestationIntent::CreateIntent);
    assert!(intent.creates_intent());
}

#[test]
fn duplicate_idempotent_finalization_outcome_projects_to_idempotent_only() {
    let intent = project_finalization_outcome_to_attestation_intent(
        &GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent,
    );
    assert_eq!(intent, DurableCompletionAttestationIntent::IdempotentOnly);
    assert!(!intent.creates_intent());
}

#[test]
fn non_finalizing_finalization_outcomes_create_no_attestation_intent() {
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    for finalization in [
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
        let intent = project_finalization_outcome_to_attestation_intent(&finalization);
        assert!(
            !intent.creates_intent(),
            "finalization outcome {} must not create an attestation intent",
            finalization.tag()
        );
    }
}

#[test]
fn only_durable_completion_attested_authorizes_modeled_attestation() {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    assert!(attestation_outcome_authorizes_modeled_attestation(
        &Att::DurableCompletionAttested
    ));
    // Every other outcome does not authorize a new modeled attestation.
    for outcome in [
        Att::LegacyBypassNoAttestation,
        Att::RejectedBeforeFinalizationNoAttestation,
        Att::FinalizationDidNotFinalizeNoAttestation,
        Att::DurableCompletionAttestationDuplicateIdempotent,
        Att::DurableCompletionAttestationRejectedBeforeRecord,
        Att::DurableCompletionAttestationRecordFailedNoAttestation,
        Att::DurableCompletionAttestationRolledBackNoAttestation,
        Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
        Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
        Att::ProductionAttestorUnavailableNoAttestation,
        Att::MainNetAttestorUnavailableNoAttestation,
        Att::MainNetPeerDrivenApplyRefusedNoAttestation,
        Att::ValidatorSetRotationUnsupportedNoAttestation,
        Att::PolicyChangeUnsupportedNoAttestation,
    ] {
        assert!(
            !attestation_outcome_authorizes_modeled_attestation(&outcome),
            "{} must not authorize a modeled attestation",
            outcome.tag()
        );
    }
}

#[test]
fn no_attestation_outcomes_do_not_project_to_durable_completion_attested() {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    for outcome in [
        Att::LegacyBypassNoAttestation,
        Att::RejectedBeforeFinalizationNoAttestation,
        Att::FinalizationDidNotFinalizeNoAttestation,
        Att::DurableCompletionAttestationRejectedBeforeRecord,
        Att::DurableCompletionAttestationRecordFailedNoAttestation,
        Att::DurableCompletionAttestationRolledBackNoAttestation,
        Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
        Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
        Att::ProductionAttestorUnavailableNoAttestation,
        Att::MainNetAttestorUnavailableNoAttestation,
        Att::MainNetPeerDrivenApplyRefusedNoAttestation,
        Att::ValidatorSetRotationUnsupportedNoAttestation,
        Att::PolicyChangeUnsupportedNoAttestation,
    ] {
        assert!(
            !attestation_outcome_projects_to_durable_completion_attested(&outcome),
            "{} must not project to durable completion attested",
            outcome.tag()
        );
        assert!(outcome.no_attestation());
    }
    // Attested and idempotent-duplicate both project to durable completion attested.
    assert!(attestation_outcome_projects_to_durable_completion_attested(
        &Att::DurableCompletionAttested
    ));
    assert!(attestation_outcome_projects_to_durable_completion_attested(
        &Att::DurableCompletionAttestationDuplicateIdempotent
    ));
}

// ===========================================================================
// Stage-ordering cases
// ===========================================================================

#[test]
fn rejection_before_attestor_stage_leaves_invocation_count_zero() {
    // A binding mismatch (before the attestor stage) leaves the attestor invocation
    // count at zero.
    let mut c = devnet_ctx();
    c.env.environment = TrustBundleEnvironment::Testnet;
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let _ = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(attestor.invocations(), 0);
}

#[test]
fn attestation_record_failure_does_not_invalidate_finalization_but_does_not_attest() {
    // An attestation record failure leaves the finalized binding untouched but does
    // not authorize durable completion attestation.
    let c = devnet_ctx();
    let input = c.finalized();
    assert_eq!(
        input.finalization_binding,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        "finalizer still says finalized"
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = FixtureModeledDurableCompletionAttestor::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledDurableCompletionAttestationFault::RecordFailedNoAttestation,
    );
    let outcome = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert!(outcome.no_attestation());
    assert!(ledger.is_empty());
}

#[test]
fn ledger_snapshot_restore_models_rollback_with_no_drift() {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    // Record one attestation.
    let _ = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    let snap = ledger.snapshot();
    assert_eq!(snap.len(), 1);
    assert!(!snap.is_empty());
    // A rollback restores the snapshot exactly.
    let mut ledger2 = ModeledDurableCompletionAttestationLedger::new();
    ledger2.restore(&snap);
    assert_eq!(ledger2.len(), 1);
    assert!(ledger2.contains(ATTESTATION_ID));
}

// ===========================================================================
// Attestation-ledger cases
// ===========================================================================

#[test]
fn one_valid_attestation_inserts_exactly_one_ledger_record() {
    let c = devnet_ctx();
    let input = c.finalized();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut attestor = devnet_attestor();
    let _ = evaluate_modeled_durable_completion_attestation_projection(
        &input,
        &c.expectations,
        &mut attestor,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.records().len(), 1);
    assert_eq!(ledger.records()[0].attestation_id, ATTESTATION_ID);
}

// ===========================================================================
// Invariant helpers
// ===========================================================================

#[test]
fn invariant_helpers_hold() {
    assert!(modeled_attestation_rejection_is_non_mutating());
    assert!(modeled_attestation_never_calls_run_070());
    assert!(modeled_attestation_never_mutates_live_pqc_trust_state());
    assert!(modeled_attestation_never_writes_sequence_or_marker());
    assert!(modeled_attestation_no_rocksdb_file_schema_migration_change());
    assert!(modeled_attestation_pipeline_success_required_before_attestation());
    assert!(modeled_attestation_sink_receipt_required_before_attestation());
    assert!(modeled_attestation_completion_report_required_before_attestation());
    assert!(modeled_attestation_finalization_required_before_attestation());
    assert!(modeled_attestation_record_required_before_durable_completion_attested());
    assert!(modeled_attestation_failed_record_never_attests());
    assert!(modeled_attestation_rollback_never_attests());
    assert!(modeled_attestation_ambiguous_window_fails_closed());
    assert!(modeled_attestation_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!modeled_attestation_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(modeled_attestation_production_mainnet_unavailable());
    assert!(modeled_attestation_validator_set_rotation_unsupported());
    assert!(modeled_attestation_policy_change_unsupported());
    assert!(modeled_attestation_local_operator_cannot_satisfy_mainnet_authority());
    assert!(modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority());
}