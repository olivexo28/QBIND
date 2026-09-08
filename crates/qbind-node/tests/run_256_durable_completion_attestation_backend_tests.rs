//! Run 256 — source/test production **durable-completion attestation backend
//! interface boundary** tests.
//!
//! Source/test only. Run 256 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! durable-completion attestation backend
//! ([`evaluate_durable_completion_attestation_backend`]) records a modeled
//! in-memory backend submission **only** when the Run 254 attestor recorded a
//! `DurableCompletionAttested`, and that every other attestation outcome, every
//! backend record failure, rollback, rollback-failure, ambiguous backend window,
//! every production / MainNet / external-publication unavailable / unsupported
//! path, and every rejected binding fails closed with no backend submission.
//!
//! Every rejected path is non-mutating and non-submitting: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no external publication, no real audit-ledger
//! write, and no backend invocation where the rejection happens before the backend
//! stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_256.md`.

use qbind_node::pqc_governance_durable_completion_attestation_backend::{
    backend_outcome_authorizes_durable_attestation_submission,
    backend_outcome_projects_to_backend_submission_recorded,
    durable_completion_attestation_backend_ambiguous_window_fails_closed,
    durable_completion_attestation_backend_attestation_required,
    durable_completion_attestation_backend_completion_report_required,
    durable_completion_attestation_backend_failed_record_never_submits,
    durable_completion_attestation_backend_finalization_required,
    durable_completion_attestation_backend_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first,
    durable_completion_attestation_backend_never_calls_run_070,
    durable_completion_attestation_backend_never_mutates_live_pqc_trust_state,
    durable_completion_attestation_backend_never_writes_sequence_or_marker,
    durable_completion_attestation_backend_no_external_publication,
    durable_completion_attestation_backend_no_real_audit_ledger,
    durable_completion_attestation_backend_no_rocksdb_file_schema_migration_change,
    durable_completion_attestation_backend_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_attestation_backend_pipeline_success_required,
    durable_completion_attestation_backend_policy_change_unsupported,
    durable_completion_attestation_backend_production_mainnet_unavailable,
    durable_completion_attestation_backend_record_required_before_submission,
    durable_completion_attestation_backend_rejection_is_non_mutating,
    durable_completion_attestation_backend_rollback_never_submits,
    durable_completion_attestation_backend_sink_receipt_required,
    durable_completion_attestation_backend_validator_set_rotation_unsupported,
    evaluate_durable_completion_attestation_backend,
    project_attestation_outcome_to_backend_request,
    recover_durable_completion_attestation_backend_window,
    DurableCompletionAttestationBackendExpectations, DurableCompletionAttestationBackendFault,
    DurableCompletionAttestationBackendIdentity, DurableCompletionAttestationBackendInput,
    DurableCompletionAttestationBackendKind, DurableCompletionAttestationBackendLedger,
    DurableCompletionAttestationBackendOutcome, DurableCompletionAttestationBackendPolicy,
    DurableCompletionAttestationBackendRequest, DurableCompletionAttestationBackendRequestIntent,
    DurableCompletionAttestationBackendWindow, ExternalPublicationDurableCompletionAttestationBackend,
    FixtureDurableCompletionAttestationBackend, GovernanceDurableCompletionAttestationBackend,
    MainNetDurableCompletionAttestationBackend, ProductionDurableCompletionAttestationBackend,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_completion_attestation_projection::GovernanceModeledDurableCompletionAttestationOutcome;
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

const BACKEND_RECORD_ID: &str = "durable-completion-attestation-backend-0001";
const BACKEND_ID: &str = "fixture-backend-0001";
const DOMAIN_TAG: &str = "QBIND:run256:domain-separation:v1";
const ATTESTATION_ID: &str = "durable-completion-attestation-0001";
const ATTESTATION_DIGEST: &str = "attestation-digest-tttttttttttttttttttt";
const FINALIZATION_DECISION_DIGEST: &str = "finalization-decision-digest-llllllllll";
const REPORTER_DIGEST: &str = "reporter-decision-digest-eeeeeeeeeeeeeeee";
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
    request: DurableCompletionAttestationBackendRequest,
    expectations: DurableCompletionAttestationBackendExpectations,
}

fn identity(
    policy: DurableCompletionAttestationBackendPolicy,
    kind: DurableCompletionAttestationBackendKind,
) -> DurableCompletionAttestationBackendIdentity {
    DurableCompletionAttestationBackendIdentity {
        backend_id: BACKEND_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: DOMAIN_TAG.to_string(),
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionAttestationBackendPolicy,
    kind: DurableCompletionAttestationBackendKind,
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
    let id = identity(policy, kind);
    let request = DurableCompletionAttestationBackendRequest {
        backend_record_id: BACKEND_RECORD_ID.to_string(),
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        governance_surface: ms,
        validation_surface: vs,
        mutation_surface: ms,
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
        sink_decision_digest: SINK_DIGEST.to_string(),
        reporter_decision_digest: REPORTER_DIGEST.to_string(),
        finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        attestation_digest: ATTESTATION_DIGEST.to_string(),
        attestation_id: ATTESTATION_ID.to_string(),
        identity: id.clone(),
        domain_separation_tag: DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionAttestationBackendExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_reporter_decision_digest: REPORTER_DIGEST.to_string(),
        expected_finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        expected_attestation_digest: ATTESTATION_DIGEST.to_string(),
        expected_attestation_id: ATTESTATION_ID.to_string(),
        expected_backend_record_id: BACKEND_RECORD_ID.to_string(),
        expected_identity: id,
        expected_backend_kind: kind,
        expected_backend_policy: policy,
        expected_domain_separation_tag: DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
    }
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionAttestationBackendPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
    ) -> DurableCompletionAttestationBackendInput {
        DurableCompletionAttestationBackendInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            finalization_binding: finalization,
            attestation_binding: attestation,
            request: self.request.clone(),
        }
    }

    /// The canonical "attestor recorded an attestation" wired input.
    fn attested(&self) -> DurableCompletionAttestationBackendInput {
        self.input(
            DurableCompletionAttestationBackendPolicy::FixtureAllowed,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        )
    }

    /// The same wired input but with a Run 254 duplicate-idempotent attestation.
    fn attested_duplicate(&self) -> DurableCompletionAttestationBackendInput {
        self.input(
            DurableCompletionAttestationBackendPolicy::FixtureAllowed,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationDuplicateIdempotent,
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        DurableCompletionAttestationBackendKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        DurableCompletionAttestationBackendKind::FixtureInMemory,
    )
}

fn fixture_backend() -> FixtureDurableCompletionAttestationBackend {
    FixtureDurableCompletionAttestationBackend::new()
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_backend_policy_preserves_legacy_bypass_no_submission_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission
    );
    assert_eq!(backend.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_attestor_policy_preserves_legacy_bypass_never_invokes_backend() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::LegacyBypassNoAttestation,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission
    );
    assert_eq!(backend.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn devnet_fixture_attested_records_exactly_one_backend_submission() {
    let c = devnet_ctx();
    let input = c.attested();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    assert!(backend_outcome_authorizes_durable_attestation_submission(
        &outcome
    ));
    assert!(backend_outcome_projects_to_backend_submission_recorded(
        &outcome
    ));
    assert_eq!(backend.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(BACKEND_RECORD_ID));
}

#[test]
fn testnet_fixture_attested_records_exactly_one_backend_submission() {
    let c = testnet_ctx();
    let input = c.attested();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn duplicate_identical_backend_submission_is_idempotent() {
    let c = devnet_ctx();
    let input = c.attested();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let first = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    let second = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionDuplicateIdempotent
    );
    // Idempotent duplicate is not a new submission.
    assert!(!backend_outcome_authorizes_durable_attestation_submission(
        &second
    ));
    assert!(backend_outcome_projects_to_backend_submission_recorded(
        &second
    ));
    assert_eq!(ledger.len(), 1);
}

#[test]
fn run254_duplicate_idempotent_attestation_matches_existing_only_never_creates() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();

    // A duplicate-idempotent attestation with an empty ledger cannot create a
    // submission by itself.
    let dup = c.attested_duplicate();
    let outcome = evaluate_durable_completion_attestation_backend(
        &dup,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real attestation records, the duplicate-idempotent attestation
    // matches the already-recorded submission.
    let attested = c.attested();
    let recorded = evaluate_durable_completion_attestation_backend(
        &attested,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    let matched = evaluate_durable_completion_attestation_backend(
        &dup,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionDuplicateIdempotent
    );
    assert_eq!(ledger.len(), 1);
}

// ===========================================================================
// Production / MainNet / external-publication unavailable matrix
// ===========================================================================

#[test]
fn production_backend_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAttestationBackendPolicy::ProductionBackendRequired,
        DurableCompletionAttestationBackendKind::ProductionUnavailable,
    );
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::ProductionBackendRequired,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = ProductionDurableCompletionAttestationBackend::default();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::ProductionBackendUnavailableNoSubmission
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_backend_path_reachable_but_unavailable_records_nothing() {
    // Non-peer-driven MainNet surface so the refusal gate does not pre-empt the
    // backend; the backend itself is unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired,
        DurableCompletionAttestationBackendKind::MainNetUnavailable,
    );
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = MainNetDurableCompletionAttestationBackend::default();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::MainNetBackendUnavailableNoSubmission
    );
    assert!(ledger.is_empty());
}

#[test]
fn external_publication_backend_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAttestationBackendPolicy::ProductionBackendRequired,
        DurableCompletionAttestationBackendKind::ExternalPublicationUnavailable,
    );
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::ProductionBackendRequired,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = ExternalPublicationDurableCompletionAttestationBackend::default();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::ExternalPublicationUnavailableNoSubmission
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_backend_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired,
        DurableCompletionAttestationBackendKind::MainNetUnavailable,
    );
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = MainNetDurableCompletionAttestationBackend::default();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(backend.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix
// ===========================================================================

/// Helper: run an attested input but with a non-attesting Run 254 outcome and
/// assert the expected no-backend-submission outcome with zero invocation.
fn assert_non_attesting(
    attestation: GovernanceModeledDurableCompletionAttestationOutcome,
    expected: DurableCompletionAttestationBackendOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation,
    );
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert_eq!(backend.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn non_attesting_attestation_outcomes_never_submit() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    assert_non_attesting(
        Att::RejectedBeforeFinalizationNoAttestation,
        Backend::RejectedBeforeAttestationNoBackendSubmission,
    );
    assert_non_attesting(
        Att::FinalizationDidNotFinalizeNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::DurableCompletionAttestationRejectedBeforeRecord,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::DurableCompletionAttestationRecordFailedNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::DurableCompletionAttestationRolledBackNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::ProductionAttestorUnavailableNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::MainNetAttestorUnavailableNoAttestation,
        Backend::AttestationDidNotAttestNoBackendSubmission,
    );
    assert_non_attesting(
        Att::ValidatorSetRotationUnsupportedNoAttestation,
        Backend::ValidatorSetRotationUnsupportedNoSubmission,
    );
    assert_non_attesting(
        Att::PolicyChangeUnsupportedNoAttestation,
        Backend::PolicyChangeUnsupportedNoSubmission,
    );
}

/// Helper: a binding-mismatch ctx where the expectations differ from the request.
fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.attested();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    // A pre-backend environment/surface mismatch is rejected before the backend is
    // invoked.
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::RejectedBeforeAttestationNoBackendSubmission
    );
    assert_eq!(backend.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_environment_rejected_before_backend_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_backend_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_backend_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_genesis_hash = "genesis-other".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_backend_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_governance_surface =
            GovernanceExecutionRuntimeSurface::ReloadCheck;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_backend_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_mutation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    });
}

/// Helper: a request-identity mismatch where the request differs from the
/// expectations (binding passes, but the backend rejects before record).
fn assert_request_mismatch_rejected(mut mutate: impl FnMut(&mut DurableCompletionAttestationBackendRequest)) {
    let c = devnet_ctx();
    let mut input = c.attested();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRejectedBeforeRecord
    );
    // The backend is invoked (binding matched) but records nothing.
    assert_eq!(backend.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_backend_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_record_id = "other-record".to_string();
    });
}

#[test]
fn wrong_proposal_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.proposal_id = "other-proposal".to_string();
    });
}

#[test]
fn wrong_decision_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.decision_id = "other-decision".to_string();
    });
}

#[test]
fn wrong_candidate_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.candidate_digest = "other-candidate".to_string();
    });
}

#[test]
fn wrong_authority_domain_sequence_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.authority_domain_sequence = SEQUENCE + 1;
    });
}

#[test]
fn wrong_pipeline_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.pipeline_decision_digest = "other-pipeline".to_string();
    });
}

#[test]
fn wrong_sink_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.sink_decision_digest = "other-sink".to_string();
    });
}

#[test]
fn wrong_reporter_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.reporter_decision_digest = "other-reporter".to_string();
    });
}

#[test]
fn wrong_finalization_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.finalization_decision_digest = "other-finalization".to_string();
    });
}

#[test]
fn wrong_attestation_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.attestation_digest = "other-attestation".to_string();
    });
}

#[test]
fn wrong_attestation_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.attestation_id = "other-attestation-id".to_string();
    });
}

#[test]
fn wrong_backend_identity_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.backend_id = "other-backend".to_string();
    });
}

#[test]
fn wrong_backend_policy_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.policy = DurableCompletionAttestationBackendPolicy::ProductionBackendRequired;
    });
}

#[test]
fn wrong_backend_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind = DurableCompletionAttestationBackendKind::ProductionUnavailable;
    });
}

#[test]
fn malformed_backend_request_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.proposal_id = String::new();
    });
}

#[test]
fn same_backend_record_id_different_digest_is_equivocation_no_second_submission() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();

    // Record the first valid submission.
    let first = evaluate_durable_completion_attestation_backend(
        &c.attested(),
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );

    // A second submission with the SAME backend record id but a different
    // attestation digest must fail closed as equivocation, recording no second
    // submission. We must also adjust expectations so binding/request validation
    // passes and the equivocation gate is what rejects it.
    let mut c2 = devnet_ctx();
    c2.request.attestation_digest = "equivocating-attestation-digest".to_string();
    c2.expectations.expected_attestation_digest = "equivocating-attestation-digest".to_string();
    let equivocation = evaluate_durable_completion_attestation_backend(
        &c2.attested(),
        &c2.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRejectedBeforeRecord
    );
    assert_eq!(ledger.len(), 1);
}

// ===========================================================================
// Backend record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_submission(
    fault: DurableCompletionAttestationBackendFault,
    expected: DurableCompletionAttestationBackendOutcome,
) {
    let c = devnet_ctx();
    let input = c.attested();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = FixtureDurableCompletionAttestationBackend::with_fault(fault);
    let outcome = evaluate_durable_completion_attestation_backend(
        &input,
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_backend_submission());
    assert_eq!(backend.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn backend_record_failed_never_submits() {
    assert_fault_no_submission(
        DurableCompletionAttestationBackendFault::RecordFailedNoSubmission,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecordFailedNoSubmission,
    );
}

#[test]
fn backend_rollback_completed_never_submits() {
    assert_fault_no_submission(
        DurableCompletionAttestationBackendFault::RolledBackNoSubmission,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRolledBackNoSubmission,
    );
}

#[test]
fn backend_rollback_failed_fatal_never_submits() {
    assert_fault_no_submission(
        DurableCompletionAttestationBackendFault::RollbackFailedFatal,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRollbackFailedFatalNoSubmission,
    );
}

#[test]
fn backend_ambiguous_window_fails_closed() {
    assert_fault_no_submission(
        DurableCompletionAttestationBackendFault::AmbiguousAfterRecord,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionAmbiguousFailClosedNoSubmission,
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_attested_creates_backend_request_intent() {
    use DurableCompletionAttestationBackendRequestIntent as Intent;
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    assert_eq!(
        project_attestation_outcome_to_backend_request(&Att::DurableCompletionAttested),
        Intent::CreateRequest
    );
    assert!(project_attestation_outcome_to_backend_request(&Att::DurableCompletionAttested)
        .creates_request());
    assert_eq!(
        project_attestation_outcome_to_backend_request(
            &Att::DurableCompletionAttestationDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    // A non-attesting outcome never creates a request.
    assert!(!project_attestation_outcome_to_backend_request(&Att::LegacyBypassNoAttestation)
        .creates_request());
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_record() -> DurableCompletionAttestationBackendLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let _ = evaluate_durable_completion_attestation_backend(
        &c.attested(),
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionAttestationBackendWindow,
    with_record: bool,
    expected: DurableCompletionAttestationBackendOutcome,
) {
    let c = devnet_ctx();
    let input = c.attested();
    let ledger = recovered_record();
    let record = if with_record {
        ledger.find(BACKEND_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_attestation_backend_window(
        &input,
        window,
        DurableCompletionAttestationBackendKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

#[test]
fn pre_attestation_windows_fail_closed_no_submission() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendWindow as Window;
    for w in [
        Window::BeforePipeline,
        Window::AfterPipelineSuccessBeforeSinkIntent,
        Window::AfterSinkIntentBeforeReceiptRecord,
        Window::AfterReceiptRecordBeforeReportIntent,
        Window::AfterReportIntentBeforeReportRecord,
        Window::AfterReportRecordBeforeFinalizationIntent,
        Window::AfterFinalizationIntentBeforeFinalizationRecord,
        Window::AfterFinalizationRecordBeforeAttestationIntent,
        Window::AfterAttestationIntentBeforeAttestationRecord,
    ] {
        assert_window(w, false, Backend::AttestationDidNotAttestNoBackendSubmission);
    }
}

#[test]
fn pre_backend_record_windows_reject_before_record() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendWindow as Window;
    assert_window(
        Window::AfterAttestationRecordBeforeBackendRequest,
        false,
        Backend::BackendSubmissionRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterBackendRequestBeforeBackendRecord,
        false,
        Backend::BackendSubmissionRejectedBeforeRecord,
    );
}

#[test]
fn after_backend_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendWindow as Window;
    // Without an explicit matching record, fails closed.
    assert_window(
        Window::AfterBackendRecordBeforeBackendSuccess,
        false,
        Backend::BackendSubmissionRejectedBeforeRecord,
    );
    // With an explicit matching record, recovers as recorded.
    assert_window(
        Window::AfterBackendRecordBeforeBackendSuccess,
        true,
        Backend::BackendSubmissionRecorded,
    );
}

#[test]
fn after_backend_success_recovers_as_recorded() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendWindow as Window;
    assert_window(
        Window::AfterBackendSuccess,
        true,
        Backend::BackendSubmissionRecorded,
    );
}

#[test]
fn after_backend_ambiguous_and_unknown_fail_closed() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendWindow as Window;
    assert_window(
        Window::AfterBackendAmbiguous,
        false,
        Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
    );
    assert_window(
        Window::Unknown,
        false,
        Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
    );
    assert_window(
        Window::BackendRecordFailed,
        false,
        Backend::BackendSubmissionRecordFailedNoSubmission,
    );
    assert_window(
        Window::BackendRollbackCompleted,
        false,
        Backend::BackendSubmissionRolledBackNoSubmission,
    );
    assert_window(
        Window::BackendRollbackFailed,
        false,
        Backend::BackendSubmissionRollbackFailedFatalNoSubmission,
    );
}

#[test]
fn production_mainnet_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.attested();
    let outcome = recover_durable_completion_attestation_backend_window(
        &input,
        DurableCompletionAttestationBackendWindow::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::ProductionBackendUnavailableNoSubmission
    );
    let outcome = recover_durable_completion_attestation_backend_window(
        &input,
        DurableCompletionAttestationBackendWindow::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::MainNetBackendUnavailableNoSubmission
    );
    let outcome = recover_durable_completion_attestation_backend_window(
        &input,
        DurableCompletionAttestationBackendWindow::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::ExternalPublicationUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::ExternalPublicationUnavailableNoSubmission
    );
}

#[test]
fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired,
        DurableCompletionAttestationBackendKind::MainNetUnavailable,
    );
    let input = c.input(
        DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
    );
    let outcome = recover_durable_completion_attestation_backend_window(
        &input,
        DurableCompletionAttestationBackendWindow::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission
    );
}

// ===========================================================================
// Backend-ledger cases
// ===========================================================================

#[test]
fn rollback_restores_backend_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let _ = evaluate_durable_completion_attestation_backend(
        &c.attested(),
        &c.expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert!(!snapshot.is_empty());

    // A faulted submission rolls back, leaving the prior snapshot intact.
    let mut faulted =
        FixtureDurableCompletionAttestationBackend::with_fault(
            DurableCompletionAttestationBackendFault::RolledBackNoSubmission,
        );
    let mut c2 = devnet_ctx();
    c2.request.backend_record_id = "second-record".to_string();
    c2.expectations.expected_backend_record_id = "second-record".to_string();
    let outcome = evaluate_durable_completion_attestation_backend(
        &c2.attested(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRolledBackNoSubmission
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains("second-record"));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

#[test]
fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_attestation_backend_rejection_is_non_mutating());
    assert!(durable_completion_attestation_backend_never_calls_run_070());
    assert!(durable_completion_attestation_backend_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_attestation_backend_never_writes_sequence_or_marker());
    assert!(durable_completion_attestation_backend_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_attestation_backend_no_external_publication());
    assert!(durable_completion_attestation_backend_no_real_audit_ledger());
    assert!(durable_completion_attestation_backend_pipeline_success_required());
    assert!(durable_completion_attestation_backend_sink_receipt_required());
    assert!(durable_completion_attestation_backend_completion_report_required());
    assert!(durable_completion_attestation_backend_finalization_required());
    assert!(durable_completion_attestation_backend_attestation_required());
    assert!(durable_completion_attestation_backend_record_required_before_submission());
    assert!(durable_completion_attestation_backend_failed_record_never_submits());
    assert!(durable_completion_attestation_backend_rollback_never_submits());
    assert!(durable_completion_attestation_backend_ambiguous_window_fails_closed());
    assert!(durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(durable_completion_attestation_backend_production_mainnet_unavailable());
    assert!(durable_completion_attestation_backend_validator_set_rotation_unsupported());
    assert!(durable_completion_attestation_backend_policy_change_unsupported());
    assert!(durable_completion_attestation_backend_local_operator_cannot_satisfy_mainnet_authority());
    assert!(durable_completion_attestation_backend_peer_majority_cannot_satisfy_mainnet_authority());
}