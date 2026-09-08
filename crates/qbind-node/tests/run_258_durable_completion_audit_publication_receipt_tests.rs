//! Run 258 — source/test durable-completion backend **audit-ledger /
//! external-publication receipt boundary** tests.
//!
//! Source/test only. Run 258 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. These tests prove that the modeled
//! durable-completion audit/publication receipt boundary
//! ([`evaluate_durable_completion_audit_publication_receipt`]) records a modeled
//! in-memory receipt **only** when the Run 256 backend recorded a
//! `BackendSubmissionRecorded`, and that every other backend outcome, every receipt
//! record failure, rollback, rollback-failure, ambiguous receipt window, every
//! production / MainNet audit-ledger / external-publication unavailable / unsupported
//! path, and every rejected binding fails closed with no receipt.
//!
//! The Run 256 backend submission is driven through the **actual** Run 256
//! `evaluate_durable_completion_attestation_backend` path — every recording test
//! attaches the receipt to a real `BackendSubmissionRecorded` outcome and the real
//! Run 256 backend identity / request / response / receipt / transcript digests.
//!
//! Every rejected path is non-mutating and non-recording: no Run 070 call, no
//! `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
//! sequence write, no marker write, no external publication, no real audit-ledger
//! write, and no receipt-sink invocation where the rejection happens before the
//! receipt stage.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_258.md`.

use qbind_node::pqc_governance_durable_completion_attestation_backend::{
    backend_identity_digest, evaluate_durable_completion_attestation_backend,
    DurableCompletionAttestationBackendExpectations, DurableCompletionAttestationBackendIdentity,
    DurableCompletionAttestationBackendInput, DurableCompletionAttestationBackendKind,
    DurableCompletionAttestationBackendLedger, DurableCompletionAttestationBackendOutcome,
    DurableCompletionAttestationBackendPolicy, DurableCompletionAttestationBackendRequest,
    FixtureDurableCompletionAttestationBackend,
};
use qbind_node::pqc_governance_durable_completion_audit_publication_receipt::{
    audit_receipt_outcome_authorizes_receipt_record,
    audit_receipt_outcome_projects_to_audit_receipt_recorded,
    durable_completion_audit_receipt_ambiguous_window_fails_closed,
    durable_completion_audit_receipt_attestation_required,
    durable_completion_audit_receipt_backend_submission_required,
    durable_completion_audit_receipt_completion_report_required,
    durable_completion_audit_receipt_external_publication_unavailable,
    durable_completion_audit_receipt_failed_record_never_records,
    durable_completion_audit_receipt_finalization_required,
    durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first,
    durable_completion_audit_receipt_never_calls_run_070,
    durable_completion_audit_receipt_never_mutates_live_pqc_trust_state,
    durable_completion_audit_receipt_never_writes_sequence_or_marker,
    durable_completion_audit_receipt_no_external_publication,
    durable_completion_audit_receipt_no_real_audit_ledger,
    durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change,
    durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_audit_receipt_pipeline_success_required,
    durable_completion_audit_receipt_policy_change_unsupported,
    durable_completion_audit_receipt_production_mainnet_unavailable,
    durable_completion_audit_receipt_record_required_before_receipt,
    durable_completion_audit_receipt_rejection_is_non_mutating,
    durable_completion_audit_receipt_rollback_never_records,
    durable_completion_audit_receipt_sink_receipt_required,
    durable_completion_audit_receipt_validator_set_rotation_unsupported,
    evaluate_durable_completion_audit_publication_receipt,
    project_backend_submission_outcome_to_audit_receipt_request,
    recover_durable_completion_audit_publication_receipt_window,
    DurableCompletionAuditPublicationReceiptExpectations,
    DurableCompletionAuditPublicationReceiptFault, DurableCompletionAuditPublicationReceiptIdentity,
    DurableCompletionAuditPublicationReceiptInput, DurableCompletionAuditPublicationReceiptKind,
    DurableCompletionAuditPublicationReceiptLedger, DurableCompletionAuditPublicationReceiptOutcome,
    DurableCompletionAuditPublicationReceiptPolicy, DurableCompletionAuditPublicationReceiptRequest,
    DurableCompletionAuditPublicationReceiptRequestIntent,
    DurableCompletionAuditPublicationReceiptWindow,
    ExternalPublicationDurableCompletionReceiptSink,
    FixtureDurableCompletionAuditPublicationReceiptSink,
    GovernanceDurableCompletionAuditPublicationReceiptSink,
    MainNetAuditLedgerDurableCompletionReceiptSink,
    ProductionAuditLedgerDurableCompletionReceiptSink,
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

const RECEIPT_RECORD_ID: &str = "durable-completion-audit-publication-receipt-0001";
const RECEIPT_ID: &str = "fixture-receipt-0001";
const RECEIPT_DOMAIN_TAG: &str = "QBIND:run258:domain-separation:v1";

// Run 256 backend constants (drive the actual backend-submission path).
const BACKEND_RECORD_ID: &str = "durable-completion-attestation-backend-0001";
const BACKEND_ID: &str = "fixture-backend-0001";
const BACKEND_DOMAIN_TAG: &str = "QBIND:run256:domain-separation:v1";

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
// Actual Run 256 backend submission attachment
// ===========================================================================

/// The real Run 256 backend submission digests, captured from an *actual*
/// `evaluate_durable_completion_attestation_backend` round-trip. The receipt is
/// attached to these — never a faked, unattached receipt path.
#[derive(Clone)]
struct AttachedBackend {
    outcome: DurableCompletionAttestationBackendOutcome,
    backend_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    receipt_digest: String,
    transcript_digest: String,
}

/// A per-action backend label distinguishes the modeled governance action so each
/// action records its own backend submission and its own receipt.
struct ActionLabel {
    backend_record_id: String,
    receipt_record_id: String,
    proposal_id: String,
    decision_id: String,
    candidate_digest: String,
}

fn action_label(label: &str) -> ActionLabel {
    ActionLabel {
        backend_record_id: format!("durable-completion-attestation-backend-{label}"),
        receipt_record_id: format!("durable-completion-audit-publication-receipt-{label}"),
        proposal_id: format!("proposal-{label}"),
        decision_id: format!("decision-{label}"),
        candidate_digest: format!("candidate-digest-{label}"),
    }
}

fn default_action() -> ActionLabel {
    ActionLabel {
        backend_record_id: BACKEND_RECORD_ID.to_string(),
        receipt_record_id: RECEIPT_RECORD_ID.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
    }
}

fn run256_backend_identity() -> DurableCompletionAttestationBackendIdentity {
    DurableCompletionAttestationBackendIdentity {
        backend_id: BACKEND_ID.to_string(),
        kind: DurableCompletionAttestationBackendKind::FixtureInMemory,
        policy: DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        domain_separation_tag: BACKEND_DOMAIN_TAG.to_string(),
    }
}

fn run256_request(
    environment: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
    action: &ActionLabel,
) -> DurableCompletionAttestationBackendRequest {
    DurableCompletionAttestationBackendRequest {
        backend_record_id: action.backend_record_id.clone(),
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        governance_surface: surface,
        validation_surface: surface,
        mutation_surface: surface,
        proposal_id: action.proposal_id.clone(),
        decision_id: action.decision_id.clone(),
        candidate_digest: action.candidate_digest.clone(),
        authority_domain_sequence: SEQUENCE,
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
        sink_decision_digest: SINK_DIGEST.to_string(),
        reporter_decision_digest: REPORTER_DIGEST.to_string(),
        finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        attestation_digest: ATTESTATION_DIGEST.to_string(),
        attestation_id: ATTESTATION_ID.to_string(),
        identity: run256_backend_identity(),
        domain_separation_tag: BACKEND_DOMAIN_TAG.to_string(),
    }
}

fn run256_expectations(
    environment: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
    action: &ActionLabel,
) -> DurableCompletionAttestationBackendExpectations {
    DurableCompletionAttestationBackendExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: surface,
        expected_validation_surface: surface,
        expected_mutation_surface: surface,
        expected_proposal_id: action.proposal_id.clone(),
        expected_decision_id: action.decision_id.clone(),
        expected_candidate_digest: action.candidate_digest.clone(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_reporter_decision_digest: REPORTER_DIGEST.to_string(),
        expected_finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        expected_attestation_digest: ATTESTATION_DIGEST.to_string(),
        expected_attestation_id: ATTESTATION_ID.to_string(),
        expected_backend_record_id: action.backend_record_id.clone(),
        expected_identity: run256_backend_identity(),
        expected_backend_kind: DurableCompletionAttestationBackendKind::FixtureInMemory,
        expected_backend_policy: DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        expected_domain_separation_tag: BACKEND_DOMAIN_TAG.to_string(),
    }
}

fn run256_input(
    environment: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
    action: &ActionLabel,
) -> DurableCompletionAttestationBackendInput {
    DurableCompletionAttestationBackendInput {
        policy: DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        environment_binding: ModeledGovernanceTrustMutationEnvironmentBinding {
            environment,
            chain_id: CHAIN.to_string(),
            genesis_hash: GENESIS.to_string(),
        },
        runtime_binding: ModeledGovernanceTrustMutationRuntimeBinding {
            governance_surface: surface,
            mutation_surface: ModeledGovernanceTrustMutationSurface {
                validation_surface: surface,
                mutation_surface: surface,
            },
            authority_domain_sequence: SEQUENCE,
        },
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        finalization_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        request: run256_request(environment, surface, action),
    }
}

/// Drive the actual Run 256 backend submission path and capture its real digests.
/// `duplicate` records once and then re-evaluates to obtain the real
/// `BackendSubmissionDuplicateIdempotent` outcome (the digests are identical).
fn attach_run256_backend(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    duplicate: bool,
) -> AttachedBackend {
    // The fixture Run 256 backend records only under DevNet/TestNet. MainNet
    // receipt-environment cases use a refusal backend binding and never reach here.
    let backend_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let input = run256_input(backend_env, surface, action);
    let expectations = run256_expectations(backend_env, surface, action);
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = FixtureDurableCompletionAttestationBackend::new();

    let first = evaluate_durable_completion_attestation_backend(
        &input,
        &expectations,
        &mut backend,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded,
        "Run 256 backend submission must record for attachment"
    );

    let outcome = if duplicate {
        let second = evaluate_durable_completion_attestation_backend(
            &input,
            &expectations,
            &mut backend,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionDuplicateIdempotent
        );
        second
    } else {
        first
    };

    let record = ledger
        .find(&action.backend_record_id)
        .expect("recorded backend submission");
    AttachedBackend {
        outcome,
        backend_record_id: action.backend_record_id.clone(),
        identity_digest: backend_identity_digest(&run256_backend_identity())
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        receipt_digest: record.receipt_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
    }
}

// ===========================================================================
// Run 258 owned-context builder
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    request: DurableCompletionAuditPublicationReceiptRequest,
    expectations: DurableCompletionAuditPublicationReceiptExpectations,
    backend: AttachedBackend,
}

fn receipt_identity(
    policy: DurableCompletionAuditPublicationReceiptPolicy,
    kind: DurableCompletionAuditPublicationReceiptKind,
) -> DurableCompletionAuditPublicationReceiptIdentity {
    DurableCompletionAuditPublicationReceiptIdentity {
        receipt_id: RECEIPT_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: RECEIPT_DOMAIN_TAG.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ctx_action(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionAuditPublicationReceiptPolicy,
    kind: DurableCompletionAuditPublicationReceiptKind,
    action: &ActionLabel,
    duplicate: bool,
) -> Ctx {
    let backend = attach_run256_backend(environment, action, duplicate);
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
    let id = receipt_identity(policy, kind);
    let request = DurableCompletionAuditPublicationReceiptRequest {
        receipt_record_id: action.receipt_record_id.clone(),
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        governance_surface: ms,
        validation_surface: vs,
        mutation_surface: ms,
        proposal_id: action.proposal_id.clone(),
        decision_id: action.decision_id.clone(),
        candidate_digest: action.candidate_digest.clone(),
        authority_domain_sequence: SEQUENCE,
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
        sink_decision_digest: SINK_DIGEST.to_string(),
        reporter_decision_digest: REPORTER_DIGEST.to_string(),
        finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        attestation_digest: ATTESTATION_DIGEST.to_string(),
        attestation_id: ATTESTATION_ID.to_string(),
        backend_identity_digest: backend.identity_digest.clone(),
        backend_request_digest: backend.request_digest.clone(),
        backend_response_digest: backend.response_digest.clone(),
        backend_receipt_digest: backend.receipt_digest.clone(),
        backend_transcript_digest: backend.transcript_digest.clone(),
        backend_record_id: backend.backend_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: RECEIPT_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionAuditPublicationReceiptExpectations {
        expected_receipt_record_id: action.receipt_record_id.clone(),
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_proposal_id: action.proposal_id.clone(),
        expected_decision_id: action.decision_id.clone(),
        expected_candidate_digest: action.candidate_digest.clone(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_reporter_decision_digest: REPORTER_DIGEST.to_string(),
        expected_finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        expected_attestation_digest: ATTESTATION_DIGEST.to_string(),
        expected_attestation_id: ATTESTATION_ID.to_string(),
        expected_backend_identity_digest: backend.identity_digest.clone(),
        expected_backend_request_digest: backend.request_digest.clone(),
        expected_backend_response_digest: backend.response_digest.clone(),
        expected_backend_receipt_digest: backend.receipt_digest.clone(),
        expected_backend_transcript_digest: backend.transcript_digest.clone(),
        expected_backend_record_id: backend.backend_record_id.clone(),
        expected_identity: id,
        expected_receipt_kind: kind,
        expected_receipt_policy: policy,
        expected_domain_separation_tag: RECEIPT_DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
        backend,
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionAuditPublicationReceiptPolicy,
    kind: DurableCompletionAuditPublicationReceiptKind,
) -> Ctx {
    ctx_action(environment, vs, ms, policy, kind, &default_action(), false)
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionAuditPublicationReceiptPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
    ) -> DurableCompletionAuditPublicationReceiptInput {
        DurableCompletionAuditPublicationReceiptInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            finalization_binding: finalization,
            attestation_binding: attestation,
            backend_binding: backend,
            request: self.request.clone(),
        }
    }

    /// The canonical "backend recorded a submission" wired input, attached to the
    /// real Run 256 `BackendSubmissionRecorded` outcome.
    fn recorded(&self) -> DurableCompletionAuditPublicationReceiptInput {
        self.input(
            self.request.identity.policy,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
            self.backend.outcome.clone(),
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
    )
}

fn fixture_sink() -> FixtureDurableCompletionAuditPublicationReceiptSink {
    FixtureDurableCompletionAuditPublicationReceiptSink::new()
}

// ===========================================================================
// Accepted / compatible matrix
// ===========================================================================

#[test]
fn disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.backend.outcome.clone(),
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::LegacyBypassNoAuditReceipt
    );
    assert!(outcome.is_legacy_bypass());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_backend_policy_never_invokes_receipt_sink() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::LegacyBypassNoAuditReceipt
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission() {
    let c = devnet_ctx();
    let input = c.recorded();
    // The receipt is attached to the actual Run 256 BackendSubmissionRecorded path.
    assert_eq!(
        c.backend.outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded
    );
    assert!(audit_receipt_outcome_authorizes_receipt_record(&outcome));
    assert!(audit_receipt_outcome_projects_to_audit_receipt_recorded(
        &outcome
    ));
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(RECEIPT_RECORD_ID));
}

#[test]
fn testnet_fixture_chain_records_exactly_one_receipt() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn governance_action_variants_record_only_after_backend_submission() {
    // Each modeled governance action (add-root / retire-root / revoke-root /
    // emergency-revoke-root / noop) drives its own real Run 256 backend submission
    // and records exactly one receipt, in order, only after backend submission.
    for label in [
        "add-root",
        "retire-root",
        "revoke-root",
        "emergency-revoke-root",
        "noop",
    ] {
        let action = action_label(label);
        let c = ctx_action(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
            DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
            &action,
            false,
        );
        assert_eq!(
            c.backend.outcome,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let outcome = evaluate_durable_completion_audit_publication_receipt(
            &c.recorded(),
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            outcome,
            DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded,
            "action {label} must record after backend submission"
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&action.receipt_record_id));
    }
}

#[test]
fn duplicate_identical_receipt_is_idempotent() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let first = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded
    );
    let second = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent
    );
    assert!(!audit_receipt_outcome_authorizes_receipt_record(&second));
    assert!(audit_receipt_outcome_projects_to_audit_receipt_recorded(
        &second
    ));
    assert_eq!(ledger.len(), 1);
}

#[test]
fn run256_duplicate_idempotent_backend_only_matches_existing_never_creates() {
    // A real Run 256 BackendSubmissionDuplicateIdempotent outcome with identical
    // digests.
    let dup_ctx = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        &default_action(),
        true,
    );
    assert_eq!(
        dup_ctx.backend.outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionDuplicateIdempotent
    );

    // With no prior receipt, a duplicate-idempotent backend cannot create one.
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real receipt records, the duplicate-idempotent backend matches it.
    let rec_ctx = devnet_ctx();
    let recorded = evaluate_durable_completion_audit_publication_receipt(
        &rec_ctx.recorded(),
        &rec_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded
    );
    let matched = evaluate_durable_completion_audit_publication_receipt(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent
    );
    assert_eq!(ledger.len(), 1);
}

// ===========================================================================
// Production / MainNet audit-ledger / external-publication unavailable matrix
// ===========================================================================

#[test]
fn production_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::ProductionAuditLedgerRequired,
        DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = ProductionAuditLedgerDurableCompletionReceiptSink::default();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::ProductionAuditLedgerUnavailableNoReceipt
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = MainNetAuditLedgerDurableCompletionReceiptSink::default();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::MainNetAuditLedgerUnavailableNoReceipt
    );
    assert!(ledger.is_empty());
}

#[test]
fn external_publication_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::ExternalPublicationRequired,
        DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = ExternalPublicationDurableCompletionReceiptSink::default();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::ExternalPublicationUnavailableNoReceipt
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_receipt_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
    );
    let input = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = MainNetAuditLedgerDurableCompletionReceiptSink::default();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::MainNetPeerDrivenApplyRefusedNoReceipt
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_and_policy_change_unsupported() {
    let c = devnet_ctx();
    let rotation = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::ValidatorSetRotationUnsupportedNoSubmission,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &rotation,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::ValidatorSetRotationUnsupportedNoReceipt
    );
    assert_eq!(sink.invocations(), 0);

    let policy_change = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::PolicyChangeUnsupportedNoSubmission,
    );
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &policy_change,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::PolicyChangeUnsupportedNoReceipt
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — non-submitting backend outcomes
// ===========================================================================

/// Run an otherwise-valid receipt input but with a non-submitting Run 256 backend
/// outcome and assert the expected no-receipt outcome with zero sink invocation.
fn assert_non_submitting(
    backend: DurableCompletionAttestationBackendOutcome,
    expected: DurableCompletionAuditPublicationReceiptOutcome,
) {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_audit_receipt());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn non_submitting_backend_outcomes_never_record_receipt() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    assert_non_submitting(
        Backend::RejectedBeforeAttestationNoBackendSubmission,
        Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::AttestationDidNotAttestNoBackendSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::BackendSubmissionRejectedBeforeRecord,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::BackendSubmissionRecordFailedNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::BackendSubmissionRolledBackNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::BackendSubmissionRollbackFailedFatalNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::ProductionBackendUnavailableNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::MainNetBackendUnavailableNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::ExternalPublicationUnavailableNoSubmission,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
    );
    assert_non_submitting(
        Backend::ValidatorSetRotationUnsupportedNoSubmission,
        Receipt::ValidatorSetRotationUnsupportedNoReceipt,
    );
    assert_non_submitting(
        Backend::PolicyChangeUnsupportedNoSubmission,
        Receipt::PolicyChangeUnsupportedNoReceipt,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — binding mismatch (before sink invocation)
// ===========================================================================

fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::RejectedBeforeBackendSubmissionNoAuditReceipt
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_environment_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_environment = TrustBundleEnvironment::Testnet;
    });
}

#[test]
fn wrong_chain_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_chain_id = "qbind-other".to_string();
    });
}

#[test]
fn wrong_genesis_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_genesis_hash = "genesis-other".to_string();
    });
}

#[test]
fn wrong_governance_surface_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_governance_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    });
}

#[test]
fn wrong_mutation_surface_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_mutation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    });
}

// ===========================================================================
// Rejected / fail-closed matrix — request-identity mismatch (inside sink)
// ===========================================================================

fn assert_request_mismatch_rejected(
    mut mutate: impl FnMut(&mut DurableCompletionAuditPublicationReceiptRequest),
) {
    let c = devnet_ctx();
    let mut input = c.recorded();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRejectedBeforeRecord
    );
    // The sink is invoked (binding matched) but records nothing.
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_receipt_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.receipt_record_id = "other-receipt".to_string();
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
fn wrong_backend_identity_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_identity_digest = "other-backend-identity".to_string();
    });
}

#[test]
fn wrong_backend_request_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_request_digest = "other-backend-request".to_string();
    });
}

#[test]
fn wrong_backend_response_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_response_digest = "other-backend-response".to_string();
    });
}

#[test]
fn wrong_backend_receipt_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_receipt_digest = "other-backend-receipt".to_string();
    });
}

#[test]
fn wrong_backend_transcript_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_transcript_digest = "other-backend-transcript".to_string();
    });
}

#[test]
fn wrong_backend_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_record_id = "other-backend-record".to_string();
    });
}

#[test]
fn wrong_receipt_identity_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.receipt_id = "other-receipt-id".to_string();
    });
}

#[test]
fn wrong_receipt_policy_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.policy =
            DurableCompletionAuditPublicationReceiptPolicy::ProductionAuditLedgerRequired;
    });
}

#[test]
fn wrong_receipt_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind = DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable;
    });
}

#[test]
fn wrong_domain_separation_tag_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.domain_separation_tag = "other-domain".to_string();
    });
}

#[test]
fn malformed_receipt_request_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.proposal_id = String::new();
    });
}

#[test]
fn same_receipt_record_id_different_digest_is_equivocation_no_second_receipt() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();

    let first = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded
    );

    // A second receipt with the SAME receipt record id but a differing digest fails
    // closed as equivocation. We adjust both request and expectations on a differing
    // field so binding/request validation passes and the equivocation gate rejects.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
    let equivocation = evaluate_durable_completion_audit_publication_receipt(
        &c2.recorded(),
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRejectedBeforeRecord
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn fixture_sink_rejects_non_devnet_testnet_environment() {
    // A MainNet, non-peer-driven environment reaches the fixture sink (binding
    // matches) but the fixture sink is DevNet/TestNet evidence-only and rejects.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
    );
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRejectedBeforeRecord
    );
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Receipt record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_receipt(
    fault: DurableCompletionAuditPublicationReceiptFault,
    expected: DurableCompletionAuditPublicationReceiptOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = FixtureDurableCompletionAuditPublicationReceiptSink::with_fault(fault);
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_audit_receipt());
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn receipt_record_failed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionAuditPublicationReceiptFault::RecordFailedNoReceipt,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecordFailedNoReceipt,
    );
}

#[test]
fn receipt_rollback_completed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionAuditPublicationReceiptFault::RolledBackNoReceipt,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRolledBackNoReceipt,
    );
}

#[test]
fn receipt_rollback_failed_fatal_never_records() {
    assert_fault_no_receipt(
        DurableCompletionAuditPublicationReceiptFault::RollbackFailedFatal,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRollbackFailedFatalNoReceipt,
    );
}

#[test]
fn receipt_ambiguous_window_fails_closed() {
    assert_fault_no_receipt(
        DurableCompletionAuditPublicationReceiptFault::AmbiguousAfterRecord,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptAmbiguousFailClosedNoReceipt,
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_backend_submission_creates_receipt_request_intent() {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAuditPublicationReceiptRequestIntent as Intent;
    assert_eq!(
        project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::BackendSubmissionRecorded
        ),
        Intent::CreateRequest
    );
    assert!(project_backend_submission_outcome_to_audit_receipt_request(
        &Backend::BackendSubmissionRecorded
    )
    .creates_request());
    assert_eq!(
        project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::BackendSubmissionDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    // A non-submitting backend outcome never creates a request.
    assert!(!project_backend_submission_outcome_to_audit_receipt_request(
        &Backend::LegacyBypassNoBackendSubmission
    )
    .creates_request());
}

#[test]
fn pipeline_sink_reporter_finalization_attestation_backend_request_alone_create_no_receipt_request()
{
    // Only the *terminal* Run 256 backend outcome drives the receipt projection;
    // upstream successes that did not terminate in a backend submission never create
    // a receipt request. A non-submitting backend outcome maps to NoAuditReceipt.
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAuditPublicationReceiptRequestIntent as Intent;
    for backend in [
        Backend::LegacyBypassNoBackendSubmission,
        Backend::RejectedBeforeAttestationNoBackendSubmission,
        Backend::AttestationDidNotAttestNoBackendSubmission,
        Backend::BackendSubmissionRejectedBeforeRecord,
        Backend::BackendSubmissionRecordFailedNoSubmission,
        Backend::ProductionBackendUnavailableNoSubmission,
    ] {
        assert!(matches!(
            project_backend_submission_outcome_to_audit_receipt_request(&backend),
            Intent::NoAuditReceipt(_)
        ));
    }
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_ledger() -> DurableCompletionAuditPublicationReceiptLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionAuditPublicationReceiptWindow,
    with_record: bool,
    expected: DurableCompletionAuditPublicationReceiptOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(RECEIPT_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_audit_publication_receipt_window(
        &input,
        window,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

#[test]
fn pre_backend_success_windows_fail_closed_no_receipt() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptWindow as Window;
    for w in [
        Window::BeforePipeline,
        Window::AfterPipelineSuccessBeforeSinkIntent,
        Window::AfterSinkIntentBeforeSinkReceiptRecord,
        Window::AfterSinkReceiptRecordBeforeReportIntent,
        Window::AfterReportIntentBeforeReportRecord,
        Window::AfterReportRecordBeforeFinalizationIntent,
        Window::AfterFinalizationIntentBeforeFinalizationRecord,
        Window::AfterFinalizationRecordBeforeAttestationIntent,
        Window::AfterAttestationIntentBeforeAttestationRecord,
        Window::AfterAttestationRecordBeforeBackendRequest,
        Window::AfterBackendRequestBeforeBackendRecord,
        Window::AfterBackendRecordBeforeBackendSuccess,
    ] {
        assert_window(w, false, Receipt::BackendDidNotSubmitNoAuditReceipt);
    }
}

#[test]
fn after_backend_success_before_receipt_request_and_record_reject_before_record() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptWindow as Window;
    assert_window(
        Window::AfterBackendSuccessBeforeReceiptRequest,
        false,
        Receipt::AuditReceiptRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterReceiptRequestBeforeReceiptRecord,
        false,
        Receipt::AuditReceiptRejectedBeforeRecord,
    );
}

#[test]
fn after_receipt_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptWindow as Window;
    assert_window(
        Window::AfterReceiptRecordBeforeReceiptSuccess,
        false,
        Receipt::AuditReceiptRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterReceiptRecordBeforeReceiptSuccess,
        true,
        Receipt::AuditReceiptRecorded,
    );
}

#[test]
fn after_receipt_success_recovers_as_recorded() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptWindow as Window;
    assert_window(Window::AfterReceiptSuccess, true, Receipt::AuditReceiptRecorded);
    // Without an explicit matching record, even after-success fails closed.
    assert_window(
        Window::AfterReceiptSuccess,
        false,
        Receipt::AuditReceiptRejectedBeforeRecord,
    );
}

#[test]
fn ambiguous_record_failed_rollback_and_unknown_windows_fail_closed() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptWindow as Window;
    assert_window(
        Window::AfterReceiptAmbiguous,
        false,
        Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
    );
    assert_window(
        Window::Unknown,
        false,
        Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
    );
    assert_window(
        Window::ReceiptRecordFailed,
        false,
        Receipt::AuditReceiptRecordFailedNoReceipt,
    );
    assert_window(
        Window::ReceiptRollbackCompleted,
        false,
        Receipt::AuditReceiptRolledBackNoReceipt,
    );
    assert_window(
        Window::ReceiptRollbackFailed,
        false,
        Receipt::AuditReceiptRollbackFailedFatalNoReceipt,
    );
}

#[test]
fn production_mainnet_external_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_durable_completion_audit_publication_receipt_window(
        &input,
        DurableCompletionAuditPublicationReceiptWindow::AfterReceiptSuccess,
        DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::ProductionAuditLedgerUnavailableNoReceipt
    );
    let outcome = recover_durable_completion_audit_publication_receipt_window(
        &input,
        DurableCompletionAuditPublicationReceiptWindow::AfterReceiptSuccess,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::MainNetAuditLedgerUnavailableNoReceipt
    );
    let outcome = recover_durable_completion_audit_publication_receipt_window(
        &input,
        DurableCompletionAuditPublicationReceiptWindow::AfterReceiptSuccess,
        DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::ExternalPublicationUnavailableNoReceipt
    );
}

#[test]
fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
    );
    let input = c.input(
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let outcome = recover_durable_completion_audit_publication_receipt_window(
        &input,
        DurableCompletionAuditPublicationReceiptWindow::AfterReceiptSuccess,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::MainNetPeerDrivenApplyRefusedNoReceipt
    );
}

// ===========================================================================
// Receipt-ledger cases
// ===========================================================================

#[test]
fn rollback_restores_receipt_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_audit_publication_receipt(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(ledger.len(), 1);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert!(!snapshot.is_empty());

    // A faulted receipt rolls back, leaving the prior snapshot intact.
    let action = action_label("second-receipt");
    let c2 = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        &action,
        false,
    );
    let mut faulted = FixtureDurableCompletionAuditPublicationReceiptSink::with_fault(
        DurableCompletionAuditPublicationReceiptFault::RolledBackNoReceipt,
    );
    let outcome = evaluate_durable_completion_audit_publication_receipt(
        &c2.recorded(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRolledBackNoReceipt
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains(&action.receipt_record_id));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

#[test]
fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_audit_receipt_rejection_is_non_mutating());
    assert!(durable_completion_audit_receipt_never_calls_run_070());
    assert!(durable_completion_audit_receipt_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_audit_receipt_never_writes_sequence_or_marker());
    assert!(durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_audit_receipt_no_external_publication());
    assert!(durable_completion_audit_receipt_no_real_audit_ledger());
    assert!(durable_completion_audit_receipt_pipeline_success_required());
    assert!(durable_completion_audit_receipt_sink_receipt_required());
    assert!(durable_completion_audit_receipt_completion_report_required());
    assert!(durable_completion_audit_receipt_finalization_required());
    assert!(durable_completion_audit_receipt_attestation_required());
    assert!(durable_completion_audit_receipt_backend_submission_required());
    assert!(durable_completion_audit_receipt_record_required_before_receipt());
    assert!(durable_completion_audit_receipt_failed_record_never_records());
    assert!(durable_completion_audit_receipt_rollback_never_records());
    assert!(durable_completion_audit_receipt_ambiguous_window_fails_closed());
    assert!(durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first(
        TrustBundleEnvironment::Devnet
    ));
    assert!(durable_completion_audit_receipt_production_mainnet_unavailable());
    assert!(durable_completion_audit_receipt_external_publication_unavailable());
    assert!(durable_completion_audit_receipt_validator_set_rotation_unsupported());
    assert!(durable_completion_audit_receipt_policy_change_unsupported());
    assert!(durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority());
    assert!(durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority());
}