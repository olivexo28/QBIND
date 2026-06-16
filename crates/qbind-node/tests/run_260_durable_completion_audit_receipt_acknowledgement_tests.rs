//! Run 260 — source/test durable-completion audit-receipt acknowledgement tests.
//!
//! Mirrors Run 258 while driving the real Run 256 backend submission and the real
//! Run 258 audit/publication receipt before evaluating the Run 260 acknowledgement.

use qbind_node::pqc_governance_durable_completion_attestation_backend::{
    backend_identity_digest, evaluate_durable_completion_attestation_backend,
    DurableCompletionAttestationBackendExpectations, DurableCompletionAttestationBackendIdentity,
    DurableCompletionAttestationBackendInput, DurableCompletionAttestationBackendKind,
    DurableCompletionAttestationBackendLedger, DurableCompletionAttestationBackendOutcome,
    DurableCompletionAttestationBackendPolicy, DurableCompletionAttestationBackendRequest,
    FixtureDurableCompletionAttestationBackend,
};
use qbind_node::pqc_governance_durable_completion_audit_publication_receipt::{
    evaluate_durable_completion_audit_publication_receipt, receipt_identity_digest,
    DurableCompletionAuditPublicationReceiptExpectations,
    DurableCompletionAuditPublicationReceiptIdentity,
    DurableCompletionAuditPublicationReceiptInput, DurableCompletionAuditPublicationReceiptKind,
    DurableCompletionAuditPublicationReceiptLedger,
    DurableCompletionAuditPublicationReceiptOutcome,
    DurableCompletionAuditPublicationReceiptPolicy,
    DurableCompletionAuditPublicationReceiptRequest,
    FixtureDurableCompletionAuditPublicationReceiptSink,
};
use qbind_node::pqc_governance_durable_completion_audit_receipt_acknowledgement::{
    acknowledgement_identity_digest, acknowledgement_outcome_authorizes_acknowledgement_record,
    acknowledgement_outcome_projects_to_acknowledgement_recorded,
    durable_completion_audit_ack_ambiguous_window_fails_closed,
    durable_completion_audit_ack_attestation_required,
    durable_completion_audit_ack_backend_submission_required,
    durable_completion_audit_ack_completion_report_required,
    durable_completion_audit_ack_external_confirmation_unavailable,
    durable_completion_audit_ack_failed_record_never_records,
    durable_completion_audit_ack_finalization_required,
    durable_completion_audit_ack_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first,
    durable_completion_audit_ack_never_calls_run_070,
    durable_completion_audit_ack_never_mutates_live_pqc_trust_state,
    durable_completion_audit_ack_never_writes_sequence_or_marker,
    durable_completion_audit_ack_no_external_publication,
    durable_completion_audit_ack_no_real_audit_ledger,
    durable_completion_audit_ack_no_rocksdb_file_schema_migration_change,
    durable_completion_audit_ack_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_audit_ack_pipeline_success_required,
    durable_completion_audit_ack_policy_change_unsupported,
    durable_completion_audit_ack_production_mainnet_unavailable,
    durable_completion_audit_ack_receipt_required,
    durable_completion_audit_ack_record_required_before_ack,
    durable_completion_audit_ack_rejection_is_non_mutating,
    durable_completion_audit_ack_rollback_never_records,
    durable_completion_audit_ack_sink_receipt_required,
    durable_completion_audit_ack_validator_set_rotation_unsupported,
    evaluate_durable_completion_audit_receipt_acknowledgement,
    project_audit_receipt_outcome_to_acknowledgement_request,
    recover_durable_completion_audit_receipt_acknowledgement_window,
    DurableCompletionAuditReceiptAcknowledgementExpectations,
    DurableCompletionAuditReceiptAcknowledgementFault,
    DurableCompletionAuditReceiptAcknowledgementIdentity,
    DurableCompletionAuditReceiptAcknowledgementInput,
    DurableCompletionAuditReceiptAcknowledgementKind,
    DurableCompletionAuditReceiptAcknowledgementLedger,
    DurableCompletionAuditReceiptAcknowledgementOutcome,
    DurableCompletionAuditReceiptAcknowledgementPolicy,
    DurableCompletionAuditReceiptAcknowledgementRequest,
    DurableCompletionAuditReceiptAcknowledgementRequestIntent,
    DurableCompletionAuditReceiptAcknowledgementWindow,
    ExternalPublicationDurableCompletionConfirmationSink,
    FixtureDurableCompletionAuditReceiptAcknowledgementSink,
    GovernanceDurableCompletionAuditReceiptAcknowledgementSink,
    MainNetAuditLedgerDurableCompletionAcknowledgementSink,
    ProductionAuditLedgerDurableCompletionAcknowledgementSink,
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

const RECEIPT258_RECORD_ID: &str = "durable-completion-audit-publication-receipt-0001";
const RECEIPT258_ID: &str = "fixture-receipt-0001";
const RECEIPT258_DOMAIN_TAG: &str = "QBIND:run258:domain-separation:v1";
const ACK_RECORD_ID: &str = "durable-completion-audit-receipt-acknowledgement-0001";
const ACK_ID: &str = "fixture-acknowledgement-0001";
const ACK_DOMAIN_TAG: &str = "QBIND:run260:domain-separation:v1";
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

/// A per-action label distinguishes each modeled governance action and all three records.
struct ActionLabel {
    backend_record_id: String,
    receipt_record_id: String,
    ack_record_id: String,
    proposal_id: String,
    decision_id: String,
    candidate_digest: String,
}

fn action_label(label: &str) -> ActionLabel {
    ActionLabel {
        backend_record_id: format!("durable-completion-attestation-backend-{label}"),
        receipt_record_id: format!("durable-completion-audit-publication-receipt-{label}"),
        ack_record_id: format!("durable-completion-audit-receipt-acknowledgement-{label}"),
        proposal_id: format!("proposal-{label}"),
        decision_id: format!("decision-{label}"),
        candidate_digest: format!("candidate-digest-{label}"),
    }
}

fn default_action() -> ActionLabel {
    ActionLabel {
        backend_record_id: BACKEND_RECORD_ID.to_string(),
        receipt_record_id: RECEIPT258_RECORD_ID.to_string(),
        ack_record_id: ACK_RECORD_ID.to_string(),
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
// Actual Run 258 receipt attachment
// ===========================================================================

#[derive(Clone)]
struct AttachedReceipt {
    outcome: DurableCompletionAuditPublicationReceiptOutcome,
    receipt_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    backend: AttachedBackend,
}

fn run258_receipt_identity() -> DurableCompletionAuditPublicationReceiptIdentity {
    DurableCompletionAuditPublicationReceiptIdentity {
        receipt_id: RECEIPT258_ID.to_string(),
        kind: DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        policy: DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        domain_separation_tag: RECEIPT258_DOMAIN_TAG.to_string(),
    }
}

fn attach_run258_receipt(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    receipt_duplicate: bool,
) -> AttachedReceipt {
    let backend = attach_run256_backend(environment, action, false);
    let receipt_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: receipt_env,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let runtime = ModeledGovernanceTrustMutationRuntimeBinding {
        governance_surface: surface,
        mutation_surface: ModeledGovernanceTrustMutationSurface {
            validation_surface: surface,
            mutation_surface: surface,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let id = run258_receipt_identity();
    let request = DurableCompletionAuditPublicationReceiptRequest {
        receipt_record_id: action.receipt_record_id.clone(),
        environment: receipt_env,
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
        backend_identity_digest: backend.identity_digest.clone(),
        backend_request_digest: backend.request_digest.clone(),
        backend_response_digest: backend.response_digest.clone(),
        backend_receipt_digest: backend.receipt_digest.clone(),
        backend_transcript_digest: backend.transcript_digest.clone(),
        backend_record_id: backend.backend_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: RECEIPT258_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionAuditPublicationReceiptExpectations {
        expected_receipt_record_id: action.receipt_record_id.clone(),
        expected_environment: receipt_env,
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
        expected_backend_identity_digest: backend.identity_digest.clone(),
        expected_backend_request_digest: backend.request_digest.clone(),
        expected_backend_response_digest: backend.response_digest.clone(),
        expected_backend_receipt_digest: backend.receipt_digest.clone(),
        expected_backend_transcript_digest: backend.transcript_digest.clone(),
        expected_backend_record_id: backend.backend_record_id.clone(),
        expected_identity: id.clone(),
        expected_receipt_kind: DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        expected_receipt_policy: DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        expected_domain_separation_tag: RECEIPT258_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionAuditPublicationReceiptInput {
        policy: DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding: GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding: GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        finalization_binding: GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding: GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: backend.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = FixtureDurableCompletionAuditPublicationReceiptSink::new();
    let first = evaluate_durable_completion_audit_publication_receipt(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded
    );
    let outcome = if receipt_duplicate {
        let second = evaluate_durable_completion_audit_publication_receipt(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.receipt_record_id)
        .expect("recorded Run 258 receipt");
    AttachedReceipt {
        outcome,
        receipt_record_id: action.receipt_record_id.clone(),
        identity_digest: receipt_identity_digest(&id).as_hex().to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        backend,
    }
}

// ===========================================================================
// Run 260 owned-context builder
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    request: DurableCompletionAuditReceiptAcknowledgementRequest,
    expectations: DurableCompletionAuditReceiptAcknowledgementExpectations,
    receipt: AttachedReceipt,
}

fn ack_identity(
    policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
    kind: DurableCompletionAuditReceiptAcknowledgementKind,
) -> DurableCompletionAuditReceiptAcknowledgementIdentity {
    DurableCompletionAuditReceiptAcknowledgementIdentity {
        acknowledgement_id: ACK_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: ACK_DOMAIN_TAG.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ctx_action(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
    kind: DurableCompletionAuditReceiptAcknowledgementKind,
    action: &ActionLabel,
    receipt_duplicate: bool,
) -> Ctx {
    let receipt = attach_run258_receipt(environment, action, receipt_duplicate);
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
    let id = ack_identity(policy, kind);
    let request = DurableCompletionAuditReceiptAcknowledgementRequest {
        acknowledgement_record_id: action.ack_record_id.clone(),
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
        backend_identity_digest: receipt.backend.identity_digest.clone(),
        backend_request_digest: receipt.backend.request_digest.clone(),
        backend_response_digest: receipt.backend.response_digest.clone(),
        backend_receipt_digest: receipt.backend.receipt_digest.clone(),
        backend_transcript_digest: receipt.backend.transcript_digest.clone(),
        backend_record_id: receipt.backend.backend_record_id.clone(),
        receipt_identity_digest: receipt.identity_digest.clone(),
        receipt_request_digest: receipt.request_digest.clone(),
        receipt_response_digest: receipt.response_digest.clone(),
        receipt_record_digest: receipt.record_digest.clone(),
        receipt_transcript_digest: receipt.transcript_digest.clone(),
        receipt_record_id: receipt.receipt_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: ACK_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionAuditReceiptAcknowledgementExpectations {
        expected_acknowledgement_record_id: action.ack_record_id.clone(),
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
        expected_backend_identity_digest: receipt.backend.identity_digest.clone(),
        expected_backend_request_digest: receipt.backend.request_digest.clone(),
        expected_backend_response_digest: receipt.backend.response_digest.clone(),
        expected_backend_receipt_digest: receipt.backend.receipt_digest.clone(),
        expected_backend_transcript_digest: receipt.backend.transcript_digest.clone(),
        expected_backend_record_id: receipt.backend.backend_record_id.clone(),
        expected_receipt_identity_digest: receipt.identity_digest.clone(),
        expected_receipt_request_digest: receipt.request_digest.clone(),
        expected_receipt_response_digest: receipt.response_digest.clone(),
        expected_receipt_record_digest: receipt.record_digest.clone(),
        expected_receipt_transcript_digest: receipt.transcript_digest.clone(),
        expected_receipt_record_id: receipt.receipt_record_id.clone(),
        expected_identity: id,
        expected_acknowledgement_kind: kind,
        expected_acknowledgement_policy: policy,
        expected_domain_separation_tag: ACK_DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
        receipt,
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
    kind: DurableCompletionAuditReceiptAcknowledgementKind,
) -> Ctx {
    ctx_action(environment, vs, ms, policy, kind, &default_action(), false)
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input_with_receipt(
        &self,
        policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
        receipt: DurableCompletionAuditPublicationReceiptOutcome,
    ) -> DurableCompletionAuditReceiptAcknowledgementInput {
        DurableCompletionAuditReceiptAcknowledgementInput {
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
            receipt_binding: receipt,
            request: self.request.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
    ) -> DurableCompletionAuditReceiptAcknowledgementInput {
        self.input_with_receipt(
            policy,
            replay,
            pipeline,
            sink,
            reporter,
            finalization,
            attestation,
            backend,
            self.receipt.outcome.clone(),
        )
    }

    fn recorded(&self) -> DurableCompletionAuditReceiptAcknowledgementInput {
        self.input_with_receipt(
            self.request.identity.policy,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
            self.receipt.backend.outcome.clone(),
            self.receipt.outcome.clone(),
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
    )
}

fn fixture_sink() -> FixtureDurableCompletionAuditReceiptAcknowledgementSink {
    FixtureDurableCompletionAuditReceiptAcknowledgementSink::new()
}
#[test]
fn disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionAuditReceiptAcknowledgementPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.receipt.backend.outcome.clone(),
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::LegacyBypassNoAcknowledgement
    );
    assert!(outcome.is_legacy_bypass());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_backend_policy_never_invokes_receipt_sink() {
    let c = devnet_ctx();
    let input = c.input_with_receipt(
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission,
        DurableCompletionAuditPublicationReceiptOutcome::LegacyBypassNoAuditReceipt,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::LegacyBypassNoAcknowledgement
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
        c.receipt.backend.outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded
    );
    assert!(acknowledgement_outcome_authorizes_acknowledgement_record(
        &outcome
    ));
    assert!(acknowledgement_outcome_projects_to_acknowledgement_recorded(&outcome));
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(ACK_RECORD_ID));
    assert_eq!(
        acknowledgement_identity_digest(&c.request.identity),
        c.request.identity.digest()
    );
}

#[test]
fn testnet_fixture_chain_records_exactly_one_receipt() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded
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
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
            DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
            &action,
            false,
        );
        assert_eq!(
            c.receipt.backend.outcome,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
            &c.recorded(),
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            outcome,
            DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded,
            "action {label} must record after backend submission"
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&action.ack_record_id));
    }
}

#[test]
fn duplicate_identical_receipt_is_idempotent() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let first = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded
    );
    let second = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementDuplicateIdempotent
    );
    assert!(!acknowledgement_outcome_authorizes_acknowledgement_record(
        &second
    ));
    assert!(acknowledgement_outcome_projects_to_acknowledgement_recorded(&second));
    assert_eq!(ledger.len(), 1);
}

#[test]
fn run258_duplicate_idempotent_receipt_only_matches_existing_never_creates() {
    // A real Run 256 BackendSubmissionDuplicateIdempotent outcome with identical
    // digests.
    let dup_ctx = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        &default_action(),
        true,
    );
    assert_eq!(
        dup_ctx.receipt.outcome,
        DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent
    );

    // With no prior receipt, a duplicate-idempotent backend cannot create one.
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real receipt records, the duplicate-idempotent backend matches it.
    let rec_ctx = devnet_ctx();
    let recorded = evaluate_durable_completion_audit_receipt_acknowledgement(
        &rec_ctx.recorded(),
        &rec_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded
    );
    let matched = evaluate_durable_completion_audit_receipt_acknowledgement(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementDuplicateIdempotent
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
        DurableCompletionAuditReceiptAcknowledgementPolicy::ProductionAuditLedgerAckRequired,
        DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = ProductionAuditLedgerDurableCompletionAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::ProductionAuditLedgerAckUnavailableNoAcknowledgement
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = MainNetAuditLedgerDurableCompletionAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetAuditLedgerAckUnavailableNoAcknowledgement
    );
    assert!(ledger.is_empty());
}

#[test]
fn external_publication_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditReceiptAcknowledgementPolicy::ExternalPublicationConfirmationRequired,
        DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = ExternalPublicationDurableCompletionConfirmationSink::default();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::ExternalPublicationConfirmationUnavailableNoAcknowledgement
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_receipt_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
    );
    let input = c.input(
        DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = MainNetAuditLedgerDurableCompletionAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoAcknowledgement
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_and_policy_change_unsupported() {
    let c = devnet_ctx();
    let rotation = c.input_with_receipt(
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::ValidatorSetRotationUnsupportedNoSubmission,
        DurableCompletionAuditPublicationReceiptOutcome::ValidatorSetRotationUnsupportedNoReceipt,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &rotation,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::ValidatorSetRotationUnsupportedNoAcknowledgement
    );
    assert_eq!(sink.invocations(), 0);

    let policy_change = c.input_with_receipt(
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::PolicyChangeUnsupportedNoSubmission,
        DurableCompletionAuditPublicationReceiptOutcome::PolicyChangeUnsupportedNoReceipt,
    );
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &policy_change,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::PolicyChangeUnsupportedNoAcknowledgement
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — non-recording Run 258 receipt outcomes
// ===========================================================================

fn assert_non_recording_receipt(
    receipt: DurableCompletionAuditPublicationReceiptOutcome,
    expected: DurableCompletionAuditReceiptAcknowledgementOutcome,
) {
    let c = devnet_ctx();
    let input = c.input_with_receipt(
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.receipt.backend.outcome.clone(),
        receipt,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_acknowledgement());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn non_recording_receipt_outcomes_never_record_acknowledgement() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Ack;
    assert_non_recording_receipt(
        Receipt::LegacyBypassNoAuditReceipt,
        Ack::LegacyBypassNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
        Ack::RejectedBeforeAuditReceiptNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::BackendDidNotSubmitNoAuditReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::AuditReceiptRejectedBeforeRecord,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::AuditReceiptRecordFailedNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::AuditReceiptRolledBackNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::AuditReceiptRollbackFailedFatalNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::ProductionAuditLedgerUnavailableNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::MainNetAuditLedgerUnavailableNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::ExternalPublicationUnavailableNoReceipt,
        Ack::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::MainNetPeerDrivenApplyRefusedNoReceipt,
        Ack::MainNetPeerDrivenApplyRefusedNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::ValidatorSetRotationUnsupportedNoReceipt,
        Ack::ValidatorSetRotationUnsupportedNoAcknowledgement,
    );
    assert_non_recording_receipt(
        Receipt::PolicyChangeUnsupportedNoReceipt,
        Ack::PolicyChangeUnsupportedNoAcknowledgement,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — binding mismatch (before sink invocation)
// ===========================================================================

fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::RejectedBeforeAuditReceiptNoAcknowledgement
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
    mut mutate: impl FnMut(&mut DurableCompletionAuditReceiptAcknowledgementRequest),
) {
    let c = devnet_ctx();
    let mut input = c.recorded();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRejectedBeforeRecord
    );
    // The sink is invoked (binding matched) but records nothing.
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_ack_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.acknowledgement_record_id = "other-acknowledgement".to_string();
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
fn wrong_acknowledgement_identity_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.acknowledgement_id = "other-receipt-id".to_string();
    });
}

#[test]
fn wrong_receipt_policy_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.policy =
            DurableCompletionAuditReceiptAcknowledgementPolicy::ProductionAuditLedgerAckRequired;
    });
}

#[test]
fn wrong_receipt_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind =
            DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable;
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
fn same_ack_record_id_different_digest_is_equivocation_no_second_receipt() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();

    let first = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded
    );

    // A second receipt with the SAME receipt record id but a differing digest fails
    // closed as equivocation. We adjust both request and expectations on a differing
    // field so binding/request validation passes and the equivocation gate rejects.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
    let equivocation = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c2.recorded(),
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRejectedBeforeRecord
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
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
    );
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRejectedBeforeRecord
    );
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Receipt record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_receipt(
    fault: DurableCompletionAuditReceiptAcknowledgementFault,
    expected: DurableCompletionAuditReceiptAcknowledgementOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = FixtureDurableCompletionAuditReceiptAcknowledgementSink::with_fault(fault);
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_acknowledgement());
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn receipt_record_failed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionAuditReceiptAcknowledgementFault::RecordFailedNoAcknowledgement,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecordFailedNoAcknowledgement,
    );
}

#[test]
fn receipt_rollback_completed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionAuditReceiptAcknowledgementFault::RolledBackNoAcknowledgement,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRolledBackNoAcknowledgement,
    );
}

#[test]
fn receipt_rollback_failed_fatal_never_records() {
    assert_fault_no_receipt(
        DurableCompletionAuditReceiptAcknowledgementFault::RollbackFailedFatal,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRollbackFailedFatalNoAcknowledgement,
    );
}

#[test]
fn receipt_ambiguous_window_fails_closed() {
    assert_fault_no_receipt(
        DurableCompletionAuditReceiptAcknowledgementFault::AmbiguousAfterRecord,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementAmbiguousFailClosedNoAcknowledgement,
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_recorded_receipt_creates_acknowledgement_request_intent() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementRequestIntent as Intent;
    assert_eq!(
        project_audit_receipt_outcome_to_acknowledgement_request(&Receipt::AuditReceiptRecorded),
        Intent::CreateRequest
    );
    assert!(project_audit_receipt_outcome_to_acknowledgement_request(
        &Receipt::AuditReceiptRecorded
    )
    .creates_request());
    assert_eq!(
        project_audit_receipt_outcome_to_acknowledgement_request(
            &Receipt::AuditReceiptDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    assert!(!project_audit_receipt_outcome_to_acknowledgement_request(
        &Receipt::LegacyBypassNoAuditReceipt
    )
    .creates_request());
}

#[test]
fn non_recording_receipts_create_no_acknowledgement_request() {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementRequestIntent as Intent;
    for receipt in [
        Receipt::LegacyBypassNoAuditReceipt,
        Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
        Receipt::BackendDidNotSubmitNoAuditReceipt,
        Receipt::AuditReceiptRejectedBeforeRecord,
        Receipt::AuditReceiptRecordFailedNoReceipt,
        Receipt::ProductionAuditLedgerUnavailableNoReceipt,
    ] {
        assert!(matches!(
            project_audit_receipt_outcome_to_acknowledgement_request(&receipt),
            Intent::NoAcknowledgement(_)
        ));
    }
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_ledger() -> DurableCompletionAuditReceiptAcknowledgementLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionAuditReceiptAcknowledgementWindow,
    with_record: bool,
    expected: DurableCompletionAuditReceiptAcknowledgementOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(ACK_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_audit_receipt_acknowledgement_window(
        &input,
        window,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

#[test]
fn pre_backend_success_windows_fail_closed_no_receipt() {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementWindow as Window;
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
        assert_window(w, false, Receipt::AuditReceiptDidNotRecordNoAcknowledgement);
    }
}

#[test]
fn after_backend_success_before_receipt_request_and_record_reject_before_record() {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterReceiptSuccessBeforeAcknowledgementRequest,
        false,
        Receipt::AuditReceiptDidNotRecordNoAcknowledgement,
    );
    assert_window(
        Window::AfterAcknowledgementRequestBeforeAcknowledgementRecord,
        false,
        Receipt::AcknowledgementRejectedBeforeRecord,
    );
}

#[test]
fn after_receipt_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterAcknowledgementRecordBeforeAcknowledgementSuccess,
        false,
        Receipt::AcknowledgementRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterAcknowledgementRecordBeforeAcknowledgementSuccess,
        true,
        Receipt::AcknowledgementRecorded,
    );
}

#[test]
fn after_receipt_success_recovers_as_recorded() {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterAcknowledgementSuccess,
        true,
        Receipt::AcknowledgementRecorded,
    );
    // Without an explicit matching record, even after-success fails closed.
    assert_window(
        Window::AfterAcknowledgementSuccess,
        false,
        Receipt::AcknowledgementRejectedBeforeRecord,
    );
}

#[test]
fn ambiguous_record_failed_rollback_and_unknown_windows_fail_closed() {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterAcknowledgementAmbiguous,
        false,
        Receipt::AcknowledgementAmbiguousFailClosedNoAcknowledgement,
    );
    assert_window(
        Window::Unknown,
        false,
        Receipt::AcknowledgementAmbiguousFailClosedNoAcknowledgement,
    );
    assert_window(
        Window::AcknowledgementRecordFailed,
        false,
        Receipt::AcknowledgementRecordFailedNoAcknowledgement,
    );
    assert_window(
        Window::AcknowledgementRollbackCompleted,
        false,
        Receipt::AcknowledgementRolledBackNoAcknowledgement,
    );
    assert_window(
        Window::AcknowledgementRollbackFailed,
        false,
        Receipt::AcknowledgementRollbackFailedFatalNoAcknowledgement,
    );
}

#[test]
fn production_mainnet_external_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_durable_completion_audit_receipt_acknowledgement_window(
        &input,
        DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementSuccess,
        DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::ProductionAuditLedgerAckUnavailableNoAcknowledgement
    );
    let outcome = recover_durable_completion_audit_receipt_acknowledgement_window(
        &input,
        DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementSuccess,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetAuditLedgerAckUnavailableNoAcknowledgement
    );
    let outcome = recover_durable_completion_audit_receipt_acknowledgement_window(
        &input,
        DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementSuccess,
        DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::ExternalPublicationConfirmationUnavailableNoAcknowledgement
    );
}

#[test]
fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
    );
    let input = c.input(
        DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let outcome = recover_durable_completion_audit_receipt_acknowledgement_window(
        &input,
        DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementSuccess,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoAcknowledgement
    );
}

// ===========================================================================
// Receipt-ledger cases
// ===========================================================================

#[test]
fn rollback_restores_receipt_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_audit_receipt_acknowledgement(
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
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        &action,
        false,
    );
    let mut faulted = FixtureDurableCompletionAuditReceiptAcknowledgementSink::with_fault(
        DurableCompletionAuditReceiptAcknowledgementFault::RolledBackNoAcknowledgement,
    );
    let outcome = evaluate_durable_completion_audit_receipt_acknowledgement(
        &c2.recorded(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRolledBackNoAcknowledgement
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains(&action.ack_record_id));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

#[test]
fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_audit_ack_rejection_is_non_mutating());
    assert!(durable_completion_audit_ack_never_calls_run_070());
    assert!(durable_completion_audit_ack_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_audit_ack_never_writes_sequence_or_marker());
    assert!(durable_completion_audit_ack_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_audit_ack_no_external_publication());
    assert!(durable_completion_audit_ack_no_real_audit_ledger());
    assert!(durable_completion_audit_ack_pipeline_success_required());
    assert!(durable_completion_audit_ack_sink_receipt_required());
    assert!(durable_completion_audit_ack_completion_report_required());
    assert!(durable_completion_audit_ack_finalization_required());
    assert!(durable_completion_audit_ack_attestation_required());
    assert!(durable_completion_audit_ack_backend_submission_required());
    assert!(durable_completion_audit_ack_receipt_required());
    assert!(durable_completion_audit_ack_record_required_before_ack());
    assert!(durable_completion_audit_ack_failed_record_never_records());
    assert!(durable_completion_audit_ack_rollback_never_records());
    assert!(durable_completion_audit_ack_ambiguous_window_fails_closed());
    assert!(
        durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet
        )
    );
    assert!(
        !durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet
        )
    );
    assert!(durable_completion_audit_ack_production_mainnet_unavailable());
    assert!(durable_completion_audit_ack_external_confirmation_unavailable());
    assert!(durable_completion_audit_ack_validator_set_rotation_unsupported());
    assert!(durable_completion_audit_ack_policy_change_unsupported());
    assert!(durable_completion_audit_ack_local_operator_cannot_satisfy_mainnet_authority());
    assert!(durable_completion_audit_ack_peer_majority_cannot_satisfy_mainnet_authority());
}