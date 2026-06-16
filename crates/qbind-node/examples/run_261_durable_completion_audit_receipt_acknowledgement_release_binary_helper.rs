//! Run 261 — release-built helper for the Run 260 durable-completion audit-receipt
//! acknowledgement boundary.
//!
//! This helper is an example-only release evidence harness. It is never wired into
//! the production binary. It exercises the real Run 260 production library symbols
//! and mutates only the modeled in-memory
//! `DurableCompletionAuditReceiptAcknowledgementLedger` through the DevNet/TestNet
//! fixture sink. No real audit ledger, external publication, MainNet governance,
//! MainNet peer-driven apply, Run 070 call, `LivePqcTrustState` mutation,
//! marker/sequence write, trust swap, session eviction, RocksDB/file/schema/migration/
//! storage-format, or wire-format change is enabled.
//!
//! The Run 260 acknowledgement is driven by the *real* Run 258 audit/publication
//! receipt outcome, which is itself driven by the *real* Run 256 backend submission.
//! Only a Run 258 `AuditReceiptRecorded` outcome creates an acknowledgement request.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    acknowledgement_outcome_authorizes_acknowledgement_record,
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
    DurableCompletionAuditReceiptAcknowledgementAttestationBinding,
    DurableCompletionAuditReceiptAcknowledgementBackendBinding,
    DurableCompletionAuditReceiptAcknowledgementBinding,
    DurableCompletionAuditReceiptAcknowledgementDigest,
    DurableCompletionAuditReceiptAcknowledgementEnvironment,
    DurableCompletionAuditReceiptAcknowledgementExpectations,
    DurableCompletionAuditReceiptAcknowledgementFault,
    DurableCompletionAuditReceiptAcknowledgementFinalizationBinding,
    DurableCompletionAuditReceiptAcknowledgementIdentity,
    DurableCompletionAuditReceiptAcknowledgementInput,
    DurableCompletionAuditReceiptAcknowledgementKind,
    DurableCompletionAuditReceiptAcknowledgementLedger,
    DurableCompletionAuditReceiptAcknowledgementLedgerRecord,
    DurableCompletionAuditReceiptAcknowledgementLedgerStatus,
    DurableCompletionAuditReceiptAcknowledgementOutcome,
    DurableCompletionAuditReceiptAcknowledgementPipelineBinding,
    DurableCompletionAuditReceiptAcknowledgementPolicy,
    DurableCompletionAuditReceiptAcknowledgementReceiptBinding,
    DurableCompletionAuditReceiptAcknowledgementRecord,
    DurableCompletionAuditReceiptAcknowledgementReplayBinding,
    DurableCompletionAuditReceiptAcknowledgementReporterBinding,
    DurableCompletionAuditReceiptAcknowledgementRequest,
    DurableCompletionAuditReceiptAcknowledgementRequestIntent,
    DurableCompletionAuditReceiptAcknowledgementResponse,
    DurableCompletionAuditReceiptAcknowledgementSinkBinding,
    DurableCompletionAuditReceiptAcknowledgementSurface,
    DurableCompletionAuditReceiptAcknowledgementTranscriptDigest,
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

fn mainnet_peer_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
    )
}

impl Ctx {
    /// The standard "happy" Run 246..256 chain bindings with an explicit Run 258
    /// receipt outcome injected. Lets the corpus drive the acknowledgement off any
    /// real Run 258 receipt outcome.
    fn happy_input_with_receipt(
        &self,
        policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
        receipt: DurableCompletionAuditPublicationReceiptOutcome,
    ) -> DurableCompletionAuditReceiptAcknowledgementInput {
        self.input_with_receipt(
            policy,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
            self.receipt.backend.outcome.clone(),
            receipt,
        )
    }

    /// A full MainNet peer-driven-apply refusal chain.
    fn peer_input(&self) -> DurableCompletionAuditReceiptAcknowledgementInput {
        self.input_with_receipt(
            DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
            DurableReplayObservation::MainNetPeerDrivenApplyRefused,
            GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
            GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
            GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
            GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
            DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
            DurableCompletionAuditPublicationReceiptOutcome::MainNetPeerDrivenApplyRefusedNoReceipt,
        )
    }
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

struct Table {
    name: &'static str,
    rows: String,
    expected: String,
    actual: String,
    pass: u64,
    fail: u64,
}
impl Table {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            rows: String::new(),
            expected: String::new(),
            actual: String::new(),
            pass: 0,
            fail: 0,
        }
    }
    fn check(&mut self, id: &str, expected: &str, actual: &str) {
        let ok = expected == actual;
        self.pass += u64::from(ok);
        self.fail += u64::from(!ok);
        self.rows.push_str(&format!(
            "{id}\t{}\texpected={expected}\tactual={actual}\n",
            if ok { "PASS" } else { "FAIL" }
        ));
        self.expected.push_str(&format!("{id}\t{expected}\n"));
        self.actual.push_str(&format!("{id}\t{actual}\n"));
    }
    fn assert_true(&mut self, id: &str, ok: bool) {
        self.check(id, "true", if ok { "true" } else { "false" });
    }
    fn check_outcome(
        &mut self,
        id: &str,
        expected: &str,
        o: &DurableCompletionAuditReceiptAcknowledgementOutcome,
    ) {
        self.check(id, expected, o.tag());
    }
    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

fn drive<S: GovernanceDurableCompletionAuditReceiptAcknowledgementSink>(
    input: &DurableCompletionAuditReceiptAcknowledgementInput,
    expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
    evaluate_durable_completion_audit_receipt_acknowledgement(input, expectations, sink, ledger)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    let mut t = Table::new("accepted");
    // A1: a disabled acknowledgement policy preserves the legacy bypass and never
    // invokes the acknowledgement sink.
    {
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
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A1.ack-policy-disabled", "legacy-bypass-no-acknowledgement", &o);
        t.assert_true("A1.no-invocation", sink.invocations() == 0);
        t.assert_true("A1.ledger-empty", ledger.is_empty());
    }
    // A2..A9: every prior-stage disabled / non-recording receipt outcome preserves a
    // no-acknowledgement bypass and never invokes the acknowledgement sink.
    for (id, receipt, tag) in [
        (
            "A2.receipt-policy-disabled",
            Receipt::LegacyBypassNoAuditReceipt,
            "legacy-bypass-no-acknowledgement",
        ),
        (
            "A3.backend-disabled",
            Receipt::BackendDidNotSubmitNoAuditReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "A4.attestor-disabled",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
        (
            "A5.finalizer-disabled",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
        (
            "A6.reporter-disabled",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
        (
            "A7.sink-disabled",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
        (
            "A8.pipeline-disabled",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
        (
            "A9.evaluator-disabled",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
    ] {
        let c = devnet_ctx();
        let input = c.happy_input_with_receipt(
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
            receipt,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), tag, &o);
        t.assert_true(&format!("{id}.no-sink"), sink.invocations() == 0);
        t.assert_true(&format!("{id}.no-ack"), ledger.is_empty());
    }
    // A10/A11: DevNet/TestNet fixture chains record exactly one modeled
    // acknowledgement only after the full pipeline -> sink -> report -> finalize ->
    // attest -> backend -> audit-receipt -> acknowledgement record chain.
    for (id, c) in [("A10.devnet", devnet_ctx()), ("A11.testnet", testnet_ctx())] {
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), "acknowledgement-recorded", &o);
        t.assert_true(
            &format!("{id}.authorizes"),
            acknowledgement_outcome_authorizes_acknowledgement_record(&o),
        );
        t.assert_true(
            &format!("{id}.projects"),
            acknowledgement_outcome_projects_to_acknowledgement_recorded(&o),
        );
        t.assert_true(
            &format!("{id}.ledger-one"),
            ledger.len() == 1 && ledger.contains(&c.request.acknowledgement_record_id),
        );
        t.assert_true(&format!("{id}.sink-once"), sink.invocations() == 1);
    }
    // A12: modeled add-root / retire-root / revoke-root / emergency-revoke-root / noop
    // variants record acknowledgement only after the full chain.
    for action in [
        "add-root",
        "retire-root",
        "revoke-root",
        "emergency-revoke-root",
        "noop",
    ] {
        let label = action_label(action);
        let c = ctx_action(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
            DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
            &label,
            false,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("A12.{action}.outcome"), "acknowledgement-recorded", &o);
        t.assert_true(
            &format!("A12.{action}.ledger-one"),
            ledger.len() == 1 && ledger.contains(&label.ack_record_id),
        );
    }
    // A13: duplicate identical acknowledgement is idempotent and creates no second
    // acknowledgement.
    {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let first = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        let second = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A13.first", "acknowledgement-recorded", &first);
        t.check_outcome("A13.duplicate", "acknowledgement-duplicate-idempotent", &second);
        t.assert_true("A13.ledger-one", ledger.len() == 1);
        t.assert_true(
            "A13.duplicate-no-new-authorize",
            !acknowledgement_outcome_authorizes_acknowledgement_record(&second),
        );
    }
    // A14: a Run 258 duplicate-idempotent audit receipt projects to an
    // idempotent-only acknowledgement request; against an empty ledger it records no
    // new acknowledgement and fails closed before record.
    {
        let dup_ctx = ctx_action(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
            DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
            &default_action(),
            true,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&dup_ctx.recorded(), &dup_ctx.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "A14.receipt-duplicate-empty",
            "acknowledgement-rejected-before-record",
            &o,
        );
        t.assert_true("A14.empty", ledger.is_empty());
    }
    // A15/A16/A17: production / MainNet audit-ledger / external-publication
    // acknowledgement paths are reachable but unavailable / fail-closed and record no
    // acknowledgement.
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditReceiptAcknowledgementPolicy::ProductionAuditLedgerAckRequired,
            DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut prod = ProductionAuditLedgerDurableCompletionAcknowledgementSink::default();
        let o = drive(&c.recorded(), &c.expectations, &mut prod, &mut ledger);
        t.check_outcome(
            "A15.production",
            "production-audit-ledger-ack-unavailable-no-acknowledgement",
            &o,
        );
        t.assert_true("A15.no-record", ledger.is_empty());
        t.check(
            "A15.kind",
            "production-audit-ledger-ack-unavailable",
            prod.kind().tag(),
        );
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired,
            DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut mn = MainNetAuditLedgerDurableCompletionAcknowledgementSink::default();
        let o = drive(&c.recorded(), &c.expectations, &mut mn, &mut ledger);
        t.check_outcome(
            "A16.mainnet",
            "mainnet-audit-ledger-ack-unavailable-no-acknowledgement",
            &o,
        );
        t.assert_true("A16.no-record", ledger.is_empty());
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditReceiptAcknowledgementPolicy::ExternalPublicationConfirmationRequired,
            DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut ext = ExternalPublicationDurableCompletionConfirmationSink::default();
        let o = drive(&c.recorded(), &c.expectations, &mut ext, &mut ledger);
        t.check_outcome(
            "A17.external",
            "external-publication-confirmation-unavailable-no-acknowledgement",
            &o,
        );
        t.assert_true("A17.no-record", ledger.is_empty());
    }
    // A18: MainNet peer-driven apply is refused before pipeline progression and every
    // downstream invocation.
    {
        let c = mainnet_peer_ctx();
        let input = c.peer_input();
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = MainNetAuditLedgerDurableCompletionAcknowledgementSink::default();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "A18.mainnet-peer",
            "mainnet-peer-driven-apply-refused-no-acknowledgement",
            &o,
        );
        t.assert_true("A18.no-invocation", sink.invocations() == 0 && ledger.is_empty());
    }
    // A19/A20: validator-set rotation / policy-change unsupported and record no
    // acknowledgement.
    for (id, receipt, tag) in [
        (
            "A19.validator",
            Receipt::ValidatorSetRotationUnsupportedNoReceipt,
            "validator-set-rotation-unsupported-no-acknowledgement",
        ),
        (
            "A20.policy",
            Receipt::PolicyChangeUnsupportedNoReceipt,
            "policy-change-unsupported-no-acknowledgement",
        ),
    ] {
        let c = devnet_ctx();
        let input = c.happy_input_with_receipt(
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
            receipt,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(id, tag, &o);
        t.assert_true(
            &format!("{id}.no-sink"),
            sink.invocations() == 0 && ledger.is_empty(),
        );
    }
    t.finish(out)
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("rejection");
    // B1: a binding mismatch (wrong genesis) rejects before any acknowledgement and
    // never invokes the acknowledgement sink.
    {
        let mut c = devnet_ctx();
        c.expectations.expected_genesis_hash = "wrong".to_string();
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "B1.wrong-genesis",
            "rejected-before-audit-receipt-no-acknowledgement",
            &o,
        );
        t.assert_true("B1.no-invocation", sink.invocations() == 0 && ledger.is_empty());
    }
    // B1c: a chain-id / environment binding mismatch also rejects before any
    // acknowledgement.
    {
        let mut c = devnet_ctx();
        c.expectations.expected_chain_id = "wrong-chain".to_string();
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "B1c.wrong-chain",
            "rejected-before-audit-receipt-no-acknowledgement",
            &o,
        );
        t.assert_true("B1c.no-invocation", sink.invocations() == 0 && ledger.is_empty());
    }
    // B2..: every request-identity / digest mismatch is caught by the sink and fails
    // closed before record (sink invoked once, nothing written).
    for (label, mutate) in [
        (
            "wrong-ack-record-id",
            (|r: &mut DurableCompletionAuditReceiptAcknowledgementRequest| {
                r.acknowledgement_record_id = "x".to_string()
            }) as fn(&mut DurableCompletionAuditReceiptAcknowledgementRequest),
        ),
        ("wrong-proposal", |r| r.proposal_id = "x".to_string()),
        ("wrong-decision", |r| r.decision_id = "x".to_string()),
        ("wrong-candidate", |r| r.candidate_digest = "x".to_string()),
        ("wrong-pipeline", |r| r.pipeline_decision_digest = "x".to_string()),
        ("wrong-sink", |r| r.sink_decision_digest = "x".to_string()),
        ("wrong-reporter", |r| r.reporter_decision_digest = "x".to_string()),
        ("wrong-finalization", |r| {
            r.finalization_decision_digest = "x".to_string()
        }),
        ("wrong-attestation", |r| r.attestation_digest = "x".to_string()),
        ("wrong-backend-identity", |r| {
            r.backend_identity_digest = "x".to_string()
        }),
        ("wrong-backend-receipt", |r| {
            r.backend_receipt_digest = "x".to_string()
        }),
        ("wrong-receipt-identity", |r| {
            r.receipt_identity_digest = "x".to_string()
        }),
        ("wrong-receipt-record", |r| {
            r.receipt_record_digest = "x".to_string()
        }),
        ("wrong-receipt-record-id", |r| {
            r.receipt_record_id = "x".to_string()
        }),
        ("wrong-sequence", |r| r.authority_domain_sequence = 123),
        ("malformed-domain-tag", |r| {
            r.domain_separation_tag = String::new()
        }),
    ] {
        let c = devnet_ctx();
        let mut input = c.recorded();
        mutate(&mut input.request);
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            &format!("B2.{label}"),
            "acknowledgement-rejected-before-record",
            &o,
        );
        t.assert_true(
            &format!("B2.{label}.empty"),
            sink.invocations() == 1 && ledger.is_empty(),
        );
    }
    // B3: fixture sink faults fail closed and record no acknowledgement.
    for (label, fault, tag) in [
        (
            "record-failed",
            DurableCompletionAuditReceiptAcknowledgementFault::RecordFailedNoAcknowledgement,
            "acknowledgement-record-failed-no-acknowledgement",
        ),
        (
            "rolled-back",
            DurableCompletionAuditReceiptAcknowledgementFault::RolledBackNoAcknowledgement,
            "acknowledgement-rolled-back-no-acknowledgement",
        ),
        (
            "rollback-failed-fatal",
            DurableCompletionAuditReceiptAcknowledgementFault::RollbackFailedFatal,
            "acknowledgement-rollback-failed-fatal-no-acknowledgement",
        ),
        (
            "ambiguous",
            DurableCompletionAuditReceiptAcknowledgementFault::AmbiguousAfterRecord,
            "acknowledgement-ambiguous-fail-closed-no-acknowledgement",
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink =
            FixtureDurableCompletionAuditReceiptAcknowledgementSink::with_fault(fault);
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("B3.{label}"), tag, &o);
        t.assert_true(&format!("B3.{label}.invoked"), sink.invocations() == 1);
        t.assert_true(&format!("B3.{label}.no-ack"), o.no_acknowledgement());
    }
    // B4: a Mainnet-environment fixture request is rejected by the fixture sink
    // before any record (the fixture sink only serves DevNet/TestNet).
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
            DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        );
        let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "B4.mainnet-env-fixture",
            "acknowledgement-rejected-before-record",
            &o,
        );
        t.assert_true("B4.invoked-once", sink.invocations() == 1 && ledger.is_empty());
    }
    t.finish(out)
}

fn recorded_ack_ledger() -> DurableCompletionAuditReceiptAcknowledgementLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let _ = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    ledger
}

fn recover_devnet(
    window: DurableCompletionAuditReceiptAcknowledgementWindow,
    with_record: bool,
) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recorded_ack_ledger();
    let record = if with_record {
        ledger.find(ACK_RECORD_ID)
    } else {
        None
    };
    recover_durable_completion_audit_receipt_acknowledgement_window(
        &input,
        window,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        record,
        &c.expectations,
    )
}

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAuditReceiptAcknowledgementWindow as W;
    let mut t = Table::new("recovery");
    // The 16 pre-acknowledgement windows all classify as "the audit receipt's
    // acknowledgement never recorded".
    for (id, w) in [
        ("C.before-pipeline", W::BeforePipeline),
        ("C.after-pipeline", W::AfterPipelineSuccessBeforeSinkIntent),
        ("C.after-sink-intent", W::AfterSinkIntentBeforeSinkReceiptRecord),
        ("C.after-sink-record", W::AfterSinkReceiptRecordBeforeReportIntent),
        ("C.after-report-intent", W::AfterReportIntentBeforeReportRecord),
        ("C.after-report-record", W::AfterReportRecordBeforeFinalizationIntent),
        ("C.after-finalization-intent", W::AfterFinalizationIntentBeforeFinalizationRecord),
        ("C.after-finalization-record", W::AfterFinalizationRecordBeforeAttestationIntent),
        ("C.after-attestation-intent", W::AfterAttestationIntentBeforeAttestationRecord),
        ("C.after-attestation-record", W::AfterAttestationRecordBeforeBackendRequest),
        ("C.after-backend-request", W::AfterBackendRequestBeforeBackendRecord),
        ("C.after-backend-record", W::AfterBackendRecordBeforeBackendSuccess),
        ("C.after-backend-success", W::AfterBackendSuccessBeforeReceiptRequest),
        ("C.after-receipt-request", W::AfterReceiptRequestBeforeReceiptRecord),
        ("C.after-receipt-record", W::AfterReceiptRecordBeforeReceiptSuccess),
        ("C.after-receipt-success", W::AfterReceiptSuccessBeforeAcknowledgementRequest),
    ] {
        t.check_outcome(id, "audit-receipt-did-not-record-no-acknowledgement", &recover_devnet(w, false));
    }
    // The acknowledgement request window itself rejects before record.
    t.check_outcome(
        "C.after-ack-request",
        "acknowledgement-rejected-before-record",
        &recover_devnet(W::AfterAcknowledgementRequestBeforeAcknowledgementRecord, false),
    );
    // After-record / after-success windows recover an acknowledgement only with a
    // matching recovered record; otherwise reject before record.
    t.check_outcome(
        "C.after-ack-record-no-record",
        "acknowledgement-rejected-before-record",
        &recover_devnet(W::AfterAcknowledgementRecordBeforeAcknowledgementSuccess, false),
    );
    t.check_outcome(
        "C.after-ack-record-with-record",
        "acknowledgement-recorded",
        &recover_devnet(W::AfterAcknowledgementRecordBeforeAcknowledgementSuccess, true),
    );
    t.check_outcome(
        "C.after-ack-success-no-record",
        "acknowledgement-rejected-before-record",
        &recover_devnet(W::AfterAcknowledgementSuccess, false),
    );
    t.check_outcome(
        "C.after-ack-success-with-record",
        "acknowledgement-recorded",
        &recover_devnet(W::AfterAcknowledgementSuccess, true),
    );
    // Ambiguous / failure / rollback windows fail closed.
    t.check_outcome(
        "C.after-ack-ambiguous",
        "acknowledgement-ambiguous-fail-closed-no-acknowledgement",
        &recover_devnet(W::AfterAcknowledgementAmbiguous, false),
    );
    t.check_outcome(
        "C.unknown",
        "acknowledgement-ambiguous-fail-closed-no-acknowledgement",
        &recover_devnet(W::Unknown, false),
    );
    t.check_outcome(
        "C.record-failed",
        "acknowledgement-record-failed-no-acknowledgement",
        &recover_devnet(W::AcknowledgementRecordFailed, false),
    );
    t.check_outcome(
        "C.rollback",
        "acknowledgement-rolled-back-no-acknowledgement",
        &recover_devnet(W::AcknowledgementRollbackCompleted, false),
    );
    t.check_outcome(
        "C.rollback-failed",
        "acknowledgement-rollback-failed-fatal-no-acknowledgement",
        &recover_devnet(W::AcknowledgementRollbackFailed, false),
    );
    // Non-fixture kinds short-circuit before window classification.
    let c = devnet_ctx();
    let input = c.recorded();
    for (id, kind, tag) in [
        (
            "C.production",
            DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable,
            "production-audit-ledger-ack-unavailable-no-acknowledgement",
        ),
        (
            "C.mainnet",
            DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
            "mainnet-audit-ledger-ack-unavailable-no-acknowledgement",
        ),
        (
            "C.external",
            DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable,
            "external-publication-confirmation-unavailable-no-acknowledgement",
        ),
        (
            "C.disabled",
            DurableCompletionAuditReceiptAcknowledgementKind::Disabled,
            "legacy-bypass-no-acknowledgement",
        ),
        (
            "C.kind-unknown",
            DurableCompletionAuditReceiptAcknowledgementKind::Unknown,
            "acknowledgement-ambiguous-fail-closed-no-acknowledgement",
        ),
    ] {
        let o = recover_durable_completion_audit_receipt_acknowledgement_window(
            &input,
            W::AfterAcknowledgementSuccess,
            kind,
            None,
            &c.expectations,
        );
        t.check_outcome(id, tag, &o);
    }
    // MainNet peer-driven apply refusal precedes recovery classification.
    let cp = mainnet_peer_ctx();
    let peer_input = cp.peer_input();
    let peer = recover_durable_completion_audit_receipt_acknowledgement_window(
        &peer_input,
        W::AfterAcknowledgementSuccess,
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable,
        None,
        &cp.expectations,
    );
    t.check_outcome(
        "C.mainnet-peer-precedes",
        "mainnet-peer-driven-apply-refused-no-acknowledgement",
        &peer,
    );
    t.finish(out)
}

fn run_projection_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementRequestIntent as Intent;
    let mut t = Table::new("projection");
    let create = project_audit_receipt_outcome_to_acknowledgement_request(&Receipt::AuditReceiptRecorded);
    t.assert_true("D.only-recorded-creates", create.creates_request());
    let dup = project_audit_receipt_outcome_to_acknowledgement_request(
        &Receipt::AuditReceiptDuplicateIdempotent,
    );
    t.assert_true(
        "D.duplicate-idempotent-only",
        dup == Intent::IdempotentOnly && !dup.creates_request(),
    );
    for (label, receipt, tag) in [
        ("legacy", Receipt::LegacyBypassNoAuditReceipt, "legacy-bypass-no-acknowledgement"),
        (
            "rejected-before-backend",
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-audit-receipt-no-acknowledgement",
        ),
        (
            "backend-did-not-submit",
            Receipt::BackendDidNotSubmitNoAuditReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "receipt-rejected",
            Receipt::AuditReceiptRejectedBeforeRecord,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "receipt-record-failed",
            Receipt::AuditReceiptRecordFailedNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "receipt-rolled-back",
            Receipt::AuditReceiptRolledBackNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "receipt-rollback-failed",
            Receipt::AuditReceiptRollbackFailedFatalNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "receipt-ambiguous",
            Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "production",
            Receipt::ProductionAuditLedgerUnavailableNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "mainnet",
            Receipt::MainNetAuditLedgerUnavailableNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "external",
            Receipt::ExternalPublicationUnavailableNoReceipt,
            "audit-receipt-did-not-record-no-acknowledgement",
        ),
        (
            "mainnet-peer",
            Receipt::MainNetPeerDrivenApplyRefusedNoReceipt,
            "mainnet-peer-driven-apply-refused-no-acknowledgement",
        ),
        (
            "validator",
            Receipt::ValidatorSetRotationUnsupportedNoReceipt,
            "validator-set-rotation-unsupported-no-acknowledgement",
        ),
        (
            "policy",
            Receipt::PolicyChangeUnsupportedNoReceipt,
            "policy-change-unsupported-no-acknowledgement",
        ),
    ] {
        match project_audit_receipt_outcome_to_acknowledgement_request(&receipt) {
            Intent::NoAcknowledgement(o) => t.check(&format!("D.{label}"), tag, o.tag()),
            _ => t.check(&format!("D.{label}"), tag, "unexpected-create"),
        }
    }
    t.assert_true(
        "D.recorded-authorizes",
        acknowledgement_outcome_authorizes_acknowledgement_record(
            &DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded,
        ),
    );
    t.assert_true(
        "D.recorded-projects",
        acknowledgement_outcome_projects_to_acknowledgement_recorded(
            &DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded,
        ),
    );
    t.assert_true(
        "D.duplicate-projects",
        acknowledgement_outcome_projects_to_acknowledgement_recorded(
            &DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementDuplicateIdempotent,
        ),
    );
    t.assert_true(
        "D.duplicate-no-authorize",
        !acknowledgement_outcome_authorizes_acknowledgement_record(
            &DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementDuplicateIdempotent,
        ),
    );
    t.finish(out)
}

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("stage_ordering");
    // E1: MainNet peer-driven apply is refused before any downstream invocation.
    let c = mainnet_peer_ctx();
    let input = c.peer_input();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = MainNetAuditLedgerDurableCompletionAcknowledgementSink::default();
    let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
    t.assert_true(
        "E.mainnet-refused-first",
        o.is_mainnet_peer_driven_apply_refused() && sink.invocations() == 0 && ledger.is_empty(),
    );
    // E2: a binding mismatch is rejected before the acknowledgement sink is invoked.
    let mut c2 = devnet_ctx();
    c2.expectations.expected_genesis_hash = "wrong".to_string();
    let mut ledger2 = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink2 = fixture_sink();
    let o2 = drive(&c2.recorded(), &c2.expectations, &mut sink2, &mut ledger2);
    t.assert_true(
        "E.binding-before-sink",
        o2 == DurableCompletionAuditReceiptAcknowledgementOutcome::RejectedBeforeAuditReceiptNoAcknowledgement
            && sink2.invocations() == 0,
    );
    // E3: a record-failure invokes the sink exactly once and records no
    // acknowledgement.
    let c3 = devnet_ctx();
    let mut ledger3 = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink3 = FixtureDurableCompletionAuditReceiptAcknowledgementSink::with_fault(
        DurableCompletionAuditReceiptAcknowledgementFault::RecordFailedNoAcknowledgement,
    );
    let o3 = drive(&c3.recorded(), &c3.expectations, &mut sink3, &mut ledger3);
    t.assert_true(
        "E.record-failure-no-ack",
        o3.no_acknowledgement() && sink3.invocations() == 1 && ledger3.is_empty(),
    );
    // E4: only a Run 258 AuditReceiptRecorded creates an acknowledgement request;
    // a rejected receipt does not.
    t.assert_true(
        "E.ack-only-after-receipt",
        project_audit_receipt_outcome_to_acknowledgement_request(
            &DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded,
        )
        .creates_request(),
    );
    t.assert_true(
        "E.no-ack-on-receipt-reject",
        !project_audit_receipt_outcome_to_acknowledgement_request(
            &DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRejectedBeforeRecord,
        )
        .creates_request(),
    );
    // E5: the full pre-acknowledgement stage chain is required.
    t.assert_true(
        "E.chain-required",
        durable_completion_audit_ack_pipeline_success_required()
            && durable_completion_audit_ack_sink_receipt_required()
            && durable_completion_audit_ack_completion_report_required()
            && durable_completion_audit_ack_finalization_required()
            && durable_completion_audit_ack_attestation_required()
            && durable_completion_audit_ack_backend_submission_required()
            && durable_completion_audit_ack_receipt_required()
            && durable_completion_audit_ack_record_required_before_ack(),
    );
    t.finish(out)
}

fn run_acknowledgement_ledger_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("acknowledgement_ledger");
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    t.check_outcome("F.one-valid", "acknowledgement-recorded", &o);
    t.assert_true(
        "F.len-one",
        ledger.len() == 1 && ledger.records().len() == 1 && ledger.contains(ACK_RECORD_ID),
    );
    t.assert_true(
        "F.status",
        ledger.find(ACK_RECORD_ID).map(|r| r.status)
            == Some(DurableCompletionAuditReceiptAcknowledgementLedgerStatus::Recorded),
    );
    let snap = ledger.snapshot();
    t.assert_true("F.snapshot", snap.len() == 1 && !snap.is_empty());
    let mut restored = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    restored.restore(&snap);
    t.assert_true(
        "F.restore",
        restored.len() == 1 && restored.contains(ACK_RECORD_ID),
    );
    let request_digest: DurableCompletionAuditReceiptAcknowledgementDigest = c.request.digest();
    let record: DurableCompletionAuditReceiptAcknowledgementRecord = c.request.to_record();
    t.assert_true("F.record-id", record.acknowledgement_record_id == ACK_RECORD_ID);
    t.assert_true(
        "F.record-request-digest",
        record.request_digest == request_digest,
    );
    t.assert_true("F.request-digest-hex", !request_digest.as_hex().is_empty());
    t.assert_true("F.request-well-formed", c.request.is_well_formed());
    let response = DurableCompletionAuditReceiptAcknowledgementResponse {
        acknowledgement_record_id: ACK_RECORD_ID.to_string(),
        request_digest: request_digest.clone(),
        accepted: true,
        acknowledgement_kind: DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
    };
    let response_digest = response.digest();
    t.assert_true(
        "F.response-digest-hex",
        !response_digest.as_hex().is_empty() && response.is_well_formed(),
    );
    let transcript: DurableCompletionAuditReceiptAcknowledgementTranscriptDigest = ledger
        .find(ACK_RECORD_ID)
        .map(|r| r.transcript_digest.clone())
        .unwrap();
    t.assert_true("F.transcript-digest-hex", !transcript.as_hex().is_empty());
    // Duplicate identical acknowledgement is idempotent.
    let second = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    t.check_outcome("F.duplicate", "acknowledgement-duplicate-idempotent", &second);
    t.assert_true("F.duplicate-len-one", ledger.len() == 1);
    // Equivocation (same record id, different request) fails closed.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "different-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "different-candidate-digest".to_string();
    let o2 = drive(&c2.recorded(), &c2.expectations, &mut sink, &mut ledger);
    t.check_outcome("F.equivocation", "acknowledgement-rejected-before-record", &o2);
    t.assert_true("F.equivocation-len-one", ledger.len() == 1);
    // Rollback restores the ledger and records nothing new.
    let mut existing = ledger.clone();
    let second_action = action_label("rollback-second");
    let c3 = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        &second_action,
        false,
    );
    let mut faulted = FixtureDurableCompletionAuditReceiptAcknowledgementSink::with_fault(
        DurableCompletionAuditReceiptAcknowledgementFault::RolledBackNoAcknowledgement,
    );
    let rolled = drive(&c3.recorded(), &c3.expectations, &mut faulted, &mut existing);
    t.check_outcome("F.rollback-restores", "acknowledgement-rolled-back-no-acknowledgement", &rolled);
    t.assert_true(
        "F.rollback-len-one",
        existing.len() == 1 && !existing.contains(&second_action.ack_record_id),
    );
    t.assert_true(
        "F.fixture-memory-only",
        durable_completion_audit_ack_no_rocksdb_file_schema_migration_change()
            && durable_completion_audit_ack_no_real_audit_ledger()
            && durable_completion_audit_ack_no_external_publication(),
    );
    t.finish(out)
}

fn run_non_mutation_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("non_mutation");
    t.assert_true("G.rejection-non-mutating", durable_completion_audit_ack_rejection_is_non_mutating());
    t.assert_true("G.never-calls-run-070", durable_completion_audit_ack_never_calls_run_070());
    t.assert_true(
        "G.never-mutates-live",
        durable_completion_audit_ack_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.never-writes-sequence-or-marker",
        durable_completion_audit_ack_never_writes_sequence_or_marker(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        durable_completion_audit_ack_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true("G.no-external-publication", durable_completion_audit_ack_no_external_publication());
    t.assert_true("G.no-real-audit-ledger", durable_completion_audit_ack_no_real_audit_ledger());
    t.assert_true("G.pipeline-success-required", durable_completion_audit_ack_pipeline_success_required());
    t.assert_true("G.sink-receipt-required", durable_completion_audit_ack_sink_receipt_required());
    t.assert_true("G.completion-report-required", durable_completion_audit_ack_completion_report_required());
    t.assert_true("G.finalization-required", durable_completion_audit_ack_finalization_required());
    t.assert_true("G.attestation-required", durable_completion_audit_ack_attestation_required());
    t.assert_true("G.backend-submission-required", durable_completion_audit_ack_backend_submission_required());
    t.assert_true("G.receipt-required", durable_completion_audit_ack_receipt_required());
    t.assert_true("G.record-required-before-ack", durable_completion_audit_ack_record_required_before_ack());
    t.assert_true("G.failed-record-never-records", durable_completion_audit_ack_failed_record_never_records());
    t.assert_true("G.rollback-never-records", durable_completion_audit_ack_rollback_never_records());
    t.assert_true("G.ambiguous-fails-closed", durable_completion_audit_ack_ambiguous_window_fails_closed());
    t.assert_true(
        "G.mainnet-refused-mainnet",
        durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first(TrustBundleEnvironment::Mainnet),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first(TrustBundleEnvironment::Devnet),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        durable_completion_audit_ack_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.external-unavailable",
        durable_completion_audit_ack_external_confirmation_unavailable(),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        durable_completion_audit_ack_validator_set_rotation_unsupported(),
    );
    t.assert_true("G.policy-change-unsupported", durable_completion_audit_ack_policy_change_unsupported());
    t.assert_true(
        "G.local-operator-cannot",
        durable_completion_audit_ack_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        durable_completion_audit_ack_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    // A rejected acknowledgement leaves the ledger empty and never invokes the sink.
    let mut c = devnet_ctx();
    c.expectations.expected_genesis_hash = "wrong".to_string();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let _ = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    t.assert_true(
        "G.rejected-ledger-empty",
        ledger.is_empty() && sink.invocations() == 0,
    );
    // The production-audit-ledger path records nothing.
    let c2 = devnet_ctx();
    let mut prod_ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut prod = ProductionAuditLedgerDurableCompletionAcknowledgementSink::default();
    let _ = drive(&c2.recorded(), &c2.expectations, &mut prod, &mut prod_ledger);
    t.assert_true("G.production-path-no-record", prod_ledger.is_empty());
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Ack;
    let mut t = Table::new("reachability");
    for (o, tag) in [
        (Ack::AcknowledgementRecorded, "acknowledgement-recorded"),
        (Ack::AcknowledgementDuplicateIdempotent, "acknowledgement-duplicate-idempotent"),
        (Ack::AcknowledgementRejectedBeforeRecord, "acknowledgement-rejected-before-record"),
        (Ack::LegacyBypassNoAcknowledgement, "legacy-bypass-no-acknowledgement"),
        (Ack::RejectedBeforeAuditReceiptNoAcknowledgement, "rejected-before-audit-receipt-no-acknowledgement"),
        (Ack::AuditReceiptDidNotRecordNoAcknowledgement, "audit-receipt-did-not-record-no-acknowledgement"),
        (Ack::AcknowledgementRecordFailedNoAcknowledgement, "acknowledgement-record-failed-no-acknowledgement"),
        (Ack::AcknowledgementRolledBackNoAcknowledgement, "acknowledgement-rolled-back-no-acknowledgement"),
        (Ack::AcknowledgementRollbackFailedFatalNoAcknowledgement, "acknowledgement-rollback-failed-fatal-no-acknowledgement"),
        (Ack::AcknowledgementAmbiguousFailClosedNoAcknowledgement, "acknowledgement-ambiguous-fail-closed-no-acknowledgement"),
        (Ack::ProductionAuditLedgerAckUnavailableNoAcknowledgement, "production-audit-ledger-ack-unavailable-no-acknowledgement"),
        (Ack::MainNetAuditLedgerAckUnavailableNoAcknowledgement, "mainnet-audit-ledger-ack-unavailable-no-acknowledgement"),
        (Ack::ExternalPublicationConfirmationUnavailableNoAcknowledgement, "external-publication-confirmation-unavailable-no-acknowledgement"),
        (Ack::MainNetPeerDrivenApplyRefusedNoAcknowledgement, "mainnet-peer-driven-apply-refused-no-acknowledgement"),
        (Ack::ValidatorSetRotationUnsupportedNoAcknowledgement, "validator-set-rotation-unsupported-no-acknowledgement"),
        (Ack::PolicyChangeUnsupportedNoAcknowledgement, "policy-change-unsupported-no-acknowledgement"),
    ] {
        t.check(&format!("H.tag.{tag}"), tag, o.tag());
    }
    for (id, kind, tag) in [
        ("H.kind-disabled", DurableCompletionAuditReceiptAcknowledgementKind::Disabled, "disabled"),
        ("H.kind-fixture", DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory, "fixture-in-memory"),
        ("H.kind-production", DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable, "production-audit-ledger-ack-unavailable"),
        ("H.kind-mainnet", DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable, "mainnet-audit-ledger-ack-unavailable"),
        ("H.kind-external", DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable, "external-publication-confirmation-unavailable"),
        ("H.kind-unknown", DurableCompletionAuditReceiptAcknowledgementKind::Unknown, "unknown"),
    ] {
        t.check(id, tag, kind.tag());
    }
    t.assert_true(
        "H.kind-is-fixture",
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory.is_fixture(),
    );
    t.assert_true(
        "H.kind-is-unavailable",
        DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable.is_unavailable(),
    );
    for (id, policy, tag) in [
        ("H.policy-disabled", DurableCompletionAuditReceiptAcknowledgementPolicy::Disabled, "disabled"),
        ("H.policy-fixture", DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed, "fixture-allowed"),
        ("H.policy-production", DurableCompletionAuditReceiptAcknowledgementPolicy::ProductionAuditLedgerAckRequired, "production-audit-ledger-ack-required"),
        ("H.policy-mainnet", DurableCompletionAuditReceiptAcknowledgementPolicy::MainNetAuditLedgerAckRequired, "mainnet-audit-ledger-ack-required"),
        ("H.policy-external", DurableCompletionAuditReceiptAcknowledgementPolicy::ExternalPublicationConfirmationRequired, "external-publication-confirmation-required"),
    ] {
        t.check(id, tag, policy.tag());
    }
    t.assert_true(
        "H.policy-is-disabled",
        DurableCompletionAuditReceiptAcknowledgementPolicy::Disabled.is_disabled(),
    );
    t.assert_true(
        "H.policy-allows-fixture",
        DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed.allows_fixture(),
    );
    t.check("H.trait-fixture-kind", "fixture-in-memory", fixture_sink().kind().tag());
    t.check(
        "H.trait-production-kind",
        "production-audit-ledger-ack-unavailable",
        ProductionAuditLedgerDurableCompletionAcknowledgementSink::default().kind().tag(),
    );
    t.check(
        "H.trait-mainnet-kind",
        "mainnet-audit-ledger-ack-unavailable",
        MainNetAuditLedgerDurableCompletionAcknowledgementSink::default().kind().tag(),
    );
    t.check(
        "H.trait-external-kind",
        "external-publication-confirmation-unavailable",
        ExternalPublicationDurableCompletionConfirmationSink::default().kind().tag(),
    );
    let _aliases = std::any::type_name::<(
        DurableCompletionAuditReceiptAcknowledgementSurface,
        DurableCompletionAuditReceiptAcknowledgementEnvironment,
        DurableCompletionAuditReceiptAcknowledgementBinding,
        DurableCompletionAuditReceiptAcknowledgementReplayBinding,
        DurableCompletionAuditReceiptAcknowledgementPipelineBinding,
        DurableCompletionAuditReceiptAcknowledgementSinkBinding,
        DurableCompletionAuditReceiptAcknowledgementReporterBinding,
        DurableCompletionAuditReceiptAcknowledgementFinalizationBinding,
        DurableCompletionAuditReceiptAcknowledgementAttestationBinding,
        DurableCompletionAuditReceiptAcknowledgementBackendBinding,
        DurableCompletionAuditReceiptAcknowledgementReceiptBinding,
        DurableCompletionAuditReceiptAcknowledgementInput,
        DurableCompletionAuditReceiptAcknowledgementPolicy,
        DurableCompletionAuditReceiptAcknowledgementKind,
        DurableCompletionAuditReceiptAcknowledgementIdentity,
        DurableCompletionAuditReceiptAcknowledgementExpectations,
        DurableCompletionAuditReceiptAcknowledgementRequest,
        DurableCompletionAuditReceiptAcknowledgementResponse,
        DurableCompletionAuditReceiptAcknowledgementRecord,
        DurableCompletionAuditReceiptAcknowledgementLedger,
        DurableCompletionAuditReceiptAcknowledgementLedgerRecord,
        DurableCompletionAuditReceiptAcknowledgementDigest,
        DurableCompletionAuditReceiptAcknowledgementTranscriptDigest,
        DurableCompletionAuditReceiptAcknowledgementOutcome,
        DurableCompletionAuditReceiptAcknowledgementRequestIntent,
        DurableCompletionAuditReceiptAcknowledgementFault,
        DurableCompletionAuditReceiptAcknowledgementWindow,
        FixtureDurableCompletionAuditReceiptAcknowledgementSink,
        ProductionAuditLedgerDurableCompletionAcknowledgementSink,
        MainNetAuditLedgerDurableCompletionAcknowledgementSink,
        ExternalPublicationDurableCompletionConfirmationSink,
    )>();
    t.assert_true("H.aliases-and-types", !_aliases.is_empty());
    t.finish(out)
}

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    write_file(&dir.join("success_lifecycle.txt"), &format!(
        "outcome={} authorizes={} projects={} invocations={} ledger_len={} contains={} receipt_outcome={} backend_outcome={}\n",
        o.tag(),
        o.authorizes_acknowledgement_record(),
        o.projects_to_acknowledgement_recorded(),
        sink.invocations(),
        ledger.len(),
        ledger.contains(ACK_RECORD_ID),
        c.receipt.outcome.tag(),
        c.receipt.backend.outcome.tag(),
    ));
    let mut c2 = devnet_ctx();
    c2.expectations.expected_genesis_hash = "wrong-genesis".to_string();
    let mut ledger2 = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink2 = fixture_sink();
    let o2 = drive(&c2.recorded(), &c2.expectations, &mut sink2, &mut ledger2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} invocations={} no_acknowledgement={} ledger_len={}\n",
            o2.tag(),
            sink2.invocations(),
            o2.no_acknowledgement(),
            ledger2.len()
        ),
    );
    let cp = mainnet_peer_ctx();
    let input = cp.peer_input();
    let mut ledger3 = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink3 = MainNetAuditLedgerDurableCompletionAcknowledgementSink::default();
    let o3 = drive(&input, &cp.expectations, &mut sink3, &mut ledger3);
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} invocations={} is_refusal={} ledger_len={}\n",
            o3.tag(),
            sink3.invocations(),
            o3.is_mainnet_peer_driven_apply_refused(),
            ledger3.len()
        ),
    );
    let mut windows = String::new();
    for (label, w, with_record) in [
        ("before-pipeline", DurableCompletionAuditReceiptAcknowledgementWindow::BeforePipeline, false),
        (
            "after-receipt-success-before-ack-request",
            DurableCompletionAuditReceiptAcknowledgementWindow::AfterReceiptSuccessBeforeAcknowledgementRequest,
            false,
        ),
        (
            "after-ack-record-before-success-with-record",
            DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementRecordBeforeAcknowledgementSuccess,
            true,
        ),
        (
            "after-ack-success",
            DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementSuccess,
            true,
        ),
        (
            "after-ack-ambiguous",
            DurableCompletionAuditReceiptAcknowledgementWindow::AfterAcknowledgementAmbiguous,
            false,
        ),
        (
            "ack-rollback-failed",
            DurableCompletionAuditReceiptAcknowledgementWindow::AcknowledgementRollbackFailed,
            false,
        ),
        ("unknown", DurableCompletionAuditReceiptAcknowledgementWindow::Unknown, false),
    ] {
        windows.push_str(&format!("{label}={}\n", recover_devnet(w, with_record).tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("stage_ordering", run_stage_ordering_table),
        ("acknowledgement_ledger", run_acknowledgement_ledger_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper\n\
scope: Run 260 durable-completion audit-receipt acknowledgement boundary (pqc_governance_durable_completion_audit_receipt_acknowledgement: evaluate_durable_completion_audit_receipt_acknowledgement, recover_durable_completion_audit_receipt_acknowledgement_window, project_audit_receipt_outcome_to_acknowledgement_request, acknowledgement_outcome_authorizes_acknowledgement_record, acknowledgement_outcome_projects_to_acknowledgement_recorded, GovernanceDurableCompletionAuditReceiptAcknowledgementSink with FixtureDurableCompletionAuditReceiptAcknowledgementSink / ProductionAuditLedgerDurableCompletionAcknowledgementSink / MainNetAuditLedgerDurableCompletionAcknowledgementSink / ExternalPublicationDurableCompletionConfirmationSink, typed input/expectations/policy/kind/identity/request/response/record/digest/transcript/ledger/outcome/request-intent/fault/window bindings, and invariant helpers) exercised through release-built library symbols (release binary)\n\
note: fixture-only; the fixture acknowledgement sink mutates ONLY the in-memory DurableCompletionAuditReceiptAcknowledgementLedger. No production behavior change, no real audit ledger, no external publication, no Run 070 call, no LivePqcTrustState mutation, no marker/sequence write, no trust swap, no session eviction, no RocksDB/file/schema/migration/storage-format change, no MainNet governance, no MainNet peer-driven apply. Run 246 pipeline success, Run 248 ConsumeReceiptRecorded, Run 250 CompletionReportRecorded, Run 252 DurableCompletionFinalized, Run 254 DurableCompletionAttested, Run 256 BackendSubmissionRecorded, and Run 258 AuditReceiptRecorded are required before any acknowledgement record; only AuditReceiptRecorded creates an acknowledgement request; duplicate identical acknowledgements are idempotent; equivocation fails closed; production/MainNet/external-publication sinks remain reachable but unavailable/fail-closed.\n\n",
    );
    for (name, f) in tables {
        let (p, fcnt) = f(&out_dir);
        total_pass += p;
        total_fail += fcnt;
        summary.push_str(&format!("table {name}: pass={p} fail={fcnt}\n"));
    }
    run_fixture_dump(&out_dir);
    summary.push_str(&format!(
        "\ntotal_pass: {total_pass}\ntotal_fail: {total_fail}\nverdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}
