//! Run 265 — release-built helper for the Run 264 durable-completion consumer
//! settlement-projection sink boundary.
//!
//! Example-only release evidence harness. It is never wired into production. It
//! drives the actual Run 256 backend -> Run 258 receipt -> Run 260
//! acknowledgement -> Run 262 consumer chain and then evaluates the Run 264
//! settlement projection. Projection is intentionally from
//! `input.consumer_binding` through
//! `project_consumer_outcome_to_settlement_projection_request`. The fixture
//! settlement-projection sink mutates only the in-memory
//! `DurableCompletionConsumerSettlementProjectionLedger`.
#![allow(dead_code, unused_imports)]

use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

// Supplemental Run 264 production symbols exercised by the release reachability
// probe (in addition to the symbols already imported by the regression body).
use qbind_node::pqc_governance_durable_completion_consumer_settlement_projection::{
    consumer_settlement_projection_record_digest, consumer_settlement_projection_request_digest,
    consumer_settlement_projection_response_digest, consumer_settlement_projection_transcript_digest,
    DurableCompletionConsumerSettlementProjectionBinding,
    DurableCompletionConsumerSettlementProjectionDigest,
    DurableCompletionConsumerSettlementProjectionEnvironment,
    DurableCompletionConsumerSettlementProjectionLedgerRecord,
    DurableCompletionConsumerSettlementProjectionLedgerSnapshot,
    DurableCompletionConsumerSettlementProjectionLedgerStatus,
    DurableCompletionConsumerSettlementProjectionRecord,
    DurableCompletionConsumerSettlementProjectionResponse,
    DurableCompletionConsumerSettlementProjectionSurface,
    DurableCompletionConsumerSettlementProjectionTranscriptDigest,
};

use qbind_node::pqc_governance_durable_completion_acknowledgement_consumer::{
    consumer_identity_digest, evaluate_durable_completion_acknowledgement_consumer,
    DurableCompletionAcknowledgementConsumerExpectations,
    DurableCompletionAcknowledgementConsumerIdentity,
    DurableCompletionAcknowledgementConsumerInput, DurableCompletionAcknowledgementConsumerKind,
    DurableCompletionAcknowledgementConsumerLedger,
    DurableCompletionAcknowledgementConsumerOutcome,
    DurableCompletionAcknowledgementConsumerPolicy,
    DurableCompletionAcknowledgementConsumerRequest,
    FixtureDurableCompletionAcknowledgementConsumer,
};
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
    acknowledgement_identity_digest, evaluate_durable_completion_audit_receipt_acknowledgement,
    DurableCompletionAuditReceiptAcknowledgementExpectations,
    DurableCompletionAuditReceiptAcknowledgementIdentity,
    DurableCompletionAuditReceiptAcknowledgementInput,
    DurableCompletionAuditReceiptAcknowledgementKind,
    DurableCompletionAuditReceiptAcknowledgementLedger,
    DurableCompletionAuditReceiptAcknowledgementOutcome,
    DurableCompletionAuditReceiptAcknowledgementPolicy,
    DurableCompletionAuditReceiptAcknowledgementRequest,
    FixtureDurableCompletionAuditReceiptAcknowledgementSink,
};
use qbind_node::pqc_governance_durable_completion_consumer_settlement_projection::{
    consumer_settlement_projection_identity_digest,
    durable_completion_settlement_projection_ambiguous_window_fails_closed,
    durable_completion_settlement_projection_attestation_required,
    durable_completion_settlement_projection_backend_submission_required,
    durable_completion_settlement_projection_completion_report_required,
    durable_completion_settlement_projection_external_unavailable,
    durable_completion_settlement_projection_failed_record_never_records,
    durable_completion_settlement_projection_finalization_required,
    durable_completion_settlement_projection_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_settlement_projection_mainnet_peer_driven_apply_refused_first,
    durable_completion_settlement_projection_never_calls_run_070,
    durable_completion_settlement_projection_never_mutates_live_pqc_trust_state,
    durable_completion_settlement_projection_never_writes_sequence_or_marker,
    durable_completion_settlement_projection_no_external_publication,
    durable_completion_settlement_projection_no_real_audit_ledger,
    durable_completion_settlement_projection_no_rocksdb_file_schema_migration_change,
    durable_completion_settlement_projection_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_settlement_projection_pipeline_success_required,
    durable_completion_settlement_projection_policy_change_unsupported,
    durable_completion_settlement_projection_production_mainnet_unavailable,
    durable_completion_settlement_projection_receipt_required,
    durable_completion_settlement_projection_record_required_before_projected,
    durable_completion_settlement_projection_rejection_is_non_mutating,
    durable_completion_settlement_projection_rollback_never_records,
    durable_completion_settlement_projection_sink_receipt_required,
    durable_completion_settlement_projection_validator_set_rotation_unsupported,
    evaluate_durable_completion_consumer_settlement_projection,
    project_consumer_outcome_to_settlement_projection_request,
    recover_durable_completion_consumer_settlement_projection_window,
    settlement_projection_outcome_authorizes_record,
    settlement_projection_outcome_projects_to_recorded,
    DurableCompletionConsumerSettlementProjectionExpectations,
    DurableCompletionConsumerSettlementProjectionFault,
    DurableCompletionConsumerSettlementProjectionIdentity,
    DurableCompletionConsumerSettlementProjectionInput,
    DurableCompletionConsumerSettlementProjectionKind,
    DurableCompletionConsumerSettlementProjectionLedger,
    DurableCompletionConsumerSettlementProjectionOutcome,
    DurableCompletionConsumerSettlementProjectionPolicy,
    DurableCompletionConsumerSettlementProjectionRequest,
    DurableCompletionConsumerSettlementProjectionRequestIntent,
    DurableCompletionConsumerSettlementProjectionWindow, ExternalSettlementProjectionSink,
    FixtureDurableCompletionConsumerSettlementProjectionSink,
    GovernanceDurableCompletionConsumerSettlementProjectionSink, MainNetSettlementProjectionSink,
    ProductionSettlementProjectionSink,
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
const CONSUMER_RECORD_ID: &str = "durable-completion-acknowledgement-consumer-0001";
const CONSUMER_ID: &str = "fixture-consumer-0001";
const CONSUMER_DOMAIN_TAG: &str = "QBIND:run262:domain-separation:v1";
const PROJECTION_RECORD_ID: &str = "durable-completion-consumer-settlement-projection-0001";
const PROJECTION_ID: &str = "fixture-settlement-projection-0001";
const PROJECTION_DOMAIN_TAG: &str = "QBIND:run264:domain-separation:v1";
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
    consumer_record_id: String,
    projection_record_id: String,
    proposal_id: String,
    decision_id: String,
    candidate_digest: String,
}

fn action_label(label: &str) -> ActionLabel {
    ActionLabel {
        backend_record_id: format!("durable-completion-attestation-backend-{label}"),
        receipt_record_id: format!("durable-completion-audit-publication-receipt-{label}"),
        ack_record_id: format!("durable-completion-audit-receipt-acknowledgement-{label}"),
        consumer_record_id: format!("durable-completion-acknowledgement-consumer-{label}"),
        projection_record_id: format!("durable-completion-consumer-settlement-projection-{label}"),
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
        consumer_record_id: CONSUMER_RECORD_ID.to_string(),
        projection_record_id: PROJECTION_RECORD_ID.to_string(),
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
// Run 260 acknowledgement attachment (real upstream stage)
// ===========================================================================

#[derive(Clone)]
struct AttachedAcknowledgement {
    outcome: DurableCompletionAuditReceiptAcknowledgementOutcome,
    ack_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    receipt: AttachedReceipt,
}

fn run260_acknowledgement_identity() -> DurableCompletionAuditReceiptAcknowledgementIdentity {
    DurableCompletionAuditReceiptAcknowledgementIdentity {
        acknowledgement_id: ACK_ID.to_string(),
        kind: DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        policy: DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        domain_separation_tag: ACK_DOMAIN_TAG.to_string(),
    }
}

fn attach_run260_acknowledgement(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    receipt_duplicate: bool,
) -> AttachedAcknowledgement {
    let receipt = attach_run258_receipt(environment, action, false);
    let ack_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: ack_env,
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
    let id = run260_acknowledgement_identity();
    let request = DurableCompletionAuditReceiptAcknowledgementRequest {
        acknowledgement_record_id: action.ack_record_id.clone(),
        environment: ack_env,
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
        expected_environment: ack_env,
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
        expected_identity: id.clone(),
        expected_acknowledgement_kind:
            DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        expected_acknowledgement_policy:
            DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        expected_domain_separation_tag: ACK_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionAuditReceiptAcknowledgementInput {
        policy: DurableCompletionAuditReceiptAcknowledgementPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding: GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding: GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        finalization_binding: GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding: GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: receipt.backend.outcome.clone(),
        receipt_binding: receipt.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionAuditReceiptAcknowledgementLedger::new();
    let mut sink = FixtureDurableCompletionAuditReceiptAcknowledgementSink::new();
    let first = evaluate_durable_completion_audit_receipt_acknowledgement(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded
    );
    let outcome = if receipt_duplicate {
        let second = evaluate_durable_completion_audit_receipt_acknowledgement(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.ack_record_id)
        .expect("recorded Run 260 acknowledgement");
    AttachedAcknowledgement {
        outcome,
        ack_record_id: action.ack_record_id.clone(),
        identity_digest: acknowledgement_identity_digest(&id).as_hex().to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        receipt,
    }
}

// ===========================================================================
// Run 262 acknowledgement consumer attachment (real upstream stage)
// ===========================================================================

#[derive(Clone)]
struct AttachedConsumer {
    outcome: DurableCompletionAcknowledgementConsumerOutcome,
    consumer_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    ack: AttachedAcknowledgement,
}

fn run262_consumer_identity() -> DurableCompletionAcknowledgementConsumerIdentity {
    DurableCompletionAcknowledgementConsumerIdentity {
        consumer_id: CONSUMER_ID.to_string(),
        kind: DurableCompletionAcknowledgementConsumerKind::FixtureInMemory,
        policy: DurableCompletionAcknowledgementConsumerPolicy::FixtureAllowed,
        domain_separation_tag: CONSUMER_DOMAIN_TAG.to_string(),
    }
}

fn attach_run262_consumer(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    consumer_duplicate: bool,
) -> AttachedConsumer {
    let ack = attach_run260_acknowledgement(environment, action, false);
    let consumer_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: consumer_env,
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
    let id = run262_consumer_identity();
    let request = DurableCompletionAcknowledgementConsumerRequest {
        consumer_record_id: action.consumer_record_id.clone(),
        environment: consumer_env,
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
        backend_identity_digest: ack.receipt.backend.identity_digest.clone(),
        backend_request_digest: ack.receipt.backend.request_digest.clone(),
        backend_response_digest: ack.receipt.backend.response_digest.clone(),
        backend_receipt_digest: ack.receipt.backend.receipt_digest.clone(),
        backend_transcript_digest: ack.receipt.backend.transcript_digest.clone(),
        backend_record_id: ack.receipt.backend.backend_record_id.clone(),
        receipt_identity_digest: ack.receipt.identity_digest.clone(),
        receipt_request_digest: ack.receipt.request_digest.clone(),
        receipt_response_digest: ack.receipt.response_digest.clone(),
        receipt_record_digest: ack.receipt.record_digest.clone(),
        receipt_transcript_digest: ack.receipt.transcript_digest.clone(),
        receipt_record_id: ack.receipt.receipt_record_id.clone(),
        acknowledgement_identity_digest: ack.identity_digest.clone(),
        acknowledgement_request_digest: ack.request_digest.clone(),
        acknowledgement_response_digest: ack.response_digest.clone(),
        acknowledgement_record_digest: ack.record_digest.clone(),
        acknowledgement_transcript_digest: ack.transcript_digest.clone(),
        acknowledgement_record_id: ack.ack_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: CONSUMER_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionAcknowledgementConsumerExpectations {
        expected_consumer_record_id: action.consumer_record_id.clone(),
        expected_environment: consumer_env,
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
        expected_backend_identity_digest: ack.receipt.backend.identity_digest.clone(),
        expected_backend_request_digest: ack.receipt.backend.request_digest.clone(),
        expected_backend_response_digest: ack.receipt.backend.response_digest.clone(),
        expected_backend_receipt_digest: ack.receipt.backend.receipt_digest.clone(),
        expected_backend_transcript_digest: ack.receipt.backend.transcript_digest.clone(),
        expected_backend_record_id: ack.receipt.backend.backend_record_id.clone(),
        expected_receipt_identity_digest: ack.receipt.identity_digest.clone(),
        expected_receipt_request_digest: ack.receipt.request_digest.clone(),
        expected_receipt_response_digest: ack.receipt.response_digest.clone(),
        expected_receipt_record_digest: ack.receipt.record_digest.clone(),
        expected_receipt_transcript_digest: ack.receipt.transcript_digest.clone(),
        expected_receipt_record_id: ack.receipt.receipt_record_id.clone(),
        expected_acknowledgement_identity_digest: ack.identity_digest.clone(),
        expected_acknowledgement_request_digest: ack.request_digest.clone(),
        expected_acknowledgement_response_digest: ack.response_digest.clone(),
        expected_acknowledgement_record_digest: ack.record_digest.clone(),
        expected_acknowledgement_transcript_digest: ack.transcript_digest.clone(),
        expected_acknowledgement_record_id: ack.ack_record_id.clone(),
        expected_identity: id.clone(),
        expected_consumer_kind: DurableCompletionAcknowledgementConsumerKind::FixtureInMemory,
        expected_consumer_policy: DurableCompletionAcknowledgementConsumerPolicy::FixtureAllowed,
        expected_domain_separation_tag: CONSUMER_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionAcknowledgementConsumerInput {
        policy: DurableCompletionAcknowledgementConsumerPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding: GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding: GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        finalization_binding: GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding: GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionAcknowledgementConsumerLedger::new();
    let mut sink = FixtureDurableCompletionAcknowledgementConsumer::new();
    let first = evaluate_durable_completion_acknowledgement_consumer(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionAcknowledgementConsumerOutcome::AcknowledgementConsumed
    );
    let outcome = if consumer_duplicate {
        let second = evaluate_durable_completion_acknowledgement_consumer(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionAcknowledgementConsumerOutcome::AcknowledgementConsumerDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.consumer_record_id)
        .expect("recorded Run 262 consumer");
    AttachedConsumer {
        outcome,
        consumer_record_id: action.consumer_record_id.clone(),
        identity_digest: consumer_identity_digest(&id).as_hex().to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        ack,
    }
}

// ===========================================================================
// Run 264 owned-context builder
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    request: DurableCompletionConsumerSettlementProjectionRequest,
    expectations: DurableCompletionConsumerSettlementProjectionExpectations,
    consumer: AttachedConsumer,
}

fn ack_identity(
    policy: DurableCompletionConsumerSettlementProjectionPolicy,
    kind: DurableCompletionConsumerSettlementProjectionKind,
) -> DurableCompletionConsumerSettlementProjectionIdentity {
    DurableCompletionConsumerSettlementProjectionIdentity {
        projection_id: PROJECTION_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: PROJECTION_DOMAIN_TAG.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ctx_action(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionConsumerSettlementProjectionPolicy,
    kind: DurableCompletionConsumerSettlementProjectionKind,
    action: &ActionLabel,
    consumer_duplicate: bool,
) -> Ctx {
    let consumer = attach_run262_consumer(environment, action, consumer_duplicate);
    let ack = &consumer.ack;
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
    let request = DurableCompletionConsumerSettlementProjectionRequest {
        projection_record_id: action.projection_record_id.clone(),
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
        backend_identity_digest: ack.receipt.backend.identity_digest.clone(),
        backend_request_digest: ack.receipt.backend.request_digest.clone(),
        backend_response_digest: ack.receipt.backend.response_digest.clone(),
        backend_receipt_digest: ack.receipt.backend.receipt_digest.clone(),
        backend_transcript_digest: ack.receipt.backend.transcript_digest.clone(),
        backend_record_id: ack.receipt.backend.backend_record_id.clone(),
        receipt_identity_digest: ack.receipt.identity_digest.clone(),
        receipt_request_digest: ack.receipt.request_digest.clone(),
        receipt_response_digest: ack.receipt.response_digest.clone(),
        receipt_record_digest: ack.receipt.record_digest.clone(),
        receipt_transcript_digest: ack.receipt.transcript_digest.clone(),
        receipt_record_id: ack.receipt.receipt_record_id.clone(),
        acknowledgement_identity_digest: ack.identity_digest.clone(),
        acknowledgement_request_digest: ack.request_digest.clone(),
        acknowledgement_response_digest: ack.response_digest.clone(),
        acknowledgement_record_digest: ack.record_digest.clone(),
        acknowledgement_transcript_digest: ack.transcript_digest.clone(),
        acknowledgement_record_id: ack.ack_record_id.clone(),
        consumer_identity_digest: consumer.identity_digest.clone(),
        consumer_request_digest: consumer.request_digest.clone(),
        consumer_response_digest: consumer.response_digest.clone(),
        consumer_record_digest: consumer.record_digest.clone(),
        consumer_transcript_digest: consumer.transcript_digest.clone(),
        consumer_record_id: consumer.consumer_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: PROJECTION_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionConsumerSettlementProjectionExpectations {
        expected_projection_record_id: action.projection_record_id.clone(),
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
        expected_backend_identity_digest: ack.receipt.backend.identity_digest.clone(),
        expected_backend_request_digest: ack.receipt.backend.request_digest.clone(),
        expected_backend_response_digest: ack.receipt.backend.response_digest.clone(),
        expected_backend_receipt_digest: ack.receipt.backend.receipt_digest.clone(),
        expected_backend_transcript_digest: ack.receipt.backend.transcript_digest.clone(),
        expected_backend_record_id: ack.receipt.backend.backend_record_id.clone(),
        expected_receipt_identity_digest: ack.receipt.identity_digest.clone(),
        expected_receipt_request_digest: ack.receipt.request_digest.clone(),
        expected_receipt_response_digest: ack.receipt.response_digest.clone(),
        expected_receipt_record_digest: ack.receipt.record_digest.clone(),
        expected_receipt_transcript_digest: ack.receipt.transcript_digest.clone(),
        expected_receipt_record_id: ack.receipt.receipt_record_id.clone(),
        expected_acknowledgement_identity_digest: ack.identity_digest.clone(),
        expected_acknowledgement_request_digest: ack.request_digest.clone(),
        expected_acknowledgement_response_digest: ack.response_digest.clone(),
        expected_acknowledgement_record_digest: ack.record_digest.clone(),
        expected_acknowledgement_transcript_digest: ack.transcript_digest.clone(),
        expected_acknowledgement_record_id: ack.ack_record_id.clone(),
        expected_consumer_identity_digest: consumer.identity_digest.clone(),
        expected_consumer_request_digest: consumer.request_digest.clone(),
        expected_consumer_response_digest: consumer.response_digest.clone(),
        expected_consumer_record_digest: consumer.record_digest.clone(),
        expected_consumer_transcript_digest: consumer.transcript_digest.clone(),
        expected_consumer_record_id: consumer.consumer_record_id.clone(),
        expected_identity: id,
        expected_projection_kind: kind,
        expected_projection_policy: policy,
        expected_domain_separation_tag: PROJECTION_DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
        consumer,
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionConsumerSettlementProjectionPolicy,
    kind: DurableCompletionConsumerSettlementProjectionKind,
) -> Ctx {
    ctx_action(environment, vs, ms, policy, kind, &default_action(), false)
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input_with_consumer(
        &self,
        policy: DurableCompletionConsumerSettlementProjectionPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
        receipt: DurableCompletionAuditPublicationReceiptOutcome,
        acknowledgement: DurableCompletionAuditReceiptAcknowledgementOutcome,
        consumer: DurableCompletionAcknowledgementConsumerOutcome,
    ) -> DurableCompletionConsumerSettlementProjectionInput {
        DurableCompletionConsumerSettlementProjectionInput {
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
            acknowledgement_binding: acknowledgement,
            consumer_binding: consumer,
            request: self.request.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionConsumerSettlementProjectionPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
    ) -> DurableCompletionConsumerSettlementProjectionInput {
        self.input_with_consumer(
            policy,
            replay,
            pipeline,
            sink,
            reporter,
            finalization,
            attestation,
            backend,
            self.consumer.ack.receipt.outcome.clone(),
            self.consumer.ack.outcome.clone(),
            self.consumer.outcome.clone(),
        )
    }

    fn recorded(&self) -> DurableCompletionConsumerSettlementProjectionInput {
        self.input_with_consumer(
            self.request.identity.policy,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
            self.consumer.ack.receipt.backend.outcome.clone(),
            self.consumer.ack.receipt.outcome.clone(),
            self.consumer.ack.outcome.clone(),
            self.consumer.outcome.clone(),
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
    )
}

fn fixture_sink() -> FixtureDurableCompletionConsumerSettlementProjectionSink {
    FixtureDurableCompletionConsumerSettlementProjectionSink::new()
}
fn disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionConsumerSettlementProjectionPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::LegacyBypassNoSettlementProjection
    );
    assert!(outcome.is_legacy_bypass());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn disabled_backend_policy_never_invokes_receipt_sink() {
    let c = devnet_ctx();
    let input = c.input_with_consumer(
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission,
        DurableCompletionAuditPublicationReceiptOutcome::LegacyBypassNoAuditReceipt,
        DurableCompletionAuditReceiptAcknowledgementOutcome::LegacyBypassNoAcknowledgement,
        DurableCompletionAcknowledgementConsumerOutcome::LegacyBypassNoConsumer,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::LegacyBypassNoSettlementProjection
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission() {
    let c = devnet_ctx();
    let input = c.recorded();
    // The receipt is attached to the actual Run 256 BackendSubmissionRecorded path.
    assert_eq!(
        c.consumer.ack.receipt.backend.outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );
    assert!(settlement_projection_outcome_authorizes_record(&outcome));
    assert!(settlement_projection_outcome_projects_to_recorded(&outcome));
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(PROJECTION_RECORD_ID));
    assert_eq!(
        consumer_settlement_projection_identity_digest(&c.request.identity),
        c.request.identity.digest()
    );
}

fn testnet_fixture_chain_records_exactly_one_receipt() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );
    assert_eq!(ledger.len(), 1);
}

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
            DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
            DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
            &action,
            false,
        );
        assert_eq!(
            c.consumer.ack.receipt.backend.outcome,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
        );
        let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
        let mut sink = fixture_sink();
        let outcome = evaluate_durable_completion_consumer_settlement_projection(
            &c.recorded(),
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            outcome,
            DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded,
            "action {label} must record after backend submission"
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&action.projection_record_id));
    }
}

fn duplicate_identical_receipt_is_idempotent() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let first = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );
    let second = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionDuplicateIdempotent
    );
    assert!(!settlement_projection_outcome_authorizes_record(&second));
    assert!(settlement_projection_outcome_projects_to_recorded(&second));
    assert_eq!(ledger.len(), 1);
}

fn run262_duplicate_idempotent_consumer_only_matches_existing_never_creates() {
    // A real Run 262 AcknowledgementConsumerDuplicateIdempotent outcome with
    // identical digests.
    let dup_ctx = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
        &default_action(),
        true,
    );
    assert_eq!(
        dup_ctx.consumer.outcome,
        DurableCompletionAcknowledgementConsumerOutcome::AcknowledgementConsumerDuplicateIdempotent
    );

    // With no prior receipt, a duplicate-idempotent backend cannot create one.
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real receipt records, the duplicate-idempotent backend matches it.
    let rec_ctx = devnet_ctx();
    let recorded = evaluate_durable_completion_consumer_settlement_projection(
        &rec_ctx.recorded(),
        &rec_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );
    let matched = evaluate_durable_completion_consumer_settlement_projection(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionDuplicateIdempotent
    );
    assert_eq!(ledger.len(), 1);
}

// ===========================================================================
// Production / MainNet audit-ledger / external-publication unavailable matrix
// ===========================================================================

fn production_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::ProductionSettlementProjectionRequired,
        DurableCompletionConsumerSettlementProjectionKind::ProductionSettlementProjectionUnavailable,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = ProductionSettlementProjectionSink::default();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::ProductionSettlementProjectionUnavailableNoProjection
    );
    assert!(ledger.is_empty());
}

fn mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::MainNetSettlementProjectionRequired,
        DurableCompletionConsumerSettlementProjectionKind::MainNetSettlementProjectionUnavailable,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = MainNetSettlementProjectionSink::default();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::MainNetSettlementProjectionUnavailableNoProjection
    );
    assert!(ledger.is_empty());
}

fn external_publication_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::ExternalSettlementProjectionRequired,
        DurableCompletionConsumerSettlementProjectionKind::ExternalSettlementProjectionUnavailable,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = ExternalSettlementProjectionSink::default();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::ExternalSettlementProjectionUnavailableNoProjection
    );
    assert!(ledger.is_empty());
}

fn mainnet_peer_driven_apply_refused_before_receipt_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionConsumerSettlementProjectionPolicy::MainNetSettlementProjectionRequired,
        DurableCompletionConsumerSettlementProjectionKind::MainNetSettlementProjectionUnavailable,
    );
    let input = c.input(
        DurableCompletionConsumerSettlementProjectionPolicy::MainNetSettlementProjectionRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = MainNetSettlementProjectionSink::default();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::MainNetPeerDrivenApplyRefusedNoProjection
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn validator_set_rotation_and_policy_change_unsupported() {
    let c = devnet_ctx();
    let rotation = c.input_with_consumer(
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
        c.consumer.ack.receipt.outcome.clone(),
        c.consumer.ack.outcome.clone(),
        DurableCompletionAcknowledgementConsumerOutcome::ValidatorSetRotationUnsupportedNoConsumer,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &rotation,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::ValidatorSetRotationUnsupportedNoProjection
    );
    assert_eq!(sink.invocations(), 0);

    let policy_change = c.input_with_consumer(
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
        c.consumer.ack.receipt.outcome.clone(),
        c.consumer.ack.outcome.clone(),
        DurableCompletionAcknowledgementConsumerOutcome::PolicyChangeUnsupportedNoConsumer,
    );
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &policy_change,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::PolicyChangeUnsupportedNoProjection
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — non-recording Run 258 receipt outcomes
// ===========================================================================

fn assert_non_recording_consumer(
    consumer: DurableCompletionAcknowledgementConsumerOutcome,
    expected: DurableCompletionConsumerSettlementProjectionOutcome,
) {
    let c = devnet_ctx();
    let input = c.input_with_consumer(
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
        c.consumer.ack.receipt.outcome.clone(),
        c.consumer.ack.outcome.clone(),
        consumer,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_projection());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn non_recording_consumer_outcomes_never_record_projection() {
    use DurableCompletionAcknowledgementConsumerOutcome as Consumer;
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    assert_non_recording_consumer(
        Consumer::LegacyBypassNoConsumer,
        Projection::LegacyBypassNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::RejectedBeforeAcknowledgementNoConsumer,
        Projection::RejectedBeforeConsumerNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::AcknowledgementDidNotRecordNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::AcknowledgementConsumerRejectedBeforeRecord,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::AcknowledgementConsumerRecordFailedNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::AcknowledgementConsumerRolledBackNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::AcknowledgementConsumerRollbackFailedFatalNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::AcknowledgementConsumerAmbiguousFailClosedNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::ProductionSettlementUnavailableNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::MainNetSettlementUnavailableNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::ExternalSettlementUnavailableNoConsumer,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
    );
    assert_non_recording_consumer(
        Consumer::MainNetPeerDrivenApplyRefusedNoConsumer,
        Projection::MainNetPeerDrivenApplyRefusedNoProjection,
    );
    assert_non_recording_consumer(
        Consumer::ValidatorSetRotationUnsupportedNoConsumer,
        Projection::ValidatorSetRotationUnsupportedNoProjection,
    );
    assert_non_recording_consumer(
        Consumer::PolicyChangeUnsupportedNoConsumer,
        Projection::PolicyChangeUnsupportedNoProjection,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — binding mismatch (before sink invocation)
// ===========================================================================

fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::RejectedBeforeConsumerNoSettlementProjection
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn wrong_environment_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_environment = TrustBundleEnvironment::Testnet;
    });
}

fn wrong_chain_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_chain_id = "qbind-other".to_string();
    });
}

fn wrong_genesis_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_genesis_hash = "genesis-other".to_string();
    });
}

fn wrong_governance_surface_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_governance_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    });
}

fn wrong_mutation_surface_rejected_before_sink_invocation() {
    assert_binding_mismatch_rejected(|c| {
        c.expectations.expected_mutation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck;
    });
}

// ===========================================================================
// Rejected / fail-closed matrix — request-identity mismatch (inside sink)
// ===========================================================================

fn assert_request_mismatch_rejected(
    mut mutate: impl FnMut(&mut DurableCompletionConsumerSettlementProjectionRequest),
) {
    let c = devnet_ctx();
    let mut input = c.recorded();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRejectedBeforeRecord
    );
    // The sink is invoked (binding matched) but records nothing.
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

fn wrong_projection_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.projection_record_id = "other-projection".to_string();
    });
}

fn wrong_proposal_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.proposal_id = "other-proposal".to_string();
    });
}

fn wrong_decision_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.decision_id = "other-decision".to_string();
    });
}

fn wrong_candidate_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.candidate_digest = "other-candidate".to_string();
    });
}

fn wrong_authority_domain_sequence_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.authority_domain_sequence = SEQUENCE + 1;
    });
}

fn wrong_pipeline_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.pipeline_decision_digest = "other-pipeline".to_string();
    });
}

fn wrong_sink_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.sink_decision_digest = "other-sink".to_string();
    });
}

fn wrong_reporter_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.reporter_decision_digest = "other-reporter".to_string();
    });
}

fn wrong_finalization_decision_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.finalization_decision_digest = "other-finalization".to_string();
    });
}

fn wrong_attestation_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.attestation_digest = "other-attestation".to_string();
    });
}

fn wrong_attestation_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.attestation_id = "other-attestation-id".to_string();
    });
}

fn wrong_backend_identity_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_identity_digest = "other-backend-identity".to_string();
    });
}

fn wrong_backend_request_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_request_digest = "other-backend-request".to_string();
    });
}

fn wrong_backend_response_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_response_digest = "other-backend-response".to_string();
    });
}

fn wrong_backend_receipt_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_receipt_digest = "other-backend-receipt".to_string();
    });
}

fn wrong_backend_transcript_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_transcript_digest = "other-backend-transcript".to_string();
    });
}

fn wrong_backend_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.backend_record_id = "other-backend-record".to_string();
    });
}

fn wrong_acknowledgement_identity_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.projection_id = "other-receipt-id".to_string();
    });
}

fn wrong_consumer_identity_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_identity_digest = "other-consumer-identity".to_string();
    });
}

fn wrong_consumer_request_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_request_digest = "other-consumer-request".to_string();
    });
}

fn wrong_consumer_response_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_response_digest = "other-consumer-response".to_string();
    });
}

fn wrong_consumer_record_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_record_digest = "other-consumer-record".to_string();
    });
}

fn wrong_consumer_transcript_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_transcript_digest = "other-consumer-transcript".to_string();
    });
}

fn wrong_consumer_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_record_id = "other-consumer-record-id".to_string();
    });
}

fn wrong_receipt_policy_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.policy =
            DurableCompletionConsumerSettlementProjectionPolicy::ProductionSettlementProjectionRequired;
    });
}

fn wrong_receipt_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind =
            DurableCompletionConsumerSettlementProjectionKind::ProductionSettlementProjectionUnavailable;
    });
}

fn wrong_domain_separation_tag_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.domain_separation_tag = "other-domain".to_string();
    });
}

fn malformed_receipt_request_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.proposal_id = String::new();
    });
}

fn same_ack_record_id_different_digest_is_equivocation_no_second_receipt() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();

    let first = evaluate_durable_completion_consumer_settlement_projection(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );

    // A second receipt with the SAME receipt record id but a differing digest fails
    // closed as equivocation. We adjust both request and expectations on a differing
    // field so binding/request validation passes and the equivocation gate rejects.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
    let equivocation = evaluate_durable_completion_consumer_settlement_projection(
        &c2.recorded(),
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRejectedBeforeRecord
    );
    assert_eq!(ledger.len(), 1);
}

fn fixture_sink_rejects_non_devnet_testnet_environment() {
    // A MainNet, non-peer-driven environment reaches the fixture sink (binding
    // matches) but the fixture sink is DevNet/TestNet evidence-only and rejects.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
    );
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRejectedBeforeRecord
    );
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Receipt record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_receipt(
    fault: DurableCompletionConsumerSettlementProjectionFault,
    expected: DurableCompletionConsumerSettlementProjectionOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = FixtureDurableCompletionConsumerSettlementProjectionSink::with_fault(fault);
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_projection());
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

fn receipt_record_failed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionConsumerSettlementProjectionFault::RecordFailedNoProjection,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecordFailedNoProjection,
    );
}

fn receipt_rollback_completed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionConsumerSettlementProjectionFault::RolledBackNoProjection,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRolledBackNoProjection,
    );
}

fn receipt_rollback_failed_fatal_never_records() {
    assert_fault_no_receipt(
        DurableCompletionConsumerSettlementProjectionFault::RollbackFailedFatal,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRollbackFailedFatalNoProjection,
    );
}

fn receipt_ambiguous_window_fails_closed() {
    assert_fault_no_receipt(
        DurableCompletionConsumerSettlementProjectionFault::AmbiguousAfterRecord,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionAmbiguousFailClosedNoProjection,
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

fn only_consumed_outcome_creates_settlement_projection_request_intent() {
    use DurableCompletionAcknowledgementConsumerOutcome as Consumer;
    use DurableCompletionConsumerSettlementProjectionRequestIntent as Intent;
    assert_eq!(
        project_consumer_outcome_to_settlement_projection_request(
            &Consumer::AcknowledgementConsumed
        ),
        Intent::CreateRequest
    );
    assert!(project_consumer_outcome_to_settlement_projection_request(
        &Consumer::AcknowledgementConsumed
    )
    .creates_request());
    assert_eq!(
        project_consumer_outcome_to_settlement_projection_request(
            &Consumer::AcknowledgementConsumerDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    assert!(!project_consumer_outcome_to_settlement_projection_request(
        &Consumer::LegacyBypassNoConsumer
    )
    .creates_request());
}

fn non_consuming_consumer_outcomes_create_no_settlement_projection_request() {
    use DurableCompletionAcknowledgementConsumerOutcome as Consumer;
    use DurableCompletionConsumerSettlementProjectionRequestIntent as Intent;
    for consumer in [
        Consumer::LegacyBypassNoConsumer,
        Consumer::RejectedBeforeAcknowledgementNoConsumer,
        Consumer::AcknowledgementDidNotRecordNoConsumer,
        Consumer::AcknowledgementConsumerRejectedBeforeRecord,
        Consumer::AcknowledgementConsumerRecordFailedNoConsumer,
        Consumer::ProductionSettlementUnavailableNoConsumer,
    ] {
        assert!(matches!(
            project_consumer_outcome_to_settlement_projection_request(&consumer),
            Intent::NoProjection(_)
        ));
    }
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_ledger() -> DurableCompletionConsumerSettlementProjectionLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_consumer_settlement_projection(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionConsumerSettlementProjectionWindow,
    with_record: bool,
    expected: DurableCompletionConsumerSettlementProjectionOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(PROJECTION_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_consumer_settlement_projection_window(
        &input,
        window,
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

fn pre_settlement_projection_windows_fail_closed_no_projection() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionConsumerSettlementProjectionWindow as Window;
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
        Window::AfterBackendSuccessBeforeReceiptRequest,
        Window::AfterReceiptRequestBeforeReceiptRecord,
        Window::AfterReceiptRecordBeforeReceiptSuccess,
        Window::AfterReceiptSuccessBeforeAcknowledgementRequest,
        Window::AfterAcknowledgementRequestBeforeAcknowledgementRecord,
        Window::AfterAcknowledgementRecordBeforeAcknowledgementSuccess,
        Window::AfterAcknowledgementSuccessBeforeConsumerRequest,
        Window::AfterConsumerRequestBeforeConsumerRecord,
        Window::AfterConsumerRecordBeforeConsumerSuccess,
        Window::AfterConsumerSuccessBeforeSettlementProjectionRequest,
    ] {
        assert_window(
            w,
            false,
            Projection::ConsumerDidNotRecordNoSettlementProjection,
        );
    }
}

fn after_settlement_projection_request_before_record_rejects_before_record() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionConsumerSettlementProjectionWindow as Window;
    assert_window(
        Window::AfterSettlementProjectionRequestBeforeSettlementProjectionRecord,
        false,
        Projection::SettlementProjectionRejectedBeforeRecord,
    );
}

fn after_settlement_projection_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionConsumerSettlementProjectionWindow as Window;
    assert_window(
        Window::AfterSettlementProjectionRecordBeforeSettlementProjectionSuccess,
        false,
        Projection::SettlementProjectionRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterSettlementProjectionRecordBeforeSettlementProjectionSuccess,
        true,
        Projection::SettlementProjectionRecorded,
    );
}

fn after_settlement_projection_success_recovers_as_recorded() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionConsumerSettlementProjectionWindow as Window;
    assert_window(
        Window::AfterSettlementProjectionSuccess,
        true,
        Projection::SettlementProjectionRecorded,
    );
    // Without an explicit matching record, even after-success fails closed.
    assert_window(
        Window::AfterSettlementProjectionSuccess,
        false,
        Projection::SettlementProjectionRejectedBeforeRecord,
    );
}

fn ambiguous_record_failed_rollback_and_unknown_windows_fail_closed() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionConsumerSettlementProjectionWindow as Window;
    assert_window(
        Window::AfterSettlementProjectionAmbiguous,
        false,
        Projection::SettlementProjectionAmbiguousFailClosedNoProjection,
    );
    assert_window(
        Window::Unknown,
        false,
        Projection::SettlementProjectionAmbiguousFailClosedNoProjection,
    );
    assert_window(
        Window::SettlementProjectionRecordFailed,
        false,
        Projection::SettlementProjectionRecordFailedNoProjection,
    );
    assert_window(
        Window::SettlementProjectionRollbackCompleted,
        false,
        Projection::SettlementProjectionRolledBackNoProjection,
    );
    assert_window(
        Window::SettlementProjectionRollbackFailed,
        false,
        Projection::SettlementProjectionRollbackFailedFatalNoProjection,
    );
}

fn production_mainnet_external_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_durable_completion_consumer_settlement_projection_window(
        &input,
        DurableCompletionConsumerSettlementProjectionWindow::AfterSettlementProjectionSuccess,
        DurableCompletionConsumerSettlementProjectionKind::ProductionSettlementProjectionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::ProductionSettlementProjectionUnavailableNoProjection
    );
    let outcome = recover_durable_completion_consumer_settlement_projection_window(
        &input,
        DurableCompletionConsumerSettlementProjectionWindow::AfterSettlementProjectionSuccess,
        DurableCompletionConsumerSettlementProjectionKind::MainNetSettlementProjectionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::MainNetSettlementProjectionUnavailableNoProjection
    );
    let outcome = recover_durable_completion_consumer_settlement_projection_window(
        &input,
        DurableCompletionConsumerSettlementProjectionWindow::AfterSettlementProjectionSuccess,
        DurableCompletionConsumerSettlementProjectionKind::ExternalSettlementProjectionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::ExternalSettlementProjectionUnavailableNoProjection
    );
}

fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionConsumerSettlementProjectionPolicy::MainNetSettlementProjectionRequired,
        DurableCompletionConsumerSettlementProjectionKind::MainNetSettlementProjectionUnavailable,
    );
    let input = c.input(
        DurableCompletionConsumerSettlementProjectionPolicy::MainNetSettlementProjectionRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let outcome = recover_durable_completion_consumer_settlement_projection_window(
        &input,
        DurableCompletionConsumerSettlementProjectionWindow::AfterSettlementProjectionSuccess,
        DurableCompletionConsumerSettlementProjectionKind::MainNetSettlementProjectionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::MainNetPeerDrivenApplyRefusedNoProjection
    );
}

// ===========================================================================
// Receipt-ledger cases
// ===========================================================================

fn rollback_restores_receipt_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_consumer_settlement_projection(
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
        DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
        &action,
        false,
    );
    let mut faulted = FixtureDurableCompletionConsumerSettlementProjectionSink::with_fault(
        DurableCompletionConsumerSettlementProjectionFault::RolledBackNoProjection,
    );
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &c2.recorded(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRolledBackNoProjection
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains(&action.projection_record_id));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_settlement_projection_rejection_is_non_mutating());
    assert!(durable_completion_settlement_projection_never_calls_run_070());
    assert!(durable_completion_settlement_projection_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_settlement_projection_never_writes_sequence_or_marker());
    assert!(durable_completion_settlement_projection_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_settlement_projection_no_external_publication());
    assert!(durable_completion_settlement_projection_no_real_audit_ledger());
    assert!(durable_completion_settlement_projection_pipeline_success_required());
    assert!(durable_completion_settlement_projection_sink_receipt_required());
    assert!(durable_completion_settlement_projection_completion_report_required());
    assert!(durable_completion_settlement_projection_finalization_required());
    assert!(durable_completion_settlement_projection_attestation_required());
    assert!(durable_completion_settlement_projection_backend_submission_required());
    assert!(durable_completion_settlement_projection_receipt_required());
    assert!(durable_completion_settlement_projection_record_required_before_projected());
    assert!(durable_completion_settlement_projection_failed_record_never_records());
    assert!(durable_completion_settlement_projection_rollback_never_records());
    assert!(durable_completion_settlement_projection_ambiguous_window_fails_closed());
    assert!(
        durable_completion_settlement_projection_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet
        )
    );
    assert!(
        !durable_completion_settlement_projection_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet
        )
    );
    assert!(durable_completion_settlement_projection_production_mainnet_unavailable());
    assert!(durable_completion_settlement_projection_external_unavailable());
    assert!(durable_completion_settlement_projection_validator_set_rotation_unsupported());
    assert!(durable_completion_settlement_projection_policy_change_unsupported());
    assert!(
        durable_completion_settlement_projection_local_operator_cannot_satisfy_mainnet_authority()
    );
    assert!(
        durable_completion_settlement_projection_peer_majority_cannot_satisfy_mainnet_authority()
    );
}
// ===========================================================================
// Release symbol reachability probe — exercises the Run 264 production library
// symbols in release mode, driving projection from the Run 262 consumer outcome.
// ===========================================================================

fn release_symbol_reachability_probe() {
    let c = devnet_ctx();
    let input: DurableCompletionConsumerSettlementProjectionInput = c.recorded();

    // Projection is driven exclusively from the Run 262 consumer outcome carried
    // by `input.consumer_binding`.
    let intent = project_consumer_outcome_to_settlement_projection_request(&input.consumer_binding);
    assert!(intent.creates_request());
    assert!(matches!(
        intent,
        DurableCompletionConsumerSettlementProjectionRequestIntent::CreateRequest
    ));

    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = FixtureDurableCompletionConsumerSettlementProjectionSink::new();
    let outcome = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );
    assert!(settlement_projection_outcome_authorizes_record(&outcome));
    assert!(settlement_projection_outcome_projects_to_recorded(&outcome));
    assert!(outcome.authorizes_record());
    assert!(outcome.projects_to_recorded());
    assert!(!outcome.no_projection());
    assert_eq!(outcome.tag(), "settlement-projection-recorded");
    assert_eq!(
        sink.kind(),
        DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory
    );
    assert_eq!(sink.invocations(), 1);

    let identity_digest: DurableCompletionConsumerSettlementProjectionDigest =
        consumer_settlement_projection_identity_digest(&c.request.identity);
    let request_digest: DurableCompletionConsumerSettlementProjectionDigest =
        consumer_settlement_projection_request_digest(&c.request);
    let response = DurableCompletionConsumerSettlementProjectionResponse {
        projection_record_id: c.request.projection_record_id.clone(),
        request_digest: request_digest.clone(),
        accepted: true,
        projection_kind: DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
    };
    assert!(response.is_well_formed());
    let response_digest: DurableCompletionConsumerSettlementProjectionDigest =
        consumer_settlement_projection_response_digest(&response);
    let record: DurableCompletionConsumerSettlementProjectionRecord = c.request.to_record();
    let record_digest: DurableCompletionConsumerSettlementProjectionDigest =
        consumer_settlement_projection_record_digest(&record);
    let transcript_digest: DurableCompletionConsumerSettlementProjectionTranscriptDigest =
        consumer_settlement_projection_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );
    assert!(!identity_digest.as_hex().is_empty());
    assert!(!transcript_digest.as_hex().is_empty());

    let ledger_record: &DurableCompletionConsumerSettlementProjectionLedgerRecord = ledger
        .find(PROJECTION_RECORD_ID)
        .expect("settlement-projection ledger record");
    assert_eq!(
        ledger_record.status,
        DurableCompletionConsumerSettlementProjectionLedgerStatus::Recorded
    );
    let snapshot: DurableCompletionConsumerSettlementProjectionLedgerSnapshot = ledger.snapshot();
    assert_eq!(snapshot.len(), 1);

    let _surface: DurableCompletionConsumerSettlementProjectionSurface = input.surface();
    let _environment: DurableCompletionConsumerSettlementProjectionEnvironment =
        input.environment_binding.clone();
    let _binding: DurableCompletionConsumerSettlementProjectionBinding = input.runtime_binding.clone();

    assert!(DurableCompletionConsumerSettlementProjectionPolicy::Disabled.is_disabled());
    assert!(DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed.allows_fixture());
    assert_eq!(
        DurableCompletionConsumerSettlementProjectionPolicy::ProductionSettlementProjectionRequired
            .tag(),
        "production-settlement-projection-required"
    );
    assert!(DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory.is_fixture());
    assert!(
        DurableCompletionConsumerSettlementProjectionKind::ProductionSettlementProjectionUnavailable
            .is_unavailable()
    );
    assert_eq!(
        DurableCompletionConsumerSettlementProjectionKind::Disabled.tag(),
        "disabled"
    );
    let no_projection =
        DurableCompletionConsumerSettlementProjectionOutcome::LegacyBypassNoSettlementProjection;
    assert!(no_projection.is_legacy_bypass());
    assert!(no_projection.no_projection());
    assert!(
        DurableCompletionConsumerSettlementProjectionOutcome::MainNetPeerDrivenApplyRefusedNoProjection
            .is_mainnet_peer_driven_apply_refused()
    );

    // Production / MainNet / external settlement-projection sinks are reachable but
    // unavailable / fail-closed: they record nothing.
    let mut prod = ProductionSettlementProjectionSink::default();
    let mut mainnet = MainNetSettlementProjectionSink::default();
    let mut external = ExternalSettlementProjectionSink::default();
    let mut prod_ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    assert_eq!(
        prod.project_durable_completion_consumer_settlement(
            &c.request,
            &c.expectations,
            false,
            &mut prod_ledger
        ),
        DurableCompletionConsumerSettlementProjectionOutcome::ProductionSettlementProjectionUnavailableNoProjection
    );
    assert_eq!(
        mainnet.project_durable_completion_consumer_settlement(
            &c.request,
            &c.expectations,
            false,
            &mut prod_ledger
        ),
        DurableCompletionConsumerSettlementProjectionOutcome::MainNetSettlementProjectionUnavailableNoProjection
    );
    assert_eq!(
        external.project_durable_completion_consumer_settlement(
            &c.request,
            &c.expectations,
            false,
            &mut prod_ledger
        ),
        DurableCompletionConsumerSettlementProjectionOutcome::ExternalSettlementProjectionUnavailableNoProjection
    );
    assert!(prod_ledger.is_empty());
}

fn run_case(table: &str, name: &str, f: fn(), rows: &mut Vec<(String, String, bool)>) {
    let ok = catch_unwind(AssertUnwindSafe(f)).is_ok();
    println!("case {table} {name} {}", if ok { "PASS" } else { "FAIL" });
    rows.push((table.to_string(), name.to_string(), ok));
}

fn main() {
    let outdir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("docs/devnet/run_265_durable_completion_consumer_settlement_projection_release_binary/helper_evidence/run_265")
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");
    let mut rows: Vec<(String, String, bool)> = Vec::new();
    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation", disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation as fn()),
        ("accepted_compatible", "disabled_backend_policy_never_invokes_receipt_sink", disabled_backend_policy_never_invokes_receipt_sink as fn()),
        ("accepted_compatible", "devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission", devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission as fn()),
        ("accepted_compatible", "testnet_fixture_chain_records_exactly_one_receipt", testnet_fixture_chain_records_exactly_one_receipt as fn()),
        ("accepted_compatible", "governance_action_variants_record_only_after_backend_submission", governance_action_variants_record_only_after_backend_submission as fn()),
        ("accepted_compatible", "duplicate_identical_receipt_is_idempotent", duplicate_identical_receipt_is_idempotent as fn()),
        ("accepted_compatible", "run262_duplicate_idempotent_consumer_only_matches_existing_never_creates", run262_duplicate_idempotent_consumer_only_matches_existing_never_creates as fn()),
        ("accepted_compatible", "production_audit_ledger_path_reachable_but_unavailable_records_nothing", production_audit_ledger_path_reachable_but_unavailable_records_nothing as fn()),
        ("accepted_compatible", "mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing", mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing as fn()),
        ("accepted_compatible", "external_publication_path_reachable_but_unavailable_records_nothing", external_publication_path_reachable_but_unavailable_records_nothing as fn()),
        ("accepted_compatible", "mainnet_peer_driven_apply_refused_before_receipt_sink_invocation", mainnet_peer_driven_apply_refused_before_receipt_sink_invocation as fn()),
        ("accepted_compatible", "validator_set_rotation_and_policy_change_unsupported", validator_set_rotation_and_policy_change_unsupported as fn()),
        ("accepted_compatible", "mainnet_peer_driven_refusal_precedes_recovery_classification", mainnet_peer_driven_refusal_precedes_recovery_classification as fn()),
        ("rejection_fail_closed", "non_recording_consumer_outcomes_never_record_projection", non_recording_consumer_outcomes_never_record_projection as fn()),
        ("rejection_fail_closed", "wrong_environment_rejected_before_sink_invocation", wrong_environment_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_chain_rejected_before_sink_invocation", wrong_chain_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_genesis_rejected_before_sink_invocation", wrong_genesis_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_governance_surface_rejected_before_sink_invocation", wrong_governance_surface_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_mutation_surface_rejected_before_sink_invocation", wrong_mutation_surface_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_projection_record_id_rejected_before_record", wrong_projection_record_id_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_proposal_id_rejected_before_record", wrong_proposal_id_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_decision_id_rejected_before_record", wrong_decision_id_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_candidate_digest_rejected_before_record", wrong_candidate_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_authority_domain_sequence_rejected_before_record", wrong_authority_domain_sequence_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_pipeline_decision_digest_rejected_before_record", wrong_pipeline_decision_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_sink_decision_digest_rejected_before_record", wrong_sink_decision_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_reporter_decision_digest_rejected_before_record", wrong_reporter_decision_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_finalization_decision_digest_rejected_before_record", wrong_finalization_decision_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_attestation_digest_rejected_before_record", wrong_attestation_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_attestation_id_rejected_before_record", wrong_attestation_id_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_backend_identity_digest_rejected_before_record", wrong_backend_identity_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_backend_request_digest_rejected_before_record", wrong_backend_request_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_backend_response_digest_rejected_before_record", wrong_backend_response_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_backend_receipt_digest_rejected_before_record", wrong_backend_receipt_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_backend_transcript_digest_rejected_before_record", wrong_backend_transcript_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_backend_record_id_rejected_before_record", wrong_backend_record_id_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_acknowledgement_identity_rejected_before_record", wrong_acknowledgement_identity_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_consumer_identity_digest_rejected_before_record", wrong_consumer_identity_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_consumer_request_digest_rejected_before_record", wrong_consumer_request_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_consumer_response_digest_rejected_before_record", wrong_consumer_response_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_consumer_record_digest_rejected_before_record", wrong_consumer_record_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_consumer_transcript_digest_rejected_before_record", wrong_consumer_transcript_digest_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_consumer_record_id_rejected_before_record", wrong_consumer_record_id_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_receipt_policy_rejected_before_record", wrong_receipt_policy_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_receipt_kind_rejected_before_record", wrong_receipt_kind_rejected_before_record as fn()),
        ("rejection_fail_closed", "wrong_domain_separation_tag_rejected_before_record", wrong_domain_separation_tag_rejected_before_record as fn()),
        ("rejection_fail_closed", "malformed_receipt_request_rejected_before_record", malformed_receipt_request_rejected_before_record as fn()),
        ("rejection_fail_closed", "same_ack_record_id_different_digest_is_equivocation_no_second_receipt", same_ack_record_id_different_digest_is_equivocation_no_second_receipt as fn()),
        ("rejection_fail_closed", "fixture_sink_rejects_non_devnet_testnet_environment", fixture_sink_rejects_non_devnet_testnet_environment as fn()),
        ("rejection_fail_closed", "receipt_record_failed_never_records", receipt_record_failed_never_records as fn()),
        ("rejection_fail_closed", "receipt_rollback_completed_never_records", receipt_rollback_completed_never_records as fn()),
        ("rejection_fail_closed", "receipt_rollback_failed_fatal_never_records", receipt_rollback_failed_fatal_never_records as fn()),
        ("rejection_fail_closed", "receipt_ambiguous_window_fails_closed", receipt_ambiguous_window_fails_closed as fn()),
        ("rejection_fail_closed", "non_consuming_consumer_outcomes_create_no_settlement_projection_request", non_consuming_consumer_outcomes_create_no_settlement_projection_request as fn()),
        ("recovery_crash_window", "devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission", devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission as fn()),
        ("recovery_crash_window", "governance_action_variants_record_only_after_backend_submission", governance_action_variants_record_only_after_backend_submission as fn()),
        ("recovery_crash_window", "pre_settlement_projection_windows_fail_closed_no_projection", pre_settlement_projection_windows_fail_closed_no_projection as fn()),
        ("recovery_crash_window", "after_settlement_projection_request_before_record_rejects_before_record", after_settlement_projection_request_before_record_rejects_before_record as fn()),
        ("recovery_crash_window", "after_settlement_projection_record_before_success_requires_explicit_matching_record", after_settlement_projection_record_before_success_requires_explicit_matching_record as fn()),
        ("recovery_crash_window", "after_settlement_projection_success_recovers_as_recorded", after_settlement_projection_success_recovers_as_recorded as fn()),
        ("recovery_crash_window", "ambiguous_record_failed_rollback_and_unknown_windows_fail_closed", ambiguous_record_failed_rollback_and_unknown_windows_fail_closed as fn()),
        ("recovery_crash_window", "production_mainnet_external_recovery_classification_unavailable", production_mainnet_external_recovery_classification_unavailable as fn()),
        ("recovery_crash_window", "mainnet_peer_driven_refusal_precedes_recovery_classification", mainnet_peer_driven_refusal_precedes_recovery_classification as fn()),
        ("projection", "only_consumed_outcome_creates_settlement_projection_request_intent", only_consumed_outcome_creates_settlement_projection_request_intent as fn()),
        ("projection", "non_consuming_consumer_outcomes_create_no_settlement_projection_request", non_consuming_consumer_outcomes_create_no_settlement_projection_request as fn()),
        ("projection", "run262_duplicate_idempotent_consumer_only_matches_existing_never_creates", run262_duplicate_idempotent_consumer_only_matches_existing_never_creates as fn()),
        ("settlement_projection_ledger", "duplicate_identical_receipt_is_idempotent", duplicate_identical_receipt_is_idempotent as fn()),
        ("settlement_projection_ledger", "same_ack_record_id_different_digest_is_equivocation_no_second_receipt", same_ack_record_id_different_digest_is_equivocation_no_second_receipt as fn()),
        ("settlement_projection_ledger", "rollback_restores_receipt_ledger_snapshot", rollback_restores_receipt_ledger_snapshot as fn()),
        ("non_mutation", "disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation", disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation as fn()),
        ("non_mutation", "disabled_backend_policy_never_invokes_receipt_sink", disabled_backend_policy_never_invokes_receipt_sink as fn()),
        ("non_mutation", "non_recording_consumer_outcomes_never_record_projection", non_recording_consumer_outcomes_never_record_projection as fn()),
        ("non_mutation", "non_consuming_consumer_outcomes_create_no_settlement_projection_request", non_consuming_consumer_outcomes_create_no_settlement_projection_request as fn()),
        ("non_mutation", "invariant_helpers_assert_fail_closed_contract", invariant_helpers_assert_fail_closed_contract as fn()),
        ("reachability", "release_symbol_reachability_probe", release_symbol_reachability_probe as fn()),
        ("stage_ordering", "malformed_receipt_request_rejected_before_record", malformed_receipt_request_rejected_before_record as fn()),
        ("stage_ordering", "devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission", devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission as fn()),
        ("stage_ordering", "governance_action_variants_record_only_after_backend_submission", governance_action_variants_record_only_after_backend_submission as fn()),
        ("stage_ordering", "mainnet_peer_driven_apply_refused_before_receipt_sink_invocation", mainnet_peer_driven_apply_refused_before_receipt_sink_invocation as fn()),
        ("stage_ordering", "mainnet_peer_driven_refusal_precedes_recovery_classification", mainnet_peer_driven_refusal_precedes_recovery_classification as fn()),
    ];
    for (table, name, f) in cases {
        run_case(table, name, *f, &mut rows);
    }
    let mut tables = std::collections::BTreeMap::<String, (usize, usize)>::new();
    for (table, _name, ok) in &rows {
        let entry = tables.entry(table.clone()).or_insert((0, 0));
        if *ok { entry.0 += 1; } else { entry.1 += 1; }
    }
    let total_pass: usize = rows.iter().filter(|(_, _, ok)| *ok).count();
    let total_fail = rows.len() - total_pass;
    let mut summary = String::new();
    summary.push_str("Run 265 durable-completion consumer settlement-projection release helper\n");
    summary.push_str(&format!("verdict: {}\n", if total_fail == 0 { "PASS" } else { "FAIL" }));
    summary.push_str("projection_rule: input.consumer_binding -> project_consumer_outcome_to_settlement_projection_request\n");
    summary.push_str("attached_chain: Run256 backend -> Run258 receipt -> Run260 acknowledgement -> Run262 consumer -> Run264 settlement projection\n");
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));
    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");
    fs::write(outdir.join("fixtures/run_265_projection_rule.txt"), "input.consumer_binding\nproject_consumer_outcome_to_settlement_projection_request\nAcknowledgementConsumed -> CreateRequest\n").expect("write projection fixture");
    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}
