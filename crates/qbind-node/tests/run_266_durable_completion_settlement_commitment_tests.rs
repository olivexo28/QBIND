//! Run 266 — source/test durable-completion consumer settlement-projection tests.
//!
//! Mirrors Run 262 while driving the real Run 256 backend submission, the real
//! Run 258 audit/publication receipt, the real Run 260 audit-receipt
//! acknowledgement, and the real Run 262 acknowledgement consumer before
//! evaluating the Run 266 settlement projection.

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
    evaluate_durable_completion_consumer_settlement_projection,
    DurableCompletionConsumerSettlementProjectionExpectations,
    DurableCompletionConsumerSettlementProjectionIdentity,
    DurableCompletionConsumerSettlementProjectionInput,
    DurableCompletionConsumerSettlementProjectionKind,
    DurableCompletionConsumerSettlementProjectionLedger,
    DurableCompletionConsumerSettlementProjectionOutcome,
    DurableCompletionConsumerSettlementProjectionPolicy,
    DurableCompletionConsumerSettlementProjectionRequest,
    FixtureDurableCompletionConsumerSettlementProjectionSink,
};
use qbind_node::pqc_governance_durable_completion_settlement_commitment::{
    settlement_commitment_identity_digest,
    durable_completion_settlement_commitment_ambiguous_window_fails_closed,
    durable_completion_settlement_commitment_attestation_required,
    durable_completion_settlement_commitment_backend_submission_required,
    durable_completion_settlement_commitment_completion_report_required,
    durable_completion_settlement_commitment_external_unavailable,
    durable_completion_settlement_commitment_failed_record_never_records,
    durable_completion_settlement_commitment_finalization_required,
    durable_completion_settlement_commitment_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_settlement_commitment_mainnet_peer_driven_apply_refused_first,
    durable_completion_settlement_commitment_never_calls_run_070,
    durable_completion_settlement_commitment_never_mutates_live_pqc_trust_state,
    durable_completion_settlement_commitment_never_writes_sequence_or_marker,
    durable_completion_settlement_commitment_no_external_publication,
    durable_completion_settlement_commitment_no_real_audit_ledger,
    durable_completion_settlement_commitment_no_rocksdb_file_schema_migration_change,
    durable_completion_settlement_commitment_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_settlement_commitment_pipeline_success_required,
    durable_completion_settlement_commitment_policy_change_unsupported,
    durable_completion_settlement_commitment_production_mainnet_unavailable,
    durable_completion_settlement_commitment_receipt_required,
    durable_completion_settlement_commitment_record_required_before_committed,
    durable_completion_settlement_commitment_rejection_is_non_mutating,
    durable_completion_settlement_commitment_rollback_never_records,
    durable_completion_settlement_commitment_sink_receipt_required,
    durable_completion_settlement_commitment_validator_set_rotation_unsupported,
    evaluate_durable_completion_settlement_commitment,
    project_settlement_projection_outcome_to_commitment_request,
    recover_durable_completion_settlement_commitment_window,
    settlement_commitment_outcome_authorizes_record,
    settlement_commitment_outcome_projects_to_recorded,
    DurableCompletionSettlementCommitmentExpectations,
    DurableCompletionSettlementCommitmentFault,
    DurableCompletionSettlementCommitmentIdentity,
    DurableCompletionSettlementCommitmentInput,
    DurableCompletionSettlementCommitmentKind,
    DurableCompletionSettlementCommitmentLedger,
    DurableCompletionSettlementCommitmentOutcome,
    DurableCompletionSettlementCommitmentPolicy,
    DurableCompletionSettlementCommitmentRequest,
    DurableCompletionSettlementCommitmentRequestIntent,
    DurableCompletionSettlementCommitmentWindow, ExternalSettlementCommitmentSink,
    FixtureDurableCompletionSettlementCommitmentSink,
    GovernanceDurableCompletionSettlementCommitmentSink, MainNetSettlementCommitmentSink,
    ProductionSettlementCommitmentSink,
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
const COMMITMENT_RECORD_ID: &str = "durable-completion-settlement-commitment-0001";
const COMMITMENT_ID: &str = "fixture-settlement-commitment-0001";
const COMMITMENT_DOMAIN_TAG: &str = "QBIND:run266:domain-separation:v1";
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
    commitment_record_id: String,
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
        commitment_record_id: format!("durable-completion-settlement-commitment-{label}"),
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
        commitment_record_id: COMMITMENT_RECORD_ID.to_string(),
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
// Run 264 settlement-projection attachment (carried upstream input)
// ===========================================================================

/// A real Run 264 settlement-projection record produced by driving the actual
/// `evaluate_durable_completion_consumer_settlement_projection` round-trip on top
/// of the real Run 262 consumer chain. The Run 266 settlement-commitment boundary
/// projects this terminal outcome; it is never a faked, unattached projection.
struct AttachedSettlementProjection {
    outcome: DurableCompletionConsumerSettlementProjectionOutcome,
    projection_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
}

fn run264_projection_identity() -> DurableCompletionConsumerSettlementProjectionIdentity {
    DurableCompletionConsumerSettlementProjectionIdentity {
        projection_id: PROJECTION_ID.to_string(),
        kind: DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
        policy: DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        domain_separation_tag: PROJECTION_DOMAIN_TAG.to_string(),
    }
}

fn attach_run264_settlement_projection(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    projection_duplicate: bool,
) -> AttachedSettlementProjection {
    let consumer = attach_run262_consumer(environment, action, false);
    let ack = &consumer.ack;
    let projection_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: projection_env,
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
    let id = run264_projection_identity();
    let request = DurableCompletionConsumerSettlementProjectionRequest {
        projection_record_id: action.projection_record_id.clone(),
        environment: projection_env,
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
        expected_environment: projection_env,
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
        expected_consumer_identity_digest: consumer.identity_digest.clone(),
        expected_consumer_request_digest: consumer.request_digest.clone(),
        expected_consumer_response_digest: consumer.response_digest.clone(),
        expected_consumer_record_digest: consumer.record_digest.clone(),
        expected_consumer_transcript_digest: consumer.transcript_digest.clone(),
        expected_consumer_record_id: consumer.consumer_record_id.clone(),
        expected_identity: id.clone(),
        expected_projection_kind: DurableCompletionConsumerSettlementProjectionKind::FixtureInMemory,
        expected_projection_policy:
            DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
        expected_domain_separation_tag: PROJECTION_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionConsumerSettlementProjectionInput {
        policy: DurableCompletionConsumerSettlementProjectionPolicy::FixtureAllowed,
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
        consumer_binding: consumer.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionConsumerSettlementProjectionLedger::new();
    let mut sink = FixtureDurableCompletionConsumerSettlementProjectionSink::new();
    let first = evaluate_durable_completion_consumer_settlement_projection(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded
    );
    let outcome = if projection_duplicate {
        let second = evaluate_durable_completion_consumer_settlement_projection(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.projection_record_id)
        .expect("recorded Run 264 settlement projection");
    AttachedSettlementProjection {
        outcome,
        projection_record_id: action.projection_record_id.clone(),
        identity_digest: consumer_settlement_projection_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
    }
}

// ===========================================================================
// Run 266 owned-context builder
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    request: DurableCompletionSettlementCommitmentRequest,
    expectations: DurableCompletionSettlementCommitmentExpectations,
    consumer: AttachedConsumer,
    settlement_projection: AttachedSettlementProjection,
}

fn ack_identity(
    policy: DurableCompletionSettlementCommitmentPolicy,
    kind: DurableCompletionSettlementCommitmentKind,
) -> DurableCompletionSettlementCommitmentIdentity {
    DurableCompletionSettlementCommitmentIdentity {
        projection_id: COMMITMENT_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: COMMITMENT_DOMAIN_TAG.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ctx_action(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionSettlementCommitmentPolicy,
    kind: DurableCompletionSettlementCommitmentKind,
    action: &ActionLabel,
    consumer_duplicate: bool,
) -> Ctx {
    let settlement_projection =
        attach_run264_settlement_projection(environment, action, consumer_duplicate);
    let consumer = settlement_projection.consumer.clone();
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
    let request = DurableCompletionSettlementCommitmentRequest {
        commitment_record_id: action.commitment_record_id.clone(),
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
        settlement_projection_identity_digest: settlement_projection.identity_digest.clone(),
        settlement_projection_request_digest: settlement_projection.request_digest.clone(),
        settlement_projection_response_digest: settlement_projection.response_digest.clone(),
        settlement_projection_record_digest: settlement_projection.record_digest.clone(),
        settlement_projection_transcript_digest: settlement_projection.transcript_digest.clone(),
        settlement_projection_record_id: settlement_projection.projection_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: COMMITMENT_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionSettlementCommitmentExpectations {
        expected_commitment_record_id: action.commitment_record_id.clone(),
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
        expected_settlement_projection_identity_digest: settlement_projection.identity_digest.clone(),
        expected_settlement_projection_request_digest: settlement_projection.request_digest.clone(),
        expected_settlement_projection_response_digest: settlement_projection
            .response_digest
            .clone(),
        expected_settlement_projection_record_digest: settlement_projection.record_digest.clone(),
        expected_settlement_projection_transcript_digest: settlement_projection
            .transcript_digest
            .clone(),
        expected_settlement_projection_record_id: settlement_projection.projection_record_id.clone(),
        expected_identity: id,
        expected_commitment_kind: kind,
        expected_commitment_policy: policy,
        expected_domain_separation_tag: COMMITMENT_DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
        consumer,
        settlement_projection,
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionSettlementCommitmentPolicy,
    kind: DurableCompletionSettlementCommitmentKind,
) -> Ctx {
    ctx_action(environment, vs, ms, policy, kind, &default_action(), false)
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input_with_projection(
        &self,
        policy: DurableCompletionSettlementCommitmentPolicy,
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
        settlement_projection: DurableCompletionConsumerSettlementProjectionOutcome,
    ) -> DurableCompletionSettlementCommitmentInput {
        DurableCompletionSettlementCommitmentInput {
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
            settlement_projection_binding: settlement_projection,
            request: self.request.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionSettlementCommitmentPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        finalization: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
    ) -> DurableCompletionSettlementCommitmentInput {
        self.input_with_projection(
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
            self.settlement_projection.outcome.clone(),
        )
    }

    fn recorded(&self) -> DurableCompletionSettlementCommitmentInput {
        self.input_with_projection(
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
            self.settlement_projection.outcome.clone(),
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableCompletionSettlementCommitmentKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableCompletionSettlementCommitmentKind::FixtureInMemory,
    )
}

fn fixture_sink() -> FixtureDurableCompletionSettlementCommitmentSink {
    FixtureDurableCompletionSettlementCommitmentSink::new()
}
#[test]
fn disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionSettlementCommitmentPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::LegacyBypassNoSettlementCommitment
    );
    assert!(outcome.is_legacy_bypass());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_backend_policy_never_invokes_receipt_sink() {
    let c = devnet_ctx();
    let input = c.input_with_projection(
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
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
        DurableCompletionConsumerSettlementProjectionOutcome::LegacyBypassNoSettlementProjection,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::LegacyBypassNoSettlementCommitment
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
        c.consumer.ack.receipt.backend.outcome,
        DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded
    );
    assert!(settlement_commitment_outcome_authorizes_record(&outcome));
    assert!(settlement_commitment_outcome_projects_to_recorded(&outcome));
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(COMMITMENT_RECORD_ID));
    assert_eq!(
        settlement_commitment_identity_digest(&c.request.identity),
        c.request.identity.digest()
    );
}

#[test]
fn testnet_fixture_chain_records_exactly_one_receipt() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded
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
            DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
            DurableCompletionSettlementCommitmentKind::FixtureInMemory,
            &action,
            false,
        );
        assert_eq!(
            c.consumer.ack.receipt.backend.outcome,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
        );
        let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
        let mut sink = fixture_sink();
        let outcome = evaluate_durable_completion_settlement_commitment(
            &c.recorded(),
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            outcome,
            DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded,
            "action {label} must record after backend submission"
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&action.commitment_record_id));
    }
}

#[test]
fn duplicate_identical_receipt_is_idempotent() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let first = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded
    );
    let second = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentDuplicateIdempotent
    );
    assert!(!settlement_commitment_outcome_authorizes_record(&second));
    assert!(settlement_commitment_outcome_projects_to_recorded(&second));
    assert_eq!(ledger.len(), 1);
}

#[test]
fn run264_duplicate_idempotent_projection_only_matches_existing_never_creates() {
    // A real Run 264 SettlementProjectionDuplicateIdempotent outcome with
    // identical digests.
    let dup_ctx = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableCompletionSettlementCommitmentKind::FixtureInMemory,
        &default_action(),
        true,
    );
    assert_eq!(
        dup_ctx.settlement_projection.outcome,
        DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionDuplicateIdempotent
    );

    // With no prior receipt, a duplicate-idempotent backend cannot create one.
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real receipt records, the duplicate-idempotent backend matches it.
    let rec_ctx = devnet_ctx();
    let recorded = evaluate_durable_completion_settlement_commitment(
        &rec_ctx.recorded(),
        &rec_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded
    );
    let matched = evaluate_durable_completion_settlement_commitment(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentDuplicateIdempotent
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
        DurableCompletionSettlementCommitmentPolicy::ProductionSettlementCommitmentRequired,
        DurableCompletionSettlementCommitmentKind::ProductionSettlementCommitmentUnavailable,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = ProductionSettlementCommitmentSink::default();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::ProductionSettlementCommitmentUnavailableNoCommitment
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementCommitmentPolicy::MainNetSettlementCommitmentRequired,
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = MainNetSettlementCommitmentSink::default();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::MainNetSettlementCommitmentUnavailableNoCommitment
    );
    assert!(ledger.is_empty());
}

#[test]
fn external_publication_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementCommitmentPolicy::ExternalSettlementCommitmentRequired,
        DurableCompletionSettlementCommitmentKind::ExternalSettlementCommitmentUnavailable,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = ExternalSettlementCommitmentSink::default();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::ExternalSettlementCommitmentUnavailableNoCommitment
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_receipt_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionSettlementCommitmentPolicy::MainNetSettlementCommitmentRequired,
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable,
    );
    let input = c.input(
        DurableCompletionSettlementCommitmentPolicy::MainNetSettlementCommitmentRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = MainNetSettlementCommitmentSink::default();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::MainNetPeerDrivenApplyRefusedNoCommitment
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_and_policy_change_unsupported() {
    let c = devnet_ctx();
    let rotation = c.input_with_projection(
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
        c.consumer.ack.receipt.outcome.clone(),
        c.consumer.ack.outcome.clone(),
        c.consumer.outcome.clone(),
        DurableCompletionConsumerSettlementProjectionOutcome::ValidatorSetRotationUnsupportedNoProjection,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &rotation,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::ValidatorSetRotationUnsupportedNoCommitment
    );
    assert_eq!(sink.invocations(), 0);

    let policy_change = c.input_with_projection(
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
        c.consumer.ack.receipt.outcome.clone(),
        c.consumer.ack.outcome.clone(),
        c.consumer.outcome.clone(),
        DurableCompletionConsumerSettlementProjectionOutcome::PolicyChangeUnsupportedNoProjection,
    );
    let outcome = evaluate_durable_completion_settlement_commitment(
        &policy_change,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::PolicyChangeUnsupportedNoCommitment
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — non-recording Run 258 receipt outcomes
// ===========================================================================

fn assert_non_recording_projection(
    settlement_projection: DurableCompletionConsumerSettlementProjectionOutcome,
    expected: DurableCompletionSettlementCommitmentOutcome,
) {
    let c = devnet_ctx();
    let input = c.input_with_projection(
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
        c.consumer.ack.receipt.outcome.clone(),
        c.consumer.ack.outcome.clone(),
        c.consumer.outcome.clone(),
        settlement_projection,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
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

#[test]
fn non_recording_projection_outcomes_never_record_commitment() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionSettlementCommitmentOutcome as Commitment;
    assert_non_recording_projection(
        Projection::LegacyBypassNoSettlementProjection,
        Commitment::LegacyBypassNoSettlementCommitment,
    );
    assert_non_recording_projection(
        Projection::RejectedBeforeConsumerNoSettlementProjection,
        Commitment::RejectedBeforeSettlementProjectionNoCommitment,
    );
    assert_non_recording_projection(
        Projection::ConsumerDidNotRecordNoSettlementProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::SettlementProjectionRejectedBeforeRecord,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::SettlementProjectionRecordFailedNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::SettlementProjectionRolledBackNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::SettlementProjectionRollbackFailedFatalNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::SettlementProjectionAmbiguousFailClosedNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::ProductionSettlementProjectionUnavailableNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::MainNetSettlementProjectionUnavailableNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::ExternalSettlementProjectionUnavailableNoProjection,
        Commitment::SettlementProjectionDidNotRecordNoCommitment,
    );
    assert_non_recording_projection(
        Projection::MainNetPeerDrivenApplyRefusedNoProjection,
        Commitment::MainNetPeerDrivenApplyRefusedNoCommitment,
    );
    assert_non_recording_projection(
        Projection::ValidatorSetRotationUnsupportedNoProjection,
        Commitment::ValidatorSetRotationUnsupportedNoCommitment,
    );
    assert_non_recording_projection(
        Projection::PolicyChangeUnsupportedNoProjection,
        Commitment::PolicyChangeUnsupportedNoCommitment,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — binding mismatch (before sink invocation)
// ===========================================================================

fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::RejectedBeforeSettlementProjectionNoCommitment
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
    mut mutate: impl FnMut(&mut DurableCompletionSettlementCommitmentRequest),
) {
    let c = devnet_ctx();
    let mut input = c.recorded();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRejectedBeforeRecord
    );
    // The sink is invoked (binding matched) but records nothing.
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_commitment_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.commitment_record_id = "other-projection".to_string();
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
        r.identity.projection_id = "other-receipt-id".to_string();
    });
}

#[test]
fn wrong_consumer_identity_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_identity_digest = "other-consumer-identity".to_string();
    });
}

#[test]
fn wrong_consumer_request_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_request_digest = "other-consumer-request".to_string();
    });
}

#[test]
fn wrong_consumer_response_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_response_digest = "other-consumer-response".to_string();
    });
}

#[test]
fn wrong_consumer_record_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_record_digest = "other-consumer-record".to_string();
    });
}

#[test]
fn wrong_consumer_transcript_digest_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_transcript_digest = "other-consumer-transcript".to_string();
    });
}

#[test]
fn wrong_consumer_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.consumer_record_id = "other-consumer-record-id".to_string();
    });
}

#[test]
fn wrong_receipt_policy_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.policy =
            DurableCompletionSettlementCommitmentPolicy::ProductionSettlementCommitmentRequired;
    });
}

#[test]
fn wrong_receipt_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind =
            DurableCompletionSettlementCommitmentKind::ProductionSettlementCommitmentUnavailable;
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
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();

    let first = evaluate_durable_completion_settlement_commitment(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded
    );

    // A second receipt with the SAME receipt record id but a differing digest fails
    // closed as equivocation. We adjust both request and expectations on a differing
    // field so binding/request validation passes and the equivocation gate rejects.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
    let equivocation = evaluate_durable_completion_settlement_commitment(
        &c2.recorded(),
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRejectedBeforeRecord
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
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableCompletionSettlementCommitmentKind::FixtureInMemory,
    );
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_commitment(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRejectedBeforeRecord
    );
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Receipt record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_receipt(
    fault: DurableCompletionSettlementCommitmentFault,
    expected: DurableCompletionSettlementCommitmentOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = FixtureDurableCompletionSettlementCommitmentSink::with_fault(fault);
    let outcome = evaluate_durable_completion_settlement_commitment(
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

#[test]
fn receipt_record_failed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionSettlementCommitmentFault::RecordFailedNoProjection,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecordFailedNoCommitment,
    );
}

#[test]
fn receipt_rollback_completed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionSettlementCommitmentFault::RolledBackNoProjection,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRolledBackNoCommitment,
    );
}

#[test]
fn receipt_rollback_failed_fatal_never_records() {
    assert_fault_no_receipt(
        DurableCompletionSettlementCommitmentFault::RollbackFailedFatal,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRollbackFailedFatalNoCommitment,
    );
}

#[test]
fn receipt_ambiguous_window_fails_closed() {
    assert_fault_no_receipt(
        DurableCompletionSettlementCommitmentFault::AmbiguousAfterRecord,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentAmbiguousFailClosedNoCommitment,
    );
}

// ===========================================================================
// Projection cases
// ===========================================================================

#[test]
fn only_recorded_projection_outcome_creates_settlement_commitment_request_intent() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionSettlementCommitmentRequestIntent as Intent;
    assert_eq!(
        project_settlement_projection_outcome_to_commitment_request(
            &Projection::SettlementProjectionRecorded
        ),
        Intent::CreateRequest
    );
    assert!(project_settlement_projection_outcome_to_commitment_request(
        &Projection::SettlementProjectionRecorded
    )
    .creates_request());
    assert_eq!(
        project_settlement_projection_outcome_to_commitment_request(
            &Projection::SettlementProjectionDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    assert!(!project_settlement_projection_outcome_to_commitment_request(
        &Projection::LegacyBypassNoSettlementProjection
    )
    .creates_request());
}

#[test]
fn non_recording_projection_outcomes_create_no_settlement_commitment_request() {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionSettlementCommitmentRequestIntent as Intent;
    for projection in [
        Projection::LegacyBypassNoSettlementProjection,
        Projection::RejectedBeforeConsumerNoSettlementProjection,
        Projection::ConsumerDidNotRecordNoSettlementProjection,
        Projection::SettlementProjectionRejectedBeforeRecord,
        Projection::SettlementProjectionRecordFailedNoProjection,
        Projection::ProductionSettlementProjectionUnavailableNoProjection,
    ] {
        assert!(matches!(
            project_settlement_projection_outcome_to_commitment_request(&projection),
            Intent::NoProjection(_)
        ));
    }
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_ledger() -> DurableCompletionSettlementCommitmentLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_settlement_commitment(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionSettlementCommitmentWindow,
    with_record: bool,
    expected: DurableCompletionSettlementCommitmentOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(COMMITMENT_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_settlement_commitment_window(
        &input,
        window,
        DurableCompletionSettlementCommitmentKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

#[test]
fn pre_settlement_projection_windows_fail_closed_no_projection() {
    use DurableCompletionSettlementCommitmentOutcome as Projection;
    use DurableCompletionSettlementCommitmentWindow as Window;
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
        Window::AfterSettlementProjectionRequestBeforeSettlementProjectionRecord,
        Window::AfterSettlementProjectionRecordBeforeSettlementProjectionSuccess,
        Window::AfterSettlementProjectionSuccessBeforeSettlementCommitmentRequest,
    ] {
        assert_window(
            w,
            false,
            Projection::SettlementProjectionDidNotRecordNoCommitment,
        );
    }
}

#[test]
fn after_settlement_projection_request_before_record_rejects_before_record() {
    use DurableCompletionSettlementCommitmentOutcome as Projection;
    use DurableCompletionSettlementCommitmentWindow as Window;
    assert_window(
        Window::AfterSettlementCommitmentRequestBeforeSettlementCommitmentRecord,
        false,
        Projection::SettlementCommitmentRejectedBeforeRecord,
    );
}

#[test]
fn after_settlement_projection_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionSettlementCommitmentOutcome as Projection;
    use DurableCompletionSettlementCommitmentWindow as Window;
    assert_window(
        Window::AfterSettlementCommitmentRecordBeforeSettlementCommitmentSuccess,
        false,
        Projection::SettlementCommitmentRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterSettlementCommitmentRecordBeforeSettlementCommitmentSuccess,
        true,
        Projection::SettlementCommitmentRecorded,
    );
}

#[test]
fn after_settlement_projection_success_recovers_as_recorded() {
    use DurableCompletionSettlementCommitmentOutcome as Projection;
    use DurableCompletionSettlementCommitmentWindow as Window;
    assert_window(
        Window::AfterSettlementCommitmentSuccess,
        true,
        Projection::SettlementCommitmentRecorded,
    );
    // Without an explicit matching record, even after-success fails closed.
    assert_window(
        Window::AfterSettlementCommitmentSuccess,
        false,
        Projection::SettlementCommitmentRejectedBeforeRecord,
    );
}

#[test]
fn ambiguous_record_failed_rollback_and_unknown_windows_fail_closed() {
    use DurableCompletionSettlementCommitmentOutcome as Projection;
    use DurableCompletionSettlementCommitmentWindow as Window;
    assert_window(
        Window::AfterSettlementCommitmentAmbiguous,
        false,
        Projection::SettlementCommitmentAmbiguousFailClosedNoCommitment,
    );
    assert_window(
        Window::Unknown,
        false,
        Projection::SettlementCommitmentAmbiguousFailClosedNoCommitment,
    );
    assert_window(
        Window::SettlementCommitmentRecordFailed,
        false,
        Projection::SettlementCommitmentRecordFailedNoCommitment,
    );
    assert_window(
        Window::SettlementCommitmentRollbackCompleted,
        false,
        Projection::SettlementCommitmentRolledBackNoCommitment,
    );
    assert_window(
        Window::SettlementCommitmentRollbackFailed,
        false,
        Projection::SettlementCommitmentRollbackFailedFatalNoCommitment,
    );
}

#[test]
fn production_mainnet_external_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_durable_completion_settlement_commitment_window(
        &input,
        DurableCompletionSettlementCommitmentWindow::AfterSettlementCommitmentSuccess,
        DurableCompletionSettlementCommitmentKind::ProductionSettlementCommitmentUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::ProductionSettlementCommitmentUnavailableNoCommitment
    );
    let outcome = recover_durable_completion_settlement_commitment_window(
        &input,
        DurableCompletionSettlementCommitmentWindow::AfterSettlementCommitmentSuccess,
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::MainNetSettlementCommitmentUnavailableNoCommitment
    );
    let outcome = recover_durable_completion_settlement_commitment_window(
        &input,
        DurableCompletionSettlementCommitmentWindow::AfterSettlementCommitmentSuccess,
        DurableCompletionSettlementCommitmentKind::ExternalSettlementCommitmentUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::ExternalSettlementCommitmentUnavailableNoCommitment
    );
}

#[test]
fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionSettlementCommitmentPolicy::MainNetSettlementCommitmentRequired,
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable,
    );
    let input = c.input(
        DurableCompletionSettlementCommitmentPolicy::MainNetSettlementCommitmentRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let outcome = recover_durable_completion_settlement_commitment_window(
        &input,
        DurableCompletionSettlementCommitmentWindow::AfterSettlementCommitmentSuccess,
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::MainNetPeerDrivenApplyRefusedNoCommitment
    );
}

// ===========================================================================
// Receipt-ledger cases
// ===========================================================================

#[test]
fn rollback_restores_receipt_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_settlement_commitment(
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
        DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        DurableCompletionSettlementCommitmentKind::FixtureInMemory,
        &action,
        false,
    );
    let mut faulted = FixtureDurableCompletionSettlementCommitmentSink::with_fault(
        DurableCompletionSettlementCommitmentFault::RolledBackNoProjection,
    );
    let outcome = evaluate_durable_completion_settlement_commitment(
        &c2.recorded(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRolledBackNoCommitment
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains(&action.commitment_record_id));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

#[test]
fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_settlement_commitment_rejection_is_non_mutating());
    assert!(durable_completion_settlement_commitment_never_calls_run_070());
    assert!(durable_completion_settlement_commitment_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_settlement_commitment_never_writes_sequence_or_marker());
    assert!(durable_completion_settlement_commitment_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_settlement_commitment_no_external_publication());
    assert!(durable_completion_settlement_commitment_no_real_audit_ledger());
    assert!(durable_completion_settlement_commitment_pipeline_success_required());
    assert!(durable_completion_settlement_commitment_sink_receipt_required());
    assert!(durable_completion_settlement_commitment_completion_report_required());
    assert!(durable_completion_settlement_commitment_finalization_required());
    assert!(durable_completion_settlement_commitment_attestation_required());
    assert!(durable_completion_settlement_commitment_backend_submission_required());
    assert!(durable_completion_settlement_commitment_receipt_required());
    assert!(durable_completion_settlement_commitment_record_required_before_committed());
    assert!(durable_completion_settlement_commitment_failed_record_never_records());
    assert!(durable_completion_settlement_commitment_rollback_never_records());
    assert!(durable_completion_settlement_commitment_ambiguous_window_fails_closed());
    assert!(
        durable_completion_settlement_commitment_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet
        )
    );
    assert!(
        !durable_completion_settlement_commitment_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet
        )
    );
    assert!(durable_completion_settlement_commitment_production_mainnet_unavailable());
    assert!(durable_completion_settlement_commitment_external_unavailable());
    assert!(durable_completion_settlement_commitment_validator_set_rotation_unsupported());
    assert!(durable_completion_settlement_commitment_policy_change_unsupported());
    assert!(
        durable_completion_settlement_commitment_local_operator_cannot_satisfy_mainnet_authority()
    );
    assert!(
        durable_completion_settlement_commitment_peer_majority_cannot_satisfy_mainnet_authority()
    );
}