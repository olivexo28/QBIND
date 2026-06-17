// Run 270 — durable-completion settlement-receipt-acknowledgement boundary tests.
//
// Source/test-only modeled boundary that sits one rung above the Run 268
// settlement-finalization boundary. The chain attaches the real Run 256 backend,
// Run 258 receipt, Run 260 acknowledgement, Run 262 consumer, Run 264 settlement
// projection, Run 266 settlement commitment, and Run 268 settlement finalization
// records, then evaluates the Run 270 settlement-receipt-acknowledgement boundary.
// Only a Run 270 SettlementReceiptAcknowledgementRecorded outcome authorizes new
// state; every ambiguous, missing, duplicate, or mismatched window fails closed.

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
    evaluate_durable_completion_settlement_commitment,
    DurableCompletionSettlementCommitmentExpectations,
    DurableCompletionSettlementCommitmentIdentity,
    DurableCompletionSettlementCommitmentInput,
    DurableCompletionSettlementCommitmentKind,
    DurableCompletionSettlementCommitmentLedger,
    DurableCompletionSettlementCommitmentOutcome,
    DurableCompletionSettlementCommitmentPolicy,
    DurableCompletionSettlementCommitmentRequest,
    FixtureDurableCompletionSettlementCommitmentSink,
};
use qbind_node::pqc_governance_durable_completion_settlement_finalization::{
    settlement_finalization_identity_digest,
    evaluate_durable_completion_settlement_finalization,
    DurableCompletionSettlementFinalizationExpectations,
    DurableCompletionSettlementFinalizationIdentity,
    DurableCompletionSettlementFinalizationInput,
    DurableCompletionSettlementFinalizationKind,
    DurableCompletionSettlementFinalizationLedger,
    DurableCompletionSettlementFinalizationOutcome,
    DurableCompletionSettlementFinalizationPolicy,
    DurableCompletionSettlementFinalizationRequest,
    FixtureDurableCompletionSettlementFinalizationSink,
};
use qbind_node::pqc_governance_durable_completion_settlement_receipt_acknowledgement::{
    settlement_receipt_acknowledgement_identity_digest,
    durable_completion_settlement_receipt_acknowledgement_ambiguous_window_fails_closed,
    durable_completion_settlement_receipt_acknowledgement_attestation_required,
    durable_completion_settlement_receipt_acknowledgement_backend_submission_required,
    durable_completion_settlement_receipt_acknowledgement_completion_report_required,
    durable_completion_settlement_receipt_acknowledgement_external_unavailable,
    durable_completion_settlement_receipt_acknowledgement_failed_record_never_records,
    durable_completion_settlement_receipt_acknowledgement_finalization_projection_required,
    durable_completion_settlement_receipt_acknowledgement_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_settlement_receipt_acknowledgement_mainnet_peer_driven_apply_refused_first,
    durable_completion_settlement_receipt_acknowledgement_never_calls_run_070,
    durable_completion_settlement_receipt_acknowledgement_never_mutates_live_pqc_trust_state,
    durable_completion_settlement_receipt_acknowledgement_never_writes_sequence_or_marker,
    durable_completion_settlement_receipt_acknowledgement_no_external_publication,
    durable_completion_settlement_receipt_acknowledgement_no_real_audit_ledger,
    durable_completion_settlement_receipt_acknowledgement_no_rocksdb_file_schema_migration_change,
    durable_completion_settlement_receipt_acknowledgement_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_settlement_receipt_acknowledgement_pipeline_success_required,
    durable_completion_settlement_receipt_acknowledgement_policy_change_unsupported,
    durable_completion_settlement_receipt_acknowledgement_production_mainnet_unavailable,
    durable_completion_settlement_receipt_acknowledgement_receipt_required,
    durable_completion_settlement_receipt_acknowledgement_record_required_before_acknowledged,
    durable_completion_settlement_receipt_acknowledgement_rejection_is_non_mutating,
    durable_completion_settlement_receipt_acknowledgement_rollback_never_records,
    durable_completion_settlement_receipt_acknowledgement_sink_receipt_required,
    durable_completion_settlement_receipt_acknowledgement_validator_set_rotation_unsupported,
    evaluate_durable_completion_settlement_receipt_acknowledgement,
    project_settlement_finalization_outcome_to_receipt_acknowledgement_request,
    recover_durable_completion_settlement_receipt_acknowledgement_window,
    settlement_receipt_acknowledgement_outcome_authorizes_record,
    settlement_receipt_acknowledgement_outcome_projects_to_recorded,
    DurableCompletionSettlementReceiptAcknowledgementExpectations,
    DurableCompletionSettlementReceiptAcknowledgementFault,
    DurableCompletionSettlementReceiptAcknowledgementIdentity,
    DurableCompletionSettlementReceiptAcknowledgementInput,
    DurableCompletionSettlementReceiptAcknowledgementKind,
    DurableCompletionSettlementReceiptAcknowledgementLedger,
    DurableCompletionSettlementReceiptAcknowledgementOutcome,
    DurableCompletionSettlementReceiptAcknowledgementPolicy,
    DurableCompletionSettlementReceiptAcknowledgementRequest,
    DurableCompletionSettlementReceiptAcknowledgementRequestIntent,
    DurableCompletionSettlementReceiptAcknowledgementWindow, ExternalSettlementReceiptAcknowledgementSink,
    FixtureDurableCompletionSettlementReceiptAcknowledgementSink,
    GovernanceDurableCompletionSettlementReceiptAcknowledgementSink, MainNetSettlementReceiptAcknowledgementSink,
    ProductionSettlementReceiptAcknowledgementSink,
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
const FINALIZATION_RECORD_ID: &str = "durable-completion-settlement-finalization-0001";
const FINALIZATION_ID: &str = "fixture-settlement-finalization-0001";
const FINALIZATION_DOMAIN_TAG: &str = "QBIND:run268:domain-separation:v1";
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

const RECEIPT_ACKNOWLEDGEMENT_RECORD_ID: &str =
    "durable-completion-settlement-receipt-acknowledgement-0001";
const RECEIPT_ACKNOWLEDGEMENT_ID: &str = "fixture-settlement-receipt-acknowledgement-0001";
const RECEIPT_ACKNOWLEDGEMENT_DOMAIN_TAG: &str = "QBIND:run270:domain-separation:v1";

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
    finalization_record_id: String,
    receipt_acknowledgement_record_id: String,
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
        finalization_record_id: format!("durable-completion-settlement-finalization-{label}"),
        receipt_acknowledgement_record_id: format!(
            "durable-completion-settlement-receipt-acknowledgement-{label}"
        ),
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
        finalization_record_id: FINALIZATION_RECORD_ID.to_string(),
        receipt_acknowledgement_record_id: RECEIPT_ACKNOWLEDGEMENT_RECORD_ID.to_string(),
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
// Run 266 settlement-commitment attachment (carried upstream input)
// ===========================================================================

/// A real Run 266 settlement-commitment record produced by driving the actual
/// `evaluate_durable_completion_settlement_commitment` round-trip on top
/// of the real Run 262 consumer chain. The Run 268 settlement-finalization boundary
/// projects this terminal outcome; it is never a faked, unattached commitment.
struct AttachedSettlementCommitment {
    outcome: DurableCompletionSettlementCommitmentOutcome,
    commitment_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    settlement_projection: AttachedSettlementProjection,
}

fn run266_commitment_identity() -> DurableCompletionSettlementCommitmentIdentity {
    DurableCompletionSettlementCommitmentIdentity {
        projection_id: COMMITMENT_ID.to_string(),
        kind: DurableCompletionSettlementCommitmentKind::FixtureInMemory,
        policy: DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        domain_separation_tag: COMMITMENT_DOMAIN_TAG.to_string(),
    }
}

fn attach_run266_settlement_commitment(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    commitment_duplicate: bool,
) -> AttachedSettlementCommitment {
    let settlement_projection =
        attach_run264_settlement_projection(environment, action, false);
    let consumer = settlement_projection.consumer.clone();
    let ack = &consumer.ack;
    let commitment_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: commitment_env,
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
    let id = run266_commitment_identity();
    let request = DurableCompletionSettlementCommitmentRequest {
        commitment_record_id: action.commitment_record_id.clone(),
        environment: commitment_env,
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
        expected_environment: commitment_env,
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
        expected_settlement_projection_identity_digest: settlement_projection
            .identity_digest
            .clone(),
        expected_settlement_projection_request_digest: settlement_projection
            .request_digest
            .clone(),
        expected_settlement_projection_response_digest: settlement_projection
            .response_digest
            .clone(),
        expected_settlement_projection_record_digest: settlement_projection
            .record_digest
            .clone(),
        expected_settlement_projection_transcript_digest: settlement_projection
            .transcript_digest
            .clone(),
        expected_settlement_projection_record_id: settlement_projection
            .projection_record_id
            .clone(),
        expected_identity: id.clone(),
        expected_commitment_kind: DurableCompletionSettlementCommitmentKind::FixtureInMemory,
        expected_commitment_policy:
            DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
        expected_domain_separation_tag: COMMITMENT_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionSettlementCommitmentInput {
        policy: DurableCompletionSettlementCommitmentPolicy::FixtureAllowed,
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
        settlement_projection_binding: settlement_projection.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionSettlementCommitmentLedger::new();
    let mut sink = FixtureDurableCompletionSettlementCommitmentSink::new();
    let first = evaluate_durable_completion_settlement_commitment(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded
    );
    let outcome = if commitment_duplicate {
        let second = evaluate_durable_completion_settlement_commitment(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.commitment_record_id)
        .expect("recorded Run 266 settlement commitment");
    AttachedSettlementCommitment {
        outcome,
        commitment_record_id: action.commitment_record_id.clone(),
        identity_digest: settlement_commitment_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        settlement_projection,
    }
}

// ---- Run 268 settlement-finalization attachment (prior boundary) ----
struct AttachedSettlementFinalization {
    outcome: DurableCompletionSettlementFinalizationOutcome,
    finalization_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    settlement_commitment: AttachedSettlementCommitment,
}

fn run268_finalization_identity() -> DurableCompletionSettlementFinalizationIdentity {
    DurableCompletionSettlementFinalizationIdentity {
        commitment_id: FINALIZATION_ID.to_string(),
        kind: DurableCompletionSettlementFinalizationKind::FixtureInMemory,
        policy: DurableCompletionSettlementFinalizationPolicy::FixtureAllowed,
        domain_separation_tag: FINALIZATION_DOMAIN_TAG.to_string(),
    }
}

fn attach_run268_settlement_finalization(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    finalization_duplicate: bool,
) -> AttachedSettlementFinalization {
    let settlement_commitment =
        attach_run266_settlement_commitment(environment, action, false);
    let consumer = settlement_commitment.consumer.clone();
    let ack = &consumer.ack;
    let finalization_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: finalization_env,
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
    let id = run268_finalization_identity();
    let request = DurableCompletionSettlementFinalizationRequest {
        finalization_record_id: action.finalization_record_id.clone(),
        environment: finalization_env,
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
        settlement_commitment_identity_digest: settlement_commitment.identity_digest.clone(),
        settlement_commitment_request_digest: settlement_commitment.request_digest.clone(),
        settlement_commitment_response_digest: settlement_commitment.response_digest.clone(),
        settlement_commitment_record_digest: settlement_commitment.record_digest.clone(),
        settlement_commitment_transcript_digest: settlement_commitment.transcript_digest.clone(),
        settlement_commitment_record_id: settlement_commitment.commitment_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: FINALIZATION_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionSettlementFinalizationExpectations {
        expected_finalization_record_id: action.finalization_record_id.clone(),
        expected_environment: finalization_env,
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
        expected_settlement_commitment_identity_digest: settlement_commitment
            .identity_digest
            .clone(),
        expected_settlement_commitment_request_digest: settlement_commitment
            .request_digest
            .clone(),
        expected_settlement_commitment_response_digest: settlement_commitment
            .response_digest
            .clone(),
        expected_settlement_commitment_record_digest: settlement_commitment
            .record_digest
            .clone(),
        expected_settlement_commitment_transcript_digest: settlement_commitment
            .transcript_digest
            .clone(),
        expected_settlement_commitment_record_id: settlement_commitment
            .commitment_record_id
            .clone(),
        expected_identity: id.clone(),
        expected_finalization_kind: DurableCompletionSettlementFinalizationKind::FixtureInMemory,
        expected_finalization_policy:
            DurableCompletionSettlementFinalizationPolicy::FixtureAllowed,
        expected_domain_separation_tag: FINALIZATION_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionSettlementFinalizationInput {
        policy: DurableCompletionSettlementFinalizationPolicy::FixtureAllowed,
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
        settlement_commitment_binding: settlement_commitment.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionSettlementFinalizationLedger::new();
    let mut sink = FixtureDurableCompletionSettlementFinalizationSink::new();
    let first = evaluate_durable_completion_settlement_finalization(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementFinalizationOutcome::SettlementFinalizationRecorded
    );
    let outcome = if finalization_duplicate {
        let second = evaluate_durable_completion_settlement_finalization(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionSettlementFinalizationOutcome::SettlementFinalizationDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.finalization_record_id)
        .expect("recorded Run 268 settlement finalization");
    AttachedSettlementFinalization {
        outcome,
        finalization_record_id: action.finalization_record_id.clone(),
        identity_digest: settlement_finalization_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        settlement_commitment,
    }
}
// ===========================================================================
// Run 270 owned-context builder
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    request: DurableCompletionSettlementReceiptAcknowledgementRequest,
    expectations: DurableCompletionSettlementReceiptAcknowledgementExpectations,
    consumer: AttachedConsumer,
    settlement_finalization: AttachedSettlementFinalization,
}

fn ack_identity(
    policy: DurableCompletionSettlementReceiptAcknowledgementPolicy,
    kind: DurableCompletionSettlementReceiptAcknowledgementKind,
) -> DurableCompletionSettlementReceiptAcknowledgementIdentity {
    DurableCompletionSettlementReceiptAcknowledgementIdentity {
        finalization_id: RECEIPT_ACKNOWLEDGEMENT_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: RECEIPT_ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ctx_action(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionSettlementReceiptAcknowledgementPolicy,
    kind: DurableCompletionSettlementReceiptAcknowledgementKind,
    action: &ActionLabel,
    consumer_duplicate: bool,
) -> Ctx {
    let settlement_finalization =
        attach_run268_settlement_finalization(environment, action, consumer_duplicate);
    let consumer = settlement_finalization.consumer.clone();
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
    let request = DurableCompletionSettlementReceiptAcknowledgementRequest {
        receipt_acknowledgement_record_id: action.receipt_acknowledgement_record_id.clone(),
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
        settlement_finalization_identity_digest: settlement_finalization.identity_digest.clone(),
        settlement_finalization_request_digest: settlement_finalization.request_digest.clone(),
        settlement_finalization_response_digest: settlement_finalization.response_digest.clone(),
        settlement_finalization_record_digest: settlement_finalization.record_digest.clone(),
        settlement_finalization_transcript_digest: settlement_finalization.transcript_digest.clone(),
        settlement_finalization_record_id: settlement_finalization.finalization_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: RECEIPT_ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionSettlementReceiptAcknowledgementExpectations {
        expected_receipt_acknowledgement_record_id: action.receipt_acknowledgement_record_id.clone(),
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
        expected_settlement_finalization_identity_digest: settlement_finalization.identity_digest.clone(),
        expected_settlement_finalization_request_digest: settlement_finalization.request_digest.clone(),
        expected_settlement_finalization_response_digest: settlement_finalization
            .response_digest
            .clone(),
        expected_settlement_finalization_record_digest: settlement_finalization.record_digest.clone(),
        expected_settlement_finalization_transcript_digest: settlement_finalization
            .transcript_digest
            .clone(),
        expected_settlement_finalization_record_id: settlement_finalization.finalization_record_id.clone(),
        expected_identity: id,
        expected_receipt_acknowledgement_kind: kind,
        expected_receipt_acknowledgement_policy: policy,
        expected_domain_separation_tag: RECEIPT_ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
        consumer,
        settlement_finalization,
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionSettlementReceiptAcknowledgementPolicy,
    kind: DurableCompletionSettlementReceiptAcknowledgementKind,
) -> Ctx {
    ctx_action(environment, vs, ms, policy, kind, &default_action(), false)
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input_with_finalization(
        &self,
        policy: DurableCompletionSettlementReceiptAcknowledgementPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        receipt_acknowledgement: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
        receipt: DurableCompletionAuditPublicationReceiptOutcome,
        acknowledgement: DurableCompletionAuditReceiptAcknowledgementOutcome,
        consumer: DurableCompletionAcknowledgementConsumerOutcome,
        settlement_finalization: DurableCompletionSettlementFinalizationOutcome,
    ) -> DurableCompletionSettlementReceiptAcknowledgementInput {
        DurableCompletionSettlementReceiptAcknowledgementInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            finalization_binding: receipt_acknowledgement,
            attestation_binding: attestation,
            backend_binding: backend,
            receipt_binding: receipt,
            acknowledgement_binding: acknowledgement,
            consumer_binding: consumer,
            settlement_finalization_binding: settlement_finalization,
            request: self.request.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionSettlementReceiptAcknowledgementPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        receipt_acknowledgement: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
    ) -> DurableCompletionSettlementReceiptAcknowledgementInput {
        self.input_with_finalization(
            policy,
            replay,
            pipeline,
            sink,
            reporter,
            receipt_acknowledgement,
            attestation,
            backend,
            self.consumer.ack.receipt.outcome.clone(),
            self.consumer.ack.outcome.clone(),
            self.consumer.outcome.clone(),
            self.settlement_finalization.outcome.clone(),
        )
    }

    fn recorded(&self) -> DurableCompletionSettlementReceiptAcknowledgementInput {
        self.input_with_finalization(
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
            self.settlement_finalization.outcome.clone(),
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
    )
}

fn fixture_sink() -> FixtureDurableCompletionSettlementReceiptAcknowledgementSink {
    FixtureDurableCompletionSettlementReceiptAcknowledgementSink::new()
}
#[test]
fn disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::LegacyBypassNoSettlementReceiptAcknowledgement
    );
    assert!(outcome.is_legacy_bypass());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn disabled_backend_policy_never_invokes_receipt_sink() {
    let c = devnet_ctx();
    let input = c.input_with_finalization(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
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
        DurableCompletionSettlementFinalizationOutcome::LegacyBypassNoSettlementFinalization,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::LegacyBypassNoSettlementReceiptAcknowledgement
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
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded
    );
    assert!(settlement_receipt_acknowledgement_outcome_authorizes_record(&outcome));
    assert!(settlement_receipt_acknowledgement_outcome_projects_to_recorded(&outcome));
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(RECEIPT_ACKNOWLEDGEMENT_RECORD_ID));
    assert_eq!(
        settlement_receipt_acknowledgement_identity_digest(&c.request.identity),
        c.request.identity.digest()
    );
}

#[test]
fn testnet_fixture_chain_records_exactly_one_receipt() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded
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
            DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
            DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
            &action,
            false,
        );
        assert_eq!(
            c.consumer.ack.receipt.backend.outcome,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
        );
        let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
        let mut sink = fixture_sink();
        let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
            &c.recorded(),
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            outcome,
            DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded,
            "action {label} must record after backend submission"
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&action.receipt_acknowledgement_record_id));
    }
}

#[test]
fn duplicate_identical_receipt_is_idempotent() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let first = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded
    );
    let second = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementDuplicateIdempotent
    );
    assert!(!settlement_receipt_acknowledgement_outcome_authorizes_record(&second));
    assert!(settlement_receipt_acknowledgement_outcome_projects_to_recorded(&second));
    assert_eq!(ledger.len(), 1);
}

#[test]
fn run268_duplicate_idempotent_finalization_only_matches_existing_never_creates() {
    // A real Run 268 SettlementFinalizationDuplicateIdempotent outcome with
    // identical digests.
    let dup_ctx = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
        &default_action(),
        true,
    );
    assert_eq!(
        dup_ctx.settlement_finalization.outcome,
        DurableCompletionSettlementFinalizationOutcome::SettlementFinalizationDuplicateIdempotent
    );

    // With no prior receipt, a duplicate-idempotent backend cannot create one.
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real receipt records, the duplicate-idempotent backend matches it.
    let rec_ctx = devnet_ctx();
    let recorded = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &rec_ctx.recorded(),
        &rec_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded
    );
    let matched = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementDuplicateIdempotent
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
        DurableCompletionSettlementReceiptAcknowledgementPolicy::ProductionSettlementReceiptAcknowledgementRequired,
        DurableCompletionSettlementReceiptAcknowledgementKind::ProductionSettlementReceiptAcknowledgementUnavailable,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = ProductionSettlementReceiptAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::ProductionSettlementReceiptAcknowledgementUnavailableNoReceiptAcknowledgement
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::MainNetSettlementReceiptAcknowledgementRequired,
        DurableCompletionSettlementReceiptAcknowledgementKind::MainNetSettlementReceiptAcknowledgementUnavailable,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = MainNetSettlementReceiptAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::MainNetSettlementReceiptAcknowledgementUnavailableNoReceiptAcknowledgement
    );
    assert!(ledger.is_empty());
}

#[test]
fn external_publication_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::ExternalSettlementReceiptAcknowledgementRequired,
        DurableCompletionSettlementReceiptAcknowledgementKind::ExternalSettlementReceiptAcknowledgementUnavailable,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = ExternalSettlementReceiptAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::ExternalSettlementReceiptAcknowledgementUnavailableNoReceiptAcknowledgement
    );
    assert!(ledger.is_empty());
}

#[test]
fn mainnet_peer_driven_apply_refused_before_receipt_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::MainNetSettlementReceiptAcknowledgementRequired,
        DurableCompletionSettlementReceiptAcknowledgementKind::MainNetSettlementReceiptAcknowledgementUnavailable,
    );
    let input = c.input(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::MainNetSettlementReceiptAcknowledgementRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = MainNetSettlementReceiptAcknowledgementSink::default();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoReceiptAcknowledgement
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn validator_set_rotation_and_policy_change_unsupported() {
    let c = devnet_ctx();
    let rotation = c.input_with_finalization(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
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
        DurableCompletionSettlementFinalizationOutcome::ValidatorSetRotationUnsupportedNoFinalization,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &rotation,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::ValidatorSetRotationUnsupportedNoReceiptAcknowledgement
    );
    assert_eq!(sink.invocations(), 0);

    let policy_change = c.input_with_finalization(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
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
        DurableCompletionSettlementFinalizationOutcome::PolicyChangeUnsupportedNoFinalization,
    );
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &policy_change,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::PolicyChangeUnsupportedNoReceiptAcknowledgement
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — non-recording Run 258 receipt outcomes
// ===========================================================================

fn assert_non_recording_finalization(
    settlement_finalization: DurableCompletionSettlementFinalizationOutcome,
    expected: DurableCompletionSettlementReceiptAcknowledgementOutcome,
) {
    let c = devnet_ctx();
    let input = c.input_with_finalization(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
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
        settlement_finalization,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_commitment());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

#[test]
fn non_recording_finalization_outcomes_never_record_receipt_acknowledgement() {
    use DurableCompletionSettlementFinalizationOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as ReceiptAcknowledgement;
    assert_non_recording_finalization(
        Finalization::LegacyBypassNoSettlementFinalization,
        ReceiptAcknowledgement::LegacyBypassNoSettlementReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::RejectedBeforeSettlementCommitmentNoFinalization,
        ReceiptAcknowledgement::RejectedBeforeSettlementFinalizationNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::SettlementCommitmentDidNotRecordNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::SettlementFinalizationRejectedBeforeRecord,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::SettlementFinalizationRecordFailedNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::SettlementFinalizationRolledBackNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::SettlementFinalizationRollbackFailedFatalNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::SettlementFinalizationAmbiguousFailClosedNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::ProductionSettlementFinalizationUnavailableNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::MainNetSettlementFinalizationUnavailableNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::ExternalSettlementFinalizationUnavailableNoFinalization,
        ReceiptAcknowledgement::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::MainNetPeerDrivenApplyRefusedNoFinalization,
        ReceiptAcknowledgement::MainNetPeerDrivenApplyRefusedNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::ValidatorSetRotationUnsupportedNoFinalization,
        ReceiptAcknowledgement::ValidatorSetRotationUnsupportedNoReceiptAcknowledgement,
    );
    assert_non_recording_finalization(
        Finalization::PolicyChangeUnsupportedNoFinalization,
        ReceiptAcknowledgement::PolicyChangeUnsupportedNoReceiptAcknowledgement,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — binding mismatch (before sink invocation)
// ===========================================================================

fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::RejectedBeforeSettlementFinalizationNoReceiptAcknowledgement
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
    mut mutate: impl FnMut(&mut DurableCompletionSettlementReceiptAcknowledgementRequest),
) {
    let c = devnet_ctx();
    let mut input = c.recorded();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRejectedBeforeRecord
    );
    // The sink is invoked (binding matched) but records nothing.
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn wrong_receipt_acknowledgement_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.receipt_acknowledgement_record_id = "other-finalization".to_string();
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
        r.finalization_decision_digest = "other-receipt-acknowledgement".to_string();
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
        r.identity.finalization_id = "other-receipt-id".to_string();
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
            DurableCompletionSettlementReceiptAcknowledgementPolicy::ProductionSettlementReceiptAcknowledgementRequired;
    });
}

#[test]
fn wrong_receipt_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind =
            DurableCompletionSettlementReceiptAcknowledgementKind::ProductionSettlementReceiptAcknowledgementUnavailable;
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
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();

    let first = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded
    );

    // A second receipt with the SAME receipt record id but a differing digest fails
    // closed as equivocation. We adjust both request and expectations on a differing
    // field so binding/request validation passes and the equivocation gate rejects.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
    let equivocation = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c2.recorded(),
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRejectedBeforeRecord
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
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
    );
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRejectedBeforeRecord
    );
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Receipt record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_receipt(
    fault: DurableCompletionSettlementReceiptAcknowledgementFault,
    expected: DurableCompletionSettlementReceiptAcknowledgementOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = FixtureDurableCompletionSettlementReceiptAcknowledgementSink::with_fault(fault);
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(outcome, expected);
    assert!(outcome.no_commitment());
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

#[test]
fn receipt_record_failed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionSettlementReceiptAcknowledgementFault::RecordFailedNoFinalization,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecordFailedNoReceiptAcknowledgement,
    );
}

#[test]
fn receipt_rollback_completed_never_records() {
    assert_fault_no_receipt(
        DurableCompletionSettlementReceiptAcknowledgementFault::RolledBackNoFinalization,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRolledBackNoReceiptAcknowledgement,
    );
}

#[test]
fn receipt_rollback_failed_fatal_never_records() {
    assert_fault_no_receipt(
        DurableCompletionSettlementReceiptAcknowledgementFault::RollbackFailedFatal,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRollbackFailedFatalNoReceiptAcknowledgement,
    );
}

#[test]
fn receipt_ambiguous_window_fails_closed() {
    assert_fault_no_receipt(
        DurableCompletionSettlementReceiptAcknowledgementFault::AmbiguousAfterRecord,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementAmbiguousFailClosedNoReceiptAcknowledgement,
    );
}

// ===========================================================================
// Finalization cases
// ===========================================================================

#[test]
fn only_recorded_finalization_outcome_creates_settlement_receipt_acknowledgement_request_intent() {
    use DurableCompletionSettlementFinalizationOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementRequestIntent as Intent;
    assert_eq!(
        project_settlement_finalization_outcome_to_receipt_acknowledgement_request(
            &Finalization::SettlementFinalizationRecorded
        ),
        Intent::CreateRequest
    );
    assert!(project_settlement_finalization_outcome_to_receipt_acknowledgement_request(
        &Finalization::SettlementFinalizationRecorded
    )
    .creates_request());
    assert_eq!(
        project_settlement_finalization_outcome_to_receipt_acknowledgement_request(
            &Finalization::SettlementFinalizationDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    assert!(!project_settlement_finalization_outcome_to_receipt_acknowledgement_request(
        &Finalization::LegacyBypassNoSettlementFinalization
    )
    .creates_request());
}

#[test]
fn non_recording_finalization_outcomes_create_no_settlement_receipt_acknowledgement_request() {
    use DurableCompletionSettlementFinalizationOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementRequestIntent as Intent;
    for finalization in [
        Finalization::LegacyBypassNoSettlementFinalization,
        Finalization::RejectedBeforeSettlementCommitmentNoFinalization,
        Finalization::SettlementCommitmentDidNotRecordNoFinalization,
        Finalization::SettlementFinalizationRejectedBeforeRecord,
        Finalization::SettlementFinalizationRecordFailedNoFinalization,
        Finalization::ProductionSettlementFinalizationUnavailableNoFinalization,
    ] {
        assert!(matches!(
            project_settlement_finalization_outcome_to_receipt_acknowledgement_request(&finalization),
            Intent::NoFinalization(_)
        ));
    }
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_ledger() -> DurableCompletionSettlementReceiptAcknowledgementLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionSettlementReceiptAcknowledgementWindow,
    with_record: bool,
    expected: DurableCompletionSettlementReceiptAcknowledgementOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(RECEIPT_ACKNOWLEDGEMENT_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_settlement_receipt_acknowledgement_window(
        &input,
        window,
        DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

#[test]
fn pre_settlement_finalization_windows_fail_closed_no_commitment() {
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementWindow as Window;
    for w in [
        Window::BeforePipeline,
        Window::AfterPipelineSuccessBeforeSinkIntent,
        Window::AfterSinkIntentBeforeSinkReceiptRecord,
        Window::AfterSinkReceiptRecordBeforeReportIntent,
        Window::AfterReportIntentBeforeReportRecord,
        Window::AfterReportRecordBeforeReceiptAcknowledgementIntent,
        Window::AfterReceiptAcknowledgementIntentBeforeReceiptAcknowledgementRecord,
        Window::AfterReceiptAcknowledgementRecordBeforeAttestationIntent,
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
        Window::AfterConsumerSuccessBeforeSettlementFinalizationRequest,
        Window::AfterSettlementFinalizationRequestBeforeSettlementFinalizationRecord,
        Window::AfterSettlementFinalizationRecordBeforeSettlementFinalizationSuccess,
        Window::AfterSettlementFinalizationSuccessBeforeSettlementReceiptAcknowledgementRequest,
    ] {
        assert_window(
            w,
            false,
            Finalization::SettlementFinalizationDidNotRecordNoReceiptAcknowledgement,
        );
    }
}

#[test]
fn after_settlement_finalization_request_before_record_rejects_before_record() {
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterSettlementReceiptAcknowledgementRequestBeforeSettlementReceiptAcknowledgementRecord,
        false,
        Finalization::SettlementReceiptAcknowledgementRejectedBeforeRecord,
    );
}

#[test]
fn after_settlement_finalization_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterSettlementReceiptAcknowledgementRecordBeforeSettlementReceiptAcknowledgementSuccess,
        false,
        Finalization::SettlementReceiptAcknowledgementRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterSettlementReceiptAcknowledgementRecordBeforeSettlementReceiptAcknowledgementSuccess,
        true,
        Finalization::SettlementReceiptAcknowledgementRecorded,
    );
}

#[test]
fn after_settlement_finalization_success_recovers_as_recorded() {
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterSettlementReceiptAcknowledgementSuccess,
        true,
        Finalization::SettlementReceiptAcknowledgementRecorded,
    );
    // Without an explicit matching record, even after-success fails closed.
    assert_window(
        Window::AfterSettlementReceiptAcknowledgementSuccess,
        false,
        Finalization::SettlementReceiptAcknowledgementRejectedBeforeRecord,
    );
}

#[test]
fn ambiguous_record_failed_rollback_and_unknown_windows_fail_closed() {
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as Finalization;
    use DurableCompletionSettlementReceiptAcknowledgementWindow as Window;
    assert_window(
        Window::AfterSettlementReceiptAcknowledgementAmbiguous,
        false,
        Finalization::SettlementReceiptAcknowledgementAmbiguousFailClosedNoReceiptAcknowledgement,
    );
    assert_window(
        Window::Unknown,
        false,
        Finalization::SettlementReceiptAcknowledgementAmbiguousFailClosedNoReceiptAcknowledgement,
    );
    assert_window(
        Window::SettlementReceiptAcknowledgementRecordFailed,
        false,
        Finalization::SettlementReceiptAcknowledgementRecordFailedNoReceiptAcknowledgement,
    );
    assert_window(
        Window::SettlementReceiptAcknowledgementRollbackCompleted,
        false,
        Finalization::SettlementReceiptAcknowledgementRolledBackNoReceiptAcknowledgement,
    );
    assert_window(
        Window::SettlementReceiptAcknowledgementRollbackFailed,
        false,
        Finalization::SettlementReceiptAcknowledgementRollbackFailedFatalNoReceiptAcknowledgement,
    );
}

#[test]
fn production_mainnet_external_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_durable_completion_settlement_receipt_acknowledgement_window(
        &input,
        DurableCompletionSettlementReceiptAcknowledgementWindow::AfterSettlementReceiptAcknowledgementSuccess,
        DurableCompletionSettlementReceiptAcknowledgementKind::ProductionSettlementReceiptAcknowledgementUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::ProductionSettlementReceiptAcknowledgementUnavailableNoReceiptAcknowledgement
    );
    let outcome = recover_durable_completion_settlement_receipt_acknowledgement_window(
        &input,
        DurableCompletionSettlementReceiptAcknowledgementWindow::AfterSettlementReceiptAcknowledgementSuccess,
        DurableCompletionSettlementReceiptAcknowledgementKind::MainNetSettlementReceiptAcknowledgementUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::MainNetSettlementReceiptAcknowledgementUnavailableNoReceiptAcknowledgement
    );
    let outcome = recover_durable_completion_settlement_receipt_acknowledgement_window(
        &input,
        DurableCompletionSettlementReceiptAcknowledgementWindow::AfterSettlementReceiptAcknowledgementSuccess,
        DurableCompletionSettlementReceiptAcknowledgementKind::ExternalSettlementReceiptAcknowledgementUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::ExternalSettlementReceiptAcknowledgementUnavailableNoReceiptAcknowledgement
    );
}

#[test]
fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionSettlementReceiptAcknowledgementPolicy::MainNetSettlementReceiptAcknowledgementRequired,
        DurableCompletionSettlementReceiptAcknowledgementKind::MainNetSettlementReceiptAcknowledgementUnavailable,
    );
    let input = c.input(
        DurableCompletionSettlementReceiptAcknowledgementPolicy::MainNetSettlementReceiptAcknowledgementRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let outcome = recover_durable_completion_settlement_receipt_acknowledgement_window(
        &input,
        DurableCompletionSettlementReceiptAcknowledgementWindow::AfterSettlementReceiptAcknowledgementSuccess,
        DurableCompletionSettlementReceiptAcknowledgementKind::MainNetSettlementReceiptAcknowledgementUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoReceiptAcknowledgement
    );
}

// ===========================================================================
// Receipt-ledger cases
// ===========================================================================

#[test]
fn rollback_restores_receipt_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_settlement_receipt_acknowledgement(
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
        DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
        &action,
        false,
    );
    let mut faulted = FixtureDurableCompletionSettlementReceiptAcknowledgementSink::with_fault(
        DurableCompletionSettlementReceiptAcknowledgementFault::RolledBackNoFinalization,
    );
    let outcome = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &c2.recorded(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRolledBackNoReceiptAcknowledgement
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains(&action.receipt_acknowledgement_record_id));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

#[test]
fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_settlement_receipt_acknowledgement_rejection_is_non_mutating());
    assert!(durable_completion_settlement_receipt_acknowledgement_never_calls_run_070());
    assert!(durable_completion_settlement_receipt_acknowledgement_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_settlement_receipt_acknowledgement_never_writes_sequence_or_marker());
    assert!(durable_completion_settlement_receipt_acknowledgement_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_settlement_receipt_acknowledgement_no_external_publication());
    assert!(durable_completion_settlement_receipt_acknowledgement_no_real_audit_ledger());
    assert!(durable_completion_settlement_receipt_acknowledgement_pipeline_success_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_sink_receipt_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_completion_report_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_finalization_projection_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_attestation_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_backend_submission_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_receipt_required());
    assert!(durable_completion_settlement_receipt_acknowledgement_record_required_before_acknowledged());
    assert!(durable_completion_settlement_receipt_acknowledgement_failed_record_never_records());
    assert!(durable_completion_settlement_receipt_acknowledgement_rollback_never_records());
    assert!(durable_completion_settlement_receipt_acknowledgement_ambiguous_window_fails_closed());
    assert!(
        durable_completion_settlement_receipt_acknowledgement_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet
        )
    );
    assert!(
        !durable_completion_settlement_receipt_acknowledgement_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet
        )
    );
    assert!(durable_completion_settlement_receipt_acknowledgement_production_mainnet_unavailable());
    assert!(durable_completion_settlement_receipt_acknowledgement_external_unavailable());
    assert!(durable_completion_settlement_receipt_acknowledgement_validator_set_rotation_unsupported());
    assert!(durable_completion_settlement_receipt_acknowledgement_policy_change_unsupported());
    assert!(
        durable_completion_settlement_receipt_acknowledgement_local_operator_cannot_satisfy_mainnet_authority()
    );
    assert!(
        durable_completion_settlement_receipt_acknowledgement_peer_majority_cannot_satisfy_mainnet_authority()
    );
}