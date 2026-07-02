//! Run 285 — release-binary durable-completion external-publication-audit-finalization
//! consumer / external-publication-audit-completion boundary helper.
//!
//! Release-binary evidence for the Run 284 durable-completion external-publication
//! audit-finalization consumer / external-publication-audit-completion boundary.
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It attaches the real modeled chain
//! Run 256 backend -> Run 258 receipt -> Run 260 acknowledgement -> Run 262
//! consumer -> Run 264 settlement projection -> Run 266 settlement commitment ->
//! Run 268 settlement finalization -> Run 270 settlement-receipt acknowledgement
//! -> Run 272 settlement-outcome report -> Run 274 settlement-outcome publication
//! -> Run 276 external-publication confirmation -> Run 278 external-publication
//! receipt -> Run 280 external-publication acknowledgement -> Run 282
//! external-publication audit finalization, and then evaluates the Run 284
//! external-publication-audit-completion boundary. Projection is intentionally
//! from `input.external_publication_audit_finalization_binding` through
//! `project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request`.
//!
//! The helper remains dead code from the production runtime: the production
//! `qbind-node` binary never references it. The modeled external-publication
//! audit-completion path stays fixture/in-memory/dev-test only. No production
//! runtime, MainNet enablement, real settlement, or real external publication is
//! enabled. The fixture sink mutates only the in-memory
//! `DurableCompletionExternalPublicationAuditCompletionLedger`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

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
    evaluate_durable_completion_settlement_receipt_acknowledgement,
    settlement_receipt_acknowledgement_identity_digest,
    DurableCompletionSettlementReceiptAcknowledgementExpectations,
    DurableCompletionSettlementReceiptAcknowledgementIdentity,
    DurableCompletionSettlementReceiptAcknowledgementInput,
    DurableCompletionSettlementReceiptAcknowledgementKind,
    DurableCompletionSettlementReceiptAcknowledgementLedger,
    DurableCompletionSettlementReceiptAcknowledgementOutcome,
    DurableCompletionSettlementReceiptAcknowledgementPolicy,
    DurableCompletionSettlementReceiptAcknowledgementRequest,
    FixtureDurableCompletionSettlementReceiptAcknowledgementSink,
};
use qbind_node::pqc_governance_durable_completion_settlement_outcome_report::{
    evaluate_durable_completion_settlement_outcome_report,
    settlement_outcome_report_identity_digest,
    DurableCompletionSettlementOutcomeReportExpectations,
    DurableCompletionSettlementOutcomeReportIdentity,
    DurableCompletionSettlementOutcomeReportInput,
    DurableCompletionSettlementOutcomeReportKind,
    DurableCompletionSettlementOutcomeReportLedger,
    DurableCompletionSettlementOutcomeReportOutcome,
    DurableCompletionSettlementOutcomeReportPolicy,
    DurableCompletionSettlementOutcomeReportRequest,
    FixtureDurableCompletionSettlementOutcomeReportSink,
};
use qbind_node::pqc_governance_durable_completion_settlement_outcome_publication::{
    evaluate_durable_completion_settlement_outcome_publication,
    settlement_outcome_publication_identity_digest,
    DurableCompletionSettlementOutcomePublicationExpectations,
    DurableCompletionSettlementOutcomePublicationIdentity,
    DurableCompletionSettlementOutcomePublicationInput,
    DurableCompletionSettlementOutcomePublicationKind,
    DurableCompletionSettlementOutcomePublicationLedger,
    DurableCompletionSettlementOutcomePublicationOutcome,
    DurableCompletionSettlementOutcomePublicationPolicy,
    DurableCompletionSettlementOutcomePublicationRequest,
    FixtureDurableCompletionSettlementOutcomePublicationSink,
};
use qbind_node::pqc_governance_durable_completion_external_publication_confirmation::{
    external_publication_confirmation_identity_digest,
    durable_completion_external_publication_confirmation_ambiguous_window_fails_closed,
    durable_completion_external_publication_confirmation_attestation_required,
    durable_completion_external_publication_confirmation_backend_submission_required,
    durable_completion_external_publication_confirmation_completion_report_required,
    durable_completion_external_publication_confirmation_external_unavailable,
    durable_completion_external_publication_confirmation_failed_record_never_records,
    durable_completion_external_publication_confirmation_finalization_projection_required,
    durable_completion_external_publication_confirmation_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_confirmation_mainnet_peer_driven_apply_refused_first,
    durable_completion_external_publication_confirmation_never_calls_run_070,
    durable_completion_external_publication_confirmation_never_mutates_live_pqc_trust_state,
    durable_completion_external_publication_confirmation_never_writes_sequence_or_marker,
    durable_completion_external_publication_confirmation_no_external_publication,
    durable_completion_external_publication_confirmation_no_real_audit_ledger,
    durable_completion_external_publication_confirmation_no_rocksdb_file_schema_migration_change,
    durable_completion_external_publication_confirmation_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_confirmation_pipeline_success_required,
    durable_completion_external_publication_confirmation_policy_change_unsupported,
    durable_completion_external_publication_confirmation_production_mainnet_unavailable,
    durable_completion_external_publication_confirmation_receipt_required,
    durable_completion_external_publication_confirmation_record_required_before_reported,
    durable_completion_external_publication_confirmation_rejection_is_non_mutating,
    durable_completion_external_publication_confirmation_rollback_never_records,
    durable_completion_external_publication_confirmation_sink_receipt_required,
    durable_completion_external_publication_confirmation_validator_set_rotation_unsupported,
    evaluate_durable_completion_external_publication_confirmation,
    project_settlement_outcome_publication_outcome_to_external_publication_confirmation_request,
    recover_durable_completion_external_publication_confirmation_window,
    external_publication_confirmation_outcome_authorizes_record,
    external_publication_confirmation_outcome_projects_to_recorded,
    DurableCompletionExternalPublicationConfirmationExpectations,
    DurableCompletionExternalPublicationConfirmationFault,
    DurableCompletionExternalPublicationConfirmationIdentity,
    DurableCompletionExternalPublicationConfirmationInput,
    DurableCompletionExternalPublicationConfirmationKind,
    DurableCompletionExternalPublicationConfirmationLedger,
    DurableCompletionExternalPublicationConfirmationOutcome,
    DurableCompletionExternalPublicationConfirmationPolicy,
    DurableCompletionExternalPublicationConfirmationRequest,
    DurableCompletionExternalPublicationConfirmationRequestIntent,
    DurableCompletionExternalPublicationConfirmationWindow, ExternalExternalPublicationConfirmationSink,
    FixtureDurableCompletionExternalPublicationConfirmationSink,
    GovernanceDurableCompletionExternalPublicationConfirmationSink, MainNetExternalPublicationConfirmationSink,
    ProductionExternalPublicationConfirmationSink,
};
use qbind_node::pqc_governance_durable_completion_external_publication_receipt::{
    external_publication_receipt_identity_digest,
    durable_completion_external_publication_receipt_ambiguous_window_fails_closed,
    durable_completion_external_publication_receipt_attestation_required,
    durable_completion_external_publication_receipt_backend_submission_required,
    durable_completion_external_publication_receipt_completion_report_required,
    durable_completion_external_publication_receipt_external_unavailable,
    durable_completion_external_publication_receipt_failed_record_never_records,
    durable_completion_external_publication_receipt_finalization_projection_required,
    durable_completion_external_publication_receipt_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_receipt_mainnet_peer_driven_apply_refused_first,
    durable_completion_external_publication_receipt_never_calls_run_070,
    durable_completion_external_publication_receipt_never_mutates_live_pqc_trust_state,
    durable_completion_external_publication_receipt_never_writes_sequence_or_marker,
    durable_completion_external_publication_receipt_no_external_publication,
    durable_completion_external_publication_receipt_no_real_audit_ledger,
    durable_completion_external_publication_receipt_no_rocksdb_file_schema_migration_change,
    durable_completion_external_publication_receipt_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_receipt_pipeline_success_required,
    durable_completion_external_publication_receipt_policy_change_unsupported,
    durable_completion_external_publication_receipt_production_mainnet_unavailable,
    durable_completion_external_publication_receipt_receipt_required,
    durable_completion_external_publication_receipt_record_required_before_reported,
    durable_completion_external_publication_receipt_rejection_is_non_mutating,
    durable_completion_external_publication_receipt_rollback_never_records,
    durable_completion_external_publication_receipt_sink_receipt_required,
    durable_completion_external_publication_receipt_validator_set_rotation_unsupported,
    evaluate_durable_completion_external_publication_receipt,
    project_external_publication_confirmation_outcome_to_external_publication_receipt_request,
    recover_durable_completion_external_publication_receipt_window,
    external_publication_receipt_outcome_authorizes_record,
    external_publication_receipt_outcome_projects_to_recorded,
    DurableCompletionExternalPublicationReceiptExpectations,
    DurableCompletionExternalPublicationReceiptFault,
    DurableCompletionExternalPublicationReceiptIdentity,
    DurableCompletionExternalPublicationReceiptInput,
    DurableCompletionExternalPublicationReceiptKind,
    DurableCompletionExternalPublicationReceiptLedger,
    DurableCompletionExternalPublicationReceiptOutcome,
    DurableCompletionExternalPublicationReceiptPolicy,
    DurableCompletionExternalPublicationReceiptRequest,
    DurableCompletionExternalPublicationReceiptRequestIntent,
    DurableCompletionExternalPublicationReceiptWindow, ExternalExternalPublicationReceiptSink,
    FixtureDurableCompletionExternalPublicationReceiptSink,
    GovernanceDurableCompletionExternalPublicationReceiptSink, MainNetExternalPublicationReceiptSink,
    ProductionExternalPublicationReceiptSink,
};
use qbind_node::pqc_governance_durable_completion_external_publication_audit_completion::{
    external_publication_audit_completion_identity_digest,
    external_publication_audit_completion_request_digest,
    external_publication_audit_completion_response_digest,
    external_publication_audit_completion_record_digest,
    external_publication_audit_completion_transcript_digest,
    durable_completion_external_publication_audit_completion_consumer_required,
    durable_completion_external_publication_audit_completion_confirmation_required,
    durable_completion_external_publication_audit_completion_no_real_settlement,
    durable_completion_external_publication_audit_completion_no_real_settlement_finality,
    durable_completion_external_publication_audit_completion_no_real_settlement_receipt,
    durable_completion_external_publication_audit_completion_no_real_settlement_finality_projection,
    durable_completion_external_publication_audit_completion_no_real_external_publication_audit_finalization,
    durable_completion_external_publication_audit_completion_no_real_external_publication_audit_completion,
    DurableCompletionExternalPublicationAuditCompletionBinding,
    DurableCompletionExternalPublicationAuditCompletionDigest,
    DurableCompletionExternalPublicationAuditCompletionEnvironment,
    DurableCompletionExternalPublicationAuditCompletionLedgerRecord,
    DurableCompletionExternalPublicationAuditCompletionLedgerSnapshot,
    DurableCompletionExternalPublicationAuditCompletionLedgerStatus,
    DurableCompletionExternalPublicationAuditCompletionRecord,
    DurableCompletionExternalPublicationAuditCompletionResponse,
    DurableCompletionExternalPublicationAuditCompletionSurface,
    DurableCompletionExternalPublicationAuditCompletionTranscriptDigest,
    durable_completion_external_publication_audit_completion_ambiguous_window_fails_closed,
    durable_completion_external_publication_audit_completion_attestation_required,
    durable_completion_external_publication_audit_completion_backend_submission_required,
    durable_completion_external_publication_audit_completion_completion_report_required,
    durable_completion_external_publication_audit_completion_external_unavailable,
    durable_completion_external_publication_audit_completion_failed_record_never_records,
    durable_completion_external_publication_audit_completion_finalization_projection_required,
    durable_completion_external_publication_audit_completion_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_audit_completion_mainnet_peer_driven_apply_refused_first,
    durable_completion_external_publication_audit_completion_never_calls_run_070,
    durable_completion_external_publication_audit_completion_never_mutates_live_pqc_trust_state,
    durable_completion_external_publication_audit_completion_never_writes_sequence_or_marker,
    durable_completion_external_publication_audit_completion_no_external_publication,
    durable_completion_external_publication_audit_completion_no_real_audit_ledger,
    durable_completion_external_publication_audit_completion_no_rocksdb_file_schema_migration_change,
    durable_completion_external_publication_audit_completion_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_audit_completion_pipeline_success_required,
    durable_completion_external_publication_audit_completion_policy_change_unsupported,
    durable_completion_external_publication_audit_completion_production_mainnet_unavailable,
    durable_completion_external_publication_audit_completion_receipt_required,
    durable_completion_external_publication_audit_completion_record_required_before_reported,
    durable_completion_external_publication_audit_completion_rejection_is_non_mutating,
    durable_completion_external_publication_audit_completion_rollback_never_records,
    durable_completion_external_publication_audit_completion_sink_receipt_required,
    durable_completion_external_publication_audit_completion_validator_set_rotation_unsupported,
    evaluate_durable_completion_external_publication_audit_completion,
    project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request,
    recover_durable_completion_external_publication_audit_completion_window,
    external_publication_audit_completion_outcome_authorizes_record,
    external_publication_audit_completion_outcome_projects_to_recorded,
    DurableCompletionExternalPublicationAuditCompletionExpectations,
    DurableCompletionExternalPublicationAuditCompletionFault,
    DurableCompletionExternalPublicationAuditCompletionIdentity,
    DurableCompletionExternalPublicationAuditCompletionInput,
    DurableCompletionExternalPublicationAuditCompletionKind,
    DurableCompletionExternalPublicationAuditCompletionLedger,
    DurableCompletionExternalPublicationAuditCompletionOutcome,
    DurableCompletionExternalPublicationAuditCompletionPolicy,
    DurableCompletionExternalPublicationAuditCompletionRequest,
    DurableCompletionExternalPublicationAuditCompletionRequestIntent,
    DurableCompletionExternalPublicationAuditCompletionWindow, ExternalExternalPublicationAuditCompletionSink,
    FixtureDurableCompletionExternalPublicationAuditCompletionSink,
    GovernanceDurableCompletionExternalPublicationAuditCompletionSink, MainNetExternalPublicationAuditCompletionSink,
    ProductionExternalPublicationAuditCompletionSink,
};

use qbind_node::pqc_governance_durable_completion_external_publication_audit_finalization::{
    external_publication_audit_finalization_identity_digest,
    durable_completion_external_publication_audit_finalization_ambiguous_window_fails_closed,
    durable_completion_external_publication_audit_finalization_attestation_required,
    durable_completion_external_publication_audit_finalization_backend_submission_required,
    durable_completion_external_publication_audit_finalization_completion_report_required,
    durable_completion_external_publication_audit_finalization_external_unavailable,
    durable_completion_external_publication_audit_finalization_failed_record_never_records,
    durable_completion_external_publication_audit_finalization_finalization_projection_required,
    durable_completion_external_publication_audit_finalization_local_operator_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_audit_finalization_mainnet_peer_driven_apply_refused_first,
    durable_completion_external_publication_audit_finalization_never_calls_run_070,
    durable_completion_external_publication_audit_finalization_never_mutates_live_pqc_trust_state,
    durable_completion_external_publication_audit_finalization_never_writes_sequence_or_marker,
    durable_completion_external_publication_audit_finalization_no_external_publication,
    durable_completion_external_publication_audit_finalization_no_real_audit_ledger,
    durable_completion_external_publication_audit_finalization_no_rocksdb_file_schema_migration_change,
    durable_completion_external_publication_audit_finalization_peer_majority_cannot_satisfy_mainnet_authority,
    durable_completion_external_publication_audit_finalization_pipeline_success_required,
    durable_completion_external_publication_audit_finalization_policy_change_unsupported,
    durable_completion_external_publication_audit_finalization_production_mainnet_unavailable,
    durable_completion_external_publication_audit_finalization_receipt_required,
    durable_completion_external_publication_audit_finalization_record_required_before_reported,
    durable_completion_external_publication_audit_finalization_rejection_is_non_mutating,
    durable_completion_external_publication_audit_finalization_rollback_never_records,
    durable_completion_external_publication_audit_finalization_sink_receipt_required,
    durable_completion_external_publication_audit_finalization_validator_set_rotation_unsupported,
    evaluate_durable_completion_external_publication_audit_finalization,
    project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request,
    recover_durable_completion_external_publication_audit_finalization_window,
    external_publication_audit_finalization_outcome_authorizes_record,
    external_publication_audit_finalization_outcome_projects_to_recorded,
    DurableCompletionExternalPublicationAuditFinalizationExpectations,
    DurableCompletionExternalPublicationAuditFinalizationFault,
    DurableCompletionExternalPublicationAuditFinalizationIdentity,
    DurableCompletionExternalPublicationAuditFinalizationInput,
    DurableCompletionExternalPublicationAuditFinalizationKind,
    DurableCompletionExternalPublicationAuditFinalizationLedger,
    DurableCompletionExternalPublicationAuditFinalizationOutcome,
    DurableCompletionExternalPublicationAuditFinalizationPolicy,
    DurableCompletionExternalPublicationAuditFinalizationRequest,
    DurableCompletionExternalPublicationAuditFinalizationRequestIntent,
    DurableCompletionExternalPublicationAuditFinalizationWindow, ExternalExternalPublicationAuditFinalizationSink,
    FixtureDurableCompletionExternalPublicationAuditFinalizationSink,
    GovernanceDurableCompletionExternalPublicationAuditFinalizationSink, MainNetExternalPublicationAuditFinalizationSink,
    ProductionExternalPublicationAuditFinalizationSink,
};
use qbind_node::pqc_governance_durable_completion_external_publication_acknowledgement::{
    external_publication_acknowledgement_identity_digest,
    evaluate_durable_completion_external_publication_acknowledgement,
    DurableCompletionExternalPublicationAcknowledgementExpectations,
    DurableCompletionExternalPublicationAcknowledgementIdentity,
    DurableCompletionExternalPublicationAcknowledgementInput,
    DurableCompletionExternalPublicationAcknowledgementKind,
    DurableCompletionExternalPublicationAcknowledgementLedger,
    DurableCompletionExternalPublicationAcknowledgementOutcome,
    DurableCompletionExternalPublicationAcknowledgementPolicy,
    DurableCompletionExternalPublicationAcknowledgementRequest,
    FixtureDurableCompletionExternalPublicationAcknowledgementSink,
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
const OUTCOME_REPORT_ID: &str = "fixture-settlement-outcome-report-0001";
const OUTCOME_REPORT_DOMAIN_TAG: &str = "QBIND:run272:domain-separation:v1";
const OUTCOME_REPORT_RECORD_ID: &str =
    "durable-completion-settlement-outcome-report-0001";
const OUTCOME_PUBLICATION_ID: &str = "fixture-settlement-outcome-publication-0001";
const OUTCOME_PUBLICATION_DOMAIN_TAG: &str = "QBIND:run274:domain-separation:v1";
const OUTCOME_PUBLICATION_RECORD_ID: &str =
    "durable-completion-settlement-outcome-publication-0001";
const CONFIRMATION_ID: &str = "fixture-external-publication-confirmation-0001";
const CONFIRMATION_DOMAIN_TAG: &str = "QBIND:run276:domain-separation:v1";
const CONFIRMATION_RECORD_ID: &str =
    "durable-completion-external-publication-confirmation-0001";
const RECEIPT_ID: &str = "fixture-external-publication-receipt-0001";
const RECEIPT_DOMAIN_TAG: &str = "QBIND:run278:domain-separation:v1";
const RECEIPT_RECORD_ID: &str =
    "durable-completion-external-publication-receipt-0001";
const EXT_PUB_ACK_ID: &str = "fixture-external-publication-acknowledgement-0001";
const EXT_PUB_ACK_DOMAIN_TAG: &str = "QBIND:run280:domain-separation:v1";
const EXT_PUB_ACK_RECORD_ID: &str =
    "durable-completion-external-publication-acknowledgement-0001";
const ACKNOWLEDGEMENT_ID: &str = "fixture-external-publication-audit-finalization-0001";
const ACKNOWLEDGEMENT_DOMAIN_TAG: &str = "QBIND:run282:domain-separation:v1";
const ACKNOWLEDGEMENT_RECORD_ID: &str =
    "durable-completion-external-publication-audit-finalization-0001";
const AUDIT_FINALIZATION_ID: &str = "fixture-external-publication-audit-completion-0001";
const AUDIT_FINALIZATION_DOMAIN_TAG: &str = "QBIND:run284:domain-separation:v1";
const AUDIT_FINALIZATION_RECORD_ID: &str =
    "durable-completion-external-publication-audit-completion-0001";

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
    outcome_report_record_id: String,
    outcome_publication_record_id: String,
    confirmation_record_id: String,
    external_publication_receipt_record_id: String,
    external_publication_acknowledgement_record_id: String,
    external_publication_audit_finalization_record_id: String,
    external_publication_audit_completion_record_id: String,
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
        outcome_report_record_id: format!(
            "durable-completion-settlement-outcome-report-{label}"
        ),
        outcome_publication_record_id: format!(
            "durable-completion-settlement-outcome-publication-{label}"
        ),
        confirmation_record_id: format!(
            "durable-completion-external-publication-confirmation-{label}"
        ),
        external_publication_receipt_record_id: format!(
            "durable-completion-external-publication-receipt-{label}"
        ),
        external_publication_acknowledgement_record_id: format!(
            "durable-completion-external-publication-acknowledgement-{label}"
        ),
        external_publication_audit_finalization_record_id: format!(
            "durable-completion-external-publication-audit-finalization-{label}"
        ),
        external_publication_audit_completion_record_id: format!(
            "durable-completion-external-publication-audit-completion-{label}"
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
        outcome_report_record_id: OUTCOME_REPORT_RECORD_ID.to_string(),
        outcome_publication_record_id: OUTCOME_PUBLICATION_RECORD_ID.to_string(),
        confirmation_record_id: CONFIRMATION_RECORD_ID.to_string(),
        external_publication_receipt_record_id: RECEIPT_RECORD_ID.to_string(),
        external_publication_acknowledgement_record_id: EXT_PUB_ACK_RECORD_ID.to_string(),
        external_publication_audit_finalization_record_id: ACKNOWLEDGEMENT_RECORD_ID.to_string(),
        external_publication_audit_completion_record_id: AUDIT_FINALIZATION_RECORD_ID.to_string(),
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
// Run 270 settlement-receipt-acknowledgement attachment (prior boundary)
// Builds a REAL Run 270 recorded outcome from the Run 268 prior. Uses the real
// Run 270 module field names so the Run 272 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedSettlementReceiptAcknowledgement {
    outcome: DurableCompletionSettlementReceiptAcknowledgementOutcome,
    receipt_acknowledgement_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    settlement_finalization: AttachedSettlementFinalization,
}

fn run270_receipt_acknowledgement_identity() -> DurableCompletionSettlementReceiptAcknowledgementIdentity {
    DurableCompletionSettlementReceiptAcknowledgementIdentity {
        finalization_id: RECEIPT_ACKNOWLEDGEMENT_ID.to_string(),
        kind: DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
        policy: DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        domain_separation_tag: RECEIPT_ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    }
}

fn attach_run270_settlement_receipt_acknowledgement(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    receipt_acknowledgement_duplicate: bool,
) -> AttachedSettlementReceiptAcknowledgement {
    let settlement_finalization =
        attach_run268_settlement_finalization(environment, action, false);
    let consumer = settlement_finalization.consumer.clone();
    let ack = &consumer.ack;
    let receipt_acknowledgement_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: receipt_acknowledgement_env,
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
    let id = run270_receipt_acknowledgement_identity();
    let request = DurableCompletionSettlementReceiptAcknowledgementRequest {
        receipt_acknowledgement_record_id: action.receipt_acknowledgement_record_id.clone(),
        environment: receipt_acknowledgement_env,
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
        expected_environment: receipt_acknowledgement_env,
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
        expected_identity: id.clone(),
        expected_receipt_acknowledgement_kind: DurableCompletionSettlementReceiptAcknowledgementKind::FixtureInMemory,
        expected_receipt_acknowledgement_policy: DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        expected_domain_separation_tag: RECEIPT_ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionSettlementReceiptAcknowledgementInput {
        policy: DurableCompletionSettlementReceiptAcknowledgementPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
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
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        settlement_finalization_binding: settlement_finalization.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionSettlementReceiptAcknowledgementLedger::new();
    let mut sink = FixtureDurableCompletionSettlementReceiptAcknowledgementSink::new();
    let first = evaluate_durable_completion_settlement_receipt_acknowledgement(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded
    );
    let outcome = if receipt_acknowledgement_duplicate {
        let second = evaluate_durable_completion_settlement_receipt_acknowledgement(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.receipt_acknowledgement_record_id)
        .expect("recorded Run 270 settlement receipt acknowledgement");
    AttachedSettlementReceiptAcknowledgement {
        outcome,
        receipt_acknowledgement_record_id: action.receipt_acknowledgement_record_id.clone(),
        identity_digest: settlement_receipt_acknowledgement_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        settlement_finalization,
    }
}
// ===========================================================================
// Run 272 settlement-outcome-report attachment (prior boundary)
// Builds a REAL Run 272 recorded outcome from the Run 270 prior. Uses the real
// Run 272 module field names so the Run 274 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedSettlementOutcomeReport {
    outcome: DurableCompletionSettlementOutcomeReportOutcome,
    outcome_report_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    settlement_receipt_acknowledgement: AttachedSettlementReceiptAcknowledgement,
}

fn run272_outcome_report_identity() -> DurableCompletionSettlementOutcomeReportIdentity {
    DurableCompletionSettlementOutcomeReportIdentity {
        receipt_acknowledgement_id: OUTCOME_REPORT_ID.to_string(),
        kind: DurableCompletionSettlementOutcomeReportKind::FixtureInMemory,
        policy: DurableCompletionSettlementOutcomeReportPolicy::FixtureAllowed,
        domain_separation_tag: OUTCOME_REPORT_DOMAIN_TAG.to_string(),
    }
}

fn attach_run272_settlement_outcome_report(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    outcome_report_duplicate: bool,
) -> AttachedSettlementOutcomeReport {
    let settlement_receipt_acknowledgement =
        attach_run270_settlement_receipt_acknowledgement(environment, action, false);
    let consumer = settlement_receipt_acknowledgement.consumer.clone();
    let ack = &consumer.ack;
    let outcome_report_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: outcome_report_env,
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
    let id = run272_outcome_report_identity();
    let request = DurableCompletionSettlementOutcomeReportRequest {
        outcome_report_record_id: action.outcome_report_record_id.clone(),
        environment: outcome_report_env,
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
        settlement_receipt_acknowledgement_identity_digest: settlement_receipt_acknowledgement.identity_digest.clone(),
        settlement_receipt_acknowledgement_request_digest: settlement_receipt_acknowledgement.request_digest.clone(),
        settlement_receipt_acknowledgement_response_digest: settlement_receipt_acknowledgement.response_digest.clone(),
        settlement_receipt_acknowledgement_record_digest: settlement_receipt_acknowledgement.record_digest.clone(),
        settlement_receipt_acknowledgement_transcript_digest: settlement_receipt_acknowledgement.transcript_digest.clone(),
        settlement_receipt_acknowledgement_record_id: settlement_receipt_acknowledgement.receipt_acknowledgement_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: OUTCOME_REPORT_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionSettlementOutcomeReportExpectations {
        expected_outcome_report_record_id: action.outcome_report_record_id.clone(),
        expected_environment: outcome_report_env,
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
        expected_settlement_receipt_acknowledgement_identity_digest: settlement_receipt_acknowledgement.identity_digest.clone(),
        expected_settlement_receipt_acknowledgement_request_digest: settlement_receipt_acknowledgement.request_digest.clone(),
        expected_settlement_receipt_acknowledgement_response_digest: settlement_receipt_acknowledgement
            .response_digest
            .clone(),
        expected_settlement_receipt_acknowledgement_record_digest: settlement_receipt_acknowledgement.record_digest.clone(),
        expected_settlement_receipt_acknowledgement_transcript_digest: settlement_receipt_acknowledgement
            .transcript_digest
            .clone(),
        expected_settlement_receipt_acknowledgement_record_id: settlement_receipt_acknowledgement.receipt_acknowledgement_record_id.clone(),
        expected_identity: id.clone(),
        expected_outcome_report_kind: DurableCompletionSettlementOutcomeReportKind::FixtureInMemory,
        expected_outcome_report_policy: DurableCompletionSettlementOutcomeReportPolicy::FixtureAllowed,
        expected_domain_separation_tag: OUTCOME_REPORT_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionSettlementOutcomeReportInput {
        policy: DurableCompletionSettlementOutcomeReportPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        receipt_acknowledgement_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        settlement_receipt_acknowledgement_binding: settlement_receipt_acknowledgement.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionSettlementOutcomeReportLedger::new();
    let mut sink = FixtureDurableCompletionSettlementOutcomeReportSink::new();
    let first = evaluate_durable_completion_settlement_outcome_report(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementOutcomeReportOutcome::SettlementOutcomeReportRecorded
    );
    let outcome = if outcome_report_duplicate {
        let second = evaluate_durable_completion_settlement_outcome_report(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionSettlementOutcomeReportOutcome::SettlementOutcomeReportDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.outcome_report_record_id)
        .expect("recorded Run 272 settlement outcome report");
    AttachedSettlementOutcomeReport {
        outcome,
        outcome_report_record_id: action.outcome_report_record_id.clone(),
        identity_digest: settlement_outcome_report_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        settlement_receipt_acknowledgement,
    }
}
// ===========================================================================
// Run 274 settlement-outcome-publication attachment (prior boundary)
// Builds a REAL Run 274 recorded outcome from the Run 272 prior. Uses the real
// Run 274 module field names so the Run 274 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedSettlementOutcomePublication {
    outcome: DurableCompletionSettlementOutcomePublicationOutcome,
    outcome_publication_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    settlement_outcome_report: AttachedSettlementOutcomeReport,
}

fn run274_outcome_publication_identity() -> DurableCompletionSettlementOutcomePublicationIdentity {
    DurableCompletionSettlementOutcomePublicationIdentity {
        outcome_report_id: OUTCOME_PUBLICATION_ID.to_string(),
        kind: DurableCompletionSettlementOutcomePublicationKind::FixtureInMemory,
        policy: DurableCompletionSettlementOutcomePublicationPolicy::FixtureAllowed,
        domain_separation_tag: OUTCOME_PUBLICATION_DOMAIN_TAG.to_string(),
    }
}

fn attach_run274_settlement_outcome_publication(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    outcome_publication_duplicate: bool,
) -> AttachedSettlementOutcomePublication {
    let settlement_outcome_report =
        attach_run272_settlement_outcome_report(environment, action, false);
    let consumer = settlement_outcome_report.consumer.clone();
    let ack = &consumer.ack;
    let outcome_publication_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: outcome_publication_env,
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
    let id = run274_outcome_publication_identity();
    let request = DurableCompletionSettlementOutcomePublicationRequest {
        outcome_publication_record_id: action.outcome_publication_record_id.clone(),
        environment: outcome_publication_env,
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
        settlement_outcome_report_identity_digest: settlement_outcome_report.identity_digest.clone(),
        settlement_outcome_report_request_digest: settlement_outcome_report.request_digest.clone(),
        settlement_outcome_report_response_digest: settlement_outcome_report.response_digest.clone(),
        settlement_outcome_report_record_digest: settlement_outcome_report.record_digest.clone(),
        settlement_outcome_report_transcript_digest: settlement_outcome_report.transcript_digest.clone(),
        settlement_outcome_report_record_id: settlement_outcome_report.outcome_report_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: OUTCOME_PUBLICATION_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionSettlementOutcomePublicationExpectations {
        expected_outcome_publication_record_id: action.outcome_publication_record_id.clone(),
        expected_environment: outcome_publication_env,
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
        expected_settlement_outcome_report_identity_digest: settlement_outcome_report.identity_digest.clone(),
        expected_settlement_outcome_report_request_digest: settlement_outcome_report.request_digest.clone(),
        expected_settlement_outcome_report_response_digest: settlement_outcome_report
            .response_digest
            .clone(),
        expected_settlement_outcome_report_record_digest: settlement_outcome_report.record_digest.clone(),
        expected_settlement_outcome_report_transcript_digest: settlement_outcome_report
            .transcript_digest
            .clone(),
        expected_settlement_outcome_report_record_id: settlement_outcome_report.outcome_report_record_id.clone(),
        expected_identity: id.clone(),
        expected_outcome_publication_kind: DurableCompletionSettlementOutcomePublicationKind::FixtureInMemory,
        expected_outcome_publication_policy: DurableCompletionSettlementOutcomePublicationPolicy::FixtureAllowed,
        expected_domain_separation_tag: OUTCOME_PUBLICATION_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionSettlementOutcomePublicationInput {
        policy: DurableCompletionSettlementOutcomePublicationPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        outcome_report_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        settlement_outcome_report_binding: settlement_outcome_report.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionSettlementOutcomePublicationLedger::new();
    let mut sink = FixtureDurableCompletionSettlementOutcomePublicationSink::new();
    let first = evaluate_durable_completion_settlement_outcome_publication(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationRecorded
    );
    let outcome = if outcome_publication_duplicate {
        let second = evaluate_durable_completion_settlement_outcome_publication(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.outcome_publication_record_id)
        .expect("recorded Run 274 settlement outcome publication");
    AttachedSettlementOutcomePublication {
        outcome,
        outcome_publication_record_id: action.outcome_publication_record_id.clone(),
        identity_digest: settlement_outcome_publication_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        settlement_outcome_report,
    }
}

// ===========================================================================
// Run 276 external-publication-confirmation attachment (prior boundary)
// Builds a REAL Run 276 recorded outcome from the Run 274 prior. Uses the real
// Run 276 module field names so the Run 276 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedExternalPublicationConfirmation {
    outcome: DurableCompletionExternalPublicationConfirmationOutcome,
    confirmation_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    settlement_outcome_publication: AttachedSettlementOutcomePublication,
}

fn run276_confirmation_identity() -> DurableCompletionExternalPublicationConfirmationIdentity {
    DurableCompletionExternalPublicationConfirmationIdentity {
        outcome_publication_id: CONFIRMATION_ID.to_string(),
        kind: DurableCompletionExternalPublicationConfirmationKind::FixtureInMemory,
        policy: DurableCompletionExternalPublicationConfirmationPolicy::FixtureAllowed,
        domain_separation_tag: CONFIRMATION_DOMAIN_TAG.to_string(),
    }
}

fn attach_run276_external_publication_confirmation(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    confirmation_duplicate: bool,
) -> AttachedExternalPublicationConfirmation {
    let settlement_outcome_publication =
        attach_run274_settlement_outcome_publication(environment, action, false);
    let consumer = settlement_outcome_publication.consumer.clone();
    let ack = &consumer.ack;
    let confirmation_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: confirmation_env,
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
    let id = run276_confirmation_identity();
    let request = DurableCompletionExternalPublicationConfirmationRequest {
        confirmation_record_id: action.confirmation_record_id.clone(),
        environment: confirmation_env,
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
        settlement_outcome_publication_identity_digest: settlement_outcome_publication.identity_digest.clone(),
        settlement_outcome_publication_request_digest: settlement_outcome_publication.request_digest.clone(),
        settlement_outcome_publication_response_digest: settlement_outcome_publication.response_digest.clone(),
        settlement_outcome_publication_record_digest: settlement_outcome_publication.record_digest.clone(),
        settlement_outcome_publication_transcript_digest: settlement_outcome_publication.transcript_digest.clone(),
        settlement_outcome_publication_record_id: settlement_outcome_publication.outcome_publication_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: CONFIRMATION_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionExternalPublicationConfirmationExpectations {
        expected_confirmation_record_id: action.confirmation_record_id.clone(),
        expected_environment: confirmation_env,
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
        expected_settlement_outcome_publication_identity_digest: settlement_outcome_publication.identity_digest.clone(),
        expected_settlement_outcome_publication_request_digest: settlement_outcome_publication.request_digest.clone(),
        expected_settlement_outcome_publication_response_digest: settlement_outcome_publication
            .response_digest
            .clone(),
        expected_settlement_outcome_publication_record_digest: settlement_outcome_publication.record_digest.clone(),
        expected_settlement_outcome_publication_transcript_digest: settlement_outcome_publication
            .transcript_digest
            .clone(),
        expected_settlement_outcome_publication_record_id: settlement_outcome_publication.outcome_publication_record_id.clone(),
        expected_identity: id.clone(),
        expected_confirmation_kind: DurableCompletionExternalPublicationConfirmationKind::FixtureInMemory,
        expected_confirmation_policy: DurableCompletionExternalPublicationConfirmationPolicy::FixtureAllowed,
        expected_domain_separation_tag: CONFIRMATION_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionExternalPublicationConfirmationInput {
        policy: DurableCompletionExternalPublicationConfirmationPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        outcome_publication_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        settlement_outcome_publication_binding: settlement_outcome_publication.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionExternalPublicationConfirmationLedger::new();
    let mut sink = FixtureDurableCompletionExternalPublicationConfirmationSink::new();
    let first = evaluate_durable_completion_external_publication_confirmation(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionExternalPublicationConfirmationOutcome::ExternalPublicationConfirmationRecorded
    );
    let outcome = if confirmation_duplicate {
        let second = evaluate_durable_completion_external_publication_confirmation(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionExternalPublicationConfirmationOutcome::ExternalPublicationConfirmationDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.confirmation_record_id)
        .expect("recorded Run 276 settlement outcome publication");
    AttachedExternalPublicationConfirmation {
        outcome,
        confirmation_record_id: action.confirmation_record_id.clone(),
        identity_digest: external_publication_confirmation_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        settlement_outcome_publication,
    }
}
// ===========================================================================
// Run 278 external-publication-receipt attachment (prior boundary)
// Builds a REAL Run 278 recorded outcome from the Run 276 prior. Uses the real
// Run 278 module field names so the Run 278 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedExternalPublicationReceipt {
    outcome: DurableCompletionExternalPublicationReceiptOutcome,
    external_publication_receipt_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    external_publication_confirmation: AttachedExternalPublicationConfirmation,
}

fn run278_confirmation_identity() -> DurableCompletionExternalPublicationReceiptIdentity {
    DurableCompletionExternalPublicationReceiptIdentity {
        confirmation_id: RECEIPT_ID.to_string(),
        kind: DurableCompletionExternalPublicationReceiptKind::FixtureInMemory,
        policy: DurableCompletionExternalPublicationReceiptPolicy::FixtureAllowed,
        domain_separation_tag: RECEIPT_DOMAIN_TAG.to_string(),
    }
}

fn attach_run278_external_publication_receipt(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    confirmation_duplicate: bool,
) -> AttachedExternalPublicationReceipt {
    let external_publication_confirmation =
        attach_run276_external_publication_confirmation(environment, action, false);
    let consumer = external_publication_confirmation.consumer.clone();
    let ack = &consumer.ack;
    let confirmation_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: confirmation_env,
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
    let id = run278_confirmation_identity();
    let request = DurableCompletionExternalPublicationReceiptRequest {
        external_publication_receipt_record_id: action.external_publication_receipt_record_id.clone(),
        environment: confirmation_env,
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
        external_publication_confirmation_identity_digest: external_publication_confirmation.identity_digest.clone(),
        external_publication_confirmation_request_digest: external_publication_confirmation.request_digest.clone(),
        external_publication_confirmation_response_digest: external_publication_confirmation.response_digest.clone(),
        external_publication_confirmation_record_digest: external_publication_confirmation.record_digest.clone(),
        external_publication_confirmation_transcript_digest: external_publication_confirmation.transcript_digest.clone(),
        external_publication_confirmation_record_id: external_publication_confirmation.confirmation_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: RECEIPT_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionExternalPublicationReceiptExpectations {
        expected_external_publication_receipt_record_id: action.external_publication_receipt_record_id.clone(),
        expected_environment: confirmation_env,
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
        expected_external_publication_confirmation_identity_digest: external_publication_confirmation.identity_digest.clone(),
        expected_external_publication_confirmation_request_digest: external_publication_confirmation.request_digest.clone(),
        expected_external_publication_confirmation_response_digest: external_publication_confirmation
            .response_digest
            .clone(),
        expected_external_publication_confirmation_record_digest: external_publication_confirmation.record_digest.clone(),
        expected_external_publication_confirmation_transcript_digest: external_publication_confirmation
            .transcript_digest
            .clone(),
        expected_external_publication_confirmation_record_id: external_publication_confirmation.confirmation_record_id.clone(),
        expected_identity: id.clone(),
        expected_external_publication_receipt_kind: DurableCompletionExternalPublicationReceiptKind::FixtureInMemory,
        expected_external_publication_receipt_policy: DurableCompletionExternalPublicationReceiptPolicy::FixtureAllowed,
        expected_domain_separation_tag: RECEIPT_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionExternalPublicationReceiptInput {
        policy: DurableCompletionExternalPublicationReceiptPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        confirmation_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        external_publication_confirmation_binding: external_publication_confirmation.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionExternalPublicationReceiptLedger::new();
    let mut sink = FixtureDurableCompletionExternalPublicationReceiptSink::new();
    let first = evaluate_durable_completion_external_publication_receipt(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionExternalPublicationReceiptOutcome::ExternalPublicationReceiptRecorded
    );
    let outcome = if confirmation_duplicate {
        let second = evaluate_durable_completion_external_publication_receipt(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionExternalPublicationReceiptOutcome::ExternalPublicationReceiptDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.external_publication_receipt_record_id)
        .expect("recorded Run 278 settlement outcome publication");
    AttachedExternalPublicationReceipt {
        outcome,
        external_publication_receipt_record_id: action.external_publication_receipt_record_id.clone(),
        identity_digest: external_publication_receipt_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        external_publication_confirmation,
    }
}

// ===========================================================================
// Run 280 external-publication-acknowledgement attachment (prior boundary)
// Builds a REAL Run 280 recorded outcome from the Run 278 prior. Uses the real
// Run 280 module field names so the Run 280 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedExternalPublicationAcknowledgement {
    outcome: DurableCompletionExternalPublicationAcknowledgementOutcome,
    external_publication_acknowledgement_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    external_publication_receipt: AttachedExternalPublicationReceipt,
}

fn run280_confirmation_identity() -> DurableCompletionExternalPublicationAcknowledgementIdentity {
    DurableCompletionExternalPublicationAcknowledgementIdentity {
        confirmation_id: EXT_PUB_ACK_ID.to_string(),
        kind: DurableCompletionExternalPublicationAcknowledgementKind::FixtureInMemory,
        policy: DurableCompletionExternalPublicationAcknowledgementPolicy::FixtureAllowed,
        domain_separation_tag: EXT_PUB_ACK_DOMAIN_TAG.to_string(),
    }
}

fn attach_run280_external_publication_acknowledgement(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    confirmation_duplicate: bool,
) -> AttachedExternalPublicationAcknowledgement {
    let external_publication_receipt =
        attach_run278_external_publication_receipt(environment, action, false);
    let consumer = external_publication_receipt.consumer.clone();
    let ack = &consumer.ack;
    let confirmation_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: confirmation_env,
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
    let id = run280_confirmation_identity();
    let request = DurableCompletionExternalPublicationAcknowledgementRequest {
        external_publication_acknowledgement_record_id: action.external_publication_acknowledgement_record_id.clone(),
        environment: confirmation_env,
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
        external_publication_receipt_identity_digest: external_publication_receipt.identity_digest.clone(),
        external_publication_receipt_request_digest: external_publication_receipt.request_digest.clone(),
        external_publication_receipt_response_digest: external_publication_receipt.response_digest.clone(),
        external_publication_receipt_record_digest: external_publication_receipt.record_digest.clone(),
        external_publication_receipt_transcript_digest: external_publication_receipt.transcript_digest.clone(),
        external_publication_receipt_record_id: external_publication_receipt.external_publication_receipt_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: EXT_PUB_ACK_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionExternalPublicationAcknowledgementExpectations {
        expected_external_publication_acknowledgement_record_id: action.external_publication_acknowledgement_record_id.clone(),
        expected_environment: confirmation_env,
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
        expected_external_publication_receipt_identity_digest: external_publication_receipt.identity_digest.clone(),
        expected_external_publication_receipt_request_digest: external_publication_receipt.request_digest.clone(),
        expected_external_publication_receipt_response_digest: external_publication_receipt
            .response_digest
            .clone(),
        expected_external_publication_receipt_record_digest: external_publication_receipt.record_digest.clone(),
        expected_external_publication_receipt_transcript_digest: external_publication_receipt
            .transcript_digest
            .clone(),
        expected_external_publication_receipt_record_id: external_publication_receipt.external_publication_receipt_record_id.clone(),
        expected_identity: id.clone(),
        expected_external_publication_acknowledgement_kind: DurableCompletionExternalPublicationAcknowledgementKind::FixtureInMemory,
        expected_external_publication_acknowledgement_policy: DurableCompletionExternalPublicationAcknowledgementPolicy::FixtureAllowed,
        expected_domain_separation_tag: EXT_PUB_ACK_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionExternalPublicationAcknowledgementInput {
        policy: DurableCompletionExternalPublicationAcknowledgementPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        confirmation_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        external_publication_receipt_binding: external_publication_receipt.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionExternalPublicationAcknowledgementLedger::new();
    let mut sink = FixtureDurableCompletionExternalPublicationAcknowledgementSink::new();
    let first = evaluate_durable_completion_external_publication_acknowledgement(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionExternalPublicationAcknowledgementOutcome::ExternalPublicationAcknowledgementRecorded
    );
    let outcome = if confirmation_duplicate {
        let second = evaluate_durable_completion_external_publication_acknowledgement(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionExternalPublicationAcknowledgementOutcome::ExternalPublicationAcknowledgementDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.external_publication_acknowledgement_record_id)
        .expect("recorded Run 280 external-publication-acknowledgement");
    AttachedExternalPublicationAcknowledgement {
        outcome,
        external_publication_acknowledgement_record_id: action.external_publication_acknowledgement_record_id.clone(),
        identity_digest: external_publication_acknowledgement_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        external_publication_receipt,
    }
}

// ===========================================================================
// Run 282 external_publication_audit_finalization attachment (prior boundary)
// Builds a REAL Run 282 recorded outcome from the Run 280 prior. Uses the real
// Run 282 module field names so the Run 282 cur-layer can consume it.
// ===========================================================================
#[allow(dead_code)]
struct AttachedExternalPublicationAuditFinalization {
    outcome: DurableCompletionExternalPublicationAuditFinalizationOutcome,
    external_publication_audit_finalization_record_id: String,
    identity_digest: String,
    request_digest: String,
    response_digest: String,
    record_digest: String,
    transcript_digest: String,
    consumer: AttachedConsumer,
    external_publication_receipt: AttachedExternalPublicationReceipt,
}

fn run282_confirmation_identity() -> DurableCompletionExternalPublicationAuditFinalizationIdentity {
    DurableCompletionExternalPublicationAuditFinalizationIdentity {
        confirmation_id: ACKNOWLEDGEMENT_ID.to_string(),
        kind: DurableCompletionExternalPublicationAuditFinalizationKind::FixtureInMemory,
        policy: DurableCompletionExternalPublicationAuditFinalizationPolicy::FixtureAllowed,
        domain_separation_tag: ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    }
}

fn attach_run282_external_publication_audit_finalization(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    confirmation_duplicate: bool,
) -> AttachedExternalPublicationAuditFinalization {
    let external_publication_acknowledgement =
        attach_run280_external_publication_acknowledgement(environment, action, false);
    let consumer = external_publication_acknowledgement.consumer.clone();
    let ack = &consumer.ack;
    let confirmation_env = match environment {
        TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet => environment,
        TrustBundleEnvironment::Mainnet => TrustBundleEnvironment::Devnet,
    };
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment: confirmation_env,
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
    let id = run282_confirmation_identity();
    let request = DurableCompletionExternalPublicationAuditFinalizationRequest {
        external_publication_audit_finalization_record_id: action.external_publication_audit_finalization_record_id.clone(),
        environment: confirmation_env,
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
        external_publication_acknowledgement_identity_digest: external_publication_acknowledgement.identity_digest.clone(),
        external_publication_acknowledgement_request_digest: external_publication_acknowledgement.request_digest.clone(),
        external_publication_acknowledgement_response_digest: external_publication_acknowledgement.response_digest.clone(),
        external_publication_acknowledgement_record_digest: external_publication_acknowledgement.record_digest.clone(),
        external_publication_acknowledgement_transcript_digest: external_publication_acknowledgement.transcript_digest.clone(),
        external_publication_acknowledgement_record_id: external_publication_acknowledgement.external_publication_acknowledgement_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionExternalPublicationAuditFinalizationExpectations {
        expected_external_publication_audit_finalization_record_id: action.external_publication_audit_finalization_record_id.clone(),
        expected_environment: confirmation_env,
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
        expected_external_publication_acknowledgement_identity_digest: external_publication_acknowledgement.identity_digest.clone(),
        expected_external_publication_acknowledgement_request_digest: external_publication_acknowledgement.request_digest.clone(),
        expected_external_publication_acknowledgement_response_digest: external_publication_acknowledgement
            .response_digest
            .clone(),
        expected_external_publication_acknowledgement_record_digest: external_publication_acknowledgement.record_digest.clone(),
        expected_external_publication_acknowledgement_transcript_digest: external_publication_acknowledgement
            .transcript_digest
            .clone(),
        expected_external_publication_acknowledgement_record_id: external_publication_acknowledgement.external_publication_acknowledgement_record_id.clone(),
        expected_identity: id.clone(),
        expected_external_publication_audit_finalization_kind: DurableCompletionExternalPublicationAuditFinalizationKind::FixtureInMemory,
        expected_external_publication_audit_finalization_policy: DurableCompletionExternalPublicationAuditFinalizationPolicy::FixtureAllowed,
        expected_domain_separation_tag: ACKNOWLEDGEMENT_DOMAIN_TAG.to_string(),
    };
    let input = DurableCompletionExternalPublicationAuditFinalizationInput {
        policy: DurableCompletionExternalPublicationAuditFinalizationPolicy::FixtureAllowed,
        environment_binding: env,
        runtime_binding: runtime,
        replay_binding: DurableReplayObservation::MutationAuthorized,
        pipeline_binding:
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        sink_binding: GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        reporter_binding:
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        confirmation_binding:
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        attestation_binding:
            GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        backend_binding: ack.receipt.backend.outcome.clone(),
        receipt_binding: ack.receipt.outcome.clone(),
        acknowledgement_binding: ack.outcome.clone(),
        consumer_binding: consumer.outcome.clone(),
        external_publication_acknowledgement_binding: external_publication_acknowledgement.outcome.clone(),
        request,
    };
    let mut ledger = DurableCompletionExternalPublicationAuditFinalizationLedger::new();
    let mut sink = FixtureDurableCompletionExternalPublicationAuditFinalizationSink::new();
    let first = evaluate_durable_completion_external_publication_audit_finalization(
        &input,
        &expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionExternalPublicationAuditFinalizationOutcome::ExternalPublicationAuditFinalizationRecorded
    );
    let outcome = if confirmation_duplicate {
        let second = evaluate_durable_completion_external_publication_audit_finalization(
            &input,
            &expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            second,
            DurableCompletionExternalPublicationAuditFinalizationOutcome::ExternalPublicationAuditFinalizationDuplicateIdempotent
        );
        second
    } else {
        first
    };
    let record = ledger
        .find(&action.external_publication_audit_finalization_record_id)
        .expect("recorded Run 282 settlement outcome publication");
    AttachedExternalPublicationAuditFinalization {
        outcome,
        external_publication_audit_finalization_record_id: action.external_publication_audit_finalization_record_id.clone(),
        identity_digest: external_publication_audit_finalization_identity_digest(&id)
            .as_hex()
            .to_string(),
        request_digest: record.request_digest.as_hex().to_string(),
        response_digest: record.response_digest.as_hex().to_string(),
        record_digest: record.record_digest.as_hex().to_string(),
        transcript_digest: record.transcript_digest.as_hex().to_string(),
        consumer,
        external_publication_receipt: external_publication_acknowledgement.external_publication_receipt,
    }
}


// ===========================================================================
// Run 284 owned-context builder
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    request: DurableCompletionExternalPublicationAuditCompletionRequest,
    expectations: DurableCompletionExternalPublicationAuditCompletionExpectations,
    consumer: AttachedConsumer,
    external_publication_audit_finalization: AttachedExternalPublicationAuditFinalization,
}

fn ack_identity(
    policy: DurableCompletionExternalPublicationAuditCompletionPolicy,
    kind: DurableCompletionExternalPublicationAuditCompletionKind,
) -> DurableCompletionExternalPublicationAuditCompletionIdentity {
    DurableCompletionExternalPublicationAuditCompletionIdentity {
        confirmation_id: AUDIT_FINALIZATION_ID.to_string(),
        kind,
        policy,
        domain_separation_tag: AUDIT_FINALIZATION_DOMAIN_TAG.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ctx_action(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionExternalPublicationAuditCompletionPolicy,
    kind: DurableCompletionExternalPublicationAuditCompletionKind,
    action: &ActionLabel,
    consumer_duplicate: bool,
) -> Ctx {
    let external_publication_audit_finalization =
        attach_run282_external_publication_audit_finalization(environment, action, consumer_duplicate);
    let consumer = external_publication_audit_finalization.consumer.clone();
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
    let request = DurableCompletionExternalPublicationAuditCompletionRequest {
        external_publication_audit_completion_record_id: action.external_publication_audit_completion_record_id.clone(),
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
        external_publication_audit_finalization_identity_digest: external_publication_audit_finalization.identity_digest.clone(),
        external_publication_audit_finalization_request_digest: external_publication_audit_finalization.request_digest.clone(),
        external_publication_audit_finalization_response_digest: external_publication_audit_finalization.response_digest.clone(),
        external_publication_audit_finalization_record_digest: external_publication_audit_finalization.record_digest.clone(),
        external_publication_audit_finalization_transcript_digest: external_publication_audit_finalization.transcript_digest.clone(),
        external_publication_audit_finalization_record_id: external_publication_audit_finalization.external_publication_audit_finalization_record_id.clone(),
        identity: id.clone(),
        domain_separation_tag: AUDIT_FINALIZATION_DOMAIN_TAG.to_string(),
    };
    let expectations = DurableCompletionExternalPublicationAuditCompletionExpectations {
        expected_external_publication_audit_completion_record_id: action.external_publication_audit_completion_record_id.clone(),
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
        expected_external_publication_audit_finalization_identity_digest: external_publication_audit_finalization.identity_digest.clone(),
        expected_external_publication_audit_finalization_request_digest: external_publication_audit_finalization.request_digest.clone(),
        expected_external_publication_audit_finalization_response_digest: external_publication_audit_finalization
            .response_digest
            .clone(),
        expected_external_publication_audit_finalization_record_digest: external_publication_audit_finalization.record_digest.clone(),
        expected_external_publication_audit_finalization_transcript_digest: external_publication_audit_finalization
            .transcript_digest
            .clone(),
        expected_external_publication_audit_finalization_record_id: external_publication_audit_finalization.external_publication_audit_finalization_record_id.clone(),
        expected_identity: id,
        expected_external_publication_audit_completion_kind: kind,
        expected_external_publication_audit_completion_policy: policy,
        expected_domain_separation_tag: AUDIT_FINALIZATION_DOMAIN_TAG.to_string(),
    };
    Ctx {
        env,
        runtime,
        request,
        expectations,
        consumer,
        external_publication_audit_finalization,
    }
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    policy: DurableCompletionExternalPublicationAuditCompletionPolicy,
    kind: DurableCompletionExternalPublicationAuditCompletionKind,
) -> Ctx {
    ctx_action(environment, vs, ms, policy, kind, &default_action(), false)
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input_with_confirmation(
        &self,
        policy: DurableCompletionExternalPublicationAuditCompletionPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        external_publication_audit_completion: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
        receipt: DurableCompletionAuditPublicationReceiptOutcome,
        acknowledgement: DurableCompletionAuditReceiptAcknowledgementOutcome,
        consumer: DurableCompletionAcknowledgementConsumerOutcome,
        external_publication_audit_finalization: DurableCompletionExternalPublicationAuditFinalizationOutcome,
    ) -> DurableCompletionExternalPublicationAuditCompletionInput {
        DurableCompletionExternalPublicationAuditCompletionInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            confirmation_binding: external_publication_audit_completion,
            attestation_binding: attestation,
            backend_binding: backend,
            receipt_binding: receipt,
            acknowledgement_binding: acknowledgement,
            consumer_binding: consumer,
            external_publication_audit_finalization_binding: external_publication_audit_finalization,
            request: self.request.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: DurableCompletionExternalPublicationAuditCompletionPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
        reporter: GovernanceModeledDurableConsumeCompletionReporterOutcome,
        external_publication_audit_completion: GovernanceModeledDurableCompletionFinalizationOutcome,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
        backend: DurableCompletionAttestationBackendOutcome,
    ) -> DurableCompletionExternalPublicationAuditCompletionInput {
        self.input_with_confirmation(
            policy,
            replay,
            pipeline,
            sink,
            reporter,
            external_publication_audit_completion,
            attestation,
            backend,
            self.consumer.ack.receipt.outcome.clone(),
            self.consumer.ack.outcome.clone(),
            self.consumer.outcome.clone(),
            self.external_publication_audit_finalization.outcome.clone(),
        )
    }

    fn recorded(&self) -> DurableCompletionExternalPublicationAuditCompletionInput {
        self.input_with_confirmation(
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
            self.external_publication_audit_finalization.outcome.clone(),
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
    )
}

fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
    )
}

fn fixture_sink() -> FixtureDurableCompletionExternalPublicationAuditCompletionSink {
    FixtureDurableCompletionExternalPublicationAuditCompletionSink::new()
}
fn disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation() {
    let c = devnet_ctx();
    let input = c.input(
        DurableCompletionExternalPublicationAuditCompletionPolicy::Disabled,
        DurableReplayObservation::MutationAuthorized,
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
        GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested,
        c.consumer.ack.receipt.backend.outcome.clone(),
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::LegacyBypassNoExternalPublicationAuditCompletion
    );
    assert!(outcome.is_legacy_bypass());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn disabled_backend_policy_never_invokes_receipt_sink() {
    let c = devnet_ctx();
    let input = c.input_with_confirmation(
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
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
        DurableCompletionExternalPublicationAuditFinalizationOutcome::LegacyBypassNoExternalPublicationAuditFinalization,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::LegacyBypassNoExternalPublicationAuditCompletion
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
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded
    );
    assert!(external_publication_audit_completion_outcome_authorizes_record(&outcome));
    assert!(external_publication_audit_completion_outcome_projects_to_recorded(&outcome));
    assert_eq!(sink.invocations(), 1);
    assert_eq!(ledger.len(), 1);
    assert!(ledger.contains(AUDIT_FINALIZATION_RECORD_ID));
    assert_eq!(
        external_publication_audit_completion_identity_digest(&c.request.identity),
        c.request.identity.digest()
    );
}

fn testnet_fixture_chain_records_exactly_one_receipt() {
    let c = testnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded
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
            DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
            DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
            &action,
            false,
        );
        assert_eq!(
            c.consumer.ack.receipt.backend.outcome,
            DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded
        );
        let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
        let mut sink = fixture_sink();
        let outcome = evaluate_durable_completion_external_publication_audit_completion(
            &c.recorded(),
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        assert_eq!(
            outcome,
            DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded,
            "action {label} must record after backend submission"
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&action.external_publication_audit_completion_record_id));
    }
}

fn duplicate_identical_receipt_is_idempotent() {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let first = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded
    );
    let second = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        second,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionDuplicateIdempotent
    );
    assert!(!external_publication_audit_completion_outcome_authorizes_record(&second));
    assert!(external_publication_audit_completion_outcome_projects_to_recorded(&second));
    assert_eq!(ledger.len(), 1);
}

fn run268_duplicate_idempotent_confirmation_only_matches_existing_never_creates() {
    // A real Run 282 ExternalPublicationAuditFinalizationDuplicateIdempotent outcome with
    // identical digests.
    let dup_ctx = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
        &default_action(),
        true,
    );
    assert_eq!(
        dup_ctx.external_publication_audit_finalization.outcome,
        DurableCompletionExternalPublicationAuditFinalizationOutcome::ExternalPublicationAuditFinalizationDuplicateIdempotent
    );

    // With no prior receipt, a duplicate-idempotent backend cannot create one.
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRejectedBeforeRecord
    );
    assert!(ledger.is_empty());

    // After a real receipt records, the duplicate-idempotent backend matches it.
    let rec_ctx = devnet_ctx();
    let recorded = evaluate_durable_completion_external_publication_audit_completion(
        &rec_ctx.recorded(),
        &rec_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        recorded,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded
    );
    let matched = evaluate_durable_completion_external_publication_audit_completion(
        &dup_ctx.recorded(),
        &dup_ctx.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        matched,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionDuplicateIdempotent
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
        DurableCompletionExternalPublicationAuditCompletionPolicy::ProductionExternalPublicationAuditCompletionRequired,
        DurableCompletionExternalPublicationAuditCompletionKind::ProductionExternalPublicationAuditCompletionUnavailable,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = ProductionExternalPublicationAuditCompletionSink::default();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ProductionExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    assert!(ledger.is_empty());
}

fn mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionExternalPublicationAuditCompletionPolicy::MainNetExternalPublicationAuditCompletionRequired,
        DurableCompletionExternalPublicationAuditCompletionKind::MainNetExternalPublicationAuditCompletionUnavailable,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = MainNetExternalPublicationAuditCompletionSink::default();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::MainNetExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    assert!(ledger.is_empty());
}

fn external_publication_path_reachable_but_unavailable_records_nothing() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionExternalPublicationAuditCompletionPolicy::ExternalExternalPublicationAuditCompletionRequired,
        DurableCompletionExternalPublicationAuditCompletionKind::ExternalExternalPublicationAuditCompletionUnavailable,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = ExternalExternalPublicationAuditCompletionSink::default();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    assert!(ledger.is_empty());
}

fn mainnet_peer_driven_apply_refused_before_receipt_sink_invocation() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionExternalPublicationAuditCompletionPolicy::MainNetExternalPublicationAuditCompletionRequired,
        DurableCompletionExternalPublicationAuditCompletionKind::MainNetExternalPublicationAuditCompletionUnavailable,
    );
    let input = c.input(
        DurableCompletionExternalPublicationAuditCompletionPolicy::MainNetExternalPublicationAuditCompletionRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = MainNetExternalPublicationAuditCompletionSink::default();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::MainNetPeerDrivenApplyRefusedNoAuditCompletion
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

fn validator_set_rotation_and_policy_change_unsupported() {
    let c = devnet_ctx();
    let rotation = c.input_with_confirmation(
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
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
        DurableCompletionExternalPublicationAuditFinalizationOutcome::ValidatorSetRotationUnsupportedNoAuditFinalization,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &rotation,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ValidatorSetRotationUnsupportedNoAuditCompletion
    );
    assert_eq!(sink.invocations(), 0);

    let policy_change = c.input_with_confirmation(
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
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
        DurableCompletionExternalPublicationAuditFinalizationOutcome::PolicyChangeUnsupportedNoAuditFinalization,
    );
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &policy_change,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::PolicyChangeUnsupportedNoAuditCompletion
    );
    assert_eq!(sink.invocations(), 0);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Rejected / fail-closed matrix — non-recording Run 258 receipt outcomes
// ===========================================================================

fn assert_non_recording_confirmation(
    external_publication_audit_finalization: DurableCompletionExternalPublicationAuditFinalizationOutcome,
    expected: DurableCompletionExternalPublicationAuditCompletionOutcome,
) {
    let c = devnet_ctx();
    let input = c.input_with_confirmation(
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
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
        external_publication_audit_finalization,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
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

fn non_recording_confirmation_outcomes_never_record_external_publication_audit_completion() {
    use DurableCompletionExternalPublicationAuditFinalizationOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionOutcome as Receipt;
    assert_non_recording_confirmation(
        Finalization::LegacyBypassNoExternalPublicationAuditFinalization,
        Receipt::LegacyBypassNoExternalPublicationAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::RejectedBeforeExternalPublicationAcknowledgementNoAuditFinalization,
        Receipt::RejectedBeforeExternalPublicationAuditFinalizationNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalPublicationAcknowledgementDidNotRecordNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalPublicationAuditFinalizationRejectedBeforeRecord,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalPublicationAuditFinalizationRecordFailedNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalPublicationAuditFinalizationRolledBackNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalPublicationAuditFinalizationRollbackFailedFatalNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalPublicationAuditFinalizationAmbiguousFailClosedNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ProductionExternalPublicationAuditFinalizationUnavailableNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::MainNetExternalPublicationAuditFinalizationUnavailableNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ExternalExternalPublicationAuditFinalizationUnavailableNoAuditFinalization,
        Receipt::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::MainNetPeerDrivenApplyRefusedNoAuditFinalization,
        Receipt::MainNetPeerDrivenApplyRefusedNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::ValidatorSetRotationUnsupportedNoAuditFinalization,
        Receipt::ValidatorSetRotationUnsupportedNoAuditCompletion,
    );
    assert_non_recording_confirmation(
        Finalization::PolicyChangeUnsupportedNoAuditFinalization,
        Receipt::PolicyChangeUnsupportedNoAuditCompletion,
    );
}

// ===========================================================================
// Rejected / fail-closed matrix — binding mismatch (before sink invocation)
// ===========================================================================

fn assert_binding_mismatch_rejected(mut mutate: impl FnMut(&mut Ctx)) {
    let mut c = devnet_ctx();
    mutate(&mut c);
    let input = c.recorded();
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::RejectedBeforeExternalPublicationAuditFinalizationNoAuditCompletion
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
    mut mutate: impl FnMut(&mut DurableCompletionExternalPublicationAuditCompletionRequest),
) {
    let c = devnet_ctx();
    let mut input = c.recorded();
    mutate(&mut input.request);
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRejectedBeforeRecord
    );
    // The sink is invoked (binding matched) but records nothing.
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

fn wrong_external_publication_audit_completion_record_id_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.external_publication_audit_completion_record_id = "other-confirmation".to_string();
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
        r.finalization_decision_digest = "other-outcome-publication".to_string();
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
        r.identity.confirmation_id = "other-receipt-id".to_string();
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
            DurableCompletionExternalPublicationAuditCompletionPolicy::ProductionExternalPublicationAuditCompletionRequired;
    });
}

fn wrong_receipt_kind_rejected_before_record() {
    assert_request_mismatch_rejected(|r| {
        r.identity.kind =
            DurableCompletionExternalPublicationAuditCompletionKind::ProductionExternalPublicationAuditCompletionUnavailable;
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
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();

    let first = evaluate_durable_completion_external_publication_audit_completion(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        first,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded
    );

    // A second receipt with the SAME receipt record id but a differing digest fails
    // closed as equivocation. We adjust both request and expectations on a differing
    // field so binding/request validation passes and the equivocation gate rejects.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
    let equivocation = evaluate_durable_completion_external_publication_audit_completion(
        &c2.recorded(),
        &c2.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        equivocation,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRejectedBeforeRecord
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
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
    );
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRejectedBeforeRecord
    );
    assert_eq!(sink.invocations(), 1);
    assert!(ledger.is_empty());
}

// ===========================================================================
// Receipt record failure / rollback / ambiguous
// ===========================================================================

fn assert_fault_no_acknowledgement(
    fault: DurableCompletionExternalPublicationAuditCompletionFault,
    expected: DurableCompletionExternalPublicationAuditCompletionOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = FixtureDurableCompletionExternalPublicationAuditCompletionSink::with_fault(fault);
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
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

fn receipt_record_failed_never_records() {
    assert_fault_no_acknowledgement(
        DurableCompletionExternalPublicationAuditCompletionFault::RecordFailedNoReceipt,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecordFailedNoAuditCompletion,
    );
}

fn receipt_rollback_completed_never_records() {
    assert_fault_no_acknowledgement(
        DurableCompletionExternalPublicationAuditCompletionFault::RolledBackNoReceipt,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRolledBackNoAuditCompletion,
    );
}

fn receipt_rollback_failed_fatal_never_records() {
    assert_fault_no_acknowledgement(
        DurableCompletionExternalPublicationAuditCompletionFault::RollbackFailedFatal,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRollbackFailedFatalNoAuditCompletion,
    );
}

fn receipt_ambiguous_window_fails_closed() {
    assert_fault_no_acknowledgement(
        DurableCompletionExternalPublicationAuditCompletionFault::AmbiguousAfterRecord,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionAmbiguousFailClosedNoAuditCompletion,
    );
}

// ===========================================================================
// Finalization cases
// ===========================================================================

fn only_recorded_confirmation_outcome_creates_external_publication_audit_completion_request_intent() {
    use DurableCompletionExternalPublicationAuditFinalizationOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionRequestIntent as Intent;
    assert_eq!(
        project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request(
            &Finalization::ExternalPublicationAuditFinalizationRecorded
        ),
        Intent::CreateRequest
    );
    assert!(project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request(
        &Finalization::ExternalPublicationAuditFinalizationRecorded
    )
    .creates_request());
    assert_eq!(
        project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request(
            &Finalization::ExternalPublicationAuditFinalizationDuplicateIdempotent
        ),
        Intent::IdempotentOnly
    );
    assert!(!project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request(
        &Finalization::LegacyBypassNoExternalPublicationAuditFinalization
    )
    .creates_request());
}

fn non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request() {
    use DurableCompletionExternalPublicationAuditFinalizationOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionRequestIntent as Intent;
    for confirmation in [
        Finalization::LegacyBypassNoExternalPublicationAuditFinalization,
        Finalization::RejectedBeforeExternalPublicationAcknowledgementNoAuditFinalization,
        Finalization::ExternalPublicationAcknowledgementDidNotRecordNoAuditFinalization,
        Finalization::ExternalPublicationAuditFinalizationRejectedBeforeRecord,
        Finalization::ExternalPublicationAuditFinalizationRecordFailedNoAuditFinalization,
        Finalization::ProductionExternalPublicationAuditFinalizationUnavailableNoAuditFinalization,
    ] {
        assert!(matches!(
            project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request(&confirmation),
            Intent::NoReceipt(_)
        ));
    }
}

// ===========================================================================
// Recovery / crash-window cases
// ===========================================================================

fn recovered_ledger() -> DurableCompletionExternalPublicationAuditCompletionLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_external_publication_audit_completion(
        &c.recorded(),
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    ledger
}

fn assert_window(
    window: DurableCompletionExternalPublicationAuditCompletionWindow,
    with_record: bool,
    expected: DurableCompletionExternalPublicationAuditCompletionOutcome,
) {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(AUDIT_FINALIZATION_RECORD_ID)
    } else {
        None
    };
    let outcome = recover_durable_completion_external_publication_audit_completion_window(
        &input,
        window,
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
        record,
        &c.expectations,
    );
    assert_eq!(outcome, expected);
}

fn pre_external_publication_audit_finalization_windows_fail_closed_no_commitment() {
    use DurableCompletionExternalPublicationAuditCompletionOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionWindow as Window;
    for w in [
        Window::BeforePipeline,
        Window::AfterPipelineSuccessBeforeSinkIntent,
        Window::AfterSinkIntentBeforeSinkReceiptRecord,
        Window::AfterSinkReceiptRecordBeforePublicationIntent,
        Window::AfterPublicationIntentBeforePublicationRecord,
        Window::AfterPublicationRecordBeforeReceiptIntent,
        Window::AfterReceiptIntentBeforeReceiptRecord,
        Window::AfterReceiptRecordBeforeAttestationIntent,
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
        Window::AfterConsumerSuccessBeforeExternalPublicationAuditFinalizationRequest,
        Window::AfterExternalPublicationAuditFinalizationRequestBeforeExternalPublicationAuditFinalizationRecord,
        Window::AfterExternalPublicationAuditFinalizationRecordBeforeExternalPublicationAuditFinalizationSuccess,
        Window::AfterExternalPublicationAuditFinalizationSuccessBeforeExternalPublicationAuditCompletionRequest,
    ] {
        assert_window(
            w,
            false,
            Finalization::ExternalPublicationAuditFinalizationDidNotRecordNoAuditCompletion,
        );
    }
}

fn after_external_publication_audit_finalization_request_before_record_rejects_before_record() {
    use DurableCompletionExternalPublicationAuditCompletionOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionWindow as Window;
    assert_window(
        Window::AfterExternalPublicationAuditCompletionRequestBeforeExternalPublicationAuditCompletionRecord,
        false,
        Finalization::ExternalPublicationAuditCompletionRejectedBeforeRecord,
    );
}

fn after_external_publication_audit_finalization_record_before_success_requires_explicit_matching_record() {
    use DurableCompletionExternalPublicationAuditCompletionOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionWindow as Window;
    assert_window(
        Window::AfterExternalPublicationAuditCompletionRecordBeforeExternalPublicationAuditCompletionSuccess,
        false,
        Finalization::ExternalPublicationAuditCompletionRejectedBeforeRecord,
    );
    assert_window(
        Window::AfterExternalPublicationAuditCompletionRecordBeforeExternalPublicationAuditCompletionSuccess,
        true,
        Finalization::ExternalPublicationAuditCompletionRecorded,
    );
}

fn after_external_publication_audit_finalization_success_recovers_as_recorded() {
    use DurableCompletionExternalPublicationAuditCompletionOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionWindow as Window;
    assert_window(
        Window::AfterExternalPublicationAuditCompletionSuccess,
        true,
        Finalization::ExternalPublicationAuditCompletionRecorded,
    );
    // Without an explicit matching record, even after-success fails closed.
    assert_window(
        Window::AfterExternalPublicationAuditCompletionSuccess,
        false,
        Finalization::ExternalPublicationAuditCompletionRejectedBeforeRecord,
    );
}

fn ambiguous_record_failed_rollback_and_unknown_windows_fail_closed() {
    use DurableCompletionExternalPublicationAuditCompletionOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditCompletionWindow as Window;
    assert_window(
        Window::AfterExternalPublicationAuditCompletionAmbiguous,
        false,
        Finalization::ExternalPublicationAuditCompletionAmbiguousFailClosedNoAuditCompletion,
    );
    assert_window(
        Window::Unknown,
        false,
        Finalization::ExternalPublicationAuditCompletionAmbiguousFailClosedNoAuditCompletion,
    );
    assert_window(
        Window::ExternalPublicationAuditCompletionRecordFailed,
        false,
        Finalization::ExternalPublicationAuditCompletionRecordFailedNoAuditCompletion,
    );
    assert_window(
        Window::ExternalPublicationAuditCompletionRollbackCompleted,
        false,
        Finalization::ExternalPublicationAuditCompletionRolledBackNoAuditCompletion,
    );
    assert_window(
        Window::ExternalPublicationAuditCompletionRollbackFailed,
        false,
        Finalization::ExternalPublicationAuditCompletionRollbackFailedFatalNoAuditCompletion,
    );
}

fn production_mainnet_external_recovery_classification_unavailable() {
    let c = devnet_ctx();
    let input = c.recorded();
    let outcome = recover_durable_completion_external_publication_audit_completion_window(
        &input,
        DurableCompletionExternalPublicationAuditCompletionWindow::AfterExternalPublicationAuditCompletionSuccess,
        DurableCompletionExternalPublicationAuditCompletionKind::ProductionExternalPublicationAuditCompletionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ProductionExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    let outcome = recover_durable_completion_external_publication_audit_completion_window(
        &input,
        DurableCompletionExternalPublicationAuditCompletionWindow::AfterExternalPublicationAuditCompletionSuccess,
        DurableCompletionExternalPublicationAuditCompletionKind::MainNetExternalPublicationAuditCompletionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::MainNetExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    let outcome = recover_durable_completion_external_publication_audit_completion_window(
        &input,
        DurableCompletionExternalPublicationAuditCompletionWindow::AfterExternalPublicationAuditCompletionSuccess,
        DurableCompletionExternalPublicationAuditCompletionKind::ExternalExternalPublicationAuditCompletionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
}

fn mainnet_peer_driven_refusal_precedes_recovery_classification() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionExternalPublicationAuditCompletionPolicy::MainNetExternalPublicationAuditCompletionRequired,
        DurableCompletionExternalPublicationAuditCompletionKind::MainNetExternalPublicationAuditCompletionUnavailable,
    );
    let input = c.input(
        DurableCompletionExternalPublicationAuditCompletionPolicy::MainNetExternalPublicationAuditCompletionRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let outcome = recover_durable_completion_external_publication_audit_completion_window(
        &input,
        DurableCompletionExternalPublicationAuditCompletionWindow::AfterExternalPublicationAuditCompletionSuccess,
        DurableCompletionExternalPublicationAuditCompletionKind::MainNetExternalPublicationAuditCompletionUnavailable,
        None,
        &c.expectations,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::MainNetPeerDrivenApplyRefusedNoAuditCompletion
    );
}

// ===========================================================================
// Receipt-ledger cases
// ===========================================================================

fn rollback_restores_receipt_ledger_snapshot() {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = fixture_sink();
    let _ = evaluate_durable_completion_external_publication_audit_completion(
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
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed,
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
        &action,
        false,
    );
    let mut faulted = FixtureDurableCompletionExternalPublicationAuditCompletionSink::with_fault(
        DurableCompletionExternalPublicationAuditCompletionFault::RolledBackNoReceipt,
    );
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &c2.recorded(),
        &c2.expectations,
        &mut faulted,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRolledBackNoAuditCompletion
    );
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.contains(&action.external_publication_audit_completion_record_id));
}

// ===========================================================================
// Invariant / non-mutation helpers
// ===========================================================================

fn invariant_helpers_assert_fail_closed_contract() {
    assert!(durable_completion_external_publication_audit_completion_rejection_is_non_mutating());
    assert!(durable_completion_external_publication_audit_completion_never_calls_run_070());
    assert!(durable_completion_external_publication_audit_completion_never_mutates_live_pqc_trust_state());
    assert!(durable_completion_external_publication_audit_completion_never_writes_sequence_or_marker());
    assert!(durable_completion_external_publication_audit_completion_no_rocksdb_file_schema_migration_change());
    assert!(durable_completion_external_publication_audit_completion_no_external_publication());
    assert!(durable_completion_external_publication_audit_completion_no_real_audit_ledger());
    assert!(durable_completion_external_publication_audit_completion_pipeline_success_required());
    assert!(durable_completion_external_publication_audit_completion_sink_receipt_required());
    assert!(durable_completion_external_publication_audit_completion_completion_report_required());
    assert!(durable_completion_external_publication_audit_completion_finalization_projection_required());
    assert!(durable_completion_external_publication_audit_completion_attestation_required());
    assert!(durable_completion_external_publication_audit_completion_backend_submission_required());
    assert!(durable_completion_external_publication_audit_completion_receipt_required());
    assert!(durable_completion_external_publication_audit_completion_record_required_before_reported());
    assert!(durable_completion_external_publication_audit_completion_failed_record_never_records());
    assert!(durable_completion_external_publication_audit_completion_rollback_never_records());
    assert!(durable_completion_external_publication_audit_completion_ambiguous_window_fails_closed());
    assert!(
        durable_completion_external_publication_audit_completion_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet
        )
    );
    assert!(
        !durable_completion_external_publication_audit_completion_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet
        )
    );
    assert!(durable_completion_external_publication_audit_completion_production_mainnet_unavailable());
    assert!(durable_completion_external_publication_audit_completion_external_unavailable());
    assert!(durable_completion_external_publication_audit_completion_validator_set_rotation_unsupported());
    assert!(durable_completion_external_publication_audit_completion_policy_change_unsupported());
    assert!(
        durable_completion_external_publication_audit_completion_local_operator_cannot_satisfy_mainnet_authority()
    );
    assert!(
        durable_completion_external_publication_audit_completion_peer_majority_cannot_satisfy_mainnet_authority()
    );
}
fn release_symbol_reachability_probe() {
    let c = devnet_ctx();
    let input: DurableCompletionExternalPublicationAuditCompletionInput = c.recorded();

    let intent =
        project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request(
            &input.external_publication_audit_finalization_binding,
        );
    assert!(intent.creates_request());
    assert!(matches!(
        intent,
        DurableCompletionExternalPublicationAuditCompletionRequestIntent::CreateRequest
    ));

    let mut ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    let mut sink = FixtureDurableCompletionExternalPublicationAuditCompletionSink::new();
    let outcome = evaluate_durable_completion_external_publication_audit_completion(
        &input,
        &c.expectations,
        &mut sink,
        &mut ledger,
    );
    assert_eq!(
        outcome,
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalPublicationAuditCompletionRecorded
    );
    assert!(external_publication_audit_completion_outcome_authorizes_record(&outcome));
    assert!(external_publication_audit_completion_outcome_projects_to_recorded(&outcome));
    assert!(outcome.authorizes_record());
    assert!(outcome.projects_to_recorded());
    assert!(!outcome.no_commitment());
    assert_eq!(
        outcome.tag(),
        "external-publication-audit-completion-recorded"
    );
    assert_eq!(
        sink.kind(),
        DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory
    );
    assert_eq!(sink.invocations(), 1);

    let identity_digest: DurableCompletionExternalPublicationAuditCompletionDigest =
        external_publication_audit_completion_identity_digest(&c.request.identity);
    let request_digest: DurableCompletionExternalPublicationAuditCompletionDigest =
        external_publication_audit_completion_request_digest(&c.request);
    let response = DurableCompletionExternalPublicationAuditCompletionResponse {
        external_publication_audit_completion_record_id: c
            .request
            .external_publication_audit_completion_record_id
            .clone(),
        request_digest: request_digest.clone(),
        accepted: true,
        external_publication_audit_completion_kind:
            DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory,
    };
    assert!(response.is_well_formed());
    let response_digest: DurableCompletionExternalPublicationAuditCompletionDigest =
        external_publication_audit_completion_response_digest(&response);
    let record: DurableCompletionExternalPublicationAuditCompletionRecord = c.request.to_record();
    let record_digest: DurableCompletionExternalPublicationAuditCompletionDigest =
        external_publication_audit_completion_record_digest(&record);
    let transcript_digest: DurableCompletionExternalPublicationAuditCompletionTranscriptDigest =
        external_publication_audit_completion_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );
    assert!(!identity_digest.as_hex().is_empty());
    assert!(!transcript_digest.as_hex().is_empty());

    let ledger_record: &DurableCompletionExternalPublicationAuditCompletionLedgerRecord = ledger
        .find(AUDIT_FINALIZATION_RECORD_ID)
        .expect("external-publication-audit-completion ledger record");
    assert_eq!(
        ledger_record.status,
        DurableCompletionExternalPublicationAuditCompletionLedgerStatus::Recorded
    );
    let snapshot: DurableCompletionExternalPublicationAuditCompletionLedgerSnapshot =
        ledger.snapshot();
    assert_eq!(snapshot.len(), 1);

    let _surface: DurableCompletionExternalPublicationAuditCompletionSurface = input.surface();
    let _environment: DurableCompletionExternalPublicationAuditCompletionEnvironment =
        input.environment_binding.clone();
    let _binding: DurableCompletionExternalPublicationAuditCompletionBinding =
        input.runtime_binding.clone();

    assert!(DurableCompletionExternalPublicationAuditCompletionPolicy::Disabled.is_disabled());
    assert!(
        DurableCompletionExternalPublicationAuditCompletionPolicy::FixtureAllowed.allows_fixture()
    );
    assert_eq!(
        DurableCompletionExternalPublicationAuditCompletionPolicy::ProductionExternalPublicationAuditCompletionRequired.tag(),
        "production-external-publication-audit-completion-required"
    );
    assert!(DurableCompletionExternalPublicationAuditCompletionKind::FixtureInMemory.is_fixture());
    assert!(DurableCompletionExternalPublicationAuditCompletionKind::ProductionExternalPublicationAuditCompletionUnavailable.is_unavailable());
    assert_eq!(
        DurableCompletionExternalPublicationAuditCompletionKind::Disabled.tag(),
        "disabled"
    );
    let no_finalization =
        DurableCompletionExternalPublicationAuditCompletionOutcome::LegacyBypassNoExternalPublicationAuditCompletion;
    assert!(no_finalization.is_legacy_bypass());
    assert!(no_finalization.no_commitment());
    assert!(
        DurableCompletionExternalPublicationAuditCompletionOutcome::MainNetPeerDrivenApplyRefusedNoAuditCompletion
            .is_mainnet_peer_driven_apply_refused()
    );

    // Invariant helpers — fail-closed contract asserted by the release helper.
    assert!(durable_completion_external_publication_audit_completion_consumer_required());
    assert!(durable_completion_external_publication_audit_completion_confirmation_required());
    assert!(durable_completion_external_publication_audit_completion_no_real_settlement());
    assert!(durable_completion_external_publication_audit_completion_no_real_settlement_finality());
    assert!(durable_completion_external_publication_audit_completion_no_real_settlement_receipt());
    assert!(
        durable_completion_external_publication_audit_completion_no_real_settlement_finality_projection()
    );
    assert!(
        durable_completion_external_publication_audit_completion_no_real_external_publication_audit_finalization()
    );
    assert!(durable_completion_external_publication_audit_completion_no_real_external_publication_audit_completion());

    let mut prod = ProductionExternalPublicationAuditCompletionSink::default();
    let mut mainnet = MainNetExternalPublicationAuditCompletionSink::default();
    let mut external = ExternalExternalPublicationAuditCompletionSink::default();
    let mut prod_ledger = DurableCompletionExternalPublicationAuditCompletionLedger::new();
    assert_eq!(
        prod.project_durable_completion_external_publication_audit_completion(
            &c.request,
            &c.expectations,
            false,
            &mut prod_ledger,
        ),
        DurableCompletionExternalPublicationAuditCompletionOutcome::ProductionExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    assert_eq!(
        mainnet.project_durable_completion_external_publication_audit_completion(
            &c.request,
            &c.expectations,
            false,
            &mut prod_ledger,
        ),
        DurableCompletionExternalPublicationAuditCompletionOutcome::MainNetExternalPublicationAuditCompletionUnavailableNoAuditCompletion
    );
    assert_eq!(
        external.project_durable_completion_external_publication_audit_completion(
            &c.request,
            &c.expectations,
            false,
            &mut prod_ledger,
        ),
        DurableCompletionExternalPublicationAuditCompletionOutcome::ExternalExternalPublicationAuditCompletionUnavailableNoAuditCompletion
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
        PathBuf::from("docs/devnet/run_285_durable_completion_external_publication_audit_completion_release_binary/helper_evidence/run_285")
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
        ("accepted_compatible", "run268_duplicate_idempotent_confirmation_only_matches_existing_never_creates", run268_duplicate_idempotent_confirmation_only_matches_existing_never_creates as fn()),
        ("accepted_compatible", "production_audit_ledger_path_reachable_but_unavailable_records_nothing", production_audit_ledger_path_reachable_but_unavailable_records_nothing as fn()),
        ("accepted_compatible", "mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing", mainnet_audit_ledger_path_reachable_but_unavailable_records_nothing as fn()),
        ("accepted_compatible", "external_publication_path_reachable_but_unavailable_records_nothing", external_publication_path_reachable_but_unavailable_records_nothing as fn()),
        ("accepted_compatible", "mainnet_peer_driven_apply_refused_before_receipt_sink_invocation", mainnet_peer_driven_apply_refused_before_receipt_sink_invocation as fn()),
        ("accepted_compatible", "validator_set_rotation_and_policy_change_unsupported", validator_set_rotation_and_policy_change_unsupported as fn()),
        ("accepted_compatible", "mainnet_peer_driven_refusal_precedes_recovery_classification", mainnet_peer_driven_refusal_precedes_recovery_classification as fn()),
        ("rejection_fail_closed", "non_recording_confirmation_outcomes_never_record_external_publication_audit_completion", non_recording_confirmation_outcomes_never_record_external_publication_audit_completion as fn()),
        ("rejection_fail_closed", "wrong_environment_rejected_before_sink_invocation", wrong_environment_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_chain_rejected_before_sink_invocation", wrong_chain_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_genesis_rejected_before_sink_invocation", wrong_genesis_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_governance_surface_rejected_before_sink_invocation", wrong_governance_surface_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_mutation_surface_rejected_before_sink_invocation", wrong_mutation_surface_rejected_before_sink_invocation as fn()),
        ("rejection_fail_closed", "wrong_external_publication_audit_completion_record_id_rejected_before_record", wrong_external_publication_audit_completion_record_id_rejected_before_record as fn()),
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
        ("rejection_fail_closed", "non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request", non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request as fn()),
        ("recovery_crash_window", "devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission", devnet_fixture_chain_records_exactly_one_receipt_only_after_backend_submission as fn()),
        ("recovery_crash_window", "governance_action_variants_record_only_after_backend_submission", governance_action_variants_record_only_after_backend_submission as fn()),
        ("recovery_crash_window", "pre_external_publication_audit_finalization_windows_fail_closed_no_commitment", pre_external_publication_audit_finalization_windows_fail_closed_no_commitment as fn()),
        ("recovery_crash_window", "after_external_publication_audit_finalization_request_before_record_rejects_before_record", after_external_publication_audit_finalization_request_before_record_rejects_before_record as fn()),
        ("recovery_crash_window", "after_external_publication_audit_finalization_record_before_success_requires_explicit_matching_record", after_external_publication_audit_finalization_record_before_success_requires_explicit_matching_record as fn()),
        ("recovery_crash_window", "after_external_publication_audit_finalization_success_recovers_as_recorded", after_external_publication_audit_finalization_success_recovers_as_recorded as fn()),
        ("recovery_crash_window", "ambiguous_record_failed_rollback_and_unknown_windows_fail_closed", ambiguous_record_failed_rollback_and_unknown_windows_fail_closed as fn()),
        ("recovery_crash_window", "production_mainnet_external_recovery_classification_unavailable", production_mainnet_external_recovery_classification_unavailable as fn()),
        ("recovery_crash_window", "mainnet_peer_driven_refusal_precedes_recovery_classification", mainnet_peer_driven_refusal_precedes_recovery_classification as fn()),
        ("projection", "only_recorded_confirmation_outcome_creates_external_publication_audit_completion_request_intent", only_recorded_confirmation_outcome_creates_external_publication_audit_completion_request_intent as fn()),
        ("projection", "non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request", non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request as fn()),
        ("projection", "run268_duplicate_idempotent_confirmation_only_matches_existing_never_creates", run268_duplicate_idempotent_confirmation_only_matches_existing_never_creates as fn()),
        ("external_publication_audit_completion_ledger", "duplicate_identical_receipt_is_idempotent", duplicate_identical_receipt_is_idempotent as fn()),
        ("external_publication_audit_completion_ledger", "same_ack_record_id_different_digest_is_equivocation_no_second_receipt", same_ack_record_id_different_digest_is_equivocation_no_second_receipt as fn()),
        ("external_publication_audit_completion_ledger", "rollback_restores_receipt_ledger_snapshot", rollback_restores_receipt_ledger_snapshot as fn()),
        ("non_mutation", "disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation", disabled_receipt_policy_preserves_legacy_bypass_no_record_no_invocation as fn()),
        ("non_mutation", "disabled_backend_policy_never_invokes_receipt_sink", disabled_backend_policy_never_invokes_receipt_sink as fn()),
        ("non_mutation", "non_recording_confirmation_outcomes_never_record_external_publication_audit_completion", non_recording_confirmation_outcomes_never_record_external_publication_audit_completion as fn()),
        ("non_mutation", "non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request", non_recording_confirmation_outcomes_create_no_external_publication_audit_completion_request as fn()),
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
    let mut tables = BTreeMap::<String, (usize, usize)>::new();
    for (table, _name, ok) in &rows {
        let entry = tables.entry(table.clone()).or_insert((0, 0));
        if *ok {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    let total_pass: usize = rows.iter().filter(|(_, _, ok)| *ok).count();
    let total_fail = rows.len() - total_pass;
    let mut summary = String::new();
    summary.push_str(
        "Run 285 durable-completion external-publication-audit-completion release helper\n",
    );
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str("projection_rule: input.external_publication_audit_finalization_binding -> project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request\n");
    summary.push_str("attached_chain: Run256 backend -> Run258 receipt -> Run260 acknowledgement -> Run262 consumer -> Run264 settlement projection -> Run266 settlement commitment -> Run268 settlement finalization -> Run270 settlement-receipt acknowledgement -> Run272 settlement-outcome report -> Run274 settlement-outcome publication -> Run276 external-publication confirmation -> Run278 external-publication receipt -> Run280 external-publication acknowledgement -> Run282 external-publication audit finalization -> Run284 external-publication audit completion\n");
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));
    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");
    fs::write(
        outdir.join("fixtures/run_285_projection_rule.txt"),
        "input.external_publication_audit_finalization_binding\nproject_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request\nExternalPublicationAuditFinalizationRecorded -> CreateRequest\n",
    ).expect("write projection fixture");
    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}