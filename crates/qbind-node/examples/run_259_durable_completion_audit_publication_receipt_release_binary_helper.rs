//! Run 259 — release-built helper for the Run 258 durable-completion backend
//! audit-ledger / external-publication receipt boundary.
//!
//! This helper is an example-only release evidence harness. It is never wired into
//! the production binary. It exercises the real Run 258 production library symbols
//! and mutates only the modeled in-memory `DurableCompletionAuditPublicationReceiptLedger`
//! through the DevNet/TestNet fixture sink. No real audit ledger, external
//! publication, MainNet governance, MainNet peer-driven apply, Run 070 call,
//! `LivePqcTrustState` mutation, marker/sequence write, trust swap, session
//! eviction, RocksDB/file/schema/migration/storage-format, or wire-format change is
//! enabled.

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
    DurableCompletionAuditPublicationReceiptAttestationBinding,
    DurableCompletionAuditPublicationReceiptBackendBinding,
    DurableCompletionAuditPublicationReceiptBinding,
    DurableCompletionAuditPublicationReceiptDigest,
    DurableCompletionAuditPublicationReceiptEnvironment,
    DurableCompletionAuditPublicationReceiptExpectations,
    DurableCompletionAuditPublicationReceiptFault,
    DurableCompletionAuditPublicationReceiptFinalizationBinding,
    DurableCompletionAuditPublicationReceiptIdentity,
    DurableCompletionAuditPublicationReceiptInput, DurableCompletionAuditPublicationReceiptKind,
    DurableCompletionAuditPublicationReceiptLedger,
    DurableCompletionAuditPublicationReceiptLedgerRecord,
    DurableCompletionAuditPublicationReceiptLedgerStatus,
    DurableCompletionAuditPublicationReceiptOutcome,
    DurableCompletionAuditPublicationReceiptPipelineBinding,
    DurableCompletionAuditPublicationReceiptPolicy, DurableCompletionAuditPublicationReceiptRecord,
    DurableCompletionAuditPublicationReceiptReplayBinding,
    DurableCompletionAuditPublicationReceiptReporterBinding,
    DurableCompletionAuditPublicationReceiptRequest,
    DurableCompletionAuditPublicationReceiptRequestIntent,
    DurableCompletionAuditPublicationReceiptResponse,
    DurableCompletionAuditPublicationReceiptSinkBinding,
    DurableCompletionAuditPublicationReceiptSurface,
    DurableCompletionAuditPublicationReceiptTranscriptDigest,
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

const RECEIPT_RECORD_ID: &str = "durable-completion-audit-publication-receipt-0001";
const RECEIPT_ID: &str = "fixture-receipt-0001";
const RECEIPT_DOMAIN_TAG: &str = "QBIND:run258:domain-separation:v1";
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

fn attach_run256_backend(
    environment: TrustBundleEnvironment,
    action: &ActionLabel,
    duplicate: bool,
) -> AttachedBackend {
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
        "Run 256 backend submission must record for Run 259 receipt evidence"
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
        .expect("recorded Run 256 backend submission");
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

fn mainnet_peer_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
    )
}

fn fixture_sink() -> FixtureDurableCompletionAuditPublicationReceiptSink {
    FixtureDurableCompletionAuditPublicationReceiptSink::new()
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
        o: &DurableCompletionAuditPublicationReceiptOutcome,
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

fn drive<S: GovernanceDurableCompletionAuditPublicationReceiptSink>(
    input: &DurableCompletionAuditPublicationReceiptInput,
    expectations: &DurableCompletionAuditPublicationReceiptExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
) -> DurableCompletionAuditPublicationReceiptOutcome {
    evaluate_durable_completion_audit_publication_receipt(input, expectations, sink, ledger)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("accepted");
    {
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
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "A1.receipt-policy-disabled",
            "legacy-bypass-no-audit-receipt",
            &o,
        );
        t.assert_true("A1.no-invocation", sink.invocations() == 0);
        t.assert_true("A1.ledger-empty", ledger.is_empty());
    }
    for (id, backend) in [
        ("A2.backend-policy-disabled", DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission),
        ("A3.attestor-disabled", DurableCompletionAttestationBackendOutcome::AttestationDidNotAttestNoBackendSubmission),
        ("A4.finalizer-disabled", DurableCompletionAttestationBackendOutcome::AttestationDidNotAttestNoBackendSubmission),
        ("A5.reporter-disabled", DurableCompletionAttestationBackendOutcome::AttestationDidNotAttestNoBackendSubmission),
        ("A6.sink-disabled", DurableCompletionAttestationBackendOutcome::RejectedBeforeAttestationNoBackendSubmission),
        ("A7.pipeline-disabled", DurableCompletionAttestationBackendOutcome::RejectedBeforeAttestationNoBackendSubmission),
        ("A8.evaluator-disabled", DurableCompletionAttestationBackendOutcome::RejectedBeforeAttestationNoBackendSubmission),
    ] {
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
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        let expected = if matches!(input.backend_binding, DurableCompletionAttestationBackendOutcome::LegacyBypassNoBackendSubmission) {
            "legacy-bypass-no-audit-receipt"
        } else if matches!(input.backend_binding, DurableCompletionAttestationBackendOutcome::RejectedBeforeAttestationNoBackendSubmission) {
            "rejected-before-backend-submission-no-audit-receipt"
        } else {
            "backend-did-not-submit-no-audit-receipt"
        };
        t.check_outcome(&format!("{id}.outcome"), expected, &o);
        t.assert_true(&format!("{id}.no-sink"), sink.invocations() == 0);
        t.assert_true(&format!("{id}.no-receipt"), ledger.is_empty());
    }
    for (id, c) in [("A9.devnet", devnet_ctx()), ("A10.testnet", testnet_ctx())] {
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), "audit-receipt-recorded", &o);
        t.assert_true(
            &format!("{id}.authorizes"),
            audit_receipt_outcome_authorizes_receipt_record(&o),
        );
        t.assert_true(
            &format!("{id}.projects"),
            audit_receipt_outcome_projects_to_audit_receipt_recorded(&o),
        );
        t.assert_true(
            &format!("{id}.ledger-one"),
            ledger.len() == 1 && ledger.contains(&c.request.receipt_record_id),
        );
        t.assert_true(&format!("{id}.sink-once"), sink.invocations() == 1);
    }
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
            DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
            DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
            &label,
            false,
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            &format!("A11.{action}.outcome"),
            "audit-receipt-recorded",
            &o,
        );
        t.assert_true(
            &format!("A11.{action}.ledger-one"),
            ledger.len() == 1 && ledger.contains(&label.receipt_record_id),
        );
    }
    {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let first = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        let second = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A12.first", "audit-receipt-recorded", &first);
        t.check_outcome(
            "A12.duplicate",
            "audit-receipt-duplicate-idempotent",
            &second,
        );
        t.assert_true("A12.ledger-one", ledger.len() == 1);
        t.assert_true(
            "A12.duplicate-no-new-authorize",
            !audit_receipt_outcome_authorizes_receipt_record(&second),
        );
    }
    {
        let dup_ctx = ctx_action(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
            DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
            &default_action(),
            true,
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let o = drive(
            &dup_ctx.recorded(),
            &dup_ctx.expectations,
            &mut sink,
            &mut ledger,
        );
        t.check_outcome(
            "A13.backend-duplicate-empty",
            "audit-receipt-rejected-before-record",
            &o,
        );
        t.assert_true("A13.empty", ledger.is_empty());
        let rec_ctx = devnet_ctx();
        let _ = drive(
            &rec_ctx.recorded(),
            &rec_ctx.expectations,
            &mut sink,
            &mut ledger,
        );
        let matched = drive(
            &dup_ctx.recorded(),
            &dup_ctx.expectations,
            &mut sink,
            &mut ledger,
        );
        t.check_outcome(
            "A13.backend-duplicate-matches",
            "audit-receipt-duplicate-idempotent",
            &matched,
        );
        t.assert_true("A13.ledger-one", ledger.len() == 1);
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditPublicationReceiptPolicy::ProductionAuditLedgerRequired,
            DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable,
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut prod = ProductionAuditLedgerDurableCompletionReceiptSink::default();
        let o = drive(&c.recorded(), &c.expectations, &mut prod, &mut ledger);
        t.check_outcome(
            "A14.production",
            "production-audit-ledger-unavailable-no-receipt",
            &o,
        );
        t.assert_true("A14.no-record", ledger.is_empty());
        t.check(
            "A14.kind",
            "production-audit-ledger-unavailable",
            prod.kind().tag(),
        );
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
            DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut mn = MainNetAuditLedgerDurableCompletionReceiptSink::default();
        let o = drive(&c.recorded(), &c.expectations, &mut mn, &mut ledger);
        t.check_outcome(
            "A15.mainnet",
            "mainnet-audit-ledger-unavailable-no-receipt",
            &o,
        );
        t.assert_true("A15.no-record", ledger.is_empty());
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditPublicationReceiptPolicy::ExternalPublicationRequired,
            DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable,
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut ext = ExternalPublicationDurableCompletionReceiptSink::default();
        let o = drive(&c.recorded(), &c.expectations, &mut ext, &mut ledger);
        t.check_outcome(
            "A16.external",
            "external-publication-unavailable-no-receipt",
            &o,
        );
        t.assert_true("A16.no-record", ledger.is_empty());
    }
    {
        let c = mainnet_peer_ctx();
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
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "A17.mainnet-peer",
            "mainnet-peer-driven-apply-refused-no-receipt",
            &o,
        );
        t.assert_true(
            "A17.no-invocation",
            sink.invocations() == 0 && ledger.is_empty(),
        );
    }
    for (id, backend, tag) in [
        (
            "A18.validator",
            DurableCompletionAttestationBackendOutcome::ValidatorSetRotationUnsupportedNoSubmission,
            "validator-set-rotation-unsupported-no-receipt",
        ),
        (
            "A19.policy",
            DurableCompletionAttestationBackendOutcome::PolicyChangeUnsupportedNoSubmission,
            "policy-change-unsupported-no-receipt",
        ),
    ] {
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
    use DurableCompletionAttestationBackendOutcome as Backend;
    let backend_cases: [(&str, Backend, &str); 14] = [
        (
            "legacy",
            Backend::LegacyBypassNoBackendSubmission,
            "legacy-bypass-no-audit-receipt",
        ),
        (
            "rejected-before-attestation",
            Backend::RejectedBeforeAttestationNoBackendSubmission,
            "rejected-before-backend-submission-no-audit-receipt",
        ),
        (
            "attestation-did-not-attest",
            Backend::AttestationDidNotAttestNoBackendSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "backend-rejected",
            Backend::BackendSubmissionRejectedBeforeRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "record-failed",
            Backend::BackendSubmissionRecordFailedNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "rolled-back",
            Backend::BackendSubmissionRolledBackNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "rollback-failed",
            Backend::BackendSubmissionRollbackFailedFatalNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "ambiguous",
            Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "production-backend",
            Backend::ProductionBackendUnavailableNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "mainnet-backend",
            Backend::MainNetBackendUnavailableNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "external-backend",
            Backend::ExternalPublicationUnavailableNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "mainnet-peer",
            Backend::MainNetPeerDrivenApplyRefusedNoSubmission,
            "mainnet-peer-driven-apply-refused-no-receipt",
        ),
        (
            "validator",
            Backend::ValidatorSetRotationUnsupportedNoSubmission,
            "validator-set-rotation-unsupported-no-receipt",
        ),
        (
            "policy",
            Backend::PolicyChangeUnsupportedNoSubmission,
            "policy-change-unsupported-no-receipt",
        ),
    ];
    for (label, backend, tag) in backend_cases {
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
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("B.backend.{label}"), tag, &o);
        t.assert_true(
            &format!("B.backend.{label}.no-invocation"),
            sink.invocations() == 0,
        );
        t.assert_true(&format!("B.backend.{label}.no-record"), ledger.is_empty());
    }
    for (label, mutate) in [
        (
            "wrong-environment",
            (|c: &mut Ctx| c.expectations.expected_environment = TrustBundleEnvironment::Testnet)
                as fn(&mut Ctx),
        ),
        (
            "wrong-chain",
            (|c: &mut Ctx| c.expectations.expected_chain_id = "qbind-other".to_string())
                as fn(&mut Ctx),
        ),
        (
            "wrong-genesis",
            (|c: &mut Ctx| c.expectations.expected_genesis_hash = "genesis-other".to_string())
                as fn(&mut Ctx),
        ),
        (
            "wrong-governance-surface",
            (|c: &mut Ctx| {
                c.expectations.expected_governance_surface =
                    GovernanceExecutionRuntimeSurface::ReloadCheck
            }) as fn(&mut Ctx),
        ),
        (
            "wrong-validation-surface",
            (|c: &mut Ctx| {
                c.expectations.expected_validation_surface =
                    GovernanceExecutionRuntimeSurface::ReloadCheck
            }) as fn(&mut Ctx),
        ),
        (
            "wrong-mutation-surface",
            (|c: &mut Ctx| {
                c.expectations.expected_mutation_surface =
                    GovernanceExecutionRuntimeSurface::ReloadCheck
            }) as fn(&mut Ctx),
        ),
    ] {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            &format!("B.binding.{label}"),
            "rejected-before-backend-submission-no-audit-receipt",
            &o,
        );
        t.assert_true(
            &format!("B.binding.{label}.no-invocation"),
            sink.invocations() == 0 && ledger.is_empty(),
        );
    }
    let request_cases: [(
        &str,
        fn(&mut DurableCompletionAuditPublicationReceiptRequest),
    ); 26] = [
        ("wrong-receipt-record-id", |r| {
            r.receipt_record_id = "other".to_string()
        }),
        ("wrong-environment", |r| {
            r.environment = TrustBundleEnvironment::Testnet
        }),
        ("wrong-chain", |r| r.chain_id = "wrong".to_string()),
        ("wrong-genesis", |r| r.genesis_hash = "wrong".to_string()),
        ("wrong-governance-surface", |r| {
            r.governance_surface = GovernanceExecutionRuntimeSurface::ReloadCheck
        }),
        ("wrong-validation-surface", |r| {
            r.validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck
        }),
        ("wrong-mutation-surface", |r| {
            r.mutation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck
        }),
        ("wrong-proposal", |r| r.proposal_id = "wrong".to_string()),
        ("wrong-decision", |r| r.decision_id = "wrong".to_string()),
        ("wrong-candidate", |r| {
            r.candidate_digest = "wrong".to_string()
        }),
        ("wrong-sequence", |r| r.authority_domain_sequence = 99),
        ("wrong-pipeline", |r| {
            r.pipeline_decision_digest = "wrong".to_string()
        }),
        ("wrong-sink", |r| {
            r.sink_decision_digest = "wrong".to_string()
        }),
        ("wrong-reporter", |r| {
            r.reporter_decision_digest = "wrong".to_string()
        }),
        ("wrong-finalization", |r| {
            r.finalization_decision_digest = "wrong".to_string()
        }),
        ("wrong-attestation-digest", |r| {
            r.attestation_digest = "wrong".to_string()
        }),
        ("wrong-attestation-id", |r| {
            r.attestation_id = "wrong".to_string()
        }),
        ("wrong-backend-identity", |r| {
            r.backend_identity_digest = "wrong".to_string()
        }),
        ("wrong-backend-request", |r| {
            r.backend_request_digest = "wrong".to_string()
        }),
        ("wrong-backend-response", |r| {
            r.backend_response_digest = "wrong".to_string()
        }),
        ("wrong-backend-receipt", |r| {
            r.backend_receipt_digest = "wrong".to_string()
        }),
        ("wrong-backend-transcript", |r| {
            r.backend_transcript_digest = "wrong".to_string()
        }),
        ("wrong-backend-record-id", |r| {
            r.backend_record_id = "wrong".to_string()
        }),
        ("wrong-receipt-identity", |r| {
            r.identity.receipt_id = "wrong".to_string()
        }),
        ("wrong-domain", |r| {
            r.domain_separation_tag = "wrong".to_string()
        }),
        ("malformed", |r| r.proposal_id = String::new()),
    ];
    for (label, mutate) in request_cases {
        let c = devnet_ctx();
        let mut input = c.recorded();
        mutate(&mut input.request);
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            &format!("B.request.{label}"),
            "audit-receipt-rejected-before-record",
            &o,
        );
        t.assert_true(
            &format!("B.request.{label}.invoked-no-record"),
            sink.invocations() == 1 && ledger.is_empty(),
        );
    }
    for (label, fault, tag) in [
        (
            "record-failed",
            DurableCompletionAuditPublicationReceiptFault::RecordFailedNoReceipt,
            "audit-receipt-record-failed-no-receipt",
        ),
        (
            "rolled-back",
            DurableCompletionAuditPublicationReceiptFault::RolledBackNoReceipt,
            "audit-receipt-rolled-back-no-receipt",
        ),
        (
            "rollback-failed",
            DurableCompletionAuditPublicationReceiptFault::RollbackFailedFatal,
            "audit-receipt-rollback-failed-fatal-no-receipt",
        ),
        (
            "ambiguous",
            DurableCompletionAuditPublicationReceiptFault::AmbiguousAfterRecord,
            "audit-receipt-ambiguous-fail-closed-no-receipt",
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = FixtureDurableCompletionAuditPublicationReceiptSink::with_fault(fault);
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("B.fault.{label}"), tag, &o);
        t.assert_true(
            &format!("B.fault.{label}.invoked-empty"),
            sink.invocations() == 1 && ledger.is_empty(),
        );
    }
    {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let _ = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        let mut c2 = devnet_ctx();
        c2.request.candidate_digest = "equivocating-candidate-digest".to_string();
        c2.expectations.expected_candidate_digest = "equivocating-candidate-digest".to_string();
        let o = drive(&c2.recorded(), &c2.expectations, &mut sink, &mut ledger);
        t.check_outcome("B.equivocation", "audit-receipt-rejected-before-record", &o);
        t.assert_true("B.equivocation-ledger-one", ledger.len() == 1);
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
            DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        );
        let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut sink = fixture_sink();
        let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "B.fixture-mainnet-rejected",
            "audit-receipt-rejected-before-record",
            &o,
        );
        t.assert_true(
            "B.fixture-mainnet-no-record",
            sink.invocations() == 1 && ledger.is_empty(),
        );
    }
    t.assert_true(
        "B.local-operator-cannot",
        durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "B.peer-majority-cannot",
        durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    t.finish(out)
}

fn recovered_ledger() -> DurableCompletionAuditPublicationReceiptLedger {
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let _ = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    ledger
}

fn recover_devnet(
    window: DurableCompletionAuditPublicationReceiptWindow,
    with_record: bool,
) -> DurableCompletionAuditPublicationReceiptOutcome {
    let c = devnet_ctx();
    let input = c.recorded();
    let ledger = recovered_ledger();
    let record = if with_record {
        ledger.find(RECEIPT_RECORD_ID)
    } else {
        None
    };
    recover_durable_completion_audit_publication_receipt_window(
        &input,
        window,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        record,
        &c.expectations,
    )
}

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAuditPublicationReceiptWindow as W;
    let mut t = Table::new("recovery");
    for (id, w, tag) in [
        (
            "C.before-pipeline",
            W::BeforePipeline,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-pipeline-before-sink-intent",
            W::AfterPipelineSuccessBeforeSinkIntent,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-sink-intent-before-sink-receipt-record",
            W::AfterSinkIntentBeforeSinkReceiptRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-sink-receipt-record-before-report-intent",
            W::AfterSinkReceiptRecordBeforeReportIntent,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-report-intent-before-report-record",
            W::AfterReportIntentBeforeReportRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-report-record-before-finalization-intent",
            W::AfterReportRecordBeforeFinalizationIntent,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-finalization-intent-before-record",
            W::AfterFinalizationIntentBeforeFinalizationRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-finalization-record-before-attestation-intent",
            W::AfterFinalizationRecordBeforeAttestationIntent,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-attestation-intent-before-record",
            W::AfterAttestationIntentBeforeAttestationRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-attestation-record-before-backend-request",
            W::AfterAttestationRecordBeforeBackendRequest,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-backend-request-before-record",
            W::AfterBackendRequestBeforeBackendRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-backend-record-before-success",
            W::AfterBackendRecordBeforeBackendSuccess,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "C.after-backend-success-before-receipt-request",
            W::AfterBackendSuccessBeforeReceiptRequest,
            "audit-receipt-rejected-before-record",
        ),
        (
            "C.after-receipt-request-before-receipt-record",
            W::AfterReceiptRequestBeforeReceiptRecord,
            "audit-receipt-rejected-before-record",
        ),
        (
            "C.after-receipt-ambiguous",
            W::AfterReceiptAmbiguous,
            "audit-receipt-ambiguous-fail-closed-no-receipt",
        ),
        (
            "C.record-failed",
            W::ReceiptRecordFailed,
            "audit-receipt-record-failed-no-receipt",
        ),
        (
            "C.rollback",
            W::ReceiptRollbackCompleted,
            "audit-receipt-rolled-back-no-receipt",
        ),
        (
            "C.rollback-failed",
            W::ReceiptRollbackFailed,
            "audit-receipt-rollback-failed-fatal-no-receipt",
        ),
        (
            "C.unknown",
            W::Unknown,
            "audit-receipt-ambiguous-fail-closed-no-receipt",
        ),
    ] {
        t.check_outcome(id, tag, &recover_devnet(w, false));
    }
    t.check_outcome(
        "C.after-receipt-record-before-success-no-record",
        "audit-receipt-rejected-before-record",
        &recover_devnet(W::AfterReceiptRecordBeforeReceiptSuccess, false),
    );
    t.check_outcome(
        "C.after-receipt-record-before-success-with-record",
        "audit-receipt-recorded",
        &recover_devnet(W::AfterReceiptRecordBeforeReceiptSuccess, true),
    );
    t.check_outcome(
        "C.after-receipt-success",
        "audit-receipt-recorded",
        &recover_devnet(W::AfterReceiptSuccess, true),
    );
    t.check_outcome(
        "C.after-receipt-success-no-record",
        "audit-receipt-rejected-before-record",
        &recover_devnet(W::AfterReceiptSuccess, false),
    );
    let c = devnet_ctx();
    let input = c.recorded();
    for (id, kind, tag) in [
        (
            "C.production",
            DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable,
            "production-audit-ledger-unavailable-no-receipt",
        ),
        (
            "C.mainnet",
            DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
            "mainnet-audit-ledger-unavailable-no-receipt",
        ),
        (
            "C.external",
            DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable,
            "external-publication-unavailable-no-receipt",
        ),
    ] {
        let o = recover_durable_completion_audit_publication_receipt_window(
            &input,
            W::AfterReceiptSuccess,
            kind,
            None,
            &c.expectations,
        );
        t.check_outcome(id, tag, &o);
    }
    let cp = mainnet_peer_ctx();
    let peer_input = cp.input(
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let peer = recover_durable_completion_audit_publication_receipt_window(
        &peer_input,
        W::AfterReceiptSuccess,
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable,
        None,
        &cp.expectations,
    );
    t.check_outcome(
        "C.mainnet-peer-precedes",
        "mainnet-peer-driven-apply-refused-no-receipt",
        &peer,
    );
    t.finish(out)
}

fn run_projection_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAuditPublicationReceiptRequestIntent as Intent;
    let mut t = Table::new("projection");
    let intent = project_backend_submission_outcome_to_audit_receipt_request(
        &Backend::BackendSubmissionRecorded,
    );
    t.assert_true("D.only-backend-recorded-creates", intent.creates_request());
    t.assert_true(
        "D.pipeline-alone-no-create",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::RejectedBeforeAttestationNoBackendSubmission,
        )
        .creates_request(),
    );
    t.assert_true(
        "D.sink-alone-no-create",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::AttestationDidNotAttestNoBackendSubmission,
        )
        .creates_request(),
    );
    t.assert_true(
        "D.reporter-alone-no-create",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::BackendSubmissionRejectedBeforeRecord,
        )
        .creates_request(),
    );
    t.assert_true(
        "D.finalization-alone-no-create",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::BackendSubmissionRecordFailedNoSubmission,
        )
        .creates_request(),
    );
    t.assert_true(
        "D.attestation-alone-no-create",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::BackendSubmissionRolledBackNoSubmission,
        )
        .creates_request(),
    );
    t.assert_true(
        "D.backend-request-alone-no-create",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
        )
        .creates_request(),
    );
    let dup = project_backend_submission_outcome_to_audit_receipt_request(
        &Backend::BackendSubmissionDuplicateIdempotent,
    );
    t.assert_true(
        "D.duplicate-idempotent-only",
        dup == Intent::IdempotentOnly && !dup.creates_request(),
    );
    for (label, backend, tag) in [
        (
            "legacy",
            Backend::LegacyBypassNoBackendSubmission,
            "legacy-bypass-no-audit-receipt",
        ),
        (
            "rejected-before-attestation",
            Backend::RejectedBeforeAttestationNoBackendSubmission,
            "rejected-before-backend-submission-no-audit-receipt",
        ),
        (
            "attestation-did-not-attest",
            Backend::AttestationDidNotAttestNoBackendSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "backend-rejected",
            Backend::BackendSubmissionRejectedBeforeRecord,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "record-failed",
            Backend::BackendSubmissionRecordFailedNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "rolled-back",
            Backend::BackendSubmissionRolledBackNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "rollback-failed",
            Backend::BackendSubmissionRollbackFailedFatalNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "ambiguous",
            Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "production",
            Backend::ProductionBackendUnavailableNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "mainnet",
            Backend::MainNetBackendUnavailableNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "external",
            Backend::ExternalPublicationUnavailableNoSubmission,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (
            "mainnet-peer",
            Backend::MainNetPeerDrivenApplyRefusedNoSubmission,
            "mainnet-peer-driven-apply-refused-no-receipt",
        ),
        (
            "validator",
            Backend::ValidatorSetRotationUnsupportedNoSubmission,
            "validator-set-rotation-unsupported-no-receipt",
        ),
        (
            "policy",
            Backend::PolicyChangeUnsupportedNoSubmission,
            "policy-change-unsupported-no-receipt",
        ),
    ] {
        match project_backend_submission_outcome_to_audit_receipt_request(&backend) {
            Intent::NoAuditReceipt(o) => t.check(&format!("D.{label}.projection"), tag, o.tag()),
            _ => t.check(&format!("D.{label}.projection"), tag, "unexpected-create"),
        }
    }
    t.assert_true(
        "D.recorded-authorizes",
        audit_receipt_outcome_authorizes_receipt_record(
            &DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded,
        ),
    );
    t.assert_true(
        "D.recorded-projects",
        audit_receipt_outcome_projects_to_audit_receipt_recorded(
            &DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded,
        ),
    );
    t.assert_true(
        "D.duplicate-projects",
        audit_receipt_outcome_projects_to_audit_receipt_recorded(
            &DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent,
        ),
    );
    t.assert_true(
        "D.duplicate-no-authorize",
        !audit_receipt_outcome_authorizes_receipt_record(
            &DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent,
        ),
    );
    for (label, o) in [
        ("legacy", DurableCompletionAuditPublicationReceiptOutcome::LegacyBypassNoAuditReceipt),
        ("rejected", DurableCompletionAuditPublicationReceiptOutcome::RejectedBeforeBackendSubmissionNoAuditReceipt),
        ("backend-did-not", DurableCompletionAuditPublicationReceiptOutcome::BackendDidNotSubmitNoAuditReceipt),
        ("record-failed", DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecordFailedNoReceipt),
        ("rollback", DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRolledBackNoReceipt),
        ("rollback-failed", DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRollbackFailedFatalNoReceipt),
        ("ambiguous", DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptAmbiguousFailClosedNoReceipt),
        ("production", DurableCompletionAuditPublicationReceiptOutcome::ProductionAuditLedgerUnavailableNoReceipt),
        ("mainnet", DurableCompletionAuditPublicationReceiptOutcome::MainNetAuditLedgerUnavailableNoReceipt),
        ("external", DurableCompletionAuditPublicationReceiptOutcome::ExternalPublicationUnavailableNoReceipt),
        ("mainnet-peer", DurableCompletionAuditPublicationReceiptOutcome::MainNetPeerDrivenApplyRefusedNoReceipt),
        ("validator", DurableCompletionAuditPublicationReceiptOutcome::ValidatorSetRotationUnsupportedNoReceipt),
        ("policy", DurableCompletionAuditPublicationReceiptOutcome::PolicyChangeUnsupportedNoReceipt),
    ] {
        t.assert_true(&format!("D.{label}.no-receipt"), o.no_audit_receipt());
    }
    t.finish(out)
}

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("stage_ordering");
    let c = mainnet_peer_ctx();
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
    let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
    t.assert_true(
        "E.mainnet-refused-first",
        o.is_mainnet_peer_driven_apply_refused() && sink.invocations() == 0 && ledger.is_empty(),
    );
    let mut c2 = devnet_ctx();
    c2.expectations.expected_genesis_hash = "wrong".to_string();
    let mut ledger2 = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink2 = fixture_sink();
    let o2 = drive(&c2.recorded(), &c2.expectations, &mut sink2, &mut ledger2);
    t.assert_true("E.binding-before-receipt-sink", o2 == DurableCompletionAuditPublicationReceiptOutcome::RejectedBeforeBackendSubmissionNoAuditReceipt && sink2.invocations() == 0);
    let c3 = devnet_ctx();
    let mut ledger3 = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink3 = FixtureDurableCompletionAuditPublicationReceiptSink::with_fault(
        DurableCompletionAuditPublicationReceiptFault::RecordFailedNoReceipt,
    );
    let o3 = drive(&c3.recorded(), &c3.expectations, &mut sink3, &mut ledger3);
    t.assert_true(
        "E.record-failure-keeps-backend-but-no-receipt",
        o3.no_audit_receipt() && sink3.invocations() == 1 && ledger3.is_empty(),
    );
    let mut sink4 = FixtureDurableCompletionAuditPublicationReceiptSink::with_fault(
        DurableCompletionAuditPublicationReceiptFault::RollbackFailedFatal,
    );
    let mut ledger4 = DurableCompletionAuditPublicationReceiptLedger::new();
    let o4 = drive(&c3.recorded(), &c3.expectations, &mut sink4, &mut ledger4);
    t.check_outcome(
        "E.rollback-failed-fatal",
        "audit-receipt-rollback-failed-fatal-no-receipt",
        &o4,
    );
    t.assert_true(
        "E.receipt-only-after-backend",
        project_backend_submission_outcome_to_audit_receipt_request(
            &DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded,
        )
        .creates_request(),
    );
    t.assert_true(
        "E.no-receipt-sink-on-backend-reject",
        !project_backend_submission_outcome_to_audit_receipt_request(
            &DurableCompletionAttestationBackendOutcome::BackendSubmissionRejectedBeforeRecord,
        )
        .creates_request(),
    );
    t.assert_true(
        "E.fixture-only-ledger",
        durable_completion_audit_receipt_backend_submission_required()
            && durable_completion_audit_receipt_record_required_before_receipt(),
    );
    t.finish(out)
}

fn run_receipt_ledger_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("receipt_ledger");
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    t.check_outcome("F.one-valid", "audit-receipt-recorded", &o);
    t.assert_true(
        "F.len-one",
        ledger.len() == 1 && ledger.records().len() == 1 && ledger.contains(RECEIPT_RECORD_ID),
    );
    t.assert_true(
        "F.status",
        ledger.find(RECEIPT_RECORD_ID).map(|r| r.status)
            == Some(DurableCompletionAuditPublicationReceiptLedgerStatus::Recorded),
    );
    let snap = ledger.snapshot();
    t.assert_true("F.snapshot", snap.len() == 1 && !snap.is_empty());
    let mut restored = DurableCompletionAuditPublicationReceiptLedger::new();
    restored.restore(&snap);
    t.assert_true(
        "F.restore",
        restored.len() == 1 && restored.contains(RECEIPT_RECORD_ID),
    );
    let request_digest: DurableCompletionAuditPublicationReceiptDigest = c.request.digest();
    let record: DurableCompletionAuditPublicationReceiptRecord = c.request.to_record();
    t.assert_true("F.record-id", record.receipt_record_id == RECEIPT_RECORD_ID);
    t.assert_true(
        "F.record-request-digest",
        record.request_digest == request_digest,
    );
    t.assert_true("F.request-digest-hex", !request_digest.as_hex().is_empty());
    t.assert_true(
        "F.identity-digest-hex",
        !c.request.identity.digest().as_hex().is_empty(),
    );
    let response = DurableCompletionAuditPublicationReceiptResponse {
        receipt_record_id: RECEIPT_RECORD_ID.to_string(),
        request_digest: request_digest.clone(),
        accepted: true,
        receipt_kind: DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
    };
    let response_digest = response.digest();
    t.assert_true(
        "F.response-digest-hex",
        !response_digest.as_hex().is_empty() && response.is_well_formed(),
    );
    let transcript: DurableCompletionAuditPublicationReceiptTranscriptDigest = ledger
        .find(RECEIPT_RECORD_ID)
        .map(|r| r.transcript_digest.clone())
        .unwrap();
    t.assert_true("F.transcript-digest-hex", !transcript.as_hex().is_empty());
    let second = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    t.check_outcome("F.duplicate", "audit-receipt-duplicate-idempotent", &second);
    t.assert_true("F.duplicate-len-one", ledger.len() == 1);
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "different-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "different-candidate-digest".to_string();
    let o2 = drive(&c2.recorded(), &c2.expectations, &mut sink, &mut ledger);
    t.check_outcome(
        "F.equivocation",
        "audit-receipt-rejected-before-record",
        &o2,
    );
    t.assert_true("F.equivocation-len-one", ledger.len() == 1);
    for (label, mutate) in [
        (
            "wrong-receipt-identity",
            (|r: &mut DurableCompletionAuditPublicationReceiptRequest| {
                r.identity.receipt_id = "x".to_string()
            }) as fn(&mut DurableCompletionAuditPublicationReceiptRequest),
        ),
        ("wrong-request-digest", |r| r.proposal_id = "x".to_string()),
        ("wrong-response-bound", |r| {
            r.receipt_record_id = "x".to_string()
        }),
        ("wrong-backend-identity", |r| {
            r.backend_identity_digest = "x".to_string()
        }),
        ("wrong-backend-request", |r| {
            r.backend_request_digest = "x".to_string()
        }),
        ("wrong-backend-response", |r| {
            r.backend_response_digest = "x".to_string()
        }),
        ("wrong-backend-receipt", |r| {
            r.backend_receipt_digest = "x".to_string()
        }),
        ("wrong-backend-transcript", |r| {
            r.backend_transcript_digest = "x".to_string()
        }),
        ("wrong-attestation", |r| {
            r.attestation_digest = "x".to_string()
        }),
        ("wrong-finalization", |r| {
            r.finalization_decision_digest = "x".to_string()
        }),
        ("wrong-completion-report", |r| {
            r.reporter_decision_digest = "x".to_string()
        }),
        ("wrong-sink", |r| r.sink_decision_digest = "x".to_string()),
        ("wrong-pipeline", |r| {
            r.pipeline_decision_digest = "x".to_string()
        }),
        ("wrong-proposal", |r| r.proposal_id = "x".to_string()),
        ("wrong-decision", |r| r.decision_id = "x".to_string()),
        ("wrong-candidate", |r| r.candidate_digest = "x".to_string()),
        ("wrong-sequence", |r| r.authority_domain_sequence = 123),
        ("malformed-request", |r| r.backend_record_id = String::new()),
        ("malformed-response", |r| {
            r.domain_separation_tag = String::new()
        }),
    ] {
        let cc = devnet_ctx();
        let mut input = cc.recorded();
        mutate(&mut input.request);
        let mut empty = DurableCompletionAuditPublicationReceiptLedger::new();
        let mut s = fixture_sink();
        let o = drive(&input, &cc.expectations, &mut s, &mut empty);
        t.check_outcome(
            &format!("F.no-record.{label}"),
            "audit-receipt-rejected-before-record",
            &o,
        );
        t.assert_true(&format!("F.no-record.{label}.empty"), empty.is_empty());
    }
    let mut existing = ledger.clone();
    let second_action = action_label("rollback-second");
    let c3 = ctx_action(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed,
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        &second_action,
        false,
    );
    let mut faulted = FixtureDurableCompletionAuditPublicationReceiptSink::with_fault(
        DurableCompletionAuditPublicationReceiptFault::RolledBackNoReceipt,
    );
    let rolled = drive(
        &c3.recorded(),
        &c3.expectations,
        &mut faulted,
        &mut existing,
    );
    t.check_outcome(
        "F.rollback-restores",
        "audit-receipt-rolled-back-no-receipt",
        &rolled,
    );
    t.assert_true(
        "F.rollback-len-one",
        existing.len() == 1 && !existing.contains(&second_action.receipt_record_id),
    );
    t.assert_true(
        "F.fixture-memory-only",
        durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change()
            && durable_completion_audit_receipt_no_real_audit_ledger()
            && durable_completion_audit_receipt_no_external_publication(),
    );
    t.finish(out)
}

fn run_non_mutation_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("non_mutation");
    t.assert_true(
        "G.rejection-non-mutating",
        durable_completion_audit_receipt_rejection_is_non_mutating(),
    );
    t.assert_true(
        "G.never-calls-run-070",
        durable_completion_audit_receipt_never_calls_run_070(),
    );
    t.assert_true(
        "G.never-mutates-live",
        durable_completion_audit_receipt_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.never-writes-sequence-or-marker",
        durable_completion_audit_receipt_never_writes_sequence_or_marker(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "G.no-external-publication",
        durable_completion_audit_receipt_no_external_publication(),
    );
    t.assert_true(
        "G.no-real-audit-ledger",
        durable_completion_audit_receipt_no_real_audit_ledger(),
    );
    t.assert_true(
        "G.pipeline-success-required",
        durable_completion_audit_receipt_pipeline_success_required(),
    );
    t.assert_true(
        "G.sink-receipt-required",
        durable_completion_audit_receipt_sink_receipt_required(),
    );
    t.assert_true(
        "G.completion-report-required",
        durable_completion_audit_receipt_completion_report_required(),
    );
    t.assert_true(
        "G.finalization-required",
        durable_completion_audit_receipt_finalization_required(),
    );
    t.assert_true(
        "G.attestation-required",
        durable_completion_audit_receipt_attestation_required(),
    );
    t.assert_true(
        "G.backend-submission-required",
        durable_completion_audit_receipt_backend_submission_required(),
    );
    t.assert_true(
        "G.record-required",
        durable_completion_audit_receipt_record_required_before_receipt(),
    );
    t.assert_true(
        "G.failed-record-never-records",
        durable_completion_audit_receipt_failed_record_never_records(),
    );
    t.assert_true(
        "G.rollback-never-records",
        durable_completion_audit_receipt_rollback_never_records(),
    );
    t.assert_true(
        "G.ambiguous-fails-closed",
        durable_completion_audit_receipt_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "G.mainnet-refused-mainnet",
        durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet,
        ),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet,
        ),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        durable_completion_audit_receipt_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.external-unavailable",
        durable_completion_audit_receipt_external_publication_unavailable(),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        durable_completion_audit_receipt_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "G.policy-change-unsupported",
        durable_completion_audit_receipt_policy_change_unsupported(),
    );
    t.assert_true(
        "G.local-operator-cannot",
        durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    let mut c = devnet_ctx();
    c.expectations.expected_genesis_hash = "wrong".to_string();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let _ = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    t.assert_true(
        "G.rejected-ledger-empty",
        ledger.is_empty() && sink.invocations() == 0,
    );
    let c2 = devnet_ctx();
    let mut prod_ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut prod = ProductionAuditLedgerDurableCompletionReceiptSink::default();
    let _ = drive(
        &c2.recorded(),
        &c2.expectations,
        &mut prod,
        &mut prod_ledger,
    );
    t.assert_true("G.production-path-no-record", prod_ledger.is_empty());
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    let mut t = Table::new("reachability");
    for (o, tag) in [
        (
            Receipt::LegacyBypassNoAuditReceipt,
            "legacy-bypass-no-audit-receipt",
        ),
        (
            Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt,
            "rejected-before-backend-submission-no-audit-receipt",
        ),
        (
            Receipt::BackendDidNotSubmitNoAuditReceipt,
            "backend-did-not-submit-no-audit-receipt",
        ),
        (Receipt::AuditReceiptRecorded, "audit-receipt-recorded"),
        (
            Receipt::AuditReceiptDuplicateIdempotent,
            "audit-receipt-duplicate-idempotent",
        ),
        (
            Receipt::AuditReceiptRejectedBeforeRecord,
            "audit-receipt-rejected-before-record",
        ),
        (
            Receipt::AuditReceiptRecordFailedNoReceipt,
            "audit-receipt-record-failed-no-receipt",
        ),
        (
            Receipt::AuditReceiptRolledBackNoReceipt,
            "audit-receipt-rolled-back-no-receipt",
        ),
        (
            Receipt::AuditReceiptRollbackFailedFatalNoReceipt,
            "audit-receipt-rollback-failed-fatal-no-receipt",
        ),
        (
            Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
            "audit-receipt-ambiguous-fail-closed-no-receipt",
        ),
        (
            Receipt::ProductionAuditLedgerUnavailableNoReceipt,
            "production-audit-ledger-unavailable-no-receipt",
        ),
        (
            Receipt::MainNetAuditLedgerUnavailableNoReceipt,
            "mainnet-audit-ledger-unavailable-no-receipt",
        ),
        (
            Receipt::ExternalPublicationUnavailableNoReceipt,
            "external-publication-unavailable-no-receipt",
        ),
        (
            Receipt::MainNetPeerDrivenApplyRefusedNoReceipt,
            "mainnet-peer-driven-apply-refused-no-receipt",
        ),
        (
            Receipt::ValidatorSetRotationUnsupportedNoReceipt,
            "validator-set-rotation-unsupported-no-receipt",
        ),
        (
            Receipt::PolicyChangeUnsupportedNoReceipt,
            "policy-change-unsupported-no-receipt",
        ),
    ] {
        t.check(&format!("H.tag.{tag}"), tag, o.tag());
    }
    t.check(
        "H.kind-disabled",
        "disabled",
        DurableCompletionAuditPublicationReceiptKind::Disabled.tag(),
    );
    t.check(
        "H.kind-fixture",
        "fixture-in-memory",
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory.tag(),
    );
    t.check(
        "H.kind-production",
        "production-audit-ledger-unavailable",
        DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable.tag(),
    );
    t.check(
        "H.kind-mainnet",
        "mainnet-audit-ledger-unavailable",
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable.tag(),
    );
    t.check(
        "H.kind-external",
        "external-publication-unavailable",
        DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable.tag(),
    );
    t.check(
        "H.kind-unknown",
        "unknown",
        DurableCompletionAuditPublicationReceiptKind::Unknown.tag(),
    );
    t.assert_true(
        "H.kind-fixture",
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory.is_fixture(),
    );
    t.assert_true(
        "H.kind-unavailable",
        DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable
            .is_unavailable(),
    );
    t.check(
        "H.policy-disabled",
        "disabled",
        DurableCompletionAuditPublicationReceiptPolicy::Disabled.tag(),
    );
    t.check(
        "H.policy-fixture",
        "fixture-allowed",
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed.tag(),
    );
    t.check(
        "H.policy-production",
        "production-audit-ledger-required",
        DurableCompletionAuditPublicationReceiptPolicy::ProductionAuditLedgerRequired.tag(),
    );
    t.check(
        "H.policy-mainnet",
        "mainnet-audit-ledger-required",
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired.tag(),
    );
    t.check(
        "H.policy-external",
        "external-publication-required",
        DurableCompletionAuditPublicationReceiptPolicy::ExternalPublicationRequired.tag(),
    );
    t.assert_true(
        "H.policy-is-disabled",
        DurableCompletionAuditPublicationReceiptPolicy::Disabled.is_disabled(),
    );
    t.assert_true(
        "H.policy-allows-fixture",
        DurableCompletionAuditPublicationReceiptPolicy::FixtureAllowed.allows_fixture(),
    );
    t.check(
        "H.trait-fixture-kind",
        "fixture-in-memory",
        fixture_sink().kind().tag(),
    );
    t.check(
        "H.trait-production-kind",
        "production-audit-ledger-unavailable",
        ProductionAuditLedgerDurableCompletionReceiptSink::default()
            .kind()
            .tag(),
    );
    t.check(
        "H.trait-mainnet-kind",
        "mainnet-audit-ledger-unavailable",
        MainNetAuditLedgerDurableCompletionReceiptSink::default()
            .kind()
            .tag(),
    );
    t.check(
        "H.trait-external-kind",
        "external-publication-unavailable",
        ExternalPublicationDurableCompletionReceiptSink::default()
            .kind()
            .tag(),
    );
    let _aliases = std::any::type_name::<(
        DurableCompletionAuditPublicationReceiptSurface,
        DurableCompletionAuditPublicationReceiptEnvironment,
        DurableCompletionAuditPublicationReceiptBinding,
        DurableCompletionAuditPublicationReceiptReplayBinding,
        DurableCompletionAuditPublicationReceiptPipelineBinding,
        DurableCompletionAuditPublicationReceiptSinkBinding,
        DurableCompletionAuditPublicationReceiptReporterBinding,
        DurableCompletionAuditPublicationReceiptFinalizationBinding,
        DurableCompletionAuditPublicationReceiptAttestationBinding,
        DurableCompletionAuditPublicationReceiptBackendBinding,
        DurableCompletionAuditPublicationReceiptInput,
        DurableCompletionAuditPublicationReceiptPolicy,
        DurableCompletionAuditPublicationReceiptKind,
        DurableCompletionAuditPublicationReceiptIdentity,
        DurableCompletionAuditPublicationReceiptExpectations,
        DurableCompletionAuditPublicationReceiptRequest,
        DurableCompletionAuditPublicationReceiptResponse,
        DurableCompletionAuditPublicationReceiptRecord,
        DurableCompletionAuditPublicationReceiptLedger,
        DurableCompletionAuditPublicationReceiptLedgerRecord,
        DurableCompletionAuditPublicationReceiptDigest,
        DurableCompletionAuditPublicationReceiptTranscriptDigest,
        DurableCompletionAuditPublicationReceiptOutcome,
        DurableCompletionAuditPublicationReceiptRequestIntent,
        DurableCompletionAuditPublicationReceiptFault,
        DurableCompletionAuditPublicationReceiptWindow,
        FixtureDurableCompletionAuditPublicationReceiptSink,
        ProductionAuditLedgerDurableCompletionReceiptSink,
        MainNetAuditLedgerDurableCompletionReceiptSink,
        ExternalPublicationDurableCompletionReceiptSink,
    )>();
    t.assert_true("H.aliases-and-types", !_aliases.is_empty());
    t.assert_true(
        "H.invariant-all",
        durable_completion_audit_receipt_rejection_is_non_mutating()
            && durable_completion_audit_receipt_never_calls_run_070()
            && durable_completion_audit_receipt_never_mutates_live_pqc_trust_state()
            && durable_completion_audit_receipt_never_writes_sequence_or_marker()
            && durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change()
            && durable_completion_audit_receipt_no_external_publication()
            && durable_completion_audit_receipt_no_real_audit_ledger()
            && durable_completion_audit_receipt_pipeline_success_required()
            && durable_completion_audit_receipt_sink_receipt_required()
            && durable_completion_audit_receipt_completion_report_required()
            && durable_completion_audit_receipt_finalization_required()
            && durable_completion_audit_receipt_attestation_required()
            && durable_completion_audit_receipt_backend_submission_required()
            && durable_completion_audit_receipt_record_required_before_receipt()
            && durable_completion_audit_receipt_failed_record_never_records()
            && durable_completion_audit_receipt_rollback_never_records()
            && durable_completion_audit_receipt_ambiguous_window_fails_closed()
            && durable_completion_audit_receipt_production_mainnet_unavailable()
            && durable_completion_audit_receipt_external_publication_unavailable()
            && durable_completion_audit_receipt_validator_set_rotation_unsupported()
            && durable_completion_audit_receipt_policy_change_unsupported()
            && durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority()
            && durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    t.finish(out)
}

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink = fixture_sink();
    let o = drive(&c.recorded(), &c.expectations, &mut sink, &mut ledger);
    write_file(&dir.join("success_lifecycle.txt"), &format!(
        "outcome={} authorizes={} projects={} invocations={} ledger_len={} contains={} backend_outcome={}\n",
        o.tag(),
        o.authorizes_audit_receipt_record(),
        o.projects_to_audit_receipt_recorded(),
        sink.invocations(),
        ledger.len(),
        ledger.contains(RECEIPT_RECORD_ID),
        c.backend.outcome.tag(),
    ));
    let mut c2 = devnet_ctx();
    c2.expectations.expected_genesis_hash = "wrong-genesis".to_string();
    let mut ledger2 = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink2 = fixture_sink();
    let o2 = drive(&c2.recorded(), &c2.expectations, &mut sink2, &mut ledger2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} invocations={} no_audit_receipt={} ledger_len={}\n",
            o2.tag(),
            sink2.invocations(),
            o2.no_audit_receipt(),
            ledger2.len()
        ),
    );
    let cp = mainnet_peer_ctx();
    let input = cp.input(
        DurableCompletionAuditPublicationReceiptPolicy::MainNetAuditLedgerRequired,
        DurableReplayObservation::MainNetPeerDrivenApplyRefused,
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume,
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion,
        GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization,
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation,
        DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission,
    );
    let mut ledger3 = DurableCompletionAuditPublicationReceiptLedger::new();
    let mut sink3 = MainNetAuditLedgerDurableCompletionReceiptSink::default();
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
        (
            "before-pipeline",
            DurableCompletionAuditPublicationReceiptWindow::BeforePipeline,
            false,
        ),
        (
            "after-backend-success-before-receipt-request",
            DurableCompletionAuditPublicationReceiptWindow::AfterBackendSuccessBeforeReceiptRequest,
            false,
        ),
        (
            "after-receipt-record-before-success-with-record",
            DurableCompletionAuditPublicationReceiptWindow::AfterReceiptRecordBeforeReceiptSuccess,
            true,
        ),
        (
            "after-receipt-success",
            DurableCompletionAuditPublicationReceiptWindow::AfterReceiptSuccess,
            true,
        ),
        (
            "after-receipt-ambiguous",
            DurableCompletionAuditPublicationReceiptWindow::AfterReceiptAmbiguous,
            false,
        ),
        (
            "receipt-rollback-failed",
            DurableCompletionAuditPublicationReceiptWindow::ReceiptRollbackFailed,
            false,
        ),
        (
            "unknown",
            DurableCompletionAuditPublicationReceiptWindow::Unknown,
            false,
        ),
    ] {
        windows.push_str(&format!(
            "{label}={}\n",
            recover_devnet(w, with_record).tag()
        ));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_259_durable_completion_audit_publication_receipt_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("stage_ordering", run_stage_ordering_table),
        ("receipt_ledger", run_receipt_ledger_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_259_durable_completion_audit_publication_receipt_release_binary_helper\n\
scope: Run 258 durable-completion audit-ledger / external-publication receipt boundary (pqc_governance_durable_completion_audit_publication_receipt: evaluate_durable_completion_audit_publication_receipt, recover_durable_completion_audit_publication_receipt_window, project_backend_submission_outcome_to_audit_receipt_request, audit_receipt_outcome_authorizes_receipt_record, audit_receipt_outcome_projects_to_audit_receipt_recorded, GovernanceDurableCompletionAuditPublicationReceiptSink with FixtureDurableCompletionAuditPublicationReceiptSink / ProductionAuditLedgerDurableCompletionReceiptSink / MainNetAuditLedgerDurableCompletionReceiptSink / ExternalPublicationDurableCompletionReceiptSink, typed input/expectations/policy/kind/identity/request/response/record/digest/transcript/ledger/outcome/request-intent/fault/window bindings, and invariant helpers) exercised through release-built library symbols (release binary)\n\
note: fixture-only; the fixture receipt sink mutates ONLY the in-memory DurableCompletionAuditPublicationReceiptLedger. No production behavior change, no real audit ledger, no external publication, no Run 070 call, no LivePqcTrustState mutation, no marker/sequence write, no trust swap, no session eviction, no RocksDB/file/schema/migration/storage-format change, no MainNet governance, no MainNet peer-driven apply. Run 246 pipeline success, Run 248 ConsumeReceiptRecorded, Run 250 CompletionReportRecorded, Run 252 DurableCompletionFinalized, Run 254 DurableCompletionAttested, and Run 256 BackendSubmissionRecorded are required before any receipt record; only AuditReceiptRecorded authorizes a modeled audit/publication receipt state; duplicate identical receipts are idempotent; equivocation fails closed; production/MainNet/external-publication sinks remain reachable but unavailable/fail-closed.\n\n",
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
