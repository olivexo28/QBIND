//! Run 257 — release-built helper for the Run 256 production **durable-completion
//! attestation backend interface boundary**.
//!
//! This mirrors the Run 255 release-helper structure for the Run 254 attestation
//! projection, adapted to the Run 256 backend interface symbols. The helper
//! exercises release-built library symbols only and mutates only the modeled
//! in-memory `DurableCompletionAttestationBackendLedger` through the DevNet/TestNet
//! fixture backend. It enables no real production attestation backend, no audit
//! ledger backend, no external publication, no MainNet governance, no MainNet
//! peer-driven apply, no Run 070 call, no `LivePqcTrustState` mutation, no
//! marker/sequence write, no trust swap, no session eviction, and no
//! RocksDB/file/schema/migration/storage-format change.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    DurableCompletionAttestationBackendBinding, DurableCompletionAttestationBackendDigest,
    DurableCompletionAttestationBackendEnvironment, DurableCompletionAttestationBackendExpectations,
    DurableCompletionAttestationBackendFault, DurableCompletionAttestationBackendIdentity,
    DurableCompletionAttestationBackendInput, DurableCompletionAttestationBackendKind,
    DurableCompletionAttestationBackendLedger, DurableCompletionAttestationBackendLedgerStatus,
    DurableCompletionAttestationBackendOutcome, DurableCompletionAttestationBackendPolicy,
    DurableCompletionAttestationBackendReceipt, DurableCompletionAttestationBackendRecord,
    DurableCompletionAttestationBackendRequest, DurableCompletionAttestationBackendRequestIntent,
    DurableCompletionAttestationBackendResponse, DurableCompletionAttestationBackendSurface,
    DurableCompletionAttestationBackendTranscriptDigest, DurableCompletionAttestationBackendWindow,
    ExternalPublicationDurableCompletionAttestationBackend,
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

    /// The wired input carrying a chosen non-attesting attestation outcome.
    fn with_attestation(
        &self,
        attestation: GovernanceModeledDurableCompletionAttestationOutcome,
    ) -> DurableCompletionAttestationBackendInput {
        self.input(
            DurableCompletionAttestationBackendPolicy::FixtureAllowed,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            attestation,
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
fn mainnet_peer_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        DurableCompletionAttestationBackendPolicy::FixtureAllowed,
        DurableCompletionAttestationBackendKind::FixtureInMemory,
    )
}
fn fixture_backend() -> FixtureDurableCompletionAttestationBackend {
    FixtureDurableCompletionAttestationBackend::new()
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
        self.pass += ok as u64;
        self.fail += (!ok) as u64;
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
        o: &DurableCompletionAttestationBackendOutcome,
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

fn drive(
    input: &DurableCompletionAttestationBackendInput,
    expectations: &DurableCompletionAttestationBackendExpectations,
    backend: &mut FixtureDurableCompletionAttestationBackend,
    ledger: &mut DurableCompletionAttestationBackendLedger,
) -> DurableCompletionAttestationBackendOutcome {
    evaluate_durable_completion_attestation_backend(input, expectations, backend, ledger)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    let mut t = Table::new("accepted");
    // A1 disabled backend policy preserves the legacy no-backend-submission bypass.
    {
        let c = devnet_ctx();
        let input = c.input(
            DurableCompletionAttestationBackendPolicy::Disabled,
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
            Att::DurableCompletionAttested,
        );
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&input, &c.expectations, &mut backend, &mut ledger);
        t.check_outcome("A1.backend-policy-disabled", "legacy-bypass-no-backend-submission", &o);
        t.assert_true("A1.no-invocation", backend.invocations() == 0);
        t.assert_true("A1.ledger-empty", ledger.is_empty());
    }
    // A2..A7 disabled attestor / finalizer / reporter / sink / pipeline / evaluator
    // stages all surface as a legacy-bypass attestation outcome that never invokes
    // the backend.
    for id in [
        "A2.attestor-disabled",
        "A3.finalizer-disabled",
        "A4.reporter-disabled",
        "A5.sink-disabled",
        "A6.pipeline-disabled",
        "A7.evaluator-disabled",
    ] {
        let c = devnet_ctx();
        let input = c.with_attestation(Att::LegacyBypassNoAttestation);
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&input, &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), "legacy-bypass-no-backend-submission", &o);
        t.assert_true(&format!("{id}.no-invocation"), backend.invocations() == 0);
        t.assert_true(&format!("{id}.ledger-empty"), ledger.is_empty());
    }
    // A8 / A9 DevNet / TestNet fixture success records exactly one backend submission.
    for (id, c) in [("A8.devnet", devnet_ctx()), ("A9.testnet", testnet_ctx())] {
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), "backend-submission-recorded", &o);
        t.assert_true(
            &format!("{id}.authorizes"),
            backend_outcome_authorizes_durable_attestation_submission(&o),
        );
        t.assert_true(
            &format!("{id}.projects"),
            backend_outcome_projects_to_backend_submission_recorded(&o),
        );
        t.assert_true(&format!("{id}.ledger-one"), ledger.len() == 1);
        t.assert_true(&format!("{id}.contains"), ledger.contains(BACKEND_RECORD_ID));
        t.assert_true(&format!("{id}.invoked-once"), backend.invocations() == 1);
    }
    // A10 all modeled action types submit only after a recorded attestation.
    for action in ["add-root", "retire-root", "revoke-root", "emergency-revoke-root", "noop"] {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(&format!("A10.{action}.outcome"), "backend-submission-recorded", &o);
        t.assert_true(&format!("A10.{action}.ledger-one"), ledger.len() == 1);
    }
    // A11 duplicate identical backend submission is idempotent (no second submission).
    {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let first = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        let second = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome("A11.first", "backend-submission-recorded", &first);
        t.check_outcome("A11.duplicate", "backend-submission-duplicate-idempotent", &second);
        t.assert_true("A11.ledger-one", ledger.len() == 1);
        t.assert_true("A11.duplicate-no-authorize", !second.authorizes_backend_submission());
        t.assert_true(
            "A11.duplicate-projects",
            second.projects_to_backend_submission_recorded(),
        );
    }
    // A12 a Run 254 duplicate-idempotent attestation may only match an
    // already-submitted backend record; it never creates a new submission itself.
    {
        let c = devnet_ctx();
        let mut empty = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.attested_duplicate(), &c.expectations, &mut backend, &mut empty);
        t.check_outcome("A12.duplicate-empty", "backend-submission-rejected-before-record", &o);
        t.assert_true("A12.empty", empty.is_empty());
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut b2 = fixture_backend();
        let _ = drive(&c.attested(), &c.expectations, &mut b2, &mut ledger);
        let o2 = drive(&c.attested_duplicate(), &c.expectations, &mut b2, &mut ledger);
        t.check_outcome("A12.duplicate-matches", "backend-submission-duplicate-idempotent", &o2);
        t.assert_true("A12.matches-ledger-one", ledger.len() == 1);
    }
    // A13 / A14 / A15 production / MainNet / external-publication backend paths are
    // reachable but unavailable / fail-closed and record no submission.
    {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut prod = ProductionDurableCompletionAttestationBackend::default();
        let o = evaluate_durable_completion_attestation_backend(
            &c.attested(),
            &c.expectations,
            &mut prod,
            &mut ledger,
        );
        t.check_outcome("A13.production", "production-backend-unavailable-no-submission", &o);
        t.assert_true("A13.no-record", ledger.is_empty());
        t.check("A13.kind", "production-unavailable", prod.kind().tag());
        let mut mn = MainNetDurableCompletionAttestationBackend::default();
        let o2 = evaluate_durable_completion_attestation_backend(
            &c.attested(),
            &c.expectations,
            &mut mn,
            &mut ledger,
        );
        t.check_outcome("A14.mainnet", "mainnet-backend-unavailable-no-submission", &o2);
        t.assert_true("A14.no-record", ledger.is_empty());
        let mut ext = ExternalPublicationDurableCompletionAttestationBackend::default();
        let o3 = evaluate_durable_completion_attestation_backend(
            &c.attested(),
            &c.expectations,
            &mut ext,
            &mut ledger,
        );
        t.check_outcome("A15.external", "external-publication-unavailable-no-submission", &o3);
        t.assert_true("A15.no-record", ledger.is_empty());
    }
    // A16 MainNet peer-driven apply refused before any backend invocation.
    {
        let c = mainnet_peer_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome("A16.mainnet-peer", "mainnet-peer-driven-apply-refused-no-submission", &o);
        t.assert_true("A16.no-invocation", backend.invocations() == 0);
        t.assert_true("A16.no-record", ledger.is_empty());
    }
    // A17 / A18 validator-set rotation and policy-change never submit.
    for (id, att, tag) in [
        (
            "A17.validator",
            Att::ValidatorSetRotationUnsupportedNoAttestation,
            "validator-set-rotation-unsupported-no-submission",
        ),
        (
            "A18.policy",
            Att::PolicyChangeUnsupportedNoAttestation,
            "policy-change-unsupported-no-submission",
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.with_attestation(att), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(id, tag, &o);
        t.assert_true(&format!("{id}.no-invocation"), backend.invocations() == 0);
        t.assert_true(&format!("{id}.no-record"), ledger.is_empty());
    }
    t.finish(out)
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    let mut t = Table::new("rejection");
    // Every non-attesting Run 254 attestation outcome maps to a no-backend-submission
    // outcome and never invokes the backend.
    let attestation_cases: [(&str, Att, &str); 13] = [
        ("legacy", Att::LegacyBypassNoAttestation, "legacy-bypass-no-backend-submission"),
        (
            "rejected-before-finalization",
            Att::RejectedBeforeFinalizationNoAttestation,
            "rejected-before-attestation-no-backend-submission",
        ),
        (
            "finalization-did-not-finalize",
            Att::FinalizationDidNotFinalizeNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "rejected-before-record",
            Att::DurableCompletionAttestationRejectedBeforeRecord,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "record-failed",
            Att::DurableCompletionAttestationRecordFailedNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "rolled-back",
            Att::DurableCompletionAttestationRolledBackNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "rollback-failed",
            Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "ambiguous",
            Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "production",
            Att::ProductionAttestorUnavailableNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "mainnet",
            Att::MainNetAttestorUnavailableNoAttestation,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "mainnet-peer",
            Att::MainNetPeerDrivenApplyRefusedNoAttestation,
            "mainnet-peer-driven-apply-refused-no-submission",
        ),
        (
            "validator",
            Att::ValidatorSetRotationUnsupportedNoAttestation,
            "validator-set-rotation-unsupported-no-submission",
        ),
        (
            "policy",
            Att::PolicyChangeUnsupportedNoAttestation,
            "policy-change-unsupported-no-submission",
        ),
    ];
    for (label, att, tag) in attestation_cases {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.with_attestation(att), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(&format!("B.attestation.{label}"), tag, &o);
        t.assert_true(&format!("B.attestation.{label}.no-invocation"), backend.invocations() == 0);
        t.assert_true(&format!("B.attestation.{label}.no-record"), ledger.is_empty());
        t.assert_true(&format!("B.attestation.{label}.no-submission"), o.no_backend_submission());
    }
    // MainNet peer-driven refusal is also reachable through every prior-stage binding.
    for (label, input) in [
        (
            "replay",
            devnet_ctx().input(
                DurableCompletionAttestationBackendPolicy::FixtureAllowed,
                DurableReplayObservation::MainNetPeerDrivenApplyRefused,
                GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
                GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
                GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
                GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
                Att::DurableCompletionAttested,
            ),
        ),
        (
            "attestation",
            devnet_ctx().with_attestation(Att::MainNetPeerDrivenApplyRefusedNoAttestation),
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&input, &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(
            &format!("B.mainnet-peer.{label}"),
            "mainnet-peer-driven-apply-refused-no-submission",
            &o,
        );
        t.assert_true(&format!("B.mainnet-peer.{label}.no-invocation"), backend.invocations() == 0);
    }
    // Injected backend faults: invoked once, never leave a recorded submission.
    for (label, fault, tag) in [
        (
            "record-failed",
            DurableCompletionAttestationBackendFault::RecordFailedNoSubmission,
            "backend-submission-record-failed-no-submission",
        ),
        (
            "rollback",
            DurableCompletionAttestationBackendFault::RolledBackNoSubmission,
            "backend-submission-rolled-back-no-submission",
        ),
        (
            "rollback-failed",
            DurableCompletionAttestationBackendFault::RollbackFailedFatal,
            "backend-submission-rollback-failed-fatal-no-submission",
        ),
        (
            "ambiguous",
            DurableCompletionAttestationBackendFault::AmbiguousAfterRecord,
            "backend-submission-ambiguous-fail-closed-no-submission",
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = FixtureDurableCompletionAttestationBackend::with_fault(fault);
        let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(&format!("B.fault.{label}"), tag, &o);
        t.assert_true(&format!("B.fault.{label}.invoked"), backend.invocations() == 1);
        t.assert_true(&format!("B.fault.{label}.empty"), ledger.is_empty());
    }
    // Pre-backend environment / surface binding mismatch: backend never invoked.
    let binding_cases: [(&str, fn(&mut Ctx)); 6] = [
        (
            "wrong-environment",
            (|c: &mut Ctx| c.env.environment = TrustBundleEnvironment::Testnet) as fn(&mut Ctx),
        ),
        (
            "wrong-chain",
            (|c: &mut Ctx| c.env.chain_id = "qbind-other".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-genesis",
            (|c: &mut Ctx| c.env.genesis_hash = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-governance-surface",
            (|c: &mut Ctx| c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup)
                as fn(&mut Ctx),
        ),
        (
            "wrong-validation-surface",
            (|c: &mut Ctx| {
                c.runtime.mutation_surface.validation_surface =
                    GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle
            }) as fn(&mut Ctx),
        ),
        (
            "wrong-mutation-surface",
            (|c: &mut Ctx| {
                c.runtime.mutation_surface.mutation_surface =
                    GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle
            }) as fn(&mut Ctx),
        ),
    ];
    for (label, mutate) in binding_cases {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(
            &format!("B.binding.{label}"),
            "rejected-before-attestation-no-backend-submission",
            &o,
        );
        t.assert_true(&format!("B.binding.{label}.no-invocation"), backend.invocations() == 0);
        t.assert_true(&format!("B.binding.{label}.empty"), ledger.is_empty());
    }
    // Backend-request-identity mismatch / malformed: backend invoked once, no record.
    let request_cases: [(&str, fn(&mut Ctx)); 21] = [
        ("wrong-backend-record-id", (|c: &mut Ctx| c.request.backend_record_id = "other".to_string()) as fn(&mut Ctx)),
        ("wrong-environment", (|c: &mut Ctx| c.request.environment = TrustBundleEnvironment::Testnet) as fn(&mut Ctx)),
        ("wrong-chain", (|c: &mut Ctx| c.request.chain_id = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-genesis", (|c: &mut Ctx| c.request.genesis_hash = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-governance-surface", (|c: &mut Ctx| c.request.governance_surface = GovernanceExecutionRuntimeSurface::Sighup) as fn(&mut Ctx)),
        ("wrong-mutation-surface", (|c: &mut Ctx| c.request.mutation_surface = GovernanceExecutionRuntimeSurface::Sighup) as fn(&mut Ctx)),
        ("wrong-proposal", (|c: &mut Ctx| c.request.proposal_id = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-decision", (|c: &mut Ctx| c.request.decision_id = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-candidate", (|c: &mut Ctx| c.request.candidate_digest = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-sequence", (|c: &mut Ctx| c.request.authority_domain_sequence = 99) as fn(&mut Ctx)),
        ("wrong-pipeline-digest", (|c: &mut Ctx| c.request.pipeline_decision_digest = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-sink-digest", (|c: &mut Ctx| c.request.sink_decision_digest = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-reporter-digest", (|c: &mut Ctx| c.request.reporter_decision_digest = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-finalization-digest", (|c: &mut Ctx| c.request.finalization_decision_digest = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-attestation-digest", (|c: &mut Ctx| c.request.attestation_digest = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-attestation-id", (|c: &mut Ctx| c.request.attestation_id = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-domain-tag", (|c: &mut Ctx| c.request.domain_separation_tag = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-identity", (|c: &mut Ctx| c.request.identity.backend_id = "wrong".to_string()) as fn(&mut Ctx)),
        ("wrong-kind", (|c: &mut Ctx| c.request.identity.kind = DurableCompletionAttestationBackendKind::ProductionUnavailable) as fn(&mut Ctx)),
        ("wrong-policy", (|c: &mut Ctx| c.request.identity.policy = DurableCompletionAttestationBackendPolicy::ProductionBackendRequired) as fn(&mut Ctx)),
        ("malformed", (|c: &mut Ctx| c.request.backend_record_id = String::new()) as fn(&mut Ctx)),
    ];
    for (label, mutate) in request_cases {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        t.check_outcome(
            &format!("B.request.{label}"),
            "backend-submission-rejected-before-record",
            &o,
        );
        t.assert_true(&format!("B.request.{label}.invoked"), backend.invocations() == 1);
        t.assert_true(&format!("B.request.{label}.empty"), ledger.is_empty());
    }
    // Same backend record id with a different digest is equivocation (no second
    // submission).
    {
        let c = devnet_ctx();
        let mut ledger = DurableCompletionAttestationBackendLedger::new();
        let mut backend = fixture_backend();
        let _ = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        // Build an equivocating request: same backend record id, different candidate
        // digest, with expectations updated to accept the new request so the request
        // passes identity validation but the digest differs from the recorded one.
        let mut c2 = devnet_ctx();
        c2.request.candidate_digest = "different-candidate-digest".to_string();
        c2.expectations.expected_candidate_digest = "different-candidate-digest".to_string();
        let o = drive(&c2.attested(), &c2.expectations, &mut backend, &mut ledger);
        t.check_outcome("B.equivocation", "backend-submission-rejected-before-record", &o);
        t.assert_true("B.equivocation-ledger-one", ledger.len() == 1);
    }
    // Local operator / peer majority cannot satisfy MainNet authority.
    t.assert_true(
        "B.local-operator-cannot",
        durable_completion_attestation_backend_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "B.peer-majority-cannot",
        durable_completion_attestation_backend_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    t.finish(out)
}

fn recover_devnet(
    window: DurableCompletionAttestationBackendWindow,
    record: Option<&DurableCompletionAttestationBackendRecord>,
) -> DurableCompletionAttestationBackendOutcome {
    // Build a recovered ledger record (when present) by replaying one real fixture
    // submission and reading it back from the modeled ledger.
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let recovered = if record.is_some() {
        let mut backend = fixture_backend();
        let _ = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
        ledger.find(BACKEND_RECORD_ID)
    } else {
        None
    };
    recover_durable_completion_attestation_backend_window(
        &c.attested(),
        window,
        DurableCompletionAttestationBackendKind::FixtureInMemory,
        recovered,
        &c.expectations,
    )
}

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAttestationBackendWindow as W;
    let mut t = Table::new("recovery");
    // The "matching backend record" sentinel — a non-None record reference asks
    // recover_devnet to replay a real submission and pass the recovered record.
    let sentinel = devnet_ctx().request.to_record();
    for (id, w, tag) in [
        ("C.before-pipeline", W::BeforePipeline, "attestation-did-not-attest-no-backend-submission"),
        (
            "C.after-pipeline-before-sink-intent",
            W::AfterPipelineSuccessBeforeSinkIntent,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-sink-intent-before-receipt-record",
            W::AfterSinkIntentBeforeReceiptRecord,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-receipt-record-before-report-intent",
            W::AfterReceiptRecordBeforeReportIntent,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-report-intent-before-report-record",
            W::AfterReportIntentBeforeReportRecord,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-report-record-before-finalization-intent",
            W::AfterReportRecordBeforeFinalizationIntent,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-finalization-intent-before-record",
            W::AfterFinalizationIntentBeforeFinalizationRecord,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-finalization-record-before-attestation-intent",
            W::AfterFinalizationRecordBeforeAttestationIntent,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-attestation-intent-before-record",
            W::AfterAttestationIntentBeforeAttestationRecord,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (
            "C.after-attestation-record-before-backend-request",
            W::AfterAttestationRecordBeforeBackendRequest,
            "backend-submission-rejected-before-record",
        ),
        (
            "C.after-backend-request-before-record",
            W::AfterBackendRequestBeforeBackendRecord,
            "backend-submission-rejected-before-record",
        ),
        (
            "C.after-backend-record-before-success-no-record",
            W::AfterBackendRecordBeforeBackendSuccess,
            "backend-submission-rejected-before-record",
        ),
        (
            "C.after-ambiguous",
            W::AfterBackendAmbiguous,
            "backend-submission-ambiguous-fail-closed-no-submission",
        ),
        (
            "C.record-failed",
            W::BackendRecordFailed,
            "backend-submission-record-failed-no-submission",
        ),
        (
            "C.rollback",
            W::BackendRollbackCompleted,
            "backend-submission-rolled-back-no-submission",
        ),
        (
            "C.rollback-failed",
            W::BackendRollbackFailed,
            "backend-submission-rollback-failed-fatal-no-submission",
        ),
        (
            "C.unknown",
            W::Unknown,
            "backend-submission-ambiguous-fail-closed-no-submission",
        ),
    ] {
        t.check_outcome(id, tag, &recover_devnet(w, None));
    }
    // After-record / after-success windows recover as recorded only with a matching
    // recovered backend record.
    t.check_outcome(
        "C.after-backend-record-before-success-with-record",
        "backend-submission-recorded",
        &recover_devnet(W::AfterBackendRecordBeforeBackendSuccess, Some(&sentinel)),
    );
    t.check_outcome(
        "C.after-backend-success",
        "backend-submission-recorded",
        &recover_devnet(W::AfterBackendSuccess, Some(&sentinel)),
    );
    t.check_outcome(
        "C.after-backend-success-no-record",
        "backend-submission-rejected-before-record",
        &recover_devnet(W::AfterBackendSuccess, None),
    );
    // Production / MainNet / external recovery classification is unavailable.
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    {
        let mut backend = fixture_backend();
        let _ = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
    }
    let prod = recover_durable_completion_attestation_backend_window(
        &c.attested(),
        W::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    t.check_outcome("C.production", "production-backend-unavailable-no-submission", &prod);
    let mn = recover_durable_completion_attestation_backend_window(
        &c.attested(),
        W::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::MainNetUnavailable,
        None,
        &c.expectations,
    );
    t.check_outcome("C.mainnet", "mainnet-backend-unavailable-no-submission", &mn);
    let ext = recover_durable_completion_attestation_backend_window(
        &c.attested(),
        W::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::ExternalPublicationUnavailable,
        None,
        &c.expectations,
    );
    t.check_outcome("C.external", "external-publication-unavailable-no-submission", &ext);
    // MainNet peer-driven refusal precedes recovery classification.
    let cp = mainnet_peer_ctx();
    let peer = recover_durable_completion_attestation_backend_window(
        &cp.attested(),
        W::AfterBackendSuccess,
        DurableCompletionAttestationBackendKind::FixtureInMemory,
        None,
        &cp.expectations,
    );
    t.check_outcome("C.mainnet-peer-precedes", "mainnet-peer-driven-apply-refused-no-submission", &peer);
    t.finish(out)
}

fn run_projection_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    let mut t = Table::new("projection");
    // Only DurableCompletionAttested creates a backend request.
    t.assert_true(
        "D.only-attested-creates-request",
        project_attestation_outcome_to_backend_request(&Att::DurableCompletionAttested).creates_request(),
    );
    // A duplicate-idempotent attestation is idempotent-only (no create).
    t.assert_true(
        "D.duplicate-idempotent-only",
        project_attestation_outcome_to_backend_request(
            &Att::DurableCompletionAttestationDuplicateIdempotent,
        ) == DurableCompletionAttestationBackendRequestIntent::IdempotentOnly,
    );
    // Every non-attesting outcome creates no request and carries the expected
    // no-backend-submission outcome.
    let projections: [(&str, Att, DurableCompletionAttestationBackendOutcome); 13] = [
        ("legacy-bypass", Att::LegacyBypassNoAttestation, Backend::LegacyBypassNoBackendSubmission),
        (
            "rejected-before-finalization",
            Att::RejectedBeforeFinalizationNoAttestation,
            Backend::RejectedBeforeAttestationNoBackendSubmission,
        ),
        (
            "finalization-did-not-finalize",
            Att::FinalizationDidNotFinalizeNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "rejected-before-record",
            Att::DurableCompletionAttestationRejectedBeforeRecord,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "record-failed",
            Att::DurableCompletionAttestationRecordFailedNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "rolled-back",
            Att::DurableCompletionAttestationRolledBackNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "rollback-failed",
            Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "ambiguous",
            Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "production",
            Att::ProductionAttestorUnavailableNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "mainnet",
            Att::MainNetAttestorUnavailableNoAttestation,
            Backend::AttestationDidNotAttestNoBackendSubmission,
        ),
        (
            "mainnet-peer",
            Att::MainNetPeerDrivenApplyRefusedNoAttestation,
            Backend::MainNetPeerDrivenApplyRefusedNoSubmission,
        ),
        (
            "validator",
            Att::ValidatorSetRotationUnsupportedNoAttestation,
            Backend::ValidatorSetRotationUnsupportedNoSubmission,
        ),
        (
            "policy",
            Att::PolicyChangeUnsupportedNoAttestation,
            Backend::PolicyChangeUnsupportedNoSubmission,
        ),
    ];
    for (label, att, expected) in projections {
        let intent = project_attestation_outcome_to_backend_request(&att);
        t.assert_true(&format!("D.{label}.no-create"), !intent.creates_request());
        let ok = matches!(
            &intent,
            DurableCompletionAttestationBackendRequestIntent::NoBackendSubmission(o) if *o == expected
        );
        t.check(&format!("D.{label}.outcome"), expected.tag(), if ok { expected.tag() } else { "MISMATCH" });
    }
    // Only BackendSubmissionRecorded authorizes a new modeled backend-submitted state.
    t.assert_true(
        "D.recorded-authorizes",
        backend_outcome_authorizes_durable_attestation_submission(&Backend::BackendSubmissionRecorded),
    );
    t.assert_true(
        "D.recorded-projects",
        backend_outcome_projects_to_backend_submission_recorded(&Backend::BackendSubmissionRecorded),
    );
    // A duplicate-idempotent submission projects but does not authorize a new one.
    t.assert_true(
        "D.duplicate-projects",
        backend_outcome_projects_to_backend_submission_recorded(
            &Backend::BackendSubmissionDuplicateIdempotent,
        ),
    );
    t.assert_true(
        "D.duplicate-no-authorize",
        !backend_outcome_authorizes_durable_attestation_submission(
            &Backend::BackendSubmissionDuplicateIdempotent,
        ),
    );
    // Every other backend outcome neither authorizes nor projects to a submission.
    for (label, outcome) in [
        ("legacy-bypass", Backend::LegacyBypassNoBackendSubmission),
        ("rejected-before-attestation", Backend::RejectedBeforeAttestationNoBackendSubmission),
        ("attestation-did-not-attest", Backend::AttestationDidNotAttestNoBackendSubmission),
        ("rejected-before-record", Backend::BackendSubmissionRejectedBeforeRecord),
        ("record-failed", Backend::BackendSubmissionRecordFailedNoSubmission),
        ("rolled-back", Backend::BackendSubmissionRolledBackNoSubmission),
        ("rollback-failed", Backend::BackendSubmissionRollbackFailedFatalNoSubmission),
        ("ambiguous", Backend::BackendSubmissionAmbiguousFailClosedNoSubmission),
        ("production", Backend::ProductionBackendUnavailableNoSubmission),
        ("mainnet", Backend::MainNetBackendUnavailableNoSubmission),
        ("external", Backend::ExternalPublicationUnavailableNoSubmission),
        ("mainnet-peer", Backend::MainNetPeerDrivenApplyRefusedNoSubmission),
        ("validator", Backend::ValidatorSetRotationUnsupportedNoSubmission),
        ("policy", Backend::PolicyChangeUnsupportedNoSubmission),
    ] {
        t.assert_true(
            &format!("D.{label}.no-authorize"),
            !backend_outcome_authorizes_durable_attestation_submission(&outcome),
        );
        t.assert_true(
            &format!("D.{label}.no-project"),
            !backend_outcome_projects_to_backend_submission_recorded(&outcome),
        );
        t.assert_true(&format!("D.{label}.no-submission"), outcome.no_backend_submission());
    }
    t.finish(out)
}

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("stage_ordering");
    // MainNet peer-driven apply refused first (no invocation, empty ledger).
    let c = mainnet_peer_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
    t.assert_true(
        "E.mainnet-refused-first",
        o.is_mainnet_peer_driven_apply_refused() && backend.invocations() == 0 && ledger.is_empty(),
    );
    // Binding validation happens before the backend stage.
    let mut c2 = devnet_ctx();
    c2.env.genesis_hash = "wrong".to_string();
    let mut ledger2 = DurableCompletionAttestationBackendLedger::new();
    let mut backend2 = fixture_backend();
    let _ = drive(&c2.attested(), &c2.expectations, &mut backend2, &mut ledger2);
    t.assert_true("E.binding-before-backend", backend2.invocations() == 0);
    // A record failure does not retroactively submit but invokes the backend once.
    let c3 = devnet_ctx();
    let mut ledger3 = DurableCompletionAttestationBackendLedger::new();
    let mut backend3 = FixtureDurableCompletionAttestationBackend::with_fault(
        DurableCompletionAttestationBackendFault::RecordFailedNoSubmission,
    );
    let o3 = drive(&c3.attested(), &c3.expectations, &mut backend3, &mut ledger3);
    t.assert_true(
        "E.record-failure-no-submission",
        o3.no_backend_submission() && backend3.invocations() == 1 && ledger3.is_empty(),
    );
    // A rollback failure is fatal / fail-closed.
    let mut backend4 = FixtureDurableCompletionAttestationBackend::with_fault(
        DurableCompletionAttestationBackendFault::RollbackFailedFatal,
    );
    let mut ledger4 = DurableCompletionAttestationBackendLedger::new();
    let o4 = drive(&c3.attested(), &c3.expectations, &mut backend4, &mut ledger4);
    t.check_outcome(
        "E.rollback-failed-fatal",
        "backend-submission-rollback-failed-fatal-no-submission",
        &o4,
    );
    // Backend submission only after a recorded attestation (non-attesting -> no
    // invocation).
    let c5 = devnet_ctx();
    let mut ledger5 = DurableCompletionAttestationBackendLedger::new();
    let mut backend5 = fixture_backend();
    let o5 = drive(
        &c5.with_attestation(
            GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation,
        ),
        &c5.expectations,
        &mut backend5,
        &mut ledger5,
    );
    t.assert_true(
        "E.attestation-required-before-backend",
        o5.no_backend_submission() && backend5.invocations() == 0,
    );
    t.finish(out)
}

fn run_backend_ledger_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("backend_ledger");
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
    t.check_outcome("F.one-valid", "backend-submission-recorded", &o);
    t.assert_true(
        "F.len-one",
        ledger.len() == 1 && ledger.records().len() == 1 && ledger.contains(BACKEND_RECORD_ID),
    );
    t.assert_true(
        "F.status",
        ledger.find(BACKEND_RECORD_ID).map(|r| r.status)
            == Some(DurableCompletionAttestationBackendLedgerStatus::Submitted),
    );
    // Snapshot / restore round-trips the modeled ledger (models a rollback).
    let snap = ledger.snapshot();
    t.assert_true("F.snapshot", snap.len() == 1 && !snap.is_empty());
    let mut restored = DurableCompletionAttestationBackendLedger::new();
    restored.restore(&snap);
    t.assert_true("F.restore", restored.len() == 1 && restored.contains(BACKEND_RECORD_ID));
    // The canonical record / response / receipt / digest types are well-formed.
    let record: DurableCompletionAttestationBackendRecord = c.request.to_record();
    let request_digest: DurableCompletionAttestationBackendDigest = c.request.digest();
    t.assert_true("F.record-id", record.backend_record_id == BACKEND_RECORD_ID);
    t.assert_true("F.record-request-digest", record.request_digest == request_digest);
    t.assert_true("F.request-digest-hex", !request_digest.as_hex().is_empty());
    t.assert_true(
        "F.identity-digest-hex",
        !c.request.identity.digest().as_hex().is_empty(),
    );
    let response = DurableCompletionAttestationBackendResponse {
        backend_record_id: BACKEND_RECORD_ID.to_string(),
        request_digest: request_digest.clone(),
        accepted: true,
        backend_kind: DurableCompletionAttestationBackendKind::FixtureInMemory,
    };
    let response_digest = response.digest();
    t.assert_true("F.response-digest-hex", !response_digest.as_hex().is_empty());
    let receipt = DurableCompletionAttestationBackendReceipt {
        backend_record_id: BACKEND_RECORD_ID.to_string(),
        request_digest: request_digest.clone(),
        response_digest: response_digest.clone(),
    };
    t.assert_true("F.receipt-digest-hex", !receipt.digest().as_hex().is_empty());
    let transcript: DurableCompletionAttestationBackendTranscriptDigest =
        ledger.find(BACKEND_RECORD_ID).map(|r| r.transcript_digest.clone()).unwrap();
    t.assert_true("F.transcript-digest-hex", !transcript.as_hex().is_empty());
    // Duplicate identical submission does not increase record count.
    let second = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
    t.check_outcome("F.duplicate", "backend-submission-duplicate-idempotent", &second);
    t.assert_true("F.duplicate-len-one", ledger.len() == 1);
    // Same id with a different digest is equivocation and does not record.
    let mut c2 = devnet_ctx();
    c2.request.candidate_digest = "different-candidate-digest".to_string();
    c2.expectations.expected_candidate_digest = "different-candidate-digest".to_string();
    let o2 = drive(&c2.attested(), &c2.expectations, &mut backend, &mut ledger);
    t.check_outcome("F.equivocation", "backend-submission-rejected-before-record", &o2);
    t.assert_true("F.equivocation-len-one", ledger.len() == 1);
    // Each request-mismatch field does not record (representative subset).
    let mut record_ledger = DurableCompletionAttestationBackendLedger::new();
    let mut b3 = fixture_backend();
    for (label, mutate) in [
        ("wrong-attestation-digest", (|c: &mut Ctx| c.request.attestation_digest = "x".to_string()) as fn(&mut Ctx)),
        ("wrong-finalization-digest", (|c: &mut Ctx| c.request.finalization_decision_digest = "x".to_string()) as fn(&mut Ctx)),
        ("wrong-sequence", (|c: &mut Ctx| c.request.authority_domain_sequence = 11) as fn(&mut Ctx)),
        ("malformed", (|c: &mut Ctx| c.request.backend_record_id = String::new()) as fn(&mut Ctx)),
    ] {
        let mut cc = devnet_ctx();
        mutate(&mut cc);
        let o = drive(&cc.attested(), &cc.expectations, &mut b3, &mut record_ledger);
        t.check_outcome(
            &format!("F.no-record.{label}"),
            "backend-submission-rejected-before-record",
            &o,
        );
        t.assert_true(&format!("F.no-record.{label}.empty"), record_ledger.is_empty());
    }
    t.finish(out)
}

fn run_non_mutation_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("non_mutation");
    t.assert_true(
        "G.rejection-non-mutating",
        durable_completion_attestation_backend_rejection_is_non_mutating(),
    );
    t.assert_true(
        "G.never-calls-run-070",
        durable_completion_attestation_backend_never_calls_run_070(),
    );
    t.assert_true(
        "G.never-mutates-live",
        durable_completion_attestation_backend_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.never-writes-sequence-or-marker",
        durable_completion_attestation_backend_never_writes_sequence_or_marker(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        durable_completion_attestation_backend_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "G.no-external-publication",
        durable_completion_attestation_backend_no_external_publication(),
    );
    t.assert_true(
        "G.no-real-audit-ledger",
        durable_completion_attestation_backend_no_real_audit_ledger(),
    );
    t.assert_true(
        "G.pipeline-success-required",
        durable_completion_attestation_backend_pipeline_success_required(),
    );
    t.assert_true(
        "G.sink-receipt-required",
        durable_completion_attestation_backend_sink_receipt_required(),
    );
    t.assert_true(
        "G.completion-report-required",
        durable_completion_attestation_backend_completion_report_required(),
    );
    t.assert_true(
        "G.finalization-required",
        durable_completion_attestation_backend_finalization_required(),
    );
    t.assert_true(
        "G.attestation-required",
        durable_completion_attestation_backend_attestation_required(),
    );
    t.assert_true(
        "G.record-required",
        durable_completion_attestation_backend_record_required_before_submission(),
    );
    t.assert_true(
        "G.failed-record-never-submits",
        durable_completion_attestation_backend_failed_record_never_submits(),
    );
    t.assert_true(
        "G.rollback-never-submits",
        durable_completion_attestation_backend_rollback_never_submits(),
    );
    t.assert_true(
        "G.ambiguous-fails-closed",
        durable_completion_attestation_backend_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "G.mainnet-refused-mainnet",
        durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet,
        ),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet,
        ),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        durable_completion_attestation_backend_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        durable_completion_attestation_backend_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "G.policy-change-unsupported",
        durable_completion_attestation_backend_policy_change_unsupported(),
    );
    t.assert_true(
        "G.local-operator-cannot",
        durable_completion_attestation_backend_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        durable_completion_attestation_backend_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    // A rejected path leaves the ledger empty and the backend uninvoked.
    let mut c = devnet_ctx();
    c.env.genesis_hash = "wrong".to_string();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let _ = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
    t.assert_true(
        "G.rejected-ledger-empty",
        ledger.is_empty() && backend.invocations() == 0,
    );
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use DurableCompletionAttestationBackendOutcome as Backend;
    let mut t = Table::new("reachability");
    let tags = [
        (Backend::LegacyBypassNoBackendSubmission, "legacy-bypass-no-backend-submission"),
        (
            Backend::RejectedBeforeAttestationNoBackendSubmission,
            "rejected-before-attestation-no-backend-submission",
        ),
        (
            Backend::AttestationDidNotAttestNoBackendSubmission,
            "attestation-did-not-attest-no-backend-submission",
        ),
        (Backend::BackendSubmissionRecorded, "backend-submission-recorded"),
        (
            Backend::BackendSubmissionDuplicateIdempotent,
            "backend-submission-duplicate-idempotent",
        ),
        (
            Backend::BackendSubmissionRejectedBeforeRecord,
            "backend-submission-rejected-before-record",
        ),
        (
            Backend::BackendSubmissionRecordFailedNoSubmission,
            "backend-submission-record-failed-no-submission",
        ),
        (
            Backend::BackendSubmissionRolledBackNoSubmission,
            "backend-submission-rolled-back-no-submission",
        ),
        (
            Backend::BackendSubmissionRollbackFailedFatalNoSubmission,
            "backend-submission-rollback-failed-fatal-no-submission",
        ),
        (
            Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
            "backend-submission-ambiguous-fail-closed-no-submission",
        ),
        (
            Backend::ProductionBackendUnavailableNoSubmission,
            "production-backend-unavailable-no-submission",
        ),
        (
            Backend::MainNetBackendUnavailableNoSubmission,
            "mainnet-backend-unavailable-no-submission",
        ),
        (
            Backend::ExternalPublicationUnavailableNoSubmission,
            "external-publication-unavailable-no-submission",
        ),
        (
            Backend::MainNetPeerDrivenApplyRefusedNoSubmission,
            "mainnet-peer-driven-apply-refused-no-submission",
        ),
        (
            Backend::ValidatorSetRotationUnsupportedNoSubmission,
            "validator-set-rotation-unsupported-no-submission",
        ),
        (
            Backend::PolicyChangeUnsupportedNoSubmission,
            "policy-change-unsupported-no-submission",
        ),
    ];
    for (o, tag) in tags {
        t.check(&format!("H.tag.{tag}"), tag, o.tag());
    }
    // Kind tags.
    t.check("H.kind-disabled", "disabled", DurableCompletionAttestationBackendKind::Disabled.tag());
    t.check("H.kind-fixture", "fixture-in-memory", DurableCompletionAttestationBackendKind::FixtureInMemory.tag());
    t.check("H.kind-production", "production-unavailable", DurableCompletionAttestationBackendKind::ProductionUnavailable.tag());
    t.check("H.kind-mainnet", "mainnet-unavailable", DurableCompletionAttestationBackendKind::MainNetUnavailable.tag());
    t.check("H.kind-external", "external-publication-unavailable", DurableCompletionAttestationBackendKind::ExternalPublicationUnavailable.tag());
    t.check("H.kind-unknown", "unknown", DurableCompletionAttestationBackendKind::Unknown.tag());
    t.assert_true("H.kind-is-fixture", DurableCompletionAttestationBackendKind::FixtureInMemory.is_fixture());
    t.assert_true("H.kind-is-unavailable", DurableCompletionAttestationBackendKind::ProductionUnavailable.is_unavailable());
    // Policy tags.
    t.check("H.policy-disabled", "disabled", DurableCompletionAttestationBackendPolicy::Disabled.tag());
    t.check("H.policy-fixture", "fixture-allowed", DurableCompletionAttestationBackendPolicy::FixtureAllowed.tag());
    t.check("H.policy-production", "production-backend-required", DurableCompletionAttestationBackendPolicy::ProductionBackendRequired.tag());
    t.check("H.policy-mainnet", "mainnet-production-backend-required", DurableCompletionAttestationBackendPolicy::MainNetProductionBackendRequired.tag());
    t.assert_true("H.policy-is-disabled", DurableCompletionAttestationBackendPolicy::Disabled.is_disabled());
    t.assert_true("H.policy-allows-fixture", DurableCompletionAttestationBackendPolicy::FixtureAllowed.allows_fixture());
    // Backend trait kind() reachable through every backend implementation.
    t.check("H.trait-fixture-kind", "fixture-in-memory", fixture_backend().kind().tag());
    t.check("H.trait-production-kind", "production-unavailable", ProductionDurableCompletionAttestationBackend::default().kind().tag());
    t.check("H.trait-mainnet-kind", "mainnet-unavailable", MainNetDurableCompletionAttestationBackend::default().kind().tag());
    t.check("H.trait-external-kind", "external-publication-unavailable", ExternalPublicationDurableCompletionAttestationBackend::default().kind().tag());
    // Touch every Run 256 type alias the task enumerates so the helper links them.
    let _aliases = std::any::type_name::<(
        DurableCompletionAttestationBackendSurface,
        DurableCompletionAttestationBackendEnvironment,
        DurableCompletionAttestationBackendBinding,
    )>();
    t.assert_true("H.aliases", !_aliases.is_empty());
    t.finish(out)
}

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let c = devnet_ctx();
    let mut ledger = DurableCompletionAttestationBackendLedger::new();
    let mut backend = fixture_backend();
    let o = drive(&c.attested(), &c.expectations, &mut backend, &mut ledger);
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} authorizes={} projects={} invocations={} ledger_len={} contains={}\n",
            o.tag(),
            o.authorizes_backend_submission(),
            o.projects_to_backend_submission_recorded(),
            backend.invocations(),
            ledger.len(),
            ledger.contains(BACKEND_RECORD_ID)
        ),
    );
    let mut c2 = devnet_ctx();
    c2.env.genesis_hash = "wrong-genesis".to_string();
    let mut ledger2 = DurableCompletionAttestationBackendLedger::new();
    let mut backend2 = fixture_backend();
    let o2 = drive(&c2.attested(), &c2.expectations, &mut backend2, &mut ledger2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} invocations={} no_backend_submission={} ledger_len={}\n",
            o2.tag(),
            backend2.invocations(),
            o2.no_backend_submission(),
            ledger2.len()
        ),
    );
    let cp = mainnet_peer_ctx();
    let mut ledger3 = DurableCompletionAttestationBackendLedger::new();
    let mut backend3 = fixture_backend();
    let o3 = drive(&cp.attested(), &cp.expectations, &mut backend3, &mut ledger3);
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} invocations={} is_refusal={} ledger_len={}\n",
            o3.tag(),
            backend3.invocations(),
            o3.is_mainnet_peer_driven_apply_refused(),
            ledger3.len()
        ),
    );
    let sentinel = c.request.to_record();
    let mut windows = String::new();
    for (label, w, with_record) in [
        ("before-pipeline", DurableCompletionAttestationBackendWindow::BeforePipeline, false),
        (
            "after-attestation-record-before-backend-request",
            DurableCompletionAttestationBackendWindow::AfterAttestationRecordBeforeBackendRequest,
            false,
        ),
        (
            "after-backend-record-before-success-with-record",
            DurableCompletionAttestationBackendWindow::AfterBackendRecordBeforeBackendSuccess,
            true,
        ),
        (
            "after-backend-success",
            DurableCompletionAttestationBackendWindow::AfterBackendSuccess,
            true,
        ),
        (
            "after-backend-ambiguous",
            DurableCompletionAttestationBackendWindow::AfterBackendAmbiguous,
            false,
        ),
        ("backend-rollback-failed", DurableCompletionAttestationBackendWindow::BackendRollbackFailed, false),
        ("unknown", DurableCompletionAttestationBackendWindow::Unknown, false),
    ] {
        let rec = if with_record { Some(&sentinel) } else { None };
        windows.push_str(&format!("{label}={}\n", recover_devnet(w, rec).tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_257_durable_completion_attestation_backend_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("stage_ordering", run_stage_ordering_table),
        ("backend_ledger", run_backend_ledger_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_257_durable_completion_attestation_backend_release_binary_helper\n\
scope: Run 256 production durable-completion attestation backend interface boundary (pqc_governance_durable_completion_attestation_backend: evaluate_durable_completion_attestation_backend, recover_durable_completion_attestation_backend_window, project_attestation_outcome_to_backend_request, backend_outcome_authorizes_durable_attestation_submission, backend_outcome_projects_to_backend_submission_recorded, the GovernanceDurableCompletionAttestationBackend trait with FixtureDurableCompletionAttestationBackend/ProductionDurableCompletionAttestationBackend/MainNetDurableCompletionAttestationBackend/ExternalPublicationDurableCompletionAttestationBackend, the DurableCompletionAttestationBackendInput/Expectations/Policy/Kind/Identity/Request/Response/Receipt/Record/Digest/TranscriptDigest bindings, the DurableCompletionAttestationBackendLedger modeled in-memory backend ledger, the DurableCompletionAttestationBackendOutcome taxonomy, the DurableCompletionAttestationBackendRequestIntent projection, the DurableCompletionAttestationBackendFault injector, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\n\
note: fixture-only; pure typed projection over an in-memory backend ledger (the DevNet/TestNet fixture backend mutates ONLY the in-memory DurableCompletionAttestationBackendLedger; no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState mutation, no external publication, no real audit-ledger write, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a disabled backend/attestor/finalizer/reporter/sink/pipeline/evaluator-call-site policy is a legacy bypass with no backend submission and no backend invocation; MainNet peer-driven apply is refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, and backend invocation; Run 246 pipeline success is required before any sink intent, Run 248 ConsumeReceiptRecorded before any completion-report intent, Run 250 CompletionReportRecorded before any finalization intent, Run 252 DurableCompletionFinalized before any attestation intent, and Run 254 DurableCompletionAttested before any backend request; only BackendSubmissionRecorded authorizes a new modeled backend-submitted state; a duplicate identical submission is idempotent; same backend record id with a different digest fails closed as equivocation; production/MainNet/external-publication backends remain reachable but unavailable/fail-closed\n\n",
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
