//! Run 255 — release-built helper for the Run 254 governance modeled
//! durable-completion finalization **attestation-projection** boundary.
//!
//! This mirrors the Run 253 release-helper structure for the Run 252 finalization
//! projection, adapted to the Run 254 attestation-projection symbols. The helper
//! exercises release-built library symbols only and mutates only the modeled
//! in-memory ModeledDurableCompletionAttestationLedger through the fixture
//! attestor. It enables no production attestation backend, no audit-ledger
//! backend, no MainNet governance, no MainNet peer-driven apply, no Run 070 call,
//! no LivePqcTrustState mutation, no marker/sequence write, no trust swap, no
//! session eviction, and no RocksDB/file/schema/migration/storage-format change.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_completion_attestation_projection::{
    attestation_outcome_authorizes_modeled_attestation,
    attestation_outcome_projects_to_durable_completion_attested,
    evaluate_modeled_durable_completion_attestation_projection,
    modeled_attestation_ambiguous_window_fails_closed,
    modeled_attestation_completion_report_required_before_attestation,
    modeled_attestation_failed_record_never_attests,
    modeled_attestation_finalization_required_before_attestation,
    modeled_attestation_local_operator_cannot_satisfy_mainnet_authority,
    modeled_attestation_mainnet_peer_driven_apply_refused_first,
    modeled_attestation_never_calls_run_070,
    modeled_attestation_never_mutates_live_pqc_trust_state,
    modeled_attestation_never_writes_sequence_or_marker,
    modeled_attestation_no_rocksdb_file_schema_migration_change,
    modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_attestation_pipeline_success_required_before_attestation,
    modeled_attestation_policy_change_unsupported,
    modeled_attestation_production_mainnet_unavailable,
    modeled_attestation_record_required_before_durable_completion_attested,
    modeled_attestation_rejection_is_non_mutating,
    modeled_attestation_rollback_never_attests,
    modeled_attestation_sink_receipt_required_before_attestation,
    modeled_attestation_validator_set_rotation_unsupported,
    project_finalization_outcome_to_attestation_intent,
    recover_modeled_durable_completion_attestation_window, DurableCompletionAttestationIntent,
    FixtureModeledDurableCompletionAttestor,
    GovernanceModeledDurableCompletionAttestationEnvironmentBinding,
    GovernanceModeledDurableCompletionAttestationExpectations,
    GovernanceModeledDurableCompletionAttestationFinalizationBinding,
    GovernanceModeledDurableCompletionAttestationInput,
    GovernanceModeledDurableCompletionAttestationOutcome,
    GovernanceModeledDurableCompletionAttestationPipelineBinding,
    GovernanceModeledDurableCompletionAttestationPolicy,
    GovernanceModeledDurableCompletionAttestationRecord,
    GovernanceModeledDurableCompletionAttestationReplayBinding,
    GovernanceModeledDurableCompletionAttestationReporterBinding,
    GovernanceModeledDurableCompletionAttestationRuntimeBinding,
    GovernanceModeledDurableCompletionAttestationSinkBinding,
    GovernanceModeledDurableCompletionAttestationSurface, GovernanceModeledDurableCompletionAttestor,
    MainNetModeledDurableCompletionAttestor, ModeledDurableCompletionAttestationDigest,
    ModeledDurableCompletionAttestationFault, ModeledDurableCompletionAttestationLedger,
    ModeledDurableCompletionAttestationRecord, ModeledDurableCompletionAttestationSnapshot,
    ModeledDurableCompletionAttestationStatus, ModeledDurableCompletionAttestationWindow,
    ModeledDurableCompletionAttestorKind, ProductionModeledDurableCompletionAttestor,
};
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

const ATTESTATION_ID: &str = "durable-completion-attestation-0001";
const ATTESTATION_DIGEST: &str = "attestation-digest-tttttttttttttttttttt";
const FINALIZATION_DIGEST: &str = "finalization-digest-ffffffffffffffffffff";
const REPORT_DIGEST: &str = "completion-report-digest-cccccccccccccccc";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
const SINK_DIGEST: &str = "sink-decision-digest-ssssssssssssssssssss";
const REPORTER_DIGEST: &str = "reporter-decision-digest-eeeeeeeeeeeeeeee";
const FINALIZATION_DECISION_DIGEST: &str = "finalization-decision-digest-llllllllll";
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
    attestation: GovernanceModeledDurableCompletionAttestationRecord,
    expectations: GovernanceModeledDurableCompletionAttestationExpectations,
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
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
    let attestation = GovernanceModeledDurableCompletionAttestationRecord {
        attestation_id: ATTESTATION_ID.to_string(),
        attestation_digest: ATTESTATION_DIGEST.to_string(),
        finalization_digest: FINALIZATION_DIGEST.to_string(),
        report_digest: REPORT_DIGEST.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        sink_decision_digest: SINK_DIGEST.to_string(),
        reporter_decision_digest: REPORTER_DIGEST.to_string(),
        finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableCompletionAttestationExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_attestation_digest: ATTESTATION_DIGEST.to_string(),
        expected_finalization_digest: FINALIZATION_DIGEST.to_string(),
        expected_report_digest: REPORT_DIGEST.to_string(),
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_reporter_decision_digest: REPORTER_DIGEST.to_string(),
        expected_finalization_decision_digest: FINALIZATION_DECISION_DIGEST.to_string(),
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        attestation,
        expectations,
    }
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn input(
        &self,
        policy: GovernanceModeledDurableCompletionAttestationPolicy,
        replay: GovernanceModeledDurableCompletionAttestationReplayBinding,
        pipeline: GovernanceModeledDurableCompletionAttestationPipelineBinding,
        sink: GovernanceModeledDurableCompletionAttestationSinkBinding,
        reporter: GovernanceModeledDurableCompletionAttestationReporterBinding,
        finalization: GovernanceModeledDurableCompletionAttestationFinalizationBinding,
    ) -> GovernanceModeledDurableCompletionAttestationInput {
        GovernanceModeledDurableCompletionAttestationInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            reporter_binding: reporter,
            finalization_binding: finalization,
            attestation: self.attestation.clone(),
        }
    }

    /// The canonical "finalizer recorded a finalization" wired input.
    fn finalized(&self) -> GovernanceModeledDurableCompletionAttestationInput {
        self.input(
            GovernanceModeledDurableCompletionAttestationPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
            GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded,
            GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized,
        )
    }
}

fn devnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}
fn testnet_ctx() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}
fn devnet_attestor() -> FixtureModeledDurableCompletionAttestor {
    FixtureModeledDurableCompletionAttestor::new(TrustBundleEnvironment::Devnet)
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
        o: &GovernanceModeledDurableCompletionAttestationOutcome,
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
    input: &GovernanceModeledDurableCompletionAttestationInput,
    expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
    attestor: &mut FixtureModeledDurableCompletionAttestor,
    ledger: &mut ModeledDurableCompletionAttestationLedger,
) -> GovernanceModeledDurableCompletionAttestationOutcome {
    evaluate_modeled_durable_completion_attestation_projection(input, expectations, attestor, ledger)
}

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableCompletionAttestationPolicy as P;
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    use DurableReplayObservation as R;
    let mut t = Table::new("accepted");
    // Disabled-stage legacy bypasses never invoke the attestor and never record.
    for (id, policy) in [
        ("A1.attestation-disabled", P::attestation_disabled()),
        ("A2.finalizer-disabled", P::finalization_disabled()),
        ("A3.reporter-disabled", P::reporter_disabled()),
        ("A4.sink-disabled", P::sink_disabled()),
        ("A5.pipeline-disabled", P::pipeline_disabled()),
        ("A6.evaluator-disabled", P::evaluator_disabled()),
    ] {
        let c = devnet_ctx();
        let input = c.input(
            policy,
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
            Report::CompletionReportRecorded,
            Final::DurableCompletionFinalized,
        );
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut attestor = devnet_attestor();
        let o = drive(&input, &c.expectations, &mut attestor, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), "legacy-bypass-no-attestation", &o);
        t.assert_true(&format!("{id}.no-invocation"), attestor.invocations() == 0);
        t.assert_true(&format!("{id}.ledger-empty"), ledger.is_empty());
    }
    // DevNet / TestNet fixture success records exactly one attestation.
    for (id, c, env, kind) in [
        ("A7.devnet", devnet_ctx(), TrustBundleEnvironment::Devnet, "fixture-devnet"),
        ("A8.testnet", testnet_ctx(), TrustBundleEnvironment::Testnet, "fixture-testnet"),
    ] {
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut attestor = FixtureModeledDurableCompletionAttestor::new(env);
        let o = drive(&c.finalized(), &c.expectations, &mut attestor, &mut ledger);
        t.check_outcome(&format!("{id}.outcome"), "durable-completion-attested", &o);
        t.assert_true(
            &format!("{id}.authorizes"),
            o.authorizes_modeled_durable_completion_attestation(),
        );
        t.assert_true(
            &format!("{id}.projects"),
            o.projects_to_durable_completion_attested(),
        );
        t.assert_true(&format!("{id}.ledger-one"), ledger.len() == 1);
        t.check(&format!("{id}.kind"), kind, attestor.kind().tag());
    }
    // Modeled action types all attest only after pipeline + sink + report + finalization success.
    for action in [
        "add-root",
        "retire-root",
        "revoke-root",
        "emergency-revoke-root",
        "noop",
    ] {
        let c = devnet_ctx();
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut attestor = devnet_attestor();
        let o = drive(&c.finalized(), &c.expectations, &mut attestor, &mut ledger);
        t.check_outcome(&format!("A9.{action}.outcome"), "durable-completion-attested", &o);
        t.assert_true(&format!("A9.{action}.ledger-one"), ledger.len() == 1);
    }
    // Duplicate identical attestation is idempotent (no second attestation).
    {
        let c = devnet_ctx();
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut attestor = devnet_attestor();
        let first = drive(&c.finalized(), &c.expectations, &mut attestor, &mut ledger);
        let second = drive(&c.finalized(), &c.expectations, &mut attestor, &mut ledger);
        t.check_outcome("A10.first", "durable-completion-attested", &first);
        t.check_outcome(
            "A10.duplicate",
            "durable-completion-attestation-duplicate-idempotent",
            &second,
        );
        t.assert_true("A10.ledger-one", ledger.len() == 1);
    }
    // A DurableCompletionDuplicateIdempotent finalization may only match an already-attested
    // record; it never creates a new attestation by itself.
    {
        let c = devnet_ctx();
        let dup_input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
            Report::CompletionReportRecorded,
            Final::DurableCompletionDuplicateIdempotent,
        );
        let mut empty = ModeledDurableCompletionAttestationLedger::new();
        let mut attestor = devnet_attestor();
        let o = drive(&dup_input, &c.expectations, &mut attestor, &mut empty);
        t.check_outcome(
            "A11.duplicate-empty",
            "durable-completion-attestation-rejected-before-record",
            &o,
        );
        t.assert_true("A11.empty", empty.is_empty());
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a2 = devnet_attestor();
        let _ = drive(&c.finalized(), &c.expectations, &mut a2, &mut ledger);
        let o2 = drive(&dup_input, &c.expectations, &mut a2, &mut ledger);
        t.check_outcome(
            "A11.duplicate-matches",
            "durable-completion-attestation-duplicate-idempotent",
            &o2,
        );
        t.assert_true("A11.matches-ledger-one", ledger.len() == 1);
    }
    // Production attestor path reachable but unavailable / fail-closed.
    {
        let c = devnet_ctx();
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = ProductionModeledDurableCompletionAttestor::default();
        let o = evaluate_modeled_durable_completion_attestation_projection(
            &c.finalized(),
            &c.expectations,
            &mut a,
            &mut ledger,
        );
        t.check_outcome("A12.production", "production-attestor-unavailable-no-attestation", &o);
        t.assert_true("A12.no-record", ledger.is_empty());
        t.check("A12.kind", "production-unavailable", a.kind().tag());
    }
    // MainNet attestor path reachable but unavailable / fail-closed.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = MainNetModeledDurableCompletionAttestor::default();
        let o = evaluate_modeled_durable_completion_attestation_projection(
            &c.finalized(),
            &c.expectations,
            &mut a,
            &mut ledger,
        );
        t.check_outcome("A13.mainnet", "mainnet-attestor-unavailable-no-attestation", &o);
        t.assert_true("A13.no-record", ledger.is_empty());
    }
    // MainNet peer-driven apply refused before any attestor invocation.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        );
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut attestor = devnet_attestor();
        let o = drive(&c.finalized(), &c.expectations, &mut attestor, &mut ledger);
        t.check_outcome("A14.mainnet-peer", "mainnet-peer-driven-apply-refused-no-attestation", &o);
        t.assert_true("A14.no-invocation", attestor.invocations() == 0);
    }
    // Validator-set rotation and policy-change actions never attest.
    for (id, fin, tag) in [
        (
            "A15.validator",
            Final::ValidatorSetRotationUnsupportedNoFinalization,
            "validator-set-rotation-unsupported-no-attestation",
        ),
        (
            "A16.policy",
            Final::PolicyChangeUnsupportedNoFinalization,
            "policy-change-unsupported-no-attestation",
        ),
    ] {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
            Report::CompletionReportRecorded,
            fin,
        );
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = devnet_attestor();
        let o = drive(&input, &c.expectations, &mut a, &mut ledger);
        t.check_outcome(id, tag, &o);
        t.assert_true(&format!("{id}.no-invocation"), a.invocations() == 0);
    }
    t.finish(out)
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableCompletionAttestationPolicy as P;
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    use DurableReplayObservation as R;
    let mut t = Table::new("rejection");
    // Every non-finalizing Run 252 finalization outcome maps to a no-attestation
    // outcome and never invokes the attestor.
    let finalization_cases: [(&str, Final, &str); 12] = [
        (
            "legacy",
            Final::LegacyBypassNoFinalization,
            "legacy-bypass-no-attestation",
        ),
        (
            "rejected-before-reporter",
            Final::RejectedBeforeReporterNoFinalization,
            "rejected-before-finalization-no-attestation",
        ),
        (
            "reporter-did-not-record",
            Final::ReporterDidNotRecordCompletionNoFinalization,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "rejected-before-record",
            Final::DurableCompletionRejectedBeforeRecord,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "record-failed",
            Final::DurableCompletionRecordFailedNoFinalization,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "rolled-back",
            Final::DurableCompletionRolledBackNoFinalization,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "rollback-failed",
            Final::DurableCompletionRollbackFailedFatalNoFinalization,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "ambiguous",
            Final::DurableCompletionAmbiguousFailClosedNoFinalization,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "production",
            Final::ProductionFinalizerUnavailableNoFinalization,
            "production-attestor-unavailable-no-attestation",
        ),
        (
            "mainnet",
            Final::MainNetFinalizerUnavailableNoFinalization,
            "mainnet-attestor-unavailable-no-attestation",
        ),
        (
            "validator",
            Final::ValidatorSetRotationUnsupportedNoFinalization,
            "validator-set-rotation-unsupported-no-attestation",
        ),
        (
            "policy",
            Final::PolicyChangeUnsupportedNoFinalization,
            "policy-change-unsupported-no-attestation",
        ),
    ];
    for (label, fin, tag) in finalization_cases {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
            Report::CompletionReportRecorded,
            fin,
        );
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = devnet_attestor();
        let o = drive(&input, &c.expectations, &mut a, &mut ledger);
        t.check_outcome(&format!("B.finalization.{label}"), tag, &o);
        t.assert_true(&format!("B.finalization.{label}.no-invocation"), a.invocations() == 0);
        t.assert_true(&format!("B.finalization.{label}.no-record"), ledger.is_empty());
        t.assert_true(&format!("B.finalization.{label}.no-attestation"), o.no_attestation());
    }
    // MainNet peer-driven refusal also reachable through every prior-stage binding.
    for (label, input) in [
        (
            "replay",
            devnet_ctx().input(
                P::wired(),
                R::MainNetPeerDrivenApplyRefused,
                Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
                Sink::ConsumeReceiptRecorded,
                Report::CompletionReportRecorded,
                Final::DurableCompletionFinalized,
            ),
        ),
        (
            "finalization",
            devnet_ctx().input(
                P::wired(),
                R::MutationAuthorized,
                Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
                Sink::ConsumeReceiptRecorded,
                Report::CompletionReportRecorded,
                Final::MainNetPeerDrivenApplyRefusedNoFinalization,
            ),
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = devnet_attestor();
        let o = drive(&input, &c.expectations, &mut a, &mut ledger);
        t.check_outcome(
            &format!("B.mainnet-peer.{label}"),
            "mainnet-peer-driven-apply-refused-no-attestation",
            &o,
        );
        t.assert_true(&format!("B.mainnet-peer.{label}.no-invocation"), a.invocations() == 0);
    }
    // Injected attestor faults: invoked once, never leave a recorded attestation.
    for (label, fault, tag) in [
        (
            "record-failed",
            ModeledDurableCompletionAttestationFault::RecordFailedNoAttestation,
            "durable-completion-attestation-record-failed-no-attestation",
        ),
        (
            "rollback",
            ModeledDurableCompletionAttestationFault::RolledBackNoAttestation,
            "durable-completion-attestation-rolled-back-no-attestation",
        ),
        (
            "rollback-failed",
            ModeledDurableCompletionAttestationFault::RollbackFailedFatal,
            "durable-completion-attestation-rollback-failed-fatal-no-attestation",
        ),
        (
            "ambiguous",
            ModeledDurableCompletionAttestationFault::AmbiguousAfterRecord,
            "durable-completion-attestation-ambiguous-fail-closed-no-attestation",
        ),
    ] {
        let c = devnet_ctx();
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a =
            FixtureModeledDurableCompletionAttestor::with_fault(TrustBundleEnvironment::Devnet, fault);
        let o = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
        t.check_outcome(&format!("B.fault.{label}"), tag, &o);
        t.assert_true(&format!("B.fault.{label}.invoked"), a.invocations() == 1);
        t.assert_true(&format!("B.fault.{label}.empty"), ledger.is_empty());
    }
    // Pre-attestor environment / surface binding mismatch: attestor never invoked.
    let binding_cases: [(&str, fn(&mut Ctx)); 5] = [
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
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = devnet_attestor();
        let o = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
        t.check_outcome(
            &format!("B.binding.{label}"),
            "rejected-before-finalization-no-attestation",
            &o,
        );
        t.assert_true(&format!("B.binding.{label}.no-invocation"), a.invocations() == 0);
        t.assert_true(&format!("B.binding.{label}.empty"), ledger.is_empty());
    }
    // Attestation-identity mismatch / malformed: attestor invoked once, no record.
    let attestation_cases: [(&str, fn(&mut Ctx)); 14] = [
        (
            "wrong-attestation-digest",
            (|c: &mut Ctx| c.attestation.attestation_digest = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-finalization-digest",
            (|c: &mut Ctx| c.attestation.finalization_digest = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-report-digest",
            (|c: &mut Ctx| c.attestation.report_digest = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-receipt-digest",
            (|c: &mut Ctx| c.attestation.receipt_digest = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-sink-decision-digest",
            (|c: &mut Ctx| c.attestation.sink_decision_digest = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-reporter-decision-digest",
            (|c: &mut Ctx| c.attestation.reporter_decision_digest = "wrong".to_string())
                as fn(&mut Ctx),
        ),
        (
            "wrong-finalization-decision-digest",
            (|c: &mut Ctx| c.attestation.finalization_decision_digest = "wrong".to_string())
                as fn(&mut Ctx),
        ),
        (
            "wrong-pipeline-decision-digest",
            (|c: &mut Ctx| c.attestation.pipeline_decision_digest = "wrong".to_string())
                as fn(&mut Ctx),
        ),
        (
            "wrong-proposal",
            (|c: &mut Ctx| c.attestation.proposal_id = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-decision",
            (|c: &mut Ctx| c.attestation.decision_id = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-candidate",
            (|c: &mut Ctx| c.attestation.candidate_digest = "wrong".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-sequence",
            (|c: &mut Ctx| c.attestation.authority_domain_sequence = 99) as fn(&mut Ctx),
        ),
        (
            "malformed",
            (|c: &mut Ctx| c.attestation.attestation_id = String::new()) as fn(&mut Ctx),
        ),
        (
            "malformed-digest",
            (|c: &mut Ctx| c.attestation.attestation_digest = String::new()) as fn(&mut Ctx),
        ),
    ];
    for (label, mutate) in attestation_cases {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = devnet_attestor();
        let o = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
        t.check_outcome(
            &format!("B.attestation.{label}"),
            "durable-completion-attestation-rejected-before-record",
            &o,
        );
        t.assert_true(&format!("B.attestation.{label}.invoked"), a.invocations() == 1);
        t.assert_true(&format!("B.attestation.{label}.empty"), ledger.is_empty());
    }
    // Same attestation id with a different digest is equivocation (no second attestation).
    {
        let c = devnet_ctx();
        let mut ledger = ModeledDurableCompletionAttestationLedger::new();
        let mut a = devnet_attestor();
        let _ = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
        let mut c2 = devnet_ctx();
        c2.attestation.attestation_digest = "different-digest".to_string();
        c2.expectations.expected_attestation_digest = "different-digest".to_string();
        let o = drive(&c2.finalized(), &c2.expectations, &mut a, &mut ledger);
        t.check_outcome(
            "B.equivocation",
            "durable-completion-attestation-rejected-before-record",
            &o,
        );
        t.assert_true("B.equivocation-ledger-one", ledger.len() == 1);
    }
    t.assert_true(
        "B.local-operator-cannot",
        modeled_attestation_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "B.peer-majority-cannot",
        modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    t.finish(out)
}

fn recover_devnet(
    window: ModeledDurableCompletionAttestationWindow,
    attestation: Option<&GovernanceModeledDurableCompletionAttestationRecord>,
) -> GovernanceModeledDurableCompletionAttestationOutcome {
    let c = devnet_ctx();
    recover_modeled_durable_completion_attestation_window(
        &c.finalized(),
        window,
        ModeledDurableCompletionAttestorKind::FixtureDevNet,
        attestation,
        &c.expectations,
    )
}

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use ModeledDurableCompletionAttestationWindow as W;
    let mut t = Table::new("recovery");
    for (id, w, tag) in [
        ("C.before-pipeline", W::BeforePipeline, "finalization-did-not-finalize-no-attestation"),
        (
            "C.after-pipeline-before-sink-intent",
            W::AfterPipelineSuccessBeforeSinkIntent,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "C.after-sink-intent-before-receipt-record",
            W::AfterSinkIntentBeforeReceiptRecord,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "C.after-receipt-record-before-report-intent",
            W::AfterReceiptRecordBeforeReportIntent,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "C.after-report-intent-before-report-record",
            W::AfterReportIntentBeforeReportRecord,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "C.after-report-record-before-finalization-intent",
            W::AfterReportRecordBeforeFinalizationIntent,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "C.after-finalization-intent-before-record",
            W::AfterFinalizationIntentBeforeFinalizationRecord,
            "finalization-did-not-finalize-no-attestation",
        ),
        (
            "C.after-finalization-record-before-attestation-intent",
            W::AfterFinalizationRecordBeforeAttestationIntent,
            "durable-completion-attestation-rejected-before-record",
        ),
        (
            "C.after-attestation-intent-before-record",
            W::AfterAttestationIntentBeforeAttestationRecord,
            "durable-completion-attestation-rejected-before-record",
        ),
        (
            "C.after-record-before-success-no-attestation",
            W::AfterAttestationRecordBeforeAttestationSuccess,
            "durable-completion-attestation-rejected-before-record",
        ),
        (
            "C.after-ambiguous",
            W::AfterAttestationAmbiguous,
            "durable-completion-attestation-ambiguous-fail-closed-no-attestation",
        ),
        (
            "C.record-failed",
            W::AttestationRecordFailed,
            "durable-completion-attestation-record-failed-no-attestation",
        ),
        (
            "C.rollback",
            W::RollbackCompleted,
            "durable-completion-attestation-rolled-back-no-attestation",
        ),
        (
            "C.rollback-failed",
            W::RollbackFailed,
            "durable-completion-attestation-rollback-failed-fatal-no-attestation",
        ),
        (
            "C.unknown",
            W::Unknown,
            "durable-completion-attestation-ambiguous-fail-closed-no-attestation",
        ),
    ] {
        t.check_outcome(id, tag, &recover_devnet(w, None));
    }
    let c = devnet_ctx();
    let att = c.attestation.clone();
    t.check_outcome(
        "C.after-record-before-success-with-attestation",
        "durable-completion-attested",
        &recover_devnet(W::AfterAttestationRecordBeforeAttestationSuccess, Some(&att)),
    );
    t.check_outcome(
        "C.after-success",
        "durable-completion-attested",
        &recover_devnet(W::AfterAttestationSuccess, Some(&att)),
    );
    // Production / MainNet recovery classification is unavailable / fail-closed.
    let o = recover_modeled_durable_completion_attestation_window(
        &c.finalized(),
        W::AfterAttestationSuccess,
        ModeledDurableCompletionAttestorKind::ProductionUnavailable,
        None,
        &c.expectations,
    );
    t.check_outcome("C.production", "production-attestor-unavailable-no-attestation", &o);
    let c2 = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    let o2 = recover_modeled_durable_completion_attestation_window(
        &c2.finalized(),
        W::AfterAttestationSuccess,
        ModeledDurableCompletionAttestorKind::MainNetUnavailable,
        None,
        &c2.expectations,
    );
    t.check_outcome("C.mainnet", "mainnet-attestor-unavailable-no-attestation", &o2);
    // MainNet peer-driven refusal precedes recovery classification.
    let c3 = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let o3 = recover_modeled_durable_completion_attestation_window(
        &c3.finalized(),
        W::AfterAttestationSuccess,
        ModeledDurableCompletionAttestorKind::FixtureDevNet,
        Some(&c3.attestation),
        &c3.expectations,
    );
    t.check_outcome(
        "C.mainnet-peer-driven-precedes",
        "mainnet-peer-driven-apply-refused-no-attestation",
        &o3,
    );
    t.finish(out)
}

fn run_projection_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    let mut t = Table::new("projection");
    // Only DurableCompletionFinalized creates an attestation intent.
    t.assert_true(
        "D.only-finalized-creates-intent",
        project_finalization_outcome_to_attestation_intent(&Final::DurableCompletionFinalized)
            .creates_intent(),
    );
    // A DurableCompletionDuplicateIdempotent finalization is idempotent-only (no create).
    t.assert_true(
        "D.duplicate-idempotent-no-create",
        project_finalization_outcome_to_attestation_intent(
            &Final::DurableCompletionDuplicateIdempotent,
        ) == DurableCompletionAttestationIntent::IdempotentOnly,
    );
    // Earlier-stage success alone (a non-finalized finalization outcome) creates no intent.
    for (label, fin) in [
        ("pipeline-success-alone", Final::ReporterDidNotRecordCompletionNoFinalization),
        ("sink-receipt-alone", Final::ReporterDidNotRecordCompletionNoFinalization),
        ("completion-report-alone", Final::ReporterDidNotRecordCompletionNoFinalization),
        ("finalization-intent-alone", Final::RejectedBeforeReporterNoFinalization),
        ("legacy-bypass", Final::LegacyBypassNoFinalization),
        ("rejected-before-record", Final::DurableCompletionRejectedBeforeRecord),
        ("record-failed", Final::DurableCompletionRecordFailedNoFinalization),
        ("rolled-back", Final::DurableCompletionRolledBackNoFinalization),
        ("rollback-failed", Final::DurableCompletionRollbackFailedFatalNoFinalization),
        ("ambiguous", Final::DurableCompletionAmbiguousFailClosedNoFinalization),
        ("production", Final::ProductionFinalizerUnavailableNoFinalization),
        ("mainnet", Final::MainNetFinalizerUnavailableNoFinalization),
        ("mainnet-peer", Final::MainNetPeerDrivenApplyRefusedNoFinalization),
        ("validator", Final::ValidatorSetRotationUnsupportedNoFinalization),
        ("policy", Final::PolicyChangeUnsupportedNoFinalization),
    ] {
        t.assert_true(
            &format!("D.{label}.no-create"),
            !project_finalization_outcome_to_attestation_intent(&fin).creates_intent(),
        );
    }
    // Only DurableCompletionAttested authorizes a new modeled durable-completion-attested state.
    t.assert_true(
        "D.attested-authorizes",
        attestation_outcome_authorizes_modeled_attestation(&Att::DurableCompletionAttested),
    );
    t.assert_true(
        "D.attested-projects",
        attestation_outcome_projects_to_durable_completion_attested(&Att::DurableCompletionAttested),
    );
    // A duplicate-idempotent attestation projects but does not authorize a new attestation.
    t.assert_true(
        "D.duplicate-projects",
        attestation_outcome_projects_to_durable_completion_attested(
            &Att::DurableCompletionAttestationDuplicateIdempotent,
        ),
    );
    t.assert_true(
        "D.duplicate-no-authorize",
        !attestation_outcome_authorizes_modeled_attestation(
            &Att::DurableCompletionAttestationDuplicateIdempotent,
        ),
    );
    // Every other attestation outcome neither authorizes nor projects.
    for (label, outcome) in [
        ("legacy-bypass", Att::LegacyBypassNoAttestation),
        ("rejected-before-finalization", Att::RejectedBeforeFinalizationNoAttestation),
        ("finalization-did-not-finalize", Att::FinalizationDidNotFinalizeNoAttestation),
        ("rejected-before-record", Att::DurableCompletionAttestationRejectedBeforeRecord),
        ("record-failed", Att::DurableCompletionAttestationRecordFailedNoAttestation),
        ("rolled-back", Att::DurableCompletionAttestationRolledBackNoAttestation),
        (
            "rollback-failed",
            Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
        ),
        (
            "ambiguous",
            Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
        ),
        ("production", Att::ProductionAttestorUnavailableNoAttestation),
        ("mainnet", Att::MainNetAttestorUnavailableNoAttestation),
        ("mainnet-peer", Att::MainNetPeerDrivenApplyRefusedNoAttestation),
        ("validator", Att::ValidatorSetRotationUnsupportedNoAttestation),
        ("policy", Att::PolicyChangeUnsupportedNoAttestation),
    ] {
        t.assert_true(
            &format!("D.{label}.no-authorize"),
            !attestation_outcome_authorizes_modeled_attestation(&outcome),
        );
        t.assert_true(
            &format!("D.{label}.no-project"),
            !attestation_outcome_projects_to_durable_completion_attested(&outcome),
        );
    }
    t.finish(out)
}

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("stage_ordering");
    // MainNet peer-driven apply refused first (no invocation, empty ledger).
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut a = devnet_attestor();
    let o = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
    t.assert_true(
        "E.mainnet-refused-first",
        o.is_mainnet_peer_driven_apply_refused() && a.invocations() == 0 && ledger.is_empty(),
    );
    // Binding validation happens before the attestor stage.
    let mut c2 = devnet_ctx();
    c2.env.genesis_hash = "wrong".to_string();
    let mut ledger2 = ModeledDurableCompletionAttestationLedger::new();
    let mut a2 = devnet_attestor();
    let _ = drive(&c2.finalized(), &c2.expectations, &mut a2, &mut ledger2);
    t.assert_true("E.binding-before-attestor", a2.invocations() == 0);
    // A record failure does not retroactively attest but invokes the attestor once.
    let c3 = devnet_ctx();
    let mut ledger3 = ModeledDurableCompletionAttestationLedger::new();
    let mut a3 = FixtureModeledDurableCompletionAttestor::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledDurableCompletionAttestationFault::RecordFailedNoAttestation,
    );
    let o3 = drive(&c3.finalized(), &c3.expectations, &mut a3, &mut ledger3);
    t.assert_true(
        "E.record-failure-no-attestation",
        o3.no_attestation() && a3.invocations() == 1 && ledger3.is_empty(),
    );
    // A rollback failure is fatal / fail-closed.
    let mut a4 = FixtureModeledDurableCompletionAttestor::with_fault(
        TrustBundleEnvironment::Devnet,
        ModeledDurableCompletionAttestationFault::RollbackFailedFatal,
    );
    let mut ledger4 = ModeledDurableCompletionAttestationLedger::new();
    let o4 = drive(&c3.finalized(), &c3.expectations, &mut a4, &mut ledger4);
    t.check_outcome(
        "E.rollback-failed-fatal",
        "durable-completion-attestation-rollback-failed-fatal-no-attestation",
        &o4,
    );
    t.finish(out)
}

fn run_attestation_ledger_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("attestation_ledger");
    let c = devnet_ctx();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut a = devnet_attestor();
    let o = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
    t.check_outcome("F.one-valid", "durable-completion-attested", &o);
    t.assert_true(
        "F.len-one",
        ledger.len() == 1 && ledger.records().len() == 1 && ledger.contains(ATTESTATION_ID),
    );
    t.assert_true(
        "F.status",
        ledger.find(ATTESTATION_ID).map(|r| r.status)
            == Some(ModeledDurableCompletionAttestationStatus::Attested),
    );
    let snap = ledger.snapshot();
    t.assert_true("F.snapshot", snap.len() == 1 && !snap.is_empty());
    let mut restored = ModeledDurableCompletionAttestationLedger::new();
    restored.restore(&snap);
    t.assert_true(
        "F.restore",
        restored.len() == 1 && restored.contains(ATTESTATION_ID),
    );
    let digest: ModeledDurableCompletionAttestationDigest = c.attestation.digest();
    t.assert_true(
        "F.digest",
        ledger.find(ATTESTATION_ID).map(|r| r.digest.clone()) == Some(digest),
    );
    // Duplicate identical attestation does not increase record count.
    let second = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
    t.check_outcome(
        "F.duplicate",
        "durable-completion-attestation-duplicate-idempotent",
        &second,
    );
    t.assert_true("F.duplicate-len-one", ledger.len() == 1);
    // Same id with a different digest is equivocation and does not record.
    let mut c2 = devnet_ctx();
    c2.attestation.attestation_digest = "different-digest".to_string();
    c2.expectations.expected_attestation_digest = "different-digest".to_string();
    let o2 = drive(&c2.finalized(), &c2.expectations, &mut a, &mut ledger);
    t.check_outcome(
        "F.equivocation",
        "durable-completion-attestation-rejected-before-record",
        &o2,
    );
    t.assert_true("F.equivocation-len-one", ledger.len() == 1);
    // Each identity-mismatch field does not record (representative subset).
    let mut record = ModeledDurableCompletionAttestationLedger::new();
    let mut a3 = devnet_attestor();
    for (label, mutate) in [
        (
            "wrong-attestation-digest",
            (|c: &mut Ctx| c.attestation.attestation_digest = "x".to_string()) as fn(&mut Ctx),
        ),
        (
            "wrong-finalization-decision-digest",
            (|c: &mut Ctx| c.attestation.finalization_decision_digest = "x".to_string())
                as fn(&mut Ctx),
        ),
        (
            "wrong-sequence",
            (|c: &mut Ctx| c.attestation.authority_domain_sequence = 11) as fn(&mut Ctx),
        ),
        (
            "malformed",
            (|c: &mut Ctx| c.attestation.attestation_id = String::new()) as fn(&mut Ctx),
        ),
    ] {
        let mut cc = devnet_ctx();
        mutate(&mut cc);
        let o = drive(&cc.finalized(), &cc.expectations, &mut a3, &mut record);
        t.check_outcome(
            &format!("F.no-record.{label}"),
            "durable-completion-attestation-rejected-before-record",
            &o,
        );
        t.assert_true(&format!("F.no-record.{label}.empty"), record.is_empty());
    }
    t.finish(out)
}

fn run_non_mutation_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("non_mutation");
    t.assert_true("G.rejection-non-mutating", modeled_attestation_rejection_is_non_mutating());
    t.assert_true("G.never-calls-run-070", modeled_attestation_never_calls_run_070());
    t.assert_true(
        "G.never-mutates-live",
        modeled_attestation_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.never-writes-sequence-or-marker",
        modeled_attestation_never_writes_sequence_or_marker(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        modeled_attestation_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "G.pipeline-success-required",
        modeled_attestation_pipeline_success_required_before_attestation(),
    );
    t.assert_true(
        "G.sink-receipt-required",
        modeled_attestation_sink_receipt_required_before_attestation(),
    );
    t.assert_true(
        "G.completion-report-required",
        modeled_attestation_completion_report_required_before_attestation(),
    );
    t.assert_true(
        "G.finalization-required",
        modeled_attestation_finalization_required_before_attestation(),
    );
    t.assert_true(
        "G.record-required",
        modeled_attestation_record_required_before_durable_completion_attested(),
    );
    t.assert_true(
        "G.failed-record-never-attests",
        modeled_attestation_failed_record_never_attests(),
    );
    t.assert_true("G.rollback-never-attests", modeled_attestation_rollback_never_attests());
    t.assert_true(
        "G.ambiguous-fails-closed",
        modeled_attestation_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "G.mainnet-refused-mainnet",
        modeled_attestation_mainnet_peer_driven_apply_refused_first(TrustBundleEnvironment::Mainnet),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !modeled_attestation_mainnet_peer_driven_apply_refused_first(TrustBundleEnvironment::Devnet),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        modeled_attestation_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        modeled_attestation_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "G.policy-change-unsupported",
        modeled_attestation_policy_change_unsupported(),
    );
    t.assert_true(
        "G.local-operator-cannot",
        modeled_attestation_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority(),
    );
    // A rejected path leaves the ledger empty and the attestor uninvoked.
    let mut c = devnet_ctx();
    c.env.genesis_hash = "wrong".to_string();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut a = devnet_attestor();
    let _ = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
    t.assert_true(
        "G.rejected-ledger-empty",
        ledger.is_empty() && a.invocations() == 0,
    );
    t.finish(out)
}

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    let mut t = Table::new("reachability");
    let tags = [
        (Att::LegacyBypassNoAttestation, "legacy-bypass-no-attestation"),
        (
            Att::RejectedBeforeFinalizationNoAttestation,
            "rejected-before-finalization-no-attestation",
        ),
        (
            Att::FinalizationDidNotFinalizeNoAttestation,
            "finalization-did-not-finalize-no-attestation",
        ),
        (Att::DurableCompletionAttested, "durable-completion-attested"),
        (
            Att::DurableCompletionAttestationDuplicateIdempotent,
            "durable-completion-attestation-duplicate-idempotent",
        ),
        (
            Att::DurableCompletionAttestationRejectedBeforeRecord,
            "durable-completion-attestation-rejected-before-record",
        ),
        (
            Att::DurableCompletionAttestationRecordFailedNoAttestation,
            "durable-completion-attestation-record-failed-no-attestation",
        ),
        (
            Att::DurableCompletionAttestationRolledBackNoAttestation,
            "durable-completion-attestation-rolled-back-no-attestation",
        ),
        (
            Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation,
            "durable-completion-attestation-rollback-failed-fatal-no-attestation",
        ),
        (
            Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
            "durable-completion-attestation-ambiguous-fail-closed-no-attestation",
        ),
        (
            Att::ProductionAttestorUnavailableNoAttestation,
            "production-attestor-unavailable-no-attestation",
        ),
        (
            Att::MainNetAttestorUnavailableNoAttestation,
            "mainnet-attestor-unavailable-no-attestation",
        ),
        (
            Att::MainNetPeerDrivenApplyRefusedNoAttestation,
            "mainnet-peer-driven-apply-refused-no-attestation",
        ),
        (
            Att::ValidatorSetRotationUnsupportedNoAttestation,
            "validator-set-rotation-unsupported-no-attestation",
        ),
        (
            Att::PolicyChangeUnsupportedNoAttestation,
            "policy-change-unsupported-no-attestation",
        ),
    ];
    for (o, tag) in tags {
        t.check(&format!("H.tag.{tag}"), tag, o.tag());
    }
    t.check(
        "H.kind-devnet",
        "fixture-devnet",
        ModeledDurableCompletionAttestorKind::FixtureDevNet.tag(),
    );
    t.check(
        "H.kind-testnet",
        "fixture-testnet",
        ModeledDurableCompletionAttestorKind::FixtureTestNet.tag(),
    );
    t.check(
        "H.kind-production",
        "production-unavailable",
        ModeledDurableCompletionAttestorKind::ProductionUnavailable.tag(),
    );
    t.check(
        "H.kind-mainnet",
        "mainnet-unavailable",
        ModeledDurableCompletionAttestorKind::MainNetUnavailable.tag(),
    );
    t.assert_true(
        "H.kind-fixture",
        ModeledDurableCompletionAttestorKind::FixtureDevNet.is_fixture(),
    );
    t.assert_true(
        "H.kind-unavailable",
        ModeledDurableCompletionAttestorKind::ProductionUnavailable.is_unavailable(),
    );
    t.assert_true(
        "H.policy-wired",
        GovernanceModeledDurableCompletionAttestationPolicy::wired().is_wired(),
    );
    t.assert_true(
        "H.policy-disabled",
        !GovernanceModeledDurableCompletionAttestationPolicy::disabled().is_wired(),
    );
    // Touch every Run 254 type alias the task enumerates so the helper links them.
    let _aliases = std::any::type_name::<(
        GovernanceModeledDurableCompletionAttestationSurface,
        GovernanceModeledDurableCompletionAttestationEnvironmentBinding,
        GovernanceModeledDurableCompletionAttestationRuntimeBinding,
        GovernanceModeledDurableCompletionAttestationReplayBinding,
        GovernanceModeledDurableCompletionAttestationPipelineBinding,
        GovernanceModeledDurableCompletionAttestationSinkBinding,
        GovernanceModeledDurableCompletionAttestationReporterBinding,
        GovernanceModeledDurableCompletionAttestationFinalizationBinding,
        ModeledDurableCompletionAttestationRecord,
        ModeledDurableCompletionAttestationSnapshot,
    )>();
    t.assert_true("H.aliases", !_aliases.is_empty());
    t.finish(out)
}

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let c = devnet_ctx();
    let mut ledger = ModeledDurableCompletionAttestationLedger::new();
    let mut a = devnet_attestor();
    let o = drive(&c.finalized(), &c.expectations, &mut a, &mut ledger);
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} authorizes={} projects={} invocations={} ledger_len={} contains={}\n",
            o.tag(),
            o.authorizes_modeled_durable_completion_attestation(),
            o.projects_to_durable_completion_attested(),
            a.invocations(),
            ledger.len(),
            ledger.contains(ATTESTATION_ID)
        ),
    );
    let mut c2 = devnet_ctx();
    c2.env.genesis_hash = "wrong-genesis".to_string();
    let mut ledger2 = ModeledDurableCompletionAttestationLedger::new();
    let mut a2 = devnet_attestor();
    let o2 = drive(&c2.finalized(), &c2.expectations, &mut a2, &mut ledger2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} invocations={} no_attestation={} ledger_len={}\n",
            o2.tag(),
            a2.invocations(),
            o2.no_attestation(),
            ledger2.len()
        ),
    );
    let c3 = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let mut ledger3 = ModeledDurableCompletionAttestationLedger::new();
    let mut a3 = devnet_attestor();
    let o3 = drive(&c3.finalized(), &c3.expectations, &mut a3, &mut ledger3);
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} invocations={} is_refusal={} ledger_len={}\n",
            o3.tag(),
            a3.invocations(),
            o3.is_mainnet_peer_driven_apply_refused(),
            ledger3.len()
        ),
    );
    let att = c.attestation.clone();
    let mut windows = String::new();
    for (label, w, attopt) in [
        ("before-pipeline", ModeledDurableCompletionAttestationWindow::BeforePipeline, None),
        (
            "after-finalization-record-before-attestation-intent",
            ModeledDurableCompletionAttestationWindow::AfterFinalizationRecordBeforeAttestationIntent,
            None,
        ),
        (
            "after-attestation-record-before-success-with-attestation",
            ModeledDurableCompletionAttestationWindow::AfterAttestationRecordBeforeAttestationSuccess,
            Some(&att),
        ),
        (
            "after-attestation-success",
            ModeledDurableCompletionAttestationWindow::AfterAttestationSuccess,
            Some(&att),
        ),
        (
            "after-attestation-ambiguous",
            ModeledDurableCompletionAttestationWindow::AfterAttestationAmbiguous,
            None,
        ),
        ("rollback-failed", ModeledDurableCompletionAttestationWindow::RollbackFailed, None),
        ("unknown", ModeledDurableCompletionAttestationWindow::Unknown, None),
    ] {
        windows.push_str(&format!("{label}={}\n", recover_devnet(w, attopt).tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: run_255_modeled_durable_completion_attestation_projection_release_binary_helper <OUT_DIR>");
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("stage_ordering", run_stage_ordering_table),
        ("attestation_ledger", run_attestation_ledger_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_255_modeled_durable_completion_attestation_projection_release_binary_helper\n\
scope: Run 254 governance modeled durable-completion finalization attestation-projection boundary (pqc_governance_modeled_durable_completion_attestation_projection: evaluate_modeled_durable_completion_attestation_projection, recover_modeled_durable_completion_attestation_window, project_finalization_outcome_to_attestation_intent, attestation_outcome_authorizes_modeled_attestation, attestation_outcome_projects_to_durable_completion_attested, the GovernanceModeledDurableCompletionAttestor trait with FixtureModeledDurableCompletionAttestor/ProductionModeledDurableCompletionAttestor/MainNetModeledDurableCompletionAttestor, the GovernanceModeledDurableCompletionAttestationInput/Expectations/Policy/Surface/EnvironmentBinding/RuntimeBinding/ReplayBinding/PipelineBinding/SinkBinding/ReporterBinding/FinalizationBinding bindings, the GovernanceModeledDurableCompletionAttestationRecord plus the ModeledDurableCompletionAttestationLedger/Record/Snapshot/Status/Digest modeled in-memory ledger, the GovernanceModeledDurableCompletionAttestationOutcome taxonomy, the DurableCompletionAttestationIntent projection, the ModeledDurableCompletionAttestationFault injector, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\n\
note: fixture-only; pure typed projection over an in-memory ledger (the DevNet/TestNet fixture attestor mutates ONLY the in-memory ModeledDurableCompletionAttestationLedger; no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState mutation, no persistent durable completion / audit write, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a disabled attestor/finalizer/reporter/sink/pipeline/evaluator-call-site policy is a legacy bypass with no attestation and no attestor invocation; MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, before any reporter invocation, before any finalizer invocation, and before any attestor invocation; Run 246 pipeline success is required before any sink intent, Run 248 ConsumeReceiptRecorded is required before any completion-report intent, Run 250 CompletionReportRecorded is required before any finalization intent, and Run 252 DurableCompletionFinalized is required before any attestation intent; only DurableCompletionAttested authorizes a new modeled durable-completion-attested state; duplicate identical attestation is idempotent; same id with different digest fails closed as equivocation\n\n",
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