//! Run 251 — release-built helper for the Run 250 governance **modeled
//! durable-consume receipt-acknowledgement / completion reporter boundary**
//! (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`).
//!
//! Where Run 250 landed the pure, typed modeled durable-consume completion
//! reporter at the source/test level and captured **no** release-binary evidence,
//! Run 251 is that release-binary evidence. This helper drives an
//! accepted/compatible, rejection, recovery, projection, stage-ordering,
//! completion-report-ledger, non-mutation, and reachability corpus through the
//! **release-built** Run 250 symbols
//! (`evaluate_modeled_durable_consume_completion_reporter`,
//! `recover_modeled_durable_consume_completion_reporter_window`,
//! `project_sink_outcome_to_completion_report_intent`,
//! `completion_reporter_outcome_authorizes_modeled_completion`,
//! `completion_reporter_outcome_projects_to_durable_completion`, the
//! `GovernanceModeledDurableConsumeCompletionReporter` trait boundary with
//! `FixtureModeledDurableConsumeCompletionReporter` /
//! `ProductionModeledDurableConsumeCompletionReporter` /
//! `MainNetModeledDurableConsumeCompletionReporter`, the
//! `GovernanceModeledDurableConsumeCompletionReporterInput` /
//! `GovernanceModeledDurableConsumeCompletionReporterExpectations` /
//! `GovernanceModeledDurableConsumeCompletionReporterPolicy` /
//! `GovernanceModeledDurableConsumeCompletionReporterSurface` /
//! `GovernanceModeledDurableConsumeCompletionReporterEnvironmentBinding` /
//! `GovernanceModeledDurableConsumeCompletionReporterRuntimeBinding` /
//! `GovernanceModeledDurableConsumeCompletionReporterReplayBinding` /
//! `GovernanceModeledDurableConsumeCompletionReporterPipelineBinding` /
//! `GovernanceModeledDurableConsumeCompletionReporterSinkBinding` bindings, the
//! `GovernanceModeledDurableConsumeCompletionReport` plus the
//! `ModeledDurableConsumeCompletionReportLedger` /
//! `ModeledDurableConsumeCompletionReportRecord` /
//! `ModeledDurableConsumeCompletionReportSnapshot` /
//! `ModeledDurableConsumeCompletionReportStatus` /
//! `ModeledDurableConsumeCompletionReportDigest` modeled in-memory ledger, the
//! `GovernanceModeledDurableConsumeCompletionReporterOutcome` taxonomy, the
//! `CompletionReportIntent` projection, the `ModeledCompletionReportFault`
//! injector, and the grep-verifiable invariant / fail-closed helpers), proving in
//! release mode that:
//!
//! * a disabled reporter / sink / pipeline / evaluator-call-site policy preserves
//!   the legacy no-acknowledgement, no-completion bypass and never invokes the
//!   reporter;
//! * a DevNet/TestNet fixture pipeline success + sink receipt recorded + reporter
//!   record success records exactly one modeled in-memory completion report;
//! * the only sink outcome that creates a completion-report intent is the Run 248
//!   `ConsumeReceiptRecorded`; `ConsumeReceiptDuplicateIdempotent` may only match
//!   an already-recorded completion report; every other sink outcome maps to a
//!   no-completion fail-closed outcome and never invokes the reporter;
//! * only `CompletionReportRecorded` authorizes a new modeled completion-reported
//!   state; a duplicate identical completion report is idempotent (no second
//!   report); the same report id with a different digest fails closed as
//!   equivocation;
//! * every evaluator/call-site rejection, durable replay rejection
//!   (stale/expired/consumed/superseded/backend-unavailable), mutation-engine
//!   rejection, modeled applier reject-before-snapshot / reject-before-apply /
//!   apply-failure / rollback / rollback-failed / ambiguous, sink
//!   reject/record-failure/rollback/rollback-failed/ambiguous, binding mismatch,
//!   report-identity mismatch, malformed report, record failure, rollback,
//!   rollback failure, ambiguous acknowledgement window, unavailable
//!   production/MainNet reporter path, validator-set rotation, and policy-change
//!   attempt is non-mutating and non-completing;
//! * a rejection before the reporter stage leaves the reporter invocation count at
//!   zero;
//! * MainNet peer-driven apply is refused before pipeline progression, before any
//!   sink invocation, and before any reporter invocation;
//! * the crash-window recovery classification fails closed on every
//!   before-pipeline / after-pipeline / after-sink-intent / after-receipt-record /
//!   after-report-intent / ambiguous / record-failed / rollback / rollback-failed /
//!   unknown window, and recovers as completed only with an explicit matching
//!   completion report.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real completion-report
//! backend, durable consume backend, persistent replay backend, governance
//! execution engine, mutation engine, on-chain proof verifier, KMS/HSM, or
//! RemoteSigner backend. No RocksDB/file/schema/migration/storage-format change.
//! The reporter is a pure typed projection over an in-memory ledger; the
//! DevNet/TestNet fixture reporter mutates only the modeled in-memory
//! `ModeledDurableConsumeCompletionReportLedger`; it never mutates
//! `LivePqcTrustState`, calls Run 070, performs a real trust swap, evicts sessions,
//! writes a sequence, writes a marker, or performs a durable consume of its own.
//! MainNet peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_consume_completion_reporter::{
    completion_reporter_outcome_authorizes_modeled_completion,
    completion_reporter_outcome_projects_to_durable_completion,
    evaluate_modeled_durable_consume_completion_reporter,
    modeled_completion_reporter_ambiguous_window_fails_closed,
    modeled_completion_reporter_failed_record_never_completes,
    modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority,
    modeled_completion_reporter_mainnet_peer_driven_apply_refused_first,
    modeled_completion_reporter_never_calls_run_070,
    modeled_completion_reporter_never_mutates_live_pqc_trust_state,
    modeled_completion_reporter_never_writes_sequence_or_marker,
    modeled_completion_reporter_no_rocksdb_file_schema_migration_change,
    modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_completion_reporter_pipeline_success_required_before_report,
    modeled_completion_reporter_policy_change_unsupported,
    modeled_completion_reporter_production_mainnet_unavailable,
    modeled_completion_reporter_rejection_is_non_mutating,
    modeled_completion_reporter_report_record_required_before_completion,
    modeled_completion_reporter_rollback_never_completes,
    modeled_completion_reporter_sink_receipt_required_before_report,
    modeled_completion_reporter_validator_set_rotation_unsupported,
    project_sink_outcome_to_completion_report_intent,
    recover_modeled_durable_consume_completion_reporter_window, CompletionReportIntent,
    FixtureModeledDurableConsumeCompletionReporter, GovernanceModeledDurableConsumeCompletionReport,
    GovernanceModeledDurableConsumeCompletionReporter,
    GovernanceModeledDurableConsumeCompletionReporterExpectations,
    GovernanceModeledDurableConsumeCompletionReporterInput,
    GovernanceModeledDurableConsumeCompletionReporterOutcome,
    GovernanceModeledDurableConsumeCompletionReporterPolicy,
    MainNetModeledDurableConsumeCompletionReporter, ModeledCompletionReportFault,
    ModeledDurableConsumeCompletionReportLedger, ModeledDurableConsumeCompletionReporterKind,
    ModeledDurableConsumeCompletionReportStatus, ModeledDurableConsumeCompletionReportWindow,
    ProductionModeledDurableConsumeCompletionReporter,
};
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
// Shared constants (mirror the Run 250 corpus so the composed material binds to
// the same trust domain, proposal/decision identity, candidate digest).
// ===========================================================================

const REPORT_ID: &str = "completion-report-0001";
const REPORT_DIGEST: &str = "completion-report-digest-cccccccccccccccc";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
const SINK_DIGEST: &str = "sink-decision-digest-ssssssssssssssssssss";
const PIPELINE_DIGEST: &str = "modeled-pipeline-decision-digest-pppppppp";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SEQUENCE: u64 = 7;

// ===========================================================================
// Owned-context builder (mirrors the Run 250 test owned-context builder).
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    report: GovernanceModeledDurableConsumeCompletionReport,
    expectations: GovernanceModeledDurableConsumeCompletionReporterExpectations,
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
    let report = GovernanceModeledDurableConsumeCompletionReport {
        report_id: REPORT_ID.to_string(),
        report_digest: REPORT_DIGEST.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        sink_decision_digest: SINK_DIGEST.to_string(),
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableConsumeCompletionReporterExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_report_digest: REPORT_DIGEST.to_string(),
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_sink_decision_digest: SINK_DIGEST.to_string(),
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        report,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        policy: GovernanceModeledDurableConsumeCompletionReporterPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
        sink: GovernanceModeledDurableConsumeSinkOutcome,
    ) -> GovernanceModeledDurableConsumeCompletionReporterInput {
        GovernanceModeledDurableConsumeCompletionReporterInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            sink_binding: sink,
            report: self.report.clone(),
        }
    }

    /// The canonical "sink recorded a receipt" wired input.
    fn recorded(&self) -> GovernanceModeledDurableConsumeCompletionReporterInput {
        self.input(
            GovernanceModeledDurableConsumeCompletionReporterPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
            GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded,
        )
    }
}

/// A DevNet mutating-surface context.
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

fn devnet_reporter() -> FixtureModeledDurableConsumeCompletionReporter {
    FixtureModeledDurableConsumeCompletionReporter::new(TrustBundleEnvironment::Devnet)
}

// ===========================================================================
// Output plumbing
// ===========================================================================

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
        o: &GovernanceModeledDurableConsumeCompletionReporterOutcome,
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

/// Drive a completion-reporter round-trip over a fresh DevNet fixture reporter and
/// an empty (or supplied) modeled ledger.
fn drive(
    input: &GovernanceModeledDurableConsumeCompletionReporterInput,
    expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
    reporter: &mut FixtureModeledDurableConsumeCompletionReporter,
    ledger: &mut ModeledDurableConsumeCompletionReportLedger,
) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
    evaluate_modeled_durable_consume_completion_reporter(input, expectations, reporter, ledger)
}

// ===========================================================================
// A — accepted / compatible scenarios exercised through the release-built Run
// 250 durable-consume completion reporter symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use DurableReplayObservation as R;
    use GovernanceModeledDurableConsumeCompletionReporterPolicy as P;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("accepted");

    // A1 — disabled reporter policy preserves legacy bypass; no acknowledgement, no
    // completion report, no reporter invocation.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::reporter_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A1.outcome", "legacy-bypass-no-completion-report", &o);
        t.assert_true("A1.no-completion", o.no_completion());
        t.assert_true("A1.legacy-bypass", o.is_legacy_bypass());
        t.assert_true("A1.no-invocation", reporter.invocations() == 0);
        t.assert_true("A1.ledger-empty", ledger.is_empty());
    }

    // A2 — disabled sink policy preserves legacy bypass; never invokes the reporter.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::sink_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A2.outcome", "legacy-bypass-no-completion-report", &o);
        t.assert_true("A2.no-invocation", reporter.invocations() == 0);
        t.assert_true("A2.ledger-empty", ledger.is_empty());
    }

    // A3 — disabled pipeline policy preserves legacy bypass; never invokes the reporter.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::pipeline_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A3.outcome", "legacy-bypass-no-completion-report", &o);
        t.assert_true("A3.no-invocation", reporter.invocations() == 0);
        t.assert_true("A3.ledger-empty", ledger.is_empty());
    }

    // A4 — disabled evaluator/call-site policy preserves legacy bypass; never invokes the reporter.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::evaluator_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A4.outcome", "legacy-bypass-no-completion-report", &o);
        t.assert_true("A4.no-invocation", reporter.invocations() == 0);
        t.assert_true("A4.ledger-empty", ledger.is_empty());
    }

    // A5 — DevNet fixture pipeline success + sink receipt recorded + reporter record
    // success records exactly one modeled completion report.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A5.outcome", "completion-report-recorded", &o);
        t.assert_true("A5.authorizes", o.authorizes_modeled_completion());
        t.assert_true("A5.projects", o.projects_to_durable_completion());
        t.assert_true("A5.invoked-once", reporter.invocations() == 1);
        t.assert_true("A5.ledger-one", ledger.len() == 1);
        t.assert_true("A5.contains", ledger.contains(REPORT_ID));
        t.check("A5.kind", "fixture-devnet", reporter.kind().tag());
        t.assert_true(
            "A5.record-status",
            ledger.find(REPORT_ID).map(|r| r.status)
                == Some(ModeledDurableConsumeCompletionReportStatus::Recorded),
        );
    }

    // A6 — TestNet fixture pipeline success + sink receipt recorded + reporter record
    // success records exactly one modeled completion report.
    {
        let c = testnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter =
            FixtureModeledDurableConsumeCompletionReporter::new(TrustBundleEnvironment::Testnet);
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A6.outcome", "completion-report-recorded", &o);
        t.assert_true("A6.ledger-one", ledger.len() == 1);
        t.check("A6.kind", "fixture-testnet", reporter.kind().tag());
    }

    // A7 — duplicate identical completion report is idempotent under an explicit
    // typed outcome; creates no second report.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let first = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A7.first", "completion-report-recorded", &first);
        let second = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A7.second", "completion-report-duplicate-idempotent", &second);
        t.assert_true("A7.projects", second.projects_to_durable_completion());
        t.assert_true("A7.no-authorize-new", !second.authorizes_modeled_completion());
        t.assert_true("A7.ledger-one", ledger.len() == 1);
    }

    // A8 — ConsumeReceiptDuplicateIdempotent only matches an already-recorded
    // completion report and never creates a new one by itself.
    {
        let c = devnet_ctx();
        // First, record a real completion report.
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let recorded = drive(&c.recorded(), &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A8.recorded-first", "completion-report-recorded", &recorded);
        // Now an idempotent-duplicate sink receipt matches the recorded report.
        let dup_input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptDuplicateIdempotent,
        );
        let dup = drive(&dup_input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A8.duplicate-matches", "completion-report-duplicate-idempotent", &dup);
        t.assert_true("A8.ledger-one", ledger.len() == 1);
        // And against an EMPTY ledger, an idempotent-duplicate creates nothing.
        let mut empty_ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter2 = devnet_reporter();
        let dup_empty = drive(&dup_input, &c.expectations, &mut reporter2, &mut empty_ledger);
        t.check_outcome(
            "A8.duplicate-empty",
            "completion-report-rejected-before-record",
            &dup_empty,
        );
        t.assert_true("A8.duplicate-empty-no-record", empty_ledger.is_empty());
    }

    // A9 — modeled add/retire/revoke/emergency-revoke/noop pipeline success each
    // record a completion report only after a recorded sink receipt. The completion
    // reporter consumes the Run 248 terminal sink outcome, so each governance action
    // is modeled by the same after-receipt-recorded gate.
    for (label, replay) in [
        ("add-root", R::MutationAuthorized),
        ("retire-root", R::MutationAuthorized),
        ("revoke-root", R::MutationAuthorized),
        ("emergency-revoke-root", R::MutationAuthorized),
        ("noop", R::MutationAuthorized),
    ] {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            replay,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::ConsumeReceiptRecorded,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(&format!("A9.{label}.outcome"), "completion-report-recorded", &o);
        t.assert_true(&format!("A9.{label}.ledger-one"), ledger.len() == 1);
    }

    // A10 — production reporter path reachable but unavailable/fail-closed; records
    // no completion report.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = ProductionModeledDurableConsumeCompletionReporter::default();
        let o = evaluate_modeled_durable_consume_completion_reporter(
            &input,
            &c.expectations,
            &mut reporter,
            &mut ledger,
        );
        t.check_outcome("A10.outcome", "production-reporter-unavailable-no-completion", &o);
        t.assert_true("A10.no-completion", o.no_completion());
        t.assert_true("A10.ledger-empty", ledger.is_empty());
        t.check("A10.kind", "production-unavailable", reporter.kind().tag());
        t.assert_true("A10.unavailable", reporter.kind().is_unavailable());
    }

    // A11 — MainNet reporter path reachable but unavailable/fail-closed; records no
    // completion report. Use a non-peer-driven MainNet surface so the MainNet
    // *reporter kind* (not the peer-driven refusal) is the reason no report is
    // recorded.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = MainNetModeledDurableConsumeCompletionReporter::default();
        let o = evaluate_modeled_durable_consume_completion_reporter(
            &input,
            &c.expectations,
            &mut reporter,
            &mut ledger,
        );
        t.check_outcome("A11.outcome", "mainnet-reporter-unavailable-no-completion", &o);
        t.assert_true("A11.ledger-empty", ledger.is_empty());
        t.check("A11.kind", "mainnet-unavailable", reporter.kind().tag());
    }

    // A12 — MainNet peer-driven apply refused before pipeline progression, before
    // sink invocation, and before reporter invocation.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        );
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            "A12.outcome",
            "mainnet-peer-driven-apply-refused-no-completion",
            &o,
        );
        t.assert_true("A12.refused", o.is_mainnet_peer_driven_apply_refused());
        t.assert_true("A12.no-invocation", reporter.invocations() == 0);
        t.assert_true("A12.ledger-empty", ledger.is_empty());
    }

    // A13 — validator-set rotation unsupported; records no completion report.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ValidatorSetRotationUnsupportedNoConsume,
            Sink::ValidatorSetRotationUnsupportedNoConsume,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            "A13.outcome",
            "validator-set-rotation-unsupported-no-completion",
            &o,
        );
        t.assert_true("A13.no-invocation", reporter.invocations() == 0);
        t.assert_true("A13.ledger-empty", ledger.is_empty());
    }

    // A14 — policy-change unsupported; records no completion report.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::PolicyChangeUnsupportedNoConsume,
            Sink::PolicyChangeUnsupportedNoConsume,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("A14.outcome", "policy-change-unsupported-no-completion", &o);
        t.assert_true("A14.no-invocation", reporter.invocations() == 0);
        t.assert_true("A14.ledger-empty", ledger.is_empty());
    }

    // A15 — existing Run 248 sink compatibility: only ConsumeReceiptRecorded projects
    // a create intent; ConsumeReceiptDuplicateIdempotent projects idempotent-only.
    {
        let create =
            project_sink_outcome_to_completion_report_intent(&Sink::ConsumeReceiptRecorded);
        t.assert_true("A15.recorded-creates-intent", create.creates_intent());
        t.assert_true("A15.recorded-is-create", create == CompletionReportIntent::CreateIntent);
        let idem = project_sink_outcome_to_completion_report_intent(
            &Sink::ConsumeReceiptDuplicateIdempotent,
        );
        t.assert_true("A15.duplicate-no-create", !idem.creates_intent());
        t.assert_true(
            "A15.duplicate-is-idempotent",
            idem == CompletionReportIntent::IdempotentOnly,
        );
    }

    t.finish(out)
}

// ===========================================================================
// B — rejection / fail-closed scenarios.
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use DurableReplayObservation as R;
    use GovernanceModeledDurableConsumeCompletionReporterPolicy as P;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("rejection");

    // B-sink — every non-recording sink outcome produces no reporter invocation and
    // no completion report.
    let sink_cases: [(&str, GovernanceModeledDurableConsumeSinkOutcome); 11] = [
        ("legacy-bypass", Sink::LegacyBypassNoReceipt),
        ("rejected-before-pipeline", Sink::RejectedBeforePipelineNoReceipt),
        (
            "pipeline-did-not-authorize",
            Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        ),
        ("sink-rejected-before-record", Sink::ConsumeReceiptRejectedBeforeRecord),
        ("sink-record-failed", Sink::ConsumeReceiptRecordFailedNoConsume),
        ("sink-rolled-back", Sink::ConsumeReceiptRolledBackNoConsume),
        (
            "sink-rollback-failed",
            Sink::ConsumeReceiptRollbackFailedFatalNoConsume,
        ),
        (
            "sink-ambiguous",
            Sink::ConsumeReceiptAmbiguousFailClosedNoConsume,
        ),
        ("production-sink-unavailable", Sink::ProductionSinkUnavailableNoConsume),
        ("mainnet-sink-unavailable", Sink::MainNetSinkUnavailableNoConsume),
        (
            "validator-set-rotation",
            Sink::ValidatorSetRotationUnsupportedNoConsume,
        ),
    ];
    for (label, sink) in sink_cases {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            sink,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true(&format!("B.{label}.no-completion"), o.no_completion());
        t.assert_true(
            &format!("B.{label}.no-invocation"),
            reporter.invocations() == 0,
        );
        t.assert_true(&format!("B.{label}.ledger-empty"), ledger.is_empty());
        t.assert_true(
            &format!("B.{label}.not-authorize"),
            !o.authorizes_modeled_completion(),
        );
    }

    // B-policy-change — also a no-completion outcome (kept separate so the array
    // length above stays explicit).
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::PolicyChangeUnsupportedNoConsume,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("B.policy-change.outcome", "policy-change-unsupported-no-completion", &o);
        t.assert_true("B.policy-change.no-invocation", reporter.invocations() == 0);
    }

    // B-fault — reporter record fault paths: invoked, no completion report.
    let fault_cases: [(&str, ModeledCompletionReportFault, &str); 4] = [
        (
            "record-failed",
            ModeledCompletionReportFault::RecordFailedNoCompletion,
            "completion-report-record-failed-no-completion",
        ),
        (
            "rollback",
            ModeledCompletionReportFault::RolledBackNoCompletion,
            "completion-report-rolled-back-no-completion",
        ),
        (
            "rollback-failed",
            ModeledCompletionReportFault::RollbackFailedFatal,
            "completion-report-rollback-failed-fatal-no-completion",
        ),
        (
            "ambiguous",
            ModeledCompletionReportFault::AmbiguousAfterRecord,
            "completion-report-ambiguous-fail-closed-no-completion",
        ),
    ];
    for (label, fault, tag) in fault_cases {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = FixtureModeledDurableConsumeCompletionReporter::with_fault(
            TrustBundleEnvironment::Devnet,
            fault,
        );
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(&format!("B.fault.{label}.outcome"), tag, &o);
        t.assert_true(&format!("B.fault.{label}.no-completion"), o.no_completion());
        t.assert_true(&format!("B.fault.{label}.invoked"), reporter.invocations() == 1);
        t.assert_true(&format!("B.fault.{label}.ledger-empty"), ledger.is_empty());
    }

    // B-equivocation — same report id with a different digest is rejected; no second report.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let first = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome("B.equiv.first", "completion-report-recorded", &first);
        let mut c2 = devnet_ctx();
        c2.report.report_digest = "completion-report-digest-DIFFERENT".to_string();
        c2.expectations.expected_report_digest = "completion-report-digest-DIFFERENT".to_string();
        let input2 = c2.recorded();
        let second = drive(&input2, &c2.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            "B.equiv.second",
            "completion-report-rejected-before-record",
            &second,
        );
        t.assert_true("B.equiv.no-completion", second.no_completion());
        t.assert_true("B.equiv.ledger-one", ledger.len() == 1);
    }

    // B-binding — environment / surface mismatches reject BEFORE reporter invocation.
    let binding_cases: [(&str, fn(&mut Ctx)); 5] = [
        ("wrong-environment", |c: &mut Ctx| {
            c.env.environment = TrustBundleEnvironment::Testnet;
        }),
        ("wrong-chain", |c: &mut Ctx| {
            c.env.chain_id = "qbind-other".to_string();
        }),
        ("wrong-genesis", |c: &mut Ctx| {
            c.env.genesis_hash = "genesis-wrong".to_string();
        }),
        ("wrong-governance-surface", |c: &mut Ctx| {
            c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup;
        }),
        ("wrong-mutation-surface", |c: &mut Ctx| {
            c.runtime.mutation_surface.mutation_surface =
                GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle;
        }),
    ];
    for (label, mutate) in binding_cases {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            &format!("B.binding.{label}.outcome"),
            "rejected-before-sink-no-completion-report",
            &o,
        );
        t.assert_true(
            &format!("B.binding.{label}.no-invocation"),
            reporter.invocations() == 0,
        );
        t.assert_true(&format!("B.binding.{label}.ledger-empty"), ledger.is_empty());
    }

    // B-report — report-identity mismatches reject BEFORE record (reporter IS invoked).
    let report_cases: [(&str, fn(&mut Ctx)); 9] = [
        ("wrong-report-digest", |c: &mut Ctx| {
            c.report.report_digest = "report-digest-wrong".to_string();
        }),
        ("wrong-receipt-digest", |c: &mut Ctx| {
            c.report.receipt_digest = "receipt-digest-wrong".to_string();
        }),
        ("wrong-sink-decision-digest", |c: &mut Ctx| {
            c.report.sink_decision_digest = "sink-digest-wrong".to_string();
        }),
        ("wrong-pipeline-decision-digest", |c: &mut Ctx| {
            c.report.pipeline_decision_digest = "pipeline-digest-wrong".to_string();
        }),
        ("wrong-proposal-id", |c: &mut Ctx| {
            c.report.proposal_id = "proposal-wrong".to_string();
        }),
        ("wrong-decision-id", |c: &mut Ctx| {
            c.report.decision_id = "decision-wrong".to_string();
        }),
        ("wrong-candidate-digest", |c: &mut Ctx| {
            c.report.candidate_digest = "candidate-wrong".to_string();
        }),
        ("wrong-authority-domain-sequence", |c: &mut Ctx| {
            c.report.authority_domain_sequence = 99;
        }),
        ("malformed-report", |c: &mut Ctx| {
            c.report.report_id = String::new();
        }),
    ];
    for (label, mutate) in report_cases {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            &format!("B.report.{label}.outcome"),
            "completion-report-rejected-before-record",
            &o,
        );
        t.assert_true(
            &format!("B.report.{label}.invoked"),
            reporter.invocations() == 1,
        );
        t.assert_true(&format!("B.report.{label}.ledger-empty"), ledger.is_empty());
    }

    // B-mainnet-authority — local operator / peer majority cannot satisfy MainNet authority.
    t.assert_true(
        "B.local-operator-cannot",
        modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "B.peer-majority-cannot",
        modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority(),
    );

    // B-production/mainnet reporter unavailable records no completion report (also A10/A11).
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut preporter = ProductionModeledDurableConsumeCompletionReporter::default();
        let po = evaluate_modeled_durable_consume_completion_reporter(
            &input,
            &c.expectations,
            &mut preporter,
            &mut ledger,
        );
        t.check_outcome(
            "B.production-unavailable",
            "production-reporter-unavailable-no-completion",
            &po,
        );
        t.assert_true("B.production-ledger-empty", ledger.is_empty());
    }

    // B-completion-before-sink-receipt — a recorded report cannot exist before the
    // sink recorded a receipt; the sink-did-not-record path returns no completion.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
            Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            "B.completion-before-sink-receipt",
            "sink-did-not-record-receipt-no-completion-report",
            &o,
        );
        t.assert_true("B.completion-before-sink-receipt.no-invocation", reporter.invocations() == 0);
    }

    t.finish(out)
}

// ===========================================================================
// C — recovery / crash-window scenarios.
// ===========================================================================

fn recover_devnet(
    window: ModeledDurableConsumeCompletionReportWindow,
    report: Option<&GovernanceModeledDurableConsumeCompletionReport>,
) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
    let c = devnet_ctx();
    let input = c.recorded();
    recover_modeled_durable_consume_completion_reporter_window(
        &input,
        window,
        ModeledDurableConsumeCompletionReporterKind::FixtureDevNet,
        report,
        &c.expectations,
    )
}

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use ModeledDurableConsumeCompletionReportWindow as W;
    let mut t = Table::new("recovery");

    t.check_outcome(
        "C.before-pipeline",
        "sink-did-not-record-receipt-no-completion-report",
        &recover_devnet(W::BeforePipeline, None),
    );
    t.check_outcome(
        "C.after-pipeline-before-sink-intent",
        "sink-did-not-record-receipt-no-completion-report",
        &recover_devnet(W::AfterPipelineSuccessBeforeSinkIntent, None),
    );
    t.check_outcome(
        "C.after-sink-intent-before-receipt-record",
        "sink-did-not-record-receipt-no-completion-report",
        &recover_devnet(W::AfterSinkIntentBeforeReceiptRecord, None),
    );
    t.check_outcome(
        "C.after-receipt-record-before-report-intent",
        "completion-report-rejected-before-record",
        &recover_devnet(W::AfterReceiptRecordBeforeReportIntent, None),
    );
    t.check_outcome(
        "C.after-report-intent-before-report-record",
        "completion-report-rejected-before-record",
        &recover_devnet(W::AfterReportIntentBeforeReportRecord, None),
    );
    t.check_outcome(
        "C.after-report-record-before-success-no-report",
        "completion-report-rejected-before-record",
        &recover_devnet(W::AfterReportRecordBeforeReportSuccess, None),
    );
    {
        let c = devnet_ctx();
        let report = c.report.clone();
        t.check_outcome(
            "C.after-report-record-before-success-with-report",
            "completion-report-recorded",
            &recover_devnet(W::AfterReportRecordBeforeReportSuccess, Some(&report)),
        );
    }
    {
        let c = devnet_ctx();
        let report = c.report.clone();
        t.check_outcome(
            "C.after-report-success",
            "completion-report-recorded",
            &recover_devnet(W::AfterReportSuccess, Some(&report)),
        );
    }
    t.check_outcome(
        "C.after-report-ambiguous",
        "completion-report-ambiguous-fail-closed-no-completion",
        &recover_devnet(W::AfterReportAmbiguous, None),
    );
    t.check_outcome(
        "C.report-record-failed",
        "completion-report-record-failed-no-completion",
        &recover_devnet(W::ReportRecordFailed, None),
    );
    t.check_outcome(
        "C.rollback-completed",
        "completion-report-rolled-back-no-completion",
        &recover_devnet(W::RollbackCompleted, None),
    );
    t.check_outcome(
        "C.rollback-failed",
        "completion-report-rollback-failed-fatal-no-completion",
        &recover_devnet(W::RollbackFailed, None),
    );
    t.check_outcome(
        "C.unknown",
        "completion-report-ambiguous-fail-closed-no-completion",
        &recover_devnet(W::Unknown, None),
    );

    // Production / MainNet recovery classification unavailable.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let o = recover_modeled_durable_consume_completion_reporter_window(
            &input,
            W::AfterReportSuccess,
            ModeledDurableConsumeCompletionReporterKind::ProductionUnavailable,
            None,
            &c.expectations,
        );
        t.check_outcome(
            "C.production-unavailable",
            "production-reporter-unavailable-no-completion",
            &o,
        );
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = c.recorded();
        let o = recover_modeled_durable_consume_completion_reporter_window(
            &input,
            W::AfterReportSuccess,
            ModeledDurableConsumeCompletionReporterKind::MainNetUnavailable,
            None,
            &c.expectations,
        );
        t.check_outcome(
            "C.mainnet-unavailable",
            "mainnet-reporter-unavailable-no-completion",
            &o,
        );
    }

    // MainNet peer-driven apply refusal precedes recovery classification.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        );
        let input = c.recorded();
        let report = c.report.clone();
        let o = recover_modeled_durable_consume_completion_reporter_window(
            &input,
            W::AfterReportSuccess,
            ModeledDurableConsumeCompletionReporterKind::FixtureDevNet,
            Some(&report),
            &c.expectations,
        );
        t.check_outcome(
            "C.mainnet-peer-driven-precedes",
            "mainnet-peer-driven-apply-refused-no-completion",
            &o,
        );
    }

    t.finish(out)
}

// ===========================================================================
// D — projection scenarios.
// ===========================================================================

fn run_projection_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    let mut t = Table::new("projection");

    // Only the Run 248 ConsumeReceiptRecorded sink outcome creates a completion-report intent.
    t.assert_true(
        "D.only-recorded-creates-intent",
        project_sink_outcome_to_completion_report_intent(&Sink::ConsumeReceiptRecorded)
            .creates_intent(),
    );

    // ConsumeReceiptDuplicateIdempotent never creates a new completion report.
    t.assert_true(
        "D.duplicate-no-create",
        !project_sink_outcome_to_completion_report_intent(&Sink::ConsumeReceiptDuplicateIdempotent)
            .creates_intent(),
    );
    t.assert_true(
        "D.duplicate-is-idempotent",
        project_sink_outcome_to_completion_report_intent(&Sink::ConsumeReceiptDuplicateIdempotent)
            == CompletionReportIntent::IdempotentOnly,
    );

    // Predecessor authorizations alone create no completion-report intent.
    for (label, sink) in [
        ("sink-rejected-before-record", Sink::ConsumeReceiptRejectedBeforeRecord),
        ("legacy-bypass", Sink::LegacyBypassNoReceipt),
        ("rejected-before-pipeline", Sink::RejectedBeforePipelineNoReceipt),
        (
            "pipeline-did-not-authorize",
            Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        ),
    ] {
        t.assert_true(
            &format!("D.{label}.no-intent"),
            !project_sink_outcome_to_completion_report_intent(&sink).creates_intent(),
        );
    }

    // Only CompletionReportRecorded authorizes a new modeled completion-reported state.
    t.assert_true(
        "D.recorded-authorizes",
        completion_reporter_outcome_authorizes_modeled_completion(&Report::CompletionReportRecorded),
    );

    // Every no-completion outcome does not authorize a new completion.
    let no_completion: [(&str, GovernanceModeledDurableConsumeCompletionReporterOutcome); 13] = [
        ("legacy-bypass", Report::LegacyBypassNoCompletionReport),
        ("rejected-before-sink", Report::RejectedBeforeSinkNoCompletionReport),
        (
            "sink-did-not-record-receipt",
            Report::SinkDidNotRecordReceiptNoCompletionReport,
        ),
        ("rejected-before-record", Report::CompletionReportRejectedBeforeRecord),
        ("record-failed", Report::CompletionReportRecordFailedNoCompletion),
        ("rolled-back", Report::CompletionReportRolledBackNoCompletion),
        (
            "rollback-failed-fatal",
            Report::CompletionReportRollbackFailedFatalNoCompletion,
        ),
        (
            "ambiguous-fail-closed",
            Report::CompletionReportAmbiguousFailClosedNoCompletion,
        ),
        (
            "production-unavailable",
            Report::ProductionReporterUnavailableNoCompletion,
        ),
        ("mainnet-unavailable", Report::MainNetReporterUnavailableNoCompletion),
        (
            "mainnet-peer-driven-refused",
            Report::MainNetPeerDrivenApplyRefusedNoCompletion,
        ),
        (
            "validator-set-rotation",
            Report::ValidatorSetRotationUnsupportedNoCompletion,
        ),
        ("policy-change", Report::PolicyChangeUnsupportedNoCompletion),
    ];
    for (label, outcome) in no_completion {
        t.assert_true(
            &format!("D.{label}.no-authorize-new"),
            !completion_reporter_outcome_authorizes_modeled_completion(&outcome),
        );
        t.assert_true(
            &format!("D.{label}.no-project"),
            !completion_reporter_outcome_projects_to_durable_completion(&outcome),
        );
    }

    // Recorded and idempotent-duplicate both project to durable completion; the
    // duplicate must not be counted as a new completion.
    t.assert_true(
        "D.recorded-projects",
        completion_reporter_outcome_projects_to_durable_completion(&Report::CompletionReportRecorded),
    );
    t.assert_true(
        "D.duplicate-projects",
        completion_reporter_outcome_projects_to_durable_completion(
            &Report::CompletionReportDuplicateIdempotent,
        ),
    );
    t.assert_true(
        "D.duplicate-not-new",
        !completion_reporter_outcome_authorizes_modeled_completion(
            &Report::CompletionReportDuplicateIdempotent,
        ),
    );

    t.finish(out)
}

// ===========================================================================
// E — stage-ordering scenarios.
// ===========================================================================

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    use DurableReplayObservation as R;
    use GovernanceModeledDurableConsumeCompletionReporterPolicy as P;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("stage_ordering");

    // E1 — MainNet peer-driven apply refusal precedes pipeline progression, sink
    // invocation, and reporter invocation.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        );
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("E1.refused", o.is_mainnet_peer_driven_apply_refused());
        t.assert_true("E1.no-invocation", reporter.invocations() == 0);
    }

    // E2 — a rejection before the reporter stage leaves the reporter invocation count at zero.
    {
        let mut c = devnet_ctx();
        c.env.environment = TrustBundleEnvironment::Testnet;
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("E2.invocation-zero", reporter.invocations() == 0);
        t.assert_true("E2.ledger-empty", ledger.is_empty());
    }

    // E3 — completion report recording happens only after a recorded sink receipt.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        t.assert_true(
            "E3.sink-recorded-receipt",
            project_sink_outcome_to_completion_report_intent(&input.sink_binding).creates_intent(),
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("E3.recorded", o.authorizes_modeled_completion());
        t.assert_true("E3.invoked-after", reporter.invocations() == 1);
    }

    // E4 — a reporter record failure does not retroactively invalidate the
    // sink-recorded receipt, but does not authorize completion.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        t.assert_true(
            "E4.sink-still-recorded",
            project_sink_outcome_to_completion_report_intent(&input.sink_binding).creates_intent(),
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = FixtureModeledDurableConsumeCompletionReporter::with_fault(
            TrustBundleEnvironment::Devnet,
            ModeledCompletionReportFault::RecordFailedNoCompletion,
        );
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("E4.no-completion", o.no_completion());
        t.assert_true("E4.ledger-empty", ledger.is_empty());
    }

    // E5 — a reporter rollback failure is fatal / fail-closed and does not authorize completion.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = FixtureModeledDurableConsumeCompletionReporter::with_fault(
            TrustBundleEnvironment::Devnet,
            ModeledCompletionReportFault::RollbackFailedFatal,
        );
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.check_outcome(
            "E5.outcome",
            "completion-report-rollback-failed-fatal-no-completion",
            &o,
        );
        t.assert_true("E5.no-completion", o.no_completion());
    }

    // E6 — the reporter performs no persistent durable consume beyond modeled
    // in-memory fixture state: a non-recording sink never touches the ledger or
    // invokes the reporter.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ModeledApplierApplyFailedNoConsume,
            Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        );
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("E6.ledger-empty", ledger.is_empty());
        t.assert_true("E6.no-invocation", reporter.invocations() == 0);
    }

    t.finish(out)
}

// ===========================================================================
// F — completion-report-ledger scenarios.
// ===========================================================================

fn run_completion_report_ledger_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("completion_report_ledger");

    // F1 — one valid completion report inserts exactly one modeled in-memory record.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("F1.len-one", ledger.len() == 1);
        t.assert_true("F1.records-one", ledger.records().len() == 1);
        t.assert_true("F1.contains", ledger.contains(REPORT_ID));
    }

    // F2 — duplicate identical completion report is idempotent; record count unchanged.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("F2.len-one", ledger.len() == 1);
    }

    // F3 — same report id, different digest is equivocation; record count unchanged.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        let mut c2 = devnet_ctx();
        c2.report.report_digest = "different-digest".to_string();
        c2.expectations.expected_report_digest = "different-digest".to_string();
        let input2 = c2.recorded();
        let o = drive(&input2, &c2.expectations, &mut reporter, &mut ledger);
        t.assert_true("F3.rejected", o.no_completion());
        t.assert_true("F3.len-one", ledger.len() == 1);
    }

    // F4 — wrong identity fields never record (reporter invoked, rejected before record).
    let wrong_fields: [(&str, fn(&mut Ctx)); 7] = [
        ("wrong-report-digest", |c: &mut Ctx| {
            c.report.report_digest = "wrong".to_string();
        }),
        ("wrong-receipt-digest", |c: &mut Ctx| {
            c.report.receipt_digest = "wrong".to_string();
        }),
        ("wrong-sink-decision-digest", |c: &mut Ctx| {
            c.report.sink_decision_digest = "wrong".to_string();
        }),
        ("wrong-pipeline-decision-digest", |c: &mut Ctx| {
            c.report.pipeline_decision_digest = "wrong".to_string();
        }),
        ("wrong-proposal", |c: &mut Ctx| {
            c.report.proposal_id = "wrong".to_string();
        }),
        ("wrong-authority-sequence", |c: &mut Ctx| {
            c.report.authority_domain_sequence = 123;
        }),
        ("malformed", |c: &mut Ctx| {
            c.report.report_id = String::new();
        }),
    ];
    for (label, mutate) in wrong_fields {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true(&format!("F4.{label}.no-record"), ledger.is_empty());
        t.assert_true(&format!("F4.{label}.no-completion"), o.no_completion());
    }

    // F5 — rollback restores modeled completion-report ledger snapshot exactly.
    {
        let c = devnet_ctx();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        let snap = ledger.snapshot();
        t.assert_true("F5.snap-len-one", snap.len() == 1);
        t.assert_true("F5.snap-not-empty", !snap.is_empty());
        let mut ledger2 = ModeledDurableConsumeCompletionReportLedger::new();
        ledger2.restore(&snap);
        t.assert_true("F5.restore-len-one", ledger2.len() == 1);
        t.assert_true("F5.restore-contains", ledger2.contains(REPORT_ID));
    }

    // F6 — fixture ledger digest equality reflects the report digest material.
    {
        let c = devnet_ctx();
        let digest = c.report.digest();
        let record_digest = {
            let input = c.recorded();
            let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
            let mut reporter = devnet_reporter();
            let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
            ledger.find(REPORT_ID).map(|r| r.digest.clone())
        };
        t.assert_true("F6.digest-matches", record_digest.as_ref() == Some(&digest));
    }

    t.finish(out)
}

// ===========================================================================
// G — non-mutation scenarios (invariant helpers + ledger-only effect proof).
// ===========================================================================

fn run_non_mutation_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("non_mutation");

    t.assert_true(
        "G.rejection-non-mutating",
        modeled_completion_reporter_rejection_is_non_mutating(),
    );
    t.assert_true(
        "G.never-calls-run-070",
        modeled_completion_reporter_never_calls_run_070(),
    );
    t.assert_true(
        "G.never-mutates-live",
        modeled_completion_reporter_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.never-writes-sequence-or-marker",
        modeled_completion_reporter_never_writes_sequence_or_marker(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        modeled_completion_reporter_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "G.pipeline-success-required",
        modeled_completion_reporter_pipeline_success_required_before_report(),
    );
    t.assert_true(
        "G.sink-receipt-required",
        modeled_completion_reporter_sink_receipt_required_before_report(),
    );
    t.assert_true(
        "G.report-record-required",
        modeled_completion_reporter_report_record_required_before_completion(),
    );
    t.assert_true(
        "G.failed-record-never-completes",
        modeled_completion_reporter_failed_record_never_completes(),
    );
    t.assert_true(
        "G.rollback-never-completes",
        modeled_completion_reporter_rollback_never_completes(),
    );
    t.assert_true(
        "G.ambiguous-fails-closed",
        modeled_completion_reporter_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "G.mainnet-refused-mainnet",
        modeled_completion_reporter_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet,
        ),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !modeled_completion_reporter_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet,
        ),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        modeled_completion_reporter_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        modeled_completion_reporter_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "G.policy-change-unsupported",
        modeled_completion_reporter_policy_change_unsupported(),
    );
    t.assert_true(
        "G.local-operator-cannot",
        modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority(),
    );

    // G — the fixture reporter mutates ONLY the in-memory ledger; a rejected path
    // leaves the ledger untouched.
    {
        let mut c = devnet_ctx();
        c.env.genesis_hash = "wrong".to_string();
        let input = c.recorded();
        let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
        let mut reporter = devnet_reporter();
        let _ = drive(&input, &c.expectations, &mut reporter, &mut ledger);
        t.assert_true("G.rejected-ledger-empty", ledger.is_empty());
        t.assert_true("G.rejected-no-invocation", reporter.invocations() == 0);
    }

    t.finish(out)
}

// ===========================================================================
// H — reachability scenarios: tags / taxonomy minted in release mode.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    let mut t = Table::new("reachability");

    t.check(
        "H.tag-legacy-bypass",
        "legacy-bypass-no-completion-report",
        Report::LegacyBypassNoCompletionReport.tag(),
    );
    t.check(
        "H.tag-rejected-before-sink",
        "rejected-before-sink-no-completion-report",
        Report::RejectedBeforeSinkNoCompletionReport.tag(),
    );
    t.check(
        "H.tag-sink-did-not-record",
        "sink-did-not-record-receipt-no-completion-report",
        Report::SinkDidNotRecordReceiptNoCompletionReport.tag(),
    );
    t.check(
        "H.tag-recorded",
        "completion-report-recorded",
        Report::CompletionReportRecorded.tag(),
    );
    t.check(
        "H.tag-duplicate",
        "completion-report-duplicate-idempotent",
        Report::CompletionReportDuplicateIdempotent.tag(),
    );
    t.check(
        "H.tag-rejected-before-record",
        "completion-report-rejected-before-record",
        Report::CompletionReportRejectedBeforeRecord.tag(),
    );
    t.check(
        "H.tag-record-failed",
        "completion-report-record-failed-no-completion",
        Report::CompletionReportRecordFailedNoCompletion.tag(),
    );
    t.check(
        "H.tag-rolled-back",
        "completion-report-rolled-back-no-completion",
        Report::CompletionReportRolledBackNoCompletion.tag(),
    );
    t.check(
        "H.tag-rollback-failed",
        "completion-report-rollback-failed-fatal-no-completion",
        Report::CompletionReportRollbackFailedFatalNoCompletion.tag(),
    );
    t.check(
        "H.tag-ambiguous",
        "completion-report-ambiguous-fail-closed-no-completion",
        Report::CompletionReportAmbiguousFailClosedNoCompletion.tag(),
    );
    t.check(
        "H.tag-production-unavailable",
        "production-reporter-unavailable-no-completion",
        Report::ProductionReporterUnavailableNoCompletion.tag(),
    );
    t.check(
        "H.tag-mainnet-unavailable",
        "mainnet-reporter-unavailable-no-completion",
        Report::MainNetReporterUnavailableNoCompletion.tag(),
    );
    t.check(
        "H.tag-mainnet-peer-driven-refused",
        "mainnet-peer-driven-apply-refused-no-completion",
        Report::MainNetPeerDrivenApplyRefusedNoCompletion.tag(),
    );
    t.check(
        "H.tag-validator-rotation",
        "validator-set-rotation-unsupported-no-completion",
        Report::ValidatorSetRotationUnsupportedNoCompletion.tag(),
    );
    t.check(
        "H.tag-policy-change",
        "policy-change-unsupported-no-completion",
        Report::PolicyChangeUnsupportedNoCompletion.tag(),
    );

    // Reporter kind tags + predicates.
    t.check(
        "H.kind-devnet",
        "fixture-devnet",
        ModeledDurableConsumeCompletionReporterKind::FixtureDevNet.tag(),
    );
    t.check(
        "H.kind-testnet",
        "fixture-testnet",
        ModeledDurableConsumeCompletionReporterKind::FixtureTestNet.tag(),
    );
    t.check(
        "H.kind-production",
        "production-unavailable",
        ModeledDurableConsumeCompletionReporterKind::ProductionUnavailable.tag(),
    );
    t.check(
        "H.kind-mainnet",
        "mainnet-unavailable",
        ModeledDurableConsumeCompletionReporterKind::MainNetUnavailable.tag(),
    );
    t.assert_true(
        "H.kind-devnet-is-fixture",
        ModeledDurableConsumeCompletionReporterKind::FixtureDevNet.is_fixture(),
    );
    t.assert_true(
        "H.kind-production-unavailable",
        ModeledDurableConsumeCompletionReporterKind::ProductionUnavailable.is_unavailable(),
    );

    // Policy predicate reachability.
    t.assert_true(
        "H.policy-wired",
        GovernanceModeledDurableConsumeCompletionReporterPolicy::wired().is_wired(),
    );
    t.assert_true(
        "H.policy-disabled-not-wired",
        !GovernanceModeledDurableConsumeCompletionReporterPolicy::disabled().is_wired(),
    );

    t.finish(out)
}

// ===========================================================================
// Fixture dump (decision values minted in release mode).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");

    // Full success lifecycle: pipeline authorized -> sink receipt recorded -> report record.
    let c = devnet_ctx();
    let input = c.recorded();
    let mut ledger = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter = devnet_reporter();
    let o = drive(&input, &c.expectations, &mut reporter, &mut ledger);
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} authorizes={} projects={} invocations={} ledger_len={} contains={}\n",
            o.tag(),
            o.authorizes_modeled_completion(),
            o.projects_to_durable_completion(),
            reporter.invocations(),
            ledger.len(),
            ledger.contains(REPORT_ID),
        ),
    );

    // Rejected lifecycle: wrong genesis -> rejected-before-sink, no invocation, no record.
    let mut c2 = devnet_ctx();
    c2.env.genesis_hash = "wrong-genesis".to_string();
    let input2 = c2.recorded();
    let mut ledger2 = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter2 = devnet_reporter();
    let o2 = drive(&input2, &c2.expectations, &mut reporter2, &mut ledger2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} invocations={} no_completion={} ledger_len={}\n",
            o2.tag(),
            reporter2.invocations(),
            o2.no_completion(),
            ledger2.len(),
        ),
    );

    // MainNet peer-driven refusal precedes everything.
    let c3 = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input3 = c3.recorded();
    let mut ledger3 = ModeledDurableConsumeCompletionReportLedger::new();
    let mut reporter3 = devnet_reporter();
    let o3 = drive(&input3, &c3.expectations, &mut reporter3, &mut ledger3);
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} invocations={} is_refusal={} ledger_len={}\n",
            o3.tag(),
            reporter3.invocations(),
            o3.is_mainnet_peer_driven_apply_refused(),
            ledger3.len(),
        ),
    );

    // Recovery window classifications.
    let mut windows = String::new();
    let c4 = devnet_ctx();
    let report = c4.report.clone();
    for (label, window, rep) in [
        (
            "before-pipeline",
            ModeledDurableConsumeCompletionReportWindow::BeforePipeline,
            None,
        ),
        (
            "after-sink-intent-before-receipt-record",
            ModeledDurableConsumeCompletionReportWindow::AfterSinkIntentBeforeReceiptRecord,
            None,
        ),
        (
            "after-report-record-before-success-with-report",
            ModeledDurableConsumeCompletionReportWindow::AfterReportRecordBeforeReportSuccess,
            Some(&report),
        ),
        (
            "after-report-success",
            ModeledDurableConsumeCompletionReportWindow::AfterReportSuccess,
            Some(&report),
        ),
        (
            "after-report-ambiguous",
            ModeledDurableConsumeCompletionReportWindow::AfterReportAmbiguous,
            None,
        ),
        (
            "rollback-failed",
            ModeledDurableConsumeCompletionReportWindow::RollbackFailed,
            None,
        ),
        (
            "unknown",
            ModeledDurableConsumeCompletionReportWindow::Unknown,
            None,
        ),
    ] {
        let o = recover_devnet(window, rep);
        windows.push_str(&format!("{label}={}\n", o.tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_251_modeled_durable_consume_completion_reporter_release_binary_helper <OUT_DIR>"
        );
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("stage_ordering", run_stage_ordering_table),
        ("completion_report_ledger", run_completion_report_ledger_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_251_modeled_durable_consume_completion_reporter_release_binary_helper\nscope: Run 250 governance modeled durable-consume receipt-acknowledgement / completion reporter boundary (pqc_governance_modeled_durable_consume_completion_reporter: evaluate_modeled_durable_consume_completion_reporter, recover_modeled_durable_consume_completion_reporter_window, project_sink_outcome_to_completion_report_intent, completion_reporter_outcome_authorizes_modeled_completion, completion_reporter_outcome_projects_to_durable_completion, the GovernanceModeledDurableConsumeCompletionReporter trait with FixtureModeledDurableConsumeCompletionReporter/ProductionModeledDurableConsumeCompletionReporter/MainNetModeledDurableConsumeCompletionReporter, the GovernanceModeledDurableConsumeCompletionReporterInput/Expectations/Policy/Surface/EnvironmentBinding/RuntimeBinding/ReplayBinding/PipelineBinding/SinkBinding bindings, the GovernanceModeledDurableConsumeCompletionReport plus the ModeledDurableConsumeCompletionReportLedger/Record/Snapshot/Status/Digest modeled in-memory ledger, the GovernanceModeledDurableConsumeCompletionReporterOutcome taxonomy, the CompletionReportIntent projection, the ModeledCompletionReportFault injector, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure typed projection over an in-memory ledger (the DevNet/TestNet fixture reporter mutates ONLY the in-memory ModeledDurableConsumeCompletionReportLedger; no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState mutation, no durable consume of its own, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a disabled reporter/sink/pipeline/evaluator-call-site policy is a legacy bypass with no completion report and no reporter invocation; MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, and before any reporter invocation; Run 246 pipeline success is required before any sink intent and Run 248 ConsumeReceiptRecorded is required before any completion-report intent; only ConsumeReceiptRecorded creates a completion-report intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded completion report; only CompletionReportRecorded authorizes a new modeled completion-reported state; a duplicate identical completion report is idempotent (no second report) and the same report id with a different digest fails closed as equivocation; every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never completes; a rejection before the reporter stage leaves the reporter invocation count at zero\n\n",
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