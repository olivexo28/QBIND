//! Run 249 — release-built helper for the Run 248 governance **modeled
//! durable-consume projection sink boundary**
//! (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`).
//!
//! Where Run 248 landed the pure, typed modeled durable-consume projection sink
//! at the source/test level and captured **no** release-binary evidence, Run 249
//! is that release-binary evidence. This helper drives an accepted/compatible,
//! rejection, recovery, projection, stage-ordering, non-mutation, receipt-ledger,
//! and reachability corpus through the **release-built** Run 248 symbols
//! (`evaluate_modeled_durable_consume_projection_sink`,
//! `recover_modeled_durable_consume_projection_sink_window`,
//! `project_pipeline_outcome_to_consume_sink_intent`,
//! `sink_outcome_authorizes_modeled_consume_receipt`,
//! `sink_outcome_projects_to_durable_completion`, the
//! `GovernanceModeledDurableConsumeProjectionSink` trait boundary with
//! `FixtureModeledDurableConsumeProjectionSink` /
//! `ProductionModeledDurableConsumeProjectionSink` /
//! `MainNetModeledDurableConsumeProjectionSink`, the
//! `GovernanceModeledDurableConsumeSinkInput` /
//! `GovernanceModeledDurableConsumeSinkExpectations` /
//! `GovernanceModeledDurableConsumeSinkPolicy` /
//! `GovernanceModeledDurableConsumeSinkSurface` /
//! `GovernanceModeledDurableConsumeSinkEnvironmentBinding` /
//! `GovernanceModeledDurableConsumeSinkRuntimeBinding` /
//! `GovernanceModeledDurableConsumeSinkReplayBinding` /
//! `GovernanceModeledDurableConsumeSinkPipelineBinding` bindings, the
//! `GovernanceModeledDurableConsumeSinkReceipt` plus the
//! `ModeledDurableConsumeReceiptLedger` /
//! `ModeledDurableConsumeReceiptRecord` /
//! `ModeledDurableConsumeReceiptSnapshot` /
//! `ModeledDurableConsumeReceiptStatus` /
//! `ModeledDurableConsumeReceiptDigest` modeled in-memory ledger, the
//! `GovernanceModeledDurableConsumeSinkOutcome` taxonomy, the `ConsumeSinkIntent`
//! projection, the `ModeledConsumeSinkFault` injector, and the grep-verifiable
//! invariant / fail-closed helpers), proving in release mode that:
//!
//! * a disabled sink / pipeline / evaluator-call-site policy preserves the legacy
//!   no-receipt, no-consume bypass and never invokes the sink;
//! * a DevNet/TestNet fixture pipeline success + sink record success records
//!   exactly one modeled in-memory consume receipt;
//! * the only outcome that creates a sink intent is the Run 246
//!   `ModeledApplierAppliedAndDurableConsumeAuthorized`; every other pipeline
//!   outcome maps to a no-receipt fail-closed outcome and never invokes the sink;
//! * only `ConsumeReceiptRecorded` authorizes a new modeled receipt-recorded
//!   state; a duplicate identical receipt is idempotent (no second record); the
//!   same receipt id with a different digest fails closed as equivocation;
//! * every evaluator/call-site rejection, durable replay rejection
//!   (stale/expired/consumed/superseded/backend-unavailable), mutation-engine
//!   rejection, modeled applier reject-before-snapshot / reject-before-apply /
//!   apply-failure / rollback / rollback-failed / ambiguous, binding mismatch,
//!   receipt-identity mismatch, malformed receipt, record failure, rollback,
//!   rollback failure, ambiguous receipt window, unavailable production/MainNet
//!   sink path, validator-set rotation, and policy-change attempt is non-mutating
//!   and non-consuming;
//! * a rejection before the sink stage leaves the sink invocation count at zero;
//! * MainNet peer-driven apply is refused before pipeline projection and before
//!   any sink invocation;
//! * the crash-window recovery classification fails closed on every
//!   before-pipeline / after-pipeline / after-sink-intent / ambiguous /
//!   record-failed / rollback / rollback-failed / unknown window, and recovers as
//!   recorded only with an explicit matching receipt report.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real durable
//! consume backend, persistent replay backend, governance execution engine,
//! mutation engine, on-chain proof verifier, KMS/HSM, or RemoteSigner backend. No
//! RocksDB/file/schema/migration/storage-format change. The sink is a pure typed
//! projection over an in-memory ledger; the DevNet/TestNet fixture sink mutates
//! only the modeled in-memory `ModeledDurableConsumeReceiptLedger`; it never
//! mutates `LivePqcTrustState`, calls Run 070, performs a real trust swap, evicts
//! sessions, writes a sequence, writes a marker, or performs a durable consume of
//! its own. MainNet peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_durable_consume_projection_sink::{
    evaluate_modeled_durable_consume_projection_sink,
    modeled_consume_sink_ambiguous_window_fails_closed,
    modeled_consume_sink_failed_record_never_consumes,
    modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority,
    modeled_consume_sink_mainnet_peer_driven_apply_refused_first,
    modeled_consume_sink_never_calls_run_070,
    modeled_consume_sink_never_mutates_live_pqc_trust_state,
    modeled_consume_sink_never_writes_sequence_or_marker,
    modeled_consume_sink_no_rocksdb_file_schema_migration_change,
    modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_consume_sink_pipeline_success_required_before_receipt,
    modeled_consume_sink_policy_change_unsupported,
    modeled_consume_sink_production_mainnet_unavailable,
    modeled_consume_sink_receipt_record_required_before_consume,
    modeled_consume_sink_rejection_is_non_mutating, modeled_consume_sink_rollback_never_consumes,
    modeled_consume_sink_validator_set_rotation_unsupported,
    project_pipeline_outcome_to_consume_sink_intent,
    recover_modeled_durable_consume_projection_sink_window,
    sink_outcome_authorizes_modeled_consume_receipt, sink_outcome_projects_to_durable_completion,
    ConsumeSinkIntent, FixtureModeledDurableConsumeProjectionSink,
    GovernanceModeledDurableConsumeProjectionSink, GovernanceModeledDurableConsumeSinkExpectations,
    GovernanceModeledDurableConsumeSinkInput, GovernanceModeledDurableConsumeSinkOutcome,
    GovernanceModeledDurableConsumeSinkPolicy, GovernanceModeledDurableConsumeSinkReceipt,
    MainNetModeledDurableConsumeProjectionSink, ModeledConsumeSinkFault,
    ModeledDurableConsumeReceiptLedger, ModeledDurableConsumeReceiptStatus,
    ModeledDurableConsumeReceiptWindow, ModeledDurableConsumeSinkKind,
    ProductionModeledDurableConsumeProjectionSink,
};
use qbind_node::pqc_governance_modeled_end_to_end_pipeline::{
    DurableReplayObservation, GovernanceModeledEndToEndPipelineOutcome,
};
use qbind_node::pqc_governance_modeled_trust_mutation_applier::{
    ModeledGovernanceTrustMutationEnvironmentBinding, ModeledGovernanceTrustMutationRuntimeBinding,
    ModeledGovernanceTrustMutationSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 248 corpus so the composed material binds to
// the same trust domain, proposal/decision identity, candidate digest).
// ===========================================================================

const RECEIPT_ID: &str = "consume-receipt-0001";
const RECEIPT_DIGEST: &str = "consume-receipt-digest-rrrrrrrrrrrrrrrr";
const PIPELINE_DIGEST: &str = "modeled-pipeline-decision-digest-pppppppp";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SEQUENCE: u64 = 7;

// ===========================================================================
// Owned-context builder (mirrors the Run 248 test owned-context builder).
// ===========================================================================

struct Ctx {
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    receipt: GovernanceModeledDurableConsumeSinkReceipt,
    expectations: GovernanceModeledDurableConsumeSinkExpectations,
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
    let receipt = GovernanceModeledDurableConsumeSinkReceipt {
        receipt_id: RECEIPT_ID.to_string(),
        receipt_digest: RECEIPT_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    let expectations = GovernanceModeledDurableConsumeSinkExpectations {
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
        expected_receipt_digest: RECEIPT_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_pipeline_decision_digest: PIPELINE_DIGEST.to_string(),
    };
    Ctx {
        env,
        runtime,
        receipt,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        policy: GovernanceModeledDurableConsumeSinkPolicy,
        replay: DurableReplayObservation,
        pipeline: GovernanceModeledEndToEndPipelineOutcome,
    ) -> GovernanceModeledDurableConsumeSinkInput {
        GovernanceModeledDurableConsumeSinkInput {
            policy,
            environment_binding: self.env.clone(),
            runtime_binding: self.runtime.clone(),
            replay_binding: replay,
            pipeline_binding: pipeline,
            receipt: self.receipt.clone(),
        }
    }

    /// The canonical "pipeline authorized consume" wired input.
    fn authorized(&self) -> GovernanceModeledDurableConsumeSinkInput {
        self.input(
            GovernanceModeledDurableConsumeSinkPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized,
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

fn devnet_sink() -> FixtureModeledDurableConsumeProjectionSink {
    FixtureModeledDurableConsumeProjectionSink::new(TrustBundleEnvironment::Devnet)
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
        o: &GovernanceModeledDurableConsumeSinkOutcome,
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

/// Drive a sink round-trip with the canonical happy-path parameters over a fresh
/// DevNet fixture sink and an empty (or supplied) modeled ledger.
fn drive(
    input: &GovernanceModeledDurableConsumeSinkInput,
    expectations: &GovernanceModeledDurableConsumeSinkExpectations,
    sink: &mut FixtureModeledDurableConsumeProjectionSink,
    ledger: &mut ModeledDurableConsumeReceiptLedger,
) -> GovernanceModeledDurableConsumeSinkOutcome {
    evaluate_modeled_durable_consume_projection_sink(input, expectations, sink, ledger)
}

// ===========================================================================
// A — accepted / compatible scenarios exercised through the release-built Run
// 248 durable-consume projection sink symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use DurableReplayObservation as R;
    use GovernanceModeledDurableConsumeSinkPolicy as P;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("accepted");

    // A1 — disabled sink policy preserves legacy bypass, no receipt, no sink invocation.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::sink_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A1.outcome", "legacy-bypass-no-receipt", &o);
        t.assert_true("A1.no-consume", o.no_consume());
        t.assert_true("A1.legacy-bypass", o.is_legacy_bypass());
        t.assert_true("A1.no-invocation", sink.invocations() == 0);
        t.assert_true("A1.ledger-empty", ledger.is_empty());
    }

    // A2 — disabled pipeline policy preserves legacy bypass, never invokes the sink.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::pipeline_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A2.outcome", "legacy-bypass-no-receipt", &o);
        t.assert_true("A2.no-invocation", sink.invocations() == 0);
        t.assert_true("A2.ledger-empty", ledger.is_empty());
    }

    // A3 — disabled evaluator/call-site policy preserves legacy bypass, never invokes the sink.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::evaluator_disabled(),
            R::MutationAuthorized,
            Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A3.outcome", "legacy-bypass-no-receipt", &o);
        t.assert_true("A3.no-invocation", sink.invocations() == 0);
        t.assert_true("A3.ledger-empty", ledger.is_empty());
    }

    // A4 — DevNet fixture pipeline success + sink record success records one receipt.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A4.outcome", "consume-receipt-recorded", &o);
        t.assert_true("A4.authorizes", o.authorizes_modeled_consume_receipt());
        t.assert_true("A4.projects", o.projects_to_durable_completion());
        t.assert_true("A4.invoked-once", sink.invocations() == 1);
        t.assert_true("A4.ledger-one", ledger.len() == 1);
        t.assert_true("A4.contains", ledger.contains(RECEIPT_ID));
        t.check(
            "A4.kind",
            "fixture-devnet",
            sink.kind().tag(),
        );
        t.assert_true(
            "A4.record-status",
            ledger.find(RECEIPT_ID).map(|r| r.status)
                == Some(ModeledDurableConsumeReceiptStatus::Recorded),
        );
    }

    // A5 — TestNet fixture pipeline success + sink record success records one receipt.
    {
        let c = testnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = FixtureModeledDurableConsumeProjectionSink::new(TrustBundleEnvironment::Testnet);
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A5.outcome", "consume-receipt-recorded", &o);
        t.assert_true("A5.ledger-one", ledger.len() == 1);
        t.check("A5.kind", "fixture-testnet", sink.kind().tag());
    }

    // A6 — duplicate identical receipt is idempotent; no second record.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let first = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A6.first", "consume-receipt-recorded", &first);
        let second = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A6.second", "consume-receipt-duplicate-idempotent", &second);
        t.assert_true("A6.projects", second.projects_to_durable_completion());
        t.assert_true("A6.no-authorize-new", !second.authorizes_modeled_consume_receipt());
        t.assert_true("A6.ledger-one", ledger.len() == 1);
    }

    // A7 — production sink path reachable but unavailable/fail-closed; records no receipt.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = ProductionModeledDurableConsumeProjectionSink::default();
        let o = evaluate_modeled_durable_consume_projection_sink(
            &input,
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        t.check_outcome("A7.outcome", "production-sink-unavailable-no-consume", &o);
        t.assert_true("A7.no-consume", o.no_consume());
        t.assert_true("A7.ledger-empty", ledger.is_empty());
        t.check("A7.kind", "production-unavailable", sink.kind().tag());
        t.assert_true("A7.unavailable", sink.kind().is_unavailable());
    }

    // A8 — MainNet sink path reachable but unavailable/fail-closed; records no receipt.
    {
        // Use a non-peer-driven MainNet surface so the MainNet *sink kind* (not the
        // peer-driven refusal) is the reason no receipt is recorded.
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = MainNetModeledDurableConsumeProjectionSink::default();
        let o = evaluate_modeled_durable_consume_projection_sink(
            &input,
            &c.expectations,
            &mut sink,
            &mut ledger,
        );
        t.check_outcome("A8.outcome", "mainnet-sink-unavailable-no-consume", &o);
        t.assert_true("A8.ledger-empty", ledger.is_empty());
        t.check("A8.kind", "mainnet-unavailable", sink.kind().tag());
    }

    // A9 — MainNet peer-driven apply refused before pipeline progression and sink invocation.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        );
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "A9.outcome",
            "mainnet-peer-driven-apply-refused-no-consume",
            &o,
        );
        t.assert_true("A9.refused", o.is_mainnet_peer_driven_apply_refused());
        t.assert_true("A9.no-invocation", sink.invocations() == 0);
        t.assert_true("A9.ledger-empty", ledger.is_empty());
    }

    // A10 — validator-set rotation unsupported; records no receipt.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::ValidatorSetRotationUnsupportedNoConsume,
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "A10.outcome",
            "validator-set-rotation-unsupported-no-consume",
            &o,
        );
        t.assert_true("A10.no-invocation", sink.invocations() == 0);
        t.assert_true("A10.ledger-empty", ledger.is_empty());
    }

    // A11 — policy-change unsupported; records no receipt.
    {
        let c = devnet_ctx();
        let input = c.input(
            P::wired(),
            R::MutationAuthorized,
            Pipe::PolicyChangeUnsupportedNoConsume,
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("A11.outcome", "policy-change-unsupported-no-consume", &o);
        t.assert_true("A11.no-invocation", sink.invocations() == 0);
        t.assert_true("A11.ledger-empty", ledger.is_empty());
    }

    // A12 — existing Run 246/244/242/240 compatible: pipeline success projects to a create intent.
    {
        let intent = project_pipeline_outcome_to_consume_sink_intent(
            &Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
        );
        t.assert_true("A12.creates-intent", intent.creates_intent());
        t.assert_true("A12.is-create", intent == ConsumeSinkIntent::CreateIntent);
    }

    t.finish(out)
}

// ===========================================================================
// B — rejection / fail-closed scenarios.
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use DurableReplayObservation as R;
    use GovernanceModeledDurableConsumeSinkPolicy as P;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("rejection");

    // B-pipeline — every non-success pipeline outcome produces no sink intent and no receipt.
    let pipeline_cases: [(&str, GovernanceModeledEndToEndPipelineOutcome); 14] = [
        (
            "evaluator-reject",
            Pipe::EvaluatorRejectedBeforeReplay {
                reason: "evaluator".to_string(),
            },
        ),
        (
            "callsite-reject",
            Pipe::MutationEngineRejectedBeforeApplier {
                reason: "callsite".to_string(),
            },
        ),
        ("replay-stale", Pipe::ReplayStaleOrExpiredNoConsume),
        ("replay-consumed", Pipe::ReplayConsumedNoConsume),
        ("replay-superseded", Pipe::ReplaySupersededNoConsume),
        ("replay-backend-unavailable", Pipe::BackendUnavailableNoConsume),
        (
            "durable-replay-rejected",
            Pipe::DurableReplayRejectedBeforeMutation,
        ),
        (
            "mutation-engine-reject",
            Pipe::ModeledApplierRejectedBeforeSnapshot {
                reason: "engine".to_string(),
            },
        ),
        (
            "applier-reject-before-apply",
            Pipe::ModeledApplierRejectedBeforeApply {
                reason: "before-apply".to_string(),
            },
        ),
        ("apply-failed", Pipe::ModeledApplierApplyFailedNoConsume),
        ("rollback", Pipe::ModeledApplierRolledBackNoConsume),
        (
            "rollback-failed",
            Pipe::ModeledApplierRollbackFailedFatalNoConsume,
        ),
        (
            "ambiguous",
            Pipe::ModeledApplierAmbiguousFailClosedNoConsume,
        ),
        ("legacy-bypass", Pipe::ProceedLegacyBypassNoMutation),
    ];
    for (label, pipeline) in pipeline_cases {
        let c = devnet_ctx();
        let input = c.input(P::wired(), R::MutationAuthorized, pipeline);
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true(&format!("B.{label}.no-consume"), o.no_consume());
        t.assert_true(&format!("B.{label}.no-invocation"), sink.invocations() == 0);
        t.assert_true(&format!("B.{label}.ledger-empty"), ledger.is_empty());
        t.assert_true(
            &format!("B.{label}.not-authorize"),
            !o.authorizes_modeled_consume_receipt(),
        );
    }

    // B-fault — sink record fault paths: invoked, no receipt, no consume.
    let fault_cases: [(&str, ModeledConsumeSinkFault, &str); 4] = [
        (
            "record-failed",
            ModeledConsumeSinkFault::RecordFailedNoConsume,
            "consume-receipt-record-failed-no-consume",
        ),
        (
            "rollback",
            ModeledConsumeSinkFault::RolledBackNoConsume,
            "consume-receipt-rolled-back-no-consume",
        ),
        (
            "rollback-failed",
            ModeledConsumeSinkFault::RollbackFailedFatal,
            "consume-receipt-rollback-failed-fatal-no-consume",
        ),
        (
            "ambiguous",
            ModeledConsumeSinkFault::AmbiguousAfterRecord,
            "consume-receipt-ambiguous-fail-closed-no-consume",
        ),
    ];
    for (label, fault, tag) in fault_cases {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = FixtureModeledDurableConsumeProjectionSink::with_fault(
            TrustBundleEnvironment::Devnet,
            fault,
        );
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(&format!("B.fault.{label}.outcome"), tag, &o);
        t.assert_true(&format!("B.fault.{label}.no-consume"), o.no_consume());
        t.assert_true(&format!("B.fault.{label}.invoked"), sink.invocations() == 1);
        t.assert_true(&format!("B.fault.{label}.ledger-empty"), ledger.is_empty());
    }

    // B-equivocation — same receipt id with a different digest is rejected; no second receipt.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let first = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome("B.equiv.first", "consume-receipt-recorded", &first);
        let mut c2 = devnet_ctx();
        c2.receipt.receipt_digest = "consume-receipt-digest-DIFFERENT".to_string();
        c2.expectations.expected_receipt_digest = "consume-receipt-digest-DIFFERENT".to_string();
        let input2 = c2.authorized();
        let second = drive(&input2, &c2.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "B.equiv.second",
            "consume-receipt-rejected-before-record",
            &second,
        );
        t.assert_true("B.equiv.no-consume", second.no_consume());
        t.assert_true("B.equiv.ledger-one", ledger.len() == 1);
    }

    // B-binding — environment / surface mismatches reject BEFORE sink invocation.
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
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            &format!("B.binding.{label}.outcome"),
            "rejected-before-pipeline-no-receipt",
            &o,
        );
        t.assert_true(
            &format!("B.binding.{label}.no-invocation"),
            sink.invocations() == 0,
        );
        t.assert_true(&format!("B.binding.{label}.ledger-empty"), ledger.is_empty());
    }

    // B-receipt — receipt-identity mismatches reject BEFORE record (sink IS invoked).
    let receipt_cases: [(&str, fn(&mut Ctx)); 7] = [
        ("wrong-receipt-digest", |c: &mut Ctx| {
            c.receipt.receipt_digest = "receipt-digest-wrong".to_string();
        }),
        ("wrong-pipeline-decision-digest", |c: &mut Ctx| {
            c.receipt.pipeline_decision_digest = "pipeline-digest-wrong".to_string();
        }),
        ("wrong-proposal-id", |c: &mut Ctx| {
            c.receipt.proposal_id = "proposal-wrong".to_string();
        }),
        ("wrong-decision-id", |c: &mut Ctx| {
            c.receipt.decision_id = "decision-wrong".to_string();
        }),
        ("wrong-candidate-digest", |c: &mut Ctx| {
            c.receipt.candidate_digest = "candidate-wrong".to_string();
        }),
        ("wrong-authority-domain-sequence", |c: &mut Ctx| {
            c.receipt.authority_domain_sequence = 99;
        }),
        ("malformed-receipt", |c: &mut Ctx| {
            c.receipt.receipt_id = String::new();
        }),
    ];
    for (label, mutate) in receipt_cases {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            &format!("B.receipt.{label}.outcome"),
            "consume-receipt-rejected-before-record",
            &o,
        );
        t.assert_true(
            &format!("B.receipt.{label}.invoked"),
            sink.invocations() == 1,
        );
        t.assert_true(&format!("B.receipt.{label}.ledger-empty"), ledger.is_empty());
    }

    // B-mainnet-authority — local operator / peer majority cannot satisfy MainNet authority.
    t.assert_true(
        "B.local-operator-cannot",
        modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "B.peer-majority-cannot",
        modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority(),
    );

    // B-production/mainnet sink unavailable records no receipt (also exercised in A7/A8).
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut psink = ProductionModeledDurableConsumeProjectionSink::default();
        let po = evaluate_modeled_durable_consume_projection_sink(
            &input,
            &c.expectations,
            &mut psink,
            &mut ledger,
        );
        t.check_outcome(
            "B.production-unavailable",
            "production-sink-unavailable-no-consume",
            &po,
        );
        t.assert_true("B.production-ledger-empty", ledger.is_empty());
    }

    t.finish(out)
}

// ===========================================================================
// C — recovery / crash-window scenarios.
// ===========================================================================

fn recover_devnet(
    window: ModeledDurableConsumeReceiptWindow,
    report: Option<&GovernanceModeledDurableConsumeSinkReceipt>,
) -> GovernanceModeledDurableConsumeSinkOutcome {
    let c = devnet_ctx();
    let input = c.authorized();
    recover_modeled_durable_consume_projection_sink_window(
        &input,
        window,
        ModeledDurableConsumeSinkKind::FixtureDevNet,
        report,
        &c.expectations,
    )
}

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use ModeledDurableConsumeReceiptWindow as W;
    let mut t = Table::new("recovery");

    t.check_outcome(
        "C.before-pipeline",
        "pipeline-did-not-authorize-consume-no-receipt",
        &recover_devnet(W::BeforePipeline, None),
    );
    t.check_outcome(
        "C.after-pipeline-before-intent",
        "pipeline-did-not-authorize-consume-no-receipt",
        &recover_devnet(W::AfterPipelineSuccessBeforeSinkIntent, None),
    );
    t.check_outcome(
        "C.after-intent-before-record",
        "consume-receipt-rejected-before-record",
        &recover_devnet(W::AfterSinkIntentBeforeRecord, None),
    );
    t.check_outcome(
        "C.after-record-before-report-no-report",
        "consume-receipt-rejected-before-record",
        &recover_devnet(W::AfterRecordBeforeReport, None),
    );
    {
        let c = devnet_ctx();
        let report = c.receipt.clone();
        t.check_outcome(
            "C.after-record-before-report-with-report",
            "consume-receipt-recorded",
            &recover_devnet(W::AfterRecordBeforeReport, Some(&report)),
        );
    }
    {
        let c = devnet_ctx();
        let report = c.receipt.clone();
        t.check_outcome(
            "C.after-report-success",
            "consume-receipt-recorded",
            &recover_devnet(W::AfterReportSuccess, Some(&report)),
        );
    }
    t.check_outcome(
        "C.after-report-ambiguous",
        "consume-receipt-ambiguous-fail-closed-no-consume",
        &recover_devnet(W::AfterReportAmbiguous, None),
    );
    t.check_outcome(
        "C.record-failed",
        "consume-receipt-record-failed-no-consume",
        &recover_devnet(W::RecordFailed, None),
    );
    t.check_outcome(
        "C.rollback-completed",
        "consume-receipt-rolled-back-no-consume",
        &recover_devnet(W::RollbackCompleted, None),
    );
    t.check_outcome(
        "C.rollback-failed",
        "consume-receipt-rollback-failed-fatal-no-consume",
        &recover_devnet(W::RollbackFailed, None),
    );
    t.check_outcome(
        "C.unknown",
        "consume-receipt-ambiguous-fail-closed-no-consume",
        &recover_devnet(W::Unknown, None),
    );

    // Production / MainNet recovery classification unavailable.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let o = recover_modeled_durable_consume_projection_sink_window(
            &input,
            W::AfterReportSuccess,
            ModeledDurableConsumeSinkKind::ProductionUnavailable,
            None,
            &c.expectations,
        );
        t.check_outcome(
            "C.production-unavailable",
            "production-sink-unavailable-no-consume",
            &o,
        );
    }
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = c.authorized();
        let o = recover_modeled_durable_consume_projection_sink_window(
            &input,
            W::AfterReportSuccess,
            ModeledDurableConsumeSinkKind::MainNetUnavailable,
            None,
            &c.expectations,
        );
        t.check_outcome(
            "C.mainnet-unavailable",
            "mainnet-sink-unavailable-no-consume",
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
        let input = c.authorized();
        let report = c.receipt.clone();
        let o = recover_modeled_durable_consume_projection_sink_window(
            &input,
            W::AfterReportSuccess,
            ModeledDurableConsumeSinkKind::FixtureDevNet,
            Some(&report),
            &c.expectations,
        );
        t.check_outcome(
            "C.mainnet-peer-driven-precedes",
            "mainnet-peer-driven-apply-refused-no-consume",
            &o,
        );
    }

    t.finish(out)
}

// ===========================================================================
// D — projection scenarios.
// ===========================================================================

fn run_projection_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("projection");

    // Only the pipeline consume-authorized outcome creates a sink intent.
    t.assert_true(
        "D.only-authorized-creates-intent",
        project_pipeline_outcome_to_consume_sink_intent(
            &Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized,
        )
        .creates_intent(),
    );

    // Predecessor authorizations alone create no sink intent.
    for (label, pipeline) in [
        (
            "evaluator-success-alone",
            Pipe::EvaluatorRejectedBeforeReplay {
                reason: "x".to_string(),
            },
        ),
        ("replay-freshness-alone", Pipe::DurableReplayRejectedBeforeMutation),
        (
            "mutation-engine-alone",
            Pipe::MutationEngineRejectedBeforeApplier {
                reason: "x".to_string(),
            },
        ),
        (
            "applier-authorized-without-applied",
            Pipe::ModeledApplierRejectedBeforeApply {
                reason: "x".to_string(),
            },
        ),
    ] {
        t.assert_true(
            &format!("D.{label}.no-intent"),
            !project_pipeline_outcome_to_consume_sink_intent(&pipeline).creates_intent(),
        );
    }

    // Only ConsumeReceiptRecorded authorizes a new modeled receipt-recorded state.
    t.assert_true(
        "D.recorded-authorizes",
        sink_outcome_authorizes_modeled_consume_receipt(&Sink::ConsumeReceiptRecorded),
    );

    // Every no-receipt / no-consume outcome does not consume.
    let no_consume: [(&str, GovernanceModeledDurableConsumeSinkOutcome); 13] = [
        ("legacy-bypass", Sink::LegacyBypassNoReceipt),
        ("rejected-before-pipeline", Sink::RejectedBeforePipelineNoReceipt),
        (
            "pipeline-did-not-authorize",
            Sink::PipelineDidNotAuthorizeConsumeNoReceipt,
        ),
        ("duplicate-idempotent", Sink::ConsumeReceiptDuplicateIdempotent),
        ("rejected-before-record", Sink::ConsumeReceiptRejectedBeforeRecord),
        ("record-failed", Sink::ConsumeReceiptRecordFailedNoConsume),
        ("rolled-back", Sink::ConsumeReceiptRolledBackNoConsume),
        (
            "rollback-failed-fatal",
            Sink::ConsumeReceiptRollbackFailedFatalNoConsume,
        ),
        (
            "ambiguous-fail-closed",
            Sink::ConsumeReceiptAmbiguousFailClosedNoConsume,
        ),
        ("production-unavailable", Sink::ProductionSinkUnavailableNoConsume),
        ("mainnet-unavailable", Sink::MainNetSinkUnavailableNoConsume),
        (
            "mainnet-peer-driven-refused",
            Sink::MainNetPeerDrivenApplyRefusedNoConsume,
        ),
        (
            "validator-set-rotation",
            Sink::ValidatorSetRotationUnsupportedNoConsume,
        ),
    ];
    for (label, outcome) in no_consume {
        t.assert_true(
            &format!("D.{label}.no-authorize-new"),
            !sink_outcome_authorizes_modeled_consume_receipt(&outcome),
        );
    }

    // policy-change unsupported is also a no-consume outcome (kept separate so the
    // array length stays explicit above).
    t.assert_true(
        "D.policy-change.no-authorize-new",
        !sink_outcome_authorizes_modeled_consume_receipt(&Sink::PolicyChangeUnsupportedNoConsume),
    );

    // Recorded and idempotent-duplicate both project to durable completion; the
    // duplicate must not be counted as a new consume.
    t.assert_true(
        "D.recorded-projects",
        sink_outcome_projects_to_durable_completion(&Sink::ConsumeReceiptRecorded),
    );
    t.assert_true(
        "D.duplicate-projects",
        sink_outcome_projects_to_durable_completion(&Sink::ConsumeReceiptDuplicateIdempotent),
    );
    t.assert_true(
        "D.duplicate-not-new",
        !sink_outcome_authorizes_modeled_consume_receipt(&Sink::ConsumeReceiptDuplicateIdempotent),
    );

    // The no-consume outcomes never project to durable completion.
    t.assert_true(
        "D.legacy-bypass.no-project",
        !sink_outcome_projects_to_durable_completion(&Sink::LegacyBypassNoReceipt),
    );
    t.assert_true(
        "D.rejected-before-record.no-project",
        !sink_outcome_projects_to_durable_completion(&Sink::ConsumeReceiptRejectedBeforeRecord),
    );

    t.finish(out)
}

// ===========================================================================
// E — stage-ordering scenarios.
// ===========================================================================

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    let mut t = Table::new("stage_ordering");

    // E1 — MainNet peer-driven apply refusal precedes pipeline progression and sink invocation.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        );
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("E1.refused", o.is_mainnet_peer_driven_apply_refused());
        t.assert_true("E1.no-invocation", sink.invocations() == 0);
    }

    // E2 — a rejection before the sink stage leaves the sink invocation count at zero.
    {
        let mut c = devnet_ctx();
        c.env.environment = TrustBundleEnvironment::Testnet;
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("E2.invocation-zero", sink.invocations() == 0);
        t.assert_true("E2.ledger-empty", ledger.is_empty());
    }

    // E3 — sink receipt recording happens after pipeline consume authorization.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        t.assert_true(
            "E3.pipeline-authorized",
            input.pipeline_binding.authorizes_durable_consume(),
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("E3.recorded", o.authorizes_modeled_consume_receipt());
        t.assert_true("E3.invoked-after", sink.invocations() == 1);
    }

    // E4 — a sink record failure does not retroactively invalidate the
    // pipeline-authorized binding, but does not authorize consume.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        t.assert_true(
            "E4.pipeline-still-authorized",
            input.pipeline_binding.authorizes_durable_consume(),
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = FixtureModeledDurableConsumeProjectionSink::with_fault(
            TrustBundleEnvironment::Devnet,
            ModeledConsumeSinkFault::RecordFailedNoConsume,
        );
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("E4.no-consume", o.no_consume());
        t.assert_true("E4.ledger-empty", ledger.is_empty());
    }

    // E5 — a sink rollback failure is fatal / fail-closed and does not authorize consume.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = FixtureModeledDurableConsumeProjectionSink::with_fault(
            TrustBundleEnvironment::Devnet,
            ModeledConsumeSinkFault::RollbackFailedFatal,
        );
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.check_outcome(
            "E5.outcome",
            "consume-receipt-rollback-failed-fatal-no-consume",
            &o,
        );
        t.assert_true("E5.no-consume", o.no_consume());
    }

    // E6 — the sink performs no persistent durable consume beyond modeled in-memory
    // fixture state: a non-authorizing pipeline never touches the ledger.
    {
        let c = devnet_ctx();
        let input = c.input(
            GovernanceModeledDurableConsumeSinkPolicy::wired(),
            DurableReplayObservation::MutationAuthorized,
            Pipe::ModeledApplierApplyFailedNoConsume,
        );
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("E6.ledger-empty", ledger.is_empty());
        t.assert_true("E6.no-invocation", sink.invocations() == 0);
    }

    t.finish(out)
}

// ===========================================================================
// F — receipt-ledger scenarios.
// ===========================================================================

fn run_receipt_ledger_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("receipt_ledger");

    // F1 — one valid receipt inserts exactly one modeled in-memory ledger record.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("F1.len-one", ledger.len() == 1);
        t.assert_true("F1.records-one", ledger.records().len() == 1);
        t.assert_true("F1.contains", ledger.contains(RECEIPT_ID));
    }

    // F2 — duplicate identical receipt is idempotent; record count unchanged.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("F2.len-one", ledger.len() == 1);
    }

    // F3 — same receipt id, different digest is equivocation; record count unchanged.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        let mut c2 = devnet_ctx();
        c2.receipt.receipt_digest = "different-digest".to_string();
        c2.expectations.expected_receipt_digest = "different-digest".to_string();
        let input2 = c2.authorized();
        let o = drive(&input2, &c2.expectations, &mut sink, &mut ledger);
        t.assert_true("F3.rejected", o.no_consume());
        t.assert_true("F3.len-one", ledger.len() == 1);
    }

    // F4 — wrong identity fields never record (sink invoked, rejected before record).
    let wrong_fields: [(&str, fn(&mut Ctx)); 6] = [
        ("wrong-proposal", |c: &mut Ctx| {
            c.receipt.proposal_id = "wrong".to_string();
        }),
        ("wrong-decision", |c: &mut Ctx| {
            c.receipt.decision_id = "wrong".to_string();
        }),
        ("wrong-candidate", |c: &mut Ctx| {
            c.receipt.candidate_digest = "wrong".to_string();
        }),
        ("wrong-authority-sequence", |c: &mut Ctx| {
            c.receipt.authority_domain_sequence = 123;
        }),
        ("wrong-pipeline-decision-digest", |c: &mut Ctx| {
            c.receipt.pipeline_decision_digest = "wrong".to_string();
        }),
        ("malformed", |c: &mut Ctx| {
            c.receipt.receipt_id = String::new();
        }),
    ];
    for (label, mutate) in wrong_fields {
        let mut c = devnet_ctx();
        mutate(&mut c);
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true(&format!("F4.{label}.no-record"), ledger.is_empty());
        t.assert_true(&format!("F4.{label}.no-consume"), o.no_consume());
    }

    // F5 — rollback restores modeled ledger snapshot exactly.
    {
        let c = devnet_ctx();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        let snap = ledger.snapshot();
        t.assert_true("F5.snap-len-one", snap.len() == 1);
        t.assert_true("F5.snap-not-empty", !snap.is_empty());
        let mut ledger2 = ModeledDurableConsumeReceiptLedger::new();
        ledger2.restore(&snap);
        t.assert_true("F5.restore-len-one", ledger2.len() == 1);
        t.assert_true("F5.restore-contains", ledger2.contains(RECEIPT_ID));
    }

    // F6 — fixture ledger digest equality reflects the receipt digest material.
    {
        let c = devnet_ctx();
        let digest = c.receipt.digest();
        let record_digest = {
            let input = c.authorized();
            let mut ledger = ModeledDurableConsumeReceiptLedger::new();
            let mut sink = devnet_sink();
            let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
            ledger.find(RECEIPT_ID).map(|r| r.digest.clone())
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
        modeled_consume_sink_rejection_is_non_mutating(),
    );
    t.assert_true(
        "G.never-calls-run-070",
        modeled_consume_sink_never_calls_run_070(),
    );
    t.assert_true(
        "G.never-mutates-live",
        modeled_consume_sink_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.never-writes-sequence-or-marker",
        modeled_consume_sink_never_writes_sequence_or_marker(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        modeled_consume_sink_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "G.pipeline-success-required",
        modeled_consume_sink_pipeline_success_required_before_receipt(),
    );
    t.assert_true(
        "G.receipt-record-required",
        modeled_consume_sink_receipt_record_required_before_consume(),
    );
    t.assert_true(
        "G.failed-record-never-consumes",
        modeled_consume_sink_failed_record_never_consumes(),
    );
    t.assert_true(
        "G.rollback-never-consumes",
        modeled_consume_sink_rollback_never_consumes(),
    );
    t.assert_true(
        "G.ambiguous-fails-closed",
        modeled_consume_sink_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "G.mainnet-refused-mainnet",
        modeled_consume_sink_mainnet_peer_driven_apply_refused_first(TrustBundleEnvironment::Mainnet),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !modeled_consume_sink_mainnet_peer_driven_apply_refused_first(TrustBundleEnvironment::Devnet),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        modeled_consume_sink_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        modeled_consume_sink_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "G.policy-change-unsupported",
        modeled_consume_sink_policy_change_unsupported(),
    );
    t.assert_true(
        "G.local-operator-cannot",
        modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority(),
    );

    // G — the fixture sink mutates ONLY the in-memory ledger; a rejected path
    // leaves the ledger untouched.
    {
        let mut c = devnet_ctx();
        c.env.genesis_hash = "wrong".to_string();
        let input = c.authorized();
        let mut ledger = ModeledDurableConsumeReceiptLedger::new();
        let mut sink = devnet_sink();
        let _ = drive(&input, &c.expectations, &mut sink, &mut ledger);
        t.assert_true("G.rejected-ledger-empty", ledger.is_empty());
    }

    t.finish(out)
}

// ===========================================================================
// H — reachability scenarios: tags / taxonomy minted in release mode.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    let mut t = Table::new("reachability");

    t.check(
        "H.tag-recorded",
        "consume-receipt-recorded",
        Sink::ConsumeReceiptRecorded.tag(),
    );
    t.check(
        "H.tag-duplicate",
        "consume-receipt-duplicate-idempotent",
        Sink::ConsumeReceiptDuplicateIdempotent.tag(),
    );
    t.check(
        "H.tag-rejected-before-record",
        "consume-receipt-rejected-before-record",
        Sink::ConsumeReceiptRejectedBeforeRecord.tag(),
    );
    t.check(
        "H.tag-record-failed",
        "consume-receipt-record-failed-no-consume",
        Sink::ConsumeReceiptRecordFailedNoConsume.tag(),
    );
    t.check(
        "H.tag-rolled-back",
        "consume-receipt-rolled-back-no-consume",
        Sink::ConsumeReceiptRolledBackNoConsume.tag(),
    );
    t.check(
        "H.tag-rollback-failed",
        "consume-receipt-rollback-failed-fatal-no-consume",
        Sink::ConsumeReceiptRollbackFailedFatalNoConsume.tag(),
    );
    t.check(
        "H.tag-ambiguous",
        "consume-receipt-ambiguous-fail-closed-no-consume",
        Sink::ConsumeReceiptAmbiguousFailClosedNoConsume.tag(),
    );
    t.check(
        "H.tag-production-unavailable",
        "production-sink-unavailable-no-consume",
        Sink::ProductionSinkUnavailableNoConsume.tag(),
    );
    t.check(
        "H.tag-mainnet-unavailable",
        "mainnet-sink-unavailable-no-consume",
        Sink::MainNetSinkUnavailableNoConsume.tag(),
    );
    t.check(
        "H.tag-mainnet-peer-driven-refused",
        "mainnet-peer-driven-apply-refused-no-consume",
        Sink::MainNetPeerDrivenApplyRefusedNoConsume.tag(),
    );
    t.check(
        "H.tag-validator-rotation",
        "validator-set-rotation-unsupported-no-consume",
        Sink::ValidatorSetRotationUnsupportedNoConsume.tag(),
    );
    t.check(
        "H.tag-policy-change",
        "policy-change-unsupported-no-consume",
        Sink::PolicyChangeUnsupportedNoConsume.tag(),
    );
    t.check(
        "H.tag-legacy-bypass",
        "legacy-bypass-no-receipt",
        Sink::LegacyBypassNoReceipt.tag(),
    );
    t.check(
        "H.tag-rejected-before-pipeline",
        "rejected-before-pipeline-no-receipt",
        Sink::RejectedBeforePipelineNoReceipt.tag(),
    );
    t.check(
        "H.tag-pipeline-did-not-authorize",
        "pipeline-did-not-authorize-consume-no-receipt",
        Sink::PipelineDidNotAuthorizeConsumeNoReceipt.tag(),
    );

    // Sink kind tags + predicates.
    t.check(
        "H.kind-devnet",
        "fixture-devnet",
        ModeledDurableConsumeSinkKind::FixtureDevNet.tag(),
    );
    t.check(
        "H.kind-testnet",
        "fixture-testnet",
        ModeledDurableConsumeSinkKind::FixtureTestNet.tag(),
    );
    t.check(
        "H.kind-production",
        "production-unavailable",
        ModeledDurableConsumeSinkKind::ProductionUnavailable.tag(),
    );
    t.check(
        "H.kind-mainnet",
        "mainnet-unavailable",
        ModeledDurableConsumeSinkKind::MainNetUnavailable.tag(),
    );
    t.assert_true(
        "H.kind-devnet-is-fixture",
        ModeledDurableConsumeSinkKind::FixtureDevNet.is_fixture(),
    );
    t.assert_true(
        "H.kind-production-unavailable",
        ModeledDurableConsumeSinkKind::ProductionUnavailable.is_unavailable(),
    );

    // Policy predicate reachability.
    t.assert_true(
        "H.policy-wired",
        GovernanceModeledDurableConsumeSinkPolicy::wired().is_wired(),
    );
    t.assert_true(
        "H.policy-disabled-not-wired",
        !GovernanceModeledDurableConsumeSinkPolicy::disabled().is_wired(),
    );

    t.finish(out)
}

// ===========================================================================
// Fixture dump (decision values minted in release mode).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");

    // Full success lifecycle: pipeline authorized -> sink record -> ledger record.
    let c = devnet_ctx();
    let input = c.authorized();
    let mut ledger = ModeledDurableConsumeReceiptLedger::new();
    let mut sink = devnet_sink();
    let o = drive(&input, &c.expectations, &mut sink, &mut ledger);
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} authorizes={} projects={} invocations={} ledger_len={} contains={}\n",
            o.tag(),
            o.authorizes_modeled_consume_receipt(),
            o.projects_to_durable_completion(),
            sink.invocations(),
            ledger.len(),
            ledger.contains(RECEIPT_ID),
        ),
    );

    // Rejected lifecycle: wrong genesis -> reject-before-pipeline, no invocation, no record.
    let mut c2 = devnet_ctx();
    c2.env.genesis_hash = "wrong-genesis".to_string();
    let input2 = c2.authorized();
    let mut ledger2 = ModeledDurableConsumeReceiptLedger::new();
    let mut sink2 = devnet_sink();
    let o2 = drive(&input2, &c2.expectations, &mut sink2, &mut ledger2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} invocations={} no_consume={} ledger_len={}\n",
            o2.tag(),
            sink2.invocations(),
            o2.no_consume(),
            ledger2.len(),
        ),
    );

    // MainNet peer-driven refusal precedes everything.
    let c3 = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let input3 = c3.authorized();
    let mut ledger3 = ModeledDurableConsumeReceiptLedger::new();
    let mut sink3 = devnet_sink();
    let o3 = drive(&input3, &c3.expectations, &mut sink3, &mut ledger3);
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} invocations={} is_refusal={} ledger_len={}\n",
            o3.tag(),
            sink3.invocations(),
            o3.is_mainnet_peer_driven_apply_refused(),
            ledger3.len(),
        ),
    );

    // Recovery window classifications.
    let mut windows = String::new();
    let c4 = devnet_ctx();
    let report = c4.receipt.clone();
    for (label, window, rep) in [
        (
            "before-pipeline",
            ModeledDurableConsumeReceiptWindow::BeforePipeline,
            None,
        ),
        (
            "after-sink-intent-before-record",
            ModeledDurableConsumeReceiptWindow::AfterSinkIntentBeforeRecord,
            None,
        ),
        (
            "after-record-before-report-with-report",
            ModeledDurableConsumeReceiptWindow::AfterRecordBeforeReport,
            Some(&report),
        ),
        (
            "after-report-success",
            ModeledDurableConsumeReceiptWindow::AfterReportSuccess,
            Some(&report),
        ),
        (
            "after-report-ambiguous",
            ModeledDurableConsumeReceiptWindow::AfterReportAmbiguous,
            None,
        ),
        (
            "rollback-failed",
            ModeledDurableConsumeReceiptWindow::RollbackFailed,
            None,
        ),
        ("unknown", ModeledDurableConsumeReceiptWindow::Unknown, None),
    ] {
        let o = recover_devnet(window, rep);
        windows.push_str(&format!("{label}={}\n", o.tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_249_modeled_durable_consume_projection_sink_release_binary_helper <OUT_DIR>"
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
        ("receipt_ledger", run_receipt_ledger_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_249_modeled_durable_consume_projection_sink_release_binary_helper\nscope: Run 248 governance modeled durable-consume projection sink boundary (pqc_governance_modeled_durable_consume_projection_sink: evaluate_modeled_durable_consume_projection_sink, recover_modeled_durable_consume_projection_sink_window, project_pipeline_outcome_to_consume_sink_intent, sink_outcome_authorizes_modeled_consume_receipt, sink_outcome_projects_to_durable_completion, the GovernanceModeledDurableConsumeProjectionSink trait with FixtureModeledDurableConsumeProjectionSink/ProductionModeledDurableConsumeProjectionSink/MainNetModeledDurableConsumeProjectionSink, the GovernanceModeledDurableConsumeSinkInput/Expectations/Policy/Surface/EnvironmentBinding/RuntimeBinding/ReplayBinding/PipelineBinding bindings, the GovernanceModeledDurableConsumeSinkReceipt plus the ModeledDurableConsumeReceiptLedger/Record/Snapshot/Status/Digest modeled in-memory ledger, the GovernanceModeledDurableConsumeSinkOutcome taxonomy, the ConsumeSinkIntent projection, the ModeledConsumeSinkFault injector, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure typed projection over an in-memory ledger (the DevNet/TestNet fixture sink mutates ONLY the in-memory ModeledDurableConsumeReceiptLedger; no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState mutation, no durable consume of its own, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a disabled sink/pipeline/evaluator-call-site policy is a legacy bypass with no receipt and no sink invocation; MainNet peer-driven apply is refused before pipeline projection and before any sink invocation; only the Run 246 ModeledApplierAppliedAndDurableConsumeAuthorized outcome creates a sink intent; only ConsumeReceiptRecorded authorizes a new modeled receipt-recorded state; a duplicate identical receipt is idempotent (no second record) and the same receipt id with a different digest fails closed as equivocation; every non-success pipeline outcome, record failure, rollback, rollback-failed, ambiguous receipt window, unavailable production/MainNet sink path, and unsupported action never consumes; a rejection before the sink stage leaves the sink invocation count at zero\n\n",
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
