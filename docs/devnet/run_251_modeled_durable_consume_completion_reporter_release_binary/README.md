# Run 251 — Release-binary modeled governance durable-consume completion reporter evidence

## Scope

Run 251 is the release-binary evidence run for the Run 250 source/test
governance **modeled durable-consume completion reporter boundary** in
`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`:

* the typed reporter entry point
  `evaluate_modeled_durable_consume_completion_reporter` and the pure/mockable
  reporter trait `GovernanceModeledDurableConsumeCompletionReporter` with its
  `FixtureModeledDurableConsumeCompletionReporter`,
  `ProductionModeledDurableConsumeCompletionReporter`, and
  `MainNetModeledDurableConsumeCompletionReporter` implementations;
* the sink-outcome projector
  `project_sink_outcome_to_completion_report_intent` and the
  `CompletionReportIntent` taxonomy (the only completion-report-creating sink
  outcome is `ConsumeReceiptRecorded`; `ConsumeReceiptDuplicateIdempotent`
  projects to idempotent-only);
* the crash-window recovery helper
  `recover_modeled_durable_consume_completion_reporter_window` and the
  `ModeledDurableConsumeCompletionReportWindow` classification;
* the typed bindings
  `GovernanceModeledDurableConsumeCompletionReporterInput`,
  `GovernanceModeledDurableConsumeCompletionReporterExpectations`,
  `GovernanceModeledDurableConsumeCompletionReporterPolicy`, and the binding type
  aliases (`...ReporterSurface`, `...ReporterEnvironmentBinding`,
  `...ReporterRuntimeBinding`, `...ReporterReplayBinding`,
  `...ReporterPipelineBinding`, `...ReporterSinkBinding`);
* the completion-report-ledger model
  `ModeledDurableConsumeCompletionReportLedger`,
  `ModeledDurableConsumeCompletionReportRecord`,
  `ModeledDurableConsumeCompletionReportSnapshot`,
  `ModeledDurableConsumeCompletionReportDigest`,
  `ModeledDurableConsumeCompletionReportStatus`, and the completion-report
  carrier `GovernanceModeledDurableConsumeCompletionReport`;
* the reporter kind `ModeledDurableConsumeCompletionReporterKind` and fault
  `ModeledCompletionReportFault`;
* the `GovernanceModeledDurableConsumeCompletionReporterOutcome` taxonomy (the
  only completion-recording outcome is `CompletionReportRecorded`; a duplicate
  identical completion report is idempotent and a same-id different-digest
  completion report fails closed as equivocation) and its `tag()` / predicate
  surface (`completion_reporter_outcome_authorizes_modeled_completion`,
  `completion_reporter_outcome_projects_to_durable_completion`);
* the grep-verifiable invariant / fail-closed guard functions
  (`modeled_completion_reporter_rejection_is_non_mutating`,
  `modeled_completion_reporter_never_calls_run_070`,
  `modeled_completion_reporter_never_mutates_live_pqc_trust_state`,
  `modeled_completion_reporter_never_writes_sequence_or_marker`,
  `modeled_completion_reporter_no_rocksdb_file_schema_migration_change`,
  `modeled_completion_reporter_pipeline_success_required_before_report`,
  `modeled_completion_reporter_sink_receipt_required_before_report`,
  `modeled_completion_reporter_report_record_required_before_completion`,
  `modeled_completion_reporter_failed_record_never_completes`,
  `modeled_completion_reporter_rollback_never_completes`,
  `modeled_completion_reporter_ambiguous_window_fails_closed`,
  `modeled_completion_reporter_mainnet_peer_driven_apply_refused_first`,
  `modeled_completion_reporter_production_mainnet_unavailable`,
  `modeled_completion_reporter_validator_set_rotation_unsupported`,
  `modeled_completion_reporter_policy_change_unsupported`,
  `modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority`,
  `modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority`).

Where Run 250 proved the durable-consume completion reporter boundary at the
source/test level, Run 251 proves on real `target/release/qbind-node` plus a
release-built helper
(`crates/qbind-node/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper.rs`,
driven by
`scripts/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary.sh`)
that the release-built code exposes and exercises the boundary:

* a disabled reporter policy and a disabled sink/pipeline/evaluator/call-site
  policy preserve the legacy no-acknowledgement, no-completion bypass and never
  invoke the reporter;
* a DevNet/TestNet fixture pipeline success + sink receipt recorded + reporter
  record success records **only** the in-memory
  `ModeledDurableConsumeCompletionReportLedger` (exactly one completion report);
* the only completion-report-creating sink outcome is `ConsumeReceiptRecorded`;
  `ConsumeReceiptDuplicateIdempotent` may only match an already-recorded
  completion report; every other sink outcome maps to a no-completion outcome and
  records no completion report;
* the only completion-recording outcome is `CompletionReportRecorded`; a
  duplicate identical completion report is idempotent (no second report) and a
  same-id different-digest completion report fails closed as equivocation;
* every evaluator/replay/mutation/applier/sink rejection, binding mismatch,
  report-identity mismatch, malformed report, record failure, rollback,
  rollback-failed, ambiguous acknowledgement window, unavailable
  production/MainNet reporter path, validator-set rotation, and policy-change
  attempt is non-mutating and non-completing, and a rejection before the reporter
  stage leaves the reporter invocation counter at zero;
* **MainNet peer-driven apply remains refused** — before any pipeline
  progression, sink invocation, or reporter invocation;
* the crash-window recovery helper fails closed on every before-pipeline /
  after-sink-intent / after-receipt-record / after-report-intent / ambiguous /
  record-failed / rollback / rollback-failed / unknown window, and recovers as
  completed only with an explicit matching completion report;
* existing Run 249, Run 247, Run 245, Run 243, and Run 241 release behaviour
  remains compatible.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/
reachability/
grep_summaries/
test_results/
fixtures/
tables/
scenarios/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 250 durable-consume completion reporter boundary is a pure, typed
  projection over the already-landed Run 248 modeled durable-consume sink receipt
  plus a mockable reporter that records only the in-memory
  `ModeledDurableConsumeCompletionReportLedger`. Run 251 exercises it through
  release-built library symbols (the same symbols a future production call site
  would use), but the boundary itself performs no I/O and applies no real (live)
  completion reporting or durable consume.
* The boundary specifies the MainNet-refusal-first, legacy-bypass,
  sink-outcome-projection, pre-record binding, and report-record ordering a real
  completion reporter would have to honour, but implements **none** of that
  production behaviour: there is no real completion-report backend, no real
  durable consume backend, no real persistent replay backend, no real production
  mutation engine, no real governance execution engine, no real on-chain
  governance proof verifier, no RocksDB backend, no file format, no schema, no
  database migration, and no storage-format change.
* The `FixtureModeledDurableConsumeCompletionReporter` records only the modeled
  in-memory completion-report ledger and performs no real completion reporting or
  durable consume; the `ProductionModeledDurableConsumeCompletionReporter` and
  `MainNetModeledDurableConsumeCompletionReporter` always return the typed
  unavailable / fail-closed result.
* `CompletionReportRecorded` is the only outcome that records a new modeled
  completion report, and only after a `ConsumeReceiptRecorded` sink outcome and a
  clean pre-record binding validation; rejected, failed-record, rollback,
  rollback-failed, ambiguous, unavailable, and unsupported outcomes never
  complete.
* The boundary is non-mutating on every rejection path: it does not mutate
  `LivePqcTrustState`, writes no marker, writes no sequence, performs no live
  trust swap, evicts no sessions, performs no durable consume of its own, and
  never invokes Run 070 apply.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) before any
  pipeline progression, sink invocation, or reporter invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No real KMS / HSM / RemoteSigner backend. The boundary changes **no** network
  wire schema, trust-bundle schema, authority-marker schema, or sequence schema.
* Full C4 remains open. C5 remains open.
