# QBIND DevNet evidence — Run 250

**Title.** Source/test governance modeled durable-consume receipt-acknowledgement
/ completion reporter boundary.

**Status.** PASS (source/test only). Run 250 extends the Run 248 modeled
durable-consume projection sink with a mockable, in-memory **completion reporter**
that models how a future production call site would **report** an
after-record-only durable consume *acknowledgement* / completion report back to
the Run 240 durable completion semantics, once the Run 248 sink has recorded a
consume receipt. Run 248 proved that a modeled consume *receipt* is recorded only
after the Run 246 pipeline yields the single consume-authorizing outcome
`ModeledApplierAppliedAndDurableConsumeAuthorized` (terminating in
`ConsumeReceiptRecorded`). What was still missing was a typed source/test boundary
that models the after-record-only consume-acknowledgement / completion-report step.
Run 250 closes that source/test completion-reporter gap only.

Run 250 introduces a **completion-reporter layer**, **not** a replacement for any
existing module. It consumes the typed Run 248 sink outcome as a binding and
projects it onto a completion-report intent; only the Run 248
`ConsumeReceiptRecorded` outcome creates a completion-report intent, and a Run 248
`ConsumeReceiptDuplicateIdempotent` may only match an already-recorded completion
report and never creates a new one. The reporter is a **model only**. It implements
**no** real persistent replay backend, **no** real durable consume backend, **no**
real completion-report backend, **no** real production mutation engine, **no** real
governance execution engine, **no** real on-chain governance proof verifier, **no**
RocksDB backend, **no** file format, **no** schema, **no** database migration,
**no** storage-format change, **no** KMS/HSM backend, **no** RemoteSigner backend,
**no** MainNet governance enablement, **no** MainNet peer-driven apply enablement,
and **no** validator-set rotation. It changes **no** wire, schema, marker,
sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 250 adds a modeled durable-consume receipt-acknowledgement / completion
  reporter boundary.
* It models how a future production call site would report an after-record-only
  consume acknowledgement back to durable completion semantics.
* It does **not** implement a real persistent replay backend.
* It does **not** implement a real durable consume backend.
* It does **not** implement a real completion-report backend.
* It does **not** add RocksDB / file / schema / migration / storage-format
  changes.
* It does **not** add wire / schema / marker / sequence / trust-bundle changes.
* It does **not** write authority markers.
* It does **not** write trust-bundle sequence files.
* It does **not** call Run 070.
* It does **not** mutate `LivePqcTrustState`.
* It does **not** perform a real trust swap.
* It does **not** evict sessions.
* It does **not** implement a real production mutation engine.
* It does **not** implement a real governance execution engine.
* It does **not** implement a real on-chain governance proof verifier.
* It does **not** add KMS/HSM/RemoteSigner backend.
* It does **not** enable MainNet governance.
* It does **not** enable MainNet peer-driven apply.
* It does **not** implement validator-set rotation.
* The fixture reporter mutates only modeled in-memory completion-report state.
* Rejected reporter paths are non-mutating.
* Run 250 does not weaken any prior run (Runs 070, 130–249) and does not claim full
  C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`

Run 250 adds a new source module (registered in `lib.rs`) that defines:

* typed reporter inputs / policy / bindings
  (`GovernanceModeledDurableConsumeCompletionReporterInput`,
  `GovernanceModeledDurableConsumeCompletionReporterPolicy`,
  `GovernanceModeledDurableConsumeCompletionReporterExpectations`,
  `GovernanceModeledDurableConsumeCompletionReport`) plus type aliases over the Run
  244/246/248 bindings (`…Surface`, `…EnvironmentBinding`, `…RuntimeBinding`,
  `…ReplayBinding`, `…PipelineBinding`, `…SinkBinding`);
* modeled in-memory completion-report state
  (`ModeledDurableConsumeCompletionReportLedger`,
  `ModeledDurableConsumeCompletionReportRecord`,
  `ModeledDurableConsumeCompletionReportSnapshot`,
  `ModeledDurableConsumeCompletionReportStatus`,
  `ModeledDurableConsumeCompletionReportDigest`) — in-memory only; never touches
  RocksDB, files, markers, sequence files, or any production durable state;
* an explicit reporter outcome enum
  (`GovernanceModeledDurableConsumeCompletionReporterOutcome`) whose only
  **new**-completion authorizing variant is `CompletionReportRecorded`, including
  `LegacyBypassNoCompletionReport`, `RejectedBeforeSinkNoCompletionReport`,
  `SinkDidNotRecordReceiptNoCompletionReport`,
  `CompletionReportDuplicateIdempotent`, `CompletionReportRejectedBeforeRecord`,
  `CompletionReportRecordFailedNoCompletion`,
  `CompletionReportRolledBackNoCompletion`,
  `CompletionReportRollbackFailedFatalNoCompletion`,
  `CompletionReportAmbiguousFailClosedNoCompletion`,
  `ProductionReporterUnavailableNoCompletion`,
  `MainNetReporterUnavailableNoCompletion`,
  `MainNetPeerDrivenApplyRefusedNoCompletion`,
  `ValidatorSetRotationUnsupportedNoCompletion`, and
  `PolicyChangeUnsupportedNoCompletion`;
* a pure/mockable reporter trait
  (`GovernanceModeledDurableConsumeCompletionReporter`) with
  `record_modeled_consume_completion_report` and
  `recover_modeled_consume_completion_report_window`, plus source/test-only
  implementations (`FixtureModeledDurableConsumeCompletionReporter` for
  DevNet/TestNet, and the reachable-but-unavailable
  `ProductionModeledDurableConsumeCompletionReporter` /
  `MainNetModeledDurableConsumeCompletionReporter`). The fixture reporter exposes an
  invocation counter so tests prove non-recording sink paths never invoke it;
* composition helpers
  (`project_sink_outcome_to_completion_report_intent`,
  `evaluate_modeled_durable_consume_completion_reporter`,
  `recover_modeled_durable_consume_completion_reporter_window`,
  `completion_reporter_outcome_authorizes_modeled_completion`,
  `completion_reporter_outcome_projects_to_durable_completion`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, and **before** any reporter invocation.
2. A disabled reporter / sink / pipeline / evaluator-call-site policy preserves the
   legacy no-acknowledgement, no-completion bypass and never invokes the reporter.
3. Only the Run 248 `ConsumeReceiptRecorded` sink outcome creates a
   completion-report intent; `ConsumeReceiptDuplicateIdempotent` may only match an
   already-recorded completion report; every other sink outcome maps to a
   no-completion fail-closed outcome and never invokes the reporter.
4. Pre-reporter environment / chain / genesis / governance surface / mutation
   surface binding validation completes **before** the report is recorded; a
   mismatch fails closed with no reporter invocation.
5. The report record happens **after** the sink receipt-recorded state; the
   report-identity fields must match exactly before any modeled completion report
   is recorded.
6. Only `CompletionReportRecorded` authorizes a **new** modeled completion-reported
   state. A duplicate identical completion report is idempotent (no second report);
   the same report id with a different digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `modeled_completion_reporter_rejection_is_non_mutating`
* `modeled_completion_reporter_never_calls_run_070`
* `modeled_completion_reporter_never_mutates_live_pqc_trust_state`
* `modeled_completion_reporter_never_writes_sequence_or_marker`
* `modeled_completion_reporter_no_rocksdb_file_schema_migration_change`
* `modeled_completion_reporter_pipeline_success_required_before_report`
* `modeled_completion_reporter_sink_receipt_required_before_report`
* `modeled_completion_reporter_report_record_required_before_completion`
* `modeled_completion_reporter_failed_record_never_completes`
* `modeled_completion_reporter_rollback_never_completes`
* `modeled_completion_reporter_ambiguous_window_fails_closed`
* `modeled_completion_reporter_mainnet_peer_driven_apply_refused_first`
* `modeled_completion_reporter_production_mainnet_unavailable`
* `modeled_completion_reporter_validator_set_rotation_unsupported`
* `modeled_completion_reporter_policy_change_unsupported`
* `modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority`
* `modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_250_modeled_durable_consume_completion_reporter_tests.rs`
— 88 tests, all passing. The matrix covers:

* **Accepted / compatible:** disabled reporter / sink / pipeline /
  evaluator-call-site policy preserve the legacy no-completion bypass and never
  invoke the reporter; DevNet and TestNet sink receipt recorded + reporter record
  success record exactly one modeled in-memory completion report; modeled add-root
  / retire-root / revoke-root / emergency-revoke-root / noop actions (modeled via
  distinct candidate digests) each record a completion report only after sink
  receipt record; a duplicate identical completion report is idempotent with no
  second report; a duplicate-idempotent sink receipt matches an already-recorded
  completion report only, and never creates a new one by itself; the production and
  MainNet reporter paths are reachable but unavailable/fail-closed and record no
  completion; MainNet peer-driven apply is refused before pipeline progression,
  before any sink invocation, and before any reporter invocation; validator-set
  rotation and policy-change are unsupported and record no completion.
* **Rejected / fail-closed:** every non-recording sink outcome (legacy bypass,
  rejected-before-pipeline, pipeline-did-not-authorize, rejected-before-record,
  record-failure, rollback, rollback-failed, ambiguous window, production/MainNet
  unavailable) produces no completion-report intent, no completion, and zero
  reporter invocations; every non-success pipeline outcome (evaluator / call-site
  rejection, durable replay stale / consumed / superseded / backend unavailable,
  mutation-engine rejection, modeled applier rejected-before-apply, modeled apply
  failure, rollback, rollback-failed, ambiguous window) leaves the sink
  non-recording and records no completion; a report record failure, rollback,
  rollback-failed, and ambiguous window all fail closed without recording a report;
  the same report id with a different digest is rejected as equivocation and
  records no second report; wrong environment / chain / genesis / governance
  surface / mutation surface are rejected before reporter invocation (zero
  invocations); wrong report digest / receipt digest / sink decision digest /
  pipeline decision digest / proposal id / decision id / candidate digest /
  authority-domain sequence and a malformed completion report are rejected before
  record (reporter invoked, no record); local operator and peer majority cannot
  satisfy MainNet authority.
* **Recovery / crash-window:** before-pipeline,
  after-pipeline-success-before-sink-intent, and
  after-sink-intent-before-receipt-record windows fail closed with no report;
  after-receipt-record-before-report-intent and
  after-report-intent-before-report-record windows fail closed with no completion;
  after-report-record-before-report-success fails closed unless an explicit
  matching completion-report success exists; after-report-success recovers as
  completion reported; after-report-ambiguous, report-record-failed,
  rollback-completed, rollback-failed, and unknown windows fail closed with no
  completion; production/MainNet recovery classification is unavailable; MainNet
  peer-driven apply refusal precedes recovery classification.
* **Projection / stage-ordering:** only `ConsumeReceiptRecorded` creates a
  completion-report intent; `ConsumeReceiptDuplicateIdempotent` projects to
  idempotent-only; only `CompletionReportRecorded` authorizes a new modeled
  completion; every no-completion outcome does not project to durable completion; a
  rejection before the reporter stage leaves the reporter invocation count at zero;
  a report record failure does not invalidate the sink-recorded binding but does
  not authorize completion; one valid completion report inserts exactly one ledger
  record; the ledger snapshot/restore models a rollback with no drift.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_250_modeled_durable_consume_completion_reporter_tests`
  — `88 passed; 0 failed`.
* `cargo test -p qbind-node --test run_248_modeled_durable_consume_projection_sink_tests`
  — `68 passed; 0 failed`.
* `cargo test -p qbind-node --test run_246_governance_modeled_end_to_end_pipeline_tests`
  — `47 passed; 0 failed`.
* `cargo test -p qbind-node --test run_244_modeled_governance_trust_mutation_applier_tests`
  — `45 passed; 0 failed`.
* `cargo test -p qbind-node --test run_242_governance_execution_mutation_engine_tests`
  — `38 passed; 0 failed`.
* `cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests`
  — `63 passed; 0 failed`.
* `cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests`
  — `68 passed; 0 failed`.
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests`
  — `56 passed; 0 failed`.
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
  — `58 passed; 0 failed`.
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
  — `47 passed; 0 failed`.
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
  — `52 passed; 0 failed`.
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
  — `48 passed; 0 failed`.
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
  — `59 passed; 0 failed`.
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
  — `48 passed; 0 failed`.
* `cargo test -p qbind-node --lib pqc_authority` — `164 passed; 0 failed`.
* `cargo test -p qbind-node --lib` — `1365 passed; 0 failed`.

## Security invariants preserved

* Run 246 pipeline success is required before any sink intent can exist, and
  therefore before any completion report can be recorded.
* Run 248 `ConsumeReceiptRecorded` is required before any completion report can be
  recorded; only that sink outcome creates a completion-report intent.
* `CompletionReportRecorded` is required before any new modeled completion-reported
  state.
* Every non-recording sink outcome produces no reporter invocation and no
  completion.
* A failed completion-report record, rollback, rollback-failed, ambiguous window,
  unavailable production/MainNet path, rejected replay state, and unsupported
  action never complete.
* A reporter failure, rollback, rollback failure, or ambiguous acknowledgement
  window never retroactively claims durable consume completion.
* A duplicate identical completion report is idempotent (no second report); the
  same report id with a different digest fails closed as equivocation; a
  duplicate-idempotent sink receipt never creates a new completion report by
  itself.
* Rejected reporter paths are non-mutating: no Run 070 call, no `LivePqcTrustState`
  mutation, no live trust swap, no session eviction, no sequence write, no marker
  write, no durable consume, and no reporter invocation where the rejection happens
  before the reporter stage.
* MainNet peer-driven apply is refused before pipeline progression, before any sink
  invocation, and before any reporter invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture reporter mutates only modeled in-memory completion-report state; no
  RocksDB / file / schema / migration / storage-format change; no wire / marker /
  sequence / trust-bundle change.

## Honest limitations

* Run 250 is source/test only and introduces a completion-reporter layer over a
  modeled in-memory ledger, not a real production completion-report backend. No
  production mutating behavior is enabled.
* The fixture reporter records only modeled in-memory completion-report state; it
  performs no real durable consume acknowledgement, and the production / MainNet
  reporters are deliberately reachable-but-unavailable.
* No real persistent replay backend, durable consume backend, completion-report
  backend, production mutation engine, governance execution engine, on-chain
  governance proof verifier, or KMS/HSM/RemoteSigner backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 250 closes the source/test
modeled durable-consume completion-reporter gap only and does **not** claim full C4
or C5 closure.

## Suggested Run 251 next step

Release-binary evidence for the Run 250 modeled durable-consume completion reporter
(mirroring the Run 241 / 243 / 245 / 247 / 249 pattern): build the release binary,
exercise the Run 246 pipeline → Run 248 consume-sink projection → Run 250
completion-report projection → fixture report recording path through the
source/test fixtures, and capture grep-verifiable evidence that a modeled
completion report is recorded only after a Run 248 sink receipt record, that every
non-recording / record-failure / rollback / ambiguous / equivocation path remains
non-mutating and records no completion, and that production/MainNet reporter paths
and MainNet peer-driven apply remain refused/unavailable.