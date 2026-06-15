# QBIND DevNet evidence — Run 252

**Title.** Source/test governance modeled durable-completion finalization
projection boundary.

**Status.** PASS (source/test only). Run 252 extends the Run 250 modeled
durable-consume completion reporter with a mockable, in-memory **finalization
projection** layer that models how a future production call site would
**project** an after-completion-report-only durable-consume acknowledgement into
a terminal **modeled durable-completion-finalized** state, once the Run 250
reporter has recorded a completion report. Run 250 proved that a modeled
completion *report* is recorded only after the Run 248 sink yields the single
receipt-authorizing outcome `ConsumeReceiptRecorded` (terminating in
`CompletionReportRecorded`). What was still missing was a typed source/test
boundary that models the after-report-only finalization step. Run 252 closes
that source/test finalization-projection gap only.

Run 252 introduces a **finalization-projection layer**, **not** a replacement
for any existing module. It consumes the typed Run 250 reporter outcome as a
binding and projects it onto a finalization intent; only the Run 250
`CompletionReportRecorded` outcome creates a finalization intent, and a Run 250
`CompletionReportDuplicateIdempotent` may only match an already-finalized
completion and never creates a new one. The finalizer is a **model only**. It
implements **no** real persistent replay backend, **no** real durable consume
backend, **no** real completion-report backend, **no** real finalization
backend, **no** real production mutation engine, **no** real governance execution
engine, **no** real on-chain governance proof verifier, **no** RocksDB backend,
**no** file format, **no** schema, **no** database migration, **no**
storage-format change, **no** KMS/HSM backend, **no** RemoteSigner backend,
**no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 252 adds a modeled durable-completion finalization projection boundary.
* It models how a future production call site would project an
  after-completion-report-only acknowledgement into a terminal
  durable-completion-finalized state.
* It does **not** implement a real persistent replay backend.
* It does **not** implement a real durable consume backend.
* It does **not** implement a real completion-report backend.
* It does **not** implement a real finalization backend.
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
* The fixture finalizer mutates only modeled in-memory finalization state.
* Rejected finalizer paths are non-mutating.
* Run 252 does not weaken any prior run (Runs 070, 130–251) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_modeled_durable_completion_finalization_projection.rs`

Run 252 adds a new source module (registered in `lib.rs`) that defines:

* typed finalizer inputs / policy / bindings
  (`GovernanceModeledDurableCompletionFinalizationInput`,
  `GovernanceModeledDurableCompletionFinalizationPolicy`,
  `GovernanceModeledDurableCompletionFinalizationExpectations`,
  `GovernanceModeledDurableCompletionFinalization`) plus type aliases over the
  Run 244/246/248/250 bindings (`…Surface`, `…EnvironmentBinding`,
  `…RuntimeBinding`, `…ReplayBinding`, `…PipelineBinding`, `…SinkBinding`,
  `…ReporterBinding`);
* modeled in-memory finalization state
  (`ModeledDurableCompletionFinalizationLedger`,
  `ModeledDurableCompletionFinalizationRecord`,
  `ModeledDurableCompletionFinalizationSnapshot`,
  `ModeledDurableCompletionFinalizationStatus`,
  `ModeledDurableCompletionFinalizationDigest`) — in-memory only; never touches
  RocksDB, files, markers, sequence files, or any production durable state. The
  finalization digest/identity binds both the Run 248 `sink_decision_digest` and
  the Run 250 `reporter_decision_digest`;
* an explicit finalization outcome enum
  (`GovernanceModeledDurableCompletionFinalizationOutcome`) whose only
  **new**-finalization authorizing variant is `DurableCompletionFinalized`,
  including `LegacyBypassNoFinalization`,
  `ReporterDidNotRecordCompletionNoFinalization`,
  `RejectedBeforeReporterNoFinalization`,
  `DurableCompletionDuplicateIdempotent`,
  `DurableCompletionRejectedBeforeRecord`,
  `DurableCompletionRecordFailedNoFinalization`,
  `DurableCompletionRolledBackNoFinalization`,
  `DurableCompletionRollbackFailedFatalNoFinalization`,
  `DurableCompletionAmbiguousFailClosedNoFinalization`,
  `ProductionFinalizerUnavailableNoFinalization`,
  `MainNetFinalizerUnavailableNoFinalization`,
  `MainNetPeerDrivenApplyRefusedNoFinalization`,
  `ValidatorSetRotationUnsupportedNoFinalization`, and
  `PolicyChangeUnsupportedNoFinalization`;
* a pure/mockable finalizer trait
  (`GovernanceModeledDurableCompletionFinalizer`) with
  `record_modeled_durable_completion_finalization` and
  `recover_modeled_durable_completion_finalization_window`, plus source/test-only
  implementations (`FixtureModeledDurableCompletionFinalizer` for DevNet/TestNet,
  and the reachable-but-unavailable
  `ProductionModeledDurableCompletionFinalizer` /
  `MainNetModeledDurableCompletionFinalizer`). The fixture finalizer exposes an
  invocation counter so tests prove non-recording reporter paths never invoke it;
* composition helpers
  (`project_completion_reporter_outcome_to_finalization_intent`,
  `evaluate_modeled_durable_completion_finalization`,
  `recover_modeled_durable_completion_finalization_window`,
  `finalization_outcome_authorizes_modeled_finalization`,
  `finalization_outcome_projects_to_durable_completion_finalized`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, and
   **before** any finalizer invocation.
2. A disabled finalization / reporter / sink / pipeline / evaluator-call-site
   policy preserves the legacy no-finalization bypass and never invokes the
   finalizer.
3. Only the Run 250 `CompletionReportRecorded` reporter outcome creates a
   finalization intent; `CompletionReportDuplicateIdempotent` may only match an
   already-finalized completion; every other reporter outcome maps to a
   no-finalization fail-closed outcome and never invokes the finalizer.
4. Pre-finalizer environment / chain / genesis / governance surface / mutation
   surface binding validation completes **before** the finalization is recorded;
   a mismatch fails closed with no finalizer invocation.
5. The finalization record happens **after** the Run 250 completion-report
   recorded state; the finalization-identity fields (including both the sink and
   reporter decision digests) must match exactly before any modeled finalization
   is recorded.
6. Only `DurableCompletionFinalized` authorizes a **new** modeled
   durable-completion-finalized state. A duplicate identical finalization is
   idempotent (no second finalization); the same finalization id with a
   different digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `modeled_finalization_rejection_is_non_mutating`
* `modeled_finalization_never_calls_run_070`
* `modeled_finalization_never_mutates_live_pqc_trust_state`
* `modeled_finalization_never_writes_sequence_or_marker`
* `modeled_finalization_no_rocksdb_file_schema_migration_change`
* `modeled_finalization_pipeline_success_required_before_finalization`
* `modeled_finalization_sink_receipt_required_before_finalization`
* `modeled_finalization_completion_report_required_before_finalization`
* `modeled_finalization_record_required_before_durable_completion`
* `modeled_finalization_failed_record_never_finalizes`
* `modeled_finalization_rollback_never_finalizes`
* `modeled_finalization_ambiguous_window_fails_closed`
* `modeled_finalization_mainnet_peer_driven_apply_refused_first`
* `modeled_finalization_production_mainnet_unavailable`
* `modeled_finalization_validator_set_rotation_unsupported`
* `modeled_finalization_policy_change_unsupported`
* `modeled_finalization_local_operator_cannot_satisfy_mainnet_authority`
* `modeled_finalization_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_252_modeled_durable_completion_finalization_projection_tests.rs`
— 98 tests, all passing. The matrix covers:

* **Accepted / compatible:** disabled finalization / reporter / sink / pipeline /
  evaluator-call-site policy preserve the legacy no-finalization bypass and never
  invoke the finalizer; DevNet and TestNet completion-report recorded + finalizer
  record success record exactly one modeled in-memory finalization; modeled
  add-root / retire-root / revoke-root / emergency-revoke-root / noop actions
  (modeled via distinct candidate digests) each record a finalization only after
  the reporter completion-report record; a duplicate identical finalization is
  idempotent with no second finalization; a duplicate-idempotent completion
  report matches an already-finalized completion only, and never creates a new
  one by itself; the production and MainNet finalizer paths are reachable but
  unavailable/fail-closed and record no finalization; MainNet peer-driven apply
  is refused before pipeline progression, before any sink invocation, before any
  reporter invocation, and before any finalizer invocation; validator-set
  rotation and policy-change are unsupported and record no finalization.
* **Rejected / fail-closed:** every non-recording reporter outcome (legacy
  bypass, rejected-before-reporter, reporter-did-not-record, rejected-before-
  record, record-failure, rollback, rollback-failed, ambiguous window,
  production/MainNet unavailable) produces no finalization intent, no
  finalization, and zero finalizer invocations; a finalization record failure,
  rollback, rollback-failed, and ambiguous window all fail closed without
  recording a finalization; the same finalization id with a different digest is
  rejected as equivocation and records no second finalization; wrong environment
  / chain / genesis / governance surface / mutation surface are rejected before
  finalizer invocation (zero invocations); wrong finalization digest / reporter
  decision digest / sink decision digest / pipeline decision digest / proposal id
  / decision id / candidate digest / authority-domain sequence and a malformed
  finalization are rejected before record (finalizer invoked, no record); local
  operator and peer majority cannot satisfy MainNet authority.
* **Recovery / crash-window:** before-pipeline,
  after-pipeline-success-before-sink-intent,
  after-sink-intent-before-receipt-record,
  after-receipt-record-before-report-intent, and
  after-report-intent-before-report-record windows fail closed with no
  finalization; after-report-record-before-finalization-intent and
  after-finalization-intent-before-finalization-record windows fail closed with
  no finalization; after-finalization-record-before-finalization-success fails
  closed unless an explicit matching finalization success exists;
  after-finalization-success recovers as durable-completion finalized;
  after-finalization-ambiguous, finalization-record-failed, rollback-completed,
  rollback-failed, and unknown windows fail closed with no finalization;
  production/MainNet recovery classification is unavailable; MainNet peer-driven
  apply refusal precedes recovery classification.
* **Projection / stage-ordering:** only `CompletionReportRecorded` creates a
  finalization intent; `CompletionReportDuplicateIdempotent` projects to
  idempotent-only; only `DurableCompletionFinalized` authorizes a new modeled
  finalization; every no-finalization outcome does not project to durable
  completion finalized; a rejection before the finalizer stage leaves the
  finalizer invocation count at zero; a finalization record failure does not
  invalidate the report-recorded binding but does not authorize finalization; one
  valid finalization inserts exactly one ledger record; the ledger
  snapshot/restore models a rollback with no drift.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_252_modeled_durable_completion_finalization_projection_tests`
  — `98 passed; 0 failed`.
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
  therefore before any finalization can be recorded.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report
  intent can exist, and therefore before any finalization can be recorded.
* Run 250 `CompletionReportRecorded` is required before any finalization intent
  can exist; only that reporter outcome creates a finalization intent.
* `DurableCompletionFinalized` is required before any new modeled
  durable-completion-finalized state.
* Every non-recording reporter outcome produces no finalizer invocation and no
  finalization.
* A failed finalization record, rollback, rollback-failed, ambiguous window,
  unavailable production/MainNet path, rejected replay state, and unsupported
  action never finalize.
* A finalizer failure, rollback, rollback failure, or ambiguous finalization
  window never retroactively claims durable-completion finalization.
* A duplicate identical finalization is idempotent (no second finalization); the
  same finalization id with a different digest fails closed as equivocation; a
  duplicate-idempotent completion report never creates a new finalization by
  itself.
* Rejected finalizer paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
  sequence write, no marker write, no durable consume, and no finalizer
  invocation where the rejection happens before the finalizer stage.
* MainNet peer-driven apply is refused before pipeline progression, before any
  sink invocation, before any reporter invocation, and before any finalizer
  invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture finalizer mutates only modeled in-memory finalization state; no
  RocksDB / file / schema / migration / storage-format change; no wire / marker /
  sequence / trust-bundle change.

## Honest limitations

* Run 252 is source/test only and introduces a finalization-projection layer over
  a modeled in-memory ledger, not a real production finalization backend. No
  production mutating behavior is enabled.
* The fixture finalizer records only modeled in-memory finalization state; it
  performs no real durable-completion finalization, and the production / MainNet
  finalizers are deliberately reachable-but-unavailable.
* No real persistent replay backend, durable consume backend, completion-report
  backend, finalization backend, production mutation engine, governance execution
  engine, on-chain governance proof verifier, or KMS/HSM/RemoteSigner backend is
  implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 252 closes the source/test
modeled durable-completion finalization-projection gap only and does **not**
claim full C4 or C5 closure.

## Suggested Run 253 next step

Release-binary evidence for the Run 252 modeled durable-completion finalization
projection (mirroring the Run 241 / 243 / 245 / 247 / 249 / 251 pattern): build
the release binary, exercise the Run 246 pipeline → Run 248 consume-sink
projection → Run 250 completion-report projection → Run 252 finalization
projection → fixture finalization recording path through the source/test
fixtures, and capture grep-verifiable evidence that a modeled finalization is
recorded only after a Run 250 completion-report record, that every
non-recording / record-failure / rollback / ambiguous / equivocation path
remains non-mutating and records no finalization, and that production/MainNet
finalizer paths and MainNet peer-driven apply remain refused/unavailable.
