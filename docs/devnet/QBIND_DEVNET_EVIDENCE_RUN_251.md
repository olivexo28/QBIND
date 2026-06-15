# QBIND DevNet evidence — Run 251

**Title.** Release-binary governance modeled durable-consume completion reporter
evidence.

**Status.** PASS (release-binary evidence). Run 251 is the release-binary
evidence run for the Run 250 source/test governance **modeled durable-consume
completion reporter boundary** in
`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`.
Run 250 landed the typed durable-consume completion reporter boundary that
projects a Run 248 modeled durable-consume sink outcome into a typed
completion-report intent and records, through a pure/mockable reporter, only the
in-memory `ModeledDurableConsumeCompletionReportLedger` — refuse MainNet
peer-driven apply first, honour the legacy disabled-policy bypass, require a
`ConsumeReceiptRecorded` sink outcome, validate the pre-record bindings, then
record a completion report under report-identity, idempotency, and equivocation
gates — but captured **no** release-binary evidence (deferred to Run 251). Run
251 proves on real `target/release/qbind-node` plus a release-built helper that
the release-built code exposes and exercises that boundary.

Run 251 is **release-binary evidence only**. It implements **no** real
completion-report backend, **no** real durable consume backend, **no** real
persistent replay backend, **no** real production mutation engine, **no** real
governance execution engine, **no** real on-chain governance proof verifier,
**no** RocksDB backend, **no** file format, **no** schema, **no** database
migration, **no** storage-format change, **no** real KMS/HSM backend, **no** real
RemoteSigner backend, **no** MainNet governance enablement, **no** MainNet
peer-driven apply enablement, and **no** validator-set rotation. It changes
**no** wire, schema, marker, sequence, or trust-bundle format. Any
production-source module remains pure / source-test bounded and fail-closed; the
modeled durable-consume completion reporter boundary is release-evidenced, not
production-enabled.

## What Run 251 states

* Run 251 is release-binary evidence for Run 250.
* No production mutating behaviour is enabled.
* The modeled durable-consume completion reporter boundary is release-evidenced,
  not production-enabled.
* The release helper exercises the Run 250 production library symbols in release
  mode.
* The release helper remains dead code from the production runtime.
* The fixture reporter mutates only modeled in-memory
  `ModeledDurableConsumeCompletionReportLedger` state.
* Only the Run 248 `ConsumeReceiptRecorded` sink outcome can create a
  completion-report intent.
* `ConsumeReceiptDuplicateIdempotent` may only match an already-recorded
  completion report.
* Only `CompletionReportRecorded` authorizes a new modeled completion-reported
  state.
* A duplicate identical completion report is idempotent and creates no second
  report.
* A same report id with a different digest fails closed as equivocation.
* Every non-recording sink outcome produces no completion report.
* Failed record, rollback, rollback-failed, ambiguous acknowledgement windows,
  unavailable production/MainNet reporter paths, and unsupported actions never
  complete.
* MainNet peer-driven apply remains refused before pipeline progression, before
  any sink invocation, and before any reporter invocation.
* Rejected reporter paths are non-mutating.
* No real completion-report backend is implemented.
* No real durable consume backend is implemented.
* No real persistent replay backend is implemented.
* No real production mutation engine is implemented.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No wire/schema/marker/sequence/trust-bundle change is implemented.
* No KMS/HSM/RemoteSigner backend is implemented.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* The reporter does not call Run 070.
* The reporter does not mutate `LivePqcTrustState`.
* The reporter does not perform a real trust swap.
* The reporter does not evict sessions.
* The reporter does not write sequence files.
* The reporter does not write authority markers.
* Full C4 remains **OPEN**.
* C5 remains **OPEN**.

## Symbol substitutions

None. Every Run 250 symbol named in the task exists in
`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`
with the exact name used by the helper, harness, and this report. No
compatibility shim was required. (The helper additionally exercises the
module's `ModeledCompletionReportFault` injector and
`ModeledDurableConsumeCompletionReportWindow` classification, both of which exist
under those exact names.)

## Strict scope

* Release-binary evidence only.
* Uses the release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behaviour change (the run adds only an example helper, a
  harness script, evidence, and narrow doc updates).
* No real completion-report backend; no real durable consume backend; no real
  persistent replay backend; no real production mutation engine; no real
  governance execution engine; no real on-chain governance proof verifier; no
  RocksDB schema; no file format; no database migration; no storage-format
  change; no MainNet governance enablement; no MainNet peer-driven apply
  enablement; no validator-set rotation; no KMS/HSM backend; no RemoteSigner
  backend.
* Rejected reporter paths are non-mutating and never invoke Run 070.
* A completion report is recorded only after a `ConsumeReceiptRecorded` sink
  outcome and a clean pre-record binding validation; failed record, rollback,
  rollback failure, ambiguous windows, unavailable production/MainNet paths, and
  unsupported actions never complete.
* Run 251 does not weaken any prior run (Runs 070, 130–250) and does not claim
  full C4 or C5 closure.

## Deliverables

* **Release helper** —
  `crates/qbind-node/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper.rs`.
  Links against the release-built production library symbols and exercises
  `pqc_governance_modeled_durable_consume_completion_reporter`,
  `evaluate_modeled_durable_consume_completion_reporter`,
  `GovernanceModeledDurableConsumeCompletionReporter`,
  `FixtureModeledDurableConsumeCompletionReporter`,
  `ProductionModeledDurableConsumeCompletionReporter`,
  `MainNetModeledDurableConsumeCompletionReporter`,
  `project_sink_outcome_to_completion_report_intent`, `CompletionReportIntent`,
  `recover_modeled_durable_consume_completion_reporter_window`,
  `ModeledDurableConsumeCompletionReportWindow`,
  `GovernanceModeledDurableConsumeCompletionReporterInput`,
  `GovernanceModeledDurableConsumeCompletionReporterExpectations`,
  `GovernanceModeledDurableConsumeCompletionReporterPolicy`,
  `GovernanceModeledDurableConsumeCompletionReport`,
  `ModeledDurableConsumeCompletionReportLedger`,
  `ModeledDurableConsumeCompletionReportRecord`,
  `ModeledDurableConsumeCompletionReportSnapshot`,
  `ModeledDurableConsumeCompletionReportDigest`,
  `ModeledDurableConsumeCompletionReportStatus`,
  `ModeledDurableConsumeCompletionReporterKind`, `ModeledCompletionReportFault`,
  the `GovernanceModeledDurableConsumeCompletionReporterOutcome` taxonomy with its
  `tag()` / predicate surface
  (`completion_reporter_outcome_authorizes_modeled_completion`,
  `completion_reporter_outcome_projects_to_durable_completion`), and all
  grep-verifiable invariant / fail-closed helpers from Run 250.
* **Release harness** —
  `scripts/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary.sh`.
  Builds `target/release/qbind-node` and the Run 251 helper; captures git commit,
  rustc/cargo versions, SHA-256 + ELF Build ID for both binaries; runs
  real-binary surface scenarios; runs the helper corpus in release mode; runs
  source- and helper-reachability greps for the Run 250 symbols; runs a denylist
  proving no active production/MainNet enablement claims; runs the regression
  test corpus; and writes generated evidence into the ignored evidence directory.
* **Evidence archive** —
  `docs/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary/`
  (tracks only `README.md`, `summary.txt`, `.gitignore`; generated artifacts are
  ignored, following the Run 247 / Run 249 convention).
* **Canonical report** — this file.

## Release-helper corpus

`crates/qbind-node/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper.rs`
drives eight tables through the release-built Run 250 symbols
(316 checks total, all PASS):

* **accepted (67)** — a disabled reporter policy and a disabled
  sink/pipeline/evaluator/call-site policy preserve the legacy no-acknowledgement,
  no-completion bypass with a zero reporter-invocation count and an empty
  completion-report ledger; DevNet and TestNet fixture pipelines that resolve to a
  recorded sink receipt record a completion report only after the sink receipt,
  mutating only the in-memory `ModeledDurableConsumeCompletionReportLedger`; the
  only completion-report-creating sink outcome is `ConsumeReceiptRecorded`;
  `ConsumeReceiptDuplicateIdempotent` matches an already-recorded report only;
  production and MainNet reporter kinds are reachable but unavailable; MainNet
  peer-driven apply is refused before pipeline progression, sink invocation, and
  reporter invocation; validator-set rotation and policy-change actions are
  unsupported.
* **rejection (114)** — every non-recording sink outcome (legacy bypass,
  rejected-before-pipeline, pipeline-did-not-authorize, rejected-before-record,
  record-failed, rolled-back, rollback-failed, ambiguous, production/MainNet
  unavailable, validator-set rotation, policy-change), every reporter record fault
  (record-failed, rollback, rollback-failed, ambiguous), wrong environment / chain
  / genesis / governance surface / mutation surface binding (rejected before
  reporter invocation), wrong report-digest / receipt-digest / sink-decision-digest
  / pipeline-decision-digest / proposal / decision / candidate / authority-sequence
  identity and a malformed report (rejected before record, reporter invoked), and a
  same-id different-digest equivocation are each non-completing; local operator and
  peer majority cannot satisfy MainNet authority; every rejected path is
  non-mutating.
* **recovery (16)** — before-pipeline / after-pipeline-before-sink-intent /
  after-sink-intent-before-receipt-record fail closed as sink-did-not-record;
  after-receipt-record-before-report-intent / after-report-intent-before-record /
  after-record-before-success (without report) fail closed as rejected-before-
  record; after-record-before-success and after-report-success recover as recorded
  only with an explicit matching completion report; after-report-ambiguous,
  record-failed, rollback, rollback-failed, and unknown windows fail closed;
  production / MainNet recovery classification is unavailable; MainNet peer-driven
  apply refusal precedes recovery classification.
* **projection (37)** — only the Run 248 `ConsumeReceiptRecorded` sink outcome
  projects to a create-completion-report intent; `ConsumeReceiptDuplicateIdempotent`
  projects to idempotent-only; every other sink outcome projects to no
  completion-report intent; only `CompletionReportRecorded` authorizes a new
  modeled completion-reported state; every no-completion outcome neither authorizes
  a new completion nor projects to durable completion; the recorded and
  idempotent-duplicate outcomes both project to durable completion but only the
  recorded outcome authorizes a new completion.
* **stage_ordering (14)** — MainNet peer-driven apply refusal precedes everything;
  a rejection before the reporter stage leaves the reporter invocation count at
  zero; completion report recording happens only after a recorded sink receipt; a
  reporter record failure does not retroactively invalidate the sink-recorded
  receipt but does not authorize completion; a reporter rollback failure is fatal /
  fail-closed; a non-recording sink never touches the ledger or invokes the
  reporter.
* **completion_report_ledger (25)** — one valid completion report inserts exactly
  one modeled in-memory record; a duplicate identical completion report is
  idempotent (no second record); a same-id different-digest report fails closed as
  equivocation; wrong identity fields never record; rollback restores the modeled
  completion-report ledger snapshot exactly; the ledger digest reflects the report
  digest material.
* **non_mutation (20)** — all grep-verifiable invariant / fail-closed helpers from
  Run 250 hold in release mode; a rejected path leaves the completion-report ledger
  unchanged, performs no live trust swap, writes no marker, writes no sequence,
  evicts no session, performs no durable consume, and calls no Run 070; a rejection
  before the reporter stage leaves the reporter invocation count at zero; no fixture
  case mutates `LivePqcTrustState`.
* **reachability (23)** — every outcome / reporter-kind / policy `tag()` and
  predicate is stable in release mode.

## Real release-binary surface scenarios

The harness runs the real `target/release/qbind-node`:

* **S1** — `--help` exposes no completion-reporter enablement banner or visible
  public flag drift (rc=0).
* **S2 / S3 / S4** — default DevNet / TestNet / MainNet startup parse/smoke
  surfaces emit no completion-reporter enablement claim (rc=0).
* **S5** — the hidden governance-execution selector still parses and remains
  silent on any completion-reporter enablement (rc=1, parse-only smoke without a
  network).
* **S6** — an invalid governance-execution selector fails closed before mutation
  (rc≠0) and prints the fail-closed banner (`no marker write; no sequence write;
  no live trust swap; no session eviction; no Run 070 call`).

No Run 250/251 hidden selector or helper-only path appears as a public production
enablement surface.

## Denylist

The harness proves the captured real-binary and helper logs contain no
active/enabled claims for: real completion-report backend, modeled
completion-reporter production enabled, MainNet modeled completion-reporter, real
durable consume backend, modeled durable-consume sink production, MainNet modeled
sink, MainNet mutation engine, MainNet governance, MainNet peer-driven apply,
real production mutation engine, real governance execution engine, real on-chain
governance proof verifier, real persistent replay backend, RocksDB/file replay
backend, schema/storage-format migration, KMS/HSM/RemoteSigner backend,
validator-set rotation, policy-change action, autonomous apply / apply-on-receipt,
peer-majority authority, Run 070 apply / `LivePqcTrustState` mutation / real trust
swap / session eviction / marker write / sequence write / durable consume /
production completion reporting from the reporter boundary, and active
DummySig/DummyKem/DummyAead. All 43 forbidden patterns are proven empty.

## Tests

All regression targets PASS (rc=0):

```
cargo build -p qbind-node --release --bin qbind-node
cargo build -p qbind-node --release --example run_251_modeled_durable_consume_completion_reporter_release_binary_helper
bash scripts/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary.sh
cargo test -p qbind-node --test run_250_modeled_durable_consume_completion_reporter_tests
cargo test -p qbind-node --test run_248_modeled_durable_consume_projection_sink_tests
cargo test -p qbind-node --test run_246_governance_modeled_end_to_end_pipeline_tests
cargo test -p qbind-node --test run_244_modeled_governance_trust_mutation_applier_tests
cargo test -p qbind-node --test run_242_governance_execution_mutation_engine_tests
cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests
cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests
cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests
cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests
cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests
cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests
cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests
cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests
cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

## Security invariants preserved

* Rejected reporter paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
  sequence write, no marker write, no durable consume, and (for a
  rejection-before-reporter) no reporter invocation.
* A completion report is recorded only after a `ConsumeReceiptRecorded` sink
  outcome and a clean pre-record binding validation; only `CompletionReportRecorded`
  records a new modeled completion report.
* A duplicate identical completion report is idempotent (no second report) and a
  same-id different-digest completion report fails closed as equivocation.
* Failed record, rollback, rollback failure, ambiguous windows, unavailable
  production/MainNet paths, and unsupported actions never complete.
* Production / MainNet reporter kinds are reachable but always unavailable /
  fail-closed.
* MainNet peer-driven apply remains refused before any pipeline progression, sink
  invocation, or reporter invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes no wire / marker / sequence / trust-bundle / storage
  format and introduces no RocksDB schema, file format, or database migration.

## Honest limitations

* The Run 250 durable-consume completion reporter boundary is a pure, typed
  projection over the already-landed Run 248 modeled durable-consume sink receipt
  plus a mockable reporter that records only the in-memory
  `ModeledDurableConsumeCompletionReportLedger`, exercised here through
  release-built library symbols (the same symbols a future production call site
  would use); it applies no real (live) completion reporting or durable consume
  and performs no I/O.
* The boundary specifies the ordering a real completion reporter would have to
  honour but implements none of that production behaviour: no real
  completion-report backend, no real durable consume backend, no real persistent
  replay backend, no real production mutation engine, no real governance execution
  engine, no real on-chain governance proof verifier, no RocksDB backend, no file
  format, no schema, no database migration, and no storage-format change.
* The `FixtureModeledDurableConsumeCompletionReporter` records only the modeled
  in-memory completion-report ledger and performs no real completion reporting;
  the `ProductionModeledDurableConsumeCompletionReporter` and
  `MainNetModeledDurableConsumeCompletionReporter` are always unavailable /
  fail-closed.
* No real KMS / HSM / RemoteSigner backend. No MainNet governance enablement, no
  MainNet peer-driven apply enablement, no validator-set rotation.
* Existing Run 249, Run 247, Run 245, Run 243, and Run 241 release behaviour
  remains compatible.

## C4 / C5 status

Run 251 closes the Run 250 release-binary evidence gap only. **Full C4 remains
OPEN; C5 remains OPEN.** Run 251 makes no production mutating enablement claim.

## Suggested Run 252 next step

A source/test step that extends the Run 250 modeled durable-consume completion
reporter with a typed, mockable durable-consume *completion-receipt
finalization / durable-completion projection* — modelling how a future
production call site would project the after-completion-report-only acknowledgement
into the Run 240 durable completion semantics (e.g. a terminal durable-completion
marker model) without enabling any real persistent backend — still source/test
only, still fail-closed, with no production mutating enablement, followed by a Run
253 release-binary evidence run mirroring this one.

## Contradiction crosscheck

Run 251 was crosschecked against Runs 050–250. No contradiction was found: Run
251 adds only a release-built example helper, a harness script, an evidence
archive, this canonical report, and narrow doc updates; it changes no production
source behaviour, enables no production mutation, and preserves every prior
fail-closed invariant (MainNet peer-driven apply refusal, sink-outcome-projection /
pre-record-binding / report-record ordering, after-receipt-recorded-only
completion, report idempotency and equivocation fail-closed, and the non-mutating
rejection guarantees). A “no Run 251 contradiction” entry is recorded in
`docs/whitepaper/contradiction.md`.
