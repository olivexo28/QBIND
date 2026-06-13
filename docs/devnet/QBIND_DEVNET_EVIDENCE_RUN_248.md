# QBIND DevNet evidence — Run 248

**Title.** Source/test governance modeled durable-consume projection sink boundary.

**Status.** PASS (source/test only). Run 248 extends the Run 246 modeled
end-to-end governance pipeline with a mockable, in-memory **consume-receipt sink**
that models how a future production call site would **record** an
after-success-only durable consume *receipt* once the Run 246 pipeline has
authorized consume. Run 246 proved that a durable consume is authorized
end-to-end only after evaluator/call-site authorization, durable replay freshness,
mutation-engine authorization, and a modeled successful applier outcome all agree
(terminating in the single consume-authorizing outcome
`ModeledApplierAppliedAndDurableConsumeAuthorized`). What was still missing was a
typed source/test boundary that models the after-success-only consume-receipt
*recording* step. Run 248 closes that source/test projection-sink gap only.

Run 248 introduces a **projection-sink layer**, **not** a replacement for any
existing module. It consumes the typed Run 246 pipeline outcome as a binding and
projects it onto a consume-sink intent; only the Run 246
`ModeledApplierAppliedAndDurableConsumeAuthorized` outcome creates a sink intent.
The sink is a **model only**. It implements **no** real persistent replay backend,
**no** real durable consume backend, **no** real production mutation engine, **no**
real governance execution engine, **no** real on-chain governance proof verifier,
**no** RocksDB backend, **no** file format, **no** schema, **no** database
migration, **no** storage-format change, **no** KMS/HSM backend, **no**
RemoteSigner backend, **no** MainNet governance enablement, **no** MainNet
peer-driven apply enablement, and **no** validator-set rotation. It changes **no**
wire, schema, marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 248 adds a modeled durable-consume projection sink boundary.
* It models how a future production call site would record an after-success-only
  consume receipt.
* It does **not** implement a real persistent replay backend.
* It does **not** implement a real durable consume backend.
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
* The fixture sink mutates only modeled in-memory receipt state.
* Rejected sink paths are non-mutating.
* Run 248 does not weaken any prior run (Runs 070, 130–247) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`

Run 248 adds a new source module (registered in `lib.rs`) that defines:

* typed sink inputs / policy / bindings
  (`GovernanceModeledDurableConsumeSinkInput`,
  `GovernanceModeledDurableConsumeSinkPolicy`,
  `GovernanceModeledDurableConsumeSinkExpectations`,
  `GovernanceModeledDurableConsumeSinkReceipt`) plus type aliases over the Run
  244/246 bindings (`…Surface`, `…EnvironmentBinding`, `…RuntimeBinding`,
  `…ReplayBinding`, `…PipelineBinding`);
* modeled in-memory receipt state (`ModeledDurableConsumeReceiptLedger`,
  `ModeledDurableConsumeReceiptRecord`, `ModeledDurableConsumeReceiptSnapshot`,
  `ModeledDurableConsumeReceiptStatus`, `ModeledDurableConsumeReceiptDigest`) —
  in-memory only; never touches RocksDB, files, markers, sequence files, or any
  production durable state;
* an explicit sink outcome enum
  (`GovernanceModeledDurableConsumeSinkOutcome`) whose only **new**-receipt
  authorizing variant is `ConsumeReceiptRecorded`, including
  `LegacyBypassNoReceipt`, `RejectedBeforePipelineNoReceipt`,
  `PipelineDidNotAuthorizeConsumeNoReceipt`, `ConsumeReceiptDuplicateIdempotent`,
  `ConsumeReceiptRejectedBeforeRecord`, `ConsumeReceiptRecordFailedNoConsume`,
  `ConsumeReceiptRolledBackNoConsume`,
  `ConsumeReceiptRollbackFailedFatalNoConsume`,
  `ConsumeReceiptAmbiguousFailClosedNoConsume`,
  `ProductionSinkUnavailableNoConsume`, `MainNetSinkUnavailableNoConsume`,
  `MainNetPeerDrivenApplyRefusedNoConsume`,
  `ValidatorSetRotationUnsupportedNoConsume`, and
  `PolicyChangeUnsupportedNoConsume`;
* a pure/mockable sink trait
  (`GovernanceModeledDurableConsumeProjectionSink`) with
  `record_modeled_consume_receipt` and `recover_modeled_consume_receipt_window`,
  plus source/test-only implementations (`FixtureModeledDurableConsumeProjectionSink`
  for DevNet/TestNet, and the reachable-but-unavailable
  `ProductionModeledDurableConsumeProjectionSink` /
  `MainNetModeledDurableConsumeProjectionSink`). The fixture sink exposes an
  invocation counter so tests prove non-success paths never invoke it;
* composition helpers
  (`project_pipeline_outcome_to_consume_sink_intent`,
  `evaluate_modeled_durable_consume_projection_sink`,
  `recover_modeled_durable_consume_projection_sink_window`,
  `sink_outcome_authorizes_modeled_consume_receipt`,
  `sink_outcome_projects_to_durable_completion`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression and
   **before** any sink invocation.
2. A disabled sink / pipeline / evaluator-call-site policy preserves the legacy
   no-receipt, no-consume bypass and never invokes the sink.
3. Only the Run 246 `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome
   creates a sink intent; every other pipeline outcome maps to a no-receipt
   fail-closed outcome and never invokes the sink.
4. Pre-sink environment / chain / genesis / governance surface / mutation surface
   binding validation completes **before** the sink is invoked; a mismatch fails
   closed with no sink invocation.
5. The sink record happens **after** pipeline consume authorization; the
   receipt-identity fields must match exactly before any modeled receipt is
   recorded.
6. Only `ConsumeReceiptRecorded` authorizes a **new** modeled receipt-recorded
   state. A duplicate identical receipt is idempotent (no second receipt); the
   same receipt id with a different digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `modeled_consume_sink_rejection_is_non_mutating`
* `modeled_consume_sink_never_calls_run_070`
* `modeled_consume_sink_never_mutates_live_pqc_trust_state`
* `modeled_consume_sink_never_writes_sequence_or_marker`
* `modeled_consume_sink_no_rocksdb_file_schema_migration_change`
* `modeled_consume_sink_pipeline_success_required_before_receipt`
* `modeled_consume_sink_receipt_record_required_before_consume`
* `modeled_consume_sink_failed_record_never_consumes`
* `modeled_consume_sink_rollback_never_consumes`
* `modeled_consume_sink_ambiguous_window_fails_closed`
* `modeled_consume_sink_mainnet_peer_driven_apply_refused_first`
* `modeled_consume_sink_production_mainnet_unavailable`
* `modeled_consume_sink_validator_set_rotation_unsupported`
* `modeled_consume_sink_policy_change_unsupported`
* `modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority`
* `modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_248_modeled_durable_consume_projection_sink_tests.rs`
— 68 tests, all passing. The matrix covers:

* **Accepted / compatible:** disabled sink / pipeline / evaluator-call-site policy
  preserve the legacy no-receipt bypass and never invoke the sink; DevNet and
  TestNet pipeline success + sink record success record exactly one modeled
  in-memory receipt; a duplicate identical receipt is idempotent with no second
  receipt; the production and MainNet sink paths are reachable but
  unavailable/fail-closed and record no receipt; MainNet peer-driven apply is
  refused before pipeline progression and before any sink invocation;
  validator-set rotation and policy-change are unsupported and record no receipt.
* **Rejected / fail-closed:** every non-success pipeline outcome (evaluator /
  call-site rejection, durable replay stale / consumed / superseded / backend
  unavailable / rejected-before-mutation, mutation-engine rejection, modeled
  applier rejected-before-apply, modeled apply failure, rollback, rollback-failed,
  ambiguous window) produces no sink intent, no receipt, and zero sink
  invocations; a sink record failure, rollback, rollback-failed, and ambiguous
  window all fail closed without recording a receipt; the same receipt id with a
  different digest is rejected as equivocation and records no second receipt;
  wrong environment / chain / genesis / governance surface / mutation surface are
  rejected before sink invocation (zero invocations); wrong receipt digest /
  pipeline decision digest / proposal id / decision id / candidate digest /
  authority-domain sequence and a malformed receipt are rejected before record
  (sink invoked, no record); local operator and peer majority cannot satisfy
  MainNet authority.
* **Recovery / crash-window:** before-pipeline, after-pipeline-success-before-sink-intent,
  and after-sink-intent-before-record windows fail closed with no receipt;
  after-record-before-report fails closed unless an explicit matching receipt
  report exists; after-report-success recovers as receipt recorded;
  after-report-ambiguous, record-failed, rollback-completed, rollback-failed, and
  unknown windows fail closed with no consume; production/MainNet recovery
  classification is unavailable; MainNet peer-driven apply refusal precedes
  recovery classification.
* **Projection / stage-ordering:** only
  `ModeledApplierAppliedAndDurableConsumeAuthorized` creates a sink intent; only
  `ConsumeReceiptRecorded` authorizes a new modeled receipt; every no-receipt
  outcome does not project to durable completion; a rejection before the sink
  stage leaves the sink invocation count at zero; a sink record failure does not
  invalidate the pipeline-authorized binding but does not authorize consume; the
  ledger snapshot/restore models a rollback with no drift.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
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

* Run 246 pipeline success is required before any sink receipt can be recorded;
  only `ModeledApplierAppliedAndDurableConsumeAuthorized` creates a sink intent.
* `ConsumeReceiptRecorded` is required before any new modeled receipt-recorded
  state.
* Every non-success pipeline outcome produces no sink invocation and no receipt.
* A failed receipt record, rollback, rollback-failed, ambiguous window,
  unavailable production/MainNet path, rejected replay state, and unsupported
  action never consume.
* A sink failure, rollback, rollback failure, or ambiguous receipt window never
  retroactively claims durable consume success.
* A duplicate identical receipt is idempotent (no second receipt); the same
  receipt id with a different digest fails closed as equivocation.
* Rejected sink paths are non-mutating: no Run 070 call, no `LivePqcTrustState`
  mutation, no live trust swap, no session eviction, no sequence write, no marker
  write, no durable consume, and no sink invocation where the rejection happens
  before the sink stage.
* MainNet peer-driven apply is refused before pipeline progression and before any
  sink invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture sink mutates only modeled in-memory receipt state; no RocksDB /
  file / schema / migration / storage-format change; no wire / marker / sequence /
  trust-bundle change.

## Honest limitations

* Run 248 is source/test only and introduces a projection-sink layer over a
  modeled in-memory ledger, not a real production durable-consume backend. No
  production mutating behavior is enabled.
* The fixture sink records only modeled in-memory receipt state; it performs no
  real durable consume, and the production / MainNet sinks are deliberately
  reachable-but-unavailable.
* No real persistent replay backend, durable consume backend, production mutation
  engine, governance execution engine, on-chain governance proof verifier, or
  KMS/HSM/RemoteSigner backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 248 closes the source/test
modeled durable-consume projection sink gap only and does **not** claim full C4 or
C5 closure.

## Suggested Run 249 next step

Release-binary evidence for the Run 248 modeled durable-consume projection sink
(mirroring the Run 241 / 243 / 245 / 247 pattern): build the release binary,
exercise the Run 246 pipeline → consume-sink projection → fixture receipt
recording path through the source/test fixture sink, and capture grep-verifiable
evidence that a modeled consume receipt is recorded only after a Run 246
pipeline-authorized consume, that every non-success / record-failure / rollback /
ambiguous / equivocation path remains non-mutating and records no receipt, and
that production/MainNet sink paths and MainNet peer-driven apply remain
unavailable/refused in a release binary.
