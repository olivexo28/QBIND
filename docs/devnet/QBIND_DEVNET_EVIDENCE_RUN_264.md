# QBIND DevNet evidence — Run 264

**Title.** Source/test durable-completion **consumer settlement-projection sink
boundary**.

**Status.** PASS (source/test only). Run 264 extends the Run 262 modeled
durable-completion acknowledgement consumer / post-acknowledgement settlement
interface boundary with a typed, mockable, in-memory **consumer
settlement-projection sink boundary** that models the first post-consumer
projection step a future production settlement subsystem might use **after** a Run
262 `AcknowledgementConsumed` outcome has been recorded. Run 262 proved that a
modeled acknowledgement-consumer record is recorded only after the Run 260
`AcknowledgementRecorded` outcome. What was still missing was a typed source/test
boundary that converts a valid consumed-acknowledgement state into a typed
settlement-projection intent and modeled in-memory settlement-projection receipt.
Run 264 closes that source/test settlement-projection interface gap only.

Run 264 introduces a **settlement-projection interface boundary**, **not** a
replacement for any existing module. It consumes the typed Run 262 consumer outcome
(`DurableCompletionAcknowledgementConsumerOutcome`) as a `consumer_binding` and
projects it onto a settlement-projection request intent; only the Run 262
`AcknowledgementConsumed` outcome creates a settlement-projection request, and a Run
262 `AcknowledgementConsumerDuplicateIdempotent` may only match an already-recorded
settlement-projection record and never creates a new one. The settlement-projection
layer is a **model only**. It implements **no** real settlement, **no** real
audit-ledger acknowledgement, **no** real external-publication confirmation, **no**
real external publication, **no** real production attestation backend, **no** real
finalization backend, **no** real completion-report backend, **no** real durable
consume backend, **no** real persistent replay backend, **no** real governance
execution engine, **no** real production mutation engine, **no** real on-chain
governance proof verifier, **no** RocksDB backend, **no** file format, **no**
schema, **no** database migration, **no** storage-format change, **no** KMS/HSM
backend, **no** RemoteSigner backend, **no** MainNet governance enablement, **no**
MainNet peer-driven apply enablement, and **no** validator-set rotation. It changes
**no** wire, schema, marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 264 adds a durable-completion consumer settlement-projection sink boundary.
* The boundary models the first post-Run-262 settlement-projection step a future
  production settlement subsystem might use.
* The boundary consumes only Run 262 `AcknowledgementConsumed`.
* Run 262 `AcknowledgementConsumed` is required before any settlement-projection
  request can exist.
* Only `SettlementProjectionRecorded` authorizes modeled settlement-projection
  state.
* The fixture settlement-projection sink is DevNet/TestNet evidence-only and
  in-memory only.
* Production settlement-projection, MainNet settlement-projection, and external
  settlement-projection sinks are reachable but unavailable/fail-closed.
* It does **not** implement a real settlement.
* It does **not** implement a real audit-ledger acknowledgement.
* It does **not** implement a real external-publication confirmation.
* It does **not** implement a real external publication.
* It does **not** implement a real production attestation backend.
* It does **not** implement a real finalization backend.
* It does **not** implement a real completion-report backend.
* It does **not** implement a real durable consume backend.
* It does **not** implement a real persistent replay backend.
* It does **not** implement a real governance execution engine.
* It does **not** implement a real production mutation engine.
* It does **not** implement a real on-chain governance proof verifier.
* It does **not** add KMS/HSM/RemoteSigner backend.
* It does **not** add RocksDB / file / schema / migration / storage-format
  changes.
* It does **not** add wire / schema / marker / sequence / trust-bundle changes.
* It does **not** write authority markers.
* It does **not** write trust-bundle sequence files.
* It does **not** call Run 070.
* It does **not** mutate `LivePqcTrustState`.
* It does **not** perform a real trust swap.
* It does **not** evict sessions.
* It does **not** perform real external publication / network I/O.
* It does **not** enable MainNet governance.
* It does **not** enable MainNet peer-driven apply.
* It does **not** implement validator-set rotation.
* The fixture settlement-projection sink mutates only modeled in-memory
  consumer-settlement-projection state.
* Rejected settlement-projection paths are non-mutating.
* Run 264 does not weaken any prior run (Runs 070, 130–263) and does not claim full
  C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_consumer_settlement_projection.rs`

Run 264 adds a source module (registered in `lib.rs`) that defines:

* typed settlement-projection inputs / policy / identity / bindings
  (`DurableCompletionConsumerSettlementProjectionInput`,
  `DurableCompletionConsumerSettlementProjectionPolicy`,
  `DurableCompletionConsumerSettlementProjectionKind`,
  `DurableCompletionConsumerSettlementProjectionIdentity`,
  `DurableCompletionConsumerSettlementProjectionExpectations`,
  `DurableCompletionConsumerSettlementProjectionRequest`,
  `DurableCompletionConsumerSettlementProjectionResponse`,
  `DurableCompletionConsumerSettlementProjectionRecord`) plus the Run 262 consumer
  outcome (`DurableCompletionAcknowledgementConsumerOutcome`) carried as the
  `consumer_binding`, and the Run 246/248/250/252/254/256/258/260 bindings carried
  for the MainNet peer-driven composition and digest binding;
* modeled in-memory consumer-settlement-projection state
  (`DurableCompletionConsumerSettlementProjectionLedger`,
  `DurableCompletionConsumerSettlementProjectionLedgerRecord`,
  `DurableCompletionConsumerSettlementProjectionLedgerSnapshot`,
  `DurableCompletionConsumerSettlementProjectionLedgerStatus`,
  `DurableCompletionConsumerSettlementProjectionDigest`,
  `DurableCompletionConsumerSettlementProjectionTranscriptDigest`) — in-memory only;
  never touches RocksDB, files, markers, sequence files, external publications,
  confirmations, audit-ledger entries, settlement records, or any production
  durable state. The settlement-projection digests bind, via domain-separated
  SHA3-256 over length-prefixed fields, the projection identity, request, response,
  record, and transcript, including the full Run 262 consumer identity / request /
  response / record / transcript digest binding;
* an explicit settlement-projection outcome enum
  (`DurableCompletionConsumerSettlementProjectionOutcome`) whose only **new**-record
  authorizing variant is `SettlementProjectionRecorded`, including
  `LegacyBypassNoSettlementProjection`,
  `RejectedBeforeConsumerNoSettlementProjection`,
  `ConsumerDidNotRecordNoSettlementProjection`,
  `SettlementProjectionDuplicateIdempotent`,
  `SettlementProjectionRejectedBeforeRecord`,
  `SettlementProjectionRecordFailedNoProjection`,
  `SettlementProjectionRolledBackNoProjection`,
  `SettlementProjectionRollbackFailedFatalNoProjection`,
  `SettlementProjectionAmbiguousFailClosedNoProjection`,
  `ProductionSettlementProjectionUnavailableNoProjection`,
  `MainNetSettlementProjectionUnavailableNoProjection`,
  `ExternalSettlementProjectionUnavailableNoProjection`,
  `MainNetPeerDrivenApplyRefusedNoProjection`,
  `ValidatorSetRotationUnsupportedNoProjection`, and
  `PolicyChangeUnsupportedNoProjection`;
* a pure/mockable settlement-projection sink trait
  (`GovernanceDurableCompletionConsumerSettlementProjectionSink`) with
  `project_durable_completion_consumer_settlement` and
  `recover_durable_completion_consumer_settlement_projection_window`, plus
  source/test-only implementations
  (`FixtureDurableCompletionConsumerSettlementProjectionSink` for DevNet/TestNet,
  and the reachable-but-unavailable `ProductionSettlementProjectionSink`,
  `MainNetSettlementProjectionSink`, and `ExternalSettlementProjectionSink`). The
  fixture settlement-projection sink exposes an invocation counter so tests prove
  non-recording consumer paths and pre-settlement-projection rejected paths never
  invoke it;
* composition helpers
  (`project_consumer_outcome_to_settlement_projection_request`,
  `evaluate_durable_completion_consumer_settlement_projection`,
  `recover_durable_completion_consumer_settlement_projection_window`,
  `settlement_projection_outcome_authorizes_record`,
  `settlement_projection_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, **before**
   any finalizer invocation, **before** any attestor invocation, **before** any
   backend invocation, **before** any receipt sink invocation, **before** any
   acknowledgement sink invocation, **before** any consumer invocation, and
   **before** any settlement-projection invocation.
2. A disabled settlement-projection / consumer / acknowledgement / receipt /
   backend / attestation / finalization / reporter / sink / pipeline policy
   preserves the legacy no-settlement-projection bypass and never invokes the
   settlement-projection sink.
3. Only the Run 262 `AcknowledgementConsumed` consumer outcome creates a
   settlement-projection request; `AcknowledgementConsumerDuplicateIdempotent` may
   only match an already-recorded settlement-projection record; every other
   consumer outcome maps to a no-projection fail-closed outcome and never invokes
   the settlement-projection sink.
4. Pre-settlement-projection environment / chain / genesis / governance surface /
   mutation surface binding validation completes **before** the
   settlement-projection sink is invoked; a mismatch fails closed with no
   settlement-projection invocation.
5. The settlement-projection record happens **after** the Run 262
   consumer-consumed state; the projection-record-identity and request fields
   (including the full Run 262 consumer digest binding) must match exactly before
   any modeled settlement-projection record is recorded.
6. Only `SettlementProjectionRecorded` authorizes a **new** modeled
   consumer-settlement-projection state. A duplicate identical
   settlement-projection record is idempotent (no second record); the same
   settlement-projection record id with a different digest fails closed as
   equivocation.

### Grep-verifiable invariant helpers

* `durable_completion_settlement_projection_rejection_is_non_mutating`
* `durable_completion_settlement_projection_never_calls_run_070`
* `durable_completion_settlement_projection_never_mutates_live_pqc_trust_state`
* `durable_completion_settlement_projection_never_writes_sequence_or_marker`
* `durable_completion_settlement_projection_no_rocksdb_file_schema_migration_change`
* `durable_completion_settlement_projection_no_external_publication`
* `durable_completion_settlement_projection_no_real_audit_ledger`
* `durable_completion_settlement_projection_no_real_settlement`
* `durable_completion_settlement_projection_consumer_required`
* `durable_completion_settlement_projection_record_required_before_projected`
* `durable_completion_settlement_projection_failed_record_never_records`
* `durable_completion_settlement_projection_rollback_never_records`
* `durable_completion_settlement_projection_ambiguous_window_fails_closed`
* `durable_completion_settlement_projection_mainnet_peer_driven_apply_refused_first`
* `durable_completion_settlement_projection_production_mainnet_unavailable`
* `durable_completion_settlement_projection_external_unavailable`
* `durable_completion_settlement_projection_validator_set_rotation_unsupported`
* `durable_completion_settlement_projection_policy_change_unsupported`
* `durable_completion_settlement_projection_local_operator_cannot_satisfy_mainnet_authority`
* `durable_completion_settlement_projection_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_264_durable_completion_consumer_settlement_projection_tests.rs`
— 63 tests, all passing. Every recording test attaches the settlement projection to
the **actual** Run 262 `AcknowledgementConsumed` path, which in turn attaches to the
**actual** Run 260 `AcknowledgementRecorded` path, the **actual** Run 258
`AuditReceiptRecorded` path, and the **actual** Run 256 `BackendSubmissionRecorded`
path: the test harness drives a real `evaluate_durable_completion_attestation_backend`
round-trip, then a real `evaluate_durable_completion_audit_publication_receipt`
round-trip, then a real `evaluate_durable_completion_audit_receipt_acknowledgement`
round-trip, then a real `evaluate_durable_completion_acknowledgement_consumer`
round-trip, and binds the settlement-projection request to the real Run 256 backend
/ Run 258 receipt / Run 260 acknowledgement / Run 262 consumer identity / request /
response / record / transcript digests — never a faked, unattached
settlement-projection path. The matrix covers:

* **Accepted / compatible:** a disabled settlement-projection policy preserves the
  legacy no-projection bypass and never invokes the settlement-projection sink; a
  disabled consumer / acknowledgement / receipt / backend / attestation /
  finalization / reporter / sink / pipeline policy never reaches the
  settlement-projection sink; DevNet and TestNet fixture chains record exactly one
  modeled in-memory settlement-projection record only after the full Run 246
  pipeline → Run 248 sink receipt → Run 250 completion report → Run 252
  finalization → Run 254 attestation → Run 256 backend submission → Run 258 audit
  receipt → Run 260 acknowledgement → Run 262 consumer → Run 264
  settlement-projection chain; add-root / retire-root / revoke-root /
  emergency-revoke-root / noop modeled action variants preserve ordering and project
  only after Run 262 `AcknowledgementConsumed`; a duplicate identical
  settlement-projection record is idempotent with no second record; a Run 262
  duplicate-idempotent consumer outcome matches an already-recorded
  settlement-projection record only and never creates a new one by itself; the
  production settlement-projection, MainNet settlement-projection, and external
  settlement-projection paths are reachable but unavailable/fail-closed and record
  no settlement-projection state; MainNet peer-driven apply is refused before
  pipeline progression, before any sink, reporter, finalizer, attestor, backend,
  receipt, acknowledgement, consumer, or settlement-projection invocation;
  validator-set rotation and policy-change actions are unsupported and record no
  state.
* **Rejected / fail-closed:** every non-recording Run 262 consumer outcome produces
  no settlement-projection request, no settlement-projection record, and zero
  settlement-projection invocations; a settlement-projection record failure,
  rollback, rollback-failed, and ambiguous window all fail closed without recording
  a settlement-projection record; the same settlement-projection record id with a
  different digest is rejected as equivocation and records no second record; wrong
  environment / chain / genesis / governance surface / mutation surface are rejected
  before settlement-projection invocation (zero invocations); wrong
  settlement-projection identity / kind / policy / record id / request / response /
  record digest, wrong consumer / acknowledgement / receipt / backend / attestation
  / finalization / completion-report / sink / reporter / pipeline digest, wrong
  proposal id / decision id / candidate digest / authority-domain sequence, and a
  malformed settlement-projection request / response are rejected before record; the
  fixture settlement-projection sink rejects any non-DevNet/TestNet environment.
* **Recovery / crash-window:** before-pipeline through
  after-consumer-success-before-settlement-projection-request windows fail closed
  with no settlement projection; after-settlement-projection-request-before-record
  rejects before record; after-settlement-projection-record-before-success fails
  closed unless an explicit matching settlement-projection record exists;
  after-settlement-projection-success recovers as recorded only with an explicit
  matching record; ambiguous, record-failed, rollback-completed, rollback-failed,
  and unknown windows fail closed; production / MainNet / external
  settlement-projection recovery classification is unavailable; MainNet peer-driven
  apply refusal precedes recovery classification.
* **Projection / stage-ordering:** only the Run 262 `AcknowledgementConsumed`
  outcome creates a settlement-projection request intent;
  `AcknowledgementConsumerDuplicateIdempotent` projects to idempotent-only; every
  other consumer outcome projects to NoProjection; Run 246/248/250/252/254/256/258
  success alone, a Run 260 `AcknowledgementRecorded` alone, and a Run 262 consumer
  request alone create no settlement-projection request; only
  `SettlementProjectionRecorded` authorizes a new modeled settlement-projection
  record; a rejection before the settlement-projection stage leaves the
  settlement-projection invocation count at zero; one valid settlement-projection
  record inserts exactly one ledger record; the ledger snapshot/restore models a
  rollback with no drift; the grep-verifiable invariant helpers all assert their
  fail-closed contract.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_264_durable_completion_consumer_settlement_projection_tests`
  — `63 passed; 0 failed`.
* `cargo test -p qbind-node --test run_262_durable_completion_acknowledgement_consumer_tests`
  — `57 passed; 0 failed`.
* `cargo test -p qbind-node --test run_260_durable_completion_audit_receipt_acknowledgement_tests`
  — `57 passed; 0 failed`.
* `cargo test -p qbind-node --test run_258_durable_completion_audit_publication_receipt_tests`
  — `57 passed; 0 failed`.
* `cargo test -p qbind-node --test run_256_durable_completion_attestation_backend_tests`
  — `46 passed; 0 failed`.
* `cargo test -p qbind-node --test run_254_modeled_durable_completion_attestation_projection_tests`
  — `108 passed; 0 failed`.
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

> Note: as observed in Runs 260 and 262, the task brief lists the Run 232
> regression target as `run_232_governance_evaluator_replay_state_tests`; the actual
> target in the crate is `run_232_governance_evaluator_replay_runtime_integration_tests`
> (a naming collision with `run_230_governance_evaluator_replay_state_tests`). Both
> were run and both PASS.

## Security invariants preserved

* Run 246 pipeline success is required before any sink intent can exist, and
  therefore before any settlement projection.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent
  can exist, and therefore before any settlement projection.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can
  exist, and therefore before any settlement projection.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can
  exist, and therefore before any settlement projection.
* Run 254 `DurableCompletionAttested` is required before any backend request can
  exist, and therefore before any settlement projection.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication
  receipt request can exist, and therefore before any settlement projection.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement request can
  exist, and therefore before any settlement projection.
* Run 260 `AcknowledgementRecorded` is required before any consumer request can
  exist, and therefore before any settlement projection.
* Run 262 `AcknowledgementConsumed` is required before any settlement-projection
  request can exist; only that consumer outcome creates a settlement-projection
  request.
* Only `SettlementProjectionRecorded` authorizes a new modeled
  consumer-settlement-projection state.
* Every non-recorded consumer outcome produces no settlement-projection request and
  no settlement-projection record.
* A failed settlement-projection record, rollback, rollback-failed, ambiguous
  window, unavailable production/MainNet/external settlement-projection path,
  rejected replay state, and unsupported action never record.
* A settlement-projection record failure, rollback, rollback failure, or ambiguous
  settlement-projection window never retroactively claims a durable
  settlement-projection state.
* A duplicate identical settlement-projection record is idempotent (no second
  record); the same settlement-projection record id with a different digest fails
  closed as equivocation; a duplicate-idempotent consumer outcome never creates a
  new settlement-projection record by itself.
* Rejected settlement-projection paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no live trust swap, no session eviction, no sequence
  write, no marker write, no external publication, no real audit-ledger write, no
  real settlement write, and no settlement-projection invocation where the rejection
  happens before the settlement-projection stage.
* MainNet peer-driven apply is refused before pipeline progression, before any sink,
  reporter, finalizer, attestor, backend, receipt, acknowledgement, consumer, or
  settlement-projection invocation.
* The local operator and peer majority cannot satisfy MainNet authority.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture settlement-projection sink mutates only modeled in-memory
  consumer-settlement-projection state; no RocksDB / file / schema / migration /
  storage-format change; no wire / marker / sequence / trust-bundle change.

## Honest limitations

* Run 264 is source/test only and introduces a settlement-projection interface
  boundary over a modeled in-memory ledger, not a real production settlement,
  audit-ledger acknowledgement, or external-publication confirmation backend. No
  production mutating behavior is enabled.
* The fixture settlement-projection sink records only modeled in-memory
  consumer-settlement-projection state; it performs no real settlement write, no
  real audit-ledger write, no real external-publication confirmation, and no real
  external publication, and the production settlement-projection / MainNet
  settlement-projection / external settlement-projection sinks are deliberately
  reachable-but-unavailable.
* The Run 264 module carries the Run 246/248/250/252/254/256/258/260 bindings plus a
  `consumer_binding` (Run 262); the settlement-projection gate is driven by the Run
  262 `consumer_binding` projection (plus the MainNet peer-driven refusal and policy
  pre-checks). The earlier bindings are retained for the MainNet peer-driven
  composition and digest binding rather than as the primary settlement-projection
  gate.
* No real settlement backend, audit-ledger acknowledgement backend, external
  publication confirmation backend, external publication backend, production
  attestation backend, finalization backend, completion-report backend, durable
  consume backend, persistent replay backend, production mutation engine, governance
  execution engine, on-chain governance proof verifier, or KMS/HSM/RemoteSigner
  backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 264 closes the source/test
durable-completion consumer settlement-projection sink interface gap only and does
**not** claim full C4 or C5 closure.

## Suggested Run 265 next step

Release-binary evidence for the Run 264 durable-completion consumer
settlement-projection sink boundary (mirroring the Run 241 / 243 / 245 / 247 / 249 /
251 / 253 / 255 / 257 / 259 / 261 / 263 pattern): build the release binary, exercise
the Run 246 pipeline → Run 248 consume-sink projection → Run 250 completion-report
projection → Run 252 finalization projection → Run 254 attestation projection → Run
256 backend submission → Run 258 audit receipt → Run 260 acknowledgement → Run 262
consumer → Run 264 settlement-projection chain on the real
`target/release/qbind-node` plus a release-built helper, and prove the Run 264
settlement-projection symbols are present and exercised in release mode while
remaining dead code from the production runtime.