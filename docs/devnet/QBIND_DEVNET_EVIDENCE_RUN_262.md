# QBIND DevNet evidence — Run 262

**Title.** Source/test durable-completion **acknowledgement consumer /
post-acknowledgement settlement interface boundary**.

**Status.** PASS (source/test only). Run 262 extends the Run 260 modeled
durable-completion audit-receipt acknowledgement / external-publication
confirmation boundary with a typed, mockable, in-memory **acknowledgement consumer
/ post-acknowledgement settlement interface boundary** that models the first
post-Run-260 acknowledgement-consumer interface a future production settlement or
downstream durable-completion subsystem would use **after** the Run 260
`AcknowledgementRecorded` outcome has been recorded. Run 260 proved that a modeled
acknowledgement is recorded only after the Run 258 `AuditReceiptRecorded` outcome.
What was still missing was a typed source/test boundary that models the
after-acknowledgement-only consumer / settlement step (the interface a production
settlement or downstream durable-completion call site would implement). Run 262
closes that source/test consumer interface gap only.

Run 262 introduces a **consumer interface boundary**, **not** a replacement for any
existing module. It consumes the typed Run 260 acknowledgement outcome
(`DurableCompletionAuditReceiptAcknowledgementOutcome`) as an
`acknowledgement_binding` and projects it onto a consumer request intent; only the
Run 260 `AcknowledgementRecorded` outcome creates a consumer request, and a Run 260
`AcknowledgementDuplicateIdempotent` may only match an already-recorded consumer
record and never creates a new one. The consumer layer is a **model only**. It
implements **no** real settlement, **no** real audit-ledger acknowledgement, **no**
real external-publication confirmation, **no** real external publication, **no**
real production attestation backend, **no** real finalization backend, **no** real
completion-report backend, **no** real durable consume backend, **no** real
persistent replay backend, **no** real governance execution engine, **no** real
production mutation engine, **no** real on-chain governance proof verifier, **no**
RocksDB backend, **no** file format, **no** schema, **no** database migration,
**no** storage-format change, **no** KMS/HSM backend, **no** RemoteSigner backend,
**no** MainNet governance enablement, **no** MainNet peer-driven apply enablement,
and **no** validator-set rotation. It changes **no** wire, schema, marker,
sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 262 adds a durable-completion acknowledgement consumer / post-acknowledgement
  settlement interface boundary.
* The boundary models the first post-Run-260 acknowledgement consumer interface a
  future production settlement or downstream durable-completion subsystem might use.
* The fixture consumer is DevNet/TestNet evidence-only and in-memory only.
* Production settlement, MainNet settlement, and external settlement consumers are
  reachable but unavailable/fail-closed.
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
* The fixture consumer mutates only modeled in-memory
  acknowledgement-consumer state.
* Rejected consumer paths are non-mutating.
* Run 262 does not weaken any prior run (Runs 070, 130–261) and does not claim full
  C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_acknowledgement_consumer.rs`

Run 262 adds a source module (registered in `lib.rs`) that defines:

* typed consumer inputs / policy / identity / bindings
  (`DurableCompletionAcknowledgementConsumerInput`,
  `DurableCompletionAcknowledgementConsumerPolicy`,
  `DurableCompletionAcknowledgementConsumerKind`,
  `DurableCompletionAcknowledgementConsumerIdentity`,
  `DurableCompletionAcknowledgementConsumerExpectations`,
  `DurableCompletionAcknowledgementConsumerRequest`,
  `DurableCompletionAcknowledgementConsumerResponse`,
  `DurableCompletionAcknowledgementConsumerRecord`) plus the Run 260 acknowledgement
  outcome (`DurableCompletionAuditReceiptAcknowledgementOutcome`) carried as the
  `acknowledgement_binding`, and the Run 246/248/250/252/254/256/258 bindings
  carried for the MainNet peer-driven composition;
* modeled in-memory acknowledgement-consumer state
  (`DurableCompletionAcknowledgementConsumerLedger`,
  `DurableCompletionAcknowledgementConsumerLedgerRecord`,
  `DurableCompletionAcknowledgementConsumerLedgerSnapshot`,
  `DurableCompletionAcknowledgementConsumerLedgerStatus`,
  `DurableCompletionAcknowledgementConsumerDigest`,
  `DurableCompletionAcknowledgementConsumerTranscriptDigest`) — in-memory only;
  never touches RocksDB, files, markers, sequence files, external publications,
  confirmations, audit-ledger entries, settlement records, or any production
  durable state. The consumer digests bind, via domain-separated SHA3-256 over
  length-prefixed fields, the consumer identity, request, response, record, and
  transcript, including the full Run 260 acknowledgement identity / request /
  response / record / transcript digest binding;
* an explicit consumer outcome enum
  (`DurableCompletionAcknowledgementConsumerOutcome`) whose only **new**-record
  authorizing variant is `AcknowledgementConsumed`, including
  `LegacyBypassNoConsumer`,
  `RejectedBeforeAcknowledgementNoConsumer`,
  `AcknowledgementDidNotRecordNoConsumer`,
  `AcknowledgementConsumerDuplicateIdempotent`,
  `AcknowledgementConsumerRejectedBeforeRecord`,
  `AcknowledgementConsumerRecordFailedNoConsumer`,
  `AcknowledgementConsumerRolledBackNoConsumer`,
  `AcknowledgementConsumerRollbackFailedFatalNoConsumer`,
  `AcknowledgementConsumerAmbiguousFailClosedNoConsumer`,
  `ProductionSettlementUnavailableNoConsumer`,
  `MainNetSettlementUnavailableNoConsumer`,
  `ExternalSettlementUnavailableNoConsumer`,
  `MainNetPeerDrivenApplyRefusedNoConsumer`,
  `ValidatorSetRotationUnsupportedNoConsumer`, and
  `PolicyChangeUnsupportedNoConsumer`;
* a pure/mockable consumer trait
  (`GovernanceDurableCompletionAcknowledgementConsumer`) with
  `consume_durable_completion_acknowledgement` and
  `recover_durable_completion_acknowledgement_consumer_window`, plus
  source/test-only implementations
  (`FixtureDurableCompletionAcknowledgementConsumer` for DevNet/TestNet, and the
  reachable-but-unavailable `ProductionDurableCompletionSettlementConsumer`,
  `MainNetDurableCompletionSettlementConsumer`, and
  `ExternalDurableCompletionSettlementConsumer`). The fixture consumer exposes
  an invocation counter so tests prove non-recording acknowledgement paths and
  pre-acknowledgement rejected paths never invoke it;
* composition helpers
  (`project_acknowledgement_outcome_to_consumer_request`,
  `evaluate_durable_completion_acknowledgement_consumer`,
  `recover_durable_completion_acknowledgement_consumer_window`,
  `acknowledgement_consumer_outcome_authorizes_consumer_record`,
  `acknowledgement_consumer_outcome_projects_to_consumed`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, **before**
   any finalizer invocation, **before** any attestor invocation, **before** any
   backend invocation, **before** any receipt sink invocation, **before** any
   acknowledgement sink invocation, and **before** any consumer invocation.
2. A disabled consumer / acknowledgement / receipt / backend / attestation /
   finalization / reporter / sink / pipeline policy preserves the legacy
   no-consumer bypass and never invokes the consumer.
3. Only the Run 260 `AcknowledgementRecorded` acknowledgement outcome creates a
   consumer request; `AcknowledgementDuplicateIdempotent` may only match an
   already-recorded consumer record; every other acknowledgement outcome maps to a
   no-consumer fail-closed outcome and never invokes the consumer.
4. Pre-consumer environment / chain / genesis / governance surface / mutation
   surface binding validation completes **before** the consumer is invoked; a
   mismatch fails closed with no consumer invocation.
5. The consumer record happens **after** the Run 260 acknowledgement-recorded
   state; the consumer-record-identity and request fields (including the full Run
   260 acknowledgement digest binding) must match exactly before any modeled
   consumer record is recorded.
6. Only `AcknowledgementConsumed` authorizes a **new** modeled
   acknowledgement-consumer state. A duplicate identical consumer record is
   idempotent (no second record); the same consumer record id with a different
   digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `durable_completion_ack_consumer_rejection_is_non_mutating`
* `durable_completion_ack_consumer_never_calls_run_070`
* `durable_completion_ack_consumer_never_mutates_live_pqc_trust_state`
* `durable_completion_ack_consumer_never_writes_sequence_or_marker`
* `durable_completion_ack_consumer_no_rocksdb_file_schema_migration_change`
* `durable_completion_ack_consumer_no_external_publication`
* `durable_completion_ack_consumer_no_real_audit_ledger`
* `durable_completion_ack_consumer_no_real_settlement`
* `durable_completion_ack_consumer_pipeline_success_required`
* `durable_completion_ack_consumer_sink_receipt_required`
* `durable_completion_ack_consumer_completion_report_required`
* `durable_completion_ack_consumer_finalization_required`
* `durable_completion_ack_consumer_attestation_required`
* `durable_completion_ack_consumer_backend_submission_required`
* `durable_completion_ack_consumer_receipt_required`
* `durable_completion_ack_consumer_acknowledgement_required`
* `durable_completion_ack_consumer_record_required_before_consume`
* `durable_completion_ack_consumer_failed_record_never_records`
* `durable_completion_ack_consumer_rollback_never_records`
* `durable_completion_ack_consumer_ambiguous_window_fails_closed`
* `durable_completion_ack_consumer_mainnet_peer_driven_apply_refused_first`
* `durable_completion_ack_consumer_production_mainnet_unavailable`
* `durable_completion_ack_consumer_external_settlement_unavailable`
* `durable_completion_ack_consumer_validator_set_rotation_unsupported`
* `durable_completion_ack_consumer_policy_change_unsupported`
* `durable_completion_ack_consumer_local_operator_cannot_satisfy_mainnet_authority`
* `durable_completion_ack_consumer_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_262_durable_completion_acknowledgement_consumer_tests.rs`
— 57 tests, all passing. Every recording test attaches the consumer to the
**actual** Run 260 `AcknowledgementRecorded` path, which in turn attaches to the
**actual** Run 258 `AuditReceiptRecorded` path and the **actual** Run 256
`BackendSubmissionRecorded` path: the test harness drives a real
`evaluate_durable_completion_attestation_backend` round-trip, then a real
`evaluate_durable_completion_audit_publication_receipt` round-trip, then a real
`evaluate_durable_completion_audit_receipt_acknowledgement` round-trip, and binds
the consumer request to the real Run 256 backend / Run 258 receipt / Run 260
acknowledgement identity / request / response / record / transcript digests — never
a faked, unattached consumer path. The matrix covers:

* **Accepted / compatible:** a disabled consumer policy preserves the legacy
  no-consumer bypass and never invokes the consumer; a disabled acknowledgement /
  receipt / backend policy never reaches the consumer; DevNet and TestNet fixture
  chains record exactly one modeled in-memory consumer record only after the full
  Run 246 pipeline → Run 248 sink receipt → Run 250 completion report → Run 252
  finalization → Run 254 attestation → Run 256 backend submission → Run 258 audit
  receipt → Run 260 acknowledgement → Run 262 consumer chain; add-root /
  retire-root / revoke-root / emergency-revoke-root / noop modeled action variants
  preserve ordering and consume only after acknowledgement recorded; a duplicate
  identical consumer record is idempotent with no second record; a Run 260
  duplicate-idempotent acknowledgement matches an already-recorded consumer record
  only and never creates a new one by itself; the production settlement, MainNet
  settlement, and external settlement paths are reachable but
  unavailable/fail-closed and record no consumer state; MainNet peer-driven apply
  is refused before pipeline progression, before any sink, reporter, finalizer,
  attestor, backend, receipt, acknowledgement, or consumer invocation.
* **Rejected / fail-closed:** every non-recording Run 260 acknowledgement outcome
  produces no consumer request, no consumer record, and zero consumer invocations;
  a consumer record failure, rollback, rollback-failed, and ambiguous window all
  fail closed without recording a consumer record; the same consumer record id with
  a different digest is rejected as equivocation and records no second record;
  wrong environment / chain / genesis / governance surface / mutation surface are
  rejected before consumer invocation (zero invocations); wrong consumer identity /
  kind / policy / record id / request / response / record digest, wrong
  acknowledgement / receipt / backend / attestation / finalization / completion-
  report / sink / reporter / pipeline digest, wrong proposal id / decision id /
  candidate digest / authority-domain sequence, and a malformed consumer request /
  response are rejected before record; the fixture consumer rejects any
  non-DevNet/TestNet environment.
* **Recovery / crash-window:** before-pipeline through
  after-acknowledgement-success-before-consumer-request windows fail closed with no
  consumer; after-consumer-request-before-consumer-record rejects before record;
  after-consumer-record-before-consumer-success fails closed unless an explicit
  matching consumer record exists; after-consumer-success recovers as consumed only
  with an explicit matching record; ambiguous, record-failed, rollback-completed,
  rollback-failed, and unknown windows fail closed; production / MainNet / external
  settlement recovery classification is unavailable; MainNet peer-driven apply
  refusal precedes recovery classification.
* **Projection / stage-ordering:** only the Run 260 `AcknowledgementRecorded`
  outcome creates a consumer request intent; `AcknowledgementDuplicateIdempotent`
  projects to idempotent-only; every other acknowledgement outcome projects to
  NoConsumer; Run 246/248/250/252/254/256/258 success alone and a Run 260
  acknowledgement request alone create no consumer request; only
  `AcknowledgementConsumed` authorizes a new modeled consumer record; a rejection
  before the consumer stage leaves the consumer invocation count at zero; one valid
  consumer record inserts exactly one ledger record; the ledger snapshot/restore
  models a rollback with no drift; the grep-verifiable invariant helpers all assert
  their fail-closed contract.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
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
* `cargo test -p qbind-node --lib` — PASS.

> Note: as observed in Run 260, the task brief lists the Run 232 regression target
> as `run_232_governance_evaluator_replay_state_tests`; the actual target in the
> crate is `run_232_governance_evaluator_replay_runtime_integration_tests` (a naming
> collision with `run_230_governance_evaluator_replay_state_tests`). Both were run
> and both PASS.

## Security invariants preserved

* Run 246 pipeline success is required before any sink intent can exist, and
  therefore before any consumer.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent
  can exist, and therefore before any consumer.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can
  exist, and therefore before any consumer.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can
  exist, and therefore before any consumer.
* Run 254 `DurableCompletionAttested` is required before any backend request can
  exist, and therefore before any consumer.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication
  receipt request can exist, and therefore before any consumer.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement /
  confirmation request can exist, and therefore before any consumer.
* Run 260 `AcknowledgementRecorded` is required before any consumer / settlement
  request can exist; only that acknowledgement outcome creates a consumer request.
* Only `AcknowledgementConsumed` authorizes a new modeled
  acknowledgement-consumer state.
* Every non-recorded acknowledgement outcome produces no consumer request and no
  consumer record.
* A failed consumer record, rollback, rollback-failed, ambiguous window, unavailable
  production/MainNet/external settlement path, rejected replay state, and
  unsupported action never record.
* A consumer record failure, rollback, rollback failure, or ambiguous consumer
  window never retroactively claims a durable consumer state.
* A duplicate identical consumer record is idempotent (no second record); the same
  consumer record id with a different digest fails closed as equivocation; a
  duplicate-idempotent acknowledgement never creates a new consumer record by
  itself.
* Rejected consumer paths are non-mutating: no Run 070 call, no `LivePqcTrustState`
  mutation, no live trust swap, no session eviction, no sequence write, no marker
  write, no external publication, no real audit-ledger write, no real settlement
  write, and no consumer invocation where the rejection happens before the consumer
  stage.
* MainNet peer-driven apply is refused before pipeline progression, before any sink,
  reporter, finalizer, attestor, backend, receipt, acknowledgement, or consumer
  invocation.
* The local operator and peer majority cannot satisfy MainNet authority.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture consumer mutates only modeled in-memory acknowledgement-consumer
  state; no RocksDB / file / schema / migration / storage-format change; no wire /
  marker / sequence / trust-bundle change.

## Honest limitations

* Run 262 is source/test only and introduces a consumer interface boundary over a
  modeled in-memory ledger, not a real production settlement, audit-ledger
  acknowledgement, or external-publication confirmation backend. No production
  mutating behavior is enabled.
* The fixture consumer records only modeled in-memory acknowledgement-consumer
  state; it performs no real settlement write, no real audit-ledger write, no real
  external-publication confirmation, and no real external publication, and the
  production settlement / MainNet settlement / external settlement consumers are
  deliberately reachable-but-unavailable.
* The Run 262 module carries the Run 246/248/250/252/254/256/258 bindings plus an
  `acknowledgement_binding` (Run 260); the consumer gate is driven by the Run 260
  `acknowledgement_binding` projection (plus the MainNet peer-driven refusal and
  policy pre-checks). The earlier bindings are retained for the MainNet peer-driven
  composition and digest binding rather than as the primary consumer gate.
* No real settlement backend, audit-ledger acknowledgement backend, external
  publication confirmation backend, external publication backend, production
  attestation backend, finalization backend, completion-report backend, durable
  consume backend, persistent replay backend, production mutation engine,
  governance execution engine, on-chain governance proof verifier, or
  KMS/HSM/RemoteSigner backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 262 closes the source/test
durable-completion acknowledgement consumer / post-acknowledgement settlement
interface gap only and does **not** claim full C4 or C5 closure.

## Suggested Run 263 next step

Release-binary evidence for the Run 262 durable-completion acknowledgement consumer
/ post-acknowledgement settlement interface boundary (mirroring the Run 241 / 243 /
245 / 247 / 249 / 251 / 253 / 255 / 257 / 259 / 261 pattern): build the release
binary, exercise the Run 246 pipeline → Run 248 consume-sink projection → Run 250
completion-report projection → Run 252 finalization projection → Run 254 attestation
projection → Run 256 backend submission → Run 258 audit receipt → Run 260
acknowledgement → Run 262 fixture consumer path through the source/test fixtures,
and capture grep-verifiable evidence that a modeled consumer record is recorded only
after a Run 260 acknowledgement-recorded record, that every non-recording /
record-failure / rollback / ambiguous / equivocation / unavailable path remains
non-mutating and records no consumer state, and that production/MainNet/external
settlement paths and MainNet peer-driven apply remain refused/unavailable.
