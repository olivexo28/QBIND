# QBIND DevNet evidence — Run 260

**Title.** Source/test durable-completion **audit-receipt acknowledgement /
external-publication confirmation boundary**.

**Status.** PASS (source/test only). Run 260 extends the Run 258 modeled
durable-completion audit-ledger / external-publication receipt boundary with a
typed, mockable, in-memory **audit-receipt acknowledgement / external-publication
confirmation boundary** that models the first post-Run-258 receipt-consumer
acknowledgement interface a future production audit ledger or external publication
system would use **after** the Run 258 `AuditReceiptRecorded` outcome has been
recorded. Run 258 proved that a modeled audit/publication receipt is recorded only
after the Run 256 `BackendSubmissionRecorded` outcome. What was still missing was a
typed source/test boundary that models the after-audit-receipt-only acknowledgement
/ confirmation step (the interface a production audit ledger acknowledgement or
external publication confirmation call site would implement). Run 260 closes that
source/test acknowledgement interface gap only.

Run 260 introduces an **acknowledgement interface boundary**, **not** a replacement
for any existing module. It consumes the typed Run 258 receipt outcome
(`DurableCompletionAuditPublicationReceiptOutcome`) as a `receipt_binding` and
projects it onto an acknowledgement request intent; only the Run 258
`AuditReceiptRecorded` outcome creates an acknowledgement request, and a Run 258
`AuditReceiptDuplicateIdempotent` may only match an already-recorded acknowledgement
and never creates a new one. The acknowledgement layer is a **model only**. It
implements **no** real audit ledger acknowledgement, **no** real external
publication confirmation, **no** real external publication, **no** real production
attestation backend, **no** real finalization backend, **no** real completion-report
backend, **no** real durable consume backend, **no** real persistent replay backend,
**no** real governance execution engine, **no** real production mutation engine,
**no** real on-chain governance proof verifier, **no** RocksDB backend, **no** file
format, **no** schema, **no** database migration, **no** storage-format change,
**no** KMS/HSM backend, **no** RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 260 adds a durable-completion audit-receipt acknowledgement /
  external-publication confirmation boundary.
* The boundary models the first post-Run-258 receipt-consumer acknowledgement
  interface a future production audit ledger or external publication system would
  use.
* The fixture acknowledgement sink is DevNet/TestNet evidence-only and in-memory
  only.
* Production audit-ledger acknowledgement, MainNet audit-ledger acknowledgement, and
  external-publication confirmation sinks are reachable but unavailable/fail-closed.
* It does **not** implement a real audit ledger acknowledgement.
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
* The fixture acknowledgement sink mutates only modeled in-memory
  audit-receipt-acknowledgement state.
* Rejected acknowledgement paths are non-mutating.
* Run 260 does not weaken any prior run (Runs 070, 130–259) and does not claim full
  C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs`

Run 260 adds a source module (registered in `lib.rs`) that defines:

* typed acknowledgement inputs / policy / identity / bindings
  (`DurableCompletionAuditReceiptAcknowledgementInput`,
  `DurableCompletionAuditReceiptAcknowledgementPolicy`,
  `DurableCompletionAuditReceiptAcknowledgementKind`,
  `DurableCompletionAuditReceiptAcknowledgementIdentity`,
  `DurableCompletionAuditReceiptAcknowledgementExpectations`,
  `DurableCompletionAuditReceiptAcknowledgementRequest`,
  `DurableCompletionAuditReceiptAcknowledgementResponse`,
  `DurableCompletionAuditReceiptAcknowledgementRecord`) plus the Run 258 receipt
  outcome (`DurableCompletionAuditPublicationReceiptOutcome`) carried as the
  `receipt_binding`, the Run 256 backend outcome carried as the `backend_binding`,
  and the Run 246/248/250/252/254 bindings carried for the MainNet peer-driven
  composition;
* modeled in-memory audit-receipt-acknowledgement state
  (`DurableCompletionAuditReceiptAcknowledgementLedger`,
  `DurableCompletionAuditReceiptAcknowledgementLedgerRecord`,
  `DurableCompletionAuditReceiptAcknowledgementDigest`,
  `DurableCompletionAuditReceiptAcknowledgementTranscriptDigest`) — in-memory only;
  never touches RocksDB, files, markers, sequence files, external publications,
  confirmations, audit-ledger entries, or any production durable state. The
  acknowledgement digests bind, via domain-separated SHA3-256 over length-prefixed
  fields, the acknowledgement identity, request, response, record, and transcript,
  including the full Run 256 backend and Run 258 receipt identity / request /
  response / record / transcript digest binding;
* an explicit acknowledgement outcome enum
  (`DurableCompletionAuditReceiptAcknowledgementOutcome`) whose only **new**-record
  authorizing variant is `AcknowledgementRecorded`, including
  `LegacyBypassNoAcknowledgement`,
  `RejectedBeforeAuditReceiptNoAcknowledgement`,
  `AuditReceiptDidNotRecordNoAcknowledgement`,
  `AcknowledgementDuplicateIdempotent`, `AcknowledgementRejectedBeforeRecord`,
  `AcknowledgementRecordFailedNoAcknowledgement`,
  `AcknowledgementRolledBackNoAcknowledgement`,
  `AcknowledgementRollbackFailedFatalNoAcknowledgement`,
  `AcknowledgementAmbiguousFailClosedNoAcknowledgement`,
  `ProductionAuditLedgerAckUnavailableNoAcknowledgement`,
  `MainNetAuditLedgerAckUnavailableNoAcknowledgement`,
  `ExternalPublicationConfirmationUnavailableNoAcknowledgement`,
  `MainNetPeerDrivenApplyRefusedNoAcknowledgement`,
  `ValidatorSetRotationUnsupportedNoAcknowledgement`, and
  `PolicyChangeUnsupportedNoAcknowledgement`;
* a pure/mockable acknowledgement trait
  (`GovernanceDurableCompletionAuditReceiptAcknowledgementSink`) with
  `record_durable_completion_audit_receipt_acknowledgement`, plus source/test-only
  implementations (`FixtureDurableCompletionAuditReceiptAcknowledgementSink` for
  DevNet/TestNet, and the reachable-but-unavailable
  `ProductionAuditLedgerDurableCompletionAcknowledgementSink`,
  `MainNetAuditLedgerDurableCompletionAcknowledgementSink`, and
  `ExternalPublicationDurableCompletionConfirmationSink`). The fixture sink exposes
  an invocation counter so tests prove non-recording receipt paths and pre-receipt
  rejected paths never invoke it;
* composition helpers
  (`project_audit_receipt_outcome_to_acknowledgement_request`,
  `evaluate_durable_completion_audit_receipt_acknowledgement`,
  `recover_durable_completion_audit_receipt_acknowledgement_window`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, **before**
   any finalizer invocation, **before** any attestor invocation, **before** any
   backend invocation, **before** any receipt sink invocation, and **before** any
   acknowledgement sink invocation.
2. A disabled acknowledgement / receipt / backend / attestation / finalization /
   reporter / sink / pipeline policy preserves the legacy no-acknowledgement bypass
   and never invokes the acknowledgement sink.
3. Only the Run 258 `AuditReceiptRecorded` receipt outcome creates an
   acknowledgement request; `AuditReceiptDuplicateIdempotent` may only match an
   already-recorded acknowledgement; every other receipt outcome maps to a
   no-acknowledgement fail-closed outcome and never invokes the acknowledgement
   sink.
4. Pre-acknowledgement environment / chain / genesis / governance surface /
   mutation surface binding validation completes **before** the acknowledgement sink
   is invoked; a mismatch fails closed with no acknowledgement sink invocation.
5. The acknowledgement record happens **after** the Run 258 audit-receipt-recorded
   state; the acknowledgement-record-identity and request fields (including the full
   Run 256 backend and Run 258 receipt digest binding) must match exactly before any
   modeled acknowledgement is recorded.
6. Only `AcknowledgementRecorded` authorizes a **new** modeled
   audit-receipt-acknowledgement state. A duplicate identical acknowledgement is
   idempotent (no second acknowledgement); the same acknowledgement record id with a
   different digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `durable_completion_audit_ack_rejection_is_non_mutating`
* `durable_completion_audit_ack_never_calls_run_070`
* `durable_completion_audit_ack_never_mutates_live_pqc_trust_state`
* `durable_completion_audit_ack_never_writes_sequence_or_marker`
* `durable_completion_audit_ack_no_rocksdb_file_schema_migration_change`
* `durable_completion_audit_ack_no_external_publication`
* `durable_completion_audit_ack_no_real_audit_ledger`
* `durable_completion_audit_ack_pipeline_success_required`
* `durable_completion_audit_ack_sink_receipt_required`
* `durable_completion_audit_ack_completion_report_required`
* `durable_completion_audit_ack_finalization_required`
* `durable_completion_audit_ack_attestation_required`
* `durable_completion_audit_ack_backend_submission_required`
* `durable_completion_audit_ack_receipt_required`
* `durable_completion_audit_ack_record_required_before_ack`
* `durable_completion_audit_ack_failed_record_never_records`
* `durable_completion_audit_ack_rollback_never_records`
* `durable_completion_audit_ack_ambiguous_window_fails_closed`
* `durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first`
* `durable_completion_audit_ack_production_mainnet_unavailable`
* `durable_completion_audit_ack_external_confirmation_unavailable`
* `durable_completion_audit_ack_validator_set_rotation_unsupported`
* `durable_completion_audit_ack_policy_change_unsupported`
* `durable_completion_audit_ack_local_operator_cannot_satisfy_mainnet_authority`
* `durable_completion_audit_ack_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_260_durable_completion_audit_receipt_acknowledgement_tests.rs`
— 57 tests, all passing. Every recording test attaches the acknowledgement to the
**actual** Run 258 `AuditReceiptRecorded` path, which in turn attaches to the
**actual** Run 256 `BackendSubmissionRecorded` path: the test harness drives a real
`evaluate_durable_completion_attestation_backend` round-trip, then a real
`evaluate_durable_completion_audit_publication_receipt` round-trip, and binds the
acknowledgement request to the real Run 256 backend and Run 258 receipt identity /
request / response / record / transcript digests — never a faked, unattached
acknowledgement path. The matrix covers:

* **Accepted / compatible:** a disabled acknowledgement policy preserves the legacy
  no-acknowledgement bypass and never invokes the acknowledgement sink; a disabled
  receipt / backend policy never reaches the acknowledgement sink; DevNet and
  TestNet fixture chains record exactly one modeled in-memory acknowledgement only
  after the full Run 246 pipeline → Run 248 sink receipt → Run 250 completion report
  → Run 252 finalization → Run 254 attestation → Run 256 backend submission → Run
  258 audit receipt → Run 260 acknowledgement chain; add-root / retire-root /
  revoke-root / emergency-revoke-root / noop modeled action variants preserve
  ordering and acknowledge only after audit receipt recorded; a duplicate identical
  acknowledgement is idempotent with no second acknowledgement; a Run 258
  duplicate-idempotent audit receipt matches an already-recorded acknowledgement only
  and never creates a new one by itself; the production audit-ledger acknowledgement,
  MainNet audit-ledger acknowledgement, and external-publication confirmation paths
  are reachable but unavailable/fail-closed and record no acknowledgement; MainNet
  peer-driven apply is refused before pipeline progression, before any sink,
  reporter, finalizer, attestor, backend, receipt, or acknowledgement sink
  invocation.
* **Rejected / fail-closed:** every non-recording Run 258 receipt outcome produces
  no acknowledgement request, no acknowledgement, and zero acknowledgement sink
  invocations; an acknowledgement record failure, rollback, rollback-failed, and
  ambiguous window all fail closed without recording an acknowledgement; the same
  acknowledgement record id with a different digest is rejected as equivocation and
  records no second acknowledgement; wrong environment / chain / genesis /
  governance surface / mutation surface are rejected before acknowledgement sink
  invocation (zero invocations); wrong acknowledgement identity / kind / policy /
  record id / proposal id / decision id / candidate digest / authority-domain
  sequence / pipeline / sink / reporter / finalization / attestation digest /
  attestation id / backend identity / request / response / receipt / transcript
  digest / receipt identity / request / response / record / transcript digest and a
  malformed acknowledgement request are rejected before record; the fixture
  acknowledgement sink rejects any non-DevNet/TestNet environment.
* **Recovery / crash-window:** before-pipeline through
  after-receipt-success-before-acknowledgement-request windows fail closed with no
  acknowledgement; after-acknowledgement-request-before-acknowledgement-record
  rejects before record; after-acknowledgement-record-before-acknowledgement-success
  fails closed unless an explicit matching acknowledgement record exists;
  after-acknowledgement-success recovers as acknowledgement recorded only with an
  explicit matching record; ambiguous, record-failed, rollback-completed,
  rollback-failed, and unknown windows fail closed; production / MainNet
  audit-ledger acknowledgement / external-publication confirmation recovery
  classification is unavailable; MainNet peer-driven apply refusal precedes recovery
  classification.
* **Projection / stage-ordering:** only the Run 258 `AuditReceiptRecorded` outcome
  creates an acknowledgement request intent; `AuditReceiptDuplicateIdempotent`
  projects to idempotent-only; every other receipt outcome projects to
  NoAcknowledgement; Run 246/248/250/252/254/256 success alone and a Run 258 receipt
  request alone create no acknowledgement request; only `AcknowledgementRecorded`
  authorizes a new modeled acknowledgement; a rejection before the acknowledgement
  stage leaves the acknowledgement sink invocation count at zero; one valid
  acknowledgement inserts exactly one ledger record; the ledger snapshot/restore
  models a rollback with no drift; the grep-verifiable invariant helpers all assert
  their fail-closed contract.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
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

> Note: the Run 260 task brief listed the Run 232 regression target as
> `run_232_governance_evaluator_replay_state_tests`; the actual target in the crate
> is `run_232_governance_evaluator_replay_runtime_integration_tests` (a naming
> collision with `run_230_governance_evaluator_replay_state_tests`). Both were run
> and both PASS.

## Security invariants preserved

* Run 246 pipeline success is required before any sink intent can exist, and
  therefore before any acknowledgement.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent
  can exist, and therefore before any acknowledgement.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can
  exist, and therefore before any acknowledgement.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can
  exist, and therefore before any acknowledgement.
* Run 254 `DurableCompletionAttested` is required before any backend request can
  exist, and therefore before any acknowledgement.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication
  receipt request can exist, and therefore before any acknowledgement.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement /
  confirmation request can exist; only that receipt outcome creates an
  acknowledgement request.
* Only `AcknowledgementRecorded` authorizes a new modeled
  audit-receipt-acknowledgement state.
* Every non-recorded receipt outcome produces no acknowledgement request and no
  acknowledgement.
* A failed acknowledgement record, rollback, rollback-failed, ambiguous window,
  unavailable production/MainNet audit-ledger acknowledgement / external-publication
  confirmation path, rejected replay state, and unsupported action never record.
* An acknowledgement record failure, rollback, rollback failure, or ambiguous
  acknowledgement window never retroactively claims a durable acknowledgement.
* A duplicate identical acknowledgement is idempotent (no second acknowledgement);
  the same acknowledgement record id with a different digest fails closed as
  equivocation; a duplicate-idempotent audit receipt never creates a new
  acknowledgement by itself.
* Rejected acknowledgement paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no live trust swap, no session eviction, no sequence
  write, no marker write, no external publication, no real audit-ledger write, and
  no acknowledgement sink invocation where the rejection happens before the
  acknowledgement stage.
* MainNet peer-driven apply is refused before pipeline progression, before any sink,
  reporter, finalizer, attestor, backend, receipt, or acknowledgement sink
  invocation.
* The local operator and peer majority cannot satisfy MainNet authority.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture acknowledgement sink mutates only modeled in-memory
  audit-receipt-acknowledgement state; no RocksDB / file / schema / migration /
  storage-format change; no wire / marker / sequence / trust-bundle change.

## Honest limitations

* Run 260 is source/test only and introduces an acknowledgement interface boundary
  over a modeled in-memory ledger, not a real production audit ledger
  acknowledgement or external publication confirmation backend. No production
  mutating behavior is enabled.
* The fixture acknowledgement sink records only modeled in-memory
  audit-receipt-acknowledgement state; it performs no real audit-ledger write, no
  real external-publication confirmation, and no real external publication, and the
  production audit-ledger acknowledgement / MainNet audit-ledger acknowledgement /
  external-publication confirmation sinks are deliberately
  reachable-but-unavailable.
* The Run 260 module carries both a `backend_binding` (Run 256) and a
  `receipt_binding` (Run 258); the acknowledgement gate is driven by the Run 258
  `receipt_binding` projection (plus the MainNet peer-driven refusal and policy
  pre-checks). The `backend_binding` is retained for the MainNet peer-driven
  composition and digest binding rather than as the primary acknowledgement gate.
* No real audit ledger acknowledgement backend, external publication confirmation
  backend, external publication backend, production attestation backend,
  finalization backend, completion-report backend, durable consume backend,
  persistent replay backend, production mutation engine, governance execution
  engine, on-chain governance proof verifier, or KMS/HSM/RemoteSigner backend is
  implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 260 closes the source/test
durable-completion audit-receipt acknowledgement / external-publication confirmation
interface gap only and does **not** claim full C4 or C5 closure.

## Suggested Run 261 next step

Release-binary evidence for the Run 260 durable-completion audit-receipt
acknowledgement / external-publication confirmation boundary (mirroring the Run 241
/ 243 / 245 / 247 / 249 / 251 / 253 / 255 / 257 / 259 pattern): build the release
binary, exercise the Run 246 pipeline → Run 248 consume-sink projection → Run 250
completion-report projection → Run 252 finalization projection → Run 254 attestation
projection → Run 256 backend submission → Run 258 audit receipt → Run 260 fixture
acknowledgement path through the source/test fixtures, and capture grep-verifiable
evidence that a modeled acknowledgement is recorded only after a Run 258
audit-receipt-recorded record, that every non-recording / record-failure / rollback
/ ambiguous / equivocation / unavailable path remains non-mutating and records no
acknowledgement, and that production/MainNet audit-ledger acknowledgement /
external-publication confirmation paths and MainNet peer-driven apply remain
refused/unavailable.
