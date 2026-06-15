# QBIND DevNet evidence — Run 258

**Title.** Source/test durable-completion backend **audit-ledger /
external-publication receipt boundary**.

**Status.** PASS (source/test only). Run 258 extends the Run 256 modeled
durable-completion attestation backend interface boundary with a typed, mockable,
in-memory **audit-ledger / external-publication receipt boundary** that models the
first post-Run-256 backend-submission receipt interface a future production audit
ledger or external publication system would use **after** the Run 256
`BackendSubmissionRecorded` outcome has been recorded. Run 256 proved that a
modeled backend submission is recorded only after the Run 254 attestation
projection yields `DurableCompletionAttested`. What was still missing was a typed
source/test boundary that models the after-backend-submission-only audit/publication
receipt step (the interface a production audit ledger or external publication call
site would implement). Run 258 closes that source/test receipt interface gap only.

Run 258 introduces a **receipt interface boundary**, **not** a replacement for any
existing module. It consumes the typed Run 256 backend outcome
(`DurableCompletionAttestationBackendOutcome`) as a binding and projects it onto a
receipt request intent; only the Run 256 `BackendSubmissionRecorded` outcome
creates a receipt request, and a Run 256 `BackendSubmissionDuplicateIdempotent` may
only match an already-recorded receipt and never creates a new one. The receipt
layer is a **model only**. It implements **no** real audit ledger backend, **no**
real external publication backend, **no** real production attestation backend,
**no** real finalization backend, **no** real completion-report backend, **no**
real durable consume backend, **no** real persistent replay backend, **no** real
governance execution engine, **no** real production mutation engine, **no** real
on-chain governance proof verifier, **no** RocksDB backend, **no** file format,
**no** schema, **no** database migration, **no** storage-format change, **no**
KMS/HSM backend, **no** RemoteSigner backend, **no** MainNet governance enablement,
**no** MainNet peer-driven apply enablement, and **no** validator-set rotation. It
changes **no** wire, schema, marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 258 adds a durable-completion backend audit-ledger / external-publication
  receipt boundary.
* The boundary models the first post-Run-256 backend-submission receipt interface a
  future production audit ledger or external publication system would use.
* The fixture receipt sink is DevNet/TestNet evidence-only and in-memory only.
* Production audit-ledger, MainNet audit-ledger, and external-publication sinks are
  reachable but unavailable/fail-closed.
* It does **not** implement a real audit ledger backend.
* It does **not** implement a real external publication backend.
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
* The fixture receipt sink mutates only modeled in-memory audit/publication-receipt
  state.
* Rejected receipt paths are non-mutating.
* Run 258 does not weaken any prior run (Runs 070, 130–257) and does not claim full
  C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_audit_publication_receipt.rs`

Run 258 adds a new source module (registered in `lib.rs`) that defines:

* typed receipt inputs / policy / identity / bindings
  (`DurableCompletionAuditPublicationReceiptInput`,
  `DurableCompletionAuditPublicationReceiptPolicy`,
  `DurableCompletionAuditPublicationReceiptKind`,
  `DurableCompletionAuditPublicationReceiptIdentity`,
  `DurableCompletionAuditPublicationReceiptExpectations`,
  `DurableCompletionAuditPublicationReceiptRequest`,
  `DurableCompletionAuditPublicationReceiptResponse`,
  `DurableCompletionAuditPublicationReceiptRecord`) plus the Run 256 backend
  outcome (`DurableCompletionAttestationBackendOutcome`) carried as the
  `backend_binding`, and the Run 246/248/250/252/254 bindings carried for the
  MainNet peer-driven composition;
* modeled in-memory audit/publication-receipt state
  (`DurableCompletionAuditPublicationReceiptLedger`,
  `DurableCompletionAuditPublicationReceiptLedgerRecord`,
  `DurableCompletionAuditPublicationReceiptDigest`,
  `DurableCompletionAuditPublicationReceiptTranscriptDigest`) — in-memory only;
  never touches RocksDB, files, markers, sequence files, external publications,
  audit-ledger entries, or any production durable state. The receipt digests bind,
  via domain-separated SHA3-256 over length-prefixed fields, the receipt identity,
  request, response, record, and transcript, including the full Run 256 backend
  identity / request / response / receipt / transcript digest binding;
* an explicit receipt outcome enum
  (`DurableCompletionAuditPublicationReceiptOutcome`) whose only **new**-receipt
  authorizing variant is `AuditReceiptRecorded`, including
  `LegacyBypassNoAuditReceipt`,
  `RejectedBeforeBackendSubmissionNoAuditReceipt`,
  `BackendDidNotSubmitNoAuditReceipt`, `AuditReceiptDuplicateIdempotent`,
  `AuditReceiptRejectedBeforeRecord`, `AuditReceiptRecordFailedNoReceipt`,
  `AuditReceiptRolledBackNoReceipt`, `AuditReceiptRollbackFailedFatalNoReceipt`,
  `AuditReceiptAmbiguousFailClosedNoReceipt`,
  `ProductionAuditLedgerUnavailableNoReceipt`,
  `MainNetAuditLedgerUnavailableNoReceipt`,
  `ExternalPublicationUnavailableNoReceipt`,
  `MainNetPeerDrivenApplyRefusedNoReceipt`,
  `ValidatorSetRotationUnsupportedNoReceipt`, and
  `PolicyChangeUnsupportedNoReceipt`;
* a pure/mockable receipt trait
  (`GovernanceDurableCompletionAuditPublicationReceiptSink`) with
  `record_durable_completion_audit_publication_receipt`, plus source/test-only
  implementations (`FixtureDurableCompletionAuditPublicationReceiptSink` for
  DevNet/TestNet, and the reachable-but-unavailable
  `ProductionAuditLedgerDurableCompletionReceiptSink`,
  `MainNetAuditLedgerDurableCompletionReceiptSink`, and
  `ExternalPublicationDurableCompletionReceiptSink`). The fixture sink exposes an
  invocation counter so tests prove non-submitting backend paths and pre-receipt
  rejected paths never invoke it;
* composition helpers
  (`project_backend_submission_outcome_to_audit_receipt_request`,
  `evaluate_durable_completion_audit_publication_receipt`,
  `recover_durable_completion_audit_publication_receipt_window`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, **before**
   any finalizer invocation, **before** any attestor invocation, **before** any
   backend invocation, and **before** any receipt sink invocation.
2. A disabled receipt / backend / attestation / finalization / reporter / sink /
   pipeline policy preserves the legacy no-audit-receipt bypass and never invokes
   the receipt sink.
3. Only the Run 256 `BackendSubmissionRecorded` backend outcome creates a receipt
   request; `BackendSubmissionDuplicateIdempotent` may only match an
   already-recorded receipt; every other backend outcome maps to a
   no-audit-receipt fail-closed outcome and never invokes the receipt sink.
4. Pre-receipt environment / chain / genesis / governance surface / mutation
   surface binding validation completes **before** the receipt sink is invoked; a
   mismatch fails closed with no receipt sink invocation.
5. The receipt record happens **after** the Run 256 backend-submitted state; the
   receipt-record-identity and request fields (including the full Run 256 backend
   digest binding) must match exactly before any modeled receipt is recorded.
6. Only `AuditReceiptRecorded` authorizes a **new** modeled audit/publication
   receipt state. A duplicate identical receipt is idempotent (no second receipt);
   the same receipt record id with a different digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `durable_completion_audit_receipt_rejection_is_non_mutating`
* `durable_completion_audit_receipt_never_calls_run_070`
* `durable_completion_audit_receipt_never_mutates_live_pqc_trust_state`
* `durable_completion_audit_receipt_never_writes_sequence_or_marker`
* `durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change`
* `durable_completion_audit_receipt_no_external_publication`
* `durable_completion_audit_receipt_no_real_audit_ledger`
* `durable_completion_audit_receipt_pipeline_success_required`
* `durable_completion_audit_receipt_sink_receipt_required`
* `durable_completion_audit_receipt_completion_report_required`
* `durable_completion_audit_receipt_finalization_required`
* `durable_completion_audit_receipt_attestation_required`
* `durable_completion_audit_receipt_backend_submission_required`
* `durable_completion_audit_receipt_record_required_before_receipt`
* `durable_completion_audit_receipt_failed_record_never_records`
* `durable_completion_audit_receipt_rollback_never_records`
* `durable_completion_audit_receipt_ambiguous_window_fails_closed`
* `durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first`
* `durable_completion_audit_receipt_production_mainnet_unavailable`
* `durable_completion_audit_receipt_external_publication_unavailable`
* `durable_completion_audit_receipt_validator_set_rotation_unsupported`
* `durable_completion_audit_receipt_policy_change_unsupported`
* `durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority`
* `durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_258_durable_completion_audit_publication_receipt_tests.rs`
— 57 tests, all passing. Every recording test attaches the receipt to the
**actual** Run 256 `BackendSubmissionRecorded` path: the test harness drives a real
`evaluate_durable_completion_attestation_backend` round-trip and binds the receipt
request to the real Run 256 backend identity / request / response / receipt /
transcript digests — never a faked, unattached receipt path. The matrix covers:

* **Accepted / compatible:** a disabled receipt policy preserves the legacy
  no-audit-receipt bypass and never invokes the receipt sink; a disabled backend
  policy never reaches the receipt sink; DevNet and TestNet fixture chains record
  exactly one modeled in-memory receipt only after the full Run 246 pipeline → Run
  248 sink receipt → Run 250 completion report → Run 252 finalization → Run 254
  attestation → Run 256 backend submission → Run 258 receipt chain; add-root /
  retire-root / revoke-root / emergency-revoke-root / noop modeled action variants
  preserve ordering and record only after backend submission; a duplicate identical
  receipt is idempotent with no second receipt; a Run 256 duplicate-idempotent
  backend submission matches an already-recorded receipt only and never creates a
  new one by itself; the production audit-ledger, MainNet audit-ledger, and
  external-publication receipt paths are reachable but unavailable/fail-closed and
  record no receipt; MainNet peer-driven apply is refused before pipeline
  progression, before any sink, reporter, finalizer, attestor, backend, or receipt
  sink invocation.
* **Rejected / fail-closed:** every non-submitting Run 256 backend outcome produces
  no receipt request, no receipt, and zero receipt sink invocations; a receipt
  record failure, rollback, rollback-failed, and ambiguous window all fail closed
  without recording a receipt; the same receipt record id with a different digest
  is rejected as equivocation and records no second receipt; wrong environment /
  chain / genesis / governance surface / mutation surface are rejected before
  receipt sink invocation (zero invocations); wrong receipt identity / kind /
  policy / record id / proposal id / decision id / candidate digest /
  authority-domain sequence / pipeline / sink / reporter / finalization / attestation
  digest / attestation id / backend identity / request / response / receipt /
  transcript digest / backend record id / domain separation tag and a malformed
  receipt request are rejected before record (receipt sink invoked, no record); the
  fixture receipt sink rejects any non-DevNet/TestNet environment.
* **Recovery / crash-window:** before-pipeline through
  after-backend-record-before-backend-success windows fail closed with no receipt;
  after-backend-success-before-receipt-request and
  after-receipt-request-before-receipt-record reject before record;
  after-receipt-record-before-receipt-success fails closed unless an explicit
  matching receipt record exists; after-receipt-success recovers as receipt
  recorded only with an explicit matching record; ambiguous, record-failed,
  rollback-completed, rollback-failed, and unknown windows fail closed; production /
  MainNet audit-ledger / external-publication recovery classification is
  unavailable; MainNet peer-driven apply refusal precedes recovery classification.
* **Projection / stage-ordering:** only `BackendSubmissionRecorded` creates a
  receipt request intent; `BackendSubmissionDuplicateIdempotent` projects to
  idempotent-only; every other backend outcome projects to NoAuditReceipt; only
  `AuditReceiptRecorded` authorizes a new modeled receipt; a rejection before the
  receipt stage leaves the receipt sink invocation count at zero; one valid receipt
  inserts exactly one ledger record; the ledger snapshot/restore models a rollback
  with no drift; the grep-verifiable invariant helpers all assert their fail-closed
  contract.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
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

## Security invariants preserved

* Run 246 pipeline success is required before any sink intent can exist, and
  therefore before any audit/publication receipt.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent
  can exist, and therefore before any audit/publication receipt.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can
  exist, and therefore before any audit/publication receipt.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can
  exist, and therefore before any audit/publication receipt.
* Run 254 `DurableCompletionAttested` is required before any backend request can
  exist, and therefore before any audit/publication receipt.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication
  receipt request can exist; only that backend outcome creates a receipt request.
* Only `AuditReceiptRecorded` authorizes a new modeled audit/publication receipt
  state.
* Every non-submitted backend outcome produces no audit/publication receipt request
  and no receipt.
* A failed receipt record, rollback, rollback-failed, ambiguous window, unavailable
  production/MainNet audit-ledger/external-publication path, rejected replay state,
  and unsupported action never record.
* A receipt record failure, rollback, rollback failure, or ambiguous receipt window
  never retroactively claims a durable receipt.
* A duplicate identical receipt is idempotent (no second receipt); the same receipt
  record id with a different digest fails closed as equivocation; a
  duplicate-idempotent backend submission never creates a new receipt by itself.
* Rejected receipt paths are non-mutating: no Run 070 call, no `LivePqcTrustState`
  mutation, no live trust swap, no session eviction, no sequence write, no marker
  write, no external publication, no real audit-ledger write, and no receipt sink
  invocation where the rejection happens before the receipt stage.
* MainNet peer-driven apply is refused before pipeline progression, before any
  sink, reporter, finalizer, attestor, backend, or receipt sink invocation.
* The local operator and peer majority cannot satisfy MainNet authority.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture receipt sink mutates only modeled in-memory audit/publication-receipt
  state; no RocksDB / file / schema / migration / storage-format change; no wire /
  marker / sequence / trust-bundle change.

## Honest limitations

* Run 258 is source/test only and introduces a receipt interface boundary over a
  modeled in-memory ledger, not a real production audit ledger or external
  publication backend. No production mutating behavior is enabled.
* The fixture receipt sink records only modeled in-memory audit/publication-receipt
  state; it performs no real audit-ledger write and no real external publication,
  and the production audit-ledger / MainNet audit-ledger / external-publication
  sinks are deliberately reachable-but-unavailable.
* No real audit ledger backend, external publication backend, production attestation
  backend, finalization backend, completion-report backend, durable consume
  backend, persistent replay backend, production mutation engine, governance
  execution engine, on-chain governance proof verifier, or KMS/HSM/RemoteSigner
  backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 258 closes the source/test
durable-completion audit-ledger / external-publication receipt interface gap only
and does **not** claim full C4 or C5 closure.

## Suggested Run 259 next step

Release-binary evidence for the Run 258 durable-completion audit-ledger /
external-publication receipt boundary (mirroring the Run 241 / 243 / 245 / 247 /
249 / 251 / 253 / 255 / 257 pattern): build the release binary, exercise the Run
246 pipeline → Run 248 consume-sink projection → Run 250 completion-report
projection → Run 252 finalization projection → Run 254 attestation projection → Run
256 backend submission → Run 258 fixture receipt path through the source/test
fixtures, and capture grep-verifiable evidence that a modeled audit/publication
receipt is recorded only after a Run 256 backend-submitted record, that every
non-submitting / record-failure / rollback / ambiguous / equivocation / unavailable
path remains non-mutating and records no receipt, and that production/MainNet
audit-ledger/external-publication receipt paths and MainNet peer-driven apply remain
refused/unavailable.