# QBIND DevNet evidence — Run 256

**Title.** Source/test production durable-completion attestation **backend
interface boundary**.

**Status.** PASS (source/test only). Run 256 extends the Run 254 modeled
durable-completion attestation projection with a typed, mockable, in-memory
**backend interface boundary** that models the first backend-facing interface a
future production call site would use **after** the Run 254
`DurableCompletionAttested` outcome has been recorded. Run 254 proved that a
modeled attestation is recorded only after the Run 252 finalization projection
yields `DurableCompletionFinalized`. What was still missing was a typed
source/test boundary that models the after-attestation-only backend-submission
step (the interface a production attestation backend / audit-ledger / external
publication call site would implement). Run 256 closes that source/test backend
interface gap only.

Run 256 introduces a **backend interface boundary**, **not** a replacement for
any existing module. It consumes the typed Run 254 attestation outcome
(`GovernanceModeledDurableCompletionAttestationOutcome`) as a binding and
projects it onto a backend request intent; only the Run 254
`DurableCompletionAttested` outcome creates a backend request, and a Run 254
`DurableCompletionAttestationDuplicateIdempotent` may only match an
already-submitted backend record and never creates a new one. The backend is a
**model only**. It implements **no** real persistent replay backend, **no** real
durable consume backend, **no** real completion-report backend, **no** real
finalization backend, **no** real production attestation backend, **no** real
audit ledger backend, **no** real external publication backend, **no** real
production mutation engine, **no** real governance execution engine, **no** real
on-chain governance proof verifier, **no** RocksDB backend, **no** file format,
**no** schema, **no** database migration, **no** storage-format change, **no**
KMS/HSM backend, **no** RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle
format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 256 adds a production durable-completion attestation backend interface
  boundary.
* The boundary models the first backend-facing interface a future production
  call site would use after Run 254 `DurableCompletionAttested`.
* The fixture backend is DevNet/TestNet evidence-only and in-memory only.
* Production and MainNet backends are reachable but unavailable/fail-closed.
* It does **not** implement a real production attestation backend.
* It does **not** implement a real audit ledger backend.
* It does **not** implement a real external publication backend.
* It does **not** implement a real persistent replay backend.
* It does **not** implement a real durable consume backend.
* It does **not** implement a real completion-report backend.
* It does **not** implement a real finalization backend.
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
* It does **not** enable MainNet governance.
* It does **not** enable MainNet peer-driven apply.
* It does **not** implement validator-set rotation.
* The fixture backend mutates only modeled in-memory backend-submission state.
* Rejected backend paths are non-mutating.
* Run 256 does not weaken any prior run (Runs 070, 130–255) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_attestation_backend.rs`

Run 256 adds a new source module (registered in `lib.rs`) that defines:

* typed backend inputs / policy / identity / bindings
  (`DurableCompletionAttestationBackendInput`,
  `DurableCompletionAttestationBackendPolicy`,
  `DurableCompletionAttestationBackendKind`,
  `DurableCompletionAttestationBackendIdentity`,
  `DurableCompletionAttestationBackendExpectations`,
  `DurableCompletionAttestationBackendRequest`,
  `DurableCompletionAttestationBackendResponse`,
  `DurableCompletionAttestationBackendReceipt`) plus the Run 254 attestation
  outcome (`GovernanceModeledDurableCompletionAttestationOutcome`) carried as the
  `attestation_binding`, and the Run 246/248/250/252 bindings carried for the
  MainNet peer-driven composition;
* modeled in-memory backend-submission state
  (`DurableCompletionAttestationBackendLedger`,
  `DurableCompletionAttestationBackendRecord`,
  `DurableCompletionAttestationBackendDigest`,
  `DurableCompletionAttestationBackendTranscriptDigest`) — in-memory only; never
  touches RocksDB, files, markers, sequence files, or any production durable
  state. The backend digests bind, via domain-separated SHA3-256 over
  length-prefixed fields, the backend identity, request, response, receipt, and
  transcript;
* an explicit backend outcome enum
  (`DurableCompletionAttestationBackendOutcome`) whose only **new**-submission
  authorizing variant is `BackendSubmissionRecorded`, including
  `LegacyBypassNoBackendSubmission`,
  `RejectedBeforeAttestationNoBackendSubmission`,
  `AttestationDidNotAttestNoBackendSubmission`,
  `BackendSubmissionDuplicateIdempotent`,
  `BackendSubmissionRejectedBeforeRecord`,
  `BackendSubmissionRecordFailedNoSubmission`,
  `BackendSubmissionRolledBackNoSubmission`,
  `BackendSubmissionRollbackFailedFatalNoSubmission`,
  `BackendSubmissionAmbiguousFailClosedNoSubmission`,
  `ProductionBackendUnavailableNoSubmission`,
  `MainNetBackendUnavailableNoSubmission`,
  `ExternalPublicationUnavailableNoSubmission`,
  `MainNetPeerDrivenApplyRefusedNoSubmission`,
  `ValidatorSetRotationUnsupportedNoSubmission`, and
  `PolicyChangeUnsupportedNoSubmission`;
* a pure/mockable backend trait
  (`GovernanceDurableCompletionAttestationBackend`) with
  `submit_durable_completion_attestation`, plus source/test-only implementations
  (`FixtureDurableCompletionAttestationBackend` for DevNet/TestNet, and the
  reachable-but-unavailable `ProductionDurableCompletionAttestationBackend`,
  `MainNetDurableCompletionAttestationBackend`, and
  `ExternalPublicationDurableCompletionAttestationBackend`). The fixture backend
  exposes an invocation counter so tests prove non-attesting and pre-backend
  rejected paths never invoke it;
* composition helpers (`project_attestation_outcome_to_backend_request`,
  `evaluate_durable_completion_attestation_backend`,
  `recover_durable_completion_attestation_backend_window`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, **before**
   any finalizer invocation, **before** any attestor invocation, and **before**
   any backend invocation.
2. A disabled backend / attestation / finalization / reporter / sink / pipeline
   policy preserves the legacy no-backend-submission bypass and never invokes the
   backend.
3. Only the Run 254 `DurableCompletionAttested` attestation outcome creates a
   backend request; `DurableCompletionAttestationDuplicateIdempotent` may only
   match an already-submitted backend record; every other attestation outcome
   maps to a no-backend-submission fail-closed outcome and never invokes the
   backend.
4. Pre-backend environment / chain / genesis / governance surface / mutation
   surface binding validation completes **before** the backend is invoked; a
   mismatch fails closed with no backend invocation.
5. The backend submission happens **after** the Run 254
   durable-completion-attested state; the backend-identity and request fields
   must match exactly before any modeled backend record is created.
6. Only `BackendSubmissionRecorded` authorizes a **new** modeled backend-submitted
   state. A duplicate identical submission is idempotent (no second submission);
   the same backend record id with a different digest fails closed as
   equivocation.

### Grep-verifiable invariant helpers

* `durable_completion_attestation_backend_rejection_is_non_mutating`
* `durable_completion_attestation_backend_never_calls_run_070`
* `durable_completion_attestation_backend_never_mutates_live_pqc_trust_state`
* `durable_completion_attestation_backend_never_writes_sequence_or_marker`
* `durable_completion_attestation_backend_no_rocksdb_file_schema_migration_change`
* `durable_completion_attestation_backend_no_external_publication`
* `durable_completion_attestation_backend_no_real_audit_ledger`
* `durable_completion_attestation_backend_pipeline_success_required`
* `durable_completion_attestation_backend_sink_receipt_required`
* `durable_completion_attestation_backend_completion_report_required`
* `durable_completion_attestation_backend_finalization_required`
* `durable_completion_attestation_backend_attestation_required`
* `durable_completion_attestation_backend_record_required_before_submission`
* `durable_completion_attestation_backend_failed_record_never_submits`
* `durable_completion_attestation_backend_rollback_never_submits`
* `durable_completion_attestation_backend_ambiguous_window_fails_closed`
* `durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first`
* `durable_completion_attestation_backend_production_mainnet_unavailable`
* `durable_completion_attestation_backend_validator_set_rotation_unsupported`
* `durable_completion_attestation_backend_policy_change_unsupported`
* `durable_completion_attestation_backend_local_operator_cannot_satisfy_mainnet_authority`
* `durable_completion_attestation_backend_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_256_durable_completion_attestation_backend_tests.rs`
— 46 tests, all passing. The matrix covers:

* **Accepted / compatible:** a disabled backend policy preserves the legacy
  no-backend-submission bypass and never invokes the backend; DevNet and TestNet
  durable-completion attested + backend record success record exactly one modeled
  in-memory backend submission; a duplicate identical submission is idempotent
  with no second submission; a Run 254 duplicate-idempotent attestation matches an
  already-submitted backend record only, and never creates a new one by itself;
  the production, MainNet, and external-publication backend paths are reachable
  but unavailable/fail-closed and record no submission; MainNet peer-driven apply
  is refused before pipeline progression, before any sink, reporter, finalizer,
  attestor, or backend invocation.
* **Rejected / fail-closed:** every non-attesting Run 254 attestation outcome
  produces no backend request, no submission, and zero backend invocations; a
  backend record failure, rollback, rollback-failed, and ambiguous window all
  fail closed without recording a submission; the same backend record id with a
  different digest is rejected as equivocation and records no second submission;
  wrong environment / chain / genesis / governance surface / mutation surface are
  rejected before backend invocation (zero invocations); wrong backend identity /
  kind / policy / record id / attestation id / attestation digest / decision id /
  proposal id / candidate digest / pipeline / sink / reporter / finalization
  decision digests / authority-domain sequence and a malformed backend request are
  rejected before record (backend invoked, no record).
* **Recovery / crash-window:** before-attestation and intermediate intent/record
  windows fail closed with no submission;
  after-backend-record-before-success fails closed unless an explicit matching
  backend success exists; after-backend-success recovers as backend submitted;
  after-backend-ambiguous and unknown windows fail closed with no submission;
  production/MainNet recovery classification is unavailable; MainNet peer-driven
  apply refusal precedes recovery classification.
* **Projection / stage-ordering:** only `DurableCompletionAttested` creates a
  backend request intent; `DurableCompletionAttestationDuplicateIdempotent`
  projects to idempotent-only; only `BackendSubmissionRecorded` authorizes a new
  modeled submission; a rejection before the backend stage leaves the backend
  invocation count at zero; one valid submission inserts exactly one ledger
  record; the ledger snapshot/restore models a rollback with no drift; the
  grep-verifiable invariant helpers all assert their fail-closed contract.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
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
  therefore before any backend submission.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent
  can exist, and therefore before any backend submission.
* Run 250 `CompletionReportRecorded` is required before any finalization intent
  can exist, and therefore before any backend submission.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent
  can exist, and therefore before any backend submission.
* Run 254 `DurableCompletionAttested` is required before any backend request can
  exist; only that attestation outcome creates a backend request.
* Only `BackendSubmissionRecorded` authorizes a new modeled backend-submitted
  state.
* Every non-attested attestation outcome produces no backend request and no
  backend submission.
* A failed backend record, rollback, rollback-failed, ambiguous window,
  unavailable production/MainNet/external-publication path, rejected replay state,
  and unsupported action never submit.
* A backend failure, rollback, rollback failure, or ambiguous backend window never
  retroactively claims a backend submission.
* A duplicate identical submission is idempotent (no second submission); the same
  backend record id with a different digest fails closed as equivocation; a
  duplicate-idempotent attestation never creates a new submission by itself.
* Rejected backend paths are non-mutating: no Run 070 call, no `LivePqcTrustState`
  mutation, no live trust swap, no session eviction, no sequence write, no marker
  write, no external publication, no real audit ledger, and no backend invocation
  where the rejection happens before the backend stage.
* MainNet peer-driven apply is refused before pipeline progression, before any
  sink, reporter, finalizer, attestor, or backend invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture backend mutates only modeled in-memory backend-submission state; no
  RocksDB / file / schema / migration / storage-format change; no wire / marker /
  sequence / trust-bundle change.

## Honest limitations

* Run 256 is source/test only and introduces a backend interface boundary over a
  modeled in-memory ledger, not a real production attestation, audit ledger, or
  external publication backend. No production mutating behavior is enabled.
* The fixture backend records only modeled in-memory backend-submission state; it
  performs no real backend submission, and the production / MainNet /
  external-publication backends are deliberately reachable-but-unavailable.
* No real persistent replay backend, durable consume backend, completion-report
  backend, finalization backend, production attestation backend, audit ledger
  backend, external publication backend, production mutation engine, governance
  execution engine, on-chain governance proof verifier, or KMS/HSM/RemoteSigner
  backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 256 closes the source/test
production durable-completion attestation backend interface gap only and does
**not** claim full C4 or C5 closure.

## Suggested Run 257 next step

Release-binary evidence for the Run 256 durable-completion attestation backend
interface boundary (mirroring the Run 241 / 243 / 245 / 247 / 249 / 251 / 253 /
255 pattern): build the release binary, exercise the Run 246 pipeline → Run 248
consume-sink projection → Run 250 completion-report projection → Run 252
finalization projection → Run 254 attestation projection → Run 256 fixture backend
submission path through the source/test fixtures, and capture grep-verifiable
evidence that a modeled backend submission is recorded only after a Run 254
durable-completion attested record, that every non-attesting / record-failure /
rollback / ambiguous / equivocation / unavailable path remains non-mutating and
records no submission, and that production/MainNet/external-publication backend
paths and MainNet peer-driven apply remain refused/unavailable.
