# QBIND DevNet evidence — Run 284

**Title.** Source/test durable-completion **external-publication-audit-finalization
consumer / external-publication-audit-completion interface boundary**.

**Status.** PASS (source/test only). Run 284 extends the Run 282 modeled
durable-completion external-publication-audit-finalization interface boundary with a
typed, mockable, in-memory **external-publication-audit-completion sink boundary**
that models the first post-finalization external-publication-audit-completion step a
future production settlement subsystem might use **after** a Run 282
`ExternalPublicationAuditFinalizationRecorded` outcome has been recorded. Run 282
proved that a modeled external-publication-audit-finalization record is recorded only
after the Run 280 `ExternalPublicationAcknowledgementRecorded` outcome. What was still
missing was a typed source/test boundary that converts a valid recorded
external-publication-audit-finalization state into a typed
external-publication-audit-completion intent and modeled in-memory
external-publication-audit-completion record. Run 284 closes that source/test
external-publication-audit-finalization consumer /
external-publication-audit-completion interface gap only.

Run 284 introduces an **external-publication-audit-completion interface boundary**,
**not** a replacement for any existing module. It consumes the typed Run 282
external-publication-audit-finalization outcome
(`DurableCompletionExternalPublicationAuditFinalizationOutcome`) as an
`external_publication_audit_finalization_binding` and projects it onto an
external-publication-audit-completion request intent; only the Run 282
`ExternalPublicationAuditFinalizationRecorded` outcome creates an
external-publication-audit-completion request, and a Run 282
`ExternalPublicationAuditFinalizationDuplicateIdempotent` may only match an
already-recorded external-publication-audit-completion record and never creates a
new one. The external-publication-audit-completion layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 284 adds a modeled durable-completion external-publication-audit-finalization
  consumer / external-publication-audit-completion interface boundary.
* The boundary consumes only Run 282 `ExternalPublicationAuditFinalizationRecorded`.
* Run 282 `ExternalPublicationAuditFinalizationRecorded` is required before any
  external-publication-audit-completion request can exist.
* Only `ExternalPublicationAuditCompletionRecorded` authorizes modeled
  external-publication-audit-completion state.
* The fixture external-publication-audit-completion sink is DevNet/TestNet
  evidence-only and in-memory only.
* Production/MainNet/external external-publication-audit-completion sinks remain
  reachable but unavailable/fail-closed.
* No real settlement is implemented.
* No real settlement finality is implemented.
* No real settlement receipt is implemented.
* No real settlement-receipt acknowledgement is implemented.
* No real settlement-finality projection is implemented.
* No real settlement-outcome report backend is implemented.
* No real settlement-outcome publication is implemented.
* No real external publication is implemented.
* No real external-publication confirmation is implemented.
* No real external-publication receipt is implemented.
* No real external-publication acknowledgement is implemented.
* No real external-publication audit finalization is implemented.
* No real external-publication audit completion is implemented.
* No real audit-ledger acknowledgement is implemented.
* No real audit-ledger finalization is implemented.
* No real production backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No wire/schema/marker/sequence/trust-bundle change is implemented.
* No MainNet governance is enabled.
* No MainNet peer-driven apply is enabled.
* No validator-set rotation is implemented.
* No policy-change enablement is implemented.
* No Run 070 call.
* No `LivePqcTrustState` mutation.
* Rejected external-publication-audit-completion paths are non-mutating.
* Run 284 keeps the C4/C5 matrix taxonomy present and unweakened: it separates
  boundary readiness from production readiness.
* Yellow boundary rows do not equal production backend implementation.
* Red production backend rows remain Red until production implementation and
  release-binary evidence exist.
* The matrix taxonomy is not weakened and closure criteria are not weakened.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_external_publication_audit_completion.rs`

Run 284 adds a source module (registered in `lib.rs`) that defines:

* typed external-publication-audit-completion inputs / policy / identity / bindings
  (`DurableCompletionExternalPublicationAuditCompletionKind`,
  `DurableCompletionExternalPublicationAuditCompletionPolicy`,
  `DurableCompletionExternalPublicationAuditCompletionIdentity`,
  `DurableCompletionExternalPublicationAuditCompletionInput`,
  `DurableCompletionExternalPublicationAuditCompletionExpectations`,
  `DurableCompletionExternalPublicationAuditCompletionRequest`,
  `DurableCompletionExternalPublicationAuditCompletionOutcome`);
* an external-publication-audit-completion sink trait
  (`GovernanceDurableCompletionExternalPublicationAuditCompletionSink`) with a
  DevNet/TestNet in-memory fixture implementation
  (`FixtureDurableCompletionExternalPublicationAuditCompletionSink`) and
  reachable-but-unavailable `ProductionExternalPublicationAuditCompletionSink`,
  `MainNetExternalPublicationAuditCompletionSink`, and
  `ExternalExternalPublicationAuditCompletionSink` implementations;
* an in-memory ledger
  (`DurableCompletionExternalPublicationAuditCompletionLedger`);
* projection / evaluation / recovery helpers
  (`project_external_publication_audit_finalization_outcome_to_external_publication_audit_completion_request`,
  `evaluate_durable_completion_external_publication_audit_completion`,
  `recover_durable_completion_external_publication_audit_completion_window`,
  `external_publication_audit_completion_outcome_authorizes_record`,
  `external_publication_audit_completion_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_external_publication_audit_completion_external_publication_audit_finalization_required`,
  `durable_completion_external_publication_audit_completion_record_required_before_completed`,
  `durable_completion_external_publication_audit_completion_no_real_external_publication_audit_finalization`,
  `durable_completion_external_publication_audit_completion_no_real_external_publication_audit_completion`,
  `durable_completion_external_publication_audit_completion_never_calls_run_070`,
  `durable_completion_external_publication_audit_completion_never_mutates_live_pqc_trust_state`.

The fixture external-publication-audit-completion sink mutates only the in-memory
`DurableCompletionExternalPublicationAuditCompletionLedger` and exposes an
invocation counter so tests prove non-recording finalization paths and
pre-finalization rejections never invoke it.

## Tests

`crates/qbind-node/tests/run_284_durable_completion_external_publication_audit_completion_tests.rs`

Each Run 284 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 → 260
→ 262 → 264 → 266 → 268 → 270 → 272 → 274 → 276 → 278 → 280 → 282 chain (real
`evaluate_durable_completion_external_publication_audit_finalization` round-trip on top
of the real Run 280 external-publication-acknowledgement chain) before evaluating the
Run 284 external-publication-audit-completion, so the carried digests are real attached
records and never faked, unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching the audit completion; DevNet/TestNet fixture chains recording exactly one
in-memory audit-completion record only after the full chain; governance-action
ordering; duplicate idempotency; Run 282 duplicate-idempotent audit-finalization only
matching an existing audit-completion record; production/MainNet/external
reachable-but-unavailable fail-closed paths; MainNet peer-driven apply refusal first;
validator-set rotation / policy-change unsupported; the full binding-mismatch and
malformed-request rejection matrix; equivocation fail-closed; the
external-publication-audit-finalization request-intent matrix; and the recovery /
crash-window matrix (pre-finalization windows fail closed; after-completion-request
before-record fails closed; after-completion-record before-success requires an
explicit matching record; after-completion-success recovers as recorded;
ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

The full Run 284 validation corpus below was executed in the Run 284 closure pass.
Every command returned `rc=0` with the exact pass counts shown; no command failed.

* `cargo build -p qbind-node --lib` — OK. rc=0.
* `cargo test -p qbind-node --test run_284_durable_completion_external_publication_audit_completion_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_282_durable_completion_external_publication_audit_finalization_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_280_durable_completion_external_publication_acknowledgement_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_278_durable_completion_external_publication_receipt_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_276_durable_completion_external_publication_confirmation_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_274_durable_completion_settlement_outcome_publication_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_272_durable_completion_settlement_outcome_report_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_270_durable_completion_settlement_receipt_acknowledgement_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_268_durable_completion_settlement_finalization_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_266_durable_completion_settlement_commitment_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_264_durable_completion_consumer_settlement_projection_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_262_durable_completion_acknowledgement_consumer_tests` — ok. 57 passed; 0 failed.
* `cargo test -p qbind-node --test run_260_durable_completion_audit_receipt_acknowledgement_tests` — ok. 57 passed; 0 failed.
* `cargo test -p qbind-node --test run_258_durable_completion_audit_publication_receipt_tests` — ok. 57 passed; 0 failed.
* `cargo test -p qbind-node --test run_256_durable_completion_attestation_backend_tests` — ok. 46 passed; 0 failed.
* `cargo test -p qbind-node --test run_254_modeled_durable_completion_attestation_projection_tests` — ok.
* `cargo test -p qbind-node --test run_252_modeled_durable_completion_finalization_projection_tests` — ok.
* `cargo test -p qbind-node --test run_250_modeled_durable_consume_completion_reporter_tests` — ok.
* `cargo test -p qbind-node --test run_248_modeled_durable_consume_projection_sink_tests` — ok.
* `cargo test -p qbind-node --test run_246_governance_modeled_end_to_end_pipeline_tests` — ok.
* `cargo test -p qbind-node --test run_244_modeled_governance_trust_mutation_applier_tests` — ok.
* `cargo test -p qbind-node --test run_242_governance_execution_mutation_engine_tests` — ok.
* `cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests` — ok.
* `cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests` — ok.
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests` — ok.
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests` — ok.
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests` — ok.
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests` — ok.
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests` — ok.
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests` — ok.
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests` — ok.
* `cargo test -p qbind-node --lib pqc_authority` — ok.
* `cargo test -p qbind-node --lib` — ok.

## Notes on carried names

The Run 284 module is a shift-by-one continuation of the Run 282 boundary, so the
carried/upstream names from the Run 252 finalization-projection stage are preserved
deliberately:

* The carried Run 252 outcome
  (`GovernanceModeledDurableCompletionFinalizationOutcome`), its
  `finalization_decision_digest` field, and the deep finalization-projection
  predicate retain their upstream names because they reference upstream modeled
  boundaries, not the Run 284 own concept.
* The Run 284 own concept is `external_publication_audit_completion`; the
  immediately prior Run 282 concept is carried as
  `external_publication_audit_finalization`.

## C4 / C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 284 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 285 — release-binary evidence for the Run 284 durable-completion
external-publication-audit-finalization consumer / external-publication-audit-completion
interface boundary.
