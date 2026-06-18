# QBIND DevNet evidence — Run 280

**Title.** Source/test durable-completion **external-publication-receipt
consumer / external-publication-acknowledgement interface boundary**.

**Status.** PASS (source/test only). Run 280 extends the Run 278 modeled
durable-completion external-publication-receipt interface boundary with a
typed, mockable, in-memory **external-publication-acknowledgement sink boundary**
that models the first post-receipt external-publication-acknowledgement step a
future production settlement subsystem might use **after** a Run 278
`ExternalPublicationReceiptRecorded` outcome has been recorded. Run 278 proved
that a modeled external-publication-receipt record is recorded only after the
Run 276 `ExternalPublicationConfirmationRecorded` outcome. What was still missing
was a typed source/test boundary that converts a valid recorded
external-publication-receipt state into a typed external-publication-acknowledgement
intent and modeled in-memory external-publication-acknowledgement record. Run 280
closes that source/test external-publication-receipt consumer /
external-publication-acknowledgement interface gap only.

Run 280 introduces an **external-publication-acknowledgement interface boundary**,
**not** a replacement for any existing module. It consumes the typed Run 278
external-publication-receipt outcome
(`DurableCompletionExternalPublicationReceiptOutcome`) as an
`external_publication_receipt_binding` and projects it onto an
external-publication-acknowledgement request intent; only the Run 278
`ExternalPublicationReceiptRecorded` outcome creates an
external-publication-acknowledgement request, and a Run 278
`ExternalPublicationReceiptDuplicateIdempotent` may only match an
already-recorded external-publication-acknowledgement record and never creates a
new one. The external-publication-acknowledgement layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 280 adds a modeled durable-completion external-publication-receipt
  consumer / external-publication-acknowledgement interface boundary.
* The boundary consumes only Run 278 `ExternalPublicationReceiptRecorded`.
* Run 278 `ExternalPublicationReceiptRecorded` is required before any
  external-publication-acknowledgement request can exist.
* Only `ExternalPublicationAcknowledgementRecorded` authorizes modeled
  external-publication-acknowledgement state.
* The fixture external-publication-acknowledgement sink is DevNet/TestNet
  evidence-only and in-memory only.
* Production/MainNet/external external-publication-acknowledgement sinks remain
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
* No real audit-ledger acknowledgement is implemented.
* No real production backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No wire/schema/marker/sequence/trust-bundle change is implemented.
* No MainNet governance is enabled.
* No MainNet peer-driven apply is enabled.
* No validator-set rotation is implemented.
* No policy-change enablement is implemented.
* No Run 070 call.
* No `LivePqcTrustState` mutation.
* Rejected external-publication-acknowledgement paths are non-mutating.
* Run 280 keeps the C4/C5 matrix taxonomy present and unweakened: it separates
  boundary readiness from production readiness.
* Yellow boundary rows do not equal production backend implementation.
* Red production backend rows remain Red until production implementation and
  release-binary evidence exist.
* The matrix taxonomy is not weakened and closure criteria are not weakened.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_external_publication_acknowledgement.rs`

Run 280 adds a source module (registered in `lib.rs`) that defines:

* typed external-publication-acknowledgement inputs / policy / identity / bindings
  (`DurableCompletionExternalPublicationAcknowledgementKind`,
  `DurableCompletionExternalPublicationAcknowledgementPolicy`,
  `DurableCompletionExternalPublicationAcknowledgementIdentity`,
  `DurableCompletionExternalPublicationAcknowledgementInput`,
  `DurableCompletionExternalPublicationAcknowledgementExpectations`,
  `DurableCompletionExternalPublicationAcknowledgementRequest`,
  `DurableCompletionExternalPublicationAcknowledgementOutcome`);
* an external-publication-acknowledgement sink trait
  (`GovernanceDurableCompletionExternalPublicationAcknowledgementSink`) with a
  DevNet/TestNet in-memory fixture implementation
  (`FixtureDurableCompletionExternalPublicationAcknowledgementSink`) and
  reachable-but-unavailable `ProductionExternalPublicationAcknowledgementSink`,
  `MainNetExternalPublicationAcknowledgementSink`, and
  `ExternalExternalPublicationAcknowledgementSink` implementations;
* an in-memory ledger
  (`DurableCompletionExternalPublicationAcknowledgementLedger`);
* projection / evaluation / recovery helpers
  (`project_external_publication_receipt_outcome_to_external_publication_acknowledgement_request`,
  `evaluate_durable_completion_external_publication_acknowledgement`,
  `recover_durable_completion_external_publication_acknowledgement_window`,
  `external_publication_acknowledgement_outcome_authorizes_record`,
  `external_publication_acknowledgement_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_external_publication_acknowledgement_receipt_required`,
  `durable_completion_external_publication_acknowledgement_record_required_before_reported`,
  `durable_completion_external_publication_acknowledgement_no_real_external_publication_receipt`,
  `durable_completion_external_publication_acknowledgement_no_real_external_publication_acknowledgement`,
  `durable_completion_external_publication_acknowledgement_sink_receipt_required`,
  `durable_completion_external_publication_acknowledgement_never_calls_run_070`,
  `durable_completion_external_publication_acknowledgement_never_mutates_live_pqc_trust_state`.

The fixture external-publication-acknowledgement sink mutates only the in-memory
`DurableCompletionExternalPublicationAcknowledgementLedger` and exposes an
invocation counter so tests prove non-recording receipt paths and pre-receipt
rejections never invoke it.

## Tests

`crates/qbind-node/tests/run_280_durable_completion_external_publication_acknowledgement_tests.rs`

Each Run 280 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 → 260
→ 262 → 264 → 266 → 268 → 270 → 272 → 274 → 276 → 278 chain (real
`evaluate_durable_completion_external_publication_receipt` round-trip on top of
the real Run 278 external-publication-receipt chain) before evaluating the Run 280
external-publication-acknowledgement, so the carried digests are real attached
records and never faked, unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching the acknowledgement; DevNet/TestNet fixture chains recording exactly one
in-memory acknowledgement only after the full chain; governance-action ordering;
duplicate idempotency; Run 278 duplicate-idempotent receipt only matching an
existing acknowledgement; production/MainNet/external reachable-but-unavailable
fail-closed paths; MainNet peer-driven apply refusal first; validator-set rotation /
policy-change unsupported; the full binding-mismatch and malformed-request rejection
matrix; equivocation fail-closed; the external-publication-receipt request-intent
matrix; and the recovery / crash-window matrix (pre-receipt windows fail closed;
after-receipt-request before-record fails closed; after-receipt-record
before-success requires an explicit matching record; after-receipt-success
recovers as recorded; ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

The full Run 280 validation corpus below was **re-executed from scratch** in the
Run 280 closure pass (not just the Run 280 test). Every command returned `rc=0`
with the exact pass counts shown; no command failed.

* `cargo build -p qbind-node --lib` — OK. rc=0.
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
* `cargo test -p qbind-node --test run_254_modeled_durable_completion_attestation_projection_tests` — ok. 108 passed; 0 failed.
* `cargo test -p qbind-node --test run_252_modeled_durable_completion_finalization_projection_tests` — ok. 98 passed; 0 failed.
* `cargo test -p qbind-node --test run_250_modeled_durable_consume_completion_reporter_tests` — ok. 88 passed; 0 failed.
* `cargo test -p qbind-node --test run_248_modeled_durable_consume_projection_sink_tests` — ok. 68 passed; 0 failed.
* `cargo test -p qbind-node --test run_246_governance_modeled_end_to_end_pipeline_tests` — ok. 47 passed; 0 failed.
* `cargo test -p qbind-node --test run_244_modeled_governance_trust_mutation_applier_tests` — ok. 45 passed; 0 failed.
* `cargo test -p qbind-node --test run_242_governance_execution_mutation_engine_tests` — ok. 38 passed; 0 failed.
* `cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests` — ok. 63 passed; 0 failed.
* `cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests` — ok. 68 passed; 0 failed.
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests` — ok. 56 passed; 0 failed.
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests` — ok. 58 passed; 0 failed.
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests` — ok. 47 passed; 0 failed.
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests` — ok. 52 passed; 0 failed.
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests` — ok. 48 passed; 0 failed.
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests` — ok. 59 passed; 0 failed.
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests` — ok. 48 passed; 0 failed.
* `cargo test -p qbind-node --lib pqc_authority` — ok. 164 passed; 0 failed.
* `cargo test -p qbind-node --lib` — ok. 1365 passed; 0 failed.

## Notes on carried names

The Run 280 module is a shift-by-one continuation of the Run 278 boundary, so the
carried/upstream names from the Run 252 finalization-projection stage are preserved
deliberately:

* The carried Run 252 outcome
  (`GovernanceModeledDurableCompletionFinalizationOutcome`), its
  `finalization_decision_digest` field, and the deep finalization-projection
  predicate retain their upstream names because they reference upstream modeled
  boundaries, not the Run 280 own concept.
* The Run 280 own concept is `external_publication_acknowledgement`; the
  immediately prior Run 278 concept is carried as `external_publication_receipt`.

## C4 / C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 280 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 281 — release-binary evidence for the Run 280 durable-completion
external-publication-receipt consumer / external-publication-acknowledgement
interface boundary.
