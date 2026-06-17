# QBIND DevNet evidence — Run 272

**Title.** Source/test durable-completion **settlement-receipt acknowledgement
consumer / settlement-outcome report interface boundary**.

**Status.** PASS (source/test only). Run 272 extends the Run 270 modeled
durable-completion settlement-receipt acknowledgement interface boundary with a
typed, mockable, in-memory **settlement-outcome report sink boundary** that models
the first post-acknowledgement settlement-outcome report step a future production
settlement subsystem might use **after** a Run 270
`SettlementReceiptAcknowledgementRecorded` outcome has been recorded. Run 270 proved
that a modeled settlement-receipt acknowledgement record is recorded only after the
Run 268 `SettlementFinalizationRecorded` outcome. What was still missing was a typed
source/test boundary that converts a valid recorded settlement-receipt
acknowledgement state into a typed settlement-outcome report intent and modeled
in-memory settlement-outcome report record. Run 272 closes that source/test
settlement-receipt acknowledgement consumer / settlement-outcome report interface gap
only.

Run 272 introduces a **settlement-outcome report interface boundary**, **not** a
replacement for any existing module. It consumes the typed Run 270 settlement
receipt acknowledgement outcome
(`DurableCompletionSettlementReceiptAcknowledgementOutcome`) as a
`settlement_receipt_acknowledgement_binding` and projects it onto a
settlement-outcome report request intent; only the Run 270
`SettlementReceiptAcknowledgementRecorded` outcome creates a settlement-outcome
report request, and a Run 270 `SettlementReceiptAcknowledgementDuplicateIdempotent`
may only match an already-recorded settlement-outcome report record and never creates
a new one. The settlement-outcome report layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 272 adds a modeled durable-completion settlement-receipt acknowledgement
  consumer / settlement-outcome report interface boundary.
* The boundary consumes only Run 270 `SettlementReceiptAcknowledgementRecorded`.
* Run 270 `SettlementReceiptAcknowledgementRecorded` is required before any
  settlement-outcome report request can exist.
* Only `SettlementOutcomeReportRecorded` authorizes modeled settlement-outcome
  report state.
* The fixture outcome-report sink is DevNet/TestNet evidence-only and in-memory
  only.
* Production/MainNet/external outcome-report sinks remain reachable but
  unavailable/fail-closed.
* No real settlement is implemented.
* No real settlement finality is implemented.
* No real settlement receipt is implemented.
* No real settlement-receipt acknowledgement is implemented.
* No real settlement-finality projection is implemented.
* No real settlement-outcome publication is implemented.
* No real audit-ledger acknowledgement is implemented.
* No real external-publication confirmation is implemented.
* No real external publication is implemented.
* No real production backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No wire/schema/marker/sequence/trust-bundle change is implemented.
* No MainNet governance is enabled.
* No MainNet peer-driven apply is enabled.
* No validator-set rotation is implemented.
* No policy-change enablement is implemented.
* No Run 070 call.
* No `LivePqcTrustState` mutation.
* Rejected outcome-report paths are non-mutating.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_settlement_outcome_report.rs`

Run 272 adds a source module (registered in `lib.rs`) that defines:

* typed settlement-outcome report inputs / policy / identity / bindings
  (`DurableCompletionSettlementOutcomeReportKind`,
  `DurableCompletionSettlementOutcomeReportPolicy`,
  `DurableCompletionSettlementOutcomeReportIdentity`,
  `DurableCompletionSettlementOutcomeReportInput`,
  `DurableCompletionSettlementOutcomeReportExpectations`,
  `DurableCompletionSettlementOutcomeReportRequest`,
  `DurableCompletionSettlementOutcomeReportOutcome`);
* a settlement-outcome report sink trait
  (`GovernanceDurableCompletionSettlementOutcomeReportSink`) with a DevNet/TestNet
  in-memory fixture implementation
  (`FixtureDurableCompletionSettlementOutcomeReportSink`) and
  reachable-but-unavailable `ProductionSettlementOutcomeReportSink`,
  `MainNetSettlementOutcomeReportSink`, and `ExternalSettlementOutcomeReportSink`
  implementations;
* an in-memory ledger (`DurableCompletionSettlementOutcomeReportLedger`);
* projection / evaluation / recovery helpers
  (`project_settlement_receipt_acknowledgement_outcome_to_outcome_report_request`,
  `evaluate_durable_completion_settlement_outcome_report`,
  `recover_durable_completion_settlement_outcome_report_window`,
  `settlement_outcome_report_outcome_authorizes_record`,
  `settlement_outcome_report_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_settlement_outcome_report_receipt_acknowledgement_required`,
  `durable_completion_settlement_outcome_report_record_required_before_reported`,
  `durable_completion_settlement_outcome_report_no_real_settlement`,
  `durable_completion_settlement_outcome_report_no_real_settlement_finality`,
  `durable_completion_settlement_outcome_report_no_real_settlement_receipt`,
  `durable_completion_settlement_outcome_report_no_real_settlement_receipt_acknowledgement`,
  `durable_completion_settlement_outcome_report_no_real_settlement_finality_projection`,
  `durable_completion_settlement_outcome_report_no_real_settlement_outcome_publication`,
  `durable_completion_settlement_outcome_report_never_calls_run_070`,
  `durable_completion_settlement_outcome_report_never_mutates_live_pqc_trust_state`.

The fixture outcome-report sink mutates only the in-memory
`DurableCompletionSettlementOutcomeReportLedger` and exposes an invocation counter so
tests prove non-recording acknowledgement paths and pre-report rejections never
invoke it.

## Tests

`crates/qbind-node/tests/run_272_durable_completion_settlement_outcome_report_tests.rs`

Each Run 272 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 → 260
→ 262 → 264 → 266 → 268 → 270 chain (real
`evaluate_durable_completion_settlement_receipt_acknowledgement` round-trip on top of
the real Run 268 settlement-finalization chain) before evaluating the Run 272
settlement-outcome report, so the carried digests are real attached records and never
faked, unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching the report; DevNet/TestNet fixture chains recording exactly one in-memory
report only after the full chain; governance-action ordering; duplicate idempotency;
Run 270 duplicate-idempotent acknowledgement only matching an existing report;
production/MainNet/external reachable-but-unavailable fail-closed paths; MainNet
peer-driven apply refusal first; validator-set rotation / policy-change unsupported;
the full binding-mismatch and malformed-request rejection matrix; equivocation
fail-closed; the receipt-acknowledgement request-intent matrix; and the recovery /
crash-window matrix (pre-report windows fail closed; after-report-request
before-record fails closed; after-report-record before-success requires an explicit
matching record; after-report-success recovers as recorded;
ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

The full Run 272 validation corpus below was **re-executed from scratch** in the
Run 272 closure pass (not just the Run 272 test). Every command returned `rc=0`
with the exact pass counts shown; no command failed.

* `cargo build -p qbind-node --lib` — OK. rc=0.
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

The Run 272 module is a shift-by-one continuation of the Run 270 boundary, so the
carried/upstream names from the Run 252 finalization-projection stage are preserved
deliberately:

* The carried Run 252 outcome
  (`GovernanceModeledDurableCompletionFinalizationOutcome`), its
  `finalization_decision_digest` field, and the deep finalization-projection
  predicate retain their upstream names because they reference upstream modeled
  boundaries, not the Run 272 own concept.
* The Run 272 own concept is `settlement_outcome_report`; the immediately prior Run
  270 concept is carried as `settlement_receipt_acknowledgement`.

## C4 / C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 272 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 273 — release-binary evidence for the Run 272 durable-completion
settlement-receipt acknowledgement consumer / settlement-outcome report interface
boundary.