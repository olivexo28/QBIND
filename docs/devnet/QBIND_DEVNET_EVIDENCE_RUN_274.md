# QBIND DevNet evidence — Run 274

**Title.** Source/test durable-completion **settlement-outcome report
consumer / settlement-outcome publication interface boundary**.

**Status.** PASS (source/test only). Run 274 extends the Run 272 modeled
durable-completion settlement-outcome report interface boundary with a
typed, mockable, in-memory **settlement-outcome publication sink boundary** that models
the first post-report settlement-outcome publication step a future production
settlement subsystem might use **after** a Run 272
`SettlementOutcomeReportRecorded` outcome has been recorded. Run 272 proved
that a modeled settlement-outcome report record is recorded only after the
Run 270 `SettlementReceiptAcknowledgementRecorded` outcome. What was still missing was a typed
source/test boundary that converts a valid recorded settlement-outcome report state into a typed settlement-outcome publication intent and modeled
in-memory settlement-outcome publication record. Run 274 closes that source/test
settlement-outcome report consumer / settlement-outcome publication interface gap
only.

Run 274 introduces a **settlement-outcome publication interface boundary**, **not** a
replacement for any existing module. It consumes the typed Run 272 settlement
outcome report outcome
(`DurableCompletionSettlementOutcomeReportOutcome`) as a
`settlement_outcome_report_binding` and projects it onto a
settlement-outcome publication request intent; only the Run 272
`SettlementOutcomeReportRecorded` outcome creates a settlement-outcome
publication request, and a Run 272 `SettlementOutcomeReportDuplicateIdempotent`
may only match an already-recorded settlement-outcome publication record and never creates
a new one. The settlement-outcome publication layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 274 adds a modeled durable-completion settlement-outcome report
  consumer / settlement-outcome publication interface boundary.
* The boundary consumes only Run 272 `SettlementOutcomeReportRecorded`.
* Run 272 `SettlementOutcomeReportRecorded` is required before any
  settlement-outcome publication request can exist.
* Only `SettlementOutcomePublicationRecorded` authorizes modeled settlement-outcome
  publication state.
* The fixture outcome-publication sink is DevNet/TestNet evidence-only and in-memory
  only.
* Production/MainNet/external outcome-publication sinks remain reachable but
  unavailable/fail-closed.
* No real settlement is implemented.
* No real settlement finality is implemented.
* No real settlement receipt is implemented.
* No real settlement-receipt acknowledgement is implemented.
* No real settlement-finality projection is implemented.
* No real settlement-outcome report backend is implemented.
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
* Rejected outcome-publication paths are non-mutating.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_settlement_outcome_publication.rs`

Run 274 adds a source module (registered in `lib.rs`) that defines:

* typed settlement-outcome publication inputs / policy / identity / bindings
  (`DurableCompletionSettlementOutcomePublicationKind`,
  `DurableCompletionSettlementOutcomePublicationPolicy`,
  `DurableCompletionSettlementOutcomePublicationIdentity`,
  `DurableCompletionSettlementOutcomePublicationInput`,
  `DurableCompletionSettlementOutcomePublicationExpectations`,
  `DurableCompletionSettlementOutcomePublicationRequest`,
  `DurableCompletionSettlementOutcomePublicationOutcome`);
* a settlement-outcome publication sink trait
  (`GovernanceDurableCompletionSettlementOutcomePublicationSink`) with a DevNet/TestNet
  in-memory fixture implementation
  (`FixtureDurableCompletionSettlementOutcomePublicationSink`) and
  reachable-but-unavailable `ProductionSettlementOutcomePublicationSink`,
  `MainNetSettlementOutcomePublicationSink`, and `ExternalSettlementOutcomePublicationSink`
  implementations;
* an in-memory ledger (`DurableCompletionSettlementOutcomePublicationLedger`);
* projection / evaluation / recovery helpers
  (`project_settlement_outcome_report_outcome_to_outcome_publication_request`,
  `evaluate_durable_completion_settlement_outcome_publication`,
  `recover_durable_completion_settlement_outcome_publication_window`,
  `settlement_outcome_publication_outcome_authorizes_record`,
  `settlement_outcome_publication_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_settlement_outcome_publication_outcome_report_required`,
  `durable_completion_settlement_outcome_publication_record_required_before_reported`,
  `durable_completion_settlement_outcome_publication_no_real_settlement`,
  `durable_completion_settlement_outcome_publication_no_real_settlement_finality`,
  `durable_completion_settlement_outcome_publication_no_real_settlement_receipt`,
  `durable_completion_settlement_outcome_publication_no_real_settlement_outcome_report`,
  `durable_completion_settlement_outcome_publication_no_real_settlement_finality_projection`,
  `durable_completion_settlement_outcome_publication_no_real_settlement_outcome_publication`,
  `durable_completion_settlement_outcome_publication_never_calls_run_070`,
  `durable_completion_settlement_outcome_publication_never_mutates_live_pqc_trust_state`.

The fixture outcome-publication sink mutates only the in-memory
`DurableCompletionSettlementOutcomePublicationLedger` and exposes an invocation counter so
tests prove non-recording report paths and pre-publication rejections never
invoke it.

## Tests

`crates/qbind-node/tests/run_274_durable_completion_settlement_outcome_publication_tests.rs`

Each Run 274 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 → 260
→ 262 → 264 → 266 → 268 → 270 → 272 chain (real
`evaluate_durable_completion_settlement_outcome_report` round-trip on top of
the real Run 270 settlement-receipt-acknowledgement chain) before evaluating the Run 274
settlement-outcome publication, so the carried digests are real attached records and never
faked, unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching the publication; DevNet/TestNet fixture chains recording exactly one in-memory
publication only after the full chain; governance-action ordering; duplicate idempotency;
Run 272 duplicate-idempotent report only matching an existing publication;
production/MainNet/external reachable-but-unavailable fail-closed paths; MainNet
peer-driven apply refusal first; validator-set rotation / policy-change unsupported;
the full binding-mismatch and malformed-request rejection matrix; equivocation
fail-closed; the outcome-report request-intent matrix; and the recovery /
crash-window matrix (pre-publication windows fail closed; after-publication-request
before-record fails closed; after-publication-record before-success requires an explicit
matching record; after-publication-success recovers as recorded;
ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

The full Run 274 validation corpus below was **re-executed from scratch** in the
Run 274 closure pass (not just the Run 274 test). Every command returned `rc=0`
with the exact pass counts shown; no command failed.

* `cargo build -p qbind-node --lib` — OK. rc=0.
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

The Run 274 module is a shift-by-one continuation of the Run 272 boundary, so the
carried/upstream names from the Run 252 finalization-projection stage are preserved
deliberately:

* The carried Run 252 outcome
  (`GovernanceModeledDurableCompletionFinalizationOutcome`), its
  `finalization_decision_digest` field, and the deep finalization-projection
  predicate retain their upstream names because they reference upstream modeled
  boundaries, not the Run 274 own concept.
* The Run 274 own concept is `settlement_outcome_publication`; the immediately prior Run
  272 concept is carried as `settlement_outcome_report`.

## C4 / C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 274 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 275 — release-binary evidence for the Run 274 durable-completion
settlement-outcome report consumer / settlement-outcome publication interface
boundary.