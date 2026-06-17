# QBIND DevNet evidence — Run 270

**Title.** Source/test durable-completion **settlement-receipt acknowledgement /
settlement-finality projection interface boundary**.

**Status.** PASS (source/test only). Run 270 extends the Run 268 modeled
durable-completion settlement-finalization interface boundary with a typed,
mockable, in-memory **settlement-receipt acknowledgement sink boundary** that models
the first post-finalization settlement-finality projection step a future production
settlement subsystem might use **after** a Run 268 `SettlementFinalizationRecorded`
outcome has been recorded. Run 268 proved that a modeled settlement-finalization
record is recorded only after the Run 266 `SettlementCommitmentRecorded` outcome.
What was still missing was a typed source/test boundary that converts a valid
recorded settlement-finalization state into a typed settlement-receipt
acknowledgement intent and modeled in-memory settlement-receipt acknowledgement
record. Run 270 closes that source/test settlement-receipt acknowledgement /
settlement-finality projection interface gap only.

Run 270 introduces a **settlement-receipt acknowledgement interface boundary**,
**not** a replacement for any existing module. It consumes the typed Run 268
settlement finalization outcome (`DurableCompletionSettlementFinalizationOutcome`)
as a `settlement_finalization_binding` and projects it onto a settlement-receipt
acknowledgement request intent; only the Run 268 `SettlementFinalizationRecorded`
outcome creates a settlement-receipt acknowledgement request, and a Run 268
`SettlementFinalizationDuplicateIdempotent` may only match an already-recorded
settlement-receipt acknowledgement record and never creates a new one. The
settlement-receipt acknowledgement layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 270 adds a modeled durable-completion settlement-receipt acknowledgement /
  settlement-finality projection interface boundary.
* The boundary consumes only Run 268 `SettlementFinalizationRecorded`.
* Run 268 `SettlementFinalizationRecorded` is required before any
  settlement-receipt acknowledgement request can exist.
* Only `SettlementReceiptAcknowledgementRecorded` authorizes modeled
  settlement-receipt acknowledgement / settlement-finality projection state.
* The fixture acknowledgement sink is DevNet/TestNet evidence-only and in-memory
  only.
* Production/MainNet/external acknowledgement sinks remain reachable but
  unavailable/fail-closed.
* No real settlement is implemented.
* No real settlement finality is implemented.
* No real settlement receipt is implemented.
* No real settlement-receipt acknowledgement is implemented.
* No real settlement-finality projection is implemented.
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
* Rejected receipt-acknowledgement paths are non-mutating.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_settlement_receipt_acknowledgement.rs`

Run 270 adds a source module (registered in `lib.rs`) that defines:

* typed settlement-receipt acknowledgement inputs / policy / identity / bindings
  (`DurableCompletionSettlementReceiptAcknowledgementKind`,
  `DurableCompletionSettlementReceiptAcknowledgementPolicy`,
  `DurableCompletionSettlementReceiptAcknowledgementIdentity`,
  `DurableCompletionSettlementReceiptAcknowledgementInput`,
  `DurableCompletionSettlementReceiptAcknowledgementExpectations`,
  `DurableCompletionSettlementReceiptAcknowledgementRequest`,
  `DurableCompletionSettlementReceiptAcknowledgementResponse`,
  `DurableCompletionSettlementReceiptAcknowledgementRecord`,
  `DurableCompletionSettlementReceiptAcknowledgementDigest`,
  `DurableCompletionSettlementReceiptAcknowledgementTranscriptDigest`,
  `DurableCompletionSettlementReceiptAcknowledgementOutcome`);
* a settlement-receipt acknowledgement sink trait
  (`GovernanceDurableCompletionSettlementReceiptAcknowledgementSink`) with a
  DevNet/TestNet in-memory fixture implementation
  (`FixtureDurableCompletionSettlementReceiptAcknowledgementSink`) and
  reachable-but-unavailable `ProductionSettlementReceiptAcknowledgementSink`,
  `MainNetSettlementReceiptAcknowledgementSink`, and
  `ExternalSettlementReceiptAcknowledgementSink` implementations;
* an in-memory ledger
  (`DurableCompletionSettlementReceiptAcknowledgementLedger`,
  `DurableCompletionSettlementReceiptAcknowledgementLedgerRecord`,
  `DurableCompletionSettlementReceiptAcknowledgementLedgerSnapshot`,
  `DurableCompletionSettlementReceiptAcknowledgementLedgerStatus`);
* projection / evaluation / recovery helpers
  (`project_settlement_finalization_outcome_to_receipt_acknowledgement_request`,
  `evaluate_durable_completion_settlement_receipt_acknowledgement`,
  `recover_durable_completion_settlement_receipt_acknowledgement_window`,
  `settlement_receipt_acknowledgement_outcome_authorizes_record`,
  `settlement_receipt_acknowledgement_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_settlement_receipt_acknowledgement_finalization_required`,
  `durable_completion_settlement_receipt_acknowledgement_record_required_before_acknowledged`,
  `durable_completion_settlement_receipt_acknowledgement_no_real_settlement`,
  `durable_completion_settlement_receipt_acknowledgement_no_real_settlement_finality`,
  `durable_completion_settlement_receipt_acknowledgement_no_real_settlement_receipt`,
  `durable_completion_settlement_receipt_acknowledgement_no_real_settlement_receipt_acknowledgement`,
  `durable_completion_settlement_receipt_acknowledgement_no_real_settlement_finality_projection`,
  `durable_completion_settlement_receipt_acknowledgement_never_calls_run_070`,
  `durable_completion_settlement_receipt_acknowledgement_never_mutates_live_pqc_trust_state`.

The fixture acknowledgement sink mutates only the in-memory
`DurableCompletionSettlementReceiptAcknowledgementLedger` and exposes an invocation
counter so tests prove non-recording finalization paths and pre-acknowledgement
rejections never invoke it.

## Tests

`crates/qbind-node/tests/run_270_durable_completion_settlement_receipt_acknowledgement_tests.rs`

Each Run 270 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 →
260 → 262 → 264 → 266 → 268 chain (real
`evaluate_durable_completion_settlement_finalization` round-trip on top of the real
Run 266 settlement-commitment chain) before evaluating the Run 270 settlement
receipt acknowledgement, so the carried digests are real attached records and never
faked, unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching acknowledgement; DevNet/TestNet fixture chains recording exactly one
in-memory acknowledgement only after the full chain; governance-action ordering;
duplicate idempotency; Run 268 duplicate-idempotent finalization only matching an
existing acknowledgement; production/MainNet/external reachable-but-unavailable
fail-closed paths; MainNet peer-driven apply refusal first; validator-set rotation /
policy-change unsupported; the full binding-mismatch and malformed-request rejection
matrix; equivocation fail-closed; the finalization request-intent matrix; and the
recovery / crash-window matrix (pre-acknowledgement windows fail closed;
after-acknowledgement-request before-record fails closed; after-acknowledgement-record
before-success requires an explicit matching record; after-acknowledgement-success
recovers as recorded; ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

The full Run 270 validation corpus below was **re-executed from scratch** in the
Run 270 closure pass (not just the Run 270 test). Every command returned `rc=0`
with the exact pass counts shown; no command failed.

* `cargo build -p qbind-node --lib` — OK. rc=0.
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

The Run 270 module is a shift-by-one continuation of the Run 268 boundary, so two
carried/stale names are preserved deliberately:

* The Run 252 finalization-projection-required predicate is carried as
  `durable_completion_settlement_receipt_acknowledgement_finalization_projection_required`
  to avoid colliding with the new prior-required predicate
  `durable_completion_settlement_receipt_acknowledgement_finalization_required`.
* The carried Run 252 outcome
  (`GovernanceModeledDurableCompletionFinalizationOutcome`), its
  `finalization_decision_digest` field, and the `no_commitment()` predicate retain
  their upstream names because they reference upstream modeled boundaries, not the
  Run 270 own concept.

## C4 / C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 270 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 271 — release-binary evidence for the Run 270 durable-completion
settlement-receipt acknowledgement / settlement-finality projection interface
boundary.