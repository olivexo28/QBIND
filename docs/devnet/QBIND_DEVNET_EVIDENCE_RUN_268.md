# QBIND DevNet evidence — Run 268

**Title.** Source/test durable-completion **settlement-finalization /
settlement-receipt interface boundary**.

**Status.** PASS (source/test only). Run 268 extends the Run 266 modeled
durable-completion settlement-commitment interface boundary with a typed,
mockable, in-memory **settlement-finalization sink boundary** that models the first
post-commitment settlement-receipt step a future production settlement subsystem
might use **after** a Run 266 `SettlementCommitmentRecorded` outcome has been
recorded. Run 266 proved that a modeled settlement-commitment record is recorded
only after the Run 264 `SettlementProjectionRecorded` outcome. What was still
missing was a typed source/test boundary that converts a valid recorded
settlement-commitment state into a typed settlement-finalization intent and modeled
in-memory settlement-finalization receipt record. Run 268 closes that source/test
settlement-finalization interface gap only.

Run 268 introduces a **settlement-finalization interface boundary**, **not** a
replacement for any existing module. It consumes the typed Run 266 settlement
commitment outcome (`DurableCompletionSettlementCommitmentOutcome`) as a
`settlement_commitment_binding` and projects it onto a settlement-finalization
request intent; only the Run 266 `SettlementCommitmentRecorded` outcome creates a
settlement-finalization request, and a Run 266
`SettlementCommitmentDuplicateIdempotent` may only match an already-recorded
settlement-finalization record and never creates a new one. The
settlement-finalization layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 268 adds a modeled durable-completion settlement-finalization /
  settlement-receipt interface boundary.
* The boundary consumes only Run 266 `SettlementCommitmentRecorded`.
* Run 266 `SettlementCommitmentRecorded` is required before any
  settlement-finalization request can exist.
* Only `SettlementFinalizationRecorded` authorizes modeled
  settlement-finalization receipt state.
* The fixture finalization sink is DevNet/TestNet evidence-only and in-memory only.
* Production/MainNet/external finalization sinks remain reachable but
  unavailable/fail-closed.
* No real settlement is implemented.
* No real settlement finality is implemented.
* No real settlement receipt is implemented.
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
* Rejected finalization paths are non-mutating.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_settlement_finalization.rs`

Run 268 adds a source module (registered in `lib.rs`) that defines:

* typed settlement-finalization inputs / policy / identity / bindings
  (`DurableCompletionSettlementFinalizationKind`,
  `DurableCompletionSettlementFinalizationPolicy`,
  `DurableCompletionSettlementFinalizationIdentity`,
  `DurableCompletionSettlementFinalizationInput`,
  `DurableCompletionSettlementFinalizationExpectations`,
  `DurableCompletionSettlementFinalizationRequest`,
  `DurableCompletionSettlementFinalizationResponse`,
  `DurableCompletionSettlementFinalizationRecord`,
  `DurableCompletionSettlementFinalizationDigest`,
  `DurableCompletionSettlementFinalizationTranscriptDigest`,
  `DurableCompletionSettlementFinalizationOutcome`);
* a settlement-finalization sink trait
  (`GovernanceDurableCompletionSettlementFinalizationSink`) with a DevNet/TestNet
  in-memory fixture implementation
  (`FixtureDurableCompletionSettlementFinalizationSink`) and
  reachable-but-unavailable `ProductionSettlementFinalizationSink`,
  `MainNetSettlementFinalizationSink`, and `ExternalSettlementFinalizationSink`
  implementations;
* an in-memory ledger (`DurableCompletionSettlementFinalizationLedger`,
  `DurableCompletionSettlementFinalizationLedgerRecord`,
  `DurableCompletionSettlementFinalizationLedgerSnapshot`,
  `DurableCompletionSettlementFinalizationLedgerStatus`);
* projection / evaluation / recovery helpers
  (`project_settlement_commitment_outcome_to_finalization_request`,
  `evaluate_durable_completion_settlement_finalization`,
  `recover_durable_completion_settlement_finalization_window`,
  `settlement_finalization_outcome_authorizes_record`,
  `settlement_finalization_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_settlement_finalization_commitment_required`,
  `durable_completion_settlement_finalization_record_required_before_finalized`,
  `durable_completion_settlement_finalization_no_real_settlement`,
  `durable_completion_settlement_finalization_no_real_settlement_finality`,
  `durable_completion_settlement_finalization_no_real_settlement_receipt`,
  `durable_completion_settlement_finalization_never_calls_run_070`,
  `durable_completion_settlement_finalization_never_mutates_live_pqc_trust_state`.

The fixture finalization sink mutates only the in-memory
`DurableCompletionSettlementFinalizationLedger` and exposes an invocation counter so
tests prove non-recording commitment paths and pre-finalization rejections never
invoke it.

## Tests

`crates/qbind-node/tests/run_268_durable_completion_settlement_finalization_tests.rs`

Each Run 268 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 →
260 → 262 → 264 → 266 chain (real
`evaluate_durable_completion_settlement_commitment` round-trip on top of the real
Run 264 settlement-projection chain) before evaluating the Run 268 settlement
finalization, so the carried digests are real attached records and never faked,
unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching finalization; DevNet/TestNet fixture chains recording exactly one in-memory
finalization only after the full chain; governance-action ordering; duplicate
idempotency; Run 266 duplicate-idempotent commitment only matching an existing
finalization; production/MainNet/external reachable-but-unavailable fail-closed
paths; MainNet peer-driven apply refusal first; validator-set rotation /
policy-change unsupported; the full binding-mismatch and malformed-request rejection
matrix; equivocation fail-closed; the commitment request-intent matrix; and the
recovery / crash-window matrix (pre-finalization windows fail closed;
after-finalization-request before-record fails closed; after-finalization-record
before-success requires an explicit matching record; after-finalization-success
recovers as recorded; ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

* `cargo build -p qbind-node --lib` — OK.
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

## C4 / C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 268 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 269 — release-binary evidence for the Run 268 durable-completion
settlement-finalization / settlement-receipt interface boundary.
