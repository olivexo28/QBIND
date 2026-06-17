# QBIND DevNet evidence — Run 266

**Title.** Source/test durable-completion **settlement-commitment /
ledger-finalization interface boundary**.

**Status.** PASS (source/test only). Run 266 extends the Run 264 modeled
durable-completion consumer settlement-projection interface boundary with a typed,
mockable, in-memory **settlement-commitment sink boundary** that models the first
post-projection ledger-finalization step a future production settlement subsystem
might use **after** a Run 264 `SettlementProjectionRecorded` outcome has been
recorded. Run 264 proved that a modeled settlement-projection record is recorded
only after the Run 262 `AcknowledgementConsumed` outcome. What was still missing
was a typed source/test boundary that converts a valid recorded
settlement-projection state into a typed settlement-commitment intent and modeled
in-memory settlement-commitment record. Run 266 closes that source/test
settlement-commitment interface gap only.

Run 266 introduces a **settlement-commitment interface boundary**, **not** a
replacement for any existing module. It consumes the typed Run 264 settlement
projection outcome (`DurableCompletionConsumerSettlementProjectionOutcome`) as a
`settlement_projection_binding` and projects it onto a settlement-commitment request
intent; only the Run 264 `SettlementProjectionRecorded` outcome creates a
settlement-commitment request, and a Run 264
`SettlementProjectionDuplicateIdempotent` may only match an already-recorded
settlement-commitment record and never creates a new one. The settlement-commitment
layer is a **model only**.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 266 adds a modeled durable-completion settlement-projection commitment /
  ledger-finalization interface boundary.
* The boundary consumes only Run 264 `SettlementProjectionRecorded`.
* Run 264 `SettlementProjectionRecorded` is required before any
  settlement-commitment request can exist.
* Only `SettlementCommitmentRecorded` authorizes modeled settlement-commitment
  state.
* The fixture commitment sink is DevNet/TestNet evidence-only and in-memory only.
* Production/MainNet/external commitment sinks remain reachable but
  unavailable/fail-closed.
* No real settlement is implemented.
* No real settlement finality is implemented.
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
* Rejected commitment paths are non-mutating.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Module

`crates/qbind-node/src/pqc_governance_durable_completion_settlement_commitment.rs`

Run 266 adds a source module (registered in `lib.rs`) that defines:

* typed settlement-commitment inputs / policy / identity / bindings
  (`DurableCompletionSettlementCommitmentKind`,
  `DurableCompletionSettlementCommitmentPolicy`,
  `DurableCompletionSettlementCommitmentIdentity`,
  `DurableCompletionSettlementCommitmentInput`,
  `DurableCompletionSettlementCommitmentExpectations`,
  `DurableCompletionSettlementCommitmentRequest`,
  `DurableCompletionSettlementCommitmentResponse`,
  `DurableCompletionSettlementCommitmentRecord`,
  `DurableCompletionSettlementCommitmentDigest`,
  `DurableCompletionSettlementCommitmentTranscriptDigest`,
  `DurableCompletionSettlementCommitmentOutcome`);
* a settlement-commitment sink trait
  (`GovernanceDurableCompletionSettlementCommitmentSink`) with a DevNet/TestNet
  in-memory fixture implementation
  (`FixtureDurableCompletionSettlementCommitmentSink`) and reachable-but-unavailable
  `ProductionSettlementCommitmentSink`, `MainNetSettlementCommitmentSink`, and
  `ExternalSettlementCommitmentSink` implementations;
* an in-memory ledger (`DurableCompletionSettlementCommitmentLedger`,
  `DurableCompletionSettlementCommitmentLedgerRecord`,
  `DurableCompletionSettlementCommitmentLedgerSnapshot`,
  `DurableCompletionSettlementCommitmentLedgerStatus`);
* projection / evaluation / recovery helpers
  (`project_settlement_projection_outcome_to_commitment_request`,
  `evaluate_durable_completion_settlement_commitment`,
  `recover_durable_completion_settlement_commitment_window`,
  `settlement_commitment_outcome_authorizes_record`,
  `settlement_commitment_outcome_projects_to_recorded`);
* grep-verifiable invariant helpers including
  `durable_completion_settlement_commitment_projection_required`,
  `durable_completion_settlement_commitment_record_required_before_committed`,
  `durable_completion_settlement_commitment_no_real_settlement`,
  `durable_completion_settlement_commitment_never_calls_run_070`,
  `durable_completion_settlement_commitment_never_mutates_live_pqc_trust_state`.

The fixture commitment sink mutates only the in-memory
`DurableCompletionSettlementCommitmentLedger` and exposes an invocation counter so
tests prove non-recording projection paths and pre-commitment rejections never
invoke it.

## Tests

`crates/qbind-node/tests/run_266_durable_completion_settlement_commitment_tests.rs`

Each Run 266 test drives the real Run 246 → 248 → 250 → 252 → 254 → 256 → 258 →
260 → 262 → 264 chain (real
`evaluate_durable_completion_consumer_settlement_projection` round-trip on top of
the real Run 262 consumer chain) before evaluating the Run 266 settlement
commitment, so the carried digests are real attached records and never faked,
unattached values.

Coverage includes: disabled-policy legacy bypass; disabled upstream policies never
reaching commitment; DevNet/TestNet fixture chains recording exactly one in-memory
commitment only after the full chain; governance-action ordering; duplicate
idempotency; Run 264 duplicate-idempotent projection only matching an existing
commitment; production/MainNet/external reachable-but-unavailable fail-closed paths;
MainNet peer-driven apply refusal first; validator-set rotation / policy-change
unsupported; the full binding-mismatch and malformed-request rejection matrix;
equivocation fail-closed; the projection request-intent matrix; and the recovery /
crash-window matrix (pre-commitment windows fail closed; after-commitment-request
before-record fails closed; after-commitment-record before-success requires an
explicit matching record; after-commitment-success recovers as recorded;
ambiguous/record-failed/rollback/unknown windows fail closed).

## Validation commands and results

* `cargo build -p qbind-node --lib` — OK.
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

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 266 is a source/test interface
boundary and changes no production runtime, storage, wire, or trust state.

## Suggested next step

Run 267 — release-binary evidence for the Run 266 durable-completion
settlement-projection commitment / ledger-finalization interface boundary.