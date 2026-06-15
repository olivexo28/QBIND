# Run 249 — Release-binary modeled governance durable-consume projection sink evidence

## Scope

Run 249 is the release-binary evidence run for the Run 248 source/test
governance **modeled durable-consume projection sink boundary** in
`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`:

* the typed sink entry point `evaluate_modeled_durable_consume_projection_sink`
  and the pure/mockable sink trait
  `GovernanceModeledDurableConsumeProjectionSink` with its
  `FixtureModeledDurableConsumeProjectionSink`,
  `ProductionModeledDurableConsumeProjectionSink`, and
  `MainNetModeledDurableConsumeProjectionSink` implementations;
* the pipeline-outcome projector
  `project_pipeline_outcome_to_consume_sink_intent` and the `ConsumeSinkIntent`
  taxonomy (the only consume-authorizing pipeline outcome is
  `ModeledApplierAppliedAndDurableConsumeAuthorized`);
* the crash-window recovery helper
  `recover_modeled_durable_consume_projection_sink_window` and the
  `ModeledDurableConsumeReceiptWindow` classification;
* the typed bindings `GovernanceModeledDurableConsumeSinkInput`,
  `GovernanceModeledDurableConsumeSinkExpectations`,
  `GovernanceModeledDurableConsumeSinkPolicy`,
  `GovernanceModeledDurableConsumeSinkSurface`,
  `GovernanceModeledDurableConsumeSinkEnvironmentBinding`,
  `GovernanceModeledDurableConsumeSinkRuntimeBinding`,
  `GovernanceModeledDurableConsumeSinkReplayBinding`, and
  `GovernanceModeledDurableConsumeSinkPipelineBinding`;
* the receipt-ledger model `ModeledDurableConsumeReceiptLedger`,
  `ModeledDurableConsumeReceiptRecord`, `ModeledDurableConsumeReceiptSnapshot`,
  `ModeledDurableConsumeReceiptDigest`, `ModeledDurableConsumeReceiptStatus`, and
  the receipt-identity carrier `GovernanceModeledDurableConsumeSinkReceipt`;
* the sink kind `ModeledDurableConsumeSinkKind` and fault `ModeledConsumeSinkFault`;
* the `GovernanceModeledDurableConsumeSinkOutcome` taxonomy (the only
  receipt-recording outcome is `ConsumeReceiptRecorded`; a duplicate identical
  receipt is idempotent and a same-id different-digest receipt fails closed as
  equivocation) and its `tag()` / predicate surface
  (`sink_outcome_authorizes_modeled_consume_receipt`,
  `sink_outcome_projects_to_durable_completion`);
* the grep-verifiable invariant / fail-closed guard functions
  (`modeled_consume_sink_rejection_is_non_mutating`,
  `modeled_consume_sink_never_calls_run_070`,
  `modeled_consume_sink_never_mutates_live_pqc_trust_state`,
  `modeled_consume_sink_never_writes_sequence_or_marker`,
  `modeled_consume_sink_no_rocksdb_file_schema_migration_change`,
  `modeled_consume_sink_pipeline_success_required_before_receipt`,
  `modeled_consume_sink_receipt_record_required_before_consume`,
  `modeled_consume_sink_failed_record_never_consumes`,
  `modeled_consume_sink_rollback_never_consumes`,
  `modeled_consume_sink_ambiguous_window_fails_closed`,
  `modeled_consume_sink_mainnet_peer_driven_apply_refused_first`,
  `modeled_consume_sink_production_mainnet_unavailable`,
  `modeled_consume_sink_validator_set_rotation_unsupported`,
  `modeled_consume_sink_policy_change_unsupported`,
  `modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority`,
  `modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority`).

Where Run 248 proved the durable-consume projection sink boundary at the
source/test level, Run 249 proves on real `target/release/qbind-node` plus a
release-built helper
(`crates/qbind-node/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper.rs`,
driven by
`scripts/devnet/run_249_modeled_durable_consume_projection_sink_release_binary.sh`)
that the release-built code exposes and exercises the boundary:

* a disabled sink policy and a disabled pipeline/evaluator/call-site policy
  preserve the legacy no-mutation, no-consume, no-receipt bypass and never
  invoke the sink;
* a DevNet/TestNet fixture pipeline that resolves to
  `ModeledApplierAppliedAndDurableConsumeAuthorized` projects a consume-sink
  intent and records **only** the in-memory
  `ModeledDurableConsumeReceiptLedger`;
* the only consume-authorizing pipeline outcome is
  `ModeledApplierAppliedAndDurableConsumeAuthorized`; every other pipeline
  outcome projects to no sink intent and records no receipt;
* the only receipt-recording sink outcome is `ConsumeReceiptRecorded`; a
  duplicate identical receipt is idempotent (no second record) and a same-id
  different-digest receipt fails closed as equivocation;
* every pipeline rejection, record failure, rollback, rollback-failed, ambiguous
  receipt window, unavailable production/MainNet sink path, validator-set
  rotation, and policy-change attempt is non-mutating and non-consuming, and a
  rejection before the sink stage leaves the sink invocation counter at zero;
* **MainNet peer-driven apply remains refused** — before any pipeline
  projection or sink invocation;
* the crash-window recovery helper fails closed on every after-record /
  ambiguous / rollback-failed / unknown window;
* existing Run 247, Run 245, Run 243, and Run 241 release behaviour remains
  compatible.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/
reachability/
grep_summaries/
test_results/
fixtures/
tables/
scenarios/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_249_modeled_durable_consume_projection_sink_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 248 durable-consume projection sink boundary is a pure, typed
  projection over the already-landed Run 246 modeled end-to-end pipeline outcome
  plus a mockable sink that records only the in-memory
  `ModeledDurableConsumeReceiptLedger`. Run 249 exercises it through
  release-built library symbols (the same symbols a future production call site
  would use), but the boundary itself performs no I/O and applies no real (live)
  durable consume.
* The boundary specifies the MainNet-refusal-first, legacy-bypass,
  pipeline-projection, pre-sink binding, and receipt-record ordering a real
  durable-consume sink would have to honour, but implements **none** of that
  production behaviour: there is no real durable consume backend, no real
  persistent replay backend, no real production mutation engine, no real
  governance execution engine, no real on-chain governance proof verifier, no
  RocksDB backend, no file format, no schema, no database migration, and no
  storage-format change.
* The `FixtureModeledDurableConsumeProjectionSink` records only the modeled
  in-memory receipt ledger and performs no real durable consume; the
  `ProductionModeledDurableConsumeProjectionSink` and
  `MainNetModeledDurableConsumeProjectionSink` always return the typed
  unavailable / fail-closed result.
* `ConsumeReceiptRecorded` is the only outcome that records a new modeled
  receipt, and only after a `ModeledApplierAppliedAndDurableConsumeAuthorized`
  pipeline outcome and a clean pre-sink binding validation; rejected,
  failed-record, rollback, rollback-failed, ambiguous, unavailable, and
  unsupported outcomes never consume.
* The boundary is non-mutating on every rejection path: it does not mutate
  `LivePqcTrustState`, writes no marker, writes no sequence, performs no live
  trust swap, evicts no sessions, performs no durable consume of its own, and
  never invokes Run 070 apply.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) before any
  pipeline projection or sink invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No real KMS / HSM / RemoteSigner backend. The boundary changes **no** network
  wire schema, trust-bundle schema, authority-marker schema, or sequence schema.
* Full C4 remains open. C5 remains open.