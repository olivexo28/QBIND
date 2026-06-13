# Run 239 — Release-binary governance evaluator durable replay-state backend boundary evidence

## Scope

Run 239 is the release-binary evidence run for the Run 238 source/test
governance evaluator **durable replay-state backend boundary** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_backend.rs`:

* the typed binding `DurableBackendDecisionInput` /
  `DurableBackendDecisionExpectations` (built from the Run 230 freshness input /
  expectations under a declared mutation surface) and their projections;
* the pure operations `read_decision_state`, `observe_decision_if_absent`,
  `mark_consumed_after_success`, and the compare-and-set primitive
  `compare_and_mark_consumed`;
* the crash-window classifier `classify_crash_window` over a
  `CrashWindowObservation`;
* the deterministic digest helpers `durable_backend_key_digest`,
  `durable_record_digest`, `durable_operation_transcript_digest`, and
  `crash_window_transcript_digest`;
* the `DurableRecordState` / `DurableBackendOutcome` / `DurableConsumeOutcome` /
  `CrashWindow` / `DurableBackendKind` / `DurableMutationCompletion` taxonomies
  and their predicates (`is_observed`, `authorizes_proceed`, `is_deferred`,
  `is_fail_closed`, `authorizes_consume`, `no_consume`,
  `requires_fail_closed_recovery`, `is_after_mutation_before_consume`, `tag`);
* the reader / writer / atomic traits
  (`GovernanceEvaluatorReplayDurableBackendReader` / `Writer` / `Atomic`);
* the DevNet/TestNet `FixtureDurableReplayBackend` with its `restart_snapshot` /
  `from_snapshot` durability model (an in-process value clone, never a file
  format), plus the callable-but-unavailable `ProductionDurableReplayBackend` /
  `MainnetDurableReplayBackend`;
* the invariant / fail-closed guard functions
  `durable_consume_only_after_successful_mutation`,
  `production_mainnet_durable_backend_remains_unavailable`,
  `restart_durability_is_fixture_snapshot_only`,
  `local_operator_cannot_satisfy_durable_backend_policy`,
  `peer_majority_cannot_satisfy_durable_backend_policy`,
  `validator_set_rotation_remains_unsupported_under_durable_backend`,
  `policy_change_action_remains_unsupported_under_durable_backend`,
  `no_rocksdb_file_schema_migration_change_under_durable_backend`, and
  `mainnet_peer_driven_apply_remains_refused_under_durable_backend`.

Where Run 238 proved the durable replay-state backend boundary at the
source/test level, Run 239 proves on real `target/release/qbind-node` plus a
release-built helper
(`crates/qbind-node/examples/run_239_governance_evaluator_replay_durable_backend_release_binary_helper.rs`,
driven by
`scripts/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary.sh`)
that the release-built code exposes and exercises the boundary:

* a first-seen DevNet/TestNet decision records `ObservedFresh` and then reads
  `ProceedKnownFresh`;
* a fresh-but-not-yet-effective decision reads deferred — **not** a mutation
  approval;
* expired / stale decisions read fail-closed;
* an explicit consume after a modeled successful mutation marks consumed, after
  which the decision reads `FailClosedConsumed`;
* read-only validation, rollback, and failed-apply never consume;
* observe-only and consumed state both survive an in-process fixture restart
  snapshot (a value clone, never a file format);
* `compare_and_mark_consumed` consumes only on an exactly-`ObservedFresh` record
  and rejects a wrong expected state — atomicity is release-evidenced;
* the crash-window classifier types every window and never silently approves an
  after-mutation-before-consume window;
* the durable key / record / operation-transcript / crash-window transcript
  digests are deterministic in release mode;
* the production / MainNet durable backends remain callable but always fail
  closed unavailable;
* **MainNet peer-driven apply remains refused** and never observes or consumes
  even when the fixture would otherwise read fresh;
* validator-set rotation and policy-change actions remain unsupported;
* existing Run 237, Run 235, Run 233, Run 231, and Run 229 release behaviour
  remains compatible.

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
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 238 durable replay-state backend boundary is a pure, typed contract
  plus a DevNet/TestNet in-memory fixture. Run 239 exercises it through
  release-built library symbols (the same symbols a future production call site
  would use), but the boundary itself performs no I/O and authorizes no mutation
  directly.
* The contract specifies the durability, atomicity, crash-window, and
  fail-closed semantics a real persistent replay-state store would have to
  honour, but implements **none** of that storage: there is no RocksDB backend,
  no file format, no schema, no database migration, and no storage-format
  change.
* First-seen records `ObservedFresh` and reads `ProceedKnownFresh`;
  not-yet-effective reads deferred (not a mutation approval); expired / stale
  read fail-closed; `read_decision_state` is non-mutating.
* Consume is after-success-only: only `ConsumedAfterSuccess` (after a modeled
  `AppliedSuccessfully` on an exactly-`ObservedFresh` record) authorizes a
  fixture consume; before-observe, before-success, failed-apply, rolled-back,
  already-consumed, superseded, and wrong-expected-state paths never consume,
  and a malformed observe records nothing at all.
* Restart durability is modeled only by `restart_snapshot` / `from_snapshot` (an
  in-process value clone) — never by reading or writing any file, database, or
  migration.
* The `FixtureDurableReplayBackend` is an in-process map only. It is
  DevNet/TestNet evidence-only, reads as unavailable for a MainNet environment,
  and introduces **no** RocksDB schema, file format, or database migration.
* Production / MainNet durable backends are callable but always return the typed
  unavailable / fail-closed result, regardless of the resolved policy.
* No real governance execution engine, mutation engine, or on-chain governance
  proof verifier is implemented. No real persistent replay backend. No real
  KMS / HSM / RemoteSigner backend.
* The boundary is pure: it performs no network or file I/O, writes no marker,
  writes no sequence, mutates no live trust, evicts no sessions, and never
  invokes Run 070 apply. The writer is never called on a non-consume path.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) and never
  observes or consumes even when the durable state would otherwise read fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema, and implements no storage-format
  change or database migration.
* Full C4 remains open. C5 remains open.