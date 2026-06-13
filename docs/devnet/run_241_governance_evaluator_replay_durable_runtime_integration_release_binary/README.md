# Run 241 — Release-binary governance evaluator durable replay backend runtime integration evidence

## Scope

Run 241 is the release-binary evidence run for the Run 240 source/test
governance evaluator **durable replay backend runtime integration** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`:

* the typed binding `DurableReplayRuntimeIntegrationInput` (built from the Run
  238 durable backend, the Run 236 consume runtime integration, the Run 232
  replay/freshness runtime, and the Run 230 replay/freshness state under a
  declared validation/mutation surface) and its projections;
* the composition entry point `integrate_durable_replay_runtime`, which reads /
  observes durable replay state **before** mutation authorization and authorizes
  compare-and-mark-consumed **only** after a modeled successful mutation;
* the crash-window recovery helper
  `recover_durable_replay_runtime_crash_window`, which types every crash window
  and never silently approves an after-mutation-before-consume window;
* the call-site wiring helper `wire_durable_replay_runtime_callsite`;
* the `DurableReplayRuntimeOutcome` taxonomy and its predicates / `tag()`
  strings (`ProceedLegacyBypassNoDurableWrite`, `ProceedDeferredObserved`,
  `ProceedFreshObserved`, `ProceedKnownFresh`, `ProceedMutationAuthorized`,
  `ConsumeDurableAfterMutationSuccess`, `DoNotConsumeBeforeApply`,
  `DoNotConsumeApplyFailed`, `DoNotConsumeRolledBack`, `CrashWindowFailClosed`,
  `DurableReplayFailClosed`, `ReplayRuntimeFailClosed`, `ConsumeRuntimeFailClosed`,
  `ProductionDurableUnavailable`, `MainNetDurableUnavailable`,
  `MainNetPeerDrivenApplyRefused`);
* the grep-verifiable invariant / fail-closed guard functions
  (`durable_observe_happens_before_mutation_authorization`,
  `consume_only_after_successful_mutation_under_durable_runtime`,
  `crash_window_ambiguity_fails_closed_under_durable_runtime`,
  `restart_snapshot_is_fixture_source_test_only_under_durable_runtime`,
  `production_mainnet_durable_remains_unavailable_under_durable_runtime`,
  `durable_runtime_rejection_is_non_mutating`,
  `mainnet_peer_driven_apply_remains_refused_under_durable_runtime`,
  `no_rocksdb_file_schema_migration_change_under_durable_runtime`).

Where Run 240 proved the durable replay backend runtime integration at the
source/test level, Run 241 proves on real `target/release/qbind-node` plus a
release-built helper
(`crates/qbind-node/examples/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper.rs`,
driven by
`scripts/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary.sh`)
that the release-built code exposes and exercises the integration:

* a default Disabled policy performs a legacy bypass with no durable write;
* a first-seen DevNet/TestNet decision is observed fresh, then reads known
  fresh;
* a fresh-but-not-yet-effective decision reads deferred — **not** a mutation
  approval;
* expired / stale / replay-detected decisions fail closed before mutation;
* durable read / observe happens **before** mutation authorization;
* compare-and-mark-consumed happens **only** after a modeled successful
  mutation; read-only validation, failed apply, and rollback never consume;
* observe-only and consumed state both survive an in-process fixture restart
  snapshot (a value clone, never a file format);
* the crash-window recovery helper types every window and fails closed on an
  ambiguous after-mutation-before-consume window;
* the production / MainNet durable backends remain callable but always fail
  closed unavailable;
* **MainNet peer-driven apply remains refused** and never observes or consumes
  even when the fixture would otherwise read fresh;
* validator-set rotation and policy-change actions remain unsupported;
* existing Run 239, Run 237, Run 235, Run 233, and Run 231 release behaviour
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
fixtures/
tables/
scenarios/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 240 durable replay backend runtime integration is a pure, typed
  composition over the Run 238 backend, the Run 236 consume runtime, the Run 232
  replay/freshness runtime, and the Run 230 replay/freshness state, plus a
  DevNet/TestNet in-memory fixture. Run 241 exercises it through release-built
  library symbols (the same symbols a future production call site would use),
  but the integration itself performs no I/O and authorizes no mutation
  directly.
* The composition specifies the read-before-mutation, consume-after-success,
  crash-window, and fail-closed semantics a real durable runtime would have to
  honour, but implements **none** of that storage: there is no real persistent
  replay backend, no RocksDB backend, no file format, no schema, no database
  migration, and no storage-format change.
* The durable replay backend is release-evidenced as the typed runtime state
  provider; the fixture durable backend is DevNet/TestNet evidence-only and
  reads as unavailable for a MainNet environment.
* Restart durability is modeled only by the fixture restart snapshot (an
  in-process value clone) — never by reading or writing any file, database, or
  migration.
* Production / MainNet durable backends are callable but always return the typed
  unavailable / fail-closed result, regardless of the resolved policy.
* No real governance execution engine, mutation engine, or on-chain governance
  proof verifier is implemented. No real KMS / HSM / RemoteSigner backend.
* The integration is non-mutating on every rejection path: it writes no marker,
  writes no sequence, mutates no live trust, evicts no sessions, and never
  invokes Run 070 apply.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) and never
  observes or consumes even when the durable state would otherwise read fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* The integration changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema, and implements no storage-format
  change or database migration.
* Full C4 remains open. C5 remains open.
