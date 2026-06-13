# QBIND DevNet evidence — Run 241

**Title.** Release-binary durable replay backend runtime integration evidence.

**Status.** PASS (release-binary evidence). Run 241 is the release-binary
evidence run for the Run 240 source/test governance evaluator **durable replay
backend runtime integration** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`.
Run 240 landed the typed composition that wires the Run 238 durable replay-state
backend into the Run 236 / 232 / 230 replay/freshness + after-success-only
consume runtime path as the **durable state provider**, but captured **no**
release-binary evidence (deferred to Run 241). Run 241 proves on real
`target/release/qbind-node` plus a release-built helper that the release-built
code exposes and exercises that integration.

Run 241 is **release-binary evidence only**. It implements **no** real persistent
replay backend, **no** RocksDB backend, **no** file format, **no** schema, **no**
database migration, **no** storage-format change, **no** real governance
execution engine, **no** real mutation engine, **no** real on-chain governance
proof verifier, **no** real KMS/HSM backend, **no** real RemoteSigner backend,
**no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format. The durable replay backend is
release-evidenced as the typed runtime state provider; fixture restart durability
is modeled **only** through a source/test fixture snapshot (an in-process value
clone, not a file).

## What Run 241 states

* Run 241 is release-binary durable replay backend runtime integration evidence.
* The durable replay backend is release-evidenced as the typed runtime state
  provider.
* Durable read/observe happens before mutation authorization.
* Compare-and-mark-consumed happens only after successful mutation completion.
* Crash-window ambiguity is typed and fail-closed.
* The fixture durable backend remains DevNet/TestNet evidence-only.
* The fixture restart snapshot models durability only for release evidence (an
  in-process value clone), not a real file format.
* Production/MainNet durable backend remains unavailable/fail-closed.
* No real persistent replay backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No real governance engine, mutation engine, or on-chain proof verifier is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains **OPEN**.
* C5 remains **OPEN**.

## Strict scope

* Release-binary evidence only.
* Uses the release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behaviour change (the run adds only an example helper, a
  harness script, evidence, and narrow doc updates).
* No real persistent replay backend; no RocksDB schema; no file format; no
  database migration; no real governance execution engine; no real mutation
  engine; no real on-chain governance proof verifier; no MainNet governance
  enablement; no MainNet peer-driven apply enablement; no validator-set rotation;
  no KMS/HSM backend; no RemoteSigner backend.
* No wire/schema/marker/sequence/trust-bundle change.
* No autonomous apply; no automatic apply on receipt; no peer-majority authority.
* Run 241 does not weaken Runs 070, 130–240 and does not claim full C4 or C5
  closure.

## Deliverables

* **Release-binary helper** —
  `crates/qbind-node/examples/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper.rs`.
  Drives the A1–A27 / R1–R38 matrix through the **release-built** Run 240 symbols
  (`integrate_durable_replay_runtime`,
  `recover_durable_replay_runtime_crash_window`,
  `wire_durable_replay_runtime_callsite`, the
  `DurableReplayRuntimeIntegrationInput` binding, the
  `DurableReplayRuntimeOutcome` taxonomy, and the grep-verifiable invariant /
  refusal helpers), composing the Run 238 durable backend with the Run 230 / 232
  replay/freshness state path and the Run 236 consume runtime integration.
* **Release-binary harness** —
  `scripts/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary.sh`.
  Builds the release `qbind-node` and the release helper, captures their SHA-256
  and ELF Build ID, runs the helper corpus, runs the real-binary surface
  scenarios (help / default DevNet / TestNet / MainNet / hidden governance
  selector parse / invalid selector fail-closed), produces the
  source-reachability / denylist / mutation / no-mutation proofs, and runs the
  regression test corpus.
* **Evidence archive** —
  `docs/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary/`
  (only `README.md`, `summary.txt`, and `.gitignore` are tracked; per-run
  artefacts are generated and `.gitignore`d).
* **Canonical evidence report** — this file.

## Module under evidence

`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`
(Run 240). Run 241 adds **no** production source change; it exercises the
existing module through release-built library symbols.

## Release-helper matrix

The release-built helper exercises the Run 240 durable runtime integration
symbols through production library code. All cases pass in release mode.

**Accepted / compatible (A1–A27).** A1 default Disabled / legacy bypass performs
no durable write; A2/A3 first-seen DevNet/TestNet fixture decisions are observed
fresh; A4 known-fresh proceeds as known fresh; A5 deferred is observed but does
not authorize mutation; A6 fresh observed authorizes mutation only after
replay/runtime agreement; A7/A8 `AppliedSuccessfully` performs
compare-and-mark-consumed in the DevNet/TestNet fixture; A9 same decision after
durable consume reads consumed / fail-closed; A10 read-only validation observes
but does not consume; A11 apply-failed-after-observe does not consume; A12
rollback-after-observe does not consume; A13 after-mutation-before-consume crash
window is typed and fails closed; A14 after-consume crash window is typed and
fails closed; A15/A16 fixture restart snapshot preserves observed/consumed state
through the integration; A17 production durable path is reached and fails closed
unavailable; A18 MainNet durable path is reached and fails closed
unavailable/refused; A19 MainNet peer-driven apply remains refused even if the
durable state is fresh; A20 Run 236 consume runtime remains compatible; A21 Run
238 durable backend boundary remains compatible; A22 Run 239 release
durable-backend behaviour remains compatible; A23 Run 237 release consume-runtime
behaviour remains compatible; A24 Run 235 release consume-boundary behaviour
remains compatible; A25 `integrate_durable_replay_runtime` proves durable
read/observe occurs before mutation authorization; A26 compare-and-mark-consumed
is reachable only after `AppliedSuccessfully`; A27 the crash-window recovery
helper returns typed fail-closed outcomes for ambiguous windows.

**Rejection (R1–R38).** R1 expired / R2 stale / R3 replay-detected durable state
rejected before mutation; R4 consumed / R5 superseded decision rejected before
mutation; R6 malformed durable record rejected; R7 backend unavailable rejected;
R8 production durable backend unavailable rejected; R9 MainNet durable backend
unavailable/refused rejected; R10–R26 every wrong-bound field (environment,
chain, genesis, validation/mutation surface, replay-state key, source identity,
request, response, transcript, decision digest, proposal id, decision id,
lifecycle action, candidate digest, authority-domain sequence, replay nonce)
rejected before any observe/consume; R27 compare-and-mark-consumed wrong expected
state rejected; R28 consume before observe rejected; R29 consume before
successful mutation rejected; R30 consume after failed apply rejected; R31
consume after rollback rejected; R32 ambiguous crash window rejected; R33 local
operator / R34 peer majority cannot satisfy the durable replay backend policy;
R35 validator-set rotation unsupported; R36 policy-change action unsupported; R37
rejection produces no Run 070 call / live trust swap / session eviction /
sequence write / marker write (non-mutating); R38 MainNet peer-driven apply
remains refused even when the durable backend says fresh, and never consumes.

## Real release checks

The harness captures, on real release artefacts: the helper binary SHA-256 and
ELF Build ID; the `qbind-node` release binary SHA-256 and ELF Build ID; the Run
241 helper corpus PASS verdict; that durable read/observe happens before mutation
authorization; that the replay/freshness gate uses durable state; that
fresh / known-fresh is required before mutation authorization; that
compare-and-mark-consumed is after-success-only; that the fixture restart
snapshot preserves observed and consumed state; that crash-window ambiguity is
typed and fail-closed; that production/MainNet durable backend unavailable is
fail-closed; and the denylist of forbidden "active/enabled" claims proven empty
across captured logs (no real persistent backend, no RocksDB/file-format/database
migration drift, no marker/sequence write from the runtime integration layer, no
Run 070 call, MainNet peer-driven apply still refused, no real governance /
mutation engine / on-chain verifier, no MainNet governance, no validator-set
rotation, no KMS/HSM/RemoteSigner backend, no peer-majority authority, no
automatic apply / apply-on-receipt).

## Source / release reachability proof

The harness greps the production source for, and the helper exercises in release
mode, the Run 240 symbols
(`pqc_governance_evaluator_replay_durable_runtime_integration`,
`DurableReplayRuntimeIntegrationInput`, `DurableReplayRuntimeOutcome`,
`integrate_durable_replay_runtime`,
`recover_durable_replay_runtime_crash_window`,
`wire_durable_replay_runtime_callsite`, the outcome variants
`ProceedLegacyBypassNoDurableWrite`, `ProceedDeferredObserved`,
`ProceedFreshObserved`, `ProceedKnownFresh`, `ProceedMutationAuthorized`,
`ConsumeDurableAfterMutationSuccess`, `DoNotConsumeBeforeApply`,
`DoNotConsumeApplyFailed`, `DoNotConsumeRolledBack`, `CrashWindowFailClosed`,
`DurableReplayFailClosed`, `ReplayRuntimeFailClosed`, `ConsumeRuntimeFailClosed`,
`ProductionDurableUnavailable`, `MainNetDurableUnavailable`,
`MainNetPeerDrivenApplyRefused`), the Run 238 durable backend usage, the Run 236
consume runtime usage, the Run 232 replay/freshness runtime usage, the Run 230
replay/freshness state usage, the production-unavailable path, the
MainNet-unavailable/refused path, and the MainNet peer-driven refusal guard.

## Tests

The harness runs the Run 240 source/test corpus and the broader regression set:

* `run_240_governance_evaluator_replay_durable_runtime_integration_tests`
* `run_238_governance_evaluator_replay_durable_backend_tests`
* `run_236_governance_evaluator_replay_consume_runtime_integration_tests`
* `run_234_governance_evaluator_replay_consume_boundary_tests`
* `run_232_governance_evaluator_replay_runtime_integration_tests`
* `run_230_governance_evaluator_replay_state_tests`
* `run_228_peer_evaluator_context_representation_tests`
* `run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `run_224_governance_evaluator_runtime_integration_tests`
* plus the Run 222 / 220 / 217 / 215 / 213 / 211 / 157 / 152 / 150 / 148 / 142
  regression targets, `--lib pqc_authority`, and `--lib`.

## Acceptance mapping

1. The release-built helper exercises the Run 240 durable runtime integration.
2. Durable read/observe-before-mutation ordering is release-evidenced (A6, A25;
   `durable_observe_happens_before_mutation_authorization`).
3. Compare-and-mark-consumed-after-success-only ordering is release-evidenced
   (A7, A8, A26; `consume_only_after_successful_mutation_under_durable_runtime`).
4. Crash-window ambiguity is typed and fail-closed (A13, A14, A27, R32;
   `crash_window_ambiguity_fails_closed_under_durable_runtime`).
5. Fixture restart snapshot durability is release-evidenced without a real file
   format (A15, A16;
   `restart_snapshot_is_fixture_source_test_only_under_durable_runtime`).
6. Production/MainNet durable backend remains unavailable/fail-closed (A17, A18,
   R8, R9; `production_mainnet_durable_remains_unavailable_under_durable_runtime`).
7. Rejections are non-mutating (R1–R38;
   `durable_runtime_rejection_is_non_mutating`).
8. MainNet peer-driven apply remains refused (A19, R38;
   `mainnet_peer_driven_apply_remains_refused_under_durable_runtime`).
9. No RocksDB/file/schema/migration/storage-format change is claimed
   (`no_rocksdb_file_schema_migration_change_under_durable_runtime`).
10. Existing Run 239, Run 237, Run 235, Run 233, and Run 231 release behaviour
    remains compatible (A20–A24).
11. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 241 is release-binary evidence only — it exercises the Run 240 module
  through release-built library symbols (the same symbols a future production
  call site would use); it adds no production source behaviour.
* The durable replay backend is evidenced as a typed runtime state provider only;
  no real persistent replay backend is implemented.
* The fixture durable backend remains DevNet/TestNet evidence-only; the
  production / MainNet backends remain callable-but-unavailable / fail-closed.
* Fixture restart durability is modeled only through a source/test fixture
  snapshot (in-process value clone), not a real file format.
* No RocksDB / file / schema / migration / storage-format change is implemented.
* No real governance engine, mutation engine, or on-chain proof verifier is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains **OPEN**.
* C5 remains **OPEN**.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper`
* `bash scripts/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary.sh`
* `cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests`
* `cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests`
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests`
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`
