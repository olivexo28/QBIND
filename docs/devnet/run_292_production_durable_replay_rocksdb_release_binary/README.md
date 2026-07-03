# QBIND DevNet evidence — Run 292

**Title.** Release-binary evidence for the Run 291 production durable replay RocksDB backend.

**Status.** PASS (release-binary evidence). Run 292 is the release-binary evidence run for the Run 291 source/test **production durable replay RocksDB backend** in `crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs`.

Run 292 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_292_production_durable_replay_rocksdb_release_binary_helper.rs` that the Run 291 production library symbols are present and exercised in release mode against a **real on-disk RocksDB database**. The helper remains dead code from the production runtime: it opens temp-dir RocksDB databases under the `ProductionSourceTest` policy, never mutates `LivePqcTrustState`, and never wires the backend into the default runtime.

## What Run 292 states

* Run 292 is release-binary evidence for the Run 291 production durable replay RocksDB backend.
* Run 292 does not add new production runtime wiring.
* Run 292 does not add a public CLI flag.
* Run 292 does not enable the backend by default.
* Run 292 does not enable MainNet.
* Run 292 does not implement custody / RemoteSigner / KMS / HSM.
* Run 292 does not implement on-chain governance proof verification.
* Run 292 does not implement a governance execution engine.
* Run 292 does not implement validator-set rotation.
* Run 292 does not implement settlement or external publication.
* Run 292 does not call Run 070.
* Run 292 does not mutate `LivePqcTrustState`.
* Run 292 does not write trust-bundle sequence or authority marker files.
* The backend is real RocksDB persistence, not another in-memory model: it persists typed replay records to an on-disk RocksDB database, recovers across reopen, enforces schema/domain binding, uses atomic `WriteBatch` writes, verifies record digests on read, enforces `Observed → Consumed` stage ordering, supports idempotency, refuses equivocation, fails closed on corruption / wrong-domain / partial-write state, uses deterministic SHA3-256 canonical length-prefixed digests, and never silently substitutes an in-memory backend.
* The default backend policy is `Disabled`; `MainNet` is refused; DevNet/TestNet temp-dir databases only.
* The release helper exercises the Run 291 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The production durable replay RocksDB backend row is Green **only** for release-binary-evidenced backend behavior; it is not wired by default into the production runtime and does not close C4/C5.
* Red production backend rows remain Red until production implementation and release-binary evidence exist.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Backend symbols exercised

No symbol substitutions were required. Every type, function, trait, and `Error`/`Outcome` variant named by the Run 292 task resolves directly to an implemented Run 291 symbol in `crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

* Policy: `DurableReplayRocksDbPolicy` (`Disabled`, `ProductionSourceTest`).
* Identity: `DurableReplayRocksDbIdentity::new(env, chain, genesis, seq)`.
* Config: `DurableReplayRocksDbConfig::source_test(path, identity)` / `::disabled(path, identity)`.
* Backend: `ProductionDurableReplayRocksDbBackend::open_or_initialize(&config) -> (Self, DurableReplayRocksDbOpenOutcome)`.
* Trait `GovernanceProductionDurableReplayBackend`: `record_replay_event`, `read_replay_record`, `scan_replay_records`, `recover_replay_window`, `close_or_flush`.
* Events: `DurableReplayEventInput::observed_from_decision_input(&input)` / `consumed_from_decision_input(&input, prior_digest)`.
* Fault injection: `record_replay_event_simulate_precommit_failure`, `record_replay_event_simulate_partial_stage_failure`.
* Digest helpers and `durable_replay_rocksdb_record_key`, plus the module invariant helpers.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `10/0`, rejection_fail_closed `13/0`, idempotency_equivocation `8/0`, ordering_replay `8/0`, corruption `6/0`, non_mutation `6/0`, reachability `1/0`; total `52` pass, `0` fail. The helper opens real temp-dir RocksDB databases under `ProductionSourceTest`, records/reads/scans/recovers typed replay records, reopens the database to prove durability, drops and reopens the raw `rocksdb::DB` to inject corruption and wrong-domain/partial-residue states, and asserts every failure surfaces as a typed error rather than a silent substitution. The helper additionally emits `fixtures/run_292_deterministic_digests.txt` (domain digest, record id, observed record digest), and the harness runs the helper twice and diffs this fixture to prove deterministic-digest stability.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`, rc=1 as those surfaces require `--genesis-path`), S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes. S6 fails closed before any mutation with the `invalid governance-execution policy selector` message. Every captured log was asserted silent on durable-replay / RocksDB production-enablement claims. No new public CLI surface was added for Run 292. The denylist of forbidden patterns (46 patterns) was clean across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; the production durable replay RocksDB backend row is Green **for release-binary-evidenced scope only** (not default-wired, does not close C4/C5); Red production backend rows remain Red until production implementation **and** release-binary evidence both exist. Run 292 does not reinterpret the matrix clarification as C4/C5 closure. Full C4 remains **OPEN**; C5 remains **OPEN**.

## Validation

The harness `bash scripts/devnet/run_292_production_durable_replay_rocksdb_release_binary.sh` passed and ran the required release builds plus the regression corpus (`run_291` down through `run_224`, `--lib pqc_authority`, and `--lib`), all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_292_production_durable_replay_rocksdb_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 52` / `total_fail: 0`, release-binary scenarios `S1_help=0 S2=1 S3=1 S4=1 S5=1 S6=1`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL was invoked (language: rust) but did **not** complete — the analysis was **skipped because the database size is too large**, so no CodeQL coverage is claimed. CodeQL results are reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_292.md`. The underlying Run 291 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 292 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the durable replay RocksDB backend into the default runtime, and does not implement any custody / RemoteSigner / KMS / HSM backend, on-chain governance proof verifier, governance execution engine, validator-set rotation, settlement, or external publication. Run 292 closes only the Run 291 release-binary evidence gap. Full C4 remains **OPEN** and C5 remains **OPEN**.

## Suggested Run 293 next step

Run 293 should begin the next Red-row closure campaign: source/test **production RemoteSigner backend** implementation, or source/test **production KMS/HSM custody backend** implementation. In either case keep the same pattern — real backend implementation at source/test level, default `Disabled`/fail-closed, MainNet refused unless production authority criteria are satisfied, with release-binary evidence deferred to Run 294.