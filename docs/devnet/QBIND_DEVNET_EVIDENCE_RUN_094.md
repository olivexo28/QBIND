# QBIND DevNet Evidence — Run 094

**Objective:** Implement the smallest production-honest wiring that
makes the real `qbind-node` binary persist committed epoch
transitions through the Run 093 canonical `ConsensusStorage` handle
(per `task/RUN_094_TASK.txt`). Thread Run 093's opened production
`ConsensusStorage` handle into the binary-path consensus loop,
detect *canonical* engine epoch transitions, persist them via the
existing `apply_epoch_transition_atomic` machinery, preserve
atomicity / recovery / fail-closed semantics, and preserve
Run 091/092 `CurrentEpochUnavailable` trust-bundle activation
behaviour — **without** consuming `current_epoch` for activation,
**without** inventing a synthetic epoch, and **without** fabricating
a transition just to satisfy tests.

**Verdict:** **partial positive.** Run 094 lands every binary-path
plumbing piece that was identified as missing by Run 093's
documented "partial-positive boundary":

* The Run 093 opened `Arc<RocksDbConsensusStorage>` handle is
  threaded from `main.rs` through both `run_local_mesh_node` and
  `run_p2p_node` into `BinaryConsensusLoopConfig` via a new
  `with_consensus_storage(Arc<dyn ConsensusStorage>)` builder, and
  observed in the binary's release-binary release log:
  `[binary] Run 094: binary consensus loop wired to canonical
  production ConsensusStorage handle (LocalMesh).`
* The binary consensus loop tracks
  `last_persisted_epoch = engine.current_epoch()` at start and, on
  every tick path that may mutate engine state, calls a new
  `maybe_persist_engine_epoch_transition(...)` helper that issues
  `apply_epoch_transition_atomic(EpochTransitionBatch::new(target,
  previous, reconfig_block_id))` through the threaded handle if and
  only if `engine.current_epoch()` has advanced above
  `last_persisted_epoch`. The persistence trigger is *exclusively*
  the engine's own canonical `current_epoch()` counter; no wall-clock,
  view-derived, height-derived, or synthetic epoch source is used.
* Persistence failure is surfaced as a typed `EpochPersistenceFailed`
  error and the binary-path loop fail-closes on it (logs FATAL,
  records `epoch_persistence_failed=true` in the loop-exit summary,
  and breaks out of the tick loop). There is **no** silent
  downgrade to memory-only epoch.

Run 094 is **not** strongest-positive because the production binary's
consensus loop does not itself *trigger* a canonical engine epoch
transition end-to-end today: in the binary path the engine's
`current_epoch()` is initialised to `0` and only advances when a
committed reconfig block is observed under the existing consensus /
epoch rules — and the binary-path consensus loop does not yet
process reconfig blocks. That remaining piece is the separately
enumerated open C4 item "activation_epoch real runtime source"; it
is **out of scope** for Run 094 per `task/RUN_094_TASK.txt` §"Strict
non-goals". Run 094 must therefore not invent a transition just to
satisfy Scenario 2 — that is the explicitly-listed `negative` verdict
trigger ("implementation invents synthetic epoch" / "fake/test-only
persistence").

Run 094 makes **zero** change to `pqc_trust_activation::ActivationContext`,
to `StateSnapshotMeta`, to the trust-bundle wire format, to peer
propagation, to KEMTLS handshake, to any CLI flag, to any metric
family, and to any third-party dependency. Run 091/092
`CurrentEpochUnavailable` fail-closed behaviour is preserved on every
environment and every production call site; every `ActivationContext`
continues to be built with `current_epoch: None`. Fresh genesis on
the binary path remains `PresentNoCommittedEpoch` (not implicit `0`),
matching Run 093 exactly.

Run 094 does **not** claim full C4 closure and does **not** claim C5
closure.

---

## What changed

### 1. `BinaryConsensusLoopConfig` — new optional storage handle

`crates/qbind-node/src/binary_consensus_loop.rs`:

* New field `consensus_storage: Option<Arc<dyn ConsensusStorage>>`
  on `BinaryConsensusLoopConfig`.
* New builder `with_consensus_storage(Arc<dyn ConsensusStorage>)`.
* `#[derive(Debug)]` replaced by a manual `Debug` impl that prints
  `<ConsensusStorage handle>` placeholder (the trait does not
  itself require `Debug`).
* `None` (default / DevNet-without-data-dir) preserves pre-Run-094
  behaviour exactly — no persistence is attempted, no new code
  path runs. `Some(h)` wires real persistence.

### 2. Canonical engine-epoch persistence helper

`crates/qbind-node/src/binary_consensus_loop.rs`:

* New public function:

  ```rust
  pub fn maybe_persist_engine_epoch_transition(
      engine: &BasicHotStuffEngine<[u8; 32]>,
      storage: &Arc<dyn ConsensusStorage>,
      last_persisted_epoch: &mut u64,
  ) -> Result<bool, EpochPersistenceFailed>
  ```

  Reads `engine.current_epoch()` (the canonical engine epoch
  counter). If it equals `*last_persisted_epoch`, returns
  `Ok(false)` — no-op, no write. Otherwise builds
  `EpochTransitionBatch::new(target, previous, reconfig_block_id)`
  using `engine.committed_block()` as the reconfig anchor, calls
  `storage.apply_epoch_transition_atomic(batch)`, advances the
  cursor on success, and returns `Ok(true)`. On storage error
  the cursor is NOT advanced and the call returns
  `Err(EpochPersistenceFailed { previous_epoch, target_epoch,
  reconfig_block_id, source })`.

* New public error type `EpochPersistenceFailed` (`Debug + Display
  + std::error::Error`) carrying the canonical engine epoch pair
  and the `StorageError` source so operators can correlate against
  engine logs.

### 3. Binary consensus loop — fail-closed wiring at 3 call sites

`crates/qbind-node/src/binary_consensus_loop.rs::run_binary_consensus_loop_with_io`:

* `let mut last_persisted_epoch: u64 = engine.current_epoch();`
  initialised at loop start (typically `0` on fresh genesis).
* `let mut epoch_persistence_failed: Option<EpochPersistenceFailed> = None;`
* After each `update_state_metrics(...)` call (3 sites: inbound-
  message handler, ticker tick in inbound-IO branch, ticker tick in
  no-inbound-IO branch), if `cfg.consensus_storage.is_some()`, the
  loop calls `maybe_persist_engine_epoch_transition(...)`. On
  `Ok(_)` it continues. On `Err(e)` it logs
  `[binary-consensus] FATAL: <EpochPersistenceFailed>`, records
  the error, and `break`s the tick loop (fail-closed exit).
* Loop-exit summary now includes `last_persisted_epoch=<N>
  epoch_persistence_failed=<bool>` for operator-visible audit.

### 4. Production binary — handle plumbing

`crates/qbind-node/src/main.rs`:

* `run_local_mesh_node` and `run_p2p_node` both gain a new
  `consensus_storage: Option<Arc<RocksDbConsensusStorage>>`
  parameter, supplied from the existing
  `consensus_storage_lifecycle.handle.clone()` at the `main()`
  dispatch site (after Run 093's `open_production_consensus_storage`
  has already succeeded and been logged).
* Each function widens the concrete handle to `Arc<dyn
  ConsensusStorage>` and threads it onto the loop config via
  `with_consensus_storage`. When the handle is `None` (DevNet
  ad-hoc smoke without `--data-dir`), an explicit log line records
  that no Run 094 persistence is wired on this invocation.

### 5. Integration tests

New: `crates/qbind-node/tests/run_094_binary_path_epoch_transition_persistence_tests.rs`
(7 tests, all passing):

* `run_094_no_engine_advance_no_persistence` — A fresh engine
  `current_epoch() == 0` causes zero atomic-write activity. Storage
  remains `PresentNoCommittedEpoch`.
* `run_094_engine_advance_triggers_canonical_atomic_persistence` —
  When the engine canonically advances `current_epoch()` to `7`,
  the helper persists exactly `7` via `apply_epoch_transition_atomic`.
  Idempotent on re-call.
* `run_094_persistence_trigger_is_engine_current_epoch_only` — 32
  repeated no-advance calls produce zero writes; the trigger is
  *only* `current_epoch()` advance.
* `run_094_multi_step_engine_advance_persists_each_step_once` —
  Canonical 0→1→2→5 advance is persisted in three discrete writes
  with no re-thrash.
* `run_094_persistence_failure_is_fail_closed_with_canonical_epoch_pair`
  — A `FailingStorage` stub that errors in `apply_epoch_transition_atomic`
  causes `EpochPersistenceFailed { previous_epoch: 0,
  target_epoch: 3, .. }`. `last_persisted` is NOT advanced.
  Display output mentions the canonical epoch pair and the phrase
  "fail closed".
* `run_094_committed_epoch_survives_restart_via_run_093_surface` —
  End-to-end through the Run 093 surface: open
  `open_production_consensus_storage`, observe
  `PresentNoCommittedEpoch`, drive an engine epoch advance, persist,
  drop handle, re-open via the same Run 093 entry point, observe
  `CommittedEpoch(11)`. This is the minimum source-level proof
  that Run 094 wiring produces durable `meta:current_epoch` that
  survives restart.
* `run_094_consensus_storage_state_committed_epoch_is_isolated_from_activation`
  — Regression pin: `ConsensusStorageState::committed_epoch()` keeps
  its strict three-variant `Option<u64>` shape. No coercion of
  `PresentNoCommittedEpoch` into `Some(0)`.

### 6. Docs

* This evidence file.
* `docs/whitepaper/contradiction.md` — Run 094 update narrowing
  the binary-path epoch transition persistence sub-piece (storage
  threading + persistence call site + restart-durable evidence via
  Run 093 surface), explicitly NOT closing the broader C4 items
  the task lists as non-goals.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 094 note
  explaining what operators will observe on the binary path
  (`[binary] Run 094: binary consensus loop wired to canonical
  production ConsensusStorage handle (...)` at startup; durable
  `meta:current_epoch` only after a canonical engine epoch
  transition; trust-bundle activation behaviour unchanged).

---

## What did NOT change

* `crates/qbind-node/src/pqc_trust_activation.rs` — unchanged. Every
  production `ActivationContext` is still built with
  `current_epoch: None` on every code path. Run 091/092
  `CurrentEpochUnavailable` fail-closed behaviour is preserved on
  DevNet, TestNet, and MainNet.
* `crates/qbind-node/src/main.rs::pqc_trust_activation_context()` —
  unchanged. The Run 093 storage handle is NOT consulted by
  activation. The handle exists in `main`'s scope but is consumed
  only by the binary consensus loop.
* `crates/qbind-node/src/production_consensus_storage.rs` —
  unchanged. Run 094 reuses Run 093's existing open / state /
  recovery surface without modification.
* `StateSnapshotMeta` — unchanged. Snapshot epoch parity remains a
  separate cross-cutting run (explicitly out of scope for Run 094).
* Trust-bundle wire format — unchanged.
* CLI flags / metrics / config — no new flag, no new metric family,
  no new config field.
* Dependencies — no new dependency added.

---

## Release-binary evidence

### Build

```text
cargo build -p qbind-node --bin qbind-node --release
```

…produces `target/release/qbind-node` with no errors (3 pre-existing
unrelated `unused_variables` / `deprecated` warnings, all unchanged
from Run 093's baseline).

### Scenario 1 — fresh startup remains no-epoch

```text
$ rm -rf /tmp/run094_smoke/datadir
$ mkdir -p /tmp/run094_smoke/datadir
$ timeout 4 ./target/release/qbind-node --network-mode local-mesh \
    --data-dir /tmp/run094_smoke/datadir \
    > /tmp/run094_smoke/n1_fresh.stdout.log \
    2> /tmp/run094_smoke/n1_fresh.stderr.log

$ grep -E 'Run 09(3|4)|consensus storage|epoch consistency' \
    /tmp/run094_smoke/n1_fresh.stderr.log
[M16] Epoch consistency check passed: current_epoch=None
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=/tmp/run094_smoke/datadir/consensus
[binary] Run 094: binary consensus loop wired to canonical production ConsensusStorage handle (LocalMesh).

$ ls /tmp/run094_smoke/datadir/consensus
000004.log  CURRENT  IDENTITY  LOCK  LOG  MANIFEST-000005  OPTIONS-000007
```

Proves:

* canonical `<data_dir>/consensus` directory is created on first
  start (RocksDB column-family layout: `CURRENT`, `IDENTITY`,
  `LOCK`, `LOG`, `MANIFEST-*`, `OPTIONS-*`, WAL log).
* Run 093 state on first start = `present-no-committed-epoch`
  (NOT an implicit `0`; preserves Run 091/092 fail-closed
  invariant).
* Run 094 wiring is observed: `[binary] Run 094: binary consensus
  loop wired to canonical production ConsensusStorage handle
  (LocalMesh).` — proves the Run 093 handle is actually threaded
  into the consensus loop on the real production binary path.
* M16 epoch-consistency check ran on startup and reports
  `current_epoch=None` (NOT `Some(0)`; the binary preserves the
  no-implicit-zero invariant).

### Scenario 2 — real epoch transition persistence (binary path)

**Not exercised on the release binary by Run 094.** The production
binary-path consensus loop does not yet trigger a canonical engine
epoch transition end-to-end: the engine's `current_epoch()` is
initialised to `0` and only advances when a committed reconfig
block is observed under the existing consensus / epoch rules. The
binary-path consensus loop does not yet process reconfig blocks
into engine `transition_to_epoch` calls — that piece is the
separately enumerated open C4 item *"activation_epoch real runtime
source"* (`task/RUN_094_TASK.txt` §"Strict non-goals" forbids
broadening into it).

Run 094 must therefore not fabricate a synthetic transition for
Scenario 2 — per `task/RUN_094_TASK.txt` §"Expected verdicts" that
would be the explicit `negative` trigger ("implementation invents
synthetic epoch" / "persistence is fake/test-only"). The bounded
honest proof we *can* land is the source-level integration test
`run_094_committed_epoch_survives_restart_via_run_093_surface`,
which exercises the **same** `apply_epoch_transition_atomic`
machinery the binary will call, through the **same**
`open_production_consensus_storage` lifecycle the binary uses,
against an engine whose `current_epoch()` has actually advanced.
That test (passing) is the structural proof of correctness; the
release-binary end-to-end proof must wait on the separate
runtime-trigger run.

### Scenario 3 — restart proof (no-transition case)

```text
$ timeout 4 ./target/release/qbind-node --network-mode local-mesh \
    --data-dir /tmp/run094_smoke/datadir \
    > /tmp/run094_smoke/n1_restart.stdout.log \
    2> /tmp/run094_smoke/n1_restart.stderr.log

$ grep -E 'Run 09(3|4)|consensus storage|epoch consistency' \
    /tmp/run094_smoke/n1_restart.stderr.log
[M16] Epoch consistency check passed: current_epoch=None
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=/tmp/run094_smoke/datadir/consensus
[binary] Run 094: binary consensus loop wired to canonical production ConsensusStorage handle (LocalMesh).
```

Proves:

* the canonical `<data_dir>/consensus` RocksDB is re-opened
  cleanly across restart (no reset, no recreation, RocksDB LOCK is
  released cleanly between runs by Run 093's explicit-drop
  shutdown path).
* since no canonical engine epoch transition occurred in the
  first run, restart state is *correctly* still
  `present-no-committed-epoch`. NO silent downgrade. NO coercion
  to `0`.
* Restart proof for the **post-transition** case is exercised by
  `run_094_committed_epoch_survives_restart_via_run_093_surface`,
  which proves that *after* a canonical engine epoch transition
  has been persisted, restart observes `CommittedEpoch(11)`.

### Scenario 4 — persistence failure / corruption guardrail

Source-level proof:
`run_094_persistence_failure_is_fail_closed_with_canonical_epoch_pair`
— a `FailingStorage` that errors in `apply_epoch_transition_atomic`
produces `EpochPersistenceFailed { previous_epoch: 0,
target_epoch: 3, .. }`; the helper does NOT advance
`last_persisted`; the error `Display` mentions the canonical
epoch pair and the phrase "fail closed". The binary-path loop's
inline `match` on this error logs `FATAL` and `break`s the tick
loop, which the loop-exit summary records as
`epoch_persistence_failed=true`. The Run 093 atomicity /
recovery / consistency-check / corruption guardrail surface (M16,
T104) is **unchanged** — Run 094 reuses it.

### Scenario 5 — activation unchanged

* Run 091 regression suite (`tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs`,
  15 tests): all 15 / 15 passing on Run 094's branch.
* Run 093 regression suite (`tests/run_093_production_consensus_storage_lifecycle_tests.rs`,
  12 tests): all 12 / 12 passing.
* `epoch_persistence_tests.rs` and `epoch_startup_validation_tests.rs`:
  passing.
* `qbind-node --lib`: **1070 / 1070** passing.
* Binary-path smoke release-binary log lines confirm
  `[M16] Epoch consistency check passed: current_epoch=None` on
  every observed start (NOT `Some(0)`).
* No production `ActivationContext` construction site was
  changed; every site continues to set `current_epoch: None`.

---

## Test results

* New: `tests/run_094_binary_path_epoch_transition_persistence_tests.rs`
  — 7 / 7 passing.
* Run 091: 15 / 15 passing.
* Run 093: 12 / 12 passing.
* `epoch_persistence_tests`, `epoch_startup_validation_tests`:
  passing.
* `qbind-node --lib`: 1070 / 1070 passing.
* `binary_path_b1_b2_b4_tests`: 4 / 4 passing.
* `b5_restore_aware_consensus_start_tests`: 4 / 4 passing.
* `c4_b6_p2p_binary_path_interconnect_tests`: 5 / 5 passing.
* `m16_epoch_transition_hardening_tests`: pre-existing compilation
  error unrelated to Run 094 (`set_inject_write_failure` /
  `clear_epoch_transition_marker` symbols are gated behind a
  `test-utils` feature not enabled in the default test target).
  Verified to be present on the parent commit before Run 094's
  changes; not introduced by Run 094.
* Release binary build (`cargo build -p qbind-node --bin qbind-node
  --release`): success.

---

## Exact immediate next action recommended

Land **Run 095 — wire the binary-path consensus loop's reconfig-block
commit detection onto `BasicHotStuffEngine::transition_to_epoch`
using the existing reconfig block schema**. Run 095 must:

1. Identify the canonical reconfig-block detection point on the
   binary-path commit path (already exists in test harnesses; needs
   to be threaded through the binary loop).
2. On a committed reconfig block, look up `next_epoch_id` and
   `next_validator_set` through the existing `EpochStateProvider`
   surface, validate via `validate_with_governance_strict`, and
   call `engine.transition_to_epoch(...)`.
3. The Run 094 persistence call site (already in place) will then
   automatically persist the resulting `engine.current_epoch()`
   advance via `apply_epoch_transition_atomic` — Run 095 needs to
   add NO new persistence code.
4. Produce release-binary Scenario-2 evidence by exercising a
   real canonical reconfig block under the existing
   single-validator LocalMesh DevNet and observing
   `[binary-consensus] Run 094: persisting canonical engine epoch
   transition previous_epoch=0 target_epoch=1 reconfig_block_id=...`
   followed by `meta:current_epoch=1 durably persisted`, then
   restart observing `CommittedEpoch(1)`.

Run 095 must NOT consume the persisted epoch for trust-bundle
activation (that is the separate `activation_epoch` runtime-source
run further downstream).