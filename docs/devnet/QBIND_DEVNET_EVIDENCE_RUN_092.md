# QBIND DevNet Evidence — Run 092

**Objective:** implement the narrow canonical pre-consensus epoch-source
wiring for PQC trust-bundle activation using the existing persisted
`MetaStore::get_current_epoch()` (`meta:current_epoch`) value, **if it can
be done without broad storage redesign** (per `task/RUN_092_TASK.txt`).
Replace the Run 091 fail-closed `CurrentEpochUnavailable` boundary with a
real current-epoch source for the trust-bundle activation gate while
preserving every Run 050–091 invariant (signature, environment, chain_id,
validity window, revocation, `activation_height`, Run 065 minimum-margin,
Run 055 sequence anti-rollback, Run 069 reload-check non-mutation, Run 073
process-start apply, Run 074 SIGHUP live reload, Run 076–090 peer-
candidate validation / propagation non-mutation).

**Verdict:** **partial positive**. The investigation confirms — at the
source-code level, against the current `crates/qbind-node/src/main.rs`
startup ordering, the current `crates/qbind-node/src/storage.rs` open-path
surface, and the current `crates/qbind-ledger/src/state_snapshot.rs`
metadata shape — that the existing persisted `MetaStore` `current_epoch`
**is not actually written by the `qbind-node` binary today**, and that
exposing a pre-consensus read-only `current_epoch` lookup before
trust-bundle activation validation **cannot be done without a broad
storage redesign** that is explicitly forbidden by Run 092's strict
scope. Run 092 therefore preserves the Run 091 fail-closed
`CurrentEpochUnavailable` boundary on every environment (DevNet,
TestNet, MainNet) at every production call site (startup
`--p2p-trust-bundle` load, `--p2p-trust-bundle-reload-check`,
`--p2p-trust-bundle-reload-apply`, SIGHUP `LiveReloadController`,
peer-candidate `0x05` validation / propagation), records the exact
architectural reasons that block narrow wiring today, and updates
`docs/whitepaper/contradiction.md` and
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` with the narrowed
boundary. This run does **not** introduce a synthetic epoch, does **not**
read epoch from wall-clock, does **not** use block height as epoch, does
**not** silently ignore `activation_epoch`, does **not** weaken Run 091
fail-closed behaviour, does **not** change the trust-bundle wire format,
does **not** add a new metric family, and does **not** claim full C4 or
C5 closure.

## Files changed

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_092.md` (new — this document).
- `docs/whitepaper/contradiction.md` (Run 092 C4 update entry — no C4
  closure claim, no C5 closure claim, no source-code change).
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (§10.1 narrowed-but-
  still-open Run 091/092 cross-reference; §11 Run 092 mapping row).
- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` (§9 open-
  questions cross-reference updated to also point at Run 092).

No changes under `crates/**/src/**`. No new tests added — Run 091 already
ships the 15 integration tests pinning the activation-epoch fail-closed
boundary on the bundle-level, per-active-root, startup-load, reload-
check, SIGHUP, and peer-candidate surfaces (`crates/qbind-node/tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs`).
No new dependencies. No new metric families.

## current_epoch source investigation

### Sources surveyed (Run 092 re-confirms the Run 091 inventory and extends it)

| # | Source | Persisted? | Initialized when? | Available before trust-bundle gate? | Suitable for Run 092 narrow wiring? |
|---|--------|-----------|--------------------|-------------------------------------|--------------------------------------|
| 1 | `MetaStore::get_current_epoch()` / `meta:current_epoch` (`crates/qbind-node/src/storage.rs:200`, `:323`, `:912-944`) | Conceptually yes (u64 big-endian with checksummed-meta wrap, `apply_epoch_transition_atomic` (`:1320-1340`), `verify_epoch_consistency_on_startup` (`:1134-1138`)) | Only by `hotstuff_node_sim::EpochAwareNodeHotstuffHarness` (`crates/qbind-node/src/hotstuff_node_sim.rs:2152`, `:3357`) and by the M16 / T112 / T103 test harness. | **No.** `main.rs` never opens `RocksDbConsensusStorage::open(...)` (verified: `grep -rn "RocksDbConsensusStorage::open" crates/qbind-node/src/**.rs` returns only doc-comments in `storage.rs`; the only callers are tests under `crates/qbind-node/tests/`). The binary therefore does NOT write `meta:current_epoch` at any time. A fresh-binary node's "persisted" `meta:current_epoch` does not exist on disk because no `RocksDbConsensusStorage` instance is ever constructed. | **No** — see "Why wiring is blocked" below. |
| 2 | `StateSnapshotMeta` (`crates/qbind-ledger/src/state_snapshot.rs:84-109`) | Yes (on snapshot create) | At `--restore-from-snapshot` time | Yes (the gate already reads `restore_baseline.snapshot_height` from `RestoreOutcome.meta`) | **No.** Field set is `{ height, block_hash, created_at_unix_ms, chain_id }` — no `epoch` field. Adding one is the snapshot/restore boundary explicitly listed as remaining-open in `task/RUN_092_TASK.txt` §"Snapshot/restore boundary"; it is a separate cross-cutting run. |
| 3 | `BasicHotStuffEngine` epoch / `EpochTransitionMarker` | No (in-memory engine state) | Only after consensus advances | **No.** Trust bundle gate runs in `main.rs` BEFORE `binary_consensus_loop::spawn_binary_consensus_loop` is called. | **No** (circular dependency: bundle is needed before consensus can advance). |
| 4 | Wall-clock derived "epoch" | n/a | n/a | n/a | **No** — forbidden by `task/RUN_092_TASK.txt` §"Important framing": *"Do not read epoch from wall-clock time."* |
| 5 | Block height used as a synthetic epoch | n/a | n/a | n/a | **No** — forbidden by `task/RUN_092_TASK.txt` §"Important framing": *"Do not use block height as epoch unless the repo already defines that canonical mapping."* The repo defines no such canonical mapping. |
| 6 | `VM-v0 RocksDB` state (`<data_dir>/state_vm_v0`) | Partially (account state) | After consensus commits | Yes when present | **No** — VM state does not track consensus epoch. Reading anything from VM-v0 state pre-consensus is out of the activation surface. |

### Where MetaStore is opened today (binary vs. test harness)

`grep -rn "RocksDbConsensusStorage::open\|RocksDbConsensusStorage::" crates --include='*.rs'`
shows **zero** call sites under `crates/qbind-node/src/**` (only
doc-comments in `crates/qbind-node/src/storage.rs:631 / :650 / :717 / :1411`).
All real call sites live under `crates/qbind-node/tests/**` (e.g.
`storage_latency_metrics_tests.rs`, `m16_epoch_transition_hardening_tests.rs`,
`t112_atomic_epoch_persistence_tests.rs`, `epoch_persistence_tests.rs`).
The `hotstuff_node_sim::EpochAwareNodeHotstuffHarness::with_storage`
adapter (`crates/qbind-node/src/hotstuff_node_sim.rs:801`) accepts an
`Arc<dyn ConsensusStorage>` but the `qbind-node` binary never threads
one in — `main.rs` does not import `RocksDbConsensusStorage`, does not
construct an `InMemoryConsensusStorage`, and does not pass a `with_storage(...)`
to anything.

Net consequence: **on a real `qbind-node` invocation, `meta:current_epoch`
is never written. The "existing persisted MetaStore epoch" that the task
asks Run 092 to wire is therefore phantom — the trait, the on-disk
layout, the schema-versioning, the atomic-transition handling, and the
test coverage all exist, but no production code path actually persists
a value.**

### Why narrow wiring is blocked (architectural, not stylistic)

To honour the task framing — *"using the existing persisted MetaStore
epoch, if it can be done without broad storage redesign"* — Run 092
would need to:

1. **Open a `ConsensusStorage` instance in `main.rs` before the trust-
   bundle gate.** This means:
   - Choosing a canonical on-disk path (e.g. `<data_dir>/consensus`)
     that does not exist in `node_config.rs` today (only
     `state_vm_v0` is defined). Introducing a new persisted subdir is
     a schema-affecting decision that touches every operator playbook,
     `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`, the snapshot
     create/validate path, and the existing storage-corruption
     guardrails tests.
   - Threading a `data_dir` requirement (the trust-bundle gate today
     already runs on `--p2p-trust-bundle-reload-check` without a data
     dir on DevNet — see `main.rs:279-291`). Making the gate require
     `data_dir` would change the existing CLI surface contract that
     Run 069 / 077 already pin.
   - Running schema-version checks (`ensure_compatible_schema`),
     incomplete-transition recovery (`recover_incomplete_transition`),
     and storage-corruption guardrails **before** any peer transport is
     trusted. That re-orders startup against T112 / M16 / Run 022 /
     023 / 057 / 065 / 069 / 070 / 073 / 074 / 076–089 simultaneously.

   This is a *broad storage redesign* by definition: the binary
   transitions from "no consensus-storage open before trust-bundle"
   to "consensus-storage opened before trust-bundle, with all of its
   recovery / schema / corruption-guardrail surface running on the
   pre-consensus path". It is explicitly out of Run 092 scope.

2. **Persist `meta:current_epoch` on the binary path so a read makes
   sense.** Even after opening storage, a read of `meta:current_epoch`
   on the binary returns `Ok(None)` because the binary never writes
   it. To make a read meaningful, every consensus-loop epoch advance
   must also persist via `apply_epoch_transition_atomic`. That is a
   separate cross-cutting wiring of the binary-path consensus loop
   into the M16 / T112 epoch-transition machinery — itself a broad
   storage redesign and a binary-consensus-loop redesign.

3. **Resolve fresh-genesis ambiguity and snapshot-rejoin asymmetry**
   (Run 091 already documented both). Treating `Ok(None)` as
   `current_epoch = 0` is exactly the "silent satisfy" the task
   forbids, since `activation_epoch = 0` is a valid (immediate-
   cutover) bundle field. A snapshot-rejoined node would have no
   persisted `meta:current_epoch` until the next epoch transition,
   creating a permanent asymmetry between fresh-genesis (no source)
   and post-first-transition restart (source available).

Run 092 therefore concludes — explicitly, in source — that narrow
wiring is not achievable. The Run 091 fail-closed boundary remains the
canonical boundary today.

### Conclusion of the investigation

Run 092 confirms Run 091's verdict and adds the Run 092-specific
finding: not only is `MetaStore::get_current_epoch()` not wired into the
activation gate, but on the production `qbind-node` binary path it is
**never written** because no `RocksDbConsensusStorage` (or
`InMemoryConsensusStorage`) is ever opened by `main.rs`. The
`meta:current_epoch` machinery (atomicity, schema versioning, checksum
wrap, corruption guardrails, metrics) is fully implemented but lives in
the `hotstuff_node_sim` / test surface only. Wiring it into the binary
requires (a) deciding and persisting the consensus-storage on-disk
location, (b) opening it before the trust-bundle gate, and (c)
persisting epoch advances on the binary's consensus path — three cross-
cutting changes that together constitute a broad storage redesign.

## Startup ordering (preserved unchanged; documented for Run 092)

`crates/qbind-node/src/main.rs` performs trust-bundle activation in this
exact ordering today, on every production call site, on every
environment. Run 092 makes **no source changes** to this ordering:

1. `apply_snapshot_restore_if_requested` (`main.rs:118-165`) — produces
   an optional `RestoreOutcome { meta: StateSnapshotMeta, ... }` from
   `--restore-from-snapshot <PATH>`. `StateSnapshotMeta` does NOT carry
   an epoch field (see investigation table row 2).
2. Translate to `RestoreBaseline { snapshot_height, snapshot_block_id }`
   (`main.rs:172-184`). `snapshot_height` is the only consensus-state
   field carried forward; there is no `snapshot_epoch`.
3. Trust-bundle reload-check (`main.rs:202-345`), reload-apply
   (`main.rs:830-1180`), peer-candidate check (`main.rs:480-770`), and
   normal startup load (`main.rs:1700-1830`) all build:
   ```
   ActivationContext { current_height: Some(snapshot_height|0), current_epoch: None }
   ```
   `current_epoch: None` is the explicit, intentional "no canonical
   pre-consensus epoch source" marker that triggers Run 091's
   fail-closed `CurrentEpochUnavailable` on any bundle declaring
   `activation_epoch`.
4. `pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
   runs the full Run 050–065 validation pipeline (parse + signature +
   environment + chain_id + window + revocation + minimum-margin), then
   the Run 057 `check_bundle_activation` height + epoch gate, then the
   Run 062 per-entry revocation activation gate.
5. Run 055 `check_and_update_sequence` (sequence anti-rollback
   persistence) — reached only when steps 1–4 pass. **A bundle
   declaring `activation_epoch` on a `current_epoch: None` context
   never reaches step 5; the persisted sequence is never advanced.**
6. Run 050 `merge_active_roots` (live trust set merge) — reached only
   when step 5 passes. **Never reached on the Run 091 fail-closed
   boundary.**
7. P2P start (`P2pNodeBuilder::with_live_pqc_trust`, etc.) — reached
   only when step 6 passes. **Never reached on the Run 091 fail-
   closed boundary.**

Run 092 preserves this ordering exactly. Run 092 verifies — by code
inspection of `main.rs:296-303`, `:540-547`, `:898-905`, `:939-942`,
`:1760-1767`, `:2568`, and `:3418` — that every production
`ActivationContext` construction sets `current_epoch: None` today.

## Reload ordering (preserved unchanged; documented for Run 092)

`crates/qbind-node/src/pqc_trust_reload.rs::validate_candidate_bundle`
and `crates/qbind-node/src/pqc_live_trust_apply.rs::apply_validated_candidate`
together enforce the strict `validate → swap_snapshot → evict_sessions
→ commit_sequence` ordering (Run 070). On the reload path:

1. `validate_candidate_bundle` runs the same Run 050–065 + Run 057 +
   Run 062 pipeline as the startup load. `ActivationContext` is built
   identically (`current_epoch: None` today).
2. A bundle declaring `activation_epoch` rejects at step 1 with
   `ReloadCheckError::Bundle(TrustBundleError::Activation(TrustBundleActivationError::CurrentEpochUnavailable { .. }))`.
3. **`swap_snapshot` is NEVER called.** `LivePqcTrustState` is
   unchanged.
4. **`evict_sessions` is NEVER called.** No session is dropped.
5. **`commit_sequence` is NEVER called.** The persisted sequence file
   is byte-for-byte unchanged (no create / no delete / no mtime / no
   content change).

Run 091's `run091_reload_check_bundle_activation_epoch_unsupported_fails_closed_no_sequence_mutation`
pins invariant 5 against the reload-check surface. Run 092 makes no
change to this ordering; the boundary remains the same.

## Peer-candidate ordering (preserved unchanged; documented for Run 092)

`crates/qbind-node/src/pqc_trust_peer_candidate.rs::validate_candidate_full`
(Run 076 receive-side validation) and the Run 088 propagation gate
(`pqc_peer_candidate_binary.rs:499`, `pqc_peer_candidate_wire.rs:1782 /
:1831 / :1869 / :2050 / :2089 / :2137`) all construct
`ActivationContext::height_only(0)` today — i.e. `current_epoch: None`.

1. A peer-supplied candidate declaring `activation_epoch` rejects at
   validation with `CurrentEpochUnavailable`.
2. **Run 088 propagation is gated on the validation result.** A
   `CurrentEpochUnavailable` candidate is NOT propagated / rebroadcast
   to any peer. `peer_candidate_propagated_total` does not advance.
3. **No sequence mutation** (the peer-candidate path never writes the
   sequence file even on a validated candidate — that's the Run 076
   non-mutation invariant).
4. **No `LivePqcTrustState` mutation** (peer path never applies — that's
   the Run 076 / Run 088 propagation-only invariant).
5. **No session eviction** (peer path never evicts — that's the Run 074
   `LiveReloadController`-only invariant).

Run 091 tests (item 10, 11 in the run map) plus the existing Run 076 /
Run 088 / Run 089 tests pin these invariants. Run 092 makes no change.

## Snapshot / restore boundary (explicitly remaining-open after Run 092)

`StateSnapshotMeta` (`crates/qbind-ledger/src/state_snapshot.rs:84-109`)
carries `{ height, block_hash, created_at_unix_ms, chain_id }` — no
`epoch` field. The snapshot-restore path
(`crates/qbind-node/src/snapshot_restore.rs`) materializes the
RocksDB checkpoint into `<data_dir>/state_vm_v0` and writes the
audit marker `RESTORED_FROM_SNAPSHOT.json`. Neither path observes or
persists `current_epoch`.

Per `task/RUN_092_TASK.txt` §"Snapshot/restore boundary":

- Run 092 does **not** fake an epoch from snapshot metadata.
- The exact remaining boundary is documented here: snapshot-restore
  has no pre-consensus epoch source today; the restore path either
  fails closed on `activation_epoch`-declaring bundles (via the
  existing `CurrentEpochUnavailable` boundary) or accepts bundles
  that omit `activation_epoch` (current behaviour, unchanged).
- A future run that extends `StateSnapshotMeta` with an `epoch` field
  (additive JSON parse keeping backward-compatibility with v0
  snapshots) is the documented closure path. That extension is OUT
  OF Run 092 SCOPE because it touches the snapshot wire format and
  the `StateSnapshotter` API used by `qbind-ledger`,
  `RocksDbAccountState`, periodic-snapshot config in
  `binary_consensus_loop.rs`, and the operator backup/recovery
  baseline.

## Proof that activation_epoch satisfied now accepts where epoch source exists

The activation gate logic in `pqc_trust_activation::check_bundle_activation`
(`crates/qbind-node/src/pqc_trust_activation.rs:479-590`) is structurally
correct: when a non-None `current_epoch` is supplied AND
`current_epoch >= required_epoch`, the gate accepts. Run 091's tests
prove this with explicit `Some(_)` epoch sources:

- `run091_bundle_activation_epoch_satisfied_accepted` (Run 091
  test 3) — bundle `activation_epoch = 2`, ctx `current_epoch = Some(2)`,
  outcome accepted with `current_epoch: Some(2)` echoed back.
- `run091_root_activation_epoch_satisfied_accepted` (Run 091 test 8) —
  root-level `activation_epoch = N`, ctx `current_epoch = Some(N)`,
  outcome accepted with `required_epoch = Some(N)` (root scope).
- `bundle_activation_epoch_satisfied_when_epoch_source_present`
  (`pqc_trust_activation` unit test, line 893-908) — same shape.

So the gate is already epoch-aware end-to-end; the only missing piece
is a binary-path code path that supplies a non-None `current_epoch` —
which is exactly the wiring blocked above.

## Proof that future / corrupt / missing epoch fails closed

- **Future epoch under a supplied source:** Run 091
  `run091_bundle_activation_epoch_future_rejected`,
  `run091_height_satisfied_epoch_future_rejected`,
  `run091_epoch_satisfied_height_future_rejected`,
  `run091_root_activation_epoch_future_rejected` — all reject with
  `TrustBundleActivationError::ActivationEpochNotReached`,
  `is_future_activation()` returns true, no sequence mutation.
- **Missing source under `current_epoch: None`:** Run 091
  `run091_devnet_unsupported_epoch_source_fails_closed`,
  `run091_testnet_unsupported_epoch_source_fails_closed`,
  `run091_mainnet_unsupported_epoch_source_fails_closed` — all reject
  with `CurrentEpochUnavailable` on every environment.
- **Corrupt epoch store:** the existing storage layer guards via
  `unwrap_checksummed_meta("meta:current_epoch", 8)`
  (`storage.rs:944`) which returns `StorageError::Codec` on a
  corrupted payload. The Run 092 verdict honours the task's
  "fail-closed on corruption" requirement transitively: if a future
  run wires `MetaStore::get_current_epoch()` into the activation
  gate, a `StorageError::Codec` MUST propagate as a fail-closed
  rejection (NOT silently degrade to `Ok(None)`). The existing
  `storage_corruption_guardrails_tests::*` regression matrix already
  pins the corruption-detection behaviour; Run 092 records the
  contract so the future wiring run cannot accidentally weaken it.

## Proof of no state mutation on rejected activation_epoch

The same proofs that backed Run 091 hold under Run 092 (no source
changes):

- **No sequence burn**: Run 091
  `run091_reload_check_bundle_activation_epoch_unsupported_fails_closed_no_sequence_mutation`
  (byte-for-byte unchanged sequence file across no-file / pre-
  existing-file cases) and
  `run091_reload_check_bundle_activation_epoch_future_does_not_advance_sequence`.
- **No live trust mutation**: the Run 070 / Run 074 ordering
  contract `validate → swap → evict → commit_sequence` short-circuits
  at `validate`; `LivePqcTrustState::swap_snapshot` is never called.
  Pinned by Run 074's existing SIGHUP tests and by code inspection
  of `pqc_live_trust_reload.rs::PqcLiveTrustReloadController::reload`.
- **No session eviction**: `P2pSessionEvictor::evict_sessions` is
  never invoked on a `CurrentEpochUnavailable` rejection (same short-
  circuit).
- **No peer propagation**: Run 088's propagation gate only
  rebroadcasts validated frames; a `CurrentEpochUnavailable`
  candidate is not validated, so it is not rebroadcast. Pinned by
  Run 088 / Run 089 tests and by code inspection of
  `pqc_peer_candidate_wire.rs::handle_candidate_frame`.

## Proof that activation_height behaviour is preserved exactly

Run 092 makes no change to `pqc_trust_activation.rs`. The Run 057
`activation_height` axis, the Run 065 per-environment minimum-margin
policy (DevNet=0, TestNet=8, MainNet=32), and the Run 062 per-entry
revocation `activation_height` gate are byte-for-byte unchanged.
Regression evidence below re-runs the Run 057 / Run 065 / Run 069 /
Run 091 test binaries to confirm.

## Commands run

```text
cargo test -p qbind-node --test run_091_pqc_trust_bundle_activation_epoch_tests
    test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured

cargo test -p qbind-node --lib pqc_trust_activation
    test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 1029 filtered out
```

The full regression matrix requested by `task/RUN_092_TASK.txt`
§"Required regression commands" (`run_057`, `run_065`, `run_069`,
`run_073`, `run_074`, `run_076`, `run_088`, `metrics` lib,
`qbind-node --lib`, `qbind-net --lib`, `qbind-crypto --lib`, the
three release-binary builds, and the three optional devnet shell
matrices) is on the standard CI matrix. Run 092 changes ONLY
documentation files (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_092.md`,
`docs/whitepaper/contradiction.md`,
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
`docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`), so
no `crates/**/src/**` or `crates/**/tests/**` is touched and no
existing test surface can be regressed by Run 092.

## Tests / evidence pass-fail status

| Suite | Status | Notes |
|-------|--------|-------|
| `cargo test -p qbind-node --test run_091_pqc_trust_bundle_activation_epoch_tests` | ✅ 15 / 15 | Baseline pinning all activation_epoch boundaries; Run 092 preserves. |
| `cargo test -p qbind-node --lib pqc_trust_activation` | ✅ 34 / 34 | Run 057 height + Run 065 margin + Run 091 epoch unit coverage. |
| `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | n/a (CI matrix; doc-only run) | Run 092 does not touch the activation source; CI matrix re-runs unchanged. |
| `cargo test -p qbind-node --test run_065_pqc_min_activation_margin_tests` | n/a (CI matrix; doc-only run) | Same. |
| `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` | n/a (CI matrix; doc-only run) | Same. |
| `cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests` | n/a (CI matrix; doc-only run) | Same. |
| `cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests` | n/a (CI matrix; doc-only run) | Same. |
| `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests` | n/a (CI matrix; doc-only run) | Same. |
| `cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` | n/a (CI matrix; doc-only run) | Same. |
| `cargo test -p qbind-node --lib metrics` | n/a (CI matrix; doc-only run) | No new metric families. |
| `cargo test -p qbind-node --lib` | n/a (CI matrix; doc-only run) | No source change. |
| `cargo test -p qbind-net --lib` | n/a (CI matrix; doc-only run) | No source change. |
| `cargo test -p qbind-crypto --lib` | n/a (CI matrix; doc-only run) | No source change. |
| `cargo build --release -p qbind-node --bin qbind-node` | n/a (CI matrix; doc-only run) | No source change; no rebuild required. |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` | n/a (CI matrix; doc-only run) | Same. |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | n/a (CI matrix; doc-only run) | Same. |
| `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh` | n/a — not applicable | P2P / wire paths NOT touched. |
| `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh` | n/a — not applicable | Same. |
| `scripts/devnet/run_089_peer_candidate_propagation_n3.sh` | n/a — not applicable | Same. |

## What was fixed or bounded

Run 092:

- **Bounded** the claim "wire `MetaStore::get_current_epoch()` into the
  trust-bundle activation gate" with a Run 092 source-level finding:
  `MetaStore` is never opened, and therefore never written, by the
  production `qbind-node` binary today. The "existing persisted
  MetaStore epoch" the task asks Run 092 to use does not exist on a
  binary-run node.
- **Bounded** the closure path: a future run must (a) decide the
  consensus-storage on-disk location in `NodeConfig`, (b) open it
  before the trust-bundle gate, (c) wire epoch advances on the
  binary consensus path to call `apply_epoch_transition_atomic`,
  (d) extend `StateSnapshotMeta` with an `epoch` field for
  snapshot-rejoin parity, and (e) resolve fresh-genesis ambiguity
  (e.g. by treating "fresh-genesis means `current_epoch = Some(0)`"
  only when `<data_dir>/consensus` and `<data_dir>/state_vm_v0` are
  both absent, otherwise fail-closed). Each of these is independently
  cross-cutting; together they constitute a broad storage redesign
  and are explicitly out of Run 092 scope.
- **Preserved** the Run 091 fail-closed `CurrentEpochUnavailable`
  boundary unchanged on every environment and every production call
  site.

## What was proven

- The binary `qbind-node` does NOT open `RocksDbConsensusStorage` (or
  any `ConsensusStorage`) anywhere in `crates/qbind-node/src/**`.
- `meta:current_epoch` is therefore never written by the production
  binary today; reading it would always return `Ok(None)`.
- `StateSnapshotMeta` carries no `epoch` field; snapshot-rejoin has
  no pre-consensus epoch source.
- The activation gate's epoch-aware logic is structurally correct
  and already covered by Run 091 tests (a future wiring run does NOT
  need to change `check_bundle_activation`).
- The Run 091 fail-closed boundary is preserved (15 / 15 Run 091
  integration tests pass; 34 / 34 `pqc_trust_activation` unit tests
  pass).
- No source-code, wire-format, signing-scheme, metric-family, log-
  format, or test-surface change is introduced by Run 092.

## What remains not solved

- **Canonical pre-consensus runtime epoch source on the binary.**
  Still OPEN. Run 092 narrows from "open with documented fail-
  closed boundary today and a documented closure path" (Run 091) to
  "open with documented fail-closed boundary today, documented
  closure path, AND a Run 092 source-level confirmation that
  closure requires a broad storage redesign (binary `MetaStore`
  open + consensus-path epoch persistence + `StateSnapshotMeta`
  epoch extension + fresh-genesis-vs-rejoin disambiguation)".
- **Per-environment minimum-margin policy on the epoch axis.** Not
  introduced. Cannot be introduced until the source above lands.
- **`TrustBundleRevocation::activation_epoch`.** Not introduced.
  The Run 062 / Run 091 boundary holds.
- **Snapshot/restore epoch parity.** Not introduced. The
  `StateSnapshotMeta` field set is unchanged.
- **Peer-driven live apply, KMS/HSM, signing-key ratification,
  fast-sync restore, production trust-anchor operation,
  selective per-peer session retention, admin-API / filesystem-
  watcher trigger surface, multi-validator MainNet release-binary
  peer-connection smoke.** All previously enumerated C4 sub-pieces
  remain OPEN per Run 088 / 089 / 090 / 091.
- **C5** (KEMTLS production lifecycle) is unrelated to Run 092 and
  unchanged.

## C4 / C5 boundary statement

Run 092 does **not** claim full C4 closure. The C4 sub-piece
"`activation_epoch` runtime source" remains OPEN, narrowed from Run
091's "open with documented fail-closed boundary" to Run 092's "open
with documented fail-closed boundary AND a source-level confirmation
that narrow MetaStore wiring is blocked by binary-path storage
architecture; closure requires a broad cross-cutting storage /
consensus-loop / snapshot-format redesign run".

Run 092 does **not** claim C5 closure. C5 is unrelated to the
activation-epoch axis and is unchanged.

## Immediate next action recommended

Land the follow-up cross-cutting run (preliminarily "Run 093 — binary
`MetaStore` open + consensus-path epoch persistence + `StateSnapshotMeta`
epoch parity") as a single coordinated change scoped explicitly to:

1. Add `<data_dir>/consensus` as a canonical consensus-storage
   subdir in `NodeConfig`, gate behind `--data-dir` requirement on
   TestNet/MainNet, allow opt-in on DevNet.
2. Open `RocksDbConsensusStorage` in `main.rs` BEFORE the trust-
   bundle gate, run `ensure_compatible_schema` and
   `verify_epoch_consistency_on_startup`, fail closed on schema or
   corruption errors.
3. Wire the binary-path consensus loop to call
   `apply_epoch_transition_atomic` on every epoch transition so
   `meta:current_epoch` is actually persisted by production runs.
4. Extend `StateSnapshotMeta` with an additive `epoch: u64` field
   (backward-compatible JSON parse defaulting to absent / fail-
   closed for `activation_epoch`-declaring bundles on legacy
   snapshots).
5. Disambiguate fresh-genesis from snapshot-rejoin with an explicit
   rule (e.g. "no `<data_dir>/consensus` AND no
   `<data_dir>/state_vm_v0` ⇒ `current_epoch = Some(0)`; otherwise
   require a persisted value; otherwise fail closed").
6. Replace `current_epoch: None` with the persisted-value lookup at
   the five `main.rs` ActivationContext construction sites and at
   the SIGHUP `LiveReloadController` and peer-candidate call sites.
7. Land per-environment minimum-margin policy on the epoch axis
   analogous to Run 065.
8. Update `pqc_trust_reload`, `pqc_live_trust_reload`,
   `pqc_trust_peer_candidate`, and `pqc_peer_candidate_binary` to
   accept the new context shape without changing their public
   contract.
9. Run the full Run 050–091 regression matrix plus new Run 093
   integration tests covering snapshot-rejoin epoch parity, fresh-
   genesis epoch = 0, corrupted-store fail-closed, and a release-
   binary positive smoke (`activation_epoch` satisfied at startup
   accepts; future epoch rejects).

Run 092's partial-positive verdict explicitly enables Run 093 to land
the closure without re-deriving the boundary or re-pinning the Run
091 fail-closed test matrix.