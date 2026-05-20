# QBIND DevNet Evidence — Run 093

**Objective:** Establish the **minimum production binary-path
`ConsensusStorage` lifecycle and durable epoch persistence
groundwork** needed before `activation_epoch` can be safely consumed
by PQC trust-bundle activation (per `task/RUN_093_TASK.txt`). The
production `qbind-node` binary must own and open a canonical
`ConsensusStorage` instance on the real binary path, run schema /
recovery checks before consensus starts, and persist `current_epoch`
through the existing `MetaStore` mechanism — **without** yet
consuming `current_epoch` for PQC trust-bundle activation.

**Verdict:** **strongest positive** for the bounded scope, **partial
positive** for the broader C4 axis. The production `qbind-node`
binary now opens `RocksDbConsensusStorage` at the canonical
`<data_dir>/consensus` location on every production startup path
(LocalMesh and P2P), runs the T104 schema-compat check, runs the M16
incomplete-epoch-transition / consistency check, probes
`meta:current_epoch`, and surfaces an explicit
`NoConsensusStorage` / `PresentNoCommittedEpoch` / `CommittedEpoch(u64)`
distinction. Storage open / schema / recovery / probe failures
fail-closed with non-zero exit and an operator-readable error.
Committed-epoch persistence across restart is proven by exercising
the existing `ConsensusStorage::put_current_epoch` /
`get_current_epoch` MetaStore APIs through Run 093's own surface
(`tests/run_093_production_consensus_storage_lifecycle_tests.rs`).
The production consensus loop on the binary path still does **not**
emit epoch transitions onto `apply_epoch_transition_atomic`, so the
binary-path durable epoch state remains `PresentNoCommittedEpoch`
end-to-end at startup — this is the documented partial-positive
boundary that a later run must close by wiring binary-path epoch
transitions. Run 091/092 `CurrentEpochUnavailable` trust-bundle
fail-closed behaviour is preserved unchanged on every environment
(DevNet, TestNet, MainNet) at every production call site: every
`ActivationContext` continues to be built with `current_epoch: None`.
No synthetic epoch is introduced; no epoch is read from wall-clock or
block height; no fallback path is invented; no
`--p2p-trusted-root` fallback is used; no DummySig / DummyKem /
DummyAead is used; no sequence regression occurs. Run 093 does **not**
claim full C4 closure and does **not** claim C5 closure.

## Files changed

- `crates/qbind-node/src/production_consensus_storage.rs` (**new**) —
  the Run 093 lifecycle module: `ConsensusStorageState` enum,
  `OpenedProductionConsensusStorage`, `ProductionConsensusStorageError`,
  `open_production_consensus_storage(&NodeConfig)`, 7 unit tests.
- `crates/qbind-node/src/node_config.rs` — added
  `NodeConfig::consensus_storage_dir()` returning
  `Some(<data_dir>/consensus)` when `data_dir` is set, `None` otherwise.
  No other `NodeConfig` field, default, or invariant changed.
- `crates/qbind-node/src/lib.rs` — registered `pub mod
  production_consensus_storage`.
- `crates/qbind-node/src/main.rs` — imported the new module; inserted
  the Run 093 lifecycle open call **after** `VmV0RuntimeState::open_from_config`
  and **before** the network-mode dispatch (so all early-exit
  validation modes — `--p2p-trust-bundle-reload-check`,
  `--p2p-trust-bundle-reload-apply`, peer-candidate check — are
  unaffected); fail-closed on any error with operator-readable
  message; the lifecycle handle is held in `main`'s scope for the
  entire binary lifetime and is explicitly logged + dropped on clean
  shutdown.
- `crates/qbind-node/tests/run_093_production_consensus_storage_lifecycle_tests.rs`
  (**new**) — 12 integration tests pinning the canonical path,
  startup-state distinction, restart preservation, fail-closed
  behaviour, MetaStore-API-only contract, log-summary stability, and
  the no-conversion-to-`ActivationContext` invariant.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md` (**new** — this
  document).
- `docs/devnet/run_093_smoke_n1_first_start.stderr.log` /
  `.stdout.log` (**new**) — N=1 release-binary smoke evidence
  (fresh open).
- `docs/devnet/run_093_smoke_n1_restart.stderr.log` / `.stdout.log`
  (**new**) — N=1 release-binary smoke evidence (restart preserves
  storage state).
- `docs/whitepaper/contradiction.md` — Run 093 partial-positive C4
  entry; **no** C4 closure, **no** C5 closure.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — §11 Run 093
  mapping row.

No changes under `crates/qbind-*` outside `qbind-node`. No new
dependencies. No new metric families. No CLI surface change. No
change to the trust-bundle wire format. No change to
`pqc_trust_activation::ActivationContext` shape or to the call sites
that construct it.

## ConsensusStorage source investigation

Re-confirmed from Run 092's source survey, with one addition for Run 093:

| # | Source | Persisted? | Opened on binary path? | Run 093 disposition |
|---|--------|-----------|------------------------|---------------------|
| 1 | `MetaStore::get_current_epoch()` / `meta:current_epoch` (`crates/qbind-node/src/storage.rs:200`, `:323`, `:912-944`) | Yes (u64 big-endian with checksummed-meta wrap, `apply_epoch_transition_atomic`) | **Yes — Run 093 lands this**. `open_production_consensus_storage` opens `RocksDbConsensusStorage` at `<data_dir>/consensus` and probes the existing `get_current_epoch()` API. Pre–Run 093: not opened by `main.rs`. | Used. Surfaced via `ConsensusStorageState::CommittedEpoch(u64)` / `PresentNoCommittedEpoch`. **Not yet consumed by trust-bundle activation.** |
| 2 | `StateSnapshotMeta` (`crates/qbind-ledger/src/state_snapshot.rs:84-109`) | Yes, on snapshot create | Yes (already opened by `apply_snapshot_restore_if_requested`) | No `epoch` field. Snapshot epoch parity is out of Run 093 scope and remains documented-open. |
| 3 | `BasicHotStuffEngine` epoch / `EpochTransitionMarker` | No (in-memory engine state) | Yes (engine is in-process), but no production epoch-transition events emitted today | The production binary's consensus loop does not yet wire epoch transitions onto `apply_epoch_transition_atomic`. Therefore on a freshly-opened production database `meta:current_epoch` remains unwritten end-to-end. This is the partial-positive boundary. |
| 4 | Wall-clock derived "epoch" | n/a | n/a | Forbidden by task. Not used. |
| 5 | Block height as synthetic epoch | n/a | n/a | Forbidden by task (no canonical mapping defined). Not used. |
| 6 | `VM-v0 RocksDB` state (`<data_dir>/state_vm_v0`) | Partially (account state) | Yes (T164 already opens this) | Out of consensus-epoch surface. Not used. |

**Re-grep at Run 093 baseline:**

```
grep -rn "RocksDbConsensusStorage::open" crates/qbind-node/src/**.rs
```

Pre-Run-093, this returned only doc-comments. After Run 093 it returns:

- `crates/qbind-node/src/production_consensus_storage.rs:...` —
  the new production call site.
- `crates/qbind-node/src/storage.rs:...` — doc-comments (unchanged).

The binary now has exactly one production call site, in
`production_consensus_storage::open_production_consensus_storage`,
invoked exactly once per process by `main()` immediately after
`VmV0RuntimeState::open_from_config` and before the network-mode
dispatch.

## Canonical storage path decision

**Decision:** `<data_dir>/consensus`. Resolved deterministically by
`NodeConfig::consensus_storage_dir()`.

- **Deterministic** — single resolution rule (`data_dir.join("consensus")`),
  no temp fallback, no environment-dependent hidden path, no env-var
  override.
- **Mirrors the existing T164 VM-v0 layout** (`<data_dir>/state_vm_v0`)
  for operator familiarity.
- **No-data-dir branch is an explicit state, not a hidden fallback.**
  When `NodeConfig.data_dir` is `None`,
  `open_production_consensus_storage` returns the
  `ConsensusStorageState::NoConsensusStorage` variant rather than
  inventing a temp path. TestNet/MainNet already require `data_dir`
  via existing invariant validation (`NodeConfig::validate_mainnet_invariants`),
  so this branch is only reachable on DevNet ad-hoc smoke
  invocations that explicitly opt out of persistence.
- **Fail-closed on open / schema / recovery / probe errors** — any
  failure causes a non-zero `qbind-node` exit with an
  operator-readable message that names the canonical path and points
  at this evidence document and `contradiction.md` C4.

## Startup ordering

The Run 093 lifecycle open is inserted at exactly one point in
`main.rs`, **after** the existing VM-v0 open and **before** the
network-mode dispatch. The ordering relative to all prior runs is
preserved:

1. `apply_snapshot_restore_if_requested` (B3) — unchanged.
2. Snapshot → `RestoreBaseline { snapshot_height, snapshot_block_id }`
   — unchanged. `StateSnapshotMeta` still has no `epoch` field.
3. `--p2p-trust-bundle-reload-check` early-exit validation — runs
   **before** Run 093's storage open (so reload-check on DevNet
   without `--data-dir` continues to work, preserving the Run 069 /
   077 contract).
4. `--p2p-trust-bundle-reload-apply` runtime apply early-exit —
   unchanged.
5. Peer-candidate `0x05` validation early-exit — unchanged.
6. Other early-exit validation modes — unchanged.
7. `node_metrics`, metrics HTTP server spawn — unchanged.
8. `VmV0RuntimeState::open_from_config` (T164) — unchanged.
9. **NEW** — Run 093 `open_production_consensus_storage(&config)`:
   - if `data_dir` is unset → `NoConsensusStorage` (log, continue).
   - else `RocksDbConsensusStorage::open(<data_dir>/consensus)` →
     `ensure_compatible_schema` (T104) →
     `verify_epoch_consistency_on_startup` (M16) →
     `get_current_epoch` probe → state ∈
     `{PresentNoCommittedEpoch, CommittedEpoch(u64)}`.
   - Any error fails closed with non-zero exit.
   - The `Arc<RocksDbConsensusStorage>` handle is held in `main`'s
     scope for the binary lifetime, then explicitly dropped on
     clean shutdown.
10. Network-mode dispatch (`run_local_mesh_node` / `run_p2p_node`) —
    unchanged. The trust-bundle activation paths inside these
    functions continue to build
    `ActivationContext { current_epoch: None }`.

The reload-check early-exit (step 3) is intentionally before the
Run 093 open: the validation-only check must not open production
storage. The `--p2p-trust-bundle` startup load happens inside
`run_p2p_node` after step 10 and is therefore protected by the
already-open storage handle but does not yet consume it.

## Epoch persistence behavior

- `RocksDbConsensusStorage::put_current_epoch` and `get_current_epoch`
  are the existing MetaStore APIs (unchanged). No new key, no new
  schema version, no new wrapper.
- Run 093 itself never writes `meta:current_epoch`. The production
  binary's consensus loop does not yet emit epoch transitions onto
  `apply_epoch_transition_atomic`. Therefore on a fresh production
  database `meta:current_epoch` remains unwritten end-to-end —
  the observed state is `PresentNoCommittedEpoch` on first start
  **and** on every subsequent restart on the same data dir, **until
  a later run wires binary-path epoch transitions**.
- Run 093 **proves** that when `meta:current_epoch` *is* written
  (through the existing `put_current_epoch` API — exercised by
  `run_093_committed_epoch_persists_across_restart`, by
  `run_093_committed_epoch_distinguishable_from_present_no_committed_epoch`,
  and by `run_093_uses_existing_metastore_apis_only`), it is observed
  by the next process via the Run 093 probe as `CommittedEpoch(u64)`.
  This pins the contract: **the day the binary consensus loop writes
  an epoch transition, Run 093 will surface it.** No source change
  in Run 093 will be required at that point.

## Startup state distinction

The three variants are mutually exclusive and operator-distinguishable
in startup logs by the stable tag (`ConsensusStorageState::tag()`):

| Variant | Tag | Meaning | `committed_epoch()` |
|---------|-----|---------|---------------------|
| `NoConsensusStorage` | `no-consensus-storage` | `data_dir` unset; no RocksDB lock held; not reachable in TestNet/MainNet because invariant validation requires `data_dir`. | `None` |
| `PresentNoCommittedEpoch` | `present-no-committed-epoch` | RocksDB opened cleanly; schema check passed; M16 recovery passed; `meta:current_epoch` is `Ok(None)`. | `None` |
| `CommittedEpoch(u64)` | `committed-epoch` | RocksDB opened cleanly; schema check passed; M16 recovery passed; `meta:current_epoch` is `Ok(Some(e))`. | `Some(e)` |

`ConsensusStorageState::committed_epoch()` is the **only** way to
extract a `u64`. It returns `None` for both `NoConsensusStorage` and
`PresentNoCommittedEpoch`, so a missing committed epoch can never
silently collapse to `Some(0)` for any caller.
`run_093_does_not_expose_consensus_storage_state_to_activation_context`
pins this contract at the type level.

## Snapshot/restore boundary

Unchanged. `StateSnapshotMeta` still has no `epoch` field. Adding one
would be a snapshot wire-format change touching every backup, every
operator runbook, and the snapshot create/validate path; it is
explicitly out of Run 093 scope (the task framing: *"This is NOT
snapshot redesign, except documenting required future parity."*). On
`--restore-from-snapshot`, the restored node opens
`<data_dir>/consensus` and observes `PresentNoCommittedEpoch` until
the binary-path consensus loop writes an epoch transition. The
fresh-genesis vs snapshot-rejoin asymmetry documented in Run 091/092
therefore continues unchanged. Snapshot epoch parity remains an
**OPEN** C4 sub-item, to be closed by a later run that adds
`epoch` to `StateSnapshotMeta` alongside the binary-path epoch-write
wiring.

## Run 091/092 fail-closed behavior preserved

**Verified by code inspection and by passing regression tests:**

- `main.rs` ActivationContext construction (every site:
  reload-check, reload-apply, peer-candidate, startup load) is
  unchanged. Every site still passes `current_epoch: None`.
- Run 093 introduces **no** call from `production_consensus_storage`
  to `pqc_trust_activation`. The
  `run_093_does_not_expose_consensus_storage_state_to_activation_context`
  test pins this at the type level
  (`ConsensusStorageState::committed_epoch()` returns plain
  `Option<u64>`, not an `ActivationContext`).
- Run 091's 15 integration tests
  (`tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs`) all
  pass unchanged.
- Trust-bundle paths therefore continue to fail-closed with
  `CurrentEpochUnavailable` on any bundle declaring
  `activation_epoch`. No sequence advance, no live-trust mutation, no
  metric mutation.

## Existing `activation_height` behavior preserved

- `run_057_pqc_trust_bundle_activation_tests` (12 tests) — pass.
- `run_065_pqc_min_activation_margin_tests` (12 tests) — pass.
- `ActivationContext.current_height` continues to be derived from
  `restore_baseline.snapshot_height` (or 0 fresh-genesis) at every
  call site. Run 093 makes no change to that derivation.

## Tests added (Run 093)

### Unit tests in `production_consensus_storage.rs` — 7 tests

1. `canonical_path_is_data_dir_slash_consensus`
2. `no_data_dir_yields_no_consensus_storage`
3. `fresh_open_is_present_no_committed_epoch`
4. `committed_epoch_is_distinguishable_from_present_no_committed_epoch`
5. `committed_epoch_persists_across_restart`
6. `log_summary_includes_state_tag_and_epoch_when_committed`
7. `handle_is_arc_and_can_be_cloned_for_lifetime_holding`

### Integration tests in `tests/run_093_production_consensus_storage_lifecycle_tests.rs` — 12 tests

1. `run_093_canonical_path_is_data_dir_slash_consensus`
2. `run_093_no_data_dir_yields_none`
3. `run_093_no_data_dir_open_yields_no_consensus_storage_state`
4. `run_093_fresh_open_with_data_dir_is_present_no_committed_epoch`
5. `run_093_committed_epoch_distinguishable_from_present_no_committed_epoch`
6. `run_093_committed_epoch_persists_across_restart`
7. `run_093_open_failure_on_locked_db_fails_closed`
8. `run_093_open_failure_on_unwritable_data_dir_fails_closed`
9. `run_093_uses_existing_metastore_apis_only`
10. `run_093_state_tag_stability`
11. `run_093_log_summary_includes_state_and_path`
12. `run_093_does_not_expose_consensus_storage_state_to_activation_context`

## Commands run / pass-fail status

All commands run from repo root. All listed are required by
`task/RUN_093_TASK.txt` §"Required regression commands". Status as of
this evidence.

| Command | Result |
|---------|--------|
| `cargo test -p qbind-node --lib production_consensus_storage` | **PASS** (7 / 7) |
| `cargo test -p qbind-node --test run_093_production_consensus_storage_lifecycle_tests` | **PASS** (12 / 12) |
| `cargo test -p qbind-node --test run_091_pqc_trust_bundle_activation_epoch_tests` | **PASS** (15 / 15) |
| `cargo test -p qbind-node --lib pqc_trust_activation` | **PASS** (34 / 34, 1036 filtered) |
| `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | **PASS** (12 / 12) |
| `cargo test -p qbind-node --test run_065_pqc_min_activation_margin_tests` | **PASS** (12 / 12) |
| `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` | **PASS** (12 / 12) |
| `cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests` | **PASS** (10 / 10) |
| `cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests` | **PASS** (10 / 10) |
| `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests` | **PASS** (16 / 16) |
| `cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` | **PASS** (5 / 5) |
| `cargo test -p qbind-node --lib metrics` | **PASS** (116 / 116) |
| `cargo test -p qbind-node --lib` | **PASS** (1070 / 1070) |
| `cargo test -p qbind-net --lib` | **PASS** (17 / 17) |
| `cargo test -p qbind-crypto --lib` | **PASS** (68 / 68) |
| `cargo build --release -p qbind-node --bin qbind-node` | **PASS** |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` | **PASS** |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | **PASS** |

No new failures, no flakes, no regressions.

## Release-binary evidence (N=1)

Run from the release binary (`./target/release/qbind-node`) twice
against the same fresh `--data-dir /tmp/run093_data` to prove
canonical-path open + restart-preservation behaviour.

**First start (`docs/devnet/run_093_smoke_n1_first_start.stderr.log`):**

```
[T104] No schema version found in storage - treating as legacy v0 (compatible)
[M16] Epoch consistency check passed: current_epoch=None
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=/tmp/run093_data/consensus
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
```

**Restart on the same data_dir (`docs/devnet/run_093_smoke_n1_restart.stderr.log`):**

```
[T104] No schema version found in storage - treating as legacy v0 (compatible)
[M16] Epoch consistency check passed: current_epoch=None
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=/tmp/run093_data/consensus
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
```

**On-disk layout after the two starts (`ls -la /tmp/run093_data/consensus`):**

```
000008.log
CURRENT
IDENTITY
LOCK
LOG
LOG.old.1779265487228550
MANIFEST-000009
```

i.e. the RocksDB column-family layout written by `RocksDbConsensusStorage::open`
at the canonical `<data_dir>/consensus` path, present on disk after
the binary exited, and re-opened cleanly on the second start.

Mapped against `task/RUN_093_TASK.txt` §"Release-binary evidence":

1. ✅ N=1 production qbind-node starts with canonical
   `<data_dir>/consensus` opened.
2. ✅ Storage path exists and is deterministic
   (`/tmp/run093_data/consensus`).
3. ✅ Restart preserves storage state (RocksDB manifest persists;
   second start re-opens at the same path with the same
   `present-no-committed-epoch` state because the binary-path
   consensus loop does not yet emit epoch transitions).
4. **Partial.** Committed-epoch persistence across restart is
   **proven** at the API level by the Run 093 unit + integration
   tests (`committed_epoch_persists_across_restart` etc.) but is
   **not** proven end-to-end on the release binary because the
   production binary's consensus loop does not yet emit epoch
   transitions onto `apply_epoch_transition_atomic`. This is the
   documented partial-positive boundary that closes when a later run
   wires binary-path epoch transitions.
5. ✅ Storage-open / schema / recovery errors fail closed (tested in
   `run_093_open_failure_on_locked_db_fails_closed` and
   `run_093_open_failure_on_unwritable_data_dir_fails_closed`).
6. ✅ `activation_epoch` trust-bundle still fails closed with
   `CurrentEpochUnavailable` (all 15 Run 091 integration tests pass
   unchanged).
7. ✅ `activation_epoch` omitted behavior unchanged (Run 091/057/065
   tests pass unchanged).
8. ✅ No `--p2p-trusted-root` fallback (no such code path
   introduced).
9. ✅ No DummySig / DummyKem / DummyAead introduced.
10. ✅ No sequence regression (Run 088 / 069 / 073 / 074 / 076 tests
    pass unchanged).

## What was fixed or bounded

- **Fixed:** the architectural gap identified by Run 092 — the
  production `qbind-node` binary never opened
  `RocksDbConsensusStorage`. It now does, at a canonical path, with
  T104 schema-compat and M16 recovery checks, and a fail-closed
  startup. Future runs that need to read `meta:current_epoch` on the
  binary path no longer have to redesign storage lifecycle first;
  they can read directly from `ConsensusStorageState::CommittedEpoch(u64)`.
- **Bounded:** the trust-bundle activation surface is **not** wired
  to consume `current_epoch` yet. `ActivationContext { current_epoch:
  None }` is preserved at every call site, and Run 091's
  `CurrentEpochUnavailable` boundary remains the canonical
  trust-bundle behaviour today. This separation is intentional
  (storage groundwork only) and is enforced by
  `run_093_does_not_expose_consensus_storage_state_to_activation_context`.

## What was proven

- Production binary opens `<data_dir>/consensus` on every production
  startup path (LocalMesh, P2P) once and only once per process.
- Schema compatibility (T104) and incomplete-transition recovery
  (M16) run before any consensus activity begins.
- The three startup-state variants
  (`NoConsensusStorage` / `PresentNoCommittedEpoch` / `CommittedEpoch(u64)`)
  are mutually exclusive and operator-distinguishable in startup
  logs.
- Fresh-genesis does **not** silently become
  `current_epoch = 0` for trust-bundle activation (Run 091 boundary
  preserved; pinned by `ActivationContext { current_epoch: None }`
  at every call site and by Run 093's type-level test).
- The opened `RocksDbConsensusStorage` handle is held for the binary
  lifetime; the RocksDB lock is released on clean shutdown.
- A committed `meta:current_epoch` value written through the
  existing `put_current_epoch` API is observed by the Run 093 probe
  on the next process (proves the lifecycle, exercised by tests).
- The release binary opens the canonical path and re-opens it
  cleanly across restart (N=1 smoke evidence captured under
  `docs/devnet/run_093_smoke_n1_*.log`).
- All 15 Run 091 trust-bundle activation-epoch tests pass unchanged.
  All Run 057 / 065 / 069 / 073 / 074 / 076 / 088 regressions pass.
  Full `qbind-node --lib` (1070 tests), `qbind-net --lib` (17), and
  `qbind-crypto --lib` (68) pass.

## What remains not solved

These items are intentionally out of Run 093 scope and remain **OPEN**
on C4 / C5:

- **Binary-path consensus-loop epoch-transition wiring** — the
  production consensus loop does not yet emit epoch transitions onto
  `apply_epoch_transition_atomic`. Until it does, the observed
  binary-path state stays `PresentNoCommittedEpoch` end-to-end on the
  release binary.
- **Trust-bundle `activation_epoch` consumption** — `ActivationContext`
  continues to receive `current_epoch: None`. Closing this requires
  the binary-path epoch-transition wiring above plus a tight,
  explicit hand-off from `ConsensusStorageState::CommittedEpoch(u64)`
  into `ActivationContext.current_epoch` at every activation call
  site, and a documented snapshot-rejoin parity story.
- **Snapshot/restore epoch parity** — `StateSnapshotMeta` has no
  `epoch` field. Adding one is the snapshot wire-format change that
  cannot be hidden inside Run 093.
- **Peer-driven live apply** — out of Run 093 scope (Run 087 / 088
  remain the narrowed surface).
- **KMS / HSM custody** — unchanged; remains C4 open.
- **In-binary / on-chain bundle-signing-key ratification** —
  unchanged; remains C4 open.
- **Production fast-sync / consensus-storage restore** — unchanged;
  remains C4 open.
- **Per-environment production trust-anchor operation** — unchanged;
  remains C4 open.
- **Timeout-verification activation, forged-traffic rejection,
  transport-root dependency (C5)** — unrelated; C5 remains
  OPEN / narrowed.

## `contradiction.md` updated and why

Yes — `docs/whitepaper/contradiction.md` is updated with a Run 093
**partial-positive** entry under C4. The update:

- Records that the production binary now opens canonical
  `RocksDbConsensusStorage` at `<data_dir>/consensus`, runs T104 +
  M16 checks, and surfaces the three explicit startup-state variants.
- Records that the production binary-path consensus loop does not
  yet emit epoch transitions, so `meta:current_epoch` is not yet
  written on the binary path even though the storage lifecycle is
  now real.
- Pins that Run 091's `CurrentEpochUnavailable` trust-bundle
  fail-closed boundary is **preserved unchanged**.
- Records that Run 093 explicitly does **not** close full C4
  (peer-driven live apply, KMS/HSM custody, signing-key ratification,
  production fast-sync / consensus-storage restore, per-environment
  production trust-anchor operation, snapshot epoch parity remain
  OPEN) and explicitly does **not** claim C5 closure.
- Updates the immediate-next-action recommendation from Run 092's
  *"land binary `MetaStore` open + epoch persistence + snapshot
  parity"* to the narrower *"wire binary-path consensus-loop epoch
  transitions into `apply_epoch_transition_atomic`"* now that Run
  093 has landed the storage lifecycle.

The Run 093 update rule from the task is honoured per
`task/RUN_093_TASK.txt` §"contradiction.md update rules":

- **"If production binary opens canonical ConsensusStorage and epoch
  persistence is proven, record C4 narrowed."** Partial: storage is
  opened on the binary; epoch persistence is proven *at the API
  level* (by Run 093's own tests and by Run 088 / 091 / 092
  unchanged), but the binary-path consensus loop has not yet emitted
  an epoch transition to demonstrate it end-to-end on the release
  binary. → recorded as **partial-positive** with the exact boundary.
- **"Keep C4 open for activation_epoch consumption, snapshot epoch
  parity, peer-driven live apply, KMS/HSM, signing-key ratification,
  fast-sync/restore, and production trust-anchor operations."** —
  preserved.
- **"Do not close full C4."** — honoured.
- **"Do not claim C5 closure."** — honoured.

## Exact immediate next action recommended

**Run 094 — wire the production binary-path consensus loop's epoch
transitions onto `apply_epoch_transition_atomic` using the Run 093
canonical storage handle**, scoped to:

1. Pass the `Arc<RocksDbConsensusStorage>` handle from
   `production_consensus_storage::OpenedProductionConsensusStorage`
   into `binary_consensus_loop::BinaryConsensusLoopConfig` (option-
   typed, so DevNet `NoConsensusStorage` smoke continues to work).
2. At every binary-path epoch-transition event point in the
   consensus loop (search keys: `EpochTransitionMarker`,
   `EpochTransitionBatch::start_transition`, `EpochAwareNodeHotstuffHarness::apply_epoch_transition_atomic`),
   invoke `apply_epoch_transition_atomic` against the Run 093 handle
   when present. If no such event point exists yet in the *binary*
   loop, document the exact missing piece and stop — do **not**
   invent a synthetic epoch.
3. Add an integration test that:
   - Starts the binary-path consensus loop with a Run 093 storage
     handle.
   - Drives at least one real epoch transition (via the same path
     the test-harness `EpochAwareNodeHotstuffHarness` uses today).
   - Restarts the loop on the same storage and observes
     `ConsensusStorageState::CommittedEpoch(N)` for N > 0.
4. Continue to keep `ActivationContext { current_epoch: None }`. Do
   **not** consume the epoch for trust-bundle activation in Run 094
   — that hand-off is a separate, later run that also needs to
   address the snapshot-epoch-parity asymmetry.
5. Do **not** modify `StateSnapshotMeta`. Snapshot epoch parity is a
   separate cross-cutting run.

This is the smallest next step that closes the partial-positive
boundary of Run 093 (binary-path epoch writes) without introducing
the broader changes (trust-bundle epoch consumption, snapshot epoch
parity, peer-driven live apply, KMS/HSM, signing-key ratification)
that the task explicitly enumerates as remaining C4 open items.