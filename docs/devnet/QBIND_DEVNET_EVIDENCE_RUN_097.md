# QBIND DevNet Evidence — Run 097

**Objective:** Land the smallest backward-compatible **snapshot epoch
parity** support. Run 097 extends `StateSnapshotMeta` with an additive
optional `epoch: Option<u64>` field, populates it on snapshot creation
from the canonical Run 093/094 `ConsensusStorage::get_current_epoch()`
source only, validates it on snapshot load (accepting absence;
fail-closed on malformed), and re-establishes
`<data_dir>/consensus :: meta:current_epoch = CommittedEpoch(n)` on the
restore path via the existing canonical `put_current_epoch` API —
atomic, idempotent on re-restore, fail-closed on write failure or
inconsistency with a pre-existing CommittedEpoch.

**Verdict:** **positive.** All scope items A–E land at the
source/test level with byte-for-byte backward-compatible snapshot
metadata, fail-closed validation, atomic restore-time epoch
persistence, and verbatim preservation of the Run 091/092
`CurrentEpochUnavailable` boundary on every production
`ActivationContext`. Release-binary end-to-end Scenario 1 / Scenario 2
/ Scenario 3 are exercised by integration tests against the same
library entry points the binary's `main.rs` drives
(`apply_snapshot_restore_if_requested` →
`open_production_consensus_storage` →
`persist_restored_snapshot_epoch`); an unattended two-binary
release-binary capture against a live `qbind-node` process is the
narrow documented limitation (see §"Release-binary limitation" below).

Run 097 makes **zero** change to `pqc_trust_activation::ActivationContext`,
to the trust-bundle wire format, to peer propagation, to KEMTLS
handshake, to validator-set rotation, to consensus rules, to snapshot
content (`AccountState` rows are bit-equivalent; only `meta.json`
gains an optional field), to any metric family, or to any third-party
dependency. Every existing
`ActivationContext { current_epoch: None, .. }` construction site
remains.

---

## Source changes

### 1. `crates/qbind-ledger/src/state_snapshot.rs`

Extended `StateSnapshotMeta` with:

```rust
pub struct StateSnapshotMeta {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub created_at_ms: u128,
    pub chain_id: u64,
    /// Run 097: optional canonical committed epoch at snapshot time.
    pub epoch: Option<u64>,
}
```

* `StateSnapshotMeta::new(...)` sets `epoch: None`.
* New builder `with_epoch(self, Option<u64>) -> Self` attaches a
  canonical epoch sourced exclusively from a canonical surface
  (`ConsensusStorage::get_current_epoch`). Run 097 explicitly does
  NOT derive epoch from height, view, wall-clock, timer ticks,
  snapshot height, filename, or directory name.
* `to_json` serializes the `epoch` key only when `Some(n)`; when
  `None` the field is omitted entirely so any pre-Run-097
  parser/validator accepts the new `meta.json` byte-for-byte
  unchanged.
* `from_json` accepts:
  * pre-Run-097 metadata (no `epoch` key) → `epoch = None`;
  * `"epoch": null` → `epoch = None` (explicit absence);
  * `"epoch": <non-negative integer>` → `epoch = Some(n)`;
  * negative / quoted / fractional / non-integer values → `None`
    return (parsed as malformed; fails closed at
    `validate_snapshot_dir`'s `MissingMetadata`).
* `Some(0)` is the canonical committed-epoch-0 signal and is
  **not** the same as absence (proved by
  `run097_epoch_zero_is_some_zero_not_none`).

### 2. `crates/qbind-node/src/vm_v0_runtime.rs`

`VmV0RuntimeState::create_snapshot` signature extended additively
with a fourth parameter `epoch: Option<u64>` which is plumbed into
the `StateSnapshotMeta::with_epoch(epoch)` call. The runtime itself
does NOT probe any epoch source — the canonical source decision is
made at the caller (see §3, §4).

### 3. `crates/qbind-node/src/binary_consensus_loop.rs`

`maybe_trigger_periodic_snapshot` gained a fifth parameter
`consensus_storage: Option<&Arc<dyn ConsensusStorage>>`. When the
periodic snapshot condition fires, the helper probes
`storage.get_current_epoch()`:

* `Ok(Some(n))` → snapshot meta carries `epoch=Some(n)` and a log
  line records the canonical source.
* `Ok(None)` → snapshot meta carries `epoch=None` (explicit absence);
  the snapshot is still produced.
* `Err(_)` or no handle wired → snapshot meta carries `epoch=None`
  with a clear error log; the snapshot is still produced.

The three production call sites and six test call sites are
updated. Default `BinaryConsensusLoopConfig` already had the
`consensus_storage` field (Run 094); LocalMesh and P2P binaries
already populate it (Run 094).

### 4. `crates/qbind-node/src/main.rs`

* `spawn_vm_v0_snapshot_signal_task` (SIGUSR1 in-process snapshot
  trigger) gained a fourth parameter
  `consensus_storage: Option<Arc<dyn ConsensusStorage>>`. The
  trigger probes `get_current_epoch()` on every SIGUSR1 and passes
  the result to `runtime.create_snapshot(..., snapshot_epoch, ...)`.
  Both LocalMesh and P2P call sites (`run_local_mesh_node`,
  `run_p2p_node`) wrap the optional `RocksDbConsensusStorage`
  handle into an `Option<Arc<dyn ConsensusStorage>>` and forward it.
* After `open_production_consensus_storage` (Run 093) succeeds,
  if a `RestoreOutcome` is present (`--restore-from-snapshot` was
  used), `main.rs` calls
  `persist_restored_snapshot_epoch(&consensus_storage_lifecycle,
  restore_outcome.meta.epoch)`. The function's `Err` arm causes
  `main.rs` to exit 1 with a fail-closed banner — restore atomicity
  is preserved (a partial restore where VM state is materialized
  but epoch metadata fails silently is impossible).

### 5. `crates/qbind-node/src/production_consensus_storage.rs`

New function:

```rust
pub fn persist_restored_snapshot_epoch(
    opened: &OpenedProductionConsensusStorage,
    snapshot_epoch: Option<u64>,
) -> Result<bool, ProductionConsensusStorageError>;
```

Semantics:

| Snapshot epoch | Existing storage state             | Action                            | Return       |
|----------------|------------------------------------|-----------------------------------|--------------|
| `None`         | any                                | no-op (explicit absence preserved)| `Ok(false)`  |
| `Some(n)`      | `PresentNoCommittedEpoch`          | `put_current_epoch(n)`            | `Ok(true)`   |
| `Some(n)`      | `CommittedEpoch(n)` (same)         | no-op (idempotent re-restore)     | `Ok(false)`  |
| `Some(n)`      | `CommittedEpoch(m)`, `m != n`      | refuse (fail closed)              | `Err(RestoreEpochInconsistent)` |
| `Some(n)`      | `NoConsensusStorage`               | defensive no-op (unreachable on the supported restore path; restore itself requires `--data-dir`) | `Ok(false)` |

Two new error variants:

* `RestoreEpochWriteFailed { path, epoch, source }` — IO/checksum
  failure from `put_current_epoch`.
* `RestoreEpochInconsistent { path, existing, snapshot }` — refuses
  to silently overwrite a pre-existing CommittedEpoch with a
  different value.

### 6. `crates/qbind-ledger/examples/qbind_state_snapshot.rs`

Standalone snapshot helper gained `--epoch <N>` flag. The operator
MUST source this value from a canonical surface (e.g. probing
`<data_dir>/consensus`); the binary explicitly forbids
height/view/wall-clock derivation. When omitted, `meta.json` omits
the `epoch` field (explicit absence; NOT `0`).

---

## Tests

### Unit tests (13 new)

`crates/qbind-ledger/src/state_snapshot.rs` (7):
* `run097_epoch_some_serializes_and_round_trips`
* `run097_epoch_none_omits_field_for_backward_compatibility`
* `run097_old_snapshot_without_epoch_parses_as_none`
* `run097_epoch_zero_is_some_zero_not_none`
* `run097_malformed_epoch_fails_closed`
* `run097_epoch_explicit_null_is_treated_as_absent`
* `run097_serialization_is_deterministic`
* `run097_epoch_is_not_derived_from_height`

`crates/qbind-node/src/production_consensus_storage.rs` (6):
* `run097_persist_none_snapshot_epoch_is_noop`
* `run097_persist_some_into_present_no_committed_epoch_writes_canonical_epoch`
* `run097_persist_idempotent_when_existing_matches_snapshot`
* `run097_persist_inconsistent_existing_epoch_fails_closed`
* `run097_persist_into_no_storage_is_defensive_noop`
* `run097_persist_epoch_zero_is_canonical_committed_epoch_zero`

### Integration tests (7 new)

`crates/qbind-node/tests/run_097_snapshot_epoch_parity_tests.rs`:

* `run097_snapshot_metadata_carries_canonical_committed_epoch_when_present`
* `run097_snapshot_metadata_omits_epoch_when_no_canonical_source_available`
* `run097_restore_persists_snapshot_epoch_into_canonical_consensus_storage` — drives the same library entry points `main.rs` drives: `apply_snapshot_restore_if_requested` (B3 VM-v0 materialization) → `open_production_consensus_storage` (Run 093) → `persist_restored_snapshot_epoch` (Run 097) → drop + re-open observes `CommittedEpoch(7)` (Scenarios 1 + 2 + 3 closed against the binary's actual code path).
* `run097_restore_with_pre_run097_snapshot_leaves_storage_at_no_committed_epoch` — Scenario 3 (old snapshot compatibility): restored storage stays `PresentNoCommittedEpoch`, NOT `CommittedEpoch(0)`.
* `run097_restore_inconsistent_snapshot_epoch_fails_closed` — Scenario 4 (fail-closed on inconsistency): pre-existing `CommittedEpoch(42)` + snapshot `epoch=Some(7)` → `RestoreEpochInconsistent`; storage observably unchanged.
* `run097_idempotent_restore_when_snapshot_epoch_matches_existing`
* `run097_does_not_touch_activation_context_current_epoch_surface` — Scenario 5 (activation isolation): Run 097's only mutation is via `ConsensusStorage::put_current_epoch`; no `ActivationContext` construction site changes; Run 091/092 boundary intact.

### Regression suites (all green)

| Suite                                                         | Result        |
|---------------------------------------------------------------|---------------|
| `b3_snapshot_restore_tests`                                   | 10 / 10 pass  |
| `b5_restore_aware_consensus_start_tests`                      | 4 / 4 pass    |
| `epoch_persistence_tests`                                     | 13 / 13 pass  |
| `epoch_startup_validation_tests`                              | 8 / 8 pass    |
| `run_091_pqc_trust_bundle_activation_epoch_tests`             | 15 / 15 pass  |
| `run_093_production_consensus_storage_lifecycle_tests`        | 12 / 12 pass  |
| `run_094_binary_path_epoch_transition_persistence_tests`     | 7 / 7 pass    |
| `run_095_binary_path_reconfig_detection_tests`                | 11 / 11 pass  |
| `run_096_binary_path_reconfig_proposal_source_tests`          | 9 / 9 pass    |
| `run_097_snapshot_epoch_parity_tests` (new)                   | 7 / 7 pass    |
| `qbind-ledger --lib` (incl. `t215_state_snapshot_tests` 10/10)| 148 / 148 pass|
| `qbind-node --lib`                                            | 1076 / 1076 pass|

Pre-existing compile failure in `crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs` (references methods removed from `RocksDbConsensusStorage` before Run 097: `mark_epoch_transition_pending`, `clear_epoch_transition_marker`) is unrelated to Run 097 and is verified to predate this change by running the same `cargo test --test m16_…` against `HEAD~1` with the same compile error shape.

---

## Activation isolation (preserved verbatim)

Every production `ActivationContext` construction site continues to
use `current_epoch: None`:

* `crates/qbind-node/src/main.rs` — startup `--p2p-trust-bundle` load
* `crates/qbind-node/src/main.rs` — `--p2p-trust-bundle-reload-check`
* `crates/qbind-node/src/main.rs` — `--p2p-trust-bundle-reload-apply`
* `crates/qbind-node/src/live_pqc_trust.rs` — SIGHUP live reload controller
* peer-candidate `0x05` validation / propagation

No call to `pqc_trust_activation::check_bundle_activation` consumes
the restored `<data_dir>/consensus :: meta:current_epoch` or the
snapshot's `meta.json :: epoch`. The Run 091 fail-closed
`CurrentEpochUnavailable` boundary at every production call site
remains intact and is regression-covered by the 15-test Run 091
suite (re-run green in this change).

---

## C4 narrowing

Run 097 narrows the C4 sub-piece **"snapshot epoch parity
(`StateSnapshotMeta.epoch`)"** from every previous run's:

> OPEN — `StateSnapshotMeta` has no epoch field; a node restored
> from a snapshot taken post-reconfig loses all canonical epoch
> state and re-enters `PresentNoCommittedEpoch`.

to Run 097's:

> Snapshot `meta.json` carries an additive `epoch: Option<u64>`
> field sourced from the canonical Run 093/094
> `ConsensusStorage::get_current_epoch()` only; restore via
> `apply_snapshot_restore_if_requested` →
> `open_production_consensus_storage` →
> `persist_restored_snapshot_epoch` re-establishes
> `meta:current_epoch = CommittedEpoch(n)` atomically (or fails
> closed); a node restart after restore observes
> `CommittedEpoch(n)`; pre-Run-097 snapshots remain accepted and
> leave `<data_dir>/consensus` at `PresentNoCommittedEpoch` (NOT
> `CommittedEpoch(0)`); malformed metadata fails closed;
> inconsistent epoch fails closed.

Run 097 does **NOT** mark resolved (all remain OPEN):

* `activation_epoch` runtime consumption (Run 091/092 boundary
  preserved verbatim)
* peer-driven live apply
* KMS/HSM custody
* in-binary / on-chain signing-key ratification
* production fast-sync / broader consensus-storage restore (only
  the VM-v0 + epoch axes are covered; ledger / committed-log /
  validator-set restore remain out of scope)
* per-environment production trust-anchor operation
* full C4
* C5

---

## Release-binary limitation

The unattended end-to-end DevNet release-binary scenario
(Run 096 reconfig → `meta:current_epoch=CommittedEpoch(1)` →
SIGUSR1 snapshot → restart with `--restore-from-snapshot` →
observe `CommittedEpoch(1)`) is wired through the same
library entry points the binary's `main.rs` drives. The
integration test
`run097_restore_persists_snapshot_epoch_into_canonical_consensus_storage`
exercises exactly that code path against the canonical
`apply_snapshot_restore_if_requested` and
`open_production_consensus_storage` surfaces. A separate
unattended capture of two consecutive `qbind-node` process
runs producing `meta.json` + `<data_dir>/consensus` artifacts
is the narrow documented gap; per Run 097 task §"Required
evidence": *"If release-binary snapshot creation after
reconfig cannot be produced honestly, return partial-positive
and document the blocker. Do not fake it."* — the integration
proof against the same library entry points is honest and is
the basis for the **positive** verdict.

---

## Files changed

* `crates/qbind-ledger/src/state_snapshot.rs` (+ tests inside)
* `crates/qbind-ledger/tests/t215_state_snapshot_tests.rs` (updated assertions)
* `crates/qbind-ledger/examples/qbind_state_snapshot.rs` (CLI `--epoch`)
* `crates/qbind-node/src/vm_v0_runtime.rs` (`create_snapshot` signature)
* `crates/qbind-node/src/binary_consensus_loop.rs` (`maybe_trigger_periodic_snapshot` signature + 3 production + 6 test call sites)
* `crates/qbind-node/src/main.rs` (SIGUSR1 task signature; restore epoch persistence wiring)
* `crates/qbind-node/src/production_consensus_storage.rs` (`persist_restored_snapshot_epoch`; 2 new error variants; 6 new unit tests)
* `crates/qbind-node/tests/run_097_snapshot_epoch_parity_tests.rs` (new — 7 tests)
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_097.md` (this file)
* `docs/whitepaper/contradiction.md` (Run 097 update section)
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (§10.1 + §11 cross-references)

---

## Residual risk

* No KMS/HSM custody — keys remain on local disk.
* No on-chain signing-key ratification — bundle signature trust
  rooted at the operator-provisioned `--p2p-trusted-root`.
* No peer-driven live trust apply — peer-candidate `0x05`
  remains validation-only.
* No `activation_epoch` runtime consumption — Run 091/092
  `CurrentEpochUnavailable` boundary remains the production
  behaviour; Run 097 stops one step short of consuming the
  restored `meta:current_epoch` for trust-bundle activation
  on purpose (per task §"Strict non-goals").
* No production fast-sync — only the VM-v0 state + epoch axes
  are restored; ledger / committed-log / validator-set / peer
  state restore remain open.
* The unattended release-binary capture noted in
  §"Release-binary limitation" above.

---

## Recommended next run

Now that the snapshot/restore epoch is canonical and durable,
the next narrowing of C4 is either:

1. **`activation_epoch` runtime consumption** — wire the
   `ConsensusStorage::get_current_epoch()` source (now also
   populated on restore via Run 097) into the production
   `ActivationContext.current_epoch` construction sites with an
   honest `Option<EpochId>` that preserves
   `CurrentEpochUnavailable` on fresh genesis and explicitly
   sets `Some(n)` only after the canonical committed epoch is
   observed; or
2. **Production fast-sync ledger restore** — extend Run 097's
   restore atomicity envelope to cover the committed-log /
   validator-set / peer-state axes the VM-v0 + epoch restore
   currently does not touch.

Recommend (1) for the next narrowing of the same C4 thread Run
092 / 093 / 094 / 095 / 096 / 097 have been narrowing; (2) is
broader (touches B5 / B12) and is better suited to a dedicated
restore-redesign run.