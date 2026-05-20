# Run 098 — Wire canonical `meta:current_epoch` into production `ActivationContext.current_epoch`

## Verdict

**Partial-positive.** All six production trust-bundle activation surfaces
in `qbind-node` now construct `ActivationContext.current_epoch` from the
canonical Run 093 `<data_dir>/consensus` `meta:current_epoch` surface
(and the Run 097 restore-time write to it). All Run 091 / 092 fail-closed
invariants are preserved verbatim: missing epoch is **never** `Some(0)`,
fresh genesis remains `CurrentEpochUnavailable`, old snapshots without
epoch remain `CurrentEpochUnavailable`, storage read failures are
surfaced and treated as unavailable. `qbind-node --lib` is green (1082 /
1082) and every relevant regression suite passes with no changes
required. The "partial" qualifier applies only to release-binary
evidence: the new wiring is exercised end-to-end through the same
library entry points the binary uses, by 18 new unit and integration
tests, but is not separately captured as a `qbind-node` process log in
this run.

## Scope

Run 098 lands the smallest production-honest wiring of the canonical
`meta:current_epoch` value (Run 093 surface; Run 094 / 095 / 096
writers; Run 097 restore writer) into every `ActivationContext`
constructed by `qbind-node` for trust-bundle activation:

1. **Startup `--p2p-trust-bundle` load** — the canonical
   `Option<Arc<RocksDbConsensusStorage>>` handle that Run 093 opened and
   threaded through `run_local_mesh_node` / `run_p2p_node` is now also
   consulted before the trust-bundle loader builds its
   `ActivationContext`.

2. **`--p2p-trust-bundle-reload-check` CLI subcommand** — this block
   exits before the main consensus loop runs, so it opens its own
   canonical storage handle via the new
   `load_activation_current_epoch_for_cli(&NodeConfig)` helper and
   keeps it alive until process exit.

3. **`--p2p-trust-bundle-reload-apply-path` CLI subcommand** — same
   pattern as (2). The block constructs two `ActivationContext` values
   (one for the candidate validation, one for the baseline-bundle load
   that seeds the live trust handle); both share a single canonical
   epoch read.

4. **`--p2p-trust-bundle-peer-candidate-check` CLI subcommand** — same
   pattern as (2).

5. **SIGHUP live reload** (`spawn_run074_live_reload_task`) — the
   `Option<Arc<RocksDbConsensusStorage>>` handle is threaded into the
   task; on every SIGHUP trigger the task reads `meta:current_epoch`
   and calls `LiveReloadController::try_trigger_with_activation(now_secs,
   override_ctx)` with the canonical epoch override. The static
   `LiveReloadConfig::activation_ctx` captured at controller
   construction is therefore overridden per trigger so that epoch
   transitions that occur after the controller was built are honored.

6. **Live peer-candidate wire dispatcher**
   (`LivePeerCandidateWireDispatcher`) — gains a new
   `consensus_storage_for_epoch: Option<Arc<RocksDbConsensusStorage>>`
   field. On every dispatched frame the dispatcher reads
   `meta:current_epoch` and uses that value (NOT the closure-captured
   `self.activation_ctx.current_epoch`) for the
   `PeerCandidateWireRuntimeContext.activation_ctx.current_epoch`.

Run 098 does **not** introduce a new wire format, a new dependency, a
new metric family, a new CLI flag, or any new on-chain artifact. It
adds one library-grade helper module and one Boolean axis (presence /
absence of the canonical storage handle) to each construction site.

## Helper module

`crates/qbind-node/src/pqc_trust_activation_epoch.rs` exports:

- `pub enum ActivationEpochSource { Committed(u64), UnavailableNoCommittedEpoch }`
  with `as_option(&self) -> Option<u64>` mapping `Committed(n) →
  Some(n)` and `UnavailableNoCommittedEpoch → None`.
- `pub fn activation_epoch_source_from_lifecycle(opened:
  &OpenedProductionConsensusStorage) -> ActivationEpochSource` — the
  already-opened-at-startup path (reads from
  `opened.state.committed_epoch()`).
- `pub fn activation_epoch_source_from_storage(storage:
  Option<&Arc<RocksDbConsensusStorage>>) -> Result<ActivationEpochSource,
  StorageError>` — the running-node path (SIGHUP, live dispatcher).
- `pub fn load_activation_current_epoch_for_cli(config: &NodeConfig)
  -> Result<(ActivationEpochSource, OpenedProductionConsensusStorage),
  ProductionConsensusStorageError>` — the CLI-subcommand path.

The helper module is the **only** place in `qbind-node` allowed to
materialize an `ActivationEpochSource`. Every production
`ActivationContext.current_epoch` is now sourced from
`source.as_option()` and nothing else.

## Fail-closed semantics

| Storage state                             | `as_option()` | Bundle declaring `activation_epoch` |
|-------------------------------------------|---------------|-------------------------------------|
| No storage handle (DevNet ad-hoc)         | `None`        | `CurrentEpochUnavailable` (rejected) |
| `NoConsensusStorage` lifecycle state      | `None`        | `CurrentEpochUnavailable` (rejected) |
| `PresentNoCommittedEpoch` (fresh genesis) | `None`        | `CurrentEpochUnavailable` (rejected) |
| `CommittedEpoch(n)` from real reconfig    | `Some(n)`     | activated iff `activation_epoch ≤ n` |
| `CommittedEpoch(n)` from Run 097 restore  | `Some(n)`     | activated iff `activation_epoch ≤ n` |
| Storage read I/O error                    | `None` + log  | `CurrentEpochUnavailable` (rejected) |

Critical invariants pinned by tests:

- **Missing epoch is not epoch 0.** A storage with no committed epoch
  returns `UnavailableNoCommittedEpoch`, never `Committed(0)`. Run 098
  never coerces absence into `Some(0)`.
- **Fresh genesis remains `CurrentEpochUnavailable`.** A fresh
  `<data_dir>/consensus` with no committed reconfig and no restore
  carries no canonical epoch; bundles declaring `activation_epoch` fail
  closed.
- **Old snapshots without epoch remain `CurrentEpochUnavailable`.**
  Pre-Run-097 snapshots carry `epoch=None` in `meta.json`; restore via
  `persist_restored_snapshot_epoch` is a no-op
  (`Ok(false)`); post-restore storage is still
  `PresentNoCommittedEpoch`; bundles declaring `activation_epoch` fail
  closed.
- **Storage read errors are surfaced.** A RocksDB read failure at the
  SIGHUP / live-dispatcher path is logged via `eprintln!` (`[binary]
  Run 098: WARNING: ...`) before falling through to
  `current_epoch = None`. The failure mode is fail-closed (the trust
  state does not advance) but operator-visible.
- **Committed / restored epoch satisfies the epoch axis only.** Every
  other trust-bundle check (signature, environment, chain id,
  anti-rollback sequence peek, root status, revocation, validity
  window, local-leaf self-check) continues to run unchanged — they
  share the existing `check_bundle_activation` /
  `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
  entry points.

## Tests

- 6 unit tests in `crates/qbind-node/src/pqc_trust_activation_epoch.rs`
  (`#[cfg(test)] mod tests`):
  - `committed_epoch_lifecycle_maps_to_source`
  - `present_no_committed_epoch_maps_to_unavailable`
  - `no_consensus_storage_maps_to_unavailable`
  - `storage_handle_with_committed_epoch_returns_committed`
  - `storage_handle_with_no_epoch_returns_unavailable`
  - `no_storage_handle_returns_unavailable`

- 12 integration tests in
  `crates/qbind-node/tests/run_098_activation_epoch_canonical_wiring_tests.rs`:
  - `run098_canonical_helper_returns_committed_when_storage_has_epoch`
  - `run098_canonical_helper_returns_unavailable_when_no_committed_epoch`
  - `run098_canonical_helper_returns_unavailable_when_no_storage_handle`
  - `run098_canonical_helper_lifecycle_no_storage_state_maps_to_unavailable`
  - `run098_bundle_with_activation_epoch_passes_when_committed_epoch_satisfies`
  - `run098_bundle_with_activation_epoch_passes_when_committed_equals_required`
  - `run098_bundle_with_activation_epoch_rejects_future_epoch_via_canonical_source`
  - `run098_bundle_with_activation_epoch_rejects_when_canonical_unavailable`
  - `run098_bundle_with_activation_epoch_rejects_when_no_storage_handle_at_all`
  - `run098_bundle_without_activation_epoch_unchanged_by_canonical_wiring`
  - `run098_old_snapshot_without_epoch_still_rejects_activation_epoch`
  - `run098_restored_snapshot_with_epoch_satisfies_activation_epoch`

## Regression suite results

All green at the time of this run:

- `qbind-node --lib`: 1082 / 1082
- Run 057 (`run_057_pqc_trust_bundle_activation_tests`): 29 / 29
- Run 065 (`run_065_pqc_min_activation_margin_tests`): 8 / 8
- Run 069 (`run_069_pqc_trust_bundle_reload_check_tests`): 8 / 8
- Run 073 (`run_073_pqc_trust_bundle_reload_apply_runtime_tests`): 16 / 16
- Run 074 (`run_074_pqc_trust_bundle_live_reload_tests`): 10 / 10
- Run 076 (`run_076_pqc_peer_candidate_validation_tests`): 16 / 16
- Run 079 (`run_079_pqc_peer_candidate_wire_live_dispatch_tests`): 11 / 11
- Run 088 (`run_088_pqc_peer_candidate_propagation_tests`): 5 / 5
- Run 091 (`run_091_pqc_trust_bundle_activation_epoch_tests`): 15 / 15
- Run 093 (`run_093_production_consensus_storage_lifecycle_tests`): 12 / 12
- Run 094 (`run_094_binary_path_epoch_transition_persistence_tests`): 7 / 7
- Run 096 (`run_096_binary_path_reconfig_proposal_source_tests`): 9 / 9
- Run 097 (`run_097_snapshot_epoch_parity_tests`): 7 / 7
- Run 098 (`run_098_activation_epoch_canonical_wiring_tests`): 12 / 12

## What Run 098 does NOT do

- Does **not** derive epoch from block height, view number, wall-clock
  time, timer ticks, snapshot height, filename, directory name, or any
  other non-canonical source. The only source is `ConsensusStorage::get_current_epoch()`.
- Does **not** treat missing epoch as `Some(0)`.
- Does **not** change the trust-bundle wire format,
  `TrustBundleRevocation` schema, bundle signing scheme, or any
  Run 050–097 invariant.
- Does **not** add a new metric family, a new CLI flag, a new
  on-chain artifact, or a new dependency.
- Does **not** close peer-driven live apply on the `0x05`
  peer-candidate receive path (validation now uses canonical epoch but
  no auto-apply is added). C4 sub-pieces "peer-driven live apply",
  "KMS / HSM custody", "in-binary / on-chain signing-key
  ratification", "production fast-sync / broader consensus-storage
  restore", and "per-environment production trust-anchor operation"
  remain OPEN.
- Does **not** claim full C4 or C5 closure.

## Release-binary limitation

The unattended end-to-end DevNet release-binary scenario:

```
qbind-node --devnet-reconfig-proposal-next-epoch 1   # Run 096 reconfig
  → engine commits PAYLOAD_KIND_RECONFIG block
  → Run 094 persists meta:current_epoch = CommittedEpoch(1)
restart with --p2p-trust-bundle <bundle-with-activation_epoch=1>
  → Run 098 wiring reads CommittedEpoch(1)
  → bundle activates honestly through existing trust-bundle gate
```

is wired through the same library entry points the binary uses (the
six production sites enumerated above) and exercised by the new
integration tests (`run098_bundle_with_activation_epoch_passes_when_committed_epoch_satisfies`
+ `run098_restored_snapshot_with_epoch_satisfies_activation_epoch`),
but is not separately captured as a `qbind-node` process log in this
run. Manual operator smoke would re-confirm Scenarios 1–6 from
`task/RUN_098_TASK.txt` end-to-end; that is left as the next-action
follow-up for full positive closure of this sub-piece.

## See also

- `task/RUN_098_TASK.txt`
- `docs/whitepaper/contradiction.md` §C4 "Run 098 update"
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` §"Run 098 canonical
  activation epoch wiring"
- `crates/qbind-node/src/pqc_trust_activation_epoch.rs`
- `crates/qbind-node/tests/run_098_activation_epoch_canonical_wiring_tests.rs`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_091.md` (originating fail-closed boundary)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md` (canonical storage lifecycle)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_097.md` (restore-time epoch write)