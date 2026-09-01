# QBIND Public DevNet — Backup / Restore Baseline (S1) (Run 394)

> **Safety label:** experimental · resettable · no value · no uptime SLA · no guarantee of data
> permanence · no MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT
> public-DevNet launch-ready.

This document is the **public-DevNet-scoped** operator backup / restore baseline (should-have **S1**).
It describes **only** pre-existing `qbind-node` surfaces (see `crates/qbind-node/src/cli.rs`) and
defers to the internal baseline `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` for backup
principles, integrity, and drill cadence. It adds **no** CLI flag and makes **no** MainNet/TestNet
readiness or C4/C5 closure claim. DevNet is experimental and resettable; **a backup is best-effort
convenience only and provides no guarantee of data permanence.**

## 1. Scope and posture

- DevNet state has **no value** and **no persistence guarantee**. The correct default response to a
  corrupt or diverged DevNet node is usually **wipe-and-rejoin** (§8), not restore.
- Backup / restore here is a convenience so an operator can save time re-syncing an experimental node,
  **not** a durability or availability guarantee.
- There is **no uptime SLA**. Nothing in this document implies production recovery guarantees.

## 2. What files / directories may be backed up

On a **stopped** node (see §3), the following are safe to copy for local convenience:

- The node **data directory** given by `--data-dir` / `-d` (contains the materialized `state/`
  checkpoint, e.g. `<data-dir>/state_vm_v0`).
- Any **snapshot directory** given by `--snapshot-dir` (numeric `<committed_height>/` subdirectories
  in the `StateSnapshotter` format: `meta.json` + `state/`).
- The **genesis source** used at startup (`--genesis-path` input) and the **published genesis hash**
  it derives.
- Publish-safe **metadata**: release-binary SHA-256 / BuildID / toolchain, node public identifiers
  (`node_id` / `peer_id`), and the pinned genesis hash.

## 3. Safe stop-before-copy posture

Always copy from a **stopped** node so the on-disk state is consistent:

1. Stop the node process cleanly (SIGTERM / your service manager stop).
2. Confirm the process has exited and is not still writing to `--data-dir` / `--snapshot-dir`.
3. Copy the directories (`cp -a`, `rsync -a`, or an archive of the stopped tree).
4. Record provenance (§6) alongside the copy.

Do **not** copy a live data directory while the node is running; an inconsistent copy will fail to
restore or start.

## 4. What must NOT be committed or shared

Never commit to git and never publish:

- Private keys, KEM secret keys, mnemonics, seed phrases, keystore contents / passwords, HSM secrets,
  credentials, API keys, or tokens.
- Raw **node data directories** or their contents, raw snapshot bodies, raw logs, or raw `/metrics`
  dumps.
- Private / internal infrastructure hostnames, unapproved live endpoints, or **absolute build paths**.
- Branch dirty-state strings or other environment-specific ephemeral state.

Keep all backup working material **outside any git tree**. Only publish-safe values (hashes,
identifiers, status lines) may be recorded in a tracked evidence file.

## 5. Snapshot / restore command surfaces (pre-existing only)

These flags already exist in `qbind-node --help`; Run 394 invents nothing.

**Creating snapshots** (in-process VM-v0 snapshots):

```bash
qbind-node --env devnet \
  --data-dir <DATA_DIR> \
  --snapshot-dir <SNAP_DIR> \
  --snapshot-interval-blocks <N> \
  --snapshot-max-snapshots <K> \
  --genesis-path <GENESIS> \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

Snapshots are written to `<SNAP_DIR>/<committed_height>/` (`meta.json` + `state/`); `--snapshot-max-snapshots`
bounds how many numeric directories are retained.

**Restoring from a snapshot** (startup path):

```bash
qbind-node --env devnet \
  --data-dir <DATA_DIR> \
  --restore-from-snapshot <SNAP_DIR>/<committed_height> \
  --genesis-path <GENESIS> \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

`--restore-from-snapshot` validates the snapshot directory and materializes its `state/` checkpoint
into `<data-dir>/state_vm_v0` **before** starting consensus. It **requires** `--data-dir`. It fails
clearly and loudly (non-zero exit) if the snapshot is missing, has the **wrong chain id**, has the
wrong layout, or if the target state directory is **already populated** (see
`crates/qbind-node/src/snapshot_restore.rs`).

## 6. Genesis-hash pinning after restore

After a restore, always confirm the node still binds the **canonical DevNet genesis**:

```bash
# Recompute the genesis hash for the genesis source you restored against:
qbind-node --env devnet --genesis-path <GENESIS> --print-genesis-hash

# Then pin it at startup so a mismatch fails closed:
qbind-node --env devnet --data-dir <DATA_DIR> --genesis-path <GENESIS> \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

The canonical Run 101 DevNet genesis hash is
`0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`
(`docs/release/public-devnet/genesis/devnet-network-parameters.md`). A restore that does not pin to
this hash on DevNet is **not** a valid restore — wipe-and-rejoin instead (§8).

## 7. Build-provenance recording

For every backup and every restore, record publish-safe provenance so a restored node can be tied to
a known-good binary:

- Release-binary **SHA-256** and **BuildID** (`sha256sum` / `file`).
- **Toolchain** (`rustc --version`, `cargo --version`).
- Pinned **genesis hash** (§6).
- The `qbind_node_build_info{version,build_id,git_commit,env,chain_id}` metric emitted by the running
  node (see `docs/release/public-devnet/observability/METRICS.md`).

## 8. Expected failure handling / when to wipe and rejoin

`--restore-from-snapshot` is **fail-closed**. Expected failures and the correct response:

| Symptom | Meaning | Action |
|---------|---------|--------|
| non-zero exit, "wrong chain id" | Snapshot is from a different chain / after a reset. | Do **not** force. Wipe-and-rejoin. |
| non-zero exit, "wrong layout" / missing `meta.json`/`state/` | Snapshot is incomplete/corrupt. | Discard the snapshot. Wipe-and-rejoin. |
| non-zero exit, target state already populated | `--data-dir` already has state. | Restore into a fresh `--data-dir`, or wipe first. |
| genesis-hash mismatch at startup | Restored state does not match canonical DevNet genesis. | Wipe-and-rejoin. |

**Wipe-and-rejoin** (the DevNet-safe default): stop the node, remove the `--data-dir` contents, start
fresh against the canonical genesis and current seed list
(`docs/release/public-devnet/network/`), and let the node re-sync. Because DevNet has **no value** and
is **resettable**, wipe-and-rejoin is preferred over any uncertain restore. See the reset policy
`docs/release/public-devnet/ops/RESET_POLICY.md`.

## 9. Cross-links

- Data retention — `DATA_RETENTION.md`.
- Upgrade / rollback — `UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md`.
- Reset policy / incident response — `docs/release/public-devnet/ops/RESET_POLICY.md`,
  `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`.
- Observability metrics — `docs/release/public-devnet/observability/METRICS.md`.
- Genesis publication — `docs/release/public-devnet/genesis/`.
- Internal backup / recovery baseline — `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`.

## 10. Non-claims

This baseline does **not** move **M4** or **M6**, does **not** close **C4** or **C5**, and makes
**no** TestNet or MainNet readiness claim. It provides **no** uptime SLA and **no** guarantee of data
permanence. Public DevNet remains **NOT launch-ready**.
