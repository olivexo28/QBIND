# QBIND DevNet Evidence Run 022

## 1. Objective

Run 022 repeats the Run 021 failure shape after the implementation correction:
real `qbind-node` CLI support for snapshot flags, real VM-v0 runtime open at
`<data_dir>/state_vm_v0`, safe SIGUSR1 handling, in-process snapshot creation
through `StateSnapshotter::create_snapshot`, and restore from the SIGUSR1-created
snapshot.

This run does not claim full C4 operational closure. It proves only the
real-binary VM-v0 runtime-open and in-process snapshot-trigger gap isolated by
Run 021. Full production fast-sync/consensus-storage restore and production PQC
root-key distribution remain tracked under C4.

## 2. Verdict

**Positive for the Run 021 gaps.** The tested real binary exposes the snapshot
CLI flags, starts with `--snapshot-dir`, opens `/tmp/qbind-run022/data/state_vm_v0`,
receives SIGUSR1 without terminating, invokes `StateSnapshotter::create_snapshot`
in-process, creates a real RocksDB checkpoint snapshot, and restores from that
SIGUSR1-created snapshot with B3/B5 behavior intact.

A disabled-trigger run also proved SIGUSR1 is handled safely when no
`--snapshot-dir` is configured.

## 3. Binary Identity

Built command:

```bash
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
```

Identity:

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Commit | `05ab2b3b3b81cb5328c47a48df03bb8c9f30526f` |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| sha256 | `472a3e253d92ff26ee32258827c687ea7dfac2633acc0ae788a7b1ac970772ef` |
| ELF BuildID | `c9df0e7ef89546ea105698f194431370249dd702` |

## 4. Commands and Evidence Shape

Help surface:

```bash
/home/runner/work/QBIND/QBIND/target/debug/qbind-node --help \
  > /tmp/qbind-run022/help.txt
grep -E -- '--snapshot-dir|--snapshot-interval-blocks|--snapshot-max-snapshots' \
  /tmp/qbind-run022/help.txt
```

Observed:

```text
--snapshot-dir <SNAPSHOT_DIR>
--snapshot-interval-blocks <SNAPSHOT_INTERVAL_BLOCKS>
--snapshot-max-snapshots <SNAPSHOT_MAX_SNAPSHOTS>
```

The snapshot-output run used a pre-seeded real `RocksDbAccountState` under
`/tmp/qbind-run022/data/state_vm_v0` so the checkpoint would contain an SST file.
The pre-seed wrote one normal account via `RocksDbAccountState::open`,
`PersistentAccountState::put_account_state`, and `flush`; it did not create a
snapshot, did not create placeholder snapshot files, and did not bypass the
binary's in-process snapshot trigger.

Startup command:

```bash
/home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet \
  --execution-profile vm-v0 \
  --data-dir /tmp/qbind-run022/data \
  --snapshot-dir /tmp/qbind-run022/snapshots \
  --snapshot-max-snapshots 2 \
  --validator-id 0
```

Signal and shutdown were driven by numeric PID using Python `os.kill(...,
SIGUSR1)` followed by `os.kill(..., SIGINT)`.

## 5. VM-v0 Runtime Open Evidence

Startup log excerpt:

```text
[vm-v0] opened persistent state at /tmp/qbind-run022/data/state_vm_v0
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir=/tmp/qbind-run022/snapshots
```

Filesystem check passed:

```text
/tmp/qbind-run022/data/state_vm_v0 exists
```

No in-memory fallback was observed or used on the VM-v0 + data-dir path.

## 6. SIGUSR1 Snapshot Evidence

The process stayed alive after SIGUSR1 and logged:

```text
[snapshot] signal received: SIGUSR1
[snapshot] start: height=8 path=/tmp/qbind-run022/snapshots/8
[snapshot] invoking StateSnapshotter::create_snapshot height=8 path=/tmp/qbind-run022/snapshots/8
[snapshot] success: height=8 size_bytes=8585 duration_ms=1
```

Snapshot path:

```text
/tmp/qbind-run022/snapshots/8
```

Snapshot inventory:

```text
meta.json 175
state/000009.sst 1052
state/CURRENT 16
state/MANIFEST-000013 266
state/OPTIONS-000015 7251
```

Metadata:

```json
{
  "height": 8,
  "block_hash": "0000000000000000080000000000000000000000000000000700000000000000",
  "created_at_unix_ms": 1778309068569,
  "chain_id": 5855328520645203456
}
```

The snapshot contains real RocksDB checkpoint files (`CURRENT`, `MANIFEST-*`,
`*.sst`, `OPTIONS-*`) under the canonical `StateSnapshotter` layout.

## 7. Restore Evidence

Restore startup command:

```bash
/home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet \
  --execution-profile vm-v0 \
  --data-dir /tmp/qbind-run022/restored-data \
  --restore-from-snapshot /tmp/qbind-run022/snapshots/8 \
  --validator-id 0
```

Restore log excerpt:

```text
[restore] requested: snapshot_dir=/tmp/qbind-run022/snapshots/8 data_dir=/tmp/qbind-run022/restored-data expected_chain_id=0x51424e4444455600
[restore] complete: height=8 chain_id=0x51424e4444455600 bytes_copied=8585 target=/tmp/qbind-run022/restored-data/state_vm_v0
[restore] OK: restored from snapshot height=8 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=8, starting_view=9)
[vm-v0] opened persistent state at /tmp/qbind-run022/restored-data/state_vm_v0
[binary-consensus] B5: applied restore baseline: snapshot_height=8 starting_view=9 (engine committed_height=Some(8))
[binary-consensus] committed_anchor height=9 block_id=0000000000000000090000000000000000000000000000000800000000000000
```

This preserves B3 fail-closed restore format and B5 restore-aware consensus
baseline behavior.

## 8. Disabled SIGUSR1 Evidence

Command without `--snapshot-dir`:

```bash
/home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet \
  --execution-profile vm-v0 \
  --data-dir /tmp/qbind-run022-disabled/data \
  --validator-id 0
```

After SIGUSR1 the process remained alive and logged:

```text
[snapshot] VM-v0 SIGUSR1 snapshot trigger disabled: --snapshot-dir not configured
[snapshot] signal received: SIGUSR1
[snapshot] SIGUSR1 ignored: VM-v0 snapshot trigger disabled (--snapshot-dir not configured)
```

## 9. Tests and Checks Run

All passed unless otherwise noted:

```bash
cargo test -p qbind-node vm_v0_runtime --lib
cargo test -p qbind-node test_cli_snapshot_dir_enables_snapshot_config --lib
cargo test -p qbind-node test_cli_help_exposes_snapshot_flags --lib
cargo check -p qbind-node --bin qbind-node
cargo build -p qbind-node --bin qbind-node
```

Warnings: the pre-existing `bincode::config` deprecation warnings in
`binary_consensus_loop.rs` remain unrelated to this run.

## 10. Remaining Not Solved

- N=4 Required-mode B13/B14 continuation from a SIGUSR1-created snapshot was not
  repeated in this run.
- Production fast-sync/consensus-storage restore remains outside this correction.
- Production PQC KEMTLS root-key distribution remains outside this correction.
- A fresh empty VM-v0 RocksDB can produce a valid RocksDB checkpoint without an
  SST file; this run pre-seeded one real account only to demonstrate the required
  `*.sst` checkpoint-file evidence while still using the real binary snapshot
  trigger.