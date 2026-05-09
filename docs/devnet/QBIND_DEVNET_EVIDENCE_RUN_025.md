# QBIND DevNet Evidence Run 025

## 1. Objective

Run 025 checks the newly wired real-binary periodic VM-v0 snapshot trigger for
`--snapshot-interval-blocks`, without SIGUSR1. This is evidence only and does not
claim full C4 closure.

## 2. Verdict

**Positive for the local seeded real-binary periodic snapshot path; incomplete for
full N=4 Required-mode continuation.**

A seeded `qbind-node` real binary started with `--snapshot-dir`,
`--snapshot-interval-blocks 4`, and `--snapshot-max-snapshots 2`, crossed committed
height 4 without SIGUSR1, detected the periodic condition, invoked
`StateSnapshotter::create_snapshot` in-process, created a real RocksDB checkpoint
snapshot, updated snapshot metrics honestly, and a second real binary restored from
that periodic snapshot and committed above the snapshot height.

The full Run 024 N=4 Required-mode repeat, V1B/V2C restore continuation, B13/B14
multi-validator continuation, and absent-leader recovery proof were not completed in
this local evidence pass and remain the immediate follow-up.

## 3. Commands

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
cargo build -p qbind-ledger --example qbind_seed_vm_v0_state
rm -rf /tmp/run025c
mkdir -p /tmp/run025c/data/v0 /tmp/run025c/snapshots /tmp/run025c/metrics
target/debug/examples/qbind_seed_vm_v0_state /tmp/run025c/data/v0/state_vm_v0
QBIND_METRICS_HTTP_ADDR=127.0.0.1:32520 \
  target/debug/qbind-node \
  --env devnet --network-mode local-mesh --execution-profile vm-v0 \
  --data-dir /tmp/run025c/data/v0 --validator-id 0 \
  --snapshot-dir /tmp/run025c/snapshots \
  --snapshot-interval-blocks 4 \
  --snapshot-max-snapshots 2
```

No SIGUSR1 was sent in the primary periodic proof.

Restore check:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:32521 timeout -s INT 3s \
  target/debug/qbind-node \
  --env devnet --network-mode local-mesh --execution-profile vm-v0 \
  --data-dir /tmp/run025c/data/v1 --validator-id 0 \
  --restore-from-snapshot /tmp/run025c/snapshots/4
```

## 4. Periodic trigger log evidence

```text
[qbind_seed_vm_v0_state] OK: seeded /tmp/run025c/data/v0/state_vm_v0 account=cdcd...cd nonce=7 balance=4242
[snapshot] periodic snapshot trigger enabled: interval_blocks=4 snapshot_dir=/tmp/run025c/snapshots
[binary-consensus] committed_anchor height=0 block_id=00000000000000000000000000000000ffffffffffffffffffffffffffffffff
[snapshot] periodic snapshot skipped: committed height is zero
[binary-consensus] committed_anchor height=1 ...
[binary-consensus] committed_anchor height=2 ...
[binary-consensus] committed_anchor height=3 ...
[binary-consensus] committed_anchor height=4 block_id=0000000000000000040000000000000000000000000000000300000000000000
[snapshot] periodic condition detected: height=4 interval_blocks=4
[snapshot] start: height=4 path=/tmp/run025c/snapshots/4
[snapshot] invoking StateSnapshotter::create_snapshot height=4 path=/tmp/run025c/snapshots/4
[snapshot] periodic success: height=4 size_bytes=8588 duration_ms=2
```

## 5. Snapshot substrate

```text
/tmp/run025c/snapshots/4/meta.json
/tmp/run025c/snapshots/4/state/000009.sst
/tmp/run025c/snapshots/4/state/CURRENT
/tmp/run025c/snapshots/4/state/MANIFEST-000013
/tmp/run025c/snapshots/4/state/OPTIONS-000015
```

`meta.json`:

```json
{
  "height": 4,
  "block_hash": "0000000000000000040000000000000000000000000000000300000000000000",
  "created_at_unix_ms": 1778314962662,
  "chain_id": 5855328520645203456
}
```

## 6. Metrics

```text
qbind_consensus_committed_height 4
qbind_consensus_current_view 7
qbind_snapshot_last_height 4
qbind_snapshot_last_duration_ms 2
qbind_snapshot_last_size_bytes 8588
qbind_snapshot_success_total 1
qbind_snapshot_failure_total 0
qbind_snapshot_in_progress 0
```

## 7. Restore evidence

```text
[restore] requested: snapshot_dir=/tmp/run025c/snapshots/4 data_dir=/tmp/run025c/data/v1 expected_chain_id=0x51424e4444455600
[restore] complete: height=4 chain_id=0x51424e4444455600 bytes_copied=8588 target=/tmp/run025c/data/v1/state_vm_v0
[restore] audit marker written to /tmp/run025c/data/v1/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=4 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=4, starting_view=5)
[vm-v0] opened persistent state at /tmp/run025c/data/v1/state_vm_v0
[binary-consensus] B5: applied restore baseline: snapshot_height=4 starting_view=5 (engine committed_height=Some(4))
[binary-consensus] committed_anchor height=5 ...
...
[binary-consensus] committed_anchor height=32 ...
```

Materialization included `/tmp/run025c/data/v1/RESTORED_FROM_SNAPSHOT.json` and
`/tmp/run025c/data/v1/state_vm_v0/000009.sst`.

## 8. Not proven in this run

- Full N=4 Required-mode repeat of Run 024.
- V1B and V2C restore from the periodic snapshot.
- B13 post-restore multi-validator catchup exit.
- B14 absent-leader recovery after periodic-snapshot restore.
- Decode-failure / engine-reject / proposal-rejection / invalid-vote spike checks
  in an N=4 P2P topology.
- SIGUSR1 recheck in the same evidence run.