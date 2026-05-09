# QBIND DevNet Evidence Run 024

## 1. Objective

Run 024 tests the real `qbind-node` binary periodic snapshot path requested by
`--snapshot-interval-blocks <N>`. The primary question is whether a running N=4
Required-mode VM-v0 validator creates a real `StateSnapshotter::create_snapshot`
RocksDB checkpoint snapshot automatically from committed block-height progress,
without SIGUSR1.

This is an evidence run only. It does not claim full C4 closure.

## 2. Verdict

**Negative.** The real binary accepted `--snapshot-dir /tmp/run024/snapshots
--snapshot-interval-blocks 4 --snapshot-max-snapshots 2`, opened VM-v0 state,
ran an N=4 `--p2p-mutual-auth required` topology, and advanced V0 well past
multiple interval boundaries without SIGUSR1, but no periodic snapshot was
created.

Observed primary failure boundary:

- V0 committed past the configured interval boundary: `committed_height=54`,
  `current_view=58` at the post-interval scrape.
- The primary run explicitly did not send SIGUSR1:
  `NO_SIGUSR1_SENT_PRIMARY true` in `/tmp/run024/events.log`.
- V0 stayed alive after crossing the interval boundaries:
  `ALIVE_AFTER_INTERVAL {"v0": true, "v1a": true, "v2a": true, "v3a": true}`.
- `/tmp/run024/snapshots/` remained empty:
  `SNAPSHOT_DIRS_AFTER_INTERVAL []`.
- V0 metrics stayed at `qbind_snapshot_success_total 0`,
  `qbind_snapshot_failure_total 0`, `qbind_snapshot_last_height 0`,
  `qbind_snapshot_last_duration_ms 0`, `qbind_snapshot_last_size_bytes 0`, and
  `qbind_snapshot_in_progress 0`.
- V0 logs show the SIGUSR1 trigger was installed, then committed anchors advanced
  through heights `4`, `8`, `12`, `16`, `20`, ..., `54`, but no periodic
  snapshot log line and no `StateSnapshotter::create_snapshot` invocation
  appeared.

Because no periodic snapshot existed, Run 024 could not proceed to restore,
B3/B5 restore-baseline proof, B13 post-restore catchup exit, B14 post-restore
absent-leader continuation, snapshot substrate validation, snapshot metrics
success proof, or pruning proof for the periodic trigger.

## 3. Binary Identity

Built command:

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
cargo build -p qbind-ledger --example qbind_seed_vm_v0_state
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-development-another-one` |
| Commit | `ac96f601b6d38941d2b422159f661cf0ba45879d` |
| Working tree before run | clean |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| Profile | `dev` (debug) |
| sha256 | `376fd59c7d06a18c621727e312295f7ec2951227cf1c7fedc03e2c8aa5dad06e` |
| ELF BuildID | `9b16a227b107e0f90489c51f544f54fe93f2d7bd` |

## 4. CLI Surface

Command:

```sh
/home/runner/work/QBIND/QBIND/target/debug/qbind-node --help > /tmp/run024_help.txt
grep -E -- '--snapshot-dir|--snapshot-interval-blocks|--snapshot-max-snapshots|--restore-from-snapshot|--execution-profile' /tmp/run024_help.txt
```

Observed help lines:

```text
--execution-profile <EXECUTION_PROFILE>
--restore-from-snapshot <RESTORE_FROM_SNAPSHOT>
--snapshot-dir <SNAPSHOT_DIR>
--snapshot-interval-blocks <SNAPSHOT_INTERVAL_BLOCKS>
--snapshot-max-snapshots <SNAPSHOT_MAX_SNAPSHOTS>
```

The `--snapshot-dir` help text still describes the installed runtime trigger as
SIGUSR1-based: "send SIGUSR1 to this process".

## 5. Topology and Commands

N=4, `f=1`, `2f+1=3`, V0-first stagger, `--p2p-mutual-auth required`,
`--execution-profile vm-v0`, explicit data dirs, metrics enabled on every node.
`QBIND_MUTUAL_AUTH` was unset for each process.

| Node | `vid` | Listen | Metrics | Data dir | Snapshot flags |
|---|---:|---|---|---|---|
| V0 | 0 | `127.0.0.1:31050` | `127.0.0.1:31000` | `/tmp/run024/data/v0` | `--snapshot-dir /tmp/run024/snapshots --snapshot-interval-blocks 4 --snapshot-max-snapshots 2` |
| V1A | 1 | `127.0.0.1:31051` | `127.0.0.1:31001` | `/tmp/run024/data/v1a` | none |
| V2A | 2 | `127.0.0.1:31052` | `127.0.0.1:31002` | `/tmp/run024/data/v2a` | none |
| V3A | 3 | `127.0.0.1:31053` | `127.0.0.1:31003` | `/tmp/run024/data/v3a` | none |

V0 command:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:31000 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:31050 \
  --p2p-peer 1@127.0.0.1:31051 \
  --p2p-peer 2@127.0.0.1:31052 \
  --p2p-peer 3@127.0.0.1:31053 \
  --p2p-mutual-auth required --execution-profile vm-v0 \
  --data-dir /tmp/run024/data/v0 --validator-id 0 \
  --snapshot-dir /tmp/run024/snapshots \
  --snapshot-interval-blocks 4 \
  --snapshot-max-snapshots 2
```

V1A/V2A/V3A used the same shape with their own `--validator-id`, listen address,
metrics address, data dir, and peer list, without snapshot flags.

## 6. Pre-seed

V0 VM-v0 state was pre-seeded once so that any real checkpoint would have normal
RocksDB content. The seeder did not create a snapshot.

```sh
/home/runner/work/QBIND/QBIND/target/debug/examples/qbind_seed_vm_v0_state \
  /tmp/run024/data/v0/state_vm_v0
```

Observed:

```text
[qbind_seed_vm_v0_state] OK: seeded /tmp/run024/data/v0/state_vm_v0 account=cdcd...cd nonce=7 balance=4242
```

## 7. Periodic Trigger Evidence

Run timeline from `/tmp/run024/events.log`:

```text
2026-05-09T07:53:16Z RUN024_START
2026-05-09T07:53:16Z PRESEED_EXIT 0
2026-05-09T07:53:16Z PID v0 13293
2026-05-09T07:53:16Z METRICS_UP v0 True
2026-05-09T07:53:19Z METRICS_UP v1a True
2026-05-09T07:53:19Z METRICS_UP v2a True
2026-05-09T07:53:19Z METRICS_UP v3a True
2026-05-09T07:53:19Z NO_SIGUSR1_SENT_PRIMARY true
2026-05-09T07:53:27Z V0_HEIGHT_GE_16 ok=True last=18.0
2026-05-09T07:53:32Z SNAPSHOT_DIRS_AFTER_INTERVAL []
2026-05-09T07:53:32Z ALIVE_AFTER_INTERVAL {"v0": true, "v1a": true, "v2a": true, "v3a": true}
2026-05-09T07:53:32Z RUN024_END
```

V0 log excerpt:

```text
[vm-v0] opened persistent state at /tmp/run024/data/v0/state_vm_v0
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir=/tmp/run024/snapshots
[binary-consensus] committed_anchor height=4 ...
[binary-consensus] committed_anchor height=8 ...
[binary-consensus] committed_anchor height=12 ...
[binary-consensus] committed_anchor height=16 ...
[binary-consensus] committed_anchor height=20 ...
...
[binary-consensus] committed_anchor height=54 ...
[snapshot] VM-v0 snapshot trigger stopped.
```

There was no V0 log line for a periodic condition firing, no periodic
`[snapshot] start`, no periodic `invoking StateSnapshotter::create_snapshot`, and
no periodic `[snapshot] success`.

## 8. Snapshot Directory and Substrate

Command:

```sh
find /tmp/run024/snapshots -maxdepth 2 -type f -o -type d | sort
```

Observed:

```text
/tmp/run024/snapshots
```

No `meta.json`, `CURRENT`, `MANIFEST-*`, `*.sst`, or `OPTIONS-*` existed because
no periodic snapshot directory was created. This is not a placeholder-snapshot
success; it is a primary-trigger failure.

## 9. Metrics Before and After

Before interval crossing (`/tmp/run024/metrics/before_interval_summary.txt`), V0
was just starting:

```text
v0 qbind_consensus_committed_height 0
v0 qbind_consensus_current_view 0
v0 qbind_snapshot_success_total 0
v0 qbind_snapshot_failure_total 0
v0 qbind_snapshot_last_height 0
v0 qbind_snapshot_last_duration_ms 0
v0 qbind_snapshot_last_size_bytes 0
v0 qbind_snapshot_in_progress 0
```

After interval crossing (`/tmp/run024/metrics/after_interval_summary.txt`):

```text
v0 qbind_consensus_committed_height 54
v0 qbind_consensus_current_view 58
v0 qbind_restore_catchup_mode_active 0
v0 qbind_restore_catchup_mode_exited_at_height 0
v0 qbind_restore_catchup_blocks_applied_total 0
v0 qbind_consensus_view_timeouts_emitted_total 1
v0 qbind_consensus_timeout_certificates_formed_total 1
v0 qbind_consensus_outbound_new_views_sent_total 1
v0 qbind_consensus_view_timeout_advances_total 1
v0 qbind_consensus_view_timeout_decode_failures_total 0
v0 qbind_consensus_view_timeout_engine_rejects_total 0
v0 qbind_consensus_proposals_total{result="accepted"} 58
v0 qbind_consensus_proposals_total{result="rejected"} 0
v0 qbind_consensus_votes_total{result="accepted"} 171
v0 qbind_consensus_votes_total{result="invalid"} 0
v0 qbind_snapshot_success_total 0
v0 qbind_snapshot_failure_total 0
v0 qbind_snapshot_last_height 0
v0 qbind_snapshot_last_duration_ms 0
v0 qbind_snapshot_last_size_bytes 0
v0 qbind_snapshot_in_progress 0
```

All four nodes had zero decode failures, zero engine rejects, zero rejected
proposals, and zero invalid votes at the post-interval scrape. The snapshot
metrics were not fabricated: success remained zero and last-height/duration/size
remained zero because no snapshot was created.

## 10. Restore / B3 / B5 / B13 / B14

Not run for Run 024. The required restore shape depends on a periodic snapshot
directory produced by the real binary. Since the periodic trigger did not create
one, there was no honest `--restore-from-snapshot <periodic_snapshot_dir>` input
to test. B3, B5, B13, and B14 remain proven by previous runs for their stated
snapshot sources, but not for the missing periodic trigger.

## 11. Pruning

Not proven. `--snapshot-max-snapshots 2` was configured on V0, but no periodic
snapshot directory was created, so there were no numeric trigger-created snapshot
directories to prune.

## 12. Negative Checks

| Check | Result |
|---|---|
| No SIGUSR1 used for primary periodic proof | Pass: events log records `NO_SIGUSR1_SENT_PRIMARY true`; harness sent only SIGINT for shutdown. |
| No crash during periodic interval crossing | Pass: all four nodes alive after V0 crossed height 16; all exited cleanly on SIGINT. |
| No placeholder snapshot files | Pass: no snapshot files or directories were created at all. |
| No silent in-memory fallback | Pass: V0 logged `[vm-v0] opened persistent state at /tmp/run024/data/v0/state_vm_v0`. |
| No decode failures | Pass: all nodes reported `qbind_consensus_view_timeout_decode_failures_total 0`. |
| No engine rejects | Pass: all nodes reported `qbind_consensus_view_timeout_engine_rejects_total 0`. |
| No proposal rejection spike | Pass: all nodes reported `qbind_consensus_proposals_total{result="rejected"} 0`. |
| No invalid vote spike | Pass: all nodes reported `qbind_consensus_votes_total{result="invalid"} 0`. |
| No fabricated metrics | Pass: snapshot success and last snapshot gauges stayed zero because no snapshot occurred. |
| Run 023 SIGUSR1 regression recheck | Not rechecked in this primary negative run to keep the no-SIGUSR1 periodic evidence clean. |
| Run 022 disabled-SIGUSR1 regression recheck | Not rechecked in this primary negative run. |

## 13. Design / Implementation Crosscheck

The run result is consistent with the binary wiring observed in code, but it
contradicts the periodic behavior implied by `SnapshotConfig` documentation and
CLI surface:

- `crates/qbind-node/src/node_config.rs` documents that
  `snapshot_interval_blocks` creates snapshots every N committed blocks and
  exposes `SnapshotConfig::should_snapshot_at_height(height)`.
- `crates/qbind-node/src/cli.rs` accepts `--snapshot-interval-blocks` and plumbs
  it into `config.snapshot_config.snapshot_interval_blocks`.
- `crates/qbind-node/src/main.rs` starts `spawn_vm_v0_snapshot_signal_task(...)`,
  whose only call to `runtime.create_snapshot(...)` is inside the SIGUSR1 branch.
- No observed binary-path code calls `should_snapshot_at_height(...)` from the
  consensus commit path.

`docs/whitepaper/contradiction.md` was updated because this materially narrows C4:
real-binary VM-v0 SIGUSR1 snapshots remain proven by Runs 022/023, but periodic
height-triggered real-binary snapshots are not wired/proven.

## 14. Artifacts

Primary artifacts were written under `/tmp/run024/` during the run:

- `/tmp/run024/events.log`
- `/tmp/run024/logs/seed.log`
- `/tmp/run024/logs/v0.log`
- `/tmp/run024/logs/v1a.log`
- `/tmp/run024/logs/v2a.log`
- `/tmp/run024/logs/v3a.log`
- `/tmp/run024/metrics/before_interval_summary.txt`
- `/tmp/run024/metrics/after_interval_summary.txt`
- `/tmp/run024/metrics/*_v*.txt`

The orchestrator was `/tmp/run024.py` and was intentionally kept outside the
repository.