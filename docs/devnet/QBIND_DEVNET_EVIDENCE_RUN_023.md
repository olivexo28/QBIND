# QBIND DevNet Evidence Run 023

## 1. Objective

Run 023 repeats the Run 019 N=4 Required-mode B13/B14 evidence shape on the same
post-Run-022 binary, but with the snapshot under test produced **in-process by
the running real `qbind-node`** through `StateSnapshotter::create_snapshot` via
the SIGUSR1 trigger that Run 022 first proved on a single node. No alternative
snapshot path, no placeholder snapshot files, no harness-only state writer is
used as the snapshot source: the snapshot consumed by the V1B and V2C restore
processes is the exact `--snapshot-dir <DIR>/<height>/` directory that V0
created from inside the running validator on receipt of SIGUSR1.

This run does not claim full C4 operational closure. It proves only that the
B13/B14 N=4 Required-mode continuation shape — already proven on a real RocksDB
checkpoint substrate by Run 020 and on the SIGUSR1-trigger-and-restore single-
node shape by Run 022 — also holds end-to-end when the snapshot is produced by
the SIGUSR1 path of the running real binary itself. Production fast-sync /
consensus-storage restore, signature verification of `TimeoutMsg` /
`TimeoutCertificate`, exponential-backoff timeout pacing, and production PQC
KEMTLS root-key distribution remain tracked under C4.

## 2. Verdict

**Strongest positive.** The SIGUSR1-created real-binary snapshot supports the
full B3 / B5 / B13 / B14 N=4 Required-mode continuation. Every required
positive shape lands and every required negative check passes on the binary
path:

- V0 created snapshot height **10** at `/tmp/run023/snapshots/10/` via SIGUSR1
  → `StateSnapshotter::create_snapshot`; V0 stayed alive (`pid=15292`,
  `process_alive_after_SIGUSR1=yes`).
- Snapshot directory contains real RocksDB checkpoint files (`CURRENT`,
  `MANIFEST-000013`, `000009.sst`, `OPTIONS-000015`) plus `meta.json`. No
  placeholder content.
- V1B and V2C restored from `/tmp/run023/snapshots/10` with fresh `--data-dir`s
  and `--execution-profile vm-v0`. B3 marker `RESTORED_FROM_SNAPSHOT.json`
  written on both; checkpoint copied into `<data_dir>/state_vm_v0/`.
- B5 baseline applied on both restored validators: `snapshot_height=10`,
  `starting_view=11`, engine `committed_height=Some(10)` from the first tick.
- B13 strict-progress exit on both restored validators: `mode_active` 1 → 0,
  `mode_exited_at_height=14 > 10`, `restore_catchup_blocks_applied_total=6` on
  each — peer-learned certified blocks above baseline applied through the real
  binary path.
- B14 absent-leader recovery cleared the V1A/V2A/V3A-fault plateau:
  `view_timeouts_emitted_total=10`, `timeout_certificates_formed_total=10/10/9`
  on V0/V1B/V2C, `outbound_new_views_sent_total=10/10/9`,
  `view_timeout_advances_total=10`, `decode_failures_total=0`,
  `engine_rejects_total=0`. `current_view` advanced 11 → 55 and
  `committed_height` advanced 10 → 42 on all three alive nodes.
- `proposals_total{result="rejected"}=0` and `votes_total{result="invalid"}=0`
  on every node.
- A separate disabled-trigger recheck (no `--snapshot-dir`) preserved the Run
  022 shape: SIGUSR1 received, process alive, snapshot trigger ignored.

## 3. Binary Identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-development-again` |
| Commit | `83655bdcaa17b2031dd281dbbff1f1d309d24341` |
| Working tree | clean (no `git status --porcelain` output before run) |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| Profile | `dev` (debug) |
| sha256 | `376fd59c7d06a18c621727e312295f7ec2951227cf1c7fedc03e2c8aa5dad06e` |
| ELF BuildID (sha1) | `9b16a227b107e0f90489c51f544f54fe93f2d7bd` |

`--help` exposes the snapshot/restore surface introduced and verified by Runs
021/022:

```text
--execution-profile <EXECUTION_PROFILE>
--p2p-mutual-auth <P2P_MUTUAL_AUTH>
-d, --data-dir <DATA_DIR>
--restore-from-snapshot <RESTORE_FROM_SNAPSHOT>
--snapshot-dir <SNAPSHOT_DIR>
--snapshot-interval-blocks <SNAPSHOT_INTERVAL_BLOCKS>
--snapshot-max-snapshots <SNAPSHOT_MAX_SNAPSHOTS>
```

## 4. Topology and Timing

N=4, `f=1`, `2f+1 = 3`. Same shape as Run 019 with the deliberate substrate
change that the snapshot consumed by V1B/V2C is produced by SIGUSR1 →
`StateSnapshotter::create_snapshot` inside the running V0.

| Node | Phase | `vid` | Listen | Mutual auth | Profile | Data dir | Metrics | `--snapshot-dir` | `--restore-from-snapshot` |
|---|---|---:|---|---|---|---|---|---|---|
| V0  | live throughout            | 0 | `127.0.0.1:29950` | `required` | `vm-v0` | `/tmp/run023/data/v0`  | `:29900` | `/tmp/run023/snapshots` (`--snapshot-max-snapshots 4`) | — |
| V1A | live pre-fault             | 1 | `127.0.0.1:29951` | `required` | `vm-v0` | `/tmp/run023/data/v1a` | `:29901` | — | — |
| V2A | live pre-fault             | 2 | `127.0.0.1:29952` | `required` | `vm-v0` | `/tmp/run023/data/v2a` | `:29902` | — | — |
| V3A | live pre-fault             | 3 | `127.0.0.1:29953` | `required` | `vm-v0` | `/tmp/run023/data/v3a` | `:29903` | — | — |
| V1B | restored after fault       | 1 | `127.0.0.1:29951` | `required` | `vm-v0` | `/tmp/run023/data/v1b` | `:29904` | — | `/tmp/run023/snapshots/10` |
| V2C | restored compatibly after  | 2 | `127.0.0.1:29952` | `required` | `vm-v0` | `/tmp/run023/data/v2c` | `:29905` | — | `/tmp/run023/snapshots/10` |

`QBIND_MUTUAL_AUTH` was unset for every process so `--p2p-mutual-auth required`
on the CLI is the sole authority.

Timing (UTC, from `events.log`):

| Event | Time |
|---|---|
| `RUN023_START`                                  | `2026-05-09T07:25:12Z` |
| Pre-seed V0 `state_vm_v0`                       | `2026-05-09T07:25:12Z` |
| V0 start                                        | `2026-05-09T07:25:12Z` |
| V0 metrics up                                   | `2026-05-09T07:25:12Z` |
| V1A/V2A/V3A start                               | `2026-05-09T07:25:14Z` |
| V0 reached `committed_height=7`                 | `2026-05-09T07:25:16Z` |
| V0 reached `committed_height=10` (above S=7+2)  | `2026-05-09T07:25:17Z` |
| **SIGUSR1 → V0**                                | `2026-05-09T07:25:17Z` |
| Snapshot created at `/tmp/run023/snapshots/10/` | `2026-05-09T07:25:17Z` |
| SIGINT V1A/V2A/V3A                              | `2026-05-09T07:25:17Z` |
| V1B started (`--restore-from-snapshot`)         | `2026-05-09T07:25:20Z` |
| V2C started (`--restore-from-snapshot`)         | `2026-05-09T07:25:29Z` |
| Final scrape (V0/V1B/V2C `committed_height=42`) | `2026-05-09T07:26:27Z` |
| `RUN023_END`                                    | `2026-05-09T07:26:27Z` |

## 5. Pre-seed Justification

Run 022 §10 noted: *"A fresh empty VM-v0 RocksDB can produce a valid RocksDB
checkpoint without an SST file."* The task brief requires the snapshot to
contain `*.sst`. To honor that without bypassing `StateSnapshotter::create_
snapshot` or the binary's SIGUSR1 trigger, V0's `state_vm_v0` was pre-seeded
with one normal account before V0 started, using the same library path the B3
integration tests use (`crates/qbind-ledger/examples/qbind_seed_vm_v0_state.rs`,
which calls `RocksDbAccountState::open` → `put_account_state` → `flush`):

```sh
/home/runner/work/QBIND/QBIND/target/debug/examples/qbind_seed_vm_v0_state \
  /tmp/run023/data/v0/state_vm_v0
# [qbind_seed_vm_v0_state] OK: seeded /tmp/run023/data/v0/state_vm_v0 \
#   account=cdcd...cd nonce=7 balance=4242
```

The seeder did not create a snapshot, did not write any `meta.json`/`state/`
layout, and did not bypass the binary's in-process snapshot trigger. The actual
snapshot consumed by V1B/V2C was produced by V0's SIGUSR1 →
`StateSnapshotter::create_snapshot` path against this populated DB.

## 6. Commands Run

Driver: `/tmp/run023/run023.py` (Python orchestrator). Representative expanded
commands are:

V0 (live throughout, snapshot trigger configured):

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:29900 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:29950 \
  --p2p-peer 1@127.0.0.1:29951 --p2p-peer 2@127.0.0.1:29952 --p2p-peer 3@127.0.0.1:29953 \
  --p2p-mutual-auth required --execution-profile vm-v0 \
  --data-dir /tmp/run023/data/v0 --validator-id 0 \
  --snapshot-dir /tmp/run023/snapshots --snapshot-max-snapshots 4
```

V1A/V2A/V3A: same shape with `--validator-id 1/2/3`, listen
`19951/19952/19953`, metrics `29901/29902/29903`, no snapshot or restore flags.

V1B (restored from the SIGUSR1-created snapshot):

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:29904 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:29951 \
  --p2p-peer 0@127.0.0.1:29950 --p2p-peer 2@127.0.0.1:29952 --p2p-peer 3@127.0.0.1:29953 \
  --p2p-mutual-auth required --execution-profile vm-v0 \
  --data-dir /tmp/run023/data/v1b --validator-id 1 \
  --restore-from-snapshot /tmp/run023/snapshots/10
```

V2C: same shape as V1B with `--validator-id 2`, listen `19952`, metrics
`29905`, data dir `/tmp/run023/data/v2c`. SIGUSR1/SIGINT delivery used Python
`os.kill(pid, signal.SIGUSR1 | signal.SIGINT)` against the recorded numeric
PIDs — no shell expansion, no `pkill`/`killall`.

## 7. Snapshot Trigger Evidence (SIGUSR1 → real binary)

V0 startup log excerpt confirms the in-process trigger is enabled:

```text
[vm-v0] opened persistent state at /tmp/run023/data/v0/state_vm_v0
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir=/tmp/run023/snapshots
```

V0 log on SIGUSR1:

```text
[snapshot] signal received: SIGUSR1
[snapshot] start: height=10 path=/tmp/run023/snapshots/10
[snapshot] invoking StateSnapshotter::create_snapshot height=10 path=/tmp/run023/snapshots/10
[snapshot] success: height=10 size_bytes=8588 duration_ms=1
```

V0 alive after SIGUSR1: `process_alive_after_SIGUSR1=True` (driver assertion);
V0 stayed up through fault injection, V1B/V2C bring-up, and final scrape.

Snapshot inventory (`/tmp/run023/snapshot_inventory.txt`):

```text
meta.json 175
state/000009.sst 1052
state/CURRENT 16
state/MANIFEST-000013 266
state/OPTIONS-000015 7251
```

Snapshot metadata:

```json
{
  "height": 10,
  "block_hash": "02000000000000000a0000000000000001000000000000000900000000000000",
  "created_at_unix_ms": 1778311517151,
  "chain_id": 5855328520645203456
}
```

`CURRENT`, `MANIFEST-*`, `*.sst`, and `OPTIONS-*` are all present under the
canonical `StateSnapshotter` `state/` layout. `meta.json` validates against
`validate_snapshot_dir` (V1B and V2C both succeeded the validation step at
restore time — see §8).

## 8. B3 / B5 Restore Evidence

V1B restore log:

```text
[restore] requested: snapshot_dir=/tmp/run023/snapshots/10 data_dir=/tmp/run023/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=10 chain_id=0x51424e4444455600 bytes_copied=8588 target=/tmp/run023/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run023/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=10 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=10, starting_view=11)
[vm-v0] opened persistent state at /tmp/run023/data/v1b/state_vm_v0
[binary-consensus] B5: applied restore baseline: snapshot_height=10 starting_view=11 (engine committed_height=Some(10))
```

V1B `RESTORED_FROM_SNAPSHOT.json`:

```json
{"restored_at_unix_ms":1778311520659,"snapshot_dir":"/tmp/run023/snapshots/10","target_state_dir":"/tmp/run023/data/v1b/state_vm_v0","bytes_copied":8588,"snapshot_height":10,"snapshot_block_hash":"02000000000000000a0000000000000001000000000000000900000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778311517151}
```

V2C marker is identical except for `restored_at_unix_ms` and
`target_state_dir`:

```json
{"restored_at_unix_ms":1778311529163, "snapshot_dir":"/tmp/run023/snapshots/10", "target_state_dir":"/tmp/run023/data/v2c/state_vm_v0", "bytes_copied":8588, "snapshot_height":10, ...}
```

`<data_dir>/state_vm_v0` on V1B contains the materialized RocksDB state:

```text
000009.sst
000016.log
CURRENT
IDENTITY
LOCK
LOG
MANIFEST-000017
OPTIONS-000015
OPTIONS-000019
```

The `000009.sst` byte-equivalent of the snapshot's `state/000009.sst`
(`bytes_copied=8588` matches the snapshot footprint) confirms B3 fail-closed
materialization. B5 lines confirm `snapshot_height=10`,
`starting_view = snapshot_height + 1 = 11`, and engine
`committed_height=Some(10)` — the engine starts at the snapshot height, not
zero.

## 9. B13 Catchup and Exit Evidence

V1B log:

```text
[restore-catchup] applied 6 peer-learned certified blocks; committed_height=Some(14) view=17
[restore-catchup] exit: caught up to peer anchor — local committed_height=14 peer_max_observed=Some(14); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
[restore-catchup] rejected stale/mismatched response anchor: response_height=10 local_height=Some(14)
```

V2C log shows the same shape (6 blocks applied, exit at `committed_height=14`).

Final B13 metrics:

| Metric | V0 | V1B | V2C |
|---|---:|---:|---:|
| `qbind_restore_catchup_mode_active` | `0` | `0` (was `1`) | `0` (was `1`) |
| `qbind_restore_catchup_mode_exited_at_height` | `0` | `14` | `14` |
| `qbind_restore_catchup_blocks_applied_total` | `0` | `6` | `6` |
| `qbind_restore_catchup_responses_received_total` | `1` | `2` | `2` |
| `qbind_restore_catchup_responses_rejected_total` | `1` | `1` | `1` |

`mode_exited_at_height = 14 > snapshot_height = 10` — strict-progress predicate
satisfied on both restored validators. No indefinite plateau (the run-018
boundary). The single rejected response on each validator is the expected
stale-anchor rejection logged above (response anchor at the original snapshot
height after the validator already advanced past it via the other peer);
it is observation, not a failure.

## 10. B14 Absent-Leader Recovery Evidence

After V1A/V2A/V3A SIGINT and V1B/V2C restore, the V3 slot stayed absent
throughout. V0 emitted timeout messages and timeout certificates advanced the
view past V3-leader rounds:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=17 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 17 -> 18
[binary-consensus] B14: emitted TimeoutMsg for view=19 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 19 -> 20
[binary-consensus] B14: emitted TimeoutMsg for view=23 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 23 -> 24
[binary-consensus] B14: emitted TimeoutMsg for view=27 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 27 -> 28
[binary-consensus] B14: emitted TimeoutMsg for view=31 after 50 ticks of no progress
```

Per-node count of `B14: TimeoutCertificate advanced view` lines:
**V0=10, V1B=10, V2C=9**. Per-node B14 metrics:

| Metric | V0 | V1B | V2C |
|---|---:|---:|---:|
| `qbind_consensus_view_timeouts_emitted_total` | `10` | `10` | `10` |
| `qbind_consensus_timeout_certificates_formed_total` | `10` | `10` | `9` |
| `qbind_consensus_outbound_new_views_sent_total` | `10` | `10` | `9` |
| `qbind_consensus_view_timeout_advances_total` | `10` | `10` | `10` |
| `qbind_consensus_view_timeout_decode_failures_total` | `0` | `0` | `0` |
| `qbind_consensus_view_timeout_engine_rejects_total` | `0` | `0` | `0` |

(The metric family on the binary is exposed under the `qbind_consensus_*`
prefix; the task brief listed them under `qbind_*`. Same counters; only the
exposition prefix differs from the brief.)

`current_view` advanced from `11` (B5 starting view) on the restored
validators to `55` on all three alive nodes — **44 view advances**.
`committed_height` advanced from `10` to `42` on all three alive nodes —
**32 commits** above the SIGUSR1 snapshot baseline. Forward
proposal/vote/QC/commit progression resumed without operator intervention.

## 11. Metrics Before / After

V0 pre-SIGUSR1 (live cluster healthy, immediately before snapshot trigger):

| Metric | Value |
|---|---:|
| `qbind_consensus_committed_height` | `10` |
| `qbind_consensus_current_view` | `13` |
| `qbind_restore_catchup_mode_active` | `0` |
| `qbind_consensus_view_timeouts_emitted_total` | `0` |
| `qbind_consensus_timeout_certificates_formed_total` | `0` |
| `qbind_consensus_outbound_new_views_sent_total` | `0` |
| `qbind_consensus_view_timeout_advances_total` | `0` |
| `qbind_consensus_view_timeout_decode_failures_total` | `0` |
| `qbind_consensus_view_timeout_engine_rejects_total` | `0` |
| `qbind_consensus_proposals_total{result="rejected"}` | `0` |
| `qbind_consensus_votes_total{result="invalid"}` | `0` |
| `qbind_snapshot_success_total` | `0` |
| `qbind_snapshot_failure_total` | `0` |
| `qbind_snapshot_last_height` | `0` |

Final scrape (V0 / V1B / V2C, after V1A/V2A/V3A SIGINT and V1B+V2C restore):

| Metric | V0 | V1B | V2C |
|---|---:|---:|---:|
| `qbind_consensus_committed_height` | `42` | `42` | `42` |
| `qbind_consensus_current_view` | `55` | `55` | `55` |
| `qbind_restore_catchup_mode_active` | `0` | `0` | `0` |
| `qbind_restore_catchup_mode_exited_at_height` | `0` | `14` | `14` |
| `qbind_restore_catchup_blocks_applied_total` | `0` | `6` | `6` |
| `qbind_consensus_view_timeouts_emitted_total` | `10` | `10` | `10` |
| `qbind_consensus_timeout_certificates_formed_total` | `10` | `10` | `9` |
| `qbind_consensus_outbound_new_views_sent_total` | `10` | `10` | `9` |
| `qbind_consensus_view_timeout_advances_total` | `10` | `10` | `10` |
| `qbind_consensus_view_timeout_decode_failures_total` | `0` | `0` | `0` |
| `qbind_consensus_view_timeout_engine_rejects_total` | `0` | `0` | `0` |
| `qbind_consensus_proposals_total{result="rejected"}` | `0` | `0` | `0` |
| `qbind_consensus_votes_total{result="invalid"}` | `0` | `0` | `0` |
| `qbind_snapshot_success_total` | `1` | `0` | `0` |
| `qbind_snapshot_failure_total` | `0` | `0` | `0` |
| `qbind_snapshot_last_height` | `10` | `0` | `0` |

`qbind_snapshot_success_total=1` and `qbind_snapshot_last_height=10` on V0 are
direct evidence that V0's SIGUSR1 path executed exactly one successful real
snapshot through the production metrics surface
(`metrics.snapshot().record_success(...)` in
`crates/qbind-node/src/vm_v0_runtime.rs`). V1B and V2C never had `--snapshot-
dir` configured, so their snapshot counters stayed at zero, as expected.

## 12. Negative Checks

| Check | Result |
|---|---|
| No SIGUSR1 crash on V0 | ✓ `process_alive_after_SIGUSR1=True`; V0 ran from `T+0s` to `T+75s` and was SIGINT'd cleanly. |
| No placeholder snapshot files | ✓ Snapshot contains real `CURRENT` (16 B), `MANIFEST-000013` (266 B), `000009.sst` (1 052 B), `OPTIONS-000015` (7 251 B). Restore copied 8 588 bytes — same as the live RocksDB checkpoint footprint. |
| No silent in-memory fallback | ✓ V0/V1B/V2C all logged `[vm-v0] opened persistent state at <data_dir>/state_vm_v0`. No `[T164]`/`in-memory fallback` log appeared. |
| No `view_timeout_decode_failures_total` | ✓ `0` on V0/V1B/V2C. |
| No `view_timeout_engine_rejects_total` | ✓ `0` on V0/V1B/V2C. |
| No proposal rejection spike | ✓ `proposals_total{result="rejected"}=0` on V0/V1B/V2C. |
| No invalid vote spike | ✓ `votes_total{result="invalid"}=0` on V0/V1B/V2C. |
| No fabricated metrics | ✓ Every metric reported here is read directly from the node's own `/metrics` endpoint and saved verbatim to `/tmp/run023/scrapes/`. The `qbind_consensus_*` view-timeout family is the existing binary surface (the brief's `qbind_*` form is the same family minus the `consensus_` segment). |
| No regression of Run 022 disabled SIGUSR1 behavior | ✓ Separate disabled-trigger recheck (`/tmp/run023/disabled_recheck.py`) ran the binary without `--snapshot-dir`, sent SIGUSR1, observed `[snapshot] VM-v0 SIGUSR1 snapshot trigger disabled: --snapshot-dir not configured` → `[snapshot] signal received: SIGUSR1` → `[snapshot] SIGUSR1 ignored: VM-v0 snapshot trigger disabled (--snapshot-dir not configured)`, process alive, clean SIGINT exit (`rc=0`). |

## 13. Tests / Builds Run

| Command | Result |
|---|---|
| `cargo build -p qbind-node --bin qbind-node` | OK (debug; 2 pre-existing `bincode::config` deprecation warnings — unchanged from Run 022) |
| `cargo build -p qbind-ledger --example qbind_seed_vm_v0_state` | OK |
| `python3 /tmp/run023/run023.py` | OK; `RUN023_OK` followed by `RUN023_END` |
| `python3 /tmp/run023/disabled_recheck.py` | OK (`alive_after_SIGUSR1=True`, `rc=0`) |

No new tests were added by this run (no QBIND source code changed). The
existing B3/B5/B13/B14 / VM-v0 runtime / CLI snapshot-flag test suites
referenced by Runs 020/022 remain the test-grade correctness floor.

## 14. Crosscheck With Existing Spec / Design

Run 023 is consistent with the existing design and earlier-run claims:

- The SIGUSR1-trigger code path (`crates/qbind-node/src/main.rs:573-663`)
  matches Run 022's `[snapshot]` log shape, including the failure-case
  `record_failure()` branches in `vm_v0_runtime.rs`.
- The B3 restore code path (`crates/qbind-node/src/snapshot_restore.rs`)
  produced the exact same audit-marker JSON shape as documented in the body of
  C4 and Run 022.
- The B5 baseline application (`[binary] B5: restore-aware consensus start
  enabled` and `[binary-consensus] B5: applied restore baseline`) matches the
  text in C4's "B5 (restore-aware consensus start)" entry.
- The B13 strict-progress predicate (`local_height > base`) and the
  `[restore-catchup] exit:` log line match the contradiction-doc citation of
  `binary_consensus_loop.rs::RestoreCatchupModeState::maybe_exit_after_response`
  at lines 723–727.
- The B14 absent-leader recovery shape with three alive validators in normal
  participation matches the Run 016 / Run 019 shape.

No contradiction with the whitepaper or with the design notes in
`docs/whitepaper/contradiction.md` was discovered. **No new contradiction is
recorded.** A short Update-History row in `contradiction.md` is added (see §16)
to record that the SIGUSR1-created-snapshot variant of the Run 020 / Run 019
shape now lands strongest-positive end-to-end on the same binary.

## 15. What Was Proven / Not Proven

Proven by this run:

1. The real `qbind-node` binary, started with `--snapshot-dir` and
   `--execution-profile vm-v0 --data-dir <dir>`, opens
   `<data_dir>/state_vm_v0`, installs the SIGUSR1 trigger, receives SIGUSR1
   without terminating, and invokes `StateSnapshotter::create_snapshot`
   in-process at the live `committed_height` (10) recorded by the metrics
   committed-anchor.
2. The resulting snapshot directory is a real RocksDB checkpoint with
   `CURRENT`, `MANIFEST-*`, `*.sst`, and `OPTIONS-*` plus a valid
   `meta.json`.
3. Two independent restored validators (V1B vid=1, V2C vid=2) restore from
   that exact SIGUSR1-created snapshot via `--restore-from-snapshot`, write
   the B3 audit marker, materialize the checkpoint into
   `<data_dir>/state_vm_v0`, and apply the B5 baseline
   (`snapshot_height=10`, `starting_view=11`,
   engine `committed_height=Some(10)`).
4. Both restored validators apply 6 peer-learned certified blocks each
   above baseline, satisfy the B13 strict-progress predicate (exit at
   `committed_height=14 > 10`), flip `mode_active` from 1 to 0, and never
   plateau.
5. With three of four alive (V0+V1B+V2C, V3 absent) and all three in normal
   participation, B14 forms timeout certificates, advances `current_view`
   from 11 to 55 (44 advances), and the cluster commits forward from
   height 10 to height 42 (32 commits), with zero proposal rejections,
   zero invalid votes, zero decode failures, and zero engine rejects.
6. The Run 022 disabled-SIGUSR1 behavior is preserved on the same binary.

Not proven by this run (out of scope, tracked under C4):

- Production fast-sync / consensus-storage restore (only VM-v0 RocksDB
  checkpoint snapshot/restore is exercised here).
- ML-DSA signature verification of `TimeoutMsg` / `TimeoutCertificate`.
- Exponential-backoff timeout pacing (timeout interval is the existing
  fixed `view_timeout_ticks=Some(50)`).
- Production PQC KEMTLS root-key distribution (test-grade KEMTLS bring-up
  is what is exercised here, the same as Runs 019/020/022).
- Periodic snapshot trigger driven by `--snapshot-interval-blocks` (the
  CLI surface exists; only the SIGUSR1 trigger is exercised).

## 16. `contradiction.md` Update

`docs/whitepaper/contradiction.md` is updated with one Update-History row
recording Run 023 as strongest-positive closure of the **specific operational
sub-shape** of "SIGUSR1-created real-binary snapshot supports full N=4
Required-mode B3/B5/B13/B14 continuation". The C4 status row itself is **not**
re-narrowed because:

- The SIGUSR1-trigger gap and the VM-v0 runtime-open gap that Run 020/021/022
  already tracked were already updated by the Run 022 row.
- The broader C4-open items (production fast-sync / consensus-storage restore,
  signature verification of `TimeoutMsg`/`TimeoutCertificate`, exponential-
  backoff timeout pacing, production PQC KEMTLS root-key distribution) are
  unchanged by this run.

This is a sharpening, not a new contradiction. No QBIND source code was
changed by this run; the only repository change is this evidence file plus
the Update-History row.

## 17. Required Final Response Items

1. **Verdict.** Strongest positive: SIGUSR1-created real-binary snapshot
   supports full B3/B5/B13/B14 N=4 Required-mode continuation.
2. **Files changed.**
   - Added: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_023.md` (this file).
   - Added: one Update-History row in `docs/whitepaper/contradiction.md`
     (`Run 023` entry; no C4 row body change, no prior row edit).
   - No QBIND source code changed.
3. **Commands run.**
   - `cargo build -p qbind-node --bin qbind-node`
   - `cargo build -p qbind-ledger --example qbind_seed_vm_v0_state`
   - `target/debug/examples/qbind_seed_vm_v0_state /tmp/run023/data/v0/state_vm_v0`
   - `python3 /tmp/run023/run023.py` (V0/V1A/V2A/V3A start, SIGUSR1 V0,
     SIGINT V1A/V2A/V3A, V1B/V2C restore, scrape, SIGINT V0/V1B/V2C)
   - `python3 /tmp/run023/disabled_recheck.py` (Run 022 disabled-trigger
     recheck)
4. **Tests / evidence and pass/fail.**
   - Build qbind-node — **PASS**.
   - Build qbind-ledger seeder example — **PASS**.
   - Driver `run023.py` (full topology + SIGUSR1 + restore + observation) —
     **PASS** (`RUN023_OK`).
   - Disabled-trigger recheck — **PASS** (process alive, SIGUSR1 ignored
     with the expected log, clean exit `rc=0`).
   - All §7 / §8 / §9 / §10 / §11 / §12 evidence checks listed above —
     **PASS**.
5. **What was proven.** Items 1–6 in §15.
6. **What remains not solved.** The four out-of-scope items in §15
   ("Not proven by this run").
7. **`contradiction.md` updated?** Yes — one Update-History row only,
   recording Run 023's strongest-positive closure of the SIGUSR1-created-
   snapshot variant of the N=4 Required-mode B3/B5/B13/B14 continuation
   shape. The C4 status row body is **not** re-narrowed (this is a
   sharpening, not a new contradiction).
8. **Immediate next action recommended.** Exercise the `--snapshot-
   interval-blocks` periodic trigger end-to-end on the same N=4 Required-
   mode shape (the CLI surface exists today and is referenced in
   `crates/qbind-node/src/cli.rs`, but no DevNet evidence run has yet
   shown it firing in-process from a running validator and producing a
   restore-consumable snapshot). That is the smallest honest next
   sub-item of the C4 operator-trigger surface, strictly smaller than any
   of the four remaining out-of-scope items.