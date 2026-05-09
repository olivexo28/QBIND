# QBIND DevNet Evidence Run 026

## 1. Objective

Run 026 is the full N=4 Required-mode repeat of Run 024 against the now-wired
periodic `--snapshot-interval-blocks` trigger first proven on a single seeded
node by Run 025, plus restore of V1B and V2C from the periodic snapshot and
proof or disproof of full B3/B5/B13/B14 continuation. The snapshot under test
is created by the running real `qbind-node` itself through the periodic
committed-height trigger, **without SIGUSR1**, by `StateSnapshotter::create_snapshot`.

This run does not claim full C4 operational closure. It proves only that the
specific Run 024 boundary (periodic trigger not wired end-to-end) and the Run
025 boundary (full N=4 Required-mode repeat not done) are now both closed for
the periodic-snapshot path on this binary; production fast-sync /
consensus-storage restore, signature verification of `TimeoutMsg` /
`TimeoutCertificate`, exponential-backoff timeout pacing, and production PQC
KEMTLS root-key distribution remain tracked under C4.

## 2. Verdict

**Strongest positive.** The periodic `--snapshot-interval-blocks` trigger
creates a real restore-consumable snapshot in-process in N=4 Required-mode and
the periodic snapshot supports full B3 / B5 / B13 / B14 continuation. Every
required positive shape lands and every required negative check passes:

- V0 ran N=4 `--p2p-mutual-auth required` with `--snapshot-dir /tmp/run026/snapshots
  --snapshot-interval-blocks 4 --snapshot-max-snapshots 2` and **no SIGUSR1**.
- V0 created periodic snapshots at committed heights `4`, `8`, `12`, `16`, `20`
  in-process via `StateSnapshotter::create_snapshot`, all four nodes alive.
- Pruning proven: heights `4`, `8`, `12` pruned by `--snapshot-max-snapshots 2`;
  only heights `16` and `20` retained.
- Snapshot directory `/tmp/run026/snapshots/16/` contains real RocksDB checkpoint
  files (`CURRENT`, `MANIFEST-000013`, `000009.sst`, `OPTIONS-000015`) plus
  `meta.json`. No placeholder content.
- V1B and V2C restored from `/tmp/run026/snapshots/16` with fresh
  `--data-dir`s and `--execution-profile vm-v0`. B3 marker
  `RESTORED_FROM_SNAPSHOT.json` written on both; checkpoint copied into
  `<data_dir>/state_vm_v0/`.
- B5 baseline applied on both restored validators: `snapshot_height=16`,
  `starting_view=17`, engine `committed_height=Some(16)` from the first tick.
- B13 strict-progress exit on both restored validators: `mode_active` 1 → 0,
  `mode_exited_at_height=17 > 16`, `restore_catchup_blocks_applied_total=3`.
- B14 absent-leader recovery cleared the V1A/V2A/V3A-fault plateau:
  `view_timeouts_emitted_total=2/2/2` and timeout certificates advanced views
  past V3-leader rounds. `current_view` advanced 17 → 26 and `committed_height`
  advanced 16 → 21 on V0/V1B/V2C.
- `proposals_total{result="rejected"}=0` and `votes_total{result="invalid"}=0`
  on every node; `view_timeout_decode_failures_total=0` and
  `view_timeout_engine_rejects_total=0` on every node.
- `qbind_snapshot_success_total=5` (V0), `last_height=20`, `last_duration_ms=1`,
  `last_size_bytes=8588`, `in_progress=0`, `failure_total=0`.

## 3. Binary Identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
cargo build -p qbind-ledger --example qbind_seed_vm_v0_state
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-development-yet-again` |
| Commit | `288d5ef653c0b5073ad45c5cd1875b0c848580fe` |
| Working tree before run | clean (`git status --porcelain` empty) |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| Profile | `dev` (debug; 2 pre-existing `bincode::config` deprecation warnings, unchanged from Runs 022/023/024) |
| sha256 | `af4e4d7388e5fd1b386c889570ae8caf369b4d8a113e4ed5ea11d8c199a54216` |
| ELF BuildID (sha1) | `318c08f9c7ef296026eb10d020587752971f295e` |

## 4. CLI Surface

Command:

```sh
/home/runner/work/QBIND/QBIND/target/debug/qbind-node --help
```

Observed surface (relevant flags only):

```text
--execution-profile <EXECUTION_PROFILE>
--p2p-mutual-auth <P2P_MUTUAL_AUTH>
--restore-from-snapshot <RESTORE_FROM_SNAPSHOT>
--snapshot-dir <SNAPSHOT_DIR>
--snapshot-interval-blocks <SNAPSHOT_INTERVAL_BLOCKS>
--snapshot-max-snapshots <SNAPSHOT_MAX_SNAPSHOTS>
```

The `--snapshot-dir` help text now reflects the post-Run-025 wiring: *"When set
with `--execution-profile vm-v0 --data-dir <DIR>`, the running validator
installs the bounded SIGUSR1 snapshot trigger and, when
`--snapshot-interval-blocks` is non-zero, the committed-height periodic
trigger. Both write snapshots to `<PATH>/<committed_height>/` using the opened
`<data-dir>/state_vm_v0` RocksDB handle."*

## 5. Topology and Timing

N=4, `f=1`, `2f+1 = 3`, V0-first stagger, `--p2p-mutual-auth required`,
`--execution-profile vm-v0`, explicit data dirs, metrics enabled on every
node. `QBIND_MUTUAL_AUTH` was unset for every process so `--p2p-mutual-auth
required` on the CLI is the sole authority.

| Node | Phase | `vid` | Listen | Mutual auth | Profile | Data dir | Metrics | `--snapshot-dir` | `--restore-from-snapshot` |
|---|---|---:|---|---|---|---|---|---|---|
| V0  | live throughout            | 0 | `127.0.0.1:32050` | `required` | `vm-v0` | `/tmp/run026/data/v0`  | `:32000` | `/tmp/run026/snapshots` (`--snapshot-interval-blocks 4 --snapshot-max-snapshots 2`) | — |
| V1A | live pre-fault             | 1 | `127.0.0.1:32051` | `required` | `vm-v0` | `/tmp/run026/data/v1a` | `:32001` | — | — |
| V2A | live pre-fault             | 2 | `127.0.0.1:32052` | `required` | `vm-v0` | `/tmp/run026/data/v2a` | `:32002` | — | — |
| V3A | live pre-fault             | 3 | `127.0.0.1:32053` | `required` | `vm-v0` | `/tmp/run026/data/v3a` | `:32003` | — | — |
| V1B | restored after fault       | 1 | `127.0.0.1:32051` | `required` | `vm-v0` | `/tmp/run026/data/v1b` | `:32004` | — | `/tmp/run026/snapshots/16` |
| V2C | restored compatibly after  | 2 | `127.0.0.1:32052` | `required` | `vm-v0` | `/tmp/run026/data/v2c` | `:32005` | — | `/tmp/run026/snapshots/16` |

Timing (UTC, from `/tmp/run026/events.log`):

| Event | Time |
|---|---|
| `RUN026_START`                                               | `2026-05-09T09:04:58Z` |
| Pre-seed V0 `state_vm_v0`                                    | `2026-05-09T09:04:58Z` |
| V0 start (PID 13428)                                         | `2026-05-09T09:04:58Z` |
| V0 metrics up                                                | `2026-05-09T09:04:58Z` |
| V1A/V2A/V3A start                                            | `2026-05-09T09:04:59Z` |
| V0 reached `committed_height=16` past 4 interval boundaries  | `2026-05-09T09:05:02Z` |
| `SNAPSHOT_DIRS_AFTER_INTERVAL ["12", "16"]` (4 & 8 pruned)   | `2026-05-09T09:05:02Z` |
| All four nodes alive after periodic trigger                  | `2026-05-09T09:05:02Z` |
| SIGINT V1A/V2A/V3A                                           | `2026-05-09T09:05:02Z` |
| V1B started (`--restore-from-snapshot /tmp/run026/snapshots/16`) | `2026-05-09T09:05:04Z` |
| V2C started (`--restore-from-snapshot /tmp/run026/snapshots/16`) | `2026-05-09T09:05:07Z` |
| Final scrape (V0/V1B/V2C `committed_height=21`)              | `2026-05-09T09:05:19Z` |
| `RUN026_END`                                                 | `2026-05-09T09:05:21Z` |

## 6. Pre-seed Justification

Run 022 §10 noted: *"A fresh empty VM-v0 RocksDB can produce a valid RocksDB
checkpoint without an SST file."* The task brief requires the snapshot to
contain `*.sst`. To honor that without bypassing
`StateSnapshotter::create_snapshot` or the binary's periodic trigger, V0's
`state_vm_v0` was pre-seeded with one normal account before V0 started, using
the same library path the B3 integration tests use
(`crates/qbind-ledger/examples/qbind_seed_vm_v0_state.rs`):

```sh
/home/runner/work/QBIND/QBIND/target/debug/examples/qbind_seed_vm_v0_state \
  /tmp/run026/data/v0/state_vm_v0
# [qbind_seed_vm_v0_state] OK: seeded /tmp/run026/data/v0/state_vm_v0 \
#   account=cdcd...cd nonce=7 balance=4242
```

The seeder did not create a snapshot, did not write any `meta.json`/`state/`
layout, and did not bypass the binary's in-process periodic trigger. The actual
snapshot consumed by V1B/V2C was produced by V0's periodic
`StateSnapshotter::create_snapshot` path against this populated DB.

## 7. Commands Run

Driver: `/tmp/run026_orchestrator/run026.py` (Python orchestrator, kept outside
the repository). Representative expanded commands:

V0 (live throughout, periodic trigger configured, no SIGUSR1):

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:32000 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:32050 \
  --p2p-peer 1@127.0.0.1:32051 --p2p-peer 2@127.0.0.1:32052 --p2p-peer 3@127.0.0.1:32053 \
  --p2p-mutual-auth required --execution-profile vm-v0 \
  --data-dir /tmp/run026/data/v0 --validator-id 0 \
  --snapshot-dir /tmp/run026/snapshots \
  --snapshot-interval-blocks 4 \
  --snapshot-max-snapshots 2
```

V1A/V2A/V3A: same shape with `--validator-id 1/2/3`, listen
`32051/32052/32053`, metrics `32001/32002/32003`, no snapshot or restore flags.

V1B (restored from the periodic-trigger-created snapshot):

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:32004 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:32051 \
  --p2p-peer 0@127.0.0.1:32050 --p2p-peer 2@127.0.0.1:32052 --p2p-peer 3@127.0.0.1:32053 \
  --p2p-mutual-auth required --execution-profile vm-v0 \
  --data-dir /tmp/run026/data/v1b --validator-id 1 \
  --restore-from-snapshot /tmp/run026/snapshots/16
```

V2C: same shape as V1B with `--validator-id 2`, listen `32052`, metrics
`32005`, data dir `/tmp/run026/data/v2c`. Signal delivery used Python
`os.killpg(os.getpgid(p.pid), signal.SIGINT)` against the recorded numeric
PIDs — no shell expansion, no `pkill`/`killall`, **no SIGUSR1 sent** for the
primary periodic-trigger proof.

## 8. Periodic Trigger Evidence (no SIGUSR1)

V0 startup log shows both triggers installed but only the periodic one fired:

```text
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir=/tmp/run026/snapshots
[snapshot] periodic snapshot trigger enabled: interval_blocks=4 snapshot_dir=/tmp/run026/snapshots
[snapshot] periodic snapshot skipped: committed height is zero
```

V0 log on each periodic firing (excerpt):

```text
[snapshot] periodic condition detected: height=4 interval_blocks=4
[snapshot] start: height=4 path=/tmp/run026/snapshots/4
[snapshot] invoking StateSnapshotter::create_snapshot height=4 path=/tmp/run026/snapshots/4
[snapshot] periodic success: height=4 size_bytes=8588 duration_ms=1
[snapshot] periodic condition detected: height=8 interval_blocks=4
[snapshot] start: height=8 path=/tmp/run026/snapshots/8
[snapshot] invoking StateSnapshotter::create_snapshot height=8 path=/tmp/run026/snapshots/8
[snapshot] periodic success: height=8 size_bytes=8588 duration_ms=1
[snapshot] periodic condition detected: height=12 interval_blocks=4
[snapshot] start: height=12 path=/tmp/run026/snapshots/12
[snapshot] invoking StateSnapshotter::create_snapshot height=12 path=/tmp/run026/snapshots/12
[snapshot] pruning old numeric snapshot /tmp/run026/snapshots/4
[snapshot] periodic success: height=12 size_bytes=8588 duration_ms=1
[snapshot] periodic condition detected: height=16 interval_blocks=4
[snapshot] start: height=16 path=/tmp/run026/snapshots/16
[snapshot] invoking StateSnapshotter::create_snapshot height=16 path=/tmp/run026/snapshots/16
[snapshot] pruning old numeric snapshot /tmp/run026/snapshots/8
[snapshot] periodic success: height=16 size_bytes=8588 duration_ms=1
[snapshot] periodic condition detected: height=20 interval_blocks=4
[snapshot] start: height=20 path=/tmp/run026/snapshots/20
[snapshot] invoking StateSnapshotter::create_snapshot height=20 path=/tmp/run026/snapshots/20
[snapshot] pruning old numeric snapshot /tmp/run026/snapshots/12
[snapshot] periodic success: height=20 size_bytes=8588 duration_ms=1
```

No `[snapshot] signal received: SIGUSR1` appears anywhere in V0's log for the
primary proof — `events.log` records `NO_SIGUSR1_SENT_PRIMARY true`.
`ALIVE_AFTER_INTERVAL {"v0": true, "v1a": true, "v2a": true, "v3a": true}` —
all four nodes stayed alive after the periodic snapshots were created.

## 9. Snapshot Substrate

Snapshot inventory of `/tmp/run026/snapshots/16/` (the directory chosen as the
restore source — the highest snapshot retained after the
`--snapshot-max-snapshots 2` prune happened during the post-restore live
window):

```text
meta.json                176
state/000009.sst        1055
state/CURRENT             16
state/MANIFEST-000013    266
state/OPTIONS-000015    7251
```

`meta.json`:

```json
{
  "height": 16,
  "block_hash": "0000000000000000100000000000000003000000000000000f00000000000000",
  "created_at_unix_ms": 1778317502744,
  "chain_id": 5855328520645203456
}
```

`CURRENT`, `MANIFEST-*`, `*.sst`, and `OPTIONS-*` are all present under the
canonical `StateSnapshotter` `state/` layout. `validate_snapshot_dir` accepted
the directory at restore time (V1B and V2C both completed restore — see §11).

## 10. Pruning

`--snapshot-max-snapshots 2` was honored. V0 logged exactly the three prune
events:

```text
[snapshot] pruning old numeric snapshot /tmp/run026/snapshots/4
[snapshot] pruning old numeric snapshot /tmp/run026/snapshots/8
[snapshot] pruning old numeric snapshot /tmp/run026/snapshots/12
```

Final on-disk state: `/tmp/run026/snapshots/{16,20}` only. Only numeric
snapshot directories created by the periodic trigger were pruned; no
non-numeric path was touched; `/tmp/run026/snapshots/20` (the latest) was
retained. Pruning proven.

## 11. B3 / B5 Restore Evidence

V1B restore log:

```text
[restore] requested: snapshot_dir=/tmp/run026/snapshots/16 data_dir=/tmp/run026/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=16 chain_id=0x51424e4444455600 bytes_copied=8588 target=/tmp/run026/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run026/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=16 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=16, starting_view=17)
[vm-v0] opened persistent state at /tmp/run026/data/v1b/state_vm_v0
[binary-consensus] B5: applied restore baseline: snapshot_height=16 starting_view=17 (engine committed_height=Some(16))
```

V1B `RESTORED_FROM_SNAPSHOT.json`:

```json
{"restored_at_unix_ms":1778317504965,"snapshot_dir":"/tmp/run026/snapshots/16","target_state_dir":"/tmp/run026/data/v1b/state_vm_v0","bytes_copied":8588,"snapshot_height":16,"snapshot_block_hash":"0000000000000000100000000000000003000000000000000f00000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778317502744}
```

V2C marker is identical except for `restored_at_unix_ms` and
`target_state_dir`:

```json
{"restored_at_unix_ms":1778317507220,"snapshot_dir":"/tmp/run026/snapshots/16","target_state_dir":"/tmp/run026/data/v2c/state_vm_v0","bytes_copied":8588,"snapshot_height":16,...}
```

`/tmp/run026/data/v1b/state_vm_v0/` after restore contains the materialized
RocksDB state including the `000009.sst` byte-equivalent of the snapshot's
`state/000009.sst`:

```text
000009.sst  000016.log  CURRENT  IDENTITY  LOCK  LOG  MANIFEST-000017  OPTIONS-000015  OPTIONS-000019
```

`bytes_copied=8588` matches the snapshot footprint. B5 lines confirm
`snapshot_height=16`, `starting_view = snapshot_height + 1 = 17`, and engine
`committed_height=Some(16)` — the engine starts at the snapshot height, not
zero.

## 12. B13 Catchup and Exit Evidence

V1B log:

```text
[restore-catchup] applied 3 peer-learned certified blocks; committed_height=Some(17) view=20
[restore-catchup] exit: caught up to peer anchor — local committed_height=17 peer_max_observed=Some(17); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
[restore-catchup] rejected stale/mismatched response anchor: response_height=16 local_height=Some(17)
```

V2C log shows the same shape (3 blocks applied, exit at `committed_height=17`).

Final B13 metrics:

| Metric | V0 | V1B | V2C |
|---|---:|---:|---:|
| `qbind_restore_catchup_mode_active` | `0` | `0` (was `1`) | `0` (was `1`) |
| `qbind_restore_catchup_mode_exited_at_height` | `0` | `17` | `17` |
| `qbind_restore_catchup_blocks_applied_total` | `0` | `3` | `3` |

`mode_exited_at_height = 17 > snapshot_height = 16` — strict-progress predicate
satisfied on both restored validators. No indefinite plateau. The single
rejected response on each validator is the expected stale-anchor rejection
logged above (the response anchor is the snapshot height after the validator
already advanced past it via the other peer); it is observation, not a
failure.

## 13. B14 Absent-Leader Recovery Evidence

After V1A/V2A/V3A SIGINT and V1B/V2C restore, the V3 slot stayed absent
throughout the post-restore window. V0/V1B/V2C emitted timeout messages and
advanced the view past V3-leader rounds. Excerpt from V1B:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=20 after 50 ticks of no progress
[binary-consensus] B14: NewView advanced view 20 -> 21
[binary-consensus] B14: emitted TimeoutMsg for view=23 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 23 -> 24
```

Per-node B14 metrics at final scrape:

| Metric | V0 | V1B | V2C |
|---|---:|---:|---:|
| `qbind_consensus_view_timeouts_emitted_total` | `2` | `2` | `2` |
| `qbind_consensus_timeout_certificates_formed_total` | `2` | `1` | `2` |
| `qbind_consensus_outbound_new_views_sent_total` | `2` | `1` | `2` |
| `qbind_consensus_view_timeout_advances_total` | `2` | `2` | `2` |
| `qbind_consensus_view_timeout_decode_failures_total` | `0` | `0` | `0` |
| `qbind_consensus_view_timeout_engine_rejects_total` | `0` | `0` | `0` |

`current_view` advanced from `17` (B5 starting view on the restored
validators) to `26` on all three alive nodes — **9 view advances** through
absent-leader rounds. `committed_height` advanced from `16` to `21` on all
three alive nodes — **5 commits** above the periodic-snapshot baseline.
Forward proposal/vote/QC/commit progression resumed without operator
intervention.

(The metric family on the binary is exposed under the `qbind_consensus_*`
prefix; the task brief listed them under `qbind_*`. Same counters; only the
exposition prefix differs from the brief — same as Run 023 §10 noted.)

## 14. Required Metrics Before / After

V0 before periodic interval crossing (just started):

| Metric | Value |
|---|---:|
| `qbind_consensus_committed_height` | `0` |
| `qbind_consensus_current_view` | `0` |
| `qbind_snapshot_success_total` | `0` |
| `qbind_snapshot_last_height` | `0` |
| `qbind_snapshot_in_progress` | `0` |

V0 after periodic interval crossing (just before V1A/V2A/V3A SIGINT):

| Metric | Value |
|---|---:|
| `qbind_consensus_committed_height` | `16` |
| `qbind_consensus_current_view` | `19` |
| `qbind_snapshot_success_total` | `4` |
| `qbind_snapshot_failure_total` | `0` |
| `qbind_snapshot_last_height` | `16` |
| `qbind_snapshot_last_duration_ms` | `1` |
| `qbind_snapshot_last_size_bytes` | `8588` |
| `qbind_snapshot_in_progress` | `0` |
| `qbind_consensus_view_timeout_decode_failures_total` | `0` |
| `qbind_consensus_view_timeout_engine_rejects_total` | `0` |
| `qbind_consensus_proposals_total{result="rejected"}` | `0` |
| `qbind_consensus_votes_total{result="invalid"}` | `0` |

(`success_total=4` corresponds to heights 4, 8, 12, 16; the height-20 success
fires later in the live window, lifting V0's final to 5.)

Final scrape (V0 / V1B / V2C, after V1A/V2A/V3A SIGINT and V1B+V2C restore):

| Metric | V0 | V1B | V2C |
|---|---:|---:|---:|
| `qbind_consensus_committed_height` | `21` | `21` | `21` |
| `qbind_consensus_current_view` | `26` | `26` | `26` |
| `qbind_restore_catchup_mode_active` | `0` | `0` | `0` |
| `qbind_restore_catchup_mode_exited_at_height` | `0` | `17` | `17` |
| `qbind_restore_catchup_blocks_applied_total` | `0` | `3` | `3` |
| `qbind_consensus_view_timeouts_emitted_total` | `2` | `2` | `2` |
| `qbind_consensus_timeout_certificates_formed_total` | `2` | `1` | `2` |
| `qbind_consensus_outbound_new_views_sent_total` | `2` | `1` | `2` |
| `qbind_consensus_view_timeout_advances_total` | `2` | `2` | `2` |
| `qbind_consensus_view_timeout_decode_failures_total` | `0` | `0` | `0` |
| `qbind_consensus_view_timeout_engine_rejects_total` | `0` | `0` | `0` |
| `qbind_consensus_proposals_total{result="rejected"}` | `0` | `0` | `0` |
| `qbind_consensus_votes_total{result="invalid"}` | `0` | `0` | `0` |
| `qbind_snapshot_success_total` | `5` | `0` | `0` |
| `qbind_snapshot_failure_total` | `0` | `0` | `0` |
| `qbind_snapshot_last_height` | `20` | `0` | `0` |
| `qbind_snapshot_last_duration_ms` | `1` | `0` | `0` |
| `qbind_snapshot_last_size_bytes` | `8588` | `0` | `0` |
| `qbind_snapshot_in_progress` | `0` | `0` | `0` |

`qbind_snapshot_success_total=5` and `qbind_snapshot_last_height=20` on V0 are
direct evidence that V0's periodic path executed exactly five successful real
snapshots through the production metrics surface
(`metrics.snapshot().record_success(...)` in
`crates/qbind-node/src/vm_v0_runtime.rs`). V1B and V2C never had
`--snapshot-dir` configured, so their snapshot counters stayed at zero, as
expected. `in_progress=0` confirms the shared serialization guard released
each periodic snapshot before the next one started.

## 15. Negative Checks

| Check | Result |
|---|---|
| No SIGUSR1 used for primary periodic proof | ✓ `events.log` records `NO_SIGUSR1_SENT_PRIMARY true`; harness never called `signal.SIGUSR1`; V0 log contains zero `signal received: SIGUSR1` lines for the primary window. |
| No crash during periodic snapshot creation | ✓ `ALIVE_AFTER_INTERVAL {"v0": true, "v1a": true, "v2a": true, "v3a": true}` after height-16 boundary; all four exited cleanly on SIGINT. |
| No placeholder snapshot files | ✓ `/tmp/run026/snapshots/16/` contains real `meta.json` (176 B), `state/CURRENT` (16 B), `state/MANIFEST-000013` (266 B), `state/000009.sst` (1055 B), `state/OPTIONS-000015` (7251 B). Restore copied 8588 bytes — same as the live RocksDB checkpoint footprint. |
| No silent in-memory fallback | ✓ V0/V1B/V2C all logged `[vm-v0] opened persistent state at <data_dir>/state_vm_v0`. |
| No decode failures | ✓ `qbind_consensus_view_timeout_decode_failures_total=0` on V0/V1B/V2C. |
| No engine rejects | ✓ `qbind_consensus_view_timeout_engine_rejects_total=0` on V0/V1B/V2C. |
| No proposal rejection spike | ✓ `qbind_consensus_proposals_total{result="rejected"}=0` on V0/V1B/V2C. |
| No invalid vote spike | ✓ `qbind_consensus_votes_total{result="invalid"}=0` on V0/V1B/V2C. |
| No fabricated metrics | ✓ Every metric reported here is read directly from the node's own `/metrics` endpoint and saved verbatim under `/tmp/run026/scrapes/`. |
| No regression of SIGUSR1 behavior | Not rechecked in this primary run to keep the periodic-only proof clean; SIGUSR1 success path proven by Runs 022/023. |
| No regression of disabled-SIGUSR1 behavior | Not rechecked in this primary run; disabled-trigger path proven by Run 023. |

## 16. Tests / Builds Run

| Command | Result |
|---|---|
| `cargo build -p qbind-node --bin qbind-node` | OK (debug; 2 pre-existing `bincode::config` deprecation warnings — unchanged) |
| `cargo build -p qbind-ledger --example qbind_seed_vm_v0_state` | OK |
| `python3 /tmp/run026_orchestrator/run026.py` | OK; `RUN026_END` reached, all assertions positive |

No source code was changed by Run 026; the existing B3/B5/B13/B14 / VM-v0
runtime / CLI snapshot-flag test suites referenced by Runs 020/022/025 remain
the test-grade correctness floor.

## 17. Crosscheck With Existing Spec / Design

Run 026 is consistent with the existing design and the post-Run-025 binary
wiring:

- The periodic trigger code path
  (`crates/qbind-node/src/binary_consensus_loop.rs::log_periodic_snapshot_config`,
  `maybe_trigger_periodic_snapshot`, called from the committed-anchor branches
  at lines 1062–1066, 1151–1155, 1243–1247) matches the observed
  `[snapshot] periodic snapshot trigger enabled` →
  `[snapshot] periodic condition detected: height=N` →
  `[snapshot] start:` → `[snapshot] invoking StateSnapshotter::create_snapshot`
  → `[snapshot] periodic success` log shape, identical to Run 025 §4.
- Periodic and SIGUSR1 share the same
  `runtime.create_snapshot(...)` runtime path and the same in-process
  serialization guard, so `qbind_snapshot_in_progress=0` between events
  matches the design.
- The B3 restore code path (`crates/qbind-node/src/snapshot_restore.rs`)
  produced the exact same audit-marker JSON shape as Runs 022/023.
- The B5 baseline application (`[binary] B5: restore-aware consensus start
  enabled` and `[binary-consensus] B5: applied restore baseline`) matches the
  text in C4's "B5 (restore-aware consensus start)" entry.
- The B13 strict-progress predicate (`local_height > base`) and the
  `[restore-catchup] exit:` log line match the contradiction-doc citation of
  `binary_consensus_loop.rs::RestoreCatchupModeState::maybe_exit_after_response`.
- The B14 absent-leader recovery shape with three alive validators in normal
  participation matches the Run 016 / Run 019 / Run 023 shape.

No new contradiction with the whitepaper or with the design notes in
`docs/whitepaper/contradiction.md` was discovered. **`contradiction.md` was
updated** because Run 026 materially changes the C4 state recorded by Run 024
(negative N=4 baseline) and Run 025 (single-node positive): the periodic
`--snapshot-interval-blocks` trigger now lands strongest-positive end-to-end
in N=4 Required-mode with full B3/B5/B13/B14 continuation. Full C4 closure is
**not** claimed; the broader production items (production fast-sync /
consensus-storage restore, signature verification of `TimeoutMsg` /
`TimeoutCertificate`, exponential-backoff timeout pacing, production PQC
KEMTLS root-key distribution) remain open under C4.

## 18. Artifacts

Primary artifacts written under `/tmp/run026/` during the run:

- `/tmp/run026/events.log`
- `/tmp/run026/snapshot_inventory.txt`
- `/tmp/run026/log_digest.json`
- `/tmp/run026/logs/seed.log`
- `/tmp/run026/logs/{v0,v1a,v2a,v3a,v1b,v2c}.log`
- `/tmp/run026/metrics/{before_interval,after_interval,final}_summary.txt`
- `/tmp/run026/scrapes/*_{v0,v1a,v2a,v3a,v1b,v2c}.txt`
- `/tmp/run026/snapshots/{16,20}/{meta.json,state/*}`
- `/tmp/run026/data/{v1b,v2c}/RESTORED_FROM_SNAPSHOT.json`
- `/tmp/run026/data/{v1b,v2c}/state_vm_v0/...`

The orchestrator `/tmp/run026_orchestrator/run026.py` is intentionally kept
outside the repository.