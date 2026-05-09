# QBIND DevNet Evidence Run 027

## 1. Objective

Run 027 is a combined regression pass over the entire VM-v0 snapshot-trigger
surface on the same post-Run-026 real binary. In one evidence run it proves
or disproves that, on the same `qbind-node` binary, all four of these stay
stable together:

1. periodic `--snapshot-interval-blocks` trigger (Run 025/026 path),
2. SIGUSR1 trigger (Run 022/023 path),
3. disabled-trigger safety when `--snapshot-dir` is absent (Run 022 §8 path),
4. periodic ↔ SIGUSR1 interaction / serialization (new for Run 027).

Run 027 does not redesign consensus, does not redesign the snapshot format,
does not introduce another snapshot implementation, does not bypass
`StateSnapshotter::create_snapshot`, and does not use placeholder snapshot
files. It does not claim full C4 operational closure: production fast-sync /
consensus-storage restore, signature verification of `TimeoutMsg` /
`TimeoutCertificate`, exponential-backoff timeout pacing, production PQC
KEMTLS root-key distribution, and longer-window / larger-state snapshot
stability remain tracked under C4.

## 2. Verdict

**Strongest positive** for the four trigger paths under test. On the same
post-Run-026 binary:

- Sub-run A (N=4 Required-mode periodic, no SIGUSR1) created **10** real
  in-process `StateSnapshotter::create_snapshot` snapshots at committed
  heights `4, 8, 12, 16, 20, 24, 28, 32, 36, 40`, pruned to `[36, 40]` under
  `--snapshot-max-snapshots 2`, kept all four nodes alive, and a node
  restored from `/tmp/run027/A/snapshots/40` applied B3 marker + B5 baseline
  (`snapshot_height=40, starting_view=41, engine committed_height=Some(40)`)
  and continued committing past restore height.
- Sub-run B (single-node SIGUSR1) created a real snapshot at committed
  height `7` containing `meta.json`, `CURRENT`, `MANIFEST-000013`,
  `000009.sst`, `OPTIONS-000015`; the process stayed alive; restore applied
  B3 marker + B5 baseline (`snapshot_height=7, starting_view=8`).
- Sub-run C (disabled, no `--snapshot-dir`) handled three back-to-back
  SIGUSR1s without terminating, never created any snapshot directory, and
  emitted only the three explicit "trigger disabled / SIGUSR1 ignored" log
  lines. Every `qbind_snapshot_*` metric stayed at zero.
- Sub-run D (mixed periodic + SIGUSR1, 20 SIGUSR1s during ~6 s of
  committing) produced **32** real successful snapshots through the same
  `StateSnapshotter::create_snapshot` path; **0** "another snapshot is
  already in progress" overlap-skips fired (snapshots complete in ~1 ms);
  **4** SIGUSR1s landed at the same committed height as a just-completed
  periodic snapshot and were honestly logged as
  `[snapshot] ERROR: snapshot creation failed at .../<h>: snapshot already
  exists at: .../<h>` with `qbind_snapshot_failure_total` incrementing by
  exactly that count. All 3 retained snapshot directories `[56, 60, 64]`
  validate against the canonical `state/CURRENT + MANIFEST-* + *.sst +
  OPTIONS-*` layout. No partial / non-numeric entries remained in
  `/tmp/run027/D/snapshots/`. `qbind_snapshot_in_progress` returned to `0`.

Required negative checks across all sub-runs all passed: no process crash
from SIGUSR1, no placeholder files, no silent in-memory fallback, no
overlapping snapshot corruption, no partial / corrupt snapshot directories,
no fabricated metrics, no unexpected deletions outside numeric snapshot
dirs, and no regression of the periodic / SIGUSR1 / disabled-trigger paths.

One material **interaction observation** (not a regression, but worth
recording for operators): in mixed-trigger workloads, when a SIGUSR1 lands
at the same `committed_height` as a just-completed periodic snapshot,
`StateSnapshotter::create_snapshot` correctly refuses to overwrite the
existing valid directory and returns `StateSnapshotError::AlreadyExists`.
This is logged honestly and increments `qbind_snapshot_failure_total`. The
prior valid snapshot directory is unmodified. Operators that alarm on
`qbind_snapshot_failure_total > 0` should treat this as expected on
mixed-trigger nodes; bare-periodic and bare-SIGUSR1 nodes still keep
`failure_total = 0`. See §11 for the exact cite. This is a sharpening of
the Run 022/025/026 evidence shape on the same code, not a new
contradiction.

## 3. Binary Identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
cargo build -p qbind-ledger --example qbind_seed_vm_v0_state
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-status` |
| Commit | `40cc3d54316bff251516f5c11fc29cd16405e824` |
| Working tree before run | clean (`git status --porcelain` empty) |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| Profile | `dev` (debug; same 2 pre-existing `bincode::config` deprecation warnings as Runs 022 / 023 / 024 / 025 / 026, unchanged) |
| Binary sha256 | `af4e4d7388e5fd1b386c889570ae8caf369b4d8a113e4ed5ea11d8c199a54216` |
| Binary ELF BuildID (sha1) | `318c08f9c7ef296026eb10d020587752971f295e` |
| Seeder | `/home/runner/work/QBIND/QBIND/target/debug/examples/qbind_seed_vm_v0_state` |

The Run 026 → Run 027 delta on `copilot/continue-qbind-status` is
documentation-only (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_026.md` and
`docs/whitepaper/contradiction.md` Run 026 row); no QBIND source code
changed since Run 026, so the binary identity is byte-identical to Run 026.

```sh
$ sha256sum target/debug/qbind-node
af4e4d7388e5fd1b386c889570ae8caf369b4d8a113e4ed5ea11d8c199a54216  target/debug/qbind-node

$ file target/debug/qbind-node | tr ',' '\n' | grep BuildID
 BuildID[sha1]=318c08f9c7ef296026eb10d020587752971f295e
```

## 4. CLI Surface

```sh
/home/runner/work/QBIND/QBIND/target/debug/qbind-node --help
```

Observed (relevant flags only):

```text
--execution-profile <EXECUTION_PROFILE>
    --p2p-mutual-auth <P2P_MUTUAL_AUTH>
    --restore-from-snapshot <RESTORE_FROM_SNAPSHOT>
    --snapshot-dir <SNAPSHOT_DIR>
        When set with `--execution-profile vm-v0 --data-dir <DIR>`, the
        running validator installs the bounded SIGUSR1 snapshot trigger
        and, when `--snapshot-interval-blocks` is non-zero, the
        committed-height periodic trigger. Both write snapshots to
        `<PATH>/<committed_height>/` using the opened
        `<data-dir>/state_vm_v0` RocksDB handle.
    --snapshot-interval-blocks <SNAPSHOT_INTERVAL_BLOCKS>
        When paired with `--snapshot-dir`, the binary checks committed
        anchors and creates a VM-v0 snapshot at positive interval heights.
    --snapshot-max-snapshots <SNAPSHOT_MAX_SNAPSHOTS>
```

All six required CLI surfaces are exposed:
`--snapshot-dir`, `--snapshot-interval-blocks`, `--snapshot-max-snapshots`,
`--restore-from-snapshot`, `--execution-profile`, `--p2p-mutual-auth`.

## 5. Topology & Layout

| Sub-run | Topology | Triggers configured | SIGUSR1 sent | Pre-seed | Restore |
|---|---|---|---|---|---|
| **A** | N=4 Required-mode (V0/V1/V2/V3, `--p2p-mutual-auth required`, V0-first stagger), all `--execution-profile vm-v0` | V0: `--snapshot-dir /tmp/run027/A/snapshots --snapshot-interval-blocks 4 --snapshot-max-snapshots 2` | **No** | V0 `state_vm_v0` seeded | One node from `/tmp/run027/A/snapshots/40` |
| **B** | Single VM-v0 node (LocalMesh) | `--snapshot-dir /tmp/run027/B/snapshots --snapshot-max-snapshots 2`, no interval | **Yes** (1×) | V0 seeded | One node from `/tmp/run027/B/snapshots/7` |
| **C** | Single VM-v0 node | none (no `--snapshot-dir`) | **Yes** (3×) | none | n/a |
| **D** | Single VM-v0 node | both: `--snapshot-dir /tmp/run027/D/snapshots --snapshot-interval-blocks 4 --snapshot-max-snapshots 3` | **Yes** (20×, timed across ~6 s) | V0 seeded | n/a |

Each `qbind-node` was launched with `start_new_session=True` (its own
process group), `QBIND_MUTUAL_AUTH` was unset (CLI is sole authority), and
`QBIND_METRICS_HTTP_ADDR` was set per node. Signal delivery used Python
`os.kill(<numeric pid>, signal.SIGUSR1)` and `signal.SIGINT` against the
recorded numeric PIDs — no shell expansion, no `pkill` / `killall`.

Sub-run timeline (UTC, from `events.log`):

| Sub-run | Start | End |
|---|---|---|
| B          | `2026-05-09T09:39:11Z` | `2026-05-09T09:39:15Z` |
| B restore  | `2026-05-09T09:39:40Z` | `2026-05-09T09:39:46Z` |
| C          | `2026-05-09T09:40:06Z` | `2026-05-09T09:40:13Z` |
| A          | `2026-05-09T09:40:56Z` | `2026-05-09T09:41:10Z` |
| D          | `2026-05-09T09:42:03Z` | `2026-05-09T09:42:09Z` |

## 6. Pre-seed Justification

For sub-runs A, B, and D the V0 `state_vm_v0` was pre-seeded with a single
normal account before the node started, using
`crates/qbind-ledger/examples/qbind_seed_vm_v0_state.rs` (the same library
path the B3 integration tests use):

```sh
/home/runner/work/QBIND/QBIND/target/debug/examples/qbind_seed_vm_v0_state \
  /tmp/run027/A/data/v0/state_vm_v0
# [qbind_seed_vm_v0_state] OK: seeded /tmp/run027/A/data/v0/state_vm_v0 \
#   account=cdcd...cd nonce=7 balance=4242
```

The seeder did not create a snapshot, did not write any `meta.json` /
`state/` layout, and did not bypass the binary's in-process trigger. The
actual snapshots consumed in this run were produced by the running real
`qbind-node` via `StateSnapshotter::create_snapshot` against this populated
RocksDB. The seeding rationale is identical to Runs 022 §10, 023 §6,
025 §6, and 026 §6 — it ensures the produced snapshot contains an `*.sst`
file. Sub-run C deliberately does **not** pre-seed: its objective is to
prove *no* snapshot is created on the disabled-trigger path, regardless of
state shape.

## 7. Commands Run

Driver: orchestrators kept outside the repository (`/tmp/run027/orchestrate_{A,B,C,D}.py`,
plus `/tmp/run027/orchestrate_B_restore.py`). All four use `subprocess.Popen
(start_new_session=True)` and `os.kill(pid, signal.SIGUSR1 | signal.SIGINT)`.

### Sub-run A — periodic in N=4 Required-mode (representative V0 cmd)

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:32000 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:32050 \
  --p2p-peer 1@127.0.0.1:32051 --p2p-peer 2@127.0.0.1:32052 --p2p-peer 3@127.0.0.1:32053 \
  --p2p-mutual-auth required --execution-profile vm-v0 \
  --data-dir /tmp/run027/A/data/v0 --validator-id 0 \
  --snapshot-dir /tmp/run027/A/snapshots \
  --snapshot-interval-blocks 4 \
  --snapshot-max-snapshots 2
```

V1/V2/V3: same shape with `--validator-id 1/2/3`, listen `32051/32052/32053`,
metrics `32001/32002/32003`, no snapshot or restore flags.

### Sub-run B — SIGUSR1 only

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:33020 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --execution-profile vm-v0 \
  --data-dir /tmp/run027/B/data \
  --snapshot-dir /tmp/run027/B/snapshots \
  --snapshot-max-snapshots 2 --validator-id 0
# then: os.kill(pid, signal.SIGUSR1)
```

Restore:

```sh
/home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --execution-profile vm-v0 \
  --data-dir /tmp/run027/B/restored-data \
  --restore-from-snapshot /tmp/run027/B/snapshots/7 \
  --validator-id 0
```

### Sub-run C — disabled

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:33030 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --execution-profile vm-v0 \
  --data-dir /tmp/run027/C/data --validator-id 0
# then: os.kill(pid, signal.SIGUSR1) ×3
```

### Sub-run D — mixed periodic + SIGUSR1

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:33040 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --execution-profile vm-v0 \
  --data-dir /tmp/run027/D/data \
  --snapshot-dir /tmp/run027/D/snapshots \
  --snapshot-interval-blocks 4 \
  --snapshot-max-snapshots 3 --validator-id 0
# then: os.kill(pid, signal.SIGUSR1) ×20 with sub-tick offsets across ~6 s
```

## 8. Sub-run A — Periodic Trigger (no SIGUSR1)

V0 startup log shows both triggers installed but only the periodic one
fires:

```text
[vm-v0] opened persistent state at /tmp/run027/A/data/v0/state_vm_v0
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir=/tmp/run027/A/snapshots
[snapshot] periodic snapshot trigger enabled: interval_blocks=4 snapshot_dir=/tmp/run027/A/snapshots
[snapshot] periodic snapshot skipped: committed height is zero
```

V0 log on every periodic firing:

```text
[snapshot] periodic condition detected: height=4 interval_blocks=4
[snapshot] start: height=4 path=/tmp/run027/A/snapshots/4
[snapshot] invoking StateSnapshotter::create_snapshot height=4 path=/tmp/run027/A/snapshots/4
[snapshot] periodic success: height=4 size_bytes=8588 duration_ms=1
[snapshot] periodic condition detected: height=8 interval_blocks=4
... (heights 8, 12, 16, 20, 24, 28, 32, 36 all the same shape, with
     pruning of older numeric dirs) ...
[snapshot] periodic condition detected: height=40 interval_blocks=4
[snapshot] start: height=40 path=/tmp/run027/A/snapshots/40
[snapshot] invoking StateSnapshotter::create_snapshot height=40 path=/tmp/run027/A/snapshots/40
[snapshot] periodic success: height=40 size_bytes=8588 duration_ms=1
```

`grep '[snapshot] signal received: SIGUSR1' /tmp/run027/A/v0.log`
returns nothing — `events.log` records no SIGUSR1 sent in sub-run A.

`ALIVE_AFTER_PERIODIC = {"v0": True, "v1": True, "v2": True, "v3": True}`.

V0 metrics scrape (`http://127.0.0.1:32000/metrics`):

```text
qbind_snapshot_last_height 40
qbind_snapshot_last_duration_ms 1
qbind_snapshot_last_size_bytes 8588
qbind_snapshot_last_created_at_ms 1778319664031
qbind_snapshot_success_total 10
qbind_snapshot_failure_total 0
qbind_snapshot_in_progress 0
```

`success_total = 10` matches the 10 distinct heights observed in the log.
`failure_total = 0` and `in_progress = 0` confirm no failures and no leaked
in-progress flag.

Pruning evidence — only `36` and `40` retained under
`--snapshot-max-snapshots 2`:

```text
$ ls /tmp/run027/A/snapshots/
36  40
```

`/tmp/run027/A/snapshots/40/`:

```text
meta.json                      176
state/000009.sst              1055
state/CURRENT                   16
state/MANIFEST-000013          266
state/OPTIONS-000015          7251
```

`meta.json`:

```json
{
  "height": 40,
  "block_hash": "0000000000000000280000000000000003000000000000002700000000000000",
  "created_at_unix_ms": 1778319664029,
  "chain_id": 5855328520645203456
}
```

Sub-run A restore proof (B3 + B5, single restore as permitted by the
brief — Run 026 already proved the full N=4 V1B/V2C B13/B14 continuation):

```text
[restore] requested: snapshot_dir=/tmp/run027/A/snapshots/40 data_dir=/tmp/run027/A/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=40 chain_id=0x51424e4444455600 bytes_copied=8588 target=/tmp/run027/A/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run027/A/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=40 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=40, starting_view=41)
[vm-v0] opened persistent state at /tmp/run027/A/data/v1b/state_vm_v0
[binary-consensus] B5: applied restore baseline: snapshot_height=40 starting_view=41 (engine committed_height=Some(40))
[binary-consensus] committed_anchor height=41 block_id=0000000000000000290000000000000000000000000000002800000000000000
[binary-consensus] committed_anchor height=42 ...
... advances through height >=46 within 6 s
```

`/tmp/run027/A/data/v1b/RESTORED_FROM_SNAPSHOT.json`:

```json
{"restored_at_unix_ms":1778319664640,"snapshot_dir":"/tmp/run027/A/snapshots/40",
 "target_state_dir":"/tmp/run027/A/data/v1b/state_vm_v0","bytes_copied":8588,
 "snapshot_height":40,"snapshot_block_hash":"0000000000000000280000000000000003000000000000002700000000000000",
 "snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778319664029}
```

B3 marker present, B5 baseline applied (`snapshot_height=40,
starting_view=41, engine committed_height=Some(40)`), `committed_anchor`
advances strictly past restore height — periodic snapshot is restore-
consumable.

## 9. Sub-run B — SIGUSR1 Trigger

V0 (single node) startup + SIGUSR1 + snapshot in V0 log:

```text
[vm-v0] opened persistent state at /tmp/run027/B/data/state_vm_v0
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir=/tmp/run027/B/snapshots
[snapshot] periodic snapshot trigger disabled: --snapshot-interval-blocks is zero
[binary-consensus] committed_anchor height=0 ... height=7 ...
[snapshot] signal received: SIGUSR1
[snapshot] start: height=7 path=/tmp/run027/B/snapshots/7
[snapshot] invoking StateSnapshotter::create_snapshot height=7 path=/tmp/run027/B/snapshots/7
[snapshot] success: height=7 size_bytes=8588 duration_ms=1
[binary-consensus] committed_anchor height=8 ...
```

`PRE_USR1_alive=True`, `POST_USR1_alive=True`, `EXIT_CODE=0` after SIGINT.

Snapshot directory `/tmp/run027/B/snapshots/7/`:

```text
meta.json                      175
state/000009.sst              1055
state/CURRENT                   16
state/MANIFEST-000013          266
state/OPTIONS-000015          7251
```

`meta.json`:

```json
{
  "height": 7,
  "block_hash": "0000000000000000070000000000000000000000000000000600000000000000",
  "created_at_unix_ms": 1778319552499,
  "chain_id": 5855328520645203456
}
```

V0 metrics scrape (`http://127.0.0.1:33020/metrics`):

```text
qbind_snapshot_last_height 7
qbind_snapshot_last_duration_ms 1
qbind_snapshot_last_size_bytes 8588
qbind_snapshot_last_created_at_ms 1778319552501
qbind_snapshot_success_total 1
qbind_snapshot_failure_total 0
qbind_snapshot_in_progress 0
```

Restore from this SIGUSR1-created snapshot (`/tmp/run027/B/restore.log`):

```text
[restore] complete: height=7 chain_id=0x51424e4444455600 bytes_copied=8588 target=/tmp/run027/B/restored-data/state_vm_v0
[restore] audit marker written to /tmp/run027/B/restored-data/RESTORED_FROM_SNAPSHOT.json
[binary] B5: restore-aware consensus start enabled (snapshot_height=7, starting_view=8)
[vm-v0] opened persistent state at /tmp/run027/B/restored-data/state_vm_v0
[binary-consensus] B5: applied restore baseline: snapshot_height=7 starting_view=8 (engine committed_height=Some(7))
[binary-consensus] committed_anchor height=8 ... height=23 ...
```

Run 022/023 SIGUSR1 behavior is preserved verbatim on this binary.

## 10. Sub-run C — Disabled-Trigger Behavior

Single node, no `--snapshot-dir`. Three SIGUSR1s sent ~700 ms apart. Log
excerpt:

```text
[snapshot] VM-v0 SIGUSR1 snapshot trigger disabled: --snapshot-dir not configured
[snapshot] periodic snapshot trigger disabled: snapshot config disabled
[snapshot] periodic snapshot skipped: committed height is zero
[snapshot] signal received: SIGUSR1
[snapshot] SIGUSR1 ignored: VM-v0 snapshot trigger disabled (--snapshot-dir not configured)
[snapshot] signal received: SIGUSR1
[snapshot] SIGUSR1 ignored: VM-v0 snapshot trigger disabled (--snapshot-dir not configured)
[snapshot] signal received: SIGUSR1
[snapshot] SIGUSR1 ignored: VM-v0 snapshot trigger disabled (--snapshot-dir not configured)
[binary] Shutdown signal received, stopping consensus loop...
```

`POST_USR1_alive=True`, `EXIT_CODE=0` (clean SIGINT).

Filesystem under `/tmp/run027/C/`:

```text
data/         (RocksDB only, no snapshots/ inside)
events.log
metrics.txt
node.log
```

`/tmp/run027/C/snapshots/` does not exist — `events.log` records
`snapshots_dir_exists=False`.

Metrics scrape (`http://127.0.0.1:33030/metrics`):

```text
qbind_snapshot_last_height 0
qbind_snapshot_last_duration_ms 0
qbind_snapshot_last_size_bytes 0
qbind_snapshot_last_created_at_ms 0
qbind_snapshot_success_total 0
qbind_snapshot_failure_total 0
qbind_snapshot_in_progress 0
```

No fake metrics emitted, no fake directory created, three SIGUSR1s
explicitly logged as ignored. Run 022 §8 disabled behavior is preserved
verbatim.

## 11. Sub-run D — Mixed Trigger Interaction / Serialization

Both triggers configured; 20 SIGUSR1s sent across ~6 s with sub-tick
offsets so they interleave with periodic boundary firings.

Log excerpt covering both trigger types and the same-height collision
shape (the most informative window):

```text
[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 ...; snapshot_dir=/tmp/run027/D/snapshots
[snapshot] periodic snapshot trigger enabled: interval_blocks=4 snapshot_dir=/tmp/run027/D/snapshots
[snapshot] periodic condition detected: height=4 interval_blocks=4
[snapshot] start: height=4 path=/tmp/run027/D/snapshots/4
[snapshot] invoking StateSnapshotter::create_snapshot height=4 path=/tmp/run027/D/snapshots/4
[snapshot] periodic success: height=4 size_bytes=8588 duration_ms=1
[snapshot] signal received: SIGUSR1
[snapshot] start: height=6 path=/tmp/run027/D/snapshots/6
[snapshot] invoking StateSnapshotter::create_snapshot height=6 path=/tmp/run027/D/snapshots/6
[snapshot] success: height=6 size_bytes=8588 duration_ms=1
[snapshot] signal received: SIGUSR1
[snapshot] start: height=7 path=/tmp/run027/D/snapshots/7
[snapshot] invoking StateSnapshotter::create_snapshot height=7 path=/tmp/run027/D/snapshots/7
[snapshot] success: height=7 size_bytes=8588 duration_ms=1
[snapshot] periodic condition detected: height=8 interval_blocks=4
[snapshot] start: height=8 path=/tmp/run027/D/snapshots/8
[snapshot] invoking StateSnapshotter::create_snapshot height=8 path=/tmp/run027/D/snapshots/8
[snapshot] pruning old numeric snapshot /tmp/run027/D/snapshots/4
[snapshot] periodic success: height=8 size_bytes=8588 duration_ms=1
[snapshot] signal received: SIGUSR1
[snapshot] start: height=8 path=/tmp/run027/D/snapshots/8
[snapshot] invoking StateSnapshotter::create_snapshot height=8 path=/tmp/run027/D/snapshots/8
[snapshot] ERROR: snapshot creation failed at /tmp/run027/D/snapshots/8: snapshot already exists at: /tmp/run027/D/snapshots/8
[snapshot] signal received: SIGUSR1
[snapshot] start: height=9 path=/tmp/run027/D/snapshots/9
[snapshot] invoking StateSnapshotter::create_snapshot height=9 path=/tmp/run027/D/snapshots/9
[snapshot] success: height=9 size_bytes=8588 duration_ms=1
...
```

Counts measured directly from `node.log`:

| Event class | Count |
|---|---|
| `[snapshot] signal received: SIGUSR1` | 20 (matches 20 sent) |
| `[snapshot] periodic success: height=…` | 16 |
| `[snapshot] success: height=…` (SIGUSR1 path) | 16 |
| `[snapshot] ERROR: snapshot creation failed … already exists at …` | 4 |
| `[snapshot] SIGUSR1 skipped: another snapshot is already in progress` | 0 |
| `[snapshot] periodic snapshot skipped: another snapshot is already in progress` | 0 |

Final scrape (`http://127.0.0.1:33040/metrics`):

```text
qbind_snapshot_last_height 64
qbind_snapshot_last_duration_ms 1
qbind_snapshot_last_size_bytes 8588
qbind_snapshot_last_created_at_ms 1778319729759
qbind_snapshot_success_total 32
qbind_snapshot_failure_total 4
qbind_snapshot_in_progress 0
```

The metric arithmetic is internally consistent and honest:

- `success_total = 32 = 16 periodic-success + 16 SIGUSR1-success`
- `failure_total = 4 = 4 same-height `AlreadyExists` errors`
- `in_progress = 0` (returned to zero after every operation)

Both trigger paths share the same runtime: every snapshot — periodic or
SIGUSR1 — emits `[snapshot] invoking StateSnapshotter::create_snapshot
height=… path=…` immediately before opening the RocksDB checkpoint, i.e.
both call into `VmV0RuntimeState::create_snapshot` (see
`crates/qbind-node/src/vm_v0_runtime.rs:95–182`), which holds the
`snapshot_in_progress: AtomicBool` `compare_exchange(false, true)` guard
and the `state` `Mutex`. Snapshots completed in ~1 ms each in this run, so
the in-progress overlap-skip path was never exercised under this load
(0 hits) — but the guard is in place and `in_progress` returned to zero
after every attempt, including failures.

Final retained snapshot directories under `--snapshot-max-snapshots 3`
(every retained directory validates against the canonical
`StateSnapshotter` layout):

```text
$ ls /tmp/run027/D/snapshots/
56  60  64

$ ls /tmp/run027/D/snapshots/56/state/
000009.sst  CURRENT  MANIFEST-000013  OPTIONS-000015
$ ls /tmp/run027/D/snapshots/60/state/
000009.sst  CURRENT  MANIFEST-000013  OPTIONS-000015
$ ls /tmp/run027/D/snapshots/64/state/
000009.sst  CURRENT  MANIFEST-000013  OPTIONS-000015
```

Validation summary (`events.log`):

```text
SNAP_DIRS_FINAL=['56', '60', '64']
VALIDATE={'56': True, '60': True, '64': True}
NON_NUMERIC_ENTRIES=[]
```

Every retained numeric snapshot validates (has `meta.json`, `state/CURRENT`,
`MANIFEST-*`, an `*.sst`, and `OPTIONS-*`); no partial / non-numeric entry
exists in `/tmp/run027/D/snapshots/`. The 4 same-height collisions did
**not** corrupt the prior valid directory — `StateSnapshotter::create_snapshot`
checks for an existing target up front and returns
`StateSnapshotError::AlreadyExists(...)` before touching the filesystem
(see `crates/qbind-ledger/src/execution.rs:1620–1622` and
`crates/qbind-ledger/src/state_snapshot.rs:268–283`).

### Interpretation

The "trigger interaction" the brief asks about resolves cleanly into two
distinct shapes, both of which are observed honestly here:

1. **Wall-clock overlap** (one snapshot still running when the other
   trigger fires): bounded by the
   `VmV0RuntimeState::snapshot_in_progress` `AtomicBool` `compare_exchange`
   guard — the second trigger returns
   `VmV0RuntimeError::SnapshotAlreadyInProgress`, which the SIGUSR1 path
   logs as `[snapshot] SIGUSR1 skipped: another snapshot is already in
   progress` and the periodic path logs as
   `[snapshot] periodic snapshot skipped: another snapshot is already in
   progress`. **Neither path increments any metric for this skip.** Run
   027 sub-run D did not exercise this path because each snapshot runs in
   ~1 ms; the existing
   `vm_v0_snapshot_trigger_rejects_overlap_without_metric_failure` unit
   test (`crates/qbind-node/src/vm_v0_runtime.rs:398–...`) already covers
   it deterministically.
2. **Same-height collision** (both triggers want the *same* committed
   height): `StateSnapshotter::create_snapshot` refuses to overwrite a
   directory that already exists — this is a snapshot-format safety
   property, not a wall-clock race — and returns `AlreadyExists`. The
   refusal is logged as `[snapshot] ERROR: snapshot creation failed at
   .../<h>: snapshot already exists at: .../<h>` and increments
   `qbind_snapshot_failure_total`. The previously-written snapshot
   directory is unmodified. Sub-run D exercised this 4×.

Both shapes preserve the explicit invariant the brief requires: every
retained numeric snapshot directory validates, and `in_progress` returns
to zero.

## 12. Required Negative Checks

| Check | A | B | C | D |
|---|---|---|---|---|
| no process crash from SIGUSR1 | n/a (no SIGUSR1 sent) | ✅ alive after 1 SIGUSR1 | ✅ alive after 3 SIGUSR1s | ✅ alive after 20 SIGUSR1s |
| no placeholder snapshot files | ✅ all dirs have `meta.json + state/CURRENT + *.sst + MANIFEST-* + OPTIONS-*` | ✅ same | ✅ no snapshots dir | ✅ all retained dirs validate |
| no silent in-memory fallback | ✅ `[vm-v0] opened persistent state at …` on every node | ✅ | ✅ | ✅ |
| no overlapping snapshot corruption | ✅ no overlap log lines, all dirs valid | ✅ | n/a (no snapshots) | ✅ no `in progress` overlap fired; all retained dirs valid |
| no partial / corrupt snapshot dirs | ✅ `[36, 40]` both validate | ✅ `[7]` validates | ✅ no dir | ✅ `[56, 60, 64]` all validate, `NON_NUMERIC_ENTRIES=[]` |
| no fabricated metrics | ✅ `success_total=10` matches 10 distinct heights | ✅ `success_total=1` matches 1 SIGUSR1 success | ✅ all `qbind_snapshot_*` zero | ✅ `success_total=32 = 16+16`, `failure_total=4` matches 4 logged collisions |
| no unexpected deletion outside numeric dirs | ✅ only `/tmp/run027/A/snapshots/<h>/` pruned | n/a | n/a | ✅ only numeric dirs pruned, `events.log` non-numeric list is empty |
| no regression of periodic path | ✅ identical to Run 026 | n/a | n/a | ✅ 16 periodic snapshots fired exactly at heights {4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64} |
| no regression of SIGUSR1 path | n/a | ✅ identical to Run 022/023 | n/a | ✅ 16 successful SIGUSR1 snapshots produced |
| no regression of disabled-trigger safety | n/a | n/a | ✅ identical to Run 022 §8 | n/a |

## 13. Pass/Fail Table

| Sub-run | Required positive shapes | All hit? | Required negatives | All hit? | Verdict |
|---|---|---|---|---|---|
| **A — periodic in N=4 Required-mode** | periodic fires from committed height; in-process `StateSnapshotter::create_snapshot`; alive; real dir; `meta.json + CURRENT + MANIFEST-* + *.sst + OPTIONS-*`; metrics honest; pruning works; restore B3/B5 | **✅ all 8** | ✅ | **PASS** |
| **B — SIGUSR1** | SIGUSR1 received; alive; in-process `StateSnapshotter::create_snapshot`; real dir; canonical layout; metrics honest; restore B3/B5 | **✅ all 7** | ✅ | **PASS** |
| **C — disabled** | alive; explicit "trigger disabled / SIGUSR1 ignored" log; no snapshot dir created; no fake metrics | **✅ all 4** | ✅ | **PASS** |
| **D — mixed interaction** | both trigger types use the same runtime path; no overlap corruption; explicit serialization/skip behavior in logs; if skipped, log clearly; no partial dirs; metrics honest; `in_progress` returns to 0; every retained snapshot validates | **✅ all 8** | ✅ | **PASS** |

## 14. Crosscheck Against Existing Design / Spec

Crosschecked the observed behavior against
`crates/qbind-node/src/vm_v0_runtime.rs:95–182` (the in-process trigger
runtime), `crates/qbind-node/src/main.rs:600–700` (SIGUSR1 dispatch),
`crates/qbind-node/src/binary_consensus_loop.rs:2410–2480` (periodic
condition + fire), `crates/qbind-ledger/src/execution.rs:1602–1640`
(`StateSnapshotter::create_snapshot` `AlreadyExists` path), and
`crates/qbind-ledger/src/state_snapshot.rs:268–283`
(`StateSnapshotError::AlreadyExists` definition / `Display`). Everything
observed in the run is consistent with the source: a single shared runtime
path (`VmV0RuntimeState::create_snapshot`) is reused by both triggers,
with the `snapshot_in_progress` AtomicBool guarding wall-clock overlap and
the `StateSnapshotter`-level `AlreadyExists` check guarding same-height
re-write. No design contradictions found.

The only operator-facing nuance is that, on a node that runs both periodic
and SIGUSR1 triggers concurrently, `qbind_snapshot_failure_total > 0` is
*expected* whenever a SIGUSR1 lands in the same committed-height window as
a just-completed periodic snapshot. This is not a defect — it is how the
snapshot format enforces "do not silently overwrite a valid snapshot." On
nodes that run *only* the periodic trigger (Run 026 shape) or *only* the
SIGUSR1 trigger (Run 022/023 shape), `failure_total` stays at `0` (Run 026
metrics: `failure_total=0`; Run 022 metrics: `failure_total=0`).

## 15. Pass/Fail Summary

**Strongest positive.** All four trigger paths under test pass on the same
real binary with honest metrics and valid snapshots; no required negative
check failed in any sub-run.

## 16. Remaining Open Items

- Production fast-sync / consensus-storage restore (separate from VM-v0
  snapshot path) remains open under C4.
- Signature verification of `TimeoutMsg` / `TimeoutCertificate` remains
  open under C4.
- Exponential-backoff timeout pacing remains open under C4.
- Production PQC KEMTLS root-key distribution remains open under C4.
- Longer-window / larger-state snapshot stability — Run 027 ran for
  ~6–10 s per sub-run and ~20 ms per snapshot at ~8.5 KB; large-state and
  long-window stability remains tracked under C4.
- Sub-run D's wall-clock overlap path was not exercised in this run
  because each snapshot completes in ~1 ms; it remains covered only by the
  existing `vm_v0_snapshot_trigger_rejects_overlap_without_metric_failure`
  unit test. A larger-state / longer-snapshot run would exercise it
  end-to-end on the real binary.
- Sub-run A's periodic snapshot was restore-validated by a single
  single-validator restored node (B3 + B5 only); the full N=4 V1B/V2C
  B13/B14 continuation under Required-mode was already proven by Run 026
  on this same binary, so per the brief's allowance this was not
  re-proven here.

## 17. Verdict (final)

**Strongest positive.** Periodic, SIGUSR1, disabled-trigger, and
mixed-trigger serialization behavior all pass on the real binary with
honest metrics and valid snapshots. The only material observation is that
mixed-trigger workloads honestly report `qbind_snapshot_failure_total > 0`
when SIGUSR1 lands at the same committed height as a just-completed
periodic snapshot, because `StateSnapshotter::create_snapshot` correctly
refuses to overwrite the existing valid directory. This is sharpened in
the Run 027 row of `docs/whitepaper/contradiction.md`. No previously
landed binary-path capability appears regressed.