# QBIND DevNet Evidence Run 003

**Status:** Internal evidence record — third single-validator DevNet
binary-path run. Targets the specific capability landed by **B3**:
`--restore-from-snapshot <PATH>` ingestion at startup. Captures honest
restore-then-observe evidence on the actual `qbind-node` binary path.
**Audience:** Internal — protocol engineering, ops, release management.
**Run date:** 2026-05-03 (UTC).
**Author:** Execution follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_002.md` §11 ("next: restore-then-
observe on the binary path"), now that B3 has landed in
`crates/qbind-node/src/snapshot_restore.rs` and
`crates/qbind-node/src/main.rs`.

> This document is a focused third evidence artifact. It is **not** a
> Beta-readiness statement, **not** a multi-validator demonstration,
> **not** a soak result, **not** a full backup-and-recovery program
> completion, and **not** a recovery-readiness sign-off. It exists to
> record, exactly, whether the real `qbind-node` binary on the actual
> binary path can take a real `StateSnapshotter`-format snapshot,
> validate it, materialize it into the configured `<data_dir>`,
> continue into normal startup, drive the consensus loop, expose
> `/metrics`, and shut down cleanly — and to record what this run does
> *not* prove.

---

## 1. Purpose and Scope

Run 001 established that the real `qbind-node` binary starts, drives a
real `BasicHotStuffEngine` consensus loop on the binary path, exposes
`/metrics`, and shuts down cleanly on SIGINT. Run 002 closed the
specific Run-001 limitation that `/metrics` did not previously carry
live consensus progress (the binary-path metrics-wiring fix).

B3 then landed the smallest honest restore-from-snapshot startup path:
`--restore-from-snapshot <PATH>` is plumbed through
`crates/qbind-node/src/cli.rs` into
`FastSyncConfig`, and `crates/qbind-node/src/main.rs` calls
`snapshot_restore::apply_snapshot_restore_if_requested(&config)` before
the consensus loop is started. The validated snapshot's RocksDB
checkpoint is materialized into `<data_dir>/state_vm_v0` and an audit
marker `<data_dir>/RESTORED_FROM_SNAPSHOT.json` is written. Failures
exit non-zero with a precise reason; no silent degradation.

Run 003's purpose, and only purpose, is to capture concrete evidence of
whether that real binary path actually carries through:

In scope (this run):

- A. Produce a real snapshot in the **existing** `StateSnapshotter`
  format (`meta.json` + `state/` RocksDB checkpoint). No second format
  is invented.
- B. Drive the real `qbind-node` binary with `--env devnet
  --validator-id 0 --data-dir <fresh path> --restore-from-snapshot
  <snapshot path>` and `QBIND_METRICS_HTTP_ADDR=...`.
- C. Capture the `[restore]` log path: `requested → validated → copied →
  marker written → OK`.
- D. Prove materialization is **byte-identical** to the source snapshot
  `state/` (not just "flag accepted"): file-by-file `diff -r` and
  per-file SHA-256.
- E. Prove restored state is **observable** by reopening the materialized
  `<data_dir>/state_vm_v0` as a normal `RocksDbAccountState` and reading
  back two well-known accounts that were written before the snapshot.
- F. Capture the audit marker `RESTORED_FROM_SNAPSHOT.json` content.
- G. Show one negative-validation case (wrong chain id) where the binary
  exits non-zero and writes nothing into `<data_dir>/state_vm_v0` —
  evidence that validation is real, not syntactic.
- H. Show the consensus loop progresses after restore (ticks/proposals/
  commits/view) on the binary path, and that `/metrics` reflects that
  progress between two scrapes separated in wall-clock time.
- I. Show clean SIGINT shutdown after a post-restore run.

Explicitly out of scope (this run):

- Multi-validator binary-path DevNet (LocalMesh fan-in or P2P).
- Soak / 72-hour stability evidence.
- Restoring non–VM-v0 substate (consensus storage at
  `<data_dir>/consensus`, slashing ledger, gov state, …) — the existing
  `StateSnapshotter` format does not produce these and B3 does not
  pretend to. This is recorded as a known limitation in §11.
- Any change to the multi-validator P2P→consensus binary-path
  interconnect, which remains the residual sub-item under
  `contradiction.md` C4.
- Operator drill-catalog instantiation, `/health`/`/ready`, RPC.
- Any claim of MainNet recovery readiness or full
  `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` completion. This
  artifact contributes one bounded piece of restore evidence to that
  baseline; it does not satisfy it.

---

## 2. Canonical Basis

This run is grounded in, and bounded by:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_001.md`
  — established the binary-path startup/consensus/metrics/shutdown
  shape Run 003 reuses unchanged.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_002.md`
  — established that `/metrics` carries live consensus progress on the
  binary path (the comparison Run 003 reuses for §9).
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` (EXE-2)
  — §6.1 (B3 predicted gap), §7 (single-validator binary-path mode),
  §10 (next-action ordering — "restore-then-observe").
- `docs/whitepaper/contradiction.md`
  — C4 (still OPEN; B3 closed at the code level; multi-validator P2P
  binary-path interconnect remains residual). Re-evaluated in §12.
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`
  — referenced indirectly to qualify *which* recovery evidence this
  run does and does not satisfy (it adds bounded restore-then-observe
  evidence for VM-v0 state on the single-validator binary path; it
  does not satisfy the full baseline).
- `crates/qbind-node/src/snapshot_restore.rs` (B3 entry points
  `apply_snapshot_restore_if_requested` and `restore_from_snapshot`,
  audit marker constants `VM_V0_STATE_SUBDIR`, `RESTORE_MARKER_FILENAME`).
- `crates/qbind-node/src/main.rs:109–139` (B3 call site, before
  consensus startup; non-zero exit on any restore error).
- `crates/qbind-node/src/cli.rs:230–247, 962–971` (`--data-dir`,
  `--restore-from-snapshot` flag plumbing into `FastSyncConfig`).
- `crates/qbind-ledger/src/state_snapshot.rs` (existing `meta.json`
  + `state/` snapshot format and `validate_snapshot_dir`; reused, not
  re-implemented).
- `crates/qbind-node/tests/b3_snapshot_restore_tests.rs` (the in-tree
  regression tests Run 003 complements with end-to-end binary-path
  evidence).

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch
  `copilot/run-devnet-evidence-003`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`,
  `rustc 1.94.1 (e408947bf 2026-03-25)`.
- Build command (binary under test):
  `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome: `Finished `release` profile [optimized] target(s) in 5m 02s`
  (clean from cold cache). The same single pre-existing compiler
  warning carried by Run 001 / Run 002 surfaced unchanged
  (`unused variable: worker_id` in
  `crates/qbind-node/src/verify_pool.rs:262`). Out of scope.
- Resulting binary: `target/release/qbind-node`, ≈ 8.4 MiB
  (8 833 152 bytes), executable, ELF 64-bit `x86-64`.
- Host: GitHub-hosted Linux x86_64 sandbox (single host, single
  process, no peers).
- Network: no `--enable-p2p`; default LocalMesh, single-validator
  (no `--p2p-peer`).

This is, exactly as in Run 001 and Run 002, a **single-validator,
single-host, binary-path, LocalMesh, no-P2P, short-bounded run**, with
the addition of `--data-dir` and `--restore-from-snapshot` for this
run. Nothing more.

---

## 4. Snapshot Source and Format Used

The snapshot was produced by the **canonical** `StateSnapshotter`
format already in the repo
(`crates/qbind-ledger/src/state_snapshot.rs`). No second format is
invented for this run.

### 4.1 How the snapshot was produced

A small one-off helper (kept under `/tmp/run003/snapgen`, not
committed) was built against the local `qbind-ledger` crate. It does
exactly what `crates/qbind-node/tests/b3_snapshot_restore_tests.rs`
does in `build_real_snapshot`:

1. Open a fresh `RocksDbAccountState` in a scratch directory.
2. Write two well-known account states:
   - account `A` = `[0xA1; 32]` → `AccountState::new(nonce=7,
     balance=4242)`
   - account `B` = `[0xB2; 32]` → `AccountState::new(nonce=11,
     balance=999_999)`
3. `flush()` the state.
4. Build a `StateSnapshotMeta` for `height=100` with
   `chain_id = 0x51424e4444455600` (DevNet, matches
   `NodeConfig::default().chain_id().as_u64()` and the startup
   banner).
5. Call `RocksDbAccountState::create_snapshot(&meta, &out_dir)`.

The two known accounts exist *only so* §6.4 can prove restored state is
observable post-restore. They are not part of the snapshot format and
do not change it.

### 4.2 Resulting on-disk layout (observed)

```
/tmp/run003/snap-100/
├── meta.json              177 bytes
└── state/
    ├── 000009.sst         1080 bytes
    ├── CURRENT              16 bytes
    ├── MANIFEST-000005     250 bytes
    └── OPTIONS-000007     7251 bytes
```

Total snapshot payload (including `meta.json`): 8 774 bytes on disk;
`state/` payload alone: 8 597 bytes (matches the `bytes_copied=8597`
the binary later reports; see §6.2).

### 4.3 `meta.json` (exact, unedited)

```
{
  "height": 100,
  "block_hash": "0000000000000064000000000000000000000000000000000000000000000000",
  "created_at_unix_ms": 1777825067184,
  "chain_id": 5855328520645203456
}
```

`5855328520645203456` (decimal) = `0x51424e4444455600` (hex), exactly
the DevNet chain id `qbind-node` logs in its startup banner. This
matters: `validate_snapshot_dir` will compare this against
`config.chain_id().as_u64()` and reject a mismatch (see §6.5).

### 4.4 What this snapshot represents and what it does not

- It is a real RocksDB checkpoint of a real `RocksDbAccountState`
  produced by the canonical T215 path. The binary will validate it
  with the same `validate_snapshot_dir` it would use for any other
  snapshot.
- It is **VM-v0 account state only**. It does not contain consensus
  storage (`<data_dir>/consensus`), slashing ledger state, governance
  state, or anything else `StateSnapshotter` does not produce. B3
  itself is scoped to VM-v0 and does not pretend otherwise; see §11.

---

## 5. Commands and Configuration Used

### 5.1 Build (binary under test)

```
cargo build --release -p qbind-node --bin qbind-node
```

### 5.2 Run command (canonical EXE-2 §7 single-validator-with-metrics shape, plus B3 flags)

```
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node \
    --env devnet \
    --validator-id 0 \
    --data-dir <fresh path> \
    --restore-from-snapshot /tmp/run003/snap-100
```

The shape `--env devnet --validator-id 0` and the
`QBIND_METRICS_HTTP_ADDR` env var are byte-for-byte the same as in
Run 001 §4.2 and Run 002 §4.2. This is deliberate, so any new behavior
here is attributable only to the addition of `--data-dir` and
`--restore-from-snapshot` (the B3 surface) and not to a configuration
drift from earlier runs.

### 5.3 Bounded-run wrappers used for evidence capture

To produce reproducible, ordered shutdowns without an interactive
`Ctrl+C`, each run was started under `timeout --foreground -s INT
<seconds>` — the same `SIGINT` a human operator's `Ctrl+C` delivers
and the same signal `tokio::signal::ctrl_c()` listens for in
`crates/qbind-node/src/main.rs::run_local_mesh_node`. **No code path
in `qbind-node` was modified for this run.**

Three short bounded runs were executed:

- **Run 1** (8-second bound, fresh `--data-dir`): full restore →
  startup → progression → shutdown capture. Evidence in §6, §7,
  §8.1, §10.1.
- **Run 2** (8-second bound, fresh `--data-dir`): same shape as Run 1,
  but while it was running `/metrics` was scraped twice — once
  shortly after the metrics listener became reachable
  (**Scrape A**, "early"), and again after a 4-second wait (**Scrape
  B**, "late"). Evidence in §9.
- **Run 3** (5-second bound, fresh `--data-dir`): negative-validation
  case using a hand-edited `meta.json` with `chain_id=12345` (i.e.
  not the DevNet chain id). Evidence in §6.5.

### 5.4 Environment variables

Only one environment variable was set, identical to Run 001 / Run 002:

| Variable | Value | Purpose |
|---|---|---|
| `QBIND_METRICS_HTTP_ADDR` | `127.0.0.1:9100` | Enable `/metrics` HTTP server. Read by `MetricsHttpConfig::from_env()`. |

No other QBIND-prefixed env vars were set. No config file was used.
CLI flags were `--env devnet --validator-id 0 --data-dir <path>
--restore-from-snapshot <path>` only.

---

## 6. Restore Validation Evidence

### 6.1 `[restore]` log sequence (Run 1, exact, unedited, in observed order)

```
[restore] requested: snapshot_dir=/tmp/run003/snap-100 data_dir=/tmp/run003/data-dir-1 expected_chain_id=0x51424e4444455600
[restore] complete: height=100 chain_id=0x51424e4444455600 bytes_copied=8597 target=/tmp/run003/data-dir-1/state_vm_v0
[restore] audit marker written to /tmp/run003/data-dir-1/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=100 chain_id=0x51424e4444455600
```

Observed (direct):

- `expected_chain_id=0x51424e4444455600` is the DevNet chain id
  derived from `config.chain_id().as_u64()` — i.e. validation is
  pinned to the binary's own configured chain id, not to whatever
  the snapshot claims.
- `bytes_copied=8597` matches the byte-count of the source
  `snap-100/state/` payload from §4.2 exactly.
- The `[restore] complete` line is emitted only after
  `validate_snapshot_dir` returns `SnapshotValidationResult::Valid(meta)`
  *and* `copy_dir_recursive` has finished copying the checkpoint. The
  surrounding control flow (`apply_snapshot_restore_if_requested` →
  `restore_from_snapshot` →
  `copy_dir_recursive` → `write_restore_marker`) is the documented
  one in `crates/qbind-node/src/snapshot_restore.rs:170–283`.

### 6.2 Materialized target — observed `<data_dir>` tree

```
/tmp/run003/data-dir-1/
├── RESTORED_FROM_SNAPSHOT.json       347 bytes
└── state_vm_v0/
    ├── 000009.sst                   1080 bytes
    ├── CURRENT                        16 bytes
    ├── MANIFEST-000005               250 bytes
    └── OPTIONS-000007               7251 bytes
```

This is exactly the documented post-restore layout: the snapshot's
`state/` was copied into `<data_dir>/state_vm_v0` (the
`VM_V0_STATE_SUBDIR` constant from
`crates/qbind-node/src/snapshot_restore.rs:66`) and the audit marker
was written at `<data_dir>/RESTORED_FROM_SNAPSHOT.json` (the
`RESTORE_MARKER_FILENAME` constant from `:73`).

### 6.3 Materialization is byte-identical to the source (the load-bearing proof)

`diff -r` against the source `snap-100/state/`:

```
$ diff -r /tmp/run003/snap-100/state /tmp/run003/data-dir-1/state_vm_v0
(no output — directories are byte-identical)
```

Per-file SHA-256 of the materialized state:

```
016d828912746bb7b0af877776034ce3a1774ea5b2c5e43e66332c18e214a202  OPTIONS-000007
0dd8ed5fb26ea702b1be8b44690018ebc2028a60d089bdb4d7313533e38930d6  MANIFEST-000005
9c283f6e81028b9eb0760d918ee4bc0aa256ed3b926393c1734c760c4bd724fd  CURRENT
a1f4300f16b310e5d9fa1b89f32d71900524cb8af90c4d8028736a5233cc9a01  000009.sst
```

The same `sha256sum` set computed against the source `snap-100/state/`
files was identical (verified by `diff` of the two sorted-`sha256sum`
outputs; no differences). This is direct evidence that the binary
materialized the snapshot, file-for-file, byte-for-byte — not "flag
accepted, nothing copied".

### 6.4 Restored state is observable post-restore (proof restore is real, not syntactic)

After Run 1 had shut down (releasing the RocksDB lock on
`<data_dir>/state_vm_v0`), the materialized state directory was
reopened via the **same** `RocksDbAccountState::open` that the
production runtime uses, and the two well-known accounts written
before the snapshot were read back:

```
readback dir = /tmp/run003/data-dir-1/state_vm_v0
account A (0xA1*32) = AccountState { nonce: 7, balance: 4242 }
account B (0xB2*32) = AccountState { nonce: 11, balance: 999999 }
OK: both account states match pre-snapshot values.
```

`AccountState::new(7, 4242)` and `AccountState::new(11, 999_999)` are
exactly the values written before `create_snapshot` (see §4.1). This
is the same proof shape exercised in
`crates/qbind-node/tests/b3_snapshot_restore_tests.rs::b3_restored_state_is_observable_after_reopen`,
but applied here to a directory materialized by the **real binary**,
not by an in-process test driver.

This closes the "restore is real, not syntactic" expectation from §7
of the task: the bytes the binary copied parse as a valid
RocksDB-format VM-v0 store and contain the pre-snapshot state.

### 6.5 Negative-validation evidence (wrong chain id)

To prove validation is **real and binary-side** (not just "the layout
looked OK"), Run 3 used a snapshot whose `meta.json` was hand-edited
to `chain_id=12345` (`0x3039`). Everything else
(`state/000009.sst`, `state/MANIFEST-...`, `state/CURRENT`,
`state/OPTIONS-...`) was untouched and on its own would have copied
fine.

Observed `[restore]` log (Run 3, exact):

```
[restore] requested: snapshot_dir=/tmp/run003/snap-100-wrongchain data_dir=/tmp/run003/data-dir-wrongchain expected_chain_id=0x51424e4444455600
[restore] ERROR: restore-from-snapshot snapshot is invalid: chain ID mismatch: expected 0x51424e4444455600, got 0x3039
[restore] qbind-node refuses to start because the requested snapshot restore could not be honestly applied. See docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md and docs/whitepaper/contradiction.md C4 (B3).
```

Process exit code: `1` (non-zero). Post-failure inspection of
`/tmp/run003/data-dir-wrongchain` showed the directory **did not
exist** — no `state_vm_v0/`, no `RESTORED_FROM_SNAPSHOT.json`. That
confirms `restore_from_snapshot` returns the validation error
*before* `create_dir_all(data_dir)` would otherwise be reached for the
copy phase, exactly as the source code orders the checks
(`crates/qbind-node/src/snapshot_restore.rs:226–243`).

This is concrete evidence that:

- restore validation is enforced by the binary, not just by the
  helper that produced the snapshot;
- a bad snapshot does **not** silently degrade to "no restore" —
  the binary refuses to start at all;
- the failure path leaves the configured `<data_dir>` untouched.

### 6.6 Audit marker (`RESTORED_FROM_SNAPSHOT.json`) — exact contents

From Run 1, exact, unedited (single line; reflowed only here for
readability — the on-disk file is one JSON object terminated by `\n`):

```
{"restored_at_unix_ms":1777825074246,
 "snapshot_dir":"/tmp/run003/snap-100",
 "target_state_dir":"/tmp/run003/data-dir-1/state_vm_v0",
 "bytes_copied":8597,
 "snapshot_height":100,
 "snapshot_block_hash":"0000000000000064000000000000000000000000000000000000000000000000",
 "snapshot_chain_id":5855328520645203456,
 "snapshot_created_at_unix_ms":1777825067184}
```

This is the documented append-only JSON-line format from
`crates/qbind-node/src/snapshot_restore.rs:333–378`. All fields match
the §4.3 `meta.json` and the §6.1 `[restore]` log:

- `snapshot_chain_id` = `5855328520645203456` =
  `0x51424e4444455600` (DevNet);
- `snapshot_height` = `100`;
- `bytes_copied` = `8597` (matches the §6.1 log and the §4.2 source
  payload byte-count);
- `snapshot_block_hash` matches `meta.json` byte-for-byte.

The marker is operator-readable, grep-able, and survives shutdown — it
is the persistent receipt that this `<data_dir>` was booted from a
snapshot.

---

## 7. Post-Restore Startup Evidence

### 7.1 Captured startup log (Run 1 — exact, unedited, in observed order)

`stdout` (single line):

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=local-mesh p2p=disabled gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
```

`stderr`, in order of emission, post-restore (the `[restore]` block
from §6.1 precedes everything below):

```
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9100 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9100 (set via QBIND_METRICS_HTTP_ADDR)
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=1
[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick.
[binary] Consensus loop running. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms
[metrics_http] Listening on 127.0.0.1:9100
```

### 7.2 What this evidences

Observed (direct):

- The `[restore]` block runs **before** any startup banner or any
  metrics/consensus startup message — exactly the ordering documented
  in `crates/qbind-node/src/main.rs:109–139` ("the node validates and
  materializes the snapshot ... before the consensus loop is started").
- After the restore block, `log_startup_info` runs and emits the
  standard Run 001 / Run 002 startup banner, *byte-identical* to the
  Run 002 §4.5 banner. Restore did not perturb the startup path.
- `MetricsHttpConfig::from_env()` correctly read
  `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100` (the metrics-listen flow
  proven in Run 002 still applies).
- `run_binary_consensus_loop` was entered with
  `local_id=ValidatorId(0) num_validators=1 tick=100ms` — identical to
  Run 002 §5.1.

Comparison vs. Run 002:

- Identical post-`[restore]` stderr banners, identical ordering,
  identical stdout banner. Restore-from-snapshot does not change the
  binary's normal startup path; it only runs ahead of it.

Not observed (and acknowledged):

- The post-restore consensus engine starts at **view 0** of a fresh
  `BasicHotStuffEngine` instance. There is no in-binary code today
  that reads the restored `state_vm_v0` *into the consensus engine's
  initial view/height*. That is consistent with B3's documented
  scope: B3 restores VM-v0 account-state substate on disk; it does
  not (and the docs do not claim it does) seed the consensus engine
  from snapshot height. This is recorded in §11.

---

## 8. Post-Restore Consensus Progress Evidence

### 8.1 Run 1 final progression line (exact, unedited)

```
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80
```

This is the same loop-exit summary shape Run 001 §6 and Run 002 §6
captured. Post-restore, the binary advanced views 0→80, generated
80 proposals, committed 78 of them, and reached committed height 77 —
all in the 8-second bounded window, after the `[restore]` block had
run.

### 8.2 What this evidences

Observed (direct):

- The consensus loop did progress on the binary path **after**
  restore. There is no observable degradation in tick rate vs.
  Run 002 (which on this same hardware also reached the
  ticks ≈ proposals ≈ commits + few range in a comparable window).
- Single-validator self-quorum committing is unchanged — `[binary]
  Single-validator LocalMesh: leader self-quorum will commit a block
  per tick.` is still the design.
- The ratio `commits = ticks - 2` is consistent with the engine
  starting at view 0 and taking 2 ticks before the first commit
  pipeline-flushes (matches Run 002's 78/80).

Not observed (and acknowledged):

- The `committed_height=Some(77)` is the engine's *internal* committed
  height from boot — it is **not** offset by the restored snapshot
  `height=100`. This is consistent with §7.2: B3 does not seed
  consensus from snapshot height. This is the single most important
  thing this run does *not* claim and is recorded in §11.

---

## 9. Post-Restore Metrics Evidence

`/metrics` was scraped twice during Run 2, separated in wall-clock
time, with the binary in a single live restore-then-run. Exact
timestamps:

```
scrape A at 2026-05-03T16:18:26.532850321Z
scrape B at 2026-05-03T16:18:30.540887282Z
```

Both responses returned 317 lines of Prometheus exposition.

### 9.1 Consensus-class series — Scrape A vs. Scrape B (excerpt, exact)

Scrape A (early, ~0.2 s after listener became reachable):

```
qbind_consensus_view_changes_total 3
qbind_consensus_current_view 3
qbind_consensus_highest_seen_view 3
qbind_consensus_proposals_total{result="accepted"} 3
qbind_consensus_view_number 3
eezo_commit_latency_ms_count 1
```

Scrape B (late, ~4 s later):

```
qbind_consensus_view_changes_total 43
qbind_consensus_current_view 43
qbind_consensus_highest_seen_view 43
qbind_consensus_proposals_total{result="accepted"} 43
qbind_consensus_view_number 43
eezo_commit_latency_ms_count 41
```

### 9.2 What this evidences

Observed (direct):

- Five `qbind_consensus_*` series and one `eezo_commit_latency_ms_count`
  series strictly increased between Scrape A and Scrape B. Engine
  progress observed by Run 002 is preserved post-restore — the
  metrics-wiring fix in
  `crates/qbind-node/src/binary_consensus_loop.rs` continues to
  reflect live engine state from a node that started via the B3 path.
- The view delta (`43 - 3 = 40`) is consistent with the wall-clock gap
  (~4.0 s) and the documented `tick=100ms`.
- Post-shutdown, `curl http://127.0.0.1:9100/metrics` returns no
  response (`%{http_code}` `000` / connection refused) — i.e. the
  metrics listener actually goes away on shutdown, not just leaks.

Not observed (and acknowledged):

- `qbind_consensus_qcs_formed_total`,
  `qbind_consensus_votes_observed_total`, and
  `qbind_consensus_votes_total{result="accepted"}` all read `0` in
  both scrapes. This matches Run 002's observed behavior on the
  single-validator self-quorum path and is *not* a regression from
  B3. Recorded in §11.

---

## 10. Shutdown Evidence

### 10.1 Run 1 shutdown trail (exact, unedited)

```
[binary] Shutdown signal received, stopping consensus loop...
[binary-consensus] Shutdown signal received after 80 ticks.
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80
[binary] LocalMesh node stopped.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

The Run 2 shutdown trail is byte-identical (verified) and is not
duplicated here.

### 10.2 What this evidences

Observed (direct):

- The same SIGINT shutdown sequence Run 001 and Run 002 captured runs
  to completion after a B3 restore. No hang, no panic, no leftover
  process.
- Final terminal line is `[binary] Shutdown complete.` for both Run 1
  and Run 2, exactly as in Run 001 §9 and Run 002 §9.
- Post-shutdown inspection of `<data_dir>/state_vm_v0` shows the
  RocksDB lockfile is released (the §6.4 readback was performed
  *after* shutdown and succeeded). No corruption-on-shutdown signal.

---

## 11. Limitations and Anomalies Observed

This run is bounded. The following are the explicit, honest gaps —
they are not failures of the run and they are not blockers for the run
itself, but they must be recorded so the evidence is not overclaimed.

1. **Restore is VM-v0 substate only.** B3 (and therefore Run 003)
   only validates and materializes the `StateSnapshotter` format
   (`meta.json` + `state/`), which today only contains VM-v0 RocksDB
   account state. Other on-disk substores under `<data_dir>` —
   in particular `<data_dir>/consensus` (consensus storage), and any
   future slashing-ledger or governance substores — are **not**
   produced by `StateSnapshotter`, are **not** restored, and the
   binary does not pretend to. This is documented in
   `crates/qbind-node/src/snapshot_restore.rs:39–47` and is
   explicitly out of scope for B3/Run 003.

2. **Consensus engine is not seeded from snapshot height.** Post-
   restore, the engine starts at view 0 / height 0 and reaches
   `committed_height=Some(77)` from a fresh genesis state, **not**
   from the snapshot's `height=100`. The `state_vm_v0` directory is
   on disk and is observable via
   `RocksDbAccountState::open` (§6.4), but the consensus driver in
   `binary_consensus_loop.rs` does not read snapshot height into the
   engine's initial view/height in this version. This is consistent
   with B3's documented scope (it lands the **smallest honest**
   restore-from-snapshot startup path; it does not pretend to do
   "fast sync" on the consensus layer). Wiring snapshot height into
   the consensus engine's initial state is a future execution item;
   it would be the natural successor to B3, not a property of B3.

3. **Single-validator self-quorum metric pattern is unchanged.**
   `qbind_consensus_qcs_formed_total = 0`,
   `qbind_consensus_votes_observed_total = 0`,
   `qbind_consensus_votes_total{result="accepted"} = 0` in both
   §9 scrapes. This is the same pattern Run 002 observed and is
   inherent to the single-validator self-quorum path; it is **not**
   introduced by B3. Multi-validator vote/QC observability remains
   an EXE-2 multi-validator P2P interconnect concern and is out of
   scope.

4. **No multi-validator binary-path P2P restore evidence.** Run 003
   covers only the single-validator binary path. The residual C4
   sub-item — wiring inbound P2P consensus events into the engine
   driver from the binary path so that multi-node clusters can be
   driven via the binary — is **unchanged** by this run, and Run 003
   does not contribute evidence for it.

5. **No soak / no stability evidence beyond seconds.** Both Runs were
   bounded to 8 seconds. This run does not measure restore latency
   for large snapshots, restore + 72-hour soak, restore-then-second-
   restore, or any concurrency edge case.

6. **`bytes_copied` / size are tiny.** The snapshot is intentionally
   small (8 597 bytes of `state/` payload). This proves the
   restore mechanism works end-to-end but does not exercise large-
   file copy paths. Operator drills against realistic-size DevNet
   state are tracked separately under
   `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md`.

7. **One pre-existing compiler warning.** `unused variable:
   worker_id` in `crates/qbind-node/src/verify_pool.rs:262` is the
   same warning Run 001 and Run 002 captured. Not B3-related, not
   addressed here.

None of the above were unexpected. None of them undermine the
restore-validation, materialization, observability, or shutdown
evidence captured in §6–§10.

---

## 12. Assessment of Evidence Value

### 12.1 Direct answers to the required questions

| Question | Answer | Evidence section |
|---|---|---|
| A. Was a valid snapshot used? | **Yes** — canonical `StateSnapshotter` format (`meta.json` + `state/` RocksDB checkpoint), DevNet chain id `0x51424e4444455600`, height `100`. No new format was invented. | §4 |
| B. Did the binary accept and validate the restore input? | **Yes** — `[restore] requested → complete → marker written → OK`, with `expected_chain_id` derived from `config.chain_id().as_u64()`. A wrong-chain snapshot was refused with non-zero exit and no state materialized. | §6.1, §6.5 |
| C. Was restored state actually materialized into the expected target? | **Yes — proven byte-identical.** `<data_dir>/state_vm_v0` is `diff -r`-clean against the source `snap-100/state/`; per-file SHA-256 sets are equal. | §6.2, §6.3 |
| D. Did the node continue into normal startup after restore? | **Yes** — post-`[restore]` stderr banner sequence is byte-identical to Run 002 §4.5; `log_startup_info` emits the standard banner; metrics HTTP and consensus loop start in the same order as Run 002. | §7 |
| E. Did post-restore consensus progression occur? | **Yes** — `Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80` after an 8-second bounded run, comparable to Run 002 on the same hardware. | §8 |
| F. Did `/metrics` still work after restore? | **Yes** — two scrapes 4 seconds apart show strictly-increasing consensus-class series (`view`, `view_changes`, `proposals_accepted`, `eezo_commit_latency_ms_count`); listener goes away cleanly post-shutdown. | §9 |
| G. Did shutdown complete cleanly? | **Yes** — full `[binary-consensus] Shutdown signal received → Loop exit → LocalMesh node stopped → metrics HTTP Shutting down → Shutdown complete.` sequence, identical shape to Run 001/Run 002. The post-shutdown RocksDB readback in §6.4 also confirms the lockfile was released. | §10 |
| H. Does this materially strengthen DevNet recovery evidence? | **Yes — but bounded.** Run 003 is the first end-to-end binary-path artifact showing real `qbind-node` consuming a real snapshot, materializing it byte-identically, and continuing into a live consensus loop with `/metrics` reachable. It does **not** satisfy `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` and it does **not** seed consensus from snapshot height; it adds one concrete VM-v0 restore-then-observe data point to the recovery story. | §6 + §11 |
| I. What exact next execution action is recommended after Run 003? | **Wire snapshot height into the consensus engine's initial view/height on the binary path** (i.e. make a B3-restored boot start consensus *from* the restored height instead of from view 0), then re-run a Run-003-shaped exercise to capture that as evidence. This is the single highest-leverage next step in the restore story without broadening into multi-validator P2P or full backup-and-recovery. See §13. | §13 |

### 12.2 Summary verdict

**Verdict:** The single-validator binary-path restore-then-observe
exercise on the real `qbind-node` binary **passed** for the bounded
scope it sets out to cover. The B3 restore path is observable,
materially applied, byte-identical, validated against chain id,
audit-marked, and compatible with the existing post-startup behavior
(consensus loop progression and `/metrics` liveness from Run 002 are
preserved). One important honest caveat — that consensus does not
yet boot *from* the restored snapshot height — is recorded in §11.

This is bounded restore evidence. It is **not** recovery readiness,
**not** Beta readiness, **not** MainNet readiness, and **not** a
substitute for `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`.

---

## 13. Recommended Immediate Next Action

The single highest-leverage next execution action, after Run 003,
is:

> **Seed the consensus engine's initial view/height from the
> restored snapshot's `meta.json` on the binary path.**
>
> Concretely: after `apply_snapshot_restore_if_requested` returns
> `Ok(Some(outcome))`, thread `outcome.meta.height` (and any other
> restore-relevant initial state already producible from the
> existing T215 metadata) into `run_binary_consensus_loop` /
> `BasicHotStuffEngine` initialization, so that a B3-restored boot
> starts consensus *from* the restored height rather than from
> view 0. Re-run a Run-003-shaped exercise and capture
> `committed_height` post-restore advancing **above** the snapshot's
> `height`, not from zero.

This is bounded, sits squarely on the existing B3 surface, does not
broaden into multi-validator P2P, and would close the single most
honest caveat this run records in §11 #2.

The natural follow-up after that — but **only** after that — is to
return to the residual C4 sub-item (multi-validator P2P binary-path
interconnect routing inbound consensus events into the engine
driver from the binary path), which remains unchanged by Run 003
and is not the right next step yet.

---

*Run 003 ends here. Subsequent restore evidence, including any
consensus-engine seeding work described in §13, will be recorded in a
separate artifact (Run 004 or successor), not by amending this file.*