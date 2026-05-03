# QBIND DevNet Evidence Run 004

**Status:** Internal evidence record — fourth single-validator DevNet
binary-path run. Targets the specific capability landed by **B5**:
restore-aware consensus start
(`BasicHotStuffEngine::initialize_from_snapshot_baseline` +
`binary_consensus_loop::RestoreBaseline` +
`main.rs` `RestoreOutcome → RestoreBaseline` translation). Captures
honest end-to-end evidence on the actual `qbind-node` binary path that
post-restore committed height advances **above** the restored snapshot
height.
**Audience:** Internal — protocol engineering, ops, release management.
**Run date:** 2026-05-03 (UTC).
**Author:** Execution follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_003.md` §13 ("Seed the
consensus engine's initial view/height from the restored snapshot's
`meta.json` on the binary path"), now that B5 has landed in
`crates/qbind-consensus/src/basic_hotstuff_engine.rs`,
`crates/qbind-node/src/binary_consensus_loop.rs`, and
`crates/qbind-node/src/main.rs`.

> This document is a focused fourth evidence artifact. It is **not** a
> Beta-readiness statement, **not** a multi-validator demonstration,
> **not** a soak result, **not** a full backup-and-recovery program
> completion, and **not** a recovery-readiness sign-off. It exists to
> record, exactly, whether the real `qbind-node` binary on the actual
> binary path can take a real `StateSnapshotter`-format snapshot,
> validate it via B3, **apply the B5 restore-aware consensus baseline
> before the first tick**, and then drive the consensus loop so that
> `committed_height` actually advances **above** the restored snapshot
> height — and to record what this run does *not* prove.

---

## 1. Purpose and Scope

Run 003 captured the first end-to-end binary-path proof that B3
restore-from-snapshot is real (snapshot validated, materialized
byte-identically into `<data_dir>/state_vm_v0`, audit marker written,
consensus loop and `/metrics` healthy after restore, clean shutdown).
Run 003 §11 #2 recorded one important honest caveat:

> The post-restore consensus engine starts at view 0 / height 0 of a
> fresh `BasicHotStuffEngine` instance. There is no in-binary code
> today that reads the restored `state_vm_v0` *into the consensus
> engine's initial view/height*.

B5 lands the smallest honest fix for that caveat:

- `crates/qbind-consensus/src/basic_hotstuff_engine.rs:869–892`
  introduces `BasicHotStuffEngine::initialize_from_snapshot_baseline`
  (and its underlying `HotStuffStateEngine` counterpart) which seeds
  `committed_height = snapshot_height`, registers the snapshot anchor
  block in the local block tree at `height = snapshot_height`, and
  sets `current_view = snapshot_height + 1`.
- `crates/qbind-node/src/binary_consensus_loop.rs:112–123, 126–147,
  169–175, 230–262` introduces `RestoreBaseline { snapshot_height,
  snapshot_block_id }` and
  `BinaryConsensusLoopConfig::with_restore_baseline`, and applies the
  baseline **before the first tick** of the loop.
- `crates/qbind-node/src/main.rs:64, 73, 119–167, 208–212, 245–344`
  translates the existing B3 `RestoreOutcome` into a `RestoreBaseline`
  using only `StateSnapshotMeta::height` and
  `StateSnapshotMeta::block_hash` (no invented metadata) and threads
  it into both `run_local_mesh_node` and `run_p2p_node`.

Run 004's purpose, and only purpose, is to capture concrete
end-to-end binary-path evidence of whether B5 actually carries
through.

In scope (this run):

- A. Produce a real snapshot in the **existing** `StateSnapshotter`
  format (`meta.json` + `state/` RocksDB checkpoint), reusing the
  exact same Run 003 §4 production path. No second format is
  invented.
- B. Drive the real `qbind-node` binary with `--env devnet
  --validator-id 0 --data-dir <fresh path> --restore-from-snapshot
  <snapshot path>` and `QBIND_METRICS_HTTP_ADDR=...`.
- C. Capture the B3 `[restore]` log path unchanged from Run 003.
- D. Capture the **new B5 startup log lines** showing the restore
  baseline was actually applied to the engine before the first tick:
  `[binary] B5: restore-aware consensus start enabled ...` and
  `[binary-consensus] B5: applied restore baseline: snapshot_height=H
   starting_view=H+1 (engine committed_height=Some(H))`, and the
  `restore_baseline=true` field in the `Starting consensus loop`
  banner.
- E. Show the consensus loop progresses **above** the snapshot height
  on the binary path: the loop-exit summary
  `committed_height=Some(X)` must satisfy `X > snapshot_height` (not
  `Some(77)` as in Run 003).
- F. Show `/metrics` reflects the same post-baseline progression: the
  `qbind_consensus_view_number` / `current_view` counters scraped
  during the run must be in the `> snapshot_height` band, and must
  strictly increase between two scrapes separated in wall-clock time.
- G. Show clean SIGINT shutdown after a B5-restored run.
- H. Compare directly against the Run 003 caveat (§11 #2) to record
  whether it is now closed.

Explicitly out of scope (this run):

- Multi-validator binary-path DevNet (LocalMesh fan-in or P2P).
- Soak / 72-hour stability evidence.
- Restoring non–VM-v0 substate (consensus storage at
  `<data_dir>/consensus`, slashing ledger, governance state, …) —
  the existing `StateSnapshotter` format does not produce these and
  B5 does not pretend otherwise (Run 003 §11 #1 still applies).
- Any change to the multi-validator P2P→consensus binary-path
  interconnect, which remains the residual sub-item under
  `contradiction.md` C4.
- Operator drill-catalog instantiation, `/health` / `/ready`, RPC.
- Any claim of MainNet recovery readiness or full
  `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` completion. This
  artifact contributes one bounded piece of restore-aware-consensus
  evidence to that baseline; it does not satisfy it.

---

## 2. Canonical Basis

This run is grounded in, and bounded by:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_001.md` — established the
  binary-path startup/consensus/metrics/shutdown shape Run 004 reuses
  unchanged.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_002.md` — established that
  `/metrics` carries live consensus progress on the binary path.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_003.md` — established that
  B3 restore-from-snapshot is real on the binary path; recorded the
  "consensus engine is not seeded from snapshot height" caveat in
  §11 #2 that Run 004 directly targets.
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` (EXE-2) — §6.1, §7,
  §10 (next-action ordering).
- `docs/whitepaper/contradiction.md` C4 — already records that B5 has
  landed and that the residual sub-item is multi-validator P2P
  binary-path interconnect. Re-evaluated in §12.
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` — referenced
  indirectly to qualify *which* recovery evidence this run does and
  does not satisfy.
- `crates/qbind-consensus/src/basic_hotstuff_engine.rs:869–892`
  (`BasicHotStuffEngine::initialize_from_snapshot_baseline`).
- `crates/qbind-node/src/binary_consensus_loop.rs:112–123, 126–147,
  169–175, 230–262, 347–352` (`RestoreBaseline`,
  `with_restore_baseline`, baseline-applied log line, `Loop exit`
  summary).
- `crates/qbind-node/src/main.rs:64, 73, 119–167, 208–212, 245–344`
  (B5 wiring; `RestoreOutcome → RestoreBaseline` translation;
  `[binary] B5: ...` log line).
- `crates/qbind-node/src/snapshot_restore.rs` (B3 entry points
  `apply_snapshot_restore_if_requested` / `restore_from_snapshot`,
  reused unchanged).
- `crates/qbind-ledger/src/state_snapshot.rs` (existing snapshot
  creation + validation; reused unchanged from Run 003).
- `crates/qbind-node/tests/b5_restore_aware_consensus_start_tests.rs`
  (in-tree integration tests; Run 004 complements with end-to-end
  binary-path evidence).
- `crates/qbind-node/tests/b3_snapshot_restore_tests.rs` (Run 003
  basis; reused as the "restore observable post-restore" sanity.)

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch
  `copilot/execute-devnet-evidence-run-004`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`,
  `rustc 1.94.1 (e408947bf 2026-03-25)`.
- Build command (binary under test):
  `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome: `Finished `release` profile [optimized] target(s) in
  4m 47s` (warm-cache incremental rebuild from the Run 003 cache;
  changed surfaces rebuilt: `qbind-consensus` and `qbind-node`).
  The same single pre-existing compiler warning carried by Run 001 /
  Run 002 / Run 003 surfaced unchanged
  (`unused variable: worker_id` in
  `crates/qbind-node/src/verify_pool.rs:262`). Out of scope.
- Resulting binary: `target/release/qbind-node`, ≈ 8.4 MiB
  (8 837 760 bytes), executable, ELF 64-bit `x86-64`. Size delta
  vs. the Run 003 binary is +4 608 bytes, consistent with the small
  additional code in B5.
- Host: GitHub-hosted Linux x86_64 sandbox (single host, single
  process, no peers).
- Network: no `--enable-p2p`; default LocalMesh, single-validator
  (no `--p2p-peer`).

This is, exactly as in Runs 001/002/003, a **single-validator,
single-host, binary-path, LocalMesh, no-P2P, short-bounded run**, with
the same `--data-dir` + `--restore-from-snapshot` shape as Run 003.
The only meaningful change between Run 003 and Run 004 is the binary
itself (B5 in-tree, otherwise byte-for-byte the same invocation).

---

## 4. Snapshot Source and Baseline Used

The snapshot was produced by the **canonical** `StateSnapshotter`
format already in the repo
(`crates/qbind-ledger/src/state_snapshot.rs`). This is the same
format Run 003 used. No second format is invented.

### 4.1 How the snapshot was produced

The same one-off helper Run 003 §4.1 used (kept under
`/tmp/run004/snapgen`, not committed) was rebuilt against the local
`qbind-ledger` crate. It does exactly what
`crates/qbind-node/tests/b3_snapshot_restore_tests.rs::build_real_snapshot`
does, but at a **deliberately nontrivial height** so that "progress
above H" is unambiguous and visibly distinct from any small-integer
internal counter the engine could produce from genesis:

1. Open a fresh `RocksDbAccountState` in a scratch directory.
2. Write two well-known account states:
   - account `A` = `[0xA1; 32]` → `AccountState::new(nonce=7,
     balance=4242)`
   - account `B` = `[0xB2; 32]` → `AccountState::new(nonce=11,
     balance=999_999)`
3. `flush()` the state.
4. Build a `StateSnapshotMeta` for **`height = 1000`** with
   `chain_id = 0x51424e4444455600` (DevNet) and
   `block_hash = [0x00; 32]` with the height encoded in the leading
   8 bytes (the same convention `b3_snapshot_restore_tests.rs` uses
   in `build_real_snapshot`).
5. Call `RocksDbAccountState::create_snapshot(&meta, &out_dir)`.

A snapshot height of `1 000` was chosen deliberately:

- It is far above any small-integer `committed_height` value
  `BasicHotStuffEngine` could produce in an 8-second bounded run from
  genesis (Run 003 reached `committed_height=Some(77)`). The order
  of magnitude alone makes the proof "progressed above the snapshot"
  visually unmistakable.
- It is small enough that a single-validator self-quorum loop running
  at `tick=100ms` will *not* incidentally reach `1 000` from genesis
  inside any 8-second window — i.e. there is no plausible "the loop
  would have got there anyway" confound.

### 4.2 Resulting on-disk layout (observed)

```
/tmp/run004/snap-1000/
├── meta.json              178 bytes
└── state/
    ├── 000009.sst         1080 bytes
    ├── CURRENT              16 bytes
    ├── MANIFEST-000005     250 bytes
    └── OPTIONS-000007     7251 bytes
```

Total snapshot payload (including `meta.json`): 8 775 bytes on disk;
`state/` payload alone: 8 597 bytes (matches the `bytes_copied=8597`
the binary later reports; see §6).

### 4.3 `meta.json` (exact, unedited)

```
{
  "height": 1000,
  "block_hash": "00000000000003e8000000000000000000000000000000000000000000000000",
  "created_at_unix_ms": 1777825614921,
  "chain_id": 5855328520645203456
}
```

`5855328520645203456` (decimal) = `0x51424e4444455600` (hex), the
DevNet chain id `qbind-node` logs in its startup banner. The leading
`00000000000003e8` = `1000` decimal, which is the convention used by
`build_real_snapshot` and which `StateSnapshotMeta::block_hash`
carries through into `RestoreOutcome::meta.block_hash` → the
`RestoreBaseline::snapshot_block_id` the engine seeds the block tree
with (`crates/qbind-node/src/main.rs:155–159`).

### 4.4 Derived restore-aware consensus baseline

Per `crates/qbind-node/src/main.rs:155–167`, the `RestoreOutcome` from
B3 is translated into:

```
RestoreBaseline {
    snapshot_height:    o.meta.height,         // = 1000
    snapshot_block_id:  o.meta.block_hash,     // = 0x...03e8000...000
}
```

and the binary logs:

```
[binary] B5: restore-aware consensus start enabled (snapshot_height=1000, starting_view=1001)
```

This is the baseline that should be observable in §7 and §8.

### 4.5 What this snapshot represents and what it does not

- VM-v0 RocksDB account state only. Run 003 §11 #1 still applies in
  full. B5 does not extend the **restore surface**; it extends what
  the binary does **with** the restore on the consensus side.

---

## 5. Commands and Configuration Used

### 5.1 Build (binary under test)

```
cargo build --release -p qbind-node --bin qbind-node
```

### 5.2 Run command (canonical Run 003 §5.2 shape, unchanged)

```
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node \
    --env devnet \
    --validator-id 0 \
    --data-dir <fresh path> \
    --restore-from-snapshot /tmp/run004/snap-1000
```

This is byte-for-byte the same flag shape as Run 003 §5.2 (only the
snapshot directory and the `--data-dir` paths change between runs).
This is deliberate, so any new behavior here is attributable only to
B5 (and not to a configuration drift).

### 5.3 Bounded-run wrappers used for evidence capture

Same wrapper shape as Run 003 §5.3: `timeout --foreground -s INT
<seconds>` was used to deliver SIGINT after a fixed wall-clock
window, identical to a human operator's `Ctrl+C`. **No code path
in `qbind-node` was modified for this run.**

Two short bounded runs were executed:

- **Run 1** (8-second bound, fresh `--data-dir`): full restore →
  B5 baseline application → progression → shutdown capture.
  Evidence in §6, §7, §8.1, §10.1.
- **Run 2** (8-second bound, fresh `--data-dir`): same shape as
  Run 1, but with `/metrics` scraped twice during the live run
  (**Scrape A** ~0.2 s after the listener became reachable;
  **Scrape B** ~4 s later). Evidence in §9.

A negative-validation run was not repeated here — Run 003 §6.5 already
captured "wrong chain id → non-zero exit, nothing materialized" on
the same binary surface, and B5 does not change the validation path.

### 5.4 Environment variables

Only one environment variable was set, identical to Runs 001/002/003:

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
[restore] requested: snapshot_dir=/tmp/run004/snap-1000 data_dir=/tmp/run004/data-dir-1 expected_chain_id=0x51424e4444455600
[restore] complete: height=1000 chain_id=0x51424e4444455600 bytes_copied=8597 target=/tmp/run004/data-dir-1/state_vm_v0
[restore] audit marker written to /tmp/run004/data-dir-1/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=1000 chain_id=0x51424e4444455600
```

Observed (direct):

- `expected_chain_id=0x51424e4444455600` (DevNet, derived from
  `config.chain_id().as_u64()`) — same as Run 003 §6.1.
- `height=1000` — matches §4.3 `meta.json`.
- `bytes_copied=8597` matches the byte-count of the source
  `snap-1000/state/` payload from §4.2 exactly, identical to Run 003
  (the snapshot payload is the same RocksDB checkpoint contents at
  a different metadata height).
- The `[restore] complete` line is emitted only after
  `validate_snapshot_dir` returns
  `SnapshotValidationResult::Valid(meta)` *and* `copy_dir_recursive`
  has finished copying the checkpoint. Same control flow as Run 003.

### 6.2 Materialized target — observed `<data_dir>` tree

```
/tmp/run004/data-dir-1/
├── RESTORED_FROM_SNAPSHOT.json       347 bytes
└── state_vm_v0/
    ├── 000009.sst                   1080 bytes
    ├── CURRENT                        16 bytes
    ├── MANIFEST-000005               250 bytes
    └── OPTIONS-000007               7251 bytes
```

`diff -r` against the source `snap-1000/state/`:

```
$ diff -r /tmp/run004/snap-1000/state /tmp/run004/data-dir-1/state_vm_v0
(no output — directories are byte-identical)
```

Same B3 invariant Run 003 §6.3 captured: the binary materialized the
snapshot file-for-file, byte-for-byte. B5 did not perturb the
materialization path.

### 6.3 Audit marker (`RESTORED_FROM_SNAPSHOT.json`) — exact contents

From Run 1, exact, unedited (single line; reflowed only here for
readability):

```
{"restored_at_unix_ms":1777825622188,
 "snapshot_dir":"/tmp/run004/snap-1000",
 "target_state_dir":"/tmp/run004/data-dir-1/state_vm_v0",
 "bytes_copied":8597,
 "snapshot_height":1000,
 "snapshot_block_hash":"00000000000003e8000000000000000000000000000000000000000000000000",
 "snapshot_chain_id":5855328520645203456,
 "snapshot_created_at_unix_ms":1777825614921}
```

`snapshot_height=1000` is the value B5 will translate into the
`RestoreBaseline.snapshot_height` consumed by
`run_binary_consensus_loop` — i.e. the audit marker, the
`[restore]` log, the `[binary] B5: ...` log, and the
`[binary-consensus] B5: ...` log all carry the same `1000`. This
cross-log consistency is the cheapest available proof that the same
metadata is flowing through every layer, not getting silently
dropped.

---

## 7. Restore-Aware Consensus Baseline Evidence

### 7.1 Captured startup log (Run 1 — exact, unedited, in observed order)

`stderr`, in order of emission, post-`[restore]` block (which is
identical to §6.1 and is not duplicated here):

```
[binary] B5: restore-aware consensus start enabled (snapshot_height=1000, starting_view=1001)
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9100 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9100 (set via QBIND_METRICS_HTTP_ADDR)
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=1 restore_baseline=true
[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick.
[binary] Consensus loop running. Press Ctrl+C to exit.
[binary-consensus] B5: applied restore baseline: snapshot_height=1000 starting_view=1001 (engine committed_height=Some(1000))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms restore_baseline=true
[metrics_http] Listening on 127.0.0.1:9100
```

`stdout` (single line, byte-identical to Run 003 §7.1 — restore-aware
consensus start does not perturb the startup banner):

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=local-mesh p2p=disabled gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
```

### 7.2 What this evidences (load-bearing)

Observed (direct):

- The new `[binary] B5: restore-aware consensus start enabled
  (snapshot_height=1000, starting_view=1001)` line was emitted
  exactly once, between `[restore] OK ...` and the consensus loop
  start. This is the `main.rs:160–167` log line, gated on
  `restore_baseline.is_some()`. Direct evidence that `main.rs`
  observed `Ok(Some(outcome))` from
  `apply_snapshot_restore_if_requested` and translated it into a
  `RestoreBaseline` (per `main.rs:155–159`).
- The `[binary] Consensus loop config: ... restore_baseline=true`
  banner (per `main.rs:267–272`) confirms the baseline was actually
  threaded through to `BinaryConsensusLoopConfig` — not just logged
  and dropped.
- The new `[binary-consensus] B5: applied restore baseline:
  snapshot_height=1000 starting_view=1001 (engine
  committed_height=Some(1000))` line is the
  `binary_consensus_loop.rs:246–252` log line, emitted **after**
  `engine.initialize_from_snapshot_baseline(...)` returned
  (`binary_consensus_loop.rs:241–245`). Two facts are recorded
  there *by the engine itself, not by us*:
  - `engine.committed_height()` reads back `Some(1000)`. This is
    direct evidence that
    `HotStuffStateEngine::initialize_from_snapshot_baseline` seeded
    `committed_height = snapshot_height = 1000`.
  - `engine.current_view()` reads back `1001`. This is direct
    evidence that `BasicHotStuffEngine::initialize_from_snapshot_baseline`
    set `current_view = snapshot_height + 1 = 1001`
    (`basic_hotstuff_engine.rs:887`).
- The next `[binary-consensus] Starting consensus loop: ...
  restore_baseline=true` banner
  (`binary_consensus_loop.rs:255–262`) confirms the loop is
  *aware* the baseline is configured at the moment it begins
  ticking. Combined with the prior line, the baseline is provably
  applied **before the first tick fires**.

Inferred (with reasoning):

- Because both engine readbacks (`committed_height=Some(1000)`,
  `current_view=1001`) come from the engine's own getter API
  (`current_view()` at `basic_hotstuff_engine.rs:515`,
  `committed_height()` at `:752`) inside the same binary process,
  they cannot be a logging artifact: they would have to lie about
  the engine's actual internal state, which the engine subsequently
  uses to drive proposals. The post-tick observations in §8 and
  §9 then independently confirm the engine *did* in fact start
  ticking from these values — i.e. the seeded state was real,
  not just logged.

Comparison vs. Run 003 §7.1:

- Run 003 had no `[binary] B5: ...` line, no `restore_baseline=true`
  in the consensus loop config banner, and no
  `[binary-consensus] B5: applied restore baseline: ...` line.
- Run 003 §11 #2 explicitly recorded that the engine started at
  view 0 / no committed prefix despite the snapshot. Run 004 shows
  the engine starting at `current_view=1001` with
  `committed_height=Some(1000)`. **This is the qualitative change
  Run 004 is here to evidence.**

---

## 8. Post-Restore Consensus Progress Evidence

### 8.1 Run 1 final progression line (exact, unedited)

```
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(1078) view=1080
```

This is the same `Loop exit` summary shape Runs 001 / 002 / 003
captured (`binary_consensus_loop.rs:347–352`), with the post-restore
absolute-height numbers Run 004 cares about.

### 8.2 What this evidences (load-bearing)

Observed (direct):

- `committed_height=Some(1078)` is **strictly greater than the
  restored snapshot height (`1000`)**: `1078 > 1000`, with a delta
  of `+78`. This is the direct numeric proof Run 004 was set up to
  capture.
- `view=1080` is **strictly greater than `snapshot_height + 1 =
  1001`** (the seeded starting view): `1080 > 1001`, with a delta
  of `+79`. The engine advanced views from `1001 → 1080` in the
  8-second bounded window — i.e. the seeded `current_view` was
  really used as the starting point, not "logged then ignored".
- The internal pipeline shape is identical to the no-restore case
  shape Runs 001/002/003 captured: `proposals = ticks` (one
  proposal per tick) and `commits = ticks - 2` (two-tick pipeline
  warm-up before the locking-rule prefix is satisfied). Here
  `commits = 78 = 80 - 2`. This means the engine is doing the
  same self-quorum self-vote / form-QC / commit-on-3-chain pipeline
  on top of the seeded baseline that it does on top of genesis —
  which is exactly the design intent of B5: extend the prefix, do
  not change the loop logic.

Comparison vs. Run 003 §8.1:

- Run 003 (no B5): `committed_height=Some(77) view=80` — both well
  *below* the snapshot height (1000), indistinguishable from a
  fresh-genesis run. This is what §11 #2 of Run 003 flagged as the
  load-bearing caveat.
- Run 004 (with B5): `committed_height=Some(1078) view=1080` —
  both **above** the snapshot height (1000) by a margin (`+78` /
  `+79`) that is consistent with the same per-tick advance Run 003
  exhibited (`+77` / `+80`). The shape of the per-tick advance is
  preserved; only the absolute floor moved from `0` to
  `snapshot_height = 1000`.

This is the concrete proof that B5's effect on the binary path is
exactly the documented one: post-restore consensus extends the
restored prefix rather than restarting from zero.

Inferred (with reasoning):

- Because Run 004 ran on the same single-host hardware as Run 003,
  with the same `tick=100ms` and the same 8-second bound, the per-
  tick advance is expected to be substantially identical. It is
  (`80 ticks` in both runs). This rules out the alternative
  hypothesis "B5 is logged but the loop silently restarted at view
  0" — under that hypothesis we would have seen a Run-003-shaped
  `committed_height=Some(77)` *despite* the §7 logs claiming
  baseline application.

### 8.3 What this run does **not** claim about post-restore progression

- It does not claim correctness of multi-validator restore
  semantics. Single-validator self-quorum is the only mode under
  test (Run 003 §11 #4 still applies).
- It does not claim recovery of consensus storage (`<data_dir>/
  consensus`) or any non–VM-v0 substate (Run 003 §11 #1 still
  applies).
- It does not claim large-snapshot or long-soak behavior.

---

## 9. Post-Restore Metrics Evidence

`/metrics` was scraped twice during Run 2, separated in wall-clock
time, with the binary in a single live B5-restored run. Exact
timestamps:

```
scrape A at 2026-05-03T17:24:18.741320144Z
scrape B at 2026-05-03T17:24:22.748906511Z
```

Both responses returned 317 lines of Prometheus exposition (same
317-line shape Run 003 §9 reported).

### 9.1 Consensus-class series — Scrape A vs. Scrape B (excerpt, exact)

Scrape A (early, ~0.2 s after listener became reachable):

```
qbind_consensus_view_changes_total 3
qbind_consensus_current_view 1003
qbind_consensus_highest_seen_view 1003
qbind_consensus_proposals_total{result="accepted"} 3
qbind_consensus_view_number 1003
eezo_commit_latency_ms_count 1
```

Scrape B (late, ~4 s later):

```
qbind_consensus_view_changes_total 43
qbind_consensus_current_view 1043
qbind_consensus_highest_seen_view 1043
qbind_consensus_proposals_total{result="accepted"} 43
qbind_consensus_view_number 1043
eezo_commit_latency_ms_count 41
```

### 9.2 What this evidences (load-bearing)

Observed (direct):

- `qbind_consensus_current_view`, `qbind_consensus_highest_seen_view`
  and `qbind_consensus_view_number` are **all `>= 1003` in Scrape A
  and `>= 1043` in Scrape B** — i.e. all three view-position metrics
  are above the snapshot height (`1000`) and above the seeded
  starting view (`1001`) at the very first scrape. This is
  /metrics' independent corroboration of the §7 engine readback
  (`current_view=1001` after baseline application, before the first
  tick) and the §8 loop-exit (`view=1080` after 80 ticks).
- All five `qbind_consensus_*` series and `eezo_commit_latency_ms_count`
  strictly increased between Scrape A and Scrape B (deltas: view
  +40, view_changes +40, accepted_proposals +40, commit_latency_count
  +40). The view delta is consistent with the wall-clock gap
  (~4.0 s) and the documented `tick=100ms`, identical *shape* to
  Run 003 §9.1 (`+40` view-changes in `~4 s`); only the absolute
  floor differs (`+1000` vs Run 003).
- `qbind_consensus_view_changes_total` reads `3` in Scrape A and
  `43` in Scrape B (i.e. it counts view changes **since the engine
  started ticking**, not since absolute view 0). This is the
  documented Run 002 / Run 003 counter shape and is unchanged by
  B5. Run 004 does **not** double-count the seeded starting view as
  a view-change, which matches the engine's intent.
- Post-shutdown, `curl http://127.0.0.1:9100/metrics` returns no
  response (`%{http_code}` `000` / connection refused) — the metrics
  listener actually goes away on shutdown, identical to Run 003 §9.

Inferred (with reasoning):

- The fact that `qbind_consensus_current_view` reads `1003` at the
  first scrape is direct, independent evidence that the engine's
  `current_view` field really is `> 1000` at that moment. The
  metric is sourced from the same engine state via the
  `binary_consensus_loop` metrics-wiring fix proven in Run 002, so
  no fresh metric-source change is involved here. This is the
  `/metrics`-side corroboration the task asks for.

Not observed (and acknowledged):

- `qbind_consensus_qcs_formed_total`,
  `qbind_consensus_votes_observed_total`, and
  `qbind_consensus_votes_total{result="accepted"}` all read `0` in
  both scrapes. This is the same single-validator self-quorum
  pattern Run 002 / Run 003 observed and is **not** introduced by
  B5. Recorded in §11.

---

## 10. Shutdown Evidence

### 10.1 Run 1 shutdown trail (exact, unedited)

```
[binary] Shutdown signal received, stopping consensus loop...
[binary-consensus] Shutdown signal received after 80 ticks.
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(1078) view=1080
[binary] LocalMesh node stopped.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

The Run 2 shutdown trail is byte-identical (verified) and is not
duplicated here.

### 10.2 What this evidences

Observed (direct):

- The same SIGINT shutdown sequence Runs 001/002/003 captured runs
  to completion after a B5 restore-aware boot. No hang, no panic,
  no leftover process.
- Final terminal line is `[binary] Shutdown complete.` for both
  Run 1 and Run 2, exactly as in Run 003 §10.
- Post-shutdown inspection of `<data_dir>/state_vm_v0` shows the
  RocksDB lockfile is released. No corruption-on-shutdown signal.

B5 did not perturb the shutdown path.

---

## 11. Limitations and Anomalies Observed

This run is bounded. The following are the explicit, honest gaps —
they are not failures of the run itself, but they must be recorded
so the evidence is not overclaimed.

1. **Restore is still VM-v0 substate only.** B3 (and therefore the
   B5 baseline B5 derives from B3's `RestoreOutcome`) only validates
   and materializes the `StateSnapshotter` format
   (`meta.json` + `state/`), which today only contains VM-v0 RocksDB
   account state. Other on-disk substores under `<data_dir>` —
   `<data_dir>/consensus`, slashing-ledger, governance — are **not**
   produced by `StateSnapshotter`, are **not** restored, and the
   binary does not pretend to. Run 003 §11 #1 still applies in
   full; B5 narrows the consensus-side caveat (Run 003 §11 #2) but
   does not widen the restore *surface*.

2. **The engine's seeded `committed_height=Some(snapshot_height)` is
   a single-validator-safe baseline, not a recovered QC chain.**
   Per `basic_hotstuff_engine.rs:858–865` the snapshot anchor block
   is registered with no `own_qc`, which is deliberate (it prevents
   the 3-chain commit rule from re-firing on the baseline). A
   consequence: the post-restore engine has no validated
   pre-snapshot QC chain locally; multi-validator chain catchup
   above the snapshot prefix is **not** solved by B5 and is out of
   scope of Run 004.

3. **Single-validator self-quorum metric pattern is unchanged.**
   `qbind_consensus_qcs_formed_total = 0`,
   `qbind_consensus_votes_observed_total = 0`,
   `qbind_consensus_votes_total{result="accepted"} = 0` in both
   §9 scrapes. This is the same pattern Runs 002/003 observed and
   is inherent to the single-validator self-quorum path; it is
   **not** introduced by B5.

4. **No multi-validator binary-path P2P restore evidence.** Run 004
   covers only the single-validator binary path. The residual C4
   sub-item — wiring inbound P2P consensus events into the engine
   driver from the binary path so that multi-node clusters can be
   driven via the binary — is **unchanged** by this run, and Run 004
   does not contribute evidence for it.

5. **No soak / no stability evidence beyond seconds.** Both Runs
   were bounded to 8 seconds. Run 004 does not measure restore
   latency for large snapshots, restore + 72-hour soak, restore-
   then-second-restore, or any concurrency edge case.

6. **Snapshot payload is intentionally tiny.** The snapshot is
   `8 597` bytes of `state/` payload — same as Run 003. Run 004
   exercises the *consensus*-side B5 baseline application; it does
   not exercise large-file restore I/O.

7. **One pre-existing compiler warning.** `unused variable:
   worker_id` in `crates/qbind-node/src/verify_pool.rs:262`
   continues to surface, identical to Runs 001/002/003. Not B5-
   related, not addressed here.

None of the above were unexpected. None of them undermine the
restore-validation, baseline-application, post-restore-progression,
metrics, or shutdown evidence captured in §6–§10.

---

## 12. Assessment of Evidence Value

### 12.1 Direct answers to the required questions

| Question | Answer | Evidence section |
|---|---|---|
| A. Was a valid snapshot used? | **Yes** — canonical `StateSnapshotter` format (`meta.json` + `state/` RocksDB checkpoint), DevNet chain id `0x51424e4444455600`, height **`1000`** (deliberately nontrivial). No new format invented. | §4 |
| B. Was the restore-aware baseline actually applied? | **Yes — by the engine itself, before the first tick.** `[binary-consensus] B5: applied restore baseline: snapshot_height=1000 starting_view=1001 (engine committed_height=Some(1000))` is the engine's own readback (`engine.current_view()` / `engine.committed_height()`) immediately after `engine.initialize_from_snapshot_baseline(...)`. The `[binary] Consensus loop config: ... restore_baseline=true` and `[binary-consensus] Starting consensus loop: ... restore_baseline=true` banners independently confirm the baseline was threaded through `BinaryConsensusLoopConfig::with_restore_baseline`. | §7 |
| C. Did consensus after restore start from the restored baseline rather than from zero? | **Yes — directly observed.** Engine `current_view=1001`, `committed_height=Some(1000)` *before* the first tick (§7); the ticking loop then advanced from those values, not from zero. Compare directly against Run 003 §11 #2's "engine starts at view 0 / height 0". | §7, §8 |
| D. Did committed height progress above snapshot height? | **Yes — by `+78`.** `Loop exit: ... committed_height=Some(1078) view=1080`, against `snapshot_height=1000`. The `+78` per-8-second-window advance is consistent with Run 003's `+77` advance from genesis on the same hardware, i.e. the engine's per-tick rate is preserved. | §8 |
| E. Did `/metrics` still work and reflect that progress? | **Yes.** `qbind_consensus_current_view` = `1003` at Scrape A (already above snapshot height), `1043` at Scrape B, with strictly-increasing `view_changes_total`, `proposals_accepted`, `view_number`, `highest_seen_view`, and `eezo_commit_latency_ms_count` between the two scrapes. The metrics listener also goes away cleanly post-shutdown. | §9 |
| F. Did shutdown complete cleanly? | **Yes.** Full `[binary] Shutdown signal received → [binary-consensus] Shutdown signal received → Loop exit → LocalMesh node stopped → metrics_http Shutting down → Shutdown complete.` sequence, byte-identical shape to Run 003 §10. | §10 |
| G. Does this materially strengthen and narrow the restore side of C4? | **Yes — for the *consensus-side* sub-issue.** Run 004 closes the load-bearing Run 003 §11 #2 caveat (engine no longer starts effectively from zero after restore). The remaining residual sub-items of C4 are unchanged: multi-validator P2P binary-path interconnect, and broader out-of-scope restore surfaces (non-VM-v0 substate, full backup-and-recovery baseline). The C4 row in `contradiction.md` already records this state correctly (the row was last updated when B5 landed); Run 004 supplies the empirical confirmation, not a narrowing the row does not already reflect. See §12.3. | §6–§10 + §11 |
| H. What exact next execution action is recommended after Run 004? | **Wire inbound P2P consensus events from the binary path into the engine's `on_proposal_event` / `on_vote_event` so that a multi-validator binary-path cluster can be driven via the binary** (the residual C4 sub-item). This is the single highest-leverage next step now that the restore side has empirical end-to-end evidence. See §13. | §13 |

### 12.2 Summary verdict

**Verdict:** The single-validator binary-path restore-aware
consensus-start exercise on the real `qbind-node` binary **passed**
for the bounded scope it sets out to cover. B5 is observable on the
binary path, applied by the engine itself before the first tick,
correctly seeds `committed_height` to the snapshot height and
`current_view` to `snapshot_height + 1`, and the consensus loop
then advances strictly above the snapshot height — empirically
confirmed by both the loop-exit summary (`committed_height=
Some(1078)` vs `snapshot_height=1000`) and `/metrics` (`current_view`
= `1003` → `1043` across two scrapes 4 s apart). Shutdown remains
clean. The post-restore progress shape on top of the seeded baseline
matches the no-restore progress shape from Run 003, ruling out the
"baseline logged but ignored" alternative.

This run **materially closes the load-bearing caveat recorded in
Run 003 §11 #2**: post-restore consensus on the binary path no
longer starts effectively from zero. The remaining open items under
C4 are the multi-validator P2P binary-path interconnect (unchanged)
and broader out-of-scope restore surfaces (unchanged).

This is bounded restore-aware-consensus-start evidence. It is
**not** recovery readiness, **not** Beta readiness, **not** MainNet
readiness, and **not** a substitute for
`docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`.

### 12.3 Decision on `contradiction.md`

`docs/whitepaper/contradiction.md` is **not updated** by Run 004.
Justification:

- The C4 row's `Status`, `Code Location`, `Description`, `Impact`,
  `Remaining`, and `Tracking` cells were already updated when B5
  landed and already record:
  - that B5 has landed with the precise `RestoreOutcome →
    RestoreBaseline → initialize_from_snapshot_baseline` chain,
  - that `committed_height = snapshot_height` and
    `current_view = snapshot_height + 1` after baseline application,
  - that the residual sub-item is the multi-validator P2P binary-
    path interconnect.
- Run 004 supplies the empirical end-to-end confirmation that the
  *coded* B5 behavior actually occurs on the real binary path. It
  does **not** reveal a new contradiction. It does **not** narrow
  C4 beyond what the C4 row already records (the row was already
  conservative about scope).
- The task explicitly says: "Only update contradiction.md if Run 004
  reveals a new genuine contradiction, or C4 must now be materially
  narrowed/sharpened based on actual evidence." Neither condition
  is met.

If a future run (e.g. multi-validator P2P binary-path interconnect
landing) materially narrows C4 further, *that* run's evidence record
should be the one to update `contradiction.md` — not this one.

---

## 13. Recommended Immediate Next Action

The single highest-leverage next execution action, after Run 004,
is:

> **Wire inbound P2P consensus events from the binary path into the
> engine's `on_proposal_event` / `on_vote_event`.**
>
> Concretely: in `run_p2p_node`
> (`crates/qbind-node/src/main.rs:307–344`), connect the existing
> `P2pConsensusNetwork` inbound stream into the
> `BasicHotStuffEngine` driver inside `binary_consensus_loop`, so
> that a multi-node cluster invoked entirely via `qbind-node`
> processes (with `--enable-p2p` and `--p2p-peer ...`) can drive
> real cross-node proposals → votes → QCs → commits **without** the
> existing `NodeHotstuffHarness`-style integration test scaffolding.
> This is the residual sub-item of C4 explicitly called out in the
> contradiction.md `Remaining` cell.

This is bounded, sits squarely on the existing B1 / B2 / B3 / B5
surface, does not broaden into multi-validator restore semantics or
full backup-and-recovery, and would close the last documented C4
sub-item. The natural follow-up after that — but **only** after that
— is a Run-004-shaped exercise extended to a multi-validator
binary-path cluster, capturing post-restore committed-height
progression *across multiple binary processes*. That would be the
right time to revisit `contradiction.md` C4.

---

*Run 004 ends here. Subsequent restore-aware and multi-validator
binary-path evidence will be recorded in a separately numbered
DevNet evidence run.*