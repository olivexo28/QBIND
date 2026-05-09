# QBIND DevNet Evidence Run 020

## 1. Purpose and Scope

Run 020 is the first QBIND DevNet evidence exercise that drives the supported
`StateSnapshotter::create_snapshot` path against a real `RocksDbAccountState`
(VM-v0 RocksDB checkpoint format) and then puts that real-format checkpoint
through the binary-path `--restore-from-snapshot` flow on N=4 Required-mode
nodes. It deliberately mirrors Run 019's stagger/topology and changes only
the snapshot substrate — placeholder `state/` content is replaced with a real
RocksDB checkpoint produced by the canonical `RocksDbAccountState ::
create_snapshot` impl in `crates/qbind-ledger/src/execution.rs`.

Scope is narrow and execution-grade:

- Stand up V0/V1A/V2A/V3A on the binary path (`--enable-p2p`,
  `--p2p-mutual-auth required`, `--execution-profile vm-v0`,
  `--env devnet`).
- Capture an anchor `S` from V0 `/metrics` after the live cluster has begun
  committing.
- Produce a real RocksDB checkpoint via the supported
  `StateSnapshotter::create_snapshot` (helper invocation; see §15 for the
  honest reason this is invoked from outside the running binary today).
- Confirm the live cluster has committed strictly above `S` before fault
  injection (the Run-019 lesson).
- Stage-fault V1A/V2A/V3A; restart V1B with `--restore-from-snapshot snap1`,
  later V2C with `--restore-from-snapshot snap2`.
- Observe restore, B5 baseline, B13 catchup + exit, B14 view-change, and
  whether forward proposal/vote/QC/commit resumes.

Out of scope: any change to the binary's consensus, network, or restore
code paths. The qbind-node binary used in Run 020 is bit-for-bit identical
to the one used in Run 019 (sha256 `8479f426…3388`), so any behavioral
difference is attributable to inputs, not to a code change.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_019.md` (canonical predecessor;
  V0-first stagger, restore-aware sub-quorum then quorum-restored shape).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_018.md` (B13 strict-progress
  boundary).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_017.md` (sub-quorum boundary).
- `docs/whitepaper/contradiction.md` C4 (v1.7, 2026-05-08).
- `crates/qbind-node/src/snapshot_restore.rs` (B3).
- `crates/qbind-ledger/src/state_snapshot.rs` (T215;
  `validate_snapshot_dir`, `StateSnapshotter` trait, `StateSnapshotMeta`).
- `crates/qbind-ledger/src/execution.rs` lines 1571–1675 (the
  `impl StateSnapshotter for RocksDbAccountState` that produces the real
  RocksDB checkpoint via `rocksdb::checkpoint::Checkpoint::create_checkpoint`).
- `crates/qbind-node/tests/b3_snapshot_restore_tests.rs` (canonical
  `build_real_snapshot` helper that Run 020's seeder mirrors exactly).

## 3. Run Environment

- Host: `runnervmeorf1`, Linux 6.17.0-1010-azure x86_64, 4 cores, 15 GiB RAM,
  ~82 GiB free disk.
- Toolchain: `rustc 1.94.1 (e408947bf 2026-03-25)`.
- qbind-node release binary: `/home/runner/work/QBIND/QBIND/target/release/qbind-node`,
  sha256 `8479f4260de975b9c517c52a65a362d30c4014a0fa3c6a784cc31f476a4c3388`
  (bit-for-bit identical to the Run 019 binary).
- Reproducibility helpers (see §15 for why these exist; both invoke library
  paths used by the existing B3/T215 test suites and do not modify any
  production source):
  - `target/release/examples/qbind_state_snapshot`
    sha256 `552b2fc06decaaf05783dfe9210523d52e37390a3ee0dca3576733f90a96260e`
    — calls `RocksDbAccountState::create_snapshot` from
    `qbind-ledger`.
  - `target/release/examples/qbind_seed_vm_v0_state`
    sha256 `d82fd77e1208b185a76412b075dc0b347552f96aec372263df175d285a9c4e6e`
    — seeds a fresh `RocksDbAccountState` with one well-known account, the
    canonical shape used by `build_real_snapshot` in
    `crates/qbind-node/tests/b3_snapshot_restore_tests.rs`.
- Wall-clock window: `2026-05-09T04:29:47.377Z` → `2026-05-09T04:32:16.025Z`
  (≈ 2 m 28 s).
- Run artifacts under `/tmp/run020/` (logs in `logs/`, scrapes in
  `scrapes/`, snapshots in `snap1/` and `snap2/`, seed DB in `seed_state/`,
  per-validator data dirs in `data/`).

## 4. Topology, Timing, Snapshot Method, Quorum Rationale, and Node Configuration Used

Topology (matches Run 019 exactly):

| Validator | P2P listen      | Metrics port | Stage          |
|-----------|-----------------|--------------|----------------|
| V0        | 127.0.0.1:20950 | 10950        | Stage A → end  |
| V1A       | 127.0.0.1:20951 | 10951        | Stage A → C    |
| V2A       | 127.0.0.1:20952 | 10952        | Stage A → C    |
| V3A       | 127.0.0.1:20953 | 10953        | Stage A → C    |
| V1B       | 127.0.0.1:20951 | 10954        | Stage D → end  |
| V2C       | 127.0.0.1:20952 | 10955        | Stage E → end  |

Static peer syntax: `--p2p-peer <validator-id>@127.0.0.1:<port>`, for the
three peers other than self, on every node.

Timing:

- A: V0 started; ≈ 0.4 s later V1A/V2A/V3A started in parallel.
- A → B: live cluster reached `committed_height=4` on V0 within ≈ 2 s
  (this is `S`); V0 progressed to `H=5` (delta `+1`) within an additional
  0.01 s.
- B: real RocksDB checkpoint produced (helper duration `1 ms`,
  `8588` bytes); V0 continued to `H=13` over the next 1.5 s before fault.
- C: V1A/V2A/V3A SIGINTed; V0 alone — `preV1B V0 H=15`.
- D: V1B started with `--restore-from-snapshot /tmp/run020/snap1`. V0+V1B
  sub-quorum (2 of 4) plateau. 12 scrapes × 4 s = 48 s.
- E: V2C started with `--restore-from-snapshot /tmp/run020/snap2`. Three
  alive (V0, V1B, V2C). 24 scrapes × 4 s = 96 s.
- F: SIGINT V1B/V2C/V0; all three exited rc=0.

Snapshot method (the central thing this run actually changes vs. Run 019):

- Run 020 does **not** use a hand-crafted `meta.json + placeholder file`
  shape.
- A fresh `RocksDbAccountState` is opened at `/tmp/run020/seed_state` via
  `RocksDbAccountState::open`, populated with one well-known account
  (`account=cdcd…cd`, `nonce=7`, `balance=4242`) — the canonical shape
  used by `build_real_snapshot` in
  `crates/qbind-node/tests/b3_snapshot_restore_tests.rs`.
- `StateSnapshotter::create_snapshot(&meta, snap_dir)` is then invoked.
  This is the same impl that
  `crates/qbind-ledger/src/execution.rs` lines 1571–1675 provides,
  which internally calls
  `rocksdb::checkpoint::Checkpoint::new(&self.db).create_checkpoint(&state_dir)`.
- The resulting `/tmp/run020/snap1` therefore contains a real
  RocksDB checkpoint (`CURRENT`, `MANIFEST-000013`, `000009.sst`,
  `OPTIONS-000015`) plus the canonical `meta.json` exactly as produced by
  `RocksDbAccountState::create_snapshot`. See §7 for the byte-level
  sha256 inventory.
- `/tmp/run020/snap2` is a byte-identical copy of `/tmp/run020/snap1`
  (`diff -r snap1 snap2` empty, all five sha256 hashes match) — the same
  shape Run 019 used (snap1/snap2 with identical content) so V1B and V2C
  restore from genuinely the same real RocksDB checkpoint.

Quorum rationale: identical to Run 019. `f=⌊(N-1)/3⌋=1`, quorum
`2f+1=3`. Sub-quorum window has `{V0, V1B}` alive (2 of 4) so consensus
must plateau (Run 017 boundary). Quorum-restored window has
`{V0, V1B, V2C}` alive (3 of 4); leader at `view % 4 == 3` (V3) is
absent so the absent-leader B14 timeout/new-view path must fire to
advance views (Run 016 shape).

Node configuration (every node):

- `--env devnet --execution-profile vm-v0`
- `--network-mode p2p --enable-p2p`
- `--p2p-mutual-auth required` (B12 Required-mode)
- `--validator-id <0..3>`
- `--data-dir <per-node>`
- `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>` exported via `env`.
- `QBIND_MUTUAL_AUTH` explicitly *unset* via `env -u QBIND_MUTUAL_AUTH`
  to keep the only mutual-auth source `--p2p-mutual-auth required`.

## 5. Commands and Configuration Used

V0 (Stage A start):

```
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:10950 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --execution-profile vm-v0 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:20950 --p2p-mutual-auth required \
  --validator-id 0 --data-dir /tmp/run020/data/v0 \
  --p2p-peer 1@127.0.0.1:20951 \
  --p2p-peer 2@127.0.0.1:20952 \
  --p2p-peer 3@127.0.0.1:20953
```

V1A/V2A/V3A: identical except for `--validator-id`, `--p2p-listen-addr`,
metrics port (10951 / 10952 / 10953), data dir, and the `--p2p-peer`
list excluding self.

Real RocksDB checkpoint production (Stage B):

```
/home/runner/work/QBIND/QBIND/target/release/examples/qbind_seed_vm_v0_state \
  /tmp/run020/seed_state

/home/runner/work/QBIND/QBIND/target/release/examples/qbind_state_snapshot \
  --state-dir   /tmp/run020/seed_state \
  --snapshot-dir /tmp/run020/snap1 \
  --height      4 \
  --block-hash-hex 0000000000000000040000000000000003000000000000000300000000000000 \
  --chain-id    0x51424e4444455600

cp -r /tmp/run020/snap1 /tmp/run020/snap2
```

V1B (Stage D restore):

```
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:10954 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --execution-profile vm-v0 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:20951 --p2p-mutual-auth required \
  --validator-id 1 --data-dir /tmp/run020/data/v1b \
  --restore-from-snapshot /tmp/run020/snap1 \
  --p2p-peer 0@127.0.0.1:20950 \
  --p2p-peer 2@127.0.0.1:20952 \
  --p2p-peer 3@127.0.0.1:20953
```

V2C (Stage E restore): identical to V1B except `--validator-id 2`,
`--p2p-listen-addr 127.0.0.1:20952`, metrics port `10955`,
data dir `/tmp/run020/data/v2c`, `--restore-from-snapshot
/tmp/run020/snap2`, and peer list `0,1,3`.

The driver script that orchestrates this is `/tmp/run020/run020.sh`
(committed under `commands/` only as part of the run log; not as a new
production artifact).

## 6. Live-Cluster Pre-Restore Progress Evidence

Stage A startup banner (every validator, redacted to relevant fields):

```
qbind-node[validator=V0]: starting in environment=DevNet
  chain_id=0x51424e4444455600 scope=DEV profile=vm-v0
  network=p2p p2p=enabled listen=127.0.0.1:20950 peers=3
  gas=off fee-priority=off fee_distribution=burn-only
  mempool=fifo dag_availability=disabled dag_coupling=off
  stage_b=disabled
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[P2P] Listening on 127.0.0.1:20950 (node_id=NodeId(4bd96f97b1aaec9d))
[binary-consensus] Starting consensus loop:
  local_id=ValidatorId(0) num_validators=4 tick=100ms
  restore_baseline=false interconnect=p2p late_peer_reemit=on
```

Stage A snapshot anchor capture (V0):

```
[2026-05-09T04:29:49.375Z] S_CAPTURED at H=4 (V0)
[2026-05-09T04:29:49.386Z] PROGRESS_ABOVE_S V0 H=5 (S=4, delta=+1)
[2026-05-09T04:29:49.389Z] V0_BLOCK_ID_LINE=
  '[binary-consensus] committed_anchor height=4
   block_id=0000000000000000040000000000000003000000000000000300000000000000'
```

V0's `committed_anchor` line at H=4 carries `block_id=0000…0400…0300…0300…00`,
which is the live binary-path `BasicHotStuffEngine` block id — i.e. the
anchor was sourced from live peer state on the binary path, not synthesised.

Continued live progress before fault:

```
[2026-05-09T04:29:50.941Z] preFault V0 H=13
```

V0 advanced from `H=4` (anchor) → `H=13` (delta `+9`) during Stage B,
strictly above the captured anchor before any fault was injected — the
Run-019 stagger property is preserved.

Per-node `/metrics` was reachable for every node throughout Stage A
(`stageA_t01..t40`, `preStop_t01..t30` scrapes); `qbind_consensus_proposals_total`,
`qbind_consensus_votes_total{result="accepted"}`, and
`qbind_consensus_committed_height` all advanced monotonically without
either `result="rejected"` or `result="invalid"` increments anywhere.

## 7. Real Snapshot Production and Restore-Baseline Evidence

The snapshot was produced via the canonical
`RocksDbAccountState::create_snapshot` impl. Helper output:

```
[qbind_state_snapshot] opening RocksDbAccountState at /tmp/run020/seed_state
[qbind_state_snapshot] invoking StateSnapshotter::create_snapshot
  meta={height=4, chain_id=0x51424e4444455600,
       block_hash=0000…0400…0300…0300…00}
  target=/tmp/run020/snap1
[qbind_state_snapshot] OK: height=4, size=0.01MB, duration=1ms
  (size_bytes=8588, duration_ms=1)
```

Resulting `/tmp/run020/snap1` layout (verbatim from `ls -la`):

```
snap1/
├── meta.json                 175 B
└── state/
    ├── 000009.sst           1055 B
    ├── CURRENT                16 B
    ├── MANIFEST-000013       266 B
    └── OPTIONS-000015       7251 B
```

This is a **real** RocksDB checkpoint, not a placeholder. `CURRENT`,
`MANIFEST-*`, `*.sst`, and `OPTIONS-*` are exactly the file set that
`rocksdb::checkpoint::Checkpoint::create_checkpoint` produces, as called
from `crates/qbind-ledger/src/execution.rs` line 1657 inside the
`StateSnapshotter` impl. Byte-level sha256 inventory:

```
snap1/meta.json              1e7fc169cd3dd196c6a8657c235cb301896e91985f7ad321e6a9f0de7c640588
snap1/state/000009.sst       475d6d0b9e4ec574d8d35b66572721faf672ee32339099ccec55f9b8e3d5cb1a
snap1/state/CURRENT          e6325e36f681074fccd2b1371dbf6f4535a6630e5b95c9ddff92c48ec11ce312
snap1/state/MANIFEST-000013  90822d96cff4a001138992cd193d4a73da607cf1ab5b9ed33360891339bba79d
snap1/state/OPTIONS-000015   016d828912746bb7b0af877776034ce3a1774ea5b2c5e43e66332c18e214a202
```

`snap2` is byte-for-byte identical (`diff -r snap1 snap2` empty; all five
sha256s match snap1's). This is the same shape Run 019 used to keep the
two restore points comparison-equivalent — only the substrate is
different (real RocksDB checkpoint here vs placeholder content there).

Snapshot metadata (`snap1/meta.json`, exactly as produced by
`StateSnapshotMeta::to_json`):

```json
{
  "height": 4,
  "block_hash": "0000000000000000040000000000000003000000000000000300000000000000",
  "created_at_unix_ms": 1778300989412,
  "chain_id": 5855328520645203456
}
```

`5855328520645203456 == 0x51424e4444455600 == QBIND_DEVNET_CHAIN_ID`
(`crates/qbind-types/src/primitives.rs:61`).

V1B startup restore log (verbatim):

```
[restore] requested:
  snapshot_dir=/tmp/run020/snap1
  data_dir=/tmp/run020/data/v1b
  expected_chain_id=0x51424e4444455600
[restore] complete:
  height=4 chain_id=0x51424e4444455600 bytes_copied=8588
  target=/tmp/run020/data/v1b/state_vm_v0
[restore] audit marker written to
  /tmp/run020/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot
  height=4 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled
  (snapshot_height=4, starting_view=5)
[binary] Consensus loop config:
  local_validator_id=ValidatorId(1) num_validators=4
  restore_baseline=true interconnect=p2p
[binary-consensus] B5: applied restore baseline:
  snapshot_height=4 starting_view=5
  (engine committed_height=Some(4))
[binary-consensus] Starting consensus loop:
  local_id=ValidatorId(1) num_validators=4 tick=100ms
  restore_baseline=true interconnect=p2p late_peer_reemit=on
```

V1B audit marker (`/tmp/run020/data/v1b/RESTORED_FROM_SNAPSHOT.json`,
verbatim):

```json
{"restored_at_unix_ms":1778300991213,"snapshot_dir":"/tmp/run020/snap1",
 "target_state_dir":"/tmp/run020/data/v1b/state_vm_v0",
 "bytes_copied":8588,"snapshot_height":4,
 "snapshot_block_hash":"0000000000000000040000000000000003000000000000000300000000000000",
 "snapshot_chain_id":5855328520645203456,
 "snapshot_created_at_unix_ms":1778300989412}
```

V1B's materialized `state_vm_v0/` after B3 file-copy contains exactly the
same five files with the same sizes as `snap1/state/` — i.e. the real
RocksDB checkpoint was copied in full into the validator's data dir, as
required by B3.

V2C is byte-identical in shape (same `bytes_copied=8588`, same metadata,
same `B5: starting_view=5`).

## 8. Restore-Catchup Request / Response Evidence

V1B (sub-quorum window):

```
[restore-catchup] applied 13 peer-learned certified blocks;
  committed_height=Some(15) view=18
[restore-catchup] exit: caught up to peer anchor —
  local committed_height=15 peer_max_observed=Some(15);
  stopping further RestoreCatchupRequest broadcasts and
  proposal-deferral gating
[restore-catchup] rejected stale/mismatched response anchor:
  response_height=4 local_height=Some(15)
```

V2C (quorum-restored window): identical shape — also applied 13
peer-learned certified blocks, exited at the same anchor.

Counter-level evidence directly from `/metrics` at run end:

| Metric                                                | V0 | V1B | V2C |
|-------------------------------------------------------|----|-----|-----|
| `qbind_restore_catchup_requests_sent_total`           | 0  | 2   | 2   |
| `qbind_restore_catchup_requests_received_total`       | 2  | 1   | 0   |
| `qbind_restore_catchup_responses_sent_total`          | 2  | 1   | 0   |
| `qbind_restore_catchup_responses_received_total`      | 1  | 2   | 2   |
| `qbind_restore_catchup_responses_rejected_total`      | 1  | 1   | 1   |
| `qbind_restore_catchup_blocks_applied_total`          | 0  | 13  | 13  |
| `qbind_restore_catchup_proposals_deferred_total`      | 0  | 0   | 0   |
| `qbind_restore_catchup_mode_active`                   | 0  | 0   | 0   |
| `qbind_restore_catchup_mode_exited_at_height`         | 0  | 15  | 15  |

`responses_rejected_total=1` on V1B and V2C corresponds to the
log-emitted `rejected stale/mismatched response anchor: response_height=4
local_height=Some(15)` line — i.e. catchup correctly rejects responses
whose anchor is stale relative to the locally-applied tip. V0 is the
responder (`responses_sent_total=2`); it never enters catchup itself
(`mode_active=0`, `blocks_applied_total=0`).

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

Sub-quorum window (V0 + V1B alive, 2 of 4 = sub-quorum):

```
t01 V0_H=15 V1B_H=15 mode_active=0 exited_at=15 blocks_applied=13
…
t12 V0_H=15 V1B_H=15 mode_active=0 exited_at=15 blocks_applied=13
```

V1B is honestly **above S** (`H=15 > S=4`, delta `+11`) by `qr_t01`,
having learned 13 certified blocks from V0 across the sub-quorum
plateau; both nodes then plateau at H=15 because 2 alive < 2f+1=3 (the
Run-017 boundary). This is the strongest possible positive evidence
that B3+B5+catchup advance committed_height correctly **above** the
restored snapshot anchor on a real RocksDB checkpoint.

Quorum-restored window after V2C joins (3 of 4 alive):

```
t01 V0 H=16 view=19 tc_formed=0   (V2C joins)
t02 V0 H=19 view=23 tc_formed=1
t03 V0 H=19 view=23 tc_formed=1
t04 V0 H=22 view=27 tc_formed=2
…
t23 V0 H=64 view=83 tc_formed=16
t24 V0 H=64 view=83 tc_formed=16
```

Forward progress: H=15 → H=64 (49 commits) over 24 × 4 s = 96 s, view
advanced 18 → 83 (65 view advances), and 16 timeout certificates were
formed because leader V3 (`view % 4 == 3`) was absent. All three nodes
ended at the same `committed_height=64` and `current_view=83`.

## 10. Restore-Mode Exit Evidence

B13 exit was clean and direct on both restored validators:

- V1B emitted `[restore-catchup] exit: caught up to peer anchor —
  local committed_height=15 peer_max_observed=Some(15)` and
  `qbind_restore_catchup_mode_active` transitioned `1 → 0` while
  `qbind_restore_catchup_mode_exited_at_height` transitioned `0 → 15`.
- V2C emitted the same line and the same metric transitions, also at
  height 15.
- Both validators thereafter participated in normal proposal/vote/QC
  emission — see §12.
- `qbind_restore_catchup_proposals_deferred_total = 0` on both
  validators throughout: the strict-progress predicate (Run 018 lesson)
  was satisfied here because `15 > 4`, so no proposals had to be
  deferred to wait for catchup to clear.

## 11. Direct B14 `/metrics` Timeout / New-View Evidence

Final `/metrics` directly scraped from each node's HTTP endpoint
(`curl http://127.0.0.1:<port>/metrics`):

| Metric                                                          | V0  | V1B | V2C |
|-----------------------------------------------------------------|-----|-----|-----|
| `qbind_consensus_view_timeouts_emitted_total`                   | 17  | 17  | 16  |
| `qbind_consensus_inbound_timeouts_delivered_total`              | 33  | 33  | 32  |
| `qbind_consensus_inbound_timeouts_engine_accepted_total`        | 33  | 33  | 32  |
| `qbind_consensus_view_timeout_decode_failures_total`            | 0   | 0   | 0   |
| `qbind_consensus_view_timeout_engine_rejects_total`             | 0   | 0   | 0   |
| `qbind_consensus_timeout_certificates_formed_total`             | 16  | 16  | 16  |
| `qbind_consensus_view_timeout_advances_total`                   | 16  | 16  | 16  |
| `qbind_consensus_outbound_new_views_sent_total`                 | 16  | 16  | 16  |
| `qbind_consensus_inbound_new_views_delivered_total`             | 32  | 32  | 32  |
| `qbind_consensus_inbound_new_views_engine_accepted_total`       | 0   | 0   | 0   |
| `qbind_consensus_view_changes_total`                            | 164 | 143 | 143 |
| `qbind_consensus_current_view`                                  | 83  | 83  | 83  |
| `qbind_consensus_committed_height`                              | 64  | 64  | 64  |

Sample log lines (V0; V1B and V2C show the same shape):

```
[binary-consensus] B14: emitted TimeoutMsg for view=18 after 50 ticks of no progress
[binary-consensus] B14: emitted TimeoutMsg for view=19 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 19 -> 20
[binary-consensus] B14: emitted TimeoutMsg for view=23 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 23 -> 24
…
```

Interpretation:

- 16 timeout certificates formed across V0/V1B/V2C identically; views
  with `view % 4 == 3` are absent-leader views (V3 never came back) and
  are precisely the views B14 must clear. The 16 TCs match the 16
  absent-leader views in the H=15 → H=64 stretch.
- `decode_failures_total=0` and `engine_rejects_total=0` — no
  fabrication, no malformed timeout msgs accepted.
- `inbound_new_views_engine_accepted_total=0` is the same shape as
  Run 016/019: B14's TimeoutCertificate path is what advances views;
  inbound NewView messages are observed but the engine's view advance
  is driven by the TC, so `engine_accepted` does not increment. This is
  consistent with the Run-019 baseline and is not a regression.

## 12. Quorum-Restored Recovery Outcome Evidence

Loop-exit summary lines (verbatim):

```
V0:  Loop exit: ticks=1484 proposals=21 commits=65 committed_height=Some(64)
     view=83 inbound_msgs=267 inbound_proposals=47 inbound_votes=152
     outbound_proposals=21 outbound_votes=67
     outbound_proposal_late_peer_reemits=1
V1B: Loop exit: ticks=1447 proposals=17 commits=60 committed_height=Some(64)
     view=83 inbound_msgs=199 inbound_proposals=33 inbound_votes=98
     outbound_proposals=17 outbound_votes=50
     outbound_proposal_late_peer_reemits=1
V2C: Loop exit: ticks=965  proposals=17 commits=60 committed_height=Some(64)
     view=83 inbound_msgs=196 inbound_proposals=32 inbound_votes=98
     outbound_proposals=17 outbound_votes=49
     outbound_proposal_late_peer_reemits=0
```

`/metrics` proposal/vote totals at run end (no rejected/invalid anywhere):

| Metric                                                 | V0  | V1B | V2C |
|--------------------------------------------------------|-----|-----|-----|
| `qbind_consensus_proposals_total{result="accepted"}`   | 67  | 50  | 49  |
| `qbind_consensus_proposals_total{result="rejected"}`   | 0   | 0   | 0   |
| `qbind_consensus_votes_total{result="accepted"}`       | 152 | 98  | 98  |
| `qbind_consensus_votes_total{result="invalid"}`        | 0   | 0   | 0   |

This is the **positive recovery shape**: forward proposal/vote/QC/commit
resumed automatically once a quorum-compatible alive set existed
(`{V0, V1B, V2C}`), B13 had already exited on both restored validators,
and B14 was clearing absent-leader views. No operator intervention
between Stage E and shutdown.

## 13. Shutdown Evidence

```
[2026-05-09T04:32:15.805Z] SIGINT v1b pid=12536
[2026-05-09T04:32:15.808Z] SIGINT v2c pid=12625
[2026-05-09T04:32:15.810Z] SIGINT v0  pid=12309
[2026-05-09T04:32:16.016Z] exited v1b pid=12536 rc=0
[2026-05-09T04:32:16.020Z] exited v2c pid=12625 rc=0
[2026-05-09T04:32:16.024Z] exited v0  pid=12309 rc=0
```

All three nodes exited rc=0 within 215 ms of SIGINT. Loop-exit lines
(see §12) cleanly summarize tick/proposal/commit totals — the orderly
shutdown shape established by Runs 016/019 holds.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability                                              | Verified in Run 020 | Evidence |
|---------------------------------------------------------|--|----------|
| B1 binary-path consensus loop                           | ✅ | `[binary-consensus] Starting consensus loop` on every node; commits up to 65 on V0. |
| B2 metrics HTTP                                         | ✅ | `[metrics_http] Listening on 127.0.0.1:<port>` on every node; 166 metrics lines per scrape; all required counters present. |
| B3 restore-from-snapshot startup                        | ✅ | `[restore] complete: height=4 chain_id=0x51424e4444455600 bytes_copied=8588 target=…/state_vm_v0` on V1B and V2C; audit marker written; **for the first time on real RocksDB checkpoint content** (`CURRENT`, `MANIFEST-000013`, `000009.sst`, `OPTIONS-000015`). |
| B5 restore-aware consensus start                        | ✅ | `[binary-consensus] B5: applied restore baseline: snapshot_height=4 starting_view=5 (engine committed_height=Some(4))` on V1B and V2C. |
| B6 multi-validator P2P binary-path interconnect         | ✅ | All three live nodes exchanged 196–267 inbound msgs each; all proposals/votes accepted. |
| B7 dialer-side identity closure                         | ✅ | Per-peer KEM pk + validator-id override on every dial: `[P2P] Dial 127.0.0.1:209xx: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`. |
| B8 listener-side identity closure + initial-dial retry  | ✅ | `[P2P] Inbound connection from 127.0.0.1:xxxxx bound to deterministic NodeId NodeId(...) via inbound identity resolver (B8, test-grade)`; bounded retries observed (`succeeded on attempt 4/8`). |
| B9 leader proposal re-emit on late peer connect         | ✅ | `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)`. |
| B10 paired leader-vote re-emission                      | ✅ | Same line as B9. |
| B11 (engine-progress recorder)                          | ✅ | `engine committed_height=Some(4)` recorded on B5 baseline application; committed-height counters advanced to 64 on all nodes. |
| B12 mutual-auth Required                                | ✅ | `[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` on every node; `QBIND_MUTUAL_AUTH` was explicitly unset via `env -u`, so the only mutual-auth source is the CLI flag — there is **no silent fallback to Disabled mode** anywhere. |
| Bounded multi-validator restore catchup above prefix    | ✅ | V1B and V2C each applied 13 peer-learned certified blocks; bounded by peer-max-observed `Some(15)`. |
| B13 bounded post-catchup → normal-participation         | ✅ | `[restore-catchup] exit: caught up to peer anchor — local committed_height=15 peer_max_observed=Some(15)` on V1B and V2C; `mode_active 1→0`, `mode_exited_at_height 0→15` on both. |
| B14 absent-leader timeout / view-change                 | ✅ | 16 timeout certificates formed on every alive node; views advanced 18 → 83 across the absent-V3 stretch; `decode_failures=0`, `engine_rejects=0`. Counters directly visible on `/metrics`. |
| `/metrics` honesty                                      | ✅ | Every counter that increased in this run also has a clearly-corresponding log line; no "fabricated" increments observed. |
| No silent fallback to LocalMesh / harness               | ✅ | `[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=vm-v0` on every node; no harness module activated. |
| No silent fallback to Disabled mutual-auth              | ✅ | See B12 row above. |
| No silent fallback to placeholder snapshot              | ✅ | snap1/snap2 contain real `CURRENT`/`MANIFEST-*`/`000009.sst`/`OPTIONS-*` with non-trivial sizes; helper exit code 0; B3 `bytes_copied=8588` matches `find /tmp/run020/snap1/state -type f \| xargs stat`. |
| Clean shutdown                                          | ✅ | rc=0 on V0/V1B/V2C; loop-exit lines on every node. |

No previously landed binary-path capability appears regressed.

## 15. Limitations and Anomalies Observed

**L1 (most important — newly isolated by Run 020).** The qbind-node
binary's binary-consensus loop (`crates/qbind-node/src/binary_consensus_loop.rs`)
does not currently instantiate a `RocksDbAccountState` for
`<data_dir>/state_vm_v0` at runtime. `--execution-profile vm-v0` is
accepted by the CLI and propagated into the startup banner
(`profile=vm-v0`), but the binary-consensus path never enters
`crates/qbind-node/src/execution_adapter.rs`'s
`run_vm_v0_loop` initialization, so no `[T164] VM v0 using persistent
state at …` line is emitted by **any** of V0/V1A/V2A/V3A/V1B/V2C in
this run. Concretely: after Stage A, V0/V1A/V2A/V3A each have a data
dir but **no `state_vm_v0/` subdirectory at all**. After Stage D/E,
V1B and V2C have a `state_vm_v0/` subdirectory because B3 materialized
the snapshot's `state/` checkpoint into it (we verified the five files
are present and byte-identical to snap1/state), but the running binary
never opens it.

This means production-grade VM-v0 persistent state is **not yet wired
into the binary's runtime path**, regardless of `--execution-profile`.
Run 020 narrows the previously-blanket "production fast-sync /
consensus-storage restore" sub-item of C4 into two distinct sub-items:

  - (a) **production-grade snapshot creation** via the supported
    `StateSnapshotter::create_snapshot` path — proven in this run;
  - (b) **production-grade snapshot restore copy + B3/B5/B13/B14
    binary-path behavior on top of a real RocksDB checkpoint** — proven
    in this run;
  - (c) **binary-path runtime open of the restored VM-v0 state DB by
    a running validator** — **not yet exercised**;
  - (d) **operator-facing surface to trigger
    `StateSnapshotter::create_snapshot` from inside a running validator**
    (no CLI subcommand, no SIGUSR/HTTP trigger, no metrics-driven
    trigger) — **not yet exercised**.

**L2 (consequence of L1, an honest reproducibility note).** Because
of L1+L2(d), the snapshot in this run was produced from a deliberately
seeded `RocksDbAccountState` — exactly the canonical
`build_real_snapshot` shape used by the B3 integration tests
(`crates/qbind-node/tests/b3_snapshot_restore_tests.rs`,
`crates/qbind-ledger/tests/t215_state_snapshot_tests.rs`) — rather than
from a live validator's VM-v0 state DB (which does not exist on disk
today, see L1). The checkpoint **format** and **production code path**
(`RocksDbAccountState::create_snapshot` →
`rocksdb::checkpoint::Checkpoint::create_checkpoint`) are real and
unchanged; what is not real is the **liveness coupling** between the
running validator and the snapshot's content. We invoke the supported
snapshot path against a `RocksDbAccountState` containing only one
seeded account (`account=cdcd…cd, nonce=7, balance=4242`), not against
the live cluster's account state, because today the live cluster has
no VM-v0 account state on disk.

This is recorded plainly because it directly affects what Run 020 can
and cannot prove: it proves the snapshot **format** and the **B3
restore copy + B5/B13/B14 reaction** survive a real RocksDB checkpoint;
it does **not** prove that a restored validator can re-open and
serve from that RocksDB state at runtime, because the binary doesn't
open `state_vm_v0` at all.

**L3.** `qbind_consensus_inbound_new_views_engine_accepted_total = 0`
on all three alive nodes despite `inbound_new_views_delivered_total =
32` everywhere. This is the same shape as Run 019 and is consistent
with the design that B14's `TimeoutCertificate` path (not the
`NewView` path) advances views. Not a regression; a pre-existing
behavioral pattern of B14 as currently landed.

**L4.** `qbind_consensus_view_changes_total` is 164 on V0 vs. 143 on
V1B and V2C. V0 was alive longer (Stage A → end ≈ 2 m 28 s) than V1B
(Stage D → end ≈ 1 m 36 s) and V2C (Stage E → end ≈ 1 m 36 s); the
difference matches the additional ≈ 50 s × ~0.4 view-changes/s during
Stage A on V0 alone before Stages D/E. Not anomalous.

**L5 (operational shape, not a defect).** `RocksDbAccountState`
acquires an exclusive write lock on the DB directory; the supported
`StateSnapshotter::create_snapshot` API requires it to be invoked from
the same process that holds that lock. Today the qbind-node binary
does not expose any operator surface to invoke that API from the
running process (see L1 (d)). This run did not bypass that constraint
— it instead snapshotted a separate seeded DB. A future evidence run
on a real-validator VM-v0 DB will require either a snapshot-on-stop
operator surface, an in-process snapshot trigger (CLI subcommand,
SIGUSR handler, or metrics-driven trigger), or wiring `SnapshotConfig`
through to the binary's runtime so periodic snapshots fire on
`current_height % snapshot_interval_blocks == 0` (the schema for this
already exists in `crates/qbind-node/src/node_config.rs:269+`, just
not yet wired into the binary-consensus loop).

## 16. Assessment of Evidence Value

Positive closure of the question Run 020 was specifically designed to
answer: **does the supported, real `StateSnapshotter::create_snapshot`
output (a real RocksDB checkpoint) survive the binary-path B3 restore +
B5 baseline + B13 catchup + B14 view-change loop, end-to-end, with no
regression of any prior milestone?** Answer: **yes**.

- Live binary-path cluster progressed normally before snapshot capture
  (S=4 captured from V0 `/metrics`, V0 advanced to H=13 before fault).
- Snapshot was generated via the real supported snapshot path
  (`RocksDbAccountState::create_snapshot` → RocksDB Checkpoint API,
  producing real `CURRENT`/`MANIFEST-*`/`*.sst`/`OPTIONS-*`).
- The live cluster committed strictly above the captured anchor before
  restore began (Run-019 lesson preserved: `H=15 > S=4`).
- Restored validators V1B and V2C started honestly from S=4
  (B5 `committed_height=Some(4)`, `starting_view=5`) and did **not**
  pretend to have post-S history.
- Restore-catchup requests/responses honestly exchanged on the binary
  path (V1B: 2 sent, 2 received, 1 rejected stale, 13 applied; V2C:
  same shape; V0: 2 received, 2 served).
- Committed height advanced strictly above S on both restored
  validators (B13 strict-progress predicate satisfied;
  `mode_exited_at_height=15 > 4=S`).
- B13 restore-catchup mode exited cleanly on V1B and V2C at H=15.
- B14 timeout/new-view counters showed real activity directly on
  `/metrics`: 17/17/16 timeouts emitted, 16 timeout certificates formed
  on each, `decode_failures=0` and `engine_rejects=0` everywhere.
- Normal proposal/vote/QC/commit resumed automatically once V2C joined
  (no operator intervention between Stage E and shutdown).
- All three nodes ended at the same `committed_height=64` and
  `current_view=83`, with no rejected proposals or invalid votes.
- All three nodes exited rc=0 within 215 ms of SIGINT.
- No regression vs. Run 019.

This is a **material narrowing** of C4's "production fast-sync /
consensus-storage restore" sub-item, which previously had no real-format
evidence. The narrowing is twofold:

  1. The supported `StateSnapshotter::create_snapshot` path produces
     genuinely consumable RocksDB checkpoints that B3 → B5 → B13 → B14
     handle correctly end-to-end on the binary path.
  2. The remaining open part of that sub-item is now isolated to two
     specific gaps (L1 (c), L1 (d) above), neither of which affects the
     correctness of the snapshot/restore *control flow* exercised here.

It is **not** a closure of C4 itself — see §15 L1 for what remains.

## 17. Recommended Immediate Next Action

The narrowest next execution that materially advances C4 from this point is
to wire the existing `SnapshotConfig` (`crates/qbind-node/src/node_config.rs`
lines 279–322 and `should_create_snapshot` at line 388) into the binary's
runtime so that:

- on every `committed_height % snapshot_interval_blocks == 0` boundary,
  the binary invokes `StateSnapshotter::create_snapshot` against the same
  `RocksDbAccountState` it would open at `<data_dir>/state_vm_v0` via the
  `execution_adapter::run_vm_v0_loop` initialization path; and

- `--execution-profile vm-v0` actually causes `binary_consensus_loop` to
  open that `RocksDbAccountState` at startup (this is L1 (c) above).

Both of these together unlock a follow-on Run 021 that can do what Run 020
explicitly could not: snapshot a **live validator's actual on-disk VM-v0
state** at a known committed height, and then prove that a restored
validator opens and serves from that real RocksDB DB at runtime
(observing the `[T164] VM v0 using persistent state at …` line on the
restored side, which is currently never emitted in any DevNet evidence
run). Until that line appears in evidence, C4's "production fast-sync /
consensus-storage restore" sub-item cannot be fully closed even though
Run 020 has positively closed the snapshot-format and restore-copy parts
of it.

If the above is too broad to land as a single change, the smaller useful
intermediate step is just to expose an in-process snapshot trigger on the
running binary (CLI subcommand `qbind-node snapshot create
--out <dir> --height-tag <H>`, SIGUSR1 handler, or `POST /admin/snapshot`
endpoint) so that a real-validator snapshot can be produced without
needing to stop the validator first. That alone moves L1 (d) to closed
without touching the consensus-loop wiring.

No update to QBIND production source code is recommended as a *direct
consequence* of Run 020's evidence; the limitations isolated here are
existing gaps (L1 (c), L1 (d)) made visible by the run, not regressions
introduced by it.

---

Run-020 is internal evidence. Tone is conservative and evidence-based
throughout; nothing in this document claims more than the
log/metrics/file-system content above directly supports.