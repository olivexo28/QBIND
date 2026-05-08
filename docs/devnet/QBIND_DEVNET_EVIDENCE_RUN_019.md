# QBIND DevNet Evidence Run 019

## 1. Purpose and Scope

Run 019 is the narrow disambiguation that Run 018 explicitly identified as the next required execution. The goal was to repeat the Run-018 N=4 Required-mode shape on the same binary, but with a deliberately different stagger: start V0 first, allow the live cluster to commit at least one — ideally two — blocks **above** the captured snapshot anchor `S` before V1B is started, so that restored validators have a genuine chance to satisfy the B13 strict-progress-above-baseline exit predicate (`local_committed_height > snapshot_baseline_height`). Then determine whether B13 exits on the restored validators, B14 timeout certificates form, `current_view` advances, and forward consensus resumes automatically once the third validator (V2C) is restored compatibly.

Verdict: **POSITIVE CLOSURE.** Under the revised stagger the Run-018 boundary is fully resolved on the real binary path. With `S=5` captured from V0 `/metrics` while the four-validator live cluster was healthy and V0 already past `S`, V0 progressed to `committed_height=8` after fault injection, and V1B's restore-catchup applied **5** peer-learned certified blocks against V0 over the real binary path, advancing V1B's `committed_height` from `5` to `8`. The B13 strict-progress predicate `local_height > base` (`8 > 5`) was satisfied immediately, V1B logged `[restore-catchup] exit: caught up to peer anchor — local committed_height=8 peer_max_observed=Some(8)`, and `qbind_restore_catchup_mode_active` flipped from `1` to `0` with `qbind_restore_catchup_mode_exited_at_height=8`. V2C, restored from the same `S=5` anchor while V0 + V1B were already a stable 2-of-4 sub-quorum at `H=8`, did the same: 5 peer-learned blocks applied, `mode_active=0`, `exited_at_height=8`. With V0 + V1B + V2C numerically equal to `2f+1` **and all three in normal participation (B13 fully exited)**, B14 cleared the absent-V3 leader plateau exactly as Run 016 proved it should: V0 emitted `B14: emitted TimeoutMsg for view=11 after 50 ticks of no progress`, **20** `TimeoutCertificate`s formed on V0 (18 on V1B, 20 on V2C), `current_view` advanced from 11 → 95 (an advance of **84 views**), and `committed_height` advanced from 8 → 71 (an advance of **63 commits**) on all three nodes. Final loop-exit lines: V0 `commits=72 committed_height=Some(71) view=95`, V1B `commits=66 committed_height=Some(71) view=95`, V2C `commits=66 committed_height=Some(71) view=95`. All B14 counters are directly visible on `/metrics`. `decode_failures_total=0`, `engine_rejects_total=0`. Shutdown was clean on all six processes (V1A/V2A/V3A pre-fault, V0/V1B/V2C post-observation).

No QBIND source code was changed by this task. The only repository documentation created by this task is this file. `docs/whitepaper/contradiction.md` is updated to record the positive closure of the B13 strict-progress-above-baseline operational sub-item that Run 018 narrowed; this is a sharpening/narrowing of C4, not a new contradiction (see §16).

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_018.md` — narrow B13 boundary: snapshot anchor sourced from a sub-quorum responder parked at the snapshot height left both restored validators in `mode_active=1` indefinitely, gating them out of B14 emission.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_017.md` — two-of-four sub-quorum boundary: V0 + V1B alone could not form `2f+1` timeout cohorts.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_016.md` — B14 cleared the strict Run-015 absent-leader plateau when three of four validators were alive *and in normal participation* after restore.
- `docs/whitepaper/contradiction.md` — C4 v1.7 (2026-05-08), narrowed by Run 018 to record the B13 strict-progress-above-baseline operational sub-item.
- `crates/qbind-node/src/binary_consensus_loop.rs` — `RestoreCatchupModeState::maybe_exit_after_response` (B13 strict-progress predicate at lines 723–727: `if local_height <= base { return None; }`); `ViewTimeoutState` and B14 emission/aggregation logic.
- `crates/qbind-node/src/snapshot_restore.rs` — B3 `--restore-from-snapshot` validation and materialization.
- `crates/qbind-ledger/src/state_snapshot.rs` — `validate_snapshot_dir`, `StateSnapshotMeta` JSON layout.

Validation/build before execution:

```sh
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node
```

Result:

```text
warning: use of deprecated function `bincode::config`: please use `options()` instead
    --> crates/qbind-node/src/binary_consensus_loop.rs:1731:28
warning: use of deprecated function `bincode::config`: please use `options()` instead
    --> crates/qbind-node/src/binary_consensus_loop.rs:1802:28
warning: unused variable: `worker_id`
   --> crates/qbind-node/src/verify_pool.rs:262:9
warning: `qbind-node` (lib) generated 3 warnings
    Finished `release` profile [optimized] target(s) in 6m 29s
```

These warnings are pre-existing in the current tree and were not introduced by Run 019.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-run-019-qbind` |
| HEAD (pre-task) | `6a668ef` |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9182184` bytes |
| Binary sha256 | `8479f4260de975b9c517c52a65a362d30c4014a0fa3c6a784cc31f476a4c3388` (identical to Runs 017 and 018) |
| Binary Build ID | `e8cecf091418b4bcf1d340e0fde20dc1bfbf0c7c` |
| Run directory | `/tmp/run019` |
| Driver script | `/tmp/run019/run019.sh` |
| Script start UTC | `2026-05-08T16:24:29.558Z` |
| Script end UTC | `2026-05-08T16:27:46.750Z` |
| `QBIND_MUTUAL_AUTH` | unset; every node used CLI `--p2p-mutual-auth required` |
| B14 default | `view_timeout_ticks = Some(50)`; no timeout override used |

Binary equality with Runs 017 and 018 is intentional: this run isolates restore/quorum/stagger behaviour at the same code under test.

## 4. Topology, Timing, Quorum Rationale, and Node Configuration Used

N=4, `f=1`, `2f+1 = 3`, comparison-friendly with Runs 015/016/017/018.

| Node | Phase | Validator | Listen | Static peers | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---:|---:|---|---|---|---|---|---|
| V0 | live throughout | `0` | `127.0.0.1:19950` | `1@127.0.0.1:19951`, `2@127.0.0.1:19952`, `3@127.0.0.1:19953` | `required` | `/tmp/run019/data/v0` | `127.0.0.1:9950` | none |
| V1A | live pre-fault | `1` | `127.0.0.1:19951` | `0@…:19950`, `2@…:19952`, `3@…:19953` | `required` | `/tmp/run019/data/v1a` | `127.0.0.1:9951` | none |
| V2A | live pre-fault | `2` | `127.0.0.1:19952` | `0@…:19950`, `1@…:19951`, `3@…:19953` | `required` | `/tmp/run019/data/v2a` | `127.0.0.1:9952` | none |
| V3A | live pre-fault | `3` | `127.0.0.1:19953` | `0@…:19950`, `1@…:19951`, `2@…:19952` | `required` | `/tmp/run019/data/v3a` | `127.0.0.1:9953` | none |
| V1B | restored during sub-quorum | `1` | `127.0.0.1:19951` | `0@…:19950`, `2@…:19952`, `3@…:19953` | `required` | `/tmp/run019/data/v1b` | `127.0.0.1:9954` | `/tmp/run019/snap1` |
| V2C | third validator restored compatibly | `2` | `127.0.0.1:19952` | `0@…:19950`, `1@…:19951`, `3@…:19953` | `required` | `/tmp/run019/data/v2c` | `127.0.0.1:9955` | `/tmp/run019/snap2` |

The deliberate difference relative to Run 018 is the **stagger**: V0 is started first (Run 018 started V0 last). All other ports/IDs/data dirs are different from Run 018 only because Run 019 uses `/tmp/run019` and `19950+/9950+` instead of `/tmp/run018` and `19850+/9850+`, to keep the runs cleanly isolated.

Timing (UTC):

| Event | Time |
|---|---|
| `RUN019_START` | `2026-05-08T16:24:29.558Z` |
| V0 start | `2026-05-08T16:24:29.560Z` |
| V1A start | `2026-05-08T16:24:31.564Z` |
| V2A start | `2026-05-08T16:24:31.566Z` |
| V3A start | `2026-05-08T16:24:31.569Z` |
| V0 metrics endpoint up | `2026-05-08T16:24:31.636Z` |
| `S_CAPTURED` (V0 at `H=5`) | `2026-05-08T16:24:32.898Z` |
| `PROGRESS_ABOVE_S` (V0 at `H_after_S=7`, delta `+2`) | `2026-05-08T16:24:33.211Z` |
| Pre-fault scrape | `2026-05-08T16:24:33.234Z` |
| `SNAP1_BUILT` | `2026-05-08T16:24:33.237Z` |
| V1A SIGINT | `2026-05-08T16:24:33.242Z` |
| V2A SIGINT | `2026-05-08T16:24:33.246Z` |
| V3A SIGINT | `2026-05-08T16:24:33.251Z` |
| Post-fault V0 scrape (`H_POST=8`) | `2026-05-08T16:24:38.265Z` |
| V1B restored start | `2026-05-08T16:24:38.267Z` |
| Sub-quorum observation | 12 scrapes every 5 s, `subq_t01` … `subq_t12` |
| `SNAP2_BUILT` | `2026-05-08T16:25:40.627Z` |
| Pre-V2C scrape | `2026-05-08T16:25:40.652Z` |
| V2C compatible-restore start | `2026-05-08T16:25:40.654Z` |
| Quorum-restored observation | 24 scrapes every 5 s, `qr_t01` … `qr_t24` |
| Final scrape | `2026-05-08T16:27:43.729Z` |
| V1B / V2C / V0 SIGINT | `2026-05-08T16:27:43.734Z` / `.740Z` / `.746Z` |
| `RUN019_END` | `2026-05-08T16:27:46.750Z` |

Quorum rationale:

- Pre-fault: alive set `{V0, V1A, V2A, V3A}` = 4 of 4. Above `2f+1=3`. Live progress observed (V0 reached `committed_height=8`, `current_view=11` before fault).
- Sub-quorum window: alive set `{V0, V1B}` = 2 of 4. Strictly below `2f+1`. Reproduces the Run-017 boundary.
- Quorum-restore window: alive set `{V0, V1B, V2C}` = 3 of 4. Numerically equal to `2f+1`, with the third validator returning via `--restore-from-snapshot` (the same shape Run 018 attempted).
- V3 remained absent throughout. There is no other absent honest validator pretending to participate.

The stagger guarantees the **strict-progress invariant** that Run 018 lacked: at the moment V1B is started, the only continuously-alive peer (V0) is at `committed_height=8 > S=5`, providing a strictly-higher catchup target so that V1B's `local_committed_height` can rise above `snapshot_baseline_height` and B13 can exit.

## 5. Commands and Configuration Used

The driver script is `/tmp/run019/run019.sh`. Representative exact node commands after expansion:

V0:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9950 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19950 \
  --p2p-peer 1@127.0.0.1:19951 \
  --p2p-peer 2@127.0.0.1:19952 \
  --p2p-peer 3@127.0.0.1:19953 \
  --p2p-mutual-auth required \
  --validator-id 0 \
  --data-dir /tmp/run019/data/v0 \
  > /tmp/run019/logs/v0.log 2>&1 &
```

V1A/V2A/V3A used the same command shape with validator IDs `1/2/3`, listen ports `19951/19952/19953`, metrics ports `9951/9952/9953`, the corresponding peer lists, and data dirs `/tmp/run019/data/v1a`, `/tmp/run019/data/v2a`, `/tmp/run019/data/v3a`.

V1B restored:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9954 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19951 \
  --p2p-peer 0@127.0.0.1:19950 \
  --p2p-peer 2@127.0.0.1:19952 \
  --p2p-peer 3@127.0.0.1:19953 \
  --p2p-mutual-auth required \
  --validator-id 1 \
  --data-dir /tmp/run019/data/v1b \
  --restore-from-snapshot /tmp/run019/snap1 \
  > /tmp/run019/logs/v1b.log 2>&1 &
```

V2C compatible-restore:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9955 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19952 \
  --p2p-peer 0@127.0.0.1:19950 \
  --p2p-peer 1@127.0.0.1:19951 \
  --p2p-peer 3@127.0.0.1:19953 \
  --p2p-mutual-auth required \
  --validator-id 2 \
  --data-dir /tmp/run019/data/v2c \
  --restore-from-snapshot /tmp/run019/snap2 \
  > /tmp/run019/logs/v2c.log 2>&1 &
```

The run scraped `http://127.0.0.1:9950/metrics`, `:9951`, `:9952`, `:9953`, `:9954`, and `:9955`. No LocalMesh process, harness-only recovery, fake timeout/NewView path, or mutual-auth fallback was used. `QBIND_MUTUAL_AUTH` was explicitly unset so the CLI flag is the sole source of mutual-auth mode.

## 6. Live-Cluster Pre-Restore Progress Evidence

V0 startup excerpt confirms real binary P2P + Required mutual auth:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] P2P transport up. Listen address: 127.0.0.1:19950, static peers: 3
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=4 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)
```

V0 `committed_anchor` log shows healthy chain progression past the chosen anchor `S=5` and continuing to `H=8` at the moment of fault injection:

```text
[binary-consensus] committed_anchor height=0 block_id=00000000000000000000000000000000ffffffffffffffffffffffffffffffff
[binary-consensus] committed_anchor height=1 block_id=0100000000000000010000000000000000000000000000000000000000000000
[binary-consensus] committed_anchor height=2 block_id=0200000000000000020000000000000001000000000000000100000000000000
[binary-consensus] committed_anchor height=3 block_id=0300000000000000030000000000000002000000000000000200000000000000
[binary-consensus] committed_anchor height=4 block_id=0000000000000000040000000000000003000000000000000300000000000000
[binary-consensus] committed_anchor height=5 block_id=0100000000000000050000000000000000000000000000000400000000000000
[binary-consensus] committed_anchor height=6 block_id=0200000000000000060000000000000001000000000000000500000000000000
[binary-consensus] committed_anchor height=7 block_id=0300000000000000070000000000000002000000000000000600000000000000
[binary-consensus] committed_anchor height=8 block_id=0000000000000000080000000000000003000000000000000700000000000000
```

Pre-fault `/metrics` snapshot at `2026-05-08T16:24:33.234Z`:

| Metric | V0 | V1A | V2A | V3A |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 11 | 11 | 10 | 10 |
| `qbind_consensus_committed_height` | **8** | 8 | 7 | 7 |
| `qbind_consensus_qcs_formed_total` | 20 | 21 | 20 | 20 |
| `qbind_consensus_proposals_total{result="accepted"}` | 11 | 11 | 11 | 11 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeouts_emitted_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_timeout_certificates_formed_total` | 0 | 0 | 0 | 0 |

V0 is `+3` blocks above `S=5` at this scrape; the cluster as a whole is at minimum `+2` above `S` (V2A/V3A at `H=7`). Slight tick-alignment asymmetry between nodes is the same micro-effect Runs 015–018 documented and is not regression.

Post-fault V0 scrape at `2026-05-08T16:24:38.265Z` (5 s after V1A/V2A/V3A SIGINT, V0 alone):

```text
qbind_consensus_committed_height 8
qbind_consensus_current_view 11
```

V0 is at `H_POST=8`, **strictly above** `S=5`. The `H_POST > S` invariant required by the Run-019 hypothesis is satisfied.

Answer A: **yes.** The live binary-path cluster progressed normally before the harsher shape was created.
Answer C: **yes.** The live cluster committed at least one (in fact three) blocks above the captured snapshot anchor before V1B started.

## 7. Snapshot Anchor and Restore-Baseline Evidence

`SNAP1` was sourced from V0 `/metrics` at `2026-05-08T16:24:32.898Z` while V0 was at `committed_height=5`:

```json
{
  "height": 5,
  "block_hash": "0100000000000000050000000000000000000000000000000400000000000000",
  "created_at_unix_ms": 1778257472896,
  "chain_id": 5855328520645203456
}
```

`SNAP1` file hashes:

```text
b20f23dc40a9ffa65056309c89fbe0780ec32eef6a4afa5b9e4a7d245d64c9a9  /tmp/run019/snap1/meta.json
9bd8a227359f278698341d0b5e990b73b0993488b940427e584689f1e32265d2  /tmp/run019/snap1/state/.placeholder.txt
```

`chain_id=5855328520645203456 = 0x51424e4444455600` matches the devnet chain-id constant the binary expects. The block_hash `0100…0400…00` is the exact `committed_block_info{block_id=…}` V0 reported at `H=5`, and matches V0's own `committed_anchor height=5 block_id=0100000000000000050000000000000000000000000000000400000000000000` log line — i.e. it is a real prefix of V0's chain.

V1B startup excerpt (`/tmp/run019/logs/v1b.log`):

```text
[restore] requested: snapshot_dir=/tmp/run019/snap1 data_dir=/tmp/run019/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=5 chain_id=0x51424e4444455600 bytes_copied=31 target=/tmp/run019/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run019/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=5 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=5, starting_view=6)
[binary-consensus] B5: applied restore baseline: snapshot_height=5 starting_view=6 (engine committed_height=Some(5))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=4 tick=100ms restore_baseline=true interconnect=p2p late_peer_reemit=on
```

V1B audit marker (`/tmp/run019/data/v1b/RESTORED_FROM_SNAPSHOT.json`):

```json
{"restored_at_unix_ms":1778257478272,"snapshot_dir":"/tmp/run019/snap1","target_state_dir":"/tmp/run019/data/v1b/state_vm_v0","bytes_copied":31,"snapshot_height":5,"snapshot_block_hash":"0100000000000000050000000000000000000000000000000400000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778257472896}
```

`SNAP2` re-uses the same `(height, block_hash)` (which is the exact prefix V0 attests at height 5) with a refreshed `created_at_unix_ms`, written at `2026-05-08T16:25:40.627Z`:

```json
{
  "height": 5,
  "block_hash": "0100000000000000050000000000000000000000000000000400000000000000",
  "created_at_unix_ms": 1778257540624,
  "chain_id": 5855328520645203456
}
```

`SNAP2` file hashes:

```text
516741507cff970df9135d6385e000290c5b9f9a22a73e645b0c5b2c127bc64a  /tmp/run019/snap2/meta.json
3812de265a5607380325f0a6b7e06e403cfb58cfa8379372e760aed6d12904f0  /tmp/run019/snap2/state/.placeholder.txt
```

V2C startup excerpt (`/tmp/run019/logs/v2c.log`):

```text
[restore] requested: snapshot_dir=/tmp/run019/snap2 data_dir=/tmp/run019/data/v2c expected_chain_id=0x51424e4444455600
[restore] complete: height=5 chain_id=0x51424e4444455600 bytes_copied=31 target=/tmp/run019/data/v2c/state_vm_v0
[restore] audit marker written to /tmp/run019/data/v2c/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=5 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=5, starting_view=6)
[binary-consensus] B5: applied restore baseline: snapshot_height=5 starting_view=6 (engine committed_height=Some(5))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(2) num_validators=4 tick=100ms restore_baseline=true interconnect=p2p late_peer_reemit=on
```

V2C audit marker (`/tmp/run019/data/v2c/RESTORED_FROM_SNAPSHOT.json`):

```json
{"restored_at_unix_ms":1778257540658,"snapshot_dir":"/tmp/run019/snap2","target_state_dir":"/tmp/run019/data/v2c/state_vm_v0","bytes_copied":31,"snapshot_height":5,"snapshot_block_hash":"0100000000000000050000000000000000000000000000000400000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778257540624}
```

Answers B / D: **yes / yes.** Both `SNAP1` and `SNAP2` are sourced from live V0 peer state at `H=5`. V1B and V2C both started honestly from `S=5` with `B5: applied restore baseline: snapshot_height=5 starting_view=6 (engine committed_height=Some(5))`, neither pretends to already have post-S history.

## 8. Restore-Catchup Request / Response Evidence

V1B:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=4 restore_baseline=true interconnect=p2p
[restore-catchup] applied 5 peer-learned certified blocks; committed_height=Some(8) view=11
[restore-catchup] exit: caught up to peer anchor — local committed_height=8 peer_max_observed=Some(8); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

V2C:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(2) node_id=NodeId(eadb48d7b679d681) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(2) num_validators=4 restore_baseline=true interconnect=p2p
[restore-catchup] applied 5 peer-learned certified blocks; committed_height=Some(8) view=11
[restore-catchup] exit: caught up to peer anchor — local committed_height=8 peer_max_observed=Some(8); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Restore-catchup metrics directly scraped from `/metrics`:

V1B:

| Time | `requests_sent_total` | `responses_received_total` | `blocks_applied_total` | `responses_rejected_total` | `mode_active` | `mode_exited_at_height` |
|---|---:|---:|---:|---:|---:|---:|
| `subq_t01` (≈ 2 s after V1B start) | 2 | 1 | **5** | 0 | **0** | **8** |
| `subq_t12` (end of sub-quorum) | 2 | 1 | 5 | 0 | 0 | 8 |
| final | 2 | 2 | 5 | 1 | 0 | 8 |

V2C:

| Time | `requests_sent_total` | `responses_received_total` | `blocks_applied_total` | `responses_rejected_total` | `mode_active` | `mode_exited_at_height` |
|---|---:|---:|---:|---:|---:|---:|
| `qr_t01` (≈ 2 s after V2C start) | 2 | 2 | **5** | 0 | **0** | **8** |
| final | 2 | 2 | 5 | 1 | 0 | 8 |

V0 (responder side) at `pre_v2c_v0` scrape (after V1B's catchup, before V2C joined):

```text
qbind_restore_catchup_requests_received_total 1
qbind_restore_catchup_responses_sent_total 1
qbind_restore_catchup_responses_rejected_total 0
```

The single `responses_rejected_total=1` recorded at the final scrape on each restored validator is honest: `[restore-catchup] rejected stale/mismatched response anchor: response_height=5 local_height=Some(8)` — a late-arriving response carrying the original `S=5` anchor was correctly rejected because `local_height=8` was already past it. This is expected post-exit hygiene, not a real catchup failure.

Answer E / F: **yes / yes.** Both V1B and V2C issued real binary-path `RestoreCatchupRequest` frames over P2P, V0 received and answered them on the real binary path, both validators applied 5 peer-learned certified blocks each (`blocks_applied_total=5`), and zero responses were rejected during the catchup window itself. No LocalMesh / harness fallback occurred.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

This is the section where the Run-018 narrow boundary fully resolves.

V1B's `committed_height` progression:

| Phase | `committed_height` | Notes |
|---|---:|---|
| B5 baseline (snapshot apply) | 5 | Logged: `engine committed_height=Some(5)` |
| After 5 catchup blocks applied (≈ 2 s post-start) | **8** | Logged: `applied 5 peer-learned certified blocks; committed_height=Some(8)`; B13 exit predicate `8 > 5` satisfied |
| Sub-quorum window end (`subq_t12`) | 8 | V1B in normal participation; V0+V1B unable to form `2f+1` |
| Quorum-restore window | 8 → 71 | Tracks V0/V2C lockstep |
| Final loop-exit | **71** | `view=95`, advance of 66 commits above baseline |

V2C's `committed_height` progression:

| Phase | `committed_height` | Notes |
|---|---:|---|
| B5 baseline | 5 | Logged: `engine committed_height=Some(5)` |
| After 5 catchup blocks applied (≈ 2 s post-start) | **8** | B13 exit predicate `8 > 5` satisfied |
| Quorum-restore window | 8 → 71 | Tracks V0/V1B lockstep |
| Final loop-exit | **71** | `view=95`, advance of 66 commits above baseline |

V0's `committed_height` progression across the run:

| Phase | `committed_height` | `current_view` |
|---|---:|---:|
| Pre-fault | 8 | 11 |
| Post-fault (alone) | 8 | 11 |
| Through V1B sub-quorum window | 8 | 11 |
| QR_T1 (V2C just connected) | 8 | 11 |
| QR_T2 (5 s later) | 11 | 15 |
| QR_T6 | 20 | 27 |
| QR_T12 | 35 | 47 |
| QR_T18 | 53 | 71 |
| QR_T24 (final scrape) | **68** | **91** |
| Final loop-exit | **71** | **95** |

Answer G: **yes.** `committed_height` advanced strictly above `S=5` on **both** restored validators within the first ~2 seconds of their respective starts (V1B: 5→8, V2C: 5→8), and continued to advance to 71 once the third validator was present.

## 10. Restore-Mode Exit Evidence

`qbind_restore_catchup_mode_active` flipped from `1` to `0` and `qbind_restore_catchup_mode_exited_at_height` flipped from `0` to `8` on **both** restored nodes within the very first scrape after each respective start:

| Time | V1B `mode_active` | V1B `exited_at_height` | V2C `mode_active` | V2C `exited_at_height` |
|---|---:|---:|---:|---:|
| `subq_t01` | **0** | **8** | n/a | n/a |
| `subq_t12` | 0 | 8 | n/a | n/a |
| `pre_v2c` | 0 | 8 | n/a | n/a |
| `qr_t01` | 0 | 8 | **0** | **8** |
| `qr_t12` | 0 | 8 | 0 | 8 |
| final | **0** | **8** | **0** | **8** |

Direct log evidence:

V1B:

```text
[restore-catchup] applied 5 peer-learned certified blocks; committed_height=Some(8) view=11
[restore-catchup] exit: caught up to peer anchor — local committed_height=8 peer_max_observed=Some(8); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

V2C:

```text
[restore-catchup] applied 5 peer-learned certified blocks; committed_height=Some(8) view=11
[restore-catchup] exit: caught up to peer anchor — local committed_height=8 peer_max_observed=Some(8); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Answer H: **yes.** B13 restore-catchup mode exited honestly on **both** restored validators at `local_committed_height=8 = peer_max_observed`. Both `[restore-catchup] exit:` log lines (the same wording Run 017 V1B emitted) are present, and the `/metrics` gauge transition is directly observable on the very first post-exit scrape. The B13 strict-progress-above-baseline operational sub-item that Run 018 narrowed is fully cleared by the revised stagger.

## 11. Direct B14 `/metrics` Timeout / New-View Evidence

B14 counters were directly scraped from `/metrics`. During the sub-quorum window (V0 + V1B alive in N=4):

| Time | Node | `current_view` | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `outbound_new_views_sent_total` | `inbound_new_views_engine_accepted_total` | `view_timeout_advances_total` |
|---|---|---:|---:|---:|---:|---:|---:|
| `subq_t01` | V0 | 11 | 1 | 0 | 0 | 0 | 0 |
| `subq_t01` | V1B | 11 | 0 | 0 | 0 | 0 | 0 |
| `subq_t12` | V0 | 11 | 1 | 0 | 0 | 0 | 0 |
| `subq_t12` | V1B | 11 | 1 | 0 | 0 | 0 | 0 |

(V1B emitted its own `view=11` timeout once it had exited B13 — a strict consequence of having advanced into normal participation.)

After V2C joined (alive set = 3 of 4):

| Time | Node | `current_view` | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `outbound_new_views_sent_total` | `view_timeout_advances_total` |
|---|---|---:|---:|---:|---:|---:|
| `qr_t01` | V0 | 11 | 1 | 0 | 0 | 0 |
| `qr_t02` | V0 | 15 | 2 | **1** | 1 | 1 |
| `qr_t06` | V0 | 27 | 5 | 4 | 4 | 4 |
| `qr_t12` | V0 | 47 | 10 | 9 | 9 | 9 |
| `qr_t18` | V0 | 71 | 15 | 14 | 14 | 14 |
| `qr_t24` | V0 | 91 | **19** | **19** | 19 | 19 |
| final | V0 | **95** | **21** | **20** | **20** | **21** |
| final | V1B | 95 | 21 | **18** | 18 | 21 |
| final | V2C | 95 | 21 | **20** | 20 | 21 |

Direct log evidence on V0 (representative slice; the pattern repeats every ~4 views):

```text
[binary-consensus] B14: emitted TimeoutMsg for view=11 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 11 -> 12
[binary-consensus] B14: emitted TimeoutMsg for view=15 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 15 -> 16
[binary-consensus] B14: emitted TimeoutMsg for view=19 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 19 -> 20
…
[binary-consensus] B14: emitted TimeoutMsg for view=47 after 50 ticks of no progress
[binary-consensus] B14: NewView advanced view 47 -> 48
…
[binary-consensus] B14: emitted TimeoutMsg for view=91 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 91 -> 92
```

`qbind_consensus_view_timeout_decode_failures_total = 0` and `qbind_consensus_view_timeout_engine_rejects_total = 0` on V0 across the entire run — the B14 path is exercised honestly, not silently failing.

Answers I / J / K: **all yes.**

- I. B14 timeout / new-view counters showed **real** activity directly on `/metrics` (V0 final: `view_timeouts_emitted_total=21`, `timeout_certificates_formed_total=20`, `outbound_new_views_sent_total=20`, `inbound_new_views_engine_accepted_total=1`, `view_timeout_advances_total=21`).
- J. Once the third (compatibly-restored) validator V2C was present and both restored validators were out of B13 mode, **20** `TimeoutCertificate`s formed on V0 (18 on V1B, 20 on V2C) across the 24-scrape observation window.
- K. `current_view` advanced from 11 → 95 on all three nodes; `view_timeout_advances_total=21` on V0 directly attributes 21 of those view advances to B14 (the remaining ~63 view advances are from normal QC-driven proposal/commit progression, see §12).

## 12. Quorum-Restored Recovery Outcome Evidence

Final loop-exit lines (from logs):

```text
V0:  [binary-consensus] Loop exit: ticks=1942 proposals=24 commits=72 committed_height=Some(71) view=95 inbound_msgs=294 inbound_proposals=51 inbound_votes=160 outbound_proposals=24 outbound_votes=74 outbound_proposal_late_peer_reemits=1
V1B: [binary-consensus] Loop exit: ticks=1855 proposals=21 commits=66 committed_height=Some(71) view=95 inbound_msgs=254 inbound_proposals=43 inbound_votes=127 outbound_proposals=21 outbound_votes=63 outbound_proposal_late_peer_reemits=0
V2C: [binary-consensus] Loop exit: ticks=1231 proposals=22 commits=66 committed_height=Some(71) view=95 inbound_msgs=248 inbound_proposals=42 inbound_votes=126 outbound_proposals=22 outbound_votes=64 outbound_proposal_late_peer_reemits=1
```

Final scrape comparison across all three nodes:

| Node | Final `committed_height` | Final `current_view` | Final `qcs_formed_total` | Final accepted proposals | Final B14 TCs | Final B13 `mode_active` |
|---|---:|---:|---:|---:|---:|---:|
| V0  | **71** | **95** | 85 | 74 | 20 | 0 (never restored) |
| V1B | **71** | **95** | 64 | 63 | 18 | **0** |
| V2C | **71** | **95** | 63 | 64 | 20 | **0** |

Answer L: **yes.** Normal proposal/vote/QC/commit progression resumed automatically once the compatibly-restored third validator was present and both restored validators had exited B13. Between V2C connect (`qr_t01`, V0 at view 11, height 8) and the final loop-exit (`view=95`, `committed_height=71`), the cluster pipelined **63 commits** and **84 view advances** without operator intervention, with B14 timeouts handling the absent-V3 leader views (one per cycle of four views, since V3 is the leader of every fourth view in a static round-robin) and normal HotStuff QC-formation handling the other three views per cycle. The interleaving is directly observable in the V0 log: `B14: TimeoutCertificate advanced view N → N+1` (for views 11, 15, 19, 23, … ≡ 3 mod 4) interspersed with normal `committed_anchor height=K` lines (for the views where V0/V1B/V2C are leader).

Answer M (narrowest exact remaining boundary): **none, for the Run-018 question.** The exact boundary that Run 018 isolated — the B13 strict-progress-above-baseline gate interacting with a snapshot anchor whose responder is parked at the same height — is fully addressable by the operational stagger applied here. No new narrower boundary surfaced inside Run 019. The previously-recorded broader open items in C4 (production fast-sync / consensus-storage restore, signature-verified `TimeoutMsg`/`TimeoutCertificate`, exponential-backoff timeout pacing, production PQC KEMTLS root-key distribution) remain open exactly as they were before this run; Run 019 does not narrow them and does not weaken them.

## 13. Shutdown Evidence

Shutdown events (`/tmp/run019/timeline.log`):

```text
2026-05-08T16:27:43.729Z FINAL_SCRAPE
2026-05-08T16:27:43.734Z v1b SIGINT pid=10639
2026-05-08T16:27:43.740Z v2c SIGINT pid=10868
2026-05-08T16:27:43.746Z v0  SIGINT pid=10471
2026-05-08T16:27:46.750Z RUN019_END
```

Representative shutdown logs (V0/V1B/V2C; V1A/V2A/V3A also confirmed — see §14):

```text
V0:  [binary] Shutdown signal received, stopping P2P node...
V0:  [binary-consensus] Shutdown signal received after 1942 ticks.
V0:  [T175] P2P node shutdown complete
V0:  [binary] P2P node shutdown complete.
V0:  [binary] Shutdown complete.
V1B: [binary] Shutdown signal received, stopping P2P node...
V1B: [binary-consensus] Shutdown signal received after 1855 ticks.
V1B: [T175] P2P node shutdown complete
V1B: [binary] Shutdown complete.
V2C: [binary] Shutdown signal received, stopping P2P node...
V2C: [binary-consensus] Shutdown signal received after 1231 ticks.
V2C: [T175] P2P node shutdown complete
V2C: [binary] Shutdown complete.
```

Post-SIGINT process check (no qbind-node processes survived):

```text
UID          PID    PPID  C STIME TTY          TIME CMD
no qbind-node processes
```

Answers N / O: **yes / yes.** `/metrics` remained honest throughout — every counter increment on the wire (timeout emissions, `TimeoutCertificate`s, `NewView`s, view advances, QCs, commits) corresponds to a real log-visible event; no counter advanced without a matching log line; restore-catchup metrics matched the catchup logs; `decode_failures_total=0`, `engine_rejects_total=0` on V0 throughout. Shutdown remained clean on all six processes.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 019 observation | Assessment |
|---|---|---|
| B1 / B2 (binary consensus loop + metrics) | V0 emitted `[binary-consensus] Starting consensus loop:` and reached `commits=72 committed_height=Some(71)`; `/metrics` exposed all expected counters | not regressed |
| B3 restore startup | V1B applied `/tmp/run019/snap1` and V2C applied `/tmp/run019/snap2`; both wrote `RESTORED_FROM_SNAPSHOT.json`; both used live-sourced `snapshot_height=5`, block hash `0100…0400…00`, `chain_id=0x51424e4444455600` | not regressed |
| B5 restore-aware baseline | V1B logged `B5: applied restore baseline: snapshot_height=5 starting_view=6 (engine committed_height=Some(5))`; V2C logged the identical line | not regressed |
| B6 P2P routing | live cluster progressed via P2P; V1B and V2C both connected to V0 over P2P; V1B/V2C exchanged restore-catchup frames with V0 over P2P; sustained `BroadcastProposal`/`BroadcastVote` traffic crossed all three live binaries during the QR window (V0 inbound_proposals=51 inbound_votes=160; V1B inbound_proposals=43 inbound_votes=127; V2C inbound_proposals=42 inbound_votes=126) | not regressed; **actively exercised at scale** |
| B7 / B8 identity and bounded dial | P2P dials logged `pk_len=32, has_vid=true`; deterministic NodeIds `4bd96f97b1aaec9d` / `92115fddcd4f93a0` / `eadb48d7b679d681` for V0/V1B/V2C; bounded retry on V1B/V2C dials of absent V3A visible in logs | not regressed |
| B9 / B10 late-peer reemit | V0 logged one bounded view-0 reemit (`B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)`); V2C logged one bounded view-6 reemit on connect | not regressed |
| B12 Required mode | every node used `--p2p-mutual-auth required`; logs show `B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` and `mutual_auth=Required` on all six node startups | not regressed |
| Bounded restore-catchup | both V1B and V2C sent real binary-path `RestoreCatchupRequest` frames, received responses, applied **5** peer-learned certified blocks each; zero responses rejected during catchup; one stale response correctly rejected post-exit on each (`response_height=5 local_height=Some(8)`) — exactly the honest stale-anchor rejection logic | not regressed; **actively exercised** |
| B13 transition | B13 honestly reported `mode_active=1 → 0` and `exited_at_height=0 → 8` on both restored nodes; `[restore-catchup] exit: …` log lines emitted; behavior consistent with the source's strict-progress-above-baseline guard — which **does** exit cleanly under the revised stagger | not regressed; **operationally cleared** |
| B14 `/metrics` exports | direct counters exposed sustained activity throughout the QR window; final V0 `view_timeouts_emitted_total=21`, `timeout_certificates_formed_total=20`, `outbound_new_views_sent_total=20`, `view_timeout_advances_total=21`; `decode_failures_total=0`, `engine_rejects_total=0` | not regressed; **actively exercised** |
| No LocalMesh / harness fallback | every node ran with `--network-mode p2p --enable-p2p`; no LocalMesh recovery path; no harness-only timeout/NewView injection | satisfied |
| Metrics honesty | every counter increment matches a log-visible event (timeouts ↔ `B14: emitted TimeoutMsg` lines; TCs ↔ `B14: TimeoutCertificate advanced` lines; restore-catchup mode flip ↔ `[restore-catchup] exit:` line; QCs ↔ engine record_qc_formed call sites; commits ↔ `committed_anchor height=…` lines) | satisfied |
| Clean shutdown | all six processes ran `[binary] Shutdown signal received, stopping P2P node…` → `[binary-consensus] Shutdown signal received after N ticks.` → `[T175] P2P node shutdown complete` → `[binary] Shutdown complete.`; `ps -fC qbind-node` post-run is empty | satisfied |

Answer P: **no previously landed binary-path capability appears regressed.** B14 recovery, B13 exit, B6/B7/B8/B9/B10 P2P + identity, B12 mutual-auth, and B3/B5 restore are all directly exercised and observable.

## 15. Limitations and Anomalies Observed

- This is a single execution, not a statistical soak. The result is a single positive-closure event; running it many times would harden the claim further.
- The snapshot anchor `S=5` is small (Run 018 used `S=13`, Run 017 used `S=12`); this is because the deliberate stagger (V0 first) intentionally captures `S` as soon as V0 reaches `H≥4`, in order to have V0_height advance past `S` quickly and still observe the entire run within a small wall-clock window. It does not affect any behavioural property under test.
- `/tmp/run019/snap*/state/.placeholder.txt` (31 bytes each, content `QBIND-RUN019-SNAP{1,2}-PLACEHOLDER`) is a non-empty stand-in for a real RocksDB checkpoint, matching the same `validate_snapshot_dir` requirement Runs 017 and 018 used. Production fast-sync / consensus-storage restore (so a restored validator can carry post-S certified material on its own without depending on a live peer's residual progress) remains an existing C4 open item; Run 019 does not address that and does not claim to.
- Production signature verification of `TimeoutMsg`/`TimeoutCertificate`, exponential-backoff timeout pacing, and production PQC KEMTLS root-key distribution remain outside this run.
- `qbind_restore_catchup_responses_rejected_total=1` on V1B and V2C at the final scrape is honest stale-anchor hygiene (`response_height=5 local_height=Some(8)`), not a real catchup failure.
- The B14 `inbound_new_views_engine_accepted_total` counter is `1` on V0, `3` on V1B, and `1` on V2C at the final scrape, while `outbound_new_views_sent_total` is `20`, `18`, `20` respectively. The `inbound_*_engine_accepted_total < outbound_*_sent_total` pattern reflects the engine's stale-`NewView` rejection logic (a `NewView` for view K is no longer needed once the engine has already advanced past K via a `TimeoutCertificate` on the same view); this is design-correct, not a regression. One `NewView`-driven advance is directly visible in V0's log: `B14: NewView advanced view 47 -> 48`.
- V3 remained absent throughout. There is no other absent honest validator pretending to participate.

Answer Q (limitations remaining): production fast-sync / consensus-storage restore; signature-verified `TimeoutMsg`/`TimeoutCertificate` payload validation; production exponential-backoff timeout pacing; production PQC KEMTLS root-key distribution. None of these are introduced by Run 019; Run 019 only positively closes the B13 strict-progress-above-baseline operational sub-item Run 018 narrowed.

## 16. Assessment of Evidence Value

Run 019 is a **strongest-positive** result on the same binary as Runs 017 and 018, addressing the exact narrow disambiguation Run 018 identified:

- Run 015 isolated the strict N=4 absent-leader plateau (no view advance without B14).
- Run 016 proved B14 clears the plateau when three of four validators are alive *and in normal participation*.
- Run 017 proved that two of four validators alone cannot form `2f+1` timeout cohorts.
- Run 018 attempted to restore a third validator via `--restore-from-snapshot` but found that, when the snapshot anchor was sourced from a sub-quorum responder parked at the snapshot height, both restored validators stayed in B13 `mode_active=1` indefinitely, were gated out of B14 emission, and so could not contribute to a `2f+1` timeout cohort.
- **Run 019** keeps every other condition equal to Run 018 — same binary, same N=4 Required-mode topology, same `--restore-from-snapshot` path, same `2f+1`-numerically-compatible alive set with V3 absent — and changes only the stagger so that V0 starts first and the live cluster commits at least two blocks above `S` before V1B starts. Result: B13 exits cleanly on both restored validators (`exited_at_height=8`), B14 timeout certificates form (V0: 20 TCs over the QR window), `current_view` advances (11 → 95 on all three nodes), and forward consensus resumes automatically (`committed_height` 8 → 71 on all three nodes, 63 commits, 84 view advances, no operator intervention).

This positively closes the Run-017 follow-up question for B14 modulo the operational requirement isolated by Run 018: **the live cluster must commit at least one block above the captured snapshot anchor before the restore window begins.** This is a property of the existing B13 strict-progress-above-baseline guard interacting with the snapshot capture moment — not a defect, not a redesign — and is fully expressed as an operational stagger requirement that the driver script encodes explicitly.

Because Run 019 positively closes the operational sub-item Run 018 narrowed, `docs/whitepaper/contradiction.md` is updated to record this closure (a sharpening, not a new contradiction). Specifically the C4 status row's Run-018 narrowing — "restored validators stay in `mode_active=1` indefinitely" because the snapshot-anchor responder is itself parked — is now annotated with Run 019's positive empirical closure under the documented stagger. The broader open items in C4 (production fast-sync / consensus-storage restore, signature verification of `TimeoutMsg`/`TimeoutCertificate`, exponential-backoff timeout pacing, production PQC KEMTLS root-key distribution) remain open exactly as they were before this run.

Run 019 evidence value summary: **strongest-positive, comparison-friendly with Runs 016/017/018, conservatively scoped, no regression of any prior milestone, fully resolves the B13 strict-progress-above-baseline operational sub-item, leaves the broader fast-sync / consensus-storage restore question and the signature-verified-timeout question exactly where Run 018 left them.**

## 17. Recommended Immediate Next Action

Two candidate next executions, in priority order:

1. **Production-grade snapshot restore execution.** Replace the `placeholder.txt` stand-in for `/state/` in the snapshot directory with a real RocksDB-checkpoint-format VM-v0 state, captured by an actual `StateSnapshotter::snapshot_to_dir` call against a running validator's state DB at the chosen height. This closes the largest remaining C4 sub-item (production fast-sync / consensus-storage restore) and would also subsume the operational stagger requirement Run 019 just resolved at test-grade — a restored validator that imports a certified-block proof up to some `H_cert > snapshot_height` would pass the B13 strict-progress predicate immediately, regardless of whether the live peer happens to be parked at the snapshot height or not.

2. **Signature-verified `TimeoutMsg` / `TimeoutCertificate` payload validation.** Currently `view_timeout_decode_failures_total` and `view_timeout_engine_rejects_total` are decode-only checks. Adding cryptographic verification of the timeout payload would close another open C4 sub-item without disturbing the B14 wiring Run 019 has now empirically validated end-to-end.

Either of these can be executed independently. Neither weakens the existing positive closure of B13/B14 demonstrated by Run 019.