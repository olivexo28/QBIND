# QBIND DevNet Evidence Run 018

## 1. Purpose and Scope

Run 018 is the narrow quorum-restoration follow-up that Run 017 explicitly identified as the next required execution. The goal was to repeat the Run-017 two-of-four sub-quorum window honestly on the real binary path, and then bring back a third validator with a true `--restore-from-snapshot` baseline (rather than the empty-state V2B return that Run 017 used) so that a `2f+1` quorum of consensus-state-compatible validators exists, and then determine whether B14 timeout certificates form, `current_view` advances, and normal proposal/vote/QC/commit progression resumes automatically.

Verdict: **PARTIAL NEGATIVE — the run is comparison-friendly and narrowly informative, but it does not show automatic forward-consensus resumption. It instead isolates a new, narrower remaining boundary not previously isolated by Run 017: the B13 restore-mode strict-progress-above-baseline exit predicate is *not* satisfied when the snapshot anchor is sourced from a peer whose own `committed_height` cannot subsequently advance (because that peer is itself in sub-quorum and stays at the snapshot height). Both restored validators (V1B and V2C) therefore stayed in bounded restore-catchup mode for the full observation window, never transitioning to normal participation. Even though the alive set reached three of four (V0 + V1B + V2C) — the same numeric shape Run 016 proved sufficient for B14 — no timeout certificate formed, no `NewView` was emitted/accepted, `current_view` did not advance, and no QC formation / commit progression occurred.**

The N=4 Required-mode P2P live cluster did progress normally before fault injection. V0 reached `committed_height=13, current_view=16`. The snapshot anchor was sourced honestly from V0 `/metrics` at `S=13`. V1B restored from that anchor honestly and connected to V0 over real P2P with mutual-auth Required. The Run-017 sub-quorum boundary was reproduced cleanly: V0+V1B alone produced timeout emissions but no timeout certificate. V2C was then started with `--restore-from-snapshot=<snap2>` from a fresh anchor scraped from V0 (still at `S=13`, because V0 in sub-quorum had not advanced). V2C also restored honestly and connected over real P2P with mutual-auth Required. After ~120 s of observation in the alive-set-of-three configuration, the cluster did **not** make any forward-consensus progress: no commits, no QCs, no view advances, no `TimeoutCertificate`, no `NewView`. This isolates a precise, narrow secondary boundary on top of the Run-017 sub-quorum boundary.

No QBIND source code was changed by this task. The only repository documentation created by this task is this file. `docs/whitepaper/contradiction.md` was sharpened to reflect the new B13 boundary identified by Run 018 (see §16); the change is a narrowing/clarification of C4, not a new contradiction.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_017.md` — two-of-four sub-quorum boundary; V2B return without restore baseline left clean quorum-restored recovery unproven.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_016.md` — B14 cleared the strict Run-015 N=4 absent-leader plateau when three of four validators were alive after restore.
- `docs/whitepaper/contradiction.md` C4 v1.6, 2026-05-08 — B1/B2/B3/B5/B6/B7/B8/B9/B10/B11/B12/B13/B14 landed; production fast-sync / consensus-storage restore, signature verification of `TimeoutMsg`/`TimeoutCertificate`, exponential-backoff timeout pacing, and production PQC KEMTLS root-key distribution remain outstanding.
- `crates/qbind-node/src/binary_consensus_loop.rs` — `RestoreCatchupModeState::maybe_exit_after_response` (B13 exit predicate), `ViewTimeoutState` and B14 emission logic.
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
    Finished `release` profile [optimized] target(s) in 6m 46s
```

These warnings are pre-existing in the current tree and were not introduced by Run 018.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-run-018-qbind` |
| HEAD (pre-task) | `6f0084c` (graft of `7973bfee727b66f0fad9e2c424d25338d51b1939`) |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9182184` bytes |
| Binary sha256 | `8479f4260de975b9c517c52a65a362d30c4014a0fa3c6a784cc31f476a4c3388` (identical to Run 017) |
| Binary Build ID | `e8cecf091418b4bcf1d340e0fde20dc1bfbf0c7c` |
| Run directory | `/tmp/run018` |
| Script start UTC | `2026-05-08T13:26:48.414Z` |
| Script end UTC | `2026-05-08T13:30:13.350Z` |
| `QBIND_MUTUAL_AUTH` | unset; every node used CLI `--p2p-mutual-auth required` |
| B14 default | `view_timeout_ticks = Some(50)`; no timeout override used |

Binary equality with Run 017 is intentional: this run isolates restore/quorum behaviour at the same code under test.

## 4. Topology, Timing, Quorum Rationale, and Node Configuration Used

N=4 was used to remain comparison-friendly with Runs 015, 016, and 017. With N=4, `f=1` and the quorum / timeout-certificate threshold is `2f+1 = 3`.

| Node | Phase | Validator | Listen | Static peers | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---:|---:|---|---|---|---|---|---|
| V0 | live throughout | `0` | `127.0.0.1:19850` | `1@127.0.0.1:19851`, `2@127.0.0.1:19852`, `3@127.0.0.1:19853` | `required` | `/tmp/run018/data/v0` | `127.0.0.1:9850` | none |
| V1A | live pre-fault | `1` | `127.0.0.1:19851` | `0@127.0.0.1:19850`, `2@127.0.0.1:19852`, `3@127.0.0.1:19853` | `required` | `/tmp/run018/data/v1a` | `127.0.0.1:9851` | none |
| V2A | live pre-fault | `2` | `127.0.0.1:19852` | `0@127.0.0.1:19850`, `1@127.0.0.1:19851`, `3@127.0.0.1:19853` | `required` | `/tmp/run018/data/v2a` | `127.0.0.1:9852` | none |
| V3A | live pre-fault | `3` | `127.0.0.1:19853` | `0@127.0.0.1:19850`, `1@127.0.0.1:19851`, `2@127.0.0.1:19852` | `required` | `/tmp/run018/data/v3a` | `127.0.0.1:9853` | none |
| V1B | restored during sub-quorum | `1` | `127.0.0.1:19851` | `0@127.0.0.1:19850`, `2@127.0.0.1:19852`, `3@127.0.0.1:19853` | `required` | `/tmp/run018/data/v1b` | `127.0.0.1:9854` | `/tmp/run018/snap1` |
| V2C | **third validator restored compatibly** | `2` | `127.0.0.1:19852` | `0@127.0.0.1:19850`, `1@127.0.0.1:19851`, `3@127.0.0.1:19853` | `required` | `/tmp/run018/data/v2c` | `127.0.0.1:9855` | `/tmp/run018/snap2` |

V2C is the explicit improvement over Run 017's V2B: it uses a **fresh data directory** (no leftover pre-fault state) and an **honest `--restore-from-snapshot` baseline** sourced from live peer state immediately before V2C startup. This is the same B3 path V1B uses, so V2C enters the loop with `restore_baseline=true` and B5 applies the snapshot baseline before the first tick. Run 017's V2B reused `/tmp/run017/data/v2a` without any restore directive, did not load a baseline, and reported `committed_height=None`. V2C does not have that defect.

Timing:

| Event | UTC |
|---|---|
| `RUN018_START` | `2026-05-08T13:26:48.414Z` |
| V1A start | `2026-05-08T13:26:48.430Z` |
| V2A start | `2026-05-08T13:26:48.434Z` |
| V3A start | `2026-05-08T13:26:48.439Z` |
| V0 start | `2026-05-08T13:26:50.445Z` |
| Pre-fault scrape | `2026-05-08T13:26:53.448Z` |
| Live-ready marker | `LIVE_READY V0 height=13 view=16 block=01000000…00000000` |
| `SNAP1_ANCHOR` capture | `2026-05-08T13:26:53.485Z` |
| V1A SIGINT | `2026-05-08T13:26:53.492Z` |
| V2A SIGINT | `2026-05-08T13:26:53.495Z` |
| V3A SIGINT | `2026-05-08T13:26:53.499Z` |
| Pre-restore scrape (V0 alone) | `2026-05-08T13:27:01.502Z` |
| V1B restored start | `2026-05-08T13:27:01.514Z` |
| Sub-quorum observation | 12 scrapes every 5 s, through `2026-05-08T13:28:06.791Z` |
| `SNAP2_ANCHOR` capture | `2026-05-08T13:28:06.809Z` |
| V2C compatible-restore start | `2026-05-08T13:28:06.818Z` |
| Quorum-restore observation | 24 scrapes every 5 s, through `2026-05-08T13:30:10.300Z` |
| Final scrape | `2026-05-08T13:30:10.300Z` |
| V1B / V2C / V0 SIGINT | `2026-05-08T13:30:10.322Z` / `.326Z` / `.330Z` |
| `RUN018_END` | `2026-05-08T13:30:13.350Z` |

Quorum rationale (Run-018-specific):

- Pre-fault: alive set `{V0, V1A, V2A, V3A}` = 4 of 4. Above the `2f+1 = 3` threshold. Live progress observed.
- Sub-quorum window: alive set `{V0, V1B}` = 2 of 4 in N=4. Strictly below `2f+1`. Reproduces the Run-017 boundary.
- Quorum-restore window: alive set `{V0, V1B, V2C}` = 3 of 4 in N=4. Numerically equal to `2f+1`. Same shape Run 016 proved sufficient for B14 to clear the absent-leader plateau, but with the *third* validator coming back via the explicit `--restore-from-snapshot` path — which is precisely the comparison Run 017 said was missing.
- V3 remained absent throughout. There is no other absent honest validator pretending to participate.

## 5. Commands and Configuration Used

The driver script is `/tmp/run018/run018.sh`. Representative exact node commands after expansion (env vars, listen addrs, peer lists, validator IDs, data dirs all explicit):

V0:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9850 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19850 \
  --p2p-peer 1@127.0.0.1:19851 \
  --p2p-peer 2@127.0.0.1:19852 \
  --p2p-peer 3@127.0.0.1:19853 \
  --p2p-mutual-auth required \
  --validator-id 0 \
  --data-dir /tmp/run018/data/v0 \
  > /tmp/run018/logs/v0.log 2>&1 &
```

V1A/V2A/V3A used the same command shape with validator IDs `1/2/3`, listen ports `19851/19852/19853`, metrics ports `9851/9852/9853`, corresponding peer lists, and data dirs `/tmp/run018/data/v1a`, `/tmp/run018/data/v2a`, `/tmp/run018/data/v3a`.

V1B restored:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9854 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19851 \
  --p2p-peer 0@127.0.0.1:19850 \
  --p2p-peer 2@127.0.0.1:19852 \
  --p2p-peer 3@127.0.0.1:19853 \
  --p2p-mutual-auth required \
  --validator-id 1 \
  --data-dir /tmp/run018/data/v1b \
  --restore-from-snapshot /tmp/run018/snap1 \
  > /tmp/run018/logs/v1b.log 2>&1 &
```

V2C compatible-restore (the new piece relative to Run 017's V2B):

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9855 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19852 \
  --p2p-peer 0@127.0.0.1:19850 \
  --p2p-peer 1@127.0.0.1:19851 \
  --p2p-peer 3@127.0.0.1:19853 \
  --p2p-mutual-auth required \
  --validator-id 2 \
  --data-dir /tmp/run018/data/v2c \
  --restore-from-snapshot /tmp/run018/snap2 \
  > /tmp/run018/logs/v2c.log 2>&1 &
```

The run scraped `http://127.0.0.1:9850/metrics`, `:9851`, `:9852`, `:9853`, `:9854`, and `:9855`. No LocalMesh process, harness-only recovery, fake timeout/NewView path, or mutual-auth fallback was used. `QBIND_MUTUAL_AUTH` was explicitly unset so the CLI flag is the sole source of mutual-auth mode.

## 6. Live-Cluster Pre-Restore Progress Evidence

Startup excerpts confirm the real binary P2P path and Required mutual auth (V0):

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=4 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)
```

V0 committed-anchor log shows healthy chain progression up to height 13 before the fault:

```text
[binary-consensus] committed_anchor height=0  block_id=00000000000000000000000000000000ffffffffffffffffffffffffffffffff
[binary-consensus] committed_anchor height=1  block_id=01000000…00000000
…
[binary-consensus] committed_anchor height=12 block_id=00000000000000000c0000000000000003000000000000000b00000000000000
[binary-consensus] committed_anchor height=13 block_id=01000000000000000d0000000000000000000000000000000c00000000000000
```

Live anchor metrics at `2026-05-08T13:26:53.448Z`:

| Metric | V0 | V1A | V2A | V3A |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 16 | 15 | 15 | 15 |
| `qbind_consensus_committed_height` | 13 | 12 | 12 | 12 |
| `qbind_consensus_qcs_formed_total` | 28 | 30 | 30 | 30 |
| `qbind_consensus_proposals_total{result="accepted"}` | 17 | (not separately shown) | (not separately shown) | (not separately shown) |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeouts_emitted_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_timeout_certificates_formed_total` | 0 | 0 | 0 | 0 |

V0 was started after V1A/V2A/V3A and shows the `B9+B10` late-peer-reemit footprint expected in this stagger, and reaches the committed prefix in normal flow. V1A/V2A/V3A briefly show slightly higher `qcs_formed_total` (30) but slightly lower `committed_height` (12) than V0 (28 / 13) because each engine's pipelined-HotStuff state has different exact tick alignment around the moment of the scrape; this is the same micro-asymmetry observed in Runs 015/016/017 and is not regression.

Answer A: **yes.** The live binary-path cluster progressed normally before the harsher shape was created.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor `SNAP1` was sourced from live V0 `/metrics` at `2026-05-08T13:26:53.485Z` (`/tmp/run018/scrapes/pre_v0`):

```text
qbind_consensus_current_view 16
qbind_consensus_committed_height 13
qbind_consensus_committed_block_info{block_id="01000000000000000d0000000000000000000000000000000c00000000000000"} 1
```

`SNAP1` metadata (`/tmp/run018/snap1/meta.json`):

```json
{
  "height": 13,
  "block_hash": "01000000000000000d0000000000000000000000000000000c00000000000000",
  "created_at_unix_ms": 1778246813486,
  "chain_id": 5855328520645203456
}
```

`SNAP1` file hashes:

```text
2f3bbdd7247600b9106c731328a0fde3224b2872e1b6c9b732147926b63746a9  /tmp/run018/snap1/meta.json
2dea8ae2060d398ad55b10dd9a74945e7c0e6eddbb3caf785f803cbf9aba2939  /tmp/run018/snap1/state/.placeholder.txt
```

`chain_id=5855328520645203456 = 0x51424e4444455600` matches the devnet chain id constant the binary expects.

V1B restore startup (`/tmp/run018/logs/v1b.log`):

```text
[restore] requested: snapshot_dir=/tmp/run018/snap1 data_dir=/tmp/run018/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=13 chain_id=0x51424e4444455600 bytes_copied=47 target=/tmp/run018/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run018/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=13 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=13, starting_view=14)
[binary-consensus] B5: applied restore baseline: snapshot_height=13 starting_view=14 (engine committed_height=Some(13))
```

V1B audit marker (`/tmp/run018/data/v1b/RESTORED_FROM_SNAPSHOT.json`):

```json
{"restored_at_unix_ms":1778246821515,"snapshot_dir":"/tmp/run018/snap1","target_state_dir":"/tmp/run018/data/v1b/state_vm_v0","bytes_copied":47,"snapshot_height":13,"snapshot_block_hash":"01000000000000000d0000000000000000000000000000000c00000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778246813486}
```

`SNAP2` was captured from a fresh V0 `/metrics` scrape immediately before V2C startup at `2026-05-08T13:28:06.809Z`. Because the cluster was sub-quorum during the entire window between SNAP1 and SNAP2, V0 had no opportunity to advance, so SNAP2 anchors the same height/block as SNAP1 (this is the property the binary preserves — the snapshot reflects the actual live committed state, not a fabricated one):

```json
{
  "height": 13,
  "block_hash": "01000000000000000d0000000000000000000000000000000c00000000000000",
  "created_at_unix_ms": 1778246886811,
  "chain_id": 5855328520645203456
}
```

`SNAP2` file hashes:

```text
a775d0d37358ccb6047b4ae4f90be637fbae0a3fc349de0e44a23c8630de4435  /tmp/run018/snap2/meta.json
2dea8ae2060d398ad55b10dd9a74945e7c0e6eddbb3caf785f803cbf9aba2939  /tmp/run018/snap2/state/.placeholder.txt
```

V2C restore startup (`/tmp/run018/logs/v2c.log`):

```text
[restore] requested: snapshot_dir=/tmp/run018/snap2 data_dir=/tmp/run018/data/v2c expected_chain_id=0x51424e4444455600
[restore] complete: height=13 chain_id=0x51424e4444455600 bytes_copied=47 target=/tmp/run018/data/v2c/state_vm_v0
[restore] audit marker written to /tmp/run018/data/v2c/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=13 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=13, starting_view=14)
[binary-consensus] B5: applied restore baseline: snapshot_height=13 starting_view=14 (engine committed_height=Some(13))
```

V2C audit marker (`/tmp/run018/data/v2c/RESTORED_FROM_SNAPSHOT.json`):

```json
{"restored_at_unix_ms":1778246886818,"snapshot_dir":"/tmp/run018/snap2","target_state_dir":"/tmp/run018/data/v2c/state_vm_v0","bytes_copied":47,"snapshot_height":13,"snapshot_block_hash":"01000000000000000d0000000000000000000000000000000c00000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778246886811}
```

Answers B/C: **yes.** Both `SNAP1` and `SNAP2` came from live peer state. V1B and V2C both started honestly from `S=13` and applied B5 with `snapshot_height=13, starting_view=14, engine committed_height=Some(13)` — neither pretends to already have post-S history.

## 8. Restore-Catchup Request / Response Evidence

Both V1B and V2C used the real P2P / Required path with the new identity / KEM closure (B7/B8/B12):

V1B:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=4 restore_baseline=true interconnect=p2p
[P2P] Dial 127.0.0.1:19850: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
```

V2C:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(2) node_id=NodeId(eadb48d7b679d681) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(2) num_validators=4 restore_baseline=true interconnect=p2p
[P2P] Dial 127.0.0.1:19851: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Dial 127.0.0.1:19850: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
```

Restore-catchup metrics over time, directly scraped from `/metrics`:

V1B:

| Time | `requests_sent_total` | `responses_received_total` | `blocks_applied_total` | `responses_rejected_total` | `mode_active` | `mode_exited_at_height` |
|---|---:|---:|---:|---:|---:|---:|
| `qr_t1` (V2C just started) | 69 | 72 | 144 | 0 | **1** | **0** |
| `qr_t6` | 94 | 148 | 296 | 0 | 1 | 0 |
| `qr_t12` | 124 | 238 | 476 | 0 | 1 | 0 |
| `qr_t24` | 184 | 418 | 836 | 0 | 1 | 0 |
| final | 189 | 433 | 866 | 0 | **1** | **0** |

V2C:

| Time | `requests_sent_total` | `responses_received_total` | `blocks_applied_total` | `responses_rejected_total` | `mode_active` | `mode_exited_at_height` |
|---|---:|---:|---:|---:|---:|---:|
| `qr_t1` | 4 | 7 | 14 | 0 | **1** | **0** |
| `qr_t6` | 29 | 82 | 164 | 0 | 1 | 0 |
| `qr_t12` | 59 | 174 | 348 | 0 | 1 | 0 |
| `qr_t24` | 119 | 354 | 708 | 0 | 1 | 0 |
| final | 124 | 369 | 738 | 0 | **1** | **0** |

V0 (the responder) confirms the receive-and-respond side:

| Time | `requests_received_total` | `responses_sent_total` | `responses_rejected_total` | `mode_active` |
|---|---:|---:|---:|---:|
| `qr_t1` | 70 | 70 | 0 | 0 |
| `qr_t6` | 121 | 121 | 0 | 0 |
| `qr_t24` | 301 | 301 | 0 | 0 |
| final | 311 | 311 | 0 | 0 |

V1B log (illustrative; the same line repeats throughout the run):

```text
[restore-catchup] applied 2 peer-learned certified blocks; committed_height=Some(13) view=16
[restore-catchup] applied 2 peer-learned certified blocks; committed_height=Some(13) view=16
…
```

Answer D: **yes.** Both V1B and V2C issued real binary-path `RestoreCatchupRequest` frames over P2P, V0 received and answered them on the real binary path, and zero responses were rejected. No LocalMesh / harness fallback occurred.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

This is the section where Run 018's narrow new boundary becomes visible.

V1B and V2C both received many real binary-path catchup responses. The `qbind_restore_catchup_blocks_applied_total` counter ticked up steadily for both restored nodes. However, neither restored node's `committed_height` ever advanced above the snapshot baseline of 13:

| Time | V0 `committed_height` | V0 `current_view` | V1B `committed_height` | V1B `current_view` | V2C `committed_height` | V2C `current_view` |
|---|---:|---:|---:|---:|---:|---:|
| pre-restore (V0 alone) | 13 | 16 | n/a | n/a | n/a | n/a |
| `subq_t1` (V1B just connected) | 13 | 16 | 13 | 16 | n/a | n/a |
| `subq_t12` (end of sub-quorum) | 13 | 16 | 13 | 16 | n/a | n/a |
| `qr_t1` (V2C just connected) | 13 | 16 | 13 | 16 | 13 | 16 |
| `qr_t6` | 13 | 16 | 13 | 16 | 13 | 16 |
| `qr_t12` | 13 | 16 | 13 | 16 | 13 | 16 |
| `qr_t24` | 13 | 16 | 13 | 16 | 13 | 16 |
| final | 13 | 16 | 13 | 16 | 13 | 16 |

The reason — supported directly by the source — is the B13 exit predicate in `crates/qbind-node/src/binary_consensus_loop.rs`:

```rust
// Require strict progress above the snapshot baseline. This
// prevents flipping "caught up" purely on the restored prefix
// when no peer-learned material has actually been applied.
if let Some(base) = self.snapshot_baseline_height {
    if local_height <= base {
        return None;
    }
}
```

In Run 017, V0 advanced from `S=12` to `H=14` on residual in-flight certified material before SIGINT-of-V1A/V2A/V3A took effect. Therefore V1B's restore-catchup target (`peer_max_observed_committed_height`) became `14`, and V1B's `local_height=14 > base=12`, so V1B exited B13 cleanly. In Run 018, V0 was started **after** V1A/V2A/V3A (deliberately, to make the snapshot capture immediately-fresh and reproducible), and the SIGINTs landed before any further commit could pipeline through V0. V0 stayed at `H=13`. So when V1B's catchup completed against V0, `peer_max_observed_committed_height = 13`, `local_height = 13`, `base = 13`, and the strict `local_height <= base` gate keeps `active=true` indefinitely. V2C, sourced from `SNAP2` which is also at `H=13`, hits the same gate.

Answers E/F: **partial.** Both restored nodes did receive and *apply* real peer-learned material on the binary path (`blocks_applied_total` is nonzero and monotonically increasing). However, **`committed_height` never advanced above the snapshot baseline `S=13`** for either restored node, because the only continuously-alive peer (V0) was itself in sub-quorum during the SNAP1 anchoring instant and could not advance to provide a strictly-higher target. This is materially different from Run 017, where V1B did advance to `H=14`.

## 10. Restore-Mode Exit Evidence

`qbind_restore_catchup_mode_active` stays at `1` and `qbind_restore_catchup_mode_exited_at_height` stays at `0` for **both** V1B and V2C across every scrape:

| Time | V1B `mode_active` | V1B `exited_at_height` | V2C `mode_active` | V2C `exited_at_height` |
|---|---:|---:|---:|---:|
| `qr_t1` | 1 | 0 | 1 | 0 |
| `qr_t6` | 1 | 0 | 1 | 0 |
| `qr_t12` | 1 | 0 | 1 | 0 |
| `qr_t24` | 1 | 0 | 1 | 0 |
| final | **1** | **0** | **1** | **0** |

There is no `[restore-catchup] exit:` line in either V1B's or V2C's log — by direct inspection of `/tmp/run018/logs/v1b.log` and `/tmp/run018/logs/v2c.log`. (Compare Run 017 V1B, which logged `[restore-catchup] exit: caught up to peer anchor — local committed_height=14 peer_max_observed=Some(14); …`.)

Answer G: **no.** B13 restore-catchup mode did **not** exit in this run on either restored node. The B13 mechanism itself is honest — it correctly refuses to flip "caught up" purely on the restored prefix — but the exit predicate's strict-progress-above-baseline guard interacts with the snapshot-from-sub-quorum-peer scenario in a way that leaves the restored nodes permanently in catchup mode.

## 11. Direct B14 `/metrics` Timeout / New-View Evidence

B14 counters were directly scraped from `/metrics`. During the sub-quorum window (V0 + V1B alive in N=4):

| Time | Node | `current_view` | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `outbound_new_views_sent_total` | `inbound_new_views_engine_accepted_total` | `view_timeout_advances_total` |
|---|---|---:|---:|---:|---:|---:|---:|
| pre-restore (V0 alone) | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `subq_t1` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `subq_t1` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |
| `subq_t6` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `subq_t6` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |
| `subq_t12` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `subq_t12` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |

V1B's `view_timeouts_emitted_total` stays at zero because V1B is in restore-catchup mode and B14's gate `restore_mode.is_active() == false` is not satisfied. This is by design (`crates/qbind-node/src/binary_consensus_loop.rs`, B14 emission gates: "we never time out a view we are still catching up to from a snapshot"). V0 emitted exactly one `TimeoutMsg` for `view=16` on the real binary path; this is visible in `logs/v0.log`:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=16 after 50 ticks of no progress
```

After V2C joined (alive set = 3 of 4):

| Time | Node | `current_view` | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `outbound_new_views_sent_total` | `inbound_new_views_engine_accepted_total` | `view_timeout_advances_total` |
|---|---|---:|---:|---:|---:|---:|---:|
| `qr_t1` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `qr_t1` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t1` | V2C | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t6` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `qr_t6` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t6` | V2C | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t12` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `qr_t12` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t12` | V2C | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t24` | V0 | 16 | 1 | 0 | 0 | 0 | 0 |
| `qr_t24` | V1B | 16 | 0 | 0 | 0 | 0 | 0 |
| `qr_t24` | V2C | 16 | 0 | 0 | 0 | 0 | 0 |
| final | V0 | 16 | **1** | **0** | **0** | **0** | **0** |
| final | V1B | 16 | **0** | **0** | **0** | **0** | **0** |
| final | V2C | 16 | **0** | **0** | **0** | **0** | **0** |

There were also zero `decode_failures_total`, zero `engine_rejects_total` for all three nodes throughout — the B14 path is exercised honestly, not silently failing. V0's already-emitted timeout for view 16 is single-shot per view (`engine.timeout_emitted_in_view() == false` gate), so the counter does not increase further while the cluster is parked at view 16.

Answer H: **partial.** B14 counters are directly visible on `/metrics` and showed real activity (V0's one timeout emission is honest). But neither V1B nor V2C ever exited restore-catchup mode, so neither emitted a timeout, so V0 was the only validator emitting B14 timeout material at all, so no `2f+1` timeout cohort could be formed. `qbind_consensus_timeout_certificates_formed_total`, `qbind_consensus_outbound_new_views_sent_total`, `qbind_consensus_inbound_new_views_engine_accepted_total`, and `qbind_consensus_view_timeout_advances_total` all remained at zero across all three nodes for the full quorum-restore observation window.

## 12. Quorum-Restored Recovery Outcome Evidence

Final loop-exit lines (from logs):

```text
V0:  [binary-consensus] Loop exit: ticks=1999 proposals=5 commits=14 committed_height=Some(13) view=16 inbound_msgs=618 inbound_proposals=13 inbound_votes=49 outbound_proposals=5 outbound_votes=17 outbound_proposal_late_peer_reemits=1
V1B: [binary-consensus] Loop exit: ticks=1889 proposals=0 commits=0 committed_height=Some(13) view=16 inbound_msgs=558 inbound_proposals=1  inbound_votes=1  outbound_proposals=0 outbound_votes=0  outbound_proposal_late_peer_reemits=0
V2C: [binary-consensus] Loop exit: ticks=1236 proposals=1 commits=0 committed_height=Some(13) view=16 inbound_msgs=492 inbound_proposals=0  inbound_votes=0  outbound_proposals=1 outbound_votes=1  outbound_proposal_late_peer_reemits=1
```

V0's `proposals=5 commits=14` reflects entirely pre-fault progression (5 proposals it issued and 14 commits applied while the live cluster was alive, before fault injection); after the fault, V0 issued no new proposals and committed nothing. V1B's `proposals=0 commits=0` reflects that V1B never reached normal participation. V2C's `proposals=1 commits=0` reflects exactly one bounded view-0 broadcast on connect (B9+B10 footprint visible in `/tmp/run018/logs/v2c.log`: `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect`); V2C produced no further proposals after that.

Final scrape comparison across all three nodes:

| Node | Final `committed_height` | Final `current_view` | Final `qcs_formed_total` | Final accepted proposals | Final B14 TCs | Final B13 `mode_active` |
|---|---:|---:|---:|---:|---:|---:|
| V0 | 13 | 16 | 29 | 17 | 0 | 0 (never restored) |
| V1B | 13 | 16 | 1 | 0 | 0 | **1** |
| V2C | 13 | 16 | 0 | 1 | 0 | **1** |

Answers I/J/K/L:

- **I.** During the sub-quorum phase, the alive set was insufficient to form timeout certificates: only V0 emitted a timeout (V1B was in restore-catchup and B14-suppressed), and `2f+1 = 3` timeout cohorts cannot form from a single emitter. This is consistent with Run 017.
- **J.** Once the third validator (V2C) was restored compatibly, **no** timeout certificate formed across an additional ~120 s of observation (24 scrapes). `qbind_consensus_timeout_certificates_formed_total` stayed at 0 for all three nodes.
- **K.** `current_view` did **not** advance off `view=16` on any node.
- **L.** Normal proposal/vote/QC/commit progression did **not** resume automatically. `committed_height` stayed at 13 on all three nodes; no new QCs formed (V0 stayed at 29, V1B at 1, V2C at 0); no new accepted proposals (V0 stayed at 17, V1B at 0, V2C at 1 — and that single accepted on V2C is the post-baseline self-acknowledgement that B5 does on entry, not normal pipelined HotStuff progress).
- **M.** **Narrowest exact remaining boundary supported by the evidence:** B14 view-change recovery requires at least `2f+1` validators that are *both* (i) cryptographically/identity-compatible (Required-mode KEM identities), and (ii) actually in normal participation — i.e., **out of B13 restore-catchup mode**. Two restored validators stuck at `mode_active=1` count toward presence on the wire but do **not** count toward the `2f+1` timeout cohort because they are gated out of B14 emission. Run 018 isolates a precise sub-condition for "in normal participation": the B13 strict-progress-above-baseline exit predicate requires `local_committed_height > snapshot_baseline_height`, which is **not** achievable when the only continuously-alive peer cannot itself advance above the snapshot height (because that peer is itself in sub-quorum and parked).

The boundary can be stated even more narrowly: **a snapshot anchor whose `block_hash`/`height` exactly equals the responder's current `committed_height` at restore time produces a B13-permanent-active state for the restored validator if no validator in the alive set ever advances above that height before quorum is restored.** This is a correctness-preserving design choice — B13 explicitly refuses to flip "caught up" purely on the restored prefix — but Run 018 is the first run where this guard manifests as a recovery boundary, because Run 017's V0 happened to advance to `H=14` from in-flight pipelined material between fault injection and snapshot consumption.

## 13. Shutdown Evidence

Shutdown events (`/tmp/run018/timeline.log`):

```text
2026-05-08T13:30:10.300Z FINAL_SCRAPE
2026-05-08T13:30:10.322Z v1b SIGINT pid=10052
2026-05-08T13:30:10.326Z v2c SIGINT pid=10153
2026-05-08T13:30:10.330Z v0  SIGINT pid=9976
2026-05-08T13:30:13.350Z RUN018_END
```

Representative shutdown logs:

```text
V0:  [binary] Shutdown signal received, stopping P2P node...
V0:  [binary-consensus] Shutdown signal received after 1999 ticks.
V0:  [binary] Shutdown complete.
V1B: [binary] Shutdown signal received, stopping P2P node...
V1B: [binary-consensus] Shutdown signal received after 1889 ticks.
V1B: [binary] Shutdown complete.
V2C: [binary] Shutdown signal received, stopping P2P node...
V2C: [binary-consensus] Shutdown signal received after 1236 ticks.
V2C: [binary] Shutdown complete.
```

Post-SIGINT process check (no qbind-node processes survived):

```text
UID          PID    PPID  C STIME TTY      STAT   TIME CMD
```

Answer N: **yes.** `/metrics` remained honest throughout (timeout emissions reported only when actually emitted; zero fabricated TCs/NewViews/advances; B13 active flag remained 1 because B13 was actually still active; no fabricated QC/commit progress). Answer O: **yes.** Shutdown remained clean.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 018 observation | Assessment |
|---|---|---|
| B3 restore startup | V1B applied `/tmp/run018/snap1` and V2C applied `/tmp/run018/snap2`; both wrote `RESTORED_FROM_SNAPSHOT.json` audit markers; both used live-sourced `snapshot_height=13` / block hash `01000000…00000000` and `chain_id=0x51424e4444455600` | not regressed |
| B5 restore-aware baseline | V1B logged `B5: applied restore baseline: snapshot_height=13 starting_view=14 (engine committed_height=Some(13))`; V2C logged the identical line | not regressed |
| B6 P2P routing | live cluster progressed via P2P; V1B and V2C both connected to V0 over P2P; V1B/V2C exchanged restore-catchup frames with V0 over P2P (`requests_received_total=311` on V0 final scrape) | not regressed |
| B7/B8 identity and bounded dial behavior | P2P dials logged `pk_len=32, has_vid=true` on V0/V1B/V2C; bounded retry on V1B/V2C dials of absent V3A visible in logs (`dial 127.0.0.1:19853 attempt N/8 failed`); Required mode used deterministic validator identities | not regressed |
| B9/B10 late-peer reemit | V0 logged one bounded view-0 reemit during live startup; V2C logged the same bounded reemit on connect | not regressed |
| B12 Required mode | every node used `--p2p-mutual-auth required`; logs show `B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` and `mutual_auth=Required` on all six node startups | not regressed |
| bounded restore-catchup | both V1B and V2C sent real binary-path `RestoreCatchupRequest` frames, received responses, applied peer-learned material; zero `responses_rejected_total`; no LocalMesh fallback | not regressed; **actively exercised** |
| B13 transition | B13 honestly reported `mode_active=1` for both restored nodes throughout the run; no `[restore-catchup] exit:` lines emitted; behavior is consistent with the source's strict-progress-above-baseline guard | **not regressed; the new boundary is a property of the existing predicate, not new buggy behavior** |
| B14 `/metrics` exports | direct counters exposed exactly the V0 single-emission, zero TCs, zero NewViews, zero advances; `decode_failures_total=0`, `engine_rejects_total=0` | not regressed; actively exercised |
| No LocalMesh/harness fallback | every node ran with `--network-mode p2p --enable-p2p`; no LocalMesh recovery path; no harness-only timeout/NewView injection | satisfied |
| Metrics honesty | `/metrics` matched logs exactly: V0 timeouts emitted=1 ↔ one `B14: emitted TimeoutMsg for view=16` log line; `mode_active=1` ↔ no exit log line; zero fabricated TCs / NewViews / view advances / QC / commit progress | satisfied |

Answer P: **no previously landed binary-path capability appears regressed.** The new boundary surfaced by Run 018 is a property of the *existing* B13 strict-progress-above-baseline gate (which is itself a deliberate correctness feature, not a defect) interacting with a snapshot anchor whose responder is itself parked.

## 15. Limitations and Anomalies Observed

- This is a single execution, not a statistical soak.
- The cluster pre-fault committed prefix in this run reached only `H=13` before the snapshot capture (Run 017 reached `H=12` at snapshot capture but V0 then independently advanced to `H=14` from in-flight material before V1B caught up). This is a normal pipelined-HotStuff timing artifact, not a regression. It is, however, the proximate cause of the Run-018 narrow boundary (see §12.M).
- The `/tmp/run018/snap1/state/.placeholder.txt` and `/tmp/run018/snap2/state/.placeholder.txt` files are non-empty stand-ins for a real RocksDB checkpoint; this matches Run 017's snapshot construction and is consistent with `validate_snapshot_dir`'s requirement that `state/` be non-empty. Production fast-sync / consensus-storage restore is still outstanding (existing C4 item).
- Production signature verification for timeout payloads, exponential-backoff timeout pacing, and production PQC KEMTLS root-key distribution remain outside this run.
- V2C's loop counter shows `proposals=1 outbound_proposals=1` and `outbound_votes=1`. This is the bounded view-0 BroadcastProposal/BroadcastVote re-emission triggered by the late-peer-connect handler at the moment V2C's first peer (V1B) connected. It does not represent normal HotStuff proposal/vote progression. After that one bounded reemit, V2C produced no further proposals or votes for the rest of the run — consistent with V2C being permanently in B13 restore-catchup mode.
- V3 remained absent throughout. There is no other absent honest validator pretending to participate.

Answer Q (limitations remaining): production fast-sync / consensus-storage restore (so that a third validator's `snapshot_baseline_height` can include peer-confirmed post-S progress without depending on residual in-flight material at the live peer); B13 strict-progress guard interaction with the immediately-fault-injected case; production signature-verified timeout-cert pacing; production PQC KEMTLS root-key distribution. None of these are introduced by Run 018; Run 018 only sharpens the B13 sub-item.

## 16. Assessment of Evidence Value

Run 018 materially narrows the post-Run-017 boundary, but **not** in the direction Run 017 hoped. Run 017 had outlined the recovery hypothesis: "restoring the third validator with an honest snapshot baseline should produce a true `2f+1` compatible quorum, at which point B14 should resume forward consensus automatically." Run 018 honestly executed that exact shape and found that **the B13 exit predicate, not just B14 cohort size, is the binding constraint** when the snapshot anchor matches the responder's parked height. Specifically:

- Run 016 proved B14 recovers the absent-leader plateau when three of four validators are alive and *in normal participation*.
- Run 017 proved that two of four validators in N=4 cannot form timeout certificates regardless of B14 wiring. It also flagged that V2B's empty-state return did not prove anything about quorum-restored recovery.
- **Run 018** proves that even when three of four validators are alive *and the third is brought back via the explicit, supported `--restore-from-snapshot` path*, B14 recovery does **not** automatically resume if the restored validators are stuck in B13 restore-catchup mode because the snapshot anchor was sourced from a peer whose own committed height equals the snapshot height and whose own progression is itself blocked by sub-quorum.

This is a positive negative finding — clean and narrow. It identifies a specific, addressable boundary:

1. The narrowest reproducible mitigation is operational: avoid sourcing the snapshot anchor while the live cluster is sub-quorum AND the responder is parked at the snapshot height. In practice, the live cluster must commit at least one block above the captured anchor before the third validator's restore is allowed to begin.
2. Alternatively, B13's exit predicate could be relaxed for the strict-equality case once the responder is observed to be itself stable at the same height for some bounded number of ticks. That would be a code change, out of Run-018 scope.
3. Production fast-sync / consensus-storage restore (the still-open part of C4) would naturally subsume this: a restored validator that imports certified-block proof up to some height `H_cert > snapshot_height` would pass the B13 strict-progress guard immediately.

Because Run 018 reveals a genuinely new, narrower failure mode that was not visible in Run 017 (Run 017's V1B exited B13 cleanly at `H=14`), `docs/whitepaper/contradiction.md` is updated in this task to sharpen C4 with the B13-strict-progress-above-baseline interaction. The update is a narrowing/clarification, not a new contradiction.

Run 018 evidence value summary: **partial, comparison-friendly, conservatively scoped, no regression of prior milestones, isolates a previously-invisible narrow B13 boundary, leaves the broader question of fast-sync / consensus-storage restore exactly where Run 017 left it.**

## 17. Recommended Immediate Next Action

Execute Run 019 as a narrow disambiguation of the B13 strict-progress boundary surfaced by this run, on the same binary, without code changes:

- Repeat the Run-018 shape, but ensure the live cluster has produced **at least two committed blocks above the captured snapshot anchor** before V1B is started. The minimal way to do this is to start V0 first, let V0+V1A+V2A+V3A reach `H ≥ S+2`, capture the snapshot anchor at `S` from V0 `/metrics`, then SIGINT V1A/V2A/V3A.
- Confirm whether under that revised stagger V1B and V2C both exit B13 (`mode_active` flips to `0`, `mode_exited_at_height` becomes nonzero, `[restore-catchup] exit:` log line appears), and whether B14 timeout certificates then form and `current_view` advances once V2C joins.

If Run 019 confirms quorum-restored recovery under the revised stagger, the Run-017 follow-up question is closed positively for B14 modulo the B13-strict-progress operational requirement, and the next true open boundary is production consensus-storage / fast-sync restore (already open in C4). If Run 019 still does not show forward consensus, the next candidate boundary would be the absence of signature-verified timeout-cert pacing, which is also already an open C4 item and would be the appropriate next focused execution.

Do not broaden Run 019 into a redesign of B13 or a new sync framework. The narrow-stagger reproducibility fix above is sufficient to isolate the next true binary-path boundary.