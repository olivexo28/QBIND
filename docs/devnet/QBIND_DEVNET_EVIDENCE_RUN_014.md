# QBIND DevNet Evidence Run 014

## 1. Purpose and Scope

Run 014 is a narrow real-binary follow-up to Run 013. It asks one question only:

> When we deliberately recreate the Run-012-style timing shape (live cluster reaches a non-trivial view; the to-be-restored peer is then absent so the live peer cannot make further progress alone; the restored node is started from a low snapshot anchor `S` and must catch up across that idle gap), does QBIND on the real binary path with B13 landed:
>
> (i) exit bounded restore-catchup mode after catching up, and
> (ii) resume normal forward proposal / vote / QC / commit progression in that specifically-deadlocked predecessor-view shape — or does the run isolate a remaining narrower missing primitive (binary-path view-timeout / view-change, responder-side pending-proposal piggyback on `RestoreCatchupResponse`, or another)?

Scope:

- two real release `qbind-node` binaries (no LocalMesh, no harness recovery);
- P2P mode, `--p2p-mutual-auth required` on every node;
- real `--restore-from-snapshot` startup for the restored node;
- live-sourced snapshot anchor from `/metrics`;
- real `ConsensusNetMsg::RestoreCatchupRequest` / `RestoreCatchupResponse` traffic;
- B13 transition state machine actually exercised on the wire;
- a 280-second post-restore observation window so we can distinguish "no recovery", "recovery only after a fresh proposal path appears", and "full automatic recovery from the deadlocked predecessor-view shape".

Verdict: **POSITIVE for the narrow Run-014 question, partial for the broader C4 boundaries it does not address.** In the recreated deadlocked-shape timing, V1B restored honestly from `S=43`, requested and received real catchup responses, applied 245 peer-learned certified blocks across two responses, exited bounded restore-catchup mode at `committed_height=284` (which is exactly the height V0 had been parked at while idle), stopped issuing fresh restore-catchup requests, and then resumed normal proposal/vote/QC/commit progression all the way to `committed_height=2956` / `current_view=2959` before clean shutdown. The narrowest remaining gap that was *not* exercised by this run is described in §15. Run 014 does **not** prove production fast-sync / consensus-storage restore, production PQC KEMTLS root-key distribution, or the `4-of-N`-style shape where the leader for the next view is the still-absent validator and there is no late-peer-reemit edge to fall back on.

No code was changed for this run. The binary is identical to the Run-013 binary (same sha256, same Build ID). This is observation-only on already-landed B13.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_013.md` — bounded non-deadlocked B13 exit and resumed forward progression on real binaries.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_012.md` — original plateau: V1B reached `committed_height=339` then never resumed forward QC formation; the reference shape this run intentionally recreates.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_011.md` — earlier bounded restore-catchup evidence.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010B.md` — positive two-node binary-path proposal/vote/QC/commit progression under Required mode.
- `docs/whitepaper/contradiction.md` — current C4 (B13 landed; deadlocked predecessor-view boundary noted).
- Code (no change in this run, observation only):
  - `crates/qbind-node/src/binary_consensus_loop.rs` — `RestoreCatchupModeState` (B13 transition gates).
  - `crates/qbind-node/src/metrics.rs` — `qbind_restore_catchup_*` family + `qbind_consensus_committed_*` family.

Validation before execution:

```sh
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node
```

Result:

```text
warning: `qbind-node` (lib) generated 1 warning (run `cargo fix --lib -p qbind-node` to apply 1 suggestion)
    Finished `release` profile [optimized] target(s) in 5m 05s
```

The pre-existing `unused variable: worker_id` warning in `crates/qbind-node/src/verify_pool.rs` is the same warning Runs 012 and 013 already record.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-predecessor-view-recovery` |
| HEAD | `c062f672db0fd896af80fa230c517f17b74824d9` |
| Build command | `cargo build --release -p qbind-node --bin qbind-node` |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9134784` bytes |
| Binary sha256 | `d2a8dd971fb3d428b3592187370ce80623587b76693f1901170d0072cc33df8c` |
| Binary Build ID | `788f79ed54933eae0eb984924f45c3085bb67dd7` |
| Run directory | `/tmp/run014` |
| Script start UTC | `2026-05-08T07:11:46.857Z` |
| Script end UTC | `2026-05-08T07:17:22.119Z` |
| `QBIND_MUTUAL_AUTH` | unset; CLI `--p2p-mutual-auth required` was used |

Note: the binary sha256 and Build ID are identical to Run 013, confirming this is the same compiled artifact and that the only variable across the two runs is the deliberately-different timing shape described in §4.

## 4. Topology, Timing, and Node Configuration Used

| Node | Phase | Validator | Listen | Static peer | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---|---|---|---|---|---|---|---|
| V0  | whole run        | `ValidatorId(0)` | `127.0.0.1:19340` | `1@127.0.0.1:19341` | `required` | `/tmp/run014/data/v0`  | `127.0.0.1:9340` | none |
| V1A | live pre-restore | `ValidatorId(1)` | `127.0.0.1:19341` | `0@127.0.0.1:19340` | `required` | `/tmp/run014/data/v1a` | `127.0.0.1:9341` | none |
| V1B | restored         | `ValidatorId(1)` | `127.0.0.1:19341` | `0@127.0.0.1:19340` | `required` | `/tmp/run014/data/v1b` | `127.0.0.1:9342` | `/tmp/run014/snap` |

Recreated-deadlock timing (actual, from `/tmp/run014/timeline.txt`):

| Event | UTC |
|---|---|
| `RUN014_START` | `2026-05-08T07:11:46.857Z` |
| `V0_START`     | `2026-05-08T07:11:46.859Z` |
| `V1A_START` (T+10s) | `2026-05-08T07:11:56.862Z` |
| `ANCHOR_CAPTURE_UTC` (S=43, height/block from V0 `/metrics`) | `2026-05-08T07:12:01.879Z` |
| `PRE_STOP_HOLD_END` (live cluster pushed past S) | `2026-05-08T07:12:26.906Z` |
| `V1A_STOP` (V0 alone; cannot form QC) | `2026-05-08T07:12:26.922Z` |
| `DEADLOCK_HOLD_END` (15s idle so V0 settles into stuck-view shape) | `2026-05-08T07:12:41.932Z` |
| `V1B_START` (`--restore-from-snapshot $SNAP`) | `2026-05-08T07:12:41.934Z` |
| Final scrape (`t=280s`) | `2026-05-08T07:17:22.040Z` |
| `V1B_STOP` (SIGINT) | `2026-05-08T07:17:22.114Z` |
| `V0_STOP`  (SIGINT) | `2026-05-08T07:17:22.117Z` |
| `RUN014_END` | `2026-05-08T07:17:22.119Z` |

The shape that distinguishes Run 014 from Run 013 is the explicit *deadlock hold*: V1A is stopped, V0 is then held alone for 15 seconds with no co-validator and so cannot form any new QC (2-of-2 quorum); only after that idle settling does V1B start. This is the closest faithful recreation of the Run-012 timing on the same binary that ran Run 013.

All nodes logged `network=p2p`, `interconnect=p2p`, `num_validators=2`, and `mutual_auth=Required`. No LocalMesh or Disabled mutual-auth fallback was used.

## 5. Commands and Configuration Used

The full executed script is preserved at `/tmp/run014.sh`. Key fragments:

Environment metadata (paraphrased — same shape as Runs 012/013):

```sh
cd /home/runner/work/QBIND/QBIND
{
  echo "SCRIPT_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  echo "HOST=$(hostname)"
  uname -a
  rustc --version
  cargo --version
  git --no-pager rev-parse HEAD
  stat -c 'BIN_SIZE=%s' target/release/qbind-node
  sha256sum target/release/qbind-node
  readelf -n target/release/qbind-node | grep 'Build ID'
}
```

V0 command:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9340 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 0 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19340 \
  --p2p-peer 1@127.0.0.1:19341 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run014/data/v0 \
  > /tmp/run014/logs/v0.log 2>&1 &
```

V1A command (10s after V0):

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9341 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19341 \
  --p2p-peer 0@127.0.0.1:19340 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run014/data/v1a \
  > /tmp/run014/logs/v1a.log 2>&1 &
```

Snapshot anchor sourced from live V0 `/metrics` (the `qbind_consensus_committed_block_info{block_id=...}` line at the moment of the anchor scrape):

```json
{
  "height": 43,
  "block_hash": "01000000000000002b0000000000000000000000000000002a00000000000000",
  "created_at_unix_ms": 1778224321888,
  "chain_id": 5855328520645203456
}
```

Snapshot file hashes:

```text
cfe3083da350336d132c7584231fc07efe16142c828823482272d6aaf2bc2d50  /tmp/run014/snap/meta.json
f4f476a377f9c1c2c25f0f1574e5237cdaa3b07797ccf6455b95442a383e2ece  /tmp/run014/snap/state/.placeholder.txt
```

V1B restored command (started 25s after V1A stop, 15s into the explicit deadlock hold):

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9342 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19341 \
  --p2p-peer 0@127.0.0.1:19340 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run014/data/v1b \
  --restore-from-snapshot /tmp/run014/snap \
  > /tmp/run014/logs/v1b.log 2>&1 &
```

Metrics scraped from:

- `http://127.0.0.1:9340/metrics`
- `http://127.0.0.1:9341/metrics`
- `http://127.0.0.1:9342/metrics`

Periodic post-restore scrapes at `t = 5, 10, 20, 40, 80, 140, 200, 280` seconds (saved as `v0_t<N>.txt` / `v1b_t<N>.txt` under `/tmp/run014/scrapes/`), plus `_anchor_capture`, `_pre_stop`, `_after_v1a_stop`, and `_final` scrapes.

## 6. Live-Cluster Pre-Restore Progress Evidence

V0 startup excerpt:

```text
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 ... network=p2p p2p=enabled listen=127.0.0.1:19340 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

V1A startup excerpt:

```text
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 ... network=p2p p2p=enabled listen=127.0.0.1:19341 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

Pre-restore metrics:

| Metric | V0 anchor scrape | V0 pre-stop | V1A pre-stop | V0 after V1A stop |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view`            | 46 | 286 | (alive) | 287 |
| `qbind_consensus_qcs_formed_total`        | 46 | 286 | (alive) | 287 |
| `qbind_consensus_committed_height`        | 43 | 283 | (alive) | 284 |
| `qbind_consensus_view_lag`                | 0  | 0   | 0       | 0   |
| `consensus_net_inbound_total{kind="vote"}`     | 46 | 286 | (alive) | 287 |
| `consensus_net_inbound_total{kind="proposal"}` | 23 | 143 | (alive) | 143 |
| `qbind_consensus_proposals_total{result="accepted"}` | 47 | 287 | (alive) | 287 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0  | 0   | 0       | 0   |

After V1A stop, V0 settles at `committed_height=284`, `current_view=287`, and stays there for the full 15s deadlock hold (V0 alone cannot form fresh QCs in 2-of-2). This is the recreated Run-012 plateau shape: a peer that the restored node will need to catch up to, sitting on a stale view with no co-validator to drive it forward.

Answer A (live binary-path cluster progressed normally before deadlock-shape recreation): **yes.** Proposals, votes, QCs, views, and commits advanced under real P2P Required mode; the live cluster reached `committed_height=283 / current_view=286` before V1A was stopped.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor provenance:

```text
ANCHOR_SOURCE=/metrics on live V0
ANCHOR_HEIGHT=43
ANCHOR_BLOCK=01000000000000002b0000000000000000000000000000002a00000000000000
ANCHOR_CAPTURE_UTC=2026-05-08T07:12:01.879Z
```

Live V0 anchor scrape excerpt:

```text
qbind_consensus_current_view 46
qbind_consensus_qcs_formed_total 46
qbind_consensus_committed_height 43
qbind_consensus_committed_block_info{block_id="01000000000000002b0000000000000000000000000000002a00000000000000"} 1
```

V1B startup excerpt (from `/tmp/run014/logs/v1b.log`):

```text
[restore] requested: snapshot_dir=/tmp/run014/snap data_dir=/tmp/run014/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=43 chain_id=0x51424e4444455600 bytes_copied=79 target=/tmp/run014/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run014/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=43 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=43, starting_view=44)
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=true interconnect=p2p
[binary-consensus] B5: applied restore baseline: snapshot_height=43 starting_view=44 (engine committed_height=Some(43))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=true interconnect=p2p late_peer_reemit=on
```

Audit marker written by V1B:

```json
{"restored_at_unix_ms":1778224361936,"snapshot_dir":"/tmp/run014/snap","target_state_dir":"/tmp/run014/data/v1b/state_vm_v0","bytes_copied":79,"snapshot_height":43,"snapshot_block_hash":"01000000000000002b0000000000000000000000000000002a00000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778224321888}
```

Answer B: yes, the snapshot anchor was sourced from live peer state via V0 `/metrics`.

Answer C: yes, V1B started honestly from `S=43`. The B5 line `engine committed_height=Some(43)` and `starting_view=44` match the snapshot, and the audit marker records the same `(height, block_hash, chain_id)`. V1B did not pretend to already have post-S history.

## 8. Restore-Catchup Request / Response Evidence

Restore-catchup counters at the first post-restore scrape (`t=5s`) and at final:

| Metric | V0 first post-restore | V1B first post-restore | V0 final | V1B final |
|---|---:|---:|---:|---:|
| `qbind_restore_catchup_requests_sent_total`     | 0 | 3   | 0 | 3   |
| `qbind_restore_catchup_requests_received_total` | 2 | 0   | 2 | 0   |
| `qbind_restore_catchup_responses_sent_total`    | 2 | 0   | 2 | 0   |
| `qbind_restore_catchup_responses_received_total`| 0 | 2   | 0 | 2   |
| `qbind_restore_catchup_blocks_applied_total`    | 0 | 245 | 0 | 245 |
| `qbind_restore_catchup_responses_rejected_total`| 0 | 0   | 0 | 0   |
| `consensus_net_inbound_total{kind="other"}`     | 2 | 2   | 2 | 2   |

V1B restore-catchup log lines:

```text
[P2P] Dial 127.0.0.1:19340: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
[restore-catchup] applied 128 peer-learned certified blocks; committed_height=Some(169) view=172
[restore-catchup] applied 117 peer-learned certified blocks; committed_height=Some(284) view=287
[restore-catchup] exit: caught up to peer anchor — local committed_height=284 peer_max_observed=Some(284); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

V0 reciprocal counters confirm it received and answered the requests.

Answer D: yes. V1B issued real `RestoreCatchupRequest` frames and received real `RestoreCatchupResponse` frames on the binary path. V0's reciprocal counters confirm it received and answered them.

Answer E: yes. V1B validated and applied learned post-S material: `qbind_restore_catchup_blocks_applied_total=245` (split as 128 + 117 across two responses, confirmed in the log), with `qbind_restore_catchup_responses_rejected_total=0`. No malformed/inconsistent payload drove the transition.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

Learned-suffix progression:

| Step | Evidence | V1B `committed_height` | V1B `current_view` |
|---|---|---:|---:|
| Restore baseline | B5 startup | 43  | 44  |
| First catchup response  | `applied 128 peer-learned certified blocks` | 169 | 172 |
| Second catchup response | `applied 117 peer-learned certified blocks` | 284 | 287 |
| First post-exit forward commit (log)   | `committed_anchor height=285 …` (then 286, 287, 288 …) | 285+ | 288+ |
| Scrape `t=10s`  | `/metrics` | 358  | 361  |
| Scrape `t=40s`  | `/metrics` | 648  | 651  |
| Scrape `t=80s`  | `/metrics` | 1032 | 1035 |
| Scrape `t=140s` | `/metrics` | 1608 | 1611 |
| Scrape `t=200s` | `/metrics` | 2186 | 2189 |
| Scrape `t=280s` | `/metrics` | 2956 | 2959 |
| Final           | `/metrics` | 2956 | 2959 |

V1B post-exit log excerpt:

```text
[binary-consensus] committed_anchor height=284 block_id=00000000000000001c0100000000000001000000000000001b01000000000000
[binary-consensus] committed_anchor height=285 block_id=01000000000000001d0100000000000000000000000000001c01000000000000
[binary-consensus] committed_anchor height=286 block_id=00000000000000001e0100000000000001000000000000001d01000000000000
[binary-consensus] committed_anchor height=287 block_id=01000000000000001f0100000000000000000000000000001e01000000000000
[binary-consensus] committed_anchor height=288 block_id=0000000000000000200100000000000001000000000000001f01000000000000
…
```

Answer F: yes. Committed height advanced above `S=43` first to `284` via catchup responses, and then continuously to `2956` via normal post-exit forward consensus.

## 10. Restore-Mode Exit Evidence

B13 exit was directly observable in both logs and metrics.

Log evidence (`/tmp/run014/logs/v1b.log`):

```text
[restore-catchup] exit: caught up to peer anchor — local committed_height=284 peer_max_observed=Some(284); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Metrics evidence:

| Scrape | `qbind_restore_catchup_mode_active` | `qbind_restore_catchup_mode_exited_at_height` | `qbind_restore_catchup_requests_sent_total` |
|---|---:|---:|---:|
| V1B `t=5s`   | 0 | 284 | 3 |
| V1B `t=10s`  | 0 | 284 | 3 |
| V1B `t=40s`  | 0 | 284 | 3 |
| V1B `t=140s` | 0 | 284 | 3 |
| V1B `t=280s` | 0 | 284 | 3 |
| V1B final    | 0 | 284 | 3 |

For comparison, V0 (never restored) consistently reports `qbind_restore_catchup_mode_active=0` and `qbind_restore_catchup_mode_exited_at_height=0` — confirming the gauge is not fabricated for non-restored nodes.

Answer G: yes. B13's `RestoreCatchupModeState.active` flipped from `true` to `false` exactly once, on V1B, at `committed_height=284` — which is precisely the V0 idle anchor (V0 had been parked at `committed_height=284 / current_view=287` for the entire deadlock hold).

Answer H: yes. Repeated restore-catchup requests stopped/flattened materially. V1B's request counter reached `3` by the first post-restore scrape and remained `3` for the entire 280-second observation window. This is the same flattening shape as Run 013 (`3` and `3`) and a clean separation from Run 012, where the request counter rose monotonically to `141`.

## 11. Deadlocked-View Recovery Evidence

This is the question the run was designed to answer. Aligned scrapes:

| Time | Node | `current_view` | `qcs_formed_total` | `committed_height` | inbound `proposal` | inbound `vote` | accepted proposals | restore req sent | mode active | exited at |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `t=5s`   | V0  | 314  | 314  | 311  | 157  | 314  | 314  | 0 | 0 | 0   |
| `t=5s`   | V1B | 313  | 26   | 310  | 13   | 26   | 27   | 3 | 0 | 284 |
| `t=10s`  | V0  | 362  | 362  | 359  | 181  | 362  | 363  | 0 | 0 | 0   |
| `t=10s`  | V1B | 361  | 74   | 358  | 37   | 74   | 75   | 3 | 0 | 284 |
| `t=20s`  | V0  | 458  | 458  | 455  | 229  | 458  | 459  | 0 | 0 | 0   |
| `t=20s`  | V1B | 457  | 170  | 454  | 85   | 170  | 171  | 3 | 0 | 284 |
| `t=40s`  | V0  | 650  | 650  | 647  | 325  | 650  | 651  | 0 | 0 | 0   |
| `t=40s`  | V1B | 651  | 364  | 648  | 182  | 364  | 364  | 3 | 0 | 284 |
| `t=80s`  | V0  | 1034 | 1034 | 1031 | 517  | 1034 | 1035 | 0 | 0 | 0   |
| `t=80s`  | V1B | 1035 | 748  | 1032 | 374  | 748  | 749  | 3 | 0 | 284 |
| `t=140s` | V0  | 1612 | 1612 | 1609 | 806  | 1612 | 1613 | 0 | 0 | 0   |
| `t=140s` | V1B | 1611 | 1324 | 1608 | 662  | 1324 | 1325 | 3 | 0 | 284 |
| `t=200s` | V0  | 2188 | 2188 | 2185 | 1094 | 2188 | 2189 | 0 | 0 | 0   |
| `t=200s` | V1B | 2189 | 1902 | 2186 | 951  | 1902 | 1903 | 3 | 0 | 284 |
| `t=280s` | V0  | 2958 | 2958 | 2955 | 1479 | 2958 | 2959 | 0 | 0 | 0   |
| `t=280s` | V1B | 2959 | 2672 | 2956 | 1336 | 2672 | 2673 | 3 | 0 | 284 |

Loop-exit counters confirm the same picture (see §13).

Answer I (normal proposal/vote participation resumed automatically in the recreated deadlocked-view shape): **yes.** V1B inbound proposal counter rose from `13` (at `t=5s`, just after catchup) to `1336` (final); inbound votes rose from `26` to `2672`; accepted proposals rose from `27` to `2673`; outbound proposals reached `1337` and outbound votes reached `2673` at clean shutdown.

Answer J (forward QC formation resumed automatically): **yes.** V1B `qbind_consensus_qcs_formed_total` rose from `26` to `2672`; V0's rose from `314` to `2958`. Both nodes reported `qbind_consensus_view_lag=0` continuously after exit.

Answer K (committed height advanced materially beyond the catchup point): **yes.** V1B committed_height advanced from the post-catchup anchor `284` to `2956` — `+2672` blocks of forward post-exit progression on the same restored validator that just exited B13 mode.

How recovery was driven. The exact mechanism the binary used to leave the deadlock-hold view, observable in the V0 log:

```text
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

V0's loop-exit counter confirms exactly one such re-emit occurred for the whole run: `outbound_proposal_late_peer_reemits=1` (vs. `0` on V1B). After that single B9+B10 view-0 re-emit and the two restore-catchup responses, the engine on both sides re-aligned, V1B exited B13 mode at `committed_height=284`, and from view `285` onward both nodes drove forward consensus through the ordinary `BasicHotStuffEngine::on_proposal_event` / `on_vote_event` paths. There was **no** binary-path view-timeout / view-change driver fired and **no** responder-side pending-proposal piggyback on `RestoreCatchupResponse` involved — neither primitive exists yet, and neither was needed to recover from this specifically-recreated deadlock shape.

So in this run, the answer to the original question is the third option from §1: full automatic recovery from the recreated deadlocked predecessor-view shape, driven by the combination of (a) the existing B9/B10 late-peer-reemit edge that fires once when V1B reconnects, (b) bounded restore-catchup, and (c) B13's transition state machine. No new primitive was needed for *this* shape.

## 12. Metrics Evidence

Final V0 `/metrics` excerpt:

```text
consensus_net_inbound_total{kind="vote"} 2958
consensus_net_inbound_total{kind="proposal"} 1479
consensus_net_inbound_total{kind="other"} 2
qbind_consensus_qcs_formed_total 2958
qbind_restore_catchup_requests_sent_total 0
qbind_restore_catchup_requests_received_total 2
qbind_restore_catchup_responses_sent_total 2
qbind_restore_catchup_responses_received_total 0
qbind_restore_catchup_blocks_applied_total 0
qbind_restore_catchup_responses_rejected_total 0
qbind_restore_catchup_proposals_deferred_total 0
qbind_restore_catchup_mode_active 0
qbind_restore_catchup_mode_exited_at_height 0
qbind_consensus_committed_height 2955
qbind_consensus_current_view 2958
qbind_consensus_view_lag 0
qbind_consensus_proposals_total{result="accepted"} 2959
qbind_consensus_proposals_total{result="rejected"} 0
```

Final V1B `/metrics` excerpt:

```text
consensus_net_inbound_total{kind="vote"} 2672
consensus_net_inbound_total{kind="proposal"} 1336
consensus_net_inbound_total{kind="other"} 2
qbind_consensus_qcs_formed_total 2672
qbind_restore_catchup_requests_sent_total 3
qbind_restore_catchup_requests_received_total 0
qbind_restore_catchup_responses_sent_total 0
qbind_restore_catchup_responses_received_total 2
qbind_restore_catchup_blocks_applied_total 245
qbind_restore_catchup_responses_rejected_total 0
qbind_restore_catchup_proposals_deferred_total 0
qbind_restore_catchup_mode_active 0
qbind_restore_catchup_mode_exited_at_height 284
qbind_consensus_committed_height 2956
qbind_consensus_current_view 2959
qbind_consensus_view_lag 0
qbind_consensus_proposals_total{result="accepted"} 2673
qbind_consensus_proposals_total{result="rejected"} 0
```

Answer M: yes. `/metrics` remained honest. The non-restored V0 reports `qbind_restore_catchup_mode_active=0` and `qbind_restore_catchup_mode_exited_at_height=0` (it was never restoring); the restored V1B reports `mode_active=0` and `mode_exited_at_height=284`. The catchup counter family (`requests_sent`, `responses_received`, `blocks_applied`, `responses_rejected`, `proposals_deferred`) is mutually consistent across V0 and V1B (V0 sent 2 responses, V1B received 2 and applied 245 blocks, 0 rejections, 0 deferrals). Forward consensus counters are mutually consistent (V0 inbound vote 2958 ≈ V1B outbound vote 2673 + the V1A-era votes V0 had counted earlier; V0 inbound proposal 1479 ≈ V1B outbound proposal 1337 + earlier V1A-era proposals; the small skew is explained by V1A's pre-restore traffic V0 had already counted and by per-side scrape-vs-loop-exit timing). No restore-exit or resumed-consensus signal was fabricated.

## 13. Shutdown Evidence

```text
/tmp/run014/logs/v1a.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run014/logs/v1a.log:[binary-consensus] Shutdown signal received after 301 ticks.
/tmp/run014/logs/v1a.log:[binary-consensus] Loop exit: ticks=301 proposals=144 commits=285 committed_height=Some(284) view=287 inbound_msgs=431 inbound_proposals=144 inbound_votes=287 outbound_proposals=144 outbound_votes=288 outbound_proposal_late_peer_reemits=0
/tmp/run014/logs/v1a.log:[binary] Shutdown complete.

/tmp/run014/logs/v1b.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run014/logs/v1b.log:[binary-consensus] Shutdown signal received after 2802 ticks.
/tmp/run014/logs/v1b.log:[binary-consensus] Loop exit: ticks=2802 proposals=1337 commits=2913 committed_height=Some(2956) view=2959 inbound_msgs=4010 inbound_proposals=1336 inbound_votes=2672 outbound_proposals=1337 outbound_votes=2673 outbound_proposal_late_peer_reemits=0
/tmp/run014/logs/v1b.log:[binary] Shutdown complete.

/tmp/run014/logs/v0.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run014/logs/v0.log:[binary-consensus] Shutdown signal received after 3353 ticks.
/tmp/run014/logs/v0.log:[binary-consensus] Loop exit: ticks=3353 proposals=1480 commits=2957 committed_height=Some(2956) view=2959 inbound_msgs=4440 inbound_proposals=1479 inbound_votes=2959 outbound_proposals=1480 outbound_votes=2959 outbound_proposal_late_peer_reemits=1
/tmp/run014/logs/v0.log:[binary] Shutdown complete.
```

Answer N: yes. All three processes (V1A, V1B, V0) responded to SIGINT, completed their loop-exit summary lines, and printed `Shutdown complete.` Loop-exit committed heights and views are consistent with the final `/metrics` scrapes (V0 commits=2957, V1B committed_height=2956, V1A commits=285). V0's `outbound_proposal_late_peer_reemits=1` is the same single B9+B10 re-emit observed during the run; no new re-emits leaked.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 014 observation | Result |
|---|---|---|
| B3 restore startup | V1B used `--restore-from-snapshot /tmp/run014/snap`; validation/materialization succeeded; `RESTORED_FROM_SNAPSHOT.json` audit marker written with the live-sourced anchor. | No regression observed |
| B5 restore-aware consensus start | V1B logged `B5: applied restore baseline: snapshot_height=43 starting_view=44 (engine committed_height=Some(43))` and `restore_baseline=true`. | No regression observed |
| B6 binary P2P routing | Live V0/V1A proposal/vote/QC counters advanced; V1B later exchanged proposal/vote and `RestoreCatchupRequest`/`RestoreCatchupResponse` frames over the same P2P transport. `consensus_net_inbound_total{kind="other"}=2` on both V0 and V1B. | No regression observed |
| B7/B8 identity / initial-dial retry | NodeIds were deterministic (`NodeId(4bd96f97b1aaec9d)` for V0, `NodeId(92115fddcd4f93a0)` for V1A and V1B); V0 logged the bounded 8-attempt initial-dial retry while V1A was not yet listening; V1B then connected on first dial after restore. | No regression observed |
| B9/B10 late-peer re-emit | V0 logged exactly one `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)` when V1B connected. Loop-exit counter `outbound_proposal_late_peer_reemits=1` on V0. | No regression observed; this primitive is what unstuck the deadlock-hold view |
| B11/B12 identity / Required mode | All nodes logged `[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` and `mutual_auth=Required`. No Disabled fallback appeared. | No regression observed |
| B13 transition | V1B logged the restore-catchup exit at `committed_height=284 peer_max_observed=Some(284)`; `qbind_restore_catchup_mode_active 0`, `qbind_restore_catchup_mode_exited_at_height 284`. After exit, the request counter remained pinned at `3` for 280s. | No regression observed; B13 active on real binaries |
| No LocalMesh fallback | All commands used `--network-mode p2p --enable-p2p`; logs showed `interconnect=p2p`. The startup line `[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh.` is the same advisory that Runs 010B/011/012/013 already record, not a fallback. | No fallback observed |
| Honest metrics | Catchup counters, exit height, flattened catchup-request count, and resumed-consensus counters all line up across V0 and V1B without fabrication. V0 (non-restored) shows `mode_active=0`, `mode_exited_at_height=0` as expected. | No fabrication observed |

Answer O (any previously-landed binary-path capability appear regressed): **no**. Every capability listed above behaved consistently with Run 013 and earlier evidence runs.

## 15. Limitations and Anomalies Observed

- **2-of-2 cluster shape**: This run uses two validators. With 2-of-2, every leader rotation alternates between V0 and V1, so once V1B reconnects there is always a leader available to propose into the deadlocked view. This run therefore does **not** test the strictly narrower shape where the leader for the next view is the still-absent validator and there is no late-peer-reemit edge to consume — that would require an `N≥3` topology with a specific leader rotation. Run 014 is honest that it does not address that strictly narrower shape, but it does close the *original Run-012 shape* on real binaries.
- **The B9/B10 view-0 re-emit was the unblock**. The deadlock hold ended because V1B's reconnect fired V0's existing late-peer re-emit primitive once. This is observable in V0's loop-exit counter (`outbound_proposal_late_peer_reemits=1`). This means in this run, recovery from the deadlocked predecessor-view shape was achieved through B13 + the *already-landed* B9/B10 primitive — **not** through any new view-timeout / view-change driver and **not** through any responder-side pending-proposal piggyback on `RestoreCatchupResponse`. Both of those proposed primitives remain unimplemented and untested; this run only shows they were not necessary for the specifically-deadlocked shape it recreated.
- **Post-shutdown skew**. Final scrape and loop-exit summaries differ slightly between V0 and V1B (V0 commits=2957 / committed_height=2956 vs V1B commits=2913 / committed_height=2956). This is the same scrape-vs-loop-exit timing skew observed in Run 013; both nodes agree on `committed_height=2956` and `current_view=2959` and `view_lag=0` at final scrape, so this is not evidence of restored-node non-participation — it is per-side timing of the SIGINT vs the last in-flight commit accounting.
- **Single VM-v0 snapshot prefix layout**. As with Runs 011/012/013, the `state/` content is the accepted VM-v0 snapshot layout used by earlier evidence; it is not a production consensus-store checkpoint. Production fast-sync / consensus-storage restore remains open. Production PQC KEMTLS root-key distribution remains open.
- **Production-grade validator/node-id mapping** still uses the `SimpleValidatorNodeMapping` identity scheme. This is adequate for the binary-path evidence runs but not for production.
- **Pre-existing build warning** in `crates/qbind-node/src/verify_pool.rs` (`unused variable: worker_id`) is unchanged from Runs 012/013.

## 16. Assessment of Evidence Value

Run 014 narrowly answers the question Run 013 left open:

- **Positive**: live cluster progressed normally before the deadlock-shape recreation (Answer A).
- **Positive**: snapshot anchor sourced from live V0 `/metrics` (Answer B).
- **Positive**: V1B started honestly from `S=43` (Answer C).
- **Positive**: V1B issued/received real restore-catchup traffic on the binary path (Answer D).
- **Positive**: V1B validated/applied 245 peer-learned certified blocks fail-closed (Answer E).
- **Positive**: committed height advanced above `S` (Answer F).
- **Positive**: B13 mode exit happened at exactly the V0 idle anchor height `284` (Answer G).
- **Positive**: restore-catchup request counter flattened at `3` for 280 seconds (Answer H).
- **Positive**: in the recreated deadlocked predecessor-view shape, normal proposal/vote/QC/commit progression resumed automatically and ran for 280s up to `committed_height=2956`, `current_view=2959`, `view_lag=0` (Answers I, J, K).
- **Positive**: `/metrics` remained honest on both V0 and V1B (Answer M).
- **Positive**: shutdown was clean for V1A, V1B, and V0 (Answer N).
- **Positive**: no previously-landed binary-path capability regressed (Answer O); B9/B10 in particular was actively exercised exactly once, as designed.
- **Still open**: production fast-sync / consensus-storage restore beyond bounded peer-certified suffix.
- **Still open**: production PQC KEMTLS root-key distribution.
- **Still open and now strictly narrower**: the strict-N≥3 shape where the leader for the next view is the still-absent validator and the late-peer-reemit edge cannot consume the deadlock — not testable under 2-of-2 and therefore not addressed by this run.

This materially narrows C4. Before Run 014, C4 listed "recovery from a fully-deadlocked predecessor view" as still unsolved on the binary path post-B13, with the candidate missing primitives being either a binary-path view-timeout / view-change driver or responder-side pending-proposal piggyback on `RestoreCatchupResponse`. Run 014 shows that, in the 2-validator binary path, the *Run-012 deadlocked predecessor-view shape* is in fact recovered post-B13 by the existing B9/B10 late-peer-reemit primitive without either of those proposed new primitives being needed. The remaining unsolved sliver of that boundary is therefore strictly narrower than C4 currently states.

## 17. Recommended Immediate Next Action

Recommended next execution action (not for this PR):

1. Stand up an `N=4` real-binary topology (single restored validator, three live peers) with the same Required-mode P2P transport and the same VM-v0 snapshot prefix path, and rerun the deadlock-hold timing arranging the leader rotation so that the restored validator is **not** the leader for the next view *and* none of the live peers would consume a late-peer-reemit edge. This is the strictly narrower shape that Run 014 cannot reach under 2-of-2. The expected outcome is one of:
   - the existing pacemaker still recovers (further sharpening C4);
   - or the run isolates a concrete view-timeout / view-change requirement on the binary path (giving C4 its narrowest possible unsolved boundary and a single, well-scoped follow-up implementation).

2. Independently, begin the smallest honest production fast-sync / consensus-storage restore prototype on a separate branch — this is the boundary that B13 was never intended to address and that no evidence run so far has touched.

Both items are out of scope for Run 014's PR. Run 014's contribution is exactly the §11 evidence: the Run-012-shape, on the post-B13 binary path, recovers without any new primitive.