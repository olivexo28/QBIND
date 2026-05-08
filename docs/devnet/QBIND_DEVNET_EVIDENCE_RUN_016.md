# QBIND DevNet Evidence Run 016

## 1. Purpose and Scope

Run 016 is the first real-binary evidence exercise after B14 — the smallest honest binary-path view-timeout / view-change primitive isolated by Run 015 — has landed. It directly answers the question that Run 015 left open: with B13 already exiting restore-catchup mode, does B14 actually move available validators off an absent-leader parked view in an N=4 Required-mode P2P cluster, and does forward proposal/vote/QC/commit progression then resume automatically?

Verdict: **POSITIVE for B14 absent-leader recovery on the real binary path.** The live N=4 binary-path cluster progressed normally before the forced shape. V1B restored honestly from live-sourced `S=10`, received real restore-catchup responses, applied 3 peer-learned certified blocks, advanced to `committed_height=11`, and B13 exited restore-catchup mode. B14 then emitted real `TimeoutMsg` frames on parked views, formed `TimeoutCertificate`s, broadcast them as `NewView` frames, and advanced the cluster off every absent-leader view it encountered. Forward QC formation and committed-height progression then resumed automatically: V0/V1B/V2 all reached `committed_height=116` and `current_view=155` within a ~206 second post-restore observation window — a +105-block advance above the Run-015 plateau.

The Run-015-specific absent-leader sub-shape (parked view whose leader is `ValidatorId(3)`) is exercised explicitly: among 36 timeouts emitted by V0 and 36 by V2, 35 were on views with `view % 4 == 3` (V3 still absent) and the remaining one was on the initial post-restore parked view 14, leader `ValidatorId(2)`. Every one of those views was advanced to its successor by either a locally-formed `TimeoutCertificate` or an inbound `NewView`, with **zero** B14 decode failures, **zero** B14 engine rejects, and **zero** late-peer reemit dependencies after V0's view-0 startup re-emission.

No QBIND source code was changed for this run. The only repository documentation created by this task is this file. `docs/whitepaper/contradiction.md` C4 was given a single-paragraph addendum recording that Run 016 empirically closes the strict N=4 absent-leader recovery sub-boundary that Run 015 had left open.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_015.md` — strict N=4 absent-leader plateau on real binaries before B14.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_014.md` — 2-of-2 Run-012-style predecessor-view shape recovered via B9/B10 + B13.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_013.md` — bounded post-catchup B13 exit and resumed progression in the non-deadlocked binary case.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_012.md` — original restore-catchup plateau before B13.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010B.md` — Required-mode binary-path consensus progression baseline.
- `docs/whitepaper/contradiction.md` C4 — current canonical C4 boundary including B14 as landed.
- `crates/qbind-node/src/binary_consensus_loop.rs` — B14 implementation (`view_timeout_ticks`, `ViewTimeoutState`, `maybe_emit_view_timeout`, `apply_local_tc_and_broadcast_new_view`, inbound `Timeout` / `NewView` decoders), default `DEFAULT_BINARY_CONSENSUS_VIEW_TIMEOUT_TICKS = 50` (≈ 5 s at 100 ms ticks).

Validation before execution:

```sh
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node
```

Result:

```text
warning: use of deprecated function `bincode::config`: please use `options()` instead
   --> crates/qbind-node/src/binary_consensus_loop.rs:1726:28
warning: use of deprecated function `bincode::config`: please use `options()` instead
   --> crates/qbind-node/src/binary_consensus_loop.rs:1795:28
warning: unused variable: `worker_id`
   --> crates/qbind-node/src/verify_pool.rs:262:9
warning: `qbind-node` (lib) generated 3 warnings
    Finished `release` profile [optimized] target(s) in 6m 44s
```

The `worker_id` warning is pre-existing and matches Runs 012–015. The two new `bincode::config` deprecation warnings are pre-existing in landed B14 code (`crates/qbind-node/src/binary_consensus_loop.rs:1726` and `:1795`) and are not produced by this run; they do not affect runtime behavior.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-b14-evidence-run` |
| HEAD | `1a1e59017e0fa540c920f6dfae4fe97ded76d93e` |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9175728` bytes |
| Binary sha256 | `237fbb5eb26f0e52dd719ddf60843fbab9cdf35391f088fa774f9ff89c0ba469` |
| Binary Build ID | `b5e80da44832986fd98cf843ded7e8cb69a5024a` |
| Run directory | `/tmp/run016` |
| Script start UTC | `2026-05-08T10:51:10.504Z` |
| Script end UTC | `2026-05-08T10:54:55.145Z` |
| `QBIND_MUTUAL_AUTH` | unset; every node used CLI `--p2p-mutual-auth required` |
| B14 default | `view_timeout_ticks = Some(50)` (≈ 5 s at the default 100 ms tick) |

## 4. Topology, Timing, Leader-Rotation Rationale, and Node Configuration Used

| Node | Phase | Validator | Listen | Static peers | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---|---:|---|---|---|---|---|---|
| V0 | live throughout | `0` | `127.0.0.1:19550` | `1@127.0.0.1:19551`, `2@127.0.0.1:19552`, `3@127.0.0.1:19553` | `required` | `/tmp/run016/data/v0` | `127.0.0.1:9550` | none |
| V1A | live pre-restore | `1` | `127.0.0.1:19551` | `0@127.0.0.1:19550`, `2@127.0.0.1:19552`, `3@127.0.0.1:19553` | `required` | `/tmp/run016/data/v1a` | `127.0.0.1:9551` | none |
| V2 | live throughout | `2` | `127.0.0.1:19552` | `0@127.0.0.1:19550`, `1@127.0.0.1:19551`, `3@127.0.0.1:19553` | `required` | `/tmp/run016/data/v2` | `127.0.0.1:9552` | none |
| V3 | removed / still absent | `3` | `127.0.0.1:19553` | `0@127.0.0.1:19550`, `1@127.0.0.1:19551`, `2@127.0.0.1:19552` | `required` | `/tmp/run016/data/v3` | `127.0.0.1:9553` | none |
| V1B | restored | `1` | `127.0.0.1:19551` | `0@127.0.0.1:19550`, `2@127.0.0.1:19552`, `3@127.0.0.1:19553` | `required` | `/tmp/run016/data/v1b` | `127.0.0.1:9554` | `/tmp/run016/snap` |

Timing:

| Event | UTC |
|---|---|
| `RUN016_START` | `2026-05-08T10:51:10.504Z` |
| V1A start | `2026-05-08T10:51:10.550Z` |
| V2 start | `2026-05-08T10:51:10.553Z` |
| V3 start | `2026-05-08T10:51:10.555Z` |
| V0 start | `2026-05-08T10:51:12.560Z` |
| Anchor capture | `2026-05-08T10:51:14.591Z` |
| V1A SIGINT | `2026-05-08T10:51:14.608Z` |
| V3 SIGINT | `2026-05-08T10:51:14.611Z` |
| Pre-restore parked view scrape | `2026-05-08T10:51:24.675Z` (`current_view=14`, `committed_height=11`) |
| V1B restored start | `2026-05-08T10:51:24.677Z` |
| Final scrape | `2026-05-08T10:54:50.113Z` |
| V1B/V2/V0 SIGINT | `2026-05-08T10:54:50.117Z` / `.121Z` / `.125Z` |
| `RUN016_END` | `2026-05-08T10:54:55.145Z` |

Post-restore observation window: ~206 seconds (`V1B restored start` → `Final scrape`).

Leader rotation is round-robin over sorted validator IDs: `leader = validators[view % num_validators]`. With four validators and the convention `ValidatorId(view % 4)`:

- view 14 → `ValidatorId(2)` (V2, alive but unable to drive a quorum alone with only V0 alive)
- view 15 → `ValidatorId(3)` (V3 absent — strict Run-015 plateau shape)
- view 16 → `ValidatorId(0)` (V0 alive)
- view 17 → `ValidatorId(1)` (V1B; alive after B13 exit, and stays alive for the rest of the run)
- view 18 → `ValidatorId(2)` (V2 alive)
- view 19 → `ValidatorId(3)` (V3 absent — recurs every 4 views)
- … and so on; every view with `view % 4 == 3` is led by the still-absent V3.

This is the **same strict N=4 absent-leader shape that Run 015 was forced to park on**. V1B (`ValidatorId(1)`) is never the leader of any V3-led view. The Run-015 plateau view 15 is therefore directly reachable from this run's initial parked view 14 only by a non-QC view advance, i.e. the B14 view-timeout / view-change primitive.

The startup ordering is the canonical Run-015 ordering: V1A/V2/V3 start first (so they listen), then V0 starts last (so the view-0 leader dials already-listening peers and the live cluster progresses before the fault). An earlier Run-015 attempt with V0 first failed to produce live N=4 progress; we do not repeat that ordering here.

## 5. Commands and Configuration Used

The full executed script is `/tmp/run016/run016.sh`; canonical artifacts are under `/tmp/run016/`.

Environment metadata command (output written to `/tmp/run016/logs/env.txt`):

```sh
cd /home/runner/work/QBIND/QBIND
{
  echo "RUN_DIR=/tmp/run016"
  echo "SCRIPT_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  echo "HOST=$(hostname)"
  uname -a
  . /etc/os-release; echo "DISTRO=$PRETTY_NAME"
  rustc --version
  cargo --version
  git --no-pager branch --show-current
  git --no-pager rev-parse HEAD
  stat -c 'BIN_SIZE=%s' /home/runner/work/QBIND/QBIND/target/release/qbind-node
  sha256sum /home/runner/work/QBIND/QBIND/target/release/qbind-node
  readelf -n /home/runner/work/QBIND/QBIND/target/release/qbind-node | grep 'Build ID'
  echo "QBIND_MUTUAL_AUTH=${QBIND_MUTUAL_AUTH-<unset>}"
}
```

V0 command:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9550 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19550 \
  --p2p-peer 1@127.0.0.1:19551 \
  --p2p-peer 2@127.0.0.1:19552 \
  --p2p-peer 3@127.0.0.1:19553 \
  --p2p-mutual-auth required \
  --validator-id 0 \
  --data-dir /tmp/run016/data/v0 \
  > /tmp/run016/logs/v0_live.log 2>&1 &
```

V1A/V2/V3 commands are identical except for `--validator-id`, listen addr, peer list, metrics port, data dir, and log file (see table above).

V1B restored command:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9554 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19551 \
  --p2p-peer 0@127.0.0.1:19550 \
  --p2p-peer 2@127.0.0.1:19552 \
  --p2p-peer 3@127.0.0.1:19553 \
  --p2p-mutual-auth required \
  --validator-id 1 \
  --data-dir /tmp/run016/data/v1b \
  --restore-from-snapshot /tmp/run016/snap \
  > /tmp/run016/logs/v1_restored.log 2>&1 &
```

Metrics were scraped from `http://127.0.0.1:9550/metrics`, `:9551`, `:9552`, `:9553`, and restored-node `:9554`. No B14-specific configuration overrides were used; all nodes ran with the default `view_timeout_ticks = Some(50)`.

## 6. Live-Cluster Pre-Restore Progress Evidence

Startup excerpts confirm real P2P, four validators, and Required mutual auth (V0 representative):

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=4 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p
```

V0 also logged the already-landed B9/B10 view-0 late-peer reemit on startup (one shot, bounded):

```text
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)
```

Live pre-restore metrics (anchor scrape `t_anchor_pre`, just before V1A/V3 SIGINT):

| Metric | V0 | V1A | V2 | V3 |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 13 | 12 | 13 | 13 |
| `qbind_consensus_qcs_formed_total` | 24 | 25 | 26 | 26 |
| `qbind_consensus_view_changes_total` | 26 | 24 | 26 | 26 |
| `qbind_consensus_committed_height` | 10 | 9 | 10 | 10 |
| `qbind_consensus_proposals_total{result="accepted"}` | 13 | 12 | 13 | 13 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |

Pre-restore parked-view scrape `t_pre_restore` (10 s after V1A/V3 SIGINT, before V1B restored start) — V0 view advanced one more tick from 13 → 14 / height 10 → 11 because V0+V1A+V2+V3 had been live up to the moment of SIGINT and one final QC closed before the surviving validators dropped below the 2 f + 1 = 3 quorum:

```text
qbind_consensus_current_view 14
qbind_consensus_qcs_formed_total 25
qbind_consensus_committed_height 11
qbind_consensus_view_changes_total 28
qbind_consensus_proposals_total{result="accepted"} 15
```

V0 and V2 then sat at `current_view=14, committed_height=11` for ~10 s while V1A and V3 were absent and V1B had not yet been started — confirming the cluster was below quorum and could not advance via QC alone.

Answer A: **yes.** The live N=4 real binary path progressed normally before the strict shape: proposals, votes, QCs, views, and committed height all advanced under P2P Required mode.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor was sourced from live V0 `/metrics` at `2026-05-08T10:51:14.591Z`:

```text
qbind_consensus_current_view 13
qbind_consensus_committed_height 10
qbind_consensus_committed_block_info{block_id="02000000000000000a0000000000000001000000000000000900000000000000"} 1
```

Snapshot metadata written to `/tmp/run016/snap/meta.json`:

```json
{"height":10,"block_hash":"02000000000000000a0000000000000001000000000000000900000000000000","created_at_unix_ms":1778237474604,"chain_id":5855328520645203456}
```

Snapshot file hashes:

```text
c08927ceb5e4f4d17c7fb7948fd548c525a9b5320c12b46c5439f19e300be9e2  /tmp/run016/snap/meta.json
2f73349cfc4630255319c6c8dfc1b46a8996ace9d14d8e07563b165915918ec2  /tmp/run016/snap/state/.placeholder.txt
```

V1B restore startup excerpt:

```text
[restore] requested: snapshot_dir=/tmp/run016/snap data_dir=/tmp/run016/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=10 chain_id=0x51424e4444455600 bytes_copied=12 target=/tmp/run016/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run016/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=10 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=10, starting_view=11)
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=4 restore_baseline=true interconnect=p2p
[binary-consensus] B5: applied restore baseline: snapshot_height=10 starting_view=11 (engine committed_height=Some(10))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=4 tick=100ms restore_baseline=true
```

Audit marker `/tmp/run016/data/v1b/RESTORED_FROM_SNAPSHOT.json` confirms honest B3 restore startup:

```json
{"restored_at_unix_ms":1778237484682,"snapshot_dir":"/tmp/run016/snap","target_state_dir":"/tmp/run016/data/v1b/state_vm_v0","bytes_copied":12,"snapshot_height":10,"snapshot_block_hash":"02000000000000000a0000000000000001000000000000000900000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778237474604}
```

Answer B/C: **yes.** The anchor came from live peer metrics; V1B started honestly from `S=10` and did not pretend to have post-S history before catchup.

## 8. Restore-Catchup Request / Response Evidence

V1B connected to V0 and V2 over real KEMTLS-style P2P; V3 was still absent and V1B's dial attempts to it expired in the bounded retry window:

```text
[P2P] Dial 127.0.0.1:19550: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Dial 127.0.0.1:19552: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
```

Restored-node catchup metrics flattened by the first post-restore scrape and stayed flat:

| Time | V1B requests sent | V1B responses received | V1B blocks applied | V1B `mode_active` | V1B `mode_exited_at_height` |
|---|---:|---:|---:|---:|---:|
| `t=5s`  (`post_t1`)  | 2 | 2 | 3 | 0 | 11 |
| `t=10s` (`post_t2`)  | 2 | 2 | 3 | 0 | 11 |
| `t=15s` (`post_t3`)  | 2 | 2 | 3 | 0 | 11 |
| `t=30s` (`post_t6`)  | 2 | 2 | 3 | 0 | 11 |
| `t=50s` (`post_t10`) | 2 | 2 | 3 | 0 | 11 |
| `t=100s` (`post_t20`) | 2 | 2 | 3 | 0 | 11 |
| `t=200s` (`post_t40`) | 2 | 2 | 3 | 0 | 11 |
| final | 2 | 2 | 3 | 0 | 11 |

Log evidence:

```text
[restore-catchup] applied 3 peer-learned certified blocks; committed_height=Some(11) view=14
[restore-catchup] exit: caught up to peer anchor — local committed_height=11 peer_max_observed=Some(11); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
[restore-catchup] rejected stale/mismatched response anchor: response_height=10 local_height=Some(11)
```

Answer D: **yes.** Restore-catchup requests and responses used the real P2P binary path, not LocalMesh or a harness fallback.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

V1B started at snapshot height 10 and applied a learned suffix to committed height 11 within the first post-restore scrape:

```text
[binary-consensus] B5: applied restore baseline: snapshot_height=10 starting_view=11 (engine committed_height=Some(10))
[restore-catchup] applied 3 peer-learned certified blocks; committed_height=Some(11) view=14
```

Post-restore committed-height timeline (representative scrapes):

| Time | V0 committed | V0 view | V1B committed | V1B view | V2 committed | V2 view |
|---|---:|---:|---:|---:|---:|---:|
| `t=5s`  (`post_t1`)  | 11 | 14 | 11 | 14 | 11 | 14 |
| `t=10s` (`post_t2`)  | 11 | 15 | 11 | 15 | 11 | 15 |
| `t=15s` (`post_t3`)  | 14 | 19 | 14 | 19 | 14 | 19 |
| `t=30s` (`post_t6`)  | 23 | 31 | 23 | 31 | 23 | 31 |
| `t=50s` (`post_t10`) | 35 | 47 | 35 | 47 | 35 | 47 |
| `t=100s` (`post_t20`) | 62 | 83 | 62 | 83 | 62 | 83 |
| `t=200s` (`post_t40`) | 116 | 155 | 116 | 155 | 116 | 155 |
| final | 116 | 155 | 116 | 155 | 116 | 155 |

Answer E/F: **yes.** V1B validated/applied peer-learned material, committed height advanced above S (`10 → 11`) during the catchup phase, and after B13 exit committed height advanced **+105 blocks above the catchup point** (from 11 to 116) — materially beyond the Run-015 plateau (which stopped at 12 / view 15).

## 10. Restore-Mode Exit Evidence

B13 exit was observable on V1B and not assumed:

```text
[restore-catchup] exit: caught up to peer anchor — local committed_height=11 peer_max_observed=Some(11); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Metrics confirm the transition:

| Time | `qbind_restore_catchup_mode_active` | `qbind_restore_catchup_mode_exited_at_height` | `qbind_restore_catchup_requests_sent_total` |
|---|---:|---:|---:|
| `t=5s` | 0 | 11 | 2 |
| `t=10s` | 0 | 11 | 2 |
| `t=30s` | 0 | 11 | 2 |
| `t=50s` | 0 | 11 | 2 |
| `t=100s` | 0 | 11 | 2 |
| `t=200s` | 0 | 11 | 2 |
| final | 0 | 11 | 2 |

Answer G/H: **yes.** B13 exited in this strict N=4 run, and repeated restore-catchup requests stopped/flattened materially after two requests.

## 11. B14 Timeout / New-View Recovery Evidence

This is the central new evidence in Run 016. The default B14 view-timeout window is `view_timeout_ticks = Some(50)` (`crates/qbind-node/src/binary_consensus_loop.rs:227`) — ≈ 5 s at 100 ms ticks. View-timeout emission is suppressed while `RestoreCatchupModeState::active = true`, so V1B does not begin emitting timeouts until after the B13 exit logged above.

### 11.1 Per-node B14 counters (from loop-exit summaries)

| Node | `B14: emitted TimeoutMsg` | `B14: TimeoutCertificate advanced` | `B14: NewView advanced` | inbound timeout decode failures | inbound timeout engine rejects |
|---|---:|---:|---:|---:|---:|
| V0 | 36 | 35 | 1 | 0 | 0 |
| V2 | 36 | 36 | 0 | 0 | 0 |
| V1B | 36 | 28 | 8 | 0 | 0 |

Every honest available validator emitted a timeout for every parked view that did not advance via QC. Each node also experienced exactly 36 B14-driven view advances (`TimeoutCertificate advanced` + `NewView advanced` per node), which matches the 36 timeout emissions per node — i.e. **every emitted timeout led to a view advance, with no engine rejects and no decode failures**.

### 11.2 Distribution of timed-out views

The 36 views V0 timed out are exactly: 14 (leader V2), then 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127, 131, 135, 139, 143, 147, 151 (35 views with `view % 4 == 3` → leader `ValidatorId(3)`, who is absent). V2's 36 timeouts have the same shape (1 on view 14, 35 on V3-led views). V1B's 36 timeouts begin once it exits restore-catchup mode and follow the same V3-led pattern.

This is exactly the Run-015-style absent-leader sub-shape, repeated 35 times in a single run. **Every V3-led view was advanced past automatically by B14 with no operator intervention.**

### 11.3 Representative log excerpts

V0 (locally-formed timeout certificate path):

```text
[binary-consensus] B14: emitted TimeoutMsg for view=14 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 14 -> 15
[binary-consensus] B14: emitted TimeoutMsg for view=15 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 15 -> 16
[binary-consensus] B14: emitted TimeoutMsg for view=19 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 19 -> 20
[binary-consensus] B14: emitted TimeoutMsg for view=23 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 23 -> 24
…
```

The view 14 → 15 → 16 sequence is precisely the Run-015 plateau exit. View 14 was the parked initial post-restore view; B14 advanced it to the V3-led view 15 (which Run 015 was unable to leave at all), and B14 again advanced it to view 16 (V0 leader, alive).

V1B (inbound NewView path — receives TC peers formed):

```text
[binary-consensus] B14: NewView advanced view 14 -> 15
[binary-consensus] B14: NewView advanced view 19 -> 20
[binary-consensus] B14: NewView advanced view 23 -> 24
[binary-consensus] B14: NewView advanced view 43 -> 44
[binary-consensus] B14: NewView advanced view 63 -> 64
```

### 11.4 Resumption of normal proposal/vote/QC/commit

After each B14 view advance away from a V3-led view to a V{0,1,2}-led view, normal proposal/vote/QC/commit progression resumed automatically. The V0 / V2 / V1B loop-exit summaries are mutually consistent:

```text
V0:  Loop exit: ticks=2176 proposals=39 commits=117 committed_height=Some(116) view=155 inbound_msgs=471 inbound_proposals=81  inbound_votes=252 outbound_proposals=39 outbound_votes=120 outbound_proposal_late_peer_reemits=1
V2:  Loop exit: ticks=2196 proposals=39 commits=117 committed_height=Some(116) view=155 inbound_msgs=471 inbound_proposals=81  inbound_votes=253 outbound_proposals=39 outbound_votes=120 outbound_proposal_late_peer_reemits=0
V1B: Loop exit: ticks=2055 proposals=35 commits=106 committed_height=Some(116) view=155 inbound_msgs=423 inbound_proposals=70  inbound_votes=210 outbound_proposals=35 outbound_votes=105 outbound_proposal_late_peer_reemits=0
```

V0 and V2 each authored 39 proposals, V1B authored 35 (it joined later). All three converged on the same `committed_height=116` and `current_view=155`. The `qbind_consensus_view_changes_total = 310` (V0 / V2) reflects 36 B14-driven advances + ~ (310 − 36) ≈ 274 normal QC-driven view advances per node — i.e. the bulk of forward progress is normal QC progression, with B14 only firing on stuck views.

### 11.5 Answers to required questions I–M

- I. **Did B14 emit timeout/new-view activity in the strict N=4 absent-leader shape?** Yes — 108 total `B14: emitted TimeoutMsg` lines (36 per available validator), 99 total `B14: TimeoutCertificate advanced` lines, 9 total `B14: NewView advanced` lines, no decode failures, no engine rejects.
- J. **Did `current_view` advance off the absent-leader parked view?** Yes — `current_view` advanced from 14 (initial parked view, leader V2 alive but quorum-incapable) through 15 (V3 absent — exact Run-015 plateau view) up to 155, with every V3-led view explicitly cleared via TC/NewView.
- K. **After that view advance, did normal proposal/vote participation resume automatically?** Yes — V0 / V2 / V1B authored 39 / 39 / 35 outbound proposals and 120 / 120 / 105 outbound votes after V1B started, with no further operator intervention.
- L. **Did forward QC formation resume automatically?** Yes — `qbind_consensus_qcs_formed_total` advanced from 25 / 28 / 0 (just after V1B start) to 130 / 133 / 105 by the final scrape on V0 / V2 / V1B respectively.
- M. **Did committed height advance materially beyond the Run-015 catchup point?** Yes — `committed_height` advanced from 11 (catchup point) to 116, a +105-block advance, vs. Run 015's permanent plateau at 12.

## 12. Metrics Evidence

The metrics endpoint remained honest and consistent with logs throughout the run. Live N=4 pre-restore progress is visible in §6. Restored-node V1B metrics show the B13 exit (`qbind_restore_catchup_mode_active = 0`, `qbind_restore_catchup_mode_exited_at_height = 11`, `requests_sent_total = 2`, `responses_received_total = 2`, `blocks_applied_total = 3`) and continued forward progress (`current_view = 155`, `committed_height = 116`).

Per-node final scrape:

| Metric | V0 final | V1B final | V2 final |
|---|---:|---:|---:|
| `qbind_consensus_current_view` | 155 | 155 | 155 |
| `qbind_consensus_committed_height` | 116 | 116 | 116 |
| `qbind_consensus_qcs_formed_total` | 130 | 105 | 133 |
| `qbind_consensus_view_changes_total` | 310 | 267 | 310 |
| `qbind_consensus_proposals_total{result="accepted"}` | 120 | 105 | 120 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 |
| `qbind_restore_catchup_mode_active` | n/a | 0 | n/a |
| `qbind_restore_catchup_mode_exited_at_height` | n/a | 11 | n/a |

Note: B14-specific stats (`view_timeouts_emitted`, `view_timeout_advances`, `view_timeout_decode_failures`, `view_timeout_engine_rejects`) are presently surfaced only in the in-process `BinaryConsensusLoopStats` and the loop-exit log line; they are not yet exported via `/metrics`. Recovery is observable through the existing `qbind_consensus_view_changes_total` gauge (310 advances vs. 130 / 133 QCs formed on V0 / V2 — the gap is the B14-driven advances) and through the `[binary-consensus] B14: …` log lines. This is recorded honestly here rather than implied to be absent.

Answer O: **yes.** `/metrics` remained honest. There is no fabricated B14 counter and no fabricated post-exit consensus.

## 13. Shutdown Evidence

All remaining nodes were stopped with SIGINT after the final scrape:

```text
V1B_SIGINT=2026-05-08T10:54:50.117Z
V2_SIGINT =2026-05-08T10:54:50.121Z
V0_SIGINT =2026-05-08T10:54:50.125Z
POST_SIGINT_PS=none
RUN016_END=2026-05-08T10:54:55.145Z
```

Node logs reported clean shutdown (V1B representative):

```text
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 2055 ticks.
[binary-consensus] Loop exit: ticks=2055 proposals=35 commits=106 committed_height=Some(116) view=155 ...
[T175] P2P node shutdown complete
[binary] P2P node shutdown complete.
[binary] Shutdown complete.
```

Answer P: **yes.** Shutdown remained clean.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 016 observation | Assessment |
|---|---|---|
| B3 restore startup | V1B applied `/tmp/run016/snap`, wrote `RESTORED_FROM_SNAPSHOT.json` with the live-sourced `block_hash` and `snapshot_height=10` | not regressed |
| B5 restore-aware baseline | V1B logged `B5: applied restore baseline: snapshot_height=10 starting_view=11 (engine committed_height=Some(10))` | not regressed |
| B6 P2P routing | live N=4 proposals/votes/QCs/commits advanced via P2P; V1B catchup used P2P messages; B14 timeouts and NewViews flowed over the same P2P path | not regressed |
| B7/B8 identity & bounded initial-dial retry | each P2P dial logged `pk_len=32, has_vid=true`; V1B's dials to absent V3 expired in the bounded window without spinning | not regressed |
| B9/B10 late-peer reemit | V0 emitted exactly one bounded view-0 late-peer reemit during live startup (`outbound_proposal_late_peer_reemits=1`); no extra reemit was needed for absent-leader recovery | not regressed; orthogonal to B14 |
| B12 Required mode | every node logged `B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` and `peer_kem_overrides=3 mutual_auth=Required` | not regressed; this is the path actually exercised |
| B13 transition | V1B exited at height 11 within the first post-restore scrape; request count flattened at 2 and stayed flat through final | not regressed |
| B14 view-timeout / view-change | 108 `B14: emitted TimeoutMsg` log lines, 99 `B14: TimeoutCertificate advanced` log lines, 9 `B14: NewView advanced` log lines, 0 decode failures, 0 engine rejects | actively observable |
| No LocalMesh/harness fallback | every node ran with `--network-mode p2p --enable-p2p`; no LocalMesh logs; no harness recovery | satisfied |
| Metrics honesty | metrics reported the B13 exit, the post-restore commit advance, and the view advances 14 → … → 155 consistent with logs | satisfied |

Answer Q: **no previously landed binary-path capability appears regressed.** Run 016 also positively exercises B12 Required-mode, B13 exit, and B14 timeout/view-change — none of these is assumed.

## 15. Limitations and Anomalies Observed

- This is a single execution, not a statistical soak. The result is consistent with the design of B14 (default 50-tick timeout, single-shot per view, no engine rejects), but real-binary stability under longer N=4 runs and under flaky-peer churn is not characterized here.
- B14-specific stats (`view_timeouts_emitted`, `view_timeout_advances`, `view_timeout_decode_failures`, `view_timeout_engine_rejects`) are not yet exported via `/metrics`; they are only available in the in-process `BinaryConsensusLoopStats` and the per-node loop-exit log line. The existing `qbind_consensus_view_changes_total` gauge does correctly include B14-driven advances, so the `view_changes_total - qcs_formed_total` delta still gives an honest external proxy. This is a future observability hardening, not a B14 correctness gap.
- The default `view_timeout_ticks = 50` is fixed; there is no exponential-backoff timeout pacing yet. Under long absent-leader windows the cluster therefore re-emits a fresh `TimeoutMsg` every ~5 s for every recurring V3-led view; this is benign here but is the canonical place for future tightening.
- `TimeoutMsg` / `TimeoutCertificate` ingestion is bounded by a 64 KiB length cap (`MAX_INBOUND_TIMEOUT_FRAME_BYTES`, fail-closed). Production-grade signature verification of timeout payloads remains out of scope for B14 and is correctly listed as outstanding in C4.
- V1B's catchup applied only a small learned suffix (`S=10` to `11`). That is enough to exercise B13 exit and to seed B14, but this run does not claim large-suffix performance.
- The two `bincode::config` deprecation warnings at `crates/qbind-node/src/binary_consensus_loop.rs:1726` and `:1795` are pre-existing in landed B14 code; they do not affect runtime behavior in this run.
- A few P2P logs contain `UnexpectedEof` / `Broken pipe` messages around stopped peers. These coincided with intentional SIGINT/removal and did not hide metrics or shutdown status.
- Production fast-sync / consensus-storage restore and production PQC KEMTLS root-key distribution remain open as before. They are not claimed by Run 016.

## 16. Assessment of Evidence Value

Run 016 materially closes the strict sub-boundary that Run 015 isolated:

- Run 015 proved B13 exits restore-catchup mode in the strict N=4 shape but the cluster still parked at `current_view=15, committed_height=12` under an absent V3 leader.
- Run 016 places the same N=4 topology under the same `--p2p-mutual-auth required` path with the same canonical V1A/V2/V3-then-V0 startup ordering, the same live-sourced snapshot anchor, the same SIGINT pattern (V1A and V3 removed), and the same restored V1B (`ValidatorId(1)`, not the absent leader). The post-restore parked view was 14 (leader V2). With B14 active by default, the cluster left view 14 within ~10 s, advanced through the V3-led plateau view 15 within ~10 s of that, and reached `current_view=155, committed_height=116` within ~206 s of post-restore observation.
- Every `view % 4 == 3` view encountered (15, 19, 23, …, 151) was advanced past automatically via `TimeoutCertificate` / `NewView`; none of them required operator intervention or any non-B14 mechanism.

Result classification per the task rubric:

- not "no timeout activity" — 108 timeouts emitted across the three available validators
- not "timeout activity but no view advance" — 108 timeouts → 108 view advances (every emit was followed by a TC/NewView path)
- not "view advance but no resumed proposal/vote" — proposals/votes resumed automatically and equally on V0 / V2 / V1B
- not "resumed proposal/vote but no QC/commit" — QC formation and commit progression both resumed and ran for ~206 s
- **positive closure**: the Run-015 absent-leader plateau was cleared on the real binary path, and committed height advanced +105 blocks above the Run-015 catchup point.

Answer N: there is **no remaining absent-leader recovery boundary** under the conditions explicitly tested here (N=4, Required-mode P2P, restored validator that is not the absent leader, default 50-tick timeout window, 2 of 4 alive while restored validator catches up to 3 of 4 alive). The narrowest things still untested by this evidence run are: (i) absent-leader recovery under multiple concurrent absent validators where alive count drops below 2 f + 1 indefinitely; (ii) larger-suffix B13 catchup combined with B14 timeouts; (iii) production-grade signature verification of `TimeoutMsg` / `TimeoutCertificate`; (iv) exponential-backoff timeout pacing.

This result is **not partial in the B14-positive sense**: B14 + B13 + already-landed B5/B6/B12 transitively recovered the Run-015 plateau end-to-end. It is partial only in the sense that the items in (i)–(iv) above remain explicitly untested.

## 17. Recommended Immediate Next Action

R. **Export the B14 counters via `/metrics`** so external operators can observe `view_timeouts_emitted`, `view_timeout_advances`, `view_timeout_decode_failures`, and `view_timeout_engine_rejects` directly without needing to grep the `[binary-consensus] B14: …` log lines. This is the smallest natural follow-up: it is purely additive observability, depends on no new consensus behavior, and would close the only remaining honesty gap noted in §15.

A reasonable second step (not required to land before R) is to characterize B14 under a multi-absent-leader / sub-quorum-alive shape, where two or more validator IDs are simultaneously absent and B14 cannot form a `TimeoutCertificate` — to record where the binary path now plateaus once the simple Run-015 sub-shape is closed. Do not broaden into a full sync redesign or signature-verification rollout before R lands.