# QBIND DevNet Evidence Run 017

## 1. Purpose and Scope

Run 017 is the first harsher real-binary recovery evidence run after B14 timeout / view-change counters became directly visible on `/metrics`.

Verdict: **PARTIAL POSITIVE for restore/B13/B14 observability, NEGATIVE for sub-quorum automatic recovery.** The N=4 Required-mode P2P cluster progressed normally before fault injection. A snapshot anchor was sourced from live V0 `/metrics` at `S=12`. V1B restored honestly from that snapshot, requested and received real binary-path restore-catchup material from the only continuously alive peer, applied four peer-learned certified blocks, advanced to `committed_height=14`, and B13 exited restore-catchup mode. During the true sub-quorum period, only V0 and V1B were alive in a four-validator set, below the `2f+1 = 3` threshold. Both emitted B14 timeouts directly visible on `/metrics`, but no timeout certificate formed, no NewView was sent/accepted, and no normal proposal/vote/QC/commit progression resumed while the alive set remained two.

An optional same-run V2 return was attempted after the sub-quorum observation window. It did not prove clean quorum-restored recovery: V2B restarted without a restore baseline and without production consensus-storage/fast-sync, reported `committed_height=None`, and remained at `current_view=17` while V0/V1B briefly advanced to `current_view=18, committed_height=15` and then stalled. That result is recorded as an anomaly/limitation, not as proof that B14 cannot recover once a fully caught-up quorum is restored.

No QBIND source code was changed. The only repository documentation created by this task is this file. `docs/whitepaper/contradiction.md` was left untouched because Run 017 confirms the expected sub-quorum boundary and the already-open consensus-storage / fast-sync limitation rather than revealing a new contradiction.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_016.md` — B14 cleared the strict Run-015-style N=4 absent-leader plateau when three of four validators were available after restore.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_015.md` — strict N=4 absent-leader plateau before B14.
- `docs/whitepaper/contradiction.md` C4 v1.6, 2026-05-08 — C4 remains open/partial; B14 is landed, while production fast-sync / consensus-storage restore and production timeout-certificate signature verification remain outstanding.
- `crates/qbind-node/src/binary_consensus_loop.rs` — B14 timeout / NewView implementation and exported `/metrics` counters.

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
Finished `release` profile [optimized] target(s) in 6m 48s
```

These warnings are pre-existing in the current tree and were not introduced by Run 017.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-multi-absent-leader-recovery` |
| HEAD | `7973bfee727b66f0fad9e2c424d25338d51b1939` |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9182184` bytes |
| Binary sha256 | `8479f4260de975b9c517c52a65a362d30c4014a0fa3c6a784cc31f476a4c3388` |
| Binary Build ID | `e8cecf091418b4bcf1d340e0fde20dc1bfbf0c7c` |
| Run directory | `/tmp/run017` |
| Script start UTC | `2026-05-08T12:45:20.249Z` |
| Script end UTC | `2026-05-08T12:49:00.699Z` |
| `QBIND_MUTUAL_AUTH` | unset; every node used CLI `--p2p-mutual-auth required` |
| B14 default | `view_timeout_ticks = Some(50)`; no timeout override used |

## 4. Topology, Timing, Quorum Rationale, and Node Configuration Used

N=4 was used for direct comparison with Runs 015 and 016. With N=4, `f=1` and the quorum / timeout-certificate threshold is `2f+1 = 3`.

| Node | Phase | Validator | Listen | Static peers | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---:|---:|---|---|---|---|---|---|
| V0 | live throughout | `0` | `127.0.0.1:19750` | `1@127.0.0.1:19751`, `2@127.0.0.1:19752`, `3@127.0.0.1:19753` | `required` | `/tmp/run017/data/v0` | `127.0.0.1:9750` | none |
| V1A | live pre-fault | `1` | `127.0.0.1:19751` | `0@127.0.0.1:19750`, `2@127.0.0.1:19752`, `3@127.0.0.1:19753` | `required` | `/tmp/run017/data/v1a` | `127.0.0.1:9751` | none |
| V2A | live pre-fault | `2` | `127.0.0.1:19752` | `0@127.0.0.1:19750`, `1@127.0.0.1:19751`, `3@127.0.0.1:19753` | `required` | `/tmp/run017/data/v2a` | `127.0.0.1:9752` | none |
| V3A | live pre-fault | `3` | `127.0.0.1:19753` | `0@127.0.0.1:19750`, `1@127.0.0.1:19751`, `2@127.0.0.1:19752` | `required` | `/tmp/run017/data/v3a` | `127.0.0.1:9753` | none |
| V1B | restored during sub-quorum | `1` | `127.0.0.1:19751` | `0@127.0.0.1:19750`, `2@127.0.0.1:19752`, `3@127.0.0.1:19753` | `required` | `/tmp/run017/data/v1b` | `127.0.0.1:9754` | `/tmp/run017/snap` |
| V2B | optional return attempt | `2` | `127.0.0.1:19752` | `0@127.0.0.1:19750`, `1@127.0.0.1:19751`, `3@127.0.0.1:19753` | `required` | `/tmp/run017/data/v2a` | `127.0.0.1:9755` | none |

Timing:

| Event | UTC |
|---|---|
| `RUN017_START` | `2026-05-08T12:45:20.247Z` |
| V1A start | `2026-05-08T12:45:20.292Z` |
| V2A start | `2026-05-08T12:45:20.295Z` |
| V3A start | `2026-05-08T12:45:20.298Z` |
| V0 start | `2026-05-08T12:45:22.303Z` |
| Live-ready marker | `LIVE_READY_HEIGHT=12 VIEW=15` |
| Anchor capture | `2026-05-08T12:45:24.896Z` |
| V1A SIGINT | `2026-05-08T12:45:24.955Z` |
| V2A SIGINT | `2026-05-08T12:45:25.132Z` |
| V3A SIGINT | `2026-05-08T12:45:25.312Z` |
| Pre-restore scrape | `2026-05-08T12:45:37.478Z` |
| V1B restored start | `2026-05-08T12:45:37.480Z` |
| Sub-quorum observation | 16 scrapes every 5 s, through `2026-05-08T12:46:57.738Z` |
| V2B return attempt start | `2026-05-08T12:46:57.740Z` |
| Post-return observation | 24 scrapes every 5 s, through `2026-05-08T12:48:58.249Z` |
| Final scrape | `2026-05-08T12:48:58.268Z` |
| V1B/V2B/V0 SIGINT | `2026-05-08T12:48:58.294Z` / `.471Z` / `.647Z` |
| `RUN017_END` | `2026-05-08T12:49:00.699Z` |

Quorum rationale:

- Run 016 had three available validators after restore (V0, V1B, V2) and B14 formed timeout certificates.
- Run 017 deliberately removed V1A, V2A, and V3A before restoring V1B. The sub-quorum period had only V0 and V1B alive in an N=4 validator set.
- Two alive validators can emit timeout messages, but cannot form `2f+1 = 3` timeout material. This is strictly harsher than Run 016.
- V3 remained absent throughout; V2 returned only in the clearly separated optional phase and did not have a restore baseline.

## 5. Commands and Configuration Used

The executed artifact script was `/tmp/run017/run017.sh`. Representative exact node commands after expansion:

V0:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9750 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19750 \
  --p2p-peer 1@127.0.0.1:19751 \
  --p2p-peer 2@127.0.0.1:19752 \
  --p2p-peer 3@127.0.0.1:19753 \
  --p2p-mutual-auth required \
  --validator-id 0 \
  --data-dir /tmp/run017/data/v0 \
  > /tmp/run017/logs/v0_live.log 2>&1 &
```

V1A/V2A/V3A used the same command shape with validator IDs `1/2/3`, listen ports `19751/19752/19753`, metrics ports `9751/9752/9753`, corresponding peer lists, and data dirs `/tmp/run017/data/v1a`, `/tmp/run017/data/v2a`, `/tmp/run017/data/v3a`.

V1B restored:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9754 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19751 \
  --p2p-peer 0@127.0.0.1:19750 \
  --p2p-peer 2@127.0.0.1:19752 \
  --p2p-peer 3@127.0.0.1:19753 \
  --p2p-mutual-auth required \
  --validator-id 1 \
  --data-dir /tmp/run017/data/v1b \
  --restore-from-snapshot /tmp/run017/snap \
  > /tmp/run017/logs/v1_restored.log 2>&1 &
```

V2B optional return attempt:

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9755 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19752 \
  --p2p-peer 0@127.0.0.1:19750 \
  --p2p-peer 1@127.0.0.1:19751 \
  --p2p-peer 3@127.0.0.1:19753 \
  --p2p-mutual-auth required \
  --validator-id 2 \
  --data-dir /tmp/run017/data/v2a \
  > /tmp/run017/logs/v2_rejoined.log 2>&1 &
```

The run scraped `http://127.0.0.1:9750/metrics`, `:9751`, `:9752`, `:9753`, `:9754`, and `:9755`. No LocalMesh process, harness-only recovery, fake timeout/NewView path, or mutual-auth fallback was used.

## 6. Live-Cluster Pre-Restore Progress Evidence

Startup excerpts confirm the real binary P2P path and Required mutual auth:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=4 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)
```

Live anchor metrics:

| Metric | V0 | V1A | V2A | V3A |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 15 | 15 | 16 | 15 |
| `qbind_consensus_committed_height` | 12 | 12 | 13 | 12 |
| `qbind_consensus_qcs_formed_total` | 28 | 29 | 31 | 29 |
| `qbind_consensus_view_changes_total` | 29 | 30 | 32 | 30 |
| `qbind_consensus_proposals_total{result="accepted"}` | 15 | 16 | 16 | 16 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeouts_emitted_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_timeout_certificates_formed_total` | 0 | 0 | 0 | 0 |

V0 log also confirms committed anchors reached and passed the chosen snapshot height:

```text
[binary-consensus] committed_anchor height=12 block_id=00000000000000000c0000000000000003000000000000000b00000000000000
[binary-consensus] committed_anchor height=13 block_id=01000000000000000d0000000000000000000000000000000c00000000000000
[binary-consensus] committed_anchor height=14 block_id=02000000000000000e0000000000000001000000000000000d00000000000000
```

Answer A: **yes.** The live binary-path cluster progressed normally before the harsher shape was created.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor was sourced from live V0 `/metrics` at `2026-05-08T12:45:24.896Z`:

```text
qbind_consensus_current_view 15
qbind_consensus_committed_height 12
qbind_consensus_committed_block_info{block_id="00000000000000000c0000000000000003000000000000000b00000000000000"} 1
```

Snapshot metadata:

```json
{"height":12,"block_hash":"00000000000000000c0000000000000003000000000000000b00000000000000","created_at_unix_ms":1778244324924,"chain_id":5855328520645203456}
```

Snapshot file hashes:

```text
883aa077e0491d3a1039fcb4f08b3d0e1b41e8ed5551481cfef8dc764924c481  /tmp/run017/snap/meta.json
b1a8a7ab2e69a13653d6c8edefd32b558a5ed33230c013bba5a8553fa45ad2b4  /tmp/run017/snap/state/.placeholder.txt
```

V1B restore startup:

```text
[restore] requested: snapshot_dir=/tmp/run017/snap data_dir=/tmp/run017/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=12 chain_id=0x51424e4444455600 bytes_copied=49 target=/tmp/run017/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run017/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=12 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=12, starting_view=13)
[binary-consensus] B5: applied restore baseline: snapshot_height=12 starting_view=13 (engine committed_height=Some(12))
```

Audit marker:

```json
{"restored_at_unix_ms":1778244337485,"snapshot_dir":"/tmp/run017/snap","target_state_dir":"/tmp/run017/data/v1b/state_vm_v0","bytes_copied":49,"snapshot_height":12,"snapshot_block_hash":"00000000000000000c0000000000000003000000000000000b00000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778244324924}
```

Answers B/C: **yes.** The snapshot anchor came from live peer state, and V1B started honestly from `S=12` rather than pretending to already have post-S history.

## 8. Restore-Catchup Request / Response Evidence

V1B used the same real P2P / Required path:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=4 restore_baseline=true interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=4 tick=100ms restore_baseline=true interconnect=p2p late_peer_reemit=on
[P2P] Dial 127.0.0.1:19750: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
```

Restore-catchup metrics:

| Time | V1B requests sent | V1B responses received | V1B blocks applied | V1B mode active | V1B exited at height |
|---|---:|---:|---:|---:|---:|
| `subq_t1` | 2 | 1 | 4 | 0 | 14 |
| `subq_t8` | 2 | 1 | 4 | 0 | 14 |
| `subq_t16` | 2 | 1 | 4 | 0 | 14 |
| final | 2 | 1 | 4 | 0 | 14 |

Log evidence:

```text
[restore-catchup] applied 4 peer-learned certified blocks; committed_height=Some(14) view=17
[restore-catchup] exit: caught up to peer anchor — local committed_height=14 peer_max_observed=Some(14); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Answer D: **yes.** V1B issued restore-catchup requests and received a real binary-path response. No LocalMesh or harness fallback occurred.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

V1B started from snapshot height `S=12`, applied learned post-S material to height 14, and later reached height 15 after the optional V2B return attempt:

| Time | V0 committed | V0 view | V1B committed | V1B view | Notes |
|---|---:|---:|---:|---:|---|
| pre-restore V0 | 14 | 17 | n/a | n/a | V0 remained alone after V1A/V2A/V3A removal; one local timeout had emitted |
| `subq_t1` | 14 | 17 | 14 | 17 | V1B catchup completed and B13 exited |
| `subq_t16` | 14 | 17 | 14 | 17 | still sub-quorum; no commit/view progress |
| `rejoin_t1` | 15 | 18 | 15 | 18 | one commit/view advance after V2B started |
| `rejoin_t24` | 15 | 18 | 15 | 18 | stalled again |
| final | 15 | 18 | 15 | 18 | no normal resumed progression |

Answers E/F: **yes, with boundary.** V1B validated/applied learned post-S material (`12 → 14`) and committed height eventually advanced above S. However, under the true two-validator sub-quorum shape, committed height did not advance beyond 14 and current view did not advance beyond 17.

## 10. Restore-Mode Exit Evidence

B13 was active and observed, not assumed:

```text
[restore-catchup] exit: caught up to peer anchor — local committed_height=14 peer_max_observed=Some(14); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Metrics confirmed the transition:

| Time | `qbind_restore_catchup_mode_active` | `qbind_restore_catchup_mode_exited_at_height` | `qbind_restore_catchup_requests_sent_total` |
|---|---:|---:|---:|
| `subq_t1` | 0 | 14 | 2 |
| `subq_t8` | 0 | 14 | 2 |
| `subq_t16` | 0 | 14 | 2 |
| final | 0 | 14 | 2 |

Answer G: **yes.** B13 restore-catchup mode exited in this run.

## 11. Direct B14 `/metrics` Timeout / New-View Evidence

B14 counters were directly scraped from `/metrics`; this is materially stronger observability than Run 016.

Sub-quorum B14 metrics:

| Time | Node | `current_view` | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `outbound_new_views_sent_total` | `inbound_new_views_engine_accepted_total` | `view_timeout_advances_total` | decode failures | engine rejects |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| pre-restore | V0 | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `subq_t1` | V0 | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `subq_t1` | V1B | 17 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `subq_t8` | V0 | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `subq_t8` | V1B | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `subq_t16` | V0 | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `subq_t16` | V1B | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |

Final B14 metrics after the optional V2B return attempt:

| Node | `current_view` | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `outbound_new_views_sent_total` | `inbound_new_views_delivered_total` | `inbound_new_views_engine_accepted_total` | `view_timeout_advances_total` |
|---|---:|---:|---:|---:|---:|---:|---:|
| V0 | 18 | 2 | 0 | 0 | 0 | 0 | 0 |
| V1B | 18 | 2 | 0 | 0 | 0 | 0 | 0 |
| V2B | 17 | 1 | 0 | 0 | 0 | 0 | 0 |

Representative logs:

```text
V0:  [binary-consensus] B14: emitted TimeoutMsg for view=17 after 50 ticks of no progress
V0:  [binary-consensus] B14: emitted TimeoutMsg for view=18 after 50 ticks of no progress
V1B: [binary-consensus] B14: emitted TimeoutMsg for view=17 after 50 ticks of no progress
V1B: [binary-consensus] B14: emitted TimeoutMsg for view=18 after 50 ticks of no progress
V2B: [binary-consensus] B14: emitted TimeoutMsg for view=17 after 50 ticks of no progress
```

Answer H: **yes.** B14 timeout/new-view counters showed real activity directly on `/metrics`. Specifically, timeout emissions were visible, while timeout-certificate and NewView counters stayed at zero.

## 12. Harsher Recovery-Shape Outcome Evidence

During the true sub-quorum period:

- Alive set: V0 + V1B = 2 validators.
- Required timeout-certificate material: `2f+1 = 3`.
- Direct `/metrics` evidence: V0 and V1B emitted timeouts, but `qbind_consensus_timeout_certificates_formed_total`, `qbind_consensus_outbound_new_views_sent_total`, `qbind_consensus_inbound_new_views_engine_accepted_total`, and `qbind_consensus_view_timeout_advances_total` all remained zero.
- V0 and V1B stayed at `current_view=17, committed_height=14` from `subq_t1` through `subq_t16`.

This cleanly answers the harsher boundary: **the alive set was not sufficient to form timeout certificates, so no B14 view-change recovery was possible while only two validators were alive in N=4.**

The optional V2B return attempt did not produce clean positive quorum-restored recovery:

| Node | Final `committed_height` | Final `current_view` | Final QCs | Final accepted proposals | Final B14 TCs |
|---|---:|---:|---:|---:|---:|
| V0 | 15 | 18 | 32 | 18 | 0 |
| V1B | 15 | 18 | 1 | 2 | 0 |
| V2B | 0 / `None` in log | 17 | 0 | 1 | 0 |

V2B loop exit:

```text
[binary-consensus] Loop exit: ticks=1208 proposals=0 commits=0 committed_height=None view=17 inbound_msgs=4 inbound_proposals=1 inbound_votes=1 outbound_proposals=0 outbound_votes=1 outbound_proposal_late_peer_reemits=0
```

Answers I/J/K/L:

- I. **No**, the true sub-quorum alive set was insufficient to form timeout certificates.
- J. During the true sub-quorum period, `current_view` did **not** advance off view 17. V0/V1B advanced to view 18 only after V2B was started, and even then no timeout certificate or NewView formed.
- K. Normal proposal/vote/QC/commit did **not** resume automatically. A single extra commit appeared after V2B started, then the cluster stalled again at `current_view=18, committed_height=15`.
- L. The narrowest supported remaining boundary is: B14 requires at least `2f+1` compatible timeout material from validators that are alive and sufficiently aligned in consensus state. Two of four validators fail closed, and simply restarting a non-restored, consensus-state-empty validator is not enough to establish a clean recovered quorum.

## 13. Shutdown Evidence

Shutdown events:

```text
FINAL_SCRAPE=2026-05-08T12:48:58.268Z
V1B_SIGINT=2026-05-08T12:48:58.294Z
V2B_SIGINT=2026-05-08T12:48:58.471Z
V0_SIGINT=2026-05-08T12:48:58.647Z
RUN017_END=2026-05-08T12:49:00.699Z
```

Representative shutdown logs:

```text
V0:  [binary] Shutdown signal received, stopping P2P node...
V0:  [binary-consensus] Shutdown signal received after 2164 ticks.
V0:  [binary] Shutdown complete.
V1B: [binary] Shutdown signal received, stopping P2P node...
V1B: [binary-consensus] Shutdown signal received after 2009 ticks.
V1B: [binary] Shutdown complete.
V2B: [binary] Shutdown signal received, stopping P2P node...
V2B: [binary-consensus] Shutdown signal received after 1208 ticks.
V2B: [binary] Shutdown complete.
```

Post-SIGINT process check:

```text
PID STAT CMD
```

Answer N: **yes.** Shutdown remained clean.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 017 observation | Assessment |
|---|---|---|
| B3 restore startup | V1B applied `/tmp/run017/snap`, wrote `RESTORED_FROM_SNAPSHOT.json`, and used live-sourced `snapshot_height=12` / block hash | not regressed |
| B5 restore-aware baseline | V1B logged `B5: applied restore baseline: snapshot_height=12 starting_view=13 (engine committed_height=Some(12))` | not regressed |
| B6 P2P routing | live cluster progressed via P2P; V1B catchup used P2P; B14 timeouts emitted on binary path | not regressed |
| B7/B8 identity and bounded dial behavior | P2P dials logged `pk_len=32, has_vid=true`; Required mode used deterministic validator identities | not regressed |
| B9/B10 late-peer reemit | V0 logged one bounded view-0 reemit during live startup | not regressed |
| B12 Required mode | every node used `--p2p-mutual-auth required`; logs show `mutual_auth=Required` | not regressed |
| bounded restore-catchup | V1B sent 2 requests, received 1 response, applied 4 blocks | not regressed |
| B13 transition | V1B mode active became 0 and exited at height 14 | not regressed |
| B14 `/metrics` exports | direct counters showed timeout emissions and zero TCs/NewViews/advances | not regressed; actively exercised |
| No LocalMesh/harness fallback | every node ran with `--network-mode p2p --enable-p2p`; no LocalMesh recovery path | satisfied |
| Metrics honesty | `/metrics` matched logs: timeouts emitted, no fabricated TC/NewView, no fabricated resumed consensus | satisfied |

Answer O: **no previously landed binary-path capability appears regressed.**

## 15. Limitations and Anomalies Observed

- This is a single execution, not a statistical soak.
- The run proves the two-of-four sub-quorum boundary, but the optional V2B return phase is **partial/ambiguous** as a quorum-restored recovery test. V2B restarted without `--restore-from-snapshot`, without a restore baseline, and without production consensus-storage / fast-sync recovery; it reported `committed_height=None`. Therefore the post-return stall cannot be attributed purely to B14.
- V0 advanced from anchor height 12 to pre-restore height 14 after V1A/V2A/V3A SIGINT because some in-flight certified material was already present. That does not weaken the sub-quorum conclusion: after V1B caught up, V0/V1B stayed flat at height 14/view 17 for the full sub-quorum window.
- V0/V1B advanced once to height 15/view 18 after V2B started. Since no B14 timeout certificate or NewView counter moved, and V2B remained consensus-state-empty, this was not normal sustained recovery.
- V3 remained absent throughout.
- Production signature verification for timeout payloads, exponential-backoff timeout pacing, production fast-sync / consensus-storage restore, and production PQC KEMTLS root-key distribution remain outside this run.

Answer M: **yes.** `/metrics` remained honest; it showed timeout emissions without falsely reporting timeout certificates, NewViews, view-timeout advances, or resumed consensus.

## 16. Assessment of Evidence Value

Run 017 materially narrows the post-B14 boundary:

- Run 016 proved B14 recovers the Run-015 absent-leader plateau when three validators are available in N=4.
- Run 017 proves that when availability drops to two validators in N=4, B14 emits real timeout messages but cannot form a timeout certificate and does not advance views through B14.
- Restore startup, restore-catchup, and B13 exit still behave honestly even under the harsher sub-quorum shape.
- The newly landed B14 `/metrics` exports are honest and directly useful: they expose the exact difference between timeout emission and timeout-certificate / NewView recovery.

This is not positive closure for harsher recovery. It is valuable negative boundary evidence: **sub-quorum makes B14 recovery impossible until enough compatible validators are restored.** The optional V2B phase shows that “enough processes are running” is not equivalent to “a compatible quorum has been restored” when the returning validator lacks restored consensus state.

Run 017 does **not** require a `docs/whitepaper/contradiction.md` update. It confirms existing C4 constraints rather than revealing a new contradiction or materially changing the open items.

## 17. Recommended Immediate Next Action

Execute Run 018 as a narrowly controlled quorum-restoration follow-up: repeat the Run 017 two-of-four sub-quorum window, then restore the third validator with an honest snapshot/restore baseline or other explicit catchup path so that the returned validator is consensus-state-compatible. The next run should isolate whether B14 recovery resumes immediately once a real `2f+1` compatible quorum exists, without conflating that with the already-open production consensus-storage / fast-sync gap.