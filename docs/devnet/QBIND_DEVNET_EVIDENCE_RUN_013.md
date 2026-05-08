# QBIND DevNet Evidence Run 013

## 1. Purpose and Scope

Run 013 is the first real-binary evidence exercise after B13. It asks whether a validator restored from a live-sourced VM-v0 snapshot prefix now leaves bounded restore-catchup mode after catching up to the peer anchor, stops repeated catchup requests, and resumes normal forward proposal / vote / QC / commit participation on the binary path.

Scope used here:

- two real release `qbind-node` binaries;
- P2P mode, not LocalMesh;
- `--p2p-mutual-auth required` on every node;
- real `--restore-from-snapshot` startup for the restored node;
- live-sourced snapshot anchor from `/metrics`;
- real `ConsensusNetMsg::RestoreCatchupRequest` / `RestoreCatchupResponse` traffic;
- B13 restore-mode transition metrics and log signals.

Verdict: **POSITIVE for the bounded Run-013 question**. V1B restored honestly from `S=5`, requested and received real catchup responses, applied 245 peer-learned certified blocks, exited restore-catchup mode at height `246`, stopped issuing fresh repeated restore-catchup requests, and then resumed normal proposal/vote/QC/commit progression. Final metrics showed V1B at `qbind_consensus_qcs_formed_total=4736`, `qbind_consensus_committed_height=4098`, `consensus_net_inbound_total{kind="proposal"}=2368`, and `consensus_net_inbound_total{kind="vote"}=4736`.

This is not a full production restore proof. It still does not solve production fast-sync / consensus-storage restore, production PQC KEMTLS root-key distribution, or deeper view-timeout / view-change recovery for a fully deadlocked predecessor view.

## 2. Canonical Basis

- `docs/whitepaper/contradiction.md` C4 with B13 landed.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_012.md` — prior plateau: catchup reached the live peer anchor but restore-catchup requests continued and normal proposal/vote/QC/commit did not resume.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_011.md` — earlier bounded restore-catchup evidence.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010B.md` — positive two-node binary-path proposal/vote/QC/commit progression under Required mode.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010A.md` — Required-mode transport / accepted-session identity baseline.

Validation before execution:

```sh
cd /home/runner/work/QBIND/QBIND
cargo test -p qbind-node binary_consensus_loop --lib
cargo build --release -p qbind-node --bin qbind-node
```

Results:

```text
Finished `test` profile [unoptimized + debuginfo] target(s) in 5m 37s
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 597 filtered out; finished in 0.12s
warning: unused variable: `worker_id`
warning: `qbind-node` (lib) generated 1 warning (run `cargo fix --lib -p qbind-node` to apply 1 suggestion)
Finished `release` profile [optimized] target(s) in 6m 08s
```

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-post-catchup-evidence-run` |
| HEAD | `b8f146e3e20914d37453fd0d16f0dd6ed52f9389` |
| Build command | `cargo build --release -p qbind-node --bin qbind-node` |
| Targeted test command | `cargo test -p qbind-node binary_consensus_loop --lib` |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9134784` bytes |
| Binary sha256 | `d2a8dd971fb3d428b3592187370ce80623587b76693f1901170d0072cc33df8c` |
| Binary Build ID | `788f79ed54933eae0eb984924f45c3085bb67dd7` |
| Run directory | `/tmp/run013` |
| Script start UTC | `2026-05-08T05:58:27.338Z` |
| Script end UTC | `2026-05-08T06:07:21.435Z` |
| `QBIND_MUTUAL_AUTH` | unset; CLI `--p2p-mutual-auth required` was used |

## 4. Topology and Node Configuration Used

| Node | Phase | Validator | Listen | Static peer | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---|---|---|---|---|---|---|---|
| V0 | whole run | `ValidatorId(0)` | `127.0.0.1:19330` | `1@127.0.0.1:19331` | `required` | `/tmp/run013/data-v0` | `127.0.0.1:9330` | none |
| V1A | live pre-restore | `ValidatorId(1)` | `127.0.0.1:19331` | `0@127.0.0.1:19330` | `required` | `/tmp/run013/data-v1-initial` | `127.0.0.1:9331` | none |
| V1B | restored | `ValidatorId(1)` | `127.0.0.1:19331` | `0@127.0.0.1:19330` | `required` | `/tmp/run013/data-v1-restored` | `127.0.0.1:9332` | `/tmp/run013/snap` |

All nodes logged `network=p2p`, `interconnect=p2p`, `num_validators=2`, and `mutual_auth=Required`. No LocalMesh or Disabled mutual-auth fallback was used.

## 5. Commands and Configuration Used

Environment and build metadata command:

```sh
cd /home/runner/work/QBIND/QBIND
{
  echo "SCRIPT_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  echo "HOST=$(hostname)"
  uname -a
  if [ -f /etc/os-release ]; then . /etc/os-release; echo "DISTRO=$PRETTY_NAME"; fi
  rustc --version
  cargo --version
  git -C /home/runner/work/QBIND/QBIND --no-pager branch --show-current
  git -C /home/runner/work/QBIND/QBIND --no-pager rev-parse HEAD
  stat -c 'BIN_SIZE=%s' /home/runner/work/QBIND/QBIND/target/release/qbind-node
  sha256sum /home/runner/work/QBIND/QBIND/target/release/qbind-node
  readelf -n /home/runner/work/QBIND/QBIND/target/release/qbind-node | grep 'Build ID'
  echo "QBIND_MUTUAL_AUTH=${QBIND_MUTUAL_AUTH-<unset>}"
}
```

V0 command:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9330 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 0 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19330 \
  --p2p-peer 1@127.0.0.1:19331 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run013/data-v0 \
  > /tmp/run013/logs/v0.log 2>&1 &
```

V1A command, 10 seconds after V0:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9331 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19331 \
  --p2p-peer 0@127.0.0.1:19330 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run013/data-v1-initial \
  > /tmp/run013/logs/v1a.log 2>&1 &
```

Snapshot creation used live V0 `/metrics` state captured in `/tmp/run013/live_anchor.txt`:

```json
{
  "height": 5,
  "block_hash": "0100000000000000050000000000000000000000000000000400000000000000",
  "created_at_unix_ms": 1778219918535,
  "chain_id": 5855328520645203456
}
```

Snapshot file hashes:

```text
cdf6a8a17a43e8305f136cf476810c5f15d7ad54f9a607296ae158f0827d6e31  /tmp/run013/snap/meta.json
3f77d3fc7d3fba2afc9668c42ce3adb74e6a6dec4a81dbd470c06df2d08c31c8  /tmp/run013/snap/state/.placeholder.txt
```

V1B restored command:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9332 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19331 \
  --p2p-peer 0@127.0.0.1:19330 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run013/data-v1-restored \
  --restore-from-snapshot /tmp/run013/snap \
  > /tmp/run013/logs/v1b.log 2>&1 &
```

Metrics were scraped from:

- `http://127.0.0.1:9330/metrics`
- `http://127.0.0.1:9331/metrics`
- `http://127.0.0.1:9332/metrics`

## 6. Live-Cluster Pre-Restore Progress Evidence

Startup excerpts:

```text
qbind-node[validator=V0]: starting in environment=DevNet ... network=p2p p2p=enabled listen=127.0.0.1:19330 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on

qbind-node[validator=V1]: starting in environment=DevNet ... network=p2p p2p=enabled listen=127.0.0.1:19331 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

Pre-restore metrics:

| Metric | V0 anchor scrape | V0 before V1A stop | V1A before stop | V0 after V1A stop |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 8 | 248 | 247 | 249 |
| `qbind_consensus_qcs_formed_total` | 8 | 248 | 247 | 249 |
| `qbind_consensus_committed_height` | 5 | 245 | 244 | 246 |
| `qbind_consensus_view_lag` | 0 | 0 | 0 | 0 |
| `consensus_net_inbound_total{kind="vote"}` | 8 | 248 | 247 | 249 |
| `consensus_net_inbound_total{kind="proposal"}` | 4 | 124 | 124 | 124 |
| `qbind_consensus_proposals_total{result="accepted"}` | 9 | 248 | 248 | 249 |

Answer A: yes. The live binary-path cluster progressed normally before restore: proposals, votes, QCs, views, and commits advanced under real P2P Required mode.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor provenance:

```text
ANCHOR_SOURCE=/metrics on live V0
ANCHOR_HEIGHT=5
ANCHOR_BLOCK=0100000000000000050000000000000000000000000000000400000000000000
ANCHOR_CAPTURE_UTC=2026-05-08T05:58:38.511Z
```

Live V0 anchor scrape:

```text
qbind_consensus_current_view 8
qbind_consensus_qcs_formed_total 8
qbind_consensus_committed_height 5
qbind_consensus_committed_block_info{block_id="0100000000000000050000000000000000000000000000000400000000000000"} 1
```

Restored-node startup excerpt:

```text
[restore] requested: snapshot_dir=/tmp/run013/snap data_dir=/tmp/run013/data-v1-restored expected_chain_id=0x51424e4444455600
[restore] complete: height=5 chain_id=0x51424e4444455600 bytes_copied=90 target=/tmp/run013/data-v1-restored/state_vm_v0
[restore] audit marker written to /tmp/run013/data-v1-restored/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=5 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=5, starting_view=6)
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=true interconnect=p2p
[binary-consensus] B5: applied restore baseline: snapshot_height=5 starting_view=6 (engine committed_height=Some(5))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=true interconnect=p2p late_peer_reemit=on
```

Answer B: yes, the snapshot anchor was sourced from live peer `/metrics` state.

Answer C: yes, V1B started honestly from `S=5`; it did not pretend to already have post-S history.

## 8. Restore-Catchup Request / Response Evidence

At the first post-restore scrape, V1B had sent catchup requests and received responses; V0 had received and answered those requests:

| Metric | V0 first post-restore scrape | V1B first post-restore scrape | V0 final | V1B final |
|---|---:|---:|---:|---:|
| `qbind_restore_catchup_requests_sent_total` | 0 | 3 | 0 | 3 |
| `qbind_restore_catchup_requests_received_total` | 2 | 0 | 2 | 0 |
| `qbind_restore_catchup_responses_sent_total` | 2 | 0 | 2 | 0 |
| `qbind_restore_catchup_responses_received_total` | 0 | 2 | 0 | 2 |
| `qbind_restore_catchup_blocks_applied_total` | 0 | 245 | 0 | 245 |
| `qbind_restore_catchup_responses_rejected_total` | 0 | 0 | 0 | 0 |
| `consensus_net_inbound_total{kind="other"}` | 2 | 2 | 2 | 2 |

V1B log excerpt:

```text
[P2P] Dial 127.0.0.1:19330: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
[restore-catchup] applied 128 peer-learned certified blocks; committed_height=Some(131) view=134
[binary-consensus] committed_anchor height=131 block_id=0100000000000000830000000000000000000000000000008200000000000000
[restore-catchup] applied 117 peer-learned certified blocks; committed_height=Some(246) view=249
```

Answer D: yes. V1B issued restore-catchup requests and received responses on the real binary path. V0's reciprocal counters confirm it received and answered the requests.

Answer E: yes. V1B validated/applied learned post-S material; `qbind_restore_catchup_blocks_applied_total=245` and `qbind_restore_catchup_responses_rejected_total=0`.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

Learned-suffix progression:

| Step | Evidence | V1B committed height | V1B view |
|---|---|---:|---:|
| Restore baseline | B5 startup | 5 | 6 |
| First catchup response | `applied 128 peer-learned certified blocks` | 131 | 134 |
| Second catchup response | `applied 117 peer-learned certified blocks` | 246 | 249 |
| First post-exit metrics scrape | `/metrics` | 272 | 275 |
| Final metrics scrape | `/metrics` | 4098 | 4985 |

Post-exit committed-anchor log excerpt:

```text
[restore-catchup] exit: caught up to peer anchor — local committed_height=246 peer_max_observed=Some(246); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
[binary-consensus] committed_anchor height=246 block_id=0000000000000000f6000000000000000100000000000000f500000000000000
[binary-consensus] committed_anchor height=247 block_id=0100000000000000f7000000000000000000000000000000f600000000000000
[binary-consensus] committed_anchor height=248 block_id=0000000000000000f8000000000000000100000000000000f700000000000000
...
[binary-consensus] committed_anchor height=4098 block_id=0000000000000000021000000000000001000000000000000110000000000000
```

Answer F: yes. Committed height advanced above `S=5`: first to `246` through catchup, then to `4098` after mode exit and resumed normal participation.

## 10. Restore-Mode Exit Evidence

B13 exit was directly observable in both logs and metrics.

Log evidence:

```text
[restore-catchup] exit: caught up to peer anchor — local committed_height=246 peer_max_observed=Some(246); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Metrics evidence:

| Scrape | `qbind_restore_catchup_mode_active` | `qbind_restore_catchup_mode_exited_at_height` | `qbind_restore_catchup_requests_sent_total` | `qbind_restore_catchup_responses_received_total` |
|---|---:|---:|---:|---:|
| first post-restore V1B scrape | 0 | 246 | 3 | 2 |
| final V1B scrape | 0 | 246 | 3 | 2 |

Answer G: yes. B13 restore-catchup mode exited at height `246`.

Answer H: yes. Repeated restore-catchup requests stopped/flattened materially. V1B's request counter was `3` at the first post-restore scrape and remained `3` at final; response counter remained `2`. This differs from Run 012, where requests continued rising to `141`.

## 11. Post-Exit Forward Proposal / Vote / QC / Commit Evidence

Post-exit progression was observed on the restored node and live peer:

| Scrape timestamp UTC | Node | View | QCs formed | Committed height | Inbound proposals | Inbound votes | Accepted proposals | Restore req sent | Mode active | Mode exited at |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `2026-05-08 05:59:10` | V0 | 276 | 276 | 273 | 138 | 276 | 276 | 0 | 0 | 0 |
| `2026-05-08 05:59:10` | V1B | 275 | 26 | 272 | 13 | 26 | 27 | 3 | 0 | 246 |
| `2026-05-08 05:59:20` | V0 | 372 | 372 | 369 | 186 | 372 | 373 | 0 | 0 | 0 |
| `2026-05-08 05:59:20` | V1B | 373 | 124 | 370 | 62 | 124 | 124 | 3 | 0 | 246 |
| `2026-05-08 05:59:40` | V0 | 566 | 566 | 563 | 283 | 566 | 566 | 0 | 0 | 0 |
| `2026-05-08 05:59:40` | V1B | 565 | 316 | 562 | 158 | 316 | 317 | 3 | 0 | 246 |
| `2026-05-08 06:00:20` | V0 | 950 | 950 | 947 | 475 | 950 | 951 | 0 | 0 | 0 |
| `2026-05-08 06:00:20` | V1B | 951 | 702 | 948 | 351 | 702 | 702 | 3 | 0 | 246 |
| `2026-05-08 06:01:41` | V0 | 1720 | 1720 | 1717 | 860 | 1720 | 1721 | 0 | 0 | 0 |
| `2026-05-08 06:01:41` | V1B | 1721 | 1472 | 1718 | 736 | 1472 | 1473 | 3 | 0 | 246 |
| `2026-05-08 06:04:01` | V0 | 3068 | 3068 | 3065 | 1534 | 3068 | 3068 | 0 | 0 | 0 |
| `2026-05-08 06:04:01` | V1B | 3067 | 2818 | 3064 | 1409 | 2818 | 2819 | 3 | 0 | 246 |
| `2026-05-08 06:07:21` | V0 | 4984 | 4984 | 4093 | 2492 | 4984 | 4985 | 0 | 0 | 0 |
| `2026-05-08 06:07:21` | V1B | 4985 | 4736 | 4098 | 2368 | 4736 | 4736 | 3 | 0 | 246 |

Answer I: yes. Normal proposal/vote participation resumed after mode exit. V1B's inbound proposal counter rose from `13` to `2368`, inbound votes rose from `26` to `4736`, accepted proposals rose from `27` to `4736`, and final loop-exit counters showed `outbound_proposals=2369` and `outbound_votes=4737`.

Answer J: yes. Forward QC formation resumed after mode exit: V1B `qbind_consensus_qcs_formed_total` rose from `26` to `4736`.

Answer K: yes. Committed height advanced beyond the Run-012 plateau shape. Run 012 plateaued at `committed_height=339`; Run 013 V1B reached `4098` and V0 reached `4093` before clean shutdown.

## 12. Metrics Evidence

Final V0 metrics excerpt:

```text
consensus_net_inbound_total{kind="vote"} 4984
consensus_net_inbound_total{kind="proposal"} 2492
consensus_net_inbound_total{kind="other"} 2
qbind_consensus_qcs_formed_total 4984
qbind_restore_catchup_requests_sent_total 0
qbind_restore_catchup_requests_received_total 2
qbind_restore_catchup_responses_sent_total 2
qbind_restore_catchup_responses_received_total 0
qbind_restore_catchup_blocks_applied_total 0
qbind_restore_catchup_responses_rejected_total 0
qbind_restore_catchup_proposals_deferred_total 0
qbind_restore_catchup_mode_active 0
qbind_restore_catchup_mode_exited_at_height 0
qbind_consensus_committed_height 4093
qbind_consensus_committed_block_info{block_id="0100000000000000fd0f0000000000000000000000000000fc0f000000000000"} 1
qbind_consensus_current_view 4984
qbind_consensus_view_lag 0
qbind_consensus_proposals_total{result="accepted"} 4985
```

Final V1B metrics excerpt:

```text
consensus_net_inbound_total{kind="vote"} 4736
consensus_net_inbound_total{kind="proposal"} 2368
consensus_net_inbound_total{kind="other"} 2
qbind_consensus_qcs_formed_total 4736
qbind_restore_catchup_requests_sent_total 3
qbind_restore_catchup_requests_received_total 0
qbind_restore_catchup_responses_sent_total 0
qbind_restore_catchup_responses_received_total 2
qbind_restore_catchup_blocks_applied_total 245
qbind_restore_catchup_responses_rejected_total 0
qbind_restore_catchup_proposals_deferred_total 0
qbind_restore_catchup_mode_active 0
qbind_restore_catchup_mode_exited_at_height 246
qbind_consensus_committed_height 4098
qbind_consensus_committed_block_info{block_id="0000000000000000021000000000000001000000000000000110000000000000"} 1
qbind_consensus_current_view 4985
qbind_consensus_view_lag 0
qbind_consensus_proposals_total{result="accepted"} 4736
```

Answer L: yes. `/metrics` remained honest. It showed the restored node's catchup, transition exit, flattened catchup requests, real proposal/vote/QC progression, and commit advancement. It did not fabricate a disabled restore mode on non-restored V0; V0 correctly remained `mode_exited_at_height=0`.

## 13. Shutdown Evidence

Shutdown was performed with SIGINT-equivalent signaling to each recorded process, so the binary shutdown path ran.

```text
/tmp/run013/logs/v1a.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run013/logs/v1a.log:[binary-consensus] Shutdown signal received after 262 ticks.
/tmp/run013/logs/v1a.log:[binary-consensus] Loop exit: ticks=262 proposals=124 commits=247 committed_height=Some(246) view=249 inbound_msgs=374 inbound_proposals=125 inbound_votes=249 outbound_proposals=124 outbound_votes=249 outbound_proposal_late_peer_reemits=0
/tmp/run013/logs/v1a.log:[binary] Shutdown complete.

/tmp/run013/logs/v1b.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run013/logs/v1b.log:[binary-consensus] Shutdown signal received after 4955 ticks.
/tmp/run013/logs/v1b.log:[binary-consensus] Loop exit: ticks=4955 proposals=2369 commits=4093 committed_height=Some(4098) view=4985 inbound_msgs=7106 inbound_proposals=2368 inbound_votes=4736 outbound_proposals=2369 outbound_votes=4737 outbound_proposal_late_peer_reemits=0
/tmp/run013/logs/v1b.log:[binary] Shutdown complete.

/tmp/run013/logs/v0.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run013/logs/v0.log:[binary-consensus] Shutdown signal received after 5338 ticks.
/tmp/run013/logs/v0.log:[binary-consensus] Loop exit: ticks=5338 proposals=2494 commits=4094 committed_height=Some(4093) view=4986 inbound_msgs=7481 inbound_proposals=2493 inbound_votes=4986 outbound_proposals=2494 outbound_votes=4987 outbound_proposal_late_peer_reemits=1
/tmp/run013/logs/v0.log:[binary] Shutdown complete.
```

Answer M: yes. Shutdown remained clean for V1A, V1B, and V0.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 013 observation | Result |
|---|---|---|
| B3 restore startup | V1B used `--restore-from-snapshot /tmp/run013/snap`; validation/materialization succeeded and wrote `RESTORED_FROM_SNAPSHOT.json`. | No regression observed |
| B5 restore-aware consensus start | V1B logged `restore_baseline=true` and `engine committed_height=Some(5)`. | No regression observed |
| B6 binary P2P routing | Live V0/V1A proposal/vote/QC counters advanced; V1B later exchanged proposal/vote traffic and catchup frames over P2P. | No regression observed |
| B7/B8 identity / retry | NodeIds were deterministic; peer validator override logs were present; V0 showed bounded initial dial retry before V1A started. | No regression observed |
| B9/B10 late-peer re-emit / recorder wiring | V0 logged `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect`; pre-restore and post-restore engine counters advanced. | No regression observed |
| B11/B12 identity / Required path | All nodes logged `mutual_auth_mode=Required (source: --p2p-mutual-auth)` and `mutual_auth=Required`; no Disabled fallback appeared. | No regression observed |
| B13 transition | V1B logged the restore-catchup exit and exposed `qbind_restore_catchup_mode_active 0`, `qbind_restore_catchup_mode_exited_at_height 246`. | No regression observed; B13 active on real binaries |
| No LocalMesh fallback | All commands used `--network-mode p2p --enable-p2p`; logs showed `interconnect=p2p`. | No fallback observed |
| Honest metrics | Metrics showed catchup counters, exit height, flattened catchup requests, and resumed consensus counters. | No fabrication observed |

Answer N: no previously landed binary-path capability appears regressed in this run.

## 15. Limitations and Anomalies Observed

- Run 013 is a positive bounded real-binary run, not a full production fast-sync / consensus-storage restore proof. The snapshot `state/` content remains the accepted VM-v0 snapshot layout used by earlier evidence; it is not a production consensus-store checkpoint.
- Run 013 does not prove recovery from the exact fully deadlocked predecessor-view shape observed in Run 012. In this run, V0 and V1B reconnected in a way that allowed forward proposal/vote/QC flow after B13 exit. C4's separate view-timeout / view-change limitation remains open.
- V0 and V1B final committed heights differed (`4093` vs `4098`) while both were still advancing and view lag was `0` at the final scrape. This was not a plateau; it appears to be a live scraping/shutdown timing skew, and both nodes had thousands of QCs and inbound votes. It should be watched in longer runs but is not evidence of restored-node non-participation.
- The script's post-restore scrape labels used interval labels (`5`, `10`, `20`, `40`, `80`, `140`, `200`) while the sleeps were cumulative. The table in §11 uses the actual metric file timestamps, not the labels, to avoid overstating elapsed timing.

## 16. Assessment of Evidence Value

Run 013 materially improves Run 012's answer:

- Positive: live cluster progressed normally before restore.
- Positive: the snapshot anchor was sourced from live V0 `/metrics`.
- Positive: V1B started honestly from `S=5` and applied B5 restore baseline.
- Positive: V1B issued/received real restore-catchup traffic under P2P Required mode.
- Positive: V1B validated/applied learned certified suffix material and advanced above `S`.
- Positive: B13 mode exit happened at height `246` and was visible in logs and metrics.
- Positive: restore-catchup request counters flattened after exit (`3` at first post-restore scrape and `3` final).
- Positive: proposal/vote/QC/commit progression resumed after exit and advanced far beyond the Run-012 plateau.
- Negative / still open: this does not solve production fast-sync / consensus-storage restore, production PQC KEMTLS root-key distribution, or deadlocked-view recovery without an active proposal/vote path.

C4 is materially sharpened by this run: B13 is no longer only unit-test and implementation evidence; it now has a positive real-binary evidence run showing restore-mode exit and resumed forward consensus in the bounded non-deadlocked case.

## 17. Recommended Immediate Next Action

Run one narrow follow-up evidence exercise that intentionally recreates the Run-012 deadlocked predecessor-view timing and verifies the exact remaining boundary: whether the system needs a binary-path view-timeout / view-change driver, responder-side pending-proposal piggybacking on catchup response, or another minimal mechanism to recover when B13 exits but no live proposal/vote path is available.