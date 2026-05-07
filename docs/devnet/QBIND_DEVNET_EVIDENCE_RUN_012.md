# QBIND DevNet Evidence Run 012

## 1. Purpose and Scope

Run 012 is the smallest follow-up to Run 011 on the real `qbind-node` binary path. It asks whether a restored validator that completes bounded restore-catchup above a VM-v0 snapshot prefix causes the two-validator cluster to resume forward QC / commit progression.

Scope:

- two real release `qbind-node` binaries;
- P2P mode, not LocalMesh;
- `--p2p-mutual-auth required` on every node;
- real `--restore-from-snapshot` startup for the restored node;
- real `ConsensusNetMsg::RestoreCatchupRequest` / `RestoreCatchupResponse` traffic;
- a small observability-only code change before the run: `/metrics` now exposes the live committed anchor and the existing restore-catchup counters. This did not alter consensus, restore, routing, or catchup validation logic.

Run 012 is **PARTIAL POSITIVE**. It closes the two Run 011 observability gaps, proves bounded catchup again from a live-sourced snapshot anchor, and proves the restored node catches up from `S=1` to `committed_height=339`. It does **not** prove resumed forward QC formation after catchup: both nodes plateaued at `current_view=342`, V0 stayed at `qbind_consensus_qcs_formed_total=342`, and V1B stayed at `qbind_consensus_qcs_formed_total=0` after catchup.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_011.md` — prior bounded restore-catchup evidence and the two observability gaps this run tightens.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010B.md` — positive two-node binary-path proposal/vote/QC/commit progression under `--p2p-mutual-auth required`.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010A.md` — Required-mode transport / accepted-session identity baseline.
- `docs/whitepaper/contradiction.md` C4 — still-open production binary-node boundary.
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` — restore-proof framing.
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — DevNet evidence framing.
- Code touched for observability only before execution:
  - `crates/qbind-node/src/metrics.rs` — added `qbind_consensus_committed_height`, `qbind_consensus_committed_block_info{block_id=...}`, and `qbind_restore_catchup_*` metric families.
  - `crates/qbind-node/src/binary_consensus_loop.rs` — publishes the existing in-loop committed anchor and restore-catchup counters into `NodeMetrics`.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-devnet-evidence-run-012` |
| HEAD | `32d01b47f46216a78ea5035bab67f07e997564ae` |
| Build command | `cargo build --release -p qbind-node --bin qbind-node` |
| Targeted test command | `cargo test -p qbind-node binary_consensus_loop --lib` |
| Post-change build result | success; pre-existing `unused variable: worker_id` warning in `crates/qbind-node/src/verify_pool.rs:262:9` |
| Post-change targeted test result | success; 8 passed, 0 failed |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9133840` bytes |
| Binary sha256 | `50cfb7978f2405d37c2af1db5790974e64de5610eccdf3382514993b42379372` |
| Binary Build ID | `be622da123fc912130c4a36ba1d29c8086c7cf02` |
| Run directory | `/tmp/run012` |
| Script start UTC | `2026-05-07T16:25:06.852Z` |
| Script end UTC | `2026-05-07T16:28:13.820Z` |

Validation commands run before execution:

```sh
cd /home/runner/work/QBIND/QBIND
cargo test -p qbind-node binary_consensus_loop --lib
cargo build --release -p qbind-node --bin qbind-node
```

## 4. Topology and Node Configuration Used

| Node | Phase | Validator | Listen | Static peer | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---|---|---|---|---|---|---|---|
| V0 | whole run | `ValidatorId(0)` | `127.0.0.1:19320` | `1@127.0.0.1:19321` | `required` | `/tmp/run012/data-v0` | `127.0.0.1:9320` | none |
| V1A | live pre-restore | `ValidatorId(1)` | `127.0.0.1:19321` | `0@127.0.0.1:19320` | `required` | `/tmp/run012/data-v1-initial` | `127.0.0.1:9321` | none |
| V1B | restored | `ValidatorId(1)` | `127.0.0.1:19321` | `0@127.0.0.1:19320` | `required` | `/tmp/run012/data-v1-restored` | `127.0.0.1:9322` | `/tmp/run012/snap` |

`QBIND_MUTUAL_AUTH` was not set; the CLI flag `--p2p-mutual-auth required` was the mutual-auth source. All nodes reported `num_validators=2`, `interconnect=p2p`, and B12 Required mode.

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
  git --no-pager branch --show-current
  git --no-pager rev-parse HEAD
  stat -c 'BIN_SIZE=%s' /home/runner/work/QBIND/QBIND/target/release/qbind-node
  sha256sum /home/runner/work/QBIND/QBIND/target/release/qbind-node
  readelf -n /home/runner/work/QBIND/QBIND/target/release/qbind-node | grep 'Build ID'
}
```

V0 command:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9320 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 0 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19320 \
  --p2p-peer 1@127.0.0.1:19321 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run012/data-v0 \
  > /tmp/run012/logs/v0.log 2>&1 &
```

V1A command, 10 seconds after V0:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9321 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19321 \
  --p2p-peer 0@127.0.0.1:19320 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run012/data-v1-initial \
  > /tmp/run012/logs/v1a.log 2>&1 &
```

Snapshot creation used the live V0 `/metrics` anchor captured in `/tmp/run012/live_anchor.txt`:

```json
{
  "height": 1,
  "block_hash": "0100000000000000010000000000000000000000000000000000000000000000",
  "created_at_unix_ms": 1778171152709,
  "chain_id": 5855328520645203456
}
```

Snapshot file hashes:

```text
b4e938626a829d67fbf31cde54dd8c3e9f02fe1f925638db59260d8938da250a  /tmp/run012/snap/meta.json
00a7807b367f5bf706531f21c04e0c0bef90f5ba592afa66a21e46c91ca5b068  /tmp/run012/snap/state/.placeholder.txt
```

V1B restored command:

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9322 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19321 \
  --p2p-peer 0@127.0.0.1:19320 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run012/data-v1-restored \
  --restore-from-snapshot /tmp/run012/snap \
  > /tmp/run012/logs/v1b.log 2>&1 &
```

Metrics were scraped from:

- `http://127.0.0.1:9320/metrics`
- `http://127.0.0.1:9321/metrics`
- `http://127.0.0.1:9322/metrics`

## 6. Live-Cluster Pre-Restore Progress Evidence

Startup evidence:

```text
qbind-node[validator=V0]: starting in environment=DevNet ... network=p2p p2p=enabled listen=127.0.0.1:19320 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on

qbind-node[validator=V1]: starting in environment=DevNet ... network=p2p p2p=enabled listen=127.0.0.1:19321 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

Pre-restore metrics:

| Metric | V0 live anchor | V0 phase A | V1A phase A | V0 after V1A stop |
|---|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 4 | 340 | 341 | 342 |
| `qbind_consensus_qcs_formed_total` | 4 | 340 | 341 | 342 |
| `qbind_consensus_committed_height` | 1 | 337 | 338 | 339 |
| `qbind_consensus_view_lag` | 0 | 0 | 0 | 0 |
| `consensus_net_inbound_total{kind="vote"}` | 4 | 340 | 341 | 342 |
| `consensus_net_inbound_total{kind="proposal"}` | 2 | 170 | 171 | 171 |
| `qbind_consensus_proposals_total{result="accepted"}` | 5 | 341 | 342 | 343 |

Answer A: yes, the live binary-path cluster progressed normally before restore. It formed QCs, advanced views, committed heights, and exchanged proposal/vote traffic on the real P2P path under Required mutual auth.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor provenance is improved over Run 011. It was sourced from live V0 `/metrics`, not recomputed offline:

```text
ANCHOR_SOURCE=/metrics on live V0
ANCHOR_HEIGHT=1
ANCHOR_BLOCK=0100000000000000010000000000000000000000000000000000000000000000
ANCHOR_CAPTURE_UTC=2026-05-07T16:25:17.565Z
```

The exact live V0 metric scrape at anchor capture showed:

```text
qbind_consensus_current_view 4
qbind_consensus_qcs_formed_total 4
qbind_consensus_committed_height 1
qbind_consensus_committed_block_info{block_id="0100000000000000010000000000000000000000000000000000000000000000"} 1
```

The snapshot was then created with that live-sourced `(height, block_hash)`. V1B restore startup excerpt:

```text
[restore] requested: snapshot_dir=/tmp/run012/snap data_dir=/tmp/run012/data-v1-restored expected_chain_id=0x51424e4444455600
[restore] complete: height=1 chain_id=0x51424e4444455600 bytes_copied=74 target=/tmp/run012/data-v1-restored/state_vm_v0
[restore] audit marker written to /tmp/run012/data-v1-restored/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=1 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=1, starting_view=2)
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=true interconnect=p2p
[binary-consensus] B5: applied restore baseline: snapshot_height=1 starting_view=2 (engine committed_height=Some(1))
```

Answer B: the snapshot anchor was sourced from live peer state via `/metrics`.

Answer C: yes, the restored node started honestly from `S=1`; it did not pretend to have post-S history.

## 8. Restore-Catchup Request / Response Evidence

`/metrics` now exposes restore-catchup counters directly. At 20 seconds after V1B restore:

| Metric | V0 | V1B |
|---|---:|---:|
| `qbind_restore_catchup_requests_sent_total` | 0 | 21 |
| `qbind_restore_catchup_requests_received_total` | 19 | 0 |
| `qbind_restore_catchup_responses_sent_total` | 19 | 0 |
| `qbind_restore_catchup_responses_received_total` | 0 | 19 |
| `qbind_restore_catchup_blocks_applied_total` | 0 | 376 |
| `qbind_restore_catchup_responses_rejected_total` | 0 | 0 |
| `consensus_net_inbound_total{kind="other"}` | 19 | 19 |

At final scrape:

| Metric | V0 | V1B |
|---|---:|---:|
| `qbind_restore_catchup_requests_sent_total` | 0 | 141 |
| `qbind_restore_catchup_requests_received_total` | 139 | 0 |
| `qbind_restore_catchup_responses_sent_total` | 139 | 0 |
| `qbind_restore_catchup_responses_received_total` | 0 | 139 |
| `qbind_restore_catchup_blocks_applied_total` | 0 | 616 |
| `qbind_restore_catchup_responses_rejected_total` | 0 | 0 |
| `consensus_net_inbound_total{kind="other"}` | 139 | 139 |

V1B stderr catchup excerpt:

```text
[restore-catchup] applied 128 peer-learned certified blocks; committed_height=Some(127) view=130
[restore-catchup] applied 128 peer-learned certified blocks; committed_height=Some(253) view=256
[restore-catchup] applied 88 peer-learned certified blocks; committed_height=Some(339) view=342
[restore-catchup] applied 2 peer-learned certified blocks; committed_height=Some(339) view=342
...
[restore-catchup] applied 2 peer-learned certified blocks; committed_height=Some(339) view=342
```

Answer D: yes, V1B issued restore-catchup requests and received responses on the real binary path. V0's reciprocal request/response counters confirm it received and answered those requests.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

The informative catchup progression was:

| Step | Applied count in log | V1B committed height | V1B view |
|---|---:|---:|---:|
| Restore baseline | n/a | 1 | 2 |
| First response | 128 | 127 | 130 |
| Second response | 128 | 253 | 256 |
| Third response | 88 | 339 | 342 |

V1B `/metrics` at 20 seconds confirmed the same endpoint state:

```text
qbind_consensus_current_view 342
qbind_consensus_committed_height 339
qbind_restore_catchup_responses_received_total 19
qbind_restore_catchup_blocks_applied_total 376
qbind_restore_catchup_responses_rejected_total 0
qbind_consensus_committed_block_info{block_id="0100000000000000530100000000000000000000000000005201000000000000"} 1
```

The repeated later `applied 2` lines did not advance committed height beyond 339. They are recorded as an anomaly in §14; they did not fake progress because `/metrics` and stderr both kept `committed_height=339` and `current_view=342`.

Answer E: yes, V1B validated/applied learned post-S material; there were zero rejected restore-catchup responses.

Answer F: yes, committed height advanced above `S=1`, reaching `339`.

## 10. Post-Catchup Forward-QC / Resume Evidence

After V1B reached `committed_height=339` / `current_view=342`, the run left V0 and V1B running for about 120 more seconds. No forward QC or commit progression resumed.

| Metric | V0 at 20s | V0 at 80s | V0 final | V1B at 20s | V1B at 80s | V1B final |
|---|---:|---:|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 342 | 342 | 342 | 342 | 342 | 342 |
| `qbind_consensus_qcs_formed_total` | 342 | 342 | 342 | 0 | 0 | 0 |
| `qbind_consensus_committed_height` | 339 | 339 | 339 | 339 | 339 | 339 |
| `consensus_net_inbound_total{kind="vote"}` | 342 | 342 | 342 | 0 | 0 | 0 |
| `consensus_net_inbound_total{kind="proposal"}` | 171 | 171 | 171 | 0 | 0 | 0 |
| `qbind_consensus_proposals_total{result="accepted"}` | 343 | 343 | 343 | 0 | 0 | 0 |

Answer G: no, forward QC formation did not resume after catchup. V0's QC counter did not advance after restore, and V1B's QC counter stayed at zero.

Answer H: the restored node's committed height advanced beyond the Run 011 plateau (`331`) by catchup, reaching `339`; however, committed height did not advance beyond the new Run 012 plateau (`339`) during the post-catchup observation window.

## 11. Metrics Evidence

Run 012 directly exposed both observability surfaces that Run 011 lacked:

1. Live committed anchor:

```text
qbind_consensus_committed_height 1
qbind_consensus_committed_block_info{block_id="0100000000000000010000000000000000000000000000000000000000000000"} 1
```

2. Restore-catchup counters:

```text
qbind_restore_catchup_requests_sent_total 141
qbind_restore_catchup_requests_received_total 0
qbind_restore_catchup_responses_sent_total 0
qbind_restore_catchup_responses_received_total 139
qbind_restore_catchup_blocks_applied_total 616
qbind_restore_catchup_responses_rejected_total 0
qbind_restore_catchup_proposals_deferred_total 0
```

Metrics remained honest rather than claiming recovery success: forward consensus counters stayed flat after catchup.

Answer I: yes, `/metrics` remained honest. It showed catchup request/response traffic and commit catchup, but also showed no post-catchup QC or commit resumption.

## 12. Shutdown Evidence

Shutdown was performed with SIGINT so the binary's `tokio::signal::ctrl_c()` path ran. Logs:

```text
/tmp/run012/logs/v0.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run012/logs/v0.log:[binary-consensus] Shutdown signal received after 1859 ticks.
/tmp/run012/logs/v0.log:[binary-consensus] Loop exit: ticks=1859 proposals=172 commits=340 committed_height=Some(339) view=342 inbound_msgs=652 inbound_proposals=171 inbound_votes=342 outbound_proposals=172 outbound_votes=343 outbound_proposal_late_peer_reemits=1
/tmp/run012/logs/v0.log:[binary] Stopping metrics HTTP server...
/tmp/run012/logs/v0.log:[binary] Shutdown complete.

/tmp/run012/logs/v1a.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run012/logs/v1a.log:[binary-consensus] Shutdown signal received after 357 ticks.
/tmp/run012/logs/v1a.log:[binary-consensus] Loop exit: ticks=357 proposals=171 commits=339 committed_height=Some(338) view=341 inbound_msgs=512 inbound_proposals=171 inbound_votes=341 outbound_proposals=171 outbound_votes=342 outbound_proposal_late_peer_reemits=0
/tmp/run012/logs/v1a.log:[binary] Stopping metrics HTTP server...
/tmp/run012/logs/v1a.log:[binary] Shutdown complete.

/tmp/run012/logs/v1b.log:[binary] Shutdown signal received, stopping P2P node...
/tmp/run012/logs/v1b.log:[binary-consensus] Shutdown signal received after 1401 ticks.
/tmp/run012/logs/v1b.log:[binary-consensus] Loop exit: ticks=1401 proposals=0 commits=338 committed_height=Some(339) view=342 inbound_msgs=139 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0 outbound_proposal_late_peer_reemits=0
/tmp/run012/logs/v1b.log:[binary] Stopping metrics HTTP server...
/tmp/run012/logs/v1b.log:[binary] Shutdown complete.
```

Answer J: yes, shutdown remained clean.

## 13. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 012 observation | Result |
|---|---|---|
| B3 restore startup | V1B used `--restore-from-snapshot /tmp/run012/snap`; validation/materialization succeeded and wrote audit marker. | No regression observed |
| B5 restore-aware consensus start | V1B logged `restore_baseline=true` and `engine committed_height=Some(1)`. | No regression observed |
| B6 binary P2P routing | V0/V1A proposal/vote counters advanced before restore; restore request/response frames crossed as `kind="other"`. | No regression observed |
| B7/B8 identity closure / deterministic node identity | startup showed deterministic NodeIds and peer validator overrides. | No regression observed |
| B9/B10 late-peer re-emit / engine recorder | V0 final loop exit showed `outbound_proposal_late_peer_reemits=1`; live QC metrics advanced pre-restore. | No regression observed |
| B12 Required mode | all nodes logged `mutual_auth_mode=Required (source: --p2p-mutual-auth)`. | No regression observed |
| No LocalMesh fallback | all nodes logged `network=p2p`, `interconnect=p2p`. | No fallback observed |
| Honest metrics | metrics showed catchup success but no forward resume. | No fabrication observed |

Answer K: no previously landed binary-path capability appears regressed. The forward-resume gap remains, but that was the question under test rather than an observed regression of prior proven behavior.

## 14. Limitations and Anomalies Observed

- Forward QC / commit did not resume after catchup. The closest precise boundary from evidence is that V1B reached V0's committed anchor (`339` / view `342`) but did not emit or receive proposal/vote traffic afterward (`outbound_proposals=0`, `outbound_votes=0`, V1B `qbind_consensus_qcs_formed_total=0`).
- V1B continued sending restore-catchup requests after reaching the live plateau, and V0 continued responding. This caused repeated `applied 2` log lines and `qbind_restore_catchup_blocks_applied_total` to rise to 616 without increasing committed height beyond 339. This is not hidden; it is a restore-catchup idempotence/termination observability anomaly for the next run.
- The snapshot `state/` file is still a placeholder accepted by the existing VM-v0 snapshot validator. The consensus anchor itself was live-sourced, and the catchup validation was real; this run still does not claim full production RocksDB / consensus-storage checkpoint restore.
- V1B restored to `S=1`, not `S=3` as in Run 011. This was intentional to capture the anchor from live V0 `/metrics` at the first non-zero committed height and then let the cluster progress to `H=339`.
- Run 012 did not introduce a broad sync framework or harness-only recovery path.

## 15. Assessment of Evidence Value

Run 012 materially improves Run 011's evidence quality in two ways:

1. The snapshot anchor was sourced directly from live V0 state exposed on `/metrics`, rather than deterministically recomputed.
2. Restore-catchup request/response/application/rejection counters were directly visible on `/metrics`.

The run remains **partial positive**:

- Positive: live binary-path cluster progressed normally; V1B restored honestly from `S=1`; real restore-catchup request/response traffic crossed the P2P binary path; V1B advanced to `committed_height=339`; metrics stayed honest; shutdown was clean.
- Negative / unresolved: after catchup, forward QC formation and commit progression did not resume. The post-catchup plateau was `current_view=342` / `committed_height=339`.

C4 is not materially narrowed enough to update `docs/whitepaper/contradiction.md`: the existing C4 already says bounded restore catchup has landed while full production fast-sync / consensus-storage restore remains outstanding. Run 012 sharpens evidence around observability and forward-resume behavior, but it does not close the remaining production recovery boundary.

## 16. Recommended Immediate Next Action

Stop adding documentation-only evidence and execute one narrow code investigation/run focused on the post-catchup resume boundary: once a restored node reaches the peer's committed anchor, stop repeated restore-catchup requests and determine why V1B emits no leader proposals/votes at `current_view=342`. The next run should instrument only that transition and should prove either resumed proposal/vote/QC flow or the exact consensus-state condition preventing it.