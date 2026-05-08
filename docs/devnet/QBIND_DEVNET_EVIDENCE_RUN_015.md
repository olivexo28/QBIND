# QBIND DevNet Evidence Run 015

## 1. Purpose and Scope

Run 015 is a real-binary N=4 recovery-boundary exercise after Run 014. It intentionally removes the 2-of-2 late-peer-reemit escape hatch that made Run 014 recover.

Question tested: with B13 already landed, does a restored validator catch up, exit restore mode, and then resume normal proposal/vote/QC/commit progression when the current/next view is led by a still-absent validator in an N=4 validator set?

Verdict: **PARTIAL POSITIVE, NEGATIVE for strict N=4 automatic recovery.** The live N=4 binary-path cluster progressed normally before the forced shape. V1B restored honestly from live-sourced `S=11`, received real restore-catchup responses, applied 3 peer-learned certified blocks, advanced to `committed_height=12`, and B13 exited restore-catchup mode. After that, the available validators remained parked at `current_view=15`, whose leader is `ValidatorId(3)`, while V3 was deliberately still absent. No normal proposal/vote/QC/commit progression resumed during the 200-second post-restore observation window.

This run supports a narrower remaining boundary: B13 is sufficient to exit restore-catchup mode in this strict N=4 shape, but the binary path still lacks an automatic way to leave a live view whose leader is absent after catchup. The smallest supported missing primitive is therefore binary-path view-timeout/view-change, or an equivalently narrow mechanism that can move available validators off an absent-leader view. Responder-side pending-proposal piggyback is not ruled out as useful, but this run did not show it would solve an absent-leader view by itself.

No QBIND source code was changed for this run. The only repository documentation created by this task is this file.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_014.md` — 2-of-2 Run-012-style predecessor-view shape recovered via already-landed B9/B10 late-peer reemit plus B13.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_013.md` — B13 bounded post-catchup restore-mode exit and normal resumed progression in the non-deadlocked binary case.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_012.md` — original restore-catchup plateau before B13.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010B.md` — Required-mode binary-path consensus progression baseline.
- `docs/whitepaper/contradiction.md` C4 — current canonical C4 boundary before Run 015.

Validation before execution:

```sh
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node
```

Result:

```text
warning: unused variable: `worker_id`
   --> crates/qbind-node/src/verify_pool.rs:262:9
warning: `qbind-node` (lib) generated 1 warning
Finished `release` profile [optimized] target(s) in 6m 43s
```

The `worker_id` warning is pre-existing and matches Runs 012-014.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1` |
| Kernel | `Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar 6 22:00:57 UTC 2026 x86_64` |
| Distro | `Ubuntu 24.04.4 LTS` |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/execute-n4-deadlock-recovery-evidence` |
| HEAD | `e928e761e6012c9a9ce7d88f3f53295b77bbaea5` |
| Binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9134784` bytes |
| Binary sha256 | `d2a8dd971fb3d428b3592187370ce80623587b76693f1901170d0072cc33df8c` |
| Binary Build ID | `788f79ed54933eae0eb984924f45c3085bb67dd7` |
| Run directory | `/tmp/run015` |
| Script start UTC | `2026-05-08T08:27:36.418Z` |
| Script end UTC | `2026-05-08T08:31:16.616Z` |
| `QBIND_MUTUAL_AUTH` | unset; every node used CLI `--p2p-mutual-auth required` |

An earlier attempted Run 015 script started V0 first and did **not** produce live N=4 progress; it was discarded as non-canonical. The canonical run above started V1/V2/V3 first, then V0, so the view-0 leader dialed already-listening peers and the live cluster progressed before the forced shape.

## 4. Topology, Timing, Leader-Rotation Rationale, and Node Configuration Used

| Node | Phase | Validator | Listen | Static peers | Mutual auth | Data dir | Metrics | Restore snapshot |
|---|---|---:|---|---|---|---|---|---|
| V0 | live throughout | `0` | `127.0.0.1:19550` | `1@127.0.0.1:19551`, `2@127.0.0.1:19552`, `3@127.0.0.1:19553` | `required` | `/tmp/run015/data/v0` | `127.0.0.1:9550` | none |
| V1A | live pre-restore | `1` | `127.0.0.1:19551` | `0@127.0.0.1:19550`, `2@127.0.0.1:19552`, `3@127.0.0.1:19553` | `required` | `/tmp/run015/data/v1a` | `127.0.0.1:9551` | none |
| V2 | live throughout | `2` | `127.0.0.1:19552` | `0@127.0.0.1:19550`, `1@127.0.0.1:19551`, `3@127.0.0.1:19553` | `required` | `/tmp/run015/data/v2` | `127.0.0.1:9552` | none |
| V3 | removed / still absent | `3` | `127.0.0.1:19553` | `0@127.0.0.1:19550`, `1@127.0.0.1:19551`, `2@127.0.0.1:19552` | `required` | `/tmp/run015/data/v3` | `127.0.0.1:9553` | none |
| V1B | restored | `1` | `127.0.0.1:19551` | `0@127.0.0.1:19550`, `2@127.0.0.1:19552`, `3@127.0.0.1:19553` | `required` | `/tmp/run015/data/v1b` | `127.0.0.1:9554` | `/tmp/run015/snap` |

Timing:

| Event | UTC |
|---|---|
| `RUN015_START` | `2026-05-08T08:27:36.417Z` |
| V1A start | `2026-05-08T08:27:36.462Z` |
| V2 start | `2026-05-08T08:27:36.465Z` |
| V3 start | `2026-05-08T08:27:36.468Z` |
| V0 start | `2026-05-08T08:27:38.472Z` |
| Anchor capture | `2026-05-08T08:27:41.059Z` |
| Target stop view | `15` |
| Target stop leader | `15 % 4 = 3`, so `ValidatorId(3)` |
| V1A SIGINT | `2026-05-08T08:27:41.227Z` |
| V3 SIGINT | `2026-05-08T08:27:41.265Z` |
| V1B restored start | `2026-05-08T08:27:51.300Z` |
| Final scrape | `2026-05-08T08:31:11.467Z` |
| V1B/V2/V0 SIGINT | `2026-05-08T08:31:11.488Z` / `.527Z` / `.565Z` |
| `RUN015_END` | `2026-05-08T08:31:16.616Z` |

Leader rotation is round-robin over sorted validator IDs: `leader = validators[view % num_validators]`. At the forced stop, the visible target was `current_view=15`; with four validators this maps to `ValidatorId(3)`. The restored validator is `ValidatorId(1)`, so it is not the leader for view 15. V3 remained absent after V1B joined. This is stricter than Run 014 because the cached B9/B10 late-peer reemit cannot be emitted by the absent view-15 leader.

## 5. Commands and Configuration Used

The full executed script was `/tmp/run015b.sh`; it wrote canonical artifacts under `/tmp/run015`.

Environment metadata command:

```sh
cd /home/runner/work/QBIND/QBIND
{
  echo "RUN_DIR=/tmp/run015"
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
  --data-dir /tmp/run015/data/v0 \
  > /tmp/run015/logs/v0_live.log 2>&1 &
```

V1A command was identical except `--validator-id 1`, listen `127.0.0.1:19551`, metrics `127.0.0.1:9551`, peers `0/2/3`, data dir `/tmp/run015/data/v1a`, and log `/tmp/run015/logs/v1_live.log`.

V2 command used `--validator-id 2`, listen `127.0.0.1:19552`, metrics `127.0.0.1:9552`, peers `0/1/3`, data dir `/tmp/run015/data/v2`, and log `/tmp/run015/logs/v2_live.log`.

V3 command used `--validator-id 3`, listen `127.0.0.1:19553`, metrics `127.0.0.1:9553`, peers `0/1/2`, data dir `/tmp/run015/data/v3`, and log `/tmp/run015/logs/v3_live.log`.

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
  --data-dir /tmp/run015/data/v1b \
  --restore-from-snapshot /tmp/run015/snap \
  > /tmp/run015/logs/v1_restored.log 2>&1 &
```

Metrics were scraped from `http://127.0.0.1:9550/metrics`, `:9551`, `:9552`, `:9553`, and restored-node `:9554`.

## 6. Live-Cluster Pre-Restore Progress Evidence

Startup path excerpts show real P2P, four validators, and Required mutual auth:

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[T175] P2P node builder: validator=ValidatorId(0) ... num_validators=4 peer_kem_overrides=3 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=4 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

Live pre-restore metrics:

| Metric | V0 anchor | V1A anchor | V2 anchor | V3 anchor | V0 pre-stop | V1A pre-stop | V2 pre-stop | V3 pre-stop |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 14 | 13 | 13 | 13 | 15 | 14 | 14 | 14 |
| `qbind_consensus_qcs_formed_total` | 25 | 26 | 26 | 26 | 27 | 28 | 28 | 28 |
| `qbind_consensus_committed_height` | 11 | 10 | 10 | 10 | 12 | 11 | 11 | 11 |
| `qbind_consensus_view_lag` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `consensus_net_inbound_total{kind="proposal"}` | 10 | 10 | 11 | 11 | 11 | 11 | 11 | 12 |
| `consensus_net_inbound_total{kind="vote"}` | 42 | 39 | 40 | 40 | 45 | 43 | 42 | 43 |
| `qbind_consensus_proposals_total{result="accepted"}` | 14 | 14 | 14 | 14 | 15 | 15 | 15 | 15 |

Answer A: yes. The live N=4 real binary path progressed normally before the strict shape: proposals, votes, QCs, views, and committed height all advanced under P2P Required mode.

## 7. Snapshot Anchor and Restore-Baseline Evidence

Snapshot anchor was sourced from live V0 `/metrics` at `2026-05-08T08:27:41.059Z`:

```text
qbind_consensus_current_view 14
qbind_consensus_qcs_formed_total 25
qbind_consensus_committed_height 11
qbind_consensus_committed_block_info{block_id="03000000000000000b0000000000000002000000000000000a00000000000000"} 1
```

Snapshot metadata:

```json
{
  "height": 11,
  "block_hash": "03000000000000000b0000000000000002000000000000000a00000000000000",
  "created_at_unix_ms": 1778228861054,
  "chain_id": 5855328520645203456
}
```

Snapshot file hashes:

```text
94aeaf44cf341eacba13c4d9e645c5cf2ae4052fa254f178084e467fbba7973b  /tmp/run015/snap/meta.json
38806617337c46c780c06f18e1e14a8cad26f162537e4c235d5b74c74bd77f84  /tmp/run015/snap/state/.placeholder.txt
```

V1B restore startup excerpt:

```text
[restore] requested: snapshot_dir=/tmp/run015/snap data_dir=/tmp/run015/data/v1b expected_chain_id=0x51424e4444455600
[restore] complete: height=11 chain_id=0x51424e4444455600 bytes_copied=55 target=/tmp/run015/data/v1b/state_vm_v0
[restore] audit marker written to /tmp/run015/data/v1b/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=11 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=11, starting_view=12)
[binary-consensus] B5: applied restore baseline: snapshot_height=11 starting_view=12 (engine committed_height=Some(11))
```

Audit marker confirms honest B3 restore startup:

```json
{"snapshot_height":11,"snapshot_block_hash":"03000000000000000b0000000000000002000000000000000a00000000000000","snapshot_chain_id":5855328520645203456}
```

Answer B/C: yes. The anchor came from live peer metrics, and V1B started from `S=11`; it did not pretend to have post-S history before catchup.

## 8. Restore-Catchup Request / Response Evidence

V1B connected only to V0 and V2; V3 was still absent:

```text
[P2P] Dial 127.0.0.1:19550: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Dial 127.0.0.1:19552: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] dial 127.0.0.1:19553 attempt 1/8 failed ...
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
[P2P] Peer NodeId(eadb48d7b679d681) connected
```

Restored-node catchup metrics flattened by the first post-restore scrape and stayed flat:

| Time | V1B requests sent | V1B responses received | V1B blocks applied | V0 responses sent | V2 responses sent |
|---|---:|---:|---:|---:|---:|
| `t=5s` | 2 | 2 | 3 | 1 | 1 |
| `t=10s` | 2 | 2 | 3 | 1 | 1 |
| `t=20s` | 2 | 2 | 3 | 1 | 1 |
| `t=40s` | 2 | 2 | 3 | 1 | 1 |
| `t=80s` | 2 | 2 | 3 | 1 | 1 |
| `t=140s` | 2 | 2 | 3 | 1 | 1 |
| `t=200s` | 2 | 2 | 3 | 1 | 1 |

Log evidence:

```text
[restore-catchup] applied 3 peer-learned certified blocks; committed_height=Some(12) view=15
[restore-catchup] rejected stale/mismatched response anchor: response_height=11 local_height=Some(12)
```

Answer D: yes. Restore-catchup requests and responses used the real P2P binary path, not LocalMesh or a harness fallback.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

V1B started at snapshot height 11 and applied a learned suffix to committed height 12:

```text
[binary-consensus] B5: applied restore baseline: snapshot_height=11 starting_view=12 (engine committed_height=Some(11))
[restore-catchup] applied 3 peer-learned certified blocks; committed_height=Some(12) view=15
[binary-consensus] committed_anchor height=12 block_id=00000000000000000c0000000000000003000000000000000b00000000000000
```

Post-restore committed-height metrics:

| Time | V0 committed | V1B committed | V2 committed |
|---|---:|---:|---:|
| after V1/V3 absent, before V1B | 12 | n/a | 12 |
| `t=5s` | 12 | 12 | 12 |
| `t=200s` | 12 | 12 | 12 |
| final | 12 | 12 | 12 |

Answer E/F: yes, V1B validated/applied peer-learned material and committed height advanced above S (`11 -> 12`). It did not advance materially beyond the catchup point afterward.

## 10. Restore-Mode Exit Evidence

B13 exit was observable and not assumed:

```text
[restore-catchup] exit: caught up to peer anchor — local committed_height=12 peer_max_observed=Some(12); stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating
```

Metrics confirmed the transition:

| Time | `qbind_restore_catchup_mode_active` | `qbind_restore_catchup_mode_exited_at_height` | `qbind_restore_catchup_requests_sent_total` |
|---|---:|---:|---:|
| `t=5s` | 0 | 12 | 2 |
| `t=10s` | 0 | 12 | 2 |
| `t=20s` | 0 | 12 | 2 |
| `t=40s` | 0 | 12 | 2 |
| `t=80s` | 0 | 12 | 2 |
| `t=140s` | 0 | 12 | 2 |
| `t=200s` | 0 | 12 | 2 |
| final | 0 | 12 | 2 |

Answer G/H: yes. B13 exited in this strict N=4 run, and repeated restore-catchup requests stopped/flattened materially after two requests.

## 11. Strict N=4 Deadlock-Recovery Evidence

The strict shape was achieved:

- N=4 validator set was active before the fault.
- V1A was removed and later restored from `S=11` as V1B.
- V3 was removed and stayed absent.
- Stop target was `current_view=15`; `15 % 4 = 3`, so V3 was the current/next leader.
- V1B (`ValidatorId(1)`) was not the leader.
- V1B repeatedly failed to dial V3 and eventually gave up after the bounded initial retry sequence.

Post-exit consensus did not resume:

| Metric | V0 after absent | V0 final | V1B `t=5s` | V1B final | V2 after absent | V2 final |
|---|---:|---:|---:|---:|---:|---:|
| `qbind_consensus_current_view` | 15 | 15 | 15 | 15 | 15 | 15 |
| `qbind_consensus_qcs_formed_total` | 27 | 27 | 0 | 0 | 30 | 30 |
| `qbind_consensus_committed_height` | 12 | 12 | 12 | 12 | 12 | 12 |
| `qbind_consensus_proposals_total{result="accepted"}` | 16 | 16 | 0 | 0 | 16 | 16 |
| `consensus_net_inbound_total{kind="proposal"}` | 12 | 12 | 0 | 0 | 12 | 12 |
| `consensus_net_inbound_total{kind="vote"}` | 46 | 46 | 0 | 0 | 46 | 46 |

Loop-exit summaries agree:

```text
V0:  Loop exit: ticks=2132 proposals=4 commits=13 committed_height=Some(12) view=15 ... outbound_proposal_late_peer_reemits=1
V1B: Loop exit: ticks=2002 proposals=0 commits=1 committed_height=Some(12) view=15 inbound_msgs=2 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0 outbound_proposal_late_peer_reemits=0
V2:  Loop exit: ticks=2151 proposals=4 commits=13 committed_height=Some(12) view=15 ... outbound_proposal_late_peer_reemits=0
```

Answer I/J/K: no. In the strict N=4 shape, normal proposal/vote participation did not resume automatically, forward QC formation did not resume automatically, and committed height did not advance materially beyond the catchup point.

## 12. Metrics Evidence

The metrics endpoint remained honest and consistent with logs:

- live metrics showed N=4 pre-restore progress (`current_view`, QCs, proposals, votes, and commits advanced);
- restored-node metrics showed `qbind_restore_catchup_mode_active=0`, `qbind_restore_catchup_mode_exited_at_height=12`, `requests_sent_total=2`, `responses_received_total=2`, and `blocks_applied_total=3`;
- post-exit metrics stayed flat for V0/V1B/V2 at `current_view=15` and `committed_height=12` through the final scrape;
- metrics did not fabricate resumed consensus, extra QCs, or commits after the strict shape was created.

Answer M: yes. `/metrics` remained honest.

## 13. Shutdown Evidence

All remaining nodes were stopped with SIGINT after the final scrape:

```text
V1B_SIGINT=2026-05-08T08:31:11.488Z
V2_SIGINT=2026-05-08T08:31:11.527Z
V0_SIGINT=2026-05-08T08:31:11.565Z
POST_SIGINT_PS=none
RUN015_END=2026-05-08T08:31:16.616Z
```

Node logs reported clean shutdown:

```text
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after ... ticks.
[T175] P2P node shutdown complete
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

Answer N: yes. Shutdown remained clean.

## 14. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 015 observation | Assessment |
|---|---|---|
| B3 restore startup | V1B applied `/tmp/run015/snap`, wrote `RESTORED_FROM_SNAPSHOT.json`, and failed neither open nor silent | not regressed |
| B5 restore-aware baseline | V1B logged `snapshot_height=11`, `starting_view=12`, and `engine committed_height=Some(11)` | not regressed |
| B6 P2P routing | live N=4 proposals/votes/QCs/commits advanced via P2P; V1B catchup used P2P messages | not regressed |
| B8/B12 identity/Required mode | all nodes logged `mutual_auth=Required`, `peer_kem_overrides=3`, and `vid@addr` static peers | not regressed |
| B9/B10 late-peer reemit | V0 emitted one bounded view-0 late-peer reemit during live startup; no hidden reemit from absent V3 | not regressed; also not sufficient for this shape |
| B13 transition | V1B exited at height 12 and request count flattened | not regressed |
| No LocalMesh/harness fallback | all nodes used `--network-mode p2p --enable-p2p`; no LocalMesh was used | satisfied |
| Metrics honesty | metrics reported both B13 exit and post-exit plateau | satisfied |

Answer O: no previously landed binary-path capability appeared regressed. The only negative result is the intentionally isolated strict N=4 absent-leader recovery boundary.

## 15. Limitations and Anomalies Observed

- This is a single execution, not a statistical soak.
- The live N=4 cluster progressed only when the startup order put V0 last. An earlier V0-first attempt did not produce live progress before the fault, so it was discarded as non-canonical. This is a startup-timing limitation/anomaly but not the strict recovery result.
- Some P2P logs contain `UnexpectedEof` / `Broken pipe` messages around stopped peers. These coincided with intentional SIGINT/removal and did not hide metrics or shutdown status.
- V1B applied only a small learned suffix (`S=11` to `12`). That is enough to exercise B13 exit, but this run does not claim large-suffix performance.
- The run does not prove production fast-sync / consensus-storage restore or production PQC KEMTLS root-key distribution.
- The run does not prove that responder-side pending-proposal piggyback is unnecessary in every shape; it only shows the strict absent-leader N=4 shape still needs a mechanism beyond B13 and existing late-peer reemit.

## 16. Assessment of Evidence Value

Run 015 materially narrows C4 beyond Run 014:

- Run 014 proved the 2-of-2 predecessor-view deadlock shape is recoverable when the late-peer-reemit edge can consume the deadlock.
- Run 015 proves B13 still works in a stricter N=4 shape: restored V1B catches up, exits restore mode, and stops repeated catchup requests.
- Run 015 also proves B13 plus B9/B10 is **not** sufficient when the parked view is led by still-absent V3 and restored V1B is not that leader.

Narrowest supported remaining boundary: binary-path absent-leader view recovery. The immediate missing primitive is most likely view-timeout/view-change on the real binary path, or another comparably narrow mechanism that lets available validators move from view 15 to a later view with a present leader.

This result is partial because it closes the B13-in-strict-shape question but does not provide positive recovery.

## 17. Recommended Immediate Next Action

Implement and test the smallest binary-path view-timeout/view-change driver sufficient to advance from an absent-leader view in an N=4 Required-mode P2P cluster, then rerun the same Run 015 topology/timing with V3 still absent and V1 restored from a live snapshot. Do not broaden into a full sync redesign before this narrow absent-leader view-change primitive is tested.