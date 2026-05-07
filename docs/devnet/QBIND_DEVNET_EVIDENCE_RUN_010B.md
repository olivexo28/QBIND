# QBIND DevNet Evidence Run 010B

## 1. Purpose and Scope

Run 010B asks the next-layer question left open by Run 010A:

> On the already-validated real `qbind-node` binary path with `--p2p-mutual-auth required`, does a two-validator DevNet topology still support real cross-node consensus progression?

The scope is deliberately narrow:

- two real `qbind-node` release binaries,
- P2P mode on both nodes,
- `--p2p-mutual-auth required` on both nodes,
- cross-node proposal / vote / QC / commit evidence,
- `/metrics` agreement with loop-exit summaries,
- shutdown evidence,
- regression check against previously landed binary-path behavior.

This run does **not** re-prove the full Run 010A identity-binding story. Run 010A already established the lower-layer Required-mode transport and cert-backed accepted-session identity baseline. Run 010B only confirms enough of the same path to prove that the same Required-mode binary path is in use while measuring the consensus layer above it.

No QBIND source code is modified by this run. The only repository file created by Run 010B is this evidence document. `docs/whitepaper/contradiction.md` is not updated because the run is positive and reveals no new contradiction; it also does not materially narrow C4 beyond the already-recorded B12 landing plus remaining production PQC root-key distribution / multi-validator restore-catchup boundaries.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010A.md` — establishes the lower-layer Required-mode binary-path prerequisite: startup under `--p2p-mutual-auth required`, mutual-auth handshake success, cert-backed listener-side accepted-session identity binding, deterministic peer NodeId registration, honest `/metrics`, clean shutdown, and no regression of earlier binary-path milestones.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_009.md` — prior binary-path full cross-node proposal / vote / QC / commit evidence under `MutualAuthMode::Disabled`.
- `docs/whitepaper/contradiction.md` C4 — current canonical contradiction boundary: B1/B2/B3/B5/B6/B7/B8/B9/B10/B12 landed; multi-validator restore catchup and production PQC KEMTLS root-key distribution remain outstanding.
- `crates/qbind-node/src/main.rs` — CLI / environment resolution for `--p2p-mutual-auth`, Required-mode startup banner, and P2P consensus-loop startup.
- `crates/qbind-node/src/binary_consensus_loop.rs` — loop-exit summaries, inbound proposal/vote accounting, outbound proposal/vote accounting, commit accounting, and late-peer re-emission counters.
- `crates/qbind-node/src/p2p_node_builder.rs` / `crates/qbind-node/src/p2p_tcp.rs` — P2P builder, deterministic peer registration, Required-mode identity resolver surface, and transport connection traces.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1`, Linux 6.17.0-1010-azure x86_64 |
| Distro | Ubuntu 24.04.4 LTS |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Repo branch | `copilot/execute-devnet-evidence-run-010b-again` |
| Repo HEAD at build | `99743f8ef9434dc617fd270442fd5653af81e63b` |
| Build command | `cargo build --release -p qbind-node --bin qbind-node` |
| Build duration | `real 6m28.603s` |
| Build result | success |
| Build warning | one pre-existing `qbind-node` lib warning: `unused variable: worker_id` at `crates/qbind-node/src/verify_pool.rs:262:9` |
| Binary used | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9089936` bytes |
| Binary file details | `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e3a9660f65f581b5ce2cc390d60bcf429330afc9, not stripped` |
| Canonical run directory | `/tmp/run010b_clean` |

Environment/build command exactly as executed:

```sh
cd /home/runner/work/QBIND/QBIND
set -o pipefail
{
  echo "HOST=$(hostname)"
  uname -a
  if [ -f /etc/os-release ]; then . /etc/os-release; echo "DISTRO=$PRETTY_NAME"; fi
  rustc --version
  cargo --version
  git --no-pager branch --show-current
  git --no-pager rev-parse HEAD
} && time cargo build --release -p qbind-node --bin qbind-node
```

Relevant build output excerpt:

```text
HOST=runnervmeorf1
Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar  6 22:00:57 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
DISTRO=Ubuntu 24.04.4 LTS
rustc 1.94.1 (e408947bf 2026-03-25)
cargo 1.94.1 (29ea6fb6a 2026-03-24)
copilot/execute-devnet-evidence-run-010b-again
99743f8ef9434dc617fd270442fd5653af81e63b
warning: unused variable: `worker_id`
   --> crates/qbind-node/src/verify_pool.rs:262:9
    |
262 |         worker_id: usize,
    |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_worker_id`
    |
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: `qbind-node` (lib) generated 1 warning (run `cargo fix --lib -p qbind-node` to apply 1 suggestion)
    Finished `release` profile [optimized] target(s) in 6m 28s

real    6m28.603s
user    22m12.247s
sys     0m40.743s
```

## 4. Topology and Node Configuration Used

| Node | Validator | Listen | Static peer (`vid@addr`) | Mutual auth | Metrics | Data dir | Start UTC |
|---|---|---|---|---|---|---|---|
| V0 | `ValidatorId(0)` | `127.0.0.1:19200` | `1@127.0.0.1:19201` | `--p2p-mutual-auth required` | `127.0.0.1:9120` | `/tmp/run010b_clean/data-v0` | `2026-05-07T10:54:44.839Z` |
| V1 | `ValidatorId(1)` | `127.0.0.1:19201` | `0@127.0.0.1:19200` | `--p2p-mutual-auth required` | `127.0.0.1:9121` | `/tmp/run010b_clean/data-v1` | `2026-05-07T10:54:54.842Z` |

V0 was started first. V1 was started approximately 10.003 seconds later. This intentionally exercises the same late-peer-connect Required-mode shape observed in Run 010A: V0's bounded initial-dial retry exhausts before V1 starts, then V1 dials V0, V0 accepts and binds V1's deterministic NodeId, and B9+B10 late-peer proposal/vote re-emission unblocks cross-node consensus progression.

## 5. Commands and Configuration Used

The canonical Run 010B execution command block was:

```sh
cd /home/runner/work/QBIND/QBIND
set -euo pipefail
RUN=/tmp/run010b_clean
rm -rf "$RUN"
mkdir -p "$RUN/logs" "$RUN/data-v0" "$RUN/data-v1" "$RUN/metrics"
unset QBIND_MUTUAL_AUTH || true
{
  echo "RUN_DIR=$RUN"
  echo "START_HOST=$(hostname)"
  date -u +"SCRIPT_START_UTC=%Y-%m-%dT%H:%M:%S.%3NZ"
  echo "QBIND_MUTUAL_AUTH=${QBIND_MUTUAL_AUTH-<unset>}"
  stat -c 'BINARY_SIZE_BYTES=%s' /home/runner/work/QBIND/QBIND/target/release/qbind-node
  file /home/runner/work/QBIND/QBIND/target/release/qbind-node
} | tee "$RUN/run.meta"

date -u +"NODE0_START_UTC=%Y-%m-%dT%H:%M:%S.%3NZ" | tee -a "$RUN/run.meta"
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9120 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19200 \
    --p2p-peer 1@127.0.0.1:19201 \
    --p2p-mutual-auth required \
    --validator-id 0 \
    --data-dir /tmp/run010b_clean/data-v0 \
  > "$RUN/logs/node0.stdout" 2> "$RUN/logs/node0.stderr" &
echo $! > "$RUN/node0.pid"
sleep 10

date -u +"NODE1_START_UTC=%Y-%m-%dT%H:%M:%S.%3NZ" | tee -a "$RUN/run.meta"
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:9121 \
  /home/runner/work/QBIND/QBIND/target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19201 \
    --p2p-peer 0@127.0.0.1:19200 \
    --p2p-mutual-auth required \
    --validator-id 1 \
    --data-dir /tmp/run010b_clean/data-v1 \
  > "$RUN/logs/node1.stdout" 2> "$RUN/logs/node1.stderr" &
echo $! > "$RUN/node1.pid"

sleep 25
date -u +"SCRAPE_T1_UTC=%Y-%m-%dT%H:%M:%S.%3NZ" | tee -a "$RUN/run.meta"
curl -fsS http://127.0.0.1:9120/metrics > "$RUN/metrics/node0-t1.prom"
curl -fsS http://127.0.0.1:9121/metrics > "$RUN/metrics/node1-t1.prom"
wc -l "$RUN/metrics/node0-t1.prom" "$RUN/metrics/node1-t1.prom" | tee -a "$RUN/run.meta"

sleep 30
date -u +"SCRAPE_T2_UTC=%Y-%m-%dT%H:%M:%S.%3NZ" | tee -a "$RUN/run.meta"
curl -fsS http://127.0.0.1:9120/metrics > "$RUN/metrics/node0-t2.prom"
curl -fsS http://127.0.0.1:9121/metrics > "$RUN/metrics/node1-t2.prom"
wc -l "$RUN/metrics/node0-t2.prom" "$RUN/metrics/node1-t2.prom" | tee -a "$RUN/run.meta"

date -u +"SIGINT_UTC=%Y-%m-%dT%H:%M:%S.%3NZ" | tee -a "$RUN/run.meta"
python3 - <<'PY'
from pathlib import Path
import os, signal
run = Path('/tmp/run010b_clean')
pids = [int((run / 'node0.pid').read_text()), int((run / 'node1.pid').read_text())]
print('PIDS=' + ' '.join(map(str, pids)))
with (run / 'run.meta').open('a') as f:
    f.write('PIDS=' + ' '.join(map(str, pids)) + '\n')
for pid in pids:
    os.kill(pid, signal.SIGINT)
PY
sleep 5
python3 - <<'PY' | tee -a /tmp/run010b_clean/run.meta
from pathlib import Path
import os
run = Path('/tmp/run010b_clean')
pids = [int((run / f'node{i}.pid').read_text()) for i in (0, 1)]
alive = []
for pid in pids:
    try:
        os.kill(pid, 0)
        alive.append(pid)
    except ProcessLookupError:
        pass
print('POST_SIGINT_PS=' + ('none' if not alive else 'still_present:' + ','.join(map(str, alive))))
PY
date -u +"SCRIPT_END_UTC=%Y-%m-%dT%H:%M:%S.%3NZ" | tee -a "$RUN/run.meta"
```

`QBIND_MUTUAL_AUTH` was unset and each node was launched with `env -u QBIND_MUTUAL_AUTH`. The only per-node environment variable used was `QBIND_METRICS_HTTP_ADDR`.

Run metadata excerpt:

```text
RUN_DIR=/tmp/run010b_clean
START_HOST=runnervmeorf1
SCRIPT_START_UTC=2026-05-07T10:54:44.831Z
QBIND_MUTUAL_AUTH=<unset>
BINARY_SIZE_BYTES=9089936
/home/runner/work/QBIND/QBIND/target/release/qbind-node: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e3a9660f65f581b5ce2cc390d60bcf429330afc9, not stripped
NODE0_START_UTC=2026-05-07T10:54:44.839Z
NODE1_START_UTC=2026-05-07T10:54:54.842Z
SCRAPE_T1_UTC=2026-05-07T10:55:19.845Z
  317 /tmp/run010b_clean/metrics/node0-t1.prom
  317 /tmp/run010b_clean/metrics/node1-t1.prom
  634 total
SCRAPE_T2_UTC=2026-05-07T10:55:49.858Z
  317 /tmp/run010b_clean/metrics/node0-t2.prom
  317 /tmp/run010b_clean/metrics/node1-t2.prom
  634 total
SIGINT_UTC=2026-05-07T10:55:49.871Z
PIDS=9614 9623
POST_SIGINT_PS=none
SCRIPT_END_UTC=2026-05-07T10:55:54.923Z
```

## 6. Required-Mode Confirmation

V0 stderr:

```text
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[restore] no --restore-from-snapshot requested; normal startup.
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9120 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9120 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=nonce-only
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[metrics_http] Listening on 127.0.0.1:9120
[binary] P2P transport up. Listen address: 127.0.0.1:19200, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

V0 stdout:

```text
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19200 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19200 (node_id=NodeId(4bd96f97b1aaec9d))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
```

V1 stderr:

```text
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[restore] no --restore-from-snapshot requested; normal startup.
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9121 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9121 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=nonce-only
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[metrics_http] Listening on 127.0.0.1:9121
[binary] P2P transport up. Listen address: 127.0.0.1:19201, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

V1 stdout:

```text
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19201 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19201 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
```

Required mode is confirmed by both nodes' `[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` banners and by both builders' `mutual_auth=Required` fields. There was no fallback to Disabled mode.

## 7. Cross-Node Proposal / Vote Evidence

P2P connection and deterministic peer-registration evidence:

V0 stdout:

```text
[P2P] dial 127.0.0.1:19201 attempt 1/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 100ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19201 attempt 2/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 200ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19201 attempt 3/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 400ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19201 attempt 4/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 800ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19201 attempt 5/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19201 attempt 6/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19201 attempt 7/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] Accepted connection from 127.0.0.1:53380
[P2P] Accepted connection from 127.0.0.1:53384
[P2P] Inbound connection from 127.0.0.1:53384 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
```

V0 stderr:

```text
[P2P] dial 127.0.0.1:19201 giving up after 8 attempt(s): I/O error: Connection refused (os error 111) (transient=true, max_attempts=8)
[P2P] Inbound connection error: Handshake error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

V1 stdout:

```text
[P2P] Dial 127.0.0.1:19200: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
```

Cross-node proposal and vote evidence from T2 `/metrics`:

```text
# V0 /metrics at 2026-05-07T10:55:49.858Z
consensus_net_inbound_total{kind="vote"} 526
consensus_net_inbound_total{kind="proposal"} 263
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 528
consensus_net_outbound_total{kind="proposal_broadcast"} 265

# V1 /metrics at 2026-05-07T10:55:49.858Z
consensus_net_inbound_total{kind="vote"} 527
consensus_net_inbound_total{kind="proposal"} 264
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 527
consensus_net_outbound_total{kind="proposal_broadcast"} 263
```

Answers for this section:

- Cross-node proposal occurred under Required mode: **yes**. V0 outbound `proposal_broadcast=265`; V1 inbound `proposal=264`. V1 outbound `proposal_broadcast=263`; V0 inbound `proposal=263`.
- Cross-node vote occurred under Required mode: **yes**. V0 outbound `vote_broadcast=528`; V1 inbound `vote=527`. V1 outbound `vote_broadcast=527`; V0 inbound `vote=526`.
- The small 0–1 frame differences are expected scrape-boundary/in-flight differences, not evidence of dropped messages; dropped and channel-closed metrics remained zero.

## 8. QC / Commit Progress Evidence

QC evidence from T1 and T2 `/metrics`:

```text
# T1, 2026-05-07T10:55:19.845Z
# V0
qbind_consensus_qcs_formed_total 238
qbind_consensus_view_changes_total 476
qbind_consensus_leader_changes_total 238
qbind_consensus_proposals_total{result="accepted"} 239
qbind_consensus_proposals_total{result="rejected"} 0
# V1
qbind_consensus_qcs_formed_total 237
qbind_consensus_view_changes_total 474
qbind_consensus_leader_changes_total 237
qbind_consensus_proposals_total{result="accepted"} 238
qbind_consensus_proposals_total{result="rejected"} 0

# T2, 2026-05-07T10:55:49.858Z
# V0
qbind_consensus_qcs_formed_total 526
qbind_consensus_view_changes_total 1052
qbind_consensus_leader_changes_total 526
qbind_consensus_proposals_total{result="accepted"} 527
qbind_consensus_proposals_total{result="rejected"} 0
# V1
qbind_consensus_qcs_formed_total 527
qbind_consensus_view_changes_total 1054
qbind_consensus_leader_changes_total 527
qbind_consensus_proposals_total{result="accepted"} 527
qbind_consensus_proposals_total{result="rejected"} 0
```

QC formation occurred under Required mode: **yes**. `qbind_consensus_qcs_formed_total` was already non-zero at T1 and advanced on both nodes by T2:

- V0: `238 -> 526` (`+288`)
- V1: `237 -> 527` (`+290`)

Commit progression evidence from loop-exit summaries:

```text
# V0 stderr
[binary-consensus] Loop exit: ticks=651 proposals=264 commits=524 committed_height=Some(523) view=526 inbound_msgs=789 inbound_proposals=263 inbound_votes=526 outbound_proposals=264 outbound_votes=527 outbound_proposal_late_peer_reemits=1

# V1 stderr
[binary-consensus] Loop exit: ticks=551 proposals=263 commits=525 committed_height=Some(524) view=527 inbound_msgs=791 inbound_proposals=264 inbound_votes=527 outbound_proposals=263 outbound_votes=527 outbound_proposal_late_peer_reemits=0
```

Commit progression occurred under Required mode: **yes**.

- V0 final `commits=524`, `committed_height=Some(523)`.
- V1 final `commits=525`, `committed_height=Some(524)`.
- The one-height difference is consistent with the nodes being scraped/shutdown at a live boundary and with V1 starting ~10 seconds after V0; it is not a safety disagreement in the evidence. Both nodes progressed through hundreds of commits on the same two-validator Required-mode path.

## 9. Metrics Evidence

Two scrapes were taken from each node. Each returned 317 lines of Prometheus text.

Selected T1 metrics:

```text
# V0 /tmp/run010b_clean/metrics/node0-t1.prom
consensus_net_inbound_total{kind="vote"} 238
consensus_net_inbound_total{kind="proposal"} 119
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 240
consensus_net_outbound_total{kind="proposal_broadcast"} 121
consensus_net_outbound_dropped_total 0
consensus_net_inbound_channel_closed_total 0
qbind_consensus_qcs_formed_total 238
qbind_consensus_view_changes_total 476
qbind_consensus_leader_changes_total 238
qbind_consensus_proposals_total{result="accepted"} 239
qbind_consensus_proposals_total{result="rejected"} 0

# V1 /tmp/run010b_clean/metrics/node1-t1.prom
consensus_net_inbound_total{kind="vote"} 237
consensus_net_inbound_total{kind="proposal"} 119
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 238
consensus_net_outbound_total{kind="proposal_broadcast"} 119
consensus_net_outbound_dropped_total 0
consensus_net_inbound_channel_closed_total 0
qbind_consensus_qcs_formed_total 237
qbind_consensus_view_changes_total 474
qbind_consensus_leader_changes_total 237
qbind_consensus_proposals_total{result="accepted"} 238
qbind_consensus_proposals_total{result="rejected"} 0
```

Selected T2 metrics:

```text
# V0 /tmp/run010b_clean/metrics/node0-t2.prom
consensus_net_inbound_total{kind="vote"} 526
consensus_net_inbound_total{kind="proposal"} 263
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 528
consensus_net_outbound_total{kind="proposal_broadcast"} 265
consensus_net_outbound_dropped_total 0
consensus_net_inbound_channel_closed_total 0
qbind_consensus_qcs_formed_total 526
qbind_consensus_view_changes_total 1052
qbind_consensus_leader_changes_total 526
qbind_consensus_proposals_total{result="accepted"} 527
qbind_consensus_proposals_total{result="rejected"} 0

# V1 /tmp/run010b_clean/metrics/node1-t2.prom
consensus_net_inbound_total{kind="vote"} 527
consensus_net_inbound_total{kind="proposal"} 264
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 527
consensus_net_outbound_total{kind="proposal_broadcast"} 263
consensus_net_outbound_dropped_total 0
consensus_net_inbound_channel_closed_total 0
qbind_consensus_qcs_formed_total 527
qbind_consensus_view_changes_total 1054
qbind_consensus_leader_changes_total 527
qbind_consensus_proposals_total{result="accepted"} 527
qbind_consensus_proposals_total{result="rejected"} 0
```

Loop-exit / metrics consistency:

| Node | T2 metric | Loop exit | Assessment |
|---|---:|---:|---|
| V0 inbound proposal | `263` | `inbound_proposals=263` | exact match |
| V0 inbound vote | `526` | `inbound_votes=526` | exact match |
| V0 outbound proposal | `proposal_broadcast=265` | `outbound_proposals=264` | one-frame scrape/loop label boundary; still consistent with live shutdown |
| V0 outbound vote | `vote_broadcast=528` | `outbound_votes=527` | one-frame scrape/loop label boundary; still consistent with live shutdown |
| V0 QC / commit | `qcs_formed_total=526` | `commits=524`, `committed_height=Some(523)`, `view=526` | consistent with HotStuff's QC/commit pipeline lag |
| V1 inbound proposal | `264` | `inbound_proposals=264` | exact match |
| V1 inbound vote | `527` | `inbound_votes=527` | exact match |
| V1 outbound proposal | `proposal_broadcast=263` | `outbound_proposals=263` | exact match |
| V1 outbound vote | `vote_broadcast=527` | `outbound_votes=527` | exact match |
| V1 QC / commit | `qcs_formed_total=527` | `commits=525`, `committed_height=Some(524)`, `view=527` | consistent with HotStuff's QC/commit pipeline lag |

`/metrics` remained honest. Counters were monotonic from T1 to T2, proposal rejections stayed zero, `consensus_net_outbound_dropped_total` stayed zero, `consensus_net_inbound_channel_closed_total` stayed zero, and the loop-exit summaries agree closely enough with the final scrape to support the run verdict.

## 10. Shutdown Evidence

SIGINT was sent at `2026-05-07T10:55:49.871Z` to PIDs `9614 9623`. Five seconds later the process check recorded `POST_SIGINT_PS=none`.

V0 shutdown excerpt:

```text
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 651 ticks.
[binary-consensus] Loop exit: ticks=651 proposals=264 commits=524 committed_height=Some(523) view=526 inbound_msgs=789 inbound_proposals=263 inbound_votes=526 outbound_proposals=264 outbound_votes=527 outbound_proposal_late_peer_reemits=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

V0 stdout shutdown excerpt:

```text
[T175] Shutting down P2P node for validator ValidatorId(0)
[T175] P2P node shutdown complete
```

V1 shutdown excerpt:

```text
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 551 ticks.
[binary-consensus] Loop exit: ticks=551 proposals=263 commits=525 committed_height=Some(524) view=527 inbound_msgs=791 inbound_proposals=264 inbound_votes=527 outbound_proposals=263 outbound_votes=527 outbound_proposal_late_peer_reemits=0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

V1 stdout shutdown excerpt:

```text
[T175] Shutting down P2P node for validator ValidatorId(1)
[T175] P2P node shutdown complete
```

Shutdown remained clean. No `WARN`, `ERROR`, `panicked`, or `ABORTED` strings appeared in either node's stdout/stderr logs.

## 11. Regression Check Against Previously Landed Binary-Path Capabilities

| Capability | Run 010B observation | Regression? |
|---|---|---|
| B1 — binary consensus loop drives `BasicHotStuffEngine` | Both nodes emit `[binary-consensus] Starting consensus loop`; loop-exit summaries show hundreds of proposals and commits. | No |
| B2 — `/metrics` HTTP endpoint | Both nodes emit `[metrics_http] Listening`; both T1 and T2 scrapes return 317 lines; metrics counters are coherent. | No |
| B3 — restore startup honesty | Both nodes emit `[restore] no --restore-from-snapshot requested; normal startup.` No restore fallback is claimed or exercised. | No regression; not exercised by design |
| B5 — restore-aware consensus start | Both loop configs include `restore_baseline=false`; no restore baseline is silently invented. | No regression; not exercised by design |
| B6 — multi-validator P2P binary interconnect | Both nodes have non-zero inbound proposal/vote counts and matching loop-exit inbound counts. | No |
| B7 — dialer-side KEMTLS / validator-id override | V1 emits `using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`. | No |
| B8 — listener-side deterministic peer binding and bounded dial retry | V0 emits bounded retry lines, `giving up after 8 attempt(s)`, and inbound bind to `NodeId(92115fddcd4f93a0)`. | No |
| B9 — late-peer proposal re-emission | V0 emits `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect ... proposal_reemits_total=1`. | No |
| B10 — paired late-peer vote re-emission and inbound accept metrics | Same B9+B10 line includes `vote_reemits_total=1`; inbound proposal/vote metrics and loop-exit counters are non-zero. | No |
| B11-era consensus network outbound metrics | `consensus_net_outbound_total{kind="proposal_broadcast"}` and `{kind="vote_broadcast"}` are non-zero on both nodes. | No |
| B12 — Required-mode mutual-auth binary plumb-through | Both nodes emit `[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)` and builder `mutual_auth=Required`; peers connect under that mode. | No |

No previously landed binary-path capability appears regressed.

## 12. Limitations and Anomalies Observed

1. **No production PKI claim.** This is DevNet evidence on the existing test-grade B12 path. It does not prove production PQC KEMTLS root-key distribution.
2. **No multi-validator restore catchup claim.** Restore was explicitly not exercised; both nodes printed `no --restore-from-snapshot requested` and `restore_baseline=false`.
3. **Transport log text still says `(B8, test-grade)`.** As already recorded in Run 010A, the successful inbound resolver log line is shared by the old B8 label and the Required-mode resolver branch. The Required-mode path is proven by the B12 startup/builder banners and Run 010A's code-path analysis, not by that parenthetical.
4. **One expected KEMTLS noise line appeared.** V0 logged one `UnexpectedEof` inbound connection error before the successful accepted connection. This is the same honest noise shape recorded in earlier runs; the successful second inbound connection and subsequent cross-node consensus progression bound the run verdict.
5. **Outbound metric vs loop-exit off by one on V0.** V0 T2 metrics show `proposal_broadcast=265` / `vote_broadcast=528`, while loop exit shows `outbound_proposals=264` / `outbound_votes=527`. Inbound counts match exactly, V1 outbound counts match exactly, dropped/channel-closed counters are zero, and QC/commit progression is positive. This is bounded to a live scrape/shutdown accounting edge and does not affect the verdict.
6. **Single canonical topology only.** Run 010B used the late-peer-connect Required-mode shape from Run 010A. It did not add a reverse-stagger/no-late-connect comparison or a soak run.

## 13. Assessment of Evidence Value

Run 010B is **positive evidence** that the already-validated mutual-auth Required binary path supports real multi-validator cross-node consensus progression.

Direct answers to the required questions:

A. Did cross-node proposal occur under Required mode? **Yes.** Both nodes had non-zero outbound proposal broadcasts and non-zero inbound proposals.

B. Did cross-node vote occur under Required mode? **Yes.** Both nodes had non-zero outbound vote broadcasts and non-zero inbound votes.

C. Did QC formation occur? **Yes.** `qbind_consensus_qcs_formed_total` was non-zero on both nodes and advanced between T1 and T2: V0 `238 -> 526`, V1 `237 -> 527`.

D. Did commit progression occur? **Yes.** Loop exits show V0 `commits=524 committed_height=Some(523)` and V1 `commits=525 committed_height=Some(524)`.

E. Did loop-exit summaries and `/metrics` agree closely enough? **Yes.** Inbound proposal/vote counters match exactly on both nodes. V1 outbound counters match exactly. V0 outbound counters differ by one frame at the live shutdown boundary. QC metrics and loop commit summaries are consistent with the expected QC-to-commit pipeline lag.

F. Did `/metrics` remain honest? **Yes.** Both endpoints remained reachable, returned 317 lines per scrape, counters were monotonic, proposal rejections stayed zero, outbound dropped stayed zero, and inbound channel closed stayed zero.

G. Did shutdown remain clean? **Yes.** Both nodes accepted SIGINT, emitted loop-exit summaries and shutdown-complete lines, and were gone after five seconds.

H. Did any earlier binary-path capability appear regressed? **No.** No regression was observed against B1/B2/B3/B5/B6/B7/B8/B9/B10/B11-era outbound metrics/B12.

I. What exact next execution action is recommended after Run 010B? See §14.

Verdict: **POSITIVE.** Run 010B proves cross-node proposal, cross-node vote, QC formation, and commit progression on two real `qbind-node` binaries under `--p2p-mutual-auth required`, with honest `/metrics`, clean shutdown, and no observed regression of previously landed binary-path capabilities.

## 14. Recommended Immediate Next Action

The exact immediate next execution action recommended after Run 010B is:

> Execute a short Required-mode comparison run with the same two real `qbind-node` binaries but with a reverse/tight start shape: start V1 first, then start V0 only after V1 is already listening, and capture whether cross-node proposal/vote/QC/commit progression still holds without relying on the B9+B10 late-peer-connect re-emission path.

This is not needed to validate Run 010B's verdict; Run 010B already proves full progression on the same Required-mode late-peer-connect path validated by Run 010A. The comparison run would sharpen the evidence boundary by separating Required-mode consensus progression from the late-peer recovery mechanism.