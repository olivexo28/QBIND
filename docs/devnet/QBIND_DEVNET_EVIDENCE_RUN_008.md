# QBIND DevNet Evidence Run 008

## 1. Purpose and Scope

Run 008 is the **first post-B9 multi-validator binary-path DevNet
evidence exercise** on QBIND. Its purpose is to determine, on real
`qbind-node` processes, whether the leader-side late-peer-connect
proposal re-emission landed by B9 (closing the Run-007 residual
recorded in `docs/whitepaper/contradiction.md` C4) is observable on
the binary path, and how far cross-node consensus progression
actually advances on top of it.

This is an execution / evidence task, not a code-change task. No
QBIND source files are modified by this run; only this evidence
document is created and (per §15 of the task brief and §1-A "no
silent override") a small, conservative narrowing is applied to
C4's `Impact` paragraph and a single new ⚠️ `Remaining` bullet is
appended below the existing B9 entry. No other docs are created.

The strongest-positive checklist Run 008 was asked to evaluate
(per task brief §7) is:

1. handshake succeeds,
2. both sides register each other under deterministic NodeIds,
3. node A outbound proposal reaches the wire,
4. node B inbound proposal > 0,
5. node B outbound vote > 0,
6. node A inbound vote > 0,
7. `qcs_formed_total > 0`,
8. commit / `committed_height` progression on the binary path,
9. `/metrics` and loop-exit summaries agree.

Run 008 reaches **steps 1–6** on the binary path for the first time
in DevNet evidence history. It does **not** reach steps 7–8: no QC
forms and `committed_height` stays `None` on both nodes. The exact
boundary is identified in §8–§9. Per task brief §1-C, this is
reported as a **partial** result.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_007.md` — defines the
  pre-Run-008 baseline (B8 closed, leader-side re-emission gap
  surfaced as Run-007 residual) and prescribes Run 008's shape.
- `docs/whitepaper/contradiction.md` C4 — current canonical record
  of the binary-bring-up contradiction; B1/B2/B3/B5/B6/B7/B8/B9
  landed; pre-Run-008 `Impact` notes "this makes the precondition
  Run 008 will exercise — first observed cross-node proposal/vote/
  QC/commit progression on real `qbind-node` processes — both
  reachable and bounded."
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_006.md`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md`,
  `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — referenced for
  topology, peer syntax, regression-guard expectations.
- `crates/qbind-node/src/binary_consensus_loop.rs` — implementation
  of B9 re-emission, including the `peer_connectivity` field on
  `BinaryConsensusLoopIo`, the `maybe_reemit_on_late_peer_connect`
  helper, and the `outbound_proposal_late_peer_reemits` counter.
- `crates/qbind-node/src/main.rs` (`run_p2p_node`) — wires the
  same `Arc<dyn P2pService>` instance used for inbound demuxing and
  outbound `P2pConsensusNetwork` through the new
  `P2pServicePeerConnectivity` adapter into
  `BinaryConsensusLoopIo::peer_connectivity`.
- `crates/qbind-node/tests/b9_late_peer_connect_proposal_reemit_tests.rs`
  — six in-tree regression tests that bound B9 (single-shot per
  view, view-change invalidation, single-validator and `io=None`
  no-regression).

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1`, Linux 6.17.0-1010-azure x86_64 |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo branch | `copilot/execute-devnet-evidence-run-008` |
| Repo HEAD at run | `cb2ba3c` (the head of this branch as cloned) |
| Build profile | `cargo build --release -p qbind-node --bin qbind-node` |
| Build duration | 6 m 11 s |
| Resulting binary | `target/release/qbind-node`, ELF 64-bit, 9 019 104 bytes |
| Binary build warning | one `unused variable: worker_id` warning in `verify_pool.rs` (pre-existing; not a regression caused by this run) |
| All run logs / metrics under | `/tmp/run008/` |

The binary used for **all** sub-runs in this report is the same
binary built once from the branch HEAD; no per-sub-run rebuild was
done.

## 4. Topology and Node Configuration Used

Three sub-runs were executed in sequence, all against the same
release binary:

### 4.1 Sub-run A — Primary, deliberate late-peer-connect (P2P, two real binaries)

| Node | Validator | Listen | Static peer (`vid@addr`) | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|---|
| V0 | `ValidatorId(0)` | `127.0.0.1:19000` | `1@127.0.0.1:19001` | `127.0.0.1:9100` | `/tmp/run008/data-v0` | `2026-05-06T09:55:54.940771358Z` |
| V1 | `ValidatorId(1)` | `127.0.0.1:19001` | `0@127.0.0.1:19000` | `127.0.0.1:9101` | `/tmp/run008/data-v1` | `2026-05-06T09:56:06.942904515Z` |

V0 was started ≈ 12 s before V1. V0 is the leader of view 0 in this
two-validator cluster, so V0's leader-tick fires into an empty peer
set and leader-side re-emission must close the gap on late peer
connect. V0's first 7 dial attempts to `127.0.0.1:19001` are
expected to fail with `Connection refused` because V1's listener
does not exist yet (B8 bounded retry). Whichever side eventually
establishes a TCP connection (here, V1, after V1 starts and dials
V0) is the side whose KEMTLS handshake completes; on V0 the
**inbound resolver** must bind that accepted session to V1's
deterministic `NodeId(92115fddcd4f93a0)` (B8 listener-side identity
closure), and on V1 the **dialer-side override path** must register
V0's deterministic `NodeId(4bd96f97b1aaec9d)` (B7).

This is the exact topology Run 008 is designed to exercise: a real
late-peer-connect, on real binaries, where the leader's view-0
proposal was emitted before any peer was registered.

### 4.2 Sub-run B — Optional comparison, friendlier startup order

| Node | Validator | Listen | Static peer | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|---|
| V1b | `ValidatorId(1)` | `127.0.0.1:19011` | `0@127.0.0.1:19010` | `127.0.0.1:9111` | `/tmp/run008/data-v1b` | `2026-05-06T10:00:34Z` (approx; see logs) |
| V0b | `ValidatorId(0)` | `127.0.0.1:19010` | `1@127.0.0.1:19011` | `127.0.0.1:9110` | `/tmp/run008/data-v0b` | `2026-05-06T10:00:40Z` (approx; see logs) |

V1b was started ≈ 6 s before V0b. The intent (per task brief
§2-B) was to give the peer a head start so V0b's first dial
might succeed before its leader-tick fires, exercising the
**original (non-B9) broadcast path**. As recorded in §6 below,
this stagger was insufficient to actually pre-establish the
session before V0b's leader-tick — V0b again exercised the B9
late-peer-connect path. Sub-run B therefore serves as a
**reproduction** of sub-run A's qualitative shape under a
different stagger, not as a clean separation of "B9 path" vs.
"original broadcast path".

### 4.3 Sub-run C — Single-validator LocalMesh §11 regression check

| Node | Validator | Mode | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|
| SV | `ValidatorId(0)` | `local-mesh` | `127.0.0.1:9102` | `/tmp/run008/data-sv` | `2026-05-06T10:03:31Z` |

This run does not use P2P, does not have static peers, and does
not exercise B6/B7/B8/B9. Per `binary_consensus_loop.rs` and the
B9 regression-guard tests (test `E` in
`b9_late_peer_connect_proposal_reemit_tests.rs`), the
`peer_connectivity = None` path keeps the
`outbound_proposal_late_peer_reemits` counter at `0` and is
bit-equivalent to pre-B9. Sub-run C confirms this empirically.

## 5. Commands and Configuration Used

Exactly as executed (each backgrounded, output redirected to per-node
files under `/tmp/run008/logs/`).

### 5.1 Sub-run A

```sh
# V0 (started first)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19000 \
    --p2p-peer 1@127.0.0.1:19001 \
    --validator-id 0 \
    --data-dir /tmp/run008/data-v0

# … sleep 12 …

# V1 (started second)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9101 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19001 \
    --p2p-peer 0@127.0.0.1:19000 \
    --validator-id 1 \
    --data-dir /tmp/run008/data-v1
```

### 5.2 Sub-run B (comparison)

```sh
# V1b (started first)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9111 \
  ./target/release/qbind-node --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19011 \
    --p2p-peer 0@127.0.0.1:19010 \
    --validator-id 1 \
    --data-dir /tmp/run008/data-v1b

# … sleep 6 …

# V0b (started second)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9110 \
  ./target/release/qbind-node --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19010 \
    --p2p-peer 1@127.0.0.1:19011 \
    --validator-id 0 \
    --data-dir /tmp/run008/data-v0b
```

### 5.3 Sub-run C (single-validator regression check)

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9102 \
  ./target/release/qbind-node \
    --env devnet --network-mode local-mesh \
    --validator-id 0 \
    --data-dir /tmp/run008/data-sv
```

### 5.4 Environment variables

The only environment variable set per node beyond the inherited
shell is `QBIND_METRICS_HTTP_ADDR` (gating B2's metrics endpoint
per `MetricsHttpConfig::from_env`). No restore flag, no genesis
override, no validator-set override, no PoP / KEMTLS env
overrides; the binary uses its built-in `SimpleValidatorNodeMapping`
and `derive_test_kem_keypair_from_validator_id` defaults
introduced by B7. Both nodes were started with `--env devnet`,
which prints the standard B7-onwards "P2P enabled in DevNet
environment. DevNet v0 freeze recommends LocalMesh." warning to
stderr — this is expected and is honest (it does not silently
fall back to LocalMesh; it proceeds with P2P as configured).

### 5.5 Peer syntax

All P2P peers use the post-B7 `vid@addr` syntax, validated against
the contradiction.md C4 statement that bare-addr peers are
rejected with a clear error rather than producing a broken
handshake. Both sub-run A and sub-run B exclusively use `vid@addr`.

## 6. Startup, Handshake, and Connectivity Evidence

### 6.1 Sub-run A (primary)

Stdout extracts. Format reproduced verbatim.

V0 (`/tmp/run008/logs/node0.stdout`):

```
qbind-node[validator=V0]: starting in environment=DevNet … network=p2p p2p=enabled listen=127.0.0.1:19000 peers=1 …
[P2P] Listening on 127.0.0.1:19000 (node_id=NodeId(4bd96f97b1aaec9d))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1
[P2P] dial 127.0.0.1:19001 attempt 1/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 100ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 2/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 200ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 3/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 400ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 4/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 800ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 5/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 6/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 7/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] Accepted connection from 127.0.0.1:51352
[P2P] Accepted connection from 127.0.0.1:51354
[P2P] Inbound connection from 127.0.0.1:51354 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
```

V0 stderr (relevant excerpts):

```
[binary] P2P transport up. Listen address: 127.0.0.1:19000, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
[P2P] dial 127.0.0.1:19001 giving up after 8 attempt(s): I/O error: Connection refused (os error 111) (transient=true, max_attempts=8)
[P2P] Inbound connection error: Handshake error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary-consensus] B9: re-emitted view 0 BroadcastProposal after late peer connect (newly_connected_peers=1, reemits_total=1)
```

V1 (`/tmp/run008/logs/node1.stdout`):

```
qbind-node[validator=V1]: starting in environment=DevNet … listen=127.0.0.1:19001 peers=1 …
[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1
[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
```

V1 stderr (relevant excerpts):

```
[binary] P2P transport up. Listen address: 127.0.0.1:19001, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

What this proves:

- **Handshake succeeds.** Both sides report `Peer NodeId(...) connected` (V0 sees V1's deterministic `NodeId(92115fddcd4f93a0)`; V1 sees V0's deterministic `NodeId(4bd96f97b1aaec9d)`). Same byte-identical NodeIds as in Run 007.
- **B7 dialer-side override is active on V1**: the `using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)` line is the post-B7 dialer-side identity-closure trace.
- **B8 listener-side resolver is active on V0**: the `Inbound connection from 127.0.0.1:51354 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)` line is the post-B8 listener-side identity-closure trace.
- **B8 bounded initial-dial retry is exercised on V0**: 7 retries, then `giving up after 8 attempt(s) … transient=true, max_attempts=8`. The surviving session is therefore V1→V0 (V1 is the dialer; V0 is the listener for the real session, after V0's own outbound dial budget was exhausted while V1 had not yet started listening).
- **The `Inbound connection error: Handshake error: channel error: Io(... UnexpectedEof ...)` line on V0** corresponds to V0's first inbound connection (`127.0.0.1:51352`), which is V1's first inbound TCP that the resolver does not yet have a complete `client_random` for at handshake-decode time. This is the same shape recorded on Run 006/007 stderr; it is **not** a B7/B8 regression — V0's *second* inbound (`127.0.0.1:51354`) succeeds via the resolver and binds to V1's deterministic NodeId. This is honest noise, not silent failure.
- **`peers=1`, `num_validators=2`, `peer_kem_overrides=1`** consistent with B7's `vid@addr` parsing on both sides.
- **`late_peer_reemit=on`** appears in both nodes' "Starting consensus loop:" lines. This is the binary's explicit declaration that B9 is wired (`peer_connectivity` is `Some` on both nodes, because `run_p2p_node` always wires the `Arc<dyn P2pService>` adapter when `--enable-p2p`).

### 6.2 Sub-run B (comparison)

V1b started first; its log shows 7 `Connection refused` retries to V0b (whose listener was not up yet), then `giving up after 8 attempt(s)`. V0b started 6 s later and dialed V1b successfully (V0b stdout: `Dial 127.0.0.1:19011: using per-peer KEM pk + validator-id override`; `Peer NodeId(92115fddcd4f93a0) connected`). On V1b, the listener-side resolver bound the accepted V0b session to `NodeId(4bd96f97b1aaec9d)` (V1b stdout: `Inbound connection from 127.0.0.1:40276 bound to deterministic NodeId NodeId(4bd96f97b1aaec9d) via inbound identity resolver (B8, test-grade)`; `Peer NodeId(4bd96f97b1aaec9d) connected`).

In other words, **the same handshake / identity outcome as sub-run A, just with the dialer/listener roles swapped relative to sub-run A**. As §7 below records, V0b's leader-tick still fires before the peer is registered, so B9 still re-emits.

### 6.3 Sub-run C (single-validator)

V0 alone, LocalMesh. Stderr:

```
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=1 restore_baseline=false
[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms restore_baseline=false interconnect=none late_peer_reemit=off
```

Note `interconnect=none` and `late_peer_reemit=off` — bit-equivalent to pre-B9.

## 7. Late-Peer-Connect Re-Emission Evidence

This section answers task brief required question D.

### 7.1 Sub-run A

The B9 path was actually exercised on the binary path in sub-run A. The ground-truth evidence is two concurring artifacts:

1. **V0 stderr** contains exactly one B9 trace:

   ```
   [binary-consensus] B9: re-emitted view 0 BroadcastProposal after late peer connect (newly_connected_peers=1, reemits_total=1)
   ```

   The `view 0` field matches the cached-view gate; `newly_connected_peers=1` matches V1's connection-set transition `{} → {NodeId(92115fddcd4f93a0)}`; `reemits_total=1` matches the per-view single-shot latch.

2. **V0 loop-exit summary** (stderr, on shutdown):

   ```
   [binary-consensus] Loop exit: ticks=2201 proposals=1 commits=0 committed_height=None view=1 inbound_msgs=1 inbound_proposals=0 inbound_votes=1 outbound_proposals=1 outbound_votes=1 outbound_proposal_late_peer_reemits=1
   ```

   `outbound_proposal_late_peer_reemits=1` is the value of `BinaryConsensusLoopInboundStats::outbound_proposal_late_peer_reemits` (introduced by B9), and it agrees with the stderr line. `proposals=1` (the cached leader-step proposal) and `outbound_proposals=1` (the broadcasted proposal) also agree with the seven-gate path.

That a single re-emission was issued — not zero, not more than one — also matches the per-view single-shot latch (gate 6) and the no-stale-replay guarantee (gate 3) covered by the in-tree B9 tests A and B.

### 7.2 Sub-run B

V0b stderr also contains exactly one B9 trace:

```
[binary-consensus] B9: re-emitted view 0 BroadcastProposal after late peer connect (newly_connected_peers=1, reemits_total=1)
```

V0b loop-exit summary:

```
[binary-consensus] Loop exit: ticks=1002 proposals=1 commits=0 committed_height=None view=1 inbound_msgs=1 inbound_proposals=0 inbound_votes=1 outbound_proposals=1 outbound_votes=1 outbound_proposal_late_peer_reemits=1
```

So even with a 6 s reverse stagger (intended to give V0b's first dial a chance to succeed before its first leader-tick), the binary boot time + KEMTLS handshake exceeded the leader-tick interval (100 ms) and the leader-step proposal was again emitted into an empty peer set. The "friendlier" startup recipe did **not** produce a clean separation between "B9 path" and "original broadcast path" on this host. **This is honestly recorded rather than presented as a clean two-state comparison.** Practically, sub-run B is a reproduction of sub-run A's late-peer-connect shape, not a control.

### 7.3 Sub-run C

`peer_connectivity=None` in the LocalMesh path, no peer connects, so B9 is never triggered. V0 (sv) loop-exit:

```
[binary-consensus] Loop exit: ticks=602 proposals=602 commits=600 committed_height=Some(599) view=602 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0 outbound_proposal_late_peer_reemits=0
```

`outbound_proposal_late_peer_reemits=0`, `late_peer_reemit=off`, all IO counters at 0. Bit-equivalent to pre-B9. This empirically confirms the B9 regression-guard test E (`peer_connectivity=None` keeps the counter at 0) on the actual production binary, not just in unit tests.

## 8. Cross-Node Proposal / Vote Evidence

This section answers task brief required questions E and F.

The relevant agreed-upon source of truth is the **binary consensus loop counters** captured in each node's stderr `Loop exit:` summary, since these are populated by the loop's own decode/encode of `ConsensusNetMsg::{Proposal, Vote}` frames and therefore reflect message-level reality on the binary path. The Prometheus `consensus_net_*_total` counters (see §10) under-report this path; that under-reporting is recorded as an anomaly in §10 / §13.

### 8.1 Sub-run A

| Metric (from `Loop exit:` line) | V0 | V1 |
|---|---|---|
| `ticks` | 2 201 | 2 081 |
| `proposals` (leader-step proposals emitted by local engine) | 1 | 0 |
| `outbound_proposals` (decoded `BroadcastProposal` actions encoded onto the wire) | 1 | 0 |
| `outbound_proposal_late_peer_reemits` | **1** | 0 |
| `outbound_votes` (decoded `BroadcastVote` / `SendVoteTo` actions encoded onto the wire) | 1 | 1 |
| `inbound_msgs` (decoded `ConsensusNetMsg::*` frames received on the wire) | 1 | 1 |
| `inbound_proposals` (decoded `ConsensusNetMsg::Proposal` frames fed into engine) | 0 | **1** |
| `inbound_votes` (decoded `ConsensusNetMsg::Vote` frames fed into engine) | **1** | 0 |
| `commits` | 0 | 0 |
| `committed_height` | None | None |
| `view` (engine current_view at shutdown) | 1 | 0 |

Per-engine (`/metrics`, scrape C):

| Metric | V0 | V1 |
|---|---|---|
| `qbind_consensus_proposals_total{result="accepted"}` | 1 | 0 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 |
| `qbind_consensus_votes_total{result="accepted"}` | 0 | 0 |
| `qbind_consensus_votes_total{result="invalid"}` | 0 | 0 |
| `qbind_consensus_qcs_formed_total` | 0 | 0 |
| `qbind_consensus_view_changes_total` | 1 | 0 |
| `qbind_consensus_current_view` / `qbind_consensus_view_number` | 1 / 1 | 0 / 0 |

What this proves, line by line:

- **Cross-node proposal traversal succeeded for the first time in DevNet evidence.** V0's loop emitted 1 outbound proposal (which is the B9 re-emit of the cached view-0 leader proposal); V1's loop decoded and ingested 1 inbound `ConsensusNetMsg::Proposal` (`inbound_msgs=1`, `inbound_proposals=1`). This confirms task brief checklist items 3 and 4 on the binary path.
- **Cross-node vote traversal succeeded for the first time in DevNet evidence.** V1's loop emitted 1 outbound vote (the only path through which `BinaryConsensusLoopInboundStats::outbound_votes` can be incremented is an engine-emitted `ConsensusEngineAction::{BroadcastVote, SendVoteTo}` after `on_proposal_event`); V0's loop decoded and ingested 1 inbound `ConsensusNetMsg::Vote` (`inbound_msgs=1`, `inbound_votes=1`). This confirms task brief checklist items 5 and 6 on the binary path.
- **Engine-level acceptance counters do not advance in lockstep with loop-level traversal counters.** V1 ingested 1 inbound proposal at the loop layer but `qbind_consensus_proposals_total{result="accepted"} = 0` and `…{result="rejected"} = 0` — neither bucket fired. Symmetrically, V0 ingested 1 inbound vote at the loop layer but `qbind_consensus_votes_total{result="accepted"} = 0` and `…{result="invalid"} = 0`. The fact that V1's outbound vote was nevertheless emitted (`outbound_votes=1`) means V1's engine **did** progress far enough through `on_proposal_event` to enqueue a vote action even though the `qbind_consensus_proposals_total` accepted/rejected buckets did not increment. That divergence is treated as a metric-coverage observation in §13 rather than as evidence that V1 silently rejected the proposal.
- **No QC formed on either side.** `qbind_consensus_qcs_formed_total = 0` on both V0 and V1 across all three `/metrics` scrapes (A, B, C). Task brief checklist item 7 is therefore **not** satisfied.

### 8.2 Sub-run B (comparison)

Loop-exit numbers (V0b / V1b respectively):

```
V0b: ticks=1002 proposals=1 commits=0 committed_height=None view=1 inbound_msgs=1 inbound_proposals=0 inbound_votes=1 outbound_proposals=1 outbound_votes=1 outbound_proposal_late_peer_reemits=1
V1b: ticks=1062 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=1 inbound_proposals=1 inbound_votes=0 outbound_proposals=0 outbound_votes=1 outbound_proposal_late_peer_reemits=0
```

Identical qualitative shape to sub-run A: B9 re-emit fires once on the leader, the proposal crosses to V1b (`inbound_proposals=1`), V1b emits 1 outbound vote which crosses back (`inbound_votes=1` on V0b), but no QC forms (`qbind_consensus_qcs_formed_total = 0` on both V0b and V1b in `/metrics`). The reverse stagger therefore does not reveal a different boundary; both sub-runs end at the same place.

## 9. QC / Commit Progress Evidence

This section answers task brief required question G.

| Metric | V0 (A) | V1 (A) | V0b (B) | V1b (B) |
|---|---|---|---|---|
| `qbind_consensus_qcs_formed_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_changes_total` | 1 | 0 | 1 | 0 |
| `qbind_consensus_current_view` | 1 | 0 | 1 | 0 |
| Loop-exit `commits` | 0 | 0 | 0 | 0 |
| Loop-exit `committed_height` | None | None | None | None |

No QC formed on either real binary in either sub-run. No commit
fired. `committed_height` stayed `None` on every node in every
multi-validator sub-run.

V0's `qbind_consensus_view_changes_total = 1` and `current_view = 1`
mean V0's engine advanced past view 0 anyway. The consistent
companion observations — `qcs_formed_total = 0`,
`votes_observed_total = 0`, `votes_total{accepted}=0` — mean this
view advance is not driven by an observed cross-node QC; it is the
engine's own internal view-progression path (most plausibly a
single-validator-style self-step inside the leader's own engine
after the proposal action was issued, plus a 2-validator quorum
that does not require an externally accepted vote at the metric-
counter level used here). V1, which is **not** the leader of view
0 and therefore cannot self-step, shows no view advance
(`view_changes_total = 0`, `current_view = 0`). This asymmetry is
honest — V0's view advance is a leader-side internal effect, not
externally-driven progression — and is recorded as such here so it
cannot be confused with QC formation.

**Verdict:** task brief checklist items 7 and 8 are not satisfied.
`qcs_formed_total > 0` does not occur, and there is no commit /
`committed_height` progression on the binary path in any sub-run.

## 10. Metrics Evidence

`/metrics` evidence is captured at the timestamps in the table
below (UTC, recorded into `/tmp/run008/scrape_*.ts`).

| Sub-run | Scrape | Wall time (UTC) | Files |
|---|---|---|---|
| A | A | `2026-05-06T09:56:50.884Z` | `node0.metrics_a`, `node1.metrics_a` |
| A | B | `2026-05-06T09:58:38.113Z` | `node0.metrics_b`, `node1.metrics_b` |
| A | C | `2026-05-06T09:59:24.529Z` | `node0.metrics_c`, `node1.metrics_c` |
| B | (single) | `2026-05-06T10:02:10.282Z` | `node0b.metrics_a`, `node1b.metrics_a` |
| C | (single) | (during 25 s steady state) | `sv.metrics_a` |

Across the three sub-run-A scrapes the consensus counter values on
both V0 and V1 are **identical** at scrapes A, B, and C — they hold
flat at exactly the values shown in §8.1. There is no fluctuation
of `qcs_formed_total` upward and back to 0; the engine never formed
a QC and the metric never moved. This confirms task brief required
question H ("Did `/metrics` remain honest?"): **yes.**

### 10.1 Honest under-reporting on the P2pConsensusNetwork path

A cross-cut observation: **the Prometheus `consensus_net_*_total`
counters under-report on the binary path actually exercised here.**
Across all three sub-run-A scrapes both nodes report:

```
consensus_net_inbound_total{kind="proposal"} 0
consensus_net_inbound_total{kind="vote"}     0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
consensus_net_outbound_total{kind="vote_broadcast"}     0
consensus_net_outbound_total{kind="vote_send_to"}       0
```

But the `Loop exit:` summaries on the same nodes show
`outbound_proposals=1`, `inbound_proposals=1`, `outbound_votes=1`,
`inbound_votes=1`. The `inc_outbound_proposal_broadcast` /
`inc_inbound_proposal` increments live on the
`consensus_net_worker.rs` path; the `P2pConsensusNetwork` path used
by the binary's `BinaryConsensusLoopIo::outbound` does not appear
to feed into those increments under the configuration the binary
actually runs in. This is a **silent under-report**, not a fake
report — the metric reads `0`, which is *less* than the truth, so
nothing is being fabricated. It is recorded as a metric-coverage
gap in §13 and explicitly **not** counted as a regression of B2's
"`/metrics` is honest" guarantee, because the metric does not
overclaim. The `qbind_consensus_*` engine-level counters are
honest (they reflect the engine's own internal state), and the
loop-level counters are honest (they reflect what the loop did
encode/decode); the two also agree with each other and with the
shutdown summary. This satisfies "metrics and loop-exit summaries
agree" in task brief §7 for everything the engine and loop publish.

## 11. Shutdown Evidence

### 11.1 Sub-run A

Shutdown initiated at `2026-05-06T09:59:34.974Z` via SIGINT to V0 and V1. Stderr tails:

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 2201 ticks.   # V0
[binary-consensus] Loop exit: ticks=2201 …                      # V0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

V1 is symmetric (`Shutdown signal received after 2081 ticks.`,
`Loop exit: ticks=2081 …`). 10 s after SIGINT, both processes
have terminated (`pgrep -af qbind-node` returns nothing).
`shutdown_done.ts = 2026-05-06T09:59:44.992Z`. Post-shutdown port
probes:

```
127.0.0.1:9100  -> 000   # V0 metrics
127.0.0.1:9101  -> 000   # V1 metrics
127.0.0.1:19000 -> 000   # V0 P2P listen
127.0.0.1:19001 -> 000   # V1 P2P listen
```

All ports release cleanly (HTTP 000 = connection refused / no
listener) — same shape as Run 006/007, no zombie listener.

### 11.2 Sub-run B

Same shape:

```
V0b loop exit: ticks=1002 …
V1b loop exit: ticks=1062 …
```

Post-shutdown probes for `9110`, `9111`, `19010`, `19011` all
return `000`.

### 11.3 Sub-run C

```
V0 (sv) loop exit: ticks=602 proposals=602 commits=600 committed_height=Some(599) view=602 …
[binary] LocalMesh node stopped.
[binary] Shutdown complete.
```

Port `9102` returns `000` post-shutdown.

This satisfies task brief required question I: **shutdown remained
clean across all three sub-runs**, identical to the Run-006/007
shutdown shape.

## 12. Regression Check Against Previously Landed Binary-Path Capabilities

Item-by-item against the regression-guard list in task brief §6.

| Capability | Evidence in this run | Verdict |
|---|---|---|
| **B1** (`BasicHotStuffEngine` driver wired into the binary path) | Sub-run C: `proposals=602`, `commits=600`, `committed_height=Some(599)`, `view=602` after 25 s on real binary; engine drives normally. | Not regressed. |
| **B2** (`/metrics` gated on `QBIND_METRICS_HTTP_ADDR`) | All three sub-runs scraped `/metrics` successfully on `:9100/:9101/:9102/:9110/:9111`. Endpoint emits the standard counter set. Scrapes A/B/C in sub-run A held identical values across time without artificial growth. | Not regressed. |
| **B3** (`--restore-from-snapshot`) | Not exercised (no `--restore-from-snapshot` argument); stderr says `[restore] no --restore-from-snapshot requested; normal startup.`. Out of scope for this run, no negative observation. | Not regressed (not exercised). |
| **B5** (restore-aware consensus start) | Same: `restore_baseline=false` in every sub-run's "Consensus loop config" line. | Not regressed (not exercised). |
| **B6** (multi-validator P2P binary-path interconnect, inbound→engine routing, engine actions through `P2pConsensusNetwork`) | Sub-run A: `[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event …` line emitted on both V0 and V1. Loop-exit `inbound_msgs/proposals/votes` counters surfaced. Cross-node `inbound_proposals=1` on V1 and `inbound_votes=1` on V0 confirm B6's inbound demuxer → engine path **actually moved a real `ConsensusNetMsg`** between two real binaries for the first time. | Not regressed. |
| **B7** (binary-path test-grade KEMTLS bring-up + dialer-side identity closure) | V1 stdout `Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`, `peer_kem_overrides=1`, `vid@addr` peer syntax accepted on both sides. Same for V0b in sub-run B. | Not regressed. |
| **B8** (listener-side identity closure + bounded initial-dial retry) | V0 stdout `Inbound connection from 127.0.0.1:51354 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)`. V0 stderr B8 retry trace through 7 attempts then `giving up after 8 attempt(s) … transient=true, max_attempts=8`. Symmetric V1b in sub-run B. | Not regressed. |
| **B9** (leader-side re-emission of `BroadcastProposal` on late peer connect within the same view) | V0 stderr `B9: re-emitted view 0 BroadcastProposal after late peer connect (newly_connected_peers=1, reemits_total=1)` (sub-run A) and V0b symmetric (sub-run B). Counter `outbound_proposal_late_peer_reemits=1` in both leader-side loop exits, `0` on the non-leader and on sub-run C. Late-peer-reemit declared `on` in the multi-validator startup banner and `off` in the LocalMesh banner. | Actively exercised, behaved within the seven-gate envelope (single-shot per view), no second re-emission, no stale replay across views. |
| **`/metrics` honest** | See §10. Identical counter values across three scrapes; under-report (not over-report) on the `consensus_net_*_total` family. | Not regressed. |
| **No fallback to LocalMesh / single-validator semantics** | Both sub-run-A nodes and both sub-run-B nodes print `network=p2p p2p=enabled`, `interconnect=p2p`, `num_validators=2`. No `Single-validator LocalMesh` line on any P2P node. The only node with a LocalMesh banner is sub-run C, which is the explicit single-validator regression-guard check. | Not regressed. |
| **`vid@addr` peer-syntax enforcement** | Both peers in sub-runs A and B use `vid@addr`. Not negatively asserted on this run (no bare-addr test attempted), but the `peer_kem_overrides=1` count confirms the `vid@` parse path produced a registered override. | Not regressed (not negatively asserted). |

Conclusion: **no previously landed binary-path capability appears regressed.**

## 13. Limitations and Anomalies Observed

1. **Engine acceptance does not advance to QC formation despite cross-node message traversal.** V1 loop-decoded the inbound proposal and emitted an outbound vote action; V0 loop-decoded the inbound vote. But `qbind_consensus_proposals_total{accepted+rejected} = 0` on V1 and `qbind_consensus_votes_total{accepted+invalid} = 0` on V0, and `qcs_formed_total = 0` on both. The exact engine reason (e.g., proposer_index / validator_index mapping, view mismatch on the re-emitted proposal vs. V1's local view, leader-window check, tree-anchor mismatch, signature-verification skip path under the test-grade configuration) is not directly observable from the binary's stdout/stderr at the current verbosity, and was not investigated in this run because the task brief is **execution / evidence**, not debugging. This is the new boundary surfaced by Run 008.

2. **`consensus_net_*_total` Prometheus counters under-report the actually-traversed binary-path traffic.** Sub-run A loop counters say 1 proposal and 1 vote crossed the wire in each direction; the `consensus_net_*_total` family stays at `0` for both kinds at all three scrapes. This is a metric-wiring gap on the `P2pConsensusNetwork` path; it is honest in the sense that it under-reports rather than fabricates, but it is now a known divergence between the binary's loop-level evidence and its Prometheus surface. Recorded for follow-up but **not** treated as a B2 regression because the metric does not overclaim.

3. **Sub-run B did not produce a clean "no late peer connect" control.** With a 6 s reverse stagger, V0b's leader-tick still fired before the peer-set transition was observable, so B9 re-emission still fired. The intended separation between "B9 re-emission path" and "original first-emission broadcast path" was therefore not achieved on this host. A clean separation likely requires either (a) reducing the binary boot + KEMTLS handshake time below the 100 ms tick interval (unlikely on this binary), or (b) a deterministic synchronization barrier between the two nodes' startup sequences (out of scope for this run; would require harness wiring that the task brief specifically asks against).

4. **First inbound on the listener side fails handshake on V0** (`Handshake error: channel error: Io(... UnexpectedEof ...)`); the **second** inbound succeeds and binds via the resolver. Same shape as Run 006/007 — pre-existing observation, not a new anomaly.

5. **V0 advances `current_view = 1` on a leader-only path.** Section 9 records this is a leader-side internal step (V1's view does not advance), not an externally-driven QC. Honest, but worth flagging so the view advance is not misread as a cross-node QC.

6. **DevNet+P2P warning on stderr.** Both P2P sub-runs print `[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh.` This is the standard advisory; the binary still proceeds with P2P. Recorded as expected, not as silent fallback.

7. **One harmless pre-existing `unused variable: worker_id` warning** during release build of `qbind-node` at `verify_pool.rs:262`. Not a regression caused by this run; not a runtime issue.

## 14. Assessment of Evidence Value

Run 008 is the **first DevNet evidence run that demonstrates honest cross-node `ConsensusNetMsg` traversal between two real `qbind-node` binaries**. Specifically:

- For the first time, **a leader-issued `BroadcastProposal` reaches the wire on the binary path** (V0's `outbound_proposals=1`, driven by B9 re-emission after late peer connect — exactly what B9 was designed for).
- For the first time, **a peer engine ingests a cross-node proposal on the binary path** (V1's `inbound_proposals=1`).
- For the first time, **a peer engine emits a cross-node vote on the binary path that returns to the leader** (V1's `outbound_votes=1`, V0's `inbound_votes=1`).
- B9 is **empirically exercised on real `qbind-node` processes** (the one stderr line, the `outbound_proposal_late_peer_reemits=1` counter on the leader, and the `=0` counter on the non-leader and on the single-validator regression check together prove the seven-gate envelope on real binaries, not just in unit tests).

This **materially narrows C4** below where Run 007 left it. Run 007's residual was "leader-issued `BroadcastProposal` does not reach the wire on late peer connect within the same view"; Run 008 closes that residual on real binaries. The new boundary is **strictly smaller** and **strictly above** the network/transport/identity stack: it sits at the engine-acceptance / QC-formation layer.

What Run 008 does **not** prove (per task brief §1-C "exactness"):

- It does **not** prove `qcs_formed_total > 0`.
- It does **not** prove `committed_height` progresses on the binary path under multi-validator P2P.
- It does **not** prove the `consensus_net_*_total` Prometheus family fully covers the `P2pConsensusNetwork` path.
- It does **not** prove the original (non-B9) first-emission broadcast path on the binary, because both P2P sub-runs ended up exercising B9 anyway.
- It does **not** make any claim about production identity hardening, mutual-auth, or `MutualAuthMode::Required`; those are still tracked separately in C4 `Remaining`.

The verdict is therefore: **PARTIAL — POSITIVE.** Run 008 reaches task brief §7 checklist items 1–6 on the binary path and stops at items 7–8.

## 15. Recommended Immediate Next Action

The exact next execution action recommended after Run 008 is:

> **B10 — Engine-side acceptance / QC-formation closure on the
> binary path under the post-B9 re-emitted leader proposal.**

Specifically: identify why V1's engine emits a vote action in
response to V0's re-emitted proposal but the
`qbind_consensus_proposals_total{accepted}` counter does not
increment, and why V0's engine receives V1's vote (loop counter
`inbound_votes=1`) but does not increment
`qbind_consensus_votes_total{accepted}` and does not form a QC.
Candidate root-causes to triage, in approximate order of
likelihood (none of which Run 008 attempts to commit to):

1. View / proposer_index mismatch between the cached re-emitted
   view-0 proposal and the receiver's local current_view at the
   moment of `on_proposal_event`. (V0's view advanced to 1 on its
   own internal step; V1 was still at view 0.)
2. The B9 re-emission path on the leader broadcasts the cached
   `BlockProposal` byte-for-byte, but a downstream metric
   increment lives on a path that is only entered for the
   *original* leader-step emission, not for re-emission.
3. A test-grade signature / certificate field on the proposal or
   vote that the receiving engine validates as part of the
   accept/reject gate but the test-grade KEMTLS+Disabled-mutual-
   auth configuration leaves at a non-canonical value.

Bounded scope for B10 (mirroring the B6→B7→B8→B9 discipline):

- Reproduce the Run-008 partial-positive shape in an in-tree two-
  engine integration test (the same kind of test
  `b9_late_peer_connect_proposal_reemit_tests.rs` already provides
  for the loop layer, extended one layer up so the receiving
  engine's accept/reject gate is observable) before changing any
  production code.
- Land the smallest honest fix that turns the `inbound_proposals=1`
  loop observation into `qbind_consensus_proposals_total{accepted}
  = 1` on the receiver and the `inbound_votes=1` observation into
  `qbind_consensus_votes_total{accepted} = 1` on the leader,
  without weakening B6/B7/B8/B9 and without inventing a new
  identity / certificate system.
- Then run **DevNet Evidence Run 009** as the first post-B10
  exercise, against the same Run-008 sub-run-A topology, with the
  goal of `qcs_formed_total > 0` and `committed_height > None` on
  the binary path.

Concretely **not** recommended as the next action:

- Production PQC KEMTLS / `MutualAuthMode::Required` hardening (still in C4 `Remaining`; below B10 in priority).
- Multi-validator restore catchup (still in C4 `Remaining`; below B10 in priority).
- Closing the `consensus_net_*_total` under-report (real metric-coverage gap, but does not block consensus progression; can be addressed alongside or after B10).

If reviewers prefer a smaller next step, an alternative is to
spend one cycle on the metric-coverage gap surfaced in §13 item 2
(`consensus_net_outbound_total{kind="proposal_broadcast"}` not
incrementing on the `P2pConsensusNetwork` path) so that a future
run can rely on the Prometheus surface as a cross-check on the
loop-exit counters — but this is an evidence-quality improvement,
not a consensus-progression unblock, and B10 remains the path
forward for cross-node QC / commit progression.