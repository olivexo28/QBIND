# QBIND DevNet Evidence Run 009

## 1. Purpose and Scope

Run 009 is the **first post-B10 multi-validator binary-path DevNet
evidence exercise** on QBIND. Its purpose is to determine, on real
`qbind-node` processes, whether the engine-side acceptance / QC-formation
closure landed by B10 (closing the Run-008 residual recorded in
`docs/whitepaper/contradiction.md` C4 — "engine accept / QC formation
layer above the network/transport/identity stack") is observable on the
binary path, and whether cross-node `committed_height` progression now
actually fires.

This is an execution / evidence task. No QBIND source files are modified
by this run; only this evidence document is created and a small,
conservative narrowing is applied to C4's `Impact` paragraph plus a
single new row in the C4 `Update History` table. No other docs are
created.

The strongest-positive checklist Run 009 was asked to evaluate
(per task brief §7) is:

1. handshake succeeds,
2. both sides register each other under deterministic NodeIds,
3. if late-peer-connect shape is used, B9 proposal re-emission is
   observable,
4. if late-peer-connect shape is used, B10 paired leader-vote
   re-emission is observable,
5. node A outbound proposal reaches the wire,
6. node B inbound proposal > 0,
7. node B inbound leader-vote > 0 (where applicable),
8. node B engine accepted proposal > 0,
9. node A engine accepted vote > 0,
10. `qcs_formed_total > 0`,
11. `committed_height > None` on at least one node, preferably both,
12. `/metrics` and loop-exit summaries agree, except where an honest
    under-report is explicitly identified.

Run 009 reaches **all twelve items** on the binary path, on two real
`qbind-node` binaries, for the first time in DevNet evidence history.
Per task brief §1-C, this is reported as a **POSITIVE** result, with
the precise honest under-report on the `consensus_net_*_total`
Prometheus family carried forward from Run 008 explicitly identified
(see §10.1) — that is the only respect in which the run is not
"complete-positive across every metric surface".

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_008.md` — defines the
  pre-Run-009 baseline (B6–B9 closed and exercised, B10 identified as
  the residual closure point) and prescribes Run 009's shape.
- `docs/whitepaper/contradiction.md` C4 — current canonical record of
  the binary-bring-up contradiction. B1/B2/B3/B5/B6/B7/B8/B9/B10 all
  recorded as landed in the body; the pre-Run-009 `Impact` paragraph
  states "what remains is the empirical proof on real `qbind-node`
  processes, which DevNet Evidence Run 009 is now positioned to
  provide." Run 009 is that empirical proof.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_007.md` — referenced for
  topology, peer syntax, and regression-guard expectations carried
  forward.
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — referenced for the
  binary-path operability / observability shape expected on startup.
- `crates/qbind-node/src/binary_consensus_loop.rs` — implementation
  of B10 (paired leader-vote cache + paired re-emit at gates 1–7,
  `outbound_vote_late_peer_reemits` counter, the
  `Arc<dyn ConsensusProgressRecorder>` adapter wiring, and the
  inbound-side `inbound_proposals_engine_accepted` /
  `inbound_votes_engine_accepted` increments).
- `crates/qbind-node/tests/b10_engine_acceptance_qc_closure_tests.rs`
  — the in-tree B10 closure / regression tests that shape Run 009.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1`, Linux 6.17.0-1010-azure x86_64 |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo branch | `copilot/execute-devnet-evidence-run-009` |
| Repo HEAD at run | `16ba05c` (head of branch as cloned, prior to this doc) |
| Build profile | `cargo build --release -p qbind-node --bin qbind-node` |
| Build duration | 6 m 18 s |
| Resulting binary | `target/release/qbind-node`, ELF 64-bit, 9 076 248 bytes, BuildID `486d379b69517f989b62917a4650e2e4dbb5bee5` |
| Binary build warning | one pre-existing `qbind-node` (lib) warning (same shape as Run 008's `unused variable: worker_id` in `verify_pool.rs`); no regression caused by this run |
| All run logs / metrics under | `/tmp/run009/` |

The binary used for **all** sub-runs in this report is the same binary
built once from the branch HEAD; no per-sub-run rebuild was done.

## 4. Topology and Node Configuration Used

Two sub-runs were executed in sequence, both against the same release
binary:

### 4.1 Sub-run A — Primary, deliberate late-peer-connect (P2P, two real binaries)

| Node | Validator | Listen | Static peer (`vid@addr`) | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|---|
| V0 | `ValidatorId(0)` | `127.0.0.1:19000` | `1@127.0.0.1:19001` | `127.0.0.1:9100` | `/tmp/run009/data-v0` | `2026-05-06T14:06:58.020Z` |
| V1 | `ValidatorId(1)` | `127.0.0.1:19001` | `0@127.0.0.1:19000` | `127.0.0.1:9101` | `/tmp/run009/data-v1` | `2026-05-06T14:07:10.024Z` |

V0 was started ≈ 12 s before V1 — the same deliberate late-peer-connect
stagger Run 008 used, chosen explicitly because B9+B10 are the bounded
closure exactly designed for that shape. V0 is the leader of view 0 in
this two-validator cluster, so V0's first leader-tick fires into an
empty peer set; V0's first 7 dial attempts to `127.0.0.1:19001` are
expected to fail with `Connection refused` (B8 bounded retry); whichever
side eventually establishes a TCP connection (here, V1, after V1 starts
and dials V0) is the side whose KEMTLS handshake completes; on V0 the
**inbound resolver** must bind that accepted session to V1's
deterministic `NodeId(92115fddcd4f93a0)` (B8 listener-side identity
closure), and on V1 the **dialer-side override path** must register
V0's deterministic `NodeId(4bd96f97b1aaec9d)` (B7).

This is the exact topology Run 008 ran, repeated under post-B10
binaries. The intent of Run 009 is to demonstrate that the same
late-peer-connect shape that ended at "proposal+vote cross but no QC
forms, no commit fires" in Run 008 now actually progresses to QC
formation and commit on both nodes.

### 4.2 Sub-run B — Single-validator LocalMesh §11 regression check

| Node | Validator | Mode | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|
| SV | `ValidatorId(0)` | `local-mesh` | `127.0.0.1:9102` | `/tmp/run009/data-sv` | `2026-05-06T14:10:29.766Z` |

This run does not use P2P, does not have static peers, and does not
exercise B6/B7/B8/B9/B10. Per `binary_consensus_loop.rs` and the B9/B10
regression-guard tests E (`io = None` LocalMesh) and F (`peer_connectivity
= None`), the LocalMesh path keeps `late_peer_reemit=off`, the
`outbound_proposal_late_peer_reemits` counter at `0`, and is bit-equivalent
to pre-B9/pre-B10. Sub-run B confirms this empirically on the
production binary.

### 4.3 No "comparison" sub-run with friendlier stagger

Run 008 attempted a reverse-stagger comparison sub-run and recorded
honestly that even a 6 s reverse stagger on this host did not produce a
clean separation between "B9 path" and "original first-emission
broadcast path" (binary boot + KEMTLS handshake exceeded the 100 ms
tick interval, so B9 still fired). Run 009 therefore deliberately omits
that comparison, since it is known not to produce a clean control on
this host and would not add evidence value relative to the primary
late-peer-connect shape.

## 5. Commands and Configuration Used

Exactly as executed (each backgrounded under a launcher script,
output redirected to per-node files under `/tmp/run009/logs/`).

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
    --data-dir /tmp/run009/data-v0

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
    --data-dir /tmp/run009/data-v1
```

### 5.2 Sub-run B (single-validator regression check)

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9102 \
  ./target/release/qbind-node \
    --env devnet --network-mode local-mesh \
    --validator-id 0 \
    --data-dir /tmp/run009/data-sv
```

### 5.3 Environment variables

The only environment variable set per node beyond the inherited shell
is `QBIND_METRICS_HTTP_ADDR` (gating B2's metrics endpoint per
`MetricsHttpConfig::from_env`). No `--restore-from-snapshot`, no
genesis override, no validator-set override, no PoP / KEMTLS env
overrides; the binary uses its built-in `SimpleValidatorNodeMapping`
and `derive_test_kem_keypair_from_validator_id` defaults introduced by
B7. Both P2P nodes were started with `--env devnet`, which prints the
standard B7-onwards "P2P enabled in DevNet environment. DevNet v0
freeze recommends LocalMesh." advisory to stderr — this is expected and
honest (it does not silently fall back to LocalMesh; it proceeds with
P2P as configured). The `[restore] no --restore-from-snapshot
requested; normal startup.` line confirms B3 was honestly not
exercised.

### 5.4 Peer syntax

All P2P peers use the post-B7 `vid@addr` syntax. Both V0 and V1 in
sub-run A exclusively use `vid@addr`; both nodes' stdout logs the
post-B7 line `peer_kem_overrides=1`, which is the count of `vid@`-form
overrides that were successfully parsed and registered.

## 6. Startup, Handshake, and Connectivity Evidence

### 6.1 Sub-run A (primary)

V0 stdout (`/tmp/run009/logs/node0.stdout`) — relevant lines verbatim:

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
[P2P] Accepted connection from 127.0.0.1:60126
[P2P] Accepted connection from 127.0.0.1:60132
[P2P] Inbound connection from 127.0.0.1:60132 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
```

V0 stderr (`/tmp/run009/logs/node0.stderr`) — relevant excerpts:

```
[binary] P2P transport up. Listen address: 127.0.0.1:19000, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
[P2P] dial 127.0.0.1:19001 giving up after 8 attempt(s): I/O error: Connection refused (os error 111) (transient=true, max_attempts=8)
[P2P] Inbound connection error: Handshake error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

V1 stdout (`/tmp/run009/logs/node1.stdout`):

```
qbind-node[validator=V1]: starting in environment=DevNet … listen=127.0.0.1:19001 peers=1 …
[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1
[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
```

V1 stderr (`/tmp/run009/logs/node1.stderr`) — relevant excerpts:

```
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

What this proves:

- **Handshake succeeds.** Both sides report `Peer NodeId(...) connected`
  (V0 sees V1's deterministic `NodeId(92115fddcd4f93a0)`; V1 sees V0's
  deterministic `NodeId(4bd96f97b1aaec9d)`). Same byte-identical NodeIds
  as in Runs 007 / 008 — i.e. the same `derive_test_node_id_from_validator_id`
  derivation B7 introduced.
- **B7 dialer-side override is active on V1**: the
  `using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`
  line is the post-B7 dialer-side identity-closure trace.
- **B8 listener-side resolver is active on V0**: the
  `Inbound connection from 127.0.0.1:60132 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)`
  line is the post-B8 listener-side identity-closure trace.
- **B8 bounded initial-dial retry is exercised on V0**: 7 retries with
  the documented {100, 200, 400, 800, 1000, 1000, 1000} ms backoff,
  then `giving up after 8 attempt(s) … transient=true, max_attempts=8`
  — identical shape to Run 008.
- **`peers=1`, `num_validators=2`, `peer_kem_overrides=1`** consistent
  with B7 `vid@addr` parsing on both sides.
- **`late_peer_reemit=on`** appears in both nodes' "Starting consensus
  loop:" lines. This is the binary's explicit declaration that the
  B9/B10 paired-reemit path is wired (`peer_connectivity` is `Some` on
  both nodes, because `run_p2p_node` always wires the
  `Arc<dyn P2pService>` adapter when `--enable-p2p`). The same single
  `late_peer_reemit=on` flag now controls both the proposal cache (B9)
  and the paired vote cache (B10), per `binary_consensus_loop.rs`.
- **The `Inbound connection error: Handshake error: … UnexpectedEof`
  line on V0** corresponds to V0's first inbound connection
  (`127.0.0.1:60126`), exactly the same shape recorded on Runs
  006 / 007 / 008 stderr; V0's *second* inbound (`127.0.0.1:60132`)
  succeeds via the resolver and binds to V1's deterministic NodeId.
  This is honest noise, not silent failure, and not a B7/B8/B9/B10
  regression.

### 6.2 Sub-run B (single-validator)

```
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms restore_baseline=false interconnect=none late_peer_reemit=off
```

`interconnect=none` and `late_peer_reemit=off` — bit-equivalent to
pre-B9/pre-B10.

## 7. Late-Peer-Connect Re-Emission Evidence

This section answers task brief required questions D and (paired) the
new B10 question on leader-vote re-emission.

### 7.1 Sub-run A — B9 + B10 paired re-emission was actually exercised

The post-B10 re-emit path was exercised on the binary path in sub-run
A. The ground-truth evidence is two concurring artifacts:

1. **V0 stderr** contains exactly one B9+B10 trace, with the new
   B10-aware format that explicitly records both reemit totals:

   ```
   [binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
   ```

   - The `view 0` field matches the cached-view gate (gate 3).
   - `newly_connected_peers=1` matches V1's connection-set transition
     `{} → {NodeId(92115fddcd4f93a0)}`.
   - `proposal_reemits_total=1` and `vote_reemits_total=1` together
     prove B10's paired-cache assertion: the leader's view-0
     `BroadcastProposal` AND the leader's same-view `BroadcastVote` were
     both re-emitted on the same tick, under the same per-view
     single-shot latch (gate 6 extended to cover the pair).

2. **V0 loop-exit summary** (stderr, on shutdown):

   ```
   [binary-consensus] Loop exit: ticks=1636 proposals=728 commits=1454 committed_height=Some(1453) view=1456 inbound_msgs=2184 inbound_proposals=728 inbound_votes=1456 outbound_proposals=728 outbound_votes=1456 outbound_proposal_late_peer_reemits=1
   ```

   `outbound_proposal_late_peer_reemits=1` — the B9 counter — agrees
   with `proposal_reemits_total=1` in the stderr trace. The B10
   `outbound_vote_late_peer_reemits` counter is not currently surfaced
   in the `Loop exit:` summary line (the loop-exit format adopted by
   B9 was not extended when B10 added the paired-vote counter); its
   value is recorded only in the stderr trace above and in
   `BinaryConsensusLoopInboundStats::outbound_vote_late_peer_reemits`.
   That this is the only divergence between the loop-exit one-liner
   and the structured stats is recorded honestly in §13.

That a single paired re-emission was issued — not zero, not more than
one — also matches the B10-extended per-view single-shot latch
(`reemitted_for_view: Option<u64>` covering both proposal and vote)
and the no-stale-replay guarantee covered by the in-tree B10 tests A
and D.

### 7.2 Sub-run B (LocalMesh)

`peer_connectivity = None` in the LocalMesh path, no peer connects, so
neither B9 nor B10 is ever triggered. SV loop-exit:

```
[binary-consensus] Loop exit: ticks=384 proposals=384 commits=382 committed_height=Some(381) view=384 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0 outbound_proposal_late_peer_reemits=0
```

`outbound_proposal_late_peer_reemits=0`, `late_peer_reemit=off`, all
IO counters at 0. Bit-equivalent to pre-B9/pre-B10. This empirically
confirms the B10 regression-guard test E (`io = None`
single-validator path still commits) on the production binary, not
just in unit tests.

## 8. Cross-Node Proposal / Vote Evidence

This section answers task brief required questions E, F, and the
post-B10 leader-vote-delivered question.

The agreed-upon source of truth, per Run 008's §8 and carried forward
unchanged here, is the **binary consensus loop counters** captured in
each node's stderr `Loop exit:` summary, since these are populated by
the loop's own decode/encode of `ConsensusNetMsg::{Proposal, Vote}`
frames and therefore reflect message-level reality on the binary path.
The Prometheus `consensus_net_*_total` counters under-report this path
for the same reason recorded in Run 008 §10 (the `P2pConsensusNetwork`
path does not feed those increments); that under-report is recorded
again as a non-progression-blocking metric-coverage gap in §10.1 / §13.

### 8.1 Sub-run A loop-exit numbers (final, at shutdown)

| Metric (from `Loop exit:` line) | V0 | V1 |
|---|---|---|
| `ticks` | 1 636 | 1 516 |
| `proposals` (leader-step proposals emitted by local engine) | 728 | 728 |
| `outbound_proposals` (decoded `BroadcastProposal` actions encoded onto the wire) | 728 | 728 |
| `outbound_proposal_late_peer_reemits` | **1** | 0 |
| `outbound_votes` (decoded `BroadcastVote` / `SendVoteTo` actions encoded onto the wire) | 1 456 | 1 456 |
| `inbound_msgs` (decoded `ConsensusNetMsg::*` frames received on the wire) | 2 184 | 2 183 |
| `inbound_proposals` (decoded `ConsensusNetMsg::Proposal` frames fed into engine) | 728 | 728 |
| `inbound_votes` (decoded `ConsensusNetMsg::Vote` frames fed into engine) | 1 456 | 1 455 |
| `commits` | **1 454** | **1 453** |
| `committed_height` | **Some(1 453)** | **Some(1 452)** |
| `view` (engine current_view at shutdown) | 1 456 | 1 455 |

### 8.2 Sub-run A `/metrics` engine counters across three scrapes

Three scrapes were taken at `2026-05-06T14:07:47.474Z` (A),
`2026-05-06T14:08:28.289Z` (B), and `2026-05-06T14:09:00.746Z` (C),
files `/tmp/run009/node{0,1}.metrics_{a,b,c}`.

| Metric | V0 (A) | V0 (B) | V0 (C) | V1 (A) | V1 (B) | V1 (C) |
|---|---|---|---|---|---|---|
| `qbind_consensus_proposals_total{result="accepted"}` | 359 | 751 | 1 063 | 359 | 751 | 1 064 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 | 0 | 0 |
| `qbind_consensus_votes_total{result="accepted"}` | 358 | 750 | 1 062 | 359 | 751 | 1 063 |
| `qbind_consensus_votes_total{result="invalid"}` | 0 | 0 | 0 | 0 | 0 | 0 |
| `qbind_consensus_qcs_formed_total` | **358** | **750** | **1 062** | **359** | **751** | **1 063** |
| `qbind_consensus_view_changes_total` | 716 | 1 500 | 2 124 | 718 | 1 502 | 2 126 |
| `qbind_consensus_leader_changes_total` | n/a (A) | 750 | 1 062 | n/a (A) | 751 | 1 063 |
| `qbind_consensus_view_number` | 358 | 750 | 1 062 | 359 | 751 | 1 063 |

What this proves, line by line:

- **Cross-node proposal traversal succeeded continuously across the
  ~2½-minute multi-validator session, not just for view 0.** Both
  nodes' loop-decoded `inbound_proposals=728` and locally-emitted
  `proposals=728` match (each tick that node was leader, it produced 1
  proposal; that proposal also returned to it as a normal cross-wire
  inbound under multi-validator round-robin). Task brief checklist
  items 5 and 6 are satisfied.
- **Cross-node vote traversal succeeded continuously.** Both nodes'
  `outbound_votes=1 456` (each tick both nodes produced a vote — the
  leader's self-vote plus the non-leader's vote on the leader's
  proposal, plus all subsequent view votes), `inbound_votes` is 1 456
  on V0 and 1 455 on V1 (V1 shut down 1 view before V0, so V1 is
  trailing by exactly one inbound vote — internally consistent with
  the `view` and `commits` deltas). Task brief checklist item 7 is
  satisfied. The "leader paired vote reaches peer" precondition is
  now positively observable: even on the **first view** specifically,
  V0's paired re-emit (the B9+B10 line) put the cached view-0
  `BroadcastVote` onto the wire, V1 received and decoded it
  (`inbound_votes=1 455` on V1; the very first of those is the
  re-emitted view-0 leader vote — without it, the Run-008 boundary
  reproduces and the rest of the run does not happen).
- **Engine acceptance counters now advance in lockstep with loop-level
  traversal counters.** V1's `qbind_consensus_proposals_total{result="accepted"}`
  reaches 1 064 at scrape C (= V0's `inbound_proposals` + 1 because V1
  is at view 1 063 and ingested one more proposal), and V0's
  `qbind_consensus_votes_total{result="accepted"}` reaches 1 062 at
  scrape C — the exact gap that Run 008 reported (loop says 1, engine
  acceptance counter says 0) is now closed at every scrape. This is
  the direct empirical observation of B10's
  `inbound_proposals_engine_accepted` /
  `inbound_votes_engine_accepted` recorder wiring on real binaries.
  Task brief checklist items 8 and 9 are satisfied.
- **QCs form on both sides, not just one.** `qcs_formed_total` is
  monotonically increasing on both V0 and V1 across all three scrapes
  and ends at 1 062 / 1 063 respectively at shutdown. This is the
  precise residual Run 008 closed at zero. Task brief checklist item
  10 is satisfied.

The 1-view trail between V0 and V1 (V0=1 456, V1=1 455 at shutdown;
V0=358, V1=359 at scrape A) is exactly the round-robin offset induced
by V0 being leader at even views and V1 at odd views in a 2-validator
cluster: at any instant one of them has just formed a QC and advanced
while the other is one tick behind. This is internally consistent and
honest.

## 9. Engine Acceptance / QC / Commit Progress Evidence

This section answers task brief required questions G, H, I, J.

| Metric | V0 (A) | V1 (A) | V0 (B) | V1 (B) | V0 (C) | V1 (C) | V0 final | V1 final |
|---|---|---|---|---|---|---|---|---|
| `qbind_consensus_qcs_formed_total` | 358 | 359 | 750 | 751 | 1 062 | 1 063 | 1 062 (last scrape) | 1 063 (last scrape) |
| `qbind_consensus_view_number` | 358 | 359 | 750 | 751 | 1 062 | 1 063 | 1 062 | 1 063 |
| `qbind_consensus_proposals_total{result="accepted"}` | 359 | 359 | 751 | 751 | 1 063 | 1 064 | (last scrape) | (last scrape) |
| `qbind_consensus_votes_total{result="accepted"}` | 358 | 359 | 750 | 751 | 1 062 | 1 063 | (last scrape) | (last scrape) |
| Loop-exit `commits` | n/a | n/a | n/a | n/a | n/a | n/a | **1 454** | **1 453** |
| Loop-exit `committed_height` | n/a | n/a | n/a | n/a | n/a | n/a | **Some(1 453)** | **Some(1 452)** |

**QCs are formed on both real binaries** — not just one of them — and
their counters advance monotonically across all three scrapes, on the
same multi-second wall-clock cadence as the engine `view_number`. **No
QC counter ever decreased**, **no rejected/invalid bucket ever fired**,
and there was no scrape where `qcs_formed_total` regressed below a
prior scrape — that is the direct empirical bound on
"`/metrics` honest" and on "no fabricated progress".

**Commit / `committed_height` progression occurs on both nodes.** V0
commits 1 454 blocks and ends at `committed_height = Some(1 453)`; V1
commits 1 453 blocks and ends at `committed_height = Some(1 452)`. The
HotStuff 3-chain commit rule expects `commits ≈ qcs_formed_total - 2`
in steady state; observed values are consistent with that rule
(1 062 − 2 = 1 060, 1 063 − 2 = 1 061; Loop-exit `commits` reflects the
cumulative count at shutdown including final-tick commits, which is
why it is somewhat above the last-scrape `qcs_formed_total - 2` — the
`Loop exit:` line is sampled after `qcs_formed_total` at shutdown was
already past 1 062/1 063). Task brief checklist items 7, 8, 10, 11 are
all satisfied. Run 008's residual at the engine accept / QC formation
layer **is empirically closed on real binaries by Run 009.**

## 10. Metrics Evidence

`/metrics` evidence is captured at the timestamps in the table below
(UTC, recorded into `/tmp/run009/scrape_*.ts`).

| Sub-run | Scrape | Wall time (UTC) | Files |
|---|---|---|---|
| A | A | `2026-05-06T14:07:47.474Z` | `node0.metrics_a`, `node1.metrics_a` |
| A | B | `2026-05-06T14:08:28.289Z` | `node0.metrics_b`, `node1.metrics_b` |
| A | C | `2026-05-06T14:09:00.746Z` | `node0.metrics_c`, `node1.metrics_c` |
| B (SV) | (single) | `2026-05-06T14:10:54.771Z` | `sv.metrics_a` |

Across the three sub-run-A scrapes the consensus counter values on
both V0 and V1 are **monotonically increasing** with no fluctuation
downward and no sudden spikes inconsistent with the elapsed wall-clock
time (≈ 41 s elapsed between scrapes A and B, ≈ 32 s between B and C;
qcs_formed_total deltas of ~392 and ~312 over those intervals are
consistent with a 100 ms tick × 2-validator round-robin). This
satisfies task brief required question K ("Did `/metrics` remain
honest?"): **yes.**

### 10.1 Honest under-reporting on the P2pConsensusNetwork path (carried forward from Run 008)

The Run-008 metric-coverage gap is **still present** in Run 009.
Across all three sub-run-A scrapes both nodes report:

```
consensus_net_inbound_total{kind="proposal"} 0
consensus_net_inbound_total{kind="vote"}     0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
consensus_net_outbound_total{kind="vote_broadcast"}     0
consensus_net_outbound_total{kind="vote_send_to"}       0
```

But the Loop exit summaries on the same nodes show
`outbound_proposals=728`, `inbound_proposals=728`, `outbound_votes=1 456`,
`inbound_votes=1 456 / 1 455`. The `inc_outbound_proposal_broadcast` /
`inc_inbound_proposal` increments live on the
`consensus_net_worker.rs` path; the `P2pConsensusNetwork` path used by
the binary's `BinaryConsensusLoopIo::outbound` does not appear to feed
into those increments under the configuration the binary actually runs
in. This is a **silent under-report**, not a fake report — the metric
reads `0`, which is *less* than the truth, so nothing is being
fabricated. It is recorded again as a metric-coverage gap in §13 and
explicitly **not** counted as a regression of B2's "`/metrics` is
honest" guarantee, because the metric does not overclaim. The
`qbind_consensus_*` engine-level counters are honest (they reflect the
engine's own internal state, now correctly populated by B10's
`ConsensusProgressRecorder` adapter), and the loop-level counters are
honest (they reflect what the loop did encode/decode); the two also
agree with each other and with the shutdown summary. This satisfies
"metrics and loop-exit summaries agree" in task brief §7 for everything
the engine and loop publish.

The Run-008 ⚠️ `Remaining` bullet on this gap therefore continues to
apply unchanged; Run 009 does not propose a substantive narrowing of
that bullet because no metric-wiring fix landed for it, and Run 009 is
explicitly an evidence run, not a code-change run.

## 11. Shutdown Evidence

### 11.1 Sub-run A

Shutdown initiated at `2026-05-06T14:09:41.597Z` via SIGINT to V0 and
V1. Stderr tails:

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1636 ticks.   # V0
[binary-consensus] Loop exit: ticks=1636 …                      # V0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

V1 is symmetric (`Shutdown signal received after 1516 ticks.`,
`Loop exit: ticks=1516 …`). 8 s after SIGINT, both processes have
terminated (`pgrep -af qbind-node` returns nothing).
`shutdown_done.ts = 2026-05-06T14:09:49.601Z`. Post-shutdown port
probes:

```
127.0.0.1:9100  -> 000   # V0 metrics
127.0.0.1:9101  -> 000   # V1 metrics
127.0.0.1:19000 -> 000   # V0 P2P listen
127.0.0.1:19001 -> 000   # V1 P2P listen
```

All ports release cleanly (HTTP 000 = connection refused / no
listener) — same shape as Runs 006 / 007 / 008.

### 11.2 Sub-run B (single-validator)

```
V0 (sv) loop exit: ticks=384 proposals=384 commits=382 committed_height=Some(381) view=384 …
[binary] LocalMesh node stopped.
```

Post-shutdown port `:9102` returns `000`.

This satisfies task brief required question L: **shutdown remained
clean across both sub-runs**, identical to the Run-006 / 007 / 008
shutdown shape.

## 12. Regression Check Against Previously Landed Binary-Path Capabilities

Item-by-item against the regression-guard list in task brief §6.

| Capability | Evidence in this run | Verdict |
|---|---|---|
| **B1** (`BasicHotStuffEngine` driver wired into the binary path) | Sub-run B (LocalMesh): `proposals=384`, `commits=382`, `committed_height=Some(381)`, `view=384` after ≈ 25 s on real binary; engine drives normally. Also visible on the multi-validator path: V0 `proposals=728`, V1 `proposals=728`, with continuous commit progression on both. | Not regressed. |
| **B2** (`/metrics` gated on `QBIND_METRICS_HTTP_ADDR`) | All sub-runs scraped `/metrics` successfully on `:9100/:9101/:9102`. Endpoint emits the standard counter set. Three scrapes in sub-run A move monotonically upward with elapsed-time-consistent deltas; no fabrication. | Not regressed. |
| **B3** (`--restore-from-snapshot`) | Not exercised (no `--restore-from-snapshot` argument). Stderr says `[restore] no --restore-from-snapshot requested; normal startup.` Out of scope for this run; no negative observation. | Not regressed (not exercised). |
| **B5** (restore-aware consensus start) | `restore_baseline=false` in every sub-run's "Consensus loop config" line. | Not regressed (not exercised). |
| **B6** (multi-validator P2P binary-path interconnect: inbound→engine routing, engine actions through `P2pConsensusNetwork`) | Sub-run A: `[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event …` line emitted on both V0 and V1. Loop-exit `inbound_msgs=2 184 / 2 183`, `inbound_proposals=728` and `inbound_votes=1 456 / 1 455` — the same demuxer path Run 008 first lit, now sustained across 1 500+ views. | Not regressed; actively driving the run. |
| **B7** (binary-path test-grade KEMTLS bring-up + dialer-side identity closure) | V1 stdout `Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`, `peer_kem_overrides=1`, `vid@addr` peer syntax accepted on both sides. | Not regressed. |
| **B8** (listener-side identity closure + bounded initial-dial retry) | V0 stdout `Inbound connection from 127.0.0.1:60132 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)`. V0 stderr B8 retry trace through 7 attempts then `giving up after 8 attempt(s) … transient=true, max_attempts=8`. | Not regressed. |
| **B9** (leader-side proposal re-emission on late peer connect within the same view) | V0 stderr `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)`. Counter `outbound_proposal_late_peer_reemits=1` in V0's loop-exit, `0` on V1 and on sub-run B. The single-shot per-view latch held — no second re-emission across 1 500+ subsequent views. | Actively exercised; behaves within the seven-gate envelope. |
| **B10** (paired leader-vote re-emission on the same B9 trigger + engine-progress recorder wiring + inbound engine-accept metric closure) | The same B9+B10 stderr line above proves the paired-vote re-emit fired exactly once. The `qbind_consensus_qcs_formed_total` metric advances from 0 to 1 062 / 1 063 across the run (this counter was empirically stuck at 0 in Run 008 because no progress recorder was wired); `qbind_consensus_proposals_total{result="accepted"}` and `qbind_consensus_votes_total{result="accepted"}` both advance to ~1 062 (these counters were also stuck at 0 in Run 008). All three of B10's additive changes are observably driving the run on real binaries. | Actively exercised; closes the Run-008 residual on real binaries. |
| **`/metrics` honest** | See §10. Three monotonic scrapes with elapsed-time-consistent deltas; no fabrication. The `consensus_net_*_total` family continues to under-report (does not over-report) on the `P2pConsensusNetwork` path — same shape as Run 008 §10.1, recorded as a known coverage gap in §13. | Not regressed. |
| **No fallback to LocalMesh / single-validator semantics** | Both sub-run-A nodes print `network=p2p p2p=enabled`, `interconnect=p2p`, `num_validators=2`. No `Single-validator LocalMesh` line on any P2P node. The only node with a LocalMesh banner is sub-run B, which is the explicit single-validator regression-guard check. | Not regressed. |
| **`vid@addr` peer-syntax enforcement** | Both peers in sub-run A use `vid@addr`. `peer_kem_overrides=1` confirms the `vid@` parse path produced a registered override. Bare-addr negative assertion not run on this exercise (same as Run 008). | Not regressed (not negatively asserted). |

Conclusion: **no previously landed binary-path capability appears
regressed.** Run 009 is the first run in the sequence in which every
binary-path capability from B1 through B10 is *simultaneously*
observably driving consensus progression on real `qbind-node`
binaries.

## 13. Limitations and Anomalies Observed

1. **`consensus_net_*_total` Prometheus counters still under-report
   the actually-traversed binary-path traffic.** Same shape as Run 008
   §10.1 / §13 item 2: loop counters say 728 proposals × 2 directions
   and 1 456 votes × 2 directions crossed the wire; the
   `consensus_net_*_total` family stays at `0` for both kinds at all
   three scrapes. This is honest in the sense that it under-reports
   rather than fabricates, but it is now a known divergence between
   the binary's loop-level evidence and its Prometheus surface.
   Recorded for follow-up but **not** treated as a B2 regression
   because the metric does not overclaim.

2. **B10 paired-vote re-emit counter is not surfaced in the loop-exit
   one-liner.** B9 added `outbound_proposal_late_peer_reemits=…` to the
   `Loop exit:` summary string in `binary_consensus_loop.rs`. B10
   added the field
   `BinaryConsensusLoopInboundStats::outbound_vote_late_peer_reemits`
   but did **not** extend the `Loop exit:` `eprintln!` format to
   include it. It is observable only via the dedicated
   `[binary-consensus] B9+B10: …` stderr trace and via the structured
   `BinaryConsensusLoopInboundStats` returned by
   `run_binary_consensus_loop_with_io`. Honestly recorded; this is a
   logging-format gap, not a counter-correctness gap (the value `1`
   *is* recorded in the dedicated stderr line and in the structured
   return).

3. **First inbound on the listener side fails handshake on V0**
   (`Handshake error: channel error: Io(... UnexpectedEof ...)`); the
   **second** inbound succeeds and binds via the resolver. Same shape
   as Runs 006 / 007 / 008 — pre-existing observation, not a new
   anomaly.

4. **DevNet+P2P warning on stderr.** Both P2P sub-runs print the
   standard `[T175] Warning: P2P enabled in DevNet environment.
   DevNet v0 freeze recommends LocalMesh.` advisory; the binary still
   proceeds with P2P. Recorded as expected, not as silent fallback.

5. **One harmless pre-existing warning** during release build of
   `qbind-node` (lib). Not a regression caused by this run; not a
   runtime issue.

6. **Reverse-stagger / "friendlier startup" comparison sub-run not
   attempted.** Run 008 §7.2 honestly recorded that on this host the
   reverse stagger did not produce a clean separation between the B9
   path and the original first-emission broadcast path; Run 009 does
   not attempt a comparison sub-run that is known not to be cleanly
   informative on this host.

## 14. Contradiction File Metadata Note

This section answers task brief required question N and §8.

The header of `docs/whitepaper/contradiction.md` currently reads:

```
# QBIND Whitepaper Contradictions and Undocumented Behaviors

**Version**: 1.3
**Date**: 2026-05-03
**Status**: Active Tracking Document
```

The `## Update History` table at the bottom of the same document
contains rows for `2026-05-03` (EXE-1, B3) and `2026-05-04` (B6, B7,
B8) — but **no Update History row exists for B9, B10, Run 007, Run
008, or (prior to this run) Run 009**, despite the C4 body text
containing extensive substantive narrowings recorded by all of those.
The header `Version: 1.3` and `Date: 2026-05-03` are therefore stale
relative to the actual content of the document.

**The header metadata mismatch persists in this run.** It is recorded
here explicitly as a documentation-hygiene note, per task brief §8:

- Header `Version: 1.3` has not been bumped through any of B6/B7/B8/B9/B10
  or Runs 005/006/007/008/009 even though all of those have left
  substantive narrowings or appended `Remaining` / `Impact` material in
  C4's body.
- Header `Date: 2026-05-03` predates the latest Update-History row
  (`2026-05-04` for B8) and predates every B9 / B10 / Run-005..009
  body update.
- The `## Update History` table itself has no rows for any update
  after 2026-05-04 (B8) and no rows for B9, B10, Run 007, Run 008, or
  Run 009 — even though Run 009 (this delta) does append a small
  conservative C4 `Impact` narrowing.

This run does **not** silently bump `Version` or `Date`, exactly to
keep the documentation-hygiene mismatch surfaced rather than absorbing
it into an evidence-run delta. The hygiene fix — bump header
`Version`/`Date`, add Update-History rows for B9, B10, Run 007, Run
008, Run 009 — is recommended as a separate documentation-only delta;
it is intentionally **not** combined with this evidence run, which is
scoped to a small, conservative C4 `Impact` narrowing only (see §15).

## 15. Assessment of Evidence Value

Run 009 is the **first DevNet evidence run that demonstrates honest,
sustained cross-node QC formation and `committed_height` progression
between two real `qbind-node` binaries**. Specifically:

- For the first time, **`qbind_consensus_qcs_formed_total` is
  observably > 0 on both real binaries**, advancing monotonically
  across three scrapes to 1 062 / 1 063 — directly closing the
  Run-008 residual at the engine accept / QC-formation layer.
- For the first time, **`committed_height > None` on both real
  binaries**: V0 reaches `Some(1 453)` and V1 reaches `Some(1 452)` at
  shutdown, both strictly above the snapshot height of `None` and
  consistent with the HotStuff 3-chain commit rule applied to the
  observed QC counts.
- For the first time, the **B9+B10 paired late-peer re-emit** is
  empirically observable on real binaries (the new
  `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after
  late peer connect (newly_connected_peers=1, proposal_reemits_total=1,
  vote_reemits_total=1)` stderr line, with `outbound_proposal_late_peer_reemits=1`
  on V0 only and `=0` on V1 and on the LocalMesh single-validator
  regression check). The seven-gate envelope (now extended to cover
  the paired vote) holds: exactly one paired re-emit per view, never
  one without the other across 1 500+ subsequent views.
- B10's three additive changes — paired vote cache, `ConsensusProgressRecorder`
  adapter wiring, and inbound `proposals_engine_accepted` /
  `votes_engine_accepted` increments — are **all observably driving
  the run**: the metric counters that were empirically stuck at 0 in
  Run 008 (`qbind_consensus_qcs_formed_total`,
  `qbind_consensus_proposals_total{result="accepted"}`,
  `qbind_consensus_votes_total{result="accepted"}`) are now non-zero
  and monotonic.

This **materially narrows C4** below where Run 008 left it. Run 008's
residual was "engine-side acceptance / QC-formation closure on the
binary path under post-B9 re-emitted leader proposal (B9-residual)";
Run 009 closes that residual on real binaries. The new boundary is
**strictly smaller** than Run 008's: the engine accept / QC-formation
layer is closed, and what remains in C4 is at the level of (a)
production identity hardening (mutual-auth `MutualAuthMode::Required`,
real PQC certs), (b) multi-validator restore catchup (P2P chain
catchup above the snapshot prefix), and (c) the `consensus_net_*_total`
Prometheus coverage gap that does not block consensus progression.
None of those are surfaced or claimed by Run 009 as newly closed; all
are kept honestly open in C4's `Remaining`.

What Run 009 does **not** prove (per task brief §1-C "exactness"):

- It does **not** prove production identity hardening, mutual-auth, or
  `MutualAuthMode::Required`.
- It does **not** prove multi-validator restore catchup.
- It does **not** prove the `consensus_net_*_total` Prometheus family
  fully covers the `P2pConsensusNetwork` path; that under-report
  persists honestly.
- It does **not** prove the original (non-B9/B10) first-emission
  broadcast path on the binary, because the run intentionally
  exercises the late-peer-connect shape (and Run 008 already recorded
  that the reverse-stagger comparison does not cleanly separate the
  two paths on this host).
- It does **not** prove behavior under > 2 validators or under
  Byzantine peers; the bring-up sequence is still focused on the
  honest-2-validator binary path.

The verdict is therefore: **POSITIVE — strongest result available at
this stage of the bring-up.** All twelve checklist items in §1 are
satisfied on the binary path, with the single carried-forward honest
under-report on `consensus_net_*_total` explicitly identified.

A small, conservative C4 narrowing is applied as part of this run
(`docs/whitepaper/contradiction.md` C4 `Impact` paragraph appended
with one Run-009 sentence and one new `Update History` row dated
`2026-05-06`). The C4 `Remaining` bullet for "engine accept /
QC-formation closure on the binary path under post-B9 re-emitted
leader proposal (B9-residual)" is updated from "intentionally below
B6/B7/B8/B9 in scope and does not redesign consensus, transport, or
identity" to record that this residual is now empirically closed by
Run 009; the other open `Remaining` bullets are unchanged. No new
contradiction is introduced. Per §14, the header `Version` / `Date`
metadata mismatch is **not** silently corrected; that hygiene fix is
deferred to a dedicated documentation delta.

## 16. Recommended Immediate Next Action

Now that the binary-path multi-validator consensus progression loop is
empirically observable end-to-end (handshake → identity closure →
proposal → paired vote re-emit → QC formation → commit, on two real
`qbind-node` processes, sustained across 1 500+ views), the next
recommended execution action is **one of two equally bounded
candidates**, in priority order:

1. **B11 (preferred) — Close the `consensus_net_*_total` Prometheus
   coverage gap on the `P2pConsensusNetwork` path** (the Run-008/Run-009
   honest under-report). The smallest honest fix is to call
   `inc_outbound_proposal_broadcast` / `inc_outbound_vote_broadcast` /
   `inc_inbound_proposal` / `inc_inbound_vote` from the
   `P2pConsensusNetwork` outbound facade and from the
   `BinaryConsensusLoopIo` inbound decode path, mirroring what
   `consensus_net_worker.rs` already does on its own path. This is a
   metric-coverage fix only, not a consensus-progression change. It
   removes the only remaining surface on which the Prometheus output
   under-reports the binary's actual behavior, and it makes future
   evidence runs scrape-only (no need to read loop-exit summaries to
   cross-check). A new `crates/qbind-node/tests/b11_*` regression file
   would assert that the four `consensus_net_*_total` counters move in
   lockstep with the loop-level counters in a multi-validator
   integration test. This is the smallest, lowest-risk continuation
   of the B6→B7→B8→B9→B10 discipline.

2. **Documentation hygiene delta** (independent, can be done in
   parallel) — a separate documentation-only PR that bumps the
   `docs/whitepaper/contradiction.md` header `Version` and `Date`,
   adds Update-History rows for B9, B10, Run 007, Run 008, and Run
   009, and audits the body for any places where stale "next run is
   Run 008" / "next run is Run 009" forward references remain. This
   is intentionally **not** combined with B11 to keep the hygiene fix
   surfaced and reviewable in isolation, and to avoid silently
   absorbing a header bump into a code-change delta. Per §14, this is
   the explicit follow-up to the contradiction-file header metadata
   mismatch noted again in this run.

Concretely **not** recommended as the immediate next action:

- Production PQC KEMTLS / `MutualAuthMode::Required` hardening —
  remains in C4 `Remaining`; significantly larger scope than the
  current bring-up cadence and not unblocked by Run 009.
- Multi-validator restore catchup (P2P chain catchup above snapshot
  prefix) — also remains in C4 `Remaining`; not unblocked by Run 009.
- Three-validator or larger-cluster evidence runs — not needed before
  closing the metric-coverage gap (B11) and the documentation hygiene
  mismatch; would otherwise reproduce the same metric-coverage
  divergence at larger scale.