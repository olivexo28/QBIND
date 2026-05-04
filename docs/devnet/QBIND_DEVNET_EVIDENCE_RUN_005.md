# QBIND DevNet Evidence Run 005

**Status:** Internal evidence record — first **multi-validator
binary-path** DevNet run. Targets the residual C4 sub-item that
B6 was supposed to unblock: cross-node proposal/vote/QC/commit
progression on real `qbind-node` processes connected via the real
P2P path.
**Audience:** Internal — protocol engineering, ops, release
management.
**Run date:** 2026-05-04 (UTC).
**Author:** Execution follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_004.md` §13 ("Wire inbound
P2P consensus events from the binary path into the engine's
`on_proposal_event` / `on_vote_event`"), now that B6 has landed in
`crates/qbind-node/src/p2p_node_builder.rs`,
`crates/qbind-node/src/binary_consensus_loop.rs`, and
`crates/qbind-node/src/main.rs::run_p2p_node`.

> This document is a focused fifth evidence artifact. It is **not**
> a Beta-readiness statement, **not** a soak result, **not** a full
> backup-and-recovery program completion, **not** a claim of
> production-grade validator/node-id identity, and **not** a claim
> that QBIND has a working multi-validator DevNet on the binary
> path. It exists to record, exactly, what happened when two real
> `qbind-node` binaries were started and wired to each other via
> `--enable-p2p` / `--p2p-peer ...`, and what this empirically tells
> us about the residual C4 sub-item B6 was supposed to close.

---

## 1. Purpose and Scope

Runs 001–004 exercised the **single-validator** binary path
(LocalMesh, B1/B2/B3/B5). Run 005 is the first run that attempts
to drive two real `qbind-node` *processes* against each other via
the real P2P path.

Run 005's purpose, and only purpose, is to capture concrete
end-to-end binary-path evidence of whether the **first multi-validator
binary-path DevNet evidence exercise** can produce honest
cross-node proposal / vote / QC / commit progression.

In scope (this run):

- A. Bring up two real `qbind-node` binaries on a single host with
  real `--network-mode p2p --enable-p2p` startup, distinct
  `--data-dir`s, distinct `--validator-id`s, distinct
  `--p2p-listen-addr`s, and `--p2p-peer` cross-references.
- B. Observe each node's startup banner, B6 multi-validator banner,
  consensus loop start, P2P listener bind, dial attempt against
  the peer, and any inbound connection events.
- C. Observe whether `ConsensusNetMsg::{Proposal, Vote}` traffic
  actually crosses node boundaries via the binary `inbound_msgs` /
  `inbound_proposals` / `inbound_votes` counters surfaced in the
  loop-exit summary (`binary_consensus_loop.rs:347–352`).
- D. Observe whether `BasicHotStuffEngine` view / committed-height
  state advances on either node beyond its post-startup baseline
  (genesis here, since no `--restore-from-snapshot` was used).
- E. Observe `/metrics` on both nodes during the run.
- F. Observe orderly SIGINT shutdown on both nodes.
- G. Record exactly what is and is not proven by this run.

Explicitly out of scope (this run):

- Restore-aware multi-validator behavior (Runs 003/004 are the
  restore-side artifacts; Run 005 is the connectivity-side
  artifact and intentionally uses no `--restore-from-snapshot`).
- 3-node clusters (a 2-node cluster is sufficient to disambiguate
  the load-bearing question — "do messages cross node boundaries
  on the binary path?" — and the failure mode below makes a 3rd
  node uninformative).
- Soak / long-duration stability.
- Alpha/Beta readiness.
- Production-grade validator/node-id / PQC KEMTLS identity
  hardening (the binary uses
  `make_test_crypto_provider` + `SimpleValidatorNodeMapping` —
  intentionally a test-grade path; Run 005 records what that path
  empirically does, not a claim that it is production-suitable).
- Inbound `ConsensusNetMsg::Timeout` / `NewView` routing
  (intentionally deferred per `contradiction.md` C4 `Remaining`).
- `--restore-from-snapshot` interaction with multi-validator catchup
  (still tracked separately under C4).

---

## 2. Canonical Basis

This run is grounded in, and bounded by:

- `docs/whitepaper/contradiction.md` C4 — the residual sub-item
  ("multi-validator P2P binary-path interconnect") that B6 closes
  at the *wiring* level and Run 005 is the first to exercise on
  the binary.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_001.md` — established the
  binary-path startup/consensus/metrics/shutdown shape Run 005
  reuses.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_002.md` — established that
  `/metrics` carries live consensus progress on the binary path
  (Run 005 reuses unchanged).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_003.md` /
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_004.md` — the restore-side
  binary-path artifacts. Run 005 deliberately does not interact
  with these (no `--restore-from-snapshot`).
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` (EXE-2) — §6.1, §7,
  §10 (next-action ordering).
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` §4 (signal
  classes), referenced for `/metrics` sanity.
- `crates/qbind-node/src/main.rs` (`run_p2p_node`,
  `crates/qbind-node/src/main.rs:317–415`) — the actual binary
  surface under test in P2P mode.
- `crates/qbind-node/src/binary_consensus_loop.rs`
  (`BinaryConsensusLoopIo`, `run_binary_consensus_loop_with_io`,
  `Loop exit` summary) — the surface that records
  `inbound_msgs` / `inbound_proposals` / `inbound_votes` /
  `outbound_proposals` / `outbound_votes`.
- `crates/qbind-node/src/p2p_node_builder.rs`
  (`P2pNodeBuilder::build`, `create_connection_configs`,
  `make_test_crypto_provider`) — the P2P transport bring-up path
  Run 005 exercises.
- `crates/qbind-node/src/consensus_net_p2p.rs`
  (`SimpleValidatorNodeMapping`, `P2pConsensusNetwork`) — the
  outbound facade Run 005 uses.
- `crates/qbind-node/tests/c4_b6_p2p_binary_path_interconnect_tests.rs`
  — in-tree integration tests that prove the binary-path *wiring*
  works when fed via in-process `mpsc` channels. Run 005
  complements (and contrasts with) those tests by going through
  the real TCP+KEMTLS transport in two real processes.

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch
  `copilot/execute-first-multi-validator-evidence-run`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`,
  `rustc 1.94.1 (e408947bf 2026-03-25)`.
- Build command (binary under test):
  `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome:
  `Finished `release` profile [optimized] target(s) in 6m 33s`
  (cold cache on this branch). The single pre-existing compiler
  warning carried by Runs 001–004 surfaced unchanged
  (`unused variable: worker_id` in
  `crates/qbind-node/src/verify_pool.rs:262`). Out of scope.
- Resulting binary: `target/release/qbind-node`,
  `8 952 536` bytes, executable, ELF 64-bit `x86-64`.
- Host: GitHub-hosted Linux x86_64 sandbox (single host, two
  `qbind-node` processes running concurrently).
- Network: loopback `127.0.0.1` only. No external network. No
  TLS certificate authority — the binary uses the in-tree
  `make_test_crypto_provider` + `SimpleValidatorNodeMapping`
  test-grade path (`p2p_node_builder.rs:305–316, 497–584`).

This is, deliberately, a **two-process, single-host, real-binary,
real-P2P-path, no-restore, short-bounded run** with the smallest
honest two-validator cluster possible. The smallness is intentional:
the load-bearing question is whether *any* `ConsensusNetMsg` crosses
between two real `qbind-node` processes, not whether the cluster
scales.

---

## 4. Topology and Node Configuration Used

Two-node cluster, all on `127.0.0.1`:

```
        +-----------------------+              +-----------------------+
        | qbind-node v0 (V0)    |              | qbind-node v1 (V1)    |
        |                       |              |                       |
        |  P2P  127.0.0.1:19000 |<-- dials --->| P2P  127.0.0.1:19001  |
        |  /metrics  9100       |              | /metrics  9101        |
        |  data /tmp/run005/    |              | data /tmp/run005/     |
        |       data-v0         |              |      data-v1          |
        |                       |              |                       |
        |  --p2p-peer           |              |  --p2p-peer           |
        |     127.0.0.1:19001 ──┘              └── 127.0.0.1:19000     |
        +-----------------------+              +-----------------------+
```

Node 0 (validator id `0`):
- listen: `127.0.0.1:19000`
- static peer: `127.0.0.1:19001`
- data dir: `/tmp/run005/data-v0`
- metrics: `127.0.0.1:9100`
- B6 view of cluster size (per `main.rs:332`): `static_peers.len() + 1
  = 1 + 1 = 2` validators.

Node 1 (validator id `1`):
- listen: `127.0.0.1:19001`
- static peer: `127.0.0.1:19000`
- data dir: `/tmp/run005/data-v1`
- metrics: `127.0.0.1:9101`
- B6 view of cluster size: `2` validators.

Both processes were started in detached background mode so neither
was killed when the launching shell session exited. (An earlier
attempt without detachment had both processes terminated when the
launching shell exited; that attempt is not used as evidence here
and is recorded only for completeness.)

---

## 5. Commands and Configuration Used

### 5.1 Build (binary under test)

```
cargo build --release -p qbind-node --bin qbind-node
```

### 5.2 Reset run state

```
rm -rf /tmp/run005/data-v0 /tmp/run005/data-v1
mkdir -p /tmp/run005/data-v0 /tmp/run005/data-v1 /tmp/run005/logs
```

### 5.3 Run command — node 0 (validator 0)

```
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19000 \
    --p2p-peer 127.0.0.1:19001 \
    --validator-id 0 \
    --data-dir /tmp/run005/data-v0 \
    > /tmp/run005/logs/node0.stdout \
    2> /tmp/run005/logs/node0.stderr
```

### 5.4 Run command — node 1 (validator 1)

```
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9101 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19001 \
    --p2p-peer 127.0.0.1:19000 \
    --validator-id 1 \
    --data-dir /tmp/run005/data-v1 \
    > /tmp/run005/logs/node1.stdout \
    2> /tmp/run005/logs/node1.stderr
```

### 5.5 Environment variables

| Variable                   | Value              | Set on   | Purpose |
|----------------------------|--------------------|----------|---------|
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9100`   | node 0   | enable `/metrics` on node 0 |
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9101`   | node 1   | enable `/metrics` on node 1 |

No other QBIND-prefixed env vars were set. No config file. CLI
flags above only.

### 5.6 Run wall-clock window

- Node 0 started at `06:11:47Z` (approx; first stderr line written).
- Node 1 started at `06:11:51Z` (approx; ~4 s after node 0).
- `/metrics` Scrape A: `2026-05-04T06:12:05.869525239Z`.
- `/metrics` Scrape B: `2026-05-04T06:12:36.610731078Z` (~31 s
  after Scrape A).
- SIGINT delivered to both PIDs at: `2026-05-04T06:13:35.558807511Z`.
- Total node-0 lifetime per its own loop summary: `1075 ticks`
  at `tick=100ms` ≈ `107.5 s`.
- Total node-1 lifetime per its own loop summary: `1036 ticks`
  ≈ `103.6 s`. The ~4 s lifetime delta matches the ~4 s startup
  stagger (node 1 was started after node 0).

---

## 6. Startup and Connectivity Evidence

### 6.1 Node 0 — full `stderr` (exact, unedited, in observed order)

```
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[restore] no --restore-from-snapshot requested; normal startup.
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9100 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9100 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=nonce-only
[metrics_http] Listening on 127.0.0.1:9100
[P2P] Failed to dial 127.0.0.1:19001: I/O error: Connection refused (os error 111)
[binary] P2P transport up. Listen address: 127.0.0.1:19000, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p
[P2P] Inbound connection error: Handshake error: channel error: Io(Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" })
[P2P] Read error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1075 ticks.
[binary-consensus] Loop exit: ticks=1075 proposals=1 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=1 outbound_votes=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 6.2 Node 0 — full `stdout` (exact, unedited)

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19000 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19000 (node_id=NodeId(0000000000000000))
[P2P] Dialing 127.0.0.1:19001
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(0000000000000000) num_validators=2
[P2P] Accepted connection from 127.0.0.1:52186
[P2P] Accepted connection from 127.0.0.1:52194
[P2P] Inbound connection from 127.0.0.1:52194 assigned temporary session NodeId NodeId(1a9811f18a2a5fbb)
[P2P] Peer NodeId(1a9811f18a2a5fbb) connected
[T175] Shutting down P2P node for validator ValidatorId(0)
[T175] P2P node shutdown complete
```

### 6.3 Node 1 — full `stderr` (exact, unedited, in observed order)

```
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[restore] no --restore-from-snapshot requested; normal startup.
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9101 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9101 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=nonce-only
[metrics_http] Listening on 127.0.0.1:9101
[P2P] Failed to dial 127.0.0.1:19000: Handshake error: channel error: Net(Protocol("client handle_server_accept failed"))
[binary] P2P transport up. Listen address: 127.0.0.1:19001, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1036 ticks.
[binary-consensus] Loop exit: ticks=1036 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 6.4 Node 1 — full `stdout` (exact, unedited)

```
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19001 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(0100000000000000))
[P2P] Dialing 127.0.0.1:19000
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(0100000000000000) num_validators=2
[T175] Shutting down P2P node for validator ValidatorId(1)
[T175] P2P node shutdown complete
```

### 6.5 Listening sockets (observed via `ss -ltn`)

```
LISTEN 0 4096 127.0.0.1:9101  0.0.0.0:*
LISTEN 0 4096 127.0.0.1:9100  0.0.0.0:*
LISTEN 0 4096 127.0.0.1:19001 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:19000 0.0.0.0:*
```

### 6.6 What this evidences (load-bearing)

Observed (direct):

- **Both `qbind-node` binaries started successfully and remained
  running concurrently.** Each emitted the expected B1/B2 banner
  (`P2P transport up. Listen address: …, static peers: 1`),
  and each emitted the new B6 banner
  (`Multi-validator P2P (2 validators): inbound P2P consensus
   messages are routed into BasicHotStuffEngine via
   on_proposal_event / on_vote_event; engine actions flow back out
   through P2pConsensusNetwork.`) — direct evidence that the
  binary's `run_p2p_node` (`main.rs:317–415`) entered the
  `num_validators > 1` branch and that B6 wiring is in fact present
  in the running binary, not just in tests.
- **Both nodes bound their P2P listeners and their `/metrics`
  listeners.** All four sockets (`19000`, `19001`, `9100`, `9101`)
  appear in `ss -ltn` while the cluster is live.
- **TCP connectivity at the loopback level worked.** Node 0's
  stdout shows `[P2P] Accepted connection from 127.0.0.1:52186`
  and `[P2P] Accepted connection from 127.0.0.1:52194` — i.e.
  node 1's dial reached node 0's listener.
- **Node 0 logged `[P2P] Peer connected`, but with a *temporary*
  NodeId.** The exact line is:
  `[P2P] Inbound connection from 127.0.0.1:52194 assigned temporary
   session NodeId NodeId(1a9811f18a2a5fbb)`, followed by
  `[P2P] Peer NodeId(1a9811f18a2a5fbb) connected`. **The connected
  peer's NodeId is `1a9811f18a2a5fbb`, not the deterministic NodeId
  of validator 1, which is `0100000000000000`** (per
  `SimpleValidatorNodeMapping::node_id_from_validator_index(1)` in
  `consensus_net_p2p.rs:115–121` and confirmed by node 1's own
  `[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(0100000000000000))`
  banner). I.e. node 0 sees *some* peer connected, but does **not**
  recognize that peer as ValidatorId(1).
- **Both nodes logged P2P handshake errors.**
  - Node 0: `[P2P] Inbound connection error: Handshake error:
    channel error: Io(Os { code: 11, kind: WouldBlock, ... })` and
    `[P2P] Read error: channel error: Io(Error { kind: UnexpectedEof,
    ... })`.
  - Node 1: `[P2P] Failed to dial 127.0.0.1:19000: Handshake error:
    channel error: Net(Protocol("client handle_server_accept
    failed"))`.

  Two distinct dial attempts are reflected:
  the very first dial on each side (initiated when the peer's
  listener was not yet up) returned `Connection refused (os error
  111)` on node 0 and `Net(Protocol("client handle_server_accept
  failed"))` on node 1. The latter is the load-bearing signal: it
  means node 1's *KEMTLS handshake* against node 0 failed at the
  application protocol layer, not at the TCP layer. The corresponding
  inbound-side observation on node 0 (`Inbound connection error:
  Handshake error: ... WouldBlock`) is the matching server-side
  failure of the same handshake attempt.

Inferred (with reasoning):

- The `[P2P] Peer NodeId(1a9811f18a2a5fbb) connected` line on node 0
  combined with the absence of any `inbound_proposals` /
  `inbound_votes` / `inbound_msgs` increments in the §8 loop-exit
  summary indicates that whatever connection node 0 admitted under
  that temporary NodeId did not deliver any framed `ConsensusNetMsg`
  to the consensus demuxer. This is consistent with a session that
  completed enough TCP/handshake negotiation to log a
  "peer connected" event but did not establish a fully validated,
  identity-bound, framed consensus channel.

- The KEMTLS handshake failure shape
  (`Net(Protocol("client handle_server_accept failed"))`) is
  consistent with a known structural property of the current
  test-grade transport bring-up path. The dialer's
  `ClientConnectionConfig.peer_kem_pk`
  (`p2p_node_builder.rs:575`) is set from `server_kem_pk`, which
  in `create_connection_configs` is derived deterministically
  from the **local** `validator_id`
  (`p2p_node_builder.rs:514–518`):

  ```
  let server_kem_pk: Vec<u8> = (0u8..32u8)
      .map(|i| i.wrapping_add(validator_id.as_u64() as u8))
      .collect();
  ```

  i.e. when node 0 dials node 1, node 0's `peer_kem_pk` is
  derived from `validator_id = 0` (its own), not from
  `validator_id = 1` (its peer's). The two sides therefore do
  not have a matching KEM keypair view of the remote endpoint,
  and the handshake fails as the dialer reaches the server-accept
  step. This is **inferred** from the code, not declared by the
  binary; it is recorded here as the most plausible explanation of
  the observed handshake failure shape and is consistent with all
  observed log lines.

  This is the smallest honest framing of the residual issue: the
  current `make_test_crypto_provider` + `create_connection_configs`
  path does not provide a peer-aware view of remote KEM public keys
  on the binary. It is **not** the same as "PQC identity certificate
  hardening", which is a strictly later piece of work; this is more
  basic than that — it is the test-grade transport's binary-mode
  out-of-the-box wiring.

---

## 7. Cross-Node Proposal / Vote Evidence

### 7.1 Direct counts from each node's loop-exit summary

| Counter                  | Node 0 (V0)                   | Node 1 (V1)                   |
|--------------------------|-------------------------------|-------------------------------|
| `ticks`                  | `1075`                        | `1036`                        |
| `proposals` (engine-emitted) | `1`                       | `0`                           |
| `commits`                | `0`                           | `0`                           |
| `committed_height`       | `None`                        | `None`                        |
| `view`                   | `0`                           | `0`                           |
| `inbound_msgs`           | `0`                           | `0`                           |
| `inbound_proposals`      | `0`                           | `0`                           |
| `inbound_votes`          | `0`                           | `0`                           |
| `outbound_proposals`     | `1`                           | `0`                           |
| `outbound_votes`         | `1`                           | `0`                           |

Source: the `[binary-consensus] Loop exit: …` lines in §6.1 and
§6.3, produced unedited by `binary_consensus_loop.rs:347–352`.

### 7.2 What this evidences (load-bearing)

Observed (direct):

- **No proposal crossed node boundaries on the binary path during
  this run.** Both nodes reported `inbound_proposals = 0`. Node 0
  (the leader of view 0 under round-robin / first-validator
  leader selection) did emit one proposal locally
  (`outbound_proposals = 1`), but it never reached node 1's engine
  via the inbound `ConsensusNetMsg` path
  (`inbound_proposals = 0` on node 1 confirms this).
- **No vote crossed node boundaries on the binary path during this
  run.** Both nodes reported `inbound_votes = 0`. Node 0 emitted
  one outbound vote (`outbound_votes = 1`, the engine's own vote
  on its own proposal), but no peer vote was received.
- **No `ConsensusNetMsg` of any kind crossed node boundaries on
  the binary path during this run.** `inbound_msgs = 0` on both
  nodes is the most aggressive form of this statement and comes
  directly from the loop's own counters, which are incremented in
  `binary_consensus_loop.rs` *as the message is dequeued from the
  inbound channel*, before any decode/dispatch. If even a single
  byte had reached the inbound demuxer's typed channel,
  `inbound_msgs` would be ≥ 1.
- **Neither engine advanced past view 0.** Both nodes reported
  `view = 0`, `committed_height = None`. This is consistent with
  a 2-of-2 quorum requirement that was never met because no peer
  vote ever arrived.
- **The single proposal node 0 emitted was self-counted as
  `accepted` once (per Scrape A `qbind_consensus_proposals_total
  {result="accepted"} 1`) and then never again** — the leader did
  not retry, view 0 simply never closed. This is the unmodified
  behavior of `BasicHotStuffEngine` when no `ConsensusNetMsg::Vote`
  is received and no timeout/new-view path advances the view.

Inferred (with reasoning):

- The combination "TCP connections are accepted, KEMTLS fails,
  no `ConsensusNetMsg` reaches the inbound channel" is the
  expected observable shape of a transport that never establishes
  a framed application-layer session. The B6 wiring sits *above*
  the transport: it consumes from the same channel
  `TcpKemTlsP2pService::subscribe()` produces. If the transport
  produces nothing, the B6 path correctly stays dark — which it
  does (`inbound_msgs = 0`, no panic, no busy-loop). I.e. **B6
  wiring is in the binary and is honest about doing nothing when
  the transport delivers nothing.** The failure here is below B6,
  in the transport bring-up path.

- The B6 in-tree integration tests
  (`crates/qbind-node/tests/c4_b6_p2p_binary_path_interconnect_tests.rs`)
  bypass the transport entirely (they feed
  `ConsensusNetMsg` directly into the loop's inbound `mpsc`).
  Those tests therefore correctly proved that B6 *wiring* is
  correct, but did not — and were not designed to — exercise the
  real binary-to-binary KEMTLS bring-up. Run 005 is the first
  artifact that exercises that path, and it is the first artifact
  that records that path is currently non-functional.

### 7.3 What this run does **not** claim

- It does **not** claim that B6's *engine-routing* code is broken.
  All available evidence is consistent with B6's engine-routing
  code being correct; it simply was never exercised because no
  inbound `ConsensusNetMsg` arrived.
- It does **not** claim that the consensus engine is broken.
  `BasicHotStuffEngine` is well-tested under quorum; it correctly
  refuses to advance past view 0 in the absence of a peer vote.
- It does **not** claim production-grade PQC KEMTLS is broken.
  This run only exercised the test-grade
  `make_test_crypto_provider` / `SimpleValidatorNodeMapping` path
  that the binary defaults to today.
- It does **not** claim the TCP layer is broken. TCP-level
  connect/accept worked; the failure is at the KEMTLS/handshake
  layer.

---

## 8. QC / Commit Progress Evidence

### 8.1 Direct observations (per node)

- Node 0: `commits = 0`, `committed_height = None`, `view = 0`,
  `qbind_consensus_qcs_formed_total = 0`,
  `qbind_consensus_votes_observed_total = 0`,
  `qbind_consensus_view_changes_total = 0`.
- Node 1: identical to node 0 across every consensus-progression
  series above.

### 8.2 What this evidences

Observed (direct):

- **No QC was formed on either node during this run.**
  `qbind_consensus_qcs_formed_total = 0` in both Scrape A and
  Scrape B on both nodes (§9), and `qcs_formed = 0` is also
  consistent with the loop-exit `commits = 0`.
- **No commit fired on either node during this run.**
  `committed_height = None` on both nodes is the strongest
  available form of this statement: not "committed_height stuck
  at the seeded baseline", but `None` — the engine never reached
  even a first commit.

This is the honest negative: **on this run, on the binary path,
QC / commit progression was not no-longer-harness-only — there
was no QC / commit progression at all.** Whether the underlying
B6 routing code is capable of producing cross-node QC/commit
progression cannot be determined from this run alone, because the
prerequisite (real `ConsensusNetMsg` arriving from a peer) never
held.

The pre-existing B6 in-tree integration tests
(`c4_b6_p2p_binary_path_interconnect_tests.rs`, in particular the
"two-engine cross-wired binary-path progression" test) do exhibit
QC formation and view advancement when the inbound channel is
fed directly. That is documented in `contradiction.md` C4
already; Run 005 does **not** contradict it. Run 005 contributes
the additional, narrower observation that the in-process channel-
fed test does not generalize to two real binaries through the
real transport with the current test-crypto wiring.

---

## 9. Metrics Evidence

### 9.1 Scrape A (early in the run)

Timestamp: `2026-05-04T06:12:05.869525239Z` (approximately 14 s
after node 0 started, ~10 s after node 1 started).

Node 0 — consensus-class series (exact):

```
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_votes_observed_current_view 0
qbind_consensus_view_changes_total 0
qbind_consensus_leader_changes_total 0
qbind_consensus_qc_formation_latency_ms_count 0
qbind_consensus_qc_formation_latency_ms_sum 0
qbind_consensus_qc_formation_latency_ms_bucket{le="100"} 0
qbind_consensus_qc_formation_latency_ms_bucket{le="500"} 0
qbind_consensus_qc_formation_latency_ms_bucket{le="2000"} 0
qbind_consensus_qc_formation_latency_ms_bucket{le="+Inf"} 0
qbind_consensus_current_view 0
qbind_consensus_highest_seen_view 0
qbind_consensus_view_lag 0
qbind_consensus_proposals_total{result="accepted"} 1
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="accepted"} 0
qbind_consensus_votes_total{result="invalid"} 0
qbind_consensus_timeouts_total 0
qbind_consensus_view_number 0
```

Node 1 — consensus-class series (exact):

```
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_votes_observed_current_view 0
qbind_consensus_view_changes_total 0
qbind_consensus_leader_changes_total 0
qbind_consensus_qc_formation_latency_ms_count 0
qbind_consensus_qc_formation_latency_ms_sum 0
qbind_consensus_qc_formation_latency_ms_bucket{le="100"} 0
qbind_consensus_qc_formation_latency_ms_bucket{le="500"} 0
qbind_consensus_qc_formation_latency_ms_bucket{le="2000"} 0
qbind_consensus_qc_formation_latency_ms_bucket{le="+Inf"} 0
qbind_consensus_current_view 0
qbind_consensus_highest_seen_view 0
qbind_consensus_view_lag 0
qbind_consensus_proposals_total{result="accepted"} 0
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="accepted"} 0
qbind_consensus_votes_total{result="invalid"} 0
qbind_consensus_timeouts_total 0
qbind_consensus_view_number 0
```

### 9.2 Scrape B (~31 s later)

Timestamp: `2026-05-04T06:12:36.610731078Z`.

Node 0 — consensus-class series (excerpt; deltas are the
load-bearing read):

```
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_view_changes_total 0
qbind_consensus_current_view 0
qbind_consensus_highest_seen_view 0
qbind_consensus_proposals_total{result="accepted"} 1
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="accepted"} 0
qbind_consensus_votes_total{result="invalid"} 0
qbind_consensus_view_number 0
```

Node 1 — consensus-class series (excerpt):

```
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_view_changes_total 0
qbind_consensus_current_view 0
qbind_consensus_highest_seen_view 0
qbind_consensus_proposals_total{result="accepted"} 0
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="accepted"} 0
qbind_consensus_votes_total{result="invalid"} 0
qbind_consensus_view_number 0
```

### 9.3 What this evidences

Observed (direct):

- `/metrics` was reachable on both nodes during the live run, on
  both ports (`9100`, `9101`). Both endpoints returned full
  Prometheus exposition (`317` text lines on node 0; node 1 of
  the same shape).
- `/metrics` was honest about consensus state. Every consensus
  series that *should* be `0` was `0`, including
  `qcs_formed_total`, `votes_observed_total`,
  `votes_total{result="accepted"}`, and `current_view`. There is
  no metric reading that contradicts the loop-exit `commits = 0`,
  `committed_height = None`, `view = 0` story from §7/§8.
- The only nonzero consensus counter on either node is node 0's
  `qbind_consensus_proposals_total{result="accepted"} = 1`, which
  matches the leader's own self-acceptance of its own view-0
  proposal and is consistent with `outbound_proposals = 1` in §7.
- **Between Scrape A and Scrape B (~31 s apart) every consensus
  counter was unchanged on both nodes.** This is the strongest
  available proof from `/metrics` that consensus made no progress
  during the steady-state portion of the run. It is the inverse
  of Run 002 §9 / Run 003 §9 / Run 004 §9, where between two
  scrapes the view-position counters strictly increased — i.e.
  this run *correctly* did not show the single-validator
  self-quorum advance shape, because the cluster is not
  single-validator and no peer vote ever arrived.
- Post-shutdown, `curl http://127.0.0.1:9100/metrics` and
  `curl http://127.0.0.1:9101/metrics` both returned
  `Connection refused` (`%{http_code} = 000`), identical to the
  shutdown-side observation in Runs 003 §9 / 004 §9. The metrics
  listeners actually go away on shutdown.

Inferred (with reasoning):

- `/metrics` is therefore **honest on the binary path under a
  failed multi-validator P2P bring-up**: it does not invent
  progress, does not double-count anything, and does not lag
  past the engine state. This is the same `/metrics` honesty
  property Run 002 first established; Run 005 confirms it survives
  unchanged in the multi-validator P2P case.

---

## 10. Shutdown Evidence

### 10.1 Shutdown trail — node 0 (exact, unedited)

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1075 ticks.
[binary-consensus] Loop exit: ticks=1075 proposals=1 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=1 outbound_votes=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 10.2 Shutdown trail — node 1 (exact, unedited)

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1036 ticks.
[binary-consensus] Loop exit: ticks=1036 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 10.3 What this evidences

Observed (direct):

- **Both nodes shut down cleanly under SIGINT.** Both terminated
  with `[binary] Shutdown complete.`, both released their P2P
  listener and `/metrics` listener (verified by post-shutdown
  `curl … Connection refused` on both ports), and neither hung,
  panicked, or left an orphaned process (`ps -p` returned empty
  for both PIDs after shutdown).
- The shutdown trail shape is identical (modulo per-node tick
  counts) to the single-validator runs (Runs 001/002/003/004 §10).
  B6 multi-validator P2P does not perturb the SIGINT path.
- The B6 inbound channel's "channel close is handled honestly"
  property covered by `c4_b6_p2p_binary_path_interconnect_tests`
  test D is consistent with the observed clean shutdown — the
  loop exited cleanly even though `inbound_msgs = 0` for the
  whole lifetime of the loop.

---

## 11. Limitations and Anomalies Observed

This run is bounded. The following are the explicit, honest gaps
and observations — they are the central content of the run, not
incidental.

1. **No `ConsensusNetMsg` crossed between the two binaries.** This
   is the load-bearing negative observation of Run 005. Per §7,
   `inbound_msgs = 0` on both nodes, `inbound_proposals = 0` on
   both nodes, `inbound_votes = 0` on both nodes. The B6 wiring
   is verifiably in the running binary (per the §6 banner), but
   this run did not exercise it because the prerequisite did not
   hold.

2. **The KEMTLS handshake fails between two real `qbind-node`
   processes under the current test-grade transport configuration.**
   Concrete log evidence: node 1's
   `[P2P] Failed to dial 127.0.0.1:19000: Handshake error:
   channel error: Net(Protocol("client handle_server_accept
   failed"))`, paired with node 0's
   `[P2P] Inbound connection error: Handshake error: …`. The
   most plausible structural explanation (inferred, see §6.6)
   is that
   `P2pNodeBuilder::create_connection_configs` derives
   `peer_kem_pk` from the local `validator_id`
   (`p2p_node_builder.rs:514–518, 575`) rather than the peer's,
   so the dialer's KEM view of the remote endpoint cannot match
   the remote endpoint's actual KEM keypair. This is a binary-side
   transport-bring-up gap that is *prior to* (and smaller than)
   "production-grade PQC KEMTLS identity hardening".

3. **The peer-identity mapping was not closed.** Node 0's
   `[P2P] Peer NodeId(1a9811f18a2a5fbb) connected` line shows
   the connected peer is **not** recognized as ValidatorId(1)
   (whose deterministic NodeId is `0100000000000000`). Even if
   a `ConsensusNetMsg` had been delivered over that session, the
   `P2pConsensusNetwork` outbound facade — which uses
   `SimpleValidatorNodeMapping` to address peers by `ValidatorId`
   — would have nowhere to direct outbound `BroadcastVote` /
   `SendVoteTo` traffic targeted at ValidatorId(1). This is a
   second observable manifestation of the same underlying gap
   as item 2.

4. **Initial dial races are real but transient.** Both nodes
   logged at least one `Failed to dial` before settling into a
   listening state. Node 0's first dial failed with
   `Connection refused (os error 111)` because node 1's listener
   was not yet up (node 0 was started ~4 s before node 1). Node 1's
   first dial failed at the KEMTLS layer (item 2). These two
   failure shapes are distinct and both are recorded above. After
   the initial dial, neither node retried at the binary level
   inside the run window.

5. **No restore semantics were exercised.** Run 005 deliberately
   did not pass `--restore-from-snapshot`, to keep the connectivity
   question separate from the restore-aware question. Runs 003 /
   004 are the relevant restore artifacts.

6. **No timeout / new-view evidence either way.** Inbound
   `ConsensusNetMsg::Timeout` / `NewView` routing remains the
   "received but unhandled" case noted in `contradiction.md` C4
   `Remaining`; Run 005 does not exercise this path because no
   inbound `ConsensusNetMsg` of any class arrived.

7. **Single host, two processes only.** A 3-node configuration
   would not be informative until item 2 is closed: it would
   produce the same handshake failure shape between every pair.

8. **Pre-existing compiler warning unchanged.** `unused variable:
   worker_id` in `crates/qbind-node/src/verify_pool.rs:262`
   continues to surface, identical to Runs 001–004. Not related
   to this run.

None of items 1–3 above were silently expected: B6's `Remaining`
cell in `contradiction.md` C4 already flagged "validator/node-id
identity hardening" and "real PQC KEMTLS handshake / identity
certificate path" as outstanding. Run 005 supplies the empirical
shape of *what specifically breaks* on the binary today, which is
narrower and more actionable than those general categories.

---

## 12. Assessment of Evidence Value

### 12.1 Direct answers to the required questions

| Question | Answer | Evidence section |
|---|---|---|
| A. Did multiple real `qbind-node` processes start successfully? | **Yes.** Two real processes (V0, V1) ran concurrently for ≈ 100 s, both bound their P2P + `/metrics` listeners, both entered the binary `run_p2p_node` multi-validator path with `num_validators=2`, both emitted the B6 banner. | §6 |
| B. Did the binary P2P path come up between them? | **Partially — TCP only.** TCP connect/accept succeeded (`[P2P] Accepted connection from 127.0.0.1:52186/52194`). KEMTLS handshake **failed** on both sides (`Net(Protocol("client handle_server_accept failed"))` on node 1; matching `Inbound connection error: Handshake error` on node 0). One inbound session was admitted at node 0 under a *temporary* NodeId (`1a9811f18a2a5fbb`), not the deterministic peer NodeId (`0100…`), so peer-identity mapping was never closed. | §6.6, §11 #2, §11 #3 |
| C. Did proposals cross node boundaries and reach the engine? | **No.** `inbound_proposals = 0` on both nodes' loop-exit summary; node 0 emitted one outbound proposal that was never received by node 1. | §7 |
| D. Did votes cross node boundaries and reach the engine? | **No.** `inbound_votes = 0` on both nodes; node 0 emitted one outbound vote (its own self-vote) that was never received by node 1. | §7 |
| E. Did QC / commit progression happen across the binary path? | **No.** Both nodes: `qcs_formed_total = 0`, `commits = 0`, `committed_height = None`, `view = 0` for the entire run. Cross-node progression on the binary path was **not** demonstrated by Run 005. | §8, §9 |
| F. Did `/metrics` still work honestly? | **Yes.** Both `/metrics` endpoints returned full Prometheus exposition during the live run, accurately reflected the stuck-at-view-0 state, did not invent any progress between Scrape A and Scrape B (~31 s apart), and went away cleanly on shutdown. | §9 |
| G. Did shutdown complete cleanly? | **Yes.** Both nodes shut down under SIGINT with the standard shutdown trail, no hang, no orphan process, listeners released. B6 multi-validator P2P does not perturb the shutdown path. | §10 |
| H. Does this materially strengthen the multi-validator side of DevNet evidence? | **Yes — but as a sharper *negative* result, not a *positive* one.** Run 005 is the first artifact that exercises the real binary-to-binary P2P path. It empirically demonstrates that B6's *engine-routing* code is in the binary and is correctly dormant when no inbound `ConsensusNetMsg` arrives, **and** that the prerequisite (a working binary-to-binary KEMTLS session that closes the validator-identity mapping) is currently not satisfied by the test-grade transport bring-up path. This is concrete, actionable narrowing of the residual C4 sub-item: the next blocker is no longer "B6 wiring exists?" (it does, observable), it is "fix `P2pNodeBuilder::create_connection_configs` so each side's `peer_kem_pk` is the *peer's* KEM public key (and validator-identity binding closes on connect)". | §6, §7, §11 |
| I. What exact next execution action is recommended after Run 005? | **Fix the binary-path test-grade KEMTLS bring-up so two `qbind-node` processes can complete a KEMTLS handshake and close peer-validator-identity mapping**, then re-run a Run-005-shaped exercise to capture the first cross-node proposal/vote/QC/commit progression on the binary path. See §13. | §13 |

### 12.2 Summary verdict

**Verdict (exact):** The first multi-validator binary-path DevNet
evidence exercise on real `qbind-node` binaries **partially passed
and partially failed**, in a clean, observable way:

- **PASSED:** real multi-process startup, real P2P listener bind,
  real cluster-shape recognition (`num_validators = 2`,
  multi-validator B6 banner emitted), real `/metrics` honesty,
  real clean shutdown, and observable confirmation that B6
  wiring is present in the running binary and is correctly
  dormant when no `ConsensusNetMsg` arrives.
- **FAILED:** the prerequisite condition for B6's load-bearing
  proof. No proposal, vote, QC, or commit crossed between the two
  binaries during the run. The KEMTLS handshake between two
  `qbind-node` processes does not currently complete under the
  default `make_test_crypto_provider` /
  `create_connection_configs` path, and the peer-validator
  identity mapping is not closed on the surviving inbound session.

**Run 005 therefore does NOT prove "QC / commit progression is no
longer harness-only on the binary path" as the original goal
phrased it.** It proves that statement is *not yet true* at the
binary level, and identifies the specific, narrow gap that is
preventing it. Treat this as the first honest negative that
B6's design intent did not, by itself, deliver an end-to-end
binary-path multi-validator DevNet — there is one more piece of
work below B6 (in the transport bring-up) before that becomes
observable.

This is bounded multi-validator P2P bring-up evidence. It is
**not** Beta readiness, **not** Alpha readiness, **not** a soak
result, **not** a claim of production identity hardening, **not**
a claim of a working multi-validator DevNet. It is, narrowly, the
first time the load-bearing question has been asked of two real
binaries, and the first time the answer has been recorded
honestly.

### 12.3 Decision on `contradiction.md`

`docs/whitepaper/contradiction.md` C4 **is updated** by Run 005,
in the smallest scope that the new empirical evidence justifies.

Justification:

- The `Remaining` cell of C4 already lists "validator/node-id
  identity hardening for production" and "real PQC KEMTLS
  handshake / identity certificate path on the binary" as open
  items. These are correct, but Run 005 reveals a **strictly
  smaller, strictly more concrete** gap that was not previously
  documented: the binary's *test-grade* transport bring-up path
  itself does not produce a working binary-to-binary KEMTLS
  session in the simplest possible 2-node case, because
  `P2pNodeBuilder::create_connection_configs` derives
  `peer_kem_pk` from the **local** `validator_id` rather than the
  peer's. This is a real, observable, sub-`peer_kem_pk`-shaped
  narrowing of C4 that was not previously known empirically.
- The C4 row's `Status` ("OPEN — partial") and `Description` /
  `Impact` cells need a small qualifier to record: B6 wiring is
  observable on the binary; the binary-path multi-validator
  *transport* prerequisite is not yet met; the immediate next
  execution action shifts from "observe B6 in a multi-validator
  binary cluster" (the post-Run-004 next action) to "fix the
  binary's test-grade KEMTLS bring-up" (the post-Run-005 next
  action).
- Per the run constraints, the edit is intentionally minimal:
  one short additional `Remaining` bullet citing Run 005 and
  the specific gap, plus a sentence in `Impact` reflecting the
  empirical finding. No rewriting of the existing B1/B2/B3/B5/B6
  cells.

The full, exact contradiction.md edit is described in §12.4.

### 12.4 Exact contradiction.md edit applied

A new bullet was added to the `Remaining` cell of the C4 row
recording the Run 005 finding, and a short sentence was added to
the `Impact` cell to reflect the empirical observation. No other
contradiction-row state (`Status`, `Code Location`, `Description`)
was changed: the *coded* state is unchanged from B6 landing; only
empirical evidence and the prioritized next step have changed.

The `Tracking` cell now also references Run 005 alongside the
existing Run 004 reference.

---

## 13. Recommended Immediate Next Action

The single highest-leverage next execution action, after Run 005,
is:

> **Fix the binary's test-grade KEMTLS bring-up so two `qbind-node`
> processes can complete a KEMTLS handshake and close the
> peer-validator identity mapping in the default
> `--enable-p2p` / `--p2p-peer …` configuration.**
>
> Concretely (the smallest honest fix the §11 #2 evidence
> supports):
>
> 1. In `crates/qbind-node/src/p2p_node_builder.rs::create_connection_configs`,
>    derive `peer_kem_pk` from the **peer's** validator id rather
>    than the local node's. The current line (`p2p_node_builder.rs:575`)
>    uses `peer_kem_pk: server_kem_pk`, which is the *local*
>    KEM public key. The peer's KEM public key for validator
>    `i` is `(0..32).map(|j| j.wrapping_add(i as u8))`, the same
>    formula at `p2p_node_builder.rs:514–518`. The dialer needs
>    to know which peer it is dialing — this can be plumbed
>    through `--p2p-peer` + a small validator-index-per-peer
>    convention, or by augmenting the dial to carry the target
>    `ValidatorId`.
> 2. Close the peer-validator mapping on accept so connected
>    peers are recognized as ValidatorId(N) rather than as a
>    temporary session NodeId. The mapping is already maintained
>    by `SimpleValidatorNodeMapping` — the gap is that the
>    inbound side does not currently bind the accepted session
>    to a known validator id.
> 3. Re-run the Run-005 shape exercise on the same binary surface,
>    and capture the first true `inbound_proposals > 0`,
>    `inbound_votes > 0`, `qcs_formed_total > 0`, `commits > 0`,
>    `committed_height = Some(_)` evidence on the binary path
>    across two real processes.
>
> This sits squarely on the existing B6 surface, does not
> broaden into multi-validator restore semantics or full backup-
> and-recovery, and is the smallest change that would make the
> goal of Run 005 actually achievable. Until this is done, no
> further multi-validator binary-path evidence runs will
> observe cross-node progression. *After* this is done, the
> right follow-up — but only after — is a Run-005-shaped
> exercise extended to capture the actual cross-node QC / commit
> progression evidence the original Run 005 goal asked for, and
> the right time to re-evaluate the C4 `Remaining` cell.

---

*Run 005 ends here. Subsequent multi-validator binary-path
evidence will be recorded in a separately numbered DevNet
evidence run.*