# QBIND DevNet Evidence Run 006

**Status:** Internal evidence record — second **multi-validator
binary-path** DevNet run, after **B7** (binary-path test-grade
KEMTLS bring-up + dialer-side peer-validator identity closure)
landed on top of B6. Re-runs the Run-005-shaped exercise to
determine, on real `qbind-node` binaries, whether the post-B7
path now provides honest cross-node binary-path progression.
**Audience:** Internal — protocol engineering, ops, release
management.
**Run date:** 2026-05-04 (UTC).
**Author:** Execution follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` §13 ("Fix the
binary's test-grade KEMTLS bring-up so two `qbind-node` processes
can complete a KEMTLS handshake and close the peer-validator
identity mapping").

> This document is a focused sixth evidence artifact. It is **not**
> a Beta-readiness statement, **not** a soak result, **not** a full
> backup-and-recovery program completion, **not** a claim of
> production-grade validator/node-id identity, and **not** a claim
> that QBIND has a working multi-validator DevNet on the binary
> path. It exists to record, exactly, what happened when two real
> `qbind-node` binaries were started post-B7 and wired to each
> other via `--enable-p2p` / `--p2p-peer vid@addr`, and what this
> empirically tells us about the residual C4 sub-item that B7 was
> intended to narrow.

---

## 1. Purpose and Scope

Run 005 established the first empirical multi-validator
binary-path shape and identified the load-bearing transport-level
blocker (the test-grade KEMTLS handshake failed; the surviving
inbound session was admitted under a temporary NodeId, not the
peer's deterministic NodeId; `inbound_msgs = 0` on both nodes).
B7 was the smallest honest fix to that finding: it centralizes the
test-grade KEM keypair and NodeId derivation rules
(`derive_test_kem_keypair_from_validator_id`,
`derive_test_node_id_from_validator_id`), threads per-peer
`peer_kem_pk` + expected `validator_id` overrides through
`TcpKemTlsP2pService::dial_peer`, requires `--p2p-peer` to be of
the form `vid@addr` for multi-validator runs, and fixes a latent
inbound-side `set_nonblocking(false)` bug that was tripping
`WouldBlock` on the very first read of the blocking handshake.

Run 006's purpose, and only purpose, is to capture concrete
end-to-end binary-path evidence of whether the post-B7 path now
demonstrably advances the multi-validator binary-path question
beyond Run 005's stuck-at-zero shape, and exactly where it does
or does not.

In scope (this run):

- A. Bring up two real `qbind-node` binaries on a single host with
  the same general shape as Run 005, but with the new B7-required
  `vid@addr` peer syntax.
- B. Observe each node's startup banner, multi-validator banner,
  consensus loop start, P2P listener bind, KEMTLS handshake
  success/failure shape, peer-NodeId binding shape, and whether
  the post-B7 dialer-side override line
  (`Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id
  override (pk_len=32, has_vid=true)`) appears.
- C. Observe whether `ConsensusNetMsg::{Proposal, Vote}` traffic
  actually crosses node boundaries via the binary `inbound_msgs` /
  `inbound_proposals` / `inbound_votes` counters surfaced in the
  loop-exit summary (`binary_consensus_loop.rs`).
- D. Observe whether `BasicHotStuffEngine` view / committed-height
  state advances on either node beyond its post-startup baseline.
- E. Observe `/metrics` on both nodes during the run, two scrapes
  apart, to detect any fabricated progression.
- F. Observe orderly SIGINT shutdown on both nodes.
- G. Cross-check the single-validator LocalMesh path independently
  to detect any regression of B1/B2 introduced by the B7 changes.
- H. Record exactly what is and is not proven by this run, and
  whether C4 is materially narrowed.

Explicitly out of scope (this run):

- Restore-aware multi-validator behavior (Runs 003/004 are the
  restore-side artifacts; Run 006, like Run 005, intentionally
  uses no `--restore-from-snapshot`).
- 3-node clusters. The 2-node result is sufficient to disambiguate
  the load-bearing question — "do messages cross node boundaries
  on the binary path now?" — and the Run 006 outcome below makes
  a 3-node extension uninformative on this artifact (it would face
  the same residual binding shape on every accepting side, and
  diluting the 2-node result is explicitly forbidden by this run's
  charter).
- Soak / long-duration stability.
- Alpha/Beta readiness.
- Production-grade PQC KEMTLS identity hardening (the binary
  uses the test-grade `derive_test_kem_keypair_from_validator_id`
  + `SimpleValidatorNodeMapping` path that B7 fixed but did not
  productionize; Run 006 records what that path empirically does
  post-B7, not a claim that it is production-suitable).
- Inbound `ConsensusNetMsg::Timeout` / `NewView` routing
  (intentionally deferred per `contradiction.md` C4 `Remaining`).
- Full mutual-auth KEMTLS (`MutualAuthMode::Required`); the
  test builder still uses `MutualAuthMode::Disabled` per the
  documented B7-residual.

---

## 2. Canonical Basis

This run is grounded in, and bounded by:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` — the immediately
  preceding negative-result artifact whose §13 next-action is what
  Run 006 actually exercises.
- `docs/whitepaper/contradiction.md` C4 — the residual sub-item
  ("multi-validator P2P binary-path interconnect"), including the
  B7 update that lists the fix surface, the regression test
  surface, and the explicit "B7-residual" note about inbound-side
  validator identity binding.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_004.md` — the most recent
  single-validator binary-path baseline that Run 006's regression
  guard (§11) is checked against.
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` (EXE-2) — §6.1, §7,
  §10 (next-action ordering).
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` §4 (signal
  classes), referenced for `/metrics` sanity.
- `crates/qbind-node/src/main.rs` (`run_p2p_node`) — the binary
  surface under test in P2P mode.
- `crates/qbind-node/src/binary_consensus_loop.rs`
  (`BinaryConsensusLoopIo`, `run_binary_consensus_loop_with_io`,
  `Loop exit` summary) — the surface that records
  `inbound_msgs` / `inbound_proposals` / `inbound_votes` /
  `outbound_proposals` / `outbound_votes`.
- `crates/qbind-node/src/p2p_node_builder.rs` — B7 surface:
  `derive_test_kem_keypair_from_validator_id`,
  `derive_test_node_id_from_validator_id`, `parse_peer_spec`,
  `set_peer_kem_pk_overrides`, `set_peer_validator_id_overrides`,
  the `B7: --p2p-peer entries must be of the form 'vid@addr'`
  reject path.
- `crates/qbind-node/src/p2p_tcp.rs` — B7 surface:
  `set_nonblocking(false)` before the blocking handshake on
  `handle_inbound_connection`; per-peer override application in
  `dial_peer`.
- `crates/qbind-net/src/handshake.rs` — the protocol-level
  `delegation_cert.validator_id == client_init.validator_id`
  check that B7's `set_peer_validator_id_overrides` is designed
  to satisfy.
- `crates/qbind-node/tests/b7_kemtls_bringup_identity_closure_tests.rs`
  — in-tree integration tests proving B7 works through the real
  TCP+KEMTLS transport in-process. Run 006 complements those
  tests by going through two **separate** `qbind-node` processes.
- `crates/qbind-node/tests/c4_b6_p2p_binary_path_interconnect_tests.rs`
  — B6 in-tree integration tests (engine-routing wiring).

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch
  `copilot/rerun-multi-validator-evidence-after-b7`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`,
  `rustc 1.94.1 (e408947bf 2026-03-25)` — bit-equivalent to Run
  005's toolchain.
- Build command (binary under test):
  `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome:
  `Finished `release` profile [optimized] target(s) in 6m 35s`
  (cold cache on this branch). The single pre-existing compiler
  warning carried by Runs 001–005 surfaced unchanged
  (`unused variable: worker_id` in
  `crates/qbind-node/src/verify_pool.rs:262`). Out of scope; not
  a regression.
- Resulting binary: `target/release/qbind-node`,
  `8 998 048` bytes, `ELF 64-bit LSB pie executable, x86-64,
  version 1 (SYSV), dynamically linked, ... BuildID[sha1]=
  6b18e3faad00cba2bb0db961feae892615f01482, not stripped`.
  (Slightly larger than Run 005's `8 952 536` bytes, consistent
  with the small B7 code addition.)
- Host: GitHub-hosted Linux x86_64 sandbox, kernel
  `6.17.0-1010-azure`, single host, two `qbind-node` processes
  running concurrently for the two-node phase, one separate
  process for the §11 single-validator regression check.
- Network: loopback `127.0.0.1` only. No external network. No
  TLS certificate authority — the binary uses the in-tree
  `derive_test_kem_keypair_from_validator_id` /
  `SimpleValidatorNodeMapping` test-grade path (post-B7).

This is, deliberately, a **two-process, single-host, real-binary,
real-P2P-path, no-restore, short-bounded run** with the smallest
honest two-validator cluster possible — the same shape as Run 005
so the comparison is direct.

---

## 4. Topology and Node Configuration Used

Two-node cluster, all on `127.0.0.1`. Identical port and data-dir
shape as Run 005, with the B7-required `vid@addr` peer syntax:

```
        +-----------------------+              +-----------------------+
        | qbind-node v0 (V0)    |              | qbind-node v1 (V1)    |
        |                       |              |                       |
        |  P2P  127.0.0.1:19000 |<-- dials --->| P2P  127.0.0.1:19001  |
        |  /metrics  9100       |              | /metrics  9101        |
        |  data /tmp/run006/    |              | data /tmp/run006/     |
        |       data-v0         |              |      data-v1          |
        |                       |              |                       |
        |  --p2p-peer           |              |  --p2p-peer           |
        |     1@127.0.0.1:19001 |              |     0@127.0.0.1:19000 |
        +-----------------------+              +-----------------------+
```

Node 0 (validator id `0`):
- listen: `127.0.0.1:19000`
- static peer: `1@127.0.0.1:19001` (B7 `vid@addr` syntax)
- data dir: `/tmp/run006/data-v0`
- metrics: `127.0.0.1:9100`
- B6 view of cluster size: `static_peers.len() + 1 = 2` validators.

Node 1 (validator id `1`):
- listen: `127.0.0.1:19001`
- static peer: `0@127.0.0.1:19000` (B7 `vid@addr` syntax)
- data dir: `/tmp/run006/data-v1`
- metrics: `127.0.0.1:9101`
- B6 view of cluster size: `2` validators.

Both processes were started in detached background mode (via
`setsid ... </dev/null & disown`) so neither was killed when the
launching shell session exited. This matches the Run 005
discipline.

A separate single-validator LocalMesh node on metrics port `9102`
+ data dir `/tmp/run006/data-sv` was used for the §11 regression
guard; it ran *after* both two-node processes had cleanly shut
down, so there is no port or PID overlap.

---

## 5. Commands and Configuration Used

### 5.1 Build (binary under test)

```
cargo build --release -p qbind-node --bin qbind-node
```

### 5.2 Reset run state

```
rm -rf /tmp/run006
mkdir -p /tmp/run006/data-v0 /tmp/run006/data-v1 /tmp/run006/logs
```

### 5.3 Run command — node 0 (validator 0)

```
setsid env QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19000 \
    --p2p-peer 1@127.0.0.1:19001 \
    --validator-id 0 \
    --data-dir /tmp/run006/data-v0 \
    > /tmp/run006/logs/node0.stdout \
    2> /tmp/run006/logs/node0.stderr \
    < /dev/null & disown
```

### 5.4 Run command — node 1 (validator 1)

```
setsid env QBIND_METRICS_HTTP_ADDR=127.0.0.1:9101 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19001 \
    --p2p-peer 0@127.0.0.1:19000 \
    --validator-id 1 \
    --data-dir /tmp/run006/data-v1 \
    > /tmp/run006/logs/node1.stdout \
    2> /tmp/run006/logs/node1.stderr \
    < /dev/null & disown
```

### 5.5 Environment variables

| Variable                   | Value              | Set on   | Purpose |
|----------------------------|--------------------|----------|---------|
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9100`   | node 0   | enable `/metrics` on node 0 |
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9101`   | node 1   | enable `/metrics` on node 1 |
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9102`   | sv node  | enable `/metrics` on §11 single-validator regression node |

No other QBIND-prefixed env vars were set. No config file. CLI
flags above only.

### 5.6 Run wall-clock window

- Node 0 started at `08:56:59Z` (approx; first stderr line
  written; PID `11400`).
- Node 1 started at `08:57:13Z` (approx; ~14 s after node 0;
  PID `11425`).
- `/metrics` Scrape A: `2026-05-04T08:57:29.299408385Z`.
- `/metrics` Scrape B: `2026-05-04T08:58:25.913242187Z` (~56 s
  after Scrape A).
- SIGINT delivered to both PIDs at:
  `2026-05-04T08:58:52.185869150Z`.
- Total node-0 lifetime per its own loop summary: `1191 ticks`
  at `tick=100ms` ≈ `119.1 s`.
- Total node-1 lifetime per its own loop summary: `1047 ticks`
  ≈ `104.7 s`. The ~14 s lifetime delta matches the ~14 s
  startup stagger.
- §11 single-validator regression check: started after the
  two-node cluster shut down, scraped once after ~8 s, SIGINT,
  total lifetime per its loop summary: `202 ticks` ≈ `20.2 s`.

---

## 6. Startup, Handshake, and Connectivity Evidence

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
[P2P] Inbound connection error: Handshake error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1191 ticks.
[binary-consensus] Loop exit: ticks=1191 proposals=1 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=1 outbound_votes=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 6.2 Node 0 — full `stdout` (exact, unedited)

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19000 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19000 (node_id=NodeId(4bd96f97b1aaec9d))
[P2P] Dialing 127.0.0.1:19001
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1
[P2P] Accepted connection from 127.0.0.1:42378
[P2P] Accepted connection from 127.0.0.1:42392
[P2P] Inbound connection from 127.0.0.1:42392 assigned temporary session NodeId NodeId(a8a4efbced6091a2)
[P2P] Peer NodeId(a8a4efbced6091a2) connected
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
[binary] P2P transport up. Listen address: 127.0.0.1:19001, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1047 ticks.
[binary-consensus] Loop exit: ticks=1047 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 6.4 Node 1 — full `stdout` (exact, unedited)

```
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19001 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(92115fddcd4f93a0))
[P2P] Dialing 127.0.0.1:19000
[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1
[T175] Shutting down P2P node for validator ValidatorId(1)
[T175] P2P node shutdown complete
```

### 6.5 Listening sockets (observed via `ss -ltn` while live)

```
LISTEN 0 4096 127.0.0.1:9101  0.0.0.0:*
LISTEN 0 4096 127.0.0.1:9100  0.0.0.0:*
LISTEN 0 4096 127.0.0.1:19001 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:19000 0.0.0.0:*
```

### 6.6 What this evidences (load-bearing)

Observed (direct):

- **Both `qbind-node` binaries started successfully and remained
  running concurrently.** Both emitted the B1/B2 banner
  (`P2P transport up. Listen address: ..., static peers: 1`) and
  the B6 multi-validator banner. The `run_p2p_node` path entered
  the `num_validators > 1` branch on both.
- **Both nodes bound their P2P listeners and their `/metrics`
  listeners.** All four sockets appeared in `ss -ltn` while live.
- **B7 path is being exercised, not bypassed.** Three independent
  pieces of direct log evidence:
  1. Both stdout banners include `peer_kem_overrides=1` —
     `P2pNodeBuilder::build` populated exactly one per-peer
     KEM-pk override entry (matching the one `vid@addr` peer
     each node was given).
  2. Node 1's stdout includes
     `[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk +
     validator-id override (pk_len=32, has_vid=true)` — the
     post-B7 dial-time log emitted from
     `TcpKemTlsP2pService::dial_peer` when both
     `set_peer_kem_pk_overrides` *and*
     `set_peer_validator_id_overrides` resolve a hit for the
     dialed address.
  3. Node 0's deterministic `node_id` is now
     `NodeId(4bd96f97b1aaec9d)` and node 1's is
     `NodeId(92115fddcd4f93a0)` — both materially **different**
     from the Run-005-era values
     (`NodeId(0000000000000000)` and `NodeId(0100000000000000)`),
     confirming the post-B7
     `derive_test_node_id_from_validator_id` rule
     (`sha3_256_tagged("QBIND:nodeid:v1", test_kem_pk(vid))`) is
     the live derivation, not the old prefix-byte rule.
- **Post-B7 KEMTLS handshake succeeds in the V1→V0 direction.**
  Node 1 logs `[P2P] Peer NodeId(4bd96f97b1aaec9d) connected`,
  and the connected NodeId is **byte-identical** to node 0's
  *deterministic* listening NodeId. This is the dialer-side
  peer-validator identity closure working as B7 designed it: the
  dialer that wrote `1@127.0.0.1:19001` actually ended up bound,
  on the transport, to V0's deterministic NodeId. Run 005 saw
  `Net(Protocol("client handle_server_accept failed"))` in this
  exact same log slot. Run 006 does **not** see that error in
  any form on either node. The Run-005 KEMTLS protocol failure
  has been closed.
- **One inbound dial-race error of a different shape than Run 005.**
  Node 0 logs `[P2P] Inbound connection error: Handshake error:
  channel error: Io(Error { kind: UnexpectedEof, message:
  "failed to fill whole buffer" })`. This corresponds to the
  *first* accepted TCP connection (`from 127.0.0.1:42378`) which
  was opened by node 1's first dial attempt and then dropped
  before the handshake completed. The shape is now `UnexpectedEof`
  rather than Run 005's `WouldBlock`, which is direct evidence
  that the B7 inbound-side `set_nonblocking(false)` fix is
  active: the blocking read no longer trips immediately on a
  non-blocking socket. Note that there is no such
  `Net(Protocol(...))` error this run.
- **Post-B7 inbound-side identity binding remains "session
  temporary" — the documented B7-residual.** Node 0 admits the
  *second* (and surviving) inbound connection (`from
  127.0.0.1:42392`, opened by node 1's successful dial) and
  logs:
  `[P2P] Inbound connection from 127.0.0.1:42392 assigned
   temporary session NodeId NodeId(a8a4efbced6091a2)` →
  `[P2P] Peer NodeId(a8a4efbced6091a2) connected`. The connected
  peer's session NodeId is `a8a4efbced6091a2`, **not**
  `92115fddcd4f93a0` (V1's deterministic NodeId). This matches
  exactly the published B7-residual in `contradiction.md` C4:
  the test-grade KEMTLS-PDK protocol does not exchange a client
  cert under `MutualAuthMode::Disabled`, so the inbound side
  has no cryptographic basis to bind the accepted session to a
  specific `ValidatorId`. The dialer side knows it dialed V0;
  the listener side does not know the connected peer is V1.
- **One direction of TCP topology only emerged at runtime.**
  Node 0's first dial to `127.0.0.1:19001` (issued before node 1
  started) failed with `Connection refused (os error 111)` and
  was not retried at the binary level. Node 1's later dial to
  `127.0.0.1:19000` succeeded. Net result: there is exactly one
  end-to-end transport session between the two binaries — the
  V1→V0 direction (V1 outbound, V0 inbound). There is no V0→V1
  outbound session.
- **Initial dial races are real but transient.** Both nodes
  logged at least one early failed dial. After the initial dial,
  neither node retried at the binary level inside the run window,
  matching Run 005's observation. This is independent of B7.

Inferred (with reasoning):

- The combination "V1 dialer bound to V0's deterministic NodeId"
  + "V0 listener bound to a temporary, non-deterministic session
  NodeId" produces an asymmetric peer-identity view of the same
  transport session. This is exactly the mode the C4 row's
  `B7-residual` bullet describes:

  > Outbound dials now bind the connected peer to the peer's
  > deterministic NodeId + ValidatorId, and `send_to(ValidatorId)`
  > round-trips. Inbound accepts still admit under a temporary
  > session NodeId because the current test-grade KEMTLS-PDK
  > protocol does not exchange a client cert.

  Run 006 supplies the first empirical, log-level, two-process
  observation of that exact mode.

---

## 7. Cross-Node Proposal / Vote Evidence

### 7.1 Direct counts from each node's loop-exit summary

Source: the `[binary-consensus] Loop exit: …` lines in §6.1 and
§6.3, produced unedited by `binary_consensus_loop.rs`.

| Counter                  | Node 0 (V0)                   | Node 1 (V1)                   |
|--------------------------|-------------------------------|-------------------------------|
| `ticks`                  | `1191`                        | `1047`                        |
| `proposals` (engine-emitted) | `1`                       | `0`                           |
| `commits`                | `0`                           | `0`                           |
| `committed_height`       | `None`                        | `None`                        |
| `view`                   | `0`                           | `0`                           |
| `inbound_msgs`           | `0`                           | `0`                           |
| `inbound_proposals`      | `0`                           | `0`                           |
| `inbound_votes`          | `0`                           | `0`                           |
| `outbound_proposals`     | `1`                           | `0`                           |
| `outbound_votes`         | `1`                           | `0`                           |

### 7.2 Direct comparison with Run 005

| Counter                  | Run 005 V0 / V1 | Run 006 V0 / V1 | Δ                            |
|--------------------------|------------------|------------------|------------------------------|
| `inbound_msgs`           | 0 / 0            | 0 / 0            | unchanged (still zero)       |
| `inbound_proposals`      | 0 / 0            | 0 / 0            | unchanged (still zero)       |
| `inbound_votes`          | 0 / 0            | 0 / 0            | unchanged (still zero)       |
| `outbound_proposals`     | 1 / 0            | 1 / 0            | unchanged                    |
| `outbound_votes`         | 1 / 0            | 1 / 0            | unchanged                    |
| KEMTLS handshake outcome | failed           | **succeeded** in V1→V0 dir; V0 still binds inbound under temp NodeId | **changed** |
| Dialer-side identity     | not closed       | **closed** (V1's `Peer NodeId(4bd...)` matches V0 deterministic) | **changed** |
| Listener-side identity   | not closed       | not closed (still temp NodeId, B7-residual) | unchanged    |

The transport-level *shape* improved materially. The
consensus-message-flow level *counters* did not.

### 7.3 What this evidences (load-bearing)

Observed (direct):

- **No proposal crossed node boundaries on the binary path during
  this run.** Both nodes reported `inbound_proposals = 0`. Node 0
  (the leader of view 0) emitted one proposal locally
  (`outbound_proposals = 1`), but it never reached node 1's engine
  via the inbound `ConsensusNetMsg` path
  (`inbound_proposals = 0` on node 1).
- **No vote crossed node boundaries on the binary path during this
  run.** Both nodes reported `inbound_votes = 0`. Node 0 emitted
  one outbound vote (its own self-vote on its own proposal), but
  no peer vote was received. Node 1's `outbound_votes = 0`
  confirms node 1 *never had a vote to send* — consistent with
  the absence of an inbound proposal at node 1.
- **No `ConsensusNetMsg` of any kind crossed node boundaries on
  the binary path during this run.** `inbound_msgs = 0` on both
  nodes is the most aggressive form of this statement: it is
  incremented by `binary_consensus_loop.rs` *as the message is
  dequeued from the inbound channel*, before any decode/dispatch.
  If a single byte had reached the inbound demuxer's typed
  channel, `inbound_msgs` would be ≥ 1.
- **Neither engine advanced past view 0.** Both nodes reported
  `view = 0`, `committed_height = None`. No QC formation, no
  view change.
- **Node 0's single proposal was self-counted as `accepted`
  exactly once** (Scrape A and Scrape B both report
  `qbind_consensus_proposals_total{result="accepted"} 1`,
  unchanged across ~56 s) — the leader did not retry, view 0
  simply never closed. This is the unmodified behavior of
  `BasicHotStuffEngine` when no `ConsensusNetMsg::Vote` is
  received and no timeout/new-view path advances the view.

Inferred (with reasoning):

- **Why no message crossed, given the handshake now succeeds:**
  the engine actions emitted by V0 are
  `ConsensusEngineAction::BroadcastProposal` (outbound proposal
  to all peers) and `ConsensusEngineAction::BroadcastVote`
  (V0's self-vote, broadcast to all peers).
  `P2pConsensusNetwork` resolves "all peers" through
  `SimpleValidatorNodeMapping`, which deterministically maps
  `ValidatorId(1)` →
  `derive_test_node_id_from_validator_id(1) =
  NodeId(92115fddcd4f93a0)`. To deliver, the transport must have
  a session registered under that NodeId. But:
  - V0 has *no* outbound session to V1 (its initial dial was
    refused as a race; no retry).
  - V0's only live session to anything is the **inbound** session
    from V1, registered under the temporary
    `NodeId(a8a4efbced6091a2)` — not under
    `NodeId(92115fddcd4f93a0)`.

  So V0's `BroadcastProposal` resolves to an unknown destination
  on the transport and is silently not delivered. V1 therefore
  never gets the proposal, never emits a vote, and the consensus
  loop on both sides remains at view 0.

  This is a strictly *narrower* failure than Run 005's: in Run
  005, the handshake itself failed at the KEMTLS protocol layer.
  In Run 006, the handshake succeeds, but the listener-side
  validator-identity binding is still "temp NodeId" (the
  documented B7-residual), and the dialer-only outbound topology
  cannot carry V0's leader-side broadcast back to V1.

- **It is not safe to claim from Run 006 alone that the residual
  is *only* the inbound-binding gap.** A second compounding
  factor is the V0→V1 dial-race: V0's first dial failed and was
  not retried, so even if the inbound-binding gap were closed
  symmetrically, V0 would still be relying on the inbound side
  for any return traffic. The cleanest single observation Run 006
  makes is therefore: **with one TCP session V1→V0 surviving and
  V0 binding it under a temporary NodeId, V0's
  `send_to(ValidatorId(1))` does not resolve to any registered
  transport session, so no engine action ever leaves V0 toward
  V1, and no proposal ever reaches V1's engine.**

### 7.4 What this run does **not** claim

- It does **not** claim B7's *handshake* code is broken. All
  available evidence shows the handshake completes successfully
  in the V1→V0 direction (`Peer NodeId(4bd...)` connected on V1
  matches V0's deterministic NodeId). The Run-005 KEMTLS protocol
  failure (`client handle_server_accept failed`) is gone.
- It does **not** claim B6's *engine-routing* code is broken.
  All available evidence is consistent with B6's engine-routing
  code being correct; it is correctly dormant when no inbound
  `ConsensusNetMsg` arrives.
- It does **not** claim the consensus engine is broken.
  `BasicHotStuffEngine` correctly refuses to advance past view 0
  in the absence of a peer vote.
- It does **not** claim B7 was a no-op. B7 demonstrably narrowed
  the failure: handshake-level → routing-level. Run 005 failed at
  KEMTLS; Run 006 fails at "outbound `send_to(ValidatorId)`
  resolves to no transport session" — a strictly downstream and
  smaller-scoped failure surface.

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
  Scrape B on both nodes (§9), consistent with `commits = 0` from
  the loop-exit summary.
- **No commit fired on either node during this run.**
  `committed_height = None` on both nodes — the engine never
  reached even a first commit.
- **No view advanced past 0 on either node.**
  `qbind_consensus_view_number = 0` on both nodes in both scrapes.

This is the honest negative on this run, and it is **the same
zero-progression shape as Run 005 at this layer**, even though
the underlying transport-layer shape is materially different
(handshake now succeeds; dialer-side identity closure works).

The pre-existing B6 + B7 in-tree integration tests
(`c4_b6_p2p_binary_path_interconnect_tests.rs`,
`b7_kemtls_bringup_identity_closure_tests.rs`) do exhibit
handshake closure and (for B6) QC formation when the inbound
channel is fed directly. Run 006 does not contradict either; it
contributes the additional, narrower observation that the B7
fix, sufficient to unblock the *handshake* for two real
binaries, is not by itself sufficient to deliver
`ConsensusNetMsg` flow on the listener side under
`MutualAuthMode::Disabled` when the V0→V1 outbound dial races
and is never retried.

---

## 9. Metrics Evidence

### 9.1 Scrape A (early in the run)

Timestamp: `2026-05-04T08:57:29.299408385Z` (≈ 30 s after node 0
started, ≈ 16 s after node 1 started).
Lines returned per scrape: 317 on each node.

Node 0 — consensus-class series (exact):

```
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_votes_observed_current_view 0
qbind_consensus_view_changes_total 0
qbind_consensus_leader_changes_total 0
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

### 9.2 Scrape B (~56 s later)

Timestamp: `2026-05-04T08:58:25.913242187Z`.

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

KEMTLS-class series (`qbind_net_kem_*`) on both nodes were also
all zero in both scrapes; the test-grade transport's metric
hooks are not wired into the in-process KEMTLS-PDK path under
this build, which is consistent with Runs 001–005 and is not a
regression. The honest observable is: handshake completion is
recorded in `stdout` (`Peer NodeId(...) connected`), not in
`/metrics`.

### 9.3 What this evidences

Observed (direct):

- `/metrics` was reachable on both nodes during the live run, on
  both ports (`9100`, `9101`). Both endpoints returned full
  Prometheus exposition (317 text lines on each).
- `/metrics` was honest about consensus state. Every consensus
  series that *should* be `0` was `0`, including
  `qcs_formed_total`, `votes_observed_total`,
  `votes_total{result="accepted"}`, and `current_view`. There is
  no metric reading that contradicts the loop-exit `commits = 0`,
  `committed_height = None`, `view = 0` story from §7/§8.
- The only nonzero consensus counter on either node is node 0's
  `qbind_consensus_proposals_total{result="accepted"} = 1`, which
  matches the leader's own self-acceptance of its own view-0
  proposal and is consistent with `outbound_proposals = 1`
  in §7.
- **Between Scrape A and Scrape B (~56 s apart) every consensus
  counter was unchanged on both nodes.** This is the strongest
  available proof from `/metrics` that consensus made no progress
  during the steady-state portion of the run. It is the inverse
  of Run 002 §9 / Run 003 §9 / Run 004 §9, where between two
  scrapes the view-position counters strictly increased — i.e.
  this run *correctly* did not show the single-validator
  self-quorum advance shape (because the cluster is not
  single-validator) and *correctly* did not invent any progression
  (because no peer vote ever arrived).
- Post-shutdown, `curl http://127.0.0.1:9100/metrics` and
  `curl http://127.0.0.1:9101/metrics` both returned
  `%{http_code} = 000` (Connection refused), identical to the
  shutdown-side observation in Runs 003/004/005. The metrics
  listeners actually go away on shutdown.

Inferred (with reasoning):

- `/metrics` is therefore **honest on the binary path under a
  post-B7 multi-validator P2P bring-up where the handshake
  succeeds but the listener-side identity binding does not
  close**: it does not invent progress, does not double-count
  anything, and does not lag past the engine state. This is the
  same `/metrics` honesty property Run 002 first established;
  Run 005 confirmed it survives a transport-level failure;
  Run 006 confirms it survives a routing-level failure as well.

---

## 10. Shutdown Evidence

### 10.1 Shutdown trail — node 0 (exact, unedited)

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1191 ticks.
[binary-consensus] Loop exit: ticks=1191 proposals=1 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=1 outbound_votes=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 10.2 Shutdown trail — node 1 (exact, unedited)

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1047 ticks.
[binary-consensus] Loop exit: ticks=1047 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
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
  panicked, or left an orphaned process (`ps -p` on both PIDs
  returned empty after shutdown).
- The shutdown trail shape is identical (modulo per-node tick
  counts) to Runs 001/002/003/004/005 §10. B6 + B7 do not
  perturb the SIGINT path.
- The B6 inbound-channel "channel close is handled honestly"
  property is consistent with the observed clean shutdown — the
  loop exited cleanly even though `inbound_msgs = 0` for the
  whole lifetime of the loop, on both nodes.

---

## 11. Regression Check Against Previously Landed Binary-Path Capabilities

This section is the explicit regression guard required by the
run charter. It records, with direct log evidence, what was
checked and what was observed.

### 11.1 Single-validator LocalMesh path (B1 / B2 baseline)

After the two-node cluster shut down (so there is no port
collision risk), one independent `qbind-node` process was started
in single-validator LocalMesh mode for ≈ 20 s, scraped, and
SIGINTed.

Command:

```
setsid env QBIND_METRICS_HTTP_ADDR=127.0.0.1:9102 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode local-mesh \
    --validator-id 0 \
    --data-dir /tmp/run006/data-sv \
    > /tmp/run006/logs/sv.stdout \
    2> /tmp/run006/logs/sv.stderr \
    < /dev/null & disown
```

Live `/metrics` excerpt (after ~8 s, scrape via
`curl http://127.0.0.1:9102/metrics`):

```
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_view_changes_total 81
qbind_consensus_current_view 81
qbind_consensus_highest_seen_view 81
qbind_consensus_proposals_total{result="accepted"} 81
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="accepted"} 0
qbind_consensus_votes_total{result="invalid"} 0
qbind_consensus_view_number 81
```

Loop-exit summary on SIGINT (exact):

```
[binary-consensus] Loop exit: ticks=202 proposals=202 commits=200 committed_height=Some(199) view=202 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
```

What this evidences:

- Single-validator commit progression is observable end-to-end on
  this binary: `commits = 200`, `committed_height = Some(199)`,
  `view = 202`. This is the same shape Runs 001–004 reported.
- `inbound_msgs / inbound_proposals / inbound_votes /
  outbound_proposals / outbound_votes = 0` is the **correct**
  shape for the single-validator path: in `run_local_mesh_node`,
  the binary calls the original 4-arg `spawn_binary_consensus_loop`
  which delegates to `run_binary_consensus_loop_with_io(..., None)`
  — i.e. the B6 IO surface is `None`, so all five B6/B7 counters
  must be zero. They are. **B6/B7 did not silently turn on the
  P2P routing surface in single-validator mode.**
- Shutdown trail and post-shutdown `curl ... Connection refused`
  match Runs 001–005.

### 11.2 B6 routing path active in the running multi-validator binary

Direct evidence in §6:

- Both nodes emitted the B6 multi-validator banner
  (`Multi-validator P2P (2 validators): inbound P2P consensus
  messages are routed into BasicHotStuffEngine via
  on_proposal_event / on_vote_event; engine actions flow back
  out through P2pConsensusNetwork.`).
- Both loop-exit summaries report all five B6 counters
  (`inbound_msgs`, `inbound_proposals`, `inbound_votes`,
  `outbound_proposals`, `outbound_votes`), confirming
  `BinaryConsensusLoopIo` was wired and surfaced; node 0 reports
  `outbound_proposals = 1, outbound_votes = 1`, confirming the
  outbound side of B6 fired at least once. The fact that all
  five inbound counters are zero is a routing-side outcome, not
  a B6-wiring regression.

### 11.3 B7 path actively exercised, not bypassed

Direct evidence in §6:

- Both startup banners include `peer_kem_overrides=1`.
- Node 1's stdout includes the post-B7 dial-time line:
  `[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk +
  validator-id override (pk_len=32, has_vid=true)`.
- Both deterministic NodeIds are
  `sha3_256_tagged(...)`-derived (`4bd96f97b1aaec9d`,
  `92115fddcd4f93a0`), not the pre-B7 prefix-byte values
  (`0000000000000000`, `0100000000000000`).
- The dialer-side closure is observable: V1's
  `Peer NodeId(4bd96f97b1aaec9d) connected` matches V0's
  deterministic NodeId byte-for-byte.
- No fallback to bare-addr peers occurred; the binary required
  `vid@addr` (a bare-addr `--p2p-peer` entry would have produced
  the post-B7 reject error
  `B7: --p2p-peer entries must be of the form 'vid@addr' …`,
  which is **not** present in either log).

### 11.4 No fallback to LocalMesh / single-validator semantics

- Both stdout banners contain `network=p2p p2p=enabled
  listen=127.0.0.1:19000` (resp. `19001`) and `peers=1`.
- Both stderr banners contain `[binary] P2P mode: starting
  transport + consensus loop` (the `run_p2p_node` branch),
  not `[binary] LocalMesh mode: …`.
- Both consensus-loop banners say
  `interconnect=p2p` (not `interconnect=local-mesh`).

### 11.5 `/metrics` honesty — no fabricated progression

Per §9: every consensus counter held flat across two scrapes ~56 s
apart on both nodes. None of the metrics endpoints reported a
nonzero `qcs_formed_total`, `votes_observed_total`, or any
view-advancement counter. There is no fabricated progress; this
is the same honesty property Runs 002–005 established.

### 11.6 Summary

**No previously landed binary-path capability appears regressed.**
Single-validator LocalMesh commit progression (B1/B2) is preserved
bit-equivalent. B6 IO surface is honestly active and honestly
zero on the inbound side (because nothing crossed). B7 is
verifiably exercised, not bypassed. Shutdown is clean. `/metrics`
remains honest. The pre-existing `unused variable: worker_id`
compiler warning is unchanged from Runs 001–005 and unrelated.

---

## 12. Limitations and Anomalies Observed

This run is bounded. The following are the explicit, honest gaps
and observations.

1. **No `ConsensusNetMsg` crossed between the two binaries.** This
   is the load-bearing negative observation of Run 006. Per §7,
   `inbound_msgs = 0` on both nodes, `inbound_proposals = 0` on
   both nodes, `inbound_votes = 0` on both nodes. Different
   *cause* than Run 005 — see items 2 and 3 below — but the
   consensus-flow observable is the same.

2. **Listener-side identity binding still uses a temporary
   session NodeId (the documented B7-residual).** Concrete log
   evidence: node 0's
   `[P2P] Inbound connection from 127.0.0.1:42392 assigned
   temporary session NodeId NodeId(a8a4efbced6091a2)` followed by
   `[P2P] Peer NodeId(a8a4efbced6091a2) connected` — where
   `a8a4efbced6091a2 ≠ 92115fddcd4f93a0` (V1's deterministic
   NodeId). This is exactly what `contradiction.md` C4's
   `B7-residual` bullet predicts under
   `MutualAuthMode::Disabled`. Run 006 supplies the first
   two-process empirical observation of this mode.

3. **Single-direction TCP topology after a startup dial-race.**
   Node 0's first dial to `127.0.0.1:19001` failed with
   `Connection refused (os error 111)` because node 1's listener
   was not yet up (node 0 was started ~14 s before node 1).
   Node 0 did **not** retry the dial at the binary level inside
   the run window. Net result: the run produced only a single
   end-to-end transport session (V1→V0). V0 has no outbound
   session to V1 to use for `BroadcastProposal`. This is
   independent of B7 (the same non-retry behavior is observable
   in Run 005 §11 #4).

4. **The combination of (2) and (3) is what kept consensus stuck
   at view 0.** V0's `BroadcastProposal` action resolves through
   `SimpleValidatorNodeMapping` to `NodeId(92115fddcd4f93a0)`
   for V1, but no transport session is registered at V0 under
   that NodeId — neither outbound (none formed) nor inbound (the
   inbound session is registered under the temporary
   `NodeId(a8a4efbced6091a2)`). So V0's outbound proposal does
   not leave V0 toward V1. This is *inferred* from the code in
   `consensus_net_p2p.rs` (`SimpleValidatorNodeMapping`) +
   `p2p_node_builder.rs` (post-B7 NodeId derivation) +
   `p2p_tcp.rs` (inbound session registration), and is the most
   plausible explanation consistent with all observed log lines
   and counters.

5. **No restore semantics were exercised.** Run 006 deliberately
   did not pass `--restore-from-snapshot`, to keep the
   connectivity question separate from the restore-aware
   question. Runs 003 / 004 are the relevant restore artifacts.

6. **No timeout / new-view evidence either way.** Inbound
   `ConsensusNetMsg::Timeout` / `NewView` routing remains the
   "received but unhandled" case noted in `contradiction.md` C4
   `Remaining`; Run 006 does not exercise this path because no
   inbound `ConsensusNetMsg` of any class arrived.

7. **Single host, two processes only.** A 3-node configuration
   would not be informative until item 2 (or item 3 + a
   symmetric workaround) is closed: every accepting side would
   produce the same temporary-NodeId binding shape.

8. **Pre-existing compiler warning unchanged.** `unused variable:
   worker_id` in `crates/qbind-node/src/verify_pool.rs:262`
   continues to surface, identical to Runs 001–005. Not related
   to this run, not a regression.

9. **`qbind_net_kem_*` counters were zero in `/metrics` despite
   handshake completion in stdout.** The test-grade KEMTLS-PDK
   path's metric hooks are not wired into the in-process bring-up
   under this build. The honest observable for "handshake
   completed" is `[P2P] Peer NodeId(...) connected` in stdout,
   not a `/metrics` counter. Same shape as Runs 001–005; not a
   regression introduced by this run.

None of items 1–4 are silently expected. Items 2 and 4 directly
match the prior `B7-residual` text in `contradiction.md` C4. Item
3 is independent of B7 and was already noted in Run 005 §11 #4.

---

## 13. Assessment of Evidence Value

### 13.1 Direct answers to the required questions

| Question | Answer | Evidence section |
|---|---|---|
| A. Did multiple real `qbind-node` processes start successfully? | **Yes.** Two real processes (V0 PID 11400, V1 PID 11425) ran concurrently for ≈ 105–119 s, both bound their P2P + `/metrics` listeners, both entered the binary `run_p2p_node` multi-validator path with `num_validators=2`, both emitted the B6 banner, both emitted `peer_kem_overrides=1`. | §6 |
| B. Did the post-B7 binary-path handshake succeed between them? | **Yes, in the V1→V0 direction.** Node 1 logs `[P2P] Peer NodeId(4bd96f97b1aaec9d) connected`, byte-identical to node 0's deterministic listening NodeId. The Run-005 KEMTLS protocol error (`Net(Protocol("client handle_server_accept failed"))`) is **absent** from both nodes. The only inbound error this run is a different-shape early-dial-race `UnexpectedEof`, consistent with the first dial happening before the peer listener was up — not a KEMTLS protocol failure. **Failure shape changed** vs Run 005. | §6.6, §7.2 |
| C. Did peer mapping close enough for traffic delivery? | **Partially — dialer-side only.** Dialer side (V1→V0): closed; V1's `Peer NodeId(4bd...)` matches V0's deterministic NodeId; per-peer KEM-pk + validator-id override is observable in stdout. Listener side (V0 receiving V1): **not** closed; V0 admits the surviving session under a temporary `NodeId(a8a4ef...)` rather than V1's deterministic `NodeId(92115f...)` — the documented B7-residual. Combined with the V0→V1 dial-race that left V0 with *no* outbound session to V1, V0's `BroadcastProposal` has no transport session it can resolve to for V1, and the proposal never leaves V0. | §6.6, §7.3, §12 #2, §12 #3, §12 #4 |
| D. Did proposals cross node boundaries and reach the engine? | **No.** `inbound_proposals = 0` on both nodes' loop-exit summary. V0 emitted one outbound proposal (its own, view 0); it never reached V1's engine. | §7 |
| E. Did votes cross node boundaries and reach the engine? | **No.** `inbound_votes = 0` on both nodes. V1's `outbound_votes = 0` confirms V1 never had a vote to send (consistent with V1 never receiving a proposal). V0 emitted one outbound vote (its self-vote on its own proposal); it never reached V1. | §7 |
| F. Did QC / commit progression happen across the binary path? | **No.** Both nodes: `qcs_formed_total = 0`, `commits = 0`, `committed_height = None`, `view = 0` for the entire run, unchanged across two scrapes ~56 s apart. Cross-node progression on the binary path was **not** demonstrated by Run 006. | §8, §9 |
| G. Did `/metrics` remain honest? | **Yes.** Both endpoints returned 317-line Prometheus exposition during the live run, accurately reflected the stuck-at-view-0 state, did not invent any progress between Scrape A and Scrape B (~56 s apart), and went away cleanly on shutdown (`%{http_code} = 000`). | §9 |
| H. Did shutdown remain clean? | **Yes.** Both nodes shut down under SIGINT with the standard shutdown trail, no hang, no orphan, listeners released. Shutdown trail shape identical to Runs 001–005 modulo per-node tick counts. | §10 |
| I. Did any previously landed binary-path capability appear regressed? | **No.** Independent single-validator LocalMesh check (§11.1): `commits = 200`, `committed_height = Some(199)`, `view = 202`, IO counters all zero (correct for `io = None`), clean shutdown. B6 banner / counter surface preserved (§11.2). B7 path actively exercised (§11.3). No silent fallback to LocalMesh in the multi-validator binaries (§11.4). `/metrics` honesty preserved (§11.5). | §11 |
| J. What exact next execution action is recommended after Run 006? | **Close the listener-side validator-identity binding** in the test-grade transport, so an accepted KEMTLS session is registered under the dialer's *claimed* validator id (and its corresponding deterministic NodeId), not under a fresh temporary session NodeId. The cheapest path consistent with existing C4 text is to bind the inbound session at handshake completion to the `client_init.validator_id` that `qbind_net::handshake::handle_server_accept` already validated against `delegation_cert.validator_id` (`crates/qbind-net/src/handshake.rs:305`). The strictly-more-secure path is to enable `MutualAuthMode::Required` in the test builder. Either resolves item §12 #2, after which a Run-006-shaped re-run on the same binary surface should observe the first true `inbound_proposals > 0` / `inbound_votes > 0` / `qcs_formed_total > 0` / `commits > 0` evidence on the binary path. See §14. | §14 |

### 13.2 Summary verdict

**Verdict (exact):** The post-B7 multi-validator binary-path
DevNet evidence exercise on real `qbind-node` binaries
**partially passed and partially failed**, in a clean,
observable way that materially advances Run 005 at the
transport layer but does not yet reach cross-node consensus
progression:

- **PASSED (new vs Run 005):**
  - Real multi-process startup, listener bind, B6 banner — same
    as Run 005.
  - **B7 handshake closure:** the KEMTLS handshake now succeeds
    (`Peer NodeId(4bd...)` connected on V1, matching V0's
    deterministic NodeId byte-for-byte). The Run-005 KEMTLS
    protocol failure is gone.
  - **B7 dialer-side identity closure:** observable via the
    `using per-peer KEM pk + validator-id override` line and the
    deterministic-NodeId match.
  - **B7 inbound `set_nonblocking(false)` fix:** observable —
    Run 005's `WouldBlock` early-error is replaced by a
    transient `UnexpectedEof` from the dial race only.
  - `/metrics` honesty preserved, shutdown clean, no regression
    of single-validator LocalMesh (independent §11.1 check).
- **FAILED (still):**
  - **No proposal, vote, QC, or commit crossed between the two
    binaries on this run.** `inbound_msgs = 0` on both nodes,
    same shape as Run 005 at the consensus layer.
  - **Listener-side identity binding is still "temporary
    session NodeId"** (the documented B7-residual). Combined
    with a one-direction-only TCP topology that emerged from the
    V0→V1 dial race, V0's leader-side `BroadcastProposal` cannot
    resolve to a registered transport session for V1.

**Run 006 therefore does NOT prove "QC / commit progression is no
longer harness-only on the binary path".** It does prove the
*handshake-level* prerequisite is satisfied for the first time on
real binaries, that B7 demonstrably narrowed the failure surface
from "KEMTLS protocol fails" to "outbound `send_to(ValidatorId)`
finds no registered session because the listener admits under a
temp NodeId and the dial race left no outbound session", and that
`contradiction.md` C4's prior phrasing "the dialer side closure
is sufficient for `send_to(ValidatorId)` to land on the right
session in both directions for two-node runs" is **empirically
falsified** in the specific case where the V0→V1 outbound dial
fails the initial race and is not retried.

This is bounded multi-validator P2P bring-up evidence. It is
**not** Beta readiness, **not** Alpha readiness, **not** a soak
result, **not** a claim of production identity hardening, **not**
a claim of a working multi-validator DevNet. It is, narrowly, the
first time the post-B7 path has been exercised on two real
binaries, and the first time the result has been recorded
honestly.

### 13.3 Decision on `contradiction.md`

`docs/whitepaper/contradiction.md` C4 **is updated** by Run 006,
in the smallest scope the new empirical evidence justifies.

Justification:

- The `B7-residual` bullet in C4's `Remaining` cell currently
  asserts: "Outbound dials now bind the connected peer to the
  peer's deterministic NodeId + ValidatorId, and
  `send_to(ValidatorId)` round-trips. ... the dialer side closure
  is sufficient for `send_to(ValidatorId)` to land on the right
  session in both directions for two-node runs." Run 006
  empirically refutes the second sentence in the specific case
  where the V0→V1 outbound dial races and is not retried at the
  binary level: V0 then has no outbound session and the inbound
  session is bound under a temp NodeId, so V0's
  `send_to(ValidatorId(1))` does not round-trip — it resolves to
  no registered transport session.
- This is a strictly *narrower, strictly more concrete* gap
  than the existing wording captures. Run 006 contributes the
  first observation of that exact mode.
- Per the run constraints, the edit is intentionally minimal:
  one short qualifier sentence in the existing `B7-residual`
  bullet, plus a Run-006 reference in `Tracking` and a Run-006
  observation appended to `Impact`. No rewriting of the existing
  B1/B2/B3/B5/B6/B7 cells. No status change.
- The full edit is described in §13.4.

### 13.4 Exact contradiction.md edit applied

Three small additions, all within the existing C4 row:

1. The `B7-residual` bullet in `Remaining` gains a one-sentence
   qualifier recording the Run-006 empirical refutation: under
   `MutualAuthMode::Disabled`, when a V0→V1 outbound dial races
   and is not retried, the listener-side temp-NodeId binding
   means V0's `send_to(ValidatorId(1))` does **not** round-trip
   — it resolves to no registered transport session — so closing
   the listener-side binding (or enabling
   `MutualAuthMode::Required`) is what the next execution step
   needs to address.
2. The `Impact` cell gains a one-sentence "Empirical narrowing
   from DevNet Evidence Run 006" sentence recording: post-B7,
   the KEMTLS handshake itself succeeds (V1's
   `Peer NodeId(4bd...)` matches V0's deterministic NodeId) and
   the dialer-side identity closure works, but no
   `ConsensusNetMsg` crossed the two binaries this run because
   the listener-side temp-NodeId binding combined with a
   one-direction-only TCP topology prevented V0's
   `BroadcastProposal` from resolving to a registered transport
   session for V1. `/metrics` and shutdown remained honest.
3. The `Tracking` cell gains a Run-006 reference alongside the
   existing Run-005 reference.

No other contradiction-row state (`Status`, `Code Location`,
`Description`, the B1/B2/B3/B5/B6/B7 bullets) is changed: the
*coded* state is unchanged from B7 landing; only empirical
evidence and the prioritized next step have changed.

---

## 14. Recommended Immediate Next Action

The single highest-leverage next execution action, after Run 006,
is:

> **Close the listener-side validator-identity binding in the
> test-grade transport so that an accepted KEMTLS session is
> registered under the dialer's claimed `ValidatorId` (and its
> corresponding deterministic NodeId) rather than under a fresh
> temporary session NodeId.**
>
> Concretely (the smallest honest fix consistent with the §11.5
> observation and the published B7-residual text):
>
> 1. In `crates/qbind-node/src/p2p_tcp.rs` ::
>    `handle_inbound_connection`, after `accept_kemtls_async`
>    completes, take the `ValidatorId` already validated against
>    the delegation cert by `qbind_net::handshake::handle_server_accept`
>    (the existing
>    `delegation_cert.validator_id == client_init.validator_id`
>    check at `crates/qbind-net/src/handshake.rs:305`) and use
>    it to derive the post-B7 deterministic NodeId via the
>    centralized `derive_test_node_id_from_validator_id(vid)`
>    rule. Register the inbound session under that NodeId rather
>    than under the freshly-generated temporary session NodeId.
>    This is strictly smaller than turning on full
>    `MutualAuthMode::Required` and is sufficient to make
>    `send_to(ValidatorId(N))` round-trip on the listener side
>    for two-node runs.
> 2. Alternatively (or additionally), enable
>    `MutualAuthMode::Required` in
>    `make_test_crypto_provider` so the inbound side has a
>    cryptographically authenticated client identity to bind to.
>    This is the strictly-more-secure path and matches the
>    existing C4 `B7-residual` text more closely; it is a larger
>    change.
> 3. Independent of (1)/(2), also retry the initial outbound
>    dial after `Connection refused` so two-node clusters that
>    happen to start in stagger (≈ Run 006's 14 s lag) end up
>    with a *bidirectional* outbound TCP topology rather than a
>    single inbound-only session. This is independent of B7 and
>    has been latent since Run 005 §11 #4.
> 4. Re-run the Run-006 shape exercise on the same binary
>    surface, and capture the first true `inbound_proposals > 0`,
>    `inbound_votes > 0`, `qcs_formed_total > 0`, `commits > 0`,
>    `committed_height = Some(_)` evidence on the binary path
>    across two real processes.
>
> This sits squarely on the existing B7 surface, does not
> broaden into multi-validator restore semantics or full backup-
> and-recovery, and is the smallest change that would make
> cross-node `ConsensusNetMsg` flow actually observable on the
> binary path. Until at least one of (1) or (2) lands, no further
> multi-validator binary-path evidence runs are expected to
> observe cross-node consensus progression. *After* (1) or (2)
> lands, the right follow-up — but only after — is a Run-006
> shape exercise extended to capture the actual cross-node QC /
> commit progression evidence the original Run 005/006 goal
> asked for, and the right time to re-evaluate the C4
> `B7-residual` bullet.

---

*Run 006 ends here. Subsequent multi-validator binary-path
evidence will be recorded in a separately numbered DevNet
Evidence Run document.*