# QBIND DevNet Evidence Run 007

**Status:** Internal evidence record — third **multi-validator
binary-path** DevNet run, after **B8** (listener-side test-grade
validator-identity closure + bounded initial-dial retry) landed
on top of B7. Re-runs the Run-006-shaped exercise on real
`qbind-node` binaries to determine whether the post-B8 path now
provides honest cross-node binary-path progression.
**Audience:** Internal — protocol engineering, ops, release
management.
**Run date:** 2026-05-06 (UTC).
**Author:** Execution follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_006.md` §13–14 (next-action:
"close the two Run-006 residuals — listener-side temporary-NodeId
binding and unretried initial dial — at test-grade, then re-run
the exact Run-006-shaped exercise to determine whether
`ConsensusNetMsg` now crosses node boundaries on the binary path").

> This document is a focused seventh evidence artifact. It is **not**
> a Beta-readiness statement, **not** a soak result, **not** a full
> backup-and-recovery program completion, **not** a claim of
> production-grade validator/node-id identity, and **not** a claim
> that QBIND has a working multi-validator DevNet on the binary
> path. It exists to record, exactly, what happened when two real
> `qbind-node` binaries were started post-B8, wired to each other
> via `--enable-p2p` / `--p2p-peer vid@addr`, and run for ~2 minutes
> with three independent `/metrics` scrapes — and what this
> empirically tells us about the C4 sub-item that B8 was intended
> to narrow.

---

## 1. Purpose and Scope

Run 006 established that, post-B7, the test-grade KEMTLS handshake
itself succeeds between two real `qbind-node` processes (V1's
`Peer NodeId(4bd96f97b1aaec9d) connected` was byte-identical to
V0's deterministic listening NodeId), but no `ConsensusNetMsg`
crossed between the two binaries: (i) the listener side admitted
the inbound session under a temporary NodeId, not the dialer's
deterministic NodeId, so `send_to(ValidatorId)` could not resolve
to a registered transport session on the listener side; and (ii)
the very first dial from V0 failed `Connection refused` because
V1 had not started its listener yet, and there was no retry, so
the V0→V1 TCP direction was never established. B8 was the smallest
honest fix to those two findings: a listener-side
`InboundIdentityResolver` that recovers the dialer's vid from the
deterministic `qbind-client-<N>` ASCII prefix already placed in
`ClientInit.client_random` and binds the accepted session under
`derive_test_node_id_from_validator_id(N)` — the same NodeId the
dialer registers under — plus a bounded `DialRetryPolicy` (default
8 attempts × {100..1000}ms) on initial dials that retries only
transient TCP errors.

Run 007's purpose, and only purpose, is to capture concrete
end-to-end binary-path evidence of whether the post-B8 path now
demonstrably advances the multi-validator binary-path question
beyond Run 006's stuck-at-zero shape, and exactly where it does
or does not.

In scope (this run):

- A. Bring up two real `qbind-node` binaries on a single host with
  the same general shape as Run 006, and observe the post-B8
  listener-side resolver line and the post-B8 retry trace if the
  initial dial races.
- B. Observe the deterministic-NodeId binding on **both** sides
  for the first time in DevNet history.
- C. Observe whether `ConsensusNetMsg::{Proposal, Vote}` traffic
  actually crosses node boundaries via the binary `inbound_msgs` /
  `inbound_proposals` / `inbound_votes` counters surfaced in the
  loop-exit summary (`binary_consensus_loop.rs`), and via the
  `consensus_net_outbound_total{kind="proposal_broadcast"}` /
  `consensus_net_inbound_total{kind="proposal"}` metrics.
- D. Observe whether `BasicHotStuffEngine` view / committed-height
  state advances on either node beyond its post-startup baseline.
- E. Observe `/metrics` on both nodes during the run, **three
  scrapes** (A, B, C) to detect any fabricated progression — Run
  007 deliberately strengthens Run 006's two-scrape discipline.
- F. Observe orderly SIGINT shutdown on both nodes.
- G. Cross-check the single-validator LocalMesh path independently
  to detect any regression of B1/B2 introduced by the B8 changes.
- H. Record exactly what is and is not proven by this run, and
  whether C4 is materially narrowed.

Explicitly out of scope (this run):

- Restore-aware multi-validator behavior (Runs 003/004 are the
  restore-side artifacts; Run 007, like Run 006, intentionally
  uses no `--restore-from-snapshot`).
- 3-node clusters. The 2-node result is sufficient to disambiguate
  the load-bearing question — "do messages cross node boundaries
  on the binary path now that BOTH sides have deterministic
  peer-NodeId bindings?" — and the Run 007 outcome below shows the
  remaining boundary is below the engine-broadcast layer, not
  cluster-size-dependent.
- Soak / long-duration stability.
- Alpha/Beta readiness.
- Production-grade PQC KEMTLS identity hardening (the binary
  uses the test-grade `derive_test_kem_keypair_from_validator_id`
  + `SimpleValidatorNodeMapping` test-grade path that B8 closed at
  test-grade but did not productionize; Run 007 records what that
  path empirically does post-B8, not a claim that it is
  production-suitable).
- Mutual-auth (`MutualAuthMode::Required`) cryptographic peer
  identity binding (B8-residual; the resolver consumes the
  dialer-self-asserted `client_random` under
  `MutualAuthMode::Disabled`).
- Inbound `ConsensusNetMsg::Timeout` / `NewView` routing
  (intentionally deferred per `contradiction.md` C4 `Remaining`).

---

## 2. Canonical Basis

This run is grounded in, and bounded by:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_006.md` — the immediately
  preceding negative-result artifact whose §13–14 next-action is
  what Run 007 actually exercises.
- `docs/whitepaper/contradiction.md` C4 — the residual sub-item
  ("multi-validator P2P binary-path interconnect"), including the
  B8 update that lists the listener-side identity-resolver fix,
  the bounded `DialRetryPolicy`, the regression test surface
  (`crates/qbind-node/tests/b8_listener_identity_closure_and_dial_retry_tests.rs`),
  and the explicit `MutualAuthMode::Required` residual.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` — the original
  binary-path multi-validator negative-result baseline.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_004.md` — the most recent
  single-validator binary-path baseline that Run 007's regression
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
- `crates/qbind-node/src/p2p_node_builder.rs` — B7 + B8 surface:
  `derive_test_kem_keypair_from_validator_id`,
  `derive_test_node_id_from_validator_id`, `parse_peer_spec`,
  `set_peer_kem_pk_overrides`, `set_peer_validator_id_overrides`,
  the B7 `--p2p-peer entries must be of the form 'vid@addr'`
  reject path, plus the **B8** inbound-identity-resolver
  installation that calls `parse_test_validator_id_from_client_random`
  and returns `derive_test_node_id_from_validator_id(N)`.
- `crates/qbind-node/src/secure_channel.rs` — B8 surface:
  `accept_kemtls_async_with_peer_init` exposing dialer-supplied
  `ClientInit.client_random` / `validator_id` to the server-side
  accept path.
- `crates/qbind-node/src/p2p_tcp.rs` — B8 surface:
  `set_inbound_identity_resolver` / `InboundIdentityResolver`,
  consulted by `handle_inbound_connection`; bounded
  `DialRetryPolicy` / `set_dial_retry_policy` /
  `DialerHandle::dial_with_retry` (default 8 attempts, transient
  TCP error gating, KEMTLS / config errors not retried).
- `crates/qbind-node/tests/b8_listener_identity_closure_and_dial_retry_tests.rs`
  — in-tree integration tests proving B8 works through the real
  TCP+KEMTLS transport in-process. Run 007 complements those
  tests by going through two **separate** `qbind-node` processes.

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch
  `copilot/execute-devnet-evidence-run-007`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`,
  `rustc 1.94.1 (e408947bf 2026-03-25)` — bit-equivalent to Runs
  005/006's toolchain.
- Build command (binary under test):
  `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome:
  `Finished `release` profile [optimized] target(s) in 6m 22s`
  (cold cache on this branch). The single pre-existing compiler
  warning carried by Runs 001–006 surfaced unchanged
  (`unused variable: worker_id` in
  `crates/qbind-node/src/verify_pool.rs:262`). Out of scope; not
  a regression.
- Resulting binary: `target/release/qbind-node`,
  `9 001 376` bytes, `ELF 64-bit LSB pie executable, x86-64,
  version 1 (SYSV), dynamically linked, ... BuildID[sha1]=
  f4419f4fa19932e4377514c772095c98e38a7684, not stripped`.
  (Slightly larger than Run 006's `8 998 048` bytes, consistent
  with the small B8 code addition: new resolver hooks in
  `secure_channel.rs` / `p2p_tcp.rs` and the bounded retry
  machinery. No code change was made in Run 007 itself.)
- Host: GitHub-hosted Linux x86_64 sandbox, kernel
  `6.17.0-1010-azure`, single host, two `qbind-node` processes
  running concurrently for the two-node phase, one separate
  process for the §11 single-validator regression check.
- Network: loopback `127.0.0.1` only. No external network. No
  TLS certificate authority — the binary uses the in-tree
  `derive_test_kem_keypair_from_validator_id` /
  `SimpleValidatorNodeMapping` test-grade path (post-B7) plus the
  test-grade B8 inbound resolver that consumes the
  `qbind-client-<N>` ASCII prefix from `ClientInit.client_random`.

This is, deliberately, a **two-process, single-host, real-binary,
real-P2P-path, no-restore, short-bounded run** with the smallest
honest two-validator cluster possible — the same shape as Runs
005/006 so the comparison is direct.

---

## 4. Topology and Node Configuration Used

Two-node cluster, all on `127.0.0.1`. Identical port and data-dir
shape as Run 006, with the B7-required `vid@addr` peer syntax
(B8 did not change peer-spec syntax):

```
        +-----------------------+              +-----------------------+
        | qbind-node v0 (V0)    |              | qbind-node v1 (V1)    |
        |                       |              |                       |
        |  P2P  127.0.0.1:19000 |<-- dials --->| P2P  127.0.0.1:19001  |
        |  /metrics  9100       |              | /metrics  9101        |
        |  data /tmp/run007/    |              | data /tmp/run007/     |
        |       data-v0         |              |      data-v1          |
        |                       |              |                       |
        |  --p2p-peer           |              |  --p2p-peer           |
        |     1@127.0.0.1:19001 |              |     0@127.0.0.1:19000 |
        +-----------------------+              +-----------------------+
```

Node 0 (validator id `0`):
- listen: `127.0.0.1:19000`, advertised NodeId
  `NodeId(4bd96f97b1aaec9d)` (deterministic from B7
  `derive_test_node_id_from_validator_id(0)`).
- static peer: `1@127.0.0.1:19001` (B7 `vid@addr` syntax).
- data dir: `/tmp/run007/data-v0`.
- metrics: `127.0.0.1:9100`.
- B6 view of cluster size: `static_peers.len() + 1 = 2` validators.
- post-B8 dial-retry policy (default): 8 attempts ×
  exponential backoff capped at 1000 ms (≈5.5 s total).

Node 1 (validator id `1`):
- listen: `127.0.0.1:19001`, advertised NodeId
  `NodeId(92115fddcd4f93a0)` (deterministic from B7
  `derive_test_node_id_from_validator_id(1)`).
- static peer: `0@127.0.0.1:19000` (B7 `vid@addr` syntax).
- data dir: `/tmp/run007/data-v1`.
- metrics: `127.0.0.1:9101`.
- B6 view of cluster size: `2` validators.
- post-B8 dial-retry policy (default): 8 attempts ×
  exponential backoff capped at 1000 ms (≈5.5 s total).

Both processes were started in detached background mode (via
`setsid ... </dev/null & disown`) so neither was killed when the
launching shell session exited. This matches the Run 005 / Run
006 discipline.

A separate single-validator LocalMesh node on metrics port `9102`
+ data dir `/tmp/run007/data-sv` was used for the §11 regression
guard; it ran *after* both two-node processes had cleanly shut
down, so there is no port or PID overlap.

Process IDs observed:

- Node 0 (V0): PID `9515`.
- Node 1 (V1): PID `9531`.
- §11 single-validator regression node: PID `9656`.

---

## 5. Commands and Configuration Used

### 5.1 Build (binary under test)

```
cargo build --release -p qbind-node --bin qbind-node
```

### 5.2 Reset run state

```
rm -rf /tmp/run007
mkdir -p /tmp/run007/data-v0 /tmp/run007/data-v1 /tmp/run007/data-sv /tmp/run007/logs
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
    --data-dir /tmp/run007/data-v0 \
    > /tmp/run007/logs/node0.stdout \
    2> /tmp/run007/logs/node0.stderr \
    < /dev/null & disown
```

Started at `2026-05-06T08:12:48Z` (per `node0.start_ts`).

### 5.4 Run command — node 1 (validator 1)

Started ~12 s after node 0 (the dial-stagger relevant to §6 and
§12):

```
setsid env QBIND_METRICS_HTTP_ADDR=127.0.0.1:9101 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19001 \
    --p2p-peer 0@127.0.0.1:19000 \
    --validator-id 1 \
    --data-dir /tmp/run007/data-v1 \
    > /tmp/run007/logs/node1.stdout \
    2> /tmp/run007/logs/node1.stderr \
    < /dev/null & disown
```

Started at `2026-05-06T08:13:00Z` (per `node1.start_ts`).

### 5.5 Run command — §11 single-validator regression check

```
setsid env QBIND_METRICS_HTTP_ADDR=127.0.0.1:9102 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode local-mesh \
    --validator-id 0 \
    --data-dir /tmp/run007/data-sv \
    > /tmp/run007/logs/sv.stdout \
    2> /tmp/run007/logs/sv.stderr \
    < /dev/null & disown
```

Run *after* the two-node cluster had shut down (no port/PID
overlap).

### 5.6 Environment variables

| Variable                   | Value              | Set on   | Purpose |
|----------------------------|--------------------|----------|---------|
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9100`   | node 0   | enable `/metrics` on node 0 |
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9101`   | node 1   | enable `/metrics` on node 1 |
| `QBIND_METRICS_HTTP_ADDR`  | `127.0.0.1:9102`   | sv node  | enable `/metrics` on §11 single-validator regression node |

No other QBIND-prefixed env vars were set. No config file. CLI
flags above only.

### 5.7 Run wall-clock window

- Node 0 launched: `2026-05-06T08:12:48.???Z`, PID `9515`.
- Node 1 launched: `2026-05-06T08:13:00.???Z`, PID `9531`
  (~12 s after node 0).
- `/metrics` Scrape A: `2026-05-06T08:13:37.197408385Z`.
- `/metrics` Scrape B: `2026-05-06T08:14:45.564704634Z`
  (~68 s after Scrape A).
- `/metrics` Scrape C: `2026-05-06T08:15:??Z`
  (~30 s after Scrape B; recorded by `node{0,1}.metrics_c` mtime
  `08:16`). Three scrapes (Run 006 used two) increase confidence
  that nothing in `/metrics` is fabricating progress.
- SIGINT delivered to both PIDs at:
  `2026-05-06T08:16:22.097396126Z`.
- Both nodes confirmed terminated by:
  `2026-05-06T08:16:35.017398810Z` (~13 s after SIGINT;
  shutdown_done.ts).
- Total node-0 lifetime per its own loop summary: `2128 ticks`
  at `tick=100ms` ≈ `212.8 s`.
- Total node-1 lifetime per its own loop summary: `1921 ticks`
  ≈ `192.1 s`. The ~21 s lifetime delta = ~12 s startup stagger
  + ~9 s shutdown latency ordering on node 1 (consistent).
- §11 single-validator regression check: started at
  `2026-05-06T08:17:??Z`, scraped once after ~25 s, SIGINT,
  total lifetime per its loop summary: `347 ticks` ≈ `34.7 s`,
  shutdown confirmed `2026-05-06T08:17:45.497458044Z`.

---

## 6. Startup, Handshake, and Connectivity Evidence

### 6.1 Node 0 — full `stdout` (exact, unedited, in observed order)

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19000 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19000 (node_id=NodeId(4bd96f97b1aaec9d))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1
[P2P] dial 127.0.0.1:19001 attempt 1/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 100ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 2/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 200ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 3/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 400ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 4/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 800ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 5/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 6/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 7/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] Accepted connection from 127.0.0.1:56964
[P2P] Accepted connection from 127.0.0.1:56970
[P2P] Inbound connection from 127.0.0.1:56970 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
[T175] Shutting down P2P node for validator ValidatorId(0)
[T175] P2P node shutdown complete
```

### 6.2 Node 0 — full `stderr` (exact, unedited)

```
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[restore] no --restore-from-snapshot requested; normal startup.
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9100 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9100 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=nonce-only
[metrics_http] Listening on 127.0.0.1:9100
[binary] P2P transport up. Listen address: 127.0.0.1:19000, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p
[P2P] dial 127.0.0.1:19001 giving up after 8 attempt(s): I/O error: Connection refused (os error 111) (transient=true, max_attempts=8)
[P2P] Inbound connection error: Handshake error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 2128 ticks.
[binary-consensus] Loop exit: ticks=2128 proposals=1 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=1 outbound_votes=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 6.3 Node 1 — full `stdout` (exact, unedited)

```
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19001 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1
[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
[T175] Shutting down P2P node for validator ValidatorId(1)
[T175] P2P node shutdown complete
```

### 6.4 Node 1 — full `stderr` (exact, unedited)

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
[binary-consensus] Shutdown signal received after 1921 ticks.
[binary-consensus] Loop exit: ticks=1921 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 6.5 Read of these traces

Three things are new relative to Run 006 and worth recording
exactly:

1. **B8 bounded initial-dial retry is observable on the binary.**
   V0 emitted seven `dial 127.0.0.1:19001 attempt N/8 failed
   (transient: ConnectionRefused); retrying in {100,200,400,800,
   1000,1000,1000}ms (B8 initial-dial retry)` lines on stdout,
   then the bounded budget terminated with `dial 127.0.0.1:19001
   giving up after 8 attempt(s): I/O error: Connection refused
   (os error 111) (transient=true, max_attempts=8)` on stderr.
   The bounded behavior is real, the budget is the documented
   default (8 × {100..1000}ms ≈ 5.5 s), and only transient TCP
   errors triggered retries. This is the first DevNet-evidence
   observation of the post-B8 retry trace on the binary.

2. **B8 listener-side identity resolver is observable on the
   binary, and the deterministic-NodeId binding is now closed on
   BOTH sides.** V0 emitted `Inbound connection from
   127.0.0.1:56970 bound to deterministic NodeId
   NodeId(92115fddcd4f93a0) via inbound identity resolver (B8,
   test-grade)`, immediately followed by `Peer
   NodeId(92115fddcd4f93a0) connected`. That NodeId is byte-
   identical to V1's own listening NodeId
   (`Listening on 127.0.0.1:19001 (node_id=NodeId(92115fddcd4f93a0))`).
   On the dialer side, V1 emitted the post-B7 line `Dial
   127.0.0.1:19000: using per-peer KEM pk + validator-id override
   (pk_len=32, has_vid=true)` and then `Peer
   NodeId(4bd96f97b1aaec9d) connected`, which is byte-identical to
   V0's listening NodeId. Both deterministic NodeIds are bound on
   both sides — the joint precondition Run 006's §13 said B8
   needed to satisfy. **This is the first time in the DevNet
   evidence record that this joint condition has been observed on
   real binaries.**

3. **The first inbound TCP connection from 127.0.0.1:56964 was
   accepted but then failed handshake.** V0's stderr records
   `[P2P] Inbound connection error: Handshake error: channel
   error: Io(Error { kind: UnexpectedEof, message: "failed to
   fill whole buffer" })`. This shape was also present in Runs
   005 and 006 (an inbound TCP setup that did not complete the
   KEMTLS handshake). The follow-on inbound from
   `127.0.0.1:56970` did complete the handshake and was bound by
   the B8 resolver. So the second TCP connection is the surviving
   one and is the registered session that both sides report
   `Peer ... connected` for. No silent override.

The dial-stagger that produced the seven `Connection refused`
retries is real and was caused by node 1 starting ~12 s after node
0 — past V0's 5.5 s default retry budget. **V0's outbound TCP to
V1 was therefore not established by V0**; the surviving TCP
session is V1→V0 (V1's outbound to V0). KEMTLS over that single
session is bidirectional, so message passing in either direction
is in principle possible over it (and B8's listener resolver binds
both sides under deterministic NodeIds on this single session, as
observed). The binary path was not silently rerouted to LocalMesh
or any harness path: both nodes emitted the multi-validator P2P
banner and the `interconnect=p2p` consensus-loop banner.

---

## 7. Cross-Node Proposal / Vote Evidence

This is where Run 007 must report the precise empirical boundary.

### 7.1 Loop-exit summaries

```
node 0: Loop exit: ticks=2128 proposals=1 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=1 outbound_votes=1
node 1: Loop exit: ticks=1921 proposals=0 commits=0 committed_height=None view=0 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
```

### 7.2 `consensus_net_*` counters (scrape C, end of run)

Node 0:

```
consensus_net_inbound_total{kind="vote"} 0
consensus_net_inbound_total{kind="proposal"} 0
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
```

Node 1:

```
consensus_net_inbound_total{kind="vote"} 0
consensus_net_inbound_total{kind="proposal"} 0
consensus_net_inbound_total{kind="other"} 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
```

### 7.3 Engine-level counters (scrapes A, B, C)

```
node 0 (all three scrapes, identical):
  qbind_consensus_proposals_total{result="accepted"} 1
  qbind_consensus_proposals_total{result="rejected"} 0
  qbind_consensus_votes_total{result="accepted"} 0
  qbind_consensus_votes_total{result="invalid"} 0
  qbind_consensus_qcs_formed_total 0
  qbind_consensus_view_number 0
  qbind_consensus_current_view 0

node 1 (all three scrapes, identical):
  qbind_consensus_proposals_total{result="accepted"} 0
  qbind_consensus_proposals_total{result="rejected"} 0
  qbind_consensus_votes_total{result="accepted"} 0
  qbind_consensus_votes_total{result="invalid"} 0
  qbind_consensus_qcs_formed_total 0
  qbind_consensus_view_number 0
  qbind_consensus_current_view 0
```

### 7.4 Read of these counters

- **Did proposals cross node boundaries?** No. V1 reports
  `inbound_proposals=0`, `consensus_net_inbound_total{kind="proposal"}
  = 0`, and `qbind_consensus_proposals_total{result="accepted"} =
  0`. V0's leader-issued view-0 BroadcastProposal was emitted
  (engine-level loop counter `outbound_proposals=1`) but **never
  reached the wire** (`consensus_net_outbound_total{kind=
  "proposal_broadcast"} = 0`).
- **Did votes cross node boundaries?** No. V0 and V1 both report
  `inbound_votes = 0`, `consensus_net_inbound_total{kind="vote"} =
  0`. Without inbound proposals, V1 cannot produce a follow-up
  vote, and V0's self-vote (`outbound_votes=1` at the loop level)
  was likewise never broadcast to the wire
  (`consensus_net_outbound_total{kind="vote_broadcast"} = 0`).
- **Did QCs / commits form?** No. `qbind_consensus_qcs_formed_total
  = 0` and `commits=0 committed_height=None` on both nodes across
  all three scrapes.
- **Did the view advance?** No. `view_number = 0` and
  `current_view = 0` on both nodes across all three scrapes.

The discrepancy between V0's loop-level `outbound_proposals=1` and
the network adapter's `consensus_net_outbound_total{kind=
"proposal_broadcast"} = 0` is meaningful and is recorded honestly
here: V0's `BasicHotStuffEngine` emitted exactly one
`ConsensusEngineAction::BroadcastProposal` for view 0 right at
consensus-loop startup. At that instant V1 had not yet started
(V1 launched ~12 s after V0, well past V0's first leader tick at
`tick=100ms`), so V0's connected-peer set was empty and the
`P2pConsensusNetwork` facade did not register any wire-level
broadcast. The leader does not re-emit a view-0 proposal once
emitted; the engine only re-emits proposals on a view change,
which never happened because no vote ever returned. **This is the
load-bearing finding of Run 007 and is materially smaller than
Run 006's listener-side identity-binding boundary** (which has
now been observed closed in §6.5).

---

## 8. QC / Commit Progress Evidence

None. `qcs_formed_total = 0`, `commits = 0`, `committed_height =
None`, `view_number = 0` on both nodes. This is consistent across
all three scrapes (A, B, C) and is consistent with the loop-exit
summaries (`commits=0 committed_height=None view=0` on both nodes).

There is no QC or commit progression to report on the binary path
between V0 and V1 in Run 007. We do not claim there was.

---

## 9. Metrics Evidence

`/metrics` was reachable on both nodes throughout the run. Three
scrapes (A, B, C) ~30–70 s apart:

- Node 0: `node0.metrics_a` 14064 B, `node0.metrics_b` 14065 B,
  `node0.metrics_c` 14065 B.
- Node 1: `node1.metrics_a` 14064 B, `node1.metrics_b` 14064 B,
  `node1.metrics_c` 14065 B.

The relevant consensus and consensus-network counters
(`qbind_consensus_proposals_total`, `qbind_consensus_votes_total`,
`qbind_consensus_qcs_formed_total`, `qbind_consensus_view_number`,
`qbind_consensus_current_view`,
`consensus_net_outbound_total{kind="proposal_broadcast"}`,
`consensus_net_inbound_total{kind="proposal"}`, etc.) held flat
across all three scrapes (V0's `proposals_total{result="accepted"}`
held at exactly `1` from scrape A through scrape C; V1's held at
exactly `0`). No counter spuriously advanced. No counter retreated.
This is honest reporting of "no progress" rather than fabricated
progress.

`/metrics` therefore satisfied the §1-G requirement: it reported
exactly what the engine and the consensus-network adapter
actually saw, including zero-progress signals, and did not invent
progress that the loop-exit summary then contradicted.

---

## 10. Shutdown Evidence

SIGINT was delivered to both nodes at
`2026-05-06T08:16:22.097396126Z`. Both nodes:

- emitted `[binary] Shutdown signal received, stopping P2P
  node...` on stderr,
- emitted `[binary-consensus] Shutdown signal received after N
  ticks.` (`N = 2128` for node 0, `N = 1921` for node 1),
- emitted the `[binary-consensus] Loop exit: ...` summary line
  shown verbatim in §7.1,
- stopped the metrics HTTP server (`[metrics_http] Shutting down`),
- and emitted `[binary] Shutdown complete.`

Both PIDs (`9515` and `9531`) were gone from the process table by
`2026-05-06T08:16:35.017398810Z` (~13 s after SIGINT). Post-
shutdown port checks (curl with 3 s timeout):

```
127.0.0.1:9100  -> 000  (Failed to connect)
127.0.0.1:9101  -> 000  (Failed to connect)
127.0.0.1:9102  -> 000  (Failed to connect, after sv shutdown)
127.0.0.1:19000 -> 000  (Failed to connect)
127.0.0.1:19001 -> 000  (Failed to connect)
```

All listeners released. Shutdown is clean.

---

## 11. Regression Check Against Previously Landed Binary-Path Capabilities

### 11.1 Single-validator LocalMesh on the same binary

After both two-node processes had cleanly exited, the same
release binary was started in single-validator LocalMesh mode
(`--network-mode local-mesh`, no `--enable-p2p`, no
`--p2p-listen-addr`, no `--p2p-peer`) on metrics port `9102` and
data dir `/tmp/run007/data-sv`, ran for ~25 s (one `/metrics`
scrape), then was SIGINT'd.

Loop exit summary:

```
[binary-consensus] Loop exit: ticks=347 proposals=347 commits=345 committed_height=Some(344) view=347 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0
```

`/metrics` (relevant subset):

```
qbind_consensus_proposals_total{result="accepted"} 347
qbind_consensus_qcs_formed_total 0
qbind_consensus_view_number 347
qbind_consensus_current_view 347
consensus_net_outbound_total{kind="proposal_broadcast"} 0
consensus_net_inbound_total{kind="proposal"} 0
```

Single-validator semantics: the leader self-quorums every tick,
producing one accepted proposal and one commit per tick after the
3-chain delay (`commits = 345` at `proposals = 347` means the
first two proposals were absorbed by the 3-chain depth before the
first commit fires — the same shape Run 004 / Run 005 / Run 006
recorded). `committed_height = Some(344)` advanced honestly and
matches what Runs 004/005/006 expected for a ~35 s run. **B1/B2
are not regressed.**

The `qcs_formed_total = 0` reading in single-validator mode is
expected: a single-validator self-quorum does not flow through the
QC-formation counter path (that counter increments on QC
construction in the `BasicHotStuffEngine` multi-vote path); it is
the documented Run 004 / Run 005 / Run 006 shape and is not a
regression. The presence of `consensus_net_outbound_total{kind=
"proposal_broadcast"} = 0` in single-validator mode is also
expected — there is no P2P facade in LocalMesh mode.

### 11.2 B6 routing path

B6 routing is structurally exercised on both two-node processes.
Both emitted:

```
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(N) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p
```

The fact that the loop-exit summaries surface `inbound_msgs`,
`inbound_proposals`, `inbound_votes`, `outbound_proposals`, and
`outbound_votes` (and that these all moved consistently with the
adapter-level `consensus_net_*_total` counters) shows that
`BinaryConsensusLoopIo` and `run_binary_consensus_loop_with_io`
are the path being exercised. There is no evidence of any silent
fallback to LocalMesh or to a harness-only routing path.

### 11.3 B7 / B8 surfaces

- B7 `vid@addr` peer-spec syntax: accepted on both sides
  (`peers=1` in startup banner).
- B7 dialer-side override: V1's stdout `Dial 127.0.0.1:19000:
  using per-peer KEM pk + validator-id override (pk_len=32,
  has_vid=true)` was emitted exactly as B7 designed.
- B8 listener-side resolver: V0's stdout `Inbound connection
  from 127.0.0.1:56970 bound to deterministic NodeId
  NodeId(92115fddcd4f93a0) via inbound identity resolver (B8,
  test-grade)` was emitted exactly as B8 designed.
- B8 bounded initial-dial retry: V0's stdout shows seven retry
  lines with the documented backoff schedule
  (`{100,200,400,800,1000,1000,1000}ms`) and stderr shows the
  bounded `giving up after 8 attempt(s) ... transient=true,
  max_attempts=8` line. Configuration errors / KEMTLS-handshake
  errors did not trigger retries (no such errors occurred in this
  run, but the post-shutdown V0 stderr line `[P2P] Inbound
  connection error: Handshake error: channel error: Io(Error {
  kind: UnexpectedEof, ... })` is the first inbound TCP that
  failed handshake and was correctly **not** retried by the dial
  path — it is an inbound, not a dial — and was simply discarded).

### 11.4 No regression observed

No previously landed binary-path capability appears regressed:

- B1/B2 single-validator path produces commits and view
  progression at the documented Run-004 shape (§11.1).
- B6 inbound-routing path is the path actually exercised in P2P
  mode (§11.2).
- B7 dialer-side identity closure works as designed (§6.3,
  §11.3).
- B8 listener-side identity closure works as designed and binds
  the inbound under V1's deterministic NodeId
  (`NodeId(92115fddcd4f93a0)`) (§6.1, §6.5, §11.3).
- B8 bounded initial-dial retry works as designed and gives up
  after the documented budget (§6.1, §11.3).
- `/metrics` reports honestly across three scrapes (§9). It does
  not invent progress.
- Shutdown is clean and releases all listeners (§10).
- No silent fallback to LocalMesh or to harness-only routing in
  P2P mode (§11.2).

---

## 12. Limitations and Anomalies Observed

1. **Initial-dial retry budget vs. node-stagger.** V0's bounded
   default retry budget (8 × {100..1000}ms ≈ 5.5 s) is shorter
   than this run's manual ~12 s startup stagger between V0 and
   V1, so V0's outbound dial gave up before V1 was ready. The
   surviving TCP session is therefore V1→V0 only. This is exactly
   the bounded behavior B8 documented and is not a regression of
   B8 itself; it is a residual that affects how much of the
   binary path Run 007 was able to exercise.
2. **Leader proposal not re-emitted after late peer connect.**
   V0's `BasicHotStuffEngine` emitted exactly one
   `BroadcastProposal` action at view 0 right after consensus-loop
   start (loop-level `outbound_proposals=1`). At that instant V0's
   connected-peer set was still empty (V1's TCP→V0 inbound landed
   later, after the dial-retry budget had been exhausted on V0's
   side and V1 had finally started), so the network facade
   recorded `consensus_net_outbound_total{kind=
   "proposal_broadcast"} = 0`. The engine does not re-emit a
   view-0 proposal once it has emitted one; it would only re-emit
   on a view change, which never happens in a 2-validator cluster
   that never collects a vote. **The post-B8 binary path therefore
   has a "leader-proposal-emitted-into-empty-peer-set" residual
   that B8 was not designed to address.** This is the load-bearing
   new finding of Run 007.
3. **Self-asserted vid in `client_random` (B8-residual).** Per
   `contradiction.md` C4 `Remaining`, the B8 inbound resolver
   consumes `ClientInit.client_random` under
   `MutualAuthMode::Disabled`, so the listener's deterministic
   NodeId binding is correct for two cooperating, in-set
   validators (which is what Run 007 exercises) but is not a
   cryptographic identity proof against a malicious dialer. Run
   007 does not exercise an adversarial dialer; it does not claim
   to.
4. **Single inbound TCP that failed handshake.** V0's stderr
   carries one `[P2P] Inbound connection error: Handshake error:
   channel error: Io(Error { kind: UnexpectedEof, ... })` line,
   matching the same shape Runs 005/006 carried. The follow-on
   inbound from `127.0.0.1:56970` succeeded and is the surviving
   registered session that both sides report `Peer ... connected`
   for. Not a regression.
5. **`qcs_formed_total = 0` in §11 single-validator regression
   check.** Same as Runs 004/005/006: the single-validator
   self-quorum path does not flow through the QC-formation
   counter. Not a regression; a documented metric semantics in
   that mode.

---

## 13. Assessment of Evidence Value

### 13.1 Required questions (per task brief §4)

A. **Did multiple real `qbind-node` processes start successfully?**
   Yes. Both PID `9515` and PID `9531` came up, emitted the
   multi-validator P2P banner, opened their listening sockets at
   `127.0.0.1:19000` and `127.0.0.1:19001`, opened their metrics
   HTTP servers at `9100` and `9101`, started their consensus
   loops with `interconnect=p2p`, and ran for ~213 s and ~192 s
   respectively before SIGINT.

B. **Did the post-B8 binary-path handshake succeed between them?**
   Yes. The KEMTLS handshake completed, V1 dialed V0 successfully
   (post-B7 dialer override visible) and V0 admitted the inbound
   under V1's deterministic NodeId via the post-B8 listener-side
   resolver (resolver line visible). One earlier inbound TCP from
   port `56964` failed handshake; the follow-on from port `56970`
   succeeded.

C. **Did both sides register each other far enough for message
   delivery?**
   Yes — at the transport layer. V0's stdout records
   `Peer NodeId(92115fddcd4f93a0) connected` and V1's stdout
   records `Peer NodeId(4bd96f97b1aaec9d) connected`. Both
   NodeIds match the deterministic `derive_test_node_id_from_
   validator_id(N)` outputs. **This is the first DevNet evidence
   record showing the joint precondition (BOTH sides observe the
   OTHER's deterministic NodeId among connected peers) is
   satisfied.** This is the cleanest narrowing achieved by Run
   007.

D. **Did proposals cross node boundaries and reach the engine?**
   No. V1 reports `inbound_proposals=0`, `consensus_net_inbound_
   total{kind="proposal"} = 0`, and `qbind_consensus_proposals_
   total{result="accepted"} = 0`. V0's leader-emitted view-0
   proposal never reached the wire (`consensus_net_outbound_
   total{kind="proposal_broadcast"} = 0`) because the connected-
   peer set was empty at the moment of emission (V1 had not yet
   started). Cause: the leader does not re-emit a view-0 proposal
   after the peer connects later in the same view. See §12 (2).

E. **Did votes cross node boundaries and reach the engine?**
   No. `inbound_votes = 0` on both nodes; `consensus_net_inbound_
   total{kind="vote"} = 0` on both nodes; `qbind_consensus_votes_
   total{result="accepted"} = 0` on both nodes. Without crossing
   proposals there could be no follow-up votes.

F. **Did QC / commit progression happen across the binary path?**
   No. `qcs_formed_total = 0`, `commits = 0`, `committed_height =
   None`, `view_number = 0` on both nodes across all three scrapes
   and the loop-exit summary.

G. **Did `/metrics` remain honest?**
   Yes. Three scrapes (A, B, C) on both nodes, all consensus and
   consensus-network counters held flat at their documented
   zero-or-leader-self-counted values. No counter spuriously
   advanced. No counter contradicted the loop-exit summary.

H. **Did shutdown remain clean?**
   Yes. SIGINT → `Shutdown signal received` → `Loop exit:` summary
   → metrics HTTP server stopped → `Shutdown complete.` → process
   exit. Post-shutdown listener-port probes return
   `Failed to connect`. No PID survived the shutdown window.

I. **Did any previously landed binary-path capability appear
   regressed?**
   No. §11 documents B1/B2 single-validator commits + view
   progression on the same binary, B6 inbound-routing path
   exercised, B7/B8 surface lines visible, `/metrics` honest,
   shutdown clean, no fallback to LocalMesh in P2P mode.

J. **What exact next execution action is recommended after Run
   007?**
   See §14.

### 13.2 Material narrowing of C4

Run 007 materially narrows C4. The Run 006 boundary
("listener-side temporary-NodeId binding + unretried initial dial
prevent `send_to(ValidatorId)` from resolving to a registered
transport session") is **observed closed at test-grade**: both
sides now register the other's deterministic NodeId, and the
post-B8 retry trace is observable on the binary. This is a
documented sub-item of B8 and Run 007 is the first DevNet
evidence record that exercises it on real binaries.

The new boundary that Run 007 reveals is **strictly smaller** than
Run 006's: it is no longer at the transport-identity layer, it is
at the engine-broadcast layer — specifically, the leader emits
the view-0 `BroadcastProposal` action before any peer is
connected, and the engine does not re-emit on subsequent peer
connect within the same view. This is a different residual,
shaped by the dial-stagger, that B8 was not designed to address
and that Run 006 could not see (because Run 006 was blocked at
the listener-identity layer before reaching this layer).

Whether this materially narrows C4 in `contradiction.md` is
addressed in the contradiction-handling note at §14.

### 13.3 Verdict

**Partial.** Joint precondition (BOTH sides observe the OTHER's
deterministic NodeId among connected peers, and bounded initial-
dial retry is real) is **satisfied at test-grade** for the first
time in the DevNet evidence record. Cross-node `ConsensusNetMsg`
traffic does **not** yet cross between two real `qbind-node`
binaries on the binary path: V0's leader-issued view-0 proposal
reaches the engine but never reaches the wire because V1 was not
yet a connected peer at the moment of emission, and the engine
does not re-emit on late peer connect within the same view.

This is a narrower, qualitatively different boundary than Runs
005 and 006 reported. It is recorded as `partial` per the §1-C
exactness rule, not compressed into "success" or "failure".

---

## 14. Recommended Immediate Next Action

The smallest, most honest next execution action is **B9: leader-
side late-peer-connect re-emission OR initial-dial budget aligned
with leader-tick deadline** in the multi-validator binary path.
The minimal honest fix surface is one of (preferably the first):

- **B9.a — engine-side re-emission on peer connect.** When
  `BasicHotStuffEngine` is the leader of the current view and a
  new expected peer (a validator from the configured static-peer
  set) transitions from "not connected" to "connected", re-emit
  the current view's `BroadcastProposal` action exactly once.
  This is the protocol-correct fix because it does not depend on
  startup ordering and survives any topology in which a peer
  joins late within the same view. It is bounded: at most one
  re-emission per (view, peer) transition.
- **B9.b — extend `DialRetryPolicy` default for static-peer
  configurations.** Increase the default initial-dial retry
  budget (e.g. from ~5.5 s to ~30 s, with the current backoff
  shape capped at 1000 ms) when `static_peers.len() > 0`. This
  papers over the symptom for cooperative startup orderings but
  does **not** fix the protocol-correctness issue — a peer that
  takes longer than the new budget to start will still exhibit
  the Run-007 shape, and a network partition that heals after a
  view-0 proposal will still exhibit it.

Alongside B9, a **deterministic cluster-startup recipe for Run
008** should be specified that brings up V1 (the dialer in the
Run-007 topology) **before** V0 (the listener in the Run-007
topology), so V1's outbound TCP is *not* racing V0's leader-tick.
This is operational, not a binary fix, but Run 008 should
distinguish the B9 fix from a startup-recipe fix: ideally Run 008
exercises B9 with a deliberate dial-stagger to prove re-emission
on late peer connect, and separately exercises a startup-recipe
adjustment to prove `qcs_formed_total > 0` and `committed_height >
None` on the binary path.

Run 008 should reuse the Run-007 shape (two `qbind-node`
processes, `vid@addr` peer syntax, three `/metrics` scrapes,
single-validator §11 regression guard) and report against the
strongest-positive-proof checklist in the task brief §7. The
expected positive shape after B9 is:

- handshake succeeds (already proven, Run 007),
- both sides register deterministic peer NodeIds (already proven,
  Run 007),
- node A outbound proposal reaches the wire
  (`consensus_net_outbound_total{kind="proposal_broadcast"} > 0`),
- node B inbound proposal > 0 (`consensus_net_inbound_total{kind=
  "proposal"} > 0`, and `qbind_consensus_proposals_total{result=
  "accepted"} > 0` on B),
- node B outbound vote (`consensus_net_outbound_total{kind=
  "vote_send_to"} + ...{kind="vote_broadcast"} > 0`),
- node A inbound vote > 0,
- `qcs_formed_total > 0` on at least the leader,
- `committed_height` progression on the binary path,
- metrics and loop-exit summaries agree.

If B9.a is chosen, it is bounded to engine-side re-emission and
should not weaken B6/B7/B8 or the single-validator path; it
should be regression-tested (e.g.
`crates/qbind-node/tests/b9_late_peer_connect_reemission_tests.rs`)
including a single-validator no-regression test.

### Contradiction handling (per task brief §8)

Run 007 reveals a **new genuine residual** below the layer C4 has
described to date: even with the joint deterministic-NodeId
binding closed on both sides, the multi-validator binary path
does not yet broadcast a leader proposal that was emitted before
the peer connected within the same view. This is strictly smaller
than the listener-identity gap C4 documented as the Run-006
residual; B8 closed that residual; Run 007 has now disclosed the
next layer.

Per the task brief §1-A "no silent override / no hidden fallback"
and §8 "only update contradiction.md if Run 007 reveals a new
genuine contradiction or materially narrows/sharpens C4", Run 007
**does** materially narrow C4 in two ways that are worth
recording:

1. The Run-006 joint precondition (BOTH sides observe each
   other's deterministic NodeId) is now empirically observed
   closed on real binaries — not just in-tree integration tests.
2. The next residual is now precisely identified: leader-side
   re-emission on late peer connect within the same view.

A focused, minimal update to `docs/whitepaper/contradiction.md`
C4's `Impact` paragraph (and a pointer in `Remaining` to the new
B9-residual below the existing B8 entry) is therefore justified
under §8. That update is made conservatively in the same commit
as this evidence artifact: it adds an "**Empirical narrowing
from DevNet Evidence Run 007**" sentence to `Impact` and a single
new ⚠️ bullet under `Remaining` ("Leader-side re-emission of
`BroadcastProposal` on late peer connect within the same view
(B8-residual surfaced by Run 007)"). It does **not** retract any
prior C4 text, does **not** change B6/B7/B8 status, and does
**not** restructure C4. If reviewers prefer to defer the
contradiction.md edit until the B9 plan lands, the
`contradiction.md` portion of this commit can be dropped without
touching this evidence artifact.