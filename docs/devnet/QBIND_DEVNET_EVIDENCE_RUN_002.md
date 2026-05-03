# QBIND DevNet Evidence Run 002

**Status:** Internal evidence record — second single-validator DevNet
binary-path run. Targets the specific limitation surfaced and recorded by
Run 001: that `/metrics` did not previously carry live consensus progress.
**Audience:** Internal — protocol engineering, ops, release management.
**Run date:** 2026-05-03 (UTC).
**Author:** Execution follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_001.md` §11 (Option A, default
recommendation), now that the bounded observability fix landed in
`crates/qbind-node/src/binary_consensus_loop.rs`.

> This document is a focused second evidence artifact. It is **not** a
> Beta-readiness statement, **not** a multi-validator demonstration,
> **not** a soak result, and **not** a full monitoring-baseline pass.
> It exists to record, exactly, whether `/metrics` from the real
> `qbind-node` binary now reflects live consensus progress during a
> short single-validator run, and to compare that against Run 001.

---

## 1. Purpose and Scope

Run 001 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_001.md`) established that
the real `qbind-node` binary starts, drives a real `BasicHotStuffEngine`
consensus loop, advances views/proposals/commits, serves `/metrics` over
HTTP, and shuts down cleanly on `SIGINT`. Run 001 also confirmed live —
not just predicted — the single material limitation: while the engine was
visibly committing (78 / 58 commits in two short runs), the
consensus-class metric series in the `/metrics` body remained at 0
(see Run 001 §7.3).

That limitation was the basis for Run 001 §11 Option A: wire the binary
consensus loop into the existing `Arc<NodeMetrics>` so `/metrics` reflects
live engine state. That bounded observability change has since landed
(`crates/qbind-node/src/binary_consensus_loop.rs:46–77, 184, 240–254`,
296). The change is bounded — it only updates already-existing
`NodeMetrics` families from observed engine state on each real tick; it
adds no new metric families and touches nothing when the loop is not
running.

Run 002's purpose, and only purpose, is to capture concrete evidence of
whether `/metrics` itself now carries live consensus progress on the
real binary path.

In scope (this run):

- A. Repeat the Run 001 single-validator binary-path startup shape.
- B. Verify the binary-path consensus loop still progresses (views,
  proposals, commits) exactly as in Run 001.
- C. Scrape `/metrics` **twice** during a single live run, separated
  in wall-clock time, and compare the consensus-class series across
  the two scrapes — the only honest way to demonstrate "live progress
  visible in `/metrics`" without trusting any single sample.
- D. Verify clean `SIGINT` shutdown is unchanged.
- E. Compare directly against Run 001 §7.3.
- F. Decide whether Run 001's recorded `/metrics` limitation is closed.

Explicitly out of scope (this run):

- Multi-validator binary-path DevNet (LocalMesh fan-in or P2P).
- Restore-from-snapshot evidence (B3).
- Soak / 72-hour stability evidence.
- Full Class-A / Class-B / Class-C coverage of
  `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` (this run does
  not purport to satisfy the monitoring baseline; it only retires the
  one specific Run 001 gap).
- Operator drill catalog instantiation, `/health`/`/ready`, RPC.
- Any change to `contradiction.md` C4's open items B3 or the multi-validator
  P2P→consensus interconnect; both remain out of scope here. See §10.3.

---

## 2. Canonical Basis

This run is grounded in, and bounded by:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_001.md`
  — §7.3 (the limitation Run 002 targets), §11 Option A (the
  recommended next action this run executes), §10.3 (the
  contradiction-tracker decision Run 002 reassesses).
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` (EXE-2)
  — §5.3 / §6.4 (predicted gap), §7 (supported single-validator
  binary-path mode), §10 (next-action ordering).
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`
  — referenced indirectly to qualify *which* observability evidence
  this run does and does not satisfy (it satisfies the binary-path
  basic-liveness portion of the consensus-class signal expectation
  from a single validator; see §7 below).
- `docs/whitepaper/contradiction.md`
  — C4 (still OPEN; B3 still outstanding; multi-validator
  P2P→consensus interconnect still outstanding). Re-evaluated in §10.3.
- The binary-path metrics-wiring change in
  `crates/qbind-node/src/binary_consensus_loop.rs` lines 46–77 (intent),
  lines 184 and 296 (signature: `Arc<NodeMetrics>` is now plumbed in),
  lines 240–254 (the actual per-tick metric updates derived from
  observed engine state), and the in-tree tests in `mod tests` that
  exercise the loop end-to-end.

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch
  `copilot/execute-single-validator-devnet-evidence-collectio`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`,
  `rustc 1.94.1 (e408947bf 2026-03-25)`.
- Build command: `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome: `Finished `release` profile [optimized] target(s) in 6m 18s`
  (clean from cold cache).
  - The same single pre-existing compiler warning carried by Run 001
    surfaced unchanged (`unused variable: worker_id` in
    `crates/qbind-node/src/verify_pool.rs:262`). Out of scope for this run.
- Resulting binary: `target/release/qbind-node`, ≈ 8.4 MiB
  (8 782 736 bytes), executable.
- Host: GitHub-hosted Linux x86_64 sandbox (single host, single process,
  no peers).
- Network: no `--enable-p2p`; default `LocalMesh`, single-validator
  (no `--p2p-peer`).

This is, exactly as in Run 001, a **single-validator, single-host,
binary-path, LocalMesh, no-P2P, short-bounded run**. Nothing more.

---

## 4. Commands and Configuration Used

### 4.1 Build

```
cargo build --release -p qbind-node --bin qbind-node
```

### 4.2 Run command (canonical EXE-2 §7 single-validator-with-metrics shape, identical to Run 001)

```
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node --env devnet --validator-id 0
```

This is the exact shape recorded in `crates/qbind-node/src/main.rs`
("DevNet single-node smoke (LocalMesh, real consensus loop, metrics on)")
and in `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` §7 ("Single-validator
DevNet with metrics: YES"). It is unchanged from Run 001 §4.2 — that is
deliberate, so any change in `/metrics` behaviour between Run 001 and
Run 002 is attributable only to the binary-side observability fix and
not to a configuration drift.

### 4.3 Bounded-run wrappers used for evidence capture

To produce reproducible, ordered shutdowns without an interactive
`Ctrl+C`, the process was started under
`timeout --foreground -s INT <seconds>`; that is the same `SIGINT` a
human operator's `Ctrl+C` would deliver and the same signal
`tokio::signal::ctrl_c()` listens for in
`crates/qbind-node/src/main.rs::run_local_mesh_node`. No code path in
`qbind-node` was modified for this run.

Two short bounded runs were executed:

- **Run 1** — 8-second bound, full startup → progression → shutdown
  capture. Identical wrapper shape to Run 001's Run 1, used here to
  confirm that startup, progression, and shutdown remain unchanged.
- **Run 2** — 7-second bound; while it was running, `/metrics` was
  scraped twice — once shortly after the metrics listener became
  reachable (**Scrape A**, "early"), and again after a four-second
  wait (**Scrape B**, "late"). Comparing A vs. B is the load-bearing
  evidence in this document: it shows live progression *inside the
  `/metrics` body itself*, not from logs.

### 4.4 Environment variables

Only one environment variable was set, and only at the run-command
level — identical to Run 001:

| Variable | Value | Purpose |
|---|---|---|
| `QBIND_METRICS_HTTP_ADDR` | `127.0.0.1:9100` | Enable `/metrics` HTTP server. Read by `MetricsHttpConfig::from_env()` (`crates/qbind-node/src/metrics_http.rs`, called from `main.rs:126`). |

No other QBIND-prefixed env vars were set. No config file was used.
CLI flags were `--env devnet --validator-id 0` only. All other settings
come from `NodeConfig::devnet_v0_preset` (`crates/qbind-node/src/node_config.rs`).

### 4.5 Effective configuration as logged by the binary itself

From the binary's own `log_startup_info` output (Run 1 and Run 2,
identical, stdout, line 1):

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600
  scope=DEV profile=nonce-only network=local-mesh p2p=disabled gas=off
  fee-priority=off fee_distribution=burn-only mempool=fifo
  dag_availability=disabled dag_coupling=off stage_b=disabled
  diversity=off(prefix24=2,prefix16=8,buckets>=4)
```

Byte-identical to the Run 001 startup banner. No silent deviation from
the documented DevNet preset, and no drift from Run 001.

---

## 5. Startup Evidence

### 5.1 Captured startup log (Run 1 — exact, unedited, in observed order)

`stdout` (single line):

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=local-mesh p2p=disabled gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
```

`stderr`, in order of emission:

```
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9100 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9100 (set via QBIND_METRICS_HTTP_ADDR)
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=1
[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick.
[binary] Consensus loop running. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms
[metrics_http] Listening on 127.0.0.1:9100
```

### 5.2 What this evidences

Observed (direct):

- The binary process started successfully — no early exit, no panic,
  no config-validation failure, no new banner introduced or removed
  by the metrics-wiring change.
- `MetricsHttpConfig::from_env()` correctly read
  `QBIND_METRICS_HTTP_ADDR` and the metrics listener attached to
  `127.0.0.1:9100`.
- `run_binary_consensus_loop` (`binary_consensus_loop.rs:180`) was
  entered with `local_id=ValidatorId(0) num_validators=1 tick=100ms`,
  exactly as in Run 001 §5.1.
- Run 2's startup banners are byte-identical to Run 1's (verified
  against `/tmp/run002/run2.stderr`); not duplicated here.

Comparison vs. Run 001:

- Identical stdout banner, identical stderr banners, identical
  ordering. The metrics-wiring change did not perturb the startup
  path.

Not observed (and acknowledged):

- No `--profile mainnet`, no `validate_mainnet_invariants()` banner.
  Expected: DevNet, not MainNet.
- No P2P transport startup banner. Expected: `--enable-p2p` not passed.

---

## 6. Consensus Progress Evidence

### 6.1 Final consensus-loop summary lines emitted by the binary

**Run 1** (8-second bound):

```
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80
```

**Run 2** (7-second bound, with two interleaved `/metrics` scrapes):

```
[binary-consensus] Loop exit: ticks=70 proposals=70 commits=68 committed_height=Some(67) view=70
```

Emitted by `run_binary_consensus_loop` in
`crates/qbind-node/src/binary_consensus_loop.rs:280–286` from the live
`BinaryConsensusLoopProgress` snapshot. The same code path that updates
`/metrics` on each tick (`binary_consensus_loop.rs:240–254`) also
produces this snapshot, so log evidence and `/metrics` evidence share a
single source of truth.

### 6.2 What this evidences

Observed (direct):

- **Tick rate matches the configured 100 ms interval.** Run 1: 80 ticks
  in ~8 s. Run 2: 70 ticks in ~7 s. Both = 100 ms/tick. Identical to
  Run 001's tick rate.
- **Proposal emission tracks ticks 1:1** (`proposals == ticks`) in both
  runs. The metrics-wiring change did not slow or alter the
  `try_propose()` path.
- **Real view advancement.** `current_view` reached 80 (Run 1) and 70
  (Run 2) — one view advance per tick, matching the single-validator
  self-quorum-per-tick model.
- **Real commit progression.** `commits = 78` (Run 1) and `commits = 68`
  (Run 2). Each is `ticks - 2`, identical to the Run 001 relationship,
  consistent with the HotStuff locking-rule pipeline depth.
- **`committed_height` advances.** `Some(77)` and `Some(67)`,
  exactly tracking `commits - 1`.

Comparison vs. Run 001:

- The `ticks → proposals → commits → committed_height` ratios are
  identical. Engine progression behaviour was unchanged by the
  metrics-wiring fix; the fix only *observes* state, it does not drive
  it. This is the property the change was designed to have.

Inferred (clearly marked as inference):

- That blocks were *cryptographically* committed in the protocol-correct
  sense follows from `BasicHotStuffEngine::commit_log()` and
  `committed_height()` reflecting genuine engine state, exercised by
  `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs` and the
  `localmesh_integration_tests.rs` suite. As in Run 001 §6.2, this run
  does not dump committed block payloads — that remains harness-grade,
  not first-DevNet-smoke-grade.

---

## 7. Metrics Progress Evidence

This is the section where Run 002 differs materially from Run 001.

### 7.1 HTTP scrape commands (issued during Run 2, while the consensus loop was actively committing)

Both scrapes used:

```
curl -s -o /tmp/run002/metrics_<A|B>.body -D /tmp/run002/metrics_<A|B>.headers \
  -w "HTTP_STATUS=%{http_code}\nTIME=%{time_total}s\nBYTES=%{size_download}\n" \
  http://127.0.0.1:9100/metrics
```

- Scrape A — issued ~0.9 s after the metrics listener became reachable.
- Scrape B — issued ~4.0 s after Scrape A, i.e. ~40 ticks later under
  the 100 ms cadence.

### 7.2 Per-scrape transport observations

Scrape A `-w` summary:

```
HTTP_STATUS=200
TIME=0.000371s
BYTES=14062
```

Scrape A response headers:

```
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
Content-Length: 14062
Connection: close
```

Scrape B `-w` summary:

```
HTTP_STATUS=200
TIME=0.000390s
BYTES=14073
```

Scrape B response headers:

```
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
Content-Length: 14073
Connection: close
```

Observed (direct):

- Both scrapes returned HTTP 200, Prometheus exposition format
  v0.0.4, sub-millisecond latency, no contention with the live
  consensus loop (which was concurrently committing — see §6.1
  Run 2 summary).
- `Content-Length` increased between the two scrapes
  (14 062 → 14 073, +11 bytes). That alone is not consensus progress
  evidence (it could be any counter), but it is the first concrete
  byte-level signal that the body changed in flight; the substantive
  evidence is §7.3.

### 7.3 Sampled consensus-class metric values during a live run — moving counters

Filtered output of the same scrapes. These series are the ones that
were stuck at 0 in Run 001 §7.3 (where applicable) and are exactly
the families the binary-side observability fix targets:

**Scrape A (early, ~0.9 s after listener up):**

```
consensus_events_total{kind="tick"} 9
qbind_consensus_view_changes_total 9
qbind_consensus_current_view 9
qbind_consensus_highest_seen_view 9
qbind_consensus_proposals_total{result="accepted"} 9
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_view_number 9
eezo_commit_latency_ms_count 7
eezo_commit_latency_ms_sum 0
eezo_commit_latency_ms_bucket{le="1"} 7
eezo_commit_latency_ms_bucket{le="10"} 7
eezo_commit_latency_ms_bucket{le="100"} 7
eezo_commit_latency_ms_bucket{le="+Inf"} 7
```

**Scrape B (late, +~4.0 s, ~40 ticks later):**

```
consensus_events_total{kind="tick"} 49
qbind_consensus_view_changes_total 49
qbind_consensus_current_view 49
qbind_consensus_highest_seen_view 49
qbind_consensus_proposals_total{result="accepted"} 49
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_view_number 49
eezo_commit_latency_ms_count 47
eezo_commit_latency_ms_sum 0
eezo_commit_latency_ms_bucket{le="1"} 47
eezo_commit_latency_ms_bucket{le="10"} 47
eezo_commit_latency_ms_bucket{le="100"} 47
eezo_commit_latency_ms_bucket{le="+Inf"} 47
```

**Per-series A → B deltas:**

| Series | A | B | Δ | Comment |
|---|---|---|---|---|
| `consensus_events_total{kind="tick"}` | 9 | 49 | +40 | Matches expected ~40 ticks in 4 s at 100 ms cadence. |
| `qbind_consensus_view_changes_total` | 9 | 49 | +40 | Single-validator: one view advance per tick. |
| `qbind_consensus_current_view` | 9 | 49 | +40 | Gauge moved monotonically. |
| `qbind_consensus_highest_seen_view` | 9 | 49 | +40 | Tracks current view in single-validator mode. |
| `qbind_consensus_proposals_total{result="accepted"}` | 9 | 49 | +40 | `BroadcastProposal` action seen on each tick. |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | Honest: single-validator runs reject nothing. |
| `qbind_consensus_view_number` | 9 | 49 | +40 | Same-source-as `current_view`, both updated. |
| `eezo_commit_latency_ms_count` | 7 | 47 | +40 | Commits visible in `/metrics`, with the same pipeline-depth lag as §6.1. |
| `eezo_commit_latency_ms_bucket{le="1"}` | 7 | 47 | +40 | Every commit landed in the <1 ms bucket — see §9.2. |

All four families that the `binary_consensus_loop.rs` change wires
(tick events, view gauges/counters, proposal-accepted counter, and
commit latency histogram) **moved live in `/metrics`**, in lock-step
with the underlying engine progression observed in §6.1.

### 7.4 Series that remained at zero during this run, and why each is honest

Several consensus-class series were still 0 in both scrapes. Each is
expected to be 0 for this scenario, and is reported here explicitly to
avoid overclaiming what `/metrics` now covers:

```
consensus_events_total{kind="incoming_message"} 0
consensus_events_total{kind="shutdown"} 0
consensus_runtime_ticks_per_second 0
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
consensus_net_outbound_total{kind="vote_send_to", priority="critical"} 0
consensus_net_outbound_total{kind="vote_send_to", priority="normal"} 0
consensus_net_outbound_total{kind="vote_broadcast", priority="critical"} 0
consensus_net_outbound_total{kind="vote_broadcast", priority="normal"} 0
consensus_net_outbound_total{kind="proposal_broadcast", priority="critical"} 0
consensus_net_outbound_total{kind="proposal_broadcast", priority="normal"} 0
```

Honest interpretation:

- `consensus_events_total{kind="incoming_message"}` — 0 because there
  is no P2P inbound message ingestion on the binary path
  (EXE-2 §6.2). Out of scope for Run 002. The binary-loop
  metrics-wiring change deliberately does not synthesise this
  counter.
- `consensus_events_total{kind="shutdown"}` — 0 because the scrapes
  were taken *before* shutdown. After shutdown the body is no
  longer reachable, so this counter being 0 mid-run is correct.
- `consensus_runtime_ticks_per_second` — 0 in both scrapes. This is
  a derived rate gauge that is not maintained by the binary
  consensus loop today; the binary-loop metrics-wiring change did
  not begin to publish it (it was bounded to families it had a
  source for: tick events, view gauges, proposal-accepted counter,
  commit latency). This is a known partial gap; see §9.1.
- `consensus_net_outbound_total{...}` family (all label
  permutations) — 0 because there is no consensus network outbound
  on this run (no P2P, no peers). Out of scope for Run 002.
- `eezo_commit_latency_ms_sum` — 0. Expected: each per-tick
  single-validator commit's wall-time was sub-millisecond and the
  histogram sum is integer milliseconds, so the sum truncates to 0
  even though count = 47. This is a recording-resolution limitation
  of `CommitMetrics::record_commit` for sub-millisecond commits, not
  a wiring bug. See §9.2.

### 7.5 Direct comparison to Run 001 §7.3

For the same series Run 001 explicitly listed at 0 (Run 001 §7.3):

| Series | Run 001 §7.3 | Run 002 Scrape B | Status |
|---|---|---|---|
| `consensus_events_total{kind="tick"}` | 0 | 49 | **Now live** |
| `consensus_events_total{kind="incoming_message"}` | 0 | 0 | Still 0 — out of scope (no P2P) |
| `consensus_events_total{kind="shutdown"}` | 0 | 0 | Still 0 — scrape pre-shutdown |
| `consensus_runtime_ticks_per_second` | 0 | 0 | Still 0 — partial; not wired by this fix (§9.1) |
| `consensus_net_outbound_total{kind="vote_send_to"}` | 0 | 0 | Still 0 — out of scope (no P2P) |
| `consensus_net_outbound_total{kind="vote_broadcast"}` | 0 | 0 | Still 0 — out of scope (no P2P) |
| `consensus_net_outbound_total{kind="proposal_broadcast"}` | 0 | 0 | Still 0 — out of scope (no P2P) |
| `consensus_net_outbound_total{kind="vote_send_to", priority="critical"}` | 0 | 0 | Still 0 — out of scope (no P2P) |
| `consensus_net_outbound_total{kind="vote_send_to", priority="normal"}` | 0 | 0 | Still 0 — out of scope (no P2P) |
| `consensus_net_outbound_total{kind="vote_broadcast", priority="critical"}` | 0 | 0 | Still 0 — out of scope (no P2P) |

Of the ten series Run 001 listed:

- One (`consensus_events_total{kind="tick"}`) was the canonical
  binary-tick liveness signal. **It moves now.**
- Seven (the `consensus_net_outbound_total{…}` family in all label
  forms) describe consensus *network* outbound traffic; they are
  intentionally still 0 in single-validator no-P2P runs. They are
  not, and were never, in Run 002's scope.
- One (`consensus_events_total{kind="shutdown"}`) is a one-shot
  emitted at shutdown; it is correctly 0 mid-run.
- One (`consensus_runtime_ticks_per_second`) is still 0 and is the
  one residual binary-side gauge gap not covered by the current
  metrics-wiring change. Recorded as a partial limitation in §9.1.

In addition, several Run 002 series that were *not* in Run 001 §7.3's
list are also moving (`qbind_consensus_view_number`,
`qbind_consensus_current_view`, `qbind_consensus_highest_seen_view`,
`qbind_consensus_view_changes_total`,
`qbind_consensus_proposals_total{result="accepted"}`,
`eezo_commit_latency_ms_count`, `eezo_commit_latency_ms_bucket{…}`).
Together with the moving tick-event counter, these constitute the
first single-curl-scrape proof of binary-path consensus progress.

### 7.6 Net assessment

The `/metrics` endpoint **is real, reachable, well-formed, concurrent
with consensus, and now itself shows live consensus progress** on the
binary path for a single validator: ticks, view, proposals-accepted,
view-changes, commit-latency-count all advanced strictly monotonically
in lock-step with engine state across two scrapes 4 seconds apart.

The endpoint is **not yet** a complete Class-A consensus-signal
surface, because (a) consensus network outbound counters require P2P
and (b) `consensus_runtime_ticks_per_second` is still not published.
Those remain partial gaps, recorded in §9.1.

---

## 8. Shutdown Evidence

### 8.1 Captured shutdown logs (exact, in observed order)

Run 1:

```
[binary] Shutdown signal received, stopping consensus loop...
[binary-consensus] Shutdown signal received after 80 ticks.
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80
[binary] LocalMesh node stopped.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

Run 2 (structurally identical):

```
[binary] Shutdown signal received, stopping consensus loop...
[binary-consensus] Shutdown signal received after 70 ticks.
[binary-consensus] Loop exit: ticks=70 proposals=70 commits=68 committed_height=Some(67) view=70
[binary] LocalMesh node stopped.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

### 8.2 Procedure

`SIGINT` was delivered to the binary by `timeout --foreground -s INT`;
identical to Run 001.

### 8.3 What this evidences

Observed (direct):

- **Shutdown is ordered.** First `[binary] Shutdown signal received…`,
  then the consensus loop drains and emits its final summary line
  (which is the same snapshot from which `/metrics` was being fed),
  then `[binary] LocalMesh node stopped.`, then `[metrics_http]
  Shutting down`, then `[binary] Shutdown complete.` Identical to
  Run 001 §8.1.
- **No forced kill required.** The `timeout` wrapper exit code was
  124 in both runs (signal-induced termination of the timed child),
  no panic, no hung shutdown, no orphan task.
- **The metrics-wiring change did not perturb shutdown.** No new
  banners, no new errors, no re-ordering, no leaked task at exit.

Not observed (and acknowledged as out of scope):

- No persistent storage was exercised. As in Run 001 §8.3, DevNet
  preset uses `state_retention = disabled` /
  `snapshot_config = disabled`. Clean shutdown here is not evidence
  of a clean *durable* shutdown.

---

## 9. Limitations and Anomalies Observed

Stated bluntly, in roughly decreasing order of relevance:

### 9.1 Residual `/metrics` partial gaps

- **`consensus_runtime_ticks_per_second` still 0.** The current
  binary-loop metrics-wiring fix does not maintain a derived
  ticks-per-second gauge. Tick counts are now visible
  (`consensus_events_total{kind="tick"}` moved 9 → 49 over ~4 s, so
  a ticks-per-second of ~10 is *implied*), but the gauge itself is
  not published. This is the only consensus-class series that Run 001
  §7.3 listed at 0, that is still 0, and that is in scope for the
  binary path. It is a small, follow-up-sized gap; see §11.
- **`consensus_net_outbound_total{…}` family still 0.** This is
  expected and out of scope for a single-validator no-P2P run; it
  will only ever move when consensus traffic is actually leaving the
  process. Listed here for completeness, not as a regression.
- **`consensus_events_total{kind="incoming_message"}` still 0.**
  Same reasoning as above (no P2P inbound). Out of scope.

### 9.2 `eezo_commit_latency_ms_sum` remained 0 despite count = 47

Each per-tick single-validator commit completes in well under 1 ms
(`tick_elapsed` in `binary_consensus_loop.rs` is the wall time of just
the engine step, which is sub-millisecond on a hot CPU). The
`record_commit` implementation in `crates/qbind-node/src/metrics.rs`
quantises the duration to integer milliseconds via
`duration.as_millis() as u64` and adds that to `commit_total_ms`. For
sub-millisecond commits this rounds to 0, so the histogram sum stays at
0 even though count grows. This is a known recording-resolution behaviour
of `CommitMetrics`, not a wiring bug introduced by Run 002 or by the
metrics-wiring fix; the histogram *count* and the `le="1"` bucket *do*
move and are the trustworthy commit-progress signal in this scenario.
Fixing this would require either a sub-millisecond latency unit or a
different `record_commit` shape — neither is in scope here.

### 9.3 Single-host, single-process, single-validator only

No peers, no P2P, no LocalMesh fan-in. Run 002 cannot speak to
multi-validator binary-path DevNet (EXE-2 §5.1, §5.2) and does not.

### 9.4 Two short bounded runs (8 s and 7 s)

Combined wall-clock under 16 s. This is still a smoke, not a soak. The
72-hour multi-node soak remains a DevNet → TestNet Alpha exit criterion
and is unaffected by this run.

### 9.5 No restore-from-snapshot evidence

B3 remains open (EXE-2 §6.1, `contradiction.md` C4(c)). Run 002 did
not, and could not, exercise the missing path.

### 9.6 No `/health` or `/ready`, no JSON-RPC

Unchanged from Run 001 §9.5–9.6. Out of scope.

### 9.7 Per-tick log lines remain intentionally silent

Unchanged from Run 001 §9.7. The change is that `/metrics` is now an
adequate vehicle for live progress on its own, so per-tick stderr
spam is no longer needed for that purpose.

### 9.8 One pre-existing compiler warning surfaced unchanged

Same `unused variable: worker_id` warning at
`crates/qbind-node/src/verify_pool.rs:262`. Not introduced by this
run; not in scope to fix.

### 9.9 No code path was modified for this run

The binary exercised is exactly what is on the branch; the
metrics-wiring change being evidenced was already landed prior to
Run 002. No reproducibility helper script was added.

### 9.10 No surprise anomalies

No unexpected behaviour was observed beyond what §7.4 / §9.1–§9.2
already record.

---

## 10. Assessment of Evidence Value

### 10.1 Required questions, answered conservatively

| # | Question | Answer | Source in this doc |
|---|---|---|---|
| A | Did the binary start successfully? | **Yes.** Real config banner emitted; consensus loop entered without error; banners byte-identical to Run 001. | §5 |
| B | Did the consensus loop run and progress? | **Yes.** Two independent runs produced monotone advancement: ticks 80/70, proposals 80/70, commits 78/68, committed_height 77/67, view 80/70. Tick rate matches the configured 100 ms interval. Same shape as Run 001. | §6 |
| C | Did `/metrics` respond successfully? | **Yes.** HTTP 200, `Content-Type: text/plain; version=0.0.4`, ~14 KiB body, sub-millisecond latency, on both scrapes during a live run. | §7.2 |
| D | Did `/metrics` now show live consensus progress? | **Yes.** All wired consensus-class series advanced strictly between two scrapes 4 s apart: tick events 9 → 49 (Δ+40), view 9 → 49, view_changes_total 9 → 49, proposals_accepted 9 → 49, commit-latency count 7 → 47 (Δ+40). This is the single thing Run 002 was created to demonstrate. | §7.3, §7.5 |
| E | Did shutdown complete cleanly? | **Yes.** Ordered teardown (consensus → metrics → done) on `SIGINT`, no forced kill, no panic, no hang. Identical to Run 001. | §8 |
| F | Does this materially strengthen DevNet observability evidence vs. Run 001? | **Yes — narrowly.** It closes the specific limitation Run 001 surfaced: consensus progress is now provable from `/metrics` alone, with no log-scraping required. It does *not* strengthen multi-validator, P2P, restore-from-snapshot, or full monitoring-baseline evidence. | §7.5, §10.2 |
| G | What is the exact next execution action recommended? | See §11. | §11 |

### 10.2 Does this support the EXE-2 verdict honestly?

Yes — narrowly and only within the EXE-2 verdict's stated bounds, and
with a small upgrade compared to Run 001:

EXE-2 said PASS WITH LIMITATIONS, with the limitations being
multi-validator binary-path being PARTIAL, B3 being open, and Class-A
consensus signals on `/metrics` from the binary path not yet bound.
Run 002:

- Confirms again the PASS half (single-validator binary-path DevNet
  with `/metrics`).
- **Materially shrinks** one of the LIMITATIONS — the binary-path
  Class-A consensus-signal portion that pertains to single-validator
  liveness (ticks, views, proposals-accepted, commit count) is now
  observable from `/metrics` directly. Run 001 confirmed the gap;
  Run 002 confirms it is largely closed for single-validator runs,
  with two narrow residuals (§9.1, §9.2).
- Does **not** affect multi-validator binary-path DevNet, B3, or P2P
  signal coverage.

### 10.3 Contradiction tracker decision

`docs/whitepaper/contradiction.md` is **not** updated by this run.

Justification:

- C4 already states it tracks the production-binary boot-and-operate
  problem, with B1 ✅ landed, B2 ✅ landed, B3 ⚠️ still open, and
  multi-validator P2P→consensus interconnect ⚠️ still open. Run 002:
  - does not land or change B1, B2, or B3,
  - does not exercise the multi-validator P2P→consensus interconnect,
  - does not surface a *new* contradiction or a new dependency that
    is not already implicit in C4's existing wording, and
  - does not *materially sharpen* C4 — the binary-path observability
    sub-item that Run 002 retires was already noted in EXE-2 §5.3 /
    §6.4 and in Run 001 §7.3 / §10.3 as in-scope and not yet bound;
    Run 002 simply confirms it is now bound.
- The problem statement's contradiction-handling rule says to update
  only if Run 002 reveals a new genuine contradiction or materially
  sharpens C4. Neither condition is met.
- The two residual `/metrics` gaps (§9.1, §9.2) are bounded and small
  enough that they do not, by themselves, warrant a new contradiction
  entry — they are observability-quality items for a single subsystem,
  not protocol-level contradictions.

Whether C4 should later be re-scoped or partially closed in
`contradiction.md` based on the cumulative B1+B2+observability evidence
is an editorial decision belonging to the next audit pass (e.g., a
hypothetical EXE-3), not to this evidence-collection record.

---

## 11. Recommended Immediate Next Action

Pick **one** of the following two options. Both are real follow-ups;
neither broadens the scope of EXE-2 or of this run.

**Option A (preferred — closes the largest still-open half of C4 and
unblocks C4-related drill evidence):** Implement
`--restore-from-snapshot <path>` startup ingestion (B3) using the
existing `StateSnapshotter` checkpoint format, per EXE-2 §10 action 1.
After landing, run a third evidence pass (Run 003) shaped as a
restore-then-observe pass. This is the next item in the EXE-2 §10
ordering that Runs 001 and 002 have *not* yet touched, and it is the
only remaining sub-item of C4 that can be progressed without first
doing the larger P2P→consensus interconnect work.

**Option B (small, optional cleanup of the residuals from §9.1):**
Wire `consensus_runtime_ticks_per_second` (and, if cheap,
`consensus_events_total{kind="shutdown"}`) into the binary loop. This
is genuinely tiny — the source of truth (tick count + wall-clock
elapsed) is already maintained inside the loop — and it would make the
single-validator `/metrics` surface fully match Run 001 §7.3's
expectations with no residual zeros that aren't strictly
P2P-dependent. This is a polish task, not a new capability.

This document does **not** recommend attempting multi-validator
binary-path DevNet yet — that depends on the P2P→consensus interconnect
work (EXE-2 §6.2 / action 2), which is a larger code change and should
land *before*, not as part of, its first evidence run.

**Default recommendation:** Option A. It targets the only structurally
significant remaining sub-item of C4 (B3 / restore-from-snapshot) and
produces a stronger evidence artifact than another observability tweak
would. Option B can be folded into Run 003's preparation if convenient,
but does not need to gate it.