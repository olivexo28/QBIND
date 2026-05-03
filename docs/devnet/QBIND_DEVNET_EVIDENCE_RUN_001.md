# QBIND DevNet Evidence Run 001

**Status:** Internal evidence record — first real single-validator DevNet binary-path run.
**Audience:** Internal — protocol engineering, ops, release management.
**Run date:** 2026-05-03 (UTC).
**Author:** Execution follow-up to EXE-2 (`docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` §10 action 3).

> This document is a first evidence artifact, not a victory document. It captures
> what the actual `qbind-node` binary did, exactly, on a single host, in a short
> bounded run. It does **not** demonstrate multi-validator DevNet, restore-from-snapshot,
> or any soak-grade property. See §9 and §10 for explicit limitations.

---

## 1. Purpose and Scope

This is the first concrete execution-evidence record for the QBIND DevNet
posture. EXE-2 (`docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md`) returned the
verdict **"PASS WITH LIMITATIONS"**, with single-validator binary-path DevNet
plus `/metrics` declared real, and multi-validator binary-path modes plus
restore-from-snapshot (B3) declared still PARTIAL/open. EXE-2 §10 listed as
its third next action: "First DevNet evidence-collection run (single-validator
binary)". This document is that artifact.

In scope (this run):

- A. Binary startup of the real `qbind-node` release binary.
- B. Real `BasicHotStuffEngine` consensus loop activity from the binary path.
- C. View / proposal / commit progression observable from the binary's own logs.
- D. `/metrics` endpoint reachability from the binary path with `QBIND_METRICS_HTTP_ADDR`.
- E. Clean shutdown via `SIGINT`.
- F. First-pass anomalies and friction observed in the operator path.

Explicitly out of scope (this run):

- Multi-validator binary-path DevNet (LocalMesh and P2P forms remain PARTIAL —
  see EXE-2 §5.1, §5.2, §6.2).
- Restore-from-snapshot evidence (B3 still open — EXE-2 §6.1).
- Soak / 72-hour stability evidence (DevNet → TestNet Alpha exit criterion,
  not a bring-up criterion).
- Class-A consensus signal evidence in `/metrics` end-to-end (EXE-2 §5.3, §6.4
  — predicted not yet bound; this run confirms that prediction; see §7 below).
- Operator drill catalog instantiation, multi-region, RPC, `/health`/`/ready`.

---

## 2. Canonical Basis

This run is grounded in, and bounded by, the following canonical documents:

- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` (EXE-2)
  — verdict, supported modes (§7), partial-ready bounds (§5), blockers (§6),
  next actions (§10). This document executes §10 action 3.
- `docs/whitepaper/contradiction.md` C4 (OPEN — partial; B1 and B2 landed,
  B3 still outstanding).
- `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` §6, §7, §8
  — single-validator bring-up shape and the `/metrics` expectation.
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`
  — referenced indirectly to qualify what `/metrics` does and does not
  satisfy on the binary path today (Class-A consensus signals — §7 below).
- `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` (EXE-1) §6.1–§6.3, §9
  — origin of B1, B2, B3 wording.
- `docs/testnet/QBIND_BETA_OPERATOR_CHECKLIST.md`,
  `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md`,
  `docs/testnet/QBIND_BETA_EVIDENCE_PACKET_TEMPLATE.md`
  — referenced as canonical input shape; this run does **not** purport to
  satisfy the Beta operator checklist or the Beta evidence packet template.
  Those are post-DevNet artifacts.

---

## 3. Run Environment

Observed:

- Repo: `olivexo28/QBIND`, branch `copilot/execute-single-validator-devnet-evidence-collectio`.
- Toolchain: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`, `rustc 1.94.1 (e408947bf 2026-03-25)`.
- Build command: `cargo build --release -p qbind-node --bin qbind-node`.
- Build outcome: `Finished `release` profile [optimized] target(s) in 5m 07s` (clean from cold cache).
  - One pre-existing compiler warning surfaced unchanged
    (`unused variable: worker_id` in `crates/qbind-node/src/verify_pool.rs:262`).
    Out of scope for this run.
- Resulting binary: `target/release/qbind-node` (≈ 8.4 MiB, executable).
- Host: GitHub-hosted Linux x86_64 sandbox (single host, single process, no peers).
- Network: no `--enable-p2p`; default `LocalMesh`, single-validator (no `--p2p-peer`).

This is a **single-validator, single-host, binary-path, LocalMesh, no-P2P,
short-bounded run**. Nothing more.

---

## 4. Commands and Configuration Used

### 4.1 Build

```
cargo build --release -p qbind-node --bin qbind-node
```

### 4.2 Run command (canonical EXE-2 §7 single-validator-with-metrics shape)

```
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node --env devnet --validator-id 0
```

This is the exact shape recorded in `crates/qbind-node/src/main.rs` lines 8–22
(`# DevNet single-node smoke (LocalMesh, real consensus loop, metrics on)`)
and in `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` §7 ("Single-validator
DevNet with metrics: YES").

### 4.3 Bounded-run wrapper used for evidence capture

To produce a clean, reproducible shutdown without interactive `Ctrl+C`, the
process was started in the background and an explicit `SIGINT` was delivered
via `timeout --foreground -s INT <seconds>`. This is exactly what
`tokio::signal::ctrl_c()` listens for in `main.rs::run_local_mesh_node`; it is
the same signal a human operator's `Ctrl+C` would deliver. No code path in
`qbind-node` was modified for this run.

Two short bounded runs were executed:

- **Run 1** — 8-second bound, full startup → progression → shutdown capture.
- **Run 2** — 6-second bound, focused on `/metrics` HTTP scrape (status code,
  headers, body size, consensus-class counter sample).

### 4.4 Environment variables

Only one environment variable was set, and only at the run-command level:

| Variable | Value | Purpose |
|---|---|---|
| `QBIND_METRICS_HTTP_ADDR` | `127.0.0.1:9100` | Enable `/metrics` HTTP server. Read by `MetricsHttpConfig::from_env()` (`crates/qbind-node/src/metrics_http.rs`, called from `main.rs:126`). |

No other QBIND-prefixed env vars were set. No config file was used. CLI flags
were `--env devnet --validator-id 0` only. All other settings come from
`NodeConfig::devnet_v0_preset` (`crates/qbind-node/src/node_config.rs`).

### 4.5 Effective configuration as logged by the binary itself

From the binary's own `log_startup_info` output (stdout, line 1):

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600
  scope=DEV profile=nonce-only network=local-mesh p2p=disabled gas=off
  fee-priority=off fee_distribution=burn-only mempool=fifo
  dag_availability=disabled dag_coupling=off stage_b=disabled
  diversity=off(prefix24=2,prefix16=8,buckets>=4)
```

This matches `devnet_v0_preset` exactly (cf. EXE-2 §4.3): DevNet env, nonce-only
execution profile, LocalMesh, P2P disabled, gas off, FIFO mempool. No silent
deviation from the documented DevNet preset.

---

## 5. Startup Evidence

### 5.1 Captured startup log (Run 1 — exact, unedited, in observed order)

`stdout`:

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=local-mesh p2p=disabled gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
```

`stderr` (in order of emission):

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

- The binary process started successfully (exit code on shutdown was driven
  only by the external `SIGINT` from `timeout`; no early exit, no panic, no
  config-validation failure).
- `MetricsHttpConfig::from_env()` correctly read `QBIND_METRICS_HTTP_ADDR`
  and enabled the HTTP server.
- `run_local_mesh_node` (`main.rs:185`) was entered and reported the correct
  branch (`environment=DevNet profile=nonce-only`).
- The binary correctly classified the run as single-validator
  (`num_validators=1`) and emitted the audit-grade banner that single-validator
  LocalMesh self-quorums per tick. This wording matches EXE-2 §4.1 verbatim
  and `crates/qbind-node/src/main.rs:204–206`.
- `spawn_binary_consensus_loop` was invoked and `run_binary_consensus_loop`
  (`crates/qbind-node/src/binary_consensus_loop.rs:146`) reported its starting
  banner — confirming that the `BasicHotStuffEngine` was constructed and the
  100 ms tick interval scheduler was active.
- The metrics HTTP listener attached to `127.0.0.1:9100` (`[metrics_http]
  Listening on 127.0.0.1:9100`).

Not observed in this run (and acknowledged):

- No `--profile mainnet` and therefore no `validate_mainnet_invariants()`
  banner. Expected: DevNet does not satisfy MainNet invariants and must not
  trigger them (EXE-2 §4.4).
- No P2P transport startup banner. Expected: `--enable-p2p` not passed.
- No genesis banner from a non-embedded source. Expected: DevNet uses the
  embedded genesis builder (EXE-2 §5.5).

---

## 6. Consensus Progress Evidence

### 6.1 Final consensus-loop summary line emitted by the binary

**Run 1** (8-second bound):

```
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80
```

**Run 2** (6-second bound):

```
[binary-consensus] Loop exit: ticks=60 proposals=60 commits=58 committed_height=Some(57) view=60
```

This summary line is emitted by `run_binary_consensus_loop` in
`crates/qbind-node/src/binary_consensus_loop.rs:208–215` from the live
`BinaryConsensusLoopProgress` snapshot.

### 6.2 What this evidences

Observed (direct):

- **Tick rate matches the 100 ms configured interval.** Run 1: 80 ticks in
  ~8 s = 100 ms/tick. Run 2: 60 ticks in ~6 s = 100 ms/tick. The tokio
  interval scheduler is healthy.
- **Proposal emission tracks ticks 1:1.** `proposals_emitted == ticks` in both
  runs. This means `BasicHotStuffEngine::try_propose()` returned a
  `BroadcastProposal` action on every tick, which is the expected
  single-validator-leader behaviour.
- **Real view advancement.** `current_view` reached 80 (Run 1) and 60 (Run 2)
  — i.e. one view advance per tick, matching the single-validator
  self-quorum-per-tick model recorded in
  `binary_consensus_loop.rs:26–34` and EXE-2 §4.1.
- **Real commit progression.** `commits = 78` (Run 1) and `commits = 58`
  (Run 2). Each is `ticks - 2`, which is consistent with the HotStuff
  locking-rule pipeline depth (a commit fires after the locking-rule prefix
  is satisfied, hence the small constant lag). The progression is monotone
  and continues every tick.
- **`committed_height` advances.** `Some(77)` in Run 1 and `Some(57)` in
  Run 2, exactly tracking `commits - 1`, i.e. the height of the most-recently
  committed block.
- **Two independent runs produced consistent rates.** Run 1 and Run 2
  are mutually consistent (same tick rate, same `commits = ticks - 2`
  relationship, same committed_height = commits - 1 relationship, same
  view = ticks relationship).

Inferred (clearly marked as inference, not direct observation):

- That blocks were *cryptographically* committed in the protocol-correct
  sense follows from `BasicHotStuffEngine::commit_log()` and `committed_height()`
  reflecting genuine engine state — these are the same engine entry points
  exercised by `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs`
  (`b1_binary_consensus_loop_actually_drives_consensus`) and by
  `localmesh_integration_tests.rs`. We did not, in this run, dump or hash
  individual committed block payloads — that is harness-grade evidence,
  not first-DevNet-smoke evidence. We rely on the existing test suite for
  the protocol-level claim and report the binary-side counters honestly.

Not observed (and explicitly acknowledged as missing):

- No per-tick log line (the binary intentionally suppresses per-tick logging
  to keep an idle-cost low — see `binary_consensus_loop.rs`). The summary
  line at exit is the canonical evidence vehicle today.
- No leader-rotation evidence. Single-validator runs do not rotate leaders.
  Multi-validator binary-path leader rotation evidence remains harness-grade
  pending the §6.2 P2P→consensus interconnect work.

---

## 7. Metrics Endpoint Evidence

### 7.1 HTTP scrape (Run 2, while the consensus loop was actively committing)

Command:

```
curl -s -o /tmp/metrics.body -D /tmp/metrics.headers \
  -w "HTTP_STATUS=%{http_code}\nTIME=%{time_total}s\nBYTES=%{size_download}\n" \
  http://127.0.0.1:9100/metrics
```

`-w` output:

```
HTTP_STATUS=200
TIME=0.000390s
BYTES=14062
```

Response headers (full):

```
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
Content-Length: 14062
Connection: close
```

### 7.2 What this evidences

Observed (direct):

- **`/metrics` returns HTTP 200.**
- **`Content-Type: text/plain; version=0.0.4; charset=utf-8`** — Prometheus
  exposition format, version 0.0.4. This is the canonical format expected
  by `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`.
- **Response body is non-empty** (14 062 bytes) and structured as Prometheus
  text exposition (named metric series, type comments, labelled samples).
- The endpoint **served while the consensus loop was actively committing**
  (Run 2: 58 commits during the same 6-second window in which the scrape
  succeeded). The metrics server and the consensus loop are both alive
  concurrently — no contention failure observed.
- Latency was sub-millisecond (`TIME=0.000390s`) — consistent with a local
  unloaded scrape against an in-process server.

### 7.3 Sampled consensus-class counter values during a live run (CRITICAL CAVEAT)

While the engine was visibly committing blocks (proven by §6: 58 commits in
Run 2), the following consensus-class counters in the `/metrics` body were
all **0**:

```
consensus_net_outbound_total{kind="vote_send_to"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
consensus_events_total{kind="tick"} 0
consensus_events_total{kind="incoming_message"} 0
consensus_events_total{kind="shutdown"} 0
consensus_runtime_ticks_per_second 0
consensus_net_outbound_total{kind="vote_send_to", priority="critical"} 0
consensus_net_outbound_total{kind="vote_send_to", priority="normal"} 0
consensus_net_outbound_total{kind="vote_broadcast", priority="critical"} 0
```

This is **not a bug discovered by this run** — it is exactly the limitation
already recorded in `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` §5.3 and
§6.4: the binary-path consensus loop in
`crates/qbind-node/src/binary_consensus_loop.rs` does not currently update
the `Arc<NodeMetrics>` consensus counters. The metrics server returns the
counter series with their initial (zero) values for the consensus class
even while the engine is committing. This run **directly confirms** that
predicted gap from a live binary, rather than only from inspection.

Other metric families in the body (KEMTLS family, network channel-config
family, spawn_blocking buckets, etc.) are present but were not exercised
in this run (single-validator, no P2P, no peers); they are wired to publish
from their respective subsystems but had nothing to count in this scenario.

### 7.4 Net assessment

The `/metrics` endpoint **is real, reachable, well-formed, and concurrent
with consensus**. It is **not yet** sufficient to prove consensus progress
on its own — for that, the source of truth in this run is the
`[binary-consensus] Loop exit: ...` summary line. The Monitoring and Alerting
Baseline's Class-A consensus signals expectation against the binary path is
not satisfied by this artifact.

---

## 8. Shutdown Evidence

### 8.1 Captured shutdown log (Run 1 — exact, in observed order)

```
[binary] Shutdown signal received, stopping consensus loop...
[binary-consensus] Shutdown signal received after 80 ticks.
[binary-consensus] Loop exit: ticks=80 proposals=80 commits=78 committed_height=Some(77) view=80
[binary] LocalMesh node stopped.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

(Run 2 shutdown log is structurally identical, with `ticks=60 proposals=60
commits=58 committed_height=Some(57) view=60`.)

### 8.2 Procedure

`SIGINT` was delivered to the binary by `timeout --foreground -s INT`. This
is the same signal `Ctrl+C` produces and is the signal `main.rs` listens
for via `tokio::signal::ctrl_c()` (line 220).

### 8.3 What this evidences

Observed (direct):

- **Shutdown is ordered.** First `[binary] Shutdown signal received...`,
  then the consensus loop drains and emits its final summary line, then
  `[binary] LocalMesh node stopped.`, then the metrics HTTP server shuts
  down, then `[binary] Shutdown complete.` This matches the documented
  ordering in EXE-2 §4.5 ("consensus loop first, then metrics server").
- **No forced kill required.** The process responded to `SIGINT` and exited
  on its own. The `timeout` wrapper's exit code was 124 (SIGINT-induced
  termination of the timed child), as expected — there was no panic, no
  hung shutdown, no orphaned task.
- **Consensus progress was preserved up to the moment of shutdown.** The
  exit-summary `commits=78` / `committed_height=Some(77)` is consistent
  with §6 progression and confirms that the shutdown did not corrupt the
  in-memory engine state on the way out.

Not observed (and acknowledged as out of scope):

- No persistent storage was exercised. DevNet preset uses
  `state_retention = disabled` and `snapshot_config = disabled` (EXE-2
  §4.3); there is nothing on disk for shutdown to flush. A clean shutdown
  here is not evidence of a clean *durable* shutdown — that requires a
  config that engages durable storage and is out of scope for a DevNet
  smoke per EXE-2 §6.7-style positioning.

---

## 9. Limitations and Anomalies Observed

Stated bluntly:

1. **Single-host, single-process, single-validator only.** No peers, no P2P,
   no LocalMesh fan-in. This run cannot speak to multi-validator binary-path
   DevNet (EXE-2 §5.1, §5.2) and does not.
2. **Two short bounded runs (8 s and 6 s).** Total combined wall-clock under
   15 s. This is a smoke, not a soak. EXE-2 §10 explicitly described this
   action as the *first* DevNet evidence-collection run, distinct from the
   72-hour multi-node soak that is a DevNet → TestNet Alpha exit criterion.
3. **No restore-from-snapshot evidence.** B3 remains open (EXE-2 §6.1,
   `contradiction.md` C4). This run did not, and could not, exercise the
   missing path.
4. **Consensus-class `/metrics` counters stayed at 0 throughout** while the
   engine was committing. Confirmed live; recorded above (§7.3). This is
   exactly the gap predicted by EXE-2 §5.3 / §6.4 and is not a new finding.
5. **No `/health` or `/ready` endpoint.** Only `/metrics` is served. EXE-2
   §6.3 already records this; not exercised here.
6. **No JSON-RPC server.** `qbind-node` does not expose one (EXE-2 §5.4,
   referencing EXE-1 §6.7). DevNet operators following Operational Guide
   §7.5 wording about an RPC port will not find one. Confirmed unchanged
   in this run.
7. **Per-tick observability is intentionally silent.** The only consensus
   evidence vehicle the binary emits today is the *exit-time* summary line.
   For a longer DevNet smoke this is sufficient; for an operator drill that
   needs live progress signals from the binary itself (rather than from
   `/metrics`), this is a future observability item — same neighbourhood as
   the §6.4 counter-binding work.
8. **One pre-existing compiler warning surfaced unchanged**
   (`unused variable: worker_id` in `crates/qbind-node/src/verify_pool.rs:262`).
   Not introduced by this run; not in scope to fix.
9. **No code path was modified for this run.** The binary exercised is
   exactly what is on the branch. No reproducibility helper script was added,
   because the canonical command in §4.2 already runs unchanged from the
   `main.rs` doc-comment example.

No surprise anomalies were observed beyond what EXE-2 already predicted.

---

## 10. Assessment of Evidence Value

### 10.1 Required questions, answered conservatively

| # | Question | Answer | Source in this doc |
|---|---|---|---|
| A | Did the binary start successfully? | **Yes.** Real config banner emitted; consensus loop entered without error. | §5 |
| B | Did it enter the real consensus-driving loop? | **Yes.** `[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms` confirms `BasicHotStuffEngine` was constructed and ticked. | §5, §6 |
| C | Did it show real progression (not just idle logging)? | **Yes.** Two independent runs produced monotone advancement: ticks 80/60, proposals 80/60, commits 78/58, committed_height 77/57, view 80/60. Tick rate matches the configured 100 ms interval. | §6 |
| D | Did `/metrics` respond successfully? | **Yes.** HTTP 200, `Content-Type: text/plain; version=0.0.4`, 14 062 bytes, scraped during live commit activity. | §7 |
| E | Did shutdown complete cleanly? | **Yes.** Ordered teardown (consensus → metrics → done) on `SIGINT`, no forced kill, no panic, no hang. | §8 |
| F | Does this run provide real DevNet evidence or only partial evidence? | **Partial — single-validator binary-path only.** It is real evidence for the EXE-2 §7 "Supported now" claim ("Single-validator DevNet via binary path: YES" and "Single-validator DevNet with metrics: YES"). It is **not** evidence for multi-validator binary-path DevNet, restore-from-snapshot, or full Class-A `/metrics` consensus-signal coverage. | §9 |
| G | What immediate next action does this run point to? | See §11. | §11 |

### 10.2 Does this support the EXE-2 verdict honestly?

Yes — narrowly and only within the EXE-2 verdict's stated bounds.

EXE-2 said: PASS WITH LIMITATIONS, where the limitations are exactly that
multi-validator binary-path DevNet is PARTIAL, B3 is open, and Class-A
consensus signals on `/metrics` from the binary path are not yet bound.
This run:

- confirms the PASS half (single-validator binary-path DevNet plus `/metrics`
  is real and reproducible),
- confirms the LIMITATIONS half by directly observing that consensus-class
  counters in `/metrics` stay at 0 during a live commit run.

It does not move EXE-2 from PASS WITH LIMITATIONS in either direction. It
is the first concrete artifact instantiating the PASS half.

### 10.3 Contradiction tracker decision

`docs/whitepaper/contradiction.md` C4 is **not** updated by this run.

Justification:

- C4 already records: "B1 ✅ landed, B2 ✅ landed, B3 ⚠️ open, multi-validator
  P2P→consensus interconnect ⚠️ open." This run produced no new contradiction.
- The §7.3 observation (consensus-class `/metrics` counters at 0 while the
  engine commits) is **already** captured in EXE-2 §5.3 / §6.4 and in C4's
  `Description` field ("hooking [`node_metrics`] through to the consensus
  loop driver ... is part of the wider observability pass and not in scope
  for this batch"). This run *confirms* that gap in vivo, but does not
  *sharpen* it: no new degree of severity, no widened scope, no missed
  dependency surfaced.
- EXE-2 §9 explicitly states: "no existing contradiction is materially
  sharpened beyond what C4 already records." This run does not change that.
- The problem statement's contradiction-handling rule says to update only
  if the run reveals a new genuine unresolved contradiction or materially
  sharpens C4. Neither condition is met.

If a future evidence run (e.g., an attempted multi-validator binary-path
LocalMesh or P2P run, or a B3 restore attempt) surfaces new behaviour,
C4 should be revisited at that time, not now.

---

## 11. Recommended Immediate Next Action

Pick **one** of the following two options. Both are real follow-ups; neither
broadens the scope of EXE-2.

**Option A (preferred — closes a real-from-binary observability gap, small change):**
Wire the binary-path consensus loop into `Arc<NodeMetrics>` so that a future
DevNet evidence run can prove consensus progress *from `/metrics` alone*,
not only from the exit-time `[binary-consensus] Loop exit: ...` line. This
is exactly EXE-2 §6.4's "Suggested next action type: Code (small)" and is
the smallest improvement that turns Run 002 into a self-contained scrape-only
artifact. Concretely: pass `Arc<NodeMetrics>` into `spawn_binary_consensus_loop`,
and update the existing consensus counters from the live
`BinaryConsensusLoopProgress` snapshot on each tick. After landing, re-run
this evidence shape and confirm Class-A counters move.

**Option B (closes the open half of C4 and unblocks C4-related drill evidence):**
Implement `--restore-from-snapshot <path>` startup ingestion (B3) using the
existing `StateSnapshotter` checkpoint format, per EXE-2 §10 action 1. This
closes C4(c). Pair it with one DevNet drill run that produces template-shaped
restore evidence as Run 002 (or 003).

Both options are bounded, single-purpose, and grounded in EXE-2 §10. This
document does **not** recommend attempting multi-validator binary-path DevNet
yet — that depends on the P2P→consensus interconnect work (EXE-2 §6.2 /
action 2), which is a larger code change and should land before — not as
part of — its first evidence run.

**Default recommendation:** Option A. It is the smallest change with the
highest evidence-value uplift (turns the next evidence run into a
single-curl scrape proof) and directly addresses the only confirmed live
limitation surfaced by Run 001.