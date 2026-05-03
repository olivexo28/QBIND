# QBIND DevNet Readiness Audit

**Status:** Canonical (EXE-2 deliverable)
**Audience:** Internal — protocol engineering, ops, release management
**Inputs:** EXE-1 (`docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md`); `docs/whitepaper/contradiction.md` C4; B1+B2+B4 follow-up batch.

---

## 1. Purpose and Scope

This document is the EXE-2 deliverable. It answers, against the actual repository state today, the single core question:

> Can QBIND, from the real repo and real binary path, support a minimal DevNet bring-up that matches the canonical DevNet posture closely enough to begin execution evidence collection?

It does **not** assess Alpha, Beta, or MainNet readiness. It does **not** assess backup/recovery readiness. It does **not** restate protocol correctness — that is covered by `docs/protocol/QBIND_PROTOCOL_REPORT.md`, the `m*`/`t*` test suites, and contradiction.md.

EXE-2 is bounded to one question: is the DevNet starting point real now, or still paper-only?

In scope:

- **A.** Binary operability via `qbind-node` (consensus loop, view/commit progression, clean shutdown).
- **B.** Config and environment reality (DevNet defaults, environment separation).
- **C.** Metrics / observability baseline at the binary layer (`/metrics`).
- **D.** Operator bring-up practicality (DevNet Operational Guide §8 against the actual startup path).
- **E.** Minimal DevNet topology: what is honestly supported now (single-validator vs multi-validator).
- **F.** Immediate blockers that prevent honest DevNet evidence collection.

Out of scope: long-running soak, multi-region, restore drills, chaos, RPC, MainNet economics finalization.

---

## 2. Canonical Sources and Repo Paths Audited

**Canonical docs (treated as authoritative input):**

- `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` (§6 capabilities, §7 configuration, §8 bring-up, §11 observability, §13 exit criteria, §15 operator checklist)
- `docs/whitepaper/contradiction.md` (C4 — partial/open)
- `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` (EXE-1: §5.1–§5.3, §6.1–§6.3, §9 B1/B2/B3/B4)
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` (signal class baseline, referenced indirectly)
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` (referenced for B3 status)
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md` (DevNet → TestNet Alpha exit criteria)

**Repo paths grounded against:**

- Binary entry and wiring:
  - `crates/qbind-node/src/main.rs` (`run_local_mesh_node`, `run_p2p_node`)
  - `crates/qbind-node/src/binary_consensus_loop.rs` (B1 driver)
  - `crates/qbind-node/src/metrics_http.rs` (B2 `/metrics` server, `MetricsHttpConfig::from_env`)
  - `crates/qbind-node/src/cli.rs` (CLI surface)
  - `crates/qbind-node/src/p2p_node_builder.rs` (KEMTLS transport + `P2pConsensusNetwork`)
- Engine and harness anchors:
  - `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (engine driven by the binary loop)
  - `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs` (B1+B2+B4 regression)
  - `crates/qbind-node/tests/localmesh_integration_tests.rs` (single-node consensus reference behaviour)
- Config and environment defaults:
  - `crates/qbind-node/src/node_config.rs` (`devnet_v0_preset`, `validate_p2p_config`, `validate_mainnet_invariants`)
  - `crates/qbind-types/src/primitives.rs` (`NetworkEnvironment`, per-env `ChainId`)
  - `crates/qbind-genesis/src/lib.rs` (single embedded genesis builder)
- Snapshot surfaces (B3 status):
  - `crates/qbind-ledger/src/state_snapshot.rs` (creation only; no startup ingestion path)

---

## 3. Audit Method

This is an **execution-grounded audit, not a plan**. Method:

- Each canonical claim was checked against the binary path actually exercised by `qbind-node`'s `tokio::main`, the regression tests in `binary_path_b1_b2_b4_tests.rs`, and the configuration defaults in `node_config.rs`.
- "The doc says so" is **not evidence**. Items are only marked ready if the repo currently supports them.
- Classification is conservative. Where a behaviour is real but bounded, it is recorded under "Partially Ready" with the bound stated.
- Single-validator DevNet and multi-validator DevNet are evaluated and reported **separately**. They have materially different support today; collapsing them would overclaim.
- "Harness-only" capabilities (those exercised solely by `NodeHotstuffHarness`-style integration tests) are **not** counted as binary-path readiness; they are recorded as "harness evidence exists" where relevant.

---

## 4. Confirmed DevNet-Ready Areas

The following are genuinely ready enough for DevNet use now via the real binary path.

### 4.1 Binary starts and drives a real consensus loop in single-validator LocalMesh

- **Area:** Binary operability (DevNet Operational Guide §6.1, §8.4–§8.6).
- **Repo evidence:**
  - `crates/qbind-node/src/main.rs::run_local_mesh_node` calls `spawn_binary_consensus_loop` (lines ~185–225) instead of the previous "build transport, idle" stub.
  - `crates/qbind-node/src/binary_consensus_loop.rs::run_binary_consensus_loop` constructs a `BasicHotStuffEngine` with a uniform validator set, drives `try_propose()` on a tokio interval, and records `proposals_emitted`/`commits`/`current_view` progress.
  - Regression: `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs::b1_binary_consensus_loop_actually_drives_consensus` asserts ≥1 proposal emitted and `current_view > 0` within 5 s.
- **Practical meaning for DevNet:** A single-validator DevNet smoke (`qbind-node --env devnet --validator-id 0`) reaches a real proposing/voting/committing path. C4(a) is closed at the binary layer.

### 4.2 `/metrics` HTTP endpoint is spawned by the binary

- **Area:** Observability baseline (DevNet Operational Guide §6.6, §7.7, §8.7, §11.1–§11.2).
- **Repo evidence:**
  - `crates/qbind-node/src/main.rs` lines ~125–143 unconditionally constructs `MetricsHttpConfig::from_env()` and calls `spawn_metrics_http_server_with_crypto`, gated on `QBIND_METRICS_HTTP_ADDR`.
  - When unset, startup logs explicitly say the server is disabled (`[metrics] Metrics HTTP server disabled (set QBIND_METRICS_HTTP_ADDR=host:port to enable)`).
  - Regression: `binary_path_b1_b2_b4_tests.rs` exercises the same spawn helper as the binary and asserts `/metrics` is reachable and serves Prometheus-format output.
- **Practical meaning for DevNet:** Operators can scrape Prometheus metrics from a live `qbind-node` process. C4(b) is closed at the binary layer. Class-A consensus signals (proposals, commits, view) and the existing KEMTLS / network / snapshot metric families in `crates/qbind-node/src/metrics.rs` are exposed by the same server.

### 4.3 DevNet-safe config defaults are present and explicit

- **Area:** Configuration reality (DevNet Operational Guide §6.4, §6.7, §7).
- **Repo evidence:**
  - `crates/qbind-node/src/node_config.rs::devnet_v0_preset` (lines ~4148–4200) sets DevNet to: `NetworkEnvironment::Devnet`, `ExecutionProfile::NonceOnly`, `network::disabled()`, `NetworkMode::LocalMesh`, `gas_enabled = false`, `monetary_mode = Off`, `state_retention = disabled`, `snapshot_config = disabled`, `signer_mode = LoopbackTesting`, plus DevNet-default sub-configs for mempool DoS, eviction, discovery, liveness, anti-eclipse, slashing, validator stake, and genesis source.
  - The DevNet v0 freeze (LocalMesh + `enable_p2p = false`) is preserved by `validate_p2p_config` and the doc-comment block at the top of `main.rs`.
- **Practical meaning for DevNet:** An operator running `qbind-node --env devnet ...` lands on a posture consistent with the Operational Guide §6.7 ("DevNet Policy Flexibility": gas off, simpler keys, in-memory acceptable, freer slashing).

### 4.4 Environment separation is enforced enough not to contaminate DevNet

- **Area:** Environment distinction (DevNet Operational Guide §3, §7.2).
- **Repo evidence:**
  - `crates/qbind-types/src/primitives.rs::NetworkEnvironment` distinguishes `Devnet`/`Testnet`/`Mainnet` with distinct `ChainId` constants and signing-scope strings.
  - `crates/qbind-node/src/node_config.rs::validate_mainnet_invariants` and `MainnetConfigError` reject DevNet-permissive configurations (gas off, `LoopbackTesting` signer, snapshots off, etc.) when MainNet profile is selected; DevNet does not satisfy these and cannot be silently promoted.
  - `main.rs` only invokes the MainNet validation gate when `--profile mainnet` is set, so DevNet bring-up is uncontaminated by MainNet rails.
- **Practical meaning for DevNet:** DevNet defaults are walled off from MainNet-grade invariants. There is no risk of a DevNet operator accidentally satisfying a MainNet readiness gate from a DevNet run.

### 4.5 Clean shutdown on the binary path

- **Area:** Operator practicality (Operational Guide §10.2 graceful shutdown step).
- **Repo evidence:**
  - `main.rs::run_local_mesh_node` and `run_p2p_node` both await `tokio::signal::ctrl_c()`, drop the consensus shutdown channel, and `await` the consensus task. The metrics shutdown channel is dropped after, and the metrics task is awaited.
- **Practical meaning for DevNet:** A DevNet operator can `Ctrl+C` the node and observe ordered teardown (consensus loop first, then metrics server) — adequate for the Operational Guide's restart-rehearsal cycle in single-validator mode.

### 4.6 B4 (legacy MainNet doc references) is closed in the binary's user-facing paths

- **Area:** Operator trust in documentation pointers (Operational Guide Appendix A).
- **Repo evidence:**
  - `crates/qbind-node/src/main.rs` MainNet error branch points at `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` and `docs/protocol/QBIND_PROTOCOL_REPORT.md` rather than the retired `QBIND_MAINNET_V0_SPEC.md`.
  - `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs` includes a reference-cleanup guard test enumerating the retired doc names.
  - Surviving mentions of retired names in `node_config.rs` (lines 3509, 4380) and test headers (`t185`, `t222`, `t223`, `t234`, `t236`, `t237`, `t238`) are now retirement notes (e.g., "legacy `QBIND_MAINNET_V0_SPEC.md` was retired"), not live pointers. Operators following error messages no longer land at a missing doc.
- **Practical meaning for DevNet:** DevNet operators are not misdirected by stale MainNet pointers. (One residual incidental reference in `crates/qbind-ledger/src/monetary_state.rs:1112` — "QBIND_MAINNET_V0_SPEC §4.1" — is in an internal Rustdoc comment, not user-facing, and does not affect DevNet bring-up.)

---

## 5. Partially Ready Areas

The following exist with clear, specific limits.

### 5.1 Multi-validator LocalMesh from the binary

- **What works:** With `static_peers` configured, `run_local_mesh_node` computes `num_validators = static_peers.len() + 1`, instantiates the engine with that validator set, and drives `on_leader_step` each tick. When the local validator is leader, it proposes.
- **What does not work:** There is no in-process LocalMesh transport routing inbound proposals/votes from other validators back into the engine's `on_proposal_event`/`on_vote_event`. The binary explicitly logs this limitation: *"Multi-validator LocalMesh ({n} validators): the binary drives leader proposal; multi-node message ingestion is not yet wired into the binary path (covered by NodeHotstuffHarness integration tests)."* (`main.rs` lines ~207–214). Therefore, with `num_validators > 1`, the binary will not commit blocks; it will only propose-and-stall.
- **Acceptable for initial DevNet evidence?** **No** for multi-node consensus evidence. Yes only as a transparent surface where the binary accurately reports its capabilities — the limitation is logged, not silently faked.

### 5.2 Multi-validator P2P from the binary

- **What works:** `run_p2p_node` builds the P2P transport (`P2pNodeBuilder::build` → KEMTLS, demuxer, `P2pConsensusNetwork`) and concurrently spawns the same binary consensus loop. CLI flags `--enable-p2p`, `--p2p-listen-addr`, `--p2p-peer` are wired and the misconfiguration `--network-mode p2p` without `--enable-p2p` fails clearly (no silent LocalMesh fallback).
- **What does not work:** Inbound P2P consensus messages are not routed from `P2pConsensusNetwork` into the engine's `on_proposal_event`/`on_vote_event`. The transport is up; the consensus engine cannot see what the transport receives. C4 still tracks this as outstanding (the binary-path P2P→consensus interconnect).
- **Acceptable for initial DevNet evidence?** **No** for multi-node DevNet evidence collection. Multi-node consensus evidence today still has to come from `NodeHotstuffHarness`/`t132`/`t138`/`t160`-style harnesses, not from the binary.

### 5.3 Observability sufficiency

- **What works:** `/metrics` is served. `crates/qbind-node/src/metrics.rs` defines a comprehensive surface — consensus inbound/outbound vote and proposal counters, KEMTLS metrics, snapshot metrics, evidence-ingestion metrics, peer counters.
- **What does not work / is bounded:** `main.rs` itself notes that "hooking [`node_metrics`] through to the consensus loop driver (so that view advances, QC formations and commits update Prometheus counters) is part of the wider observability pass and not in scope for this batch." That is, the **metrics endpoint is up**, but the **binary consensus loop does not yet update the consensus counters** of `NodeMetrics`. As a result, scraping `/metrics` from a running DevNet single-validator binary will return the metric series with their initial (zero) values for the consensus class even while the engine is committing blocks. Only `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs` proves the endpoint serves; no test asserts that the counters it serves reflect binary-path commits.
- **Acceptable for initial DevNet evidence?** **Yes, with caveat.** It is acceptable for the first DevNet exercise — the endpoint exists, and it can collect the network/KEMTLS/snapshot families that are wired elsewhere. It is **not yet sufficient** for the Monitoring and Alerting Baseline's full Class-A consensus signal expectations on the binary path. This is a follow-up observability pass.

### 5.4 Operator bring-up walkthrough vs. real startup path

- **What works:** Operational Guide §8.4 ("Start node process") and §8.7 ("Verify metrics exposure") map cleanly onto:
  - `qbind-node --env devnet --validator-id 0` (single-validator smoke), and
  - `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 qbind-node --env devnet --validator-id 0` (with metrics).
  Both shapes are documented as the canonical bring-up examples in `crates/qbind-node/src/main.rs` lines 8–22.
- **What does not work / is bounded:**
  - Operational Guide §7.5 lists "Consensus, RPC, metrics ports." There is **no JSON-RPC server** in `qbind-node` (EXE-1 §6.7). DevNet operators following that wording will not find an RPC port to verify.
  - Operational Guide §8.7 lists "Verify health endpoint." There is **no `/health` or `/ready` endpoint** in `metrics_http.rs` (EXE-1 §6.8); only `/metrics` is served.
  - Operational Guide §9 (validator bring-up) §9.5 expects "Verify vote inclusion" / "Verify proposal participation". For multi-validator setups this is not achievable from the binary path today (§5.1, §5.2).
- **Acceptable for initial DevNet evidence?** **Yes for single-validator bring-up**, with operator notes that RPC and health endpoints are not implemented and that multi-validator verification still uses harness evidence.

### 5.5 Per-environment genesis distinctness

- **What works:** `NetworkEnvironment` and `NodeConfig::devnet_v0_preset` give DevNet a coherent runtime posture distinct from TestNet/MainNet.
- **What does not work / is bounded:** `crates/qbind-genesis/src/lib.rs::build_genesis_param_registry` is environment-agnostic — the same constants are written regardless of `NetworkEnvironment`, and the constants are self-described as "placeholder numbers, changeable via governance" (EXE-1 §5.4, §6.6). MainNet uses external genesis (T232). For DevNet this is acceptable — DevNet may use the embedded genesis — but operators must understand the embedded constants are not MainNet-fit.
- **Acceptable for initial DevNet evidence?** **Yes.** DevNet's mandate explicitly tolerates dev-defaulted parameters (Operational Guide §6.4, §6.7).

---

## 6. Remaining DevNet Blockers

The following remain blockers for some — not all — DevNet evidence classes.

### 6.1 No restore-from-snapshot path in the binary (B3)

- **Why it matters:** The DevNet Operational Guide §10.5 expects DevNet to be the place where state-recovery is rehearsed. The Backup and Recovery Baseline §C1–§C5 expects restore proofs as evidence. `crates/qbind-ledger/src/state_snapshot.rs` produces snapshots; `crates/qbind-node/src/main.rs`, `cli.rs`, and `p2p_node_builder.rs` contain no `--restore-from-snapshot` / `load_snapshot` / `apply_snapshot` invocation. A DevNet operator cannot demonstrate boot-from-snapshot end-to-end via the binary.
- **Blocks:** Backup/recovery rehearsal evidence (Operational Guide §10.5, §13.1 "Restart Safety" partially).
- **Does NOT block:** Initial single-validator DevNet bring-up, basic consensus evidence, basic observability. DevNet may begin without restore proofs and add them when B3 lands.
- **Suggested next action type:** Code + ops. Implement `--restore-from-snapshot <path>` ingestion at startup using the existing `StateSnapshotter` checkpoint format, and pair it with a drill script that produces template-shaped restore evidence.

### 6.2 No multi-validator binary-path P2P → consensus interconnect

- **Why it matters:** The DevNet Operational Guide §6.1 "Multi-node consensus (≥4 nodes) Required" and §13.1 ("Multi-node consensus stable (≥4 nodes), ≥72 hours continuous") **are exit criteria toward TestNet Alpha**, not minimal DevNet bring-up criteria. But DevNet evidence collection for those exit criteria does require multi-node consensus from real binaries. Today, multi-node consensus is exercised only by `NodeHotstuffHarness`-style integration tests; the binary path does not route inbound P2P proposals/votes into the engine.
- **Blocks:** DevNet→TestNet Alpha exit criteria evidence (4-node soak, view/round progression across processes, leader rotation observed in production-shape binaries). Operator drills involving multi-validator consensus.
- **Does NOT block:** Initial single-validator DevNet bring-up; "is the binary alive" evidence; metrics endpoint exercise; protocol correctness (already covered by harness tests).
- **Suggested next action type:** Code. Wire `P2pConsensusNetwork` inbound dispatch into `BasicHotStuffEngine::on_proposal_event` / `on_vote_event` from the binary, mirroring how `NodeHotstuffHarness` already does it for tests.

### 6.3 No `/health` or `/ready` endpoint

- **Why it matters:** The DevNet Operational Guide §8.7 expects health/readiness verification, and §11.1 lists "Health signals" as required. `metrics_http.rs` serves only `/metrics`. EXE-1 §6.8 noted this as a doc-or-cheap-code gap.
- **Blocks:** Operator-checklist completion against §15.2 ("Health endpoint returning healthy status"), and Kubernetes/Nomad-style readiness probes if any DevNet operator wants them.
- **Does NOT block:** Single-validator DevNet evidence collection — `/metrics` returning a 200 and the consensus loop emitting proposals is sufficient for an internal smoke.
- **Suggested next action type:** Code (cheap). Add `/health` returning `200 OK` once the consensus loop has reported any tick, and `/ready` returning `200 OK` once any commit has been observed. Or accept the gap and tighten the Operational Guide §8.7 wording in a later docs pass.

### 6.4 Consensus counters not yet driven from the binary loop

- **Why it matters:** Per §5.3 above, the binary consensus loop does not currently publish into `NodeMetrics` consensus counters. A DevNet operator scraping `/metrics` will see an alive endpoint but not see consensus progress reflected in the consensus class — which weakens monitoring evidence even though the engine is genuinely committing.
- **Blocks:** Monitoring baseline Class-A consensus signal evidence from the binary path; later operator drills that depend on consensus-progress alerting.
- **Does NOT block:** First DevNet bring-up, "endpoint up" evidence, network/KEMTLS/snapshot metric classes.
- **Suggested next action type:** Code (small). Pass `Arc<NodeMetrics>` into `spawn_binary_consensus_loop` and update consensus counters on each tick (proposals emitted, commits, current view, committed height) from the existing `BinaryConsensusLoopProgress` snapshot.

### 6.5 Operator artifact packaging not produced

- **Why it matters:** Even minimal DevNet evidence requires reproducible operator artifacts (config file, run command, expected log shape, expected metric output, expected exit behaviour). These are documented in the Operational Guide but not collected anywhere as a usable bundle in the repo. EXE-1 §5.5 records this as a doc/process gap.
- **Blocks:** Operator drill consistency, evidence-template instantiation.
- **Does NOT block:** A single engineer manually following Operational Guide §8 for a one-off DevNet smoke.
- **Suggested next action type:** Ops. Produce the first DevNet bring-up evidence packet from a real `qbind-node` run.

---

## 7. Supported DevNet Modes (What Actually Works Now)

This is the clearest answer in the document.

**Supported now (binary path):**

- **Single-validator DevNet via binary path: YES.**
  `qbind-node --env devnet --validator-id 0` starts the consensus loop, proposes, self-quorums, advances views, and commits blocks. With `QBIND_METRICS_HTTP_ADDR` set, `/metrics` is served. Clean shutdown on `Ctrl+C`.

- **Single-validator DevNet with metrics: YES.**
  `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 qbind-node --env devnet --validator-id 0`. Endpoint returns Prometheus-format output. Network/KEMTLS/snapshot families are present; consensus class counters are not yet driven from the binary loop (§5.3, §6.4).

- **Multi-validator local DevNet via binary path (LocalMesh): PARTIAL.**
  Engine is configured with the right validator-set size; the local validator proposes when leader. There is no inbound message routing, so commits do not occur with `num_validators > 1`. The limitation is logged at startup, not silently faked.

- **Multi-validator DevNet via binary path (P2P): PARTIAL.**
  P2P transport (KEMTLS) comes up; the consensus loop runs alongside; inbound P2P consensus messages are not yet routed into the engine. Multi-node commits via the binary are not achievable today.

- **Harness-based multi-node DevNet: YES (out-of-binary).**
  `NodeHotstuffHarness`, `t132`/`t138`/`t160`/`localmesh_integration_tests`, etc., already exercise multi-node consensus end-to-end. This is real protocol-level evidence; it is not real binary-path evidence.

**Notes / limitations:**

- "DevNet bring-up" in the canonical Operational Guide §6.1 implies multi-node consensus. The binary path supports the single-node form of that today; the multi-node form is still harness-only.
- DevNet exit criteria toward TestNet Alpha (Operational Guide §13.1) require multi-node + 72h soak. **Those exit criteria are not met by EXE-2 and were never expected to be.** EXE-2 only addresses whether DevNet evidence collection can begin, not whether it can complete.

---

## 8. Gaps Between DevNet Docs and Real Repo State

Each row: doc claim / repo reality / acceptable-as-is or later tightening.

| Operational Guide reference | Implies | Repo reality | Acceptable as-is? |
|---|---|---|---|
| §6.1 *Multi-node consensus required (≥4 nodes)* | Multi-node consensus operable from validator binaries | Single-validator binary path real; multi-validator commits binary-path-blocked (§5.1, §5.2, §6.2). Harness evidence exists. | **As-is for now.** §6.1 is an exit criterion, not a Day-1 DevNet posture. Consider future clarification that multi-node DevNet evidence currently flows through harnesses pending B3-equivalent multi-node binary work. |
| §6.6, §11.1 *Metrics required* | Prometheus endpoint reachable from a running node | `/metrics` endpoint live (gated by `QBIND_METRICS_HTTP_ADDR`); consensus counters not yet driven from the binary loop (§5.3, §6.4). | **As-is** for first DevNet exercise. Tighten later if consensus-class counters remain decoupled from the binary loop after the next observability pass. |
| §7.5 *Consensus, RPC, metrics ports* | An RPC port exists | No JSON-RPC server in `qbind-node`. | **Not as-is**: Operational Guide should remove "RPC port" wording in a later docs pass (EXE-1 §6.7). Out of scope for EXE-2. |
| §7.7 *Metrics endpoint* | A Prometheus-compatible endpoint exists | True now (B2). | **As-is, accurate.** |
| §8.4 *Start node process* | Running the binary brings up a node that produces blocks | True for single-validator (B1); not for multi-validator (§5.1, §5.2). | **As-is** for single-validator DevNet smoke. The guide does not promise multi-node from a single command, so this is not strictly inaccurate; later tightening could call out single-vs-multi explicitly. |
| §8.7 *Verify health endpoint* | A `/health` endpoint exists | None (§6.3, EXE-1 §6.8). | **Not as-is**: either land the cheap `/health` endpoint or drop the wording (EXE-1 §6.8). Out of scope for EXE-2 to fix. |
| §9.5 *Verify vote inclusion / proposal participation* | Operator can see votes/proposals from a multi-validator binary network | Today, only via harnesses (§5.2, §6.2). | **Not as-is for multi-validator**. Acceptable for single-validator (where leader self-vote is the QC). |
| §10 *Restart and reset policy* | DevNet exercises restart and recovery | Single-validator binary restart works (clean shutdown supported). State recovery (snapshot-restore) is **not** supported (§6.1). | **As-is for restart**, **not as-is for recovery**. Recovery requires B3. |
| §11.1 *Health signals required* | A health endpoint exists | None. | **Not as-is**: either land the cheap `/health` endpoint or drop the wording (EXE-1 §6.8). Out of scope for EXE-2 to fix. |
| §13.1 *DevNet → TestNet Alpha exit criteria* | Multi-node consensus, 72h soak, restart safety, observability operational | Multi-node binary-path consensus not yet operable; restore not supported; observability endpoint up but consensus counters not bound to binary loop | **As-is**: these are exit criteria, not bring-up criteria. EXE-2 is not the gate that satisfies §13.1. |
| Appendix A doc references | All listed canonical docs exist | True (legacy MainNet docs already retired, B4). | **As-is, accurate.** |

The Operational Guide does not need rewriting for EXE-2. The recorded gaps (RPC wording, health-endpoint wording, single-vs-multi explicitness) are doc-side cleanups appropriate for a later pass and are already tracked by EXE-1 §6.7 and §6.8.

---

## 9. DevNet Readiness Verdict

**Verdict: PASS WITH LIMITATIONS.**

QBIND can, from the real repo and real binary path, support a minimal DevNet bring-up that matches the canonical DevNet posture closely enough to **begin** execution evidence collection.

Specifically:

- Single-validator DevNet smoke is real: the binary starts, runs a real consensus loop, advances views, commits blocks, exposes a Prometheus `/metrics` endpoint when configured, separates DevNet config from MainNet rails, and shuts down cleanly. This is a genuine starting point — not a paper artifact.
- However, "DevNet" in the Operational Guide's full sense (multi-node consensus, restore-from-snapshot rehearsal, full Class-A observability, validator participation verification across processes) is **not yet** achievable from the binary path. Those evidence classes remain harness-only or unsupported.

Therefore EXE-2 passes — but with the explicit limitation that initial DevNet evidence is bounded to single-validator binary smoke + observability endpoint exercise, plus the existing harness-grade multi-node protocol evidence. Multi-node binary-path evidence and recovery evidence are **deferred to subsequent execution actions**.

This verdict is consistent with `docs/whitepaper/contradiction.md` C4 status: "OPEN — partial (B1 and B2 landed; B3 snapshot-restore still outstanding)". No new contradiction is opened by this audit; no existing contradiction is materially sharpened beyond what C4 already records.

---

## 10. Next Execution Actions

In priority order:

1. **B3 — Implement `--restore-from-snapshot <path>` startup ingestion.** Use the existing `StateSnapshotter` checkpoint format (`meta.json` + `state/`). Pair it with a one-page DevNet drill script that captures restore-proof evidence. Closes C4(c) and unblocks Backup/Recovery DevNet evidence (Operational Guide §10.5; Backup/Recovery Baseline §C1–§C5).
2. **Wire multi-validator binary-path P2P → consensus interconnect.** Route inbound proposals/votes from `P2pConsensusNetwork` into `BasicHotStuffEngine::on_proposal_event` / `on_vote_event` from `run_p2p_node`. Mirrors `NodeHotstuffHarness`. Closes the residual half of C4 and is the prerequisite for any honest multi-node DevNet evidence.
3. **First DevNet evidence-collection run (single-validator binary).** Execute `qbind-node --env devnet --validator-id 0` with `QBIND_METRICS_HTTP_ADDR` set; capture: startup banner, view/commit progression, `/metrics` scrape sample, clean-shutdown log. Produce the first Operator Drill Catalog-shaped artifact instance for DevNet (EXE-1 §5.5 process gap closure).
4. **Monitoring baseline exercise.** Stand up Prometheus + minimal dashboard; confirm which baseline classes (Class A / C / D / E / F per `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`) are visible from the binary today and record the gap to inform §6.4 (binding consensus counters into the binary loop) and follow-up code.
5. **First operator drill batch.** From the canonical Operational Guide §15 checklists, exercise single-validator restart and graceful-shutdown drills. Defer multi-validator and restore drills until actions 1 and 2 land.

---

## Appendix A: Document References

| Document | Location | Relationship |
|---|---|---|
| DevNet Operational Guide | `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` | Canonical DevNet posture audited here |
| Repo / Code ↔ Doc Alignment Audit (EXE-1) | `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` | Predecessor audit; B1/B2/B3/B4 origin |
| Contradiction Tracker | `docs/whitepaper/contradiction.md` | C4 (partial-open) tracks the same execution surface |
| Monitoring and Alerting Baseline | `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` | Signal-class expectations referenced in §5.3, §6.4 |
| Backup and Recovery Baseline | `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` | B3 / restore-proof expectations referenced in §6.1 |
| Release Track Spec | `docs/release/QBIND_RELEASE_TRACK_SPEC.md` | DevNet → TestNet Alpha exit criteria referenced in §8 |

---