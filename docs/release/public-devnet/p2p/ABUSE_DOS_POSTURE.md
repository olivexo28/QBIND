# QBIND Public DevNet — Abuse / DoS Posture (Run 360)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

This document describes the **abuse / DoS posture** for QBIND public DevNet against the **existing**
source surfaces (`crates/qbind-node/src/peer_rate_limiter.rs`, `metrics.rs`, `p2p_tcp.rs`). Run 360
changes **no** rate-limiter implementation, adds **no** CLI flag, and invents **no** threshold. Where
a configurable production threshold does not exist, that gap is recorded honestly (see §7).

## 1. Existing peer rate-limiter surface

The node ships a **per-peer inbound message rate limiter** implemented in
`crates/qbind-node/src/peer_rate_limiter.rs`:

- **Type:** `PeerRateLimiter` with `PeerRateLimiterConfig { max_messages_per_second, burst_allowance }`.
- **Algorithm:** a sharded token bucket per peer. Bucket capacity =
  `max_messages_per_second + burst_allowance`; refill rate = `max_messages_per_second` tokens/sec;
  each admitted message consumes one token, and a peer over budget has its message **dropped** (the
  connection itself is not torn down by the limiter).
- **Sharding:** peers are sharded across `NUM_SHARDS = 16` for concurrency.
- **Scope:** it limits **inbound consensus message rate per peer**. It is a message-rate control, not
  a connection-admission control.

## 2. Current defaults

The rate limiter is constructed with hardcoded defaults (`peer_rate_limiter.rs`):

| Constant | Value | Meaning |
|----------|-------|---------|
| `DEFAULT_MAX_MESSAGES_PER_SECOND` | `1000` | Sustained inbound messages/sec per peer. |
| `DEFAULT_BURST_ALLOWANCE` | `100` | Extra token-bucket capacity for short bursts (epoch transitions, view changes). |
| `NUM_SHARDS` | `16` | Peer shard count. |

The source rationale: for a ~100-validator network at ~10 rounds/sec, legitimate aggregate traffic is
on the order of ~1000 msgs/sec (~10/s per peer); the 1000/s per-peer limit is deliberately
conservative (high) to avoid false positives while still catching abusive floods.

## 3. What is enabled by default vs configurable

- **Enabled by default:** the per-peer rate limiter is active — the node uses
  `PeerRateLimiter::with_defaults()`, so the `1000` msg/s + `100` burst posture applies without any
  operator action.
- **Not operator-configurable via CLI:** the thresholds are **hardcoded constants**. There is **no**
  `qbind-node` CLI flag (and no documented config-file key in `qbind-node --help`) to change
  `max_messages_per_second` or `burst_allowance`. An operator cannot retune them without a source
  change, which is out of scope for Run 360.
- **Failure mode:** the limiter fails **open** on internal lock poisoning (it returns "allow") — it
  is a best-effort abuse control, not a hard security boundary.

## 4. Connection / handshake surfaces

- **P2P disabled by default:** `--enable-p2p` defaults to `false`, so a default node accepts **no**
  inbound connections at all (strongest default DoS posture).
- **Peer tracking cap:** metrics track at most `MAX_TRACKED_PEERS = 128` distinct peers
  (`metrics.rs`); this bounds per-peer metric memory, not connection count.
- **Admission is fail-closed:** untrusted/malformed/wrong-genesis peers are rejected at the KEMTLS
  handshake / trust-bundle load (see `PEER_ADMISSION_POLICY.md` §7), so malformed peers are dropped
  before consuming consensus resources.
- **Dial retry policy:** outbound dials to `--p2p-peer` use a retry policy in `p2p_tcp.rs`; operators
  should avoid configuring unreachable static peers to prevent avoidable outbound dial loops.

## 5. Metrics / logs operators should watch

Exact metric/counter surfaces (`crates/qbind-node/src/metrics.rs`):

- **Rate-limit drops (primary abuse signal):**
  - per-peer `rate_limit_drop` counter (`inc_rate_limit_drop`, `peer_rate_limit_drop_count`);
  - aggregate `total_rate_limit_drops()`.
- **Per-peer disconnects:** `consensus_net_peer_disconnect_total{peer,reason="eof|error|shutdown"}`.
- **Per-peer inbound volume:** `consensus_net_peer_inbound_total{peer,kind="vote|proposal|other"}`.
- **Outbound drops:** `consensus_net_peer_outbound_drop_total{peer}`,
  `consensus_net_outbound_dropped_total{priority}`.
- **Trust-bundle / handshake health:**
  `qbind_p2p_pqc_trust_bundle_loaded`, `qbind_p2p_pqc_trust_bundle_environment`,
  `qbind_p2p_pqc_trust_bundle_active_roots`, `qbind_p2p_pqc_trust_bundle_revoked_roots`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total`,
  `qbind_p2p_pqc_trust_bundle_signature_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`.

See the monitoring baseline (`docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`) and the PQC trust
lifecycle runbook (`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) for alerting guidance.

## 6. Minimum public DevNet recommended posture

For a future public DevNet seed exposure, the minimum recommended posture is:

- **Inbound connection rate:** keep `--p2p-mutual-auth required` so unauthenticated inbound peers are
  rejected at the handshake; front the public port with host-level firewalling appropriate to the
  advertised port. (No per-connection-rate CLI knob exists in `qbind-node`; enforce at the host/LB
  layer.)
- **Outbound dial failure loops:** configure only reachable `--p2p-peer` entries (only `status:
  "live"` seed-list entries); never dial placeholder/non-routable hosts. Watch
  `consensus_net_peer_disconnect_total{reason="error"}` for repeated failures.
- **Malformed peer traffic:** rely on fail-closed admission (untrusted/malformed peers rejected at
  handshake); alert on spikes in disconnects with `reason="error"`.
- **Handshake failures:** alert on rising trust-bundle signature rejections
  (`qbind_p2p_pqc_trust_bundle_signature_rejected_total`) and disconnect-error rates.
- **Trust-bundle validation failures:** alert on `qbind_p2p_pqc_trust_bundle_signature_rejected_total`
  and `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`; treat sustained rejection as a
  possible poisoning attempt.
- **Per-peer message floods:** watch per-peer `rate_limit_drop` / `total_rate_limit_drops()`; the
  default `1000` msg/s + `100` burst limit applies automatically per peer.
- **Peer-candidate propagation limits:** peer claims are advisory only and do not bypass ratification
  (see `PEER_ADMISSION_POLICY.md` §8); there is no operator-tunable propagation-limit CLI knob, so
  monitor rather than retune.
- **Log volume / storage hygiene:** rate-limit drops and repeated handshake failures can inflate log
  volume under abuse; rotate/cap logs and provision disk for the exposed period. Never log secret
  key material (KEM secret keys are never logged by design).

## 7. What this run does NOT implement

- Run 360 implements **no** new rate-limiter, connection-rate limiter, or DoS control, and adds **no**
  configurable threshold. It documents the **existing** per-peer message rate limiter and metrics
  only.
- **Gap (kept honest):** the per-peer rate-limiter thresholds are **hardcoded** and there is **no**
  operator-facing CLI/config surface to tune them, and there is **no** per-connection-rate or global
  inbound-connection-rate limiter exposed in `qbind-node`. Because the abuse/DoS surface is real and
  documented but the key thresholds are **not operator-configurable** and connection-rate limiting
  must be enforced externally, **M12 remains Yellow/Partial** — see
  `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## 7a. Run 361 source/test hardening boundary (no runtime change)

Run 361 landed a **source/test-only** boundary that makes the abuse/DoS posture operator-configurable
at the type level and introduces a pure, deterministic inbound connection-rate limiter model:

- Module: `crates/qbind-node/src/public_devnet_abuse_dos_config.rs`.
- Tests: `crates/qbind-node/tests/run_361_public_devnet_abuse_dos_hardening_tests.rs` (30 tests).
- `AbuseDosConfig` — typed model for per-peer max messages/sec + burst, global inbound
  connection-rate window + burst, optional per-remote-address window, a fail-open/fail-closed marker,
  environment binding, optional genesis-hash binding, and an explicit profile marker; validated to
  reject zero / nonsensical / unbounded / wrong-environment / genesis-mismatch / MainNet values.
- `ConnectionRateLimiter` + `ConnectionRateLimiterState` — a bounded token-bucket connection-rate
  limiter with deterministic outcomes (`ConnectionAllowed`, `ConnectionRateLimited`,
  `ConnectionLimiterDisabled`, `InvalidConfig`, `MainNetRefused`, `StateUnavailable`) that writes
  **only** into caller-owned fixture state.
- **Safe default:** `AbuseDosConfig::default()` preserves the current `1000` msg/s + `100` burst
  per-peer behavior and leaves the connection limiter **disabled** — importing the module changes
  nothing at runtime.

This is **source/test only**: there is **no** runtime wiring into the `p2p_tcp` accept loop, **no**
public CLI flag, and **no** default behavior change. The intended integration call site is captured as
a documentation adapter shape (`inbound_connection_adapter_shape`). No metric is registered; the future
connection-rate-drop metric name (`qbind_p2p_connection_rate_drop_total`) is reserved but not added.
Therefore **M12 stays Yellow (strengthened)** and **M12 Green is deferred to Run 362**, which must wire
the limiter into runtime, validate under load, and produce release-binary evidence. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_361.md`.

## 7b. Run 362 runtime wiring (connection-rate limiter live; default-off)

Run 362 wires the Run 361 connection-rate limiter into the **live** `p2p_tcp` accept path behind
runtime-owned, default-off state, adds a metric, and exposes hidden/devnet-only operator CLI flags:

- Runtime module: `crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs`
  (`PublicDevnetAbuseDosRuntimeConfig`, `PublicDevnetAbuseDosRuntimeState`, runtime-owned
  `ConnectionRateLimiterState`).
- Tests: `crates/qbind-node/tests/run_362_public_devnet_abuse_dos_runtime_tests.rs` (38 tests).
- Accept-loop integration: `TcpKemTlsP2pService` consults the connection-rate limiter at the top of the
  accepted-socket arm, **before** any KEMTLS handshake / trust-bundle / genesis work. An over-budget
  inbound connection is dropped deterministically (socket closed, no peer admitted). With no runtime
  state installed (the default), the accept loop is byte-for-byte the pre-Run-362 path.
- **Metric:** `qbind_p2p_connection_rate_drop_total` — an unlabeled counter on `P2pMetrics` that
  increments **only** when the connection-rate limiter refuses an inbound connection. It carries no
  endpoint labels or secrets and is registered exactly once.
- **Operator CLI (hidden / devnet-only, absent from `--help`):**
  `--p2p-connection-rate-limit-enabled`, `--p2p-connection-rate-window-ms`,
  `--p2p-connection-rate-max`, `--p2p-connection-burst`, `--p2p-max-messages-per-second`,
  `--p2p-burst-allowance`, `--p2p-per-address-connection-rate-window-ms`,
  `--p2p-per-address-connection-max`. Defaults (no flags) preserve behavior exactly; enabling requires a
  positive window + max; invalid/zero/unbounded/inconsistent values fail closed at CLI validation;
  MainNet is refused (`MainNetRefused`).
- **Default preserved:** with no flags, the limiter is disabled, per-peer defaults stay `1000` msg/s +
  `100` burst, and the accept loop is unchanged.

**M12 stays Yellow/Partial (strengthened).** The connection-rate limiter is now runtime-wired and
operator-configurable, but the live per-peer **message-rate** limiter (`PeerRateLimiter` in
`async_peer_manager`) is still not operator-configurable at runtime — the message-rate flags are
validated into the runtime config but inert against it. M12 Green remains deferred pending per-peer
message-rate runtime override + load evidence. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md` and
the release-binary evidence archive
`docs/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary/`.

## 7c. Run 363 per-peer message-rate runtime override (source/test only)

Run 363 wires the per-peer message-rate runtime override at **source/test level**, closing the Run 362
gap where the `--p2p-max-messages-per-second` / `--p2p-burst-allowance` flags were validated but inert
against the live per-peer limiter:

- `PublicDevnetAbuseDosRuntimeConfig::peer_rate_limiter_config()` derives the validated
  `PeerRateLimiterConfig` from the backing `AbuseDosConfig` (non-zero, bounded max messages/sec +
  burst; MainNet refused).
- `AsyncPeerManagerConfig` gains an optional `peer_rate_limiter_config` (default `None`) and a
  `with_peer_rate_limiter_config()` builder; `AsyncPeerManagerImpl` builds the live per-peer
  `PeerRateLimiter` from it (`None` → `PeerRateLimiter::with_defaults()`).
- Tests: `crates/qbind-node/tests/run_363_public_devnet_per_peer_message_rate_runtime_tests.rs`
  (21 tests) prove the previously inert flags now reach the live limiter construction path while
  preserving defaults (`1000` msg/s + `100` burst).
- **Default preserved:** with no flags, the peer-manager limiter is bit-for-bit
  `PeerRateLimiter::with_defaults()`.

**Run 363 is source/test only.** Release-binary evidence is deferred to **Run 364**. **M12 does not go
Green until Run 364 release-binary evidence proves both connection-rate and per-peer message-rate
runtime configurability.** M12 moves `Yellow/Partial → Yellow/stronger`. M4 remains
Yellow/launch-blocking, public DevNet remains **NOT launch-ready**, and Full **C4 / C5 remain OPEN**.
See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_363.md`.

## 7d. Run 364 release-binary evidence for both controls (M12 stays Yellow)

Run 364 produces the release-binary evidence deferred by Run 363, proving **both** abuse/DoS controls
on the real `target/release/qbind-node` binary plus a release-built helper that links the production
Run 361/362/363 symbols:

- `crates/qbind-node/examples/run_364_public_devnet_abuse_dos_m12_release_binary_helper.rs` — 7
  scenarios (default-preserves-behavior; connection-rate allow-then-refuse with metric; per-peer
  message-rate allow-then-drop reaching the live `AsyncPeerManagerImpl` limiter; combined independence;
  invalid fail-closed; MainNet refused; hidden CLI surface).
- `scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh` — release harness (captures
  SHA-256 / Build ID / toolchain, runs the helper, exercises the production-binary CLI surface).
- Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`,
  `docs/devnet/run_364_public_devnet_abuse_dos_m12_release_binary/`.

**M12 stays Yellow/Partial (strengthened) — NOT Green.** The connection-rate limiter is
production-wired and release-proven. The per-peer message-rate override reaches only the live
peer-manager *construction path*; the deployed `qbind-node` (`main.rs` / `p2p_node_builder`) does not
yet thread the CLI-derived `peer_rate_limiter_config` into its live `AsyncPeerManagerImpl`, so per-peer
operator effect on a running node is not yet delivered. M4 remains Yellow/launch-blocking; public
DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 7e. Run 365 deployed-node per-peer threading (source/test only)

Run 365 closes the deployed-node source/test gap Run 364 flagged: the deployed `P2pNodeBuilder` now
threads the CLI-derived `peer_rate_limiter_config` into the live `AsyncPeerManagerImpl` construction
path.

- `crates/qbind-node/src/p2p_node_builder.rs` — `P2pNodeBuilder::deployed_peer_rate_limiter_config`
  derives the validated `Option<PeerRateLimiterConfig>`; `deployed_async_peer_manager_config` and
  `build_deployed_peer_manager` construct the live `AsyncPeerManagerImpl` from it;
  `P2pNodeContext.peer_rate_limiter_config` records the derived config on the built context.
- Tests: `crates/qbind-node/tests/run_365_public_devnet_deployed_peer_rate_threading_tests.rs` (20).
- Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_365.md`.

Defaults are preserved bit-for-bit (`None` → `PeerRateLimiter::with_defaults()`, `1000` msg/s + `100`
burst; connection limiter disabled unless explicitly enabled); the Run 362 connection-rate limiter is
unchanged; no new public CLI flags. **Run 365 is source/test only.** Release-binary end-to-end evidence
is deferred to **Run 366**. **M12 does not go Green until Run 366** proves both controls end-to-end on
the deployed binary. M4 remains Yellow/launch-blocking; public DevNet remains **NOT launch-ready**;
Full **C4 / C5 remain OPEN**.

## 7f. Run 366 deployed-builder-path release-binary end-to-end evidence

Run 366 produces the release-binary end-to-end evidence deferred by Run 365. A release-built helper
(`crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs`) links the
real Run 361/362/363/365 symbols and drives the per-peer scenarios through the **deployed**
`P2pNodeBuilder` path (`with_abuse_dos_runtime_config` → `deployed_peer_rate_limiter_config` →
`deployed_async_peer_manager_config` → `build_deployed_peer_manager`), proving both the connection-rate
limiter and the per-peer message-rate override on real `target/release/qbind-node` (8/8 scenarios).

- Harness: `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh`.
- Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md`,
  `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/`.
- No production source change; defaults preserved bit-for-bit; no new public CLI flags.

**M12 stays Yellow/Partial (strengthened) — it does NOT move Green.** A running `qbind-node` cannot be
driven over its live P2P inbound/message socket path in this environment because DevNet runs in LocalMesh
mode (`--enable-p2p` is ignored) and blocks in the consensus loop; the evidence is deployed-builder-path
release-binary, not live-socket. M4 remains Yellow/launch-blocking; public DevNet remains **NOT
launch-ready**; Full **C4 / C5 remain OPEN**.

## 7g. Run 367 live-socket release-binary evidence (connection-rate)

Run 367 fixes the Run 366 blocker. The decision gate concluded **Conclusion A**: the existing release
binary already supports a bounded P2P-capable loopback mode
(`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`), so Run 366's "`--enable-p2p`
ignored" was a consequence of defaulting to LocalMesh (no `--network-mode p2p`), not a missing mode. The
Run 367 harness launches the real `target/release/qbind-node` in that mode, confirms `P2P transport up`,
and drives real inbound TCP connections against the accept-loop connection-rate limiter
(`p2p_tcp::spawn_accept_loop` → `PublicDevnetAbuseDosRuntimeState::should_admit`), scraping the live
`/metrics` endpoint.

- Default (no flags): connection limiter disabled; `qbind_p2p_connection_rate_drop_total = 0`.
- Configured (window 60000 ms, max 3, burst 0): 3 under-budget connections admitted with the metric at 0;
  10 total connections → 3 accepted / 7 refused; live `qbind_p2p_connection_rate_drop_total = 7`.
- Helper: `crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs` (8/8).
- Harness: `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`.
- Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`,
  `docs/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary/`.
- No production source change; defaults preserved bit-for-bit; no new public CLI flags.

**M12 stays Yellow/Partial (strengthened) — it does NOT move Green.** The **connection-rate** control is
now proven live-socket, but the per-peer **message-rate** control is not yet driven over an admitted live
peer socket (it enforces on the `AsyncPeerManagerImpl` receive path and needs a second KEMTLS peer flood
harness — see Run 368 next-step). M12 Green requires both controls over a live socket. M4 remains
Yellow/launch-blocking; public DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 7h. Run 368 admitted-peer per-peer message-rate live-socket evidence

Run 368 strengthens the per-peer **message-rate** evidence from Run 367's synchronous construction-path
`PeerRateLimiter::allow()` proof to a **real admitted-peer socket** proof. The Run 368 helper stands up a
loopback TCP socket pair, registers one side as an admitted peer on a live `AsyncPeerManagerImpl` (the
component that owns the per-peer `PeerRateLimiter`) via `add_peer_with_stream`, and floods
length-prefixed `NetMessage` frames from the other side through the actual async
`AsyncPeerManagerImpl::peer_reader_task` receive loop.

- Under budget (bucket 5/0, 5 frames): all accepted; 0 per-peer drops.
- Over budget (bucket 5/0, 80 frames): dropped by the live `PeerRateLimiter` (≈75 drops observed);
  `NodeMetrics::peer_network().total_rate_limit_drops()` / `peer_rate_limit_drop_count(peer)` increment
  and `qbind_net_per_peer_drops_total{peer="…",reason="rate_limit"}` renders.
- Independence: a connection-rate refusal increments only `qbind_p2p_connection_rate_drop_total`
  (`P2pMetrics`), a per-peer flood increments only the per-peer counter (`NodeMetrics::peer_network`).
- Connection-rate regression: the Run 367 live-socket connection-rate proof is re-run on the release
  binary (10 connections, max 3 → 3 accepted / 7 refused; metric = 7).
- Helper: `crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs`
  (9/9). Harness:
  `scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh`. Evidence:
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md`,
  `docs/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary/`.
- No production source change; defaults preserved; no new public CLI flags.

**M12 stays Yellow/Partial (strengthened) — it does NOT move Green.** Decision gate = **Route C**: the
**deployed** `qbind-node` inbound path (`TcpKemTlsP2pService::subscribe` → `P2pInboundDemuxer` →
handlers) does NOT consult the `PeerRateLimiter`, and `AsyncPeerManagerImpl` is never spawned by
`main.rs`, so Run 368's per-peer proof is at the `AsyncPeerManagerImpl` layer with a plain-TCP admitted
peer, not the deployed TcpKemTls receive path and not KEMTLS mutual-auth. M12 Green requires both
controls over the deployed live socket; the remaining blocker is wiring the `PeerRateLimiter` onto the
deployed TcpKemTls receive path (recommended Run 369). M4 remains Yellow/launch-blocking; public DevNet
remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 7i. Run 369 deployed TcpKemTls receive-path per-peer wiring (source/test only)

Run 369 closes the Run 368 Route-C blocker at the source/test level: the **deployed** inbound receive
path now consults a per-peer `PeerRateLimiter` **before** demuxer/handler dispatch.

- New adapter `crates/qbind-node/src/deployed_inbound_per_peer_limiter.rs` —
  `DeployedInboundPerPeerLimiter` wraps a `PeerRateLimiter` built from the same validated
  `PeerRateLimiterConfig` the deployed builder already derives (`deployed_peer_rate_limiter_config()`),
  defaulting to the documented `1000` msg/s + `100` burst posture. It owns a self-contained bounded
  per-peer drop counter and an optional `NodeMetrics` handle used to bump the existing
  `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter.
- `crates/qbind-node/src/p2p_tcp.rs` — `TcpKemTlsP2pService` gains an optional
  `inbound_per_peer_limiter` (installed via `set_inbound_per_peer_limiter`, `has_inbound_per_peer_limiter`
  accessor). The per-peer `read_loop` consults it AFTER a frame decodes to a structured `P2pMessage` and
  BEFORE `inbound_tx.send(..)` — the exact deployed path
  `read_loop` → `inbound_tx` → `subscribe()` → `P2pInboundDemuxer` → handlers. An over-budget frame is
  dropped and the read loop CONTINUES (a per-peer message-rate drop never tears down the connection).
- `crates/qbind-node/src/p2p_node_builder.rs` — `P2pNodeBuilder::start()` installs the adapter (from
  `deployed_peer_rate_limiter_config()`, default posture when no override) before `p2p_service.start()`.
- **Peer keying (honest):** the rate-limit bucket key is a `PeerId` derived from the first 8 bytes of the
  connection `NodeId` (big-endian). This is a coarse rate-limiting bucket selector only — **not** an
  identity/authentication claim; it never feeds admission, trust-bundle validation, or any consensus /
  authority decision.
- Tests: `crates/qbind-node/tests/run_369_public_devnet_deployed_per_peer_limiter_wiring_tests.rs` (24).

**M12 stays Yellow/Partial — deployed TcpKemTls receive-path source/test wiring landed — and does NOT
move Green.** This is a source/test run; release-binary live-socket evidence over the deployed receive
path is deferred to Run 370. Defaults preserved; no new public CLI flags; no P2P wire-format change; no
admission / trust-bundle / KEMTLS weakening; the connection-rate limiter and
`qbind_p2p_connection_rate_drop_total` metric are untouched. M4 remains Yellow/launch-blocking; public
DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 7j. Run 370 deployed per-peer exported-metric threading + release-binary live-socket evidence (Route B)

Run 370 closes the Run 369 "honest limitation" that the deployed adapter was installed with
`metrics = None`, and adds release-binary live-socket evidence.

- **Source (narrow, default-preserving):** `crates/qbind-node/src/p2p_node_builder.rs` gains an optional
  `node_metrics: Option<Arc<NodeMetrics>>` field, a `with_node_metrics(..)` method, and a shared
  `build_deployed_inbound_per_peer_limiter()` seam used by both `start()` and the source tests.
  `crates/qbind-node/src/main.rs` wires `.with_node_metrics(Arc::clone(&node_metrics))` — the SAME
  `NodeMetrics` the live `/metrics` endpoint scrapes — so a per-peer drop on the deployed `read_loop`
  bumps the exported `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter. With no handle the
  adapter keeps `metrics = None` (Run 369 posture, bit-for-bit).
- **Release evidence:** `scripts/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary.sh`
  proves on real `target/release/qbind-node`: connection-rate control live-socket (10 inbound TCP
  connections, max 3 → 3 accepted / 7 refused, live `qbind_p2p_connection_rate_drop_total = 7`), default
  no-flag posture, invalid/unbounded/MainNet fail-closed, hidden CLI surface preserved; the Run 370 helper
  (10/10) drives the exact deployed adapter object and shows the exported per-peer counter incrementing on
  over-budget drops, independent of the connection-rate metric.
- Tests: `crates/qbind-node/tests/run_370_public_devnet_deployed_live_socket_m12_tests.rs` (20).

**M12 stays Yellow/Partial (strengthened) and does NOT move Green.** The residual blocker is a
KEMTLS-admitted deployed per-peer socket flood observed on live `/metrics`; the deployed per-peer evidence
here is the deployed adapter object exercised in the release helper, not a fully live KEMTLS socket flood.
Defaults preserved; no new public CLI flags; no wire-format / admission / trust-bundle / KEMTLS weakening;
M4 remains Yellow/launch-blocking; public DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 7k. Run 371 KEMTLS-admitted deployed per-peer live-socket flood — M12 Green (Route A)

Run 371 closes the Run 370 residual blocker using **only production public APIs (no source change)**.

- **Driver:** the Run 371 helper in `dial-flood` mode (built from `P2pNodeBuilder`) acts as a **second
  KEMTLS-admitted peer**, completes a **real KEMTLS mutual-auth handshake over a real loopback socket**
  against a separate running `target/release/qbind-node`, then floods structured `P2pMessage::Consensus`
  frames (discriminator `0`, so they reach the deployed per-peer limiter after `decode_frame`).
- **Live-socket evidence on real `target/release/qbind-node`:** under-budget frames → **0 per-peer drops**
  (`qbind_net_per_peer_drops_total{reason="rate_limit"}` ABSENT); over-budget frames → live `/metrics`
  exposes that counter incrementing (~47 of 60 in a representative run) with the connection kept up (no
  teardown). The Run 367/370 connection-rate live-socket proof is preserved and independent
  (`qbind_p2p_connection_rate_drop_total = 7`; the per-peer flood leaves it at 0). Invalid/unbounded/MainNet
  configs still fail the binary closed; hidden CLI surface preserved; helper scenario suite 10/10.
- Artifacts: `crates/qbind-node/examples/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper.rs`,
  `scripts/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary.sh`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`.

**M12 moves Green for the abuse/DoS deployed live-socket controls** (connection-rate + KEMTLS-admitted
deployed per-peer message-rate, both proven over real sockets on the release binary). Green is scoped to
these two controls; the flood runs over loopback with default deterministic test-grade KEM keypairs and
default (Disabled) mutual-auth admission. No production source change; no wire-format / admission /
trust-bundle / KEMTLS weakening; defaults preserved; M4 remains Yellow/launch-blocking; public DevNet
remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.


Before a public TestNet, at minimum:

- Wire the Run 361 `AbuseDosConfig` / `ConnectionRateLimiter` boundary into the node runtime (accept
  loop) and expose operator-configurable rate-limiter thresholds (or document a supported config
  surface). **(Connection-rate limiter done in Run 362; per-peer message-rate runtime override wired at
  source/test level in Run 363; release-binary evidence for both landed in Run 364; the deployed
  builder threads the per-peer override into its live `AsyncPeerManagerImpl` at source/test level in
  Run 365; Run 366 lands deployed-builder-path release-binary end-to-end evidence; Run 367 proves the
  connection-rate control live-socket on a running P2P-capable node; Run 368 proves the per-peer
  message-rate control over a real admitted-peer socket at the `AsyncPeerManagerImpl` layer; Run 369
  wires the per-peer `PeerRateLimiter` onto the **deployed** TcpKemTls receive path at source/test level
  — release-binary live-socket evidence over that deployed path remains outstanding.)** **(Run 370 threads
  a live `NodeMetrics` handle into the deployed adapter (Route B) so the deployed per-peer drop exports
  `qbind_net_per_peer_drops_total{reason="rate_limit"}`, and adds release-binary live-socket connection-rate
  evidence; the fully-live KEMTLS-admitted deployed per-peer socket flood remains outstanding.)**
- Register and test the planned `qbind_p2p_connection_rate_drop_total` metric at the runtime call site.
  **(Done in Run 362; release-binary verified in Run 364; live-socket increment on a running node verified
  in Run 367.)**
- Publish tuned thresholds validated under real inbound load, with alerting wired to the metrics in
  §5. **(Load validation still outstanding.)**

None of this is claimed complete by Run 360/361/362/363/364/365/366/367/368/369/370; Run 360 publishes posture, Run 361 adds a
source/test boundary, Run 362 wires the connection-rate limiter into runtime with release-binary
evidence, Run 363 wires the per-peer message-rate runtime override at source/test level, Run 364 lands
release-binary evidence for both controls, Run 365 threads the per-peer override through the deployed
builder at source/test level, Run 366 lands deployed-builder-path release-binary end-to-end evidence,
Run 367 proves the connection-rate control live-socket on a running P2P-capable node,
Run 368 proves the per-peer message-rate control over a real admitted-peer socket at the
`AsyncPeerManagerImpl` layer, Run 369 wires the per-peer `PeerRateLimiter` onto the deployed TcpKemTls
receive path at source/test level,
Run 370 threads a live `NodeMetrics` handle into the deployed adapter (Route B) so the deployed per-peer
drop exports `qbind_net_per_peer_drops_total{reason="rate_limit"}` and adds release-binary live-socket
connection-rate evidence,
and all record the remaining gap (per-peer message-rate **live-socket** evidence via a KEMTLS-admitted
deployed socket flood + load validation). **Run 371 closes the KEMTLS-admitted deployed per-peer
live-socket flood gap (Route A, M12 Green for both abuse/DoS deployed live-socket controls); sustained
multi-peer load validation under production-grade keys/strict admission remains outstanding.**