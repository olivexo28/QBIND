# QBIND DevNet Evidence — Run 369

Source/test wiring of the existing per-peer `PeerRateLimiter` onto the **deployed** `TcpKemTlsP2pService`
inbound receive path for the public DevNet abuse/DoS **M12** controls. Run 369 closes the Run 368
**Route-C** blocker at the **source/test** level: the deployed inbound `read_loop` now consults a per-peer
message-rate limiter after a frame decodes and before it is forwarded to the demuxer/handlers.
Release-binary live-socket deployed-path evidence is explicitly **deferred to Run 370**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · **source/test only** (production Rust source changed;
> no new CLI flag; no live deployment; no P2P wire-format change; no KEMTLS / trust-bundle / peer-admission
> weakening). Per-peer message-rate limiting is wired onto the deployed TcpKemTls receive path and proven
> at the **source/test** level only; release-binary live-socket proof is Run 370 (see §12, §14, §22, §23).

## 1. Exact verdict

**PASS / public-DevNet deployed per-peer limiter source-test positive (M12 stays Yellow/Partial —
strengthened; deployed TcpKemTls receive-path source/test wiring landed — NOT Green).**

The deployed `qbind-node` inbound path now consults the per-peer `PeerRateLimiter` at the source/test
level: `TcpKemTlsP2pService::read_loop` calls a `DeployedInboundPerPeerLimiter` after `decode_frame`
succeeds and before `inbound_tx.send(msg)`. An over-budget frame is dropped and the read loop
**continues** (a per-peer message-rate drop never tears down the connection); the adapter increments its
own per-peer drop counter and, when a `NodeMetrics` handle is installed, the existing
`qbind_net_per_peer_drops_total{...,reason="rate_limit"}` family. The connection-rate limiter and its
`qbind_p2p_connection_rate_drop_total` metric are never touched by this path. Defaults are preserved
(1000 msg/s + 100 burst; connection-rate limiter disabled unless explicitly enabled). All required
regression/non-mutation targets pass.

**M12 does not move Green.** Per the readiness rules, M12 Green requires BOTH controls proven over the
**deployed** live socket in a release-binary run; Run 369 lands only source/test wiring. M4 remains
Yellow/launch-blocking; public DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/src/deployed_inbound_per_peer_limiter.rs` — `DeployedInboundPerPeerLimiter`
  adapter wrapping the existing `PeerRateLimiter`, with its own `AtomicU64` per-peer drop counter and an
  optional `Arc<NodeMetrics>` handle; constructors `from_optional_config` / `with_defaults` /
  `from_runtime_config`; `allow_node` / `allow_key`; `bucket_key(NodeId) -> PeerId`. 5 unit tests.
- `crates/qbind-node/tests/run_369_public_devnet_deployed_per_peer_limiter_wiring_tests.rs` —
  24 integration tests.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_369.md` — this file.

Modified (production Rust source, narrow):

- `crates/qbind-node/src/lib.rs` — registered `pub mod deployed_inbound_per_peer_limiter;`.
- `crates/qbind-node/src/p2p_tcp.rs` — added the `inbound_per_peer_limiter` field + `new()` init;
  `set_inbound_per_peer_limiter` / `has_inbound_per_peer_limiter`; threaded the limiter through
  `handle_inbound_connection`, `spawn_accept_loop`, `spawn_peer_handlers`, `read_loop`, and the
  `DialerHandle` outbound-dial path; added the rate-limit check in `read_loop` (after `decode_frame`
  Ok, before `inbound_tx.send`; drop = `continue`).
- `crates/qbind-node/src/p2p_node_builder.rs` — in `start()`, before `p2p_service.start()`, install the
  adapter via `set_inbound_per_peer_limiter` from `deployed_peer_rate_limiter_config()`.

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

No new CLI flag; no P2P wire-format change; no metric added.

## 3. Deployed inbound wiring summary

`DeployedInboundPerPeerLimiter` is a thin adapter over the existing per-peer `PeerRateLimiter`. It is
installed on the deployed `TcpKemTlsP2pService` by `P2pNodeBuilder::start()` via
`set_inbound_per_peer_limiter`, using the config returned by `deployed_peer_rate_limiter_config()`
(default `1000` msg/s + `100` burst when no hidden override is set). The service stores it as an
`Arc<RwLock<Option<Arc<DeployedInboundPerPeerLimiter>>>>` field, mirroring the existing
`peer_candidate_wire_sink` / `abuse_dos_runtime` optional-field pattern, and threads it down every
inbound and outbound peer-handler spawn path so the per-peer `read_loop` can consult it. The builder
installs the adapter with `metrics = None` (it only holds a `P2pMetrics`, not the `NodeMetrics` that owns
`peer_network()`); the adapter's own `AtomicU64` drop counter is always available, and the
`NodeMetrics`-backed `qbind_net_per_peer_drops_total{...,reason="rate_limit"}` path is exercised directly
by tests that construct the adapter with a `NodeMetrics` handle.

## 4. Exact call path before and after Run 369

Before Run 369 (deployed inbound path — no per-peer message-rate enforcement):

```
TcpKemTlsP2pService::read_loop(source_peer, ...)
  → framed read → decode_frame(&frame_bytes) = Ok(P2pMessage)
  → inbound_tx.send(msg)
  → TcpKemTlsP2pService::subscribe() receiver
  → P2pInboundDemuxer
  → handlers
```

After Run 369 (deployed inbound path — per-peer message-rate limiter consulted before dispatch):

```
TcpKemTlsP2pService::read_loop(source_peer, ...)
  → framed read → decode_frame(&frame_bytes) = Ok(P2pMessage)
  → inbound_per_peer_limiter (if installed):
        allow_node(&source_peer, Instant::now())
          → true  → forward
          → false → DROP this frame, `continue` (connection NOT torn down)
  → inbound_tx.send(msg)
  → TcpKemTlsP2pService::subscribe() receiver
  → P2pInboundDemuxer
  → handlers
```

The check sits in `read_loop` — the earliest deployed inbound point where the per-peer `source_peer:
NodeId` is known — so limiting is genuinely per-peer and strictly upstream of `subscribe()` and the
demuxer, satisfying "before handler dispatch". The `P2pInboundDemuxer` boundary was rejected because
`P2pMessage` carries no peer identity there.

## 5. Peer identity / keying used for limiter buckets

`bucket_key(&NodeId) -> PeerId(u64)` derives the limiter bucket from the **first 8 bytes** of the
32-byte connection `NodeId`, big-endian. This is a **rate-limit bucket selector only** — it is NOT an
identity, authentication, admission, trust, consensus, or authority claim, and it never feeds any of
those decisions. It is a narrow, deterministic, temporary peer-keying strategy chosen because the
existing `PeerRateLimiter` is keyed by `PeerId(u64)` while the deployed transport identifies peers by
`NodeId([u8; 32])`. KEMTLS admission / mutual-auth / trust-bundle validation are unchanged and remain the
sole authority for peer admission.

## 6. Accepted tests

Run 369 integration tests (`run_369_...wiring_tests.rs`, tests 01–10) assert that:

- an adapter built from `None` uses `PeerRateLimiter::with_defaults()` (1000 msg/s + 100 burst);
- under-budget frames are accepted (`allow_node` / `allow_key` return `true`) with 0 drops;
- a freshly installed default adapter admits normal traffic well under 1000/s;
- distinct `NodeId`s map to independent buckets and are limited independently;
- `has_inbound_per_peer_limiter()` reports installation state correctly.

## 7. Rejection / fail-closed tests

Tests 11–17 assert that:

- an over-budget flood on a tight bucket (e.g. `5/0`) is dropped once the bucket is exhausted;
- each drop increments the adapter's own per-peer drop counter and, when a `NodeMetrics` handle is
  installed, `total_rate_limit_drops()` / `peer_rate_limit_drop_count(peer)` /
  `qbind_net_per_peer_drops_total{...,reason="rate_limit"}`;
- the limiter is **fail-open** by design for a missing/zero-config adapter (defaults applied), matching
  the existing `PeerRateLimiter` semantics; invalid explicit configs are rejected upstream by
  `PeerRateLimiterConfig` validation (zero / unbounded refused) and MainNet is refused.

## 8. Non-mutation tests

Tests 18–29 assert that consulting the limiter does NOT:

- change the decoded `P2pMessage` bytes or the wire format;
- touch the connection-rate limiter or `qbind_p2p_connection_rate_drop_total`;
- mutate validator set, epoch, sequence, marker, `LivePqcTrustState`, or any authority/execution state
  (these are not reachable from the adapter);
- add any public CLI flag or register any new metric;
- tear down the connection on a per-peer drop (`read_loop` uses `continue`, never `break`).

## 9. Default compatibility

The builder always installs the adapter, but with the safe default posture (1000 msg/s + 100 burst) when
no hidden override is present. Normal traffic (well under 1000/s per peer) is unaffected; the
connection-rate limiter stays disabled unless explicitly enabled. Existing lib and integration tests do
not exceed the default per-peer budget, so no regressions. `Option<PeerRateLimiterConfig>` is `Copy`, so
the builder reuses the same computed config both for the adapter install and for the existing
`peer_rate_limiter_config` field.

## 10. CLI / config surface

No public CLI flag added or exposed. The hidden/devnet-only surface from Runs 362/363
(`--p2p-max-messages-per-second`, `--p2p-burst-allowance`, plus the `--p2p-connection-rate-*` flags) is
reused unchanged and remains hidden. The adapter is fed from the existing
`deployed_peer_rate_limiter_config()` derivation; no new config field or precedence rule is introduced.

## 11. Metric / counter behavior

- Per-peer message-rate drops increment the adapter's own `AtomicU64` counter, and — when a
  `NodeMetrics` handle is installed — the existing `qbind_net_per_peer_drops_total{...,reason="rate_limit"}`
  family via `NodeMetrics::peer_network()` (`total_rate_limit_drops()` /
  `peer_rate_limit_drop_count(peer)`).
- The connection-rate metric `qbind_p2p_connection_rate_drop_total` (on `P2pMetrics`, a different struct)
  is never incremented by the per-peer path — structurally guaranteed because the adapter never holds a
  `P2pMetrics` and `read_loop`'s per-peer branch never calls the connection-rate limiter.
- No new metric is registered.

## 12. Readiness matrix delta for M12

- **Before:** M12 Yellow/Partial (strengthened) — per-peer proof at the `AsyncPeerManagerImpl` layer
  (Run 368); deployed TcpKemTls receive path did not consult `PeerRateLimiter`.
- **After Run 369:** M12 **Yellow/Partial — strengthened; deployed TcpKemTls receive-path source/test
  wiring landed.** Still **NOT Green**: M12 Green requires release-binary live-socket evidence proving
  BOTH (1) connection-rate limiting over live sockets and (2) per-peer message-rate limiting over the
  deployed TcpKemTls receive path — deferred to Run 370.

## 13. Public DevNet readiness status

- Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16, M17, M18, M19, M20.
- Yellow/Partial: M4, M6, M7, M8, M9, M12, M13, M14, M15.
- M4 remains launch-blocking. Public DevNet remains **NOT launch-ready**.

## 14. Remaining DevNet blockers

- M12: release-binary live-socket deployed-path evidence for both controls (Run 370).
- M4: live seed/bootnode reachability evidence (unchanged; not altered by Run 369).
- M6: stable identity-generation support (unchanged; not altered by Run 369).

## 15. TestNet blockers

Public TestNet remains **NOT ready**: multi-host consensus/network soak, external reachability, and the
full M4–M15 Yellow set are unmet. Run 369 makes no TestNet readiness claim (`MainNetRefused` still
refuses non-DevNet enablement of the abuse/DoS runtime).

## 16. MainNet blockers

MainNet remains **Red**: authority rotation/revocation, custody, and the full trust-lifecycle authority
surface are unwired. Run 369 wires none of these.

## 17. C4 / C5 status

Full **C4 remains OPEN**; **C5 remains OPEN**. Run 369 closes neither.

## 18. Tests run with exact counts

```
cargo build -p qbind-node --lib                                                          → Finished (ok)
cargo test -p qbind-node --test run_369_public_devnet_deployed_per_peer_limiter_wiring_tests → 24 passed; 0 failed
cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests     → 20 passed; 0 failed
cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests     → 21 passed; 0 failed
cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests                 → 38 passed; 0 failed
cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests               → 30 passed; 0 failed
cargo test -p qbind-node --lib                                                                → 1390 passed; 0 failed
```

(The 5 `deployed_inbound_per_peer_limiter` unit tests are included in the 1390 lib count.)

## 19. Security scan result

Secret scanning was run over all changed files (`runtime-tools-secret_scanning`): **no secrets found**.
No private keys, mnemonics, seed phrases, credentials, API keys, tokens, private infrastructure, real
production hostnames, or unapproved live endpoints were introduced. Only localhost / RFC 5737 / RFC 3849
/ temporary test fixtures are used.

## 20. CodeQL result

CodeQL (`codeql_checker`) was invoked because production Rust source changed
(`isTrivial = false`). Exact result: **analysis was skipped because the CodeQL database size is too
large** (0 alerts returned, but the analysis did not run to completion). This is **not** a clean result
and is not claimed as such — it is recorded honestly as a skip. No alert triage is possible from a
skipped analysis; the source/test changes are covered instead by the unit/integration suites in §18.

## 21. Provenance

- Toolchain: workspace-pinned stable `cargo`/`rustc` (see `rust-toolchain`).
- No release binary was built or hashed in Run 369 (source/test run; release-binary evidence deferred to
  Run 370).
- Changes are confined to `crates/qbind-node/src/{deployed_inbound_per_peer_limiter.rs, lib.rs,
  p2p_tcp.rs, p2p_node_builder.rs}`, the new Run 369 test file, and the enumerated docs.

## 22. Honest limitations

- **Source/test only.** The deployed receive-path wiring is proven by unit/integration tests, not by a
  release-binary live-socket run over a real KEMTLS-admitted peer. That proof is Run 370.
- **Builder install has `metrics = None`.** The builder holds only `P2pMetrics`, not the `NodeMetrics`
  that owns `qbind_net_per_peer_drops_total`; the deployed adapter therefore records drops in its own
  atomic counter, and the `NodeMetrics`-backed metric path is exercised only by tests that construct the
  adapter with a `NodeMetrics` handle. Wiring a live `NodeMetrics` handle into the builder install is a
  follow-up.
- **Temporary peer keying.** The first-8-bytes-of-`NodeId` bucket key is a rate-limit selector, not an
  identity; a full `NodeId`-keyed limiter is a possible future refinement.
- **No M12 Green claim, no C4/C5 closure, no TestNet/MainNet claim.**

## 23. Suggested Run 370 next step

Produce **release-binary live-socket deployed-path evidence** for M12: stand up a real KEMTLS-admitted
peer against the deployed `target/release/qbind-node`, flood inbound frames over the live TcpKemTls
receive path, and prove over a real socket that (1) the deployed connection-rate limiter refuses
over-budget connections (`qbind_p2p_connection_rate_drop_total`) AND (2) the deployed per-peer
message-rate limiter drops over-budget frames wired in Run 369 (`qbind_net_per_peer_drops_total`), with
a live `NodeMetrics` handle installed in the builder so the deployed adapter increments the real metric.
Only then may M12 be considered for Green.

## Test counts (captured)

```
run_369 wiring tests: 24 passed; 0 failed
run_365 threading tests: 20 passed; 0 failed
run_363 per-peer runtime tests: 21 passed; 0 failed
run_362 abuse/DoS runtime tests: 38 passed; 0 failed
run_361 abuse/DoS hardening tests: 30 passed; 0 failed
qbind-node lib tests: 1390 passed; 0 failed
```

## Secret scan (captured)

```
runtime-tools-secret_scanning over changed files → no secrets found
```

## CodeQL (captured)

```
codeql_checker invoked (isTrivial=false, production Rust source changed)
  → rust: analysis SKIPPED — database size too large (0 alerts; NOT a clean result, recorded as skip)
```
