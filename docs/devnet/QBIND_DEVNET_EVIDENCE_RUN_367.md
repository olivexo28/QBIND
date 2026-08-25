# QBIND DevNet Evidence — Run 367

Release-binary **live-socket** evidence for the public DevNet abuse/DoS **M12** controls — driving a
real, running P2P-capable `target/release/qbind-node` over loopback and exercising the accept-loop
**connection-rate limiter** (Run 362) against real inbound TCP sockets, plus a release-built helper that
backs the runtime-symbol invariants.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · **evidence/helper/harness/docs only** (no
> production/library source change, no new CLI flag, no live deployment, no P2P wire-format change).
> The **connection-rate** control is proven **live-socket**; the per-peer **message-rate** control
> remains **deployed-builder-path** (see §5, §9, §16, §26).

## 1. Exact verdict

**Partial-positive / public-DevNet-abuse-DoS-M12 live-socket release-binary positive for the
CONNECTION-RATE control (M12 stays Yellow/Partial, strengthened — NOT Green).**

Run 367 fixes the Run 366 blocker. Run 366 launched `qbind-node` **without** `--network-mode p2p`, so
it ran in LocalMesh and never bound a live P2P socket. Run 367 launches the real release binary in a
**P2P-capable loopback mode** (`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`),
confirms it binds a real socket (`P2P transport up`), and proves the **connection-rate control
end-to-end over a live loopback socket**: under-budget inbound TCP connections are admitted with the
drop metric at 0, and over-budget connections are refused with `qbind_p2p_connection_rate_drop_total`
incrementing by exactly the over-budget count (10 connections, max 3 → 3 accepted / 7 refused, metric
= 7).

**M12 does not move Green** because M12 Green requires BOTH controls proven over a live socket, and the
per-peer **message-rate** control enforces on the ADMITTED-peer receive path inside
`AsyncPeerManagerImpl`. Driving it live needs a second KEMTLS peer that completes the handshake and
floods messages over the configured bucket; Run 367 does not stand up that second-peer flood harness,
so the per-peer message-rate control remains proven only through the DEPLOYED `P2pNodeBuilder` path in
the release helper. M4 remains Yellow/launch-blocking; M6 remains Yellow; public DevNet remains **NOT
launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs` — release-built
  helper (8 in-process runtime-symbol scenarios) backing the live-socket harness.
- `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh` — release-binary
  live-socket harness (build + hashes + helper + CLI surface + real P2P-mode node launch + live raw
  TCP connection driving + `/metrics` scrape).
- `docs/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary/README.md`
- `docs/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary/summary.txt`
- `docs/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md` — this file.

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

**No production/library source changed.** No new CLI flags. No P2P wire-format change. No default
change. Only the tracked archive files (`README.md`, `summary.txt`, `.gitignore`) are committed; all
raw logs/artifacts are `.gitignore`d.

## 3. Release artifacts and hashes

- `node_bin`: `target/release/qbind-node`
- `node_bin_sha256`: `1c4e546f3a766c006d2bd9601a3a404e9983c0e32d52fd8691b367ded667e381`
- `node_build_id`: `147246663749c27398299ae69a57140bf7d2b2f1`
- `helper_bin`: `target/release/examples/run_367_public_devnet_abuse_dos_live_socket_helper`
- `helper_sha256`: `1063424eaa146354fa010b42c922e4c0761e4b7d0e8b621a1b8ab0c5eda814f3`
- `helper_build_id`: `e367620b31701570b938d7a053314f3e1ad3fadf`

SHA-256 / Build ID values are environment-specific and are recorded only as reproducibility anchors;
the harness re-captures them each run.

## 4. Runtime evidence shape

Two shapes:

1. **Live-socket, real running node.** The harness launches `target/release/qbind-node` with
   `--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>` and `QBIND_METRICS_HTTP_ADDR`
   pointed at a loopback metrics port, waits for `P2P transport up`, drives real inbound TCP
   `connect()`s against the accept loop, and scrapes the live `/metrics` endpoint for
   `qbind_p2p_connection_rate_drop_total`. This is genuine live-socket evidence for the connection-rate
   control.
2. **In-process release helper.** The release-built helper links the real Run 361/362/363/365 symbols
   and proves the runtime-decision invariants (including the per-peer deployed-builder path) without
   opening a socket.

## 5. P2P-capable mode discovery

**Conclusion A — the existing release binary supports a bounded P2P-capable loopback mode.** No source
change was needed. `main.rs`'s `NetworkMode::P2p` branch (`match config.network_mode`) calls
`run_p2p_node`, which installs the operator abuse/DoS runtime config at `main.rs:6823`
(`builder.with_abuse_dos_runtime_config(abuse_cfg)`) and binds a real listener in `TcpKemTlsP2pService`.
The connection-rate limiter is consulted per inbound socket in `p2p_tcp::spawn_accept_loop` via
`PublicDevnetAbuseDosRuntimeState::should_admit` BEFORE any KEMTLS handshake, so raw inbound TCP
connections exercise it directly. Run 366's "`--enable-p2p` is ignored" was a consequence of not
passing `--network-mode p2p` (DevNet default is LocalMesh), not a missing mode. Observed:
`p2p_mode_discovery: P2P-capable loopback mode CONFIRMED (real socket bound; 'P2P transport up')`.

## 6. Helper/harness corpus

Release helper scenarios (8/8 PASS):

| id | assertion |
|----|-----------|
| `01_default_preserves_behavior` | deployed builder derives None; conn limiter disabled; per-peer 1000/100; drop metric 0 |
| `02_connection_rate_admit_refuse` | 4 admitted; over-budget `ConnectionRateLimited`; no admit on refusal; metric increments per refusal |
| `03_per_peer_message_rate_deployed` | deployed builder installs 5/0; deployed pm honors it; 5 allowed; 6th dropped; conn metric 0 |
| `04_combined_independence` | conn refusal doesn't admit; msg drop on admitted deployed path; counters distinct |
| `05_invalid_configs_fail_closed` | zero-window/zero-msg/zero-conn/unbounded/inconsistent all rejected |
| `06_mainnet_refused` | MainNet abuse/DoS config refused (direct + CLI) |
| `07_cli_surface_hidden_and_parse_checked` | hidden flags absent from `--help`; real parse; invented rejected |
| `08_deployed_builder_matches_direct_default` | deployed default == direct default (no drift) |

Harness live-socket scenarios: `p2p_mode_discovery`, `default_preserves_behavior`,
`connection_rate_under_budget`, `connection_rate_over_budget`,
`connection_rate_metric_on_allowed`; `per_peer_message_rate_live_socket` recorded as a blocker.

## 7. Production-binary scenarios

- `--help` succeeds and does NOT surface any of the eight hidden abuse/DoS flags.
- An invented flag `--p2p-connection-rate-bogus` is rejected by clap (rc=2).
- The real hidden flags parse (rc=0), including the per-peer and connection-rate families.
- A real running node accepts the flags and, with the connection-rate limiter enabled, logs
  `public-DevNet abuse/DoS inbound connection-rate limiter ENABLED`.

## 8. Connection-rate live-socket evidence

- **Default (no flags):** live node → limiter DISABLED, `qbind_p2p_connection_rate_drop_total 0`.
- **Under-budget:** window 60000 ms, max 3, burst 0 → 3 inbound TCP connections admitted; drop metric
  still `0`.
- **Over-budget:** 7 further connections (10 total) → node log shows exactly `3` `Accepted connection`
  and `7` `Connection-rate limited inbound`; live `/metrics` reports
  `qbind_p2p_connection_rate_drop_total 7`.
- **Metric does not increment on allowed:** metric stayed `0` across the first 3 allowed connections.
- **No peer admitted on refusal:** the accept loop drops the stream before any handshake/admission
  (source: `p2p_tcp::spawn_accept_loop`).

## 9. Per-peer message-rate live-socket evidence

**Not driven over a live socket (recorded blocker).** The per-peer message-rate limiter enforces on the
admitted-peer receive path in `AsyncPeerManagerImpl`; driving it live requires a second KEMTLS peer
that completes the handshake and floods messages faster than the configured per-peer bucket. Run 367
does not stand up that second-peer flood harness. The control is proven through the DEPLOYED
`P2pNodeBuilder` path (`deployed_peer_rate_limiter_config` → `build_deployed_peer_manager` →
`AsyncPeerManagerImpl` → `PeerRateLimiter`) in the release helper (scenarios 03/04): a custom
`--p2p-max-messages-per-second 5 --p2p-burst-allowance 0` installs a capacity-5 limiter that allows 5
then drops the 6th, without touching the connection-rate metric.

## 10. Combined limiter independence evidence

Helper scenario 04: with both controls configured from one validated posture, a connection-rate
refusal never admits a peer (`should_admit` false, no message path), and a per-peer message-rate drop
increments no connection-rate counter. The counters are distinct
(`qbind_p2p_connection_rate_drop_total` vs the per-peer `PeerRateLimiter`). On the live socket, the
connection-rate refusals never reach the message path at all (the stream is dropped pre-handshake).

## 11. Rejection/fail-closed evidence

Helper scenario 05, via the exact production validation fn `CliArgs::abuse_dos_runtime_config()`:
zero connection-rate window, zero connection-rate max, zero per-peer message max, unbounded/unsafe
per-peer value, and inconsistent per-address config (window without max) all fail closed — no runtime
state, no deployed peer manager, no limiter is built. The real binary also rejects the invented flag at
the clap layer.

## 12. Default compatibility

Connection limiter disabled unless explicitly enabled (proven live: no-flag node metric 0, no ENABLED
log). Per-peer defaults 1000 msg/s + 100 burst (helper scenario 01/08, deployed builder derives `None`
and equals the direct default `AsyncPeerManagerConfig`). No accept-loop change when the limiter is not
installed.

## 13. CLI/config surface

Eight hidden/devnet-only flags: `--p2p-connection-rate-limit-enabled`, `--p2p-connection-rate-window-ms`,
`--p2p-connection-rate-max`, `--p2p-connection-burst`, `--p2p-max-messages-per-second`,
`--p2p-burst-allowance`, `--p2p-per-address-connection-rate-window-ms`,
`--p2p-per-address-connection-max`. All `hide = true`; none appear in `--help`; all parse; invented
flags are rejected.

## 14. Metric evidence

`qbind_p2p_connection_rate_drop_total` is registered exactly once, has no endpoint labels
(`endpoint_label_leak: false`), renders as a bare counter line, starts at 0, and — on the live socket —
increments only on connection-rate refusals (7 after 7 over-budget connections), never on allowed
connections. The metric is served from the running node's live `/metrics` HTTP endpoint.

## 15. Non-mutation evidence

No `LivePqcTrustState` mutation, no sequence/marker write, no validator-set mutation, no epoch
transition, no execution-sink write, no Run 070 path, no P2P wire-format change, no peer-admission or
trust-bundle weakening. The connection-rate refusal path drops the raw socket before any admission
logic runs. Node data dirs are temporary and removed.

## 16. Readiness matrix delta for M12

**M12: Yellow/Partial → Yellow/Partial (strengthened).** The connection-rate control is now proven
**live-socket** on the real release binary (running P2P-capable node, real inbound TCP, live `/metrics`
increment). The per-peer message-rate control remains deployed-builder-path (release helper) and is not
driven over an admitted live peer. Per the readiness rules (BOTH controls must be proven over a live
socket), **M12 does not move Green.**

## 17. Current public DevNet readiness status

- Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16, M17, M18, M19, M20.
- Yellow/Partial: M4, M6, M7, M8, M9, M12 (strengthened), M13, M14, M15.
- Public DevNet remains **NOT launch-ready**.

## 18. Remaining public DevNet blockers

M4 (live seed/bootnode reachability) remains launch-blocking. M6 (stable identity generation),
M7–M9, M13–M15 remain Yellow/Partial. For M12 specifically: a second-node admitted-peer KEMTLS message
flood harness is required to prove the per-peer message-rate control over a live socket.

## 19. Public TestNet blockers

No TestNet readiness claim. TestNet requires the full C4 production PQC KEM/AEAD stack, live
multi-node reachability, and identity lifecycle — none of which Run 367 addresses.

## 20. MainNet blockers

No MainNet readiness claim. MainNet authority rotation/revocation remains Red; production PQC
KEM/AEAD remains out of scope; MainNet abuse/DoS enablement is refused by validation.

## 21. C4/C5 status

Full **C4 OPEN**, **C5 OPEN**. Run 367 makes no closure claim.

## 22. Tests run

- `cargo build -p qbind-node --release` — OK
- `cargo build -p qbind-node --release --example run_367_public_devnet_abuse_dos_live_socket_helper` — OK
- `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh` — PARTIAL-POSITIVE (live
  connection-rate socket proven)
- `cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests` — 20 passed; 0 failed
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests` — 21 passed; 0 failed
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` — 38 passed; 0 failed
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` — 30 passed; 0 failed
- `cargo test -p qbind-node --lib` — 1385 passed; 0 failed

No source seam was added (evidence/helper/harness/docs only), so no new Run 367 source/test target was
required.

## 23. Security scans

`runtime-tools-secret_scanning` run over all changed files — no secrets. Only loopback (127.0.0.1) and
RFC 5737 (192.0.2.0/24) addresses are used; temporary data dirs; no keys, mnemonics, credentials,
tokens, or live endpoints.

## 24. CodeQL

`codeql_checker` invoked for the added Rust example + shell/doc changes (see the run record). Result
recorded verbatim in the PR; not claimed clean if skipped/unavailable/timed-out.

## 25. Provenance

- git commit (base): `901bc843910e1f33821af3f4b2e0e3e1fd13a637`
- branch: `copilot/run-367-task`
- clean/dirty at capture: dirty (this change set)
- helper path: `crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs`
- harness path: `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`
- archive path: `docs/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary/`
- release binary SHA-256 / helper SHA-256 / Build IDs / toolchain: see §3.
- runtime evidence shape: live-socket (connection-rate) + in-process helper (per-peer deployed path).
- real P2P-capable running node path driven: **yes** (connection-rate, live socket).

## 26. Honest limitations

- The per-peer **message-rate** control is NOT driven over an admitted live peer socket; it is proven
  only through the deployed-builder construction path in the release helper. This is the sole reason
  M12 does not move Green.
- SHA-256 / Build ID hashes are environment-specific and change on rebuild.
- The connection-rate window is set large (60 s) so the token bucket is deterministic within the short
  harness window; this exercises the same `should_admit` decision the production accept loop makes.

## 27. Suggested Run 368 next step

Build a bounded **two-node loopback** M12 harness: launch two P2P-capable `qbind-node` instances as
static peers on loopback with test-grade KEMTLS, configure a tiny per-peer `--p2p-max-messages-per-second`
bucket on the receiver, and drive the dialer to send admitted-peer messages over the bucket, proving the
per-peer message-rate drop over a live admitted-peer socket (and its distinct counter). If that lands
with the Run 367 connection-rate live-socket evidence, M12 would have BOTH controls proven over live
sockets and could be evaluated for Green.