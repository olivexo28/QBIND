# QBIND DevNet Evidence — Run 368

Release-binary **admitted-peer per-peer message-rate live-socket** evidence for the public DevNet
abuse/DoS **M12** controls — standing up a real loopback TCP socket pair, registering one side as an
**admitted peer** on a live `AsyncPeerManagerImpl` (the component that owns the per-peer
`PeerRateLimiter`), flooding length-prefixed `NetMessage` frames from the other side, and proving over
a real socket that under-budget messages are accepted and over-budget messages are dropped by the live
limiter with the per-peer drop counter incrementing — plus a re-run of the Run 367 **connection-rate**
live-socket proof on the real `target/release/qbind-node` as a regression.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · **evidence/helper/harness/docs only** (no
> production/library source change, no new CLI flag, no live deployment, no P2P wire-format change).
> The per-peer **message-rate** control is proven over a real admitted-peer socket **at the
> `AsyncPeerManagerImpl` layer only**; the **deployed** `qbind-node` inbound path does NOT enforce it
> (see §8, §15, §16, §26).

## 1. Exact verdict

**PARTIAL-POSITIVE / public-DevNet-abuse-DoS-M12 per-peer live-socket release-binary positive at the
`AsyncPeerManagerImpl` layer (M12 stays Yellow/Partial, strengthened — NOT Green).**

Run 368 strengthens Run 367's per-peer evidence from a synchronous `PeerRateLimiter::allow()`
construction-path proof to a **real admitted-peer socket** proof: the per-peer message-rate control is
driven through the actual async `AsyncPeerManagerImpl::peer_reader_task` receive loop over a live
loopback TCP socket. Under-budget messages are accepted (0 drops); an 80-message flood over a `5/0`
bucket is dropped by the live `PeerRateLimiter` (≈75 drops observed) with
`NodeMetrics::peer_network().total_rate_limit_drops()` / `peer_rate_limit_drop_count(peer)` reflecting
the drops and the `qbind_net_per_peer_drops_total{...,reason="rate_limit"}` metric family rendering.
The Run 367 connection-rate live-socket proof is re-run on the release binary as a regression
(10 inbound TCP connections, max 3 → 3 accepted / 7 refused, `qbind_p2p_connection_rate_drop_total` = 7).

**M12 does not move Green.** M12 Green requires BOTH controls proven over the **deployed** live socket.
Decision gate = **Route C**: the deployed `qbind-node` inbound path
(`TcpKemTlsP2pService::subscribe()` → `P2pInboundDemuxer` → handlers) does NOT consult the per-peer
`PeerRateLimiter`; `build_deployed_peer_manager()` / `AsyncPeerManagerImpl` is construction-path-only
and is never spawned by `main.rs`. So Run 368's per-peer proof is at the `AsyncPeerManagerImpl` layer
with a plain-TCP admitted peer, not the deployed TcpKemTls receive path, and not a full KEMTLS
mutual-auth handshake. M4 remains Yellow/launch-blocking; M6 remains Yellow; public DevNet remains
**NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs` —
  release-built helper (9 scenarios; scenarios 02/03/04 drive a real admitted-peer loopback socket
  through `AsyncPeerManagerImpl::peer_reader_task`).
- `scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh` —
  release-binary harness (build + hashes + helper + CLI surface + live P2P-mode node launch +
  connection-rate regression + `/metrics` scrape + honest per-peer deployed-path blocker).
- `docs/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary/README.md`
- `docs/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary/summary.txt`
- `docs/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md` — this file.

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

No production/library Rust source changed; no new CLI flag; no P2P wire-format change.

## 3. Release artifacts and hashes

Captured by the harness (`summary.txt`). Hashes are environment-specific and reproduce on rebuild:

```
toolchain: rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo:     cargo 1.97.1 (c980f4866 2026-06-30)
node_bin:            target/release/qbind-node
node_bin_sha256:     1c4e546f3a766c006d2bd9601a3a404e9983c0e32d52fd8691b367ded667e381
node_bin_build_id:   147246663749c27398299ae69a57140bf7d2b2f1
helper_bin:          target/release/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper
helper_bin_sha256:   b83c7882e67abe4b1730512fdfc9184a0288d9d62d6067ca23d6494ede4ec876
helper_bin_build_id: 42dc0e8ada56f8af7f61c106ee3bc4721c0a1745
```

## 4. Runtime evidence shape

- Release helper: 9 scenarios; each writes `scenarios/<id>.txt`, aggregated into `manifest.txt`, plus
  `metric_evidence.txt` and `helper_summary.txt` (verdict PASS/FAIL). Scenarios 02/03/04 and the
  metric-evidence step open real loopback TCP socket pairs and register admitted peers on a live
  `AsyncPeerManagerImpl` with metrics.
- Harness: launches real P2P-capable loopback `qbind-node` processes, drives raw inbound TCP
  connections, scrapes `http://127.0.0.1:<metrics>/metrics`, and asserts exact accept/refuse splits and
  metric values; records the deployed per-peer path as an honest blocker.

## 5. Two-node KEMTLS admission evidence

**Not exercised (honest).** Run 368 does not stand up a full KEMTLS mutual-auth two-node handshake.
The admitted peer in the helper is a **plain-TCP** peer registered on `AsyncPeerManagerImpl` via
`add_peer_with_stream` (default `TransportSecurityMode::PlainTcp`), sufficient to drive the per-peer
receive loop and its `PeerRateLimiter`, but it is not KEMTLS admission and it is not the deployed
inbound path. No fallback roots, no placeholder seed dial, and no wire-format change are involved.

## 6. Helper/harness corpus

Helper scenarios (all PASS, 9/9):

1. `01_default_preserves_behavior`
2. `02_admitted_peer_live_socket_admission` (real socket)
3. `03_per_peer_message_rate_live_socket_under_budget` (real socket)
4. `04_per_peer_message_rate_live_socket_over_budget` (real socket)
5. `05_connection_rate_regression`
6. `06_combined_limiter_independence` (real socket per-peer + in-process conn)
7. `07_invalid_configs_fail_closed`
8. `08_mainnet_refused`
9. `09_cli_surface_hidden_and_parse_checked`

Metric-evidence step additionally floods an admitted peer over a real socket and confirms the per-peer
drop family renders (≈75 drops of 80 sent).

## 7. Production-binary scenarios

- `default_preserves_behavior` (live socket): no-flag P2P node keeps the connection limiter disabled;
  `qbind_p2p_connection_rate_drop_total` = 0.
- `connection_rate_regression` (live socket): `window=60s,max=3,burst=0` → 3 admitted / 7 refused;
  metric = 7; log shows 3 `Accepted connection` / 7 `Connection-rate limited inbound`.
- CLI surface on the real binary: hidden abuse/DoS flags absent from `--help`; invented flag rejected
  (rc=2); real hidden flags parse (rc=0).

## 8. Per-peer message-rate live-socket evidence

**Proven at the `AsyncPeerManagerImpl` layer over a real socket** (helper scenarios 02/03/04 + metric
step): a `5/0` bucket accepts exactly 5 framed messages (0 drops) and drops an 80-message flood
(≈75 drops), with `total_rate_limit_drops()` / `peer_rate_limit_drop_count(peer)` incrementing and
`qbind_net_per_peer_drops_total{...,reason="rate_limit"}` rendering.

**Not proven on the deployed live socket** (Route C blocker): the deployed inbound path
(`TcpKemTlsP2pService::subscribe` → `P2pInboundDemuxer` → handlers) does not consult the
`PeerRateLimiter`. This is why M12 stays Yellow/Partial.

## 9. Connection-rate regression evidence

The Run 367 connection-rate live-socket proof is re-run on the release binary and passes identically
(10 inbound TCP connections, max 3 → 3 accepted / 7 refused; metric = 7; under-budget-only stays 0).

## 10. Combined limiter independence evidence

Helper scenario 06: a connection-rate refusal increments only the connection metric (`P2pMetrics`,
distinct object) while a real-socket per-peer flood increments only the per-peer counter
(`NodeMetrics::peer_network`). The two controls and their counters are independent.

## 11. Rejection / fail-closed evidence

Helper scenario 07: zero connection-rate window, zero connection-rate max, zero per-peer message max,
unbounded per-peer value, and inconsistent per-address config all fail closed via the production
validation fn `CliArgs::abuse_dos_runtime_config()`; no runtime state or peer manager is built.

## 12. Default compatibility

With no flags: connection limiter disabled; per-peer defaults `1000` msg/s + `100` burst (via the
deployed builder path); connection-rate drop metric 0. Deployed builder default equals the direct
default with no drift (Run 365 threading is additive).

## 13. CLI / config surface

No new CLI flag. The hidden/devnet-only Run 362/363 abuse/DoS flags stay hidden from `--help`, the real
hidden flags parse, and invented flags are rejected by clap — verified both in-process (helper scenario
09) and on the real binary (harness §3).

## 14. Metric / counter evidence

- `qbind_p2p_connection_rate_drop_total` — registered exactly once, no endpoint-label leak; live-socket
  value 7 for the over-budget connection-rate case, 0 for defaults/under-budget.
- `qbind_net_per_peer_drops_total{peer="…",reason="rate_limit"}` — renders on live `NodeMetrics` after a
  real-socket admitted-peer flood; `total_rate_limit_drops()` / `peer_rate_limit_drop_count(peer)`
  reflect the drops.

## 15. Non-mutation evidence

No `LivePqcTrustState` mutation; no validator-set mutation; no epoch transition; no sequence/marker
write; no execution-sink write; no trust-bundle behavior change; no peer-admission weakening; no P2P
wire-format change; no Run 070 path. All sockets are bounded loopback and closed; temporary data dirs
are removed.

## 16. Readiness matrix delta for M12

**M12 remains Yellow/Partial (strengthened).** Rule: M12 → Green only if release-binary live-socket
evidence proves BOTH (1) connection-rate limiting over live sockets AND (2) per-peer message-rate
limiting over an **admitted live peer path on the deployed binary**. Run 368 satisfies (1) (re-run) and
proves per-peer drops over a real socket at the `AsyncPeerManagerImpl` layer, but the **deployed**
inbound path bypasses the `PeerRateLimiter`, so (2) is not met on the deployed binary. Per the task's
matrix rules ("If per-peer evidence is still … construction-path-only, or blocked by missing … support,
keep M12 Yellow/Partial"), M12 stays Yellow/Partial.

## 17. Current public DevNet readiness status

- Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16, M17, M18, M19, M20.
- Yellow/Partial: M4, M6, M7, M8, M9, **M12 (strengthened)**, M13, M14, M15.
- M4 remains launch-blocking. Public DevNet remains **NOT launch-ready**.

## 18. Remaining public DevNet blockers

- **M12:** wire the per-peer `PeerRateLimiter` onto the deployed TcpKemTls receive path (route inbound
  frames through `AsyncPeerManagerImpl`, or add a per-peer message-rate check in `P2pInboundDemuxer` /
  `TcpKemTlsP2pService`), then prove per-peer drops over the deployed live socket with two KEMTLS peers.
- **M4:** live seed/bootnode reachability. **M6:** stable identity generation. M7–M9/M13–M15 remain
  Yellow.

## 19. Public TestNet blockers

No TestNet readiness claimed. TestNet requires the public DevNet must-haves plus stability/soak,
identity, seed/bootnode, and abuse/DoS both-controls deployed-path proofs — none satisfied here.

## 20. MainNet blockers

No MainNet readiness claimed. MainNet authority rotation/revocation remains Red; an enabled MainNet
abuse/DoS config is refused (helper scenario 08). No MainNet enablement.

## 21. C4 / C5 status

Full **C4 OPEN**; **C5 OPEN**. Run 368 does not close either and makes no closure claim.

## 22. Tests run

- `cargo build -p qbind-node --release` — success.
- `cargo build -p qbind-node --release --example run_368_public_devnet_abuse_dos_per_peer_live_socket_helper`
  — success.
- Run 368 harness — verdict PARTIAL-POSITIVE (helper 9/9; connection-rate regression PASS).
- `cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests` — see §counts.
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests` — see §counts.
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` — see §counts.
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` — 30 (reconciled).
- `cargo test -p qbind-node --lib` — see §counts.

Exact counts recorded at the end of this document under "Test counts (captured)".

## 23. Security scans

Secret scanning run over all changed files; no private keys, mnemonics, seed phrases, credentials, API
keys, tokens, or private infrastructure introduced. Only loopback (`127.0.0.1`) and RFC 5737
documentation addresses are used; published-safe SHA-256s / Build IDs only.

## 24. CodeQL

Recorded under "CodeQL (captured)" at the end of this document (Rust example added → CodeQL invoked;
result recorded verbatim; not called clean if skipped/unavailable/timed-out).

## 25. Provenance

- Commit (pre-run): `c765645d669d9d6a227550b6df15026741e2be97`
- Branch: `copilot/run-368-task`
- Working state at authoring: dirty (new Run 368 helper/harness/archive/evidence + narrow doc updates).
- Helper: `crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs`
- Harness: `scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh`
- Archive: `docs/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary/`
- Release binary SHA-256 / Build ID, helper SHA-256 / Build ID, toolchain: see §3.
- Runtime evidence shape: §4. Admitted live peer/message path driven: yes, at the `AsyncPeerManagerImpl`
  layer over a real socket (plain-TCP admitted peer); no on the deployed TcpKemTls path.
- Helper scenarios: §6. Production-binary scenarios: §7. Test counts + secret scan + CodeQL: below.
- Readiness delta for M12: §16. Exact reason M12 is not Green: §8/§16 (deployed inbound path bypasses
  the `PeerRateLimiter`).

## 26. Honest limitations

The per-peer message-rate control is enforced only inside `AsyncPeerManagerImpl::peer_reader_task`. The
deployed `qbind-node` binary receives peer frames via `TcpKemTlsP2pService` → `P2pInboundDemuxer` →
handlers, which never consults the `PeerRateLimiter`, and `AsyncPeerManagerImpl` is not spawned by
`main.rs`. Run 368 therefore proves per-peer enforcement over a real socket at the `AsyncPeerManagerImpl`
layer only, using a plain-TCP admitted peer, not KEMTLS mutual-auth and not the deployed path. This is
the exact, recorded M12 blocker.

## 27. Suggested Run 369 next step

**Source run:** wire the per-peer `PeerRateLimiter` onto the deployed inbound path — either route
inbound peer frames through `AsyncPeerManagerImpl::peer_reader_task`, or add a per-peer message-rate
check in `P2pInboundDemuxer` / `TcpKemTlsP2pService::subscribe` fed by the CLI-derived config already
carried by `P2pNodeBuilder` (Run 365). Then add a two-KEMTLS-peer loopback flood harness that admits a
sender over the deployed socket and proves per-peer drops on the real binary's `/metrics`
(`qbind_net_per_peer_drops_total`). Only then may M12 move Yellow/Partial → Green.

---

## Test counts (captured)

<!-- filled from the actual `cargo test` output for this run -->

```
run_365_public_devnet_deployed_peer_rate_threading_tests: 20 passed; 0 failed
run_363_public_devnet_per_peer_message_rate_runtime_tests: 21 passed; 0 failed
run_362_public_devnet_abuse_dos_runtime_tests:             38 passed; 0 failed
run_361_public_devnet_abuse_dos_hardening_tests:           30 passed; 0 failed (reconciled; unchanged)
qbind-node --lib:                                          1385 passed; 0 failed
```

Build results:
```
cargo build -p qbind-node --release: Finished (success)
cargo build -p qbind-node --release --example run_368_...helper: Finished (success)
Run 368 harness: verdict PARTIAL-POSITIVE (helper 9/9; connection-rate regression PASS)
```

## Secret scan (captured)

```
runtime-tools-secret_scanning over all Run 368 changed/created files
  (helper .rs, harness .sh, docs/devnet/run_368_.../{README.md,summary.txt,.gitignore},
   docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md, readiness criteria, abuse/dos posture,
   verify, C4/C5 closure, trust-anchor authority, governance audit, PQC runbook, contradiction):
Result: No secrets detected in the scanned files. Safe to proceed with commit.
```

## CodeQL (captured)

```
codeql_checker invoked with trivialChangeDeclaration.isTrivial=false
  (reason: adds a new Rust example with async socket/network code).
Analysis Result for 'rust'. Found 0 alerts:
- rust: Analysis was skipped because the database size is too large.
Note: no CodeQL alerts were surfaced against the Run 368 changes; the Rust
analysis was skipped by the checker (database size), not run-and-cleared.
```
