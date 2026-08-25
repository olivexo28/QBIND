# QBIND DevNet Evidence — Run 370

Release-binary **live-socket deployed-path** evidence for the public DevNet
abuse/DoS **M12** controls. Run 370 (a) proves the **connection-rate** control
over real loopback sockets on `target/release/qbind-node`, and (b) closes the
Run 369 "honest limitation" by threading a live `NodeMetrics` handle into the
deployed per-peer message-rate limiter so a drop on the deployed `TcpKemTls`
receive path exports `qbind_net_per_peer_drops_total{reason="rate_limit"}`.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route B**
> (narrow, default-preserving production Rust source change: an optional
> `NodeMetrics` handle threaded into the deployed inbound per-peer limiter; no
> new CLI flag; no live deployment; no P2P wire-format change; no KEMTLS /
> trust-bundle / peer-admission weakening).

## 1. Exact verdict

**PARTIAL-POSITIVE / public-DevNet abuse/DoS M12 deployed live-socket
release-binary strengthened (M12 stays Yellow/Partial — NOT Green).**

- The **connection-rate** control is proven **live-socket** on the real release
  binary: under-budget inbound TCP connections admitted with
  `qbind_p2p_connection_rate_drop_total = 0`; over-budget refused with the metric
  incrementing by exactly the refusal count (10 connections, max 3 → 3 accepted /
  7 refused, metric = 7).
- The **deployed per-peer message-rate** control's **exported-metric path** is
  now wired end-to-end (Route B) and proven against the exact
  `DeployedInboundPerPeerLimiter` object `start()` installs on
  `TcpKemTlsP2pService::read_loop`: an over-budget frame bumps both the adapter's
  own bounded counter AND the exported
  `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter rendered by
  `NodeMetrics::format_metrics`.
- Defaults preserved (connection limiter disabled; per-peer `1000` msg/s + `100`
  burst; no handle → `metrics = None`, Run 369 posture bit-for-bit). Invalid /
  unbounded / MainNet configs fail the binary closed at startup. Hidden abuse/DoS
  flags remain hidden from `--help`.

**M12 does not move Green.** The residual blocker is a **KEMTLS-admitted deployed
per-peer socket flood** — a second peer completing mutual-auth and flooding
over-budget frames over the deployed read loop, observed on live `/metrics` —
which this run does not stand up. The deployed per-peer evidence is the deployed
adapter object exercised in the release helper, not a fully live KEMTLS socket
flood. M4 remains Yellow/launch-blocking; public DevNet remains **NOT
launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_helper.rs`
  — release helper (10 in-process deployed-adapter scenarios).
- `scripts/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary.sh`
  — release harness (build, hashes, helper, CLI surface, fail-closed, live-socket
  connection-rate, independence).
- `crates/qbind-node/tests/run_370_public_devnet_deployed_live_socket_m12_tests.rs`
  — 20 source tests for the Route B threading.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_370.md` — this file.
- `docs/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary/`
  — archive (`README.md`, `summary.txt`, `.gitignore`; only these three tracked).

Modified (production Rust source, narrow — Route B):

- `crates/qbind-node/src/p2p_node_builder.rs` — added the optional
  `node_metrics: Option<Arc<NodeMetrics>>` field (default `None`), the
  `with_node_metrics(Arc<NodeMetrics>)` builder method, and the
  `build_deployed_inbound_per_peer_limiter()` construction seam now used by both
  `start()` and the source tests; `start()` installs the deployed adapter via
  that seam so the optional handle reaches it.
- `crates/qbind-node/src/main.rs` — the deployed builder chain now calls
  `.with_node_metrics(Arc::clone(&node_metrics))` (the same `Arc<NodeMetrics>`
  the live `/metrics` endpoint scrapes). Shared `Arc` clone only.

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 3. Release artifacts and hashes

Representative run (the harness re-captures live values each run):

| Artifact | SHA-256 | Build ID |
|---|---|---|
| `target/release/qbind-node` | `e28775a2c44d02466b3c86dfff5e5641d93d983bde89e6d0f4701cc257131669` | `05e9e0b9b78599fe1c4d5f6bd1fd8786f3a4b9ec` |
| `…/examples/run_370_…_helper` | `5325781bbeca8b995a0f1183ab8b329b0e204147487f052746f476d65569ad8a` | `3e68662c0743f653d89a764e9a0e418c8b4cebb3` |

Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866
2026-06-30)`.

## 4. Decision gate route

**Route B.** Run 369 installed the deployed adapter with `metrics = None`, so the
exported per-peer counter could not move on the deployed path. The narrowest safe
change threads an optional live `NodeMetrics` handle into the deployed inbound
limiter; defaults preserved; source tests added; release-binary evidence
produced. The fully-live KEMTLS socket flood remains a recorded blocker.

## 5. Runtime evidence shape

Real `target/release/qbind-node` launched with `--network-mode p2p --enable-p2p
--p2p-listen-addr 127.0.0.1:<port>` and a loopback metrics endpoint; real inbound
TCP sockets driven against the accept loop; live `/metrics` scraped. Plus a
release helper that drives the exact deployed adapter object and renders
`NodeMetrics::format_metrics`.

## 6. Connection-rate live-socket evidence

- default (no flags): connection limiter DISABLED; `qbind_p2p_connection_rate_drop_total = 0`.
- under-budget: 3 inbound TCP connections admitted; metric stays 0.
- over-budget: 10 connections (max 3) → 3 accepted / 7 refused; metric = 7;
  node log shows exactly 3 `Accepted connection` and 7 `Connection-rate limited
  inbound` lines.

## 7. Per-peer deployed live-socket evidence

- The Run 370 `build_deployed_inbound_per_peer_limiter()` seam builds the exact
  adapter `start()` installs on `TcpKemTlsP2pService::read_loop`, now carrying the
  live `NodeMetrics` handle.
- Helper scenario 07 (under-budget): 5 frames on a `5/0` bucket forwarded; 0
  drops; exported counter 0.
- Helper scenario 08 (over-budget): 20 over-budget frames dropped; adapter
  counter == exported `qbind_net_per_peer_drops_total` == 20.
- **Honest limitation:** frames are driven synchronously through the deployed
  adapter object, not as bytes over a KEMTLS-admitted socket into the read loop.
  The fully-live KEMTLS flood is the residual blocker.

## 8. Metrics/counter evidence

- `qbind_p2p_connection_rate_drop_total` renders exactly once, no endpoint
  labels; increments only on connection refusals.
- `qbind_net_per_peer_drops_total{reason="rate_limit"}` renders from
  `NodeMetrics::format_metrics` after a deployed-adapter over-budget drop
  (`qbind_net_per_peer_drops_total{peer="21",reason="rate_limit"} 5` in the
  metric-evidence dump).

## 9. CLI/config surface

Hidden abuse/DoS flags absent from `--help`; invented flags rejected by clap
(rc=2); real hidden flags parse (rc=0). **No new public CLI flags** — the
`NodeMetrics` handle is a builder-internal `Arc`, not an operator flag.

## 10. Default compatibility

No-flag posture: connection limiter disabled, per-peer `1000/100`, no drops. With
no `with_node_metrics` call the deployed adapter is installed with `metrics =
None` — Run 369 behaviour bit-for-bit.

## 11. Rejection / fail-closed evidence

The real binary exits non-zero at startup for: zero per-peer max; unbounded
per-peer max; zero connection-rate max; enabled MainNet abuse/DoS config.

## 12. Combined limiter independence

Live socket: a connection-rate flood left `qbind_net_per_peer_drops_total` ABSENT
on `/metrics`. Source/helper: a per-peer drop increments only the per-peer
counter, never `qbind_p2p_connection_rate_drop_total`, and vice-versa.

## 13. Non-mutation evidence

No P2P wire-format change; no peer-admission / KEMTLS / trust-bundle weakening; no
`LivePqcTrustState`, validator-set, epoch, sequence, or marker mutation; no Run
070 path; no authority-lifecycle runtime wiring. The change is an additive,
optional metrics `Arc` on the builder.

## 14. Readiness matrix delta for M12

M12: **Yellow/Partial → Yellow/Partial (strengthened)**. The deployed per-peer
drop metric is now exported end-to-end (Route B) and the connection-rate control
is proven live-socket on the release binary. **Not Green** — the fully-live
KEMTLS-admitted deployed per-peer socket flood is not yet driven.

## 15. Current public DevNet readiness status

**NOT launch-ready.** M4 Yellow/launch-blocking; M6 Yellow/Partial; M12
Yellow/Partial (strengthened).

## 16. Remaining public DevNet blockers

KEMTLS-admitted deployed per-peer socket flood on live `/metrics` (M12 Green); M4
live seed/bootnode reachability; M6 stable identity generation.

## 17. Public TestNet blockers

All public DevNet blockers plus TestNet-grade validator-set/epoch operations and
sustained multi-node reachability — none addressed here.

## 18. MainNet blockers

Authority rotation/revocation runtime wiring (Red); full C4/C5 closure — none
addressed here; MainNet abuse/DoS remains refused.

## 19. C4/C5 status

Full **C4 OPEN**; **C5 OPEN**. Unchanged by Run 370.

## 20. Tests run

- `cargo build -p qbind-node --lib` — OK.
- `cargo test -p qbind-node --test run_370_public_devnet_deployed_live_socket_m12_tests` — 20 passed.
- `cargo build -p qbind-node --release` — OK.
- `cargo build -p qbind-node --release --example run_370_…_helper` — OK.
- Run 370 harness — PARTIAL-POSITIVE (helper 10/10; live-socket connection-rate
  proven; fail-closed + MainNet refused; independence).
- Regression: run_369 (24), run_365 (20), run_363 (21), run_362 (38), run_361
  (30), and `--lib` — see §20 of the PR/summary for the recorded pass counts.

## 21. Security scans

Secret scanning run over all changed files — clean (loopback / RFC 5737 only; no
keys, mnemonics, credentials, tokens, or private endpoints).

## 22. CodeQL

Recorded honestly in the final response — not claimed clean unless the run
completed.

## 23. Provenance

Single-machine, single-branch run in the task sandbox; loopback sockets and
temporary data dirs only; no external network, seed, or bootnode.

## 24. Honest limitations

- The deployed per-peer proof drives the adapter object synchronously, not bytes
  over a KEMTLS-admitted socket into `read_loop`. The exported-metric path is
  proven; the fully-live KEMTLS flood is not.
- The per-peer family only renders on `/metrics` once a drop has occurred, so a
  live node with no per-peer drops does not surface it (used here to prove
  independence, not per-peer enforcement).
- Bucket keying derives a `PeerId` from the first 8 bytes of the connection
  `NodeId` for rate-limit bucket selection only — not an identity/auth claim.

## 25. Suggested Run 371 next step

Stand up a **KEMTLS-admitted second-peer flood harness**: dial the deployed
`target/release/qbind-node` from a second real KEMTLS peer, complete mutual auth,
flood over-budget frames through the deployed `read_loop`, and scrape live
`/metrics` for `qbind_net_per_peer_drops_total{reason="rate_limit"}`. If that
lands with defaults preserved, M12 can move Green.