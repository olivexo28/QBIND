# QBIND DevNet evidence — Run 370

**Title.** Release-binary **M12 deployed live-socket** evidence for the public
DevNet abuse/DoS controls — proving on the real `target/release/qbind-node` that
the **connection-rate** control is enforced over real loopback sockets, and that
the Run 369 deployed per-peer message-rate limiter now exports
`qbind_net_per_peer_drops_total{reason="rate_limit"}` end-to-end via a narrow,
default-preserving `NodeMetrics` threading change (Route B).

**Status.** PARTIAL-POSITIVE (strengthened). Run 370 closes the Run 369 "honest
limitation" that the deployed `DeployedInboundPerPeerLimiter` was installed with
`metrics = None` — so a per-peer message-rate drop on the deployed `TcpKemTls`
read loop bumped only the adapter's own bounded counter, never the exported
`/metrics` counter. A narrow source change threads an optional live
`Arc<NodeMetrics>` through `P2pNodeBuilder::with_node_metrics` and the shared
`build_deployed_inbound_per_peer_limiter()` seam that `start()` uses, wired in
`main.rs` with the SAME `NodeMetrics` instance the live `/metrics` endpoint
scrapes. Over-budget frames on the deployed adapter now increment the exported
`qbind_net_per_peer_drops_total{reason="rate_limit"}` counter.

**M12 stays Yellow/Partial (strengthened) — it does NOT move Green.** M12 Green
requires BOTH controls proven over a fully **deployed** live socket. The
connection-rate control is proven over real loopback sockets on the release
binary (10 inbound TCP connections, max 3 → 3 accepted / 7 refused, live
`qbind_p2p_connection_rate_drop_total = 7`). The deployed per-peer message-rate
control's exported-metric path is now wired end-to-end and proven against the
**exact adapter object** `start()` installs on `TcpKemTlsP2pService::read_loop`
(driven in the release helper). The residual blocker is a **KEMTLS-admitted
deployed per-peer socket flood** — a second peer completing mutual-auth and
flooding over-budget frames over the deployed read loop, observed on live
`/metrics` — which this run does not stand up.

## Decision gate (recorded) — Route B

Per `task/RUN_370_TASK.txt`, the decision gate resolves to **Route B**: the
existing deployed binary path could NOT expose per-peer drop evidence on live
`/metrics` without a source change, because Run 369 installed the adapter with
`metrics = None` (the builder held a `P2pMetrics`, not the `NodeMetrics` that
owns `qbind_net_per_peer_drops_total`). The narrowest safe fix threads an
optional live `NodeMetrics` handle into the deployed inbound limiter; defaults
are preserved (no handle → `metrics = None`, Run 369 posture bit-for-bit), source
tests are added, and release-binary evidence is produced. Route A (no source
change) is impossible; Route C (record blocker only) is superseded for the
exported-metric wiring but still applies to the fully-live KEMTLS socket flood.

## Files

Tracked in this archive directory (only these three):

- `README.md` — this file.
- `summary.txt` — curated release-run summary with hashes, scenarios, and the
  recorded honest limitation.
- `.gitignore` — ignores all raw/generated artifacts (helper output, node logs,
  temp data dirs, per-scenario files, metric dumps).

Everything else the harness writes under its `OUTDIR` (helper output, node logs,
`nodes/`, `failclosed/`, `help.txt`, `metric_evidence.txt`, `manifest.txt`, …)
is intentionally gitignored: it contains absolute paths and ephemeral data.

## How to reproduce

```bash
bash scripts/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary.sh
# artifacts land under the OUTDIR printed by the harness (default /tmp/...).
```

The harness:

1. builds `target/release/qbind-node` and the Run 370 release helper, capturing
   SHA-256, Build IDs, and toolchain versions;
2. runs the release helper (10/10 in-process deployed-adapter scenarios,
   including the exported per-peer drop metric);
3. checks the production CLI surface (hidden flags absent from `--help`, invented
   flags rejected, real hidden flags parse);
4. proves invalid zero/unbounded per-peer and zero connection-rate configs, and
   an enabled MainNet abuse/DoS config, fail the real binary closed at startup;
5. launches P2P-capable loopback nodes and drives real inbound TCP sockets to
   prove the connection-rate control live-socket and its independence from the
   per-peer counter;
6. records the KEMTLS-admitted deployed per-peer socket flood as the residual
   blocker (not driven).

## Runtime evidence (representative run)

- `target/release/qbind-node` sha256
  `e28775a2c44d02466b3c86dfff5e5641d93d983bde89e6d0f4701cc257131669`,
  build_id `05e9e0b9b78599fe1c4d5f6bd1fd8786f3a4b9ec`.
- helper sha256
  `5325781bbeca8b995a0f1183ab8b329b0e204147487f052746f476d65569ad8a`,
  build_id `3e68662c0743f653d89a764e9a0e418c8b4cebb3`.
- connection-rate live socket: 10 inbound TCP connections, max 3 →
  3 accepted / 7 refused; live `qbind_p2p_connection_rate_drop_total = 7`.
- deployed per-peer exported metric (helper, deployed adapter object):
  `qbind_net_per_peer_drops_total{peer="21",reason="rate_limit"} 5` rendered by
  `NodeMetrics::format_metrics`; scenario 08 over-budget: adapter counter ==
  exported counter == 20.
- independence: a connection-rate flood left `qbind_net_per_peer_drops_total`
  ABSENT on live `/metrics`; the per-peer drop path never touches
  `qbind_p2p_connection_rate_drop_total`.

## Scope / non-mutation

No public DevNet launch; no seed/bootnode/faucet/RPC/explorer/status page; no
TestNet/MainNet readiness claim; no C4/C5 closure; no P2P wire-format change; no
peer-admission / KEMTLS / trust-bundle weakening; no `LivePqcTrustState`,
validator-set, epoch, sequence, or marker mutation; no new public CLI flags
(hidden abuse/DoS flags remain hidden). All addresses are loopback (127.0.0.1) or
RFC 5737; temporary data dirs are used and removed; no secrets are committed.
