# Run 371 — public DevNet abuse/DoS M12 KEMTLS per-peer live-socket flood (release binary)

This directory is the tracked archive for Run 371. Only three files are tracked:
`README.md`, `summary.txt`, and `.gitignore`. Every per-run artifact (raw logs,
generated KEMTLS certs / keys / trust bundles, node data dirs, metrics dumps,
helper output, temp files) is **gitignored** — it contains absolute paths and
ephemeral, machine-specific data and must never be committed.

## What Run 371 proves

Run 370 strengthened M12 by wiring the exported
`qbind_net_per_peer_drops_total{reason="rate_limit"}` counter end-to-end onto the
deployed `TcpKemTlsP2pService::read_loop` per-peer limiter, but it did **not**
drive a KEMTLS-admitted deployed socket flood: its per-peer proof called the
deployed adapter object directly (`allow_node`), with no socket and no handshake.

Run 371 closes that gap using **only production public APIs (Route A — no
production source change)**:

* A second peer (the Run 371 helper in `dial-flood` mode) completes a **real
  KEMTLS mutual-auth handshake over a real loopback socket** against a separate
  running `target/release/qbind-node`.
* It floods structured `P2pMessage::Consensus` frames (discriminator `0`, so they
  reach the deployed per-peer limiter after `decode_frame`, unlike `0x05`
  peer-candidate frames).
* The deployed node's **live `/metrics`** exposes
  `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing for the
  over-budget flood and stays absent for the under-budget flood.
* The Run 367/370 connection-rate live-socket proof (10 inbound TCP connections,
  max 3 → 3 accepted / 7 refused, `qbind_p2p_connection_rate_drop_total = 7`) is
  preserved in the same harness.
* The two controls are independent: the per-peer flood never touches the
  connection-rate counter and vice-versa.

Both deployed live-socket controls are now proven on the real release binary, so
Run 371 supports moving **M12 Yellow/Partial → Green**.

## How to reproduce

```bash
# From the repository root:
bash scripts/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary.sh \
  /tmp/qbind-run371-out
cat /tmp/qbind-run371-out/summary.txt
```

The harness builds `target/release/qbind-node` and the Run 371 release helper,
runs the in-process two-node KEMTLS flood scenarios, checks the production CLI
surface / fail-closed configs / MainNet refusal, then stands up real
`qbind-node` processes on loopback and drives:

1. the connection-rate live-socket regression, and
2. the KEMTLS-admitted per-peer under/over-budget flood, scraping live `/metrics`.

## Scope / safety

* Loopback (`127.0.0.1`) and OS-assigned ports only; temporary data dirs; no
  public DevNet, seed, bootnode, faucet, RPC, explorer, or status page.
* No P2P wire-format change; no peer-admission / KEMTLS / trust-bundle weakening;
  no `LivePqcTrustState` / validator-set / epoch / sequence / marker mutation.
* The hidden/devnet-only abuse/DoS flags stay absent from `--help`.
* No committed secrets or live endpoints; generated KEMTLS material is temporary,
  dev-only, and gitignored.

See the canonical evidence write-up at
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`.
