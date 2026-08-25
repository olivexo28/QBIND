# Run 372 — public DevNet abuse/DoS M12 strict-mutual-auth + multi-peer concurrent flood (release binary)

This directory is the tracked archive for Run 372. Only three files are tracked:
`README.md`, `summary.txt`, and `.gitignore`. Every per-run artifact (raw logs,
runtime-generated PQC/KEMTLS certs / keys / trust bundles, node data dirs,
metrics dumps, helper output, temp files) is **gitignored** — it contains
absolute paths and ephemeral, machine-specific data and must never be committed.

## What Run 372 proves

Run 371 (accepted POSITIVE) moved **M12 Yellow/Partial → Green** for the public
DevNet readiness track by driving ONE KEMTLS-admitted peer (default
`MutualAuthMode::Disabled`) that flooded structured frames over the deployed
`TcpKemTlsP2pService::read_loop` of a running `target/release/qbind-node`, with
live `/metrics` exposing `qbind_net_per_peer_drops_total{reason="rate_limit"}`.

Run 372 re-proves that Green result under **stricter admission** and
**multi-peer concurrent flood** conditions, using **only production public APIs
(Route A — no production source change)**:

* **Strict mutual-auth admission** — the deployed node runs with the pre-existing
  public flag `--p2p-mutual-auth required`, and each flooding peer completes a
  full `MutualAuthMode::Required` KEMTLS handshake before flooding. The listener
  registers each peer under its **verified cert-derived NodeId**, not a
  self-asserted `client_random`.
* **Production-grade / PQC-static-root material** — the release helper drives a
  two-node `PqcRootMode::PqcStaticRoot` strict mutual-auth handshake with
  runtime-generated ML-DSA-44 root + ML-KEM-768 leaf material (never written to
  disk), proving the strict admission path also works with production-grade (not
  default deterministic test-grade) material.
* **Multi-peer bucket isolation** — TWO KEMTLS-admitted peers run
  simultaneously: an HONEST peer (validator id 1, under budget) and an ABUSIVE
  peer (validator id 2, over budget). On live `/metrics` the abusive peer's drops
  appear ONLY under the abusive peer's deterministic `peer="<key>"` label, while
  the honest peer's label records NO drops.
* **Abusive peer does not consume the honest peer's budget** — the honest peer
  stays fully under budget throughout the abusive flood.
* **Controls remain independent** — the Run 367/370 connection-rate live-socket
  regression (10 inbound TCP connections, max 3 → 3 accepted / 7 refused,
  `qbind_p2p_connection_rate_drop_total = 7`) is preserved, and neither control
  ever touches the other's counter.

All Run 371 guarantees are preserved. Run 372 is **hardening evidence for M12
only**; it does NOT broaden scope toward public DevNet launch readiness.

## How to reproduce

```bash
# From the repository root:
bash scripts/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary.sh \
  /tmp/qbind-run372-out
cat /tmp/qbind-run372-out/summary.txt
```

The harness builds `target/release/qbind-node` and the Run 372 release helper,
runs the in-process strict-auth multi-peer flood scenarios, checks the production
CLI surface / fail-closed configs / MainNet refusal, then stands up real
`qbind-node` processes on loopback and drives:

1. the connection-rate live-socket regression, and
2. the strict-auth multi-peer per-peer flood (honest under-budget + abusive
   over-budget, concurrently), scraping live `/metrics` per bucket label.

## Scope / safety

* Loopback (`127.0.0.1`) and OS-assigned ports only; temporary data dirs; no
  public DevNet, seed, bootnode, faucet, RPC, explorer, or status page.
* No P2P wire-format change; no peer-admission / KEMTLS / trust-bundle weakening
  (strict mutual-auth only TIGHTENS admission); no `LivePqcTrustState` /
  validator-set / epoch / sequence / marker mutation.
* No new public CLI flags: the abuse/DoS flags stay hidden; `--p2p-mutual-auth`
  is a pre-existing public flag.
* No committed secrets or live endpoints; generated PQC/KEMTLS material is
  temporary, dev-only, in-memory, and gitignored.

See the canonical evidence write-up at
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_372.md`.
