# Run 373 — public DevNet abuse/DoS M12 cross-process PqcStaticRoot strict-mutual-auth (release binary)

This directory is the tracked archive for Run 373. Only three files are tracked:
`README.md`, `summary.txt`, and `.gitignore`. Every per-run artifact (raw logs,
runtime-generated PQC/KEMTLS roots / certs / KEM secret keys, node data dirs,
metrics dumps, helper output, temp files) is **gitignored** — it contains
absolute paths and ephemeral, machine-specific data and must never be committed.

## What Run 373 proves

Run 371 (accepted POSITIVE) moved **M12 Yellow/Partial → Green** for the public
DevNet readiness track; Run 372 (accepted POSITIVE) preserved that Green result
under strict `MutualAuthMode::Required` admission with two simultaneous KEMTLS
peers and isolated per-peer buckets. Run 372's only recorded limitation was that
its `PqcRootMode::PqcStaticRoot` proof was **in-process only** — it was not
driven cross-process against the standalone `target/release/qbind-node` with
operator-configured `--p2p-trusted-root` / `--p2p-leaf-cert` / `--p2p-leaf-cert-key`
material.

Run 373 closes exactly that gap, using **only production public APIs and the
pre-existing public/hidden CLI surface (Route A — no production source change)**:

* **Cross-process static-root strict-auth admission** — the harness mints
  **temporary** ML-DSA-44 root + ML-KEM-768 leaf material with the pre-existing
  `devnet_pqc_root_helper` example, then launches the standalone
  `target/release/qbind-node` under `--p2p-mutual-auth required
  --p2p-pqc-root-mode pqc-static-root --p2p-trusted-root <spec> --p2p-leaf-cert
  <path> --p2p-leaf-cert-key <path>` (plus `--p2p-peer` / `--p2p-peer-leaf-cert`
  for the peers) on a loopback listen + metrics endpoint. Live `/metrics` exports
  `qbind_p2p_pqc_root_mode 1` and `qbind_p2p_pqc_roots_configured 1`.
* **Cert-derived identity** — the Run 373 helper (dial-flood-static-root mode)
  builds node B peers from the SAME operator material and completes the Required
  KEMTLS mutual-auth handshake. Under PqcStaticRoot the NodeId is derived from the
  certified leaf ML-KEM-768 public key; the deployed listener registers each peer
  under exactly that **verified cert-derived NodeId**, and each peer observes the
  deployed node's cert-derived NodeId in return.
* **Per-peer static-root flood + bucket isolation** — TWO KEMTLS-admitted peers
  run simultaneously: an HONEST peer (validator id 1, under budget) and an
  ABUSIVE peer (validator id 2, over budget). On live `/metrics` the abusive
  peer's drops appear ONLY under its cert-derived `peer="<key>"` label (computed
  by the helper's `bucket-key-cert` mode from the shared leaf cert), while the
  honest peer's label records NO drops. The abusive peer does **not** consume the
  honest peer's budget.
* **Controls remain independent** — the Run 367/370 connection-rate live-socket
  regression (10 inbound TCP connections, max 3 → 3 accepted / 7 refused,
  `qbind_p2p_connection_rate_drop_total = 7`) is preserved, and neither control
  ever touches the other's counter.

All Run 371/372 guarantees are preserved. Run 373 is **hardening evidence for M12
only**; it does NOT broaden scope toward public DevNet launch readiness.

## How to reproduce

```bash
# From the repository root:
bash scripts/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary.sh \
  /tmp/qbind-run373-out
cat /tmp/qbind-run373-out/summary.txt
```

The harness builds `target/release/qbind-node`, the Run 373 release helper, and
the `devnet_pqc_root_helper` example, runs the in-process static-root strict-auth
scenarios, checks the production CLI surface / fail-closed configs / MainNet
refusal, then stands up real `qbind-node` processes on loopback and drives:

1. the connection-rate live-socket regression, and
2. the cross-process static-root strict-auth multi-peer per-peer flood (honest
   under-budget + abusive over-budget, concurrently), scraping live `/metrics`
   per cert-derived bucket label.

The temporary PQC material dir is removed on exit.

## Scope / safety

* Loopback (`127.0.0.1`) and OS-assigned ports only; temporary data dirs; no
  public DevNet, seed, bootnode, faucet, RPC, explorer, or status page.
* No P2P wire-format change; no peer-admission / KEMTLS / trust-bundle weakening
  (strict mutual-auth only TIGHTENS admission); no `LivePqcTrustState` /
  validator-set / epoch / sequence / marker mutation.
* No new public CLI flags: the abuse/DoS flags stay hidden; `--p2p-mutual-auth`,
  `--p2p-pqc-root-mode`, `--p2p-trusted-root`, and `--p2p-leaf-cert*` are all
  pre-existing public flags.
* No committed secrets or live endpoints; generated PQC/KEMTLS material
  (including private KEM secret keys) is temporary, dev-only, written only into
  temp dirs, removed on exit, and gitignored. The root signing key is held in
  memory only and never written to disk.

See the canonical evidence write-up at
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_373.md`.
