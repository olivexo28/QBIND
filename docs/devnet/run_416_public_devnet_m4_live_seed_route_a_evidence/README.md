# Run 416 evidence archive — public DevNet M4 live seed Route A (real external reachability)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · **external reachability PROVEN (Route A)** ·
> **no M4 Green** (no durable published `devnet-seeds.live.json`) · no M6 fully-Green ·
> no S5 Green · no S7 Green · no TestNet readiness · no MainNet readiness ·
> **C4/C5 OPEN**. **No private key material is committed.**

This archive packages the **first successful real external reachability run** for a
public DevNet seed. Where Runs 378 / 388 / 391 / 393 / 397 all executed the **Route A**
objective and reached a **Route C / NEGATIVE-FOR-EXTERNAL** finding (no external ingress
and no independent off-host vantage point inside the sandboxed CI environment), Run 416
was executed on **real operator infrastructure**: a routable public seed VPS and a
genuinely independent off-host dialer on a different network. External TCP **and** KEMTLS
mutual-auth static-root reachability were proven from outside the seed operator's own
host/NAT.

Canonical evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_416.md`.
Reachability evidence record: `docs/release/public-devnet/network/reachability/RUN_416_qbind-devnet-seed-1.md`.

## What was run (Route A topology)

- **Seed (VPS):** `qbind-node` listening on `0.0.0.0:30333`, externally reachable at
  `188.166.227.87:30333`. Seed host: `ubuntu-s-1vcpu-1gb-sgp1` (DigitalOcean SGP1,
  `1vcpu-1gb`).
- **Off-host dialer:** Laptop 1 WSL (host `olivegigi`), on a **different network**
  (public egress address observed by the seed as `110.226.112.166`), dialing
  `0@188.166.227.87:30333`.
- **Transport:** `--p2p-mutual-auth required`.
- **PQC root mode:** `--p2p-pqc-root-mode pqc-static-root`.
- **Dialer override:** a per-peer KEM public key + `--validator-id` override was supplied
  by the dialer so it could complete the mutual-auth static-root handshake against the
  seed's advertised identity.
- **PQC material:** **temporary DevNet** ML-DSA-44 root + ML-KEM-768 leaf material generated
  on **both** sides by `crates/qbind-node/examples/devnet_pqc_root_helper.rs`. It is
  ephemeral, dev-only, and **discarded**; only public identifiers and status lines are
  recorded here.

## Runtime provenance (important accuracy note)

- The **runtime evidence commit** recorded in **both** manifests (seed and dialer) is
  `1c2ba28d1532474a9e1124bc9873cd54193f29b6`. The live `qbind-node` binary used on the seed
  and dialer was built from that commit.
- Run 415 (`50eed16b docs: add Run 415 readiness artifact path reference lint`) was committed
  **after** the live binary was built. This archive therefore does **not** claim the live
  binary was built from `50eed16b`; it was built from `1c2ba28d…`.

## Tracked (publish-safe) files

| File | Contents |
|------|----------|
| `README.md` | This guide. |
| `summary.txt` | Publish-safe status lines (verdict, endpoints, hosts, socket evidence, redaction). |
| `SHA256SUMS.txt` | SHA-256 of the tracked publish-safe evidence text files below. |
| `laptop1/manifest.txt` | Dialer capture manifest (runtime commit, host, run parameters, redaction). |
| `laptop1/dialer-process.txt` | Publish-safe description of the dialer `qbind-node` invocation. |
| `laptop1/dialer-sockets.txt` | Publish-safe dialer socket state (established connection to the seed). |
| `laptop1/dialer-log-extract.txt` | Publish-safe extract of the dialer P2P/handshake log lines. |
| `laptop1/dialer-metrics.txt` | Publish-safe `qbind-node` build/identity metrics facts from the dialer. |
| `vps/manifest.txt` | Seed capture manifest (runtime commit, host, listen posture, redaction). |
| `vps/seed-process.txt` | Publish-safe description of the seed `qbind-node` invocation. |
| `vps/seed-sockets.txt` | Publish-safe seed socket state (`LISTEN` + inbound `ESTAB` from the dialer). |
| `vps/seed-log-extract.txt` | Publish-safe extract of the seed P2P/accept log lines. |
| `vps/seed-metrics.txt` | Publish-safe `qbind-node` build/identity metrics facts from the seed. |

## NOT committed (gitignored)

The raw operator-side capture bundles — `bundles/qbind-m4-evidence-laptop1.tgz` and
`bundles/qbind-m4-evidence-vps.tgz` — are produced on the operator's own machines and are
**not** committed. They contain absolute paths, full host process tables, raw logs / metrics
dumps, and the temporary DevNet PQC material (root signing key, KEM leaf secret). The
`.gitignore` in this directory blocks them, along with any key/cert/data-dir/log artifact,
as a backstop. Only the publish-safe transcriptions above are tracked.

## What this proves — and does not prove

**Proven:** external TCP reachability and an external KEMTLS mutual-auth static-root
handshake to a real, routable public DevNet seed from an independent off-host vantage on a
different network — the exact external step Runs 378/388/391/393/397 could not demonstrate.

**Not proven / not claimed:** a **durable** published live seed. The seed identity used
temporary DevNet PQC material that was discarded, the VPS is not committed as a permanent
operator seed, and **no `devnet-seeds.live.json` is published**. The committed
`docs/release/public-devnet/network/devnet-seeds.live-candidate.json` therefore stays
`status: planned`. **M4 stays Yellow / launch-blocking**; the remaining Green gate narrows
to provisioning a durable (non-ephemeral) operator seed identity on the externally reachable
host and publishing it as `devnet-seeds.live.json` with `status: live`. No C4/C5 closure,
no TestNet/MainNet readiness, and no other readiness item is claimed.
