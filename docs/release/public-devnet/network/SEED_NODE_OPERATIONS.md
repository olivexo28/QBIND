# QBIND Public DevNet — Seed-Node Operations Runbook (Run 392)

> **Safety label (applies to this document):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only** operations runbook. It is **docs-only**: it deploys **no** seed node,
> bootnode, faucet, RPC gateway, explorer, or status page, and adds **no** CLI flag. It does **not**
> make public DevNet launch-ready, does **not** move must-have **M4** (seed/bootnode reachability) to
> Green, does **not** move **M6** (validator identity) to Green, and does **not** close **C4** or
> **C5**. It describes what a **real** seed operator must do; it does **not** fake any external
> endpoint or reachability.

This runbook tells a would-be public DevNet **seed operator** exactly how to prepare, start, verify,
and retire a real, externally reachable seed node. It is the operator-facing companion to:

- `docs/release/public-devnet/network/README.md` — seed-list format + placeholder / candidate.
- `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` — the exact Route-A
  deployment checklist that must pass before M4 can move Green.
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — the reachability
  evidence record format that a live seed must carry.

None of the steps here have been executed against a real external endpoint in the run that published
this document — see §8 and the Run 391/392 evidence records. Following this runbook **prepares**, but
does not by itself achieve, the real M4 external-seed reachability run.

## 1. DevNet-only safety label

Public DevNet is **experimental** and **resettable**. It carries **no value**, offers **no MainNet
readiness**, and closes **neither C4 nor C5**. State may be wiped at any time (see
`docs/release/public-devnet/ops/RESET_POLICY.md`). Seed identities, balances, and history have no
persistence guarantee. Nothing in this runbook implies a public DevNet launch, a TestNet readiness
claim, or a MainNet readiness claim.

## 2. Seed operator role and responsibilities

A seed operator runs a stable, externally reachable `qbind-node` that new joiners dial to bootstrap
their peer set. The operator is responsible for:

- generating and **privately** custodying a durable seed identity (§3);
- running the node under the strict KEMTLS static-root posture (§4);
- opening exactly the P2P port and nothing else (§5);
- keeping metrics loopback-only (§6);
- performing the operational health checks (§7);
- handling reachability failures honestly (§8);
- retiring a bad or compromised seed cleanly (§9);
- publishing publish-safe reachability evidence, and **never** committing private key material, raw
  logs, raw metrics dumps, data dirs, private endpoints/hostnames, or absolute build paths.

## 3. Durable seed identity generation and custody

Generate the durable seed identity with the pre-existing first-class command (Run 375 path; see the
operator identity package `docs/release/public-devnet/identity/`):

```bash
qbind-node identity generate devnet seed "$OUT/seed"
qbind-node identity print-public "$OUT/seed"     # inspect the public identity only
```

Custody rules:

- The **ML-KEM leaf secret** (`$OUT/seed/leaf.kem.sk.bin`, written `0600`) is **private**. It must
  never be committed, logged, pasted, or shared.
- The **ML-DSA root signing key** is generated in memory and is **never** written to disk by the
  command; if you export it for durable custody, keep it offline and private. It must never be
  committed.
- Publish only the **public** `node_id` / `peer_id` / leaf certificate.
- Any identity that appears in a preflight document (for example the illustrative `node_id` in
  `devnet-seeds.live-candidate.json`) is **illustrative only** and its secret material was discarded.
  **Replace every preflight illustrative identity with your own durable seed identity before any live
  publication.**

Before adding a candidate to a seed list, run the non-mutating admission verifier (Run 376):

```bash
qbind-node identity register-check "$OUT/seed/public-identity.json" \
    --seed-list docs/release/public-devnet/network/devnet-seeds.live-candidate.json \
    --role seed --cert "$OUT/seed/leaf.cert.bin"
```

It opens no socket, mutates no state, and makes no live/reachability/M4 claim.

## 4. Startup command for a real public seed

Boot the seed under the **strict KEMTLS mutual-auth + PQC static-root** posture, pinning the Run 356
genesis, using only **pre-existing** flags:

```bash
qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 0.0.0.0:30333 \
    --p2p-advertised-addr <public-host-or-ip>:30333 \
    --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root <published-trusted-root> \
    --p2p-leaf-cert "$OUT/seed/leaf.cert.bin" \
    --p2p-leaf-cert-key "$OUT/seed/leaf.kem.sk.bin" \
    --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
    --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f \
    --data-dir <durable-data-dir>
```

Posture notes:

- `--env devnet` — DevNet only; never reuse MainNet/TestNet material.
- `--network-mode p2p` + `--enable-p2p` — enable P2P networking (both are off by default; the DevNet
  freeze is preserved for every other operator).
- **Bind/listen posture:** `--p2p-listen-addr 0.0.0.0:<port>` binds the P2P port on the host. Bind
  only the P2P port; do not bind RPC/metrics to a public interface.
- **Advertised address posture:** `--p2p-advertised-addr <public-host>:<port>` is the address joiners
  will dial. Behind NAT / a load balancer it must be the **externally reachable** host/port, not a
  private address.
- `--p2p-mutual-auth required` — strict KEMTLS mutual auth; joiners must present a valid leaf cert.
- `--p2p-pqc-root-mode pqc-static-root` + `--p2p-trusted-root <root>` — pin the published PQC static
  root so joiners perform strict-auth against a fixed root (see
  `docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md` and
  `docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md`).
- `--p2p-leaf-cert` / `--p2p-leaf-cert-key` — this seed's own ML-DSA-signed leaf certificate and its
  KEM secret key (the `0600` file from §3).
- `--genesis-path` / `--expect-genesis-hash` — pin the Run 356 genesis file and hash so the seed
  refuses to start against the wrong genesis.

## 5. Firewall / NAT / security-group requirements

- Open **exactly** the P2P TCP port (e.g. `30333`) inbound from the public internet — nothing else.
- Do **not** expose RPC, metrics, admin, or SSH to `0.0.0.0` for the purpose of joining; restrict
  management access to trusted sources only.
- Behind NAT, configure a port-forward for the P2P port to the seed host and ensure
  `--p2p-advertised-addr` matches the externally reachable host/port.
- In a cloud environment, the security group / firewall must allow inbound on the P2P port from
  `0.0.0.0/0` (or the intended joiner range) and the advertised address must be the routable public
  address.
- Confirm the reachable path is genuinely external: same-host, same-NAT, same-VPC / same-cloud
  internal, private-VPN-only, loopback, and RFC 5737 documentation hosts are **not** externally
  reachable and do not satisfy M4 (see the deployment checklist §5).

## 6. Metrics exposure

- Metrics are exposed **only** via the loopback opt-in `QBIND_METRICS_HTTP_ADDR` (e.g.
  `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9600`); there is **no** metrics CLI flag.
- **Never** expose unauthenticated metrics publicly. Bind the metrics endpoint to loopback and scrape
  it locally or over a private, authenticated channel (see
  `docs/release/public-devnet/observability/README.md`).

## 7. Operational checks

After startup, confirm:

1. **Process running** — the `qbind-node` process is up and has not exited.
2. **P2P port listening** — the P2P port is listening on the intended interface (e.g. `ss -ltn` shows
   the `--p2p-listen-addr` port) and, externally, is reachable from an independent off-host vantage
   (see the deployment checklist §5–§7 and the evidence template).
3. **Genesis hash pinned** — the node started with `--expect-genesis-hash` matching the Run 356
   genesis and did not fall back to a different genesis.
4. **Build provenance known** — the running binary's SHA-256 / ELF BuildID / toolchain are recorded
   (see `docs/release/public-devnet/binary/` and `qbind_node_build_info` on the loopback metrics
   endpoint).
5. **NodeId / cert matches public identity** — the observed `NodeId` and the leaf certificate match
   the published seed entry's `node_id`; re-derive deterministically with
   `qbind-node identity register-check --cert <leaf.cert.bin>`.

## 8. Failure handling

If external reachability cannot be proven from an independent off-host vantage point:

- keep the seed entry at `status: planned` (or `placeholder`) with `last_reachability_evidence:
  null`;
- do **not** publish `devnet-seeds.live.json` and do **not** mark any entry `status: live`;
- record the attempt honestly as **Route C** (no safe external infrastructure available) or as
  **Route B** (only loopback / same-host reachability demonstrated), following the pattern of the
  Run 377/378/388/391 reachability records;
- keep **M4 Yellow** — a failed or unproven external reachability attempt never moves M4 Green.

The run that published this runbook is itself **Route B** (docs + verification harness); no real
external endpoint was exposed and M4 stays Yellow.

## 9. Retirement / removal of a bad seed

To retire a failed, compromised, or decommissioned seed:

- move the entry's `status` to `retired` (schema requires `last_reachability_evidence: null` for a
  `retired` entry, so a retired seed carries no active reachability claim);
- do **not** silently replace one seed's identity/endpoint with another under the same entry — retire
  the old entry and add a new, separately verified entry;
- if the retirement follows an incident (suspected key compromise, unreachability, bad provenance),
  publish a reachability/incident note per `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`,
  redacting all private material;
- on suspected key compromise, treat the seed identity as burned: generate a fresh durable identity
  (§3), never reuse the compromised leaf/root material, and follow
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

## 10. What this runbook does not do

It does not deploy a seed, does not open an external port, does not fake an endpoint, does not
publish a live seed list, does not move M4 or M6 Green, does not close C4 or C5, and leaves public
DevNet **not** launch-ready. See the readiness matrix
(`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`) for current status.

## Provenance

Full provenance (git commit, release-binary SHA-256 / BuildID / toolchain, CLI/help verification,
schema checks, non-claim checks, readiness deltas) is recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_392.md` and reproduced by
`scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh`.
