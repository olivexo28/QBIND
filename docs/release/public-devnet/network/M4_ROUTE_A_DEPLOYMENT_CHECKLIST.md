# QBIND Public DevNet — M4 Route-A Deployment Checklist (Run 392)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim. **DevNet only.**
>
> This is the exact checklist a **real** operator must complete, on **real** external infrastructure
> and from an **independent off-host vantage point**, before must-have **M4** (seed/bootnode
> reachability) can move Yellow → Green. Publishing this checklist does **not** move M4 Green, does
> **not** move M6 Green, and does **not** close C4/C5. It does not fake any endpoint or reachability.

M4 moves Green only when **every** section below passes with real, publish-safe evidence. This is the
"Route A" path referenced by the Run 377/378/388/391 reachability records; those runs reached
**Route C** (no external ingress / no independent off-host vantage point in the sandbox), so M4 stays
Yellow. Use this checklist together with:

- `docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md` — the operator runbook.
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — the evidence format.
- `docs/release/public-devnet/network/devnet-seed-list.schema.json` — the seed-list schema.

## 1. Preflight prerequisites

- [ ] Release `qbind-node` binary built; its SHA-256 / ELF BuildID / toolchain recorded (see
      `docs/release/public-devnet/binary/`).
- [ ] Run 356 genesis package on hand; `genesis_hash`
      `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f` and genesis-file SHA-256
      `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c` confirmed.
- [ ] Published PQC static root + trust bundle available (see
      `docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md`,
      `docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md`).
- [ ] A real host with a routable public IP (or DNS name resolving to one).
- [ ] A genuinely independent off-host vantage point available for verification (§5).

## 2. Seed identity material checklist

- [ ] Durable seed identity generated via `qbind-node identity generate devnet seed <out>`.
- [ ] ML-KEM leaf secret (`leaf.kem.sk.bin`) is `0600`, private, and never committed.
- [ ] ML-DSA root signing material kept offline/private; never committed.
- [ ] Only the public `node_id` / `peer_id` / leaf cert will be published.
- [ ] Every preflight illustrative identity replaced by this durable identity.
- [ ] `qbind-node identity register-check <public-identity.json> --role seed --cert <leaf.cert.bin>`
      passes against the target seed list (non-mutating admission check).

## 3. Public endpoint checklist

- [ ] Seed bound with `--p2p-listen-addr 0.0.0.0:<port>`.
- [ ] `--p2p-advertised-addr <public-host>:<port>` set to the externally reachable host/port.
- [ ] Public host/IP is routable (not RFC 1918 private, not RFC 5737 documentation, not loopback).
- [ ] Exactly the P2P port opened inbound; RPC/metrics/admin/SSH not publicly exposed for joining.

## 4. Strict KEMTLS / static-root checklist

- [ ] `--p2p-mutual-auth required`.
- [ ] `--p2p-pqc-root-mode pqc-static-root`.
- [ ] `--p2p-trusted-root <published-root>` set to the published DevNet static root.
- [ ] `--p2p-leaf-cert <leaf.cert.bin>` + `--p2p-leaf-cert-key <leaf.kem.sk.bin>` set.
- [ ] `--genesis-path <run356-genesis>` + `--expect-genesis-hash <run356-hash>` set.
- [ ] Node starts, binds the P2P port, and logs its `NodeId`.

## 5. Independent vantage requirements

The verification vantage point **must** be genuinely external to the seed:

- [ ] Outside the seed host.
- [ ] Outside the seed's NAT / router.
- [ ] **Insufficient (do not use):** same-host / loopback (`127.0.0.0/8`), same-NAT, same-VPC /
      same-cloud-internal, private-VPN-only reachability, and RFC 5737 documentation hosts
      (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Any of these keeps the run at Route B
      and **M4 stays Yellow**.
- [ ] Prefer a different network entirely (different cloud provider, or a residential/mobile
      connection) so the dial genuinely traverses the public internet.

## 6. Required external TCP evidence

- [ ] A timestamped external TCP dial from the independent vantage succeeds against
      `<public-host>:<port>` (e.g. `nc -vz <public-host> <port>`), captured with UTC timestamp and
      the vantage identity/independence statement.

## 7. Required external KEMTLS / static-root evidence

- [ ] A timestamped external **KEMTLS mutual-auth + PQC static-root** handshake from the independent
      vantage completes against the seed (e.g. a joiner `qbind-node --network-mode p2p --enable-p2p
      --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root --p2p-peer
      <node_id>@<public-host>:<port> ...`).
- [ ] Observed remote `NodeId` / cert-derived identity captured and confirmed to match the published
      seed entry.

## 8. Seed-list promotion

- [ ] Create `docs/release/public-devnet/network/devnet-seeds.live.json` (a **new** live list; do not
      overwrite the candidate/placeholder documents).
- [ ] The live entry sets `status: "live"`.
- [ ] The live entry sets a **non-null** `last_reachability_evidence` referencing the completed
      evidence record (§ evidence template).
- [ ] `p2p_host` / `p2p_multiaddr` / `operator` set to the real public values.
- [ ] The document is **schema-valid** against `devnet-seed-list.schema.json` (which structurally
      requires `last_reachability_evidence` on a `live` entry and forbids it on non-live entries).
- [ ] `genesis_hash` / `genesis_file_sha256` / each `expected_genesis_hash` match the Run 356
      genesis package.

## 9. Required register-check live acceptance

- [ ] `qbind-node identity register-check <public-identity.json> --seed-list
      docs/release/public-devnet/network/devnet-seeds.live.json --role seed --cert <leaf.cert.bin>
      --status live --reachability-evidence <evidence-record>` **accepts**.
- [ ] The same command **without** `--reachability-evidence` still **fails closed** (structural
      guarantee that a live entry cannot be admitted without reachability evidence).

## 10. M4 Green rules and non-claims

M4 moves Green **only if** §1–§9 all pass **together** in one run, and:

- no private key, KEM secret, signing secret, token, raw log, raw metrics dump, data dir, private
  endpoint, private hostname, or absolute build path is committed;
- the live document is schema-valid with a real `status: live` entry backed by real off-host
  external reachability evidence;
- no other readiness item is silently flipped Green.

Even when M4 moves Green, this checklist makes **no** claim about M6 fully-Green, C4 closure, C5
closure, TestNet readiness, or MainNet readiness — those are tracked separately and remain governed
by `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` and the readiness matrix. Until real off-host
external reachability evidence lands, **M4 stays Yellow and public DevNet stays NOT launch-ready.**

## Provenance

Reproduced by `scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh`; full provenance
in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_392.md`.