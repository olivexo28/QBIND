# QBIND Public DevNet — Seed / Bootnode List (Run 357)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only**, **docs / artifact / verification-only** package. It deploys **no** seed
> node, bootnode, faucet, RPC gateway, explorer, or status page, and adds **no** CLI flag. The seed
> list published here is a **placeholder**: it contains **no live seeds** and **no externally
> reachable infrastructure**. Public DevNet is **NOT launch-ready** (see §6).

This directory publishes the canonical **public DevNet seed/bootnode list format** (a JSON Schema)
and a **placeholder** DevNet seed-list artifact, produced under Run 357. It is the operator-facing
structure required for future seed publication. It **does not** claim must-have **M4** (seed/bootnode
list for public join) is Green.

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This document. |
| `devnet-seed-list.schema.json` | Canonical JSON Schema (draft-07) for a DevNet seed/bootnode list. |
| `devnet-seeds.placeholder.json` | Placeholder DevNet seed list (non-live, documentation-example values only). |
| `VERIFY.md` | Exact operator verification commands and expected outputs. |
| `devnet-seeds.live-candidate.json` | **Run 377** preflight live-seed **candidate** (Route B / Partial-positive): schema-valid, single entry `status: planned` with a real Run-375-path public `node_id`/`peer_id` and a non-routable RFC 5737 host. **NOT a live seed** — external reachability was not proven. |
| `reachability/RUN_377_qbind-devnet-seed-1.md` | **Run 377** reachability evidence record (loopback/same-host only; external reachability NOT proven; M4 stays Yellow). |

This is the canonical location for the public DevNet seed/bootnode list. It sits alongside the
Run 356 genesis package (`docs/release/public-devnet/genesis/`) under the shared
`docs/release/public-devnet/` tree; no better pre-existing canonical location existed, so the new
`network/` subdirectory was created.

## 1. What the seed list is

The seed list is a **machine-readable, operator-facing catalogue** of the seed/bootnode entries an
external node would use to join the public DevNet. Its shape is fixed by
`devnet-seed-list.schema.json`, which pins, at minimum:

- top-level identity: `schema_version`, `network_name`, `environment`, `runtime_chain_id`,
  `genesis_hash`, `genesis_file_sha256`;
- a mandatory `safety_label` and an explicit `placeholder_statement`;
- a `seed_nodes` array; each entry carries `node_id`, `peer_id`, `validator_address`, `p2p_host`,
  `p2p_port`, `p2p_multiaddr`, `transport_security_mode`, `pqc_suite`, `trust_bundle_required`,
  `expected_genesis_hash`, `operator`, `status` (`placeholder` | `planned` | `live` | `retired`),
  `last_reachability_evidence`, and `notes`.

The schema enforces that a `live` entry **must** carry `last_reachability_evidence`, and that a
`placeholder` / `planned` / `retired` entry **must not** (its `last_reachability_evidence` must be
`null`). This makes it structurally impossible to mark a non-live entry as if it were reachable.

## 2. What the seed list is NOT

- It is **not** a live seed list. The committed `devnet-seeds.placeholder.json` contains **no** live
  seeds; its single entry uses `status: "placeholder"` with a non-routable **RFC 5737 TEST-NET-1**
  host (`192.0.2.1`) that is **not externally reachable**.
- It is **not** a public DevNet launch claim, a public TestNet readiness claim, or a MainNet
  readiness claim.
- It contains **no** private keys, mnemonics, seed phrases, tokens, credentials, private IPs
  intended to remain private, production hostnames, or real operator secrets.
- It does **not** close C4 or C5, and does **not** mark M4 Green.

## 3. Relationship to the Run 356 genesis package

The seed list is pinned to the Run 356 canonical genesis package
(`docs/release/public-devnet/genesis/`):

- `genesis_hash` = `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f` — the
  canonical Run 101 genesis hash published in Run 356.
- `genesis_file_sha256` = `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c` — the
  file-byte SHA-256 of `devnet-genesis.json` published in Run 356.
- Each seed entry's `expected_genesis_hash` must equal the top-level `genesis_hash`, so a joining
  operator can confirm every seed expects the same genesis they pinned.

`VERIFY.md` records the exact commands that cross-check both values against the Run 356 artifacts.

## 4. How an operator will use a future live seed list

When a future run publishes a **live** seed list (real, externally reachable seeds + reachability
evidence), an operator will:

1. Fetch the seed list and confirm `genesis_hash` / `genesis_file_sha256` match the genesis they
   intend to run (see the Run 356 genesis `VERIFY.md`).
2. Select `status: "live"` entries.
3. Start `qbind-node` against those seeds using the **pre-existing** P2P flags (§5), pinning the
   genesis hash with the pre-existing `--expect-genesis-hash`.

The placeholder entry documents this shape but must **not** be dialed — its host is a documentation
address and is not reachable.

## 5. Which existing CLI flags are expected to be used

All flags below are **pre-existing**; Run 357 adds **no** new CLI flag and changes **no** P2P wire
format, peer-admission logic, or default network behaviour.

- `--enable-p2p` — enable P2P networking (defaults to `false`; DevNet freeze preserved).
- `--p2p-listen-addr` — local P2P listen `host:port`.
- `--p2p-advertised-addr` — advertised `host:port` (NAT / load-balancer).
- `--p2p-peer` — static peer, repeatable; accepts `host:port` (or `vid@host:port`). A future live
  seed's `p2p_multiaddr` is intended to be passed here.
- `--p2p-mutual-auth` — KEMTLS mutual-auth mode (`required` | `optional` | `disabled`); maps to a
  seed entry's `transport_security_mode`.
- `--p2p-trust-bundle` (+ `--p2p-trust-bundle-signing-key`) — signed PQC trust bundle; maps to a
  seed entry's `trust_bundle_required`.
- `--expect-genesis-hash` — pin the canonical genesis hash (maps to `expected_genesis_hash`).

These map onto the seed-list fields so the document stays consistent with the actual join surface
without inventing new flags.

## 6. Why public DevNet is still NOT launch-ready

Publishing a seed-list **format** and a **placeholder** artifact does not make the network joinable.
There are still **no** externally reachable seeds. Must-have **M4** therefore remains a public DevNet
launch blocker (it moves **Red → Yellow** for the format+placeholder milestone only), and **M3**
(release-binary reproducibility / BuildID) remains **Red**. See
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. Because at least one must-have is not Green,
public DevNet is **not** launch-ready.

## 7. What evidence is required to move M4 to Green

M4 moves to **Green** only when **all** of the following land together in a future run:

1. A committed seed list with one or more `status: "live"` entries backed by **real, externally
   reachable** seed/bootnode nodes.
2. `last_reachability_evidence` for each live entry: reproducible reachability proof (e.g. a
   timestamped external dial / handshake result) from outside the operator's own host/NAT.
3. Consistent `genesis_hash` / `genesis_file_sha256` matching the published genesis package.
4. Real (public) `node_id` / `peer_id` values intentionally published as live, with no secret
   material.

Until then, M4 stays a launch blocker.

## 8. What a future run must provide

A future run must **deploy real seed/bootnode nodes** and **capture external reachability evidence**,
then replace the placeholder entry with live entries and update the readiness matrix. That deployment
work is explicitly **out of scope** for Run 357 (docs / artifact / verification only).

## 8a. Populating seed identity fields (Run 374, first-class command Run 375)

The per-seed `node_id` / `peer_id` / `validator_address` / `pqc_suite` /
`transport_security_mode` fields are produced by the Run 374 operator identity package
(`docs/release/public-devnet/identity/`). An operator generates candidate identity material with
the first-class `qbind-node identity generate` command (Run 375; the Run 374
`run_374_public_devnet_identity_generation_helper` example remains a thin wrapper), then maps the
resulting `public-identity.json` into a `seed_node` object. The command can emit the mapped object
directly:

```bash
qbind-node identity generate devnet seed "$OUT/seed"
qbind-node identity seed-candidate "$OUT/seed"   # prints a planned seed_node object
```

Candidate entries stay `status: "planned"` / `"placeholder"` with `last_reachability_evidence: null`
and require the operator to fill `p2p_host` / `p2p_multiaddr` / `operator` / `expected_genesis_hash`
— publishing a `node_id` here is **not** a live or reachability claim, and does **not** move M4.

**Run 376 — admission-check before publishing.** Before adding a candidate to a seed list, run the
non-mutating `qbind-node identity register-check` verifier. It validates the `public-identity.json`
against the operator-identity schema rules, maps it into a `devnet-seed-list.schema.json` `seed_node`
candidate against a target seed list, verifies the NodeId deterministically from the leaf cert, and
**fails closed** on private-material embedding, malformed fields, wrong environment, MainNet/TestNet
material, mismatched cert, `status=live` without reachability evidence, and `planned`+reachability:

```bash
qbind-node identity register-check "$OUT/seed/public-identity.json" \
    --seed-list docs/release/public-devnet/network/devnet-seeds.placeholder.json \
    --role seed --cert "$OUT/seed/leaf.cert.bin"
```

It opens **no** socket, mutates **no** state, and makes **no** live/reachability/M4 claim. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`.

**Run 377 — live-admission gate + reachability preflight (Route B / Partial-positive).** To admit a
*live* candidate, `register-check` requires a reachability-evidence reference:

```bash
qbind-node identity register-check "$OUT/seed/public-identity.json" \
    --seed-list docs/release/public-devnet/network/devnet-seeds.live-candidate.json \
    --role seed --cert "$OUT/seed/leaf.cert.bin" \
    --status live --reachability-evidence \
    docs/release/public-devnet/network/reachability/RUN_377_qbind-devnet-seed-1.md
```

This **accepts** only with the evidence reference and **fails closed** without it (and for
`planned`+reachability). Run 377 also boots a real loopback `qbind-node` P2P listener and dials it
same-host, but **external reachability from outside the operator host/NAT was NOT proven**, so the
committed candidate stays `status: planned` and **M4 stays Yellow**. The gate is a structural admission
decision, **not** a reachability proof (`m4_green_claim=false`). See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_377.md` and
`docs/release/public-devnet/network/reachability/RUN_377_qbind-devnet-seed-1.md`.

## Provenance

Full provenance (git commit, branch, clean/dirty state, artifact paths + hashes, Run 356 genesis
hash + file SHA-256, commands, test results, security scan, readiness deltas) is recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_357.md`.