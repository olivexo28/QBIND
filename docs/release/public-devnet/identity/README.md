# QBIND Public DevNet — Operator Identity Package (Run 374)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.**

This directory is the canonical, operator-facing **identity-generation and
verification** package for the QBIND public DevNet. It lets an external DevNet
operator **generate, inspect, verify, and safely handle** the identity material a
`qbind-node` peer needs to join a KEMTLS strict-auth
(`PqcRootMode::PqcStaticRoot`) DevNet, and shows how that material maps to the
Run 357 seed-list and the pre-existing P2P flags.

It closes the **generation** half of the M6 gap that
`docs/release/public-devnet/operator/IDENTITY.md` §9 documented (loading /
selection were already CLI-validated; a repeatable generation command was
missing). See "Readiness status" below for the exact matrix delta.

## Contents

| File | Purpose |
|------|---------|
| `README.md` | This overview + index. |
| `IDENTITY_GENERATION.md` | Exact commands to generate node / seed / validator-candidate identity material and what each output is. |
| `IDENTITY_VERIFY.md` | Exact commands to print / verify / re-derive public identity, validate against schema, and map to the seed-list. |
| `OPERATOR_IDENTITY_SCHEMA.json` | JSON Schema (draft-07) for the public identity document emitted by the helper. |
| `EXAMPLE_PUBLIC_IDENTITY.json` | A public-only example identity document (placeholder values) that validates against the schema. |
| `SAFETY.md` | What is safe to publish, what must never be published, rotation/revocation limits, DevNet-only labelling. |
| `VERIFY.md` | Copy-paste verification steps a reviewer runs to confirm the package. |

## Tooling

- **Generator / verifier (release-built example, not a production runtime path):**
  `crates/qbind-node/examples/run_374_public_devnet_identity_generation_helper.rs`
- **Evidence harness:**
  `scripts/devnet/run_374_public_devnet_identity_generation.sh`
- **Evidence record:**
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_374.md`

The helper consolidates the pre-existing DevNet identity primitives
(`mint_devnet_root` + ML-KEM-768 leaf keygen + `issue_leaf_delegation_cert` +
`derive_node_id_from_pubkey` + `leaf_cert_fingerprint`) into a single documented
command. It adds **no** production source change and **no** new `qbind-node` CLI
flag. The peer identity it produces is consumed by the **pre-existing** public
flags `--p2p-trusted-root`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`,
`--validator-id`, and `--p2p-peer` / `--p2p-peer-leaf-cert`.

## Identity types covered

| Identity | Public value(s) | Private value(s) |
|----------|-----------------|------------------|
| **Node identity** | `node_id` (sha3-256 of the certified leaf ML-KEM-768 public key) | — |
| **Peer identity** | `peer_id` (= `node_id` for the KEMTLS transport identity), leaf cert, `leaf_cert_fingerprint` | ML-KEM-768 secret key (`leaf.kem.sk.bin`) |
| **Trust-root / root authority identity** | `root_key_id`, root public key, `root_pk_fingerprint`, `trusted_root_spec` | root ML-DSA-44 **signing** key (never written to disk) |
| **KEMTLS leaf identity** | leaf `NetworkDelegationCert` (`leaf.cert.bin`) | ML-KEM-768 secret key |
| **Validator candidate identity** | `validator_address` (DevNet fixture label `qbind-val-<index>`) | validator consensus signing key (out of scope of this helper; see `IDENTITY.md` §2) |
| **Seed-list identity fields** | `node_id`, `peer_id`, `validator_address`, `pqc_suite`, `transport_security_mode` | — |

## Readiness status

- **M6 (validator/node identity generation):** **Yellow / Partial → materially
  narrowed, remains Yellow / Partial.** A stable, repeatable, release-built
  operator-facing identity **generation + verification** package now exists with a
  schema, exact commands, safety guidance, and cross-checked evidence (including a
  real loopback strict-auth boot of `qbind-node` on the generated material). It is
  intentionally kept **Yellow / Partial** because generation is delivered as a
  **release-built example helper** (the repo's established operator-tooling
  pattern) rather than a first-class `qbind-node` subcommand, and because **no
  live public DevNet exists to register an identity into** (that registration path
  is gated on M4). See
  `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.
- **M4 (seed / bootnodes):** unchanged **Yellow / launch-blocking**. This package
  does **not** publish live seeds or reachability evidence.
- **Public DevNet:** remains **NOT launch-ready**.
- **C4 / C5:** remain **OPEN**. This package creates **no** MainNet custody and is
  **not** a C5 closure. Helper-generated material is **not** production custody.