# QBIND Public DevNet — Operator Identity Package (Run 374, first-class command Run 375)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.**

> **Run 375 — first-class command.** The identity-generation and verification
> workflow described in this package is now available as a stable, first-class
> `qbind-node identity` subcommand (no example build required):
>
> ```bash
> qbind-node identity generate devnet full-node <outdir>
> qbind-node identity generate devnet seed <outdir>
> qbind-node identity generate devnet validator-candidate <outdir> [validator_index]
> qbind-node identity verify <outdir>/leaf.cert.bin
> qbind-node identity print-public <outdir>
> qbind-node identity seed-candidate <outdir>
> ```
>
> The command emits the **same** files, the **same** schema-compatible
> `public-identity.json`, the **same** `0600` KEM secret key, the same
> in-memory-only root signing key, and the same MainNet/TestNet refusals as the
> Run 374 helper (which is now a thin wrapper over the shared implementation).
> It changes **no** default node behavior: it is only reached when `identity` is
> the first CLI token. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`.

> **Run 376 — registration / admission-check.** A **non-mutating**
> `qbind-node identity register-check` subcommand now decides whether a
> generated public identity is admissible as a future DevNet seed-list entry:
>
> ```bash
> qbind-node identity register-check <outdir>/public-identity.json \
>     --seed-list docs/release/public-devnet/network/devnet-seeds.placeholder.json \
>     [--role full-node|seed|validator-candidate] [--cert <outdir>/leaf.cert.bin] \
>     [--status planned|live] [--reachability-evidence <ref>]
> ```
>
> It reads **public material only**, validates `public-identity.json` against the
> operator-identity schema rules, maps it into a `devnet-seed-list.schema.json`
> `seed_node` candidate, verifies the NodeId deterministically from the leaf cert,
> and **fails closed** on private-material embedding, malformed fields, wrong
> environment, MainNet/TestNet material, mismatched cert, `status=live` without
> reachability evidence, and `planned`+reachability. It opens **no** socket,
> mutates **no** runtime state, and makes **no** live / reachability / M4 / C4 / C5
> claim. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`.

> **Run 401 — operator identity continuity / rotation-revocation deferral.**
> `IDENTITY_CONTINUITY.md` documents how an operator keeps a **durable operator
> identity** across public DevNet restarts (reuse the same `leaf.kem.sk.bin` +
> `leaf.cert.bin` to preserve `node_id`/`peer_id`), what public/private material
> is involved, exactly what **may be reused** between restarts, and what **must
> not be rotated by hand**. `ROTATION_REVOCATION_DEFERRAL.md` states that
> production rotation/revocation is **NOT implemented** and is **explicitly
> deferred** to C4/C5/MainNet work. Both are **docs only** (no CLI flag, no source
> change, no live apply) and verified against the existing `qbind-node identity`
> surfaces by `scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh`.
> **M6 stays Yellow / Partial** (better documented); **M4** stays Yellow; **C4/C5**
> remain **OPEN**. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md`.

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
| `IDENTITY_CONTINUITY.md` | How to keep a durable operator identity across DevNet restarts: public/private material, what may be reused, what must not be rotated by hand (Run 401). |
| `ROTATION_REVOCATION_DEFERRAL.md` | Statement that production rotation/revocation is NOT implemented and is explicitly deferred to C4/C5/MainNet (Run 401). |
| `VERIFY.md` | Copy-paste verification steps a reviewer runs to confirm the package. |

## Tooling

- **First-class command (Run 375, preferred):** `qbind-node identity`
  (`generate` / `verify` / `print-public` / `seed-candidate` / `register-check`),
  implemented in `crates/qbind-node/src/identity_cli.rs`. Evidence:
  `scripts/devnet/run_375_public_devnet_identity_cli.sh` /
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`; registration/admission-check
  (Run 376): `scripts/devnet/run_376_public_devnet_identity_registration.sh` /
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`.
- **Generator / verifier (release-built example, now a thin wrapper over the
  first-class command):**
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