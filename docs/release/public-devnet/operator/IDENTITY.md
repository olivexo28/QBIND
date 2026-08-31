# QBIND Public DevNet — Operator Identity Guidance (Run 358)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**

This document explains the identity concepts an external DevNet operator encounters, which
repository-supported surfaces exist to configure or load identity material, what is safe to publish,
and what must never be published. Run 358 introduces **no** production / MainNet identity or custody
material and adds **no** CLI flag. Public DevNet is **NOT launch-ready** (see
`docs/release/public-devnet/operator/README.md` §6 and `SAFETY.md`).

## 1. Identity types

| Identity | What it is | Where it appears |
|----------|-----------|------------------|
| **Node identity** | The logical identity of a running `qbind-node` process within a deployment. On DevNet it is selected by an **index** into the genesis validator set, not minted by the node. | `--validator-id <index>` (`crates/qbind-node/src/cli.rs`); the validator set in `devnet-genesis.json`. |
| **Peer identity** | The transport-level identity a node presents to other peers over P2P (KEMTLS leaf certificate / trusted-root material). | `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-trusted-root`, `--p2p-peer-leaf-cert` (pre-existing P2P flags). Seed-list field: `peer_id`. |
| **Validator address** | The on-chain address of a validator entry in the genesis validator set (a public identifier). | `address` field in `devnet-genesis.json` validator entries; seed-list field `validator_address`. |
| **Validator signing identity** | The PQC signing key a validator uses to sign consensus messages (the **private** part is secret). | Signer surfaces: `--signer-mode`, `--signer-keystore-path`, `--remote-signer-url`, `--hsm-config-path`. |
| **PQC transport / trust-bundle material** | The signed PQC trust bundle and roots that gate P2P admission (public bundle + signing-key reference). | `--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`, `--p2p-pqc-root-mode`, `--p2p-trusted-root`. Seed-list field: `trust_bundle_required`. |

**Key distinction:** a **validator address** and **public** keys / fingerprints / peer-ids are public
identifiers. A **validator signing key** and any **trust-bundle signing key** have a **private**
component that is secret.

## 2. Existing CLI / config surfaces for identity

All surfaces below are **pre-existing** in `crates/qbind-node/src/cli.rs`; Run 358 adds none:

- **Node / validator selection:** `--validator-id <index>` selects a validator by its 0-based index
  in the genesis validator set.
- **Signer mode:** `--signer-mode` (e.g. `loopback-testing`, `encrypted-fs`, `remote-signer`,
  `hsm-pkcs11`), with `--signer-keystore-path` (encrypted-fs keystore directory),
  `--remote-signer-url` (remote signer service), and `--hsm-config-path` (HSM/PKCS#11 config).
- **Peer / transport identity:** `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-trusted-root`,
  `--p2p-peer-leaf-cert`, `--p2p-pqc-root-mode`.
- **Trust-bundle material:** `--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`.
- **Genesis authority material:** the genesis `authority` block (public fingerprint + public key hex)
  is documented in the Run 356 genesis package `README.md` §9.

## 3. Which identity material is safe to publish

- Validator **addresses** (public identifiers).
- **Public** keys, key fingerprints, and peer-ids intentionally published as public.
- The genesis `authority` block's **public** fingerprint / public-key hex (already published, Run 356).
- Non-routable **documentation-example** host values (e.g. RFC 5737 `192.0.2.1`) used in the seed-list
  placeholder.

## 4. Which material must NEVER be published

- Validator **signing** keys (private component) — private PQC signing keys.
- Trust-bundle **signing** keys (private component).
- Keystore contents, keystore passwords, or any secret referenced by `--signer-keystore-path`.
- Mnemonics, seed phrases, credentials, API keys, tokens.
- Private / internal infrastructure hostnames, real production hostnames, or unapproved live
  endpoints.

Nothing in this Run 358 package contains any of the above. The DevNet genesis validator/authority
material is fixture / dev-only **public** material with **no** value.

## 5. Guidance for placeholder / planned / live seed entries

- **placeholder** / **planned** / **retired** entries carry `null` `node_id` / `peer_id` /
  `validator_address` (no real identity is generated) and **must** have `last_reachability_evidence:
  null`. They are documentation shapes only and must **not** be dialed.
- **live** entries (future runs only) carry real, intentionally-**public** `node_id` / `peer_id` /
  `validator_address` and **must** carry `last_reachability_evidence`. Only these may be dialed. No
  secret material is ever placed in a seed entry.

## 6. Validators vs full nodes

- A **full node** does not need a validator signing identity; it can build, verify the genesis, and
  run locally (see `QUICKSTART.md` §6) without signer configuration.
- A **validator** additionally needs a validator signing identity via the signer surfaces in §2. On
  DevNet the validator set is a **fixture**; there is no live public validator set to register into.

## 7. No production / MainNet identity introduced

This run introduces **no** production or MainNet identity, custody, or signing material. It publishes
**no** private keys, mnemonics, seed phrases, credentials, tokens, or API keys, and creates **no**
MainNet or TestNet identity artifact. MainNet custody and MainNet authority rotation/revocation remain
**Red**; C4 and C5 remain **OPEN**.

## 8. Repository-supported commands to inspect identity material

- `./target/release/qbind-node --help` lists the identity/signer/peer flags above (validated in
  `VERIFY.md`).
- `./target/release/qbind-node --env devnet --genesis-path
  docs/release/public-devnet/genesis/devnet-genesis.json --print-genesis-hash` prints the canonical
  genesis hash; its provenance line reports the environment and authority context bound into the
  genesis (the genesis `authority` block is the published public authority material).

## 9. Identity generation for external operators (M6) — Run 374 package

**Run 374** publishes a stable, release-built operator-facing identity
**generation and verification** package under
`docs/release/public-devnet/identity/` (see its `README.md`,
`IDENTITY_GENERATION.md`, `IDENTITY_VERIFY.md`, `OPERATOR_IDENTITY_SCHEMA.json`,
`EXAMPLE_PUBLIC_IDENTITY.json`, `SAFETY.md`, `VERIFY.md`). It is backed by the
release-built example `run_374_public_devnet_identity_generation_helper` (Route B
— **no** production source change, **no** new `qbind-node` CLI flag) and the
harness `scripts/devnet/run_374_public_devnet_identity_generation.sh`. The helper
**generates** node / seed / validator-candidate identity material (root ML-DSA-44
signing key held in memory only; ML-KEM-768 leaf secret written `0600` to an
operator-selected temp path), emits a schema-validated public identity JSON,
deterministically re-derives the NodeId from the public cert, maps into the Run
357 seed-list, and is accepted by a real loopback `qbind-node` boot under
`--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root`. MainNet/TestNet
generation and mismatched material fail closed.

Because generation is delivered as a **release-built example helper** (the repo's
established operator-tooling pattern) rather than a first-class `qbind-node`
subcommand, and because **no live public DevNet exists to register an identity
into** (M4-gated), must-have **M6** is **materially narrowed but remains Yellow
(Partial)**. The remaining support needed to move M6 Green is: promoting the
helper to a stable first-class `qbind-node` subcommand (with operator-supplied
root reuse/rotation) plus a live registration path. See
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_374.md`.

### 9.1 Run 375 — first-class `qbind-node identity` command

**Run 375** promotes the Run 374 workflow into a stable, first-class
`qbind-node identity` subcommand (Route B — DevNet-gated, default-safe, no
runtime behavior change; it is only reached when `identity` is the first CLI
token):

```bash
qbind-node identity generate devnet full-node <outdir>
qbind-node identity generate devnet seed <outdir>
qbind-node identity generate devnet validator-candidate <outdir> [validator_index]
qbind-node identity verify <outdir>/leaf.cert.bin
qbind-node identity print-public <outdir>
qbind-node identity seed-candidate <outdir>
```

The command reuses the exact Run 374 primitives (the Run 374 example is now a
thin wrapper over the shared `crate::identity_cli` implementation), so all Run
374 evidence — file set, schema-compatible `public-identity.json`, `0600` KEM
secret key, in-memory-only root signing key, deterministic NodeId, seed-list
mapping, loopback strict-auth boot, mismatch fail-closed, MainNet/TestNet
refusal — is preserved and reproducible. Evidence:
`scripts/devnet/run_375_public_devnet_identity_cli.sh`,
`crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`, and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`.

**M6 delta (Run 375):** the first-class **generation + verification** half of M6
is now **Green-for-scope** (stable command, documented, release-binary-evidenced,
schema-compatible, safe for external DevNet operators). M6 as a whole **remains
Yellow (Partial)** because a **live registration path** into a running public
DevNet does not exist (M4-gated) and operator-supplied root reuse/rotation/
revocation is still C4/C5-OPEN. No M4 Green, no C4/C5 closure is claimed.

### 9.2 Run 376 — non-mutating `identity register-check` admission boundary

**Run 376** adds a **non-mutating** admission verifier that decides whether a
generated public identity is admissible as a future seed-list entry:

```bash
qbind-node identity register-check <outdir>/public-identity.json \
    --seed-list docs/release/public-devnet/network/devnet-seeds.placeholder.json \
    [--role full-node|seed|validator-candidate] [--cert <outdir>/leaf.cert.bin] \
    [--status planned|live] [--reachability-evidence <ref>]
```

It reads **public material only**, validates `public-identity.json` against the
operator-identity schema rules, maps it into a `devnet-seed-list.schema.json`
`seed_node` candidate (`status=planned`, `expected_genesis_hash` from the target
seed list, `last_reachability_evidence=null`), verifies the NodeId
deterministically from the leaf cert when supplied, and **fails closed** on
private-material embedding, malformed fields, wrong environment, MainNet/TestNet
material, mismatched cert, `status=live` without reachability evidence, and
`planned`+reachability. It opens **no** socket, mutates **no** runtime state, and
makes **no** live / reachability / M4 / C4 / C5 claim. Evidence:
`scripts/devnet/run_376_public_devnet_identity_registration.sh`,
`crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs`,
and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`.

**M6 delta (Run 376):** the **registration / admission-check** half of M6 is now
**Green-for-scope** (a stable generate → verify → register-check workflow exists
for external operators). M6 as a whole **remains Yellow (Partial)** because the
*live* registration half is inseparable from M4 live seed reachability, which has
not landed. No M4 Green, no C4/C5 closure is claimed.

### 9.3 Run 377 — live-admission gate + reachability preflight (Route B / Partial-positive)

**Run 377** exercises the *live* branch of `register-check`:
`register-check … --status live --reachability-evidence <ref>` **accepts** a
cert-verified live candidate only when a reachability-evidence reference is
supplied, and **fails closed** without it (and for `planned`+reachability). Run
377 also boots a real loopback `qbind-node` P2P listener and dials it same-host,
proving the deployed listener path is reachable over loopback. **External
reachability from outside the seed operator's own host/NAT was NOT proven**, so
the committed candidate
(`docs/release/public-devnet/network/devnet-seeds.live-candidate.json`) stays
`status: planned` with null reachability and **M4 stays Yellow**. The admission
gate is a structural decision, not a reachability proof
(`m4_green_claim=false`, `live_reachability_claim=false`). Canonical record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_377.md`;
`docs/release/public-devnet/network/reachability/RUN_377_qbind-devnet-seed-1.md`.
## 10. Security: key-management + PQC trust bootstrap (Run 389)

**Run 389** publishes the consolidated public DevNet **security** package under
`docs/release/public-devnet/security/`, which extends this identity guidance with:

- `KEY_MANAGEMENT.md` (**M7**) — the full key inventory (node/KEMTLS leaf key,
  transport trust root, consensus/block signer key, trust-bundle signing key,
  operator identity JSON) with public-vs-private marking, local signer-mode
  guidance (`--signer-mode` loopback-testing / encrypted-fs / remote-signer /
  hsm-pkcs11), remote-signer/HSM posture, private-key `0600` permissions,
  rotation/revocation status, backup guidance, and an explicit refusal of
  MainNet custody claims.
- `PQC_TRUST_BOOTSTRAP.md` (**M8**) — the DevNet PQC trust-bundle bootstrap flow
  (`--p2p-trust-bundle` / `--p2p-trust-bundle-signing-key`, genesis pinning,
  validation-only reload-check, no peer-driven live apply).
- `PQC_ROOT_AND_SIGNING_KEYS.md` (**M9**) — generating and verifying DevNet
  root/leaf/signing-key material and which files are public vs private.

The package is verified against the real CLI/helper surfaces (see
`docs/release/public-devnet/security/VERIFY.md` and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md`). It adds **no** CLI flag, applies
**no** live trust, and makes **no** M4/M6-Green or C4/C5-closure claim.
