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

## 9. Honest gap — identity generation for external operators (M6)

There is currently **no** externally documented, stable `qbind-node` command that **generates** a
fresh public validator / node / peer identity for an external operator to register on a live public
DevNet. Key generation exists internally (e.g. within test/fixture helpers and the signer subsystem),
but it is **not** exposed as a stable, operator-facing "generate my identity" CLI command, and no live
public DevNet exists to register such an identity into.

Because identity **loading / selection / signer configuration** is validated against real
pre-existing CLI surfaces, but identity **generation** for external operators is **not** yet exposed
as a stable operator-facing command, must-have **M6** remains **Yellow (Partial)**. The exact missing
support is: a stable, documented CLI command (or documented procedure over a stable command) for an
external operator to generate a publishable node/peer/validator identity, plus a live registration
path. See `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.