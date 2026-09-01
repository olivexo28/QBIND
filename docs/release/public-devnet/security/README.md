# QBIND Public DevNet — Security: Key-Management & PQC Trust Bootstrap (Run 389)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only**, **docs / verification-only** package. It deploys **no** seed node,
> bootnode, faucet, RPC gateway, explorer, or status page, and adds **no** CLI flag. Public DevNet is
> **NOT launch-ready** (see `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`). Nothing here is
> a public DevNet launch claim, a public TestNet readiness claim, or a MainNet readiness claim. **C4
> and C5 remain OPEN.**

This directory publishes the canonical **public DevNet security operator** material for
key-management and PQC trust-root bootstrap, produced under **Run 389**. It consolidates the guidance
a DevNet operator needs to (a) understand which keys exist and which are public vs private, (b)
bootstrap a DevNet PQC transport trust bundle, and (c) generate / verify DevNet PQC root and
signing-key material — all against the **existing** `qbind-node` CLI surfaces and the existing DevNet
helper examples, with **no** production source change and **no** invented flag.

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This document (index, scope, cross-links, readiness statement). |
| `KEY_MANAGEMENT.md` | **M7** — validator/node key-management guidance: which keys exist, local signer modes, remote-signer / HSM posture, file permissions, rotation/revocation status, backup, and refusal of MainNet custody. |
| `PQC_TRUST_BOOTSTRAP.md` | **M8** — DevNet PQC trust-bundle bootstrap flow: genesis pinning, transport roots vs bundle-signing keys, `--p2p-trust-bundle` loading, reload-check/apply/SIGHUP surfaces, and no-peer-driven-apply / no-fallback-root guarantees. |
| `PQC_ROOT_AND_SIGNING_KEYS.md` | **M9** — DevNet PQC root/leaf/signing-key generation & verification: which files are public vs private, fingerprint/NodeId derivation, static-root pinning, bundle-signature verification, and wrong-chain/env/genesis detection. |
| `SAFETY.md` | User-facing safety label / disclaimer publication for this package. |
| `VERIFY.md` | Exact copy-paste operator verification checks and expected outputs. |

## Canonical location

This is the canonical location for public DevNet **security** operator material. It sits alongside
the operator onboarding package (`docs/release/public-devnet/operator/`), the identity
generation/verification package (`docs/release/public-devnet/identity/`), and the P2P posture package
(`docs/release/public-devnet/p2p/`) under the shared `docs/release/public-devnet/` tree.

## Reading order

1. `SAFETY.md` — understand the experimental / resettable / no-value / no-custody posture first.
2. `KEY_MANAGEMENT.md` — what keys exist, what is public vs private, signer modes, permissions.
3. `PQC_ROOT_AND_SIGNING_KEYS.md` — generate & verify DevNet root/leaf/signing-key material.
4. `PQC_TRUST_BOOTSTRAP.md` — bootstrap and validate a DevNet PQC trust bundle.
5. `VERIFY.md` — reproduce every CLI-surface and fail-closed check.

## Cross-links

- Operator onboarding — `docs/release/public-devnet/operator/` (`README.md`, `QUICKSTART.md`,
  `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`).
- Identity generation/verification — `docs/release/public-devnet/identity/`
  (`IDENTITY_GENERATION.md`, `IDENTITY_VERIFY.md`, `OPERATOR_IDENTITY_SCHEMA.json`).
- P2P posture / admission — `docs/release/public-devnet/p2p/` (`PEER_ADMISSION_POLICY.md`,
  `P2P_PORT_POSTURE.md`, `VERIFY.md`).
- PQC trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.
- Ops (reset policy + incident response) — `docs/release/public-devnet/ops/` (`RESET_POLICY.md`,
  `INCIDENT_RESPONSE.md`; a suspected key/trust-root compromise is an incident class and a reset
  trigger).
- Trust-anchor authority model — `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
- C4/C5 closure criteria — `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`.

## Readiness track relationship

This package targets public DevNet readiness must-haves **M7** (key-management guidance), **M8** (PQC
trust-bundle bootstrap), and **M9** (PQC root/signing-key guidance), tracked in
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. Run 389 publishes and verifies this guidance
against the real CLI/helper surfaces (see `VERIFY.md` and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md`). It does **not** move **M4** (Yellow / launch-blocking)
or **M6** (Yellow / Partial), and it does **not** close **C4** or **C5** — both remain **OPEN**.
Because at least one must-have (M4) is not Green, public DevNet is **not** launch-ready.

## Provenance

Full provenance (git commit, artifact paths + hashes, release-binary SHA-256 / BuildID / toolchain,
CLI/help verification, identity generation/verification evidence, trust-bundle bootstrap evidence,
fail-closed evidence, tests, security scan, readiness deltas) is recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md`.