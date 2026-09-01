# QBIND Public DevNet — Security Package Safety (Run 389)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document states the DevNet-only safety posture for the Run 389 security package
(`docs/release/public-devnet/security/`). It restates, for the key-management and PQC trust-bootstrap
guidance, what is safe to publish, what must **never** be published, and what this package does **not**
claim.

## 1. Safe to publish (public material)

- Validator/node **addresses**, `node_id` / `peer_id`, and public key **fingerprints**.
- ML-DSA-44 **root public** keys and ids (`root.pk.hex`, `root.id.hex`, `trusted-root.spec`).
- Trust-bundle **signing verification** keys (`signing-key.pk.hex`, `signing-key.id.hex`,
  `signing-key.spec` — the `--p2p-trust-bundle-signing-key` value).
- Leaf `NetworkDelegationCert`s (`leaf.cert.bin` / `v<N>.cert.bin`) and the trust bundle document
  (`trust-bundle.json`).
- The whole `public-identity.json` document (it records private-file **paths** only, never contents).

## 2. Must NEVER be published or committed (secret material)

- The **ML-KEM-768 secret key** (`leaf.kem.sk.bin` / `v<N>.kem.sk.bin`) — mode `0600`.
- The **transport root ML-DSA-44 signing key** — never written to disk (in memory only).
- The **trust-bundle ML-DSA-44 signing secret key** — never written to disk (only the public
  verification key is emitted).
- Any **validator consensus signing** key, `encrypted-fs` **keystore** contents, keystore passwords,
  or HSM secrets.
- Mnemonics, seed phrases, credentials, API keys, tokens.
- Private / internal infrastructure hostnames, real production hostnames, unapproved live endpoints,
  raw logs, raw metrics dumps, data dirs, or absolute build paths.

## 3. DevNet-only / no-value / resettable / no custody

- All keys and trust material here protect an **experimental, resettable, no-value** network. None is
  production custody.
- The identity command **refuses** `mainnet` / `testnet` generation (non-zero exit; no material
  written), and the trust-bundle helper is DevNet-only. MainNet/TestNet enforce stricter policy that
  DevNet conveniences do **not** weaken.
- The transport root / bundle-signing **signing secrets are generated in memory only** — there is no
  key ceremony, no CA lifecycle, and no KMS/HSM production custody here.

## 4. Handling rules

- Generate all material into an operator-selected path **outside any git tree** (e.g. `mktemp -d`);
  never place secret material under the repository.
- Keep every `*.kem.sk.bin` at `0600` and every keystore/HSM config directory at `0700`, readable by
  the `qbind-node` user only. Never log, paste, or commit a secret key.
- As a backstop, the repository `.gitignore` ignores `*.kem.sk.bin` / `*.cert.bin`, and the Run 389
  archive directory carries its own `.gitignore` over the per-run `material/` output.

## 5. Rotation / revocation limitations

- This package provides **guidance + verification only**. It performs **no** live trust apply, **no**
  production key rotation, and **no** online revocation. On DevNet you "rotate" by regenerating fresh
  material and re-pinning it locally.
- Production rotation/revocation and authority lifecycle remain **C4/C5 OPEN**, and MainNet authority
  rotation/revocation remains **Red** (`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`).

## 6. What this package does NOT claim

- It is **not** a public DevNet launch and deploys **no** live seed/bootnode/faucet/RPC/explorer/status
  page.
- It does **not** move **M4** to Green (no live reachability evidence) and does **not** move **M6** to
  fully Green (no live registration path).
- It does **not** close **C4** or **C5**, create MainNet custody, or make any TestNet/MainNet readiness
  claim.
- It changes **no** P2P wire format, weakens **no** peer admission (strict mutual-auth only tightens
  it), enables **no** peer-driven apply, and mutates **no** trust/validator/epoch/sequence state.