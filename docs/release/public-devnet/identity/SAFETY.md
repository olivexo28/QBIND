# QBIND Public DevNet — Identity Safety (Run 374)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.

This document states what identity material is safe to publish, what must
**never** be published, and the DevNet-only handling rules for the Run 374
identity package.

## 1. Safe to publish (public material)

- `node_id` / `node_id_short` and `peer_id` (derived from the certified leaf
  ML-KEM-768 public key).
- `leaf_cert_fingerprint` / `leaf_cert_fingerprint_short`.
- `root_key_id` and the root **public** key (`root.pk.hex`) and its fingerprint.
- `trusted_root_spec` (the `--p2p-trusted-root` value — root id + suite + root
  **public** key only).
- The leaf `NetworkDelegationCert` (`leaf.cert.bin`) — public transport material.
- `validator_address` for a validator-candidate (the public DevNet fixture label
  `qbind-val-<index>`).
- The whole `public-identity.json` document (it contains only the above).

## 2. Must NEVER be published or committed (secret material)

- The **ML-KEM-768 secret key** (`leaf.kem.sk.bin`) — the peer's private KEM key.
- The **root ML-DSA-44 signing key** — never written to disk by the helper; it is
  held in memory for the single run and dropped.
- Any **validator signing** key (ML-DSA signing secret) or **trust-bundle
  signing** key.
- Mnemonics, seed phrases, keystore passwords, private config tokens, API keys,
  or credentials.
- Private / internal infrastructure hostnames, real production hostnames, or
  unapproved live endpoints.

`public-identity.json` records the **paths** of private files (for operator
convenience) but never their contents.

## 3. DevNet-only / no-value / resettable

- All generated material is **DevNet-only, experimental, resettable, and carries
  no value**. A DevNet can be reset at any time; regenerate identities freely.
- The helper **refuses** to generate under `mainnet` or `testnet` (non-zero exit,
  no material written). It creates **no** MainNet or TestNet custody.
- Helper-generated material is **not production custody**. A production CA /
  custody / KMS/HSM flow is out of scope and tracked under **C4/C5**
  (`docs/whitepaper/contradiction.md`,
  `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`).

## 4. Handling rules

- Generate into an operator-selected path **outside any git tree** (e.g.
  `mktemp -d`). Do not place generated material under the repository.
- The KEM secret key is written with `0600` perms (Unix). Keep it readable only
  by the node process; never log it or copy it into a seed list, issue, or PR.
- As a backstop, the repository `.gitignore` ignores `*.kem.sk.bin`, `*.cert.bin`,
  `*.kem.pk.bin`, and a conventional `qbind-identity-out/` output directory. This
  is a safety net, **not** a licence to generate inside the repo tree.

## 5. Rotation / revocation limitations

- This package provides **generation and verification only**. It does **not**
  provide production key **rotation** or **revocation**: there is no CA lifecycle,
  no revocation-list publication flow, and no live trust-state mutation here.
- To "rotate" a DevNet identity you simply generate a new one and update the
  (non-live) seed-list candidate entry; there is no online revocation of a
  previously published DevNet `node_id`.
- Production rotation/revocation and authority lifecycle remain **C4/C5 OPEN** and
  MainNet authority rotation/revocation remains **Red**. See
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` and
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

## 6. What this package does NOT claim

- It is **not** a public DevNet launch, and publishes **no** live seed/bootnode.
- It does **not** move **M4** to Green (no live reachability evidence).
- It does **not** close **C4** or **C5**, create MainNet custody, or make any
  TestNet/MainNet readiness claim.
- It changes **no** P2P wire format, weakens **no** peer admission (strict
  mutual-auth only tightens it), and mutates **no** trust/validator/epoch state.