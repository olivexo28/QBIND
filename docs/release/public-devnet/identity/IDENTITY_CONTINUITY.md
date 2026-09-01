# QBIND Public DevNet — Operator Identity Continuity (Run 401)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.

This document explains how an external DevNet operator keeps a **durable
operator identity** across public DevNet restarts, what public/private material
is involved, exactly **what may be reused** between restarts, and **what must
not be rotated by hand**. It is **operational guidance only**: it introduces
**no** new `qbind-node` CLI flag, **no** production source change, **no** key
rotation/revocation mechanism, and **no** live trust/authority mutation. Manual
rotation and revocation are covered — and explicitly **deferred** — in
`ROTATION_REVOCATION_DEFERRAL.md`.

All commands referenced here are the **pre-existing** first-class
`qbind-node identity` surfaces (Run 375/376): `generate`, `verify`,
`print-public`, `seed-candidate`, and the non-mutating `register-check`. See
`README.md`, `IDENTITY_GENERATION.md`, `IDENTITY_VERIFY.md`, and
`docs/release/public-devnet/operator/IDENTITY.md`.

## 1. What "durable operator identity" means on DevNet

A DevNet operator's identity is a small set of **files** generated once by
`qbind-node identity generate devnet <role> <outdir>` and then **reused** by the
node process on every start:

| File | Kind | Reused between restarts? | Notes |
|------|------|--------------------------|-------|
| `leaf.kem.sk.bin` | **private** (ML-KEM-768 secret key, `0600`) | **Yes** — keep the same file | The peer's durable KEMTLS secret. Losing it forces regeneration → a **new** `node_id`/`peer_id`. |
| `leaf.cert.bin` | public (KEMTLS leaf `NetworkDelegationCert`) | **Yes** | Loaded via `--p2p-leaf-cert`. |
| `root.pk.hex` / `trusted_root_spec` | public (root ML-DSA-44 **public** key + `--p2p-trusted-root` spec) | **Yes** | The trust anchor the leaf certifies against. |
| `public-identity.json` | public (identity summary; records private **paths** only) | **Yes** (informational) | Byte-compatible with the schema; safe to publish. |
| root ML-DSA-44 **signing** key | **private**, in-memory only | **No** — never written to disk by the tool | Held in memory for the single `generate` run and dropped; see §5. |

The **durable, reusable identity** an operator preserves across restarts is the
`(leaf.kem.sk.bin, leaf.cert.bin, trusted_root_spec/root.pk.hex)` triple. As long
as the operator keeps the **same** `leaf.kem.sk.bin` and `leaf.cert.bin`, the
node presents the **same** `node_id` / `peer_id` (the SHA3-256 of the certified
leaf ML-KEM-768 public key) after any restart. This is what makes an operator's
seed-list entry stable across DevNet process restarts.

`node_id` / `peer_id` determinism is verifiable **offline** with the existing
tooling:

```bash
qbind-node identity print-public <outdir>            # prints the stored node_id
qbind-node identity verify <outdir>/leaf.cert.bin    # re-derives node_id from the public cert
```

If the two `node_id` values match, the identity is intact and reusable; if
`verify` cannot re-derive the same `node_id`, the certified material has changed
and the entry must be re-verified before reuse.

## 2. Safe public/private material handling

- **Public material — safe to publish / commit into a seed-list entry:**
  `node_id`, `peer_id`, `leaf_cert_fingerprint`, `root_key_id`, the root
  **public** key (`root.pk.hex`) and its fingerprint, `trusted_root_spec`, the
  leaf `NetworkDelegationCert` (`leaf.cert.bin`), `validator_address`, and the
  whole `public-identity.json` document (it contains only the above).
- **Private material — must NEVER be published, committed, logged, or copied
  into a seed list / issue / PR:** `leaf.kem.sk.bin` (the ML-KEM-768 secret key),
  the root ML-DSA-44 **signing** key, any validator or trust-bundle signing key,
  and any mnemonic / seed phrase / keystore password / API token.
- **Storage:** generate into an operator-selected path **outside any git tree**
  (e.g. `mktemp -d`), keep `leaf.kem.sk.bin` `0600`, and back it up like any
  other private key (see `docs/release/public-devnet/recovery/BACKUP_RESTORE.md`
  and `docs/release/public-devnet/security/KEY_MANAGEMENT.md`). The repository
  `.gitignore` ignores `*.kem.sk.bin` / `*.cert.bin` as a backstop only — not a
  licence to generate inside the repo tree.

`register-check` is an additional guard: it reads **public material only** and
**fails closed** if a `public-identity.json` embeds any private indicator
(`secret_key`, `private_key`, `mnemonic`, `seed_phrase`, PEM `-----begin`). Run
it before treating any published identity as a candidate seed entry.

## 3. What operators MAY reuse between DevNet restarts

Provided the DevNet **genesis has not been reset** (same
`expected_genesis_hash`), an operator may reuse, unchanged, across restarts:

- the **same `leaf.kem.sk.bin`** (durable KEMTLS secret) and the **same
  `leaf.cert.bin`** — this preserves the `node_id` / `peer_id`;
- the **same `trusted_root_spec` / `root.pk.hex`** (`--p2p-trusted-root`);
- the **same `validator_address`** (`qbind-val-<index>`) and `--validator-id
  <index>` selection;
- the **same `public-identity.json`** and the **same** `status: planned`
  seed-list candidate entry produced by `qbind-node identity seed-candidate` and
  admitted by `register-check`.

Reuse is verified, not asserted: after a restart, re-run
`qbind-node identity verify <outdir>/leaf.cert.bin` and confirm the `node_id`
still matches the published seed-list entry, and confirm the node's genesis pin
(`--expect-genesis-hash`) still matches the DevNet genesis.

## 4. What must NOT be rotated or edited by hand

- **Do not hand-edit** `leaf.cert.bin`, `leaf.kem.sk.bin`, `root.pk.hex`,
  `public-identity.json`, or a committed seed-list entry. To change identity
  material you **regenerate** with `qbind-node identity generate …`; there is no
  supported in-place edit.
- **Do not manually "rotate"** a live `node_id` / `peer_id` mid-DevNet. On DevNet,
  "rotation" is simply generating a **new** identity and publishing a **new**
  `status: planned` candidate; there is **no** online revocation of a previously
  published DevNet `node_id`. See `ROTATION_REVOCATION_DEFERRAL.md`.
- **Do not hand-edit trust / authority / validator / epoch / sequence / marker
  state** to force continuity. Those surfaces are not part of operator identity
  reuse and are governed by
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` and
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`. The only offline authority
  ceremony that exists (`--authority-state-reset`, Run 127) is a hidden,
  offline, genesis-derived marker ceremony that implies **no** live governance or
  C4/C5 closure (see `docs/release/public-devnet/ops/RESET_POLICY.md`).

## 5. Root signing key and continuity (honest limitation)

The `qbind-node identity generate` tool mints a **fresh** root ML-DSA-44 signing
key **in memory only** for each run and never writes it to disk, so a durable,
operator-supplied **root** that is reused (or rotated) across generations is **not**
provided by this tooling. In practice DevNet continuity is anchored on the
**leaf** material (`leaf.kem.sk.bin` + `leaf.cert.bin`) plus the published root
**public** key, which is sufficient to preserve `node_id` / `peer_id` across
restarts. Operator-supplied durable **root** reuse/rotation (a production CA /
custody / KMS/HSM lifecycle) is out of scope here and is tracked under **C4/C5**;
see `ROTATION_REVOCATION_DEFERRAL.md`,
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and
`docs/whitepaper/contradiction.md`.

## 6. What this document does NOT claim

- It is **not** a public DevNet launch and publishes **no** live seed/bootnode;
  it does **not** move **M4** to Green (no external reachability evidence).
- It does **not** move **M6** to Green: no live public DevNet exists to register a
  continuous identity into (M4-gated), and operator-supplied root
  reuse/rotation/revocation remains **C4/C5 OPEN**. M6 stays **Yellow / Partial**.
- It provides **no** production key **rotation** or **revocation** and closes
  **neither C4 nor C5**; it makes **no** TestNet or MainNet readiness claim.
- It changes **no** P2P wire format, weakens **no** peer admission, and mutates
  **no** trust / validator / epoch / sequence / marker state.
