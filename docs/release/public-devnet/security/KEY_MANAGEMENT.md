# QBIND Public DevNet — Key Management (M7) (Run 389)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document is the consolidated **key-management guidance** for a public DevNet operator. It uses
**only** the pre-existing `qbind-node` CLI surfaces (`crates/qbind-node/src/cli.rs`) and the existing
DevNet identity command (`qbind-node identity …`, `crates/qbind-node/src/identity_cli.rs`). Run 389
adds **no** CLI flag and changes **no** default behaviour. Every flag named here is validated to
appear in `qbind-node --help` (see `VERIFY.md`).

## 1. DevNet-only safety label

Everything below is **DevNet-only** operational guidance. DevNet keys protect an **experimental,
resettable, no-value** network. **No key described here is production custody**, and none secures any
asset with monetary value. MainNet custody, MainNet authority rotation/revocation, and any
value-bearing signing flow are **out of scope** and remain **Red**; **C4 and C5 remain OPEN**
(`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`).

## 2. What keys exist

| Key / material | Public or private | Where it lives | Consumed by |
|----------------|-------------------|----------------|-------------|
| **Node / KEMTLS leaf key** (ML-KEM-768 secret) | **PRIVATE** | `leaf.kem.sk.bin` (mode `0600`) | `--p2p-leaf-cert-key` |
| **KEMTLS leaf certificate** (`NetworkDelegationCert`) | public transport material | `leaf.cert.bin` | `--p2p-leaf-cert`, `--p2p-peer-leaf-cert <vid>:<path>` |
| **Transport trust root** (ML-DSA-44 root public key + id) | **public** | `root.id.hex`, `root.pk.hex`, `trusted-root.spec` | `--p2p-trusted-root`, `--p2p-pqc-root-mode` |
| **Transport root signing key** (ML-DSA-44 secret) | **PRIVATE** | held **in memory only** — never written to disk by DevNet helpers | root/leaf issuance (offline) |
| **Consensus / block signer key** (validator signing key, private) | **PRIVATE** | signer-mode-dependent (in-memory / encrypted-fs keystore / remote signer / HSM) | `--signer-mode` + mode-specific flag |
| **Trust-bundle signing key** (ML-DSA-44 secret) | **PRIVATE** | held **in memory only** by the DevNet helper; only the **public** verification key is emitted | bundle signing (offline) |
| **Trust-bundle signing verification key** (public) | **public** | `signing-key.id.hex`, `signing-key.pk.hex`, `signing-key.spec` | `--p2p-trust-bundle-signing-key` |
| **Operator identity JSON** | **public** | `public-identity.json` (records private-key **paths** only, never contents) | published / seed-list mapping |

**Public vs private, in one line:** validator/node **addresses**, **public** keys, **fingerprints**,
**node/peer ids**, **root public keys**, **bundle-signing verification keys**, and the operator
**public-identity JSON** are public identifiers. The **KEM leaf secret**, the **transport root
signing key**, the **consensus signing key**, and the **trust-bundle signing key** are secret and
**must never be published or committed**.

See `PQC_ROOT_AND_SIGNING_KEYS.md` for exactly how each file is generated and `IDENTITY.md`
(operator) for the identity concepts.

## 3. Local signer mode guidance (existing CLI only)

The validator consensus signing key is selected with the pre-existing `--signer-mode` flag and its
mode-specific companions:

| `--signer-mode` | Companion flag | Posture |
|-----------------|----------------|---------|
| `loopback-testing` | *(none)* | In-memory keys for **DevNet/testing only**. **Forbidden on MainNet** by the MainNet profile. Convenient for local DevNet bring-up; provides no at-rest protection. |
| `encrypted-fs` | `--signer-keystore-path <dir>` | Encrypted filesystem keystore (keys encrypted at rest). Recommended when you need at-rest protection on DevNet. |
| `remote-signer` | `--remote-signer-url <grpc://|http://|unix://…>` | External signer service; the node never holds the raw key. |
| `hsm-pkcs11` | `--hsm-config-path <file>` | Hardware Security Module via PKCS#11. |

DevNet bring-up examples (a **full node** needs no signer; a **validator** does):

```bash
# DevNet full node — no consensus signer key required
./target/release/qbind-node --env devnet --validator-id 0 --data-dir "$DATA"

# DevNet validator — loopback-testing signer (DevNet only)
./target/release/qbind-node --env devnet --validator-id 0 --data-dir "$DATA" \
  --signer-mode loopback-testing

# DevNet validator — encrypted filesystem keystore
./target/release/qbind-node --env devnet --validator-id 0 --data-dir "$DATA" \
  --signer-mode encrypted-fs --signer-keystore-path "$KEYSTORE"
```

`loopback-testing` is DevNet-appropriate but is **not** an at-rest-protected mode; prefer
`encrypted-fs` (or a remote signer / HSM) when the operator wants the DevNet signing key encrypted on
disk.

## 4. Remote signer / HSM / KMS posture

The surfaces exist today as CLI flags:

- **Remote signer** — `--signer-mode remote-signer --remote-signer-url <url>` (`grpc://`, `http://`,
  or `unix://`). The remote-signer transport/policy/attestation boundary lives under
  `crates/qbind-remote-signer/` and the Run 195/197/199/202/294 helper examples.
- **HSM / PKCS#11** — `--signer-mode hsm-pkcs11 --hsm-config-path <file>` (library path, slot id, key
  label).

**Honest posture note.** These flags are present and parsed today, and the MainNet profile already
**fails closed** on `loopback-testing` and enforces production-remote-signer / attestation policy
selectors (see `crates/qbind-node/src/cli.rs` signer-policy docs). However, this Run does **not**
stand up a production remote signer/HSM/KMS backend, does **not** prove an end-to-end
production-custody signing path, and makes **no** claim that remote-signer/HSM custody is
production-ready. Treat remote-signer/HSM on DevNet as a **posture / integration surface**, and not as
a production custody guarantee. Production custody remains **C4-open**.

## 5. File permission requirements

- Every **private** key file **must** be mode `0600` (owner read/write only). The DevNet identity and
  trust-bundle helpers already write `leaf.kem.sk.bin` / `v<N>.kem.sk.bin` as `0600`; verify it:

  ```bash
  stat -c '%a %n' "$OUT"/leaf.kem.sk.bin   # expect: 600
  ```

- The **transport root signing key** and **trust-bundle signing key** are generated **in memory only**
  and are **never** written to disk by the DevNet helpers — there is no `0600` file to protect because
  there is no file at all.
- The **encrypted-fs keystore directory** (`--signer-keystore-path`) and any HSM config
  (`--hsm-config-path`) must likewise be readable only by the `qbind-node` user; keep the whole
  keystore directory `0700`.
- Secret-key file paths are **never** logged by `qbind-node`.

## 6. Rotation / revocation status

- **DevNet operational guidance only.** On DevNet you rotate a key by generating fresh material (see
  `PQC_ROOT_AND_SIGNING_KEYS.md`) and re-pinning the new root/leaf on the nodes you control; DevNet is
  **resettable**, so key rotation is an operator convenience, not a custody guarantee.
- **Revocation** on the transport trust plane is expressed through the trust bundle (root `status`
  = `active | retired | revoked` and an explicit revocation list; see `PQC_TRUST_BOOTSTRAP.md`).
- **No MainNet custody.** There is **no** MainNet custody, MainNet authority rotation, or MainNet
  revocation flow here.
- **C4/C5 remain OPEN.** Operator-supplied root reuse / rotation / revocation as a full production CA
  lifecycle is tracked under **C4**, and governance-executed authority lifecycle under **C5** — both
  remain **OPEN** (`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`,
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`).

## 7. Backup guidance

- **What to back up (privately, offline):** the private `leaf.kem.sk.bin` for each node you must keep
  stable, the `encrypted-fs` keystore directory, and any HSM config — stored encrypted and offline,
  readable only by the operator.
- **What to publish:** the **public** identity JSON, root public key / id (`root.pk.hex`,
  `root.id.hex`, `trusted-root.spec`), leaf certificate, and bundle-signing **verification** key
  (`signing-key.pk.hex`, `signing-key.id.hex`, `signing-key.spec`).
- **What never to commit:** any `*.kem.sk.bin`, any root/bundle **signing secret**, keystore contents,
  keystore passwords, mnemonics, seed phrases, credentials, tokens, or private endpoints/hostnames.
  The repository `.gitignore` ignores `*.kem.sk.bin` / `*.cert.bin` and the archive `.gitignore`
  backstops the per-run material directory.
- **Recovering from lost DevNet keys:** because DevNet is **resettable/no-value**, the recovery path
  for a lost DevNet private key is simply to **regenerate** fresh identity/root material and re-pin it
  on your nodes (`PQC_ROOT_AND_SIGNING_KEYS.md`). There is no DevNet key-escrow or recovery service,
  and none is implied for MainNet.

## 8. No value-bearing / MainNet custody

This guidance is **explicitly not** a value-bearing or MainNet custody procedure. It provides **no**
custody of any asset, **no** MainNet key management, and **no** production key-ceremony. Any use of
these DevNet flows to imply MainNet custody readiness is incorrect. MainNet custody remains **Red**;
**C4 and C5 remain OPEN**.

## 9. Cross-links

- Identity concepts / loading — `docs/release/public-devnet/operator/IDENTITY.md`.
- Generation & verification — `docs/release/public-devnet/identity/IDENTITY_GENERATION.md`,
  `PQC_ROOT_AND_SIGNING_KEYS.md`.
- Trust-bundle bootstrap — `PQC_TRUST_BOOTSTRAP.md`.
- Admission / P2P posture — `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`.
- Trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.
