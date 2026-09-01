# QBIND Public DevNet — PQC Root & Signing Keys (M9) (Run 389)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document gives the **exact** operator steps to generate and verify DevNet PQC root / leaf /
bundle-signing material using the **existing** helpers (the first-class `qbind-node identity` command,
`crates/qbind-node/src/identity_cli.rs`; the DevNet root helper
`crates/qbind-node/examples/devnet_pqc_root_helper.rs`; and the DevNet trust-bundle helper
`crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`). Run 389 adds **no** CLI flag and
changes **no** default behaviour.

## 1. Generate DevNet root / leaf material (existing helpers)

### 1a. First-class identity command (preferred for node/seed/validator identity)

```bash
cargo build -p qbind-node --release --bin qbind-node
BIN="./target/release/qbind-node identity"
OUT="$(mktemp -d)"          # operator-selected temp dir OUTSIDE any git tree

$BIN generate devnet full-node          "$OUT/node"
$BIN generate devnet seed               "$OUT/seed"
$BIN generate devnet validator-candidate "$OUT/val" 0
```

`devnet` is the **only** accepted environment; `mainnet` / `testnet` are refused with a non-zero exit
(this tooling creates no MainNet/TestNet custody). See
`docs/release/public-devnet/identity/IDENTITY_GENERATION.md`.

### 1b. DevNet root + signed trust-bundle helper (for trust-bundle bootstrap)

```bash
cargo build -p qbind-node --release --example devnet_pqc_trust_bundle_helper
TB="./target/release/examples/devnet_pqc_trust_bundle_helper"
$TB "$OUT/tb" 1 signed-devnet     # 1 validator leaf; a valid *signed* DevNet bundle
```

A pure root/leaf mint (no bundle) is also available via
`devnet_pqc_root_helper <outdir> <num_validators> [validity_mode]`.

## 2. Which generated files are PUBLIC

| File | Meaning |
|------|---------|
| `public-identity.json` | Publishable identity document (validates against `OPERATOR_IDENTITY_SCHEMA.json`); records private-key **paths** only, never contents. |
| `leaf.cert.bin` / `v<N>.cert.bin` | Encoded `NetworkDelegationCert` (public transport material). |
| `root.id.hex` | 64-hex `root_key_id`. |
| `root.pk.hex` | ML-DSA-44 root **public** key, hex. |
| `trusted-root.spec` | Ready-to-copy `--p2p-trusted-root` value (`id:100:pk`). |
| `signing-key.id.hex` | (signed bundle) bundle-signing key id. |
| `signing-key.pk.hex` | (signed bundle) bundle-signing **public** key, hex. |
| `signing-key.spec` | (signed bundle) ready-to-copy `--p2p-trust-bundle-signing-key` value (`id:100:pk`). |
| `trust-bundle.json` | The PQC trust-anchor bundle document (public). |
| `v<N>.leaf-fp.hex` | Leaf cert fingerprint (public). |

## 3. Which generated files are PRIVATE (never commit)

| File | Meaning |
|------|---------|
| `leaf.kem.sk.bin` / `v<N>.kem.sk.bin` | ML-KEM-768 **secret** key for `--p2p-leaf-cert-key`. Mode `0600`. **NEVER publish or commit.** |

Additionally, **never written to disk at all** by the DevNet helpers (in-memory only, so there is no
file to protect):

- the **transport root ML-DSA-44 signing key** (generated fresh on every run);
- the **trust-bundle ML-DSA-44 signing secret key** (only the public verification key id/pk/spec is
  emitted).

A production CA / custody / rotation / revocation flow is **out of scope** and tracked under **C4/C5**
(`docs/whitepaper/contradiction.md`, `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`).

## 4. How root fingerprints / NodeIds are derived and verified

- The `node_id` is `sha3_256("QBIND:nodeid:v1" || leaf_kem_pk)` — deterministic from the **public**
  leaf cert. Re-derive it from the public cert alone (no secret touched):

  ```bash
  ./target/release/qbind-node identity verify "$OUT/node/leaf.cert.bin"
  ```

  The printed `node_id` must equal the `node_id` field in `public-identity.json` and is the exact value
  a deployed `PqcStaticRoot` listener registers an admitted peer under.
- The `root_pk_fingerprint` and `leaf_cert_fingerprint` in `public-identity.json` are public
  fingerprints over the corresponding public keys/certs.

## 5. How to pin a trusted root for strict KEMTLS

Use the generated `trusted-root.spec` under strict static-root mode:

```bash
SPEC="$(cat "$OUT/node/trusted-root.spec")"
./target/release/qbind-node --env devnet --network-mode p2p --enable-p2p \
  --validator-id 0 --data-dir "$OUT/node-data" \
  --p2p-listen-addr 127.0.0.1:0 \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$SPEC" \
  --p2p-leaf-cert "$OUT/node/leaf.cert.bin" \
  --p2p-leaf-cert-key "$OUT/node/leaf.kem.sk.bin"
```

Under `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>` the live `/metrics` then reports
`qbind_p2p_pqc_root_mode 1` and `qbind_p2p_pqc_roots_configured 1`, confirming the deployed binary
accepted the static-root material (see `docs/release/public-devnet/identity/IDENTITY_GENERATION.md` §6
and the observability package).

## 6. How to verify a trust-bundle signature

Use the **validation-only** reload-check with the published verification key spec:

```bash
SPEC="$(cat "$OUT/tb/signing-key.spec")"
./target/release/qbind-node --env devnet \
  --p2p-trust-bundle-reload-check "$OUT/tb/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert "$OUT/tb/v0.cert.bin" \
  --p2p-leaf-cert-key "$OUT/tb/v0.kem.sk.bin"
# expect: signature_verified=true … VERDICT=valid (validation-only; no live trust apply)
```

This never applies the bundle live (see `PQC_TRUST_BOOTSTRAP.md` §7).

## 7. How to identify wrong-chain / wrong-env / wrong-genesis material

The loader **fails closed** on mismatched material; you can reproduce each rejection with the helper's
negative fixtures and the reload-check:

| Symptom | How it is detected |
|---------|--------------------|
| Wrong **environment** | A bundle whose `TrustBundleEnvironment` ≠ runtime `--env` (`wrong-environment` fixture) fails closed at load. |
| Wrong **chain / genesis** | Node started with a mismatched `--expect-genesis-hash` refuses to start before any peer contact; the bundle `chain_id` must match. |
| **Tampered** bundle | `signed-tampered` fixture → `VERDICT=invalid` (signature verification failed). |
| **Wrong signing key** | `signed-wrong-key` fixture → signature verification fails closed. |
| **Unsupported suite** | any `suite_id ≠ 100` (`unsupported-suite` fixture) is rejected. |
| **Expired / not-yet-valid** root | `expired-root` / validity-window fixtures fail closed. |
| **Revoked** root | `root-status-revoked` / revocation-list fixtures exclude/reject the root. |

## 8. What is NOT production custody

None of the above is production custody. DevNet root/leaf/signing material protects an experimental,
resettable, **no-value** network. The helpers generate signing secrets **in memory only** precisely
because this is **not** a production key ceremony. There is **no** MainNet custody, **no** MainNet
authority material, and **no** value-bearing signing flow here.

## 9. What remains C4/C5-open

- **C4** — operator-supplied root reuse / rotation / revocation as a full production CA lifecycle
  remains **OPEN**.
- **C5** — governance-executed authority lifecycle (runtime-wired authority mutation) remains **OPEN**.

See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` and
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`. This document makes **no** C4/C5 closure claim.

## 10. Cross-links

- Key roles / permissions / backup — `KEY_MANAGEMENT.md`.
- Trust-bundle bootstrap flow — `PQC_TRUST_BOOTSTRAP.md`.
- Identity generation / verification — `docs/release/public-devnet/identity/IDENTITY_GENERATION.md`,
  `docs/release/public-devnet/identity/IDENTITY_VERIFY.md`.
- Admission — `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`.
- Trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.