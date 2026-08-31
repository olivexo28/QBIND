# QBIND Public DevNet — PQC Trust-Bundle Bootstrap (M8) (Run 389)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document describes the **DevNet PQC trust-bundle bootstrap flow** using **only** the pre-existing
`qbind-node` CLI surfaces and the existing DevNet trust-bundle helper example
(`crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`). Run 389 adds **no** CLI flag, changes
**no** wire format, weakens **no** peer admission, and applies **no** trust bundle live. Every
non-hidden flag named here is validated to appear in `qbind-node --help` (see `VERIFY.md`).

## 1. DevNet trust-bundle bootstrap flow

At a high level, bootstrapping a DevNet PQC transport trust bundle is:

1. **Mint** a DevNet root + per-validator leaf certs and (optionally) a **signed** trust bundle with
   the existing helper (`PQC_ROOT_AND_SIGNING_KEYS.md` §1).
2. **Validate** the bundle offline with `qbind-node --p2p-trust-bundle-reload-check` (validation-only;
   no live apply) before it is trusted by any running node.
3. **Load** the validated bundle at node startup with `--p2p-trust-bundle` (plus
   `--p2p-trust-bundle-signing-key` for a signed bundle), alongside strict
   `--p2p-mutual-auth required` / `--p2p-pqc-root-mode pqc-static-root` admission.
4. **Pin** the genesis hash (`--expect-genesis-hash`) so a node started against the wrong genesis
   refuses to start before any peer contact.

The bundle is **loaded locally by each operator** on the nodes they control. There is **no**
peer-driven adoption of trust material (see §8–§9).

## 2. Genesis-hash pinning

Every node pins the canonical DevNet genesis hash so that admission and trust are bound to the same
chain:

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f \
  …
```

On a genesis mismatch the node **refuses to start** before any network/consensus start. The trust
bundle additionally carries a `TrustBundleEnvironment` (`devnet`/`testnet`/`mainnet`) and a
`chain_id`, both of which must match the runtime `--env` / genesis a joining node verified (see §6 and
`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md` §5).

## 3. Transport roots vs bundle-signing keys (separation)

Two distinct PQC key roles must not be conflated:

- **Transport trust roots** (`--p2p-trusted-root` / roots inside `--p2p-trust-bundle`) are the
  ML-DSA-44 **root public keys** that issue and vouch for peer leaf certificates. They gate **who is
  admitted** on the transport.
- **Bundle-signing keys** (`--p2p-trust-bundle-signing-key`) are the ML-DSA-44 keys whose **public**
  half verifies the **signature over the bundle document itself**. They gate **whether the bundle is
  authentic**, not who is admitted.

The DevNet helper deliberately emits these as separate files (`root.*` vs `signing-key.*`) and a
`signed-key-root-collision` negative fixture proves the loader rejects a bundle that tries to reuse a
root id as its signing-key id. Keep the two roles separate; never point `--p2p-trusted-root` at a
bundle-signing key or vice versa.

## 4. `--p2p-trust-bundle` loading

`--p2p-trust-bundle <path>` supplies a PQC transport trust-anchor bundle (JSON). At load it is
strictly validated for:

- **environment binding** (`TrustBundleEnvironment` must equal runtime `--env`);
- per-root **validity windows** (`not_before` / `not_after`);
- **root status** (`active | retired | revoked`);
- an explicit **revocation list**;
- **suite id** (only suite `100` = ML-DSA-44 is accepted; any other suite fails closed);
- **signature** (for signed bundles — see §5).

Any parse / validity / signature failure **aborts startup** with a typed error (fail closed); there is
no silent acceptance and no fallback to an implicit anchor.

## 5. `--p2p-trust-bundle-signing-key` (candidate signing-key usage)

`--p2p-trust-bundle-signing-key KEYID:SUITE:PK` (suite `100`, repeatable) supplies the **public**
verification key(s) used to check a **signed** bundle's signature. The DevNet helper's
`signed-devnet` fixture writes a ready-to-copy `signing-key.spec` in exactly this
`KEYID:100:PK` shape:

```bash
SPEC="$(cat "$OUT/tb/signing-key.spec")"
./target/release/qbind-node --env devnet \
  --p2p-trust-bundle-reload-check "$OUT/tb/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert "$OUT/tb/v0.cert.bin" \
  --p2p-leaf-cert-key "$OUT/tb/v0.kem.sk.bin"
```

- On DevNet an **unsigned** bundle is accepted; a **signed** bundle is verified against the configured
  keys (`signature_verified=true` on success).
- On **TestNet/MainNet** a signing key is **required** when a bundle is supplied — unsigned bundles are
  refused. This DevNet convenience does **not** leak into the stricter environments (see §11).
- The **private** signing key is never needed by, or given to, the node; only the public verification
  key is passed. The DevNet helper never writes the signing secret to disk.

## 6. `--p2p-trusted-root` / static-root posture and DevNet limitations

`--p2p-trusted-root ROOT_KEY_ID_HEX:SUITE:ROOT_PK_HEX` (suite `100`, repeatable) supplies trusted PQC
transport **root public keys** directly, required for production `--p2p-pqc-root-mode pqc-static-root`
mode. On DevNet you may run either:

- `--p2p-pqc-root-mode test-grade-dummy-sig` (DevNet-only DummySig; convenience/testing), or
- `--p2p-pqc-root-mode pqc-static-root` (production ML-DSA-44; the intended strict posture, pinning
  `--p2p-trusted-root` / bundle roots).

**DevNet limitation:** DevNet permits the DummySig test-grade mode and unsigned bundles for developer
convenience. These conveniences are **DevNet-only** and are **not** a MainNet/TestNet posture. The
strict, launch-relevant DevNet posture is `pqc-static-root` + a signed bundle + pinned roots.

## 7. Reload-check / reload-apply / SIGHUP surfaces

- **reload-check** — `--p2p-trust-bundle-reload-check <path>` is the **validation-only** preflight used
  throughout this document. It parses, validates, and (for signed bundles) verifies the signature, then
  reports `VERDICT=valid|invalid` and exits **without** applying anything live: **no** live trust
  apply, **no** sequence-persistence write, **no** peer/session mutation, **no** `/metrics` mutation.
  On TestNet/MainNet it requires at least one `--p2p-trust-bundle-signing-key`.
- **reload-apply** — a separate, **hidden/advanced**, long-running-node mutating trigger exists
  (`--p2p-trust-bundle-reload-apply-enabled` + `--p2p-trust-bundle-reload-apply-path`, plus an optional
  **SIGHUP** live-reload handler). These **mutate** the live trust state and are **out of scope for
  DevNet bootstrap** in this guidance; do not enable them as part of a routine DevNet bring-up. They
  are governed by the Run 069/073/074 apply pipeline and the ratification/governance gates documented
  in `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

For DevNet bootstrap, always **reload-check first**, then load a validated bundle at **startup** with
`--p2p-trust-bundle`.

## 8. Peer-candidate validation/propagation is advisory / non-mutating

Peer-candidate trust-bundle **validation** and **propagation** surfaces remain **advisory and
non-mutating** unless an operator explicitly opts in via the prior safe flags. A peer asserting trust
material does **not** cause a node to adopt it; local trust-root / trust-bundle validation is
authoritative (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md` §8).

## 9. No peer-driven live apply

Peer-driven trust-bundle **apply** (a peer causing a node to adopt new trust material) remains **out
of scope** for public DevNet admission and is **not** enabled by this package. See
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`. This bootstrap flow loads only
**locally configured** trust anchors.

## 10. No fallback roots or hidden default trust anchors

There is **no** implicit fallback root and **no** hidden default trust anchor. Under `pqc-static-root`
a peer whose cert does not chain to an explicitly loaded trusted root (from `--p2p-trusted-root` or the
bundle) is **rejected** during the KEMTLS handshake. A missing/invalid bundle fails closed rather than
silently trusting anything.

## 11. MainNet / TestNet are stricter (no DevNet shortcut leakage)

MainNet/TestNet enforce a **stricter** policy than DevNet:

- unsigned bundles are **refused** (a signing key is required);
- `test-grade-dummy-sig` root mode / `loopback-testing` signer are **forbidden**;
- governance/ratification gates are invoked by default.

The DevNet conveniences (unsigned bundle, DummySig mode) described here **do not** apply to and **do
not** weaken TestNet/MainNet. This guidance makes **no** TestNet or MainNet readiness claim and
performs **no** live trust apply. **C4 and C5 remain OPEN.**

## 12. Cross-links

- Root/leaf/signing-key generation — `PQC_ROOT_AND_SIGNING_KEYS.md`.
- Key roles / permissions / backup — `KEY_MANAGEMENT.md`.
- Admission / fail-closed matrix — `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`,
  `docs/release/public-devnet/p2p/VERIFY.md`.
- Trust lifecycle runbook (reload/apply/SIGHUP, ratification) —
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.
- Authority model / closure criteria — `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`.
