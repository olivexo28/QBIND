# QBIND PQC Trust Lifecycle Operator Runbook

**Run:** 060
**Status:** Operator playbook landed; full C4 remains OPEN
**Scope owner:** transport trust-anchor + bundle-signing lifecycle
**Date:** 2026-05-13

This runbook converts the PQC trust-bundle machinery proven by
Runs 050–059 into a concrete operator playbook for production
custody, rotation, revocation, and bundle-signing-key rotation.

It is **operator documentation**. It is **not** a redesign of any
runtime layer. It does **not** introduce new bypass flags, does
**not** weaken any fail-closed check, and does **not** advocate
any fallback that the binary already refuses. If anything in this
document appears to contradict the implementation, the
implementation wins and this runbook MUST be updated.

References to behaviour are anchored in:

- `crates/qbind-node/src/pqc_trust_bundle.rs` (envelope, canonical
  fingerprint, ML-DSA-44 signature verification — Runs 050/051/053).
- `crates/qbind-node/src/pqc_trust_sequence.rs` (sequence anti-
  rollback persistence — Run 055).
- `crates/qbind-node/src/pqc_trust_activation.rs` (activation height
  / epoch gating — Run 057).
- `crates/qbind-node/src/pqc_root_config.rs` (root parsing,
  `PQC_TRANSPORT_SUITE_ML_DSA_44 = 100`).
- `crates/qbind-node/src/p2p_node_builder.rs::make_pqc_static_root_crypto_provider`
  (real `MlDsa44SignatureSuite`, real `MlKem768Backend`, real
  `ChaCha20Poly1305Backend` — Runs 037/039/040).
- `crates/qbind-node/src/main.rs` trust-bundle load path (calls
  `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
  then `check_and_update_sequence` BEFORE root merge).
- `crates/qbind-node/examples/devnet_pqc_root_helper.rs` and
  `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`
  (DevNet evidence tooling only — not production custody).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_050.md` through `RUN_059.md`
  (live-binary smoke evidence for every fail-closed boundary cited
  below).

Per-environment chain ids (`crates/qbind-types/src/primitives.rs`):

- DevNet:  `0x51424E4444455600`
- TestNet: `0x51424E4454535400`
- MainNet: `0x51424E444D41494E`

---

## 1. Scope and non-goals

### 1.1 In scope

- Transport trust-anchor (ML-DSA-44 root) lifecycle: generation,
  custody, normal rotation, emergency revocation.
- Bundle-signing key lifecycle: generation, custody, distribution,
  rotation.
- Validator leaf delegation certificate rotation.
- Sequence anti-rollback persistence behaviour at rotation and
  recovery time.
- Activation-height gating policy at rotation time.
- DevNet / TestNet / MainNet per-environment policy.
- Promotion, incident, and evidence checklists operators must run
  for every production trust-bundle change.

### 1.2 Out of scope (explicit non-goals)

- Any redesign of KEMTLS, the trust-bundle envelope, the
  sequence-persistence format, the activation-gate semantics,
  consensus, NewView, timeout verification, or transport crypto.
- Any new CLI flag, environment variable, or compile-time feature
  that would let an operator bypass signed-bundle verification,
  chain_id check, sequence anti-rollback, activation gating, leaf
  revocation, or environment binding.
- A full external KMS / HSM integration. The runbook treats the
  signing-key custody surface as an **interface / runbook boundary**;
  operators MAY back this with HSM/KMS in production but the
  binary today consumes ML-DSA-44 keys via the existing
  `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` flag, which is
  a **verification** public key — see §4.
- On-chain bundle-signing-key rotation (the binary does **not**
  ratify a new signing key inside the bundle itself; the
  `signing_key_id` is verified against an out-of-band-distributed
  CLI-configured set — see §6.D).
- An epoch-gating runtime source (Run 057 boundary: bundles that
  declare `activation_epoch` continue to fail closed with
  `TrustBundleActivationError::CurrentEpochUnavailable`).
- A startup self-check that fails the binary closed when
  `--p2p-leaf-cert` matches an active entry in the loaded bundle's
  `revoked_leaf_fingerprints` (Run 052/054 boundary — still open).
- A per-environment minimum-activation-height policy enforced by
  the binary (this runbook recommends one in §5.3 but the binary
  does not yet enforce it).
- Production fast-sync / consensus-storage restore (separate C4
  piece).

### 1.3 Strictly preserved invariants

This runbook MUST NOT contradict any of the following. They are
production-honest fail-closed behaviours proven by Runs 050–059
and must not be weakened by any operator procedure described here:

| Invariant | Where enforced | Proof |
|---|---|---|
| Bundle signature MUST verify against a configured `--p2p-trust-bundle-signing-key` on TestNet/MainNet. Unsigned bundle on TestNet/MainNet fails closed. | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys_and_chain_id` | RUN_051, RUN_059 Smoke 2 |
| Tampered bundle (any byte of canonical preimage flipped after signing) fails closed at ML-DSA-44 verify. | same | RUN_051, RUN_059 Smoke 3 |
| Wrong signing key (`signing_key_id` not in the operator's `--p2p-trust-bundle-signing-key` set) fails closed. | same | RUN_051, RUN_059 Smoke 4 |
| Wrong `chain_id` fails closed BEFORE signature verification side-effects on the live trust set. | same | RUN_053, RUN_059 Smoke 5 |
| Wrong `environment` fails closed. | same | RUN_050 |
| Expired / not-yet-valid bundle window fails closed. | same | RUN_050 |
| Expired / not-yet-valid root window excludes that root. | same | RUN_050 |
| Revoked root (`status=revoked` OR listed in `revocations[]`) excluded from active set. | same | RUN_050 |
| `signing_key_id` MUST NOT collide with any transport `root_id` (trust separation). | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys` | RUN_051 |
| `--p2p-trust-bundle-signing-key` MUST NOT collide with any `--p2p-trusted-root` id at startup (trust separation, defence in depth). | `main.rs` startup check | RUN_051 |
| Lower-`sequence` bundle on the same trust domain fails closed (rollback). | `pqc_trust_sequence::check_and_update_sequence` | RUN_055, RUN_056 Smoke 3 |
| Equal-`sequence` different-fingerprint bundle fails closed (equivocation). | same | RUN_055, RUN_056 Smoke 5 |
| Corrupted persistence file is never silently deleted / truncated / reset; loader fails closed. | same | RUN_055, RUN_056 Smoke 6 |
| `activation_height` in the future fails closed; does NOT advance persisted sequence; does NOT merge roots. | `pqc_trust_activation::check_bundle_activation`, ordering pinned by `pqc_trust_activation::tests::future_activation_does_not_advance_sequence_persistence` and RUN_057 integration test of the same name | RUN_057, RUN_058 Smoke 2/3/4 |
| `activation_epoch` declared without a runtime epoch source fails closed (`CurrentEpochUnavailable`). | same | RUN_057 |
| On any bundle-load failure, the binary does NOT silently fall back to `--p2p-trusted-root`. FATAL message ends with the literal phrase `No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade)`. | `main.rs` | every Run 050–059 negative smoke |
| Under `--p2p-pqc-root-mode pqc-static-root`, the registered crypto provider is the real ML-DSA-44 / ML-KEM-768 / ChaCha20-Poly1305 set. No `DummySig` / `DummyKem` / `DummyAead` is registered. | `p2p_node_builder::make_pqc_static_root_crypto_provider` | RUN_037/039/040, RUN_041 |

If any procedure in this runbook appears to require violating one
of the above, the procedure is wrong, not the implementation. Open
a defect and update `docs/whitepaper/contradiction.md`.

---

## 2. Trust model and roles

The trust lifecycle separates **five** distinct authorities. They
MUST be held by different keys, and operationally SHOULD be held
by different humans / hardware / environments where possible.

### 2.1 Authorities and key separation

| Authority | What it can do | What it MUST NOT also be |
|---|---|---|
| **Transport root authority** | Owns the ML-DSA-44 root signing key. Signs validator leaf delegation certs (`NetworkDelegationCert`). | A bundle-signing key. A validator leaf KEM secret. A validator consensus signing key. |
| **Bundle-signing authority** | Owns the ML-DSA-44 bundle-signing secret. Signs the canonical trust-bundle preimage. The `signing_key_id` it produces MUST NOT equal any transport `root_id`. Distinct domain separator (`QBIND:pqc-trust-bundle-signature:v1`) prevents preimage collision with transport certs. | A transport root key. A validator leaf KEM secret. A validator consensus signing key. |
| **Validator node operator** | Holds the validator's leaf delegation cert (`v<N>.cert.bin`) and the matching ML-KEM-768 leaf secret (`v<N>.kem.sk.bin`). Holds the validator consensus signing key (separate `--signer-keystore-path` ML-DSA-44 keystore). Runs the `qbind-node` binary. Consumes the trust bundle. | A transport root signing key. A bundle-signing secret. A revocation authority key. |
| **Bundle publisher / distributor** | Distributes the latest `trust-bundle.json` artifact and the current `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` lines out-of-band to validator operators. Read-only with respect to keys: never possesses the bundle-signing secret. | Bundle-signing authority. Transport root authority. |
| **Incident responder / emergency revocation authority** | Authorised to mint and publish a `sequence=N+1` bundle that revokes a compromised root or leaf fingerprint **using the existing bundle-signing authority's key**. Does NOT add new signing keys; uses the already-distributed signing authority. | A new bundle-signing key holder (would be a different rotation, not a revocation). |
| **Auditor** | Read-only access to bundles, persistence records, evidence logs, and `/metrics`. | Any signing authority. |

Helper-generated keys (`devnet_pqc_root_helper`,
`devnet_pqc_trust_bundle_helper`) are **DevNet-ephemeral** and are
generated fresh in memory; the helpers never write the root or
bundle-signing **secret** to disk. They are **not** production
custody. Production root and bundle-signing keys MUST be generated
on, and never leave, an offline / HSM-backed host (§3, §4).

### 2.2 Why this separation matters

- A transport root key signs **per-validator delegation certs**.
  Reusing it as a bundle-signing key would let the entity that
  issues a validator's transport identity also unilaterally change
  the set of trusted networks roots — that is a privilege merger
  forbidden by `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys`
  (collision check between `signing_key_id` and any `roots[].root_id`).
- A bundle-signing key authorises **policy** (which roots are
  trusted, which leaves are revoked, at what activation height).
  Reusing it as a validator consensus signing key would conflate
  consensus participation with trust-policy authority.
- A validator leaf KEM secret authorises **traffic** (this peer
  may complete KEMTLS handshakes). It is per-validator and is
  rotated independently of roots.

---

## 3. Artifact inventory

For each production artifact: where it lives, who may access it,
online/offline classification, rotation cadence, emergency
handling, backup/recovery notes, logging rules.

### 3.1 Transport root public key

- **Format:** 1312 bytes ML-DSA-44 public key, lowercase hex.
- **Where:** distributed to all validators as part of the
  signed `trust-bundle.json` under `roots[i].root_pk` AND on the
  CLI startup banner as the safe-fingerprint
  `id=<8 hex>.. suite=100 fp=<8 hex>` (see Run 037 banner).
- **Online/offline:** public; may be distributed online; HASH /
  fingerprint MUST be cross-checked against an out-of-band source
  before first install on a new validator (§7 promotion checklist).
- **Rotation cadence:** at least every 12 months; sooner under any
  cryptographic transition or operator-suspected compromise.
- **Emergency:** §6.B.
- **Backup/recovery:** any number of identical copies; the
  authoritative copy is whichever the signed bundle declares.
- **Logging:** safe to log fingerprint (`fp=<8 hex>`); never log
  the full key in raw form in production logs (the existing Run
  037 banner is the canonical safe form).

### 3.2 Transport root signing secret

- **Format:** ML-DSA-44 secret key.
- **Where:** an offline / HSM-backed host. **Never** written to a
  validator node's disk. The DevNet helpers explicitly mint this
  in memory and never persist it (`mint_devnet_root`).
- **Online/offline:** offline only. SHOULD live on a physically
  airgapped or HSM-protected host.
- **Access:** transport root authority (§2.1). Multi-party control
  (m-of-n) is RECOMMENDED but not enforced by the binary.
- **Rotation cadence:** at least every 12 months (must precede the
  validator leaf cert rotation it enables).
- **Emergency:** treat any suspected compromise as a §6.B incident
  and a §6.A rotation simultaneously.
- **Backup/recovery:** HSM-vendor-specific encrypted backups; no
  plaintext backups; recovery requires multi-party authorisation.
- **Logging:** **never** log the secret in any form. The DevNet
  helpers' "never persisted" property is the production target.

### 3.3 Bundle-signing public key

- **Format:** 1312 bytes ML-DSA-44 public key. Distributed as a
  `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` line where
  - `KEYID` is exactly 64 lowercase hex chars (32 bytes), MUST NOT
    collide with any transport root id;
  - `100` is the ML-DSA-44 suite id;
  - `HEXPK` is the lowercase hex public key.
- **Where:** distributed to all validators out-of-band; supplied
  on the `qbind-node` command line. Multiple entries are accepted
  during overlap windows.
- **Online/offline:** public; the bundle-signing public KEY is
  online.
- **Rotation cadence:** every 6–12 months, or on suspected
  compromise of the corresponding secret.
- **Emergency:** §6.D.
- **Backup/recovery:** same distribution channel as the bundle.
- **Logging:** safe to log `signing_key_id` (the verifier prints
  `signature=verified(signing_key_id=<8 hex>..)` — see Run 050/051
  banner).

### 3.4 Bundle-signing secret

- **Format:** ML-DSA-44 secret key.
- **Where:** offline / HSM-backed host. Separate from the
  transport root authority's host where operationally feasible.
- **Online/offline:** offline only. SHOULD be HSM-backed in
  MainNet.
- **Access:** bundle-signing authority + incident responder.
- **Rotation cadence:** 6–12 months; immediately on suspected
  compromise.
- **Emergency:** §6.D plus a separate §6.B revocation if the
  compromise window may have produced rogue bundles.
- **Backup/recovery:** HSM-vendor-specific encrypted backups; no
  plaintext backups.
- **Logging:** **never** log the secret in any form.

### 3.5 Validator leaf delegation certificate

- **File:** `v<N>.cert.bin` (the encoded `NetworkDelegationCert`
  produced by `pqc_devnet_helper::issue_leaf_delegation_cert` +
  `encode_cert` in DevNet; in production the same wire format
  produced by the offline transport root authority).
- **Where:** validator node disk; loaded via `--p2p-leaf-cert`.
- **Online/offline:** lives online on the validator host (the
  validator must present it on every handshake).
- **Access:** validator node operator. The corresponding KEM
  secret (§3.6) MUST share the same access boundary.
- **Rotation cadence:** every 3–12 months, AND on root rotation,
  AND on validator-host compromise.
- **Emergency:** §6.C (leaf rotation) or §6.B (root revocation
  if the compromise extends to the root).
- **Backup/recovery:** the leaf cert is public; the operator
  re-runs the issuance flow against the current transport root.
- **Logging:** safe to log the cert fingerprint (8-byte SHA3 prefix
  used by `cert_leaf_fingerprint_hex`); never log the matching KEM
  secret.

### 3.6 Validator leaf KEM secret

- **File:** `v<N>.kem.sk.bin` (mode `0o600` on the helper output;
  same discipline expected on production validator hosts).
- **Where:** validator node disk; loaded via `--p2p-leaf-cert-key`.
- **Online/offline:** online on the validator host only.
- **Access:** validator node operator only.
- **Rotation cadence:** with every leaf cert rotation.
- **Emergency:** §6.C; if a validator's KEM secret is suspected
  compromised AND the cert may still be presented by an attacker,
  also publish a `revoked_leaf_fingerprints[]` entry (§6.C).
- **Backup/recovery:** treated as a fresh-generation artifact; if
  lost, re-issue a new leaf cert + KEM secret (§6.C).
- **Logging:** **never** log raw bytes. The helper's `0o600` mode
  is the production target.

### 3.7 Trust bundle JSON

- **File:** `trust-bundle.json`, the artifact consumed by
  `--p2p-trust-bundle`. Schema pinned by
  `pqc_trust_bundle::TrustBundle` (`bundle_version = 1`).
- **Fields operators MUST set:** `bundle_version`, `environment`,
  `chain_id` (MUST equal the runtime chain id — RUN_053),
  `generated_at`, `valid_from`, `valid_until`, `sequence`,
  `roots[]`, `revocations[]`, optional `activation_height` /
  `activation_epoch` (RUN_057), `signature` (RUN_051; required on
  TestNet/MainNet).
- **Where:** distributed by the bundle publisher; consumed by
  every validator.
- **Online/offline:** public.
- **Rotation cadence:** at least one new `sequence` for every
  policy change (root added, root retired, root revoked, leaf
  fingerprint revoked, activation declared). Sequence MUST be
  strictly monotonic per `(environment, chain_id)` trust domain
  (RUN_055).
- **Logging:** safe to log canonical fingerprint and `sequence`.
  The Run 050/051 banner is the canonical form.

### 3.8 Sequence persistence file

- **File:** `<data_dir>/pqc_trust_bundle_sequence.json`, schema
  pinned by `pqc_trust_sequence` (`record_version = 1`,
  `environment`, `chain_id`, `highest_sequence`,
  `bundle_fingerprint`, `updated_at_unix_secs`).
- **Where:** per-validator node disk.
- **Online/offline:** online (state must be readable at every
  startup).
- **Lifecycle:** written ONLY by `check_and_update_sequence`
  (atomically), AFTER signature / chain_id / activation gate pass.
- **Backup/recovery:** OPERATORS MUST NOT manually edit this file.
  A corrupted file fails the node closed at startup; the **only**
  supported recovery is to investigate why it was corrupted, then
  replace the entire `--data-dir` from a clean snapshot of the
  same trust domain (i.e. another honest validator's persisted
  record at the same or higher sequence). Never roll the
  `highest_sequence` field backwards manually. Never set
  `bundle_fingerprint` manually. Run 055 explicitly never silently
  deletes or truncates this file (RUN_056 Smoke 6).
- **Logging:** safe to log `highest_sequence` and the canonical
  fingerprint. Never log the raw file path with privilege material.

### 3.9 Revocation entries

- **Where:** the `revocations[]` array on the `trust-bundle.json`,
  with `root_id`, optional `leaf_cert_fingerprint`, `reason`,
  `effective_from` (Unix seconds).
- **Activation:** entries with `effective_from > validation_time`
  are NOT yet active (the validity-window layer). Activation
  height / epoch gating on revocation entries is NOT yet
  implemented (Run 052/054 boundary — recorded in §10).
- **Logging:** safe to log root_id prefix + reason; never log
  the `leaf_cert_fingerprint` of a compromised validator more
  noisily than the rest of the run log requires.

### 3.10 Activation height / epoch field

- **Where:** `activation_height` / `activation_epoch` on the bundle
  envelope and on each root entry (RUN_057).
- **Semantics:** inclusive `current >= required`. Missing field =
  no restriction.
- **Operator policy:** RECOMMENDED for every planned rotation on
  TestNet/MainNet; SET to a height comfortably past the current
  finalised height so all live validators see and persist the
  bundle before it takes effect.
- **Boundary:** `activation_epoch` is rejected today with
  `CurrentEpochUnavailable` (Run 057 boundary — recorded in §10).
  Operators MUST NOT set `activation_epoch` on a production bundle.

### 3.11 Chain_id field

- **Where:** `chain_id` on the bundle envelope. Constants live in
  `crates/qbind-types/src/primitives.rs` and are surfaced through
  `NetworkEnvironment::chain_id()`.
- **Operator policy:** MUST be set to the correct chain_id for the
  target environment on every signed TestNet/MainNet bundle. RUN_053
  pinned the crosscheck and RUN_059 Smoke 5 proves the live
  release binary rejects a mismatched chain_id even on a validly
  signed bundle.

### 3.12 Environment field

- **Where:** `environment` on the bundle envelope. Lowercase
  string (`devnet` | `testnet` | `mainnet`).
- **Operator policy:** MUST match the runtime `--env` exactly. A
  bundle for the wrong environment fails closed (RUN_050).

---

## 4. Key generation and custody

### 4.1 Transport root key generation

1. On the offline / HSM-backed transport root host:
   - Generate an ML-DSA-44 keypair using the same primitive as
     `MlDsa44Backend::keygen` (`crates/qbind-crypto/src/ml_dsa44.rs`).
     The DevNet helper `devnet_pqc_root_helper` is the
     reproducibility reference; production replaces the in-memory
     mint with an HSM-backed mint.
   - Compute `root_key_id = sha3_256_tagged("QBIND:pqc-root-id:v1",
     root_pk)` (matches the helper's `mint_devnet_root` shape and
     the `pqc_root_config::PqcTrustedRoot.root_key_id` field).
   - Compute `fp = sha3_256(root_pk)[..8]` for the safe banner
     fingerprint.
2. Record `root_key_id`, `root_pk` (hex), and `fp` in an
   air-gapped artifact-inventory log signed by two custodians.
3. **Never** copy `root_sk` to disk; keep it inside the HSM /
   offline host. The DevNet helper's "never persisted" invariant
   is the production target.

### 4.2 Bundle-signing key generation

Identical to §4.1 but on a **different** host / HSM context so the
two authorities cannot be conflated. The resulting `signing_key_id`
MUST NOT equal any `root_id` (the binary refuses startup if they
collide — pinned by `main.rs` and
`pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys`).

### 4.3 Validator leaf cert issuance

Performed by the transport root authority for each validator:

1. Validator operator produces an ML-KEM-768 keypair on the
   validator host (`MlKem768Backend::generate_keypair`); sends the
   public key out-of-band to the root authority.
2. Root authority mints a `NetworkDelegationCert` (see
   `pqc_devnet_helper::issue_leaf_delegation_cert` for the
   reference shape) carrying:
   - `validator_id` for the target validator;
   - `root_key_id` of the issuing root;
   - `leaf_kem_pk` (the validator's KEM public key);
   - `not_before` / `not_after` validity window (Run 045
     enforced on the binary path);
   - ML-DSA-44 signature by the transport root secret.
3. Root authority returns `v<N>.cert.bin` to the validator (the
   secret never leaves the offline / HSM host).
4. Validator operator places `v<N>.cert.bin` and
   `v<N>.kem.sk.bin` (mode `0o600`) under the validator's data
   directory.

### 4.4 Custody rules

| Rule | Why |
|---|---|
| Transport root secret never on a validator host. | Prevents root compromise on a validator-host compromise. |
| Bundle-signing secret never on a validator host. | Same. |
| Bundle-signing key host distinct from transport root host where feasible. | Defence in depth: a single compromise does not yield both authorities. |
| Validator leaf KEM secret only on its own validator host, mode `0o600`. | Prevents one validator-host compromise from yielding another validator's traffic identity. |
| No private key bytes appear in any log or evidence artifact. | RUN_037 through RUN_059 invariant. The DevNet helpers' "never persisted, never logged" property is the production target. |
| Multi-party (m-of-n) authorisation for any production root or bundle-signing operation. | Operator policy; not enforced by the binary today. |

---

## 5. Per-environment policy

### 5.1 DevNet

- **Bundles:** unsigned bundles ARE allowed by the binary
  (`TrustBundle::validate_at_with_signing_keys` accepts them on
  DevNet, refuses them on TestNet/MainNet — RUN_050/051).
- **Convenience helpers:** `devnet_pqc_root_helper` and
  `devnet_pqc_trust_bundle_helper` are the supported way to mint
  ephemeral roots, leaf certs, and bundles. They are explicitly
  **NOT** production custody (they generate keys in memory and
  never persist secrets).
- **Sequence persistence:** Run 055 applies on DevNet exactly as
  on TestNet/MainNet; rollback / equivocation / corrupt-file
  fail-closed semantics are preserved (RUN_055/056).
- **Activation gating:** the `activation_height` field is
  honoured on DevNet (RUN_057/058 smokes were DevNet).
- **Operators MUST NOT** treat any DevNet helper output as
  production-safe material.

### 5.2 TestNet

- **Signed bundles required.** Unsigned bundles fail closed at
  load.
- **`--p2p-trust-bundle-signing-key` required** when
  `--p2p-trust-bundle` is supplied (`main.rs` enforces this).
- **Sequence persistence required.** Operators MUST configure
  `--data-dir` so the persistence file is written; running on
  TestNet without `--data-dir` is unsupported.
- **`chain_id` MUST match TestNet** (`0x51424E4454535400`). RUN_053
  pinned the crosscheck.
- **Activation gating SHOULD be used** for planned rotations: set
  `activation_height` to a height past the current finalised
  height so every honest validator persists the bundle before it
  takes effect.
- **`activation_epoch` MUST NOT be set** (Run 057 boundary).
- **Negative smokes expected before promotion to MainNet:** see
  §7 promotion checklist.

### 5.3 MainNet

All TestNet requirements PLUS:

- **Bundle-signing keys MUST be offline or HSM-backed.** The
  ephemeral in-memory keys used by the DevNet helpers are not
  acceptable for MainNet.
- **Static CLI roots MUST NOT be mixed with bundles.** `main.rs`
  rejects `--p2p-trust-bundle` and `--p2p-trusted-root` being
  supplied together on TestNet/MainNet (Run 050/051 invariant).
- **No unsigned bundle.** RUN_059 Smoke 2 proves the live release
  binary rejects this on MainNet.
- **No fallback.** Every Run 050–059 negative smoke proves the
  release binary exits before merging any root from any source on
  bundle failure.
- **Recommended minimum activation-height margin:** set
  `activation_height = last_finalised_height + N` where N is the
  expected maximum operator rollout window (at least one finality
  block; recommended ≥ 100 blocks). Note: the **binary does not
  enforce a minimum margin today** (recorded in §10); this is an
  operator policy.

---

## 6. Workflows

Every workflow below preserves the §1.3 invariants. Each step is
either an offline / HSM action (§3.2, §3.4) or a CLI action on an
operator workstation / validator. **No step requires editing the
sequence persistence file by hand.**

### 6.A Normal transport root rotation

Goal: introduce a new transport root and retire the old one with
zero handshake outages.

Preconditions:

- Current bundle sequence = N, active root R_old, signed by
  bundle-signing key BSK.
- All validators are running on a `--data-dir` whose persistence
  record has `highest_sequence = N` and a current chain_id.

Steps:

1. **Mint R_new offline** (§4.1). Record `root_id_new`, `root_pk_new`,
   `fp_new` in the artifact-inventory log.
2. **Issue new leaf certs for every validator under R_new** (§4.3).
   Distribute each `v<N>.cert.bin` to its validator operator.
   Validators DO NOT install them on disk yet.
3. **Mint overlap bundle (sequence = N+1) signed by BSK**:
   - `roots[]` = `[R_old(status=active), R_new(status=active)]`.
   - `revocations[]` unchanged.
   - `activation_height` = current_finalised_height + safety margin
     (§5.3).
   - `valid_from` / `valid_until` as policy dictates.
   - `chain_id` MUST match the runtime chain id (§3.11).
   - Sign with BSK offline.
4. **Publish bundle N+1** to all validators. Each validator restarts
   with `--p2p-trust-bundle <N+1.json>` and the unchanged
   `--p2p-trust-bundle-signing-key BSK_ID:100:BSK_PK`. The binary
   prints the Run 057 activation banner and the Run 055 sequence
   persistence banner (`upgraded previous_sequence=N -> new_sequence=N+1`).
5. **Wait until `current_height >= activation_height`** on the live
   network. The activation gate now passes; both R_old and R_new
   are in the active trust set.
6. **Roll validators to leaf certs under R_new**: each validator
   operator restarts with `--p2p-leaf-cert v<N>_new.cert.bin
   --p2p-leaf-cert-key v<N>_new.kem.sk.bin` while bundle N+1
   remains the active bundle. Existing handshakes with R_old
   leaves still verify (both roots are active).
7. **Mint retire bundle (sequence = N+2) signed by BSK**:
   - `roots[]` = `[R_old(status=retired), R_new(status=active)]`.
   - `revocations[]` unchanged.
   - `activation_height` = current_finalised_height + margin.
   - Sign with BSK offline.
8. **Publish bundle N+2.** Validators restart and persist sequence
   N+2. R_old becomes ineligible for cert verification (RUN_050:
   `RootStatus::Retired` is not acceptable for verification).
9. **Optional bundle N+3 (revoke R_old):** mint a bundle with
   `roots[]` = `[R_old(status=revoked), R_new(status=active)]` and
   a `revocations[]` entry for R_old with `effective_from = now`.
   Use this if the rotation reason was compromise rather than
   scheduled rotation.

Rollback proofs:

- After any validator persists sequence N+1, re-loading the old
  sequence N bundle fails closed at
  `pqc_trust_sequence::check_and_update_sequence` (RUN_055,
  RUN_056 Smoke 3). The release binary refuses to start and exits
  1 BEFORE merging any root.
- Equivocation: if an attacker mints a different "sequence N+1"
  bundle with a distinct fingerprint, the persisted record's
  `bundle_fingerprint` mismatch fails closed (RUN_056 Smoke 5).

### 6.B Emergency transport root revocation

Goal: revoke a compromised root R_bad as quickly as the bundle
distribution channel allows, without silently downgrading any
fail-closed check.

Preconditions:

- Current bundle sequence = N.
- A new replacement root R_new SHOULD already be in active rotation
  (i.e. an earlier §6.A produced bundle N including R_new). If
  R_new is not yet rotated in, run §6.A in parallel; emergency
  revocation BEFORE replacement causes a liveness outage for
  validators whose only leaf cert chains to R_bad.

Steps:

1. **Mint revocation bundle (sequence = N+1) signed by BSK**:
   - `roots[]` = `[R_bad(status=revoked), R_new(status=active),
     …]`.
   - `revocations[]` += `{root_id: R_bad, reason: "compromise",
     effective_from: now}`.
   - `activation_height` = current_finalised_height (no margin —
     emergency).
   - Sign with BSK offline.
2. **Publish bundle N+1.** Validators restart with the new bundle.
   Any validator whose leaf cert chains to R_bad MUST already have
   a replacement leaf cert under R_new on disk; otherwise that
   validator stops being able to complete KEMTLS handshakes (it
   will not silently fall back — RUN_037/038/039/040).
3. **No `--p2p-trusted-root` fallback.** Operators MUST NOT add a
   `--p2p-trusted-root` line to "bridge" validators that have not
   yet rolled to R_new; that combination is refused with
   `--p2p-trust-bundle` on TestNet/MainNet, and would not bypass
   the revocation anyway.
4. **No Dummy crypto fallback.** Under
   `--p2p-pqc-root-mode pqc-static-root`, the registered crypto
   provider remains real `MlDsa44SignatureSuite` / `MlKem768Backend`
   / `ChaCha20Poly1305Backend` (RUN_037/039/040/041).
5. **Document the liveness tradeoff honestly.** If a non-trivial
   fraction of validators were chained to R_bad and had not yet
   completed the §6.A leaf rotation, emergency revocation WILL
   cause those validators to drop out until they roll to R_new
   leaves. This is the **correct** fail-closed behaviour.

### 6.C Leaf certificate rotation

Goal: rotate a single validator's leaf certificate without
touching the trust root or the bundle.

Variant 1: scheduled leaf rotation, no revocation needed.

1. Validator operator generates a new ML-KEM-768 keypair on the
   validator host.
2. Transport root authority issues a new
   `v<N>_new.cert.bin` under the current root.
3. Validator operator restarts with
   `--p2p-leaf-cert v<N>_new.cert.bin
    --p2p-leaf-cert-key v<N>_new.kem.sk.bin`.
4. **No bundle change required** — the root and the bundle layer
   are unchanged.

Variant 2: leaf compromise suspected (key may be in attacker
hands).

1. Steps 1–3 of Variant 1.
2. **Mint bundle (sequence = N+1) signed by BSK** adding the
   compromised leaf cert fingerprint to `revoked_leaf_fingerprints`
   (see `pqc_trust_bundle::revoked_leaf_fingerprints()` —
   RUN_052/054). The fingerprint is the 8-byte SHA3-256 prefix
   of the leaf cert wire encoding, as produced by
   `pqc_trust_bundle::cert_leaf_fingerprint`.
3. **Publish bundle N+1.** All validators reject inbound handshakes
   presenting the revoked fingerprint at the listener side
   (RUN_052, RUN_054).
4. **Operator MUST also ensure the local validator's
   `--p2p-leaf-cert` does NOT match an active entry in
   `revoked_leaf_fingerprints`** — otherwise it would be telling
   peers "I am presenting a revoked cert", and would itself be
   refused. **Note:** the binary does NOT yet self-check this at
   startup (Run 052/054 remaining boundary — §10). Operator MUST
   verify out-of-band.

### 6.D Bundle-signing key rotation

This is the most operator-load-bearing workflow because the binary
does NOT update the bundle-signing **verification** key set from
inside the bundle itself. The `--p2p-trust-bundle-signing-key` CLI
flag is the authoritative configuration.

**Honest current boundary.** A bundle is signed by the current
bundle-signing secret. The signed `signing_key_id` is then verified
at load time against the union of all
`--p2p-trust-bundle-signing-key` CLI lines on the validator's
command line. There is no on-chain ratification of a new
bundle-signing key; rotation is an operator-orchestrated overlap
of two CLI-configured verification keys. If a future runtime adds
on-chain bundle-signing-key ratification, this section MUST be
updated and any out-of-date claims here treated as a defect.

Steps:

1. **Mint BSK_new offline** (§4.2). Record `signing_key_id_new`,
   `signing_pk_new`. MUST NOT collide with any transport root id.
2. **Distribute the new
   `--p2p-trust-bundle-signing-key signing_key_id_new:100:signing_pk_new`
   line out-of-band to every validator.** Operators MUST add this
   line ALONGSIDE the existing
   `--p2p-trust-bundle-signing-key signing_key_id_old:100:signing_pk_old`
   line. The binary accepts multiple verification keys.
3. **Each validator restarts** with both `--p2p-trust-bundle-signing-key`
   entries. Bundles signed by BSK_old continue to verify (the
   currently-in-use signing key id is in the configured set).
4. **Mint the next bundle (sequence = N+1) signed by BSK_new**.
   Include `activation_height` as policy dictates.
5. **Publish bundle N+1.** Validators verify against BSK_new
   (whose verification key is now in the configured set) AND
   persist sequence N+1. The validator startup log records
   `signature=verified(signing_key_id=<new prefix>..)`.
6. **Wait for full operator rollout confirmation** (every validator
   has restarted with both signing keys AND has accepted bundle
   N+1 — confirmable via `qbind_p2p_pqc_trust_bundle_sequence_highest`
   on `/metrics`).
7. **Remove the `--p2p-trust-bundle-signing-key signing_key_id_old:...`
   line from every validator's command line.** Validators restart.
8. Optionally mint bundle N+2 with the same content under BSK_new
   to confirm the post-removal state.

Rollback safety:

- Persistence of `highest_sequence = N+1` ensures a re-introduction
  of a bundle signed by BSK_old at sequence ≤ N is rejected.
- Sequence ordering is INDEPENDENT of which signing key signed the
  bundle. The anti-rollback layer keys off `(environment, chain_id)`
  only (RUN_055).

---

## 7. Promotion checklist (every production trust-bundle change)

Run this before promoting a bundle to TestNet, and again before
promoting to MainNet. Every item must be confirmed green; any red
item blocks promotion.

- [ ] Bundle `bundle_version == 1`.
- [ ] Bundle `environment` matches the target runtime
      (`--env devnet|testnet|mainnet`).
- [ ] Bundle `chain_id` matches the runtime chain id constant
      (DevNet `0x51424E4444455600`, TestNet `0x51424E4454535400`,
      MainNet `0x51424E444D41494E`).
- [ ] Bundle `sequence` is strictly greater than the previously
      published bundle's `sequence` for this trust domain.
- [ ] Bundle `activation_height` (if set) is at least the current
      finalised height plus the operator margin (§5.3).
- [ ] Bundle `activation_epoch` is **NOT** set (Run 057 boundary).
- [ ] Bundle `valid_from <= now <= valid_until`.
- [ ] Every `roots[i]` has `suite_id == 100`, valid ML-DSA-44
      `root_pk` length, lowercase hex, and a window covering the
      activation period.
- [ ] `revocations[i].effective_from` is at most the current time
      for any entry intended to be active immediately.
- [ ] `signing_key_id` does NOT equal any `roots[i].root_id`.
- [ ] Bundle ML-DSA-44 signature verifies against the operator's
      configured `--p2p-trust-bundle-signing-key` set.
- [ ] Canonical fingerprint computed by
      `pqc_trust_bundle::canonical_fingerprint` recorded in the
      artifact-inventory log.
- [ ] Negative tamper test passes (flip any byte of
      `roots[0].not_after`; the test fixture must fail closed —
      RUN_059 Smoke 3 shape).
- [ ] Wrong-chain test passes (relabel `chain_id` to a different
      environment's id; loader must fail closed — RUN_059 Smoke
      5 shape).
- [ ] Rollback test passes (after persisting sequence N+1, attempt
      to load sequence N; loader must fail closed — RUN_056 Smoke 3).
- [ ] Equivocation test passes (mint a second distinct bundle at
      the same sequence with a different fingerprint; loader must
      fail closed — RUN_056 Smoke 5).
- [ ] If a revoked root or revoked leaf is being introduced, a
      revoked-root / revoked-leaf negative test passes (RUN_052,
      RUN_054).
- [ ] On a clean test validator, the live binary prints the Run
      050/051/053/055/057 banners with the expected fingerprints
      and ends with the Run 040 `[Run040] P2pNodeBuilder: ...
      dummy_kem_registered=false dummy_aead_registered=false ...`
      banner — confirming no fallback to test-grade primitives.
- [ ] No `--p2p-trusted-root` line on TestNet/MainNet validators.
- [ ] Archive: bundle fingerprint, signing_key_id, release
      `qbind-node` `sha256` + `ELF BuildID`, helper `sha256` if
      one was used to mint the bundle.

---

## 8. Incident checklist

Run this on any of: suspected root compromise, suspected
bundle-signing key compromise, suspected validator leaf
compromise, observed rollback / equivocation attempt.

- [ ] Quarantine the suspected compromised material. Do not
      re-use any compromised key for **any** subsequent step.
- [ ] Identify which authority (§2.1) is compromised. Root,
      bundle-signing, and leaf compromises follow different
      workflows (§6.B, §6.D, §6.C).
- [ ] Mint replacement material on a clean offline / HSM host
      (§4).
- [ ] Mint an `(N+1)` bundle that excludes the compromised
      material, with `activation_height = current_finalised_height`
      (no margin — emergency). Sign with the currently-trusted
      bundle-signing authority.
- [ ] Distribute the new bundle out-of-band on the same channel
      as steady-state bundles.
- [ ] Confirm every validator reports `qbind_p2p_pqc_trust_bundle_sequence_highest`
      = `N+1` on `/metrics`.
- [ ] Confirm `qbind_p2p_pqc_trust_bundle_signature_rejected_total`
      stays 0 on every validator after the change.
- [ ] If a bundle-signing key was compromised, follow §6.D in the
      shortened "emergency rotation" form: distribute BSK_new
      before the next steady-state bundle, mint bundle N+2 under
      BSK_new, then remove BSK_old in N+3 once rollout is
      confirmed.
- [ ] Update `docs/whitepaper/contradiction.md` with the incident
      narrative if the incident revealed a missing fail-closed
      check.
- [ ] Postmortem: ensure §7 promotion checklist did not pass
      under the compromised authority; if it did, fix the gap.

---

## 9. Evidence checklist (for every production trust-bundle change)

This is the artefact set the auditor MUST be able to retrieve for
every bundle change. The directory layout MAY follow the existing
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_*.md` shape.

- [ ] `bundle.json` (the artifact that was distributed).
- [ ] `bundle.fp.hex` (the canonical fingerprint).
- [ ] `signing-key.spec` (the `--p2p-trust-bundle-signing-key`
      line used to verify; verification key only, never secret).
- [ ] `signing-key.id.hex` (the 64-hex `signing_key_id`).
- [ ] `previous-bundle.fp.hex` and `previous-bundle.sequence`
      (the bundle this one replaces).
- [ ] Positive smoke transcript: a fresh validator started with
      the new bundle, with `--p2p-pqc-root-mode pqc-static-root`,
      printed the Run 050/051/053/055/057 banners and the Run 040
      `dummy_kem_registered=false dummy_aead_registered=false`
      banner; `/metrics` reports the expected
      `qbind_p2p_pqc_trust_bundle_*` series.
- [ ] Negative tamper smoke transcript (RUN_059 Smoke 3 shape).
- [ ] Wrong-chain smoke transcript (RUN_059 Smoke 5 shape).
- [ ] Rollback smoke transcript (RUN_056 Smoke 3 shape).
- [ ] If a root was revoked: revoked-root smoke (RUN_052 shape).
- [ ] If a leaf was revoked: revoked-leaf smoke (RUN_054 shape).
- [ ] Confirmation that no `--p2p-trusted-root` line was supplied
      on any validator.
- [ ] Confirmation that `pqc_root_mode=pqc-static-root` and no
      `Dummy*` is registered on every validator (Run 040 banner).
- [ ] Release binary identity: `sha256` and `ELF BuildID` of the
      `qbind-node` binary that ran the smokes.

---

## 10. Residual risks (NOT solved by this runbook)

This runbook narrows the C4 "production CA / certificate rotation
/ signing-key rotation operator playbook" item. It does **NOT**
close any of the following, which remain open under C4:

1. **Epoch-gating runtime source.** `activation_epoch` continues
   to fail closed with `TrustBundleActivationError::CurrentEpochUnavailable`
   (Run 057). Operators MUST NOT set `activation_epoch` on
   production bundles.
2. **Activation gates on revocation entries.** `revocations[]`
   honour only `effective_from` (Unix seconds); no
   `activation_height` / `activation_epoch` field on a revocation
   entry today.
3. **Per-environment minimum activation-height policy.** The
   binary does not enforce a minimum margin between
   `activation_height` and the current finalised height. This
   runbook RECOMMENDS one in §5.3 but the enforcement is operator
   policy, not binary policy.
4. **Startup self-check that fails the binary closed when
   `--p2p-leaf-cert` matches an active entry in
   `revoked_leaf_fingerprints`** (Run 052/054 boundary). Operators
   MUST verify out-of-band that they are not loading a revoked
   leaf as their own identity.
5. **Production fast-sync / consensus-storage restore.** Separate
   C4 piece; trust-bundle persistence is independent.
6. **Per-environment production trust-anchor operation.** Not
   fully solved by documentation alone; depends on the operator
   actually using offline / HSM custody for the secrets in §3.2
   and §3.4.
7. **In-binary bundle-signing-key rotation / ratification.** The
   binary does NOT ratify a new bundle-signing key on-chain. §6.D
   is an out-of-band CLI overlap procedure. If a future runtime
   adds on-chain ratification, this runbook MUST be updated.
8. **Two-node / N-node MainNet release-binary smoke evidence.**
   RUN_059 produced a single-validator MainNet release-binary
   smoke; a multi-validator MainNet peer-connection smoke remains
   on the C4 list (blocked by unrelated production-config items —
   validator keystore loading on startup, per-peer consensus-key
   distribution).
9. **External KMS / HSM integration.** This runbook treats the
   signing-key custody surface as an interface boundary; full
   KMS integration is not in scope.

**Full C4 remains OPEN. C5 is NOT closed by this runbook.**

---

## 11. Mapping to Runs 050–059

| Run | What it proved | What §section of this runbook relies on it |
|---|---|---|
| 050 | Structured bundle schema, environment + chain_id + validity + revocation fail-closed boundaries. | §1.3, §3.7, §5.1–5.3, §6.A, §7. |
| 051 | ML-DSA-44 signed-bundle verification; signing-key/root-id collision check. | §1.3, §2.2, §3.3, §4.2, §6.D, §7. |
| 052 | Leaf-level revocation; listener-side fail-closed on revoked-leaf handshake. | §3.6, §3.9, §6.C, §7, §9. |
| 053 | `chain_id` crosscheck at bundle load (before signature side-effects). | §1.3, §3.11, §5.2, §5.3, §7. |
| 054 | Release-binary leaf-revocation evidence helper modes. | §3.9, §6.C, §7, §9. |
| 055 | Sequence anti-rollback persistence (rollback, equivocation, corrupt-file fail-closed). | §1.3, §3.8, §6.A, §6.B, §6.D, §7. |
| 056 | Release-binary anti-rollback evidence (positive upgrade, rollback, equal-sequence different-fp, corrupt persistence). | §3.8, §6.A, §7. |
| 057 | Activation-height gating (`current_height` source from restore baseline or 0; future activation does NOT advance persisted sequence). | §1.3, §3.10, §6.A, §7. |
| 058 | Release-binary activation-height evidence (positive active-now, negative future-height, positive upgrade-after-rejection). | §3.10, §6.A, §7. |
| 059 | MainNet signed-bundle release-binary smoke (positive, unsigned, tampered, wrong key, wrong chain). | §1.3, §5.3, §7, §9. |
| 037 / 039 / 040 / 041 | Real `MlDsa44SignatureSuite`, `MlKem768Backend`, `ChaCha20Poly1305Backend` registration; no `Dummy*` under `pqc-static-root`. | §1.3, §5.3, §6.B, §9. |

---

## 12. Glossary of operator-facing flags

- `--env devnet|testnet|mainnet` — runtime environment.
- `--p2p-pqc-root-mode pqc-static-root` — selects the production-
  honest cert-verification path. Test-grade DummySig mode is the
  default (DevNet-only) and is refused on MainNet.
- `--p2p-trust-bundle <PATH>` — path to `trust-bundle.json`.
- `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` — repeatable;
  the bundle-signing verification key set.
- `--p2p-trusted-root ROOTID:100:HEXPK` — static CLI roots; on
  TestNet/MainNet, MUST NOT be combined with `--p2p-trust-bundle`.
- `--p2p-leaf-cert <PATH>` / `--p2p-leaf-cert-key <PATH>` —
  validator's leaf delegation cert and matching ML-KEM-768 secret.
- `--p2p-mutual-auth required` — production setting.
- `--data-dir <PATH>` — REQUIRED for the sequence persistence file
  on TestNet/MainNet.

---

*If anything here appears to permit a fallback that the binary
refuses, the binary wins and this runbook is the defect. Open an
issue against `docs/whitepaper/contradiction.md` immediately.*