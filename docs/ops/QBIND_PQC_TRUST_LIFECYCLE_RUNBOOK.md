# QBIND PQC Trust Lifecycle Operator Runbook

**Run:** 066 (prose update of the Run 064 playbook for Run 065)
**Status:** Operator playbook landed and updated for Runs 050–065; full C4 remains OPEN
**Scope owner:** transport trust-anchor + bundle-signing lifecycle
**Date:** 2026-05-13

This runbook converts the PQC trust-bundle machinery proven by
Runs 050–065 into a concrete operator playbook for production
custody, rotation, revocation, and bundle-signing-key rotation.
Run 066 is a documentation-only update of the Run 064 playbook
that incorporates Run 065 (per-environment minimum activation-
height policy enforced at bundle load on the `--p2p-trust-bundle`
path: DevNet 0 / TestNet 8 / MainNet 32 blocks; half-open
`[current_height, current_height + margin)` reject window; applies
to bundle-level `activation_height`, per-active-root
`activation_height`, and per-entry revocation `activation_height`
when `Some(_)`; `activation_height = None` immediate revocations
preserved). No runtime code, no test source, and no helper source
is changed by Run 066.

It is **operator documentation**. It is **not** a redesign of any
runtime layer. It does **not** introduce new bypass flags, does
**not** weaken any fail-closed check, and does **not** advocate
any fallback that the binary already refuses. If anything in this
document appears to contradict the implementation, the
implementation wins and this runbook MUST be updated.

References to behaviour are anchored in:

- `crates/qbind-node/src/pqc_trust_bundle.rs` (envelope, canonical
  fingerprint, ML-DSA-44 signature verification — Runs 050/051/053;
  leaf-fingerprint domain separator `QBIND:pqc-trust-bundle-leaf-fp:v1`
  — Runs 052/054; sequence anti-rollback persistence — Run 055;
  per-entry revocation `activation_height` + active/pending split —
  Run 062; local-leaf startup self-check helper
  `check_local_leaf_not_revoked` — Run 061; local-issuer-root startup
  self-check helper `check_local_leaf_issuer_root_not_revoked` —
  Run 063).
- `crates/qbind-node/src/pqc_trust_sequence.rs` (sequence anti-
  rollback persistence — Run 055).
- `crates/qbind-node/src/pqc_trust_activation.rs` (bundle-level
  activation height / epoch gating — Run 057; per-environment
  minimum activation-margin constants and policy helper — Run 065:
  `MIN_DEVNET_ACTIVATION_MARGIN = 0`,
  `MIN_TESTNET_ACTIVATION_MARGIN = 8`,
  `MIN_MAINNET_ACTIVATION_MARGIN = 32`;
  `ActivationPolicy::for_environment`;
  `minimum_activation_margin_for_environment`;
  `check_min_activation_height_policy`;
  `TrustBundleActivationError::ActivationHeightBelowMinimumMargin`;
  `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`;
  `RevocationScope`).
- `crates/qbind-node/src/pqc_root_config.rs` (root parsing,
  `PQC_TRANSPORT_SUITE_ML_DSA_44 = 100`).
- `crates/qbind-node/src/p2p_node_builder.rs::make_pqc_static_root_crypto_provider`
  (real `MlDsa44SignatureSuite`, real `MlKem768Backend`, real
  `ChaCha20Poly1305Backend` — Runs 037/039/040).
- `crates/qbind-node/src/main.rs` trust-bundle load path (calls
  `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
  then `check_and_update_sequence` BEFORE root merge; emits the
  Run 062 revocation-activation banner; runs the Run 061
  local-leaf-fingerprint and Run 063 local-issuer-root startup
  self-checks BEFORE `PqcStaticRootConfig` construction; the
  Run 065 per-environment minimum activation-margin policy is
  applied AFTER signature/chain_id/environment/revocation
  structural validation and BEFORE Run 057's future-height gate,
  Run 055's sequence persistence, and Run 050's root merge — its
  two new error variants
  `TrustBundleActivationError::ActivationHeightBelowMinimumMargin`
  and
  `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`
  flow through the existing `TrustBundleError::Activation(..)`
  FATAL printer with the static "No fallback to
  --p2p-trusted-root" marker).
- `crates/qbind-node/examples/devnet_pqc_root_helper.rs` and
  `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`
  (DevNet evidence tooling only — not production custody).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_050.md` through `RUN_065.md`
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
- A per-environment minimum-activation-height policy enforced by
  the binary on a **gossiped / peer-supplied** bundle path. Run 065
  enforces this policy on the binary's `--p2p-trust-bundle` load
  path (DevNet 0 / TestNet 8 / MainNet 32 blocks; half-open
  `[current_height, current_height + margin)` reject window;
  applies to bundle-level `activation_height`, per-active-root
  `activation_height`, and per-entry revocation `activation_height`
  when `Some(_)`); the bundle is not yet gossiped between peers,
  and when on-the-fly trust-bundle distribution lands the same
  `check_min_activation_height_policy` helper must be threaded
  through that path. The Run 065 helper itself is reusable today
  (`crates/qbind-node/src/pqc_trust_activation.rs::check_min_activation_height_policy`).
- On-the-fly trust-bundle hot reload. The bundle is loaded exactly
  once per process lifetime; the Run 062 active/pending gauges are
  sticky-at-startup snapshots. Rotation today requires a validator
  restart.
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
| **Local-leaf startup self-check (Run 061).** If a configured `--p2p-leaf-cert` has a canonical leaf fingerprint (SHA3-256 of `b"QBIND:pqc-trust-bundle-leaf-fp:v1" \|\| cert.encode()`) that appears in the loaded bundle's currently-**active** `revoked_leaf_fingerprints` set, the binary emits one `[binary] FATAL: Run 061 local leaf certificate revoked …` line and exits 1 BEFORE `PqcStaticRootConfig` is built and BEFORE any peer handshake. The Run 052 peer-handshake counter `qbind_p2p_pqc_cert_verify_rejected_revoked_total` is NOT bumped. | `pqc_trust_bundle::check_local_leaf_not_revoked`, wired in `main.rs` between Run 050/051/062 banners and `pqc_config` construction | RUN_061 |
| **Per-entry revocation activation gate (Run 062).** A `revocations[]` entry with `activation_height: None` is immediate. A signature-valid entry with `activation_height > current_height` is **PENDING** — surfaced via `pending_revoked_root_ids` / `pending_revoked_leaf_fingerprints` and the `_revocations_*_pending` gauges, but NOT enforced anywhere (not in `active_roots`, not in the Run 061 startup self-check, not in the Run 052 peer-handshake context). An entry with `activation_height <= current_height` is **ACTIVE** and enforced bit-for-bit as the legacy immediate revocation. Tampering `activation_height` after signing invalidates the ML-DSA-44 bundle signature (canonical preimage coverage). | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys_chain_id_and_revocation_activation`; gauges in `metrics.rs` (`qbind_p2p_pqc_trust_bundle_revocations_{configured,active,pending}_total`, `_revocations_{root,leaf}_{active,pending}`) | RUN_062 |
| **Local-issuer-root startup self-check (Run 063).** If a configured `--p2p-leaf-cert` decodes to a `root_key_id` that appears in the loaded bundle's currently-**active** `revoked_root_ids` set, the binary emits one `[binary] FATAL: Run 063 local leaf certificate issuer root revoked …` line and exits 1 BEFORE `PqcStaticRootConfig` is built. The Run 062 pending set is explicitly NOT consulted. Independent of the Run 061 check; either failing fails closed. | `pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked`, wired in `main.rs` immediately after the Run 061 call site and BEFORE `pqc_config` is moved into the builder | RUN_063 |
| **Per-environment minimum activation-margin policy (Run 065).** A bundle whose declared `activation_height` (bundle-level OR per-active-root) falls in the half-open window `[current_height, current_height + margin)` fails closed at load with `TrustBundleActivationError::ActivationHeightBelowMinimumMargin`. A scheduled per-entry revocation whose `activation_height` is `Some(h)` and falls in the same window fails closed with `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`. Constants: DevNet `MIN_DEVNET_ACTIVATION_MARGIN = 0`, TestNet `MIN_TESTNET_ACTIVATION_MARGIN = 8`, MainNet `MIN_MAINNET_ACTIVATION_MARGIN = 32` (strict ordering DevNet < TestNet < MainNet). The reject window is half-open: bundles whose `activation_height` equals `current_height + margin` pass Run 065 and fall through to Run 057's "not yet reached" gate; bundles whose `activation_height` is strictly less than `current_height` are already-effective and are NOT retroactively rejected (snapshot-rejoin semantics). Per-entry revocations with `activation_height = None` are immediate and NEVER subject to Run 065 (preserves the emergency-revocation path). The policy runs AFTER signature / chain_id / environment / revocation structural validation and BEFORE Run 057's future-height gate, Run 055's sequence persistence, and Run 050's root merge — a rejected too-soon bundle does NOT create `pqc_trust_bundle_sequence.json` and does NOT update `loaded.active_roots`. `required_min_height = current_height.saturating_add(margin)` defends against `u64::MAX` wrap. | `pqc_trust_activation::check_min_activation_height_policy`, `MIN_{DEVNET,TESTNET,MAINNET}_ACTIVATION_MARGIN` constants, `ActivationPolicy::for_environment`; called from `pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`; errors flow through the existing `TrustBundleError::Activation(..)` FATAL printer in `main.rs` with the static "No fallback to --p2p-trusted-root" marker | RUN_065 |

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
  `effective_from` (Unix seconds), and (Run 062) optional
  `activation_height` (`Option<u64>`).
- **Active vs pending (Run 062).** Resolution rule at bundle load:
  - entry is **ACTIVE** iff `effective_from <= validation_time`
    AND (`activation_height` is absent OR
    `current_height >= activation_height`);
  - entry is **PENDING** iff signature-valid + `effective_from`
    satisfied but `activation_height > current_height` (or no
    runtime height source is available);
  - entries with `effective_from > validation_time` remain neither
    active nor pending (the wall-clock validity-window layer keeps
    them off both surfaces, exactly as in Run 050).
  Pending entries are surfaced on `pending_revoked_root_ids` /
  `pending_revoked_leaf_fingerprints` and on the new
  `qbind_p2p_pqc_trust_bundle_revocations_*_pending` gauges, but
  are NOT enforced anywhere (not in `active_roots`, not in the
  Run 061 startup self-check, not in the Run 052 peer-handshake
  context, not in the Run 063 issuer-root startup self-check).
- **`current_height` source (Run 062, mirrors Run 057, consumed
  by Run 065).** If `--restore-from-snapshot` is used,
  `current_height` is the restore baseline `snapshot_height`.
  Otherwise `current_height` is `0` at startup. There is no
  production runtime epoch source; per-entry `activation_epoch`
  is intentionally NOT supported (Run 057 boundary stands). The
  same `Option<u64>` `current_height` source feeds the Run 065
  minimum-margin policy.
- **Bundle-level vs per-entry activation.** DO NOT confuse:
  - bundle-level `activation_height` (Run 057) gates whether the
    whole bundle may take effect (sequence persist + root merge);
  - per-entry revocation `activation_height` (Run 062) gates only
    whether one specific revocation is enforced once the bundle
    has already loaded and persisted.
  A bundle that does NOT pass the bundle-level activation gate
  never publishes ANY revocation (active or pending). A bundle
  that DOES pass the bundle-level gate publishes its revocations
  according to the per-entry rule above.
- **Sequence interaction (Run 055 + Run 062).** A scheduled
  revocation bundle MAY advance `highest_sequence` immediately
  (the bundle itself is active and signature-valid); its
  scheduled revocation entries remain PENDING until each entry's
  own `activation_height` is reached. The persisted sequence
  record never rolls back on activation.
- **Operational recommendation:** use `activation_height` only for
  scheduled revocations where operators can safely coordinate a
  cutover (and have already issued replacement credentials to any
  validator that would otherwise fail closed at activation).
  Emergency-compromise revocations SHOULD be immediate (omit
  `activation_height`; `activation_height = None` is exempt from
  the Run 065 minimum-margin policy and remains available on
  MainNet for emergency response). Scheduled revocations with
  `activation_height = Some(h)` on TestNet/MainNet MUST respect
  the Run 065 minimum margin (§3.10): `h >= current_height +
  minimum_activation_margin` or the bundle is rejected at load
  with `RevocationActivationHeightBelowMinimumMargin`.
- **Logging:** safe to log root_id prefix + reason; never log
  the `leaf_cert_fingerprint` of a compromised validator more
  noisily than the rest of the run log requires.

### 3.10 Activation height / epoch field

- **Where:** `activation_height` / `activation_epoch` on the bundle
  envelope and on each root entry (RUN_057). Per-entry revocations
  also carry an optional `activation_height` (RUN_062).
- **Semantics:** inclusive `current >= required`. Missing field =
  no restriction (subject to the Run 065 minimum-margin policy
  below for `activation_height`).
- **Minimum-margin policy (Run 065).** The binary enforces a
  per-environment minimum activation margin on the bundle-level
  `activation_height`, on each active root's `activation_height`,
  and on every per-entry revocation whose `activation_height` is
  `Some(_)`:
  - DevNet: `MIN_DEVNET_ACTIVATION_MARGIN = 0` blocks.
  - TestNet: `MIN_TESTNET_ACTIVATION_MARGIN = 8` blocks.
  - MainNet: `MIN_MAINNET_ACTIVATION_MARGIN = 32` blocks.
  The reject window is the half-open interval
  `[current_height, current_height + margin)`:
  `activation_height >= current_height + margin` passes Run 065
  (and then reaches Run 057's "not yet reached" gate until
  `current_height` catches up); `activation_height < current_height`
  is already-effective and not retroactively rejected (preserves
  snapshot-rejoin semantics).
- **Operator policy:** REQUIRED for every planned rotation on
  TestNet/MainNet; SET `activation_height` to a height comfortably
  past the current finalised height. `activation_height ==
  current_height` is rejected at load on TestNet/MainNet by the
  Run 065 policy (and is the intentional `--data-dir`/sequence-
  safe behaviour: a rejected too-soon bundle does not burn the
  persisted sequence number).
- **Emergency immediate revocation.** Per-entry revocations whose
  `activation_height = None` are NEVER subject to the Run 065
  minimum-margin policy and remain available on every environment,
  including MainNet, regardless of `current_height` (§6.B / §6.C
  variant 2).
- **Boundary:** `activation_epoch` is rejected today with
  `CurrentEpochUnavailable` (Run 057 boundary — recorded in §10).
  Operators MUST NOT set `activation_epoch` on a production bundle.
  Run 065 does NOT introduce a minimum-margin policy on the epoch
  axis (the epoch runtime source itself remains open).

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
- **Minimum activation-margin (Run 065):**
  `MIN_DEVNET_ACTIVATION_MARGIN = 0` blocks. This preserves the
  DevNet immediate-cutover shape used by every Run 050–064 DevNet
  smoke: `activation_height = current_height` (and
  `activation_height = 0`) remain accepted on DevNet.
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
- **Minimum activation-margin (Run 065):**
  `MIN_TESTNET_ACTIVATION_MARGIN = 8` blocks. Every bundle whose
  bundle-level `activation_height`, per-active-root
  `activation_height`, or per-entry revocation `activation_height`
  (when `Some(_)`) falls in `[current_height, current_height + 8)`
  is rejected at load with the Run 065 FATAL. Operators MUST set
  `activation_height >= current_height + 8` on TestNet; emergency
  revocations may instead omit `activation_height` (immediate).
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
  expected maximum operator rollout window. Run 065 enforces a
  hard floor of `MIN_MAINNET_ACTIVATION_MARGIN = 32` blocks on
  MainNet: every bundle whose bundle-level `activation_height`,
  per-active-root `activation_height`, or per-entry revocation
  `activation_height` (when `Some(_)`) falls in
  `[current_height, current_height + 32)` is rejected at load
  with the Run 065 FATAL `pqc trust-bundle minimum activation-
  height policy violation (… environment=mainnet, …
  minimum_margin=32, required_min_height=<current+32>); …
  Reschedule the bundle with activation_height >= <current+32>`.
  Operators MAY (and SHOULD) choose `N` strictly greater than 32
  for additional operator-rollout headroom; 32 is the binary
  floor, not the operator target. Emergency revocations remain
  available without `activation_height` (immediate).

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
     (§5.3; MUST be `>= current_finalised_height + 8` on TestNet
     and `>= current_finalised_height + 32` on MainNet, the
     binary-enforced Run 065 floors).
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
   scheduled rotation. For scheduled rotation, the operator MAY
   instead set the `revocations[]` entry's `activation_height`
   (Run 062) to a future block height comfortably past the point
   by which every validator is expected to have rolled to an
   R_new leaf — until that height the entry is PENDING and not
   enforced, so the cutover is observable on the
   `qbind_p2p_pqc_trust_bundle_revocations_root_pending` gauge
   before any validator fails closed at startup.

**Run 063 interaction at root retire/revoke.** Once a bundle that
**actively** revokes R_old is loaded, any validator still booting
with a `--p2p-leaf-cert` chained to R_old will fail closed at
startup (Run 063 local-issuer-root self-check) BEFORE reaching the
peer-handshake layer. Operators MUST therefore confirm that every
validator has rolled to R_new leaf material BEFORE the R_old
revocation entry's `activation_height` becomes satisfied. PENDING
root revocations do NOT trip the Run 063 check (the helper reads
the **active** `revoked_root_ids` set only).

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
     effective_from: now, activation_height: None}`.
     `activation_height = None` (immediate) is the correct emergency
     shape and is NEVER subject to the Run 065 minimum-margin
     policy regardless of environment.
   - The bundle-level `activation_height` MAY be omitted entirely
     for the fastest emergency rotation. If set on TestNet/MainNet,
     it MUST satisfy the Run 065 floor (`>= current_finalised_height
     + 8` on TestNet, `+ 32` on MainNet); a bundle-level
     `activation_height = current_finalised_height` on MainNet is
     rejected at load by the Run 065 policy. Omitting the
     bundle-level `activation_height` (no restriction) is the
     emergency-correct shape because it makes the new bundle
     effective at every restarted validator immediately while
     preserving the per-entry immediate revocation.
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
   Run 063 makes this drop-out happen at **startup** (one FATAL
   line, exit 1) instead of silently at the peer-handshake layer
   — operators see the affected validator set immediately on
   restart rather than via degraded handshake counters.
6. **Scheduled vs immediate emergency revocation (Run 062).** For a
   true compromise, the revocation MUST be immediate (omit
   `activation_height` or set it to `<= current_finalised_height`).
   `activation_height` is appropriate ONLY when the rotation is
   pre-planned and replacement leaves are already provisioned. Do
   NOT use `activation_height` to "soften" a compromise revocation;
   between bundle load and activation the compromised root is
   still in `active_roots` and still issues handshake-acceptable
   certs.

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
4. **Local-leaf startup self-check (Run 061).** Beginning with
   Run 061, the binary itself fails closed at startup if the local
   `--p2p-leaf-cert` matches an **active** entry in
   `revoked_leaf_fingerprints`. The operator therefore receives an
   immediate, in-process FATAL on the compromised validator if it
   is restarted with the still-revoked credential, rather than
   relying on out-of-band verification. The check uses the same
   canonical fingerprint as the Run 052 peer-handshake layer
   (SHA3-256 of `b"QBIND:pqc-trust-bundle-leaf-fp:v1" \|\| cert.encode()`)
   and the same active set the peer-handshake layer consults.
   PENDING leaf revocations (Run 062 `activation_height` in the
   future) do NOT trip the Run 061 check; the entry must be
   active for startup to fail closed.
5. **Coordinated cutover via `activation_height` (Run 062).** For a
   scheduled leaf retirement (e.g. a planned validator-host
   migration), an operator MAY set `activation_height` on the
   leaf-revocation entry to a future block height. Until that
   height is reached the entry is PENDING and neither the Run 061
   startup self-check nor the Run 052 peer-handshake enforcement
   fires; on or after that height it becomes ACTIVE and both
   surfaces fire as in Variant 2 step 3/4. Operators MUST ensure
   the affected validator(s) have rolled to a non-revoked leaf
   BEFORE the activation height; otherwise those validators will
   fail closed at next restart (Run 061) and on every subsequent
   handshake (Run 052).
6. **Suspected-compromise revocations SHOULD be immediate.** Do not
   use `activation_height` to delay enforcement of a leaf revocation
   that arose from suspected key compromise. Between bundle load
   and activation the compromised leaf is still acceptable to
   peers; that is the wrong default for a compromise event.

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

### 6.E Scheduled revocation via per-entry `activation_height` (Run 062)

Use this workflow when an operator wants to publish a revocation
NOW but have it take effect at a known future block height (for
example, to coordinate a retirement window across all validators).
For suspected-compromise revocations, prefer §6.B (root) or §6.C
variant 2 (leaf) without `activation_height`.

Steps:

1. **Decide the target activation height.** Pick
   `activation_height_target = current_finalised_height + N` where
   N is large enough that every validator restart window
   completes before the entry becomes active. The binary enforces
   a per-environment floor (Run 065, §3.10 / §5):
   `activation_height_target >= current_finalised_height + 0` on
   DevNet, `+ 8` on TestNet, and `+ 32` on MainNet. Operators
   SHOULD pick `N` strictly greater than the floor for additional
   operator-rollout headroom; the floor is what the binary will
   refuse at load, not the operator target. A bundle with a
   per-entry revocation `activation_height` in the half-open
   reject window `[current_finalised_height, current_finalised_height
   + margin)` is rejected at load with
   `RevocationActivationHeightBelowMinimumMargin` and never
   updates the persisted sequence or merges any root.
2. **Mint the bundle (sequence = N+1)** with the revocation entry
   carrying `activation_height = activation_height_target`. Sign
   with BSK offline.
3. **Publish bundle N+1.** On every validator restart the binary
   prints `[binary] Run 062: trust-bundle revocation activation
   (configured=K active=A pending=P root_active=Ra root_pending=Rp
   leaf_active=La leaf_pending=Lp)`. The pending counters
   `qbind_p2p_pqc_trust_bundle_revocations_{leaf,root}_pending`
   confirm the scheduled entry is loaded but not yet enforced.
4. **Cutover preparation.** Before `activation_height_target` is
   reached:
   - confirm every affected validator has been issued, and has
     deployed, a non-revoked replacement credential (a new leaf
     under a non-revoked root for a leaf-revocation; a new leaf
     under R_new for a root-revocation);
   - confirm replacement KEM secrets are on every affected
     validator host with mode `0o600`;
   - if a validator cannot be migrated before
     `activation_height_target`, EITHER republish the bundle at
     `sequence = N+2` with the revocation entry's
     `activation_height` advanced further, OR accept the liveness
     consequence at activation.
5. **Activation.** At `current_height >= activation_height_target`
   the entry transitions from PENDING to ACTIVE. From the next
   validator restart onward:
   - a leaf-fingerprint entry trips the Run 061 local-leaf startup
     self-check on any validator still using the revoked cert;
   - a root entry trips the Run 063 local-issuer-root startup
     self-check on any validator still using a cert chained to
     the revoked root;
   - peer-handshake enforcement (Run 052 for leaf, Run 050 for
     root) is in effect against all peers from this point.
6. **Confirm activation.** After at least one validator has
   restarted on or after the activation height, the corresponding
   `_revocations_*_active` gauge increments and the `_pending`
   gauge decrements by one. Audit
   `qbind_p2p_pqc_trust_bundle_revocations_*` across the
   validator fleet to confirm a clean cutover.

Notes:

- A scheduled-revocation bundle MAY simultaneously advance the
  bundle-level `sequence` and the bundle-level `activation_height`.
  The two activation gates are independent: the bundle-level gate
  controls whether ANY of the bundle's roots / revocations take
  effect; the per-entry gate controls whether one specific
  revocation is enforced once the bundle has loaded.
- `activation_height` is intentionally NOT the same field as
  `effective_from`. `effective_from` is a wall-clock validity
  window (Run 050). `activation_height` is block-height-gated
  (Run 062). Both gates must pass for an entry to be active.
- There is no on-the-fly hot reload (§10). Validators that never
  restart between bundle load and `activation_height` will not see
  the transition in their in-process state; the next restart will.

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
- [ ] Bundle `activation_height` (if set) satisfies the Run 065
      per-environment minimum margin against `current_height`
      (§3.10 / §5): `activation_height >= current_height` on
      DevNet, `>= current_height + 8` on TestNet, `>= current_height
      + 32` on MainNet. A bundle with `activation_height` in the
      half-open reject window `[current_height, current_height +
      margin)` will be refused at load and will NOT advance the
      persisted sequence file.
- [ ] Bundle `activation_epoch` is **NOT** set (Run 057 boundary).
- [ ] Bundle `valid_from <= now <= valid_until`.
- [ ] Every `roots[i]` has `suite_id == 100`, valid ML-DSA-44
      `root_pk` length, lowercase hex, and a window covering the
      activation period.
- [ ] `revocations[i].effective_from` is at most the current time
      for any entry intended to be active immediately.
- [ ] For each `revocations[i]`, `activation_height` (Run 062) is
      EITHER absent (immediate; exempt from Run 065) OR satisfies
      the Run 065 per-environment minimum margin (§3.10 / §5.3)
      against the current finalised height. Emergency compromise
      revocations MUST NOT carry an `activation_height` that
      postpones enforcement past the next validator restart — set
      `activation_height = None` for immediate compromise
      revocations. A scheduled-revocation `activation_height` in
      the half-open reject window
      `[current_height, current_height + margin)` will be refused
      at load with `RevocationActivationHeightBelowMinimumMargin`.
- [ ] `signing_key_id` does NOT equal any `roots[i].root_id`.
- [ ] Bundle ML-DSA-44 signature verifies against the operator's
      configured `--p2p-trust-bundle-signing-key` set.
- [ ] Canonical fingerprint computed by
      `pqc_trust_bundle::canonical_fingerprint` recorded in the
      artifact-inventory log. Per-entry `activation_height` is
      covered by the canonical preimage (Run 062): tampering it
      after signing must invalidate the bundle signature.
- [ ] Confirm `current_height` source for the validator fleet
      (Run 057 / Run 065): with `--restore-from-snapshot`,
      `current_height = restore_baseline.snapshot_height`; otherwise
      `current_height = 0`. Operator margin choice for
      `activation_height` MUST be computed against this value.
- [ ] Confirm the chosen `activation_height` (bundle-level,
      per-active-root, AND any per-entry scheduled revocation) is
      OUTSIDE the Run 065 half-open reject window
      `[current_height, current_height + minimum_activation_margin)`
      on the target environment, OR is `None` (immediate
      revocation only).
- [ ] Confirm a rejected too-soon bundle would NOT burn the
      persisted sequence number (Run 065 ordering: the policy
      runs BEFORE `check_and_update_sequence`; rejected bundles
      leave `pqc_trust_bundle_sequence.json` and `loaded.active_roots`
      untouched).
- [ ] If the bundle is for TestNet/MainNet, a Run 065 too-soon
      negative smoke passes for that environment (RUN_065 Smoke 2
      shape for TestNet, Smoke 4 shape for MainNet): mint a
      same-shape bundle with `activation_height = current_height +
      (margin - 1)`, attempt to load, observe the FATAL `pqc
      trust-bundle minimum activation-height policy violation
      (… environment=<env>, … minimum_margin=<8|32>, …)`, AND
      verify the data directory is NOT created.
- [ ] Sufficient-margin smoke passes: mint a same-shape bundle
      with `activation_height = current_height + margin` (exactly
      at the inclusive upper boundary); the live binary passes
      the Run 065 policy and falls through to Run 057's
      "activation height not yet reached" FATAL (RUN_065 Smoke 3
      shape for TestNet, Smoke 5 shape for MainNet). This proves
      orthogonal composition of Run 065 and Run 057.
- [ ] If immediate emergency revocation is intentional, confirm
      every `revocations[i].activation_height` is `None` (the
      Run 065 emergency-revocation-preserved boundary, pinned by
      `run065_immediate_revocation_preserved_on_signed_mainnet`).
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
- [ ] If a SCHEDULED revocation entry is being introduced
      (`activation_height` set in the future), a pending-revocation
      smoke passes: the live binary reports the entry on the
      `_revocations_*_pending` gauge AND on the `Run 062: …
      pending=…` log line, AND neither the Run 061 nor the Run 063
      local startup self-check fires (RUN_062 Smokes 1/3 shape).
- [ ] If a leaf revocation is intended to be ACTIVE on a validator
      that currently uses that leaf, a Run 061 local-leaf
      startup self-check FATAL smoke passes (RUN_061 Smoke 2 shape).
- [ ] If a root revocation is intended to be ACTIVE on a validator
      whose local leaf is chained to that root, a Run 063
      local-issuer-root startup self-check FATAL smoke passes
      (RUN_063 Smoke 2 shape).
- [ ] On a clean test validator, the live binary prints the Run
      050/051/053/055/057/062/061/063 banners (in the order the
      binary emits them) with the expected fingerprints
      and ends with the Run 040 `[Run040] P2pNodeBuilder: ...
      dummy_kem_registered=false dummy_aead_registered=false ...`
      banner — confirming no fallback to test-grade primitives.
      On a too-soon TestNet/MainNet bundle the binary instead
      emits the Run 065 FATAL `pqc trust-bundle minimum
      activation-height policy violation` and exits 1 BEFORE any
      of the post-load banners.
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
      workflows (§6.B, §6.D, §6.C). Decide explicitly whether the
      revocation is root-level or leaf-level, and whether it must
      be immediate or scheduled (§6.E). Compromise revocations
      MUST be immediate.
- [ ] Identify, for each candidate revocation entry, what
      `activation_height` (if any) is appropriate. For an
      emergency compromise event the answer is "none / immediate"
      (`activation_height = None`); per-entry `activation_height
      = None` is the only way to publish an immediate revocation
      on TestNet/MainNet within the Run 065 minimum-margin policy
      (any `Some(h)` with `h` in the half-open reject window is
      refused at load). Distinguish a planned scheduled revocation
      (`activation_height = Some(h)`, `h >= current_height +
      minimum_activation_margin`) from an emergency immediate
      revocation (`activation_height = None`); they are not
      interchangeable.
- [ ] Confirm the liveness impact BEFORE publishing an immediate
      root revocation: every validator whose local
      `--p2p-leaf-cert` is chained to the revoked root will fail
      closed at next restart (Run 063 startup self-check) and
      every handshake to that validator will fail closed (Run 050
      / Run 052 peer-handshake context). If a non-trivial
      fraction of validators are in that set, the validator drop-
      out is the correct fail-closed behaviour but it must be a
      conscious operator decision.
- [ ] If a root revocation is being scheduled (not immediate),
      confirm every affected validator has a replacement leaf
      cert chained to a non-revoked root deployed on disk BEFORE
      the entry's `activation_height` is reached. The Run 065
      minimum margin on TestNet (8 blocks) and MainNet (32
      blocks) is a hard floor, not a sufficient operator window —
      operators SHOULD use a comfortably larger margin when the
      replacement-cert distribution is operator-bound.
- [ ] Identify which validators will fail closed at startup once
      the revocation activates. For a leaf revocation: validators
      whose local `--p2p-leaf-cert` matches the revoked
      fingerprint will trip the Run 061 self-check. For a root
      revocation: validators whose local leaf cert is issued by
      the revoked root will trip the Run 063 self-check. Confirm
      that any validator that MUST stay alive has a replacement
      credential ready BEFORE the entry becomes active.
- [ ] Mint replacement material on a clean offline / HSM host
      (§4).
- [ ] Mint an `(N+1)` bundle that excludes the compromised
      material. For an emergency compromise the per-entry
      revocation MUST carry `activation_height = None` (immediate;
      exempt from Run 065). The bundle-level `activation_height`
      SHOULD be omitted (no restriction) for the fastest emergency
      rotation; if set on TestNet/MainNet it MUST satisfy the
      Run 065 minimum margin (`>= current_height + 8` on TestNet,
      `+ 32` on MainNet) or the bundle is rejected at load.
      Sign with the currently-trusted bundle-signing authority.
- [ ] Distribute the new bundle out-of-band on the same channel
      as steady-state bundles.
- [ ] Confirm every validator reports `qbind_p2p_pqc_trust_bundle_sequence_highest`
      = `N+1` on `/metrics`.
- [ ] Confirm `qbind_p2p_pqc_trust_bundle_signature_rejected_total`
      stays 0 on every validator after the change.
- [ ] Confirm the Run 062 revocation banner shows
      `active=K pending=0` for the compromise entry on every
      validator (i.e. no validator silently treats the compromise
      revocation as pending due to a stale runtime height source).
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
      printed the Run 050/051/053/055/057 banners, the Run 062
      `[binary] Run 062: trust-bundle revocation activation
      (configured=… active=… pending=…)` banner, the Run 061
      `local-leaf startup self-check passed` line (when a
      `--p2p-leaf-cert` is supplied), the Run 063 `local-leaf
      issuer-root startup self-check passed` line, and the Run 040
      `dummy_kem_registered=false dummy_aead_registered=false`
      banner; `/metrics` reports the expected
      `qbind_p2p_pqc_trust_bundle_*` series, including the seven
      Run 062 `_revocations_*` gauges.
- [ ] Negative tamper smoke transcript (RUN_059 Smoke 3 shape).
- [ ] Wrong-chain smoke transcript (RUN_059 Smoke 5 shape).
- [ ] Rollback smoke transcript (RUN_056 Smoke 3 shape).
- [ ] If a root was revoked (immediate): revoked-root smoke
      (RUN_050 / RUN_062 Smoke 4 shape; expects the Run 050
      "no trusted roots" FATAL if all roots are revoked, or
      successful exclusion from `active_roots` otherwise).
- [ ] If a leaf was revoked (immediate): revoked-leaf smoke
      (RUN_054 / RUN_062 Smoke 2 shape) AND a Run 061 local-leaf
      startup self-check FATAL transcript on the validator that
      still uses that leaf (RUN_061 Smoke 2 shape).
- [ ] If a root revocation is intended to affect a validator
      whose local leaf was issued by that root: a Run 063
      local-issuer-root startup self-check FATAL transcript
      (RUN_063 Smoke 2 shape).
- [ ] If any revocation is SCHEDULED (`activation_height` set):
      a pending-revocation smoke transcript (RUN_062 Smoke 1 for
      leaf-scope OR Smoke 3 for root-scope) — exit non-FATAL, the
      `_revocations_*_pending` gauge shows the entry, and NEITHER
      the Run 061 nor the Run 063 startup self-check fires.
- [ ] If the bundle targets TestNet or MainNet: a Run 065 too-soon
      negative smoke transcript (RUN_065 Smoke 2 shape for
      TestNet, Smoke 4 shape for MainNet) — exit 1; the FATAL
      contains `pqc trust-bundle minimum activation-height policy
      violation (scope=bundle, environment=<env>, current_height=<h>,
      activation_height=<a>, minimum_margin=<8|32>,
      required_min_height=<h+margin>)`; the explicit "No fallback
      to --p2p-trusted-root" marker; AND a filesystem check
      confirming `pqc_trust_bundle_sequence.json` is NOT present
      under the `--data-dir` (i.e. the rejected bundle did not
      touch the loader outcome).
- [ ] Sufficient-margin / Run-057 boundary smoke transcript
      (RUN_065 Smoke 3 shape for TestNet at `activation_height =
      current + 8`, OR RUN_065 Smoke 5 shape for MainNet at
      `activation_height = current + 32`) — exit 1; the FATAL
      contains Run 057's `activation height not yet reached
      (scope=bundle, current_height=<h>, required_height=<h+margin>)`,
      NOT the Run 065 marker phrase. This proves Run 065 passed
      at the inclusive upper boundary and Run 057 took over.
- [ ] If a SCHEDULED revocation with `activation_height = Some(h)`
      is being introduced on TestNet/MainNet: confirmation that
      `h >= current_height + minimum_activation_margin` was used
      (otherwise the bundle would have been rejected at load with
      `RevocationActivationHeightBelowMinimumMargin`).
- [ ] Confirmation that no `--p2p-trusted-root` line was supplied
      on any validator.
- [ ] Confirmation that `pqc_root_mode=pqc-static-root` and no
      `Dummy*` is registered on every validator (Run 040 banner).
- [ ] Release binary identity: `sha256` and `ELF BuildID` of the
      `qbind-node` binary that ran the smokes.

---

## 10. Residual risks (NOT solved by this runbook)

This runbook narrows the C4 "production CA / certificate rotation
/ signing-key rotation operator playbook" item; Runs 061–063
closed three previously-open boundaries (local-leaf-fingerprint
startup self-check, per-entry revocation `activation_height`, and
local-issuer-root startup self-check); and Run 065 closed the
per-environment minimum-activation-margin boundary on the binary
`--p2p-trust-bundle` load path. The following remain open under C4:

1. **Epoch-gating runtime source.** Bundle-level `activation_epoch`
   continues to fail closed with
   `TrustBundleActivationError::CurrentEpochUnavailable` (Run 057).
   Per-entry `activation_epoch` on revocations is intentionally
   NOT supported either (Run 062 boundary). Operators MUST NOT
   set `activation_epoch` on production bundles or on revocation
   entries. Run 065 does NOT introduce a minimum-margin policy on
   the epoch axis (the epoch runtime source itself remains open).
2. **Per-environment minimum activation-margin policy on the
   gossiped / peer-supplied trust-bundle path.** Run 065 enforces
   the policy at
   `pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
   — the path the binary uses for `--p2p-trust-bundle`. The
   bundle is not currently gossiped between peers (operator-
   distributed); when on-the-fly trust-bundle distribution lands,
   the same `pqc_trust_activation::check_min_activation_height_policy`
   helper must be threaded through that path.
3. **On-the-fly trust-bundle hot reload.** The bundle is loaded
   exactly once per process lifetime. The Run 062 active/pending
   gauges are sticky-at-startup snapshots; a scheduled revocation
   does NOT transition from PENDING to ACTIVE inside a running
   validator without a restart. The Run 061 and Run 063 startup
   self-checks therefore observe only the trust state present at
   process boot, and the Run 065 policy fires at that single load.
4. **Production fast-sync / consensus-storage restore.** Separate
   C4 piece; trust-bundle persistence is independent. The
   `--restore-from-snapshot` `snapshot_height` already feeds the
   Run 057 + Run 065 `current_height` source via
   `ActivationContext::height_only`; a fully-fledged production
   fast-sync surface is a separate boundary.
5. **Per-environment production trust-anchor operation.** Not
   fully solved by documentation alone; depends on the operator
   actually using offline / HSM custody for the secrets in §3.2
   and §3.4.
6. **In-binary / on-chain bundle-signing-key rotation /
   ratification.** The binary does NOT ratify a new bundle-signing
   key on-chain or in-binary. §6.D is an out-of-band CLI overlap
   procedure. If a future runtime adds on-chain ratification,
   this runbook MUST be updated.
7. **Two-node / N-node MainNet release-binary peer-connection
   smoke evidence.** RUN_059 produced a single-validator MainNet
   release-binary smoke; a multi-validator MainNet
   peer-connection smoke remains on the C4 list (blocked by
   unrelated production-config items — validator keystore loading
   on startup, per-peer consensus-key distribution).
8. **External KMS / HSM integration.** This runbook treats the
   signing-key custody surface as an interface boundary; full
   KMS integration is not in scope.

**Closed by Runs 061–063 and Run 065 (no longer in §10):**

- Local-leaf-fingerprint startup self-check — closed by Run 061
  (`pqc_trust_bundle::check_local_leaf_not_revoked` + the FATAL
  call site in `main.rs`). The binary now fails closed at startup
  if `--p2p-leaf-cert`'s canonical fingerprint is in the
  bundle's active `revoked_leaf_fingerprints`.
- Per-entry revocation activation gate — closed by Run 062
  (optional, ML-DSA-44-signature-covered `activation_height` on
  every revocation entry; deterministic active/pending split;
  seven new `qbind_p2p_pqc_trust_bundle_revocations_*` gauges).
- Local-issuer-root startup self-check — closed by Run 063
  (`pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked` +
  the FATAL call site immediately after Run 061). The binary now
  fails closed at startup if the local leaf cert decodes to a
  `root_key_id` in the bundle's active `revoked_root_ids`.
- Per-environment minimum activation-margin policy on the binary
  `--p2p-trust-bundle` load path — closed by Run 065
  (`pqc_trust_activation::check_min_activation_height_policy` +
  `MIN_{DEVNET,TESTNET,MAINNET}_ACTIVATION_MARGIN` constants
  (`0` / `8` / `32`)). The binary now fails closed at load if a
  bundle's `activation_height` (bundle-level, per-active-root, or
  per-entry revocation when `Some(_)`) is in the half-open reject
  window `[current_height, current_height + margin)` on the
  configured environment. Emergency immediate revocations
  (`activation_height = None`) remain exempt.

**Full C4 remains OPEN. C5 is NOT closed by this runbook.**

---

## 11. Mapping to Runs 050–065

| Run | What it proved | What §section of this runbook relies on it |
|---|---|---|
| 050 | Structured bundle schema, environment + chain_id + validity + revocation fail-closed boundaries. | §1.3, §3.7, §5.1–5.3, §6.A, §7. |
| 051 | ML-DSA-44 signed-bundle verification; signing-key/root-id collision check. | §1.3, §2.2, §3.3, §4.2, §6.D, §7. |
| 052 | Leaf-level revocation; listener-side fail-closed on revoked-leaf handshake. | §3.6, §3.9, §6.C, §7, §9. |
| 053 | `chain_id` crosscheck at bundle load (before signature side-effects). | §1.3, §3.11, §5.2, §5.3, §7. |
| 054 | Release-binary leaf-revocation evidence helper modes. | §3.9, §6.C, §7, §9. |
| 055 | Sequence anti-rollback persistence (rollback, equivocation, corrupt-file fail-closed). | §1.3, §3.8, §6.A, §6.B, §6.D, §7. |
| 056 | Release-binary anti-rollback evidence (positive upgrade, rollback, equal-sequence different-fp, corrupt persistence). | §3.8, §6.A, §7. |
| 057 | Bundle-level activation-height gating (`current_height` source from restore baseline or 0; future activation does NOT advance persisted sequence). | §1.3, §3.10, §6.A, §6.E, §7. |
| 058 | Release-binary activation-height evidence (positive active-now, negative future-height, positive upgrade-after-rejection). | §3.10, §6.A, §7. |
| 059 | MainNet signed-bundle release-binary smoke (positive, unsigned, tampered, wrong key, wrong chain). | §1.3, §5.3, §7, §9. |
| 060 | Operator playbook landed (this runbook). | All §sections. |
| 061 | Local-leaf-fingerprint startup self-check: binary fails closed before P2P startup if `--p2p-leaf-cert` is in the bundle's active `revoked_leaf_fingerprints`. | §1.3, §3.9, §6.C variant 2, §7, §9, §10 (closed item). |
| 062 | Per-entry revocation `activation_height`: signature-covered, active/pending split, seven new `qbind_p2p_pqc_trust_bundle_revocations_*` gauges. | §1.3, §3.9, §3.10, §6.A, §6.B, §6.C, §6.E, §7, §9, §10 (closed item). |
| 063 | Local-issuer-root startup self-check: binary fails closed before P2P startup if the local leaf cert decodes to a `root_key_id` in the bundle's active `revoked_root_ids`. Independent of Run 061. | §1.3, §6.A, §6.B, §6.E, §7, §9, §10 (closed item). |
| 064 | Operator-playbook prose update for Runs 061–063 (docs-only). | All §sections. |
| 065 | Per-environment minimum activation-margin policy on the `--p2p-trust-bundle` load path: `MIN_DEVNET_ACTIVATION_MARGIN = 0`, `MIN_TESTNET_ACTIVATION_MARGIN = 8`, `MIN_MAINNET_ACTIVATION_MARGIN = 32`. Half-open `[current_height, current_height + margin)` reject window covers bundle-level, per-active-root, and per-entry revocation `activation_height` when `Some(_)`. Already-effective bundles are NOT retroactively rejected (snapshot-rejoin). Per-entry revocations with `activation_height = None` are immediate and exempt (emergency-revocation path preserved on MainNet). Policy runs BEFORE Run 057's future-height gate, Run 055's sequence persistence, and Run 050's root merge — rejected too-soon bundles do not touch the persisted sequence or the live trust set. Proved on the live release binary by RUN_065 Smokes 1 (DevNet positive at activation_height=0), 2 (TestNet too-soon negative, Run 065 fires), 3 (TestNet at-margin = Run 057 boundary), 4 (MainNet too-soon negative, Run 065 fires with margin=32), 5 (MainNet at-margin = Run 057 boundary with required_height=32). | §1.3, §3.9, §3.10, §5.1, §5.2, §5.3, §6.A, §6.B, §6.E, §7, §8, §9, §10 (closed item). |
| 066 | Operator-playbook prose update for Run 065 (docs-only). | All §sections. |
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