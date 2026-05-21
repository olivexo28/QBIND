# QBIND Trust-Anchor Authority and Bundle-Signing-Key Ratification Model

**Run:** 100
**Status:** Design / specification only. No runtime behavior change.
**Date:** 2026-05-21
**Scope:** Production-grade authority and ratification model for PQC trust
anchors and bundle-signing keys across DevNet, TestNet, and MainNet.

This document is **spec-first**. It defines how QBIND will decide which
bundle-signing keys and trust-anchor authorities are valid, how they are
established at genesis, how they are ratified, rotated, and revoked, and how
DevNet / TestNet / MainNet differ. It does **not** implement any of that
behavior. The strict non-goals enumerated at the end of §1 are binding on this
document.

This document is the canonical companion to:

- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` (Run 087 —
  future peer-driven propagation/apply gates).
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Runs 050–097 trust-bundle
  operator lifecycle).
- `docs/whitepaper/contradiction.md` (C4 / C5 tracking).

When this document and any of the above disagree, the trust-bundle binary in
`crates/qbind-node` wins; the conflicting document is a defect. Any
contradictions found while writing this document are recorded in
`docs/whitepaper/contradiction.md` Run 100 update.

---

## 1. Scope and non-goals

### 1.1 In scope

1. How initial trust anchors are established at genesis.
2. How genesis trust-anchor authority is cryptographically bound at boot.
3. How bundle-signing keys are ratified.
4. How bundle-signing keys rotate.
5. How bundle-signing keys are revoked (planned and emergency).
6. How DevNet, TestNet, and MainNet differ in policy.
7. What nodes MUST refuse in each environment.
8. What anti-rollback rules apply to authority state.
9. What persistence and recovery semantics are required before implementation.
10. What future implementation runs MUST satisfy.

### 1.2 Strict non-goals for Run 100

Run 100 MUST NOT:

- implement peer-driven live apply;
- implement a bundle-signing-key ratification verifier;
- implement KMS/HSM custody;
- implement governance;
- implement validator-set rotation;
- implement on-chain ratification;
- change the trust-bundle wire format;
- change the peer-candidate wire format;
- change consensus or KEMTLS;
- change `activation_epoch` semantics;
- add production static root anchors as source-code constants;
- add fallback roots or fallback signing keys;
- weaken any existing signed-bundle verification, chain_id enforcement,
  environment enforcement, sequence anti-rollback, activation-height check,
  `activation_epoch` check, Run 065 minimum-margin policy, revocation check,
  reload-check non-mutation discipline, or reload-apply ordering;
- claim full C4 closure or any C5 closure.

### 1.3 Architectural decision (binding for all future runs)

Initial production authority is established by a **genesis configuration file
bound by a boot-time cryptographic hash**, NOT by Rust source-code constants.

Allowed:

- Test-only / dev-only static constants behind explicit non-production gates
  (existing `make_test_crypto_provider`, `DummySig`/`DummyKem`/`DummyAead`
  registration sites that are MainNet/TestNet-refused today).
- Examples and fixtures for tests.
- Documented DevNet local shortcuts that are explicit (no silent fallback).

Not allowed:

- MainNet production root anchors hard-coded in Rust source as authoritative
  constants.
- Hidden fallback anchors compiled into the binary.
- Implicit trust roots outside genesis / config.
- Environment-ambiguous root anchors (e.g., one constant that applies to all
  environments without explicit binding).

The canonical authority root is the genesis configuration. Bundle-signing
authority is in turn derived from that root and ratified per §5.

---

## 2. Threat model

A future authority / ratification design MUST treat the following as in scope:

- **Malicious bundle signer.** A signing key holder publishes a signature-
  valid but operationally invalid (e.g., wrong-chain, wrong-environment,
  rollback, equivocation, premature activation, or revocation-bypass) bundle.
- **Compromised bundle-signing key.** A previously authorized signing key is
  exfiltrated or coerced; an adversary forges arbitrary bundles under that
  key.
- **Compromised or stale genesis config.** An operator boots against the wrong
  genesis bytes; a stale genesis file is restored from backup; a malicious
  CDN serves a tampered genesis file.
- **Wrong-chain authority reuse.** An authority object from chain A is
  presented to a node on chain B.
- **Wrong-environment authority reuse.** A DevNet authority is presented to a
  MainNet node.
- **Rollback to old authority.** An attacker (or operator error) attempts to
  install an older authority sequence after a newer one was accepted.
- **Snapshot restore rollback.** A node restored from an older snapshot rolls
  the local authority state backwards.
- **Peer-gossiped unratified authority.** A peer publishes a candidate
  signed by a key whose ratification cannot be proven against the local
  genesis-bound authority root.
- **Operator misconfiguration.** Two operators distribute disagreeing
  authority claims; a single operator sets the wrong `--p2p-trust-bundle-
  signing-key` value; a release-binary smoke leaks DevNet shortcuts into a
  MainNet `--data-dir`.
- **Partitioned authority updates.** A network partition causes part of the
  network to accept a new authority while the other part does not.
- **Emergency revocation abuse.** An adversary triggers an unwarranted
  emergency revocation to disable a legitimate signing key, or replays an old
  emergency revocation after the affected key has been retired.
- **Static source-code anchor drift.** A future code change accidentally
  reintroduces a hard-coded production anchor or a hidden fallback path; or a
  pre-existing test-only constant becomes reachable on a production runtime
  branch.
- **Dev/test shortcuts leaking into MainNet.** A DevNet helper file
  (helper-generated signing key, helper-generated trust-bundle, helper-
  generated root) is accidentally loaded with `--env mainnet`.

The minimum threat model from
`docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` §2 also applies
verbatim and is not duplicated here.

---

## 3. Trust assumptions

The model assumes — and any future implementation MUST enforce or document —
the following:

1. **Genesis file integrity is operator-bound.** Operators receive the
   genesis file through an out-of-band trusted channel and are expected to
   compare its hash against the expected genesis hash before boot.
2. **Boot-time hash binding.** The binary computes the canonical genesis
   hash from the loaded bytes and compares it to an operator-supplied
   expected hash (CLI flag or pinned in `NodeConfig`); a mismatch is
   fail-closed at boot, before any P2P / consensus / trust-bundle activity.
3. **Authority roots are bound to `chain_id` and `environment`.** A genesis
   that declares `chain_id = qbind-mainnet-v0` MUST NOT be loaded with
   `--env devnet`, and vice versa. Both fields participate in the canonical
   genesis hash preimage.
4. **Local CLI configuration alone is not sufficient on MainNet.** On
   MainNet, the `--p2p-trust-bundle-signing-key` set MUST be derived from
   (or cryptographically chained to) the genesis-bound authority root. A
   key that is operator-supplied but not provably authorized by the
   genesis-bound authority MUST be rejected on MainNet.
5. **Peers are advisory only.** The current Run 076 / Run 078 / Run 088
   peer-candidate validation-only and propagation-only paths remain
   validation-only. Peer authority claims do not bypass ratification.
6. **Operator approval does not replace cryptographic ratification on
   MainNet.** Local-operator-triggered SIGHUP reload (Run 074), reload-apply
   (Run 073), or peer-candidate matrix (Runs 081–085) MUST refuse to apply
   a bundle signed by an unratified signing key on MainNet.
7. **KMS/HSM custody is future work, not assumed complete.** The model
   defines the surface where KMS/HSM custody plugs in; it does not assume
   any specific KMS/HSM implementation.

---

## 4. Current state (investigation)

This section records the pre-Run-100 state of every authority-relevant
surface, so future implementation runs can reason about deltas.

### 4.1 Current trust-anchor inputs

Every current source of trust-anchor authority on the production binary:

| # | Source | Production-intended? | Production semantics today |
|---|--------|---------------------|----------------------------|
| 1 | `--p2p-trust-bundle <PATH>` | Yes (TestNet/MainNet) | Loaded by `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`; environment, chain_id, validity-window, revocation, signing-key verification, Run 065 minimum-margin, Run 057 activation-height, and Run 055 sequence-anti-rollback all run BEFORE roots merge into `trusted_roots`. |
| 2 | `--p2p-trusted-root ROOTID:100:HEXPK` | DevNet shortcut only | Refused at startup on TestNet/MainNet when combined with `--p2p-trust-bundle`; never silently substituted on failure of (1) (the binary's FATAL line explicitly ends with `No fallback to --p2p-trusted-root on bundle failure`). |
| 3 | Signed trust-bundle `roots[*]` | Yes | Merged into the live `LivePqcTrustState` snapshot only after (1) passes. |
| 4 | Local static-root test/dev config | Dev/test only | `make_test_crypto_provider` path; statically unreachable when `pqc_active==true`; refused at top of `main.rs` on Mainnet/Testnet. |
| 5 | DevNet helper-generated roots (`crates/qbind-node/examples/devnet_pqc_root_helper.rs`, `devnet_pqc_trust_bundle_helper.rs`) | DevNet/TestNet/MainNet helpers; **NOT** production custody | Helpers mint ephemeral in-memory keys for evidence runs only. **Helper outputs are NOT a production authority source today.** |
| 6 | Peer-candidate `0x05` bundle roots (Runs 076 / 078 / 079) | Validation-only today | Routed through the same Run 050/051/053/057/065 startup pipeline; receiver is end-of-line. No live mutation, no sequence write, no session eviction. Per Run 088 propagation-only path, may be rebroadcast (validation-before-rebroadcast) but never applied. |
| 7 | Reload-check / reload-apply / SIGHUP live reload (Runs 069 / 070 / 073 / 074) | Yes (local operator) | Local-file paths. Reload-check is non-mutating. Reload-apply / SIGHUP follow the strict Run 070 `validate → snapshot → swap → evict → commit` ordering. No peer source today. |
| 8 | Genesis references to root anchors | **None today** | The `qbind-ledger` `GenesisConfig` (`crates/qbind-ledger/src/genesis.rs::GenesisConfig`) carries `chain_id`, `genesis_time_unix_ms`, `allocations`, `validators`, `council`, `monetary`, and `extra`. It does **not** carry PQC transport trust anchors or a bundle-signing authority root today. This is the additive gap §6 specifies. |
| 9 | Hard-coded / test fixture roots | None on production paths | None compiled in as authoritative MainNet constants. Test fixtures live under `crates/qbind-node/examples/**` and `crates/**/tests/**` only and are statically unreachable on the production startup path. |

**Production-intended:** (1), (3), (6) (validation/propagation-only), (7) (local operator). All other entries are dev/test or absent.

### 4.2 Current bundle-signing-key authority

Currently a trust-bundle is authenticated by:

- **Configured signing-key set** via repeatable `--p2p-trust-bundle-signing-key KEYID:100:HEXPK`.
- **Helper-generated signing keys** for DevNet evidence runs (`crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`).
- **Environment / chain-id binding**: `environment` and `chain_id` are part of the canonical signing preimage and the canonical fingerprint
  (`pqc_trust_bundle::canonical_signing_bytes`, `canonical_fingerprint`).
- **Signature verification preimage**: a deterministic canonical-bytes
  encoding covering version, environment, chain_id, sequence, valid_from,
  valid_until, every active root, every revocation, every signing-key
  fingerprint, and the bundle-level `activation_height` /
  `activation_epoch`.
- **Sequence anti-rollback**: Run 055 persistence at `<data_dir>/pqc_trust_bundle_sequence.json` (record_version, environment, chain_id, highest_sequence, bundle_fingerprint).
- **Activation-height / `activation_epoch` checks**: Run 057 enforces
  `activation_height`; Run 091/092 keeps `activation_epoch` fail-closed via
  `CurrentEpochUnavailable` until the Run 098 wiring lands `current_epoch`
  from the canonical `<data_dir>/consensus :: meta:current_epoch` source.
- **Revocation checks**: bundle-level `revocations[*]`, per-active-root
  `revoked_root_ids`, Run 062 per-entry revocation `activation_height`
  (active vs pending split), and Run 052 leaf-fingerprint revocation.

**The current gap (the gap Run 100 specifies how to close).** A bundle may
be signature-valid under a locally configured signing key, but the
production system today has **no formal ratification source that proves
the signing key is authorized by genesis or governance authority**. The
operator is implicitly trusted to have configured the correct signing key
set out-of-band. On MainNet this is not strong enough.

### 4.3 Genesis configuration surface (where future authority fields plug in)

| Item | Today |
|------|-------|
| Where genesis is loaded | `--genesis-path <PATH>` (CLI flag in `crates/qbind-node/src/cli.rs::CliArgs::genesis_path`; threads through `NodeConfig::genesis_source.genesis_path` at `crates/qbind-node/src/node_config.rs:2528`). MainNet REQUIRES `genesis_path` to be set (`node_config.rs:2608-2609`). |
| How `chain_id` is represented | `GenesisConfig::chain_id: String` (e.g., `"qbind-mainnet-v0"`, `"qbind-testnet-beta"`) at `crates/qbind-ledger/src/genesis.rs:453`. Embedded in domain-separated signatures across the codebase. |
| Whether genesis hash already exists | YES — `crates/qbind-ledger/src/genesis.rs::compute_genesis_hash_bytes`, `format_genesis_hash`, `parse_genesis_hash` are already defined. `ChainMeta` already binds `(chain_id, genesis_hash)` (`genesis.rs:855-873`). |
| Whether validators are bound to genesis | YES — `GenesisConfig::validators: Vec<GenesisValidator>` (`genesis.rs:471`). |
| Whether PQC trust anchors are in genesis | **NO**. |
| Whether bundle-signing authority is in genesis | **NO**. |
| What additive fields are needed later | See §6. |

The genesis surface is structurally ready for additive authority fields
(serde forwards-compatible via `#[serde(default)]` and the existing
`GenesisConfig::extra: serde_json::Value` placeholder). Run 100 does NOT
add any of those fields. Run 101 will.

### 4.4 Environment model recap (operational policy today)

DevNet, TestNet, and MainNet are already separated by:

- `--env devnet|testnet|mainnet` (top-level flag).
- Per-environment minimum activation margin (Run 065:
  `MIN_DEVNET_ACTIVATION_MARGIN = 0`, `MIN_TESTNET = 8`, `MIN_MAINNET = 32`).
- MainNet refusal of `--p2p-pqc-root-mode test-grade-dummy-sig` and of
  `--p2p-trusted-root` combined with `--p2p-trust-bundle`.
- MainNet refusal of `--devnet-reconfig-proposal-next-epoch` (Run 096).
- Production-honest binary refuses `pqc_active == false` on MainNet/TestNet.

This document extends that policy to authority and ratification (§7).

---

## 5. Bundle-signing-key ratification model (specification)

The ratification model defines, in the abstract, **what must be true on disk
and in memory before a bundle-signing key is considered authorized to sign
bundles for a given environment, chain, and authority epoch**.

### 5.1 Ratification object (future on-disk / on-chain shape)

A ratification is a typed, signed, deterministically-encoded object. The
following fields are normative for future implementation:

| Field | Type | Purpose |
|-------|------|---------|
| `version` | `u16` | Schema version; current spec defines `1`. |
| `chain_id` | string | MUST equal the receiver's runtime chain id. |
| `environment` | enum `{DevNet, TestNet, MainNet}` | MUST equal the receiver's runtime environment. |
| `genesis_hash` | 32 bytes | MUST equal the receiver's canonical genesis hash. |
| `authority_epoch` | `u64` | Monotonic counter, strictly increasing per `(chain_id, environment, genesis_hash)`. |
| `bundle_signing_public_key` | bytes | The newly-authorized signing key's canonical bytes. |
| `bundle_signing_public_key_fingerprint` | 32 bytes | Deterministic fingerprint (BLAKE3 or SHA3-256) over the canonical key bytes; redundant with the key but enables fast operator inspection. |
| `signature_suite_id` | `u16` | Suite identifier for the *signing key being ratified* (e.g., `100` = ML-DSA-44). PQC-only; suite-agile. |
| `activation_height` | `Option<u64>` | Earliest height at which bundles signed by this key may be applied. `None` = effective at activation_epoch only. |
| `activation_epoch` | `Option<u64>` | Earliest epoch at which bundles signed by this key may be applied. `None` = effective at activation_height only. At least one of `activation_height` / `activation_epoch` MUST be `Some`. |
| `valid_from_unix_secs` | `u64` | Wall-clock validity-window start (operator-visible only; NOT used in fail-closed checks). |
| `valid_until_unix_secs` | `u64` | Wall-clock validity-window end (operator-visible only; NOT used in fail-closed checks). |
| `expiration_epoch` | `Option<u64>` | Optional hard expiration in epochs; after this epoch the key MUST be refused even if not explicitly revoked. |
| `revocation_status` | enum `{Active, Retired, Revoked, EmergencyRevoked}` | Stamped on the ratification at issuance time; may be flipped by a later revocation ratification of higher `authority_epoch`. |
| `issuer_authority` | enum `{GenesisBound, OnChainGovernance, EmergencyCouncil}` | Authority class that issued this ratification. |
| `issuer_authority_proof` | bytes | Authority-class-specific proof (e.g., genesis-bound signature, on-chain governance receipt root, emergency-council multisig). |
| `issuer_signature_suite_id` | `u16` | Suite identifier for the *issuer's* signature. |
| `issuer_signature` | bytes | Signature by the issuing authority over the canonical signing preimage. |
| `domain_separation_tag` | static string | `"QBIND:BUNDLE_SIGNING_KEY_RATIFICATION:v1"` — included in the signing preimage to prevent cross-protocol replay. |

### 5.2 Canonical signing preimage

The ratification signing preimage is the deterministic byte concatenation of
the domain separation tag followed by the canonical encoding of every field
above EXCEPT `issuer_signature` and EXCEPT any field tagged
"operator-visible only" above. Implementation MUST reuse the existing
`pqc_trust_bundle::canonical_signing_bytes` shape (length-prefixed,
deterministic, PQC-only). Implementation MUST NOT introduce a parallel
canonical-bytes scheme.

### 5.3 Suite agility

`signature_suite_id` and `issuer_signature_suite_id` are PQC-only (e.g.,
ML-DSA-44 = `100`). The model does NOT pick a classical algorithm. The
verifier MUST refuse any non-PQC suite identifier even on DevNet.

### 5.4 Activation semantics

A bundle-signing key K is authorized to sign a bundle B at observation time
T iff **all** of the following hold:

1. There exists a ratification R such that `R.bundle_signing_public_key == K`.
2. `R.chain_id == receiver.chain_id`.
3. `R.environment == receiver.environment`.
4. `R.genesis_hash == receiver.genesis_hash` (the receiver's canonical
   boot-time hash).
5. `R.authority_epoch <= receiver.observed_authority_epoch` (no
   accept-newer-than-locally-observed; this is anti-rollback's converse).
6. `R.revocation_status == Active`.
7. If `R.activation_height.is_some()`, `receiver.current_height >=
   R.activation_height`.
8. If `R.activation_epoch.is_some()`, `receiver.current_epoch ==
   Some(n)` and `n >= R.activation_epoch`. (If
   `receiver.current_epoch == None`, the check is fail-closed exactly the
   way Run 091 / 092 / 098 fail closed on `CurrentEpochUnavailable`.)
9. If `R.expiration_epoch.is_some()`, `receiver.current_epoch <
   R.expiration_epoch`.
10. The verifier successfully verified `R.issuer_signature` against
    `R.issuer_authority_proof` over the canonical signing preimage of R.

If any condition fails, the bundle MUST be refused with a typed error;
the receiver MUST NOT mutate `LivePqcTrustState`, MUST NOT advance the
persisted Run 055 sequence, and MUST NOT call `P2pSessionEvictor`.

### 5.5 Rotation semantics

Rotation is the issuance of a new ratification R' with
`R'.authority_epoch > R.authority_epoch` and a different
`bundle_signing_public_key`. The receiver MUST:

1. Accept R' only when §5.4 conditions 1–10 hold for R'.
2. Persist R' as the active ratification for that `(chain_id, environment,
   genesis_hash)` tuple, advancing the persisted `authority_epoch` monotonically.
3. NOT delete the previous ratification R; instead, mark it `Retired` once
   `R'.activation_height` (or `R'.activation_epoch`) is satisfied, so that
   bundles signed by K continue to verify only up to (but not past) the
   activation boundary of K'.

Operators retain Run 074 SIGHUP and Run 073 reload-apply as the LOCAL
trigger surface for installing R'. There is no peer-driven install in this
spec.

### 5.6 Revocation semantics

Three revocation classes are supported:

| Class | Trigger | Effect |
|-------|---------|--------|
| `Retired` | A higher-epoch ratification supersedes this one and its activation boundary has passed. | The key MAY still verify signatures over bundles whose `activation_height` / `activation_epoch` is strictly below the successor's activation boundary; otherwise refused. |
| `Revoked` | An explicit revocation ratification of higher `authority_epoch` flips `revocation_status` to `Revoked`. | The key MUST be refused for any new bundle. Bundles already applied are NOT retroactively invalidated. |
| `EmergencyRevoked` | An emergency-council ratification per §9. | Same as `Revoked`, but takes effect immediately (no activation margin), at the smallest possible delay (next observation, irrespective of Run 065 per-environment minimum-margin). |

A revocation ratification carries the same shape as a rotation ratification
(§5.1) but with `bundle_signing_public_key` referring to the key being
revoked and `revocation_status` set accordingly.

### 5.7 Expiration semantics (optional)

If `expiration_epoch.is_some()`, the verifier refuses the key once
`receiver.current_epoch >= expiration_epoch` even in the absence of an
explicit revocation. This is operator hygiene against keys whose owners
have rotated out of the operator pool without explicit revocation.

---

## 6. Genesis-bound initial authority (specification)

### 6.1 Required additive genesis fields (future)

A future Run 101 will extend `crates/qbind-ledger/src/genesis.rs::GenesisConfig`
with the following additive fields. All fields are serde-defaulted so that
pre-Run-101 genesis files remain parseable; canonical-bytes derivation MUST
include the fields with their canonical absence encoding (length-prefixed,
not "omit when None") to prevent ambiguity in the hash preimage:

| Field | Type | Purpose |
|-------|------|---------|
| `genesis_pqc_transport_trust_anchors` | `Vec<GenesisTrustAnchor>` (canonical bytes; `(root_id, suite_id, pk_bytes)`) | Initial KEMTLS transport root anchors at genesis. Distinct from bundle-signing keys (the trust-separation invariant from Run 050 applies). |
| `genesis_bundle_signing_authority_root` | `GenesisBundleSigningAuthorityRoot` (`{root_pk_bytes, suite_id, fingerprint, domain_tag}`) | The single canonical root from which all subsequent bundle-signing-key ratifications must chain. |
| `genesis_initial_authority_epoch` | `u64` | Initial value of `authority_epoch` at genesis. Typically `1`. |
| `genesis_initial_bundle_signing_key` | `Option<GenesisInitialSigningKey>` | Optional initial signing key directly authorized at genesis (so the chain can produce signed trust-bundles from height 0); if `Some`, MUST be accompanied by a Run-101 self-ratification embedded in genesis. |
| `genesis_activation_policy` | `GenesisActivationPolicy` | Per-environment minimum activation margins, expiration policy, emergency-council quorum (if any). MUST NOT be operator-mutable post-genesis on MainNet. |
| `genesis_authority_sequence_zero` | `u64` | Initial value of the persisted Run-055-shaped trust-bundle sequence counter; default `0`. |

### 6.2 Canonical serialization requirement

The canonical serialization of `GenesisConfig` is the input to
`compute_genesis_hash_bytes` (already defined at `genesis.rs:753`). Future
runs MUST extend the canonical serializer to include the §6.1 fields in a
deterministic, length-prefixed, key-sorted layout. The hash output is
`GenesisHash` (32 bytes).

### 6.3 Hash binding requirement

At boot, the binary MUST:

1. Load the genesis file from `--genesis-path` (or `NodeConfig.genesis_source.genesis_path`).
2. Compute `actual_genesis_hash = compute_genesis_hash_bytes(canonical_bytes)`.
3. Read `expected_genesis_hash` from an operator-supplied source (CLI flag
   `--expected-genesis-hash <hex>` and/or pinned in `NodeConfig`).
4. Compare `actual == expected`. On mismatch, FATAL exit BEFORE any P2P /
   consensus / trust-bundle / `LivePqcTrustState` initialization.
5. Verify `genesis.chain_id == NodeConfig.chain_id` (already partially in
   place via existing chain_id plumbing).
6. Verify `genesis.environment == NodeConfig.environment`.

### 6.4 Initial authority state derivation

After the §6.3 verification passes, the binary derives:

- `LiveAuthorityState.genesis_hash = actual_genesis_hash`
- `LiveAuthorityState.authority_epoch = genesis.genesis_initial_authority_epoch`
- `LiveAuthorityState.signing_keys = {genesis_initial_bundle_signing_key}` if `Some`, else `{}`.
- `LiveAuthorityState.bundle_signing_authority_root = genesis.genesis_bundle_signing_authority_root`.

This `LiveAuthorityState` is held in an `Arc<RwLock<Arc<...>>>` shaped
analogously to Run 071's `LivePqcTrustState`. It is consulted by every
trust-bundle activation surface (the six from Run 098) before activation
gating runs.

### 6.5 Failure behavior

Every failure in §6.3 / §6.4 is fail-closed at boot, before P2P listener
bind, before consensus loop start, before `LivePqcTrustState` mutation,
and before any sequence file is touched. The FATAL line MUST contain the
stable substring `Run 101` (or whichever run implements the wiring) and
MUST NOT contain `--p2p-trusted-root` (no silent downgrade is possible
from this path because no fallback exists).

### 6.6 Environment separation

A genesis file with `genesis.environment = MainNet` MUST be refused with
`--env devnet` or `--env testnet`, and vice versa. The environment field
participates in the canonical hash preimage, so even bit-for-bit-identical
chain-id genesis files for different environments produce different hashes.

---

## 7. Per-environment policy

### 7.1 DevNet

- MAY allow local operator / helper-generated authority (helper-issued
  ratifications signed under a DevNet-only genesis-bound authority root).
- MAY allow hidden evidence flags (the existing Run 077 / 079 / 080 / 088
  hidden flags continue to behave exactly as they do today).
- MUST still be explicit: no silent fallback from `--p2p-trust-bundle`
  failure to `--p2p-trusted-root`; no implicit DevNet shortcut on a
  non-DevNet environment.
- MAY skip §6.3 expected-hash comparison via an explicit
  `--devnet-skip-expected-genesis-hash-check` flag (refused on
  TestNet/MainNet); MUST log a single banner line if used.

### 7.2 TestNet

- MUST require genesis-bound authority per §6.
- MAY allow staged / pre-ratified governance fixtures (e.g., a TestNet
  multisig council that signs ratifications without on-chain governance).
- MUST reject DevNet-only shortcuts (helper-generated authority,
  `--devnet-skip-expected-genesis-hash-check`,
  `--devnet-reconfig-proposal-next-epoch`).
- MUST honor Run 065 `MIN_TESTNET_ACTIVATION_MARGIN = 8` for authority
  rotation in addition to bundle activation.

### 7.3 MainNet

- MUST require genesis-bound authority per §6.
- MUST require ratification per §5.
- MUST reject local-operator / dev shortcuts in their entirety (no
  helper-issued signing keys, no DevNet-only flags, no
  `--devnet-reconfig-proposal-next-epoch`, no
  `make_test_crypto_provider`, no `DummySig`/`DummyKem`/`DummyAead`
  registration).
- MUST reject unratified bundle-signing keys even when the operator has
  configured them via `--p2p-trust-bundle-signing-key` (the CLI-configured
  set becomes the *candidate* set; ratification chooses the *authorized*
  subset).
- MUST reject fallback static roots (no `--p2p-trusted-root` combined with
  `--p2p-trust-bundle`).
- MUST define emergency paths explicitly via §9.
- MUST honor Run 065 `MIN_MAINNET_ACTIVATION_MARGIN = 32` for authority
  rotation in addition to bundle activation, except for `EmergencyRevoked`
  which is immediate per §5.6 / §9.

---

## 8. Persistence and anti-rollback

### 8.1 Authority-state persistence

A new persisted file MUST be introduced at
`<data_dir>/pqc_authority_state.json` (or co-located with the existing Run
055 `pqc_trust_bundle_sequence.json`). Its record schema is:

| Field | Type | Purpose |
|-------|------|---------|
| `record_version` | `u16` | Schema version. |
| `environment` | string | Receiver's environment (refuses cross-env mount). |
| `chain_id` | string | Receiver's chain id (refuses cross-chain mount). |
| `genesis_hash_hex` | string | Receiver's canonical genesis hash (refuses cross-genesis mount). |
| `highest_authority_epoch` | `u64` | Monotonically non-decreasing. |
| `active_signing_key_fingerprints` | `Vec<String>` | Currently active per §5.4 / §5.5 / §5.6. |
| `retired_signing_key_fingerprints` | `Vec<String>` | Past keys retained for back-verification within their activation window. |
| `revoked_signing_key_fingerprints` | `Vec<String>` | Explicit and emergency revocations. |
| `last_persisted_unix_secs` | `u64` | Audit only. |

### 8.2 Monotonic sequence / epoch

`highest_authority_epoch` is monotonically non-decreasing across reload,
SIGHUP, restart, and snapshot restore. Any attempt to install an
authority object with `authority_epoch < highest_authority_epoch` MUST be
refused with a typed `AuthorityRollbackRefused` error. The error MUST
NOT advance the persisted state.

### 8.3 Crash consistency

The persisted file is written using the same atomic-rename pattern Run
055 uses (write to `<path>.tmp`, fsync, rename, fsync parent). A partial
write leaves the previous record intact. A corruption check at read time
(e.g., embedded SHA-256 of the JSON body, or a wrapping integrity record)
is REQUIRED before the file is trusted to seed `LiveAuthorityState`.

### 8.4 Restore interaction

`apply_snapshot_restore_if_requested` (Run 097's epoch-parity extension)
MUST be paired with an analogous authority-state restore step:

- If the snapshot carries `meta.authority_epoch == Some(n)`, the
  receiver writes `highest_authority_epoch = n` through the same
  `persist_restored_snapshot_*` pattern Run 097 uses for epoch.
- If the existing on-disk `highest_authority_epoch > n`, fail-closed
  with `AuthorityRestoreInconsistent` (no silent downgrade — same shape
  as Run 097's `RestoreEpochInconsistent`).

### 8.5 Snapshot interaction

`StateSnapshotMeta` MUST be extended additively with
`authority_epoch: Option<u64>` and
`authority_state_fingerprint: Option<[u8; 32]>`. Pre-extension snapshots
restore cleanly and leave the persisted authority state at its on-disk
value (NOT silently `0`). This mirrors Run 097's epoch-parity additive
extension.

### 8.6 Failure behavior

Every failure in §8.2 – §8.5 is fail-closed before any apply / mutate /
session-evict step. Rejected authority candidates do NOT advance
`highest_authority_epoch` and do NOT touch
`active_signing_key_fingerprints`.

### 8.7 Interaction with existing anti-rollback machinery

The authority anti-rollback is **independent** of (and additive to):

- Run 055 trust-bundle sequence anti-rollback.
- Run 057 `activation_height` gate.
- Run 091/092/098 `activation_epoch` gate.
- Run 065 per-environment minimum margin.

A bundle MUST pass all of these AND the authority check before being
applied. None of them are weakened by this spec.

---

## 9. Emergency authority model

### 9.1 Who can revoke a compromised bundle-signing key?

Three classes, in order of preference:

1. **Holder of the current authority root.** Issues a §5.6 `Revoked`
   ratification with `authority_epoch = current + 1`, signed by the
   issuer authority. Applied through Run 074 SIGHUP or Run 073 reload-
   apply on every node.
2. **Emergency council multisig** (if defined in
   `GenesisActivationPolicy.emergency_council`). Issues an
   `EmergencyRevoked` ratification, with `issuer_authority =
   EmergencyCouncil` and `issuer_authority_proof = multisig payload`.
   Applied immediately (no Run 065 minimum margin).
3. **Operator-only emergency disablement on DevNet/TestNet** via a
   future explicit flag (NOT introduced today). MUST be refused on
   MainNet.

### 9.2 What if the active signing key is compromised?

The owner of the next ratification (per §9.1 class 1 or 2) MUST issue an
`EmergencyRevoked` ratification AND a new rotation ratification in the
SAME apply step, so that the network is never left without an active
authorized signing key.

### 9.3 What if genesis authority is compromised?

There is no in-protocol recovery from genesis-authority compromise.
Recovery is an out-of-band coordination event requiring a new genesis
file with a new `genesis_hash` and a coordinated operator reboot.
The spec MUST NOT introduce a "rotate genesis authority on the running
chain" surface, because that would create the exact static-source-code
anchor drift this document refuses.

### 9.4 What if nodes are partitioned?

Two partitions may independently accept ratifications up to the same
`authority_epoch`. The anti-rollback rule (§8.2) prevents the
post-partition merge from rolling either side back. If the two
ratifications at the same epoch diverge (different
`bundle_signing_public_key`), the node MUST refuse to install either
silently and surface an `AuthorityEpochEquivocation` operator alert.
Resolution is out-of-band, just as Run 056 equivocation resolution is.

### 9.5 What if a revoked key signs a future-dated bundle?

The bundle is refused because §5.4 condition 1 fails (no Active
ratification for that key). The bundle does NOT advance the Run 055
sequence. The receiver bumps an authority-side counter
(`qbind_p2p_pqc_trust_bundle_authority_refused_total`, future Run 102
metric) and logs once.

### 9.6 What if an old snapshot restores an old signing authority?

The Run 097 epoch-parity pattern is extended to authority-state per §8.4.
A snapshot whose `authority_epoch < current persisted highest_authority_epoch`
fails closed at restore time with `AuthorityRestoreInconsistent`. The
operator MUST take an explicit override action to install a fresh
post-snapshot authority state.

### 9.7 What MUST MainNet refuse?

- A ratification whose `issuer_authority == GenesisBound` but whose
  `issuer_authority_proof` does not chain to the live
  `LiveAuthorityState.bundle_signing_authority_root`.
- A ratification whose `environment != MainNet`.
- A ratification whose `genesis_hash != receiver.genesis_hash`.
- A ratification whose `authority_epoch <= highest_authority_epoch`.
- A ratification whose `issuer_signature` verification fails.
- A ratification whose `signature_suite_id` is not PQC (e.g., classical
  Ed25519, RSA, ECDSA).
- A ratification that has no `activation_height` AND no
  `activation_epoch`.
- A ratification that names a signing key whose suite is not PQC.
- A ratification carried over the wire by a peer that the receiver does
  not separately validate against the local genesis-bound authority
  (peer is advisory only; the wire form does not bypass §5.4).

---

## 10. Peer-driven apply dependency

Peer-driven live apply remains **forbidden** until ALL of the following
exist:

1. Bundle-signing-key ratification verifier (this spec — implementation
   in Run 102).
2. Authority anti-rollback (§8 — implementation in Run 103).
3. KMS/HSM custody assumptions (Run 105) at least defined; full HSM
   integration not required for DevNet/TestNet apply, but defined for
   MainNet.
4. Operator override / emergency controls per §9.
5. Release-binary evidence proving non-mutation / fail-closed boundaries
   across propagation + apply, equivalent to what Run 084 / 085 / 089
   prove for validation-only and propagation-only paths today.

Even when all five exist, peer-driven live apply MUST stay
disabled-by-default and gated by an explicit operator flag, and MUST
inherit the Run 087 propagation/apply safety specification verbatim.

---

## 11. Unsafe designs explicitly rejected

This spec rejects, by construction, the following design directions. A
future implementation that proposes any of them MUST be refused at code
review:

- **Source-code static MainNet anchors.** Introducing a Rust constant
  that compiles authoritative MainNet root bytes into the binary.
- **Hidden fallback anchors.** Any code path that, on failure of the
  genesis-bound load, silently consults a baked-in anchor.
- **Implicit trust roots outside genesis / config.** Any trust source
  not enumerated in §4.1.
- **Peer-provided authority without ratification.** A future code path
  that allows a peer to install an authority object that the receiver
  did not independently verify against the local genesis-bound
  authority.
- **Local config as sole MainNet authority.** A path that treats
  `--p2p-trust-bundle-signing-key` as ratification proof on MainNet.
- **Fallback signing keys.** Any "if no ratified key matches, try this
  static key" behavior.
- **Treating majority gossip as authority.** Any path that lets peer
  vote count substitute for cryptographic ratification.
- **Restoring old authority silently.** Any restore path that
  overwrites `highest_authority_epoch` downward without an explicit
  operator action.
- **Accepting wrong-chain / wrong-environment authority.** Any code
  path that does not bind the authority object to
  `(chain_id, environment, genesis_hash)`.
- **Accepting unratified bundle-signing keys.** On MainNet.
- **Accepting expired / revoked signing keys.** Per §5.6 / §5.7.
- **Classical (non-PQC) signature suites** for any authority surface.

---

## 12. Operational lifecycle (specification)

### 12.1 Bootstrap

1. Operator obtains genesis file out-of-band; verifies hash matches the
   chain's published canonical genesis hash.
2. Operator launches `qbind-node` with `--env <env>`, `--genesis-path
   <PATH>`, `--expected-genesis-hash <hex>`, and the rest of the
   existing trust-bundle / leaf / consensus-key flags.
3. Binary computes actual hash, compares to expected, fails closed on
   mismatch.
4. Binary derives `LiveAuthorityState` from genesis-bound fields (§6.4).
5. Binary loads the operator-supplied `--p2p-trust-bundle` and verifies
   its signature against the genesis-authorized signing key set, in
   addition to all existing Run 050–098 checks.
6. Node starts.

### 12.2 Normal rotation

1. Authority root (or governance) issues a new ratification R' at
   `authority_epoch = current + 1` with a new signing key K'.
2. Operators distribute R' AND a trust-bundle signed by K' (or a
   trust-bundle still signed by K with a higher Run-055 sequence).
3. Each node receives R' through SIGHUP / reload-apply (Runs 073/074
   extended with a future `--p2p-authority-ratification` flag in Run
   102).
4. Node verifies R' per §5.4, persists `highest_authority_epoch =
   current + 1`, swaps `LiveAuthorityState`, and from this point
   refuses bundles signed by K only for `activation_height >
   R'.activation_height` (per §5.5).

### 12.3 Emergency revocation

1. Authority (genesis-bound or emergency council) issues an
   `EmergencyRevoked` ratification.
2. Operators distribute through SIGHUP on every node.
3. Receivers install immediately (no Run 065 minimum margin per §5.6).
4. Bundles signed by the revoked key are refused on the next bundle
   activation surface (startup, reload-check, reload-apply, SIGHUP,
   peer-candidate validation/propagation).

### 12.4 Recovery

1. From corrupted authority-state file: receiver fails closed at
   startup with `AuthorityStateCorrupt`. Operator restores from
   backup; if no backup, restores from the most recent snapshot
   carrying `authority_epoch` per §8.5 and applies any missed
   ratifications via SIGHUP.
2. From compromised genesis authority: out-of-band per §9.3.

### 12.5 Restore

Per §8.4 / §8.5. Atomic with VM-state restore so that authority and VM
state are always consistent.

### 12.6 Audit evidence

A future Run 102 / 103 / 104 MUST produce release-binary evidence per
the shape of the existing Run 056 / 058 / 059 / 084 / 085 / 089
evidence: positive apply, rollback refusal, equivocation refusal,
emergency revocation immediate apply, snapshot-restore parity.

---

## 13. Future implementation plan

Run 100 stages the following dependent runs. Numbering is indicative
and may shift; the staged architecture MUST be preserved.

| Run | Scope |
|-----|-------|
| **Run 101** | Additive genesis-config fields (§6.1) + canonical-serialization extension (§6.2) + boot-time `expected_genesis_hash` comparison (§6.3) + initial `LiveAuthorityState` derivation (§6.4) + fail-closed behavior (§6.5) + environment separation (§6.6). DevNet/TestNet-only at first; MainNet refusal of missing fields lands in this run. |
| **Run 102** | In-binary bundle-signing-key ratification verifier per §5. New persistent file at `<data_dir>/pqc_authority_state.json` per §8.1. New CLI flag for ratification install per §12.2. Six new `qbind_p2p_pqc_trust_bundle_authority_*` counters. |
| **Run 103** | Authority-state persistence and anti-rollback per §8 (full crash consistency, restore interaction, snapshot interaction, `AuthorityRollbackRefused`/`AuthorityStateCorrupt`/`AuthorityRestoreInconsistent` typed errors). |
| **Run 104** | Release-binary signing-key rotation / revocation evidence (N=2 / N=3 DevNet matrix following the Run 084 / 089 shape; N=4 MainNet matrix following the Run 085 shape). Emergency revocation immediate-apply path proven on release binary. |
| **Run 105** | KMS/HSM custody model: define the operator-facing interface, the `Arc<dyn AuthoritySigner>` trait shape, and the per-environment minimum custody policy. May land HSM integration tests but not the production HSM driver. |
| **Run 106+** | Peer-driven apply gates (per §10), in dependency order with the Run 087 propagation/apply safety spec. NOT to be started before Run 102 + Run 103 + Run 104 are positive. |

Future runs MUST update this document only narrowly when implementation
diverges from spec; the spec MUST be updated before implementation if
the divergence is intentional.

---

## 14. Mapping to existing Runs

| Existing Run | Relevance to this spec |
|---|---|
| 050 / 051 / 053 / 055 | Structured bundle schema, signature, chain_id, sequence anti-rollback — Run 100's authority layer is additive to these; none are weakened. |
| 057 / 062 / 065 | `activation_height` + per-entry revocation + Run 065 per-environment minimum margin — apply to authority rotation activation per §5.4 / §7. |
| 069 / 070 / 071 / 072 / 073 / 074 | Local-operator-triggered hot-reload lifecycle — the local install trigger for ratifications per §12.2 lands on this surface in Run 102. |
| 076 / 077 / 078 / 079 / 080 / 084 / 085 / 087 / 088 / 089 | Peer-candidate validation-only and propagation-only paths + the formal propagation/apply safety spec — peer-driven apply remains forbidden per §10. |
| 091 / 092 / 093 / 094 / 095 / 096 / 097 / 098 / 099 | Canonical `<data_dir>/consensus :: meta:current_epoch` lifecycle — provides the `current_epoch` source §5.4 condition 8 consumes (when the activation_epoch axis of authority gating fires). |

---

## 15. Documentation cross-check

This document was cross-checked against:

- `docs/whitepaper/QBIND_WHITEPAPER.md` — no contradiction found; the
  whitepaper does not specify a contrary authority model.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — runbook is operator-
  focused and does not yet describe authority ratification; Run 100
  adds the §13 Run 100 row + Run 100 prose note pointing here.
- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` — Run 087
  spec already says peer authority is advisory; §10 of this document is
  the canonical extension.
- `docs/whitepaper/contradiction.md` — Run 100 update appended.
- `docs/testnet/QBIND_TESTNET_*.md`, `docs/devnet/QBIND_DEVNET_*.md`
  (sampling) — no contradiction with §7 environment policy.

No silent contradictions were ignored. Where existing prose calls the
`--p2p-trust-bundle-signing-key` CLI set "the signing authority", that
phrasing is now understood as "the operator-supplied *candidate* set;
ratification per §5 chooses the *authorized* subset on TestNet/MainNet
once Run 102 lands". The runbook update for Run 100 notes this
narrowing.

---

## 16. Status

- **Run 100 verdict:** positive (design / specification only).
- **Implementation:** none in this run.
- **C4:** narrowed — production trust-anchor authority model and
  bundle-signing-key ratification model now have a formal spec; runtime
  implementation remains future work. Full C4 NOT closed.
- **C5:** unchanged. NOT closed.
- **Peer-driven live apply:** remains forbidden until §10 conditions are
  met.
- **KMS/HSM custody:** remains future work (Run 105).

If anything in this document drifts from the binary's behavior once
Runs 101–106 land, this document is the defect: update this document
before merging the implementation change.
---

## 17. Run 101 update — additive genesis authority fields and canonical
## genesis hash landed (partial implementation of §6)

**Date:** 2026-05-21
**Status:** partial implementation of §6 ("Genesis-bound initial authority")
of this specification; specification text in §1–§16 above is unchanged.

Run 101 implements the **fields and hash** layer of the genesis-bound
authority described in §6, without yet implementing the ratification
verifier (§5), the on-disk `pqc_authority_state.json` persistence (§8
beyond hash binding), the operator override / emergency authority surface
(§9), or any peer-driven apply (§10). Those remain Run 102–106+ scope per
§13 staging.

### 17.1 What Run 101 lands

- `qbind_ledger::genesis::GenesisAuthorityRoot` —
  `{ suite_id, key_fingerprint, label, not_before_epoch }`.
- `qbind_ledger::genesis::GenesisAuthorityConfig` —
  `{ authority_policy_version, authority_sequence, authority_epoch,
     pqc_transport_roots, bundle_signing_authority_roots }`.
- `qbind_ledger::genesis::GenesisConfig.authority:
  Option<GenesisAuthorityConfig>` — additive, backward-compatible via
  `#[serde(default)]`.
- `qbind_ledger::genesis::compute_canonical_genesis_hash(&GenesisConfig,
  env) -> [u8; 32]` with the domain-separation tag
  `b"QBIND:GENESIS:v1"`. Length-prefixed framing of every field;
  optional fields carry an explicit discriminator byte so `None` ≠
  `Some(empty)`. Includes the environment scope (`DEV`/`TST`/`MAIN`),
  the `chain_id`, every allocation/validator/council/monetary field, and
  the full authority block. **Distinct from** the existing T233
  `compute_genesis_hash_bytes` (file-bytes hash), which is kept
  unchanged and continues to back `--expect-genesis-hash`.
- `qbind_ledger::genesis::verify_boot_time_genesis(env, &GenesisConfig,
  Option<&GenesisHash>) -> Result<BootGenesisVerification,
  BootGenesisVerificationError>` — performs structural per-environment
  validation, chain_id ↔ environment binding check, canonical hash
  computation, and (on MainNet) refusal when the expected canonical
  hash is missing or mismatched.
- `qbind_ledger::genesis::GenesisConfig::validate_for_environment(env)`
  — env-aware structural + authority validation.
- Constants: `GENESIS_AUTHORITY_SUITE_ML_DSA_44 = 100`,
  `GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_PROD = 64`,
  `GENESIS_AUTHORITY_POLICY_VERSION_RUN_101 = 1`,
  `CANONICAL_GENESIS_HASH_DOMAIN_V1 = b"QBIND:GENESIS:v1"`.
- 24 unit tests in `crates/qbind-ledger/src/genesis.rs::tests` and 11
  release-binary-facing integration tests in
  `crates/qbind-node/tests/run_101_genesis_authority_tests.rs`.

### 17.2 Per-environment policy as implemented by Run 101

| Environment | `authority` block | Canonical hash flag           | Chain-id check  |
|-------------|-------------------|-------------------------------|-----------------|
| DevNet      | optional (legacy) | optional                      | best-effort     |
| TestNet     | **required**      | strongly recommended          | strict          |
| MainNet     | **required**      | **required (fail-closed)**    | strict          |

MainNet refusals (distinct error variants, no vague messages):
`Missing { env: Mainnet }`, `EmptyBundleSigningRoots`,
`UnsupportedSuite`, `MalformedFingerprint`, `EmptyLabel`,
`EmptyFingerprint`, `DuplicateAuthorityRoot`, `InvalidPolicyVersion`,
`ExpectedCanonicalHashMissing { env: Mainnet }`,
`CanonicalHashMismatch`, `ChainEnvironmentMismatch`.

### 17.3 What Run 101 explicitly does NOT land

(Quoted verbatim from `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md` §7
non-claims):

> Bundle-signing-key ratification verifier (Run 102), signing-key
> rotation, signing-key revocation, authority anti-rollback persistence
> beyond genesis hash binding (no `<data_dir>/pqc_authority_state.json`
> is added — Run 103 scope), KMS/HSM custody (Run 105), peer-driven live
> apply (Run 106+, gated by §10), governance, validator-set rotation,
> production static source-code anchors of any kind, fallback roots or
> fallback signing keys, changes to the trust-bundle or peer-candidate
> wire format, weakening of any Run 050–099 invariant, full C4 closure,
> C5 closure.

### 17.4 Cross-document binding

- Evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md`.
- contradiction tracker: Run 101 update in
  `docs/whitepaper/contradiction.md` — C4 sub-piece
  "genesis-bound authority root surface and boot-time hash binding"
  moves from OPEN to partial-positive; full C4 remains OPEN.
- Runbook: Run 101 row added to
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` §11 mapping with a
  prose note linking to the evidence record.

### 17.5 Why partial-positive and not positive

The `verify_boot_time_genesis` helper is exposed and exercised by tests
through the public API the release binary links against, but the
*single call site* from the release-binary `async_runner` startup
sequence is deferred to Run 102 alongside the ratification verifier
(§13 staging). The existing T233 file-bytes
`MainnetConfigError::ExpectedGenesisHashMissing` CLI-layer refusal
continues to fail closed for MainNet without `--expect-genesis-hash`,
so MainNet operators cannot accidentally start without a hash binding.
Run 102 will move the canonical-hash + authority refusal into the same
pre-network startup point and supersede the file-bytes shield.

If anything in this update drifts from the binary's behaviour once
Run 102 lands, this update is the defect: update it before merging the
Run 102 change.

## 18. Run 102 update — release-binary genesis verification wiring and canonical `--print-genesis-hash` LANDED

Run 102 implements the **release-binary wiring** layer of the
genesis-bound authority surface (§13 staging Run 102, narrowed). It does
not implement signing-key rotation/revocation (§9), the in-binary
bundle-signing-key ratification verifier (deferred to Run 103, see §18.3
below), persistent `<data_dir>/pqc_authority_state.json` (Run 103), or
any peer-driven apply (§10).

### 18.1 What Run 102 lands

- A new `qbind-node` module
  `crates/qbind-node/src/pqc_boot_genesis.rs` exposing
  `run_boot_time_genesis_verification(&NodeConfig) -> Result<…>` which:
  loads `config.genesis_source.genesis_path` as a strict
  `GenesisConfig`, maps `NetworkEnvironment → NetworkEnvironmentPolicy`,
  and delegates to `qbind_ledger::verify_boot_time_genesis(env_policy,
  &cfg, config.expected_genesis_hash.as_ref())`. No defaults are filled,
  no embedded fallback is consulted, no source-code production root
  anchor is referenced.
- A new module function
  `compute_print_genesis_hash(&Path, NetworkEnvironmentPolicy)` powering
  the canonical `--print-genesis-hash` operator surface, which now
  computes the **canonical Run 101 hash over the parsed `GenesisConfig`**
  (not the raw file bytes). The printed value is `0x`-prefixed
  64-char lowercase hex and pasteable verbatim into `--expect-genesis-hash`.
- Two new `main.rs` startup blocks: (a) the `--print-genesis-hash` early
  exit (positioned after `to_node_config` so the printer works for any
  resolved env; refuses with non-zero exit on missing path, malformed
  JSON, or I/O failure); (b) the boot-time genesis verification call
  positioned **after** T185 MainNet invariants and **before** B3 restore,
  Run 069 reload-check, Run 077 peer-candidate check, P2P startup, and
  the binary-path consensus loop. Operator-precise log lines: `[run-102]
  OK: …` on success and `[run-102] FATAL: …` (with a typed reason) on
  refusal.
- Updated `--print-genesis-hash` / `--expect-genesis-hash` help text in
  `crates/qbind-node/src/cli.rs` that explicitly describes canonical
  Run 101 parsed-genesis semantics and that there is no raw-file-byte
  fallback.

### 18.2 Per-environment policy as implemented by Run 102

| env     | external genesis file | expected hash | authority | outcome on misconfiguration                                                                |
|---------|----------------------|--------------|-----------|---------------------------------------------------------------------------------------------|
| DevNet  | optional             | optional     | optional  | `SkippedNoExternalGenesis` with log line if no `--genesis-path`; otherwise normal verifier. |
| TestNet | optional             | optional     | optional (Run 101 partial-positive) | as above; existing Run 101 TestNet relaxation preserved.                                    |
| MainNet | **required** (T185 + belt-and-braces in Run 102) | **required** | **required** (Run 101) | release binary refuses to start with typed `BootGenesisError` *before* trust-bundle / network / consensus startup. |

### 18.3 What Run 102 explicitly does NOT land

Per the task's explicit scope rule — *"If the skeleton cannot be added
cleanly without broad redesign, do not implement it in Run 102.
Document it as Run 103 instead."* — the bundle-signing-key
**ratification verifier skeleton** is deferred to Run 103. Run 102 also
does NOT land:

> persistent `<data_dir>/pqc_authority_state.json` (Run 103),
> signing-key rotation, signing-key revocation, KMS/HSM custody
> (Run 105), peer-driven live apply (Run 106+, gated by §10),
> governance, validator-set rotation, production static source-code
> anchors of any kind, fallback roots or fallback signing keys, changes
> to the trust-bundle or peer-candidate wire format, new CLI flags
> beyond the existing T232/T233 surface, new dependencies, new metric
> families, new admin-API surfaces, new filesystem watchers, new
> network listeners or gossip subscriptions, weakening of any Run 050–
> 101 invariant, full C4 closure, C5 closure.

### 18.4 Cross-document binding

- Evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md` with
  10 release-binary smoke scenarios (incl. authority-only-diff canonical
  hash divergence proof and Run 102 OK ordering before all `[restore]` /
  `[metrics]` / `[binary]` / `[binary-consensus]` lines), plus
  fixtures and stdout/stderr captures in
  `docs/devnet/run_102_genesis_verification_evidence/`.
- Tests: 8 in-module unit tests (`pqc_boot_genesis::tests`) and 14
  integration tests (`crates/qbind-node/tests/run_102_boot_genesis_wiring_tests.rs`).
- Regression linkage: Run 101 (11), T232 (7), T233 (16), T237 (24)
  remain green; T233's `MainnetConfigError::ExpectedGenesisHashMissing`
  shield is preserved bit-for-bit and *composes* with Run 102 (Run 102
  adds the actual canonical hash comparison the shield never did, and
  adds a belt-and-braces refusal for callers that bypass
  `--profile mainnet`).
- contradiction tracker: see Run 102 update in
  `docs/whitepaper/contradiction.md`.

### 18.5 Why partial-positive and not positive

Run 102 closes the *release-binary wiring* gap recorded in the Run 101
evidence note (the helper is now actually invoked from `main` before
any trust-bundle / network / consensus startup), and replaces the
pre-Run-101 raw-file-byte `--print-genesis-hash` semantics with
canonical Run 101 semantics. It does not yet land the bundle-signing-key
ratification verifier — Run 103.

If anything in this update drifts from the binary's behaviour once
Run 103 lands, this update is the defect: update it before merging the
Run 103 change.
---

## 19. Run 103 Update — Minimal Bundle-Signing-Key Ratification Verifier

**Status:** POSITIVE (library-level verifier landed; consumption boundary into trust-bundle apply paths deferred to Run 104 by task design).
**Task:** `task/RUN_103_TASK.txt`.
**Evidence:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_103.md`.

### 19.1 What landed

Run 103 implements the verifier primitive that §5 and §13 require and
that the Run 102 update (§18.3) explicitly deferred:

- A versioned, domain-separated `BundleSigningRatification` schema
  authorising **exactly one** bundle-signing public key against
  **exactly one** genesis-bound bundle-signing authority root, on
  **exactly one** chain/environment, under **exactly one** PQC
  signature suite. Domain separator:
  `b"QBIND:BUNDLE-SIGNING-RATIFICATION:v1"`. Schema version:
  `BUNDLE_SIGNING_RATIFICATION_VERSION_V1 = 1`.
- A deterministic, length-prefixed binary canonical preimage
  (`canonical_ratification_preimage`) — no JSON map-order or
  whitespace ambiguity is possible.
- `verify_bundle_signing_key_ratification(...)` — fail-closed
  verifier API returning `Result<RatifiedBundleSigningKey,
  RatificationFailure>` where every reject reason is precisely typed
  (no "invalid object" catch-all).
- PQC-only verification via the existing production
  `qbind_crypto::MlDsa44SignatureSuite` adapter (FIPS 204; suite id
  `100`). No parallel crypto stack, no classical signatures, no
  dummy verifier.
- Authority-root lookup restricted to
  `authority.bundle_signing_authority_roots`; entries in
  `pqc_transport_roots` are consulted **only** to produce the precise
  `TransportRootNotAllowed` diagnostic and can never authorise a
  bundle-signing key.
- Honest authority-key-material boundary: when genesis stores only a
  64-hex SHA3 fingerprint (Run 101 allows this), the verifier returns
  the typed `AuthorityKeyMaterialUnavailable` reason rather than
  faking verification.

### 19.2 Where it lives

| Concern | Location |
|---|---|
| Verifier module | `crates/qbind-ledger/src/bundle_signing_ratification.rs` |
| Re-exports | `crates/qbind-ledger/src/lib.rs` (Run 103 block) |
| Test-helpers feature gate | `crates/qbind-ledger/Cargo.toml` (`features.test-helpers = []`) |
| Unit tests | `crates/qbind-ledger/src/bundle_signing_ratification.rs::tests` (19) |
| Integration tests | `crates/qbind-node/tests/run_103_bundle_signing_ratification_tests.rs` (8) |
| Evidence | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_103.md` |

### 19.3 What Run 103 explicitly does NOT do

Per the task's "Strict non-goals" rule and the Run 102 update's
deferral, Run 103 does **NOT**:

- wire the verifier into trust-bundle startup load / reload-check /
  reload-apply / SIGHUP / peer-candidate / propagation paths
  (Run 104);
- add `<data_dir>/pqc_authority_state.json` (Run 104);
- add a `RatifiedSigningKeyRegistry` cache (Run 104);
- include an `authority_sequence` anti-rollback field in the
  ratification object (Run 104);
- add an authority-key-material registry to resolve short
  fingerprints to full PKs (Run 104);
- introduce KMS/HSM custody (Run 105);
- implement signing-key rotation / revocation (Run 105+);
- implement governance / validator-set rotation;
- add peer-driven live apply (Run 106+, gated by §10);
- change the trust-bundle wire format, peer-candidate wire format,
  consensus, KEMTLS, or `activation_epoch` semantics;
- introduce production static root anchors as source-code constants;
- add CLI flags, admin-API endpoints, filesystem watchers, network
  listeners, gossip publishers/subscribers, metric families, or
  dependencies.

### 19.4 Anchoring

- Implementation: `crates/qbind-ledger/src/bundle_signing_ratification.rs`.
- Tests: 19 in-module unit + 8 release-binary-facing integration tests
  (the integration tests link through `qbind-node`'s Cargo against the
  same `qbind_ledger::verify_bundle_signing_key_ratification` re-export
  the production binary links against).
- Evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_103.md`.
- Contradiction tracker: see Run 103 update in
  `docs/whitepaper/contradiction.md`.
- Regression linkage: Run 101 (11), Run 102 (14), qbind-ledger lib
  (196), qbind-node lib (1090), qbind-crypto lib (68) all remain green
  bit-for-bit.

### 19.5 Why positive (and not strongest-positive)

Run 103 lands the full minimal verifier with strong tests and zero
mocking of crypto. The verdict is `positive` rather than
`strongest-positive` because the genesis-bound
`GenesisAuthorityRoot::key_fingerprint` field still overloads
"short fingerprint" and "full PK" semantics — cleanly separating those
representations and lifting the `AuthorityKeyMaterialUnavailable`
boundary is Run 104 work. Until that lands, operators that wish to
use the verifier in production must store the full ML-DSA-44 public
key bytes (hex-encoded) in `key_fingerprint`; Run 101 already permits
this within `GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX = 16 KiB`.

If anything in this update drifts from the binary's behaviour once
Run 104 lands, this update is the defect: update it before merging
the Run 104 change.