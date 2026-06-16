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
| 7 | Reload-check / reload-apply / SIGHUP live reload (Runs 069 / 070 / 073 / 074, **+ Run 105 ratification enforcement: Run 106 dispatch on reload-check (Run 106), peer-candidate-check (Run 107), peer-candidate-wire (Run 109), reload-apply (Run 112), and SIGHUP (Run 114)**) | Yes (local operator) | Local-file paths. Reload-check is non-mutating. Reload-apply / SIGHUP follow the strict Run 070 `validate → snapshot → swap → evict → commit` ordering. **Under Run 106 policy: MainNet/TestNet always require a Run 105 ratification sidecar; DevNet requires one only with `--p2p-trust-bundle-ratification-enforcement-enabled`. Refused ratification fails closed BEFORE any apply step on all surfaces, including per-SIGHUP via Run 114 (sidecar JSON re-read on every trigger).** No peer source today. |
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

---

## 20. Run 104 Update — Genesis-Bound Authority Key Material Registry

**Status:** landed. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_104.md`.

### 20.1 What Run 104 closes

Run 104 closes the §19.5 boundary: the genesis-bound bundle-signing
authority root now carries a structurally separate, validated
ML-DSA-44 public key, and the Run 103 verifier consumes it directly.

Schema additions on `GenesisAuthorityRoot`:

| Field             | Type             | MainNet bundle-signing | TestNet / DevNet |
|-------------------|------------------|------------------------|------------------|
| `public_key_hex`  | `Option<String>` | **required**           | optional (legacy short fingerprint tolerated) |

When `public_key_hex` is `Some`, validation enforces:

1. Lowercase hex, even length, ≤ `GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX`.
2. Suite-specific byte length: ML-DSA-44 = 1312 bytes (= 2624 hex).
3. `key_fingerprint.len() == 64` AND
   `sha3_256_hex(decoded_public_key) == key_fingerprint`
   (binding enforced via `authority_public_key_fingerprint`).

When `public_key_hex` is `None` on a MainNet bundle-signing root,
`validate_for_environment` fails closed with
`GenesisAuthorityValidationError::MissingPublicKeyMaterial`.

Config-level validation additionally rejects duplicate
`(suite_id, public_key_hex)` pairs with
`DuplicateAuthorityPublicKey`.

### 20.2 Canonical hash binding

`encode_authority_root` was extended with
`encode_optional_str(buf, root.public_key_hex.as_deref())`. Any
mutation of the new field — including its presence/absence — changes
the canonical genesis hash, so Run 102 boot-time hash pinning
transitively protects the new material.

### 20.3 Verifier integration

`verify_bundle_signing_key_ratification` resolution order:

1. Use `bundle_root.public_key_hex` if present (Run 104 clean path).
   Malformed bytes → `AuthorityKeyMaterialMalformed` (new variant).
2. Fall back to the Run 103 legacy 2624-hex `key_fingerprint`
   overload (preserved for DevNet/TestNet backward compatibility
   only).
3. Otherwise → `AuthorityKeyMaterialUnavailable` (unchanged).

No fake verification path is introduced; no fallback authority is
consulted.

### 20.4 What Run 104 explicitly does NOT do

- Does not wire the verifier into any trust-bundle apply call site
  (Run 105+).
- Does not implement signing-key rotation, revocation, custody, or
  authority anti-rollback persistence.
- Does not enable peer-driven live apply.
- Does not change `--print-genesis-hash` byte layout or CLI surface.

### 20.5 Operator obligation (MainNet)

MainNet genesis files MUST now carry `public_key_hex` for every
bundle-signing-authority root. Genesis files written before Run 104
that relied on either (a) only a 64-hex SHA3 fingerprint, or
(b) the Run 103 legacy 2624-hex `key_fingerprint` overload, will be
refused by `validate_for_environment(Mainnet)` and must be
regenerated using `GenesisAuthorityRoot::with_public_key_bytes(...)`

---

## 21. Run 105 Update — Non-Mutating Ratification Enforcement

Run 105 lands the **first non-mutating enforcement gate** for the
Run 103/104 verifier on the existing local validation surfaces. It
introduces no peer-driven path, no live-apply mutation, no
filesystem watcher, no SIGHUP wiring, and no network listener — those
remain Run 106+ scope.

### 21.1 What Run 105 enforces

When the operator opts in via
`--p2p-trust-bundle-ratification-enforcement-enabled`, the binary
runs `qbind_ledger::enforce_bundle_signing_key_ratification` on the
candidate bundle's signing key at three positions:

1. **Startup `--p2p-trust-bundle` preflight.** AFTER all
   Run 050/051/053/057/062/065 validation succeeds and the activation
   gate is satisfied, BEFORE the Run 055 sequence write and BEFORE
   bundle roots are merged into `trusted_roots`. Fail-closed prevents
   any new bundle-signing key from establishing live trust without a
   genesis-bound ratification.
2. **`--p2p-trust-bundle-reload-check` validation-only path.** AFTER
   the Run 069 read-only pipeline succeeds. The reload-check path
   itself remains read-only on every branch — the gate adds zero
   file writes.
3. **New library entry points.** `validate_candidate_bundle_full_with_ratification`
   and `validate_candidate_bundle_with_ratification` give downstream
   library consumers (and Run 106+ wiring) a typed,
   non-breaking-change handle to the gate.

### 21.2 Per-environment policy

* MainNet — always Strict. Refuses unratified bundles in two places
  (the binary's policy choice AND the helper's
  `MainnetLegacyUnratifiedRefused` defense in depth).
* TestNet/DevNet — Strict by default; the operator MAY opt in to
  `RatificationEnforcementPolicy::AllowLegacyUnratified` via
  `--p2p-trust-bundle-allow-unratified-testnet-devnet`. The legacy
  verdict is always logged distinctly as
  `RatificationEnforcementOutcome::LegacyUnratifiedAccepted`; it is
  NEVER a "passed ratification" verdict.

### 21.3 What Run 105 explicitly does NOT do

- No peer-driven ratification acceptance (no `0x05` extension, no
  gossip path, no propagation rebroadcast).
- No live-apply trust mutation; no session eviction; no SIGHUP wiring.
- No signing-key custody, rotation, or revocation mechanism.
- No `--p2p-trust-bundle-peer-candidate-check` binary-side gate
  wiring (deferred to Run 106; the Run 076 validator path is
  bit-for-bit unchanged).

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md` for the full
artefact set, test counts, and operator workflow.
or by populating `public_key_hex` directly.
---

## §21. Run 106 update — MainNet/TestNet ratification enforcement promoted to DEFAULT-STRICT on the two Run-105 surfaces

Run 106 narrows §20 (Run 105) on one and only one axis: the **invocation
decision** of the Run 105 bundle-signing-key ratification gate is
promoted from operator-opt-in (`--p2p-trust-bundle-ratification-
enforcement-enabled`) to **per-environment default-strict** on the two
trust-bundle validation surfaces Run 105 wired — the
`--p2p-trust-bundle` startup preflight (before the Run 055 sequence
write and before bundle roots are merged into `trusted_roots`) and the
`--p2p-trust-bundle-reload-check` validation-only path.

### Per-environment contract

| Environment | Opt-in flag | Invocation decision | Reason label |
|-------------|-------------|--------------------|--------------|
| MainNet     | (any)       | **Invoke**         | `mainnet-default-strict` |
| TestNet     | (any)       | **Invoke**         | `testnet-default-strict` |
| DevNet      | `false`     | Skip               | `devnet-no-operator-opt-in` |
| DevNet      | `true`      | Invoke             | `devnet-operator-opt-in` |

MainNet/TestNet behaviour is **independent of the opt-in flag**: the
flag can neither enable enforcement (it is already on) nor disable it
(the helper ignores the flag on those environments). DevNet preserves
the Run 105 operator-opt-in behaviour so unsigned/legacy bundles
continue to work in developer workflows. The DevNet `Skip` decision is
structurally unreachable on MainNet/TestNet (pinned by
`devnet_opt_in_does_not_weaken_mainnet` and
`run_106_devnet_skip_decision_is_never_returned_for_mainnet_or_testnet`).

### Helper location

The decision lives in the new module
`qbind_node::pqc_ratification_policy` (file
`crates/qbind-node/src/pqc_ratification_policy.rs`) as the pure,
no-I/O, no-crypto function:

```text
ratification_gate_decision(env: NetworkEnvironment, operator_opt_in: bool)
    -> RatificationGateDecision
```

The gate body itself (`apply_run_105_ratification_gate_at_startup` and
`validate_candidate_bundle_with_ratification`) is bit-for-bit unchanged
from Run 105. The Run 105 in-gate `RatificationEnforcementPolicy::Strict`
selection on MainNet is preserved as defense in depth: even if a future
change accidentally flipped the invocation decision back to opt-in,
MainNet would still refuse legacy unratified bundles inside the gate.

### Mutation-ordering invariants

Run 106 changes only the **guard** around the existing gate. The
Run 050/051/053/055/057/061/062/063/065/091/099/103/105 ordering at
every covered surface is preserved bit-for-bit. A refused ratification
still fails closed BEFORE the Run 055 sequence write and BEFORE bundle
roots are merged into `trusted_roots`; no session is touched; no
network is started on the rejected path.

### What Run 106 explicitly does NOT do

- No wiring of `--p2p-trust-bundle-peer-candidate-check` into
  ratification-aware validation (still unwired; honest blocker: needs
  a factored ratification-context builder).
- No live peer-candidate wire validation enforcement (still unchanged;
  honest blocker: adding fields to `PeerCandidateRuntimeContext`
  breaks ~18 call sites — needs `*_with_ratification` wrapper
  factoring).
- No propagation/rebroadcast enforcement (depends on live wire
  validation landing first).
- No reload-apply (Run 073) enforcement (still unchanged; honest
  blocker: requires extending the apply context without mutating the
  trait shape).
- No SIGHUP live reload (Run 074) enforcement (depends on
  reload-apply landing first).
- No release-binary smoke logs for the Run 106 invocation-policy
  change itself (the Run 105 smokes for the gate body remain valid
  because the body is bit-for-bit unchanged; the operator-side CLI
  change on MainNet/TestNet is documented in source).
- No signing-key rotation, signing-key revocation, anti-rollback
  persistence, KMS/HSM custody, governance, validator-set rotation,
  peer-driven live apply, production source-code anchors, fallback
  roots, or fallback signing keys.

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_106.md` for the full
artefact set, test counts, mutation-ordering invariants, deferred
surfaces with explicit blockers, and the recommended Run 107 scope
(wire `--p2p-trust-bundle-peer-candidate-check` first, then layer the
remaining surfaces on the resulting factored context builder).
---

## Run 107 update — local peer-candidate check ratification enforcement

Run 107 implements one additional non-mutating enforcement surface from the Run 100 authority model: the local `--p2p-trust-bundle-peer-candidate-check <PATH>` CLI path now reuses the Run 105 sidecar ratification input and the Run 106 per-environment invocation policy.

The policy is unchanged: MainNet and TestNet invoke bundle-signing-key ratification by default; DevNet invokes only when the operator supplies `--p2p-trust-bundle-ratification-enforcement-enabled`. The sidecar format remains `qbind_ledger::BundleSigningRatification` loaded through the existing `--p2p-trust-bundle-ratification <PATH>` flag.

Security boundaries preserved:

- local config alone is still not enough for MainNet bundle-signing authority;
- authority is genesis-bound through the canonical genesis hash and authority block;
- transport roots cannot authorize bundle-signing keys;
- rejection remains validation-only and non-mutating;
- no peer-candidate wire format change was made;
- live peer-candidate wire validation, propagation/rebroadcast, reload-apply, SIGHUP, peer-driven apply, rotation/revocation, authority anti-rollback persistence, KMS/HSM, governance, and validator-set rotation remain future work.

Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_107.md`. Because release-binary smoke evidence was not produced, Run 107 is partial-positive and does not claim full C4 or C5 closure.

---

## Run 108 update — release-binary evidence closure for local peer-candidate check ratification

Run 108 produces release-binary evidence for the exact Run 107 local CLI surface. The release `qbind-node` binary proves MainNet default-strict ratification on `--p2p-trust-bundle-peer-candidate-check`, including valid-ratification success, missing-ratification fail-closed behavior, and bad-signature fail-closed behavior. It also proves the intended DevNet policy: no opt-in preserves legacy unratified local-check behavior, while `--p2p-trust-bundle-ratification-enforcement-enabled` enforces valid/missing/bad ratification outcomes.

Security boundaries remain unchanged:

- local config alone is still not enough for MainNet bundle-signing authority;
- authority remains genesis-bound through the canonical genesis hash and authority block;
- static production source-code anchors remain rejected;
- rejection remains validation-only and non-mutating;
- no sequence file is written, no root merge occurs, no live trust state is mutated, no sessions are evicted, no propagation occurs, and the node does not start;
- no trust-bundle or peer-candidate wire format changes were made;
- live peer-candidate wire validation, propagation/rebroadcast, reload-apply, SIGHUP, peer-driven apply, rotation/revocation, authority anti-rollback persistence, KMS/HSM, governance, validator-set rotation, full C4, and C5 remain future work.

Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_108.md` and `docs/devnet/run_108_peer_candidate_check_ratification_release_binary_evidence/`. Run 108 closes only the Run 107 release-binary evidence gap for the local peer-candidate check; it does not claim live-path or applying-surface closure.

## Run 109 update — live inbound `0x05` peer-candidate wire validation ratification gate

Run 109 wires the existing Run 105 / 106 / 107 bundle-signing-key ratification verifier stack into the live inbound `0x05` peer-candidate wire validation path. The live `LivePeerCandidateWireDispatcher` (the Run 079 owned-fields dispatcher used by the production read loop) now carries an optional owned `LiveRatificationConfig` (the owned-fields version of the borrowed `RatificationEnforcementContext` Runs 105 and 107 use). When the Run 106 `ratification_gate_decision` says invoke, every inbound `0x05` frame is routed through `PeerCandidateWireReceiver::try_handle_frame_with_ratification(...)`, which delegates to the same `PeerCandidateValidator::try_accept_with_ratification(...)` Run 107 uses on the local CLI path. The Run 088 propagation step downstream is gated on a `Validated` outcome, so every ratification refusal (`ReloadCheckError::RatificationRefused(..)`) is counted into the existing `peer_candidate_propagation_suppressed_invalid_total` family and the frame is NEVER rebroadcast.

Run 109 reuses the operator-supplied Run 105 sidecar (`--p2p-trust-bundle-ratification <PATH>`) as the ratification-object source for live frames. No new wire-format field, no peer-supplied ratification object, no parallel validation stack. The binary refuses to install the live dispatcher (FATAL exit, no fallback) when the gate says invoke and the context cannot be built (missing `--genesis-path`, missing authority block, malformed sidecar). MainNet/TestNet always invoke (Run 106 default-strict); DevNet invokes only under `--p2p-trust-bundle-ratification-enforcement-enabled`; DevNet without opt-in preserves the pre-Run-109 unguarded path bit-for-bit.

Security boundaries remain unchanged:

- local config alone is still not enough for MainNet bundle-signing authority — the ratification verifier is rooted in the genesis authority block via the canonical genesis hash;
- static production source-code anchors remain rejected;
- transport roots cannot ratify bundle-signing keys (the `TransportRootNotAllowed` rejection is pinned by the Run 109 test suite on the live wire path identically to the Run 107 local CLI path);
- rejection remains validation-only and non-mutating: no sequence file is written, no root merge occurs, no live trust state is mutated, no sessions are evicted, no `_applied_total` metric family was introduced, and no `0x05` rebroadcast happens on rejection;
- no trust-bundle or peer-candidate wire format changes were made;
- peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation lifecycle, authority anti-rollback persistence, peer-distributed ratification objects on the wire, fast-sync / consensus-storage-restore ratification parity, KMS/HSM custody, governance, validator-set rotation, full C4, and C5 all remain future work.

Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_109.md`. Run 109 is **partial-positive**: focused integration tests (`crates/qbind-node/tests/run_109_pqc_peer_candidate_wire_live_ratification_tests.rs`, 23 passing) plus the unchanged Run 089 N=3 DevNet release-binary propagation harness mechanically cover the live `0x05` plumbing; a fresh ratification-aware multi-node release-binary capture was descoped in this run and is recommended for a future run.

## Run 110 update — release-binary N=3 DevNet live ratification harness

Run 110 lands the release-binary multi-node evidence layer that Run 109 explicitly deferred. The deliverable is harness-only and does not change the Run 100 authority model, Run 101 genesis authority implementation, Run 102 boot verification, Run 103 verifier, Run 104 key-material rules, Run 105 enforcement body, Run 106 default-strict policy, Run 107 local peer-candidate check wiring, or Run 109 live wire wiring. No production runtime code changed.

The harness `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` reuses the Run 089 N=3 DevNet mutual-auth topology (V0 / V1 / V2 on loopback, ML-KEM-768 + ChaCha20-Poly1305 + ML-DSA-44, real consensus signer keystores, signed DevNet bundle) and overlays it via `crates/qbind-node/examples/run_110_live_ratification_fixture_helper.rs` with a freshly-minted genesis authority root, a Run 102 canonical genesis hash, a Run 103 signed ratification sidecar covering the cluster's R1 baseline signing key, a tampered sidecar, and a freshly-minted U1 unratified signing key plus a U1-signed alternate trust bundle. V1 (the relay) and V2 (the observer) are started with `--p2p-trust-bundle-ratification-enforcement-enabled` plus `--p2p-trust-bundle-ratification ratification.valid.json`; every node accepts BOTH R1 and U1 via two `--p2p-trust-bundle-signing-key` lines, so the inner Run 050 / 076 signature check accepts both bundles and the **only** layer that distinguishes ratified from unratified on the live wire is the Run 109 ratification gate.

Run 110 asserts six scenarios on release binaries (`baseline_ratification`, `valid_ratified`, `missing_ratification`, `bad_ratification_startup_refuse`, `duplicate_unratified_no_promotion`, `devnet_no_opt_in_legacy`) and across every scenario pins the cross-cutting non-mutation invariants from Run 087 / 088 / 089 / 105 / 107 / 109. The bad-signature scenario lives at the **startup boundary** (Run 105 preflight refuses to install the live dispatcher with a tampered sidecar; the binary exits non-zero and never reaches `P2P transport up`) because Run 109 reuses the Run 105 sidecar model and the `0x05` wire has no peer-supplied ratification field — that is the truthful defense-in-depth shape and would only widen if a future run extends the wire format with a peer-distributed ratification object.

Security boundaries remain unchanged:

- local config alone is still not enough for MainNet bundle-signing authority — the ratification verifier is rooted in the genesis authority block via the canonical genesis hash, and the Run 110 harness mints a fresh DevNet authority for each run and never reuses any production identity;
- authority remains genesis-bound through the canonical genesis hash and authority block;
- static production source-code anchors remain rejected;
- transport roots cannot ratify bundle-signing keys — the `--p2p-trust-bundle-signing-key` flags in the Run 110 harness accept only ML-DSA-44 bundle-signing keys (R1 and U1), never the transport ML-KEM-768 root;
- rejection remains validation-only and non-mutating;
- no sequence file is written, no root merge occurs, no live trust state is mutated, no sessions are evicted, no propagation occurs on rejection, no `_applied_total` metric family is introduced, and no node reload-applies on rejection;
- no trust-bundle or peer-candidate wire format changes were made;
- peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, peer-distributed ratification objects on the wire, fast-sync / consensus-storage-restore ratification parity, KMS/HSM custody, governance, validator-set rotation, full C4, and C5 all remain future work.

Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_110.md`. Run 110 is **partial-positive**: the harness, fixture helper, and docs land in-tree and are repeatable end-to-end on any host with a release Rust toolchain; a fresh full release-binary capture (archived `docs/devnet/run_110_live_peer_candidate_ratification_n3/`) was not produced under this PR and is the next step for an operator or CI environment.
## Run 111 update — release-binary N=3 DevNet live ratification capture executed and archived

Run 111 is the evidence-only execution and archive of the Run 110 harness. No code changes, no policy changes, no wire-format changes. `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` was executed end-to-end on real release `target/release/qbind-node` plus the four supporting release helper binaries; all six scenarios passed first-shot. The fresh release-binary multi-node capture is archived under `docs/devnet/run_110_live_peer_candidate_ratification_n3/` and contains: a SHA-256 + ELF BuildID manifest for every binary under test; per-node stderr / stdout / `/metrics` snapshots for every scenario; per-node `pqc_trust_bundle_sequence.json` SHA-256 hashes before and after every applicable scenario (every diff zero); the genesis-authority + ratification fixtures; and the harness's `summary.txt`, `ratification_lines.txt`, and `run033_run040_lines.txt`. Targeted source-level tests on the same build: `qbind-ledger --lib` 222/0, `qbind-crypto --lib` 68/0, `run_076` 16/0, `run_078` 19/0, `run_079` 11/0, `run_088` 5/0, `run_105` 6/0, `run_106` 7/0, `run_107` 6/0, `run_109` 23/0.

Every security boundary from Runs 100 → 110 remains intact and is now also evidenced on release binaries running concurrently in an N=3 mutual-auth DevNet topology:

- local config alone is still not enough for MainNet bundle-signing authority — the ratification verifier is rooted in the genesis authority block via the canonical genesis hash, and the Run 111 capture used a freshly-minted DevNet authority per run with no reuse of any production identity;
- static production source-code anchors remain rejected — Run 111 introduced no new anchors and no fallback authorities;
- transport roots cannot ratify bundle-signing keys — only ML-DSA-44 R1 and U1 were accepted as bundle-signing keys via `--p2p-trust-bundle-signing-key`; the ML-KEM-768 transport root was never accepted as a signing key;
- rejection remains validation-only and non-mutating — sequence-file SHA-256 invariance before / after every scenario was directly verified, and `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` was absent from every `/metrics` response, and all `live_reload_apply_*` / `session_eviction_*` counters were `0`;
- no wire-format changes — `0x05` peer-candidate envelopes and the trust-bundle on-disk format are bit-for-bit unchanged.

Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_111.md` and the canonical archive directory above. Run 111 is **strongest-positive**: the harness, fixture helper, and docs were unchanged, the fresh full release-binary multi-node capture exists in-tree, and no production runtime code was modified. Run 111 does NOT introduce peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, peer-distributed ratification objects on the wire, KMS/HSM custody, governance, validator-set rotation, or full C4 / C5 closure.

## Run 112 update — process-start reload-apply ratification enforcement wired

Run 112 binds the Run 105 bundle-signing-key ratification enforcement body to the existing **process-start reload-apply** path (Run 070 / Run 073 flags `--p2p-trust-bundle-reload-apply-enabled` and `--p2p-trust-bundle-reload-apply-path`). A new library entry `qbind_node::pqc_trust_reload::apply_validated_candidate_with_previous_and_ratification` invokes the Run 103 PQC verifier on the Run 105 sidecar against the Run 101 genesis-authority root set **before** any snapshot, swap, session eviction, or sequence commit; the binary dispatches on the Run 106 gate (`ratification_gate_decision`) and calls this new entry on `Invoke(_)` (MainNet/TestNet always; DevNet only with `--p2p-trust-bundle-ratification-enforcement-enabled`). On the `Skip(DevnetNoOperatorOptIn)` branch the binary falls through to the legacy `apply_validated_candidate_with_previous`, preserving the pre-Run-112 DevNet ergonomics bit-for-bit. The Run 070 four-step `validate → snapshot → swap → evict_sessions → commit_sequence` ordering is preserved exactly: the post-validation pipeline was extracted into a shared private helper that both entries call, so the only operational difference between the legacy and ratification-enforced entries is the upstream validator. On any refusal the function returns `ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))` and no mutation occurs; this is pinned by `crates/qbind-node/tests/run_112_reload_apply_ratification_tests.rs` (10/10 passing) across missing / bad-signature / wrong-chain / wrong-environment / unknown-authority-root / wrong-key scenarios, all of which assert ZERO `FakeLiveTrustApplyContext` callbacks and ZERO sequence-file mutations. Regressions on the same build: `run_070` 13/0, `run_073` 10/0, `run_105` 6/0, `run_106` 7/0. Run 112 reuses the existing `--p2p-trust-bundle-ratification` sidecar flag (no new operator flag) and adds no wire-format change, no verifier change, and no policy change beyond binding the existing Run 105 body to a new caller. Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_112.md`. Run 112 is **positive** for source + integration-test surface and **partial-positive** for release-binary evidence (deferred). Run 112 does NOT introduce SIGHUP live reload ratification, peer-driven live apply, signing-key rotation/revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync ratification parity, governance, validator-set rotation, or full C4 / C5 closure.
## Run 113 update — process-start reload-apply ratification enforcement release-binary evidence CLOSED

Run 113 is evidence-only and closes the release-binary evidence gap left by Run 112. No production runtime code changed. The Run 113 harness (`scripts/devnet/run_113_reload_apply_ratification_release_binary.sh`) runs a real `target/release/qbind-node` subprocess against ephemeral genesis-authority + ratification fixtures minted by `crates/qbind-node/examples/run_113_reload_apply_ratification_fixture_helper.rs`, and asserts on the release binary that:

- MainNet valid ratification drives the canonical Run 070 `validate → snapshot → swap → evict_sessions → commit_sequence` ordering (Run 070 `APPLIED live (... sequence_commit=ok)` + Run 073 `VERDICT=applied` markers co-present; `pqc_trust_bundle_sequence.json` written and recorded);
- MainNet missing / bad-signature / wrong-chain / wrong-environment / unknown-authority-root ratification each refuse with the matching Run 105 structured reason BEFORE any snapshot, swap, session eviction, sequence commit, sequence-file write, or root merge (no Run 070 line, no Run 073 `VERDICT=applied`, no `session_evictions>=1`, and no `pqc_trust_bundle_sequence.json` under the scenario data dir);
- DevNet without `--p2p-trust-bundle-ratification-enforcement-enabled` emits the `[run-112] reload-apply ratification gate SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet)` marker and applies the candidate via the legacy entry, preserving the pre-Run-112 DevNet ergonomics bit-for-bit;
- DevNet with opt-in matches MainNet/TestNet behaviour: applies on valid ratification, refuses on missing.

The captured release binary sha256 (`83a0c3cd51103c0ccff670e4bca08d3b48fe3249a6a2c6273c61e39b8b7e7d93`), ELF BuildID, fixture-helper sha256, per-scenario stdout/stderr/exit-code, the per-scenario sequence-file inventory (WRITTEN/NOT WRITTEN + sha256 of written files), and the grep-extracted Run 102 / Run 112 / Run 070 / Run 073 marker lines are archived under `docs/devnet/run_113_reload_apply_ratification_release_binary/`. The Run 113 evidence document is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_113.md`.

Trust-anchor authority model implications:

- local config alone is still not enough for MainNet bundle-signing authority — the ratification verifier remains rooted in the Run 101 genesis-authority block via the canonical Run 102 genesis hash, and the Run 113 harness mints a fresh ephemeral authority per run with no reuse of any production identity;
- static production source-code anchors remain rejected — Run 113 introduced no new anchors and no fallback authorities, on either the source or evidence layer;
- transport roots still cannot authorise bundle-signing keys — Run 113 minted a transport root via `mint_devnet_root` only to seed the trust-bundle's transport-root field, while ratification was minted by a separate ML-DSA-44 authority keypair whose public key is bound into `genesis.authority.bundle_signing_authority_roots`;
- the `bundle-signing-key ratification` enforcement body that the binary runs at process-start reload-apply is byte-for-byte the same body Runs 105 / 107 / 109 / 112 already exercise — Run 113 is the release-binary witness that the new caller behaves identically to the existing source/integration-test evidence.

Run 113 is **strongest-positive**: the harness, fixture helper, and docs were the only additions; no production runtime code was modified; all nine scenarios passed on the captured release binary on the first non-pattern-tuning attempt; mutation-ordering and no-mutation-on-rejection invariants are proven; docs are synchronised. Run 113 does NOT introduce SIGHUP live reload ratification (still OPEN), peer-driven live apply (still intentionally non-mutating per Run 109 / 111), signing-key rotation lifecycle, signing-key revocation lifecycle, authority anti-rollback persistence, peer-distributed ratification objects on the wire, KMS/HSM custody, fast-sync / consensus-storage-restore ratification parity, governance, validator-set rotation, or full C4 / C5 closure.

## Run 114 update — SIGHUP live reload ratification enforcement wired

Run 114 binds the Run 105 bundle-signing-key ratification enforcement body to the **SIGHUP live trust-bundle reload-apply trigger** (Run 074, `--p2p-trust-bundle-live-reload-enabled` / `--p2p-trust-bundle-live-reload-path`). The `LiveReloadController` now carries an optional `LiveReloadRatificationConfig` (authority block, canonical genesis hash, environment policy, chain-id string, per-surface policy, and operator-supplied sidecar path). On every SIGHUP the controller **re-reads the sidecar JSON** at the configured path and routes the validated candidate through the Run 112 `apply_validated_candidate_with_previous_and_ratification` entry, which invokes the Run 103 PQC verifier against the Run 101 genesis-authority root set BEFORE any snapshot, swap, session eviction, or sequence commit. The binary's `spawn_run074_live_reload_task` dispatches on the same Run 106 gate (`ratification_gate_decision`) already used by reload-check / peer-candidate-check / peer-candidate-wire / process-start reload-apply: `Invoke(_)` populates the ratification config (MainNet always, TestNet always, DevNet only with `--p2p-trust-bundle-ratification-enforcement-enabled`); `Skip(DevnetNoOperatorOptIn)` leaves it `None` and the SIGHUP path uses the pre-Run-114 entry bit-for-bit. Context-build failure under `Invoke` is FATAL: the SIGHUP handler is not installed, no live trust apply will occur via SIGHUP, and the node continues running on the baseline trust bundle. Sidecar I/O / parse failures on a configured-but-unreadable sidecar fail closed through the same pre-mutation pathway as candidate-load failure (`ReloadCheckError::Bundle(_)`). The Run 074 `validate → snapshot → swap → evict_sessions → commit_sequence` ordering is preserved bit-for-bit on the accept path. The Run 105 sidecar / input model is reused verbatim via `--p2p-trust-bundle-ratification`; no new flag, no new metric family, no new wire format, no new verifier semantics. Pinned by `crates/qbind-node/tests/run_114_sighup_live_reload_ratification_tests.rs` (14/14 passing) across (a) Strict valid; (b) Strict missing; (c) Strict bad-signature; (d) Strict wrong-chain; (e) Strict wrong-environment; (f) Strict unknown-authority-root; (g) Strict ratifies-different-key; (h) sidecar I/O failure; (i) sidecar parse failure; (j) operator-flow "invalid → drop valid → valid"; (k) "valid → overwrite malformed → invalid" preserves prior valid state; (l) repeated invalid SIGHUPs do not mutate or advance sequence; (m) DevNet skip path applies; (n) refusal short-circuits before any later check. All assert ZERO live state mutation, ZERO sequence-file writes, and ZERO session evictions on every refusal path. Regressions on the same build: `run_069` 12/0, `run_070` 13/0, `run_073` 10/0, `run_074` 10/0, `run_105` 6/0, `run_106` 7/0, `run_107` 6/0, `run_109` 23/0, `run_112` 10/0. Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_114.md`. Run 114 is **positive** for source + integration-test surface and **partial-positive** for release-binary evidence (closed by Run 115 below). Run 114 does NOT introduce peer-driven live apply, signing-key rotation/revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync ratification parity, governance, validator-set rotation, or full C4 / C5 closure.

## Run 115 update — SIGHUP live reload ratification enforcement release-binary evidence CLOSED

Run 115 is evidence-only and closes the release-binary evidence gap left by Run 114. No production runtime code changed. The Run 115 harness (`scripts/devnet/run_115_sighup_ratification_release_binary.sh`) drives a real `target/release/qbind-node` running in P2P mode against ephemeral per-environment genesis-authority + ratification fixtures minted by `crates/qbind-node/examples/run_115_sighup_ratification_fixture_helper.rs`, and asserts on the release binary that:

- (i) MainNet valid ratification + `kill -HUP <pid>` produces the Run 114 invocation marker followed by the Run 074 aggregation `VERDICT=applied (... session_evictions=N; sequence_commit=ok)` — the `LiveReloadOutcome::Applied::log_line` is emitted only after the full `validate → snapshot → swap → evict_sessions → commit_sequence` pipeline, so its presence is end-to-end ordering proof on the SIGHUP path;
- (ii) MainNet **missing** ratification (sidecar deleted after the Run 074 `ENABLED` marker, before the SIGHUP) refuses with `Run 074: VERDICT=invalid` and leaves `pqc_trust_bundle_sequence.json` byte-identical to the baseline `highest_sequence:1` Run 055 wrote at startup — no snapshot, no swap, no eviction, no sequence commit, no sequence-file advance, no root merge;
- (iii) MainNet **bad-signature** ratification refuses with `BadSignature` / `signature failed PQC verification`, identical non-mutation invariants;
- (iv) MainNet **wrong-chain** refuses with `ChainMismatch`;
- (v) MainNet **wrong-environment** refuses with `EnvironmentMismatch`;
- (vi) MainNet **unknown-authority-root** refuses with `UnknownAuthorityRoot` / `not present in genesis`;
- (vii) DevNet without operator opt-in emits the Run 114 `SKIPPED (policy=devnet-no-opt-in, env=Devnet)` marker and the Run 074 pipeline applies through the pre-Run-114 entry, preserving DevNet ergonomics bit-for-bit;
- (viii) DevNet with opt-in + valid ratification emits `[run-114] ... INVOKED ... Devnet` and applies;
- (ix) DevNet with opt-in + missing ratification refuses identically to MainNet;
- (x) **Repeated-trigger safety on a single long-running PID:** 5 SIGHUPs against ONE release-binary process with the on-disk sidecar mutated in-place between triggers (`rm` → drop valid → overwrite with bad-signature → `rm` → still missing) produce exactly 1×`VERDICT=applied` + 4×`VERDICT=invalid` on that one PID's stderr; the on-disk sequence file is byte-identical pre-SIGHUP and post-each-refusal-after-the-first-apply (no rollback of valid state on later refusals, no advance on repeated invalids); the SIGHUP handler is single-shot per trigger and does NOT coalesce in a way that hides a refusal.

The captured release-binary sha256 (`c9680b3cff34fc4def081bd7ec5a55650863652ccade7ec5db95e30c3b9b30b0`), ELF BuildID, fixture-helper sha256, per-scenario stdout/stderr, the per-scenario verdict ledger, and the canonical Run 074 / Run 114 marker lines are archived under `docs/devnet/run_115_sighup_ratification_release_binary/`. The Run 115 evidence document is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_115.md`.

In particular Run 115 evidences on the release binary, with no production source change, that:

- local config alone is still not enough for MainNet bundle-signing authority — the SIGHUP-time ratification verifier remains rooted in the Run 101 genesis-authority block via the canonical Run 102 genesis hash, and the Run 115 harness mints a fresh ephemeral authority per run with no reuse of any production identity;
- static production source-code anchors remain rejected — Run 115 introduced no new anchors and no fallback authorities, on either the source or evidence layer;
- transport roots still cannot authorise bundle-signing keys — Run 115 mints a transport root only to seed the trust-bundle's transport-root field and the v0 leaf delegation cert the SIGHUP path needs in order to enter `run_p2p_node`, while ratification is minted by a separate ML-DSA-44 authority keypair whose public key is bound into `genesis.authority.bundle_signing_authority_roots`;
- the SIGHUP gate is the SAME Run 105 enforcement body the Runs 105 / 107 / 109 / 112 evidence pinned — Run 115 is the release-binary witness that the Run 114 SIGHUP caller behaves identically to the existing source / integration-test evidence and to the Run 113 process-start release-binary evidence.

Run 115 is **strongest-positive**: the harness, fixture helper, and docs were the only additions; no production runtime code was modified; all 10 scenarios passed on the captured release binary; mutation-ordering, no-mutation-on-rejection, and repeated-trigger-safety invariants are proven; docs are synchronised. Run 115 does NOT introduce peer-driven live apply (still intentionally non-mutating per Run 109 / 111), signing-key rotation lifecycle, signing-key revocation lifecycle, authority anti-rollback persistence, peer-distributed ratification objects on the wire, KMS/HSM custody, fast-sync / consensus-storage-restore ratification parity, governance, validator-set rotation, or full C4 / C5 closure.

## Run 116 update — authority anti-rollback persistence model (spec-first)

Run 116 is **spec-first** and lands the durable anti-rollback persistence model for ratified bundle-signing authority state. No production runtime code changed; no wire format changed; no verifier semantics changed; no policy changed. The full design, investigation, monotonic comparison rule, persistence-location justification, crash-consistency analysis, snapshot/restore interaction, environment policy, operator-recovery procedure, and Run 117 → Run 120 staged implementation plan are recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_116.md`. The headline decisions binding on Run 117+ are:

- **Persistence file.** `<data_dir>/pqc_authority_state.json`, sibling of the Run 055 `pqc_trust_bundle_sequence.json`. The path is exactly the one the Run 101 `GenesisAuthorityConfig::authority_sequence` source comment already names (`crates/qbind-ledger/src/genesis.rs` lines 760–764: *"Run 101 hash-binds this value but does NOT persist it (no `<data_dir>/pqc_authority_state.json` yet)"*). Run 117 will introduce a new `crates/qbind-node/src/pqc_authority_state.rs` module mirroring the Run 055 `pqc_trust_sequence.rs` atomic tmp+rename + schema-versioned + chain/env-bound record-store pattern, plus a parent-dir `fsync` step Run 055 currently omits.

- **Record schema (Run 117 = v1).** `PersistentAuthorityStateRecord { record_version: u32, chain_id: String, environment: AuthorityStateEnvironment, genesis_hash: [u8; 32], authority_policy_version: u32, authority_sequence: u64, authority_epoch: Option<u64>, authority_root_fingerprint: String, ratified_bundle_signing_key_fingerprint: String, ratification_object_hash: [u8; 32], last_update_source: AuthorityStateSource, updated_at_unix_secs: u64 }`. No private keys are ever persisted. The ratification object is recorded only by its 32-byte SHA3-256 `canonical_ratification_digest` (Run 103 helper), and the ratified PK is recorded only by its 64-hex SHA3-256 fingerprint.

- **Anchor.** The monotonic field is the **genesis-bound** `GenesisAuthorityConfig::authority_sequence` (Run 101), **not** the trust-bundle sequence (Run 055), **not** the activation_epoch (Runs 091–099). The two-layer separation between "authority sequence" and "trust-bundle sequence" is binding: Run 117 must not derive one from the other. The Run 103 `BundleSigningRatification` object itself carries **no** per-key monotonic field today (`crates/qbind-ledger/src/bundle_signing_ratification.rs` lines 162–218 / 360–410); adding one is deferred to **Run 120** as the prerequisite for any signing-key rotation lifecycle, behind a schema bump to `BundleSigningRatification::version = 2`.

- **Monotonic comparison rule.** Decisions: `FirstLoad`, `EqualIdempotent` (no rewrite), `Upgrade`, `RollbackRefused` (lower `authority_sequence`), `SameSequenceConflictingHash` (equivocation / sidecar swap), `SameSequenceConflictingKey` (corruption signal), `ChainMismatch`, `EnvironmentMismatch`, `GenesisHashMismatch`, `PolicyVersionRegression`, `Corrupt`. Every reject variant is typed and fail-closed; there is no "explicitly allowed" loophole for same-sequence-different-hash in Run 117 — any legitimate rotation-within-a-sequence requires the Run 120 schema bump.

- **Ordering relative to the existing apply pipeline.** The Run 070 `validate → snapshot → swap → evict_sessions → commit_sequence` four-step is preserved exactly. Run 118 will insert `commit_authority_state` **after** `commit_sequence` on the three mutating surfaces (startup-load, process-start reload-apply, SIGHUP live reload). Crash interleavings are enumerated and shown fail-closed or idempotent in the evidence doc. The non-mutating surfaces (reload-check, local peer-candidate check, live `0x05` peer-candidate validation) gain a **rejection** condition against the persisted marker but never mutate it themselves — preserving the Run 109 "intentionally non-mutating" contract on the peer-candidate wire.

- **Snapshot/restore interaction.** Run 117 must extend Run 097 snapshot metadata to carry `(chain_id, environment, genesis_hash, authority_policy_version, authority_sequence, authority_epoch, authority_root_fingerprint, ratification_object_hash)` (or an explicit "absent" marker for legacy snapshots). Restore is **forward-only**: a snapshot whose authority metadata is lower or conflicting than the local marker, or absent while the local marker is present, fails closed and requires the explicit operator-recovery procedure below. The Run 097 `snapshot_epoch` parity lesson is the direct conceptual predecessor.

- **Environment policy.** MainNet and TestNet enforce the marker on every boot; missing/corrupt/rollback is FATAL with non-zero exit. DevNet defaults to no-op (preserves Run 089 / Run 106 / Run 110 / Run 111 / Run 115 DevNet ergonomics bit-for-bit). DevNet opt-in via the existing `--p2p-trust-bundle-ratification-enforcement-enabled` flag activates MainNet/TestNet semantics. **Local config alone never grants MainNet authority.** The marker is the *outcome* of operator-supplied genesis + sidecar validation, not a standalone authority anchor; missing genesis or missing sidecar still exits non-zero on MainNet/TestNet exactly as Runs 106 / 112 / 114 already do.

- **Operator recovery.** Run 117 will introduce a single explicit recovery flag `--allow-authority-state-reset` plus mandatory companion `--authority-state-reset-reason <string>`. This is the **only** way the marker is ever deleted by the binary. It is single-shot per boot, valid on every environment, logged as a structured `[run-117] OPERATOR-RECOVERY` line, and never persists "recovery acknowledged" across boots. There is no time-based expiration, no auto-prune, and no other bypass.

- **Staged implementation plan.** Run 117 lands the primitive + snapshot-metadata extension. Run 118 wires it into the three mutating surfaces and adds the three validation-only rejection conditions, plus the operator-recovery flag. Run 119 produces release-binary evidence for rollback rejection (first write accepted, equal idempotent, lower-sequence rejected, same-sequence-different-hash rejected, wrong-chain/env/genesis rejected, corrupt rejected, snapshot-restore happy path / backward rejected, data-dir copy mismatch rejected, `--allow-authority-state-reset` happy path + missing-reason rejected). Run 120 lands the `BundleSigningRatification` schema bump that adds the per-key monotonic field needed before any signing-key rotation lifecycle can land. KMS/HSM custody, revocation lifecycle, peer-driven live apply, governance, validator-set rotation, fast-sync ratification parity remain explicitly out of scope for Runs 116 → 120.

Run 116 strengthens the model document by binding the **authority anti-rollback persistence** sub-piece (§8) of the original Run 100 in-scope list to a concrete schema, location, comparison rule, crash-consistency story, snapshot contract, environment policy, and operator-recovery flag — without committing any runtime code change that could weaken Runs 100–115. Evidence is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_116.md`. Run 116 is **positive** (spec-first; no implementation lands, but the design is complete enough to drive Run 117 without further design work). Run 116 does NOT introduce peer-driven live apply, reload-apply / SIGHUP ratification changes (Runs 112 / 114 unchanged), signing-key rotation or revocation lifecycle, KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, full C4 closure, or C5 closure. Static production source-code anchors remain rejected; local config alone is still not enough for MainNet bundle-signing authority. One artifact-hygiene check on the Run 115 archive's `summary.txt` was performed and is recorded in the Run 116 evidence document (§9.1): the Run 115 summary is correct (10-scenario SIGHUP ratification ledger, release-binary sha256 `c9680b3cff34fc4def081bd7ec5a55650863652ccade7ec5db95e30c3b9b30b0`); no archive file was modified.

## Run 117 update — Storage primitive and snapshot metadata extension landed

Run 117 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_117.md`) implements the Run 116 model at the **storage and snapshot-metadata level only**. The new module `crates/qbind-node/src/pqc_authority_state.rs` lands the typed `PersistentAuthorityStateRecord { record_version=1, chain_id, environment, genesis_hash, authority_policy_version, authority_sequence, authority_epoch, authority_root_fingerprint, ratified_bundle_signing_key_fingerprint, ratification_object_hash, last_update_source, updated_at_unix_secs }` exactly as Run 116 specified; the domain-separated `canonical_authority_state_preimage` / `canonical_authority_state_digest` (SHA3-256, tag `QBIND:AUTHORITY-STATE:v1`) that mirrors the existing `QBIND:GENESIS:v1` / `QBIND:BUNDLE-SIGNING-RATIFICATION:v1` convention; the pure-function `compare_authority_state` with all eleven typed outcomes (`FirstLoad`, `EqualIdempotent` (no rewrite), `Upgrade`, `RollbackRefused`, `SameSequenceConflictingHash`, `SameSequenceConflictingKey`, `ChainMismatch`, `EnvironmentMismatch`, `GenesisHashMismatch`, `PolicyVersionRegression`, `Corrupt`); a `load_authority_state` helper that returns `Ok(None)` on file-absent and fails closed on JSON / version / structural corruption (`AuthorityStateError::{Io, Malformed, UnsupportedRecordVersion, PersistFailure}`); and a `persist_authority_state_atomic` helper that mirrors the Run 055 `pqc_trust_sequence::atomic_write_record` tmp + `sync_all` + rename pattern and additionally performs the parent-directory `sync_all` step on Unix that Run 116 called out — so a mid-write crash leaves either the old record or a `.tmp` sibling but never a corrupted destination file. The companion snapshot extension lands in `crates/qbind-ledger/src/state_snapshot.rs`: the new `AuthorityStateSnapshotMeta` carrier (defined in `qbind-ledger` because `qbind-ledger` cannot depend on `qbind-node`) and the additive `StateSnapshotMeta::authority_state: Option<AuthorityStateSnapshotMeta>` field with builder `with_authority_state(...)` and deterministic JSON serialisation — `None` omits the `"authority_state"` key entirely so pre-Run-117 snapshots parse cleanly (`authority_state: None`), explicit `null` is treated as absence, malformed authority blocks fail closed (parser returns `None`), and `authority_state` is independent of the Run 097 `epoch` field (each may be `Some`/`None` independently and round-trip losslessly). Run 117 deliberately ships **no surface wiring**: no production validation or apply surface yet calls into `pqc_authority_state`. The marker file `<data_dir>/pqc_authority_state.json` is defined but not yet written by any production binary on any of the five mutating / validation-only surfaces enumerated by Run 116 — that wiring is the entire Run 118 scope, intentionally split out so Run 118 is a narrow "call the right function in the right place" change. Tests landed: 38 unit tests in `pqc_authority_state` (digest determinism, domain separation, every-security-relevant-field-flips-the-digest, informational-fields-excluded-from-digest, all eleven comparison variants, persistence round-trip, idempotent overwrite, parent-dir creation, fail-closed on corrupt JSON / unsupported version / truncated record / structurally invalid record, no-tmp-file-leftover); 10 new unit tests in `state_snapshot` (`run117_*`) covering additive serialisation, byte-identical absence when `None`, legacy parse, legacy-with-`epoch`-only parse, explicit-`null`-treated-as-absent, malformed-block-fails-closed, `authority_epoch: None` round-trip, deterministic output, `epoch` / `authority_state` independence; and all 8 Run 097 unit tests plus all 7 Run 097 integration tests (`crates/qbind-node/tests/run_097_snapshot_epoch_parity_tests.rs`) continue to pass byte-identically. The "authority anti-rollback persistence" C4 sub-item narrows further from "OPEN, complete design landed in Run 116, implementation staged to Run 117" to "OPEN, **storage primitive + snapshot metadata extension landed in Run 117**, surface wiring staged to Run 118, release-binary evidence staged to Run 119, ratification schema bump for per-key monotonic field staged to Run 120". Run 117 explicitly does **not** address signing-key rotation lifecycle (still requires Run 120 schema bump on `BundleSigningRatification`), signing-key revocation lifecycle, peer-driven live apply (Run 109 contract unchanged — the marker is **not** wired into the `0x05` validation-only path even though the primitive exists), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, full C4 closure, or C5 closure. The "local-config alone is not enough on MainNet" posture is preserved bit-for-bit: a fresh boot with no genesis or no sidecar still exits non-zero exactly as the existing Run 102 / 105 / 106 / 112 / 114 surfaces enforce — the new marker is the *outcome* of operator-supplied genesis + sidecar validation, never a standalone authority anchor. Static production source-code anchors remain rejected.

## Run 118 update — Marker derivation and compare-before-accept helpers landed (partial-positive); production surface wiring still OPEN

Run 118 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_118.md`) is the **helper-layer step** between the Run 117 storage primitive and the surface wiring the Run 116 model requires. The verdict is intentionally **partial-positive** because the run lands the bridging helpers with full unit coverage but does **not** yet wire any production validation or apply surface — that wiring is staged so the six call-site changes (three mutating, three validation-only) can land separately against a stable, already-tested helper layer.

Code landed inside the existing `crates/qbind-node/src/pqc_authority_state.rs` module (no new module, no new dependency, no public API change to any pre-existing Run 117 type): a typed `AuthorityStateDerivationInputs<'a>` input bundle that explicitly captures the verified Run 102/104 boot context (`runtime_env`, `runtime_chain_id`, `runtime_genesis_hash_hex`, `authority_policy_version`, `authority_sequence`, `authority_epoch`) plus the Run 103/105 verifier output (a `&BundleSigningRatification` *and* its matching `&RatifiedBundleSigningKey`) plus the two audit-only fields (`update_source`, `updated_at_unix_secs`); a typed `AuthorityStateDerivationError` enum with five fail-closed precondition variants (`MalformedRuntimeGenesisHash`, `EnvironmentMismatch`, `ChainIdMismatch`, `RatificationVerifierInconsistent`, `InvalidDerivedRecord`); and a pure helper `derive_authority_state_from_ratification(inputs) -> Result<PersistentAuthorityStateRecord, AuthorityStateDerivationError>` that (i) cross-checks `ratification.environment` against `runtime_env`, `ratification.chain_id` against the canonical 16-char lowercase hex of `runtime_chain_id`, and `ratification.authority_root_fingerprint` against `RatifiedBundleSigningKey.authority_root_fingerprint` so a caller misuse fails closed before any marker is produced; (ii) computes the `ratification_object_hash` field directly from `canonical_ratification_digest(&ratification)` so the marker can never disagree with the verifier on which ratification object it records; and (iii) calls `PersistentAuthorityStateRecord::validate_structure()` so a derived record that survived the cross-checks is always structurally valid and may be passed to `persist_authority_state_atomic`, `compare_authority_state`, or `validate_record_for_domain` without re-validation.

The companion compare-before-accept wrapper lands in the same module: a six-variant typed outcome `AuthorityStatePrepareOutcome` (`FirstWrite`, `AlreadyPersistedIdempotent`, `Upgrade { previous_sequence, new_sequence }`, `ConflictReject(AuthorityStateComparison)`, `LoadFailedFailClosed(AuthorityStateError)`, `PersistedDomainMismatch(AuthorityStateComparison)`) with `is_accept` / `is_reject` / `should_persist` classification helpers; and a pure `prepare_marker_for_acceptance(marker_path, candidate, runtime_env, runtime_chain_id, runtime_genesis_hash_hex)` function that folds the existing Run 117 `load_authority_state` + `validate_record_for_domain` + `compare_authority_state` pipeline into a single typed outcome. The wrapper validates the **persisted** record's `(env, chain_id, genesis_hash)` against the runtime **before** the rollback / equivocation comparison, so the wrong-data-dir / wrong-snapshot-copy case surfaces as `PersistedDomainMismatch(...)` and not as a generic chain mismatch reported against the candidate. The wrapper **never writes**: a dedicated `prepare_does_not_persist` unit test asserts the marker file is not created on a `FirstWrite` outcome. Mutating surfaces are expected to call `persist_authority_state_atomic` separately at the safest commit boundary; validation-only surfaces may call the wrapper safely without any risk of accidental marker mutation. A `LoadFailedFailClosed` outcome preserves the on-disk bytes verbatim — the wrapper does not delete, truncate, or repair a corrupted marker, and operator intervention (the `--allow-authority-state-reset` flag staged to Run 119) is the only recovery path.

Surface wiring: **none**. No production call site in `crates/qbind-node/src/main.rs`, in `startup_validation.rs`, in `pqc_live_trust_apply.rs` (Run 112), in `pqc_live_trust_reload.rs` (Run 114), in `pqc_trust_reload.rs` (reload-check), in `pqc_trust_peer_candidate.rs` (local peer-candidate check), or in `pqc_peer_candidate_binary.rs` (live `0x05` validation) yet invokes the helpers — Run 118 deliberately keeps that change set out of this run so Run 119 can wire the six surfaces against a stable, test-covered helper layer rather than landing helpers and call sites in a single risky merge. The binding mutating-surface ordering documented for Run 119 is: `verify ratification (Run 103/105) → derive_authority_state_from_ratification → prepare_marker_for_acceptance → existing validate → snapshot → swap → evict_sessions → commit_sequence → persist_authority_state_atomic`. The marker is persisted **after** the Run 070 `commit_sequence` step so a crash window leaves the marker stale-by-one (a `Upgrade` outcome on the next boot replays the comparison and re-persists), never ahead of the sequence (which would block legitimate future bumps).

Tests landed: 21 new unit tests under `pqc_authority_state::tests::run118::*` covering derivation (same-ratification → same-marker; chain / environment / genesis-hash / authority-root / ratified-key / ratification-digest changes each flip the digest; audit-only fields excluded from the digest; malformed genesis-hash hex / runtime-env disagreement / runtime-chain disagreement / fabricated verifier-output inconsistency each rejected) and compare-before-accept (no-prior-marker → `FirstWrite`; equal-with-different-audit-fields → `AlreadyPersistedIdempotent` and no rewrite; higher-sequence → `Upgrade`; lower-sequence → `ConflictReject(RollbackRefused)`; same-sequence-different-content → `ConflictReject(SameSequenceConflictingHash)`; wrong-domain on-disk → `PersistedDomainMismatch`; corrupt-file → `LoadFailedFailClosed` with on-disk bytes preserved verbatim; never-persist invariant of the wrapper; outcome-classification helpers). All 38 prior Run 117 unit tests pass byte-identically; the entire `qbind-node --lib` (1158 / 1158) and `qbind-ledger --lib` (231 / 231) test suites pass with no regression.

The "authority anti-rollback persistence" C4 sub-item narrows further from "OPEN, storage primitive + snapshot metadata extension landed in Run 117, surface wiring staged to Run 118" to "OPEN, **marker-derivation and compare-before-accept helpers landed in Run 118 (test-covered, pure, no surface wiring)**, surface wiring on the three mutating + three validation-only paths staged to Run 119, release-binary evidence for the rollback rejection scenarios staged to Run 119, snapshot-restore conflict enforcement staged to Run 119, `--allow-authority-state-reset` operator-recovery flag staged to Run 119, ratification schema bump for the per-key monotonic field staged to Run 120". Run 118 explicitly does **not** address signing-key rotation lifecycle (still requires Run 120 schema bump on `BundleSigningRatification` — the helpers preserve the bounded protection limit Run 117 documented and emit `ConflictReject(SameSequenceConflictingHash|SameSequenceConflictingKey)` rather than pretending to detect same-sequence key-level downgrades), signing-key revocation lifecycle, peer-driven live apply (Run 109 contract preserved bit-for-bit — no path in Run 118 accepts a marker produced from a peer-supplied ratification on the wire, and the helpers are not invoked from any peer-driven path), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity (the Run 117 `AuthorityStateSnapshotMeta` carrier is present but no restore-side conflict check consumes it yet), full C4 closure, or C5 closure. The "local-config alone is not enough on MainNet" posture is preserved bit-for-bit: the helper requires a verified `(BundleSigningRatification, RatifiedBundleSigningKey)` pair, which the production verifier only emits for ratifications signed by a genesis-bound root, so a fresh boot with no genesis or no sidecar still exits non-zero exactly as the existing Run 102 / 105 / 106 / 112 / 114 surfaces enforce — the marker remains the *outcome* of operator-supplied genesis + sidecar validation, never a standalone authority anchor. Static production source-code anchors remain rejected.
## Run 119 update — Process-start reload-apply surface wired with shared accept-and-persist composition (partial-positive); startup + SIGHUP wiring and release-binary evidence still OPEN

Run 119 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md`) is the **first surface-wiring step** following the Run 118 helper-layer step. The verdict is intentionally **partial-positive** because the run wires the shared accept-and-persist composition into exactly one of the three mutating surfaces (process-start reload-apply, the cleanest surface with an explicit `commit_sequence` boundary already exposed by the Run 070 trait) and **does not** yet wire the startup `--p2p-trust-bundle` acceptance path or the Run 074/114 SIGHUP live-reload path — those two are deferred to Run 120a / 120b so each can be reviewed against a stable Run-119 build that already proves the composition.

Code landed in a **new** `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` module, declared `pub mod pqc_authority_marker_acceptance;` in `crates/qbind-node/src/lib.rs`, with no new dependency, no Cargo.toml change, and no API change to any pre-existing Run 117 / Run 118 type. The new module exposes: a typed `MutatingSurfaceMarkerError` enum collapsing all reject reasons into a single error type used by every mutating surface — `DerivationFailed(AuthorityStateDerivationError)`, `LoadOrCorruption(AuthorityStateError)`, `PersistedDomainMismatch(PersistedAuthorityStateDomainValidationFailure)`, `AuthorityRootFingerprintMismatch { persisted_fingerprint, candidate_fingerprint }`, `RatifiedSigningKeyFingerprintMismatch { persisted_fingerprint, candidate_fingerprint, authority_sequence }`, `AuthoritySequenceRollback { persisted_sequence, candidate_sequence }`, `SameSequenceConflictingHash { ... }`, `PolicyVersionRegression { ... }`, and `PersistFailure(AuthorityStateError)`. A borrowed `MarkerAcceptanceInputs<'a>` input bundle threads the same Run 118 derivation inputs into the new surface. A typed accept-decision `MarkerAcceptDecision { marker_path, candidate, kind, should_persist }` plus enum `MarkerAcceptKind { FirstWrite | Upgrade | Idempotent }` is what `decide_marker_acceptance` returns on success; the decision carries the candidate record and the marker file path, but **never persists by itself**. The pure helper `decide_marker_acceptance(inputs) -> Result<MarkerAcceptDecision, MutatingSurfaceMarkerError>` composes Run 118 `derive_authority_state_from_ratification → prepare_marker_for_acceptance`, maps each Run 118 outcome onto either a typed accept (`MarkerAcceptDecision`) or a typed reject (`MutatingSurfaceMarkerError`), and explicitly **performs no write** — a dedicated `decide_does_not_persist` unit test asserts the marker file is not created on a `FirstWrite` outcome. A separate pure helper `persist_accepted_marker_after_commit_boundary(decision) -> Result<(), MutatingSurfaceMarkerError>` wraps the Run 117 `persist_authority_state_atomic` write so the only path to mutate the on-disk marker goes through this exact function. The wrapper is a **strict no-op when `should_persist == false`** (i.e. on the `Idempotent` decision) and surfaces any I/O failure as `MutatingSurfaceMarkerError::PersistFailure(...)` without panic. Callers MUST call this helper AFTER the existing `commit_sequence` step so a crash window leaves the on-disk marker stale-by-one (the next accepted mutation will replay the comparison as `Upgrade` and re-persist), never ahead of the trust-bundle sequence.

Surface wiring lands in `crates/qbind-node/src/main.rs` only, on the `--p2p-trust-bundle-reload-apply-path` block: inside the existing `gate_decision.should_invoke()` arm and after `build_run_105_reload_check_context(...)` succeeds, a new `preflight_run_119_marker_decision(...)` helper (1) re-loads the candidate bundle using the same `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation` loader the apply pipeline uses; (2) extracts the candidate's `signing_key_id` from `BundleSignatureStatus::Verified`, looks up the configured `BundleSigningKey::pk_bytes`, and runs the Run 105 `enforce_bundle_signing_key_ratification(...)` itself to obtain a verified `RatifiedBundleSigningKey`; (3) builds `MarkerAcceptanceInputs` and calls `decide_marker_acceptance(...)`. On `Err` from preflight, the binary prints `[run-119] FATAL: reload-apply refused by authority-marker preflight: ...` and `std::process::exit(1)` — BEFORE any apply call, so no `snapshot_active`, no `swap_trust_state`, no `evict_sessions`, no `commit_sequence`, no on-disk marker write, no metrics mutation. On `Ok(Some(decision))` the binary proceeds with the unchanged `apply_validated_candidate_with_previous_and_ratification(...)` call; on `Ok(applied)` the binary calls `persist_accepted_marker_after_commit_boundary(&decision)` and prints either `[run-119] authority-marker persisted at ...` (FirstWrite / Upgrade) or `[run-119] authority-marker unchanged at ... (idempotent; no rewrite).` (Idempotent). A persist failure after a successful apply prints `[run-119] FATAL: authority-marker persist failure AFTER successful apply: ...` documenting the stale-by-one crash-window state and exits non-zero. The preflight helper returns `Ok(None)` (no marker enforcement on this branch) when `--data-dir` is unset, when the candidate is DevNet-unsigned, when `LegacyUnratifiedAccepted` (DevNet/TestNet legacy ergonomics), when the candidate's signing key id is not in the configured `BundleSigningKeySet`, or when the pre-load itself fails — those branches all defer to the apply pipeline's own typed error reporting and behave **byte-identically to a Run-118 build**.

Surfaces explicitly NOT wired in Run 119 and deferred: startup `--p2p-trust-bundle` acceptance (Run 050/051 loader) → Run 120a; Run 074/114 SIGHUP live-reload acceptance → Run 120b; release-binary evidence for §Scenario 1–4 → Run 120c. The Run 077/107 peer-candidate-check path and the Run 109 live `0x05` validation path remain validation-only and never persist the marker — no wiring is planned for those.

Tests landed: 17 in-module unit tests under `pqc_authority_marker_acceptance::tests` covering clean accept (FirstWrite, Upgrade, Idempotent), every typed reject variant (rollback, same-sequence conflict, persisted-domain mismatch, corrupt marker, malformed runtime genesis hex, env mismatch, chain mismatch, root mismatch, with-wrong-but-well-formed-genesis sanity), the never-touches-disk invariant of `decide_marker_acceptance`, the rejected-path-does-not-touch-disk invariant of the composition, the persist-writes-first-write-marker round-trip, and the persist-failure → `PersistFailure` mapping; plus 4 new integration tests under `crates/qbind-node/tests/run_119_authority_marker_acceptance_tests.rs` exercising the decide → apply → persist sandwich against a deterministic `FakeLiveTrustApplyContext` (clean first-write preserves Run 070 callback ordering bit-for-bit; pre-persisted rollback marker refuses BEFORE any apply callback fires; apply failure after accept does NOT persist the marker; idempotent re-apply leaves marker bytes byte-identical). All 38 prior Run 117 unit tests, all 21 prior Run 118 unit tests, the entire `qbind-node --lib` test suite, and the entire `qbind-ledger --lib` test suite continue to pass byte-identically; no existing test was modified.

The "authority anti-rollback persistence" C4 sub-item narrows further from "OPEN, marker-derivation and compare-before-accept helpers landed in Run 118 (test-covered, pure, no surface wiring), surface wiring on the three mutating + three validation-only paths staged to Run 119" to "OPEN, **process-start reload-apply surface wired with shared accept-and-persist composition in Run 119**, startup `--p2p-trust-bundle` acceptance wiring staged to Run 120a, SIGHUP live-reload wiring staged to Run 120b, release-binary evidence for rollback rejection scenarios staged to Run 120c, snapshot-restore conflict enforcement and `--allow-authority-state-reset` operator-recovery flag staged to Run 121, ratification schema bump for the per-key monotonic field staged to Run 122". Run 119 explicitly does **not** address signing-key rotation lifecycle (still requires Run 122 schema bump on `BundleSigningRatification`), signing-key revocation lifecycle, peer-driven live apply (Run 109 contract preserved bit-for-bit — no path in Run 119 invokes the marker helpers from any peer-driven surface), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, full C4 closure, or C5 closure. The "local-config alone is not enough on MainNet" posture is preserved bit-for-bit: the new wiring requires a verified `(BundleSigningRatification, RatifiedBundleSigningKey)` pair from the same Run 102 / 105 / 106 / 112 / 114 verifier the binary already uses, so a fresh boot with no genesis or no sidecar still exits non-zero exactly as before — the marker remains the *outcome* of operator-supplied genesis + sidecar validation, never a standalone authority anchor. Static production source-code anchors remain rejected.
## Run 120 update — Startup `--p2p-trust-bundle` acceptance surface wired with the shared Run 119 helpers (positive); SIGHUP wiring still OPEN

Run 120 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_120.md`) is the **second surface-wiring step** following Run 119. The verdict is **positive** because the run wires the Run 119 shared accept-and-persist composition into the startup `--p2p-trust-bundle` acceptance surface (the Run 050/051 loader in `crates/qbind-node/src/main.rs`) without changing the Run 119 helpers, without changing the `PersistentAuthorityStateRecord` schema, without adding a new module, and without adding a new CLI flag. The startup surface now sandwiches the existing Run 055 `check_and_update_sequence` anti-rollback write with a marker compare-before-mutation (`decide_marker_acceptance`) and a marker persist-after-commit-boundary (`persist_accepted_marker_after_commit_boundary`), reusing the SAME Run 119 primitives the process-start reload-apply surface uses — there is now a SINGLE source of truth for marker accept-and-persist across two of the three mutating surfaces. The only new symbol is the binary-side helper `preflight_run_120_marker_decision_for_startup(...)`, modelled directly on the `preflight_run_119_marker_decision(...)` reload-apply helper; the helper skips on `--data-dir` unset (DevNet convenience), `BundleSignatureStatus::Unsigned` (no ratified key to anchor a marker on), and `RatificationEnforcementOutcome::LegacyUnratifiedAccepted` (DevNet/TestNet legacy ergonomics under `--p2p-trust-bundle-allow-unratified-testnet-devnet`) — preserving the existing Run 105/106 startup gate semantics bit-for-bit, including the DevNet no-opt-in branch where the ratification gate is `Skip` and no marker is written from unratified state.

The compare step runs BEFORE the Run 055 sequence anti-rollback write and BEFORE the active-roots merge into `trusted_roots` and BEFORE P2P startup, so a rollback / same-sequence-equivocation / persisted-domain mismatch / corrupt marker fail-closes the startup `std::process::exit(1)` without writing the Run 055 sequence record, without merging any new trust anchor, and without starting P2P. The persist step runs only inside the `Ok(...)` arm of `match check_and_update_sequence(...)` so the marker can never advance ahead of the trust-bundle sequence; a crash window between the sequence write and the marker persist leaves the marker stale-by-one (replayed as `Upgrade` on the next accepted startup per Run 118 §D). The marker is persisted with `AuthorityStateUpdateSource::StartupLoad` (audit-only field, does not enter the canonical digest) so operator log lines can distinguish startup acceptance from reload-apply acceptance. The startup arm logs three new operator-facing lines: `[run-120] authority-marker startup preflight skipped: ...` (one per skip condition, with the reason verbatim), `[run-120] authority-marker persisted at <path> (<kind>; candidate authority_sequence=<n>).` (FirstWrite / Upgrade accepted and persisted), `[run-120] authority-marker unchanged at <path> (idempotent; no rewrite).` (Idempotent accepted), plus the two fatal lines `[run-120] FATAL: startup --p2p-trust-bundle refused by authority-marker preflight: ...` and `[run-120] FATAL: authority-marker persist failure AFTER successful Run 055 sequence write at startup: ...`. Each fatal line documents the precise stale-by-one or no-mutation state and `std::process::exit(1)`s; there is no fallback to `--p2p-trusted-root` on marker rejection.

Surfaces explicitly NOT wired in Run 120 and deferred: Run 074/114 SIGHUP live-reload acceptance → next sub-run; release-binary evidence for §Scenario 1–4 → next sub-run (optional per task spec). The Run 069/106 reload-check, Run 077/107 peer-candidate-check, and Run 109 live `0x05` peer-candidate validation paths remain validation-only and never persist the marker — Run 120 explicitly does NOT extend the validation-only surfaces with marker comparison either, preserving the Run 119 partial-positive surface map.

Tests landed: 9 new in-module unit tests under `pqc_authority_marker_acceptance::tests` (each named `run_120_*`) covering the startup contract specifically — first-accept persists with the `StartupLoad` audit tag, same-marker is idempotent across simulated restarts (no rewrite), conflicting markers (rollback / wrong-domain / same-sequence-different-digest) reject BEFORE any startup mutation, corrupt marker fails closed without auto-overwrite, strictly higher authority_sequence accepts as `Upgrade`, `decide_marker_acceptance` never persists on the startup path (ordering proof), and a dropped decision (simulating a Run 055 sequence-write failure between preflight and persist) leaves the on-disk marker untouched. All 17 prior Run 119 unit tests, all 21 prior Run 118 unit tests, all 38 prior Run 117 unit tests, the 4 prior Run 119 reload-apply integration tests, the entire `qbind-node --lib` test suite (1184 tests), and the entire `qbind-ledger --lib` test suite (231 tests) continue to pass byte-identically; no existing test was modified.

The "authority anti-rollback persistence" C4 sub-item narrows further from "OPEN, process-start reload-apply surface wired with shared accept-and-persist composition in Run 119, startup `--p2p-trust-bundle` acceptance wiring staged to Run 120a, SIGHUP live-reload wiring staged to Run 120b" to "OPEN, **startup `--p2p-trust-bundle` acceptance surface wired with the shared Run 119 helpers in Run 120**, SIGHUP live-reload wiring staged to next sub-run, release-binary evidence for rollback rejection scenarios staged to next sub-run, snapshot-restore conflict enforcement and `--allow-authority-state-reset` operator-recovery flag staged to Run 121, ratification schema bump for the per-key monotonic field staged to Run 122". Run 120 explicitly does **not** address signing-key rotation lifecycle (still requires a future schema bump on `BundleSigningRatification`), signing-key revocation lifecycle, peer-driven live apply (Run 109 contract preserved bit-for-bit — no path in Run 120 invokes the marker helpers from any peer-driven surface), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, full C4 closure, or C5 closure. The "local-config alone is not enough on MainNet" posture is preserved bit-for-bit: the new startup wiring requires the SAME verified `(BundleSigningRatification, RatifiedBundleSigningKey)` pair from the Run 102 / 105 / 106 startup gate the binary already enforces, so a fresh MainNet/TestNet boot with no genesis or no sidecar still exits non-zero exactly as before — the marker remains the *outcome* of operator-supplied genesis + sidecar validation, never a standalone authority anchor. Static production source-code anchors remain rejected.
## Run 121 update — SIGHUP live-reload acceptance surface wired with the shared Run 119 helpers (positive); marker now active on all three mutating surfaces

Run 121 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_121.md`) is the **third and final mutating-surface wiring step** for the authority anti-rollback marker, completing the trio with Run 119 (process-start `--p2p-trust-bundle-reload-apply-path`) and Run 120 (startup `--p2p-trust-bundle`). The verdict is **positive**. The Run 074/114 SIGHUP live-reload path now sandwiches the existing apply pipeline with the same Run 119 `decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary` helpers — single source of truth across **all three** mutating surfaces, zero parallel acceptance code.

The wiring lives in `LiveReloadController::run_apply_pipeline` (`crates/qbind-node/src/pqc_live_trust_reload.rs`) and in the binary's `spawn_run074_live_reload_task` (`crates/qbind-node/src/main.rs`). The controller gains an optional `LiveReloadAuthorityMarkerConfig` field (per-controller, populated once at SIGHUP-task construction with `<data_dir>/pqc_authority_state.json`) and a SIGHUP-specific preflight `preflight_sighup_marker_decision(...)` that mirrors `preflight_run_119_marker_decision(...)` and `preflight_run_120_marker_decision_for_startup(...)`. The marker file is persisted with `AuthorityStateUpdateSource::SighupReload` (audit-only field, does not enter the canonical digest) so operator log lines distinguish SIGHUP acceptance from startup acceptance from reload-apply acceptance.

The compare step runs AFTER the existing Run 114 sidecar load and ratification enforcement but BEFORE the apply pipeline's `snapshot_active → swap_trust_state → evict_sessions → commit_sequence` sequence (a rollback / same-sequence-equivocation / persisted-domain mismatch / corrupt marker fail-closes the SIGHUP without burning a sequence number or mutating live trust state or sessions). The persist step runs only inside the `Ok(applied)` arm AFTER the apply pipeline returns successfully, so the marker can never advance ahead of the trust-bundle sequence; a crash window between the trust-bundle commit and the marker persist leaves the marker stale-by-one (safely replayed as `Upgrade` on the next accepted SIGHUP / startup / reload-apply per Run 118 §D). Two new `LiveReloadOutcome` variants — `MarkerRejected(MutatingSurfaceMarkerError)` (pre-mutation refusal; live state and on-disk records all byte-identical) and `MarkerPersistFailureAfterCommit { applied, marker_error }` (apply succeeded; marker atomic write failed; `is_fatal() == true` so the binary's SIGHUP signal-handler task routes through the existing single graceful-shutdown surface) — name the precise failure class in the operator log line: `[binary] Run 121: VERDICT=marker-rejected (...)` and `[binary] Run 121: VERDICT=FATAL-marker-persist (...)`.

Surfaces explicitly NOT wired in Run 121 and deferred: release-binary evidence for the §Scenario 1–4 acceptance table → optional sub-run; validation-only surfaces (Run 069/106 reload-check, Run 077/107 peer-candidate-check, Run 109 live `0x05` peer-candidate validation) remain validation-only and never persist the marker; restore-side conflict enforcement and `--allow-authority-state-reset` operator-recovery flag → future run; `BundleSigningRatification` v2 per-key monotonic field → future run.

Tests landed: 7 new integration tests under `crates/qbind-node/tests/run_121_sighup_authority_marker_tests.rs` covering the SIGHUP contract specifically — first-write creates the marker with `SighupReload` audit tag and the exact ratification-derived fields; same-candidate re-trigger is idempotent (no marker rewrite, no mtime touch); a pre-persisted higher-sequence marker fail-closes the SIGHUP with `MarkerRejected` and no live trust mutation, no sequence write, no eviction; a cross-domain pre-persisted marker fail-closes the same way; a corrupt marker file fail-closes and is NOT silently overwritten; DevNet without operator opt-in skips the marker entirely (pre-Run-121 SIGHUP path byte-identical); and a read-only marker-parent directory injects a persist failure that surfaces `MarkerPersistFailureAfterCommit` with `is_fatal() == true` and proves the apply DID succeed (`is_applied() == true`, sequence file written, eviction called). All prior tests continue to pass byte-identically: `qbind-node --lib` (1184 tests), `qbind-ledger --lib` (231 tests), Run 074 integration (10 tests), Run 114 integration (14 tests), Run 119 integration (4 tests). The only changes to existing test files are the additive `authority_marker: None` field on `LiveReloadConfig` builders required because `LiveReloadConfig` is a public bare struct — no assertion or scenario was modified.

The "authority anti-rollback persistence" C4 sub-item narrows further from "OPEN, startup `--p2p-trust-bundle` acceptance surface wired in Run 120 with the shared Run 119 helpers (single source of truth across two of the three mutating surfaces), Run 074/114 SIGHUP live-reload wiring staged to next sub-run" to "OPEN, **SIGHUP live-reload acceptance surface wired in Run 121 with the same shared Run 119 helpers — single source of truth across ALL THREE mutating surfaces**; release-binary evidence for §Scenario 1–4 deferred to optional sub-run; restore-side conflict enforcement and `--allow-authority-state-reset` operator-recovery flag staged to future run; ratification schema bump for the per-key monotonic field staged to future run". Run 121 explicitly does NOT mark resolved: full C4 closure; signing-key rotation / revocation lifecycle; peer-driven live apply (Run 109 contract preserved bit-for-bit — the marker helpers are not invoked from any peer-driven path); KMS/HSM custody; governance; validator-set rotation; fast-sync / consensus-storage-restore ratification parity; or C5 closure. Run 121 weakens no existing invariant: no Run 050 / 051 / 055 / 057 / 061 / 063 / 065 / 069 / 070 / 071 / 072 / 073 / 074 / 076 / 077 / 087 / 088 / 089 / 091–099 / 100 / 101 / 102 / 103 / 104 / 105 / 106 / 107 / 108 / 109 / 110 / 111 / 112 / 113 / 114 / 115 / 116 / 117 / 118 / 119 / 120 invariant changes — the SIGHUP surface still produces the same `[binary] Run 074: VERDICT=applied` log line on the accept path, the same Run 070 callback ordering (`snapshot_active → swap_trust_state → evict_sessions → commit_sequence`) bit-for-bit (the marker persist step lives STRICTLY OUTSIDE the apply pipeline), the same fatal-shutdown surface for unrecoverable branches, the same DevNet no-opt-in behaviour (marker config is `None`; pre-Run-121 SIGHUP path runs verbatim). Every other surface (startup `--p2p-trust-bundle`, reload-apply, reload-check, peer-candidate-check, live `0x05` validation) is byte-identical to a Run-120 build because no production call site on those surfaces calls into Run 121.
## Run 122 update — Release-binary evidence for authority marker behavior on all three mutating surfaces (strongest-positive evidence-only)

Run 122 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_122.md`) is an **evidence-only** run — no production runtime code was changed. The harness (`scripts/devnet/run_122_authority_marker_mutating_surfaces_release_binary.sh`), fixture helper outputs, and documentation are the only additions. Run 122 closes the release-binary evidence gap identified by Runs 119, 120, and 121 (each of which deferred release-binary marker evidence to a "future sub-run that can present startup + reload-apply + SIGHUP release-binary evidence together on the same build"). Run 122 is that sub-run.

The evidence proves on real `target/release/qbind-node` binaries:

| # | Surface | Scenario | Verdict |
|---|---------|----------|---------|
| 1 | Reload-apply (Run 119) | First accepted ratified mutation persists marker (`first-write`) | PASS |
| 2 | Reload-apply (Run 119) | Same marker idempotent — byte-identical on re-run | PASS |
| 3 | Reload-apply (Run 119) | Conflicting marker (same-sequence equivocation) rejects before mutation | PASS |
| 4 | Reload-apply (Run 119) | Corrupt marker (non-JSON) fails closed before mutation | PASS |
| 5 | Reload-apply (Run 119) | DevNet no-opt-in does not write marker | PASS |
| 6 | Reload-apply (Run 119) | Marker persists after commit boundary (cross-check S1+S2) | PASS |
| 7 | SIGHUP (Run 121) | First marker written at startup (Run 120), SIGHUP gate invoked | PASS |
| 8 | SIGHUP (Run 121) | Same marker idempotent across SIGHUP | PASS |
| 9 | SIGHUP (Run 121) | Conflicting marker (tampered post-startup) rejected before SIGHUP mutation | PASS |
| 10 | SIGHUP (Run 121) | Corrupt marker (non-JSON, tampered post-startup) fails closed | PASS |

The startup surface (Run 120) is implicitly proven by scenario 7: the SIGHUP evidence shows the marker was written at startup by Run 120 (with `last_update_source: "startup-load"`) before the SIGHUP handler was installed, confirming the startup marker write path works on a real release binary.

The "authority anti-rollback persistence" C4 sub-item status: **OPEN, all three mutating surfaces wired (Run 119/120/121) and release-binary evidence captured (Run 122)**. Remaining items: restore-side conflict enforcement, `--allow-authority-state-reset` operator-recovery flag, `BundleSigningRatification` v2 per-key monotonic field, signing-key rotation/revocation lifecycle, peer-driven live apply (intentionally non-mutating), KMS/HSM custody, governance, validator-set rotation, full C4 closure, C5 closure. Run 122 explicitly does NOT mark resolved any of these remaining items. No production source change, no test change, no metric change, no wire format change.
### Run 123 update — validation-only authority marker conflict checks

Run 123 extends the authority anti-rollback marker system to the three **validation-only** surfaces that never persist marker state:

| Surface | Marker check wired | On conflict | On no marker | Persists? |
|---------|-------------------|-------------|--------------|-----------|
| `--p2p-trust-bundle-reload-check` (Run 069/106) | After ratification, before success exit | `exit(1)` | Pass (first-seen) | Never |
| `--p2p-trust-bundle-peer-candidate-check` (Run 077/107) | After ratification, before success exit | `exit(1)` | Pass (first-seen) | Never |
| Live inbound `0x05` (Run 109) | After ratification, before propagation eligibility | `Rejected(MarkerConflict)` — propagation suppressed | Pass (first-seen) | Never |

The shared helper `verify_marker_for_validation_only(...)` composes `derive_authority_state_from_ratification` + `prepare_marker_for_acceptance` (single source of truth with the mutating-surface helpers from Run 119) but calls no disk-write function.

Missing-marker policy: validation-only surfaces pass when no persisted marker exists. This is safe because (a) the candidate is already fully ratified by Run 103/105, (b) no trust mutation occurs from a validation-only surface, and (c) the next mutating surface will write the marker.

The per-key monotonic ratification schema bump is future work (Run 125+, not Run 122 as previously referenced).

The "authority anti-rollback persistence" C4 sub-item status: **OPEN, all three mutating surfaces wired and evidenced (Runs 119/120/121/122), all three validation-only surfaces wired (Run 123)**. Remaining items: restore-side conflict enforcement, `--allow-authority-state-reset` operator-recovery flag, per-key monotonic field schema bump (Run 125+), signing-key rotation/revocation lifecycle, peer-driven live apply, KMS/HSM custody, governance, validator-set rotation, full C4 closure, C5 closure.### Run 124 update — snapshot/restore authority anti-rollback marker conflict enforcement

Run 124 extends the authority anti-rollback marker system to the **snapshot restore** surface. The restore path (`--restore-from-snapshot`, B3/B5) now consumes the Run 117 additive `AuthorityStateSnapshotMeta` block carried in `StateSnapshotMeta` and compares it against the locally persisted `<data_dir>/pqc_authority_state.json` marker BEFORE materializing any state checkpoint or writing the B3 audit marker.

| Local marker | Snapshot `authority_state` | Decision | Local marker after restore |
|--------------|---------------------------|----------|----------------------------|
| Absent | Absent (legacy snapshot) | Accept (`NoMarkerEitherSide`) | Still absent — not synthesised |
| Absent | Present, matches runtime trust domain | Accept (`AcceptSnapshotMarkerNoLocal`) | Still absent — never synthesised from snapshot bytes |
| Absent | Present, wrong domain | Reject (`RejectSnapshotMarkerWrongDomain`) | Still absent |
| Present, structurally valid, runtime trust domain | Absent (legacy snapshot) | **Reject** (`RejectMissingSnapshotMarker`) | Bytes preserved verbatim |
| Present | Present, identical | Accept (`AcceptMatchingMarker`) | Bytes preserved verbatim (no rewrite) |
| Present | Present, conflicting | Reject (`RejectConflict(...)`) — typed reason carries `RollbackRefused` / `SameSequenceConflictingHash` / `SameSequenceConflictingKey` / `PolicyVersionRegression` / `ChainMismatch` / `EnvironmentMismatch` / `GenesisHashMismatch` | Bytes preserved verbatim |
| Present, wrong-domain for runtime | Either | Reject (`RejectLocalMarkerWrongDomain`) | Bytes preserved verbatim |
| Corrupt / unsupported record version | Either | Reject (`RejectLocalMarkerCorrupt`) | Bytes preserved verbatim |

**Implementation single source of truth.** The new pure helper `verify_snapshot_authority_state_for_restore(...)` in `crates/qbind-node/src/pqc_authority_state.rs` composes the existing `load_authority_state` + `validate_record_for_domain` + `check_snapshot_meta_domain` + `compare_authority_state` primitives — there is no new comparison rule, no new conflict variant, and no new digest. The snapshot block is reconstructed as a `PersistentAuthorityStateRecord` (with the two informational-only audit fields `last_update_source` and `updated_at_unix_secs` set to neutral test-or-fixture values; neither participates in `canonical_authority_state_digest` or `compare_authority_state` equality rules) and routed through the same `compare_authority_state` surface mutating callers use. The Run 116 bounded protection limit (same-sequence key-level downgrade) carries over verbatim.

**Restore surface contract.** The new wiring lives entirely in `crates/qbind-node/src/snapshot_restore.rs` and `crates/qbind-node/src/main.rs`:

- `restore_from_snapshot_with_authority_marker_check(...)` validates the snapshot layout first (existing B3 `validate_snapshot_dir` pipeline), then runs the Run 124 check, then materializes — so a snapshot-layer failure is reported as a snapshot-layer failure, not as an authority-check failure.
- `RestoreError::AuthorityMarkerConflict(SnapshotRestoreAuthorityCheckOutcome)` carries the typed reject outcome to the binary so the operator log line is precise.
- The local `<data_dir>/pqc_authority_state.json` file is NEVER written, rewritten, or deleted by the restore surface — Run 124's strict non-goal of "do not synthesise marker state from snapshot bytes" is enforced structurally.
- The binary surface (`main.rs`) supplies the runtime authority context (`runtime_env`, `runtime_chain_id`, `runtime_genesis_hash_hex`) from the same Run 102 canonical genesis verification the rest of the trust pipeline uses. When Run 102 took the `SkippedNoExternalGenesis` branch (DevNet/TestNet without `--genesis-path`) the legacy `apply_snapshot_restore_if_requested` is used, which itself fails closed with `AuthorityContextMissing` whenever a pre-existing local marker is on disk — there is no silent shadowing through the no-context path either.

**Snapshot creation behaviour** is unchanged by Run 124. The Run 117 additive `with_authority_state(...)` builder on `StateSnapshotMeta` already lets snapshot producers attach the local marker when one exists; pre-Run-117 snapshots and producers that omit the block continue to parse and (where policy permits) restore exactly as before. Run 124 does not modify `StateSnapshotter` or any snapshot-side serialisation.

The "authority anti-rollback persistence" C4 sub-item narrows further to: **OPEN, all three mutating surfaces wired (Runs 119/120/121, evidenced by Run 122), all three validation-only surfaces wired (Run 123), snapshot/restore surface wired (Run 124)**. Remaining items: `--allow-authority-state-reset` operator-recovery flag (future run), `BundleSigningRatification` v2 per-key monotonic field (future run, Run 125+), signing-key rotation/revocation lifecycle, peer-driven live apply (intentionally non-mutating), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity beyond the local restore surface, full C4 closure, C5 closure. Run 124 explicitly does NOT mark resolved any of these remaining items, does not implement `--allow-authority-state-reset`, does not change any wire format, does not change the persistence format, does not weaken any Run 050–123 invariant (B3 / B5 / Run 097 snapshot epoch parity all preserved bit-for-bit on accept paths), and does not introduce a static production source-code anchor.
### Run 125 update — release-binary evidence for snapshot/restore authority anti-rollback marker conflict enforcement (strongest-positive evidence-only)

Run 125 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_125.md`) is **evidence-only** — no production runtime code was changed. The verdict is **strongest-positive**. Run 125 closes the release-binary evidence gap that Run 124 explicitly deferred ("release-binary evidence deferred to optional future sub-run, matching the Run 119 → Run 122 pattern").

The harness `scripts/devnet/run_125_snapshot_restore_authority_marker_release_binary.sh` builds `target/release/qbind-node` and a new evidence-only fixture helper (`crates/qbind-node/examples/run_125_snapshot_restore_authority_marker_fixture_helper.rs`) that mints an ephemeral DevNet genesis with a Run 101 authority block, computes the canonical Run 101 genesis hash, builds four real B3 snapshot directories via the canonical `StateSnapshotter::create_snapshot` API (legacy / matching / same-sequence-conflicting / wrong-genesis-domain), and emits matching + corrupt local-marker JSON fixtures.

Seven release-binary scenarios pass end-to-end against the captured `target/release/qbind-node` build (sha256 + build-id recorded in `docs/devnet/run_125_snapshot_restore_authority_marker/summary.txt`):

1. Legacy snapshot into a fresh data dir → `[restore] OK` accept; B3 `RESTORED_FROM_SNAPSHOT.json` audit marker written; no synthetic local `pqc_authority_state.json` invented from snapshot bytes.
2. Legacy snapshot would silently shadow a present local marker → rc=1 `RejectMissingSnapshotMarker`; no state mutation; no audit marker; local marker bytes byte-identical (sha256 before == sha256 after).
3. Matching snapshot `authority_state` + matching local marker → `[restore] OK` accept; local marker bytes byte-identical post-run (the restore surface NEVER writes the local marker file, even when the snapshot block matches it bit-for-bit).
4. Same `authority_sequence` with a different `ratification_object_hash` → rc=1 `RejectConflict(SameSequenceConflictingHash)`; local bytes preserved verbatim; Run 117 "two distinct ratifications cannot share the same authority_sequence" rule enforced on the release binary.
5. Corrupt local marker (non-JSON bytes) + matching snapshot → rc=1 `RejectLocalMarkerCorrupt`; the corrupt bytes are preserved verbatim (no auto-repair, no overwrite, no delete).
6. Wrong-domain snapshot (`genesis_hash_hex` differs from the runtime canonical Run 101 hash) → rc=1 `RejectSnapshotMarkerWrongDomain`; no state mutation; refused before any audit marker write.
7. Legacy no-context entry point (no `--genesis-path`) + local marker present → rc=1 `AuthorityContextMissing`; local marker bytes preserved (Run 124's "no silent shadowing through the no-context path" invariant proven on the release binary).

**Snapshot creation behaviour is unchanged by Run 125.** The Run 117 additive `with_authority_state(...)` builder on `StateSnapshotMeta` continues to be the only producer-side surface; Run 125 does not modify `StateSnapshotter` or any snapshot-side serialisation. The fixture helper is the same `StateSnapshotter::create_snapshot` API a real snapshot producer would call.

All existing unit and integration tests pass byte-identically on the same build: `run_124_snapshot_restore_authority_marker_tests` (7/7), `b3_snapshot_restore_tests` (10/10), `run_119_authority_marker_acceptance_tests` (4/4), `run_121_sighup_authority_marker_tests` (7/7), `qbind-node --lib pqc_authority_state` (74/74). No existing test was modified. No production `crates/**/src/**` change — the only new code under `crates/` is the `examples/` fixture helper, which is not compiled into `qbind-node` and is not invoked by any production binary path.

The "authority anti-rollback persistence" C4 sub-item status: **OPEN, all three mutating surfaces wired and evidenced (Runs 119/120/121, evidenced by Run 122), all three validation-only surfaces wired (Run 123), snapshot/restore surface wired (Run 124) and release-binary evidence captured (Run 125)**. Remaining items: `--allow-authority-state-reset` operator-recovery flag (future run), `BundleSigningRatification` v2 per-key monotonic field (future run, Run 126+), signing-key rotation/revocation lifecycle, peer-driven live apply (intentionally non-mutating), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity beyond the local restore surface, full C4 closure, C5 closure.

Run 125 explicitly does NOT mark resolved any of these remaining items, does not implement `--allow-authority-state-reset`, does not change any wire format, does not change the persistence format, does not weaken any Run 050–124 invariant (B3 / B5 / Run 097 snapshot epoch parity all preserved bit-for-bit on accept paths), and does not introduce a static production source-code anchor.

### Run 126 update — explicit authority-state reset/recovery procedure specification (positive, spec-first / docs-only)

Run 126 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_126.md`) is **spec-first / docs-only** — no production runtime code was changed, no CLI reset command was implemented, and no runtime behavior was modified. The verdict is **positive**.

Run 126 defines the formal specification for authority-state reset/recovery after fail-closed anti-rollback events. The specification covers:

1. **Threat model** (9 threats: malicious rollback, accidental restore, stale snapshot, stale ratification, conflicting injection, corrupt marker temptation, DevNet-to-MainNet flag leak, peer-triggered reset, local config authority escalation).
2. **Failure mode classification** (8 failure conditions from Runs 117–125 classified as operator-recoverable, environment-reset-only, governance-required, or forbidden).
3. **Environment policy** (DevNet: allow with ceremony + audit; TestNet: allow with ceremony + stronger proof + audit; MainNet: disallowed by default, governance-required).
4. **Operator ceremony** (12-step staged process: stop → archive → verify → compare → execute future command → restart and verify).
5. **Refusal cases** (13 mandatory conditions: missing/wrong genesis, wrong chain_id/env, malformed root, transport root authority, missing/bad ratification, MainNet-without-governance, peer-triggered, node-running, missing audit path, marker erasure without replacement).
6. **Audit record schema** (17-field conceptual schema: record_version, action, environment, chain_id, genesis_hash, old/new marker hash/record, ratification_hash, bundle fingerprint, snapshot metadata, operator note, binary sha256/build-id, timestamp, result).
7. **Reset safety invariants** (10 mandatory invariants: never implicit, never at startup, never peer-triggered, never from validation-only, never synthesize from snapshot, never bypass ratification, never transport root authority, never local-config-only MainNet, always audit, irreversible without new ceremony).
8. **Future ratification v2 interaction** (current marker detects conflict but does not prove per-key monotonic progression; future v2 must add monotonic field; reset must not substitute for rotation/revocation; post-v2 reset must respect monotonic chain).
9. **Future CLI design** (conceptual `qbind-node authority-state-reset` subcommand with environment-gated behavior: DevNet allows, TestNet requires confirmation, MainNet refuses without governance artifact).
10. **Future implementation plan** (Run 127: CLI skeleton + refusal; Run 128: release-binary evidence; Run 129+: ratification v2 monotonic schema).

**Key design decisions:**

- MainNet local reset is disallowed by default. Any MainNet recovery requires a future governance/ratification procedure or offline signed recovery artifact — not local config alone.
- Reset is a separate subcommand (`authority-state-reset`), not a flag on normal startup. This prevents implicit or accidental reset during routine operations.
- Audit record production is mandatory in all environments (including DevNet).
- Reset must be offline-only (node stopped) — no live reset, no peer-triggered reset.
- Transport roots cannot authorize reset (preserving Run 100/101 authority separation).
- Ratification verification is required before reset (the target key must be provably ratified under genesis authority).

The "authority anti-rollback persistence" C4 sub-item status: **OPEN, all three mutating surfaces wired and evidenced (Runs 119/120/121, evidenced by Run 122), all three validation-only surfaces wired (Run 123), snapshot/restore surface wired (Run 124) and release-binary evidence captured (Run 125), reset/recovery procedure formally specified (Run 126)**. Remaining items: `--allow-authority-state-reset` implementation (Run 127), release-binary evidence for reset refusal/allowed cases (Run 128), `BundleSigningRatification` v2 per-key monotonic field (Run 129+), signing-key rotation/revocation lifecycle, peer-driven live apply (intentionally non-mutating), KMS/HSM custody, MainNet governance artifact design, validator-set rotation, fast-sync / consensus-storage-restore ratification parity beyond the local restore surface, full C4 closure, C5 closure.

Run 126 explicitly does NOT implement: `--allow-authority-state-reset`; any reset CLI command; any runtime code change; signing-key rotation/revocation; peer-driven live apply; KMS/HSM custody; governance artifact format; validator-set rotation; ratification v2 monotonic schema. Run 126 does not claim full C4 closure and does not claim C5 closure. Run 126 does not weaken any Run 050–125 invariant. Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority.
## Run 127 update — offline authority-state reset CLI skeleton

**Date:** 2026-05-23
**Source:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_127.md`
**Verdict:** positive (source + unit test evidence; release-binary evidence deferred)

Run 127 implements the Run 126 specification skeleton for the offline authority-state reset ceremony. Key implementation facts:

### New module: `pqc_authority_state_reset`

`crates/qbind-node/src/pqc_authority_state_reset.rs` provides:

- **`AuthorityResetRefusal`** — 23-variant typed enum; every variant has a `stable_id()` for the audit log and a `detail()` for stderr/operator.
- **`AuthorityResetAuditRecord`** — deterministic Serde struct (fixed field order); no wall-clock in security-relevant fields; operator note embedded as SHA3-256 fingerprint only; no private key material.
- **`verify_authority_reset_inputs`** — pure pre-flight; all validation, no disk writes.
- **`execute_authority_state_reset`** — orchestrates the full ceremony with crash-safe pending→success audit update.

### Environment policy

| Environment | Reset allowed |
|---|---|
| DevNet | Yes, when all checks pass and audit output path is supplied |
| TestNet | Yes, under same strict ceremony as DevNet |
| MainNet | **REFUSED** by default (before opening any files) |

### Refusal ordering (fail-closed)

1. Structural input presence (`MissingDataDir`, `MissingGenesisPath`, `MissingExpectedGenesisHash`, `MissingTrustBundle`, `MissingRatification`, `AuditOutputMissing`)
2. MainNet policy check (`MainNetLocalResetUnsupported`) — fires BEFORE opening any files
3. Expected genesis hash parse (`MalformedExpectedGenesisHash`)
4. Genesis file load (`GenesisLoadFailed`)
5. Genesis hash mismatch (`GenesisHashMismatch`)
6. Authority block presence/validity (`MissingAuthorityConfig`, `InvalidAuthorityConfig`)
7. Trust-bundle load/validate (`InvalidTrustBundle`)
8. Signing-key bytes resolution (`AuthorityKeyMaterialMalformed`, `AuthorityKeyMaterialUnavailable`)
9. Ratification load/parse (`InvalidRatification`)
10. Ratification enforcement — always `Strict`; `LegacyUnratifiedAccepted` → `TransportRootNotAllowed` (`RatificationEnforcementFailed`, `TransportRootNotAllowed`)
11. Marker derivation (`TargetMarkerDerivationFailed`)
12. Existing marker archive — corrupt is a refusal, never auto-repaired (`ExistingMarkerCorrupt`)
13. Audit write failure (`AuditWriteFailed`)
14. Marker persist failure (`MarkerPersistFailed`)

### Crash safety

The audit record is written as `result = "pending"` before `persist_authority_state_atomic`, then updated to `result = "success"` after. A crash between the two steps leaves a self-describing pending artifact. A persist failure re-writes the audit record as `result = "refused"` / `MarkerPersistFailed`. A crash before the audit write leaves the marker untouched.

### CLI surface

Three new hidden opt-in flags: `--authority-state-reset`, `--authority-state-reset-output-audit`, `--authority-state-reset-operator-note`. The early-exit dispatch fires before `--print-genesis-hash`, before MainNet invariant validation, before all networking/consensus/metrics/SIGHUP/reload/peer-candidate machinery.

### C4 status after Run 127

**OPEN**, all three mutating surfaces wired and evidenced (Runs 119/120/121/122), all three validation-only surfaces wired (Run 123), snapshot/restore surface wired and evidenced (Runs 124/125), reset/recovery specified (Run 126) and CLI skeleton implemented (Run 127). Remaining: release-binary evidence for reset (Run 128), `BundleSigningRatification` v2 monotonic field (Run 129+), signing-key rotation/revocation, peer-driven live apply, KMS/HSM custody, MainNet governance artifact, validator-set rotation, full C4 closure, C5 closure.

Run 127 does NOT implement: MainNet governance artifact verification; signing-key rotation/revocation; per-key monotonic authority sequence; peer-driven live apply; KMS/HSM custody. Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority. Run 127 does not claim full C4 closure and does not claim C5 closure. Run 127 weakens no Run 050–126 invariant.

## Run 128 update — release-binary authority-state reset evidence

**Date:** 2026-05-24  
**Source:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_128.md`  
**Verdict:** strongest-positive (release-binary evidence)

Run 128 is evidence-only and lands no production runtime source changes. It adds the release-binary harness `scripts/devnet/run_128_authority_state_reset_release_binary.sh` and archive `docs/devnet/run_128_authority_state_reset_release_binary/`, proving on a real `target/release/qbind-node` binary:

1. DevNet valid reset succeeds (`rc=0`) and writes both marker + audit.
2. MainNet local reset refuses (`MainNetLocalResetUnsupported`) with no marker write.
3. Missing ratification refuses (`MissingRatification`) with no marker write.
4. Bad ratification refuses (`RatificationEnforcementFailed`) with no marker write.
5. Wrong expected genesis hash refuses (`GenesisHashMismatch`) with no marker write.
6. Corrupt existing marker refuses (`ExistingMarkerCorrupt`) and corrupt bytes are preserved verbatim (no repair/delete/overwrite).
7. Missing audit-output flag refuses (`AuditOutputMissing`) with no marker write.
8. Wrong-chain and wrong-environment ratification sidecars refuse (`RatificationEnforcementFailed`) with no marker write.

Run 128 additionally proves:

- no normal startup markers on reset path (no P2P, consensus, metrics, SIGHUP, reload, peer-candidate dispatch);
- stable audit schema presence for success/refusal records (`record_version`, `action`, `environment`, `result`, refusal stable-id on refusal);
- marker write only on success path; every refusal case preserves marker SHA before/after.

C4 status after Run 128: **OPEN but narrowed** — all three mutating surfaces wired/evidenced (Runs 119/120/121 + 122), all three validation-only surfaces wired (Run 123), snapshot/restore wired/evidenced (Runs 124/125), reset/recovery specified (Run 126), reset CLI implemented (Run 127), and release-binary reset refusal/success evidence captured (Run 128). Remaining open pieces are unchanged: MainNet governance artifact verification, ratification v2 per-key monotonic schema, signing-key rotation/revocation lifecycle, peer-driven live apply, KMS/HSM custody, validator-set rotation, full C4 closure, and C5 closure.

## Run 129 update — ratification v2 monotonic schema specification (spec-first / docs-only)

**Date:** 2026-05-24  
**Source:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_129.md`  
**Verdict:** positive (spec/design only; no runtime behavior change)

### Run 128 doc-sync checkpoint (corrected and synchronized)

Run 129 first performs the required Run 128 documentation synchronization across protocol/runbook/contradiction tracking. The synchronized statement is:

- Run 128 produced release-binary evidence for the offline authority-state reset CLI.
- DevNet valid reset succeeds and writes marker + audit.
- MainNet local reset refuses (`MainNetLocalResetUnsupported`).
- Missing/bad ratification, wrong expected genesis hash, corrupt marker, missing audit output flag, wrong-chain ratification, and wrong-environment ratification all refuse.
- Refusal paths do not write or mutate marker bytes.
- Reset exits before normal startup surfaces.
- MainNet governance artifact support remains OPEN.
- Ratification v2 monotonic schema remains OPEN before Run 129 specification.
- Rotation/revocation lifecycle, KMS/HSM custody, peer-driven live apply, full C4 closure, and C5 closure remain OPEN.

### 1) Current v1 baseline (investigation result)

Current ratification object is `BundleSigningRatification` (Run 103, schema version `1`) with canonical domain tag `QBIND:BUNDLE-SIGNING-RATIFICATION:v1`, deterministic length-prefixed preimage, and SHA3-256 digest binding:

- `version`
- `chain_id`
- `environment`
- `genesis_hash`
- `authority_root_fingerprint`
- `signature_suite_id`
- `bundle_signing_public_key`
- `bundle_signing_public_key_fingerprint`
- signature over `sha3_256(canonical_preimage)` (signature bytes are not in the preimage)

Current verifier failure modes are typed (`RatificationFailure`) and fail closed (unsupported version/suite, chain/environment/genesis mismatch, unknown or transport authority root, key material unavailable/malformed, malformed key/signature sizes, bad signature, missing authority block).

### 2) Current authority marker baseline (investigation result)

Current marker record is `PersistentAuthorityStateRecord` (`record_version=1`) and carries:

- domain binding: `chain_id`, `environment`, `genesis_hash`
- authority binding: `authority_policy_version`, `authority_sequence`, `authority_epoch`, `authority_root_fingerprint`
- ratified key anchor: `ratified_bundle_signing_key_fingerprint`
- canonical ratification anchor: `ratification_object_hash` (`canonical_ratification_digest` hex)
- informational fields: `last_update_source`, `updated_at_unix_secs` (not in marker digest)

Current `authority_sequence` is a genesis authority-policy sequence anchor, not a signing-key lifecycle sequence. It is insufficient for key-rotation/revocation ordering because same-sequence conflicting key/digest outcomes are only fail-closed conflicts, not a canonical lifecycle progression.

### 3) Threat model addressed by v2 schema

Run 129 schema explicitly targets:

- replay of older ratifications for an old key;
- same-sequence equivocation (different ratification at same sequence);
- key rollback after rotation;
- stale sidecar reuse;
- cross-environment / cross-chain replay;
- reset/recovery downgrade attempts;
- v1 downgrade after v2 activation;
- compromised authority root issuing conflicting histories;
- partitioned nodes observing divergent histories.

### 4) Monotonic design decision

Run 129 selects **per-authority-domain monotonic sequencing** (one sequence line per `(environment, chain_id, genesis_hash, authority_root_fingerprint)` domain), not per-key sequencing.

Rationale:

- Orders all lifecycle actions (ratify/rotate/revoke) in one total order.
- Eliminates ambiguity when transitioning between different keys.
- Makes reset/recovery comparison deterministic against a single persisted `latest_authority_sequence`.
- Avoids per-key counters that cannot naturally order cross-key transitions.

Conflict prevention rule: same sequence with different canonical ratification digest is always fail-closed equivocation.

### 5) Ratification v2 object schema (design)

Run 129 defines conceptual `BundleSigningRatificationV2` fields:

- `schema_version` (=2)
- `environment`
- `chain_id`
- `genesis_hash`
- `authority_policy_version`
- `authority_root_fingerprint`
- `authority_root_suite_id`
- `target_bundle_signing_key_fingerprint`
- `target_bundle_signing_key_suite_id`
- `target_bundle_signing_public_key` (or canonical reference when explicitly standardized)
- `authority_domain_sequence` (u64 monotonic per authority domain)
- `key_lifecycle_action` (`ratify` | `rotate` | `revoke`)
- `previous_key_fingerprint_if_rotation` (required for `rotate`)
- `previous_ratification_digest_if_rotation` (required for `rotate`)
- `valid_from_epoch_if_used` (optional and explicit)
- `valid_until_epoch_if_used` (optional and explicit)
- `revocation_reason_if_revoke` (required for `revoke`)
- `capabilities_scope` (explicit bound scope)
- `signature`

### 6) Canonical v2 preimage and digest

Run 129 defines a deterministic length-prefixed preimage with distinct domain tag:

- domain tag: `QBIND:BUNDLE-SIGNING-RATIFICATION:v2`
- includes all security-relevant fields above except `signature`
- big-endian integer encoding, length-prefixed variable fields, no JSON map-order ambiguity
- binds chain/environment/genesis, authority root, target key, monotonic sequence, and lifecycle action
- canonical digest is `sha3_256(v2_preimage)`

Wrong domain tag, missing required lifecycle-linked fields, or malformed preimage fields are verifier refusal conditions.

### 7) Signature verification and comparison policy (v2)

Verifier policy remains typed and fail-closed:

- reject on domain/environment/chain/genesis mismatch;
- reject on unsupported schema version or suite;
- reject on unknown/transport authority roots;
- reject on malformed key material or bad signature;
- reject on lifecycle-field inconsistency (e.g., `rotate` without `previous_*`, `revoke` without reason);
- reject on sequence downgrade or same-sequence conflicting digest.

Comparison outcomes:

- first v2 in domain (no v2 marker state): accept and persist;
- same sequence + same digest: idempotent accept;
- same sequence + different digest: reject equivocation;
- lower sequence: reject rollback;
- higher sequence: accept upgrade;
- wrong domain/root/key bindings: reject;
- revoked key attempt after revoke state: reject;
- v1 after v2 marker exists: reject downgrade (fail closed);
- v2 after v1 marker exists: allowed only via explicit migration rule below.

### 8) Marker v2 evolution (design-only, no implementation in Run 129)

`PersistentAuthorityStateRecord` evolution target (`record_version=2` in future implementation):

- `authority_schema_version`
- `latest_authority_sequence`
- `latest_key_lifecycle_action`
- `active_key_fingerprint`
- `previous_key_fingerprint`
- `latest_ratification_digest`
- `revoked_key_set_digest` (or explicit future revocation accumulator field)

Migration principle: upgrade in place from v1 marker when first accepted v2 ratification is validated; do not require local reset for normal migration.

### 9) Compatibility and migration policy

- v1 on node with no marker: allowed under existing v1 rules pre-v2 activation.
- v1 on node with v1 marker: allowed under existing v1 rules pre-v2 activation.
- v2 on node with v1 marker: allowed as migration path when v2 verifies and sequence policy passes.
- v1 after v2 marker exists: **refused fail-closed** (downgrade ambiguity).
- v2 lower sequence: refused.
- v2 same sequence + same digest: idempotent.
- v2 same sequence + different digest: refused.
- v2 higher sequence: accepted.
- migration from v1 to v2: first accepted v2 ratification establishes v2 monotonic state; no reset required.
- migration after reset/recovery: reset must not bypass sequence policy; recovered state must still reject downgrade/replay.

Activation policy: v2 acceptance MUST be explicit and domain-bound, tied to authoritative policy (e.g., authority policy version/governance artifact) and MUST NOT be local-config-only on MainNet.

### 10) Future implementation staging

- **Run 130** — implement v2 schema/types/canonical preimage + verifier unit tests.
- **Run 131** — implement marker v2 record extension and migration logic.
- **Run 132** — wire v2 verification/comparison into enforcement surfaces with compatibility gates.
- **Run 133** — release-binary evidence for v2 acceptance/rejection matrix.
- **Run 134+** — key rotation lifecycle.
- **Later** — revocation lifecycle, KMS/HSM custody, MainNet governance artifact support, broader C4/C5 closure work.

### Run 129 explicit non-changes

Run 129 is spec-only and does **not** implement:

- v2 verifier/runtime code;
- production runtime behavior changes;
- trust-bundle wire changes;
- peer-candidate wire changes;
- reset CLI behavior changes;
- authority marker persistence behavior changes;
- rotation/revocation lifecycle;
- KMS/HSM custody;
- MainNet governance artifact verification;
- peer-driven live apply;
- full C4 closure or C5 closure.

## Run 130 update — ratification v2 schema, canonical preimage, and verifier tests

**Type:** Implementation (additive types + verifier tests; no production wiring).
**Date:** 2026-05-24.

Run 130 implements the ratification v2 schema, canonical preimage, domain-separated digest, and verifier primitive exactly per the Run 129 specification. No production enforcement surface is wired to v2.

Run 131 doc-sync checkpoint confirms this Run 130 status remains exact: `RatificationV2Failure` typed failures are landed; marker v2 migration is Run 131 scope; production enforcement wiring remains Run 132; release-binary v2 evidence remains Run 133; rotation/revocation lifecycle remains future work; full C4 and C5 remain open.

### New types and functions

All v2 additions are in `crates/qbind-ledger/src/bundle_signing_ratification.rs`:

- `BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2` — domain tag `QBIND:BUNDLE-SIGNING-RATIFICATION:v2` (distinct from v1).
- `BUNDLE_SIGNING_RATIFICATION_VERSION_V2 = 2`.
- `BundleSigningRatificationV2Action` enum: `Ratify`, `Rotate`, `Revoke`.
- `BundleSigningRatificationV2` struct — full v2 object with `authority_domain_sequence`, `key_lifecycle_action`, rotation-chain linkage, and revocation fields.
- `ratification_v2_signing_preimage` — deterministic length-prefixed preimage.
- `canonical_ratification_v2_digest` — SHA3-256 of preimage.
- `RatificationV2Failure` — 22-variant typed failure enum.
- `RatifiedBundleSigningKeyV2` — typed success result.
- `RatificationV2VerifierInputs` / `verify_bundle_signing_key_ratification_v2` — verifier entry point.
- `v2_test_helpers::build_signed_ratification_v2` — test-only signer.

### Security invariants

- v2 domain tag is cryptographically distinct from v1; no preimage ambiguity.
- `authority_domain_sequence` bound into every v2 digest; sequence 0 is invalid.
- `key_lifecycle_action` bound into every v2 digest.
- Authority root lookup restricted to `bundle_signing_authority_roots`; transport roots rejected with `TransportRootNotAllowed`.
- All ML-DSA-44 signature verification performed via the existing `MlDsa44SignatureSuite` adapter — no parallel crypto stack.
- Rotation fields absent on `Ratify`; absent on `Revoke`; mandatory on `Rotate`.
- `Revoke` requires at least one of `revocation_reason` or `capabilities_scope`.

### Test coverage

32 new v2-specific tests (preimage determinism, domain tag separation, per-field digest change, verifier success for all three actions, typed failure cases, v1 regression, v1/v2 separation).

### Run 130 explicit non-changes

Run 130 does NOT implement:

- production v2 enforcement wiring (startup, reload-check, peer-candidate, live inbound 0x05, SIGHUP);
- authority marker v2 migration;
- signing-key rotation lifecycle;
- signing-key revocation lifecycle;
- KMS/HSM custody;
- MainNet governance artifact verification;
- peer-driven live apply;
- full C4 closure or C5 closure.

Static production source-code anchors remain rejected. Local config alone is still not enough for MainNet bundle-signing authority. v1 verifier behavior is preserved bit-for-bit.

C4 status after Run 130: **OPEN but narrowed** — ratification v2 schema/types/preimage/verifier primitive are now implemented and tested. Remaining open pieces: production v2 enforcement wiring (Run 132), marker v2 migration (Run 131), signing-key rotation/revocation lifecycle (Run 134+), peer-driven live apply, KMS/HSM custody, MainNet governance artifact verification, validator-set rotation, full C4 closure, C5 closure.
## Run 131 update — authority marker v2 primitive

**Type:** Implementation (additive marker types + comparison helpers; no production surface wiring).
**Date:** 2026-05-24.

Run 131 implements the authority marker v2 primitive needed to compose the Run 130 v2 verifier into validation-only surfaces in Run 132. No production v2 surface is wired in Run 131.

### New types and functions

All v2 marker additions live alongside the existing Run 117/118 authority marker code:

- `PersistentAuthorityStateRecordVersioned::{V1, V2}` — versioned record dispatch.
- `PersistentAuthorityStateRecordV2` — versioned record schema carrying `schema_version=2`, latest accepted `authority_domain_sequence`, latest `key_lifecycle_action`, latest active/previous key fingerprints, and latest accepted v2 ratification digest.
- `derive_authority_state_v2_from_ratification(...)` — derives a v2 marker candidate from a verified `RatifiedBundleSigningKeyV2` (Run 130) under an explicit `AuthorityStateUpdateSource`.
- `compare_authority_marker_v2(...)` — typed comparison helper that distinguishes idempotent (same sequence + same digest), upgrade-compatible (higher sequence), lower-sequence-refused, same-sequence-different-digest-refused, and v1-after-v2-refused outcomes.
- `migrate_authority_marker_v1_to_v2(...)` — one-way migration helper used by Run 132 validation-only surfaces to assemble a v2 marker candidate from an existing v1 marker on disk.
- `prepare_v2_marker_for_acceptance(...)` — validation-only assembly entry point that does not persist.

### Security invariants

- v2 marker comparison NEVER persists; persistence is the caller's responsibility on mutating surfaces.
- v1 marker on-disk format is preserved bit-for-bit; the versioned dispatch is the only consumer of the new variant.
- Migration from v1 to v2 marker state is one-way and explicit; downgrade is not modeled.
- v2 marker comparison is fail-closed on corrupt records, unknown schema versions, and bound-domain mismatches.

### Run 131 explicit non-changes

- No production v2 surface wiring (deferred to Run 132).
- No release-binary v2 evidence (deferred to Run 133).
- No CLI flag changes.
- No trust-bundle or peer-candidate wire format changes.
- No automatic v1→v2 marker migration on production surfaces.
- No rotation or revocation lifecycle implementation.
- No KMS/HSM, MainNet governance artifact, or peer-driven live apply.
- No full C4 or C5 closure claim.

## Run 132 update — v2 validation-only surface wiring

**Type:** Implementation (validation-only surface wiring; no mutating-surface wiring; no persistence).
**Date:** 2026-05-24.

Run 132 wires v2 ratification and v2 marker compatibility into the two validation-only binary surfaces: `--p2p-trust-bundle-reload-check` and the local `--p2p-peer-candidate-check`. Mutating-surface v2 wiring, live inbound `0x05` v2 wiring, and release-binary v2 evidence remain deferred.

### What Run 132 wired

- Run 132 wired v2 validation-only support for `reload-check` and local `peer-candidate-check`.
- Run 132 added versioned sidecar dispatch via `VersionedRatificationSidecar::{V1, V2}` and `load_versioned_ratification_from_path()` in `crates/qbind-node/src/pqc_ratification_input.rs`.
- Run 132 preserved existing v1 behavior: the existing `load_ratification_from_path` and `preflight_run_123_validation_only_marker_check` v1 path are unchanged. When the operator-supplied sidecar is v1, dispatch falls through to the v1 path unmodified.
- Run 132 uses the Run 130 v2 verifier (`verify_bundle_signing_key_ratification_v2`) and Run 131 v2 marker comparison (`derive_authority_state_v2_from_ratification` + `compare_authority_marker_v2`).

### v2 compatibility/downgrade policy enforced on validation-only surfaces

- v1-after-v2 rejects (typed `V1AfterV2Rejected`).
- lower v2 sequence rejects (typed `LowerV2SequenceRefused`).
- same-sequence/different-digest rejects (typed `SameSequenceDifferentDigestRefused`).
- same-sequence/same-digest is idempotent (typed `Idempotent`).
- higher v2 sequence is upgrade-compatible (typed `UpgradeCompatible`).
- v2-after-v1 is accepted only as an explicit migration candidate (typed `V2AfterV1MigrationCandidate`).
- unknown/malformed sidecar schema fails closed (typed `VersionedRatificationInputError`).

### Persistence invariant

Validation-only surfaces never persist marker state. This is enforced structurally (no `persist_authority_state_atomic` call on any validation-only path) and verified by 9 dedicated unit tests including `run132_v2_no_marker_write_occurs_in_any_case`.

### Deferred / future scope

- Live inbound `0x05` v2 wiring remains deferred.
- Mutating-surface v2 wiring (startup `--p2p-trust-bundle`, process-start reload-apply, SIGHUP live reload) remains deferred.
- Release-binary v2 evidence remains open until Run 133.
- Rotation lifecycle, revocation lifecycle, KMS/HSM custody, MainNet governance artifact support, peer-driven live apply, full C4 and C5 closure remain future work.

### Run 132 explicit non-changes

- No v2 wiring into any mutating surface.
- No v2 marker persistence from validation-only checks.
- No live inbound `0x05` v2 wiring.
- No trust-bundle wire-format change.
- No peer-candidate wire-format change.
- No reset CLI behavior change.
- No KMS/HSM, MainNet governance artifact, or peer-driven live apply implementation.
- No rotation or revocation lifecycle implementation.
- No full C4 or C5 closure claim.

Static production source-code anchors remain rejected. Local config alone is still not enough for MainNet bundle-signing authority. v1 verifier behavior is preserved bit-for-bit.

## Run 133 update — release-binary v2 validation-only evidence

Run 133 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_133.md`) is the **release-binary evidence run** for the Run 132 v2 validation-only wiring on the `--p2p-trust-bundle-reload-check` and `--p2p-trust-bundle-peer-candidate-check` surfaces. This is evidence-only — no production runtime code path is changed by Run 133.

A new ephemeral fixture helper (`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`) mints ML-DSA-44 authority and bundle-signing key material, a Run 101 genesis with the authority root bound in, a signed baseline trust bundle, a signed candidate trust bundle, a v1 ratification sidecar (for the v1 fall-through regression), the full Run 132 acceptance/rejection matrix of v2 ratification sidecars (`ratify@seq=1`, `ratify@seq=2`, `rotate@seq=2`, `revoke@seq=2`, `equivocation@seq=1`, `lower@seq=1`, `bad-signature`, `wrong-chain`, `wrong-environment`, `wrong-genesis`, `sequence-zero`), and two pre-seeded markers (`seed-marker.v1.json` and `seed-marker.v2.seq1.json`, plus `seed-marker.v2.seq2.json`) so the harness can drive every typed accept reason and every typed refusal path against `target/release/qbind-node`.

A new harness (`scripts/devnet/run_133_v2_validation_only_release_binary.sh`) builds the release binary, mints the fixtures, and runs the 16-scenario matrix asserting exit code, expected typed log line, and the four-part non-mutation invariant (no `pqc_authority_state.json` is created/rewritten/left as `.tmp`, no `pqc_trust_bundle_sequence.json` is written, no apply / propagate / session-eviction / SIGHUP / KMS markers appear in stderr). All 16 scenarios pass.

Run 133 also fixes three pre-existing release-build warnings on `qbind-node` so the harness can build warning-free: the deprecated `bincode::config()` call at two sites in `crates/qbind-node/src/binary_consensus_loop.rs` is replaced by `bincode::options()` (wire-compatible; 63 binary-consensus tests pass), and the release-build unused `worker_id` parameter in `crates/qbind-node/src/verify_pool.rs::worker_loop` is silenced under `cfg(not(debug_assertions))` while the debug-build self-check remains verbatim.

Run 133 confirms the Run 132 trust-anchor model invariants on the binary path: (1) validation-only surfaces never persist marker state, regardless of acceptance/refusal outcome or sidecar version; (2) the v1 path is unchanged when the sidecar is v1; (3) the v2 path emits its typed accept reason verbatim on success and its typed refusal verbatim on failure, with `Run 132: VERDICT=invalid` on every refusal; (4) the v2-after-v1 case yields `V2AfterV1MigrationCandidate` (not a refusal) on the validation-only surface, leaving explicit migration to a future Run on the mutating surface; (5) the same-sequence-different-digest case fail-closes the binary at runtime with the typed `V2SameSequenceDifferentDigestRefused`, demonstrating per-authority-domain monotonicity from Run 129 / Run 131 is honored end-to-end.

Run 133 does NOT change any wire format, does NOT wire v2 into any mutating surface, does NOT persist v2 markers from the release binary on any path, does NOT introduce KMS/HSM custody, does NOT add MainNet governance artifact verification, does NOT implement signing-key rotation or revocation, does NOT change the v1 marker on-disk format, and does NOT auto-migrate existing v1 markers on production. Trust-anchor model invariants from Run 050–132 are preserved verbatim.

## Run 134 update — v2 mutating-surface accept-and-persist on the process-start reload-apply path

Run 134 narrows the Run 133 "v2 wired only on validation-only surfaces" status: as of Run 134, the **process-start reload-apply** mutating surface (`--p2p-trust-bundle-reload-apply-path` + `--p2p-trust-bundle-reload-apply-enabled`) now accepts v2 sidecars, runs the Run 130 v2 verifier and the Run 131 v2 marker comparison as a pre-mutation preflight, drives the Run 070 apply pipeline, and persists the v2 marker after `commit_sequence`. The v1 path remains bit-for-bit unchanged. Other mutating surfaces (startup `--p2p-trust-bundle`, SIGHUP live reload, snapshot/restore, peer-driven live apply) remain v1-only and are deferred to follow-on runs.

### What Run 134 wired into the trust-anchor authority model

- `persist_authority_state_v2_atomic` (in `crates/qbind-node/src/pqc_authority_state.rs`) mirrors the Run 117 v1 atomic-persister durability contract bit-for-bit (`tmp + sync_all(tmp) + rename + sync_all(parent_dir)`); the on-disk JSON keeps the same versioned discriminator so `load_authority_state_versioned` reads back as `PersistentAuthorityStateRecordVersioned::V2`.
- `decide_marker_acceptance_v2(...)` composes Run 131 `derive_authority_state_v2_from_ratification` + `load_authority_state_versioned` + `compare_authority_marker_v2`; performs zero disk writes; returns a typed `MutatingSurfaceMarkerV2Error` (10 variants) or a `MarkerAcceptDecisionV2` carrying the derived candidate + `should_persist` + `MarkerAcceptKindV2` (`FirstV2Write` / `Idempotent` / `UpgradeV2{prev,new}` / `V2AfterV1Migration`).
- `persist_accepted_v2_marker_after_commit_boundary(...)` is the only Run 134 v2-write path; it is the post-`commit_sequence` partner of `decide_marker_acceptance_v2` and is a strict no-op when `should_persist=false`.
- `preflight_run_134_v2_marker_decision(...)` and the reload-apply dispatch in `crates/qbind-node/src/main.rs` invoke the v2 path when `Run105ReloadCheckContextData::ratification_v2` is `Some`, driving the apply pipeline through `apply_validated_candidate_with_previous` **without** a v1 `RatificationEnforcementContext` (the v2 verifier already ran in the preflight).

### Run 134 preserved invariants

- v1 reload-apply path (Run 119) is bit-for-bit unchanged when the sidecar is v1 (or absent under `AllowLegacyUnratified`).
- Run 070 apply-callback ordering (`snapshot_active` → `swap_trust_state` → `evict_sessions` → `commit_sequence`) is preserved bit-for-bit on the v2 path (asserted by `run134_clean_v2_first_write_decide_then_apply_then_persist`).
- Run 118 §D / Run 131 stale-by-one crash-window rule: a mid-write crash AFTER `commit_sequence` leaves the on-disk v2 marker stale-by-one but safely replayable as `UpgradeV2` on the next accepted v2 ratification; a non-crash persist failure is FATAL on the binary and surfaced operatorially.
- Fail-closed compare-before-mutation: rollback (`LowerV2SequenceRefused`), same-sequence equivocation (`SameSequenceConflictingDigest`), and wrong-domain rejects all run BEFORE any apply callback fires; on reject the on-disk marker is byte-for-byte unchanged and no sequence-file write occurs.
- MainNet behavior: `--p2p-trust-bundle-reload-apply-path` requires `--data-dir`, the same precondition the v1 path enforces; the v2 preflight returns `Ok(None)` when `--data-dir` is unset (DevNet-only convenience, identical to the v1 branch).
- CLI flag surface, wire formats, /metrics families: all unchanged.

### Run 134 explicit non-changes

- SIGHUP live-reload-apply v2 wiring (Run 074 / Run 121 pattern) — deferred.
- Snapshot/restore v2 marker wiring (Run 124 pattern) — deferred.
- Startup `--p2p-trust-bundle` v2 wiring (Run 120 pattern) — deferred.
- Peer-driven live apply v2 wiring (live inbound `0x05` over the v2 protocol) — deferred.
- Release-binary v2 mutating-surface evidence harness mirroring Run 133's shape — deferred.
- Signing-key rotation/revocation lifecycle plumbing beyond what the Run 130 verifier and Run 131 derivation already enforce — deferred.
- KMS/HSM custody, MainNet governance artifact verification, validator-set rotation, peer-driven live apply: all deferred.

### C4 status after Run 134

**OPEN but further narrowed for the process-start reload-apply mutating surface**. v2 schema/verifier (Run 130), v2 marker primitives (Run 131), v2 validation-only wiring (Run 132), release-binary v2 validation-only evidence (Run 133), and v2 mutating-surface wiring on the process-start reload-apply path (Run 134) are all implemented and tested. Remaining open pieces: v2 wiring on the other mutating surfaces (startup `--p2p-trust-bundle`, SIGHUP live reload, snapshot/restore), peer-driven live apply v2, release-binary v2 mutating-surface evidence, signing-key rotation/revocation lifecycle, KMS/HSM custody, MainNet governance artifact verification, validator-set rotation, full C4 closure, C5 closure. Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority. No Run 050–133 invariant was changed.

### What Run 135 added to the trust-anchor authority model

Nothing — Run 135 added **release-binary evidence**, not protocol or
code surface. The behaviour described in the Run 134 section above is
the protocol behaviour Run 135 proves on the actual release binary.

Run 135 captured release-binary evidence for the Run 134 process-start
reload-apply v2 wiring via `scripts/devnet/run_135_v2_reload_apply_release_binary.sh`
(harness) and `docs/devnet/run_135_v2_reload_apply_release_binary/`
(archive). The harness reuses the Run 133 fixture helper
(`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`)
unchanged, then drives `target/release/qbind-node` through 9 scenarios:

- **A1** first v2 write (no marker, ratify@seq=1) — accepted, v2
  marker persisted with `record_version=2`, `latest_authority_domain_sequence=1`,
  `latest_lifecycle_action="ratify"`, `last_update_source="reload-apply"`;
  Run 070 `sequence_commit=ok` strictly precedes the
  `[run-134] v2 authority-marker persisted` log line.
- **A2** v2-after-v1 migration (seeded v1 marker, ratify@seq=2) —
  accepted, v2 marker replaces v1 on disk only after
  `commit_sequence`; `cmp -s` confirms the v1 seed and v2 result
  differ.
- **A3** idempotent same-digest (seeded v2-seq=1, same-seq1 sidecar) —
  accepted, binary prints `v2 authority-marker unchanged (idempotent;
  no rewrite)`, `cmp -s` confirms marker bytes byte-identical
  pre/post.
- **A4** higher-sequence upgrade (seeded v2-seq=1, ratify@seq=2) —
  accepted, marker advances from seq=1 to seq=2 only after
  `commit_sequence`.
- **R1** lower-sequence (seeded v2-seq=2, lower-seq=1 sidecar) —
  refused before mutation; binary prints
  `[run-134] FATAL: reload-apply refused by v2 authority-marker preflight: Run 134: v2 authority-marker rollback rejected: attempted authority_domain_sequence=1 is lower than persisted authority_domain_sequence=2 (fail closed)`,
  exit code 1, marker bytes byte-identical pre/post, no sequence file
  written, no `.tmp` sibling.
- **R2** same-sequence / different-digest (seeded v2-seq=1, equivocation
  sidecar) — refused before mutation with typed
  `SameSequenceConflicting…` message, marker bytes byte-identical
  pre/post.
- **R3a** bad signature — Run 130 verifier refuses; binary surfaces
  `signature failed ML-DSA-44 PQC verification` through the Run 134
  preflight; no marker created.
- **R3b** wrong environment — Run 130 verifier refuses; binary
  surfaces `environment mismatch` through the Run 134 preflight; no
  marker created.
- **V1** v1 regression (no marker, valid v1 ratification) — Run 119
  v1 path runs unchanged; on-disk marker is V1
  (`record_version=1`); the binary emits **no**
  `[run-134] reload-apply v2 ratification path SELECTED` or
  `[run-134] v2 authority-marker persisted` log line. Proves the v1
  path is fully preserved when no v2 sidecar is supplied.

The R4 (apply failure after preflight) behaviour is **not**
reproducible on a release binary with operator-supplied flags alone;
it remains covered by the Run 134 §C.3 test-only scenario
`run134_apply_failure_after_v2_accept_does_not_persist_marker`
(`crates/qbind-node/tests/run_134_reload_apply_v2_authority_marker_tests.rs`).

Across **every** scenario, the Run 135 harness asserts the release-
binary stderr contains no `SIGHUP-driven live trust-bundle reload-apply
trigger is ACTIVE`, no `KMS|HSM`, no `live inbound 0x05`, no
`peer-driven live apply`, no `signing-key (rotation|revocation)
lifecycle`, and no `[run-132] reload-check v2` /
`[run-132] peer-candidate-check v2` lines — proof that Run 135 only
exercises the Run 134 process-start reload-apply v2 surface and
nothing beyond it.

### Run 135 preserved invariants

- v1 verifier behaviour — unchanged on every surface.
- v1 marker on-disk format — unchanged.
- Run 134 §2.3 dispatch contract: v2 dispatched only when
  `ctx_data.ratification_v2.is_some()`; v1 path bit-for-bit when no v2
  sidecar is supplied (V1 scenario above).
- Run 070 apply-pipeline ordering
  (`validate → snapshot → swap → evict_sessions → commit_sequence`)
  preserved on every accepted scenario; v2 marker persist runs strictly
  after `commit_sequence`.
- Run 118 §D / Run 131 stale-by-one crash-window rule preserved.
- CLI flag surface — unchanged.
- /metrics families — unchanged.
- Trust-bundle, peer-candidate, and ratification wire formats —
  unchanged.

### Run 135 explicit non-changes

- SIGHUP live-reload-apply v2 wiring — still deferred (Run 074 / Run
  121 pattern).
- Snapshot/restore v2 marker wiring — still deferred (Run 124 pattern).
- `--p2p-trust-bundle` startup-acceptance v2 wiring — still deferred
  (Run 120 pattern).
- Peer-driven live apply v2 — still deferred.
- Live inbound `0x05` v2 — still deferred.
- Signing-key rotation/revocation lifecycle plumbing beyond what the
  Run 130 verifier and Run 131 derivation already enforce — still
  deferred.
- KMS/HSM custody, MainNet governance artifact verification,
  validator-set rotation — still deferred.

### C4 status after Run 135

**OPEN but further narrowed for the process-start reload-apply mutating
surface, now release-binary-evidenced**. v2 schema/verifier (Run 130),
v2 marker primitives (Run 131), v2 validation-only wiring (Run 132),
release-binary v2 validation-only evidence (Run 133), v2 mutating-
surface wiring on the process-start reload-apply path (Run 134), and
release-binary v2 mutating-surface evidence on the process-start
reload-apply path (Run 135) are all implemented and proved
end-to-end on the binary. Remaining open pieces: v2 wiring on the
other mutating surfaces (startup `--p2p-trust-bundle`, SIGHUP live
reload, snapshot/restore), peer-driven live apply v2, signing-key
rotation/revocation lifecycle, KMS/HSM custody, MainNet governance
artifact verification, validator-set rotation, full C4 closure, C5
closure. Static production source-code anchors remain rejected. Local
config alone remains insufficient for MainNet bundle-signing
authority. No Run 050–134 invariant was changed.

## Run 136 update — v2 mutating-surface accept-and-persist on the startup `--p2p-trust-bundle` path

Run 136 ports the Run 134 v2 mutating-surface composition onto the
**startup `--p2p-trust-bundle`** binary surface (the same code path that
the Run 105/106 startup gate and the Run 120 v1 marker preflight guard).
The wiring is a thin dispatcher in `crates/qbind-node/src/main.rs` that
inspects `Run105ReloadCheckContextData::ratification_v2` and:

- When the operator supplied a v2 sidecar (schema_version=2), SKIPS the
  v1-only `apply_run_105_ratification_gate_at_startup` (which cannot
  parse v2) and runs a new
  `preflight_run_136_v2_marker_decision_for_startup` helper that
  composes the Run 130 v2 verifier with the Run 134
  `decide_marker_acceptance_v2` helper. The persisted-record audit tag
  is `AuthorityStateUpdateSource::StartupLoad`.
- When the operator supplied a v1 sidecar or no sidecar, the v1 startup
  flow (Run 105 gate + Run 120 preflight) runs bit-for-bit unchanged.

The v2 marker is persisted via the existing
`persist_accepted_v2_marker_after_commit_boundary` helper AFTER the
Run 055 `check_and_update_sequence` write succeeds — exactly the same
ordering the Run 120 v1 path uses. The two persist blocks (v1 vs v2)
are mutually exclusive by construction; exactly one fires per startup.

### Run 136 preserved invariants

- The v1 startup gate / Run 120 v1 marker preflight are untouched
  for v1 sidecars and the no-sidecar legacy DevNet path.
- The Run 134 reload-apply v2 wiring is untouched (Run 136 reuses the
  same `decide_marker_acceptance_v2` / `persist_accepted_v2_marker_after_commit_boundary`
  helpers; only the audit-tag value differs).
- The Run 055 trust-bundle sequence persistence ordering is untouched
  (preflight decide before the write; persist v2 after the write).
- A v2 verifier failure / lower-sequence rollback / same-sequence
  equivocation / wrong-domain / corrupt persisted marker on the
  startup path FATAL-exits before any Run 055 sequence write, before
  any bundle-root merge into the live trust set, before any P2P
  startup, and without rewriting the marker file.

### Run 136 explicit non-changes

- No new CLI flags. No changes to existing flags.
- No new /metrics counters; the new path emits operator-log lines
  only.
- No on-disk schema changes (the v2 marker schema is the same one
  Run 131 introduced and Run 134/135 already write on the
  reload-apply path).
- No change to MainNet behaviour beyond what the Run 130 v2 verifier
  + Run 131 monotonic comparison already enforce.
- Snapshot/restore (Run 124), SIGHUP live reload (Run 074/121),
  peer-driven live apply (Run 109/114), signing-key rotation/
  revocation lifecycle, KMS/HSM custody, MainNet governance artifact
  verification, validator-set rotation — still deferred.

### C4 status after Run 136

**OPEN but further narrowed: the startup `--p2p-trust-bundle` mutating
surface now accepts v2 ratifications and persists v2 markers in the
same accept-and-persist shape as the process-start reload-apply
surface**. The remaining open mutating surfaces are SIGHUP live reload
and snapshot/restore. All other open Run 135 items remain open. No
Run 050–135 invariant was changed.
## Run 137 update — release-binary evidence for the Run 136 startup `--p2p-trust-bundle` v2 wiring

Run 137 captures release-binary evidence for the Run 136 startup
`--p2p-trust-bundle` v2 mutating-surface wiring. The harness
`scripts/devnet/run_137_v2_startup_trust_bundle_release_binary.sh`
exercises an 11-scenario matrix on DevNet against
`target/release/qbind-node` using the mutating startup flag block
(`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>
--p2p-trust-bundle <bundle> --p2p-trust-bundle-signing-key
<ratified-spec> --p2p-trust-bundle-ratification <sidecar>
--p2p-trust-bundle-ratification-enforcement-enabled --data-dir
<data_dir>`) and reuses the Run 133 ephemeral fixture helper
(`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`).
No production runtime source changed.

### Run 137 evidence shape

- Acceptance scenarios (A1 v2-first-write, A2 v2-after-v1 migration,
  A3 idempotent, A4 higher-sequence upgrade) bound the still-running
  release binary with `timeout --signal=TERM --kill-after=5s` after
  observing the `[run-136] v2 authority-marker persisted ...` /
  `[run-136] v2 authority-marker unchanged ...` log line, and prove
  the post-`commit_sequence` ordering on every accepted scenario:
  the `[binary] Run 055: trust-bundle sequence persistence` log line
  is **strictly earlier** in stderr than the corresponding
  `[run-136] v2 authority-marker persisted` / `unchanged` line.
- Acceptance scenarios prove the audit-tag invariant — the on-disk
  marker after commit carries
  `last_update_source = "startup-load"` (the
  `AuthorityStateUpdateSource::StartupLoad` discriminator the
  Run 136 preflight passes into `decide_marker_acceptance_v2`).
- Rejection scenarios (R1 lower-sequence, R2 same-sequence different-
  digest, R3a bad signature, R3b wrong environment, R4 wrong chain,
  R5 wrong genesis) exit `rc=1` BEFORE the binary prints
  `[binary] P2P transport up`, AND before any sequence-file or `.tmp`
  marker sibling is written, AND with pre-seeded marker bytes byte-
  identical post-run.
- The v1 regression scenario (V1) exercises the unchanged Run 105/106
  + Run 120 startup path with a valid v1 ratification sidecar and
  proves no `[run-136]` log line is emitted.
- The Run 134 §C.3 / Run 135 R4 / Run 136 §A.8 corner case (apply
  failure between the v2 preflight and the Run 055 commit boundary)
  is not feasible to trigger on a release binary with operator-
  supplied flag inputs alone and remains test-only.

### Run 137 explicit non-changes

- No production runtime source changed; the `qbind-node` and
  `qbind-ledger` `--lib` test counts and Run 134/Run 119/Run 112
  regressions are bit-for-bit unchanged from Run 136.
- No new CLI flag, no log-line change, no metric change, no trust-
  bundle / ratification / peer-candidate wire format change.
- No new mutating surface is wired for v2: SIGHUP live reload,
  snapshot/restore, peer-driven live apply, live inbound `0x05`, and
  the signing-key rotation/revocation lifecycle plumbing all remain
  deferred.
- No KMS/HSM custody, no MainNet governance artifact verification, no
  validator-set rotation.

### C4 status after Run 137

**OPEN but further narrowed: the startup `--p2p-trust-bundle`
mutating surface — already wired by Run 136 — is now release-binary-
evidenced**. The remaining open mutating surfaces are SIGHUP live
reload and snapshot/restore. All other Run 136 open items remain
open. No Run 050–136 invariant was changed.

## Run 138 — SIGHUP live-reload as a v2-marker-discipline mutating surface

Prior to Run 138, two of the three in-process mutating surfaces accepted
v2 ratifications and produced v2 authority-state markers:

| Mutating surface                                | v1 wiring | v2 wiring |
|-------------------------------------------------|-----------|-----------|
| Process-start reload-apply                      | Run 119   | **Run 134** |
| Startup `--p2p-trust-bundle` (one-shot apply)   | Run 119   | **Run 136** |
| SIGHUP live trust-bundle reload                 | Run 121   | **Run 138** |

Run 138 closes that gap by wiring the v2 verifier (Run 130) and the v2
marker accept-and-persist composition (Run 131) onto the Run 074 SIGHUP
live-reload controller. Selection is automatic per-trigger: a
`schema_version=2` sidecar dispatches through the v2 path, and a
`schema_version=1` or absent sidecar preserves the Run 121 v1 path
bit-for-bit.

The v2 SIGHUP path enforces the same invariants the Run 134 reload-apply
and Run 136 startup v2 paths enforce:

* **Pre-mutation refusal is non-fatal**: v2 verifier failures and v2
  marker pre-mutation refusals surface as `LiveReloadOutcome::MarkerRejectedV2`
  with no live mutation, no eviction, no sequence write, and no marker
  write.
* **Post-commit persist failure is fatal**: a v2 marker-persist
  failure after `sequence_commit=ok` surfaces as
  `LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 { applied,
  marker_error }` with `is_fatal() == true`, mirroring the Run 121 v1
  fatal contract; the SIGHUP signal-handler task initiates graceful
  shutdown.
* **Audit source**: the v2 marker carries
  `AuthorityStateUpdateSource::SighupReload` — the existing v1 SIGHUP
  audit variant is reused (no `AuthorityStateUpdateSource` schema
  drift).
* **V1→V2 migration through SIGHUP**: an existing on-disk v1 marker is
  rewritten as v2 strictly AFTER the Run 070 sequence commit succeeds.
* **Crash-window reconciliation**: a marker that was committed but not
  persisted (because the process was killed between sequence commit and
  marker write) reconciles on the next mutation as `UpgradeV2` under the
  Run 131 stale-by-one discipline.

Run 138 does NOT change v1 verifier behaviour, the v1 marker on-disk
format, the trust-bundle / peer-candidate / ratification wire format,
the CLI flag surface, or the `/metrics` family set. Snapshot/restore v2
marker wiring, live inbound `0x05` v2 wiring, peer-driven live apply,
signing-key rotation/revocation lifecycle, KMS/HSM custody, MainNet
governance artifact verification, and full C4 / C5 closure all remain
out of scope.

## Run 139 — SIGHUP live-reload v2 mutating surface release-binary evidence

Run 139 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_139.md`) exercises the
Run 138 source/test wiring end-to-end on a real
`target/release/qbind-node` daemon driven by a real `kill -HUP <pid>`
against ephemeral DevNet fixtures. The harness
`scripts/devnet/run_139_sighup_v2_live_reload_release_binary.sh` runs
the eleven acceptance / rejection / regression scenarios A1–A4, R1–R4,
R6–R8 on the release binary (R5 — post-commit marker-persist failure —
is release-binary-infeasible without source modification or racy
filesystem tricks and is documented as partial-positive, inheriting
coverage from the Run 138 source-level orchestration shape and the
`run138_r6_v2_marker_persist_failure_after_commit_is_fatal` integration
test). Per-scenario evidence (stdout / stderr, daemon exit code,
captured PID, signal timestamps, pre / post SHA-256 of
`pqc_authority_state.json` and `pqc_trust_bundle_sequence.json`, and a
full data-dir inventory) lands under
`docs/devnet/run_139_sighup_v2_live_reload_release_binary/`. Run 139
introduces no production runtime source changes, no test changes, no
CLI flag changes, no metric changes, and no wire-format / schema
changes; it reuses the existing
`run_133_v2_validation_only_fixture_helper` release example for
fixture minting.

## Run 140 — snapshot/restore v2 authority-marker parity (source/test only)

Run 140 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_140.md`) extends the
authority model's snapshot/restore surface to recognize the v2 authority
anti-rollback marker (Run 130 `PersistentAuthorityStateRecordV2`) at
parity with the existing v1 marker (Run 117 / 122 / 124). The
`StateSnapshotMeta` in `qbind-ledger` is extended additively with an
`authority_state_v2: Option<AuthorityStateSnapshotMetaV2>` carrier that
mirrors the security-relevant fields of
`PersistentAuthorityStateRecordV2` (`chain_id_hex`, `environment`,
`genesis_hash_hex`, `authority_root_fingerprint` /
`authority_root_suite_id`, `active_bundle_signing_key_fingerprint` /
`active_bundle_signing_key_suite_id`,
`latest_authority_domain_sequence`, `latest_lifecycle_action_byte`,
`previous_bundle_signing_key_fingerprint`,
`latest_ratification_v2_digest`, `revoked_key_metadata`). The JSON key
is omitted entirely when `None`, so the on-wire and on-disk snapshot
meta schema does not drift for any snapshot that does not advertise a
v2 marker.

On restore, when `meta.authority_state_v2.is_some()`, the new
`verify_snapshot_authority_state_for_restore_v2(...)` entry point
reconstructs a `PersistentAuthorityStateRecordV2` from the snapshot
carrier and routes the accept/reject decision through the **existing**
Run 130 `compare_authority_marker_v2(persisted, candidate)`; the v2
restore accept set is therefore exactly the v2 comparison accept set
(`FirstV2MarkerAccepted`, `SameV2MarkerIdempotent`,
`HigherSequenceAccepted`, `V2AfterV1ExplicitMigrationAllowed`) under
the additional restore-surface preconditions that (a) both the local
marker (when present) and the snapshot v2 block validate against the
runtime trust domain `(environment, chain_id, genesis_hash)` and
(b) the snapshot does not simultaneously advertise both a v1 and a v2
authority block (such a snapshot is rejected as
`RejectAmbiguousSnapshotMarkers` without consulting either side).
A snapshot with no `authority_state_v2` block is dispatched to the
Run 124 v1 path verbatim, so v1 restore behavior is preserved
bit-for-bit; a v2 marker is never fabricated when the snapshot does
not carry one. The restore-surface check is pure with respect to disk:
accept and reject paths both preserve the local marker file bytes
verbatim, and the existing materialization order (authority check →
state checkpoint copy → audit marker) is preserved so a reject leaves
the on-disk state byte-identical to its pre-restore form.

Run 140 is source/test wiring only. Release-binary snapshot/restore v2
evidence is **deferred to Run 141**. Live inbound `0x05` v2 wiring,
peer-driven live apply, signing-key rotation/revocation lifecycle,
KMS / HSM custody, MainNet governance artifact verification, full C4
closure, and C5 closure all remain out of scope.
## Run 141 — release-binary evidence for snapshot/restore v2 authority-marker parity (evidence only)

Run 141 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_141.md`) supplies the
release-binary observation evidence that Run 140 explicitly deferred
for the snapshot/restore v2 authority-marker surface. No protocol or
runtime invariant is changed; the protocol surface is unchanged from
Run 140. The deliverables are an opt-in `cargo --example` fixture
helper (`crates/qbind-node/examples/run_141_v2_snapshot_restore_fixture_helper.rs`),
a release-binary harness
(`scripts/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary.sh`),
and the captured artifacts committed under
`docs/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary/`
(`summary.txt`, per-scenario stdout/stderr/exit-code, pre/post local
marker sha256, pre/post data-directory inventories, snapshot
`meta.json`s, snapshot state inventories, in-scope and out-of-scope
grep summaries). The release `qbind-node` binary is exercised through
its pre-existing CLI surface
(`qbind-node --env devnet --data-dir <D> --genesis-path <G>
--expect-genesis-hash <H> --restore-from-snapshot <S>`) across the 11
task-mandated scenarios: A1–A4 v2 accepts (empty data dir, matching
local v2 marker, higher v2 sequence, local v1 marker with matching
authority root via the Run 140 `V2AfterV1ExplicitMigrationAllowed`
path), R1–R9 v2 rejects (every Run 140 reject variant), and R10–R11
v1/legacy regression accepts.

**Authority-model invariants reconfirmed at the release-binary level
in Run 141:**

* The snapshot/restore dispatch routes v2-bearing snapshots through
  the Run 140 v2 entry point and v1-bearing / legacy snapshots through
  the Run 124 v1 entry point with no regression — confirmed by the
  observed `[restore] Run 140 v2 authority-marker check` vs
  `[restore] Run 124 authority-marker check` dispatch labels.
* The Run 140 ambiguity guard (a single snapshot must not advertise
  both an `authority_state` (v1) block and an `authority_state_v2`
  block) fires fail-closed at the release-binary level
  (`RejectAmbiguousSnapshotMarkers` observed in R8).
* The v2 marker trust-domain check (`environment`, `chain_id_hex`,
  `genesis_hash_hex`) is enforced **before** any sequence comparison
  on the v2 path — observed in R4/R5/R6 with the precise diff between
  snapshot-advertised and runtime values logged.
* The Run 130 `compare_authority_marker_v2` rejects
  (`LowerSequenceRejected`, `SameSequenceDifferentDigestRejected`,
  `WrongAuthorityRootRejected`) are all reachable from the real CLI
  surface (R2, R3, R9).
* The restore surface is observably pure with respect to the local
  marker file: `sha256` of the local marker is byte-identical before
  and after invocation across every accept and every reject path
  where a local marker was seeded.
* The on-disk v1 → v2 marker swap (A4) and the higher-sequence v2
  persistence (A3) are **explicitly NOT** performed by the restore
  surface. The authority-model invariant that the restore surface
  never persists a v2 marker (the only v2 marker writers remain the
  existing Run 134 reload-apply, Run 136 startup-apply, and Run 138
  SIGHUP-apply surfaces) is reconfirmed at the release-binary level.
* No out-of-scope surface is reached: zero matches for
  `falling back to --p2p-trusted-root`, `\bDummySig\b`, `\bDummyKem\b`,
  `\bDummyAead\b`, `live inbound 0x05`, `peer-driven live apply`,
  `signing-key (rotation|revocation) lifecycle`, `\bKMS\b`, `\bHSM\b`
  across the entire captured stderr corpus.

Run 141 is release-binary evidence only for the snapshot/restore v2
surface. Live inbound `0x05` v2 wiring, peer-driven live apply,
signing-key rotation/revocation lifecycle, KMS / HSM custody, MainNet
governance artifact verification, validator-set rotation, the on-disk
v1→v2 marker swap surface, the higher-sequence v2 persistence
surface, full C4 closure, and C5 closure all remain out of scope.

## Run 142 — live inbound `0x05` v2 validation-only (source/test only)

Run 142 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_142.md`) extends the
authority-marker validation surface coverage to the **live inbound P2P
peer-candidate `0x05` validation-only receive path**, mirroring the
Run 132 local peer-candidate-check binary surface.

A running node that receives a peer-candidate `0x05` frame from a peer
now validates v2 material with the **same Run 130 v2 verifier and
Run 132 marker-compare discipline** that the local peer-candidate-check
surface already enforces. The dispatcher carries the operator's owned
v2 ratification sidecar as an optional `LiveRatificationConfig::
ratification_v2` slot, plumbed from the existing
`Run105ReloadCheckContextData::ratification_v2` field. Per-frame
routing:

* **Ambiguous v1+v2 in the installed `LiveRatificationConfig`** →
  fail-closed before any inner validation; no marker write; no
  rebroadcast. A single configuration cannot advertise two
  simultaneously valid authority claims to the live receive path.
* **v2-only routing** → the dispatcher bypasses the Run 109 v1
  `try_handle_frame_with_ratification` path (the v1 enforcer cannot
  consume a v2 sidecar), runs every Run 069 / Run 076 inner
  structural / signing / sequence check via `try_handle_frame`, then
  runs the Run 130 verifier and the Run 132
  `verify_marker_for_validation_only_v2` helper on validated outcomes.
* **v1-only routing** → identical to pre-Run-142 behaviour. The new
  v2 helper no-ops because `ratification_v2.is_none()`.
* **No sidecar / Skip gate** → pre-Run-109 legacy unguarded path is
  preserved verbatim.

**Validation-only guarantee on the live `0x05` receive path:**

* `pqc_authority_state.json` is **never** written by this surface.
* `pqc_trust_bundle_sequence.json` is **never** written by this
  surface.
* `LivePqcTrustState` is **never** swapped by this surface.
* Sessions are **never** evicted by this surface.
* Reload-apply, SIGHUP, snapshot/restore are **never** invoked by this
  surface.
* Peer-driven live apply remains out of scope and is not implemented.

**Parity with the local peer-candidate-check surface:** the live
`0x05` v2 validation outcome matches the
`verify_marker_for_validation_only_v2` outcome for the same candidate
— same accept/reject class, same typed error category, same
non-mutation behaviour, same wrong-domain / anti-rollback /
equivocation semantics. Both surfaces fail closed on:

* Run 130 verifier failure (bad signature, wrong environment,
  wrong chain, wrong genesis, missing/wrong authority root, schema
  version != 2).
* Run 132 marker-compare failure (lower sequence, same sequence
  different digest, v1-after-v2 downgrade, corrupt local marker,
  unsupported persisted marker version, wrong-domain on persisted
  marker).

**Propagation interaction:** unchanged from Run 088. Valid v2
candidates may be eligible for rebroadcast only when propagation is
already enabled by operator configuration; the v2 verifier and v2
marker compare run **before** the propagation step, so invalid v2
candidates never rebroadcast. Propagation remains disabled by default
and never causes any apply, sequence write, or marker write under
Run 142.

Run 142 is source/test wiring only. Release-binary live inbound `0x05`
v2 evidence is **deferred to Run 143**. Peer-driven live apply,
signing-key rotation/revocation lifecycle, KMS / HSM custody, MainNet
governance artifact verification, validator-set rotation, full C4
closure, and C5 closure all remain out of scope.
Run 143 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_143.md`) supplies the
release-binary evidence that Run 142 deferred for the **live inbound
P2P peer-candidate `0x05` v2 validation-only receive path**, and
nothing else. **No production runtime source is modified, no CLI flag
is added or renamed, no metric family is changed, no wire / on-disk /
sidecar / marker schema is changed, and no new fixture helper is
introduced** — Run 143 reuses
`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`
verbatim (same `sha256`, same ELF `BuildID` as Run 133's pinned
evidence). The deliverables are a release-binary harness
`scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh`,
the persistent evidence archive
`docs/devnet/run_143_live_inbound_0x05_v2_validation_release_binary/`,
and the canonical report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_143.md`.

The harness builds the real release `qbind-node` and the DevNet helper
binaries (`devnet_pqc_root_helper`, `devnet_pqc_trust_bundle_helper`,
`devnet_consensus_signer_keystore_helper`,
`run_133_v2_validation_only_fixture_helper`), records build provenance
(`sha256`, `build-id`, `git_commit`, `rustc --version`,
`cargo --version`), and stands up the N=3 DevNet topology used by
Run 110 — V0 publisher fires exactly one peer-candidate `0x05` frame
via `--p2p-trust-bundle-peer-candidate-wire-publish-path` +
`--p2p-trust-bundle-peer-candidate-wire-publish-once`; V1 is the v2
validation-only receiver with the operator-supplied v2 ratification
sidecar via `--p2p-trust-bundle-ratification`,
`--p2p-trust-bundle-ratification-enforcement-enabled`, and
`--p2p-trust-bundle-allow-unratified-testnet-devnet` so the Run 106
gate INVOKES the dispatcher; V2 is a second validation-only receiver
that independently exercises the v2 path and observes Run 088
propagation behaviour when V1 has
`--p2p-trust-bundle-peer-candidate-propagation-enabled`.

Run 143 covers the full task-mandated scenario matrix: A1 valid v2
first-seen, A2 v2 idempotent (against seeded v2 marker), A3 v2
higher-sequence (against seeded v2 marker), A4 v2-after-v1 migration
(against seeded v1 marker), R1 lower-sequence reject, R2 same-sequence
different-digest equivocation reject, R3 bad-signature reject (Run 130
verifier failure), R4 wrong-environment reject, R5 wrong-chain reject,
R6 wrong-genesis reject, R7 ambiguous v1+v2 fail-closed via the
operator-supplied versioned sidecar loader preflight refusal (binary
exits non-zero, P2P transport never up), R8 corrupted local marker
fail-closed (corrupt bytes preserved verbatim), R9 v1 live inbound
`0x05` regression (existing Run 109/123 v1 path verbatim, no v2 path
selected, no v2 marker fabricated), R10 DevNet no-opt-in legacy
regression (Run 106 SKIPPED branch, pre-Run-109 unguarded path), R11a
propagation-disabled valid v2 (V1 validates, V2 receives no propagated
copy), R11b propagation-enabled valid v2 (V1 validates AND rebroadcasts
only after validation, V2 receives + validates under v2), R11c
propagation-enabled invalid v2 (V1 rejects, NEVER rebroadcasts,
`propagation_suppressed_invalid_total >= 1`, `propagation_sent_total ==
0`).

For every scenario the harness asserts: (i) the Run 109 `live
peer-candidate ratification gate INVOKED` log on every v2-enforced
scenario and the Run 109 `SKIPPED` log on R10; (ii) the appropriate
`peer_candidate_validated_total` / `peer_candidate_rejected_total`
floor; (iii) `propagation_sent_total == 0` on every reject and
`propagation_suppressed_invalid_total >= 1` on every propagation-
enabled reject; (iv) V0 (the publisher) `peer_candidate_received_total
== 0` (source-peer exclusion preserved by Run 088); (v) byte-identical
`pqc_trust_bundle_sequence.json` and `pqc_authority_state.json` bytes
across pre/post on every node and every scenario; (vi) no
`pqc_authority_state.json.tmp` sibling on any node; (vii) the explicit
out-of-scope denylist — `trust-bundle candidate APPLIED live`,
`VERDICT=applied`, `session_evictions=[1-9]`, `\bSIGHUP\b`,
`reload-apply (success\|failure)`, `RESTORED_FROM_SNAPSHOT`,
`signing-key (rotation\|revocation) lifecycle`, `\bKMS\b`, `\bHSM\b`,
`MainNet governance`, `\bDummySig\b`, `\bDummyKem\b`, `\bDummyAead\b`,
`fallback to --p2p-trusted-root` — produces **zero matches** across
the captured corpus; (viii) the V1 receiver remains running after
every reject scenario (the live dispatcher must not crash on
rejection).

Run 143 is **release-binary evidence only** for the live inbound
`0x05` v2 validation-only surface. No production runtime source is
modified, no peer-driven live apply is added, no SIGHUP / reload-
apply / snapshot/restore mutating surface beyond Run 134/136/138/140's
existing wiring is touched, no v2 marker is persisted from the live
receive path (which never writes the marker file under any code
path), no trust-bundle / peer-candidate / ratification wire format is
changed, no KMS / HSM is introduced, no MainNet governance artifact
is verified, and no signing-key rotation or revocation lifecycle is
implemented. Peer-driven live trust-bundle apply, signing-key
rotation/revocation lifecycle, KMS / HSM custody, MainNet governance
artifact verification, validator-set rotation, full C4 closure, and
C5 closure all remain out of scope.
## Run 144 — peer-driven live trust-bundle apply: authority cannot be
mutated by peers (specification / design only)

Run 144 is a **specification / design only** run. It introduces no
production runtime change, no new mutating surface, no CLI flag, no
metric, and no wire / schema change. It lands the new specification
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` and the
canonical design report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_144.md`. The Run 142/143
validation-only / propagation-only behaviour of the live inbound
peer-candidate `0x05` surface is preserved verbatim.

The authority-model invariant Run 144 formalizes is:

> **Authority cannot be mutated by peer majority on any environment.**
> Receiving a validly signed peer-candidate frame, on its own, does
> not advance the local PQC trust-anchor authority state. A
> peer-driven live apply may only ever occur after passing a
> staged, fail-closed, operator-controllable, and per-environment
> policy-bound pipeline whose authorization gate refuses MainNet
> apply in the absence of separately specified governance /
> ratification / KMS-HSM authority.

Mandatory per-environment authority-model stance after Run 144:

- **DevNet** — peer-driven apply MAY be enabled in a future run
  behind an explicit hidden DevNet-only CLI flag; **disabled by
  default**; the flag MUST refuse to bind on TestNet or MainNet.
  Authority advance from a peer-driven apply on DevNet still uses
  the existing Run 070 contract verbatim.
- **TestNet** — peer-driven apply MAY be enabled only with explicit
  operator opt-in **and** a ratified v2 authority on the receiving
  node; **disabled by default**. Authority advance from a
  peer-driven apply on TestNet still uses the existing Run 070
  contract verbatim and still emits a v2 marker post-commit.
- **MainNet** — peer-driven apply is **BLOCKED** until governance /
  ratification / KMS-HSM authority is separately specified and
  evidenced. Authority on MainNet **cannot** be advanced by a
  peer-driven path under Run 144 or under any subsequent run that
  has not closed the governance / ratification / KMS-HSM
  pre-requisites. Local config alone remains insufficient for
  MainNet bundle-signing authority, and **local peer majority alone
  also remains insufficient** — Run 144 makes this explicit.

When peer-driven apply is eventually implemented, the v2 authority
marker emitted for such an apply MUST carry a distinct
`last_update_source=peer-driven-apply` audit variant so the
authority-model audit trail can distinguish a peer-driven apply from
a reload-apply (`reload-apply`), a startup-load (`startup-load`), a
SIGHUP-reload (`sighup-reload`), or a snapshot-restore. Reusing an
existing variant for peer-driven apply is **prohibited** by the
Run 144 specification.

Run 144 does not change any existing authority-model invariant. The
Run 050–143 invariants remain in force verbatim: Run 055 anti-
rollback, Run 065/091 activation gates, Run 070 apply ordering,
Run 076/079/088 envelope and propagation discipline, Run 109/123 v1
enforcement, Run 130/131 v2 verifier and marker primitives,
Run 132/142 validation-only paths, Run 134/136/138 post-commit marker
discipline, Run 140/141 snapshot/restore parity, and the
`--p2p-trusted-root` fallback rejection. **Static production source-
code anchors remain rejected.** **Local config alone remains
insufficient for MainNet bundle-signing authority.** **Local peer
majority alone is insufficient for MainNet bundle-signing authority
(formalized by Run 144).** Peer-driven live trust-bundle apply,
signing-key rotation / revocation lifecycle, KMS / HSM authority-key
custody, MainNet governance attestation, validator-set rotation,
full C4 closure, and C5 closure all remain out of scope.
## Run 145 — Peer-driven trust-bundle apply: non-authoritative staged
candidate queue source/test scaffold

Run 145 lands the first source-level scaffold of the **Phase 2
("eligibility to stage")** layer described by
`QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` (Run 144). The new
component is `crates/qbind-node/src/pqc_peer_candidate_staging.rs`'s
`PeerCandidateStagingQueue` — a bounded, deduplicated, TTL-bounded,
per-peer-bounded, disabled-by-default, environment-gated, in-memory
queue of log-safe `StagedPeerCandidate` metadata records.

A staged candidate is **non-authoritative**. Holding a
`StagedPeerCandidate` does **NOT**:

* mean the candidate has been applied;
* mean the candidate has been propagated;
* mean the candidate has been persisted as accepted authority;
* mutate `LivePqcTrustState`;
* write `pqc_trust_bundle_sequence.json`;
* write `pqc_authority_state.json`;
* evict P2P / KEMTLS sessions;
* invoke Run 070 apply / SIGHUP reload-apply / process-start apply.

The Run 145 queue does not change any existing authority-model
invariant:

* The trust anchor remains the genesis-pinned authority root for the
  resolved `(environment, chain_id, genesis_hash)`.
* The bundle-signing key set is still authoritative only when it is
  ratified by the genesis-pinned authority via either the v1
  ratification or, on environments running v2 ratification, the
  Run 130 v2 verifier.
* `LivePqcTrustState` is still swapped only by the existing Run 070
  apply contract.
* Peer-driven live trust-bundle apply remains **unimplemented and
  disabled by default** on every environment.

Environment matrix for the new staging queue:

* **DevNet** — MAY stage when `enabled && allow_devnet`. Default:
  disabled.
* **TestNet** — MAY stage when `enabled && allow_testnet` AND the
  upstream Run 130 v2 verifier and Run 132/142 v2 marker
  validation-only check accepted the candidate. Default: disabled.
* **MainNet** — **REFUSED unconditionally** by the Run 145 queue,
  regardless of `enabled`/`allow_mainnet`. The refusal is fail-closed
  and intentional. **Local peer majority remains insufficient for
  MainNet bundle-signing authority** (formalized by Run 144,
  reaffirmed by Run 145).

Run 145 introduces no new wire format, no new schema, no new metric
family, and no new operator log line. The new module is **library-level
only** in this run: no production caller invokes it. The future Run
146 release-binary hook will introduce a hidden DevNet-only CLI flag
that refuses to bind on TestNet / MainNet at the flag-bind step.

Crosscheck performed against Runs 050–144 invariants: Run 145
introduces no contradictions because the new module is dead code in
the release binary and the staging queue itself performs no mutation.
Every Run 050–144 invariant remains intact, including Run 055
anti-rollback, Run 065/091 activation gates, Run 070 apply ordering,
Run 076/079/088 envelope/propagation discipline, Run 109/123 v1
enforcement, Run 130/131 v2 verifier and marker primitives,
Run 132/142 validation-only paths, Run 134/136/138 post-commit marker
discipline, Run 140/141 snapshot/restore parity, and the Run 144
six-phase fail-closed pipeline. **Static production source-code
anchors remain rejected.** **Local config alone remains insufficient
for MainNet bundle-signing authority.** **Local peer majority alone
is insufficient for MainNet bundle-signing authority (formalized by
Run 144; reaffirmed by Run 145).** Peer-driven live trust-bundle
apply, signing-key rotation / revocation lifecycle, KMS / HSM
authority-key custody, MainNet governance attestation, validator-set
rotation, full C4 closure, and C5 closure all remain out of scope.
## Run 146 — Peer-driven trust-bundle apply: Phase 2 staging queue wired into live inbound `0x05` (source/test wiring only)

Run 146 wires the Run 145 non-applying `PeerCandidateStagingQueue`
into the **live inbound `0x05` validation-only receive path** behind
an explicit **disabled-by-default** local policy gate. A running node
can now stage already-validated peer candidates in memory without
applying them, observed via the queue's `entries()` accessor.

The Run 146 wiring does not change any existing authority-model
invariant. In particular:

* The dispatcher's optional `staging_queue` field defaults to `None`;
  when `None`, behaviour is bit-for-bit identical to Run 143.
* The new `maybe_stage_after_validation` hook runs **after** both
  v2 (Run 142) and v1 (Run 123) marker conflict checks and **before**
  Run 088 propagation, so only fully-accepted `Validated(_)` outcomes
  ever reach the queue. Invalid candidates are filtered to
  `RefusedNotValidated` by `try_stage_outcome` itself.
* Staging performs no Run 070 apply call, no `LivePqcTrustState`
  swap, no sequence-file write, no authority-marker write, no
  session eviction, no SIGHUP, no reload-apply, and no propagation
  side effect.

The authority bar for each environment is unchanged from Run 145:

* **DevNet / TestNet** — peer-driven staging may be **enabled by
  operator policy** (`PeerDrivenStagingPolicy.enabled = true`); even
  then, **no apply** occurs — the queue is observation only.
* **MainNet** — **REFUSED unconditionally** by the Run 145 queue,
  irrespective of the local policy's `enabled` / `allow_mainnet`
  flags. Run 146 does not weaken this barrier in any path.

Run 146 introduces no new wire format, no new on-disk schema, no new
metric family, and no CLI flag. The dispatcher's
`LivePeerCandidateWireDispatcherConfig::staging_queue` field is
additive (`Option<_>`); all pre-Run-146 dispatcher initializers
construct `staging_queue: None` and exercise the Run 143
validation-only / propagation-only path verbatim.

Crosscheck performed against Runs 050–145 invariants: Run 146
introduces no contradictions because the staging hook is dead code
when `staging_queue = None` (the default for the release binary in
Run 146), and even when armed it performs no mutation. Every
Run 050–145 invariant remains intact, including Run 055
anti-rollback, Run 065/091 activation gates, Run 070 apply ordering,
Run 076/079/088 envelope/propagation discipline, Run 109/123 v1
enforcement, Run 130/131 v2 verifier and marker primitives,
Run 132/142 validation-only paths, Run 134/136/138 post-commit marker
discipline, Run 140/141 snapshot/restore parity, the Run 144
six-phase fail-closed pipeline, and the Run 145 staging-queue
non-application property. **Static production source-code anchors
remain rejected.** **Local config alone remains insufficient for
MainNet bundle-signing authority.** **Local peer majority alone is
insufficient for MainNet bundle-signing authority (formalized by
Run 144; reaffirmed by Runs 145 and 146).** Peer-driven live
trust-bundle apply, MainNet staging enablement, signing-key
rotation / revocation lifecycle, KMS / HSM authority-key custody,
MainNet governance attestation, validator-set rotation, full C4
closure, and C5 closure all remain out of scope.
## Run 147 — Peer-driven trust-bundle apply: release-binary evidence for the live `0x05` peer-candidate staging hook (hidden opt-in arming flag)

Run 147 produces release-binary evidence that Run 146 explicitly
deferred for the Run 145 / Run 146 non-applying
`PeerCandidateStagingQueue`. The Run 147 feasibility gate ("can a
real `target/release/qbind-node` binary arm
`LivePeerCandidateWireDispatcher::staging_queue` through an
existing runtime config path?") returned **NO** against the Run 146
state. Per `task/RUN_147_TASK.txt`'s "preferred path if a flag is
necessary" allowance, Run 147 adds the smallest hidden,
disabled-by-default DevNet/TestNet-only arming flag
`--p2p-trust-bundle-peer-candidate-staging-enabled` plus a
top-level partial-config refusal gate and a single inline branch in
`crates/qbind-node/src/main.rs` that installs a bounded
`PeerCandidateStagingQueue` into the dispatcher config when (and
only when) the flag is supplied with valid co-requisites on
DevNet/TestNet. **No dispatcher-level code is changed; no other
authority-model surface is touched.**

The Run 147 wiring does not change any existing authority-model
contract:

* The authority-marker is **still** persisted only by the existing
  Run 134 / Run 136 / Run 138 / Run 140 / Run 141 paths. The
  staging hook never writes the marker file under any code path.
  Run 147 confirms this on release binaries by asserting
  `pqc_authority_state.json` is byte-identical pre/post on every
  scenario.
* The persistent trust-bundle sequence file is **still** written
  only by the existing Run 070 apply contract. The staging hook
  never writes the sequence file. Run 147 confirms this on release
  binaries by asserting `pqc_trust_bundle_sequence.json` is
  byte-identical pre/post on every scenario.
* `LivePqcTrustState` is **still** mutated only by the existing
  Run 070 apply contract. The staging hook does not own a
  `LivePqcTrustState` and does not construct one.
* P2P / KEMTLS sessions are **still** evicted only by the existing
  Run 072 / Run 074 paths. The staging hook does not own a
  `P2pSessionEvictor` and does not construct one.
* The SIGHUP / reload-apply paths (Run 073 / Run 074 / Run 138)
  are unchanged.
* The snapshot / restore authority-marker surface (Run 124 / Run 130 /
  Run 140 / Run 141) is unchanged.
* The MainNet authority barrier is reinforced: the Run 147 flag is
  refused on MainNet **twice** (top-level CLI gate and queue
  construction defensive guard); local peer majority remains
  insufficient for MainNet bundle-signing authority.

Run 147 introduces no new wire format, no new on-disk schema, no
new metric family. The only public source-surface delta is the
single new hidden CLI flag plus its install branch, both
documented in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md`. The
Run 146 dispatcher contract (`set_staging_queue`, `staging_queue()`,
`staging_hook_is_armed()`) is preserved verbatim and exercised at
install time inline; the late-install API remains usable for tests
and future runs unchanged.

Crosscheck performed against Runs 050–146 invariants: Run 147
introduces no contradictions because the staging hook is dead code
when the new flag is not supplied (the default for every release
binary), and even when armed it performs no mutation. Every
Run 050–146 invariant remains intact, including Run 055
anti-rollback, Run 065/091 activation gates, Run 070 apply
ordering, Run 076/079/088 envelope/propagation discipline,
Run 109/123 v1 enforcement, Run 130/131 v2 verifier and marker
primitives, Run 132/142 validation-only paths, Run 134/136/138
post-commit marker discipline, Run 140/141 snapshot/restore parity,
the Run 144 six-phase fail-closed pipeline, the Run 145 staging-queue
non-application property, and the Run 146 dispatcher hook ordering.
**Static production source-code anchors remain rejected.** **Local
config alone remains insufficient for MainNet bundle-signing
authority.** **Local peer majority alone is insufficient for MainNet
bundle-signing authority (formalized by Run 144; reaffirmed by
Runs 145, 146, and 147).** Peer-driven live trust-bundle apply,
MainNet staging enablement (refused fail-closed by Run 147),
signing-key rotation / revocation lifecycle, KMS / HSM
authority-key custody, MainNet governance attestation, validator-set
rotation, full C4 closure, and C5 closure all remain out of scope.

## Run 148 progress entry — peer-driven apply controller (source/test only)

Run 148 introduces a source-and-test peer-driven apply controller
that consumes staged peer candidates (Run 145 queue, Run 146
dispatcher hook, Run 147 hidden arming flag) and applies them
through the existing Run 070 apply contract. It is library-only
and reachable only behind an explicit local
`PeerDrivenApplyPolicy::devnet_enabled()` or
`PeerDrivenApplyPolicy::testnet_enabled()`. The node binary's
reload-apply and SIGHUP surfaces are not modified.

Authority model invariants reaffirmed by Run 148:

* **MainNet bundle-signing authority is not local-config-driven.**
  Peer-driven apply refuses MainNet unconditionally
  (`PeerDrivenApplyOutcome::RefusedMainNet`) regardless of any
  policy field, including `allow_mainnet`. A local DevNet/TestNet
  peer majority does **not** confer MainNet authority.
* **The v2 authority anti-rollback marker is persisted only after
  the Run 070 sequence commit succeeds**, by delegating to a
  `V2MarkerCoordinator` whose production implementation wraps
  `persist_accepted_v2_marker_after_commit_boundary`. Pre-apply
  marker conflicts (lower sequence, same-sequence different
  digest) refuse **before** any state mutation.
* **The Run 070 apply contract is reused verbatim**: validate →
  snapshot active → swap trust state → evict sessions →
  commit sequence, with the same rollback semantics. Run 148 adds
  no new privileged path into trust state.
* **Validation-only, staging-only, and propagation-only surfaces
  are unchanged.** Run 142 / Run 088 / Run 145 / Run 146 / Run 147
  behaviour is preserved.

Open items unchanged:

* Governance / KMS / HSM / signing-key rotation / revocation
  lifecycle.
* MainNet governance artifact verification.
* Validator-set rotation.
* Release-binary peer-driven apply evidence (deferred to Run 149).
* Full C4 closure.
* C5 closure.
## Run 149 progress entry — DevNet/TestNet peer-driven apply arming surface (release-binary evidence; partial-positive)

Run 149 layers the **first operator-visible release-binary arming
surface** on top of the Run 148 source/test peer-driven apply
controller. The smallest hidden, disabled-by-default DevNet/TestNet-only
arming flag was added (`--p2p-trust-bundle-peer-candidate-apply-enabled`)
with the matching MainNet refusal + co-requisites gate and a
controller-layer `PeerDrivenApplyPolicy` arming banner. No
queue-to-controller drain caller is wired in this run (forbidden
by `task/RUN_149_TASK.txt` §20 — "must not create a new apply
algorithm"); release-binary end-to-end apply is therefore cited
honestly as Run 148 source/test coverage per the partial-positive
verdict.

Authority model invariants reaffirmed by Run 149:

* **MainNet bundle-signing authority remains NOT
  local-config-driven.** The Run 149 flag is refused on MainNet
  at three independent layers: (i) the early CLI gate at the
  top of `run_node`, (ii) a defensive duplicate refusal inside
  the co-requisites block, and (iii) the controller-layer
  arming-banner match arm. The Run 148 controller's runtime
  `PeerDrivenApplyOutcome::RefusedMainNet` continues to be the
  final defensive layer at the controller call site itself. Local
  DevNet/TestNet peer majority does **not** confer MainNet
  authority.
* **Local peer majority is NOT authority on any environment for
  bundle signing.** The Run 149 flag does not change the
  authority basis on DevNet/TestNet either — apply still requires
  validation acceptance through the Run 130 v2 verifier and the
  Run 132 / Run 142 v2 marker validation-only check; the flag
  only arms the policy that the Run 148 controller would consult
  when a future drain caller invokes it.
* **The v2 authority anti-rollback marker is persisted only after
  the Run 070 sequence commit succeeds** — Run 148's
  `V2MarkerCoordinator` post-commit boundary is unchanged.
  Pre-apply marker conflicts (lower sequence, same-sequence
  different digest, v1-after-v2 downgrade, wrong domain) continue
  to refuse before any state mutation per the Run 148 controller's
  gate order.
* **The Run 070 apply contract is reused verbatim.** Apply is
  delegated through the Run 148 controller's call to
  `apply_validated_candidate_with_previous(...)`. Run 149 adds
  no new path into trust state, no new validation surface, no
  new apply algorithm, and no new marker / sequence / activation
  bypass.
* **Validation-only, staging-only, and propagation-only surfaces
  are unchanged.** When the new Run 149 flag is absent, the
  binary behaves bit-for-bit identically to Run 147 (the entire
  Run 149 source delta is gated by the new flag); Run 142 /
  Run 088 / Run 145 / Run 146 / Run 147 behaviour is preserved
  verbatim.
* **The Run 144 §6 "Local authorization gate" allowance is
  honoured.** Run 149 is the minimum hidden DevNet/TestNet-only
  arming surface required to make the Run 148 controller
  reachable from a real release binary; it does NOT lift the
  Run 144 MainNet refusal under any circumstance, and it does
  NOT introduce a governance / ratification / KMS-HSM authority
  claim.

Open items unchanged:

* Governance / ratification authority for any future MainNet
  peer-driven apply enablement.
* KMS / HSM authority-key custody.
* Signing-key rotation / revocation lifecycle.
* MainNet governance artifact verification.
* Validator-set rotation.
* The queue-to-controller drain caller surface (deferred to a
  future run under a strictly specified ordering contract that
  is not a new apply algorithm).
* Full C4 closure.
* C5 closure.

**Local config alone remains insufficient for MainNet bundle-signing
authority.** **Local peer majority alone is insufficient for
MainNet bundle-signing authority (formalized by Run 144;
reaffirmed by Runs 145, 146, 147, 148, and 149).**

## Run 150 progress entry — drain trigger landed (source/test only); authority model unchanged

Run 150 adds source-and-test wiring for an explicit peer-driven
apply **drain trigger** (`PeerDrivenApplyDrain::try_drain_once`) that
connects the Run 145/146 staged peer-candidate queue to the Run 148
peer-driven apply controller, and through it to the existing Run 070
apply contract. **No authority-model invariant is changed.** Run 150
is a source/test landing; release-binary operator-trigger evidence
is deferred to Run 151.

Authority invariants reaffirmed by Run 150:

* **Local config alone remains insufficient for MainNet
  bundle-signing authority.** The Run 150 drain refuses MainNet at
  the policy-gate layer (`PeerDrivenDrainPolicy::mainnet_attempted`
  refuses by construction), at the runtime-domain check inside
  `try_drain_once`, defensively inside the environment-permission
  match, and through delegation to the Run 148 controller which
  enforces its own MainNet refusal. Four independent refusal layers
  guard the MainNet boundary on this path.
* **Local peer majority remains insufficient for MainNet
  bundle-signing authority.** No new peer-majority surface is
  introduced. The drain consumes a single staged candidate per
  trigger; no quorum, no voting, no ratification claim.
* **Static production source-code anchors remain rejected.** The
  Run 150 module does not embed any trust-anchor material and does
  not add any source-code anchor surface.
* **DevNet/TestNet drain is explicitly behind disabled-by-default
  local config.** The new `PeerDrivenDrainPolicy` mirrors Run 145 /
  Run 148 policy shape: `enabled / allow_devnet / allow_testnet` all
  default to `false`; explicit `devnet_enabled()` / `testnet_enabled()`
  constructors are required to reach the drain pipeline.

Authority-relevant negative assertions for Run 150:

* No new MainNet enablement path.
* No new MainNet governance attestation surface.
* No new validator-set rotation surface.
* No KMS / HSM integration.
* No signing-key rotation / revocation lifecycle change.
* No new wire format, no new on-disk schema, no new on-disk anchor.
* No new metric family.
* No SIGHUP / reload-apply behaviour change.
* No autonomous / background / on-receipt apply.
* No release-binary operator trigger (deferred to Run 151).

Open items after Run 150 (unchanged from Run 149):

* Release-binary operator-visible peer-driven apply trigger
  (deferred to Run 151).
* Governance / ratification authority implementation.
* KMS / HSM custody for bundle-signing keys.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Full C4 closure; C5 closure.

Run 150's contribution to the authority model is therefore strictly
the addition of an explicit, disabled-by-default, MainNet-refused,
source/test-only drain entry point — a wiring step toward the Run
151 release-binary trigger, with **no change to who may sign a
MainNet trust bundle and no change to which anchors are accepted
on which domain.**
## Run 151 — release-binary surface for the explicit DevNet/TestNet drain trigger

Run 151 surfaces the Run 150 source/test
`PeerDrivenApplyDrain::try_drain_once` controller on the real
`target/release/qbind-node` via the smallest hidden,
disabled-by-default DevNet/TestNet-only CLI flag
`--p2p-trust-bundle-peer-candidate-drain-once` plus the
matching `main.rs` early-startup MainNet refusal, co-requisites
gate (requires `--p2p-trust-bundle-peer-candidate-apply-enabled`,
which itself transitively requires staging-enabled +
wire-validation-enabled), acceptance banner, and Run 150
controller-layer arming banner with an observably initialized
`in_progress=false` concurrency flag.

Authority invariants reaffirmed by Run 151:

* **Local peer majority is NOT MainNet bundle-signing
  authority.** The Run 151 drain-once trigger refuses MainNet
  at three independent layers (early-startup gate; co-
  requisites gate; Run 150 `PeerDrivenDrainPolicy` MainNet
  unconditional refusal); local config alone remains
  insufficient for MainNet bundle-signing authority.
* **No new authority predicate.** The Run 151 trigger
  delegates drain to the Run 150 controller, which delegates
  apply to the Run 148 controller, which delegates apply to
  the existing Run 070
  `apply_validated_candidate_with_previous` contract. No new
  authority-domain predicate, no new sequence rule, no new
  marker rule, no new wire / schema / on-disk anchor.
* **No new authority surface.** The drain controller object is
  materialized at the arming banner and immediately dropped;
  no production drain caller is constructed and `try_drain_once`
  is not invoked from `main.rs` (the production
  `PeerDrivenDrainInvocationBuilder` /
  `V2MarkerCoordinator` impls + cross-scope staging-queue
  plumbing are out of scope per the "smallest possible hook"
  allowance in `task/RUN_151_TASK.txt`). Run 151 is therefore
  classified as **partial-positive trigger-surface arming**.

Authority-relevant negative assertions for Run 151:

* No new MainNet enablement path.
* No new MainNet governance attestation surface.
* No new validator-set rotation surface.
* No KMS / HSM integration.
* No signing-key rotation / revocation lifecycle change.
* No new wire format, no new on-disk schema, no new on-disk
  anchor.
* No new metric family.
* No SIGHUP / reload-apply behaviour change.
* No autonomous / background / on-receipt apply.
* No production drain caller (the production
  `PeerDrivenDrainInvocationBuilder` /
  `V2MarkerCoordinator` impls + cross-scope staging-queue
  plumbing remain the next future-run piece on the C4 closure
  decomposition).

Open items after Run 151 (unchanged from Run 150):

* Production `PeerDrivenDrainInvocationBuilder` /
  `V2MarkerCoordinator` impls + cross-scope staging-queue
  plumbing for end-to-end release-binary apply through the
  drain (matrix rows A1, A2, A6, A7 currently under Run 150
  source/test coverage).
* Governance / ratification authority implementation.
* KMS / HSM custody for bundle-signing keys.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Full C4 closure; C5 closure.

Run 151's contribution to the authority model is strictly the
addition of an explicit, disabled-by-default, MainNet-refused,
release-binary-armed drain-trigger surface — the binary-level
fulfilment of the Run 150 deferral of release-binary trigger
evidence — with **no change to who may sign a MainNet trust
bundle and no change to which anchors are accepted**.

## Run 152 authority-relevant negative assertions

Run 152 is **source/test wiring only** for the binary-reachable
peer-driven drain invocation plumbing (production
`PeerDrivenDrainInvocationBuilder`, production
`V2MarkerCoordinator`, shared in-memory staging-queue handle,
shared-queue drain entry point). Authority-relevant invariants
are unchanged:

* **No new authority surface.** Run 152 does not introduce a
  new trust anchor, a new authority root, a new ratification
  primitive, a new v2 marker write site, or any new wire /
  schema. The production v2 marker coordinator reuses the
  existing Run 130/131/134/136/138 marker-acceptance helpers;
  the production drain invocation builder consumes only
  candidates already accepted by validation-only/staging.
* **No autonomous apply, no automatic apply on receipt.** The
  drain remains operator-triggered (Run 151 hidden CLI flag)
  and exactly one-shot per trigger.
* **No peer-majority authority.** Local peer majority remains
  insufficient for MainNet bundle-signing authority (Run 144;
  reaffirmed by Runs 145, 146, 147, 148, 149, 150, 151, 152).
* **MainNet refused unconditionally** at three layers
  (early-startup gate, Run 150 `PeerDrivenDrainPolicy`,
  Run 148 controller).
* **No release-binary end-to-end peer-driven apply harness**;
  release-binary end-to-end peer-driven apply evidence is
  **deferred to Run 153**.
* **No governance, KMS / HSM, or signing-key
  rotation/revocation lifecycle** is introduced; those remain
  open.
* **Full C4 is NOT claimed by Run 152; C5 remains OPEN.**

## Run 153 — release-binary end-to-end peer-driven apply evidence; authority model unchanged

Run 153 wires the Run 152 binary-reachable plumbing into the Run 151
hidden drain-once hook so the full peer-driven apply pipeline is
callable from a real `target/release/qbind-node`. **No authority-model
invariant is changed.** The drain routes through Run 150 / Run 148 /
Run 070 verbatim.

Authority invariants reaffirmed by Run 153:

* **Local config alone remains insufficient for MainNet
  bundle-signing authority.** MainNet is refused at four layers
  (early-startup gate, co-requisites gate, `PeerDrivenDrainPolicy`,
  drain-once invocation guard).
* **No new authority predicate.** The drain-once invocation block
  reuses the existing Run 150 / Run 148 / Run 070 chain; no new
  trust anchor, ratification primitive, or authority root is added.
* **Local peer majority remains insufficient for MainNet
  bundle-signing authority** (formalized by Run 144; reaffirmed by
  Runs 145, 146, 147, 148, 149, 150, 151, 152, and 153).
* **No autonomous apply, no automatic apply on receipt.** The
  drain remains operator-triggered (Run 151 hidden CLI flag)
  and exactly one-shot per trigger.

Authority-relevant negative assertions for Run 153:

* No new trust anchor embedded.
* No new authority root introduced.
* No new v2 marker write site.
* No new wire format or schema change.
* No governance implementation.
* No KMS / HSM implementation.
* No signing-key rotation / revocation lifecycle.
* No autonomous background drain.
* No automatic apply on receipt.
* No peer-majority authority.
* No MainNet enablement.

Open items after Run 153 (unchanged from Run 152):

* Governance / ratification authority.
* KMS / HSM custody.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.

Run 153's contribution to the authority model is the fulfilment of
the Run 152 deferral of release-binary end-to-end peer-driven apply
evidence. The authority model itself is unchanged; every authority
invariant from Runs 050–152 is reaffirmed. **Full C4 is NOT claimed
by Run 153; C5 remains OPEN.**
## Run 154 — TestNet fixture tooling (source/test only)

Run 154 adds **source/test TestNet fixture tooling** and changes nothing
in the authority model. The model is unchanged; every authority invariant
from Runs 050–153 is reaffirmed.

Run 154 extends the Run 133 v2 fixture helper to mint TestNet material
bound to the TestNet runtime domain (`environment = TestNet`, TestNet
`chain_id`, TestNet genesis hash, the minted authority-root fingerprint,
and the v2 authority-domain sequence). The authority-root fingerprint
carried by every TestNet artifact is derived from a **freshly minted,
ephemeral** ML-DSA-44 authority key — there is **no static production
source-code anchor**, **no fallback root**, and **no fallback signing
key**. The Run 154 tests prove TestNet artifacts verify only under a
TestNet context and fail under DevNet and MainNet contexts; **MainNet
remains refused**, and local material alone remains insufficient for
MainNet bundle-signing authority.

Open items after Run 154 (unchanged from Run 153):

* Governance / ratification authority.
* KMS / HSM custody.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.

Run 154 is source/test fixture tooling that fulfils the Run 153 A2
TestNet fixture-tooling prerequisite; release-binary TestNet end-to-end
peer-driven apply evidence is **deferred to Run 155**. **Full C4 is NOT
claimed by Run 154; C5 remains OPEN.**

## Run 155 — release-binary TestNet end-to-end peer-driven apply evidence

Run 155 produces **release-binary TestNet end-to-end peer-driven apply
evidence** and changes nothing in the authority model. The model is
unchanged; every authority invariant from Runs 050–154 is reaffirmed.

Run 155 adds **no source delta**: it reuses the Run 153 `main.rs` wiring
verbatim and binds the exercise to the TestNet runtime domain
(`environment = testnet`, TestNet `chain_id`, TestNet genesis hash, the
minted authority-root fingerprint, and the v2 authority-domain sequence)
using the Run 154 TestNet fixtures. The authority-root fingerprint carried
by every TestNet artifact is derived from a **freshly minted, ephemeral**
ML-DSA-44 authority key — there is **no static production source-code
anchor**, **no fallback root**, and **no fallback signing key**. The Run 150
drain / apply policies remain reachable only behind explicit local
`testnet_enabled()` / `devnet_enabled()` policy; **MainNet remains refused
unconditionally** at the policy-gate, runtime-domain, Run 148 controller,
and Run 144 specification layers, and local material alone remains
insufficient for MainNet bundle-signing authority. **Local peer majority
remains insufficient for MainNet bundle-signing authority.**

Open items after Run 155 (unchanged from Run 154):

* Governance / ratification authority.
* KMS / HSM custody.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.

Run 155 is release-binary TestNet evidence that closes the Run 153 A2
TestNet evidence deferral; DevNet evidence from Run 153 remains valid.
**Full C4 is NOT claimed by Run 155; C5 remains OPEN.**

## Run 156 — positive TestNet release-binary apply driven live; positive A1 BLOCKED by disjoint authority universes

Run 156 drives the **positive** TestNet end-to-end peer-driven apply path
on a real `target/release/qbind-node` over a live N=3 TestNet P2P cluster
(instead of mapping it to source/test coverage as Run 153/155 did) and
**changes nothing in the authority model**. The model is unchanged; every
authority invariant from Runs 050–155 is reaffirmed. Run 156 adds **no
source delta**: it reuses the Run 153 `main.rs` wiring verbatim.

Run 156's core finding is an **authority-universe** observation that is
itself a reaffirmation of the model: peer-driven apply requires the
published candidate to be a valid Run-070 successor of V1's live baseline
`LivePqcTrustState`, which is anchored to the **root authority of V1's live
P2P transport bundle**. On the fixtures shipped in this repository the live
transport bundle and the N=3 leaf credentials are minted by
`devnet_pqc_trust_bundle_helper` (`signed-testnet`) under one ephemeral
root authority, while the only TestNet apply candidate (`run_133` helper
`testnet/peer-candidate.valid.json`) is signed under a **disjoint**
ephemeral root authority with no matching P2P leaf credentials. Because the
candidate's authority root is not the live baseline's authority root, V1's
live `0x05` wire-validation / ratification gate **rejects** it — exactly
the authority-binding the model requires (a candidate cannot apply unless
it descends, by sequence, from the in-force authority). The drain-once
therefore returns `NoCandidate` with no live trust mutation. No existing
fixture tool mints a single unified universe binding both (a) N=3 P2P leaf
credentials and (b) a self-consistent seq1→seq2 apply pair under one shared
root authority plus the matching v2 ratification sidecar.

Every authority-root fingerprint exercised by Run 156 is derived from
**freshly minted, ephemeral** key material — there is **no static
production source-code anchor**, **no fallback root**, and **no fallback
signing key**. The Run 150 drain / apply policies remain reachable only
behind explicit local `testnet_enabled()` / `devnet_enabled()` policy;
**MainNet remains refused unconditionally** at the policy-gate,
runtime-domain, Run 148 controller, and Run 144 specification layers, and
local material alone remains insufficient for MainNet bundle-signing
authority. **Local peer majority remains insufficient for MainNet
bundle-signing authority.**

Open items after Run 156 (unchanged from Run 155):

* Governance / ratification authority.
* KMS / HSM custody.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Unified TestNet fixture tooling that binds live transport credentials and
  the apply baseline/candidate pair under one root authority (the unblock
  path for the live positive A1 apply).

Run 156 is release-binary live-path evidence plus the exact fixture
blocker; it explicitly does **not** claim the positive A1 path closed and
does **not** substitute source/test coverage for the live positive
verdict. DevNet evidence from Run 153 and TestNet evidence from Run 155
remain valid. **Full C4 is NOT claimed by Run 156; C5 remains OPEN; the
positive TestNet release-binary A1 apply remains BLOCKED pending unified
fixture tooling.**
## Run 157 note — TestNet fixture authority unification

Run 157 introduces source/test fixture tooling that mints one coherent TestNet authority universe for future positive peer-driven apply evidence. The generated baseline bundle, candidate bundle, v2 ratification sidecar, seeded marker, peer-candidate envelope, and V0/V1/V2 transport material are all bound to one TestNet genesis, authority root, transport root, and bundle-signing authority.

This does not alter the production authority model and does not create a MainNet source-code anchor or fallback root. MainNet remains refused / fixture-only; governance remains unimplemented; KMS/HSM remains unimplemented; signing-key rotation/revocation lifecycle remains open; validator-set rotation remains open; full C4 and C5 remain open. Release-binary positive TestNet apply evidence is deferred to Run 158.
## Run 158 — TestNet authority model is unchanged; positive release-binary peer-driven apply evidence drawn under Run 157 unified universe

Run 158 produces release-binary positive TestNet end-to-end peer-driven apply evidence using the Run 157 unified TestNet fixture universe. The trust-anchor authority invariant from Runs 050–157 is reaffirmed: the **only** way V1's `LivePqcTrustState` advances is through the Run 070 apply contract on a candidate that is a **valid successor** of V1's existing baseline (signed under the same active transport-root authority, with a strictly greater sequence, a matching v2 ratification sidecar bound to the same TestNet domain / chain id / genesis hash / authority root / bundle-signing authority, and a v2 authority-marker decision that strictly succeeds the seeded marker).

Run 158 introduces **no production authority-model source change** and **no MainNet source-code anchor**. It does not enable a fallback authority root; it does not enable `--p2p-trusted-root` as a fallback; it does not weaken Run 144's MainNet-refusal layering (policy-gate / runtime-domain / Run 148 controller / Run 144 safety specification, all still refusing MainNet drain-once unconditionally). The Run 153 `main.rs` wiring, the Run 152 production builder / coordinator, the Run 150 drain, the Run 148 controller, the Run 070 apply contract, and the Run 134/138 v2-marker post-commit boundary are all reused verbatim.

Every authority-root fingerprint exercised by Run 158 is derived from the unified Run 157 universe (a TestNet-domain, ephemeral, reproducible `harness()` minted on every invocation). No release-binary path imports a static MainNet authority root; the TestNet authority root used in Run 158 is per-invocation ephemeral and is **not** treated as a production authority anchor by `qbind-node`. MainNet remains refused / fixture-only.

Open items after Run 158 (unchanged from Run 157):

- Production MainNet bundle-signing authority root (governance / ratification authority).
- KMS / HSM custody.
- Signing-key rotation / revocation lifecycle.
- Validator-set rotation.
- Full C4 / C5 closure.

Run 158 is positive TestNet release-binary peer-driven apply evidence drawn against the unified Run 157 universe. The Run 156 disjoint-universe blocker is closed for any harness invocation in which the positive A1 path is recorded in `a1_apply_proof.txt`; otherwise the harness records the exact failure mode in `a1_blocker.txt` and does **not** substitute source/test coverage for the positive verdict. DevNet evidence from Run 153, TestNet refusal evidence from Run 155, and Run 156's release-binary live-path evidence + exact blocker remain valid. **Full C4 is NOT claimed by Run 158; C5 remains OPEN.** Local config alone remains insufficient for MainNet bundle-signing authority. Local peer majority remains insufficient for MainNet bundle-signing authority.
## Run 159 — source/test signing-key rotation and revocation lifecycle for v2 authority state

Run 159 lands typed pure transition validation for the v2 bundle-signing-key lifecycle as a new `qbind_node::pqc_authority_lifecycle` module exposing `validate_v2_lifecycle_transition(persisted, candidate, trust_domain) -> AuthorityLifecycleTransitionOutcome`. The validator distinguishes five logical lifecycle actions — `ActivateInitial`, `Rotate`, `Retire`, `Revoke`, `EmergencyRevoke` — pinned onto the **existing** Run 130 on-wire `BundleSigningRatificationV2Action` byte set (`Ratify=0`, `Rotate=1`, `Revoke=2`) by interpreting the existing optional lowercase-hex `revoked_key_metadata` field with a Run 159 local sub-class prefix (`01`=Revoke, `02`=Retire, `03`=EmergencyRevoke). Run 159 introduces **no new wire format**, **no trust-bundle schema change**, **no authority-marker schema change**, and **no sequence-file schema change**. Every accepted lifecycle transition is bound to environment, chain id, genesis hash, authority-root fingerprint and suite id, active bundle-signing key fingerprint and suite id, and the strictly-monotonic authority-domain sequence; same sequence + bit-for-bit identical record is idempotent; same sequence + different binding is rejected as equivocation; lower sequence is rejected as rollback; non-PQC suite ids are rejected; revoked-key reuse is rejected; retired-key reuse is rejected (no overlap window is defined in Run 159); wrong previous-key fingerprint on rotation is rejected; wrong environment / chain / genesis / authority-root is rejected; malformed revoked metadata is rejected; unsupported lifecycle action under the current persisted state is rejected; structurally malformed v2 candidates are rejected; v1-persisted with v2-candidate is explicitly refused (the existing Run 131 `migrate_authority_marker_v1_to_v2` primitive remains the authoritative path for that case).

This does not alter the production authority model and does not create a MainNet source-code anchor or fallback root. The Run 159 validator is **pure** and **typed**: it performs no I/O, never mutates the persisted authority marker, never writes the sequence file, and never touches a live trust bundle. Run 159 is intentionally **not yet wired** into any mutating surface; it is offered as a *typed pre-flight surface* that future runs may compose into the existing Run 134 / 136 / 138 / 150 / 152 marker-comparison and accept-and-persist pipeline once a wire-level encoding for `Retire` / `EmergencyRevoke` lands. Until then, the existing marker-comparison helpers remain the authoritative mutating-surface decision points and are unchanged. MainNet remains refused / fixture-only; governance remains unimplemented; KMS/HSM remains unimplemented; validator-set rotation remains open; release-binary lifecycle evidence is deferred to Run 160; full C4 and C5 remain open.

Run 159 is **source/test only**. DevNet evidence from Run 153, TestNet evidence from Runs 154/155/157, and Run 158's positive release-binary TestNet end-to-end peer-driven apply evidence remain valid and untouched. No Run 050–158 invariant is changed.
## Run 160 — release-binary evidence / boundary for the v2 signing-key lifecycle validator; authority model unchanged

Run 160 produces release-binary evidence for the Run 159 v2 bundle-signing-key lifecycle validator (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`). The trust-anchor authority invariant from Runs 050–159 is unchanged. The Run 160 source-level call graph (captured by the harness) shows that `validate_v2_lifecycle_transition` and `classify_local_lifecycle_action` have **zero** production callers — none of the eight release-binary surfaces enumerated by `task/RUN_160_TASK.txt` (startup `--p2p-trust-bundle` v2, reload-check, local peer-candidate-check, process-start reload-apply, SIGHUP, live inbound `0x05`, peer-driven staged drain-once, fixture helper / example) calls the validator. The Run 160 verdict is `partial-positive: release-binary fixture/evidence boundary captured; lifecycle validator not yet production-surface reachable`; **strongest-positive is intentionally NOT claimed**.

Run 160 introduces **no production authority-model source change** and **no MainNet source-code anchor**. The Run 159 module is still purely additive source/test infrastructure; the lifecycle validator is still pure and typed (no I/O, no sequence write, no marker write, no live trust mutation). The Run 134 / 136 / 138 / 150 / 152 marker-comparison helpers continue to own the mutating-surface accept-and-persist composition for the v2 marker; Run 160 does not rewire them. Run 160 does not enable a fallback authority root, does not enable `--p2p-trusted-root` as a fallback, and does not weaken Run 144's MainNet-refusal layering (policy-gate / runtime-domain / Run 148 controller / Run 144 safety specification, all still refusing MainNet drain-once unconditionally).

What Run 160 adds is release-binary evidence that is honestly available today: a release-built helper (`target/release/examples/run_160_authority_lifecycle_fixture_helper`) mints the lifecycle fixture corpus covering A1–A6 (`ActivateInitial`, `Rotate`, `Retire`, `Revoke`, `EmergencyRevoke`, idempotent same-record) and R1–R14 (lower-sequence rollback, same-sequence equivocation, wrong environment / chain / genesis / authority root, wrong previous-key fingerprint on rotate, revoked-key reuse, retired-key reuse, emergency-revoke replay, malformed revoked metadata, non-PQC suite, unsupported lifecycle action, V1-persisted-V2-candidate refusal); the real `target/release/qbind-node` binary identity is recorded in `provenance.txt`; and the Run 159 lifecycle test suite plus the Run 134 / 138 / 142 / 148 / 150 / 152 / 157 regression suites are run on the same checkout.

Every authority-root fingerprint and bundle-signing key fingerprint exercised by the Run 160 corpus is ephemeral and synthetic (the helper writes deterministic placeholder lowercase-hex fingerprints into the JSON corpus for Run 159 typed-validator coverage; no MainNet anchor is imported). MainNet remains refused / fixture-only.

Open items after Run 160 (unchanged from Run 159 except for the explicit identification of the next integration run):

* governance / ratification authority: open;
* KMS / HSM custody: open;
* validator-set rotation: open;
* MainNet governance attestation: open;
* **production wiring of `validate_v2_lifecycle_transition` into the Run 134 / 136 / 138 / 150 / 152 marker-comparison and accept-and-persist boundary: deferred to Run 161**;
* full C4: open;
* C5: open.

Run 160 is **release-binary evidence/boundary only**. DevNet evidence from Run 153, TestNet evidence from Runs 154 / 155 / 157 / 158, the Run 156 disjoint-universe documentation, and Run 159's source/test signing-key lifecycle coverage remain valid and untouched. No Run 050–159 invariant is changed. **Full C4 is NOT claimed by Run 160; C5 remains OPEN. Local config alone remains insufficient for MainNet bundle-signing authority. Local peer majority remains insufficient for MainNet bundle-signing authority. The exact next required integration run is Run 161.**
## Run 161 — wire the v2 signing-key lifecycle validator into the shared marker-decision helper; authority model unchanged

Run 161 is **source/test integration only**. The trust-anchor authority invariant from Runs 050–160 is unchanged. The Run 159 typed v2 bundle-signing-key lifecycle validator (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`, `classify_local_lifecycle_action`, `AuthorityTrustDomain`, `LocalLifecycleAction`, `AuthorityLifecycleTransitionOutcome`) is now composed inside the shared v2 marker-decision helper `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2` used by Run 134 / 136 / 138 / 150 / 152 mutating surfaces and Run 132 / 142 validation-only surfaces. Run 161 closes the Run 160 production-reachability boundary at the source level: `validate_v2_lifecycle_transition` and `classify_local_lifecycle_action` now have a production `src` call site outside `pqc_authority_lifecycle.rs` — namely the lifecycle gate inside `decide_marker_acceptance_v2` in `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`. Release-binary lifecycle evidence for that wiring is **deferred to Run 162**.

Run 161 introduces **no production authority-model source change** beyond the lifecycle gate inside the existing helper, **no MainNet source-code anchor**, **no fallback authority root**, **no fallback for `--p2p-trusted-root`**, and **no weakening of Run 144's MainNet-refusal layering** (policy-gate / runtime-domain / Run 148 controller / Run 144 safety specification, all still refusing MainNet drain-once unconditionally). The Run 134 / 136 / 138 / 150 / 152 marker-comparison helpers continue to own the mutating-surface accept-and-persist composition; Run 161 only adds a typed pre-mutation lifecycle gate inside the shared decision helper they all already share. The on-wire `BundleSigningRatificationV2Action` byte set (`Ratify=0`, `Rotate=1`, `Revoke=2`) is unchanged; the trust-bundle / authority-marker / sequence-file / peer-candidate-envelope schemas are unchanged; the Run 159 local sub-class metadata convention (`01`=Revoke, `02`=Retire, `03`=EmergencyRevoke) is reused verbatim. Two Run 159 reject variants are passed through to the existing comparison decision rather than escalated, by design (R20 back-compat): `InitialActivationAfterPersistedRejected` (where anti-rollback is already enforced by the existing v2 marker-schema compare) and `V1PersistedV2CandidateNotSupportedHere` (the Run 131 explicit v1→v2 migration boundary, which Run 159 deliberately does not validate). All other Run 159 reject variants are fail-closed.

Run 161 is **source/test integration only**. DevNet evidence from Run 153, TestNet evidence from Runs 154 / 155 / 157 / 158, the Run 156 disjoint-universe documentation, Run 159's source/test signing-key lifecycle coverage, and Run 160's partial-positive release-binary lifecycle boundary all remain valid and untouched. No Run 050–160 invariant is changed. **Full C4 is NOT claimed by Run 161; C5 remains OPEN. Local config alone remains insufficient for MainNet bundle-signing authority. Local peer majority remains insufficient for MainNet bundle-signing authority. Release-binary lifecycle evidence is deferred to Run 162.**
## Run 162 — release-binary lifecycle ENFORCEMENT evidence on real `target/release/qbind-node`; authority model unchanged

Run 162 is **release-binary evidence only**. The trust-anchor authority invariant from Runs 050–161 is unchanged. Run 162 produces release-binary evidence on real `target/release/qbind-node` that the Run 161 wiring of the Run 159 lifecycle validator into `decide_marker_acceptance_v2` is exercised end-to-end through the existing `--p2p-trust-bundle-reload-check` (Run 132 dispatch, validation-only) and `--p2p-trust-bundle-reload-apply-path` (Run 134 dispatch, mutating) v2 marker-decision surfaces. The new artifacts are exclusively the harness `scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`, the curated evidence archive `docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/` (only README.md + summary.txt tracked; per-run artifacts .gitignored mirroring Run 153 / 155 / 156 / 158 / 160), the canonical evidence report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md`, and four narrow doc alignment updates. **No production authority-model source change**, **no new MainNet source-code anchor**, **no fallback authority root**, **no fallback for `--p2p-trusted-root`**, and **no weakening of Run 144's MainNet-refusal layering** (policy-gate / runtime-domain / Run 148 controller / Run 144 safety specification, all still refusing MainNet drain-once unconditionally).

Run 162 **explicitly supersedes Run 160's "zero production caller" partial-positive boundary** by capturing a source-level grep over `crates/qbind-node/src/**.rs` showing `validate_v2_lifecycle_transition` and the matching `MutatingSurfaceMarkerV2Error::LifecycleRejected` constructor invoked from `pqc_authority_marker_acceptance.rs::decide_marker_acceptance_v2`, and by driving lifecycle-accepted (`ActivateInitial`, `Rotate`, `Idempotent`) and lifecycle-rejected (`lower-sequence`, `same-sequence different-digest` equivocation, `wrong environment`, `wrong chain`, `wrong genesis`, the PQC-verifier surrogate for `non-PQC suite`, and `corrupted local marker`) scenarios through the live release binary. Mutating accepts preserve the Run 070 apply pipeline (`validate → snapshot → swap → evict_sessions → commit_sequence`) and persist the v2 marker strictly **after** Run 055 sequence commit; rejects produce no live trust swap, no session eviction, no sequence write, no marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead`.

Lifecycle scenarios that depend on the Run 159 local sub-class metadata convention (Retire `02`, EmergencyRevoke `03`) and on sub-class-prefixed persisted markers (R6 wrong authority root, R7 wrong previous key, R8 revoked-key reuse, R9 retired-key reuse, R10 emergency revocation replay, R11 malformed revoked metadata) remain source/test-only on the release binary today and are cited from Run 159 + Run 161 source/test coverage; the Run 162 reachability proof together with the Run 161 wiring means those source/test results are now claims about the **same production code path** that the release binary executes, not claims about a dead-code module (which was the Run 160 boundary).

MainNet remains refused unconditionally (cited from Run 151 / Run 158 release-binary evidence; Run 162 does not enable MainNet on any surface). Governance / KMS / HSM / validator-set rotation remain unimplemented. Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority. Local peer majority remains insufficient for MainNet bundle-signing authority. **Full C4 is NOT claimed by Run 162; C5 remains OPEN.**
## Run 163 — source/test governance ratification authority verifier; authority model unchanged

Run 163 is **source/test only**. The trust-anchor authority invariant from Runs 050–162 is unchanged. Run 163 lands a typed pure non-mutating governance ratification authority verifier (`crates/qbind-node/src/pqc_governance_authority.rs`, `verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`, `GovernanceAuthorityProof`, `GovernanceAuthorityClass {GenesisBound, EmergencyCouncil, OnChainGovernance}`, `GovernanceAuthorityVerificationOutcome`, `CombinedLifecycleGovernanceOutcome`, `GovernanceIssuerSignatureVerifier`, `FixtureIssuerSignatureVerifier`, `GovernanceThreshold`) that defines and validates the local proof object that — in a future run — can authorize MainNet/TestNet governance-controlled bundle-signing-key lifecycle transitions, against the trust-domain binding (environment / chain_id / genesis_hash / authority root fingerprint and suite), the lifecycle action, the active / new / revoked bundle-signing key fingerprints, the authority-domain sequence, the candidate v2 record digest, the issuer authority class, the issuer signature suite (PQC ML-DSA-44 only), the issuer signature byte string (verified through a typed `GovernanceIssuerSignatureVerifier` hook so a future run can swap in the real PQC verifier without a surface change), and an optional `GovernanceThreshold {approvals, required, total}`.

The verifier models three authority classes: (1) **GenesisBound** — proof chains to the genesis-bound bundle-signing authority root; valid for DevNet/TestNet fixtures, future MainNet-compatible, but does NOT enable MainNet apply; (2) **EmergencyCouncil** — domain-bound emergency revocation authority; only authorizes `EmergencyRevoke` and does NOT bypass signature, genesis, chain, environment, lifecycle-action, candidate-digest, or sequence checks; (3) **OnChainGovernance** — placeholder; no proof format exists yet, the verifier is **explicitly fail-closed** as `UnsupportedOnChainGovernance` (Run 163 does **not** silently invent an on-chain proof schema). The typed reject surface explicitly carries `LocalOperatorConfigOnlyRejected` and `PeerMajorityProofRejected` so peer-majority / gossip-count and local-operator-config-only inputs are rejected as authority proofs at the type level, preserving the existing trust-anchor authority invariants that local config alone is insufficient for MainNet bundle-signing authority and local peer majority is insufficient for MainNet bundle-signing authority.

The verifier is **NOT wired into mutating apply surfaces**: it is a pure typed decision aid only, paired with a pure non-mutating helper `validate_lifecycle_with_governance_authority` that composes Run 159's typed v2 lifecycle validator with the new governance authority verifier into a single `CombinedLifecycleGovernanceOutcome` (`Accepted` / `LifecycleRejected` / `GovernanceRejected`). **No production authority-model source change**, **no new MainNet source-code anchor**, **no fallback authority root**, **no fallback for `--p2p-trusted-root`**, and **no weakening of Run 144's MainNet-refusal layering** (policy-gate / runtime-domain / Run 148 controller / Run 144 safety specification, all still refusing MainNet drain-once unconditionally).

Run 163 introduces no wire-format change (the existing v2 ratification proof fields are sufficient for `GenesisBound` and `EmergencyCouncil`; `OnChainGovernance` is deliberately fail-closed pending an explicit on-chain proof schema in a future run rather than silently inventing one), no marker schema change, no sequence-file schema change, no trust-bundle schema change, and no production runtime source change beyond the new pure typed module wired into `lib.rs` as `pub mod pqc_governance_authority` (no caller in mutating apply surfaces). MainNet peer-driven apply remains refused unconditionally; governance execution / on-chain governance / KMS / HSM / validator-set rotation remain unimplemented. **Release-binary governance verifier evidence is deferred to Run 164.** DevNet evidence from Run 153, TestNet evidence from Runs 154/155/157/158, Run 159 source/test lifecycle coverage, Run 161 source/test integration coverage, and Run 162's release-binary lifecycle enforcement evidence all remain valid. **Full C4 is NOT claimed by Run 163; C5 remains OPEN.**
## Run 164 — release-binary EVIDENCE / BOUNDARY for the Run 163 governance authority verifier; authority model unchanged

Run 164 is **release-binary evidence/boundary only**. The trust-anchor authority invariant from Runs 050–163 is unchanged. Run 164 produces the strongest honest release-binary evidence currently possible for the Run 163 typed pure governance ratification authority verifier (`qbind_node::pqc_governance_authority::verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`, `GovernanceAuthorityProof`, `GovernanceAuthorityClass {GenesisBound, EmergencyCouncil, OnChainGovernance}`, `GovernanceAuthorityVerificationOutcome`, `CombinedLifecycleGovernanceOutcome`, `GovernanceIssuerSignatureVerifier`, `FixtureIssuerSignatureVerifier`, `GovernanceThreshold`) and clearly determines that the verifier is **not** release-binary reachable from any production v2 surface today. The Run 164 source-level reachability proof confirms zero production callers of `verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`, or the `pqc_governance_authority` module in `crates/qbind-node/src/` outside the module itself and the `pub mod pqc_governance_authority;` declaration in `lib.rs`; none of the eight production release-binary v2 surfaces (startup `--p2p-trust-bundle` v2; reload-check validation-only; local peer-candidate-check validation-only; process-start reload-apply; SIGHUP live-reload; live inbound `0x05` validation-only; peer-driven staged queue / drain-once; lifecycle marker-decision path from Run 161/162) calls the Run 163 governance verifier today. Trust-anchor authority continues to be derived strictly from the existing v2 ratification verifier (Run 130), the v2 marker comparison primitives (Run 131/134/136/138/150/152), the lifecycle validator wired in Run 161 / 162, and the existing chain id / environment / genesis / authority-root binding; the Run 163 governance verifier is **observed-not-claimed** across the entire production v2 surface set.

Run 164 captures the release-binary evidence that is honestly available through the release-built helper / example binary path: the new release-built helper `crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs` mints the governance proof corpus covering A1–A5 and R1–R16, invokes the verifier on every scenario, and the harness asserts the expected typed-outcome class per scenario. The verifier models three authority classes (1) **GenesisBound**, (2) **EmergencyCouncil**, (3) **OnChainGovernance** (deliberately fail-closed); the typed reject surface explicitly carries `LocalOperatorConfigOnlyRejected` and `PeerMajorityProofRejected`, preserving the existing trust-anchor authority invariants that local operator config alone is insufficient for MainNet bundle-signing authority and local peer majority is insufficient for MainNet bundle-signing authority. Run 164 does **not** silently invent an on-chain proof schema (`OnChainGovernance` remains fail-closed pending an explicit on-chain proof format in a future run).

Run 164 introduces no wire-format change, no marker schema change, no sequence-file schema change, no trust-bundle schema change, no peer-candidate envelope schema change, no new metric family, no new CLI flag, and no production runtime source change. The verdict is `partial-positive: release-binary fixture/evidence boundary captured; governance authority verifier not yet production-surface reachable`; **strongest-positive is intentionally NOT claimed**. The exact next required integration run is **Run 165** — compose `verify_governance_authority_proof` and `validate_lifecycle_with_governance_authority` into the existing shared v2 marker-decision helper `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2` (or an immediately-upstream typed pre-flight gate); Run 166 will then be the partner release-binary ENFORCEMENT evidence run for Run 165. MainNet peer-driven apply remains refused unconditionally; governance execution / on-chain governance / KMS / HSM / validator-set rotation remain unimplemented. DevNet evidence from Run 153, TestNet evidence from Runs 154/155/157/158, Run 159 source/test lifecycle coverage, Run 161 source/test integration coverage, Run 162's release-binary lifecycle ENFORCEMENT evidence, and Run 163's source/test governance verifier coverage all remain valid. **Full C4 is NOT claimed by Run 164; C5 remains OPEN.**
## Run 165 — governance authority verification reachable from the marker-decision path (SOURCE/TEST)

Run 165 is **source/test integration only** and introduces **no wire-format change, no marker schema change, no sequence-file schema change, and no trust-bundle schema change**. The trust-anchor authority invariants are unchanged.

Run 165 wires the Run 163 governance ratification authority verifier (`verify_governance_authority_proof`) into the shared v2 lifecycle / marker-decision path, so governance authority checks become **production-source reachable** before lifecycle-sensitive marker decisions are accepted. The shared helper `decide_v2_marker_acceptance_with_lifecycle_and_governance` accepts only if every required layer accepts: trust-domain binding, v2 anti-rollback, lifecycle transition validity, and — where the active `GovernanceProofPolicy` requires it — governance authority proof validity (environment, chain, genesis, authority-root, lifecycle-action, candidate-digest, sequence, issuer signature, suite, threshold bindings). The authority model is therefore unchanged in substance but now has a single composed enforcement point.

Policy: `Rotate`/`Retire`/`Revoke`/`EmergencyRevoke` require a proof under `RequiredForLifecycleSensitive`; `EmergencyRevoke` is authorized by the `EmergencyCouncil` class (and by `GenesisBound` in the source/test model); `ActivateInitial` is governance-optional; `OnChainGovernance` remains **unsupported / fail-closed** (no on-chain proof format exists). The current v2 ratification/marker wire material does **not** carry governance proof fields (documented schema-carrying gap; Run 165 invents no schema), so production surfaces supply `GovernanceProofContext::Unavailable` under the `NotRequired` policy — behaviour-preserving. Accepting a governance proof does **not** enable MainNet apply and does **not** bypass any environment gate; MainNet apply remains refused even with a valid proof. Governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. **Release-binary governance enforcement evidence is deferred to Run 166.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_165.md`.
## Run 166 — release-binary EVIDENCE / ENFORCEMENT of the Run 165 governance gate; authority model unchanged

Run 166 is the release-binary partner of Run 165 and does **not** modify the trust-anchor authority model. The four production callers (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`, `main.rs` reload-apply pre-flight, `main.rs` startup pre-flight) continue to invoke `decide_v2_marker_acceptance_with_lifecycle_and_governance` at `policy=NotRequired` + `context=Unavailable`. Run 166 captures the source-level grep proof that the governance-aware helper, `evaluate_governance_marker_gate`, and the typed reject variants `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing` / `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected` are reachable from each of those four production call sites; exercises `NotRequired` + `Unavailable` accept live on `target/release/qbind-node` (reload-check `A1`, reload-apply `A2`, lifecycle-sensitive reload-apply `A2'`); and captures `RequiredButMissing` and `Rejected` fail-closed semantics on a release-built helper that links the same production helper symbol the release node links.

The authority model — bundle-signing-key authority root carried in `GenesisConfig`, lifecycle transitions validated by the Run 159 / 161 typed pure validator wired into the marker-decision boundary, governance ratification authority verified by the Run 163 typed pure verifier wired into the same boundary in Run 165 — is unchanged. Wire material does not yet carry a `GovernanceAuthorityProof`; the schema design is deferred to Run 167. Accepting a governance proof does not enable MainNet apply and does not bypass any environment gate; MainNet apply remains refused even with a valid proof. `OnChainGovernance` remains unsupported / fail-closed. Governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_166.md`, `docs/devnet/run_166_governance_gate_release_binary_enforcement/`.## Run 167 — source/test governance-proof carrying schema for v2 authority sidecars; authority model unchanged

Run 167 is **source/test schema/carrying work only** and introduces **no production runtime mutation surface change, no MainNet enablement, no wire/marker/sequence/trust-bundle/peer-candidate-envelope schema change, and no weakening of any prior trust-anchor authority invariant**. The Run 161/162 lifecycle gate, the Run 163/164 governance verifier, and the Run 165/166 governance gate composition are all preserved bit-for-bit.

Run 167 adds the smallest additive carrier that lets a v2 ratification sidecar transport a typed `GovernanceAuthorityProof` so existing production preflight surfaces can supply `GovernanceProofContext::Available(...)` to the Run 165 governance gate via a typed loader. The new module `qbind_node::pqc_governance_proof_wire` defines `GovernanceAuthorityProofWire` (with `GovernanceAuthorityClassWire` covering `genesis-bound` / `emergency-council` / `on-chain-governance`, `GovernanceThresholdWire`, `GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION = 1`) carrying every binding required by the Run 163 verifier (environment, chain_id, genesis_hash, authority_root_fingerprint + authority_root_suite_id, lifecycle_action, candidate_v2_digest, authority_domain_sequence, active / new / revoked bundle-signing key fingerprints where applicable, issuer authority class, issuer signature suite, issuer signature, optional threshold). The wire object is attached to the v2 ratification sidecar JSON document **only** as an additive optional sibling field `governance_authority_proof`; `qbind_ledger::BundleSigningRatificationV2` is **not** modified. The new sidecar loader `qbind_node::pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path` returns `LoadedV2RatificationSidecar { ratification, governance_proof }` where `governance_proof: GovernanceProofLoadStatus` is `Absent` (no sibling — backwards-compatible with every pre-Run-167 v2 sidecar), `Available(GovernanceAuthorityProof)` (sibling parsed cleanly), or `Malformed(GovernanceProofWireParseError)` (sibling present but unparseable / unsupported — fail-closed at the gate under any policy that requires a proof). The typed adapter `GovernanceProofLoadStatus::governance_proof_context(verifier)` builds the `GovernanceProofContext` consumed by `evaluate_governance_marker_gate`: `Available` ⇒ `Supplied { proof, verifier }`; `Absent` and `Malformed` ⇒ `Unavailable`.

The trust-anchor authority invariants from Runs 050–166 are preserved verbatim: trust-anchor authority is still derived strictly from the existing v2 ratification verifier (Run 130), the v2 marker comparison primitives (Runs 131/134/136/138/150/152), the lifecycle validator (Runs 161/162), and the governance verifier (Runs 163/165/166). The wire carrier is non-authoritative on its own — it merely supplies a typed proof object to the existing pure governance gate, which still enforces every binding (environment / chain / genesis / authority root / lifecycle action / candidate digest / sequence / signature / suite / threshold). Local operator config alone remains insufficient for MainNet bundle-signing authority (an empty issuer signature is rejected at the wire boundary as `EmptyIssuerSignature`); local peer majority remains insufficient (no peer-majority class is wire-representable); `OnChainGovernance` round-trips through the wire carrier but remains **fail-closed** at the Run 163 verifier as `UnsupportedOnChainGovernance` — Run 167 does NOT silently invent an on-chain proof schema. MainNet peer-driven apply remains refused even with a valid proof: gate acceptance is independent of the surface MainNet refusal, which is unchanged. Governance execution, KMS / HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open.

**Release-binary proof-carrying enforcement evidence is deferred to Run 168.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_167.md`.
## Run 168 — release-binary evidence for the Run 167 governance-proof carrier; authority model unchanged

Run 168 is the release-binary partner of Run 167 and introduces **no production runtime mutation surface change, no MainNet enablement, no wire/marker/sequence/trust-bundle/peer-candidate-envelope schema change, and no weakening of any prior trust-anchor authority invariant**. The Run 161/162 lifecycle gate, the Run 163/164 governance verifier, the Run 165/166 governance gate composition, and the Run 167 wire carrier and typed loader (`pqc_governance_proof_wire::GovernanceAuthorityProofWire` with `GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION = 1`; `pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path` with `GovernanceProofLoadStatus::{Absent, Available, Malformed}`) are all preserved bit-for-bit. The four production marker-decision callers (`pqc_live_trust_reload.rs` SIGHUP, `pqc_peer_candidate_apply.rs` peer-driven drain, `main.rs` reload-apply preflight, `main.rs` startup `--p2p-trust-bundle` preflight) continue to invoke `decide_v2_marker_acceptance_with_lifecycle_and_governance` at `policy=NotRequired` + `context=Unavailable`, exactly as Run 166 evidenced — wiring them to consume the typed loader is **explicitly deferred** to a follow-up wiring run.

Run 168 captures the release-binary evidence that is honestly available without changing any production caller signature: source-level grep proof of the Run 167 symbols in `crates/qbind-node/src/`; the strict back-compat path on real `target/release/qbind-node` (pre-Run-167 v2 sidecars with no `governance_authority_proof` sibling continue to load and apply bit-for-bit on reload-check `A1` and reload-apply `A2`); the typed-loader Absent / Available / Malformed matrix and the Run 165 governance gate's `RequiredButMissing` / `Rejected` matrix exercised through 13 scenarios (`H1–H13`) on a release-built helper (`crates/qbind-node/examples/run_168_governance_proof_carrier_release_binary_helper.rs`) that links the same production helper symbols the release node links; and the unchanged unconditional MainNet peer-driven-apply refusal banner on real `target/release/qbind-node` even with a structurally valid proof carrier. The trust-anchor authority invariants from Runs 050–167 are preserved verbatim: trust-anchor authority is still derived strictly from the existing v2 ratification verifier (Run 130), the v2 marker comparison primitives (Runs 131/134/136/138/150/152), the lifecycle validator (Runs 161/162), the governance verifier (Runs 163/165/166), and the governance-proof wire carrier and loader (Run 167) — Run 168 evidences these existing primitives on real release binaries without inventing new authority or new schema. The wire carrier remains non-authoritative on its own; the gate still enforces every binding (environment / chain / genesis / authority root / lifecycle action / candidate digest / sequence / signature / suite / threshold). Local operator config alone remains insufficient for MainNet bundle-signing authority; local peer majority remains insufficient; `OnChainGovernance` round-trips through the wire carrier but remains **fail-closed** at the Run 163 verifier as `UnsupportedOnChainGovernance` — Run 168 does NOT silently invent an on-chain proof schema. MainNet peer-driven apply remains refused even with a valid proof: gate acceptance is independent of the surface MainNet refusal, which is unchanged. Governance execution, KMS / HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_168.md`, `docs/devnet/run_168_governance_proof_carrier_release_binary/`.
## Run 169 — Production marker-decision callers consume the governance-proof loader (source/test)

The trust-anchor authority model is unchanged. Run 169 only wires the Run 167 typed governance-proof loader into the production v2 marker-decision callers (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, and the peer-driven coordinator) via a single non-mutating library shim, `qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`, that maps `GovernanceProofLoadStatus::{Absent, Available, Malformed}` to `GovernanceProofContext` and delegates to the Run 165 governance-aware helper. The authority hierarchy (genesis-bound authority root → ratified bundle-signing key, with optional `GenesisBound` / `EmergencyCouncil` / `OnChainGovernance` governance proof per Run 165) is unchanged. `OnChainGovernance` remains unsupported / fail-closed. MainNet bundle-signing authority still cannot be established by local config alone, by peer-majority alone, or by any static production source-code anchor. The fixture verifier `fixture_issuer_signature_verifier()` remains the only verifier wired into production callers; real-issuer-key (KMS / HSM-backed) verifier installation is deferred. No wire / marker / sequence / trust-bundle / peer-candidate-envelope schema change. Default policy in production callers remains `NotRequired`, so existing no-proof v2 sidecars continue to be accepted exactly as before; `Required` policy fails closed on `Absent` / `Malformed` carriers as `GovernanceAuthorityRequiredButMissing`. Release-binary production-surface proof-carrying evidence is deferred to Run 170. C4 / C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_169.md`.

## Run 170 — release-binary EVIDENCE for the Run 169 production-surface governance-proof loader wiring; authority model unchanged

Run 170 captures release-binary evidence that the Run 167 typed governance-proof loader (`pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`, Run 169 versioned dispatcher `load_versioned_ratification_with_governance_proof_from_path`) is reachable from each of the four production v2 marker-decision preflight call sites through the Run 169 shim `pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load` (reload-apply preflight in `crates/qbind-node/src/main.rs`, startup `--p2p-trust-bundle` preflight in `crates/qbind-node/src/main.rs`, SIGHUP preflight in `crates/qbind-node/src/pqc_live_trust_reload.rs`, peer-driven coordinator in `crates/qbind-node/src/pqc_peer_candidate_apply.rs`). The authority model is unchanged: governance authority continues to be evaluated by `evaluate_governance_marker_gate` composed with `decide_v2_marker_acceptance_with_lifecycle_and_governance`; the typed reject variants (`WrongEnvironment`, `WrongChain`, `WrongGenesis`, `WrongAuthorityRoot`, `WrongLifecycleAction`, `WrongCandidateDigest`, `WrongAuthoritySequence`, `InvalidIssuerSignature`, `UnsupportedIssuerSuite`, `NonPqcSuiteRejected`, `NonPqcAuthorityRootSuiteRejected`, `ThresholdNotMet`, `ReplayRejected`, `UnsupportedOnChainGovernance`, `EmptyIssuerSignature`) are unchanged from Run 163; default policy in production callers remains `NotRequired`, so existing no-proof v2 sidecars continue to be accepted exactly as before (`A1` reload-check / `A2` reload-apply on real `target/release/qbind-node`); `Required` policy fail-closes on `Absent` / `Malformed` carriers as `GovernanceAuthorityRequiredButMissing` (helper-replay scenarios `R1`, `R2`, `R16`); `OnChainGovernance` remains unsupported / fail-closed at the verifier (`R15`). MainNet peer-driven apply remains refused regardless of any governance-proof carrier (`R20`); local operator config alone remains insufficient as MainNet bundle-signing authority; local peer majority remains insufficient as MainNet bundle-signing authority; static production source-code anchors remain rejected. Honest limitation: lifting the release-binary CLI to expose a configurable `RequiredForLifecycleSensitive` toggle is operator-control plumbing intentionally NOT in Run 170 scope and is deferred; the full Required-policy proof-carrying matrix is exercised through the Run 168 release-built helper replay (`H1`–`H13`) and the Run 169 source/test integration suite (39 tests). No wire / marker / sequence / trust-bundle / peer-candidate-envelope schema change in Run 170. KMS/HSM-backed verifier installation remains deferred. C4 / C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_170.md`.
## Run 171 — source/test hidden Required-policy operator selector wiring; authority model unchanged

Run 171 completes the operator-control plumbing that Run 170 declared as a deferred honest limitation, at the **source/test level only**, and does not change the trust-anchor authority model. It adds a hidden, disabled-by-default selector for `GovernanceProofPolicy::RequiredForLifecycleSensitive`: a CLI flag `--p2p-trust-bundle-governance-proof-required` (declared with `clap` `hide = true`, absent from `--help`) OR-combined with the environment variable `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` (truthy values `1` / `true` / `yes` / `on`). The resolved policy (via the `governance_proof_required_env_selector_enabled` / `governance_proof_policy_from_selector` / `governance_proof_policy_from_cli_or_env` helpers in `crates/qbind-node/src/pqc_governance_proof_surface.rs`) is routed through the Run 169 shim `pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load` into the production v2 marker-decision callers (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP via the new `LiveReloadConfig::governance_proof_policy`, and the peer-driven coordinator). The authority hierarchy (genesis-bound authority root → ratified bundle-signing key, with optional `GenesisBound` / `EmergencyCouncil` / `OnChainGovernance` governance proof per Run 165) is unchanged; the typed reject variants from Run 163 are unchanged; the fixture issuer-signature verifier remains the only verifier wired into production callers. **The default policy in production callers remains `NotRequired`**, so existing no-proof v2 sidecars continue to be accepted exactly as before; the Required selector is hidden and explicit, and when enabled fails closed on `Absent` / `Malformed` carriers as `GovernanceAuthorityRequiredButMissing` while valid proof-carrying sidecars pass. MainNet bundle-signing authority still cannot be established by local config alone, by peer-majority alone, or by any static production source-code anchor; **MainNet peer-driven apply remains refused even with the Required selector enabled and a valid proof present** (refusal owned by Run 130). Honest limitation: Run 171 is source/test only; release-binary Required-policy production-surface evidence is **deferred to Run 172**. `OnChainGovernance` remains unsupported / fail-closed; governance execution remains unimplemented; KMS/HSM-backed verifier installation remains deferred; validator-set rotation remains open; no wire / marker / sequence / trust-bundle / peer-candidate-envelope schema change. Full C4 and C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_171.md`.
Run 172 — release-binary EVIDENCE for the Run 171 hidden Required-policy selector on real `target/release/qbind-node`. The trust-anchor authority model is unchanged: governance authority verification is production-source reachable after Run 165, exercised on release builds after Run 166 / 168 / 170, and now release-binary-evidenced on the **mutating** preflight surface for both CLI and env activation of the Required policy after Run 172. The wire material does not yet carry an `OnChainGovernance` `GovernanceAuthorityProof`; `OnChainGovernance` remains unsupported / fail-closed; `GenesisBound` and `EmergencyCouncil` proofs continue to be the only accepted classes via the Run 167 `GovernanceAuthorityProofWire` carrier and the Run 163 typed verifier. Required policy under Run 172 enforces, on the mutating preflight surface (process-start `--p2p-trust-bundle-reload-apply-path`, startup `--p2p-trust-bundle`, SIGHUP live reload, peer-driven `ProductionV2MarkerCoordinator`), that lifecycle-sensitive transitions (`Rotate`, `Revoke`, `Retire`, `EmergencyRevoke`) cannot proceed without a valid proof binding (class, authority root fingerprint, candidate v2 digest, authority-domain sequence, lifecycle action, issuer signature, issuer suite). Anti-rollback (Run 055), Run 130 v2 verifier, Run 131 marker derivation, Run 132/142 validation-only paths, Run 134 process-start reload-apply, Run 136 startup `--p2p-trust-bundle`, Run 138 SIGHUP, Run 144 peer-driven safety contract, Run 159 lifecycle, Run 161 lifecycle integration, Run 163 governance verifier, Run 165 governance integration, Run 167 wire schema, Run 169 loader integration, and Run 171 selector are all preserved bit-for-bit. Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority. Local peer majority remains insufficient for MainNet bundle-signing authority. KMS/HSM custody, MainNet governance attestation, validator-set rotation, full C4 closure, and C5 closure remain open. Honest limitation: validation-only surface Required-policy enforcement is a deferred source-side task (the validation-only preflight does not call `governance_proof_policy_from_cli_or_env`); the validation-only rejection branch is exercised at symbol level by Run 168 and at source-test level by Run 169/171. Release-binary boundary evidence: `docs/devnet/run_172_governance_required_policy_release_binary/`. Canonical evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_172.md`.
Run 173 — source/test wiring of the Run 171 governance-proof Required-policy selector into validation-only v2 surfaces. The trust-anchor authority model is unchanged: governance authority verification is production-source reachable after Run 165, exercised on release builds after Run 166 / 168 / 170 / 172 on the mutating preflight surfaces, and now wired at source/test level into the validation-only preflight surfaces (`--p2p-trust-bundle-reload-check`, local `--p2p-trust-bundle-peer-candidate-check`) after Run 173. The new shim `pqc_governance_proof_surface::preflight_v2_validation_only_marker_check_with_governance_proof_load` is the **single integration shim** for validation-only callers — it delegates to the existing Run 169 mutating shim, so the gate algorithm, the typed Run 163 reject variants, and the fixture issuer-signature verifier are all unchanged. The authority hierarchy (genesis-bound authority root → ratified bundle-signing key, with optional `GenesisBound` / `EmergencyCouncil` / `OnChainGovernance` governance proof per Run 165) is unchanged. `OnChainGovernance` remains unsupported / fail-closed at the Run 163 verifier on every surface, including the new validation-only surface. **The default policy on validation-only surfaces remains `NotRequired`** so existing no-proof v2 sidecars continue to be accepted exactly as before; the Required selector is hidden, explicit, and OR-combined from the Run 171 CLI flag and env var. Under Required: valid proof-carrying sidecars pass and missing / malformed / invalid proofs fail closed on validation-only surfaces with the same typed errors as on mutating surfaces, BEFORE the (already non-existent) marker / sequence / live-trust mutation that validation-only surfaces never perform. MainNet bundle-signing authority still cannot be established by local config alone, by peer-majority alone, or by any static production source-code anchor; **MainNet peer-driven apply remains refused even with the Required selector enabled, a valid proof present, and a passing validation-only gate** (refusal owned by Run 130 / Run 147 at the upstream surface). Honest limitation: live inbound `0x05` peer-candidate envelopes do not carry the `governance_authority_proof` sibling on the wire, so the live `0x05` validation surface cannot yet supply a typed `GovernanceProofLoadStatus`; lifting live `0x05` to Required policy is documented and deferred because the Run 173 task explicitly forbids peer-candidate envelope schema changes. **Release-binary validation-only Required-policy production-surface evidence is deferred to Run 174.** Governance execution remains unimplemented; KMS/HSM-backed verifier installation remains deferred; validator-set rotation remains open; full C4 and C5 remain open. Canonical evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_173.md`.
Run 174 — release-binary EVIDENCE for the Run 173 source/test wiring of the hidden Run 171 governance-proof Required-policy selector (`--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) into the validation-only v2 marker-decision production surfaces on real `target/release/qbind-node`. The trust-anchor authority model is unchanged: governance authority verification is still performed by the Run 163 `GovernanceAuthorityVerifier` over the Run 167 `GovernanceProofCarrier` for `Off-chain { ED25519 | DILITHIUM3 | HYBRID(ED25519+DILITHIUM3) }`; `OnChainGovernance` remains unsupported / fail-closed on every surface, including the validation-only `--p2p-trust-bundle-reload-check` and local `--p2p-trust-bundle-peer-candidate-check` surfaces (Run 174 R12 demonstrated on real `target/release/qbind-node`). The hidden Required-policy selector resolves via `governance_proof_policy_from_cli_or_env` exactly as in Run 171 / 172 / 173 (CLI explicit override; otherwise env truthy `1|true|yes|on` → `RequiredForLifecycleSensitive`; otherwise default `NotRequired`), and is consumed by the Run 173 validation-only shim `preflight_v2_validation_only_marker_check_with_governance_proof_load` which delegates to the Run 169 mutating shim `preflight_v2_marker_decision_with_governance_proof_load`. The Run 173 wiring preserves the validation-only invariant: even when the selector is enabled and a proof-carrying GenesisBound Rotate@seq=2 sidecar is accepted, no authority-marker is written, no persisted lifecycle-sequence is written, no Run 070 apply runs, no `[run-134] reload-apply v2 ratification path SELECTED` line is emitted, no `[run-134] v2 authority-marker persisted` line is emitted, no live trust mutation occurs, no session eviction occurs, no `.tmp` residue is left, no fallback to `--p2p-trusted-root` is triggered, and no active `DummySig` / `DummyKem` / `DummyAead` is reachable; under refusal, the same invariants hold and `[binary] Run 132: VERDICT=invalid (reload-check v2 authority-marker conflict; ...) Reason: <Display>` is emitted with the typed `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing` (RequiredButMissing — Run 174 R1 / R2) or `MutatingSurfaceMarkerV2Error::GovernanceAuthorityProofRejected` (Rejected — Run 174 R3 / R4 / R8 / R9 / R10 / R11 / R-extra / R12) Display string from `pqc_authority_marker_acceptance.rs`. Under default `NotRequired`, the Run 144 / Run 148–152 / Run 165 trust-anchor authority composition (Genesis-bound v2 marker + Run 130 ratification verifier) continues to govern validation-only acceptance with no proof requirement (Run 174 A1 / A6a / A6b / R19). MainNet bundle-signing authority is still anchored to the Run 070 / Run 144 / Run 147 contract: peer-driven apply on MainNet remains FATAL even with `--p2p-trust-bundle-peer-candidate-staging-enabled` + `--p2p-trust-bundle-governance-proof-required` + a valid proof-carrying Rotate sidecar (Run 174 R20). Local peer majority remains insufficient as bundle-signing authority; local operator config alone remains insufficient as bundle-signing authority; static production source-code anchors remain rejected. The selector is hidden (`hide = true`) and does not appear in `--help`. **Honest limitations preserved (Run 174 does NOT close them):** (i) live inbound `0x05` peer-candidate envelopes still do not carry a `governance_authority_proof` sibling — live `0x05` proof-carrying remains OPEN, and lifting it requires a peer-candidate envelope schema change explicitly forbidden by `task/RUN_174_TASK.txt`; (ii) local `--p2p-trust-bundle-peer-candidate-check` release-binary scenarios (A4 / A5 / R15 / R16) are deferred because the Run 172 fixture helper does not mint a peer-candidate envelope — the validation-only peer-candidate-check production surface shares `preflight_run_132_validation_only_v2_marker_check` with reload-check by construction (Run 173 wiring), so policy resolution and the gate composition are identical, and the Run 173 source-test integration suite covers both call sites at source level; (iii) R5 / R6 / R7 (wrong-environment / wrong-chain / wrong-genesis) cannot be expressed as static fixtures consumable by the binary because the Run 130 v2 ratification verifier upstream trips first — covered at source level by the Run 173 integration tests and at symbol level by the Run 168 release-built helper. Run 174 introduces no production runtime source change, no CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no schema change, no new metric family, no KMS / HSM, no governance-execution implementation, no on-chain governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. The release-binary harness is `scripts/devnet/run_174_validation_only_governance_required_policy_release_binary.sh`. The curated evidence archive is `docs/devnet/run_174_validation_only_governance_required_policy_release_binary/` (only README + summary + .gitignore tracked). No Run 050–173 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_174.md`.
Run 175 — release-binary EVIDENCE for the Run 173 source/test wiring of the hidden Run 171 governance-proof Required-policy selector (`--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) into the LOCAL `--p2p-trust-bundle-peer-candidate-check` validation-only v2 marker-decision production surface on real `target/release/qbind-node`; partner deliverable to Run 174 on the peer-candidate-check side, closing the Run 174-deferred peer-candidate-check release-binary cases. The trust-anchor authority model is unchanged: governance authority verification is still performed by the Run 163 `GovernanceAuthorityVerifier` over the Run 167 `GovernanceProofCarrier` for `Off-chain { ED25519 | DILITHIUM3 | HYBRID(ED25519+DILITHIUM3) }`; `OnChainGovernance` remains unsupported / fail-closed on every surface, including the validation-only `--p2p-trust-bundle-reload-check` and local `--p2p-trust-bundle-peer-candidate-check` surfaces (Run 175 R12 demonstrated on real `target/release/qbind-node`). The hidden Required-policy selector resolves via `governance_proof_policy_from_cli_or_env` exactly as in Run 171 / 172 / 173 / 174 (CLI explicit override; otherwise env truthy `1|true|yes|on` → `RequiredForLifecycleSensitive`; otherwise default `NotRequired`), and is consumed by the Run 173 validation-only shim `preflight_v2_validation_only_marker_check_with_governance_proof_load` which delegates to the Run 169 mutating shim `preflight_v2_marker_decision_with_governance_proof_load`. The Run 173 wiring preserves the validation-only invariant on the local peer-candidate-check surface: even when the selector is enabled and a proof-carrying GenesisBound Rotate@seq=2 sidecar is accepted, no authority-marker is written, no persisted lifecycle-sequence is written, no Run 070 apply runs, no `[run-134] reload-apply v2 ratification path SELECTED` line is emitted, no `[run-134] v2 authority-marker persisted` line is emitted, no live trust mutation occurs, no session eviction occurs, no `.tmp` residue is left, no fallback to `--p2p-trusted-root` is triggered, and no active `DummySig` / `DummyKem` / `DummyAead` is reachable; under refusal, the same invariants hold and `[binary] Run 132: VERDICT=invalid (peer-candidate-check v2 authority-marker conflict; ...) Reason: <Display>` is emitted with the typed `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing` (RequiredButMissing — Run 175 R1 / R2) or `MutatingSurfaceMarkerV2Error::GovernanceAuthorityProofRejected` (Rejected — Run 175 R3 / R4 / R8 / R9 / R10 / R11 / R-extra / R12) Display string from `pqc_authority_marker_acceptance.rs`. Under default `NotRequired`, the Run 144 / Run 148–152 / Run 165 / Run 174 trust-anchor authority composition (Genesis-bound v2 marker + Run 130 ratification verifier) continues to govern local peer-candidate-check acceptance with no proof requirement (Run 175 A1 / A4a / A4b / R17). MainNet bundle-signing authority is still anchored to the Run 070 / Run 144 / Run 147 contract: peer-driven apply on MainNet remains FATAL even with `--p2p-trust-bundle-peer-candidate-staging-enabled` + `--p2p-trust-bundle-governance-proof-required` + a valid proof-carrying Rotate sidecar + a valid local peer-candidate envelope (Run 175 R18). Local peer majority remains insufficient as bundle-signing authority; local operator config alone remains insufficient as bundle-signing authority; static production source-code anchors remain rejected. The local peer-candidate-check binary surface (Run 077 / Run 107) reuses the same `build_run_105_reload_check_context` constructor as `--p2p-trust-bundle-reload-check`, so the Run 171 selector capture (`governance_proof_required_selector`) and the Run 169 loader call (`load_versioned_ratification_with_governance_proof_from_path`) apply identically to both validation-only call sites by construction, with `preflight_run_132_validation_only_v2_marker_check` as the single shared entry point — there is no second selector path and no second gate path. The selector is hidden (`hide = true`) and does not appear in `--help`. **Honest limitations preserved (Run 175 does NOT close them):** (i) live inbound `0x05` peer-candidate envelopes still do not carry a `governance_authority_proof` sibling — live `0x05` proof-carrying remains OPEN, and lifting it requires a peer-candidate envelope schema change explicitly forbidden by `task/RUN_175_TASK.txt`; (ii) R5 / R6 / R7 (wrong-environment / wrong-chain / wrong-genesis) cannot be expressed as static fixtures consumable by the binary because the Run 130 v2 ratification verifier upstream trips first — covered at source level by the Run 173 integration tests and at symbol level by the Run 168 release-built helper. Run 175 introduces no production runtime source change, no CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no schema change, no new metric family, no KMS / HSM, no governance-execution implementation, no on-chain governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. The release-binary harness is `scripts/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary.sh`. The new release-built fixture helper `crates/qbind-node/examples/run_175_peer_candidate_check_governance_required_policy_release_binary_helper.rs` mints the Run 172-shape ratification corpus PLUS Run 076-schema PeerCandidateEnvelope JSONs wrapping the existing candidate trust bundles. The curated evidence archive is `docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary/` (only README + summary + .gitignore tracked). No Run 050–174 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_175.md`.
Run 176 — source/test governance-proof carrying for live inbound `0x05` peer-candidate envelopes. The live `0x05` `PeerCandidateWireEnvelopeV1` gains an additive optional `governance_authority_proof: Option<GovernanceAuthorityProofWire>` field and a `governance_proof_load_status()` helper that maps the in-band carrier to the same Run 167 `GovernanceProofLoadStatus` used by every other v2 surface (`None → Absent`, well-formed → `Available`, malformed → `Malformed`). A new validation-only library shim `preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier` routes the carrier into the Run 173 → Run 169 → Run 165 governance composition over the Run 163 verifier. `OnChainGovernance` remains unsupported / fail-closed at the Run 163 verifier. Local operator config alone is still insufficient for MainNet bundle-signing authority. Local peer majority is still insufficient for MainNet bundle-signing authority. `RequiredForLifecycleSensitive` policy still fail-closes on missing or malformed proofs (Absent under Required → RequiredButMissing; Malformed under Required → Unavailable → RequiredButMissing). The in-band carrier complements (does not replace) the Run 167 sidecar loader; both produce the same typed `GovernanceProofLoadStatus`. A5 / A6 (Revoke / EmergencyRevoke "where representable") document the pre-existing Run 161 metadata-prefix and Run 130 V2-action-enum boundaries — independent of Run 176. Source/test only — release-binary evidence is deferred to Run 177. No marker / sequence-file / trust-bundle core / authority-marker / wire-frame / wire-domain-tag schema change. No Run 050–175 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_176.md`.
Run 177 — release-binary live inbound `0x05` governance-proof carrier evidence. Run 177 closes the Run 176-deferred release-binary boundary: on real `target/release/qbind-node` nodes (DevNet N=3 V0/V1/V2 topology, real live P2P, real ML-KEM-768 / ML-DSA-44 / ChaCha20-Poly1305 path) the Run 167 governance-proof carrier is now reachable from the live `0x05` peer-candidate path through the additive Run 176 `governance_authority_proof: Option<GovernanceAuthorityProofWire>` field on `PeerCandidateWireEnvelopeV1` and the Run 177 publish-time injection point. The carrier reaches the Run 165 governance gate via the Run 176 → Run 173 → Run 169 → Run 165 chain over the Run 163 verifier. `OnChainGovernance` remains unsupported / fail-closed at the Run 163 verifier on real binaries (R13: rejected on receive). Local operator config alone is still insufficient for MainNet bundle-signing authority (R14 covered by R1 construction — no operator-config carrier in the Run 176/177 schema). Local peer majority is still insufficient for MainNet bundle-signing authority (R15 covered by R1 construction — no peer-majority carrier in the Run 176/177 schema). `RequiredForLifecycleSensitive` policy still fail-closes on missing or malformed proofs on real binaries (R1: Absent under Required → `GovernanceAuthorityRequiredButMissing`; R2: Malformed under Required → Unavailable → `GovernanceAuthorityRequiredButMissing`). The in-band carrier complements (does not replace) the Run 167 sidecar loader on real binaries; both produce the same typed `GovernanceProofLoadStatus`. R4 / R5 / R6 (wrong-environment / wrong-chain / wrong-genesis) remain release-binary-infeasible (Run 130 verifier trips upstream of the gate); covered at source level by Run 173 / Run 176 source-tests + Run 168 helper. A4 / A5 (Revoke / EmergencyRevoke release-binary representability) bounded by the Run 161 metadata-prefix lifecycle classifier and the v2 ratification action enum. The release-binary boundary is reached via a tiny harness-only hidden CLI flag `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path` (clap `hide=true`); default behaviour is unchanged. No marker / sequence-file / trust-bundle core / authority-marker / wire-frame / wire-domain-tag schema change beyond Run 176's optional envelope field. No Run 050–176 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_177.md`, `docs/devnet/run_177_live_0x05_governance_proof_release_binary/`.
Run 178 — source/test-only typed `OnChainGovernance` proof format and fail-closed verifier boundary. Before Run 178 the Run 163 `GovernanceAuthorityClass::OnChainGovernance` had only a single fail-closed verifier outcome (`UnsupportedOnChainGovernance`) — no proof object, no parsed bindings, no per-binding rejects. Run 178 adds the typed source/test-only `OnChainGovernanceProof` carrying every binding a future MainNet on-chain verifier would need (environment, chain_id, genesis_hash, authority_root_fingerprint + suite, governance_domain_id, governance_epoch, proposal_id, proposal_digest, proposal_outcome, quorum, threshold, lifecycle_action, active / new / revoked bundle-signing key fingerprints, authority_domain_sequence, candidate_v2_digest, freshness window, unique_decision_id replay nonce, proof_suite_id, proof_bytes), the `OnChainGovernanceProofPolicy::{Disabled (default), AllowFixtureSourceTest}` gate, the typed verifier outcome surface (`AcceptedOnChainGovernanceFixture`, `UnsupportedProductionOnChainGovernance`, `MainNetProductionProofUnavailable`, plus the precise rejects `WrongGovernanceDomain`, `WrongProposalDigest`, `WrongProposalOutcome`, `WrongGovernanceEpoch`, `ExpiredGovernanceProof`, `ReplayRejected`, `QuorumNotMet`, `ThresholdNotMet`, `InvalidGovernanceProof`, `UnsupportedGovernanceProofSuite`, `MalformedOnChainProof`, `LocalOperatorConfigOnlyRejected`, `PeerMajorityProofRejected`, and the standard environment / chain / genesis / authority-root / lifecycle / candidate-digest / authority-domain-sequence rejects), the pure non-mutating verifier `verify_onchain_governance_proof`, the combined lifecycle + governance helper `validate_lifecycle_with_onchain_governance_proof`, and the additive wire-safe carrier `OnChainGovernanceProofWire` (schema version 1, hex-encoded `proof_bytes`) on the existing Run 167 sidecar surface. Trust-anchor model implications: (i) the three authority classes from Run 163 (`GenesisBound`, `EmergencyCouncil`, `OnChainGovernance`) are unchanged — Run 178 preserves the Run 163 `verify_governance_authority_proof` byte-for-byte; (ii) the `OnChainGovernance` class is no longer "no proof format exists" at source/test level, but it remains explicitly fail-closed on production surfaces under the default `Disabled` policy and is **never** elevated to MainNet apply (MainNet always returns `MainNetProductionProofUnavailable`); (iii) the Run 178 fixture suite `ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1 = 0xA1` is a deterministic mock commitment over the bound fields and is **explicitly typed as fixture-only** — it is not a real on-chain proof verifier and must not be confused with a MainNet production proof; the reserved suite id `ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION = 0xA2` is rejected as `UnsupportedGovernanceProofSuite` until a future run installs a real verifier with explicit custody and governance policy; (iv) the trust-bundle core, v2 ratification, authority-marker, sequence-file, and peer-candidate-envelope schemas are unchanged — the `OnChainGovernanceProofWire` is an additive optional sibling on the existing Run 167 sidecar JSON, preserving full backward compatibility (R24); (v) MainNet anchor distribution remains pinned-image-only with no static production source-code anchor, no peer-majority authority, and no operator-config-alone authority; Run 178 introduces no new MainNet anchor distribution mechanism. Release-binary `OnChainGovernance` proof evidence is deferred to Run 179. KMS / HSM custody, governance execution, validator-set rotation, bridge / light-client integration, and real on-chain proof verification all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md`.
Run 179 — release-binary `OnChainGovernance` proof boundary evidence for the Run 178 typed verifier. Run 179 captures release-binary fixture/boundary evidence for Run 178 by exercising the full Run 178 A1–A7 / R1–R25 verifier corpus end-to-end in release mode through the production library symbols. Trust-anchor model implications: (i) the three authority classes from Run 163 (`GenesisBound`, `EmergencyCouncil`, `OnChainGovernance`) remain unchanged — Run 179 preserves the Run 163 `verify_governance_authority_proof` byte-for-byte; the Run 178 typed verifier remains a parallel source/test- and helper-reachable surface with zero production callers under `crates/qbind-node/src/` (proven on every harness invocation via the gitignored `reachability/source_reachability.txt` artifact); (ii) the `OnChainGovernance` class is still **explicitly fail-closed on production surfaces** under the default `OnChainGovernanceProofPolicy::Disabled`, and **never** elevated to MainNet apply (MainNet always returns `MainNetProductionProofUnavailable` even under the most permissive `AllowFixtureSourceTest` policy — helper R23 / binary `--help` denylist confirm this in release mode); (iii) the Run 178 fixture suite `ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1 = 0xA1` remains **explicitly typed as fixture-only** in release mode, and the reserved suite id `ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION = 0xA2` continues to be rejected as `UnsupportedGovernanceProofSuite` (helper R17 / R17b); (iv) the trust-bundle core, v2 ratification, authority-marker, sequence-file, and peer-candidate-envelope schemas are unchanged — the `OnChainGovernanceProofWire` is still the additive optional sibling on the Run 167 sidecar JSON, preserving full backward compatibility (R24 + R24b round-trip in release mode); (v) MainNet anchor distribution remains pinned-image-only with no static production source-code anchor, no peer-majority authority, and no operator-config-alone authority — Run 179 introduces no new MainNet anchor distribution mechanism; (vi) Run 179 introduces **no new operator-visible CLI flag, env knob, schema bump, wire shape, metric, or exit code** in any production module, and **no production caller** of any Run 178 verifier symbol. The verdict is honestly recorded as `partial-positive: release-binary fixture/boundary evidence captured; OnChainGovernance verifier not yet production-surface reachable`; the next integration run is identified as wiring `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` and the Run 178 verifier into a production v2 marker-decision caller behind a hidden Run 171-style selector, preserving `Disabled` as the production default and preserving MainNet refusal unconditionally. KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, and real on-chain proof verification all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md`.
Run 180 — source/test-only wiring of the Run 178 typed `OnChainGovernance` proof verifier into production marker-decision composition behind a hidden DevNet/TestNet-only `AllowFixtureSourceTest` selector. Trust-anchor model implications: (i) the three authority classes from Run 163 (`GenesisBound`, `EmergencyCouncil`, `OnChainGovernance`) remain unchanged — Run 180 introduces no new authority class and does not modify the Run 163 `verify_governance_authority_proof` byte-for-byte; instead, Run 180 wires the parallel Run 178 typed `OnChainGovernance` proof verifier (`verify_onchain_governance_proof` / `validate_lifecycle_with_onchain_governance_proof`) into a production marker-decision composition path through a single shared composed helper plus seven named per-surface delegating wrappers in `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`; (ii) the `OnChainGovernance` class on production surfaces is still **fail-closed by default** — `OnChainGovernanceProofPolicy::Disabled` is the production default on every surface, and every per-surface wrapper short-circuits with `OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled` before any verifier work runs; the `AllowFixtureSourceTest` policy is **selectable only** via the hidden CLI flag `--p2p-trust-bundle-onchain-governance-fixture-allowed` (`hide = true`, `default_value_t = false`) or the environment variable `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` (truthy values only), exactly mirroring the Run 171 governance-required selector pattern; (iii) the `OnChainGovernance` class is **never elevated to MainNet apply** under Run 180 — the shared composed helper short-circuits with `MainNetRefused` whenever any of proof / trust-domain / candidate advertises `TrustBundleEnvironment::Mainnet`, regardless of policy state and regardless of fixture-proof validity (Run 180 R3 asserts this), so the Run 147 FATAL MainNet peer-driven apply refusal continues to hold unconditionally; (iv) the Run 178 fixture suite `ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1 = 0xA1` remains **explicitly typed as fixture-only**, and the reserved suite id `ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION = 0xA2` continues to be rejected as `UnsupportedGovernanceProofSuite` (Run 180 R19 asserts this at the composition layer); (v) the trust-bundle core, v2 ratification, authority-marker, sequence-file, and peer-candidate-envelope schemas are unchanged — Run 180 introduces no schema bump, no wire field, and no metric / exit-code drift beyond Run 178's existing additive `OnChainGovernanceProofWire` shape (which Run 180 does not modify); (vi) MainNet anchor distribution remains pinned-image-only with no static production source-code anchor, no peer-majority authority, no operator-config-alone authority, no autonomous apply, and no apply-on-receipt — Run 180 introduces none of these mechanisms and does not change MainNet anchor distribution in any way; (vii) the Run 180 wiring is composition-only (no I/O on production state, no `LivePqcTrustState` mutation, no replay-set extension, no marker write, no sequence write, no Run 070 apply invocation) — the seven per-surface wrappers feed only the validation/composition layer, exactly like Run 171 / 173 / 176 / 177 governance-gate composition for the Run 163 verifier; (viii) the release-binary boundary for the Run 180 wiring is **deferred to Run 181**, so the verdict is honestly recorded as `partial-positive: source/test reachability captured; release-binary boundary deferred to Run 181`. KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, and real on-chain proof verification on MainNet all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`.
Run 181 — release-binary `OnChainGovernance` production-surface fixture-policy selector evidence for the Run 178 / Run 180 typed `OnChainGovernance` proof. Run 181 captures release-binary evidence on real `target/release/qbind-node` that the trust-anchor authority model's `GovernanceAuthorityClass::OnChainGovernance` typed-proof path (Run 178 verifier `verify_onchain_governance_proof`, Run 180 production marker-decision composition `compose_onchain_governance_marker_decision` and seven per-surface named wrappers under `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`) is selectable only via the hidden disabled-by-default Run 180 selector (`--p2p-trust-bundle-onchain-governance-fixture-allowed`, `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`), which arms `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` for DevNet / TestNet fixture proofs only and never on MainNet. For the trust-anchor authority model, Run 181 reasserts: (1) `OnChainGovernanceProofPolicy::Disabled` is the production default on every surface — `GenesisBound` and `EmergencyCouncil` proof-carrying behavior (Runs 163 / 165 / 167 / 169 / 171 / 173 / 176 / 177) is unchanged; the Run 178 `OnChainGovernance` typed verifier is reachable only when the selector is explicitly armed; (2) MainNet remains fail-closed via `MainNetProductionProofUnavailable` from the Run 178 verifier and via the Run 147 FATAL peer-driven-apply refusal at the calling surface, in two layers that agree without weakening; (3) the typed `OnChainGovernanceProof` bindings (environment, chain_id, genesis_hash, authority_root_fingerprint + suite, governance_domain_id, governance_epoch, proposal_id, proposal_digest, proposal_outcome, lifecycle_action, candidate_v2_digest, authority_domain_sequence, freshness window, unique_decision_id replay nonce, quorum, threshold, proof bytes) all participate in the per-binding fail-closed reject paths (R1–R26) exercised by the release-built helper. Honest limitation: Run 180's binary-side wiring stops at the selector-capture / banner-emission site in `main.rs`; the per-surface `--p2p-trust-bundle-*` marker-decision call sites in the production binary do not yet pass the resolved `OnChainGovernanceProofPolicy` into the per-surface wrappers, so the Run 180 / Run 181 surface remains source/test + selector-only as observed from the production binary. The trust-anchor authority model accepts no new authority class, no new authority root, no new governance authority, no validator-set rotation, no KMS/HSM custody implementation, and no real on-chain governance execution as a result of Run 181. Run 181 verdict is honestly recorded as `partial-positive`. No production source change. No MainNet apply enablement. No autonomous apply / apply-on-receipt / peer-majority authority. No real on-chain governance execution, no real on-chain proof verifier, no bridge / light-client integration, no KMS / HSM custody, no validator-set rotation. No marker / sequence-file / trust-bundle / wire / metric drift. No DummySig / DummyKem / DummyAead activation, no fallback to `--p2p-trusted-root`. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md`.Run 182 — source/test production call-site wiring of the Run 180 per-surface OnChainGovernance preflight wrappers, with re-assertion of the trust-anchor authority model invariants. For the trust-anchor authority model, Run 182 wires the seven Run 180 per-surface wrappers into the seven production v2 marker-decision call sites via the new module `crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs`. The trust-anchor authority model is unchanged: (1) `OnChainGovernanceProofPolicy::Disabled` remains the production default on every surface — `GenesisBound` and `EmergencyCouncil` proof-carrying behaviour (Runs 163 / 165 / 167 / 169 / 171 / 173 / 176 / 177) is unchanged byte-for-byte; the Run 178 `OnChainGovernance` typed verifier is reachable from production source paths only when the hidden Run 180 selector is explicitly armed; (2) MainNet remains fail-closed in three agreeing layers — the Run 147 startup environment gate, the Run 178 verifier's `MainNetProductionProofUnavailable`, and the Run 182 peer-driven-drain wiring entry's surface-level MainNet refusal; (3) the typed `OnChainGovernanceProof` bindings (environment, chain_id, genesis_hash, authority_root_fingerprint + suite, governance_domain_id, governance_epoch, proposal_id, proposal_digest, proposal_outcome, lifecycle_action, candidate_v2_digest, authority_domain_sequence, freshness window, unique_decision_id replay nonce, quorum, threshold, proof bytes) all participate in the per-binding fail-closed reject paths exercised by Run 182's R1–R27 integration tests through the wiring entries; (4) the trust-anchor authority model accepts no new authority class, no new authority root, no new governance authority, no validator-set rotation, no KMS/HSM custody implementation, and no real on-chain governance execution as a result of Run 182. Honest limitation: no peer-candidate, SIGHUP-trigger, reload-apply trigger, startup-bundle, or live `0x05` payload format today carries a typed `OnChainGovernanceProof`; production callers invoke the Run 182 wiring entries with `proof: None`. Adding a typed proof to any wire/schema is explicitly out of scope for Run 182 (no schema bump, no wire field, no sidecar field). The trust-anchor authority model therefore continues to make a typed-proof claim only when the operator supplies one in-process via library API; the production binary surface remains observation-equivalent to Run 181. Run 182 verdict is honestly recorded as `partial-positive: source/test production call-site reachability captured; release-binary evidence deferred`. Run 182 is source/test production call-site wiring for OnChainGovernance fixture proofs. Default remains `OnChainGovernanceProofPolicy::Disabled`. `AllowFixtureSourceTest` is hidden, explicit, and DevNet/TestNet fixture-only. Real on-chain governance proof verification remains unimplemented. Governance execution remains unimplemented. Production MainNet OnChainGovernance remains unsupported / fail-closed. MainNet peer-driven apply remains refused. KMS/HSM remains unimplemented. Validator-set rotation remains open. **Release-binary OnChainGovernance production-surface evidence covering the wired call sites is deferred to Run 183. Full C4 / C5 remain OPEN.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md`.Run 183 — release-binary evidence for the Run 182 production v2 marker-decision call-site wiring of the Run 180 per-surface OnChainGovernance preflight wrappers, on real `target/release/qbind-node`. Authority-model status under Run 183 is unchanged from the Run 178 / 180 / 181 / 182 baseline: the Run 178 typed `OnChainGovernance` proof verifier and the Run 161 / 163 / 165 lifecycle / authority-domain validators remain the only authority-decision sources; no peer-majority / gossip-count / local-operator-config-alone authority is granted on any surface. Run 183 captures, on real `target/release/qbind-node`, that the hidden Run 180 selector (`--p2p-trust-bundle-onchain-governance-fixture-allowed` / `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`) propagates the resolved `OnChainGovernanceProofPolicy` through `Run105ReloadCheckContextData`, `LiveReloadConfig`, and `ProductionV2MarkerCoordinator` into every Run 182 named callsite entry on each of the seven production v2 marker-decision code paths (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound `0x05`, and peer-driven drain). Under the production default `OnChainGovernanceProofPolicy::Disabled` every Run 182 callsite entry short-circuits on `PolicyDisabled`; under the hidden DevNet/TestNet `AllowFixtureSourceTest` policy the entry delegates to the Run 180 per-surface wrapper which delegates to the Run 178 typed verifier and the Run 161 / 163 / 165 lifecycle / authority-domain validators. The release-built helper exercises the full A1–A9 / R1–R26 matrix in release mode through the production library symbols. Run 183 introduces no new authority source, no new wire field, no new sidecar field, no new schema bump, no new metric, no new exit code, and no new CLI flag beyond the Run 180 hidden selector. Honest limitation (unchanged from Run 182): no current peer-candidate, SIGHUP-trigger, reload-apply trigger, startup-bundle, or live `0x05` payload format carries a typed `OnChainGovernanceProof`; adding such a field is explicitly out of scope for Run 183. Therefore production callers in real `target/release/qbind-node` invoke the Run 182 callsite entries with `proof: None`, the Run 180 wrapper short-circuits on `NoOnChainGovernanceProofSupplied`, and the existing authority-decision behaviour on every surface is preserved bit-for-bit. Production MainNet OnChainGovernance remains unsupported / fail-closed. MainNet peer-driven apply remains refused. KMS/HSM remains unimplemented. Validator-set rotation remains open. **Full C4 / C5 remain OPEN.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`.

## Run 184 update — source/test OnChainGovernance proof carrying through production v2 sidecar payload

Run 184 adds, at source/test level only, an additive optional
`onchain_governance_proof` sibling field on the existing v2 ratification
sidecar JSON wire that delivers a typed
`OnChainGovernanceProofWire` into the `proof` slot of
`OnChainGovernanceCallsiteContext` consumed by the seven Run 182
named production call-site entries. The sibling is parsed via the
same pre-extraction pattern used by Run 167's `governance_authority_proof`
carrier so unknown fields cannot poison the strict
`BundleSigningRatificationV2` parse, and legacy v2 sidecars without
the sibling continue to load identically with `proof: None`. Default
policy on every surface remains
`OnChainGovernanceProofPolicy::Disabled`; the hidden
`AllowFixtureSourceTest` policy is DevNet/TestNet fixture-only
behind the existing Run 181/183 selector. A valid carried fixture
proof reaches the production call-site context at source/test level
and is accepted only when the hidden selector is armed; an invalid
or malformed-payload sibling fails closed surface-uniformly *before*
the Run 182 entry runs, regardless of policy. MainNet peer-driven
apply remains refused even with a fully-valid DevNet fixture proof
carried through the new payload. Release-binary boundary evidence
covering the new payload-carrying surface is **deferred to Run 185**.
Real on-chain governance proof verification, governance execution,
KMS/HSM custody, validator-set rotation, bridge/light-client
integration, autonomous apply, and apply-on-receipt all remain
unimplemented. Full C4 and C5 remain open.

## Run 185 update — release-binary OnChainGovernance proof-payload-carrying accepted-proof evidence

Run 185 closes the Run 184-deferred release-binary boundary by
exercising on real `target/release/qbind-node` the additive optional
`onchain_governance_proof` sibling Run 184 introduced on the v2
ratification sidecar JSON wire and the seven Run 182 named
production call-site entries (`reload_check_callsite_`,
`reload_apply_callsite_`, `startup_p2p_trust_bundle_callsite_`,
`sighup_callsite_`, `local_peer_candidate_check_callsite_`,
`live_inbound_0x05_callsite_`,
`peer_driven_drain_callsite_onchain_governance_marker_decision`)
plus the typed argument bundle `OnChainGovernanceCallsiteContext`,
the additive selector builder
`with_onchain_governance_fixture_allowed_selector`, the Run 184
payload-carrying loaders
`load_v2_ratification_sidecar_with_onchain_governance_proof_*` /
`parse_optional_onchain_governance_proof_sibling_from_json_value`,
the routing helpers
`route_loaded_onchain_governance_proof_to_*_callsite_decision`,
and the typed `OnChainGovernanceProofPayloadParseError` boundary.
On real `target/release/qbind-node`, Run 185 captures: the
production default — neither flag nor env var truthy — emitting no
`[run-180] ... policy ARMED (AllowFixtureSourceTest)` banner and
preserving `OnChainGovernanceProofPolicy::Disabled` on every
surface, with a v2 sidecar without the Run 184 sibling parsing
byte-for-byte identically to its pre-Run-184 form (A1 / R1); the
CLI selector arming `AllowFixtureSourceTest` exactly when supplied
(A2); the env selector arming across truthy variants
`{1, true, TRUE, True, yes, YES, on, ON}` and remaining disabled
across falsey variants `{0, false, FALSE, no, off, empty, garbage}`
(A3); real
`target/release/qbind-node --p2p-trust-bundle-reload-check
<sidecar-with-sibling>
--p2p-trust-bundle-onchain-governance-fixture-allowed --network
devnet` loading a v2 sidecar carrying a valid DevNet fixture-rotate
proof, extracting the additive Run 184 sibling, parsing the typed
`OnChainGovernanceProofWire`, and reaching the Run 182 reload-check
named callsite entry through the production
`preflight_run_132_validation_only_v2_marker_check` path with no
marker write, no sequence write, no live trust swap, no session
eviction, and no Run 070 call (A2_payload); the matching
`--p2p-trust-bundle-reload-apply-enabled
--p2p-trust-bundle-reload-apply-path <sidecar-with-sibling>`
invocation arming the selector, loading the sidecar, parsing the
sibling, and invoking the Run 182 reload-apply named callsite entry
through the production `preflight_run_134_v2_marker_decision` path
on the mutating surface, with the Run 070-honest
`ReloadApplyError::UnsupportedRuntimeContext` returned on a
non-long-running invocation and the matching accepted typed outcome
captured in release mode by the new Run 185 release-built helper
through the same library symbols, with Run 055
sequence-before-marker ordering preserved at the library layer
(A4 / A5); malformed sibling payloads (non-object, unknown_schema,
empty required field, empty proof bytes) failing closed at the
typed `OnChainGovernanceProofPayloadParseError` boundary BEFORE any
verifier or marker decision runs (R2 a–d); `qbind-node --help` not
surfacing the hidden flag (`hide = true`) and not surfacing a
`run-180` / `run-181` / `run-182` / `run-183` / `run-184` /
`run-185` / `onchain-governance-fixture` token; and MainNet
peer-driven apply remaining the Run 147 / 148 / 152 FATAL invariant
even with the selector engaged on `--network mainnet` AND a
fully-valid MainNet fixture-rotate proof carried in the v2 sidecar
via the Run 184 sibling, with the Run 182 peer-driven-drain
callsite entry's surface-level `MainNetRefused` short-circuit
layered ahead of the Run 180 verifier (R26). Through both
release-built helpers (the Run 179
`run_179_onchain_governance_proof_release_binary_helper` for the
verifier corpus and the new Run 185
`run_185_onchain_governance_payload_release_binary_helper` for the
Run 184 payload-carrying / call-site-routing corpus), Run 185
captures release-mode acceptance / rejection across the full
A1–A9 / R1–R26 matrix through the production library symbols
`verify_onchain_governance_proof`,
`validate_lifecycle_with_onchain_governance_proof`,
`compose_onchain_governance_marker_decision`, every Run 180
per-surface composed wrapper, every Run 182 named callsite entry
plus `OnChainGovernanceCallsiteContext` and
`with_onchain_governance_fixture_allowed_selector`, the Run 184
payload-carrying loaders / routing helpers, and the typed
`OnChainGovernancePayloadCarryingDecisionOutcome::{MalformedOnChainGovernanceProofPayload,
Callsite}` boundary. Honest limitation: Run 184 added the additive
sibling on the v2 ratification sidecar JSON wire used by
reload-check / reload-apply / startup `--p2p-trust-bundle` / SIGHUP
only; the live `0x05` peer-candidate envelope and the peer-driven
drain inbound payload may not yet carry the typed OnChainGovernance
proof end-to-end on a real binary depending on tree state, and
where they do not, Run 185 captures the source-reachability for the
matching Run 182 named callsite entry through the release-built
helper in release mode AND records the boundary explicitly in the
archive's `mutation_proof.txt` / `no_mutation_proof.txt`. No
production source change. No MainNet apply enablement. No real
on-chain governance execution / no real on-chain proof verifier /
no bridge / light-client / KMS-HSM / validator-set rotation /
autonomous apply / apply-on-receipt / peer-majority authority. No
marker / sequence-file / trust-bundle / wire / metric drift beyond
Run 184's additive optional sibling. **Full C4 / C5 remain OPEN.**
Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md`,
`scripts/devnet/run_185_onchain_governance_payload_release_binary.sh`,
`docs/devnet/run_185_onchain_governance_payload_release_binary/`.

## Run 186 update — source/test typed production OnChainGovernance verifier boundary

Run 186 introduces, at source/test level only, a typed verifier-kind
boundary in the new
[`pqc_onchain_governance_verifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
module that cleanly separates fixture OnChainGovernance proof
verification (DevNet/TestNet evidence-only) from future real on-chain
governance proof verification (declared unavailable and fail-closed).
The boundary defines `OnChainGovernanceVerifierKind` (`Disabled` /
`FixtureSourceTest` / `ProductionUnavailable` /
`ProductionVerifierPlaceholder`), `OnChainGovernanceProofClass`
(`Fixture` / `Production`, derived from the proof suite ID via
`classify_onchain_governance_proof_class`),
`OnChainGovernanceVerifierPolicy` carrying the kind plus the Run 178
proof policy that the fixture path forwards to, and a typed
`OnChainGovernanceVerifierBoundaryOutcome` surface
(`AcceptedFixture(inner)` / `FixtureDisabled` /
`ProductionVerifierUnavailable` / `ProductionProofUnsupported` /
`ProductionProofMalformed{reason}` /
`MainNetProductionVerifierUnavailable` /
`FixtureProofRejectedAsMainNetProductionAuthority` /
`Run178Rejection(inner)`). The `OnChainGovernanceVerifier` trait has
four concrete implementations (`DisabledOnChainGovernanceVerifier`,
`FixtureSourceTestOnChainGovernanceVerifier`,
`ProductionUnavailableOnChainGovernanceVerifier`,
`ProductionVerifierPlaceholderOnChainGovernanceVerifier`), and the
pure entry points `verify_fixture_onchain_governance_proof` /
`verify_production_onchain_governance_proof` are dispatched through
`dispatch_onchain_governance_proof_through_verifier_boundary`. Default
kind on every surface is `Disabled` and refuses every proof; the
fixture path is reachable only under `FixtureSourceTest` plus the
existing `AllowFixtureSourceTest` proof policy and short-circuits to
`FixtureProofRejectedAsMainNetProductionAuthority` whenever the trust
domain, candidate root, or proof environment is MainNet — so a fixture
proof can never masquerade as a production governance authority. Both
production verifier kinds always return `ProductionVerifierUnavailable`
(or `MainNetProductionVerifierUnavailable` on MainNet) regardless of
proof material. The boundary is purely additive: no wire, no v2 sidecar
JSON, no `OnChainGovernanceProofWire`, no marker, no sequence file, no
trust-bundle core schema, and no Run 070 / 130–185 invariant changes.
Source/test acceptance and rejection are exercised by
[`run_186_onchain_governance_production_verifier_boundary_tests`](
  ../../crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs)
covering the full A1–A7 / R1–R29 matrix from `task/RUN_186_TASK.txt`
plus extras for proof-class separation, all four verifier traits,
MainNet masquerade refusal, dispatcher determinism, and call-site
reachability (44 tests, all passing). MainNet peer-driven apply remains
refused (Run 147 FATAL invariant). The release-binary boundary for the
verifier kind is explicitly deferred to Run 187. Real on-chain
governance proof verification, governance execution, KMS/HSM custody,
validator-set rotation, bridge / light-client integration, autonomous
apply, apply-on-receipt, and peer-majority authority all remain
unimplemented. **Full C4 / C5 remain OPEN.** Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_186.md`,
`crates/qbind-node/src/pqc_onchain_governance_verifier.rs`,
`crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`.
## Run 187 update — release-binary OnChainGovernance production verifier-boundary evidence

Run 187 closes the Run 186-deferred release-binary boundary for the
typed production OnChainGovernance verifier surface added by
[`pqc_onchain_governance_verifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
and preserves the trust-anchor authority model under the Run 186
typed verifier boundary on real `target/release/qbind-node`. The
authority model invariants captured by Run 187 are: fixture
OnChainGovernance proofs remain DevNet/TestNet evidence-only under
`OnChainGovernanceVerifierKind::FixtureSourceTest` and are explicitly
rejected as the typed
`FixtureProofRejectedAsMainNetProductionAuthority` outcome whenever
the trust-domain environment is MainNet — so a fixture proof can
never be promoted into a MainNet production governance authority;
production-class OnChainGovernance proof verification remains
fail-closed as `ProductionVerifierUnavailable` on DevNet/TestNet and
as `MainNetProductionVerifierUnavailable` on MainNet under both
`OnChainGovernanceVerifierKind::ProductionUnavailable` and
`OnChainGovernanceVerifierKind::ProductionVerifierPlaceholder`,
honestly encoding that no real on-chain governance proof verifier is
wired in this tree; the default
`OnChainGovernanceVerifierKind::Disabled` policy fails closed on
every production surface, so no proof — fixture-class or
production-class — can advance the authority root by default; the
hidden `AllowFixtureSourceTest` selector (`--p2p-trust-bundle-onchain-governance-fixture-allowed`
/ `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` truthy)
arms a DevNet/TestNet fixture-only verifier and **does not** enable
any production verifier, and remains hidden from `qbind-node --help`
per Runs 180/181/183; existing Run 185 reload-check / reload-apply
DevNet fixture-payload paths remain compatible under the Run 186
typed verifier-boundary contract, with the Run 184 routing helpers
continuing to short-circuit malformed-sibling payloads at the typed
`OnChainGovernanceProofPayloadParseError` boundary BEFORE any
Run 186 verifier-boundary dispatch; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal even with the selector
engaged AND a fully-valid MainNet fixture proof carried in the v2
sidecar via the Run 184 sibling, with the Run 186
`mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
helper additionally encoding the rule at the typed verifier boundary
regardless of policy kind. Through both release-built helpers (the
Run 185 [`run_185_onchain_governance_payload_release_binary_helper`](
  ../../crates/qbind-node/examples/run_185_onchain_governance_payload_release_binary_helper.rs)
for sidecar minting / payload-carrying compatibility evidence and
the new Run 187
[`run_187_onchain_governance_verifier_boundary_release_binary_helper`](
  ../../crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs)
for the typed verifier-boundary corpus), Run 187 captures
release-mode acceptance / rejection across the full A1–A8 / R1–R29
matrix from `task/RUN_187_TASK.txt` through the production library
symbols `pqc_onchain_governance_verifier::*` —
`OnChainGovernanceVerifierKind`, `OnChainGovernanceProofClass` and the
proof-class classifier, `OnChainGovernanceVerifierPolicy`,
`OnChainGovernanceVerifierBoundaryOutcome`, the
`OnChainGovernanceVerifier` trait with all four concrete impls, the
pure entry points, the dispatcher, and the MainNet refusal helper.
Honest limitation: Run 187 still wires no real on-chain governance
proof verifier and so makes no claim of full C4 closure; the typed
verifier boundary explicitly carries the unavailability through the
production library symbols rather than papering over it. No production
source change. No MainNet apply enablement. No real on-chain
governance execution. No bridge / light-client integration. No
KMS/HSM custody. No validator-set rotation. No autonomous apply. No
apply-on-receipt. No peer-majority authority. No schema / wire /
metric drift. **Full C4 / C5 remain OPEN.** Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_187.md`,
`scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`,
`docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary/`,
`crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs`.
## Run 188 — source/test KMS/HSM custody boundary

Run 188 introduces, at source/test level only, a typed authority-custody boundary
in the new `crates/qbind-node/src/pqc_authority_custody.rs` module:
`AuthorityCustodyClass` (`FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` /
`Kms` / `Hsm` / `Unknown`), `AuthorityCustodyPolicy` (`Disabled` (default) /
`FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed` /
`ProductionCustodyRequired` / `MainnetProductionCustodyRequired`),
`AuthorityCustodyAttestation` (binds environment, chain_id, genesis_hash,
authority_root_fingerprint, bundle_signing_key_fingerprint,
governance_authority_class, lifecycle_action, candidate_digest,
authority_domain_sequence, custody_class, custody_key_id,
custody_attestation_digest, and optional freshness/expiry),
`AuthorityCustodyValidationOutcome` (typed accept-fixture /
accept-local-operator / production-custody-unavailable / KMS / HSM /
RemoteSigner unavailable / unknown / wrong-binding / malformed / expired /
key-id-mismatch / unsupported-suite / MainNet refusals / policy refusal),
the pure validator `validate_authority_custody_attestation`, and the pure
composition helper `validate_lifecycle_governance_and_custody`.

Operational rules surfaced at the typed Run 188 boundary:

* **No real KMS/HSM backend is implemented.** RemoteSigner / Kms / Hsm
  are placeholder symbols only; the validator fails them closed as
  unavailable regardless of policy or environment.
* **Fixture/local custody remains DevNet/TestNet evidence-only.** It is
  reachable only under the explicit `FixtureOnly` / `DevnetLocalAllowed` /
  `TestnetLocalAllowed` policies.
* **Fixture/local custody cannot satisfy MainNet production custody.**
  Trust-domain MainNet rejects fixture custody as
  `FixtureCustodyRejectedForMainNet` and local-operator custody as
  `LocalCustodyRejectedForMainNet`, ahead of the policy gate.
* **MainNet peer-driven apply remains refused** (Run 147 FATAL invariant)
  regardless of any custody attestation contents; encoded by the
  grep-verifiable helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`.
* **Governance execution remains unimplemented.** Run 188 does not call
  the Run 163 / 178 / 186 governance verifier; the calling surface threads
  the already-validated governance class into the composition helper.
* **Real on-chain proof verification remains unimplemented.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved.
* **Validator-set rotation remains open.**
* **Release-binary custody-boundary evidence is deferred to Run 189.**
* **Full C4 remains open. C5 remains open.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_188.md` for the full A1–A8 /
R1–R29 acceptance matrix and validation-command list.
## Run 189 update — release-binary KMS/HSM authority-custody boundary evidence

Run 189 closes the Run 188-deferred release-binary boundary for the
typed authority-custody surface in
`crates/qbind-node/src/pqc_authority_custody.rs`, **preserving every
trust-anchor authority-model invariant from Runs 070, 130–188 bit-
identically**. The trust-anchor authority-model invariants captured
by Run 189 are:

* **Custody is a property of the bundle-signing key holder, not of
  the peer-gossip path.** The Run 188 typed
  `AuthorityCustodyAttestation` binds an explicit
  `bundle_signing_key_fingerprint` (and `authority_root_fingerprint`,
  `governance_authority_class`, `lifecycle_action`,
  `candidate_digest`, `authority_domain_sequence`, environment,
  chain id, genesis hash) to the custody class and key id; a
  custody attestation that does not bind the active bundle-signing
  key fingerprint is rejected by symbol with
  `WrongSigningKeyFingerprint`.
* **Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.** It is reachable only under the explicit
  `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
  policies; it is rejected by symbol whenever the trust-domain
  environment is MainNet
  (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`) ahead of the policy gate. The
  release-binary helper exercises every fixture / local-operator
  scenario across DevNet / TestNet / MainNet and asserts the
  expected typed outcome in release mode through the production
  library symbols.
* **Production custody is fail-closed unavailable.** Real KMS /
  HSM / cloud KMS / PKCS#11 / remote signer backends are not
  implemented in this tree; every `RemoteSigner` / `Kms` / `Hsm`
  attestation routes to the typed `RemoteSignerUnavailable` /
  `KmsUnavailable` / `HsmUnavailable` outcome regardless of
  policy or environment, and every `ProductionCustodyRequired` /
  `MainnetProductionCustodyRequired` policy routes to
  `ProductionCustodyUnavailable` /
  `MainNetProductionCustodyUnavailable` (or the placeholder-
  specific `*Unavailable`).
* **Peer-majority is not custody.** Encoded at the typed boundary
  via the named helper `peer_majority_cannot_satisfy_custody`. No
  count of peer attestations can satisfy any
  `*ProductionCustodyRequired` policy.
* **Local-operator config alone is not MainNet production
  custody.** Encoded at the typed boundary via the named helper
  `local_operator_config_alone_cannot_satisfy_mainnet_production_custody`.
* **MainNet peer-driven apply remains refused** at every surface
  (Run 147 / 148 / 152 FATAL invariant) and at the typed Run 188
  boundary via the named helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
  regardless of attestation contents or active policy.
* **Governance authority class and custody are independent
  invariants.** A custody attestation whose
  `governance_authority_class` does not match the calling-surface
  expectation routes to the typed `CustodyAttestationMalformed`
  outcome; conversely, a fully-valid custody attestation does not
  satisfy any governance-required gate on its own — the combined
  helper `validate_lifecycle_governance_and_custody` requires both
  the lifecycle and the governance class to be accepted by the
  calling surface before custody is checked. R23 / R24 capture
  this separation in release mode.

Through the release-built helper
`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`
and the harness
`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`,
Run 189 captures release-binary acceptance / rejection across the
full Run 188 A1–A8 / R1–R29 corpus through the production library
symbols `pqc_authority_custody::*`, plus a per-class / per-policy
fail-closed table, the three named helpers, no-mutation bit-
equality across the rejected corpus, and a deterministic re-
evaluation pass.

Honest limitation: Run 189 still wires no real KMS / HSM / cloud
KMS / PKCS#11 / remote-signer backend, no real on-chain governance
proof verifier, no governance execution engine, no validator-set
rotation, no autonomous apply, no apply-on-receipt, and no
peer-majority authority. Run 189 introduces no production source
change, no new CLI flag, no new env var, no new schema bump, no new
wire shape, no new sidecar field, no new metric, and no new exit
code. **Full C4 is NOT claimed by Run 189; C5 remains OPEN.**

See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_189.md`,
`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`,
`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`,
and `docs/devnet/run_189_authority_custody_boundary_release_binary/`
for the full release-binary scenario matrix and the canonical PASS
verdict.

## Run 190 — source/test authority-custody metadata carrying and production call-site wiring

Run 190 lifts the Run 188-honestly-recorded gap ("authority custody
metadata is not yet carried through production v2 sidecar /
peer-candidate / marker-decision contexts, and no production call
site routes custody validation into the lifecycle + governance
preflight path") at the source and test layers. The new module
`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`
adds, additively over the v2 ratification sidecar surface:

* `AuthorityCustodyAttestationWire` — the typed wire form of the
  Run 188 `AuthorityCustodyAttestation`, bound to
  `AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION = 1`, exposed
  as an optional `authority_custody_attestation` JSON sibling next
  to the existing Run 167 governance-proof and Run 184
  OnChainGovernance siblings;
* `AuthorityCustodyLoadStatus::{Absent, Available, Malformed}` —
  the typed sibling load status;
* `load_v2_sidecar_with_governance_and_custody` — the combined
  Run 167 + Run 184 + Run 190 sidecar loader returning each typed
  load status independently;
* `AuthorityCustodyCallsiteContext` — the production callsite
  context that pairs the parsed (or absent / malformed) custody
  attestation with the active `AuthorityCustodyPolicy`, the
  expected lifecycle / governance class / candidate digest /
  authority-domain sequence / custody-key-id, the trust-domain
  environment, and `now_unix`;
* seven named per-surface routing helpers — reload-check,
  reload-apply preflight, startup `--p2p-trust-bundle` preflight,
  SIGHUP preflight, local peer-candidate-check, live inbound
  `0x05`, peer-driven drain coordinator — each driving the Run 188
  composition `validate_lifecycle_governance_and_custody`;
* `AuthorityCustodyPayloadCarryingDecisionOutcome::{Accepted,
  MalformedPayload, RequiredButAbsent,
  NoCustodyAttestationSupplied, MainNetPeerDrivenApplyRefused,
  Callsite(...)}`;
* grep-verifiable named helpers
  `mainnet_peer_driven_apply_remains_refused_under_run_190`,
  `peer_majority_cannot_satisfy_run_190_custody`, and
  `local_operator_config_alone_cannot_satisfy_mainnet_run_190_custody`.

The Run 190 carrier preserves the Run 188 / Run 189 trust-anchor
authority model byte-for-byte:

* The default `AuthorityCustodyPolicy` on every surface remains
  `Disabled`. Run 190 introduces no new operator-visible CLI flag,
  env var, or selector. The active policy is supplied by the
  calling surface.
* Old v2 ratification sidecars without an
  `authority_custody_attestation` sibling continue to parse exactly
  as before through the Run 167 + Run 184 + Run 190 combined
  loader, return `AuthorityCustodyLoadStatus::Absent`, and resolve
  to `NoCustodyAttestationSupplied` under `Disabled` — a typed
  bypass deliberately distinct from `Accepted`.
* A malformed custody sibling fails closed at the typed payload
  boundary before any Run 188 validator work runs, and never
  affects the strict v2 parse or the Run 167 governance-proof /
  Run 184 OnChainGovernance sibling outcomes.
* Fixture / local-operator custody remains DevNet/TestNet
  evidence-only and is rejected by symbol whenever the trust-domain
  environment is MainNet (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`), inheriting the Run 188
  short-circuit through the Run 190 carrier.
* `RemoteSigner`, `Kms`, and `Hsm` custody classes still fail
  closed at the Run 188 typed validator with the typed
  `RemoteSignerUnavailable` / `KmsUnavailable` /
  `HsmUnavailable` outcomes regardless of attestation contents,
  schema version, sibling shape, or active policy.
* The Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal
  is preserved bit-identically. The peer-driven-drain routing
  helper layers a surface-level MainNet check ahead of the Run 188
  validator and returns `MainNetPeerDrivenApplyRefused` even when
  a custody attestation claims `Kms` or `Hsm`.

Honest limitation: Run 190 is **source / test only**. No real
KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend, no real
on-chain governance proof verifier, no governance execution
engine, no validator-set rotation, no autonomous apply, no
apply-on-receipt, and no peer-majority authority is added.
**Release-binary custody-metadata evidence is deferred to Run 191.
Full C4 is NOT claimed by Run 190; C5 remains OPEN.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_190.md` and
`crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`
for the full A1–A10 / R1–R32 acceptance matrix and the canonical
PASS verdict.

## Run 191 update — release-binary authority-custody metadata carrying evidence

Run 191 closes the Run 190-deferred release-binary boundary for the
typed authority-custody payload-carrying surface in
`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`,
composed over the Run 188 typed authority-custody boundary in
`pqc_authority_custody.rs`. Run 191 is release-binary evidence only:
no production source line is changed, no new CLI flag / env var /
schema bump / wire shape / sidecar field / metric / exit code is
introduced beyond Run 190's additive optional custody sibling. Run
190 added no operator-visible selector, so the operator-facing CLI
surface from Run 189 is preserved bit-identically — `target/release/
qbind-node --help` surfaces no `authority-custody` / `kms-hsm` /
`remote-signer` / `production custody` token; the default
`--print-genesis-hash --env {devnet,testnet,mainnet}` invocations
emit no Run 190 enablement banner and no `MainNet peer-driven apply
ENABLED` claim; and the existing Run 187 hidden
`--p2p-trust-bundle-onchain-governance-fixture-allowed` selector
(and the matching
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` env var),
armed on MainNet, still refuses MainNet peer-driven apply.

Through the release-built helper
`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`,
Run 191 exercises the Run 190 A1–A10 / R1–R32 corpus end-to-end in
**release mode** through the production library symbols
`pqc_authority_custody_payload_carrying::*` (every wire type, the
optional-sibling parser, the typed `AuthorityCustodyLoadStatus` /
`AuthorityCustodyCallsiteContext` /
`AuthorityCustodyPayloadCarryingDecisionOutcome`, the seven
per-surface routing helpers, and
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`)
composed with the Run 188 typed-boundary symbols
`pqc_authority_custody::*`. Every `RemoteSigner` / `Kms` / `Hsm`
attestation — whether in-process or wire-carried and parsed back —
fails closed with the typed `RemoteSignerUnavailable` /
`KmsUnavailable` / `HsmUnavailable` outcome regardless of policy or
environment; every `ProductionCustodyRequired` /
`MainnetProductionCustodyRequired` policy fails closed with the typed
`ProductionCustodyUnavailable` / `MainNetProductionCustodyUnavailable`;
every fixture / local-operator class on MainNet routes to
`FixtureCustodyRejectedForMainNet` / `LocalCustodyRejectedForMainNet`
ahead of the policy gate even when wire-carried; legacy / no-custody
payloads (sibling absent) under default `Disabled` route through the
seven Run 190 routing helpers without producing schema or wire drift;
malformed sibling JSON is parsed to
`AuthorityCustodyLoadStatus::Malformed { … }` and routed by every
per-surface helper to `Callsite { custody_outcome:
CustodyAttestationMalformed }` (or to peer-driven-drain
`MainNetPeerDrivenApplyRefused` where applicable) without drift. The
Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal is
preserved bit-identically at the binary surface AND at the typed Run
190 payload-carrying boundary via
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`
(which composes
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`).

Honest limitation: Run 191 wires no real KMS / HSM / cloud KMS /
PKCS#11 / remote-signer backend, no real on-chain governance proof
verifier, no governance execution engine, no validator-set rotation,
no autonomous apply, no apply-on-receipt, and no peer-majority
authority. Existing no-custody payloads remain compatible under
default `Disabled`; existing Run 184 / 185 / 187 governance fixture
proof paths remain compatible alongside the Run 190 optional custody
sibling. **Full C4 remains OPEN; C5 remains OPEN.**

See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_191.md`,
`scripts/devnet/run_191_authority_custody_payload_release_binary.sh`,
`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`,
and `docs/devnet/run_191_authority_custody_payload_release_binary/`
for the full release-binary scenario matrix, the regression test
slice, and the canonical PASS verdict.

## Run 192 — source/test hidden authority-custody policy selector and production preflight integration

Run 192 adds, at source/test level only, the smallest hidden selector
surface that lets a DevNet/TestNet evidence preflight context
explicitly choose an `AuthorityCustodyPolicy` variant and threads the
resolved policy into the seven Run 190 production v2 marker-decision
preflight contexts (reload-check, reload-apply, startup
`--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live
inbound `0x05`, peer-driven drain). The default
`AuthorityCustodyPolicy::Disabled` is preserved bit-for-bit; legacy
no-custody payloads remain accepted exactly as in Run 190 / Run 191.

The new module
`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`
exposes the env-var name
`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`, the canonical
selector tags (`disabled` / `fixture-only` / `devnet-local-allowed` /
`testnet-local-allowed` / `production-custody-required` /
`mainnet-production-custody-required`), the typed
`AuthorityCustodyPolicySelectorParseError`, the pure parsers
`authority_custody_policy_from_selector` /
`authority_custody_policy_env_selector` /
`authority_custody_policy_from_cli_or_env`, and seven thin
per-surface preflight wrappers
(`preflight_v2_marker_authority_custody_for_*`) that bind the
resolved policy into the Run 190 `AuthorityCustodyCallsiteContext`
and dispatch to the matching Run 190
`route_loaded_authority_custody_attestation_to_*_callsite_decision`
helper. The matching hidden CLI flag
`--p2p-trust-bundle-authority-custody-policy <POLICY>` (clap
`hide = true`) is added on `crates/qbind-node/src/cli.rs` as
`Option<String>`. Either source is sufficient to choose a non-default
policy; CLI wins when both are present; both absent preserves
`Disabled`; invalid values are surfaced as a typed parse error and
never silently downgrade to `Disabled`.

Run 192 is **source/test only**. No real KMS / HSM / cloud-KMS /
PKCS#11 / remote-signer backend is implemented. KMS / HSM /
RemoteSigner placeholders remain fail-closed via the Run 188
validator regardless of selector. Fixture / local custody remains
DevNet/TestNet evidence-only and cannot satisfy MainNet production
custody. The Run 147 / 148 / 152 FATAL MainNet peer-driven apply
refusal at the peer-driven apply surface remains intact regardless
of selector, attestation contents, or policy — including with
`mainnet-production-custody-required` and metadata claiming
KMS/HSM/RemoteSigner. Governance execution remains unimplemented.
Real on-chain proof verification remains unimplemented. Validator-set
rotation remains open. Release-binary custody-policy selector
evidence is deferred to **Run 193**. Full C4 remains OPEN. C5
remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_192.md`,
`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`, and
`crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs`
for the full A1–A10 / R1–R29 source/test scenario matrix and the
canonical PASS verdict.

## Run 193 — release-binary authority-custody policy selector evidence

Run 193 closes the Run 192-deferred release-binary boundary for the
hidden authority-custody policy selector. The trust-anchor authority
model is unchanged: the typed `AuthorityCustodyPolicy` lattice from
Run 188 (`Disabled` / `FixtureOnly` / `DevnetLocalAllowed` /
`TestnetLocalAllowed` / `ProductionCustodyRequired` /
`MainnetProductionCustodyRequired`), the typed `AuthorityCustodyClass`
lattice (`FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` /
`Kms` / `Hsm` / `Unknown`), the typed authority-custody validator
(`validate_authority_custody_attestation`), the typed combined
helper (`validate_lifecycle_governance_and_custody`), and the three
named refusal helpers
(`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
`peer_majority_cannot_satisfy_custody`,
`local_operator_config_alone_cannot_satisfy_mainnet_production_custody`)
all remain canonical. The Run 190 typed payload-carrying layer
(`AuthorityCustodyAttestationWire`, `AuthorityCustodyLoadStatus`,
`AuthorityCustodyCallsiteContext`,
`AuthorityCustodyPayloadCarryingDecisionOutcome`, the seven per-
surface routing helpers, the optional sibling JSON parser, and
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`)
remains canonical. The Run 192 hidden selector
(`pqc_authority_custody_policy_surface::*` — the env const, the
typed `AuthorityCustodyPolicySelectorParseError`, the three parsers
with CLI-over-env precedence, and the seven
`preflight_v2_marker_authority_custody_for_*` per-surface preflight
wrappers) remains canonical and is now exercised in **release mode**.

Run 193's authority-model contribution is therefore narrow: real
`target/release/qbind-node` is shown to preserve every Run 192
selector / Run 190 payload-carrying / Run 188 boundary invariant
end-to-end (default `Disabled` preserved when neither CLI nor env
selector is set; hidden CLI flag absent from `--help`; env-only and
CLI-only selectors each activate the typed policy without banner
drift; CLI-over-env precedence deterministic at the binary surface;
invalid selector values fail-closed at the typed parser). Fixture /
local-operator custody continues to be DevNet/TestNet evidence-only
and explicitly cannot satisfy MainNet production custody. KMS / HSM
/ RemoteSigner placeholders continue to fail-closed at the typed
validator under every policy regardless of environment. MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal even
with `mainnet-production-custody-required` armed at both env and CLI
together with the Run 187 hidden fixture selector and metadata
claiming KMS/HSM, both at the binary surface (S7, S8) and at the
typed boundary via
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`.

Run 193 introduces no production source change, no CLI / env /
sidecar / authority-marker / sequence-file / trust-bundle core /
wire / metric / schema change, no real KMS / HSM / cloud-KMS /
PKCS#11 / remote-signer backend, no real on-chain governance proof
verifier, no governance execution, no validator-set rotation, no
MainNet peer-driven apply enablement, no autonomous apply, no
apply-on-receipt, no peer-majority authority, and no weakening of
Runs 070, 130–192. Static production source-code anchors remain
rejected. Local config alone remains insufficient for MainNet bundle-
signing authority. Local peer majority remains insufficient for
MainNet bundle-signing authority. Full C4 remains OPEN. C5 remains
OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_193.md`,
`docs/devnet/run_193_authority_custody_policy_release_binary/`,
`scripts/devnet/run_193_authority_custody_policy_release_binary.sh`,
and `crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs`.

## Run 194 — source/test RemoteSigner production-custody interface boundary

Run 194 is **source/test RemoteSigner production-custody interface
boundary** work. It replaces the vague Run 188
`AuthorityCustodyClass::RemoteSigner` placeholder — until now failed
closed as `RemoteSignerUnavailable` — with a precise, typed
remote-signer custody boundary that a later run can implement safely.
The new module `crates/qbind-node/src/pqc_remote_authority_signer.rs`
defines a `RemoteSignerIdentity`, a domain-bound `RemoteSignerRequest`
/ `RemoteSignerResponse` pair (deterministic domain-separated SHA3-256
`canonical_digest` binding environment / chain / genesis / authority
root / lifecycle action / candidate digest / authority-domain sequence
/ signing-key fingerprints / governance proof digest / custody
attestation digest / anti-replay nonces / timestamp), a
`RemoteSignerPolicy` (`Disabled` default / `FixtureLoopbackAllowed` /
`ProductionRemoteSignerRequired` /
`MainnetProductionRemoteSignerRequired`), a precise
`RemoteSignerOutcome` reject taxonomy, a pure `RemoteAuthoritySigner`
trait, a DevNet/TestNet-only `FixtureLoopbackRemoteSigner`, a
fail-closed `ProductionRemoteSigner`, the pure `validate_remote_signer`
verifier, the `validate_remote_signer_for_custody_class` router that
dispatches `AuthorityCustodyClass::RemoteSigner` into the boundary, and
the pure `validate_lifecycle_governance_custody_and_remote_signer`
composition helper layered over the Run 188 custody validator.

In the trust-anchor authority model, the remote signer is a
custody-held bundle-signing authority: it is never satisfiable by a
local operator key (`LocalOperatorKeyCannotSatisfyRemoteSigner`) or by
a peer majority / gossip count
(`peer_majority_cannot_satisfy_remote_signer`). The default policy is
`RemoteSignerPolicy::Disabled` and fails every request closed. The
fixture loopback remote signer is DevNet/TestNet source/test only and
is rejected on a MainNet trust domain
(`FixtureLoopbackRejectedForMainNet`). Production RemoteSigner remains
unavailable / fail-closed. RemoteSigner does not enable MainNet
peer-driven apply: the Run 147 / 148 / 152 FATAL refusal remains intact
even when a fixture loopback remote signer signs successfully, via
`mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`.

Run 194 introduces no production source change, no CLI / env / sidecar
/ authority-marker / sequence-file / trust-bundle core / wire / metric
/ schema change. No real RemoteSigner backend is implemented; no
networked signer service; KMS / HSM remain unimplemented; no real
on-chain governance proof verifier; no governance execution; no
validator-set rotation; no MainNet peer-driven apply enablement; no
autonomous apply; no apply-on-receipt; no peer-majority authority; no
cloud-KMS / PKCS#11 integration; and no weakening of Runs 070,
130–193. Static production source-code anchors remain rejected. Local
config alone remains insufficient for MainNet bundle-signing
authority. Local peer majority remains insufficient for MainNet
bundle-signing authority. Release-binary RemoteSigner boundary
evidence is deferred to **Run 195**. Full C4 remains OPEN. C5 remains
OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_194.md`,
`crates/qbind-node/src/pqc_remote_authority_signer.rs`, and
`crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs`.

## Run 195 — release-binary RemoteSigner production-custody boundary evidence

Run 195 is **release-binary evidence** for the Run 194 RemoteSigner
production-custody interface boundary. It exercises the Run 194 typed
RemoteSigner surface on real `target/release/qbind-node` and through the
release-built helper
`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`,
which drives the Run 194 A1–A7 / R1–R31 corpus end-to-end in **release
mode** through the production library symbols
`pqc_remote_authority_signer::*` (`RemoteSignerPolicy`,
`RemoteSignerIdentity`, `RemoteSignerRequest` with deterministic
domain-separated SHA3-256 `canonical_digest`, `RemoteSignerResponse`,
`RemoteSignerExpectations`, the pure `RemoteAuthoritySigner` trait, the
DevNet/TestNet-only `FixtureLoopbackRemoteSigner`, the fail-closed
`ProductionRemoteSigner`, `validate_remote_signer`,
`validate_remote_signer_for_custody_class`,
`validate_lifecycle_governance_custody_and_remote_signer`, and the named
refusal helpers) layered above the Run 192 / 190 / 188 custody surfaces.

Relative to the trust-anchor authority model, Run 195 changes nothing: it
adds no production source change, no CLI / env / sidecar /
authority-marker / sequence-file / trust-bundle core / wire / metric /
schema change; the helper only **reads** the typed surface. The
RemoteSigner request/response binding is deterministic and domain-bound
(environment, chain, genesis, authority root, lifecycle action, candidate
digest, authority-domain sequence). Fixture loopback RemoteSigner remains
DevNet/TestNet evidence-only; production RemoteSigner remains
unavailable / fail-closed; local config alone and a local peer majority
remain insufficient to satisfy a remote signer policy or MainNet
bundle-signing authority. Static production source-code anchors remain
rejected. MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
refusal even with the Run 193 `mainnet-production-custody-required`
selector and the governance fixture selector armed.

No real RemoteSigner backend is implemented; no networked signer service;
KMS / HSM remain unimplemented; no real on-chain governance proof
verifier; no governance execution; no validator-set rotation; no MainNet
peer-driven apply enablement; no autonomous apply; no apply-on-receipt;
no peer-majority authority; no cloud-KMS / PKCS#11 integration; and no
weakening of Runs 070, 130–194. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_195.md`,
`docs/devnet/run_195_remote_authority_signer_boundary_release_binary/`,
`scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh`,
and
`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`.

## Run 196 — source/test RemoteSigner attestation payload/carrying and production-context wiring

Run 196 is **source/test RemoteSigner attestation payload/carrying and
production-context wiring**. It adds source- and test-level support for
carrying RemoteSigner identity / request / response attestation material
through the production payload and production-context paths and routing it
into the Run 194 lifecycle + governance + custody + RemoteSigner
composition, via `crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`
and `crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`.
The carrier is an **additive optional** JSON sibling
(`remote_signer_attestation`) on the v2 ratification sidecar — with wire
types (`RemoteSignerIdentityWire` / `RemoteSignerRequestWire` /
`RemoteSignerResponseWire` / `RemoteSignerAttestationWire`) that convert
to/from the Run 194 internal types and fail closed on any unsupported
schema version — mirroring the Run 190 authority-custody payload/carrying
pattern. Reproduce with
`cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests`.

Relative to the trust-anchor authority model, Run 196 changes nothing
operationally: it adds no production call-site mutation, no new CLI flag,
no new env var, no authority-marker / sequence-file / trust-bundle core /
wire / metric / schema change. Legacy no-RemoteSigner payloads remain
byte-compatible and parse as `Absent`; malformed / invalid /
unsupported-schema material fails closed in front of the verifier.
Fixture loopback RemoteSigner remains DevNet/TestNet source/test only;
production RemoteSigner remains unavailable / fail-closed; local config
alone and a local peer majority remain insufficient to satisfy a remote
signer policy or MainNet bundle-signing authority. Static production
source-code anchors remain rejected. MainNet peer-driven apply remains the
Run 147 / 148 / 152 FATAL refusal even with fixture loopback RemoteSigner
material supplied through the seven per-surface production-context helpers.

No real RemoteSigner backend is implemented; no networked signer service;
KMS / HSM remain unimplemented; no real on-chain governance proof
verifier; no governance execution; no validator-set rotation; no MainNet
peer-driven apply enablement; no autonomous apply; no apply-on-receipt; no
peer-majority authority; and no weakening of Runs 070, 130–195.
Release-binary RemoteSigner payload/carrying evidence is deferred to
**Run 197**. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_196.md`,
`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`, and
`crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`.

## Run 197 — release-binary RemoteSigner attestation payload/carrying and production-context evidence

Run 197 is **release-binary evidence** for the Run 196 RemoteSigner
attestation payload/carrying and production-context wiring. It exercises
the Run 196 module `crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`
against real `target/release/qbind-node` and through the release-built
helper
`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`,
driven by the harness
`scripts/devnet/run_197_remote_signer_payload_release_binary.sh`. Reproduce
with `bash scripts/devnet/run_197_remote_signer_payload_release_binary.sh`.

Relative to the trust-anchor authority model, Run 197 changes nothing
operationally: it makes no production source change (release example helper
+ release harness + docs only), no production call-site mutation, no new
CLI flag, no new env var, and no authority-marker / sequence-file /
trust-bundle core / wire / metric / schema change beyond Run 196's additive
optional `remote_signer_attestation` sibling. Legacy no-RemoteSigner
payloads remain byte-compatible and parse as `Absent`; malformed / invalid
/ unsupported-schema material fails closed in front of the verifier. The
release-built helper drives the Run 196 A1–A10 / R1–R34 corpus in release
mode and ends in `verdict: PASS`. Fixture loopback RemoteSigner remains
DevNet/TestNet evidence-only; production RemoteSigner remains unavailable /
fail-closed; local config alone and a local peer majority remain
insufficient to satisfy a remote signer policy or MainNet bundle-signing
authority. Static production source-code anchors remain rejected. MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal even with
fixture loopback RemoteSigner material supplied and with the Run 193
`mainnet-production-custody-required` selector armed.

No real RemoteSigner backend is implemented; no networked signer service;
KMS / HSM remain unimplemented; no real on-chain governance proof verifier;
no governance execution; no validator-set rotation; no MainNet peer-driven
apply enablement; no autonomous apply; no apply-on-receipt; no
peer-majority authority; existing custody / governance proof paths remain
compatible; and no weakening of Runs 070, 130–196. Full C4 remains OPEN.
C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_197.md`,
`docs/devnet/run_197_remote_signer_payload_release_binary/`,
`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`,
and `scripts/devnet/run_197_remote_signer_payload_release_binary.sh`.
## Run 198 — source/test hidden RemoteSigner policy selector and production preflight integration

Run 198 is **source/test hidden RemoteSigner policy selector and
production preflight integration**. It adds a hidden,
disabled-by-default RemoteSigner policy selector (hidden clap flag
`--p2p-trust-bundle-remote-signer-policy` plus the
`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` env var) in
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs`, resolving to
a `RemoteSignerPolicy` and binding it into all seven production v2
marker-decision preflight contexts through the Run 196 RemoteSigner
payload/call-site routing layer. Tests:
`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.
Reproduce with
`cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`.

Relative to the trust-anchor authority model, Run 198 changes nothing in
the authority model: the only production-source surface addition is one
additive hidden CLI flag (`hide = true`) plus one env var, both
disabled by default, with no authority-marker / sequence-file /
trust-bundle core / wire / metric / schema change. The default resolved
policy is `RemoteSignerPolicy::Disabled`; legacy no-RemoteSigner payloads
remain compatible. The selector parsers fail closed on invalid values
with a typed `RemoteSignerPolicySelectorParseError` (never a silent
downgrade to `Disabled`), and CLI takes precedence over env.

Fixture loopback RemoteSigner remains DevNet/TestNet evidence-only and
cannot satisfy MainNet production RemoteSigner; production RemoteSigner
remains unavailable / fail-closed; a local operator key and a local peer
majority remain insufficient to satisfy a RemoteSigner policy or MainNet
bundle-signing authority. Static production source-code anchors remain
rejected. MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
refusal even with `mainnet-production-remote-signer-required` and fixture
loopback material.

No real RemoteSigner backend is implemented; no networked signer service;
KMS / HSM / cloud-KMS / PKCS#11 remain unimplemented; no real on-chain
governance proof verifier; no governance execution; no validator-set
rotation; no MainNet peer-driven apply enablement; no autonomous apply;
no apply-on-receipt; no peer-majority authority; existing custody /
governance proof paths remain compatible; and no weakening of
Runs 070, 130–197. Release-binary RemoteSigner-policy selector evidence
is deferred to **Run 199**. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_198.md`,
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs`, and
`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.
## Run 199 — release-binary hidden RemoteSigner policy selector and production preflight routing evidence

Run 199 is **release-binary evidence** for the Run 198 hidden
RemoteSigner policy selector and production preflight routing. It
exercises the Run 198 module
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs` against real
`target/release/qbind-node` and through the release-built helper
`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`,
driven by the harness
`scripts/devnet/run_199_remote_signer_policy_release_binary.sh`. Reproduce
with `bash scripts/devnet/run_199_remote_signer_policy_release_binary.sh`.

Relative to the trust-anchor authority model, Run 199 changes nothing: it
makes no production source change (release example helper + release
harness + docs only) and adds no authority-marker / sequence-file /
trust-bundle core / wire / metric / schema change beyond the Run 198
hidden selector. The real binary accepts the hidden
`--p2p-trust-bundle-remote-signer-policy` flag and the
`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` env var while keeping the
flag hidden from `--help`; default resolution remains
`RemoteSignerPolicy::Disabled`. The release-built helper resolves the
selector (default / CLI / env / CLI-over-env precedence / invalid
fail-closed with a typed `RemoteSignerPolicySelectorParseError`) and
routes the resolved policy through the seven
`preflight_v2_marker_remote_signer_for_*` wrappers, ending in
`verdict: PASS` (125/0 on this checkout).

Fixture loopback RemoteSigner remains DevNet/TestNet evidence-only and
cannot satisfy MainNet production RemoteSigner; production RemoteSigner
remains unavailable / fail-closed; a local operator key and a local peer
majority remain insufficient to satisfy a RemoteSigner policy or MainNet
bundle-signing authority. MainNet peer-driven apply remains the Run 147 /
148 / 152 FATAL refusal even with `mainnet-production-remote-signer-required`
and fixture loopback material.

No real RemoteSigner backend is implemented; no networked signer service;
KMS / HSM / cloud-KMS / PKCS#11 remain unimplemented; no real on-chain
governance proof verifier; no governance execution; no validator-set
rotation; no MainNet peer-driven apply enablement; no autonomous apply;
no apply-on-receipt; no peer-majority authority; existing custody /
governance proof paths remain compatible; and no weakening of
Runs 070, 130–198. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_199.md`,
`docs/devnet/run_199_remote_signer_policy_release_binary/`,
`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`,
and `scripts/devnet/run_199_remote_signer_policy_release_binary.sh`.
## Run 200 — authority lifecycle C4/C5 consolidation, closure criteria, and remaining-work specification

Run 200 is a **docs/spec/crosscheck-only** consolidation pass over
Runs 130–199. It introduces the consolidation report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`, the formal closure
checklist `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and the static
run index `docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`.

Relative to the trust-anchor authority model, Run 200 changes nothing: it
makes no production source change and adds no authority-marker /
sequence-file / trust-bundle core / wire / metric / schema change. It
consolidates the authority-lifecycle evidence (typed v2 marker, lifecycle
transition validation, governance authority / proof carrier / Required
policy, OnChainGovernance fixture verifier and production boundary,
custody boundary, and RemoteSigner boundary) and records exactly which
production pieces remain unavailable.

Full C4 remains OPEN because the real production custody backend
(RemoteSigner / KMS / HSM), the real custody attestation verifier, the
real on-chain governance proof verifier, the governance execution engine,
validator-set rotation, the MainNet governance policy artifacts, the
satisfiable MainNet production custody policy, a production-real emergency
governance / recovery ceremony, and end-to-end MainNet authority
rotation/revocation under production custody are all unavailable or
unproven. C5 remains OPEN because production key custody, the production
CA/root/authority rotation ceremony, hardware/remote signing attestation,
the operational signing audit trail, validator-set rotation /
cryptographic reconfiguration, the long-term crypto-agility activation
policy, the production incident-response / key-compromise procedure, and
full MainNet release-binary evidence under production custody are all
incomplete.

Fixture / local / loopback custody, governance, and RemoteSigner material
remains DevNet/TestNet evidence-only and cannot satisfy MainNet
production authority; production material fails closed. A local operator
key and a local peer majority remain insufficient to satisfy a custody /
RemoteSigner policy or MainNet bundle-signing authority. MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal. The
C4/C5 closure criteria and MainNet readiness gates are now specified in
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`.

No real RemoteSigner backend is implemented; no networked signer service;
KMS / HSM / cloud-KMS / PKCS#11 remain unimplemented; no real on-chain
governance proof verifier; no governance execution; no validator-set
rotation; no MainNet peer-driven apply enablement; no autonomous apply;
no apply-on-receipt; no peer-majority authority; existing custody /
governance proof paths remain compatible; and no weakening of
Runs 070, 130–199. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`,
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and
`docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`.

## Run 201 — source/test production RemoteSigner transport boundary

Run 201 adds, in **source/test only**, the typed transport boundary that
the Run 194–199 RemoteSigner authority model lacked: a network/service
protocol boundary between the trust-anchor authority lifecycle and a
future remote signer backend. The new module
`crates/qbind-node/src/pqc_remote_signer_transport.rs` wraps the Run 194
`RemoteSignerRequest` / `RemoteSignerResponse` in request/response
envelopes bound to the authority trust domain (environment, chain id,
genesis hash, authority-root fingerprint, signer id, custody key id,
bundle signing-key fingerprint, signature suite) with deterministic
domain-separated transcript digests, a pure/mockable
`RemoteSignerTransport` trait, a DevNet/TestNet-only fixture loopback
transport, a fail-closed production transport, and a typed outcome
taxonomy. The verifier `validate_remote_signer_transport` composes the
Run 194 `validate_remote_signer` over the wrapped request/response and
then binds the transport transcript, and
`validate_lifecycle_custody_remote_signer_and_transport` layers the
transport over the Run 194 governance/custody/RemoteSigner composition.

Authority-model invariants (unchanged):

* Run 201 grants **no new authority**. It implements no real RemoteSigner
  backend, no networked signer daemon, and no production signing custody;
  the fixture loopback transport is DevNet/TestNet evidence only and the
  production transport is unavailable/fail-closed. KMS / HSM / cloud-KMS /
  PKCS#11, governance execution, and real on-chain proof verification
  remain unimplemented; validator-set rotation remains open.
* The transport boundary confers **no autonomous apply**, no
  apply-on-receipt, and no peer-majority authority; local-operator and
  peer-majority paths that cannot satisfy the transport return typed
  cannot-satisfy outcomes rather than mutating trust.
* MainNet peer-driven apply remains **refused**: a MainNet
  peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a fixture loopback transport
  configured. No Run 070 ordering, marker, sequence, or live-trust swap is
  performed by the new module.
* Release-binary transport-boundary evidence is deferred to **Run 202**.
  **Full C4 remains OPEN; C5 remains OPEN.**
## Run 202 — release-binary RemoteSigner transport boundary evidence

Run 202 proves, in **release-binary evidence only**, that the Run 201
typed RemoteSigner transport boundary preserves the trust-anchor authority
model on the real `target/release/qbind-node` plus a release-built helper.
It grants no new authority and makes **no production-source change** (a
release example helper, a release harness, and documentation only). The
release helper
`crates/qbind-node/examples/run_202_remote_signer_transport_release_binary_helper.rs`
links the production library symbols
(`pqc_remote_signer_transport::*` over the Run 194
`pqc_remote_authority_signer::*`) and exercises the Run 201 transport
corpus (accepted / rejection / separation / composition / determinism /
refusal_helpers) in release mode; the harness
`scripts/devnet/run_202_remote_signer_transport_release_binary.sh`, the
archive `docs/devnet/run_202_remote_signer_transport_release_binary/`, and
the report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_202.md` capture the
evidence.

Authority-model invariants (unchanged):

* Run 202 grants **no new authority**. It implements no real RemoteSigner
  backend, no networked signer daemon, and no production signing custody;
  the release-built helper confirms in release mode that the fixture
  loopback transport is DevNet/TestNet evidence only and refused on
  MainNet, while the production transport is unavailable/fail-closed
  (`ProductionTransportUnavailable` /
  `MainNetProductionTransportUnavailable`). KMS / HSM / cloud-KMS /
  PKCS#11, governance execution, and real on-chain proof verification
  remain unimplemented; validator-set rotation remains open.
* The transport boundary confers **no autonomous apply**, no
  apply-on-receipt, and no peer-majority authority at the release binary;
  the release helper confirms the transport request binds the full
  authority tuple and that composition with the Run 194
  `validate_remote_signer` and the custody/RemoteSigner path returns typed
  outcomes rather than mutating trust, with rejected cases leaving inputs
  byte-identical.
* MainNet peer-driven apply remains **refused**: a MainNet
  peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a fixture loopback transport
  response. The real `target/release/qbind-node` keeps every Run 070 /
  130–201 surface RemoteSigner-transport-silent (no transport /
  networked-signer / KMS / HSM / governance-execution / validator-rotation
  banner), with the Run 198 RemoteSigner policy selector, Run 193 custody
  selector, and governance fixture flag all remaining compatible. No Run
  070 ordering, marker, sequence, or live-trust swap is performed by the
  helper.
* **Full C4 remains OPEN; C5 remains OPEN.**

## Run 203 — source/test KMS/HSM backend abstraction boundary

Run 203 adds the typed, provider-neutral KMS/HSM backend abstraction
(`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`) over the Run
188 `AuthorityCustodyClass::{Kms, Hsm}` custody classes, framing how a
future production KMS/HSM signer would bind to the trust-anchor authority
model without granting any new authority. It is **source/test only**; the
only production-source change is the additive new module plus its
`lib.rs` registration, with tests
`crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs` and
the report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_203.md`.

Authority-model invariants (unchanged):

* Run 203 grants **no new authority**. It implements no real KMS backend,
  no real HSM backend, no cloud-KMS integration, and no PKCS#11
  integration; the fixture KMS/HSM backends are DevNet/TestNet source/test
  only and refused on MainNet, while the production / cloud / PKCS#11
  backends are callable but fail closed (`ProductionKmsUnavailable` /
  `ProductionHsmUnavailable` / `CloudKmsUnavailable` /
  `Pkcs11HsmUnavailable`).
* A backend response binds the **full authority tuple** (environment /
  chain / genesis / authority-root / lifecycle-action / candidate-digest /
  authority-domain-sequence / custody-class / key-id / signing-key
  fingerprints) plus deterministic request/response/transcript digests,
  anti-replay nonces, suite, attestation/signature placeholders, and
  freshness windows; the verifier returns a typed `BackendOutcome` rather
  than mutating trust, and rejected cases leave inputs byte-identical.
* The **RemoteSigner authority path (Runs 194–202) remains separate and
  unchanged**: the KMS/HSM router refuses a `RemoteSigner` custody class
  as `NotKmsHsmCustodyClass`, and local-operator / peer-majority material
  cannot satisfy a backend policy. The backend boundary confers **no
  autonomous apply**, no apply-on-receipt, and no peer-majority authority.
* MainNet peer-driven apply remains **refused**: a MainNet
  peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a valid fixture KMS/HSM
  response. No Run 070 ordering, marker, sequence, or live-trust swap is
  performed by the module. Governance execution, real on-chain proof
  verification, and validator-set rotation remain unimplemented/open;
  release-binary evidence is deferred to **Run 204**.
* **Full C4 remains OPEN; C5 remains OPEN.**

## Run 204 — release-binary KMS/HSM backend abstraction boundary evidence

Run 204 closes the Run 203-deferred release-binary boundary for the
production KMS/HSM custody backend abstraction
(`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`) over the Run 188
custody classes, capturing release-binary evidence that the framing grants
no new authority. It is **release-binary evidence only**, adding the release
helper
`crates/qbind-node/examples/run_204_kms_hsm_backend_release_binary_helper.rs`,
the release harness
`scripts/devnet/run_204_kms_hsm_backend_release_binary.sh`, the evidence
archive `docs/devnet/run_204_kms_hsm_backend_release_binary/`, and the
report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_204.md`. It makes **no
production-source change** (helper + harness + docs only).

Authority-model invariants (unchanged):

* Run 204 grants **no new authority**. It implements no real KMS backend,
  no real HSM backend, no cloud-KMS integration, and no PKCS#11
  integration; the fixture KMS/HSM backends remain DevNet/TestNet
  evidence-only and refused on MainNet, while the production / cloud /
  PKCS#11 backends fail closed as unavailable.
* The real `target/release/qbind-node` emits **no KMS / HSM / cloud-KMS /
  PKCS#11 / RemoteSigner backend enablement** banner and **no MainNet
  peer-driven apply enablement** on every captured surface, and the
  release-built helper confirms in release mode (through the production
  library symbols) that a backend response binds the **full authority
  tuple** plus deterministic request/response/transcript digests,
  anti-replay nonces, suite, attestation/signature placeholders, and
  freshness windows; the verifier returns a typed `BackendOutcome` rather
  than mutating trust, and rejected cases leave inputs byte-identical.
* The **RemoteSigner authority path (Runs 194–202) remains separate and
  unchanged**: the KMS/HSM router refuses a `RemoteSigner` custody class as
  `NotKmsHsmCustodyClass`, and local-operator / peer-majority material
  cannot satisfy a backend policy. The backend boundary confers **no
  autonomous apply**, no apply-on-receipt, and no peer-majority authority.
* MainNet peer-driven apply remains **refused**: the release helper
  confirms a MainNet peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a valid fixture KMS/HSM
  response. No Run 070 ordering, marker, sequence, or live-trust swap is
  performed. Governance execution, real on-chain proof verification, and
  validator-set rotation remain unimplemented/open.
* **Full C4 remains OPEN; C5 remains OPEN.**
## Run 205 — source/test production custody attestation verifier skeleton

Run 205 adds a typed, mockable verifier skeleton for a production custody
attestation chain
(`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`) layered over
the Run 188 custody classes, establishing that the attestation framing
grants no new authority. It is **source/test only**, adding the new module
(plus its `lib.rs` registration), the tests
`crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs`,
and the report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_205.md`.

Authority-model invariants (unchanged):

* Run 205 grants **no new authority**. It implements no real cloud-KMS
  attestation verifier, no real PKCS#11 attestation verifier, no real HSM
  vendor attestation verifier, and no real RemoteSigner attestation
  verifier; the fixture attestation remains DevNet/TestNet evidence-only
  and refused on MainNet, while the production / cloud / PKCS#11 /
  HSM-vendor / RemoteSigner attestation verifiers fail closed as the
  matching typed unavailable outcome.
* The `verify_custody_attestation` verifier binds the **full authority
  tuple** (environment, chain id, genesis hash, authority-root and
  bundle-signing-key fingerprints, the Run 188 custody class, the backend
  / provider / signer id, the custody key id, the suite id, the lifecycle
  action, the candidate digest, the authority-domain sequence, and the
  optional governance / request / response / transcript digests) plus the
  attestation commitment, anti-replay nonce, replay window, and
  freshness/expiry window over deterministic domain-separated digests; it
  returns a typed `CustodyAttestationOutcome` rather than mutating trust,
  and rejected cases leave inputs byte-identical.
* The **RemoteSigner authority path (Runs 194–202)** and the **KMS/HSM
  backend authority path (Runs 203–204)** remain separate and unchanged:
  the attestation verifier refuses a production / RemoteSigner / unknown
  attestation class as the matching typed unavailable/unknown outcome,
  and local-operator / peer-majority material cannot satisfy a production
  attestation policy. The attestation boundary confers **no autonomous
  apply**, no apply-on-receipt, and no peer-majority authority.
* MainNet peer-driven apply remains **refused**: the composition helpers
  short-circuit a MainNet peer-driven-apply preflight to
  `MainNetPeerDrivenApplyRefused` even with a valid fixture attestation,
  and the fixture attestation is itself refused on a MainNet trust
  domain. No Run 070 ordering, marker, sequence, or live-trust swap is
  performed. Governance execution, real on-chain proof verification, and
  validator-set rotation remain unimplemented/open. Release-binary
  custody-attestation verifier-boundary evidence is deferred to **Run
  206**.
* **Full C4 remains OPEN; C5 remains OPEN.**

## Run 206 — release-binary custody attestation verifier boundary evidence

Run 206 closes the Run 205-deferred release-binary boundary for the
production custody attestation verifier skeleton
(`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`) layered over
the Run 188 custody classes, the Run 203 KMS/HSM backend boundary, and the
Run 201 RemoteSigner transport boundary, establishing on release binaries
that the attestation framing grants no new authority. It is
**release-binary evidence only**, adding a release example helper
`crates/qbind-node/examples/run_206_custody_attestation_release_binary_helper.rs`,
a release harness
`scripts/devnet/run_206_custody_attestation_release_binary.sh`, the
evidence archive `docs/devnet/run_206_custody_attestation_release_binary/`,
and the report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_206.md`. It makes
**no production-source change** (helper + harness + docs only).

Authority-model invariants (unchanged):

* Run 206 grants **no new authority**. Real `target/release/qbind-node` is
  observed to emit no custody attestation / KMS / HSM / cloud-KMS /
  PKCS#11 attestation enablement and no MainNet peer-driven apply
  enablement on every captured surface (S1–S8), even with the custody and
  RemoteSigner selectors armed on `--env mainnet`.
* It implements no real cloud-KMS attestation verifier, no real PKCS#11
  attestation verifier, no real HSM vendor attestation verifier, no real
  RemoteSigner backend, and no real KMS/HSM backend; the fixture
  attestation remains DevNet/TestNet evidence-only and refused on MainNet,
  while the production / cloud / PKCS#11 / HSM-vendor / RemoteSigner
  attestation verifiers fail closed as the matching typed unavailable
  outcome (release helper `total_pass 69, total_fail 0, verdict PASS`).
* The release-built helper confirms `verify_custody_attestation` binds the
  full authority tuple over deterministic domain-separated digests and
  returns a typed `CustodyAttestationOutcome` rather than mutating trust;
  rejected cases leave inputs byte-identical.
* The **RemoteSigner authority path (Runs 194–202)** and the **KMS/HSM
  backend authority path (Runs 203–204)** remain separate and unchanged;
  local-operator / peer-majority material cannot satisfy a production
  attestation policy. The attestation boundary confers **no autonomous
  apply**, no apply-on-receipt, and no peer-majority authority.
* MainNet peer-driven apply remains **refused**: the release helper proves
  the composition short-circuits a MainNet peer-driven-apply preflight to
  `MainNetPeerDrivenApplyRefused` even with a valid fixture attestation,
  and the fixture attestation is itself refused on a MainNet trust domain.
  No Run 070 ordering, marker, sequence, or live-trust swap is performed.
  Governance execution, real on-chain proof verification, and validator-set
  rotation remain unimplemented/open.
* **Full C4 remains OPEN; C5 remains OPEN.**
## Run 207 — source/test custody-attestation payload carrying and production preflight integration

Run 207 makes the Run 205 typed custody-attestation evidence/input
reachable from production call-site contexts
(`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs`,
`crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs`).

* Run 207 grants **no new authority**. It implements no real cloud-KMS /
  PKCS#11 / HSM-vendor attestation verifier and no real RemoteSigner
  backend; the default `CustodyAttestationPolicy::Disabled` is unchanged.
* The wire types (`CustodyAttestationClassWire`,
  `CustodyAttestationEvidenceWire`, `CustodyAttestationInputWire`,
  `CustodyAttestationPayloadWire`) convert into the Run 205 internal
  attestation types and **bind the full authority tuple** — environment,
  chain_id, genesis_hash, authority-root fingerprint, bundle-signing-key
  fingerprint, Run 188 custody class, backend / provider / signer id,
  custody key id / label, suite id, lifecycle action, candidate digest,
  authority-domain sequence, and the optional governance / request /
  response / transcript digests — through the Run 205
  `verify_custody_attestation` boundary. A mismatch on any bound field is
  rejected as the matching typed Run 205 outcome.
* The carried fixture attestation is **DevNet/TestNet evidence-only** and is
  refused on a MainNet trust domain; production / cloud-KMS / PKCS#11 / HSM
  / RemoteSigner attestation remains unavailable/fail-closed; neither a
  local operator nor a peer majority can satisfy a production attestation.
* The **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend path
  (Runs 203–204)** remain separate, unchanged backend-boundary options.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** even with a carried fixture attestation. Run 207 makes no
  authority-marker / sequence-file / trust-bundle core / schema change and
  does not weaken Runs 070, 130–206. Release-binary evidence is deferred to
  **Run 208**. **Full C4 remains OPEN; C5 remains OPEN.**

## Run 208 — release-binary custody-attestation payload carrying and production-context routing evidence

Run 208 is the release-binary evidence run for the Run 207 source/test
custody-attestation payload carrying and production-context wiring
(`crates/qbind-node/examples/run_208_custody_attestation_payload_release_binary_helper.rs`,
`scripts/devnet/run_208_custody_attestation_payload_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_208.md`). It makes no production source
change (helper + harness + docs only).

* Run 208 grants **no new authority**. It implements no real cloud-KMS /
  PKCS#11 / HSM-vendor attestation verifier, no real RemoteSigner backend, no
  real KMS/HSM backend, no governance execution, no real on-chain proof
  verifier, and no validator-set rotation; the default
  `CustodyAttestationPolicy::Disabled` is unchanged.
* The release-built helper confirms in release mode, through the production
  library symbols, that the wire types convert into the Run 205 internal
  attestation types and **bind the full authority tuple** — environment,
  chain_id, genesis_hash, authority-root fingerprint, bundle-signing-key
  fingerprint, Run 188 custody class, backend / provider / signer id, custody
  key id / label, suite id, lifecycle action, candidate digest,
  authority-domain sequence, and the optional governance / request / response
  / transcript digests — through the Run 205 `verify_custody_attestation`
  boundary, with a mismatch on any bound field rejected as the matching typed
  Run 205 outcome.
* The harness drives the **real `target/release/qbind-node`** and proves that
  no captured surface advertises any new custody-attestation-payload / KMS /
  HSM / cloud-KMS / PKCS#11 / RemoteSigner-backend authority or MainNet apply
  enablement — even with the custody and RemoteSigner selectors armed on
  `--env mainnet` (S1–S8).
* The carried fixture attestation is **DevNet/TestNet evidence-only** and is
  refused on a MainNet trust domain; production / cloud-KMS / PKCS#11 / HSM /
  RemoteSigner attestation remains unavailable/fail-closed; neither a local
  operator nor a peer majority can satisfy a production attestation in release
  mode.
* The **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend path
  (Runs 203–204)** remain separate, unchanged backend-boundary options.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with a carried fixture attestation. Run 208 makes no authority-marker /
  sequence-file / trust-bundle core / wire / schema change beyond Run 207's
  additive optional sibling and does not weaken Runs 070, 130–207. **Full C4
  remains OPEN; C5 remains OPEN.**
## Run 209 — source/test hidden custody-attestation policy selector and production preflight integration

Run 209 makes the Run 205 typed `CustodyAttestationPolicy` selectable at
source/test call sites via a hidden, disabled-by-default selector (one
hidden CLI flag `--p2p-trust-bundle-custody-attestation-policy` plus the
env var `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY`) and wires the
resolved policy into the seven production v2 marker-decision preflight
contexts through the Run 207 routing layer.

* Run 209 grants **no new authority**. It implements no real cloud-KMS /
  PKCS#11 / HSM-vendor attestation verifier, no real KMS/HSM backend, no
  real RemoteSigner backend, no governance execution, no real on-chain
  proof verifier, and no validator-set rotation.
* Default remains `CustodyAttestationPolicy::Disabled`; legacy
  no-attestation payloads remain compatible. CLI wins over env when both
  are set; invalid values fail closed with a typed parse error.
* Fixture attestation remains **DevNet/TestNet evidence-only** and cannot
  satisfy MainNet production attestation; production / cloud-KMS / PKCS#11
  / HSM / RemoteSigner attestation reaches the Run 205 verifier and fails
  closed as unavailable.
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with a carried fixture attestation and
  `MainnetProductionAttestationRequired`. Run 209 makes no
  authority-marker / sequence-file / trust-bundle core / wire / schema
  change and does not weaken Runs 070, 130–208. Release-binary
  custody-attestation policy selector evidence is deferred to **Run 210**.
  **Full C4 remains OPEN; C5 remains OPEN.**
## Run 210 — release-binary custody-attestation policy selector evidence

Run 210 supplies the release-binary evidence deferred by Run 209 for the
hidden custody-attestation policy selector. It adds the release helper
`crates/qbind-node/examples/run_210_custody_attestation_policy_release_binary_helper.rs`,
the harness
`scripts/devnet/run_210_custody_attestation_policy_release_binary.sh`, the
evidence archive
`docs/devnet/run_210_custody_attestation_policy_release_binary/`, and the
canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_210.md`. It makes
**no production source change** (helper + harness + docs only).

* Run 210 grants **no new authority**. It implements no real cloud-KMS /
  PKCS#11 / HSM-vendor attestation verifier, no real KMS/HSM backend, no real
  RemoteSigner backend, no governance execution, no real on-chain proof
  verifier, and no validator-set rotation; it only proves, in release mode,
  that the existing Run 209 selector and the seven preflight wrappers behave
  as specified.
* On the real `target/release/qbind-node`, `--help` hides the Run 209
  selector flag `--p2p-trust-bundle-custody-attestation-policy` (`hide =
  true`); arming the hidden CLI/env selector confers no new
  authority-bearing capability and enables no production attestation backend.
* Default remains `CustodyAttestationPolicy::Disabled`; legacy no-attestation
  payloads remain compatible. CLI wins over env when both are set; invalid
  values fail closed with a typed parse error. Fixture attestation remains
  **DevNet/TestNet evidence-only** and cannot satisfy MainNet production
  attestation; production / cloud-KMS / PKCS#11 / HSM / RemoteSigner
  attestation reaches the Run 205 verifier and fails closed as unavailable.
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL refusal**
  even with a carried fixture attestation and
  `mainnet-production-attestation-required`. Run 210 makes no
  authority-marker / sequence-file / trust-bundle core / wire / schema change
  and does not weaken Runs 070, 130–209. **Full C4 remains OPEN; C5 remains
  OPEN.**

## Run 211 — governance execution policy boundary (source/test)

Run 211 adds a typed governance execution policy boundary
(`crates/qbind-node/src/pqc_governance_execution_policy.rs`,
`crates/qbind-node/tests/run_211_governance_execution_policy_tests.rs`)
modeling how an approved governance decision authorizes an authority
lifecycle action. It is **source/test only** and confers no new authority.

* **Governance execution grants no new authority.** Accepting a fixture
  governance decision under `evaluate_governance_execution_policy` does not
  create, rotate, retire, revoke, or activate any real signing key; it
  produces only a typed `GovernanceExecutionOutcome`. No marker write, no
  sequence write, no live trust swap, no session eviction, no Run 070 call.
* The boundary defaults to `GovernanceExecutionPolicy::Disabled`; under the
  default, the GenesisBound / EmergencyCouncil / OnChainGovernance authority
  classes and the custody / RemoteSigner / KMS-HSM / custody-attestation
  authority surfaces are unchanged.
* **Fixture governance is DevNet/TestNet evidence-only** and is refused on a
  MainNet trust domain; the production / on-chain / MainNet governance
  execution evaluators are callable but fail closed as unavailable and
  confer no authority. A local operator and a peer majority cannot satisfy
  governance execution (`local_operator_cannot_satisfy_governance_execution`,
  `peer_majority_cannot_satisfy_governance_execution`).
* **Validator-set rotation remains unsupported**
  (`validator_set_rotation_remains_unsupported`), and the policy-change
  requests are rejected as unsupported; governance execution authorizes only
  the existing GenesisBound/EmergencyCouncil lifecycle actions when the
  decision matches, with emergency revoke gated behind the explicit
  emergency fixture policy.
* Run 211 implements **no real governance execution engine, no real on-chain
  governance proof verifier, no MainNet governance, no real KMS/HSM backend,
  no real RemoteSigner backend, and no production signing-key custody**; it
  adds **no new metric, no new exit code, no CLI flag**, and makes no
  authority-marker / sequence-file / trust-bundle core / wire / schema
  change; it does not weaken Runs 070, 130–210. MainNet peer-driven apply
  remains the **Run 147 / 148 / 152 FATAL refusal** even with fixture
  governance approval. Release-binary evidence is deferred to **Run 212**.
  **Full C4 remains OPEN; C5 remains OPEN.**
## Run 212 — release-binary governance execution policy-boundary evidence

Run 212 supplies the release-binary evidence deferred by Run 211 for the
source/test governance execution policy boundary
(`crates/qbind-node/src/pqc_governance_execution_policy.rs`). It adds a release
example helper
(`crates/qbind-node/examples/run_212_governance_execution_policy_release_binary_helper.rs`),
a release harness
(`scripts/devnet/run_212_governance_execution_policy_release_binary.sh`), the
evidence archive `docs/devnet/run_212_governance_execution_policy_release_binary/`,
and the canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_212.md`.

* **Run 212 grants no new authority.** It changes no production source and
  only links and exercises the already-additive Run 211 boundary in release
  mode through the production library symbols. Accepting a fixture governance
  decision still produces only a typed `GovernanceExecutionOutcome` — no real
  signing key is created, rotated, retired, revoked, or activated, and there is
  no marker write, sequence write, live trust swap, session eviction, or Run
  070 call.
* On the real `target/release/qbind-node` no surface exposes or enables
  governance execution, advertises no production / MainNet governance
  enablement, and advertises no on-chain governance proof verifier; every
  existing Run 070 / 130–211 authority surface stays governance-execution-silent
  (S1–S7).
* **Fixture governance execution remains DevNet/TestNet evidence-only** and is
  refused on a MainNet trust domain; the production / on-chain / MainNet
  governance execution evaluators remain callable but fail closed as unavailable
  and confer no authority; a local operator and a peer majority cannot satisfy
  governance execution.
* **Validator-set rotation remains unsupported** and the policy-change requests
  are rejected as unsupported; emergency revoke remains gated behind the
  explicit emergency fixture policy.
* Run 212 implements **no real governance execution engine, no real on-chain
  governance proof verifier, no MainNet governance, no real KMS/HSM backend, no
  real RemoteSigner backend, and no production signing-key custody**; the
  existing custody / KMS-HSM / RemoteSigner / custody-attestation / governance
  proof authority surfaces remain compatible; and it does not weaken Runs 070,
  130–211. MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with a fixture governance approval. **Full C4 remains OPEN; C5
  remains OPEN.**
## Run 213 — governance-execution payload carrying and production-context wiring (source/test)

Run 213 makes the Run 211 typed governance-execution input/decision material
reachable from production call-site contexts via the new module
`crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs`, verified
by `crates/qbind-node/tests/run_213_governance_execution_payload_callsite_tests.rs`.

* **Run 213 grants no new authority.** It adds an additive, optional
  `governance_execution` sibling on the v2 ratification sidecar and source/test
  routing helpers that carry the Run 211 governance-execution material into the
  seven production marker-decision call-site contexts where it reaches the
  Run 211 evaluator. Accepting a fixture governance decision still produces only
  a typed `GovernanceExecutionOutcome` — no real signing key is created,
  rotated, retired, revoked, or activated, and there is no marker write,
  sequence write, live trust swap, session eviction, or Run 070 call.
* **Default stays compatible.** Under the default
  `GovernanceExecutionPolicy::Disabled` a legacy no-governance-execution
  payload is accepted unchanged; a present-but-malformed carrier or a
  required-but-absent carrier under a non-`Disabled` policy fails closed before
  the evaluator.
* **Fixture governance execution remains DevNet/TestNet evidence-only** and is
  refused on a MainNet trust domain; the production / on-chain / MainNet
  governance execution evaluators remain callable but fail closed as
  unavailable and confer no authority.
* **Validator-set rotation remains unsupported** and the policy-change requests
  are rejected as unsupported; emergency revoke remains gated behind the
  explicit emergency fixture policy.
* Run 213 implements **no real governance execution engine, no real on-chain
  governance proof verifier, no MainNet governance, no real KMS/HSM backend, no
  real RemoteSigner backend, and no production signing-key custody**; the
  existing custody / KMS-HSM / RemoteSigner / custody-attestation / governance
  proof authority surfaces remain compatible; and it does not weaken Runs 070,
  130–212. Release-binary governance-execution payload/carrying evidence is
  deferred to **Run 214**. MainNet peer-driven apply remains the **Run 147 /
  148 / 152 FATAL refusal** even with a fixture governance approval. **Full C4
  remains OPEN; C5 remains OPEN.**
## Run 214 — release-binary governance-execution payload/carrying evidence

Run 214 provides the release-binary evidence deferred by Run 213 for the
governance-execution payload/carrying and production-context wiring, on the real
`target/release/qbind-node` plus a release-built helper linking the production
library symbols
(`crates/qbind-node/examples/run_214_governance_execution_payload_release_binary_helper.rs`,
`scripts/devnet/run_214_governance_execution_payload_release_binary.sh`,
`docs/devnet/run_214_governance_execution_payload_release_binary/`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_214.md`).

* **Run 214 grants no new authority.** It makes no production source change and
  only proves, in release mode, that the Run 213 routing helpers carry the
  Run 211 governance-execution material into the Run 211 evaluator across the
  seven production marker-decision call-site contexts. Accepting a fixture
  governance decision still produces only a typed `GovernanceExecutionOutcome` —
  no real signing key is created, rotated, retired, revoked, or activated, and
  there is no marker write, sequence write, live trust swap, session eviction, or
  Run 070 call.
* **Default stays compatible.** The real `target/release/qbind-node` exposes no
  governance-execution surface, and under the default
  `GovernanceExecutionPolicy::Disabled` a legacy no-governance-execution payload
  is accepted unchanged; a present-but-malformed carrier or a required-but-absent
  carrier under a non-`Disabled` policy fails closed before the evaluator.
* **Fixture governance execution remains DevNet/TestNet evidence-only** and is
  refused on a MainNet trust domain; the production / on-chain / MainNet
  governance execution evaluators remain callable but fail closed as unavailable
  and confer no authority.
* **Validator-set rotation remains unsupported** and the policy-change requests
  are rejected as unsupported; emergency revoke remains gated behind the explicit
  emergency fixture policy.
* Run 214 implements **no real governance execution engine, no real on-chain
  governance proof verifier, no MainNet governance, no real KMS/HSM backend, no
  real RemoteSigner backend, and no production signing-key custody**; the existing
  custody / KMS-HSM / RemoteSigner / custody-attestation / governance proof
  authority surfaces remain compatible; and it does not weaken Runs 070,
  130–213. MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with a fixture governance approval. **Full C4 remains OPEN; C5
  remains OPEN.**

## Run 215 — hidden governance-execution policy selector (source/test)

Run 215 adds a hidden, disabled-by-default governance-execution policy selector
and wires the resolved `GovernanceExecutionPolicy` into the seven production v2
marker-decision preflight contexts through the Run 213 routing helpers. It adds
the module `crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`,
the hidden CLI flag `--p2p-trust-bundle-governance-execution-policy`, the tests
`crates/qbind-node/tests/run_215_governance_execution_policy_selector_tests.rs`,
and the canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_215.md`.

* **Run 215 grants no new authority.** It only adds an additive selector module
  plus one hidden CLI flag that *choose* among the existing Run 211
  `GovernanceExecutionPolicy` values; it does not change authority lifecycle
  semantics, the authority-marker schema, the sequence-file schema, or the
  trust-bundle core schema.
* **Disabled by default.** When the CLI flag and the
  `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var are both absent
  the resolved policy is `GovernanceExecutionPolicy::Disabled`, preserving every
  prior proof-carrier and custody authority surface bit-for-bit. The CLI flag
  wins over the env var when both are supplied; an empty / unknown value fails
  closed with a typed `GovernanceExecutionPolicySelectorParseError`.
* **Authority binding preserved.** Under an explicit fixture policy a carried
  governance decision authorizes a lifecycle action only when the action,
  candidate digest, and authority-domain sequence match; rotate and revoke are
  authorized only on matching candidate / revoked-key material and sequence;
  validator-set rotation and policy-change requests are rejected as unsupported;
  emergency revoke remains gated behind the explicit emergency-council fixture
  policy and is non-production.
* Fixture / emergency-council fixture governance execution remains
  DevNet/TestNet evidence-only and cannot satisfy MainNet production governance
  execution; production / on-chain / MainNet governance execution reaches the
  Run 211 evaluator and fails closed as unavailable.
* The live inbound `0x05` runtime config does not yet thread the per-connection
  policy; the source/test wrapper exposes the injection and the limitation is
  documented. Release-binary governance-execution-policy selector evidence is
  deferred to **Run 216**.
* Run 215 implements **no real governance execution engine, no real on-chain
  governance proof verifier, no MainNet governance, no real KMS/HSM backend, no
  real RemoteSigner backend, and no production signing-key custody**; the
  existing custody / KMS-HSM / RemoteSigner / custody-attestation / governance
  proof authority surfaces remain compatible; and it does not weaken Runs 070,
  130–214. MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with `MainnetGovernanceRequired` and a fixture governance
  approval. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 216 — release-binary governance-execution policy selector evidence

Run 216 adds release-binary evidence only for the Run 215 hidden governance-execution selector. It grants no new authority and changes no lifecycle, marker, sequence, trust-bundle, schema, or wire semantics. The release helper proves default `GovernanceExecutionPolicy::Disabled`, hidden CLI/env selection, CLI-over-env precedence, invalid fail-closed parsing, selected-policy reachability to all seven production preflight wrappers, fixture/emergency DevNet/TestNet-only acceptance, production/on-chain/MainNet unavailable outcomes, and MainNet peer-driven apply refusal. Existing custody, KMS-HSM, RemoteSigner, custody-attestation, and governance-proof authority paths remain compatible; no real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, production signing custody, or validator-set rotation is implemented. **Full C4 remains OPEN; C5 remains OPEN.**

## Run 217 — source/test governance-execution runtime policy arming wiring

Run 217 wires the Run 215 hidden governance-execution selector into the long-running runtime preflight contexts at source/test level through the carrier `GovernanceExecutionRuntimeArmingConfig`. It grants **no new authority** and changes no lifecycle, marker, sequence, trust-bundle, schema, or wire semantics. The carrier resolves the selector once (`from_cli_or_env`, preserving CLI-over-env precedence and invalid-value fail-closed behavior) and routes the resolved `GovernanceExecutionPolicy` into the seven runtime preflight wrappers, through the Run 213 routing helpers to the Run 211 evaluator. Default resolution remains `GovernanceExecutionPolicy::Disabled`, so no new authority is active by default and legacy no-governance-execution payloads remain compatible (Run 214). Fixture and emergency-council fixture execution remain DevNet/TestNet source/test only and non-production; production/on-chain/MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused; the Run 193 custody, Run 199 RemoteSigner, and Run 210 custody-attestation sibling authority selectors remain independent and compatible. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, production signing custody, or validator-set rotation is implemented; release-binary governance-execution runtime-arming evidence is deferred to **Run 218**. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 218 — release-binary governance-execution runtime-arming evidence

Run 218 is the release-binary evidence run for the Run 217 carrier `GovernanceExecutionRuntimeArmingConfig`. It grants **no new authority** and changes no lifecycle, marker, sequence, trust-bundle, schema, or wire semantics. On real `target/release/qbind-node` plus a release-built helper it proves the resolved `GovernanceExecutionPolicy` is consumed through the carrier (`from_cli_or_env` → `arm_surface` / the seven `preflight_*` methods) and routed into the production preflight contexts, with default resolution remaining `GovernanceExecutionPolicy::Disabled` (no new authority active by default; legacy no-governance-execution payloads remain compatible per Run 214). CLI-over-env precedence is deterministic at the runtime config boundary and an invalid selector fails closed before any runtime mutation. Fixture and emergency-council fixture execution remain DevNet/TestNet evidence-only and non-production; production/on-chain/MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused; the Run 193 custody, Run 199 RemoteSigner, and Run 210 custody-attestation sibling authority selectors remain independent and compatible. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, production signing custody, or validator-set rotation is implemented. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 219 — governance-execution runtime-surface gap audit

Run 219 is an **audit / spec / docs-only** run. It grants **no new authority** and changes no lifecycle, marker, sequence, trust-bundle, schema, or wire semantics. The audit maps every governance-execution runtime surface from the Run 211–218 sequence and records that the selector/policy surfaces are fully wired and real-binary evidenced, the runtime arming carrier is only partially wired on the long-running path (the resolved outcome is discarded at every live call site and the payload load status is `Absent`), the payload-carrying surfaces are helper-evidenced/source-test complete but not consumed live, five of the seven runtime call sites (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check) are partially wired, and two (live inbound `0x05`, peer-driven drain) are helper-evidenced only. The sibling authority selectors and boundaries — governance proof (Runs 171/172), OnChainGovernance (Runs 178–187), custody (Run 193), RemoteSigner (Run 199), custody-attestation (Run 210), KMS/HSM (Runs 203–204), and RemoteSigner transport (Runs 201–202) — remain independent, unchanged, and compatible; none is consumed by governance-execution runtime policy. Default resolution remains `GovernanceExecutionPolicy::Disabled`, so no new authority is active by default; fixture and emergency-council fixture execution remain DevNet/TestNet evidence-only and non-production; production/on-chain/MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused; validator-set rotation remains unsupported. The audit selects **Run 220** (source/test long-running consumption wiring) and **Run 221** (release-binary consumption evidence) as the next sequence. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, production signing custody, or validator-set rotation is implemented. See `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md`. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 220 — governance-execution runtime consumption wiring (source/test)

Run 220 is **source/test** long-running governance-execution runtime
consumption wiring. It grants **no new authority** and changes no
lifecycle, marker, sequence, trust-bundle, schema, or wire semantics.
Acting on the Run 219 finding, the four binary runtime call sites
(reload-check, reload-apply, startup `--p2p-trust-bundle`, local
peer-candidate-check) and the SIGHUP runtime hook now **consume** the
selected `GovernanceExecutionPolicy` and the **real** governance-execution
sidecar load status: the discard of the resolved outcome and the forced
`GovernanceExecutionLoadStatus::Absent` are removed on those surfaces, and
a rejected verdict fails closed before any mutation. The sibling authority
selectors and boundaries — governance proof (Runs 171/172), OnChainGovernance
(Runs 178–187), custody (Run 193), RemoteSigner (Run 199),
custody-attestation (Run 210), KMS/HSM (Runs 203–204), and RemoteSigner
transport (Runs 201–202) — remain independent, unchanged, and compatible;
none is consumed by governance-execution runtime policy. Default resolution
remains `GovernanceExecutionPolicy::Disabled`, so no new authority is active
by default and the Disabled + absent-carrier path proceeds bit-for-bit as a
legacy bypass; fixture and emergency-council fixture execution remain
DevNet/TestNet evidence-only and non-production; production/on-chain/MainNet
governance execution remains unavailable/fail-closed; MainNet peer-driven
apply remains refused; validator-set rotation remains unsupported. Because
binary/SIGHUP candidate metadata carries no governance proposal/decision
bindings, a present carrier at the binary surface reaches the Run 211
evaluator and fails closed on the expectation mismatch; live inbound `0x05`
and full positive binary acceptance are deferred to **Run 221**. No real
governance execution engine, on-chain verifier, KMS/HSM backend,
RemoteSigner backend, production signing custody, or validator-set rotation
is implemented. Release-binary runtime-consumption evidence is deferred to
**Run 221**. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_220.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**
## Run 221 — release-binary governance-execution runtime-consumption evidence

Run 221 is the release-binary evidence run for the Run 220 long-running
governance-execution runtime-consumption wiring. It grants **no new
authority** and changes no lifecycle, marker, sequence, trust-bundle,
schema, or wire semantics. On real `target/release/qbind-node` plus a
release-built helper it proves the Run 220 consumption layer
(`GovernanceExecutionRuntimeConsumption`, `consume_surface`,
`consume_surface_from_optional_sidecar_value`,
`governance_execution_load_status_from_optional_sidecar_value`) gates the
long-running path: the consumed outcome proceeds on the Disabled +
absent-carrier legacy bypass (Run 214), fails closed before any mutation on
a rejected verdict, and reads the **real** governance-execution sidecar load
status from the optional sidecar value rather than a forced `Absent` where
representable. Default resolution remains `GovernanceExecutionPolicy::Disabled`
(no new authority active by default); CLI-over-env precedence is
deterministic at the runtime config boundary and an invalid CLI or env
selector fails closed before any runtime mutation. Fixture and
emergency-council fixture execution remain DevNet/TestNet evidence-only and
non-production; production/on-chain/MainNet governance execution remains
unavailable/fail-closed; MainNet peer-driven apply remains refused; the Run
193 custody, Run 199 RemoteSigner, and Run 210 custody-attestation sibling
authority selectors remain independent and compatible. No real governance
execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend,
production signing custody, or validator-set rotation is implemented. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_221.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 222 — production governance-execution evaluator interface boundary

Run 222 is a source/test run that adds the typed production governance
execution **evaluator interface**
(`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`). It grants
**no new authority** and changes no lifecycle, marker, sequence,
trust-bundle, schema, or wire semantics. The interface models how a *future*
governance engine would supply decisions from a decision source, bind them
to an `AuthorityTrustDomain`, validate provenance, track replay, and return
fail-closed production outcomes — it is **not** a real governance engine and
**not** a real on-chain governance proof verifier, and it touches no runtime
call site. The evaluator is fail-closed by default
(`EvaluatorPolicy::Disabled`); production/on-chain/MainNet evaluators are
callable but fail closed as unavailable; the fixture evaluator is
DevNet/TestNet source/test only and is refused on a MainNet trust domain;
the emergency fixture evaluator is explicit and non-production. **MainNet
peer-driven apply remains refused**; validator-set rotation remains
unsupported; the Run 193 custody, Run 199 RemoteSigner, and Run 210
custody-attestation sibling authority selectors remain independent and
compatible; KMS/HSM, RemoteSigner, and production signing custody remain
boundary-only. No real governance execution engine, on-chain verifier,
KMS/HSM backend, RemoteSigner backend, production signing custody, or
validator-set rotation is implemented. Release-binary evaluator-interface
evidence is deferred to **Run 223**. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_222.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**
## Run 223 — release-binary governance-execution evaluator-interface evidence

Run 223 is the release-binary evidence companion to the Run 222 source/test
production governance-execution evaluator interface. It proves on real
`target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_223_governance_execution_evaluator_release_binary_helper.rs`,
driven by `scripts/devnet/run_223_governance_execution_evaluator_release_binary.sh`)
that the release-built library exposes and exercises the Run 222 evaluator
authority boundary: the fixture evaluator authority accepts only DevNet/TestNet
decision sources under the explicit fixture policy; the emergency-council
fixture evaluator authority accepts only an explicit emergency decision under
the explicit emergency policy; an evaluator response authorizes a lifecycle
action only when the authorized action, candidate digest, and sequence all
match; and production/on-chain/MainNet evaluator authorities are callable but
fail closed as unavailable. The helper records 111 typed checks (accepted 49 /
rejection 42 / reachability 20) over A1–A18 / R1–R40, and the harness proves
the release binary `--help` exposes no evaluator-interface surface and the
default DevNet/TestNet/MainNet surfaces make no evaluator / production-governance /
MainNet-governance / on-chain-verifier / validator-set-rotation enablement
claim (22 forbidden patterns proven empty). The fixture evaluator authority is
DevNet/TestNet evidence-only; the emergency fixture evaluator is explicit and
non-production. **MainNet peer-driven apply remains refused**; validator-set
rotation remains unsupported; the Run 193 custody, Run 199 RemoteSigner, and
Run 210 custody-attestation sibling authority selectors remain independent and
compatible; KMS/HSM, RemoteSigner, and production signing custody remain
boundary-only. No real governance execution engine, on-chain verifier,
KMS/HSM backend, RemoteSigner backend, production signing custody, or
validator-set rotation is implemented. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_223.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 224 — source/test governance evaluator runtime integration

Run 224 is a source/test run that integrates the Run 222 governance evaluator
authority interface into the Run 220 governance-execution runtime-consumption
pipeline at the source/test level. The new pure integration layer
(`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`)
composes runtime consumption with the evaluator request/response/interface,
Run 211 governance execution decision validation, and Run 213 payload
material, so the evaluator authority is now consulted as the next evaluation
stage inside runtime consumption — mutation authorization (`ProceedMutate`) is
produced only when both the runtime-consumption stage and the evaluator
authority agree on the same lifecycle action / candidate digest /
authority-domain sequence, after the ordered checks (selector resolution →
load-status derivation → runtime consumption → evaluator request construction
→ evaluator evaluation → governance execution decision validation → mutation
only after all required checks pass). The fixture evaluator authority remains
DevNet/TestNet source-test only; the emergency fixture evaluator authority is
explicit and non-production; production/on-chain/MainNet evaluator authorities
are callable but fail closed as unavailable. **MainNet peer-driven apply
remains refused** even where a fixture evaluator would otherwise approve;
validator-set rotation remains unsupported; the Run 193 custody, Run 199
RemoteSigner, and Run 210 custody-attestation sibling authority selectors
remain independent and compatible; KMS/HSM, RemoteSigner, and production
signing custody remain boundary-only. Every rejection path is non-mutating and
the integration module exposes no mutation API. Coverage:
`crates/qbind-node/tests/run_224_governance_evaluator_runtime_integration_tests.rs`
(48 tests, A1–A12 / R1–R30, PASS). No real governance execution engine,
on-chain verifier, KMS/HSM backend, RemoteSigner backend, production signing
custody, or validator-set rotation is implemented. Release-binary evidence is
deferred to **Run 225**. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_224.md`
and `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 225 — release-binary governance evaluator runtime integration evidence

Run 225 is the release-binary evidence companion to the Run 224 source/test
governance evaluator runtime integration. Where Run 224 landed the pure
integration layer
(`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`)
that consults the evaluator authority as the next evaluation stage inside Run
220 runtime consumption, Run 225 proves on real `target/release/qbind-node`
plus a release-built helper
(`crates/qbind-node/examples/run_225_governance_evaluator_runtime_integration_release_binary_helper.rs`,
driven by `scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh`)
that the release-built code exposes and exercises the integration: mutation
authorization (`ProceedMutate`) is produced only when both the
runtime-consumption stage and the evaluator authority agree on the same
lifecycle action / candidate digest / authority-domain sequence, after the
ordered checks. The release helper records 112 typed checks across accepted
(59) / rejection (37) / reachability (16) covering the full A1–A15 / R1–R30
matrix in release mode. The fixture evaluator authority remains DevNet/TestNet
evidence-only; the emergency fixture evaluator authority is explicit and
non-production; production/on-chain/MainNet evaluator authorities are reached
and fail closed as unavailable; **MainNet peer-driven apply remains refused**
even where a fixture evaluator would otherwise approve; validator-set rotation
remains unsupported; the Run 193 custody, Run 199 RemoteSigner, and Run 210
custody-attestation sibling authority selectors remain independent and
compatible; KMS/HSM, RemoteSigner, and production signing custody remain
boundary-only; existing Run 221 and Run 223 release behaviour remains
compatible. The harness drives the real release binary to prove `--help`
exposes no integration surface and the default DevNet/TestNet/MainNet surfaces
make no integration / governance-execution / MainNet-governance /
on-chain-verifier / validator-set-rotation / KMS-HSM / RemoteSigner /
autonomous-apply / apply-on-receipt / peer-majority / MainNet-peer-driven-apply
enablement claim (24 forbidden patterns proven empty). No real governance
execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend,
production signing custody, or validator-set rotation is implemented. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_225.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 226 — source/test governance evaluator runtime call-site wiring

Run 226 is a source/test run that wires the existing Run 220
governance-execution runtime call sites through the Run 224 governance
evaluator integration layer. Where Run 224 landed the pure integration layer
and Run 225 proved it in release mode, the runtime call sites still called the
Run 220 `consume_surface` path directly. Run 226 routes the representable call
sites (`consume_run_220_governance_execution_runtime_outcome`,
`consume_run_220_sighup_governance_execution_marker_decision`) through the
integration layer via the new wiring entry points
(`wire_governance_evaluator_runtime_callsite`,
`wire_governance_evaluator_runtime_callsite_without_evaluator_context`), so
mutation authorization (`ProceedMutate`) is produced only when both the
runtime-consumption stage and the evaluator authority agree on the same
lifecycle action / candidate digest / authority-domain sequence, after the
ordered checks.

The fixture evaluator authority remains DevNet/TestNet source-test only; the
emergency fixture evaluator authority is explicit and non-production;
production/on-chain/MainNet evaluator authorities remain unavailable/fail-closed;
**MainNet peer-driven apply remains refused** even where a fixture evaluator
would otherwise approve; validator-set rotation remains unsupported; the
Run 193 custody, Run 199 RemoteSigner, and Run 210 custody-attestation sibling
authority selectors remain independent and compatible; KMS/HSM, RemoteSigner,
and production signing custody remain boundary-only. The default Disabled +
absent-carrier `ProceedLegacyBypass` is preserved; any present carrier at the
binary call sites fails closed, strictly stricter than the Run 220 behaviour
it replaces; every rejection is non-mutating. The binary marker/candidate
metadata cannot yet carry a governance proposal/decision evaluator binding, so
the live inbound `0x05` and peer-driven drain surfaces are wired at the
source/test level but their full positive evaluator binding is not yet
representable from the binary (documented limitation; deferred to Run 227). No
real governance execution engine, on-chain verifier, KMS/HSM backend,
RemoteSigner backend, production signing custody, or validator-set rotation is
implemented. Tests:
`crates/qbind-node/tests/run_226_governance_evaluator_runtime_callsite_wiring_tests.rs`
(59, A1–A17 / R1–R31, PASS). See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_226.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 227 — release-binary governance evaluator runtime call-site wiring evidence

Run 227 is the release-binary evidence run for the Run 226 call-site wiring.
On real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper.rs`,
driven by
`scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh`)
it proves the release-built code exercises the Run 226 wiring entry points
(`wire_governance_evaluator_runtime_callsite` and
`wire_governance_evaluator_runtime_callsite_without_evaluator_context`): the
representable runtime call sites consume the
`GovernanceEvaluatorRuntimeIntegrationOutcome` (consumed, not discarded), the
default Disabled + absent-carrier legacy bypass is preserved, a present
carrier without evaluator context fails closed, production/on-chain/MainNet
evaluators remain unavailable/fail-closed, and every rejection is
non-mutating. The authority model is unchanged: the fixture evaluator remains
DevNet/TestNet evidence-only, the emergency fixture evaluator is explicit and
non-production, MainNet peer-driven apply remains refused, and no real
governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner
backend, production signing custody, or validator-set rotation is
implemented. The live inbound `0x05` and peer-driven drain surfaces remain
wired but not fully representable from the binary (documented limitation);
Run 221/223/225 release behaviour remains compatible. Tests:
`crates/qbind-node/tests/run_226_governance_evaluator_runtime_callsite_wiring_tests.rs`
(59, PASS) plus the Run 227 release helper corpus (144 checks, PASS). See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_227.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 228 — source/test peer evaluator-context representation boundary

Run 228 adds a typed evaluator-context representation boundary for the live
inbound `0x05` peer-candidate validation and peer-driven drain surfaces
(`crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`, registered
in `crates/qbind-node/src/lib.rs`, with
`crates/qbind-node/tests/run_228_peer_evaluator_context_representation_tests.rs`,
48 tests A1–A14 / R1–R27, PASS). It lets these surfaces carry or reference an
evaluator context in source/test plumbing where representable and routes that
context into the Run 226 call-site wiring → Run 224 integration layer →
Run 222 evaluator interface. The boundary is **local/source-test only and
changes no wire/schema/marker/sequence/trust-bundle format.** The authority
model is unchanged: the carrier taxonomy (`Absent`, `Present`, `Malformed`,
`UnsupportedSurface`, `WireSchemaUnavailable`, `PeerMajorityUnsupported`,
`MainNetRefused`) represents the live-wire path that cannot carry an evaluator
binding as a typed `WireSchemaUnavailable` fail-closed status — never an
approval; missing/unsupported carrier status is typed and fail-closed under an
explicit evaluator policy. The fixture evaluator remains DevNet/TestNet
evidence-only, the emergency fixture evaluator is explicit and non-production,
peer-majority gossip can never satisfy evaluator policy, **MainNet peer-driven
apply remains refused**, production/on-chain/MainNet evaluators remain
unavailable/fail-closed, validator-set rotation remains unsupported, and no
real governance execution engine, on-chain verifier, KMS/HSM backend,
RemoteSigner backend, or production signing custody is implemented. Only the
routed `ProceedMutate` outcome authorizes apply; every rejection is
non-mutating. Release-binary evidence is deferred to **Run 229**. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_228.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 229 — release-binary peer evaluator-context representation evidence

Run 229 is the **release-binary evidence** run for the Run 228 peer
evaluator-context representation boundary
(`crates/qbind-node/examples/run_229_peer_evaluator_context_representation_release_binary_helper.rs`,
`scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh`,
`docs/devnet/run_229_peer_evaluator_context_representation_release_binary/`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_229.md`). It proves on real
`target/release/qbind-node` plus a release-built helper using the production
library symbols (170 typed checks across accepted/rejection/reachability,
`verdict: PASS`) that the release-built code exposes and exercises the Run 228
representation boundary. The boundary is **local/source-test only and changes
no wire/schema/marker/sequence/trust-bundle format**, with no production source
behavior change. The authority model is unchanged: the carrier taxonomy
represents the live-wire path that cannot carry an evaluator binding as a typed
`WireSchemaUnavailable` fail-closed status — never an approval; missing/
unsupported carrier status is typed and fail-closed under an explicit evaluator
policy. The fixture evaluator remains DevNet/TestNet evidence-only, the
emergency fixture evaluator is explicit and non-production, peer-majority
gossip can never satisfy evaluator policy, **MainNet peer-driven apply remains
refused**, production/on-chain/MainNet evaluators remain unavailable/fail-closed,
validator-set rotation remains unsupported, and no real governance execution
engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or production
signing custody is implemented. Only the routed `RoutedProceedMutate` outcome
authorizes apply; every rejection is non-mutating. Regression targets
run_228/226/224/222/220/217/215/213/211/157/152/150/148/142,
`--lib pqc_authority`, and `--lib` all PASS; a 26-pattern denylist is proven
empty. **Full C4 remains OPEN; C5 remains OPEN.** See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_229.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 230 — source/test governance evaluator replay/freshness state boundary

Run 230 is source/test governance evaluator replay/freshness state boundary work. It defines a typed, pure, fail-closed replay/freshness state boundary (`crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`, registered in `lib.rs`, with `crates/qbind-node/tests/run_230_governance_evaluator_replay_state_tests.rs`, 52 tests, PASS) that decides — before any lifecycle mutation — whether an evaluator decision is fresh, not-yet-effective, expired, stale, a replay, already consumed, superseded, bound to the wrong domain, or unavailable. Only `ProceedFresh` authorizes a mutation; `ProceedDeferred` is not an approval. A DevNet/TestNet in-memory `FixtureReplayStateStore` is the only store that records anything and records a consumed decision only on an explicit consume call (read-only validation never consumes); the production/MainNet readers/writers are callable but always unavailable/fail-closed.

## Run 231 — release-binary governance evaluator replay/freshness state evidence

Run 231 is the **release-binary evidence** run for the Run 230 governance evaluator replay/freshness state boundary (`crates/qbind-node/examples/run_231_governance_evaluator_replay_state_release_binary_helper.rs`, `scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh`, `docs/devnet/run_231_governance_evaluator_replay_state_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_231.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (207 typed checks across accepted/rejection/reachability, `verdict: PASS`) that the release-built code exposes and exercises the Run 230 replay/freshness state boundary: only `ProceedFresh` authorizes a mutation; fresh, not-yet-effective (deferred), expired, stale, replayed, already-consumed, superseded, wrong-binding, and state/production/MainNet-unavailable outcomes are distinguished and every non-`ProceedFresh` outcome is non-mutating. Run 231 is release-binary evidence only — no production source behavior change, no new runtime CLI/env surface, no new mutation path, and no wire/schema/marker/sequence/trust-bundle or RocksDB/file/schema/migration/storage-format change. The real release binary makes no replay/freshness state claims and an invalid governance-execution selector fails closed before mutation (no marker write, no sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty; regression targets run_230/228/226/224/222/220/217/215/213/211/157/152/150/148/142, `--lib pqc_authority`, and `--lib` all PASS. MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_231.md`.

The boundary composes the Run 222 evaluator request/response/identity digests and the Run 211 lifecycle action / candidate / sequence binding; the replay state key binds environment, chain id, genesis hash, source identity digest, request digest, response digest, proposal id, decision id, lifecycle action, candidate digest, authority-domain sequence, and replay nonce. No authority is conferred by a local operator or peer majority: both can never satisfy a replay-state policy, and MainNet peer-driven apply remains refused even when state is fresh. Validator-set rotation and policy-change actions remain unsupported; no real governance engine, on-chain verifier, or storage/schema/migration change is implemented; every rejection is non-mutating. Release-binary replay/freshness evidence is deferred to **Run 231**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_230.md` and `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 232 — source/test governance evaluator replay/freshness runtime integration

Run 232 is source/test governance evaluator replay/freshness runtime integration work. Where Run 230 defined the replay/freshness state boundary as a standalone module and Run 231 closed its release-binary evidence, the boundary was not yet integrated into the evaluator runtime integration path as a mandatory pre-mutation gate. Run 232 adds a pure integration layer (`crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`, registered in `lib.rs`, with `crates/qbind-node/tests/run_232_governance_evaluator_replay_runtime_integration_tests.rs`, 47 tests, PASS) whose entry point `integrate_governance_evaluator_replay_runtime` composes the Run 224 evaluator-runtime integration, the Run 226 runtime call-site wiring, the Run 228 peer evaluator context (where relevant), and the Run 230 replay/freshness state boundary so the runtime integration path runs replay/freshness validation **before any mutation authorization**. The typed `GovernanceEvaluatorReplayRuntimeOutcome` distinguishes `ProceedLegacyBypass` / `ProceedDeferred` / `ProceedFresh` (the only mutation-authorizing outcome, produced only after the Run 224 layer authorized a mutate **and** the Run 230 state classified the decision fresh) / `ReplayFreshnessFailClosed` / `RuntimeIntegrationFailClosed` / `MainNetPeerDrivenApplyRefused`; `ProceedDeferred` is not an approval.

No authority is conferred by a local operator or peer majority: both can never satisfy a replay-state policy, and MainNet peer-driven apply remains refused even when state is fresh. The integration is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write) so every non-`ProceedFresh` outcome is non-mutating; it never marks a decision consumed (read-only validation never consumes; explicit consume remains fixture-only, performed by the caller after a fresh authorization). Fixture replay state remains DevNet/TestNet source-test only; production/MainNet replay state remains unavailable/fail-closed. No wire/schema/marker/sequence/trust-bundle and no RocksDB/file/schema/migration/storage-format change is introduced; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. Release-binary replay/freshness runtime-integration evidence is deferred to **Run 233**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_232.md` and `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 233 — release-binary governance evaluator replay/freshness runtime integration evidence

Run 233 is the **release-binary evidence** run for the Run 232 governance evaluator replay/freshness runtime integration (`crates/qbind-node/examples/run_233_governance_evaluator_replay_runtime_integration_release_binary_helper.rs`, `scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh`, `docs/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_233.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (184 typed checks across accepted A1–A17 / rejection R1–R27 / reachability, `verdict: PASS`) that the release-built code exposes and exercises the Run 232 composed runtime integration.

No authority is conferred by a local operator or peer majority: both can never satisfy a replay-state policy, and MainNet peer-driven apply remains refused even when state is fresh — reconfirmed in release mode. Only `ProceedFresh` authorizes a mutation, and only after the Run 224 layer authorized a mutate and the Run 230 state classified the decision fresh; `ProceedDeferred` is not an approval; expired, stale, replayed, already-consumed, superseded, wrong-binding, malformed, and unavailable replay states fail closed before mutation. The integration is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write) so every non-`ProceedFresh` outcome is non-mutating; it never marks a decision consumed (read-only validation never consumes; explicit consume remains fixture-only). Fixture replay state remains DevNet/TestNet source-test only; production/MainNet replay state remains unavailable/fail-closed. No wire/schema/marker/sequence/trust-bundle and no RocksDB/file/schema/migration/storage-format change is introduced; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. Existing Run 231/229/227/225/223 release behaviour remains compatible. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_233.md` and `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 234 — source/test governance evaluator post-mutation replay consume boundary

Run 234 is the **source/test** run that models the post-mutation replay-state consume step as a strict after-success-only boundary (`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_boundary.rs`, registered in `crates/qbind-node/src/lib.rs`, plus `crates/qbind-node/tests/run_234_governance_evaluator_replay_consume_boundary_tests.rs`, 58 tests A1-A18 / R1-R33, PASS). It separates pre-mutation freshness validation, mutation authorization (`MutationAuthorizationOutcome`), successful mutation completion (`MutationCompletionStatus`), and an explicit replay-state consume after success only, resolving a typed `ConsumeBoundaryOutcome`. The authority model is unchanged: consume is after-success-only — only `ConsumeFixtureAfterSuccess` (after `AppliedSuccessfully`) authorizes a fixture consume via the Run 230 DevNet/TestNet writer; deferred, validation-only, authorized-but-not-applied, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume.

Local-operator keys and peer-majority gossip can never satisfy the consume policy; production/MainNet consume writers remain callable but always fail closed unavailable, and MainNet peer-driven apply remains refused and never consumes even when the state is fresh. Run 234 is source/test only, implements no persistent storage, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format; evaluation is pure (no Run 070 call, no live trust swap, no session eviction, no marker/sequence write) and the writer is never called on a non-consume path. Validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. Release-binary consume-boundary evidence is deferred to **Run 235**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_234.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
## Run 235 — release-binary governance evaluator post-mutation replay consume boundary evidence

Run 235 is the **release-binary** evidence run for the Run 234 post-mutation replay-state consume boundary (`crates/qbind-node/examples/run_235_governance_evaluator_replay_consume_boundary_release_binary_helper.rs`, `scripts/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary.sh`, `docs/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_235.md`). It proves on real `target/release/qbind-node` plus a release-built helper, using the production library symbols (`evaluate_post_mutation_consume`, `perform_post_mutation_consume`, `MutationAuthorizationOutcome`, `MutationCompletionStatus`, the `ConsumeBoundaryOutcome` taxonomy, and the invariant guard functions), that consume is after-success-only: only `ConsumeFixtureAfterSuccess` (after `AppliedSuccessfully`) authorizes a fixture consume via the Run 230 DevNet/TestNet writer; deferred, validation-only, authorized-but-not-applied, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume. The release helper records 225 typed checks (A1–A21/R1–R33/reachability) with `pass=225`, `fail=0`.

The authority model is unchanged: local-operator keys and peer-majority gossip can never satisfy the consume policy; production/MainNet consume writers remain callable but always fail closed unavailable, and MainNet peer-driven apply remains refused and never consumes even when the state is fresh — and the release evidence confirms this in release mode. Run 235 is release-binary evidence only, implements no persistent storage, introduces no production source behavior change, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format; the harness proves the real binary makes no consume-boundary claims on default surfaces and fails closed before mutation on an invalid selector (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call), with an empty denylist. Validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented; existing Run 233/231/229/227/225 release behaviour remains compatible. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_235.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 236 — source/test governance evaluator replay consume runtime integration

Run 236 composes the Run 232 replay/freshness runtime integration with the Run 234 post-mutation consume boundary into a single lifecycle integration layer (`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_runtime_integration.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_236_governance_evaluator_replay_consume_runtime_integration_tests.rs`, 56 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_236.md`). `integrate_replay_consume_runtime` runs the Run 232 runtime integration first and maps any non-`ProceedFresh` outcome directly to the matching non-consuming Run 236 outcome without calling the consume writer; only on `ProceedFresh` does it override the consume binding's mutation-authorization outcome with the Run 232-derived `AuthorizedFresh`, run `perform_post_mutation_consume`, and project the Run 234 `ConsumeBoundaryOutcome` into the composed `ReplayConsumeRuntimeOutcome`. Consume is integrated as an after-success-only post-mutation step; fresh is required before mutation authorization.

The authority model is unchanged: local-operator keys and peer-majority gossip can never satisfy the consume policy; production/MainNet consume writers remain callable but always fail closed unavailable, and MainNet peer-driven apply remains refused and never consumes even when the replay state is fresh — the Run 232 layer refuses before any mutation authorization, so the composition never enters the consume boundary on a MainNet peer-driven apply. Run 236 is source/test only, implements no persistent storage, introduces no production source behavior change, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format; the composition is pure (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call) so a rejection is non-mutating and the writer is never called on a non-consume path. Validator-set rotation and policy-change actions remain unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented; existing Run 234/232 behaviour remains compatible. Release-binary consume-runtime-integration evidence is deferred to **Run 237**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_236.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.

## Run 237 — release-binary governance evaluator replay consume runtime integration evidence

Run 237 is the release-binary evidence run for the Run 236 source/test governance evaluator replay consume runtime integration (`crates/qbind-node/examples/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper.rs`, driven by `scripts/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_237.md`). The release-built helper exercises the Run 236 integration symbols through production library code on real `target/release/qbind-node`, recording 254 typed checks across accepted (A1-A23)/rejection (R1-R35)/reachability with `verdict: PASS`.

The authority model is unchanged: local-operator keys and peer-majority gossip can never satisfy the consume policy; production/MainNet consume writers remain callable but always fail closed unavailable, and MainNet peer-driven apply remains refused and never consumes even when the state is fresh — and the release evidence confirms this in release mode. Run 237 is release-binary evidence only, implements no persistent storage, introduces no production source behavior change, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format; the harness proves the real binary makes no consume-runtime-integration claims on default surfaces and fails closed before mutation on an invalid selector (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call), with an empty denylist. Validator-set rotation and policy-change actions remain unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented; existing Run 235/233/231/229/227 release behaviour remains compatible. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_237.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
## Run 238 — source/test governance evaluator replay-state durable backend boundary

Run 238 defines a typed, pure durable backend contract for the governance evaluator replay/freshness state plus a DevNet/TestNet in-memory fixture that models its durability, atomicity, crash-window, and fail-closed semantics (`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_backend.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_238_governance_evaluator_replay_durable_backend_tests.rs`, 68 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_238.md`). It adds `DurableBackendDecisionInput`/`DurableBackendDecisionExpectations` (derived from a Run 230 `EvaluatorReplayFreshnessInput` via `from_freshness_input`, carrying the Run 230 `replay_state_key_digest`); the typed `DurableRecordState`/`DurableBackendOutcome`/`DurableConsumeOutcome`/`CrashWindow`/`DurableBackendKind`/`DurableMutationCompletion` enums; reader/writer/atomic traits and the pure operations `read_decision_state`/`observe_decision_if_absent`/`mark_consumed_after_success`/`compare_and_mark_consumed`. The durable backend boundary does not extend authority: it grants no new actor the ability to apply trust. The fixture durable backend is DevNet/TestNet source-test only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused and never observes or consumes even when the would-be replay state is fresh; validator-set rotation remains unsupported. Run 238 is source/test only and implements **no** production persistence — no RocksDB, file format, schema, database migration, or storage-format change; restart durability is modeled only through a source/test fixture snapshot (an in-process value clone). The contract is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so every rejection is non-mutating, and no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS. Release-binary durable-backend evidence is deferred to **Run 239**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_238.md`.

## Run 239 — release-binary governance evaluator replay-state durable backend boundary evidence

Run 239 is the release-binary evidence run for the Run 238 durable replay-state backend boundary (`crates/qbind-node/examples/run_239_governance_evaluator_replay_durable_backend_release_binary_helper.rs`, `scripts/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary.sh`, `docs/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_239.md`). It proves on real `target/release/qbind-node` plus a release-built helper (A1-A25 / R1-R37 corpus, 202 typed checks, `pass=202`, `fail=0`, `verdict: PASS`) that the release-built code exposes and exercises the Run 238 durable backend contract through production library symbols (`read_decision_state`/`observe_decision_if_absent`/`mark_consumed_after_success`/`compare_and_mark_consumed`/`classify_crash_window`, the `DurableBackendDecisionInput`/`DurableBackendDecisionExpectations` binding, the `DurableRecordState`/`DurableBackendOutcome`/`DurableConsumeOutcome`/`CrashWindow`/`DurableBackendKind`/`DurableMutationCompletion` taxonomies, the reader/writer/atomic traits, and the `FixtureDurableReplayBackend` `restart_snapshot`/`from_snapshot` durability model). **The durable backend boundary does not extend authority: it grants no new actor the ability to apply trust.** The fixture durable backend is DevNet/TestNet evidence-only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused and never observes or consumes even when the would-be replay state is fresh; local-operator keys and peer-majority gossip can never satisfy the durable backend policy; validator-set rotation remains unsupported. Run 239 is release-binary evidence only and implements **no** production persistence — no RocksDB, file format, schema, database migration, or storage-format change; restart durability is release-evidenced only through an in-process fixture snapshot value clone (never a file). The contract stays pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so every rejection is non-mutating, and no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 237/235/233/231/229 release behaviour remains compatible; no weakening of Runs 070, 130-238. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_239.md`.
## Run 240 — source/test governance evaluator durable replay backend runtime integration

Run 240 wires the Run 238 typed durable replay-state backend boundary into the Run 236 / 232 / 230 replay/freshness + after-success-only consume runtime path as the **durable state provider** (`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_240_governance_evaluator_replay_durable_runtime_integration_tests.rs`, 63 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_240.md`). **The integrated durable runtime does not extend authority: it grants no new actor the ability to apply trust.** The durable replay backend is integrated as a typed runtime state provider only: the durable read/observe runs **before** mutation authorization, the Run 230 / 232 replay/freshness runtime still gates authorization, a durable compare-and-mark-consumed runs only after a modeled `AppliedSuccessfully` mutation on an exactly-`ObservedFresh` record, a read-only validation surface observes but never consumes, and every determinable crash window fails closed. The fixture durable backend remains DevNet/TestNet source-test only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused even when the durable state reads fresh; local-operator keys and peer-majority gossip can never satisfy the durable runtime policy; validator-set rotation remains unsupported. Run 240 is source/test only and implements **no** real persistent replay backend — no RocksDB, file format, schema, database migration, or storage-format change; the fixture restart snapshot models durability only for source/test evidence (an in-process value clone, never a file). The composition is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so every rejection is non-mutating, and no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 238/236/234/232/230 behaviour remains compatible; no weakening of Runs 070, 130-239. Release-binary durable-runtime integration evidence is deferred to **Run 241**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_240.md`.


## Run 241 — release-binary governance evaluator durable replay backend runtime integration evidence

Run 241 is the release-binary evidence run for the Run 240 source/test durable replay backend runtime integration (`crates/qbind-node/examples/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper.rs`, `scripts/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary.sh`, `docs/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_241.md`). **The release-evidenced integrated durable runtime does not extend authority: it grants no new actor the ability to apply trust.** The release helper proves on real `target/release/qbind-node` plus a release-built helper that the durable replay backend is exercised as a typed runtime state provider only: the durable read/observe runs before mutation authorization, the Run 230 / 232 replay/freshness runtime still gates authorization, a durable compare-and-mark-consumed runs only after a modeled `AppliedSuccessfully` mutation on an exactly-`ObservedFresh` record, a read-only validation surface observes but never consumes, and every determinable crash window fails closed; the helper A1–A27 / R1–R38 corpus passes 203/203. The fixture durable backend remains DevNet/TestNet evidence-only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused even when the durable state reads fresh; local-operator keys and peer-majority gossip can never satisfy the durable runtime policy; validator-set rotation remains unsupported. Run 241 is release-binary evidence only and implements **no** real persistent replay backend — no RocksDB, file format, schema, database migration, or storage-format change; the fixture restart snapshot models durability only for release evidence (an in-process value clone, never a file). The composition is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so every rejection is non-mutating, and no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, the broader regression set, `--lib pqc_authority`, and `--lib` all PASS; existing Run 239/237/235/233/231 release behaviour remains compatible; no weakening of Runs 070, 130–240. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_241.md`.

## Run 242 — source/test governance execution mutation-engine boundary

Run 242 makes the hand-off of an already-authorized governance evaluator decision to a future mutation executor explicit and typed (`crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_242_governance_execution_mutation_engine_tests.rs`, 38 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_242.md`). **The mutation-engine boundary does not extend authority: it grants no new actor the ability to apply trust.** It introduces a typed mutation-engine boundary, not a real production mutation engine. An already-authorized decision is only handed to a mockable `GovernanceMutationExecutor` after the engine refuses MainNet peer-driven apply, honours the legacy no-mutation bypass, validates the full binding (wrong environment/chain/genesis/governance surface/mutation surface/candidate digest/decision digest/proposal id/decision id/authority-domain sequence/lifecycle action, or a malformed candidate, is rejected before apply and never reaches the executor), gates out read-only validation surfaces, and rejects validator-set rotation and policy-change actions as unsupported. Local-operator keys and peer-majority gossip can never satisfy the mutation-engine authority (`local_operator_cannot_satisfy_mutation_engine_authority`, `peer_majority_cannot_satisfy_mutation_engine_authority`); the production/MainNet mutation engines remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused before any mutation attempt. Only a modeled `MutationAppliedSuccessfully` projects to the consume-eligible `DurableMutationCompletion::AppliedSuccessfully`; failed apply, rollback, and ambiguous after-authorization windows never consume. The engine is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker/durable write of its own), so every rejection is non-mutating, and no real governance engine, mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented — there is no RocksDB/file/schema/migration/storage-format or wire/marker/sequence/trust-bundle change. Regression: run_242, run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 240/238/236/234/232/230 behaviour remains compatible; no weakening of Runs 070, 130–241. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_242.md`.
## Run 243 — release-binary governance execution mutation-engine boundary evidence

Run 243 is the release-binary evidence run for the Run 242 governance execution mutation-engine boundary (`crates/qbind-node/examples/run_243_governance_execution_mutation_engine_release_binary_helper.rs`, `scripts/devnet/run_243_governance_execution_mutation_engine_release_binary.sh`, `docs/devnet/run_243_governance_execution_mutation_engine_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_243.md`). **The release-built mutation-engine boundary still does not extend authority: it grants no new actor the ability to apply trust.** On real `target/release/qbind-node` plus a release-built helper it proves the release binary exposes and exercises the Run 242 boundary symbols (`evaluate_governance_mutation_engine`, `recover_governance_mutation_window`, `wire_governance_mutation_engine_callsite`, `project_mutation_outcome_to_durable_completion`, the typed bindings, the `GovernanceMutationEngineKind`/`GovernanceMutationOutcome` taxonomy, the `GovernanceMutationExecutor` trait with `FixtureMutationExecutor`/`ProductionMutationExecutor`/`MainNetMutationExecutor`, and the grep-verifiable invariant helpers): an already-authorized decision is only handed to a mockable executor after the engine refuses MainNet peer-driven apply, honours the legacy no-mutation bypass, validates the full binding (a mismatch is rejected before apply and never reaches the executor), gates out read-only validation surfaces, and rejects validator-set rotation and policy-change actions as unsupported. Local-operator keys and peer-majority gossip can never satisfy the mutation-engine authority; the production/MainNet mutation engines remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused before binding validation and before executor invocation. Only a modeled `MutationAppliedSuccessfully` projects to the consume-eligible `DurableMutationCompletion::AppliedSuccessfully`; authorized-not-applied, failed apply, rollback, and ambiguous after-authorization windows never consume. The harness drives the real release binary to prove the default surfaces make no mutation-engine enablement claims and an invalid governance-execution selector fails closed before mutation; a 32-pattern denylist is proven empty; the release helper corpus passes 206/206. Run 243 also narrowly fixes a Run 242 docs typo (`` `Production`/`MainNetMutationUnavailable` `` → `` `ProductionMutationUnavailable` / `MainNetMutationUnavailable` ``). No real governance engine, mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented — there is no RocksDB/file/schema/migration/storage-format or wire/marker/sequence/trust-bundle change, and no MainNet governance or peer-driven apply enablement. Regression: run_242, run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 242/241 behaviour remains compatible; no weakening of Runs 070, 130–242. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_243.md`.
## Run 244 — source/test governance modeled trust-state mutation applier boundary

Run 244 is **source/test only** (`crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_244_modeled_governance_trust_mutation_applier_tests.rs`, 45 tests; evidence in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_244.md`). **The modeled mutation-applier boundary still does not extend authority: it grants no new actor the ability to apply trust.** It adds the smallest in-memory model of what a future governance mutation applier would do after every Run 242 mutation-engine gate has already passed — it snapshots a modeled trust state (`ModeledGovernanceTrustState`/`ModeledGovernanceTrustSnapshot`/`ModeledGovernanceTrustRoot`), applies a modeled trust-state update (`ModeledGovernanceTrustMutation`), reports the typed `ModeledTrustMutationOutcome`, and projects it through the Run 242 `GovernanceMutationOutcome` into the Run 240 `DurableMutationCompletion`. The modeled applier mutates ONLY the in-memory `ModeledGovernanceTrustState` in DevNet/TestNet fixture tests; it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself. `evaluate_modeled_trust_mutation` refuses MainNet peer-driven apply before any snapshot or applier invocation, validates the binding before any snapshot (a mismatch is a non-mutating reject-before-snapshot that never invokes the applier), never mutates on a read-only validation surface, treats validator-set rotation and policy-change actions as unsupported, and routes production/MainNet applier kinds to callable-but-unavailable/fail-closed; only a modeled `ModeledMutationApplied` becomes consume-eligible while failed apply/rollback/rollback-failed/ambiguous windows never consume. No real governance engine, production mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Regression: run_244, run_242 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–243. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_244.md`.
## Run 245 — release-binary governance modeled trust-state mutation applier evidence

Run 245 is the release-binary evidence run for the Run 244 source/test governance modeled trust-state mutation applier boundary (`crates/qbind-node/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper.rs`, `scripts/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary.sh`, `docs/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_245.md`). It proves on real `target/release/qbind-node` plus a release-built helper that the release-built code exposes and exercises the Run 244 boundary symbols; the release helper corpus passes 221/221 (accepted/rejection/recovery/projection/modeled-state/reachability). Run 245 changes no authority model: the modeled applier authority remains fixture-only in DevNet/TestNet, the `ProductionModeledTrustMutationApplier`/`MainNetModeledTrustMutationApplier` remain callable-but-unavailable/fail-closed, and local-operator keys and peer-majority gossip can never satisfy the modeled applier authority. The release-built modeled applier still mutates ONLY the in-memory `ModeledGovernanceTrustState` and does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself; binding validation runs before any snapshot (a mismatch is a non-mutating reject-before-snapshot that never invokes the applier), a read-only validation surface never mutates, retiring/revoking a missing root snapshots then rejects before apply with the modeled state unchanged, validator-set rotation and policy-change actions remain unsupported, MainNet peer-driven apply is refused before any snapshot and before applier invocation, and only a modeled `ModeledMutationApplied` projects through `MutationAppliedSuccessfully` to the consume-eligible `DurableMutationCompletion::AppliedSuccessfully` while not-attempted/failed apply/rollback/rollback-failed/ambiguous windows never consume. The harness proves the real release binary's default surfaces and `--help` make no modeled-applier enablement claim and an invalid governance-execution selector fails closed before mutation; a 36-pattern denylist is proven empty. Run 245 also narrowly fixes a Run 244 docs typo (`` `Production`/`MainNetModeledMutationUnavailable` `` → `` `ProductionModeledMutationUnavailable` / `MainNetModeledMutationUnavailable` ``). No real governance engine, production mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format or wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Regression: run_244, run_242, run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–244. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_245.md`.
## Run 246 — source/test governance modeled end-to-end pipeline boundary

Run 246 is **source/test only** (`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_246_governance_modeled_end_to_end_pipeline_tests.rs`, 47 tests; evidence in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_246.md`). **The modeled end-to-end pipeline still does not extend authority: it grants no new actor the ability to apply trust.** It composes the already-landed typed boundaries (Run 226 evaluator/call-site, Run 240 durable replay observation, Run 242 mutation-engine, Run 244 modeled applier) into one ordering/composition layer; it is not a replacement for any existing module. `run_modeled_end_to_end_pipeline` requires evaluator/call-site authorization, durable replay freshness, mutation-engine authorization, and a modeled applier success to all agree before durable consume is authorized (`ModeledApplierAppliedAndDurableConsumeAuthorized`); evaluator success alone, durable replay freshness alone, and mutation-engine authorization alone are each insufficient. The pipeline mutates ONLY the in-memory `ModeledGovernanceTrustState` through the composed Run 244 fixture applier in DevNet/TestNet tests; it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself. MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation; production/MainNet pipeline paths remain callable-but-unavailable/fail-closed; a local-operator key and peer-majority gossip can never satisfy a MainNet pipeline authority; validator-set rotation and policy-change actions remain unsupported; failed apply/rollback/rollback-failed/ambiguous/rejected-replay windows never consume, and a rejection before the applier stage never invokes the applier. No real governance engine, production mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Regression: run_246, run_244 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–245. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_246.md`.
## Run 247 — release-binary governance modeled end-to-end pipeline evidence

Run 247 is the **release-binary evidence** run for the Run 246 source/test governance modeled end-to-end pipeline boundary (`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`). It proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper.rs`, driven by `scripts/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary.sh`) that the release-built code exposes and exercises the Run 246 boundary symbols (`run_modeled_end_to_end_pipeline`, `GovernanceModeledEndToEndPipelineExecutor`, `recover_modeled_end_to_end_pipeline_window`, the typed bindings/stages/classifications, the `GovernanceModeledEndToEndPipelineOutcome` taxonomy, the `GovernanceModeledEndToEndPipelineDecision` result, and all grep-verifiable invariant helpers). MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation; a disabled pipeline / evaluator-call-site policy is a legacy no-mutation, no-consume bypass; durable consume is authorized only after evaluator/call-site authorization, durable replay freshness, mutation-engine authorization, and modeled applier success all agree (the only consume-authorizing outcome is `ModeledApplierAppliedAndDurableConsumeAuthorized`; each predecessor alone is insufficient); every rejection, rejected replay state, rollback, rollback-failed, ambiguous window, unavailable production/MainNet path, and unsupported action never consumes and remains non-mutating, with a rejection before the applier stage leaving the applier invocation count at zero. The release-helper corpus (262 checks: accepted=47, rejection=130, recovery=15, projection=12, stage_ordering=22, non_mutation=16, reachability=20) and the real-binary surface scenarios all PASS, with a 36-pattern denylist proven empty. Run 247 adds **no** production source behaviour change: only an example helper, a harness script, evidence, and narrow doc updates; the release helper remains dead code from the production runtime. **No real production mutation engine, governance execution engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–246.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_247.md`.
## Run 248 — source/test governance modeled durable-consume projection sink boundary

Run 248 is **source/test only**. It extends the Run 246 modeled end-to-end pipeline with a mockable, in-memory consume-receipt **sink** (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_248_modeled_durable_consume_projection_sink_tests.rs`, 68 tests) that models how a future production call site would **record** an after-success-only durable consume *receipt* once the Run 246 pipeline has authorized consume. `evaluate_modeled_durable_consume_projection_sink` orders MainNet peer-driven apply refusal → legacy bypass → pipeline-outcome projection → pre-sink environment/surface binding validation → sink record, and `recover_modeled_durable_consume_projection_sink_window` fails closed on every ambiguous/unknown window. Only the Run 246 `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome creates a sink intent; only `ConsumeReceiptRecorded` authorizes a new modeled receipt-recorded state; a duplicate identical receipt is idempotent (no second receipt) and the same receipt id with a different digest fails closed as equivocation. Every non-success pipeline outcome produces no sink invocation and no receipt; a record failure, rollback, rollback-failed, ambiguous receipt window, unavailable production/MainNet sink path, and unsupported action never consume; rejected sink paths are non-mutating. The DevNet/TestNet `FixtureModeledDurableConsumeProjectionSink` mutates ONLY the in-memory `ModeledDurableConsumeReceiptLedger` and exposes an invocation counter so tests prove non-success paths never invoke it; the production/MainNet sinks are reachable-but-unavailable/fail-closed. **No real persistent replay backend, durable consume backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–247.** Validation: run_248 (68) plus the regression corpus run_246 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_248.md`.

## Run 249 — release-binary governance modeled durable-consume projection sink evidence

## Run 250 — source/test governance modeled durable-consume completion-reporter boundary

Run 250 is **source/test only**. It extends the Run 248 modeled durable-consume projection sink with a mockable, in-memory completion **reporter** (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_250_modeled_durable_consume_completion_reporter_tests.rs`, 88 tests) that models how a future production call site would **report** an after-record-only durable consume *acknowledgement* / completion report once the Run 248 sink has recorded a consume receipt. `evaluate_modeled_durable_consume_completion_reporter` orders MainNet peer-driven apply refusal → legacy bypass → sink-outcome projection → pre-reporter environment/surface binding validation → reporter record, and `recover_modeled_durable_consume_completion_reporter_window` fails closed on every ambiguous/unknown window. Only the Run 248 `ConsumeReceiptRecorded` outcome creates a completion-report intent; `ConsumeReceiptDuplicateIdempotent` may only match an already-recorded completion report and never creates a new one; only `CompletionReportRecorded` authorizes a new modeled completion-reported state; a duplicate identical completion report is idempotent (no second report) and the same report id with a different digest fails closed as equivocation. The reporter cannot manufacture MainNet authority: a local operator and a peer majority both fail closed and cannot satisfy MainNet authority. Every non-recording sink outcome produces no reporter invocation and no completion; a record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never complete; rejected reporter paths are non-mutating. The DevNet/TestNet `FixtureModeledDurableConsumeCompletionReporter` mutates ONLY the in-memory `ModeledDurableConsumeCompletionReportLedger` and exposes an invocation counter so tests prove non-recording paths never invoke it; the production/MainNet reporters are reachable-but-unavailable/fail-closed. **No real persistent replay backend, durable consume backend, completion-report backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–249.** Validation: run_250 (88) plus the regression corpus run_248 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_250.md`.

Run 249 is the **release-binary evidence** run for the Run 248 source/test governance modeled durable-consume projection sink boundary (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`). It proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper.rs`, driven by `scripts/devnet/run_249_modeled_durable_consume_projection_sink_release_binary.sh`) that the release-built code exposes and exercises the Run 248 boundary symbols (`evaluate_modeled_durable_consume_projection_sink`, the `GovernanceModeledDurableConsumeProjectionSink` trait and its fixture/production/MainNet sinks, `project_pipeline_outcome_to_consume_sink_intent`, `recover_modeled_durable_consume_projection_sink_window`, the typed bindings/receipt-ledger model, the `GovernanceModeledDurableConsumeSinkOutcome` taxonomy, and all grep-verifiable invariant helpers). MainNet peer-driven apply is refused before any pipeline projection or sink invocation; a disabled sink / pipeline / evaluator-call-site policy is a legacy no-mutation, no-consume, no-receipt bypass; only the Run 246 `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome creates a sink intent and only `ConsumeReceiptRecorded` records a new modeled receipt, while a duplicate identical receipt is idempotent (no second record) and a same-id different-digest receipt fails closed as equivocation; every non-success pipeline outcome, record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet sink path, and unsupported action never consumes and remains non-mutating, with a rejection before the sink stage leaving the sink invocation count at zero. The release-helper corpus (280 checks: accepted=47, rejection=116, recovery=14, projection=25, stage_ordering=14, receipt_ledger=23, non_mutation=18, reachability=23) and the real-binary surface scenarios all PASS, with a 39-pattern denylist proven empty. Run 249 adds **no** production source behaviour change: only an example helper, a harness script, evidence, and narrow doc updates; the release helper remains dead code from the production runtime. **No real durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–248.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_249.md`.

## Run 251 — release-binary governance modeled durable-consume completion-reporter evidence

Run 251 is the **release-binary evidence** run for the Run 250 source/test governance modeled durable-consume completion-reporter boundary (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`). It proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper.rs`, driven by `scripts/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary.sh`) that the release-built code exposes and exercises the Run 250 boundary symbols (`evaluate_modeled_durable_consume_completion_reporter`, `GovernanceModeledDurableConsumeCompletionReporter` / `FixtureModeledDurableConsumeCompletionReporter` / `ProductionModeledDurableConsumeCompletionReporter` / `MainNetModeledDurableConsumeCompletionReporter`, `project_sink_outcome_to_completion_report_intent`, `CompletionReportIntent`, `recover_modeled_durable_consume_completion_reporter_window`, `ModeledDurableConsumeCompletionReportWindow`, the `GovernanceModeledDurableConsumeCompletionReporterInput` / `Expectations` / `Policy` bindings, the `ModeledDurableConsumeCompletionReportLedger` / `Record` / `Snapshot` / `Digest` / `Status` completion-report model, the `GovernanceModeledDurableConsumeCompletionReport` carrier, the `ModeledDurableConsumeCompletionReporterKind` / `ModeledCompletionReportFault` types, the `GovernanceModeledDurableConsumeCompletionReporterOutcome` taxonomy, the `completion_reporter_outcome_authorizes_modeled_completion` / `completion_reporter_outcome_projects_to_durable_completion` predicates, and all grep-verifiable invariant helpers): MainNet peer-driven apply is refused before any pipeline progression, sink invocation, or reporter invocation; a disabled reporter / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement, no-completion bypass with no reporter invocation; only the Run 248 `ConsumeReceiptRecorded` outcome creates a completion-report intent and only `CompletionReportRecorded` records a new modeled completion report, while a duplicate identical completion report is idempotent (no second report) and a same-id different-digest completion report fails closed as equivocation; every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never completes and remains non-mutating, with a rejection before the reporter stage leaving the reporter invocation count at zero. The release-helper corpus (316 checks: accepted=67, rejection=114, recovery=16, projection=37, stage_ordering=14, completion_report_ledger=25, non_mutation=20, reachability=23) and the real-binary surface scenarios (`--help` and default DevNet/TestNet/MainNet smoke surfaces emit no completion-reporter enablement claim; the hidden governance-execution selector still parses; an invalid selector fails closed before mutation) all PASS, with a 43-pattern denylist proven empty. Run 251 adds **no** production source behaviour change: only an example helper, a harness script, evidence, and narrow doc updates. The release helper remains dead code from the production runtime. **No real completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no weakening of Runs 070, 130–250.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_251.md`.
## Run 252 — source/test governance modeled durable-completion finalization-projection boundary

Run 252 is **source/test only** and does **not** change the trust-anchor authority model. It extends the Run 250 modeled durable-consume completion reporter with a mockable, in-memory **finalization projection** (`crates/qbind-node/src/pqc_governance_modeled_durable_completion_finalization_projection.rs`; tests in `crates/qbind-node/tests/run_252_modeled_durable_completion_finalization_projection_tests.rs`, 98 tests) that models how a future production call site would project an after-completion-report-only acknowledgement into a terminal modeled durable-completion-finalized state once the Run 250 reporter has recorded a completion report. The authority surface is unchanged: a **local operator cannot satisfy MainNet authority** (`modeled_finalization_local_operator_cannot_satisfy_mainnet_authority`) and a **peer majority cannot satisfy MainNet authority** (`modeled_finalization_peer_majority_cannot_satisfy_mainnet_authority`); MainNet peer-driven apply is refused before any finalizer invocation; validator-set rotation and policy-change actions remain unsupported. Only the Run 250 `CompletionReportRecorded` outcome creates a finalization intent and only `DurableCompletionFinalized` authorizes a new modeled finalization; the finalization identity binds both the Run 248 sink decision digest and the Run 250 reporter decision digest; the same finalization id with a different digest fails closed as equivocation. The fixture finalizer mutates only the in-memory `ModeledDurableCompletionFinalizationLedger`; the production/MainNet finalizers are reachable-but-unavailable/fail-closed. **No real finalization/durable-consume/completion-report backend; no on-chain proof verifier or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, or session eviction; no weakening of Runs 070, 130–251.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_252.md`.

## Run 253 update — release-binary governance modeled durable-completion finalization-projection evidence

Run 253 is the **release-binary evidence** run for the Run 252 source/test governance modeled durable-completion finalization-projection boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_253_modeled_durable_completion_finalization_projection_release_binary_helper.rs` (driven by `scripts/devnet/run_253_modeled_durable_completion_finalization_projection_release_binary.sh`) that the release-built code exposes and exercises the Run 252 boundary symbols: `evaluate_modeled_durable_completion_finalization_projection`, `project_completion_reporter_outcome_to_finalization_intent`, `recover_modeled_durable_completion_finalization_window`, the typed input/expectation/policy/binding model, the in-memory `ModeledDurableCompletionFinalizationLedger`, the fixture/production/MainNet finalizers, the outcome taxonomy, and all grep-verifiable invariant helpers. The helper corpus PASSes (292 checks: accepted=52, rejection=132, recovery=18, projection=32, stage_ordering=4, finalization_ledger=10, non_mutation=20, reachability=24), release-binary S1-S6 surfaces PASS, and the 43-pattern denylist is empty. Run 253 adds **no** production source behavior change; the helper remains dead code from the production runtime. No real finalization, completion-report, durable consume, persistent replay, production mutation, governance execution, on-chain verifier, KMS/HSM/RemoteSigner, RocksDB/file/schema/migration/storage-format, wire/marker/sequence/trust-bundle, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is enabled. The finalizer does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, or write a marker. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_253.md`.

## Run 254 update — source/test governance modeled durable-completion finalization attestation-projection boundary

Run 254 is **source/test only** and does **not** change the trust-anchor authority model. It extends the Run 252 modeled durable-completion finalization projection with a mockable, in-memory **attestation projection** (`crates/qbind-node/src/pqc_governance_modeled_durable_completion_attestation_projection.rs`; tests in `crates/qbind-node/tests/run_254_modeled_durable_completion_attestation_projection_tests.rs`, 108 tests) that models how a future production call site would project an after-finalization-only acknowledgement into a terminal modeled durable-completion-attested state once the Run 252 finalization projection has recorded a `DurableCompletionFinalized` outcome. The authority surface is unchanged: a **local operator cannot satisfy MainNet authority** (`modeled_attestation_local_operator_cannot_satisfy_mainnet_authority`) and a **peer majority cannot satisfy MainNet authority** (`modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority`); MainNet peer-driven apply is refused before any attestor invocation; validator-set rotation and policy-change actions remain unsupported. Only the Run 252 `DurableCompletionFinalized` outcome creates an attestation intent and only `DurableCompletionAttested` authorizes a new modeled attestation; the attestation identity binds the Run 248 sink decision digest, the Run 250 reporter decision digest, and the Run 252 finalization decision digest; the same attestation id with a different digest fails closed as equivocation. The fixture attestor mutates only the in-memory `ModeledDurableCompletionAttestationLedger`; the production/MainNet attestors are reachable-but-unavailable/fail-closed. **No real attestation/audit-ledger/finalization/durable-consume/completion-report backend; no on-chain proof verifier or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, or session eviction; no weakening of Runs 070, 130–253.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_254.md`.
## Run 255 update — release-binary governance modeled durable-completion attestation-projection evidence

Run 255 is the **release-binary evidence** run for the Run 254 source/test governance modeled durable-completion attestation-projection boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_255_modeled_durable_completion_attestation_projection_release_binary_helper.rs` (driven by `scripts/devnet/run_255_modeled_durable_completion_attestation_projection_release_binary.sh`) that the release-built code exposes and exercises the Run 254 boundary symbols: `evaluate_modeled_durable_completion_attestation_projection`, `project_finalization_outcome_to_attestation_intent`, `recover_modeled_durable_completion_attestation_window`, the typed input/expectation/policy/binding model, the in-memory `ModeledDurableCompletionAttestationLedger`, the fixture/production/MainNet attestors, the outcome taxonomy, and all grep-verifiable invariant helpers. No symbol substitutions were required. The helper corpus PASSes (315 checks: accepted=56, rejection=125, recovery=20, projection=47, stage_ordering=4, attestation_ledger=18, non_mutation=21, reachability=24), release-binary S1-S6 surfaces PASS, and the denylist is empty. Run 255 adds **no** production source behavior change; the helper remains dead code from the production runtime. No real attestation, audit ledger, finalization, completion-report, durable consume, persistent replay, production mutation, governance execution, on-chain verifier, KMS/HSM/RemoteSigner, RocksDB/file/schema/migration/storage-format, wire/marker/sequence/trust-bundle, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is enabled. The attestor does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, or write a marker. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_255.md`.
## Run 256 update — source/test production durable-completion attestation backend interface boundary

Run 256 is **source/test only**. It extends the Run 254 modeled durable-completion attestation projection with a typed, mockable, in-memory **backend interface boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_attestation_backend.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_256_durable_completion_attestation_backend_tests.rs`, 46 tests) that models the first backend-facing interface a future production call site would use **after** the Run 254 `DurableCompletionAttested` outcome has been recorded. It is a backend-interface layer — not a replacement for any existing module. `evaluate_durable_completion_attestation_backend` orders MainNet peer-driven apply refusal → legacy bypass → attestation-outcome projection (`project_attestation_outcome_to_backend_request`) → pre-backend environment/surface binding validation → backend submit, and `recover_durable_completion_attestation_backend_window` fails closed on every ambiguous/unknown window. Only the Run 254 `DurableCompletionAttested` outcome creates a backend request; `DurableCompletionAttestationDuplicateIdempotent` may only match an already-submitted backend record and never creates a new one; only `BackendSubmissionRecorded` authorizes a new modeled backend-submitted state; a duplicate identical submission is idempotent (no second submission) and the same backend record id with a different digest fails closed as equivocation. Every non-attested attestation outcome produces no backend request, no backend invocation, and no submission; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet/external-publication backend path, and unsupported action never submit. The DevNet/TestNet `FixtureDurableCompletionAttestationBackend` mutates ONLY the in-memory `DurableCompletionAttestationBackendLedger` and exposes an invocation counter so tests prove non-attesting and pre-backend-rejected paths never invoke it; the `ProductionDurableCompletionAttestationBackend` / `MainNetDurableCompletionAttestationBackend` / `ExternalPublicationDurableCompletionAttestationBackend` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself; no real persistent replay backend, durable consume backend, completion-report backend, finalization backend, production attestation backend, audit ledger backend, external publication backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_256 (46) plus the regression corpus run_254 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–255. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_256.md`.


## Run 257 update — release-binary governance durable-completion attestation backend interface evidence

Run 257 is the **release-binary evidence** run for the Run 256 source/test production durable-completion attestation backend interface boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_257_durable_completion_attestation_backend_release_binary_helper.rs` (driven by `scripts/devnet/run_257_durable_completion_attestation_backend_release_binary.sh`) that the release-built code exposes and exercises the Run 256 boundary symbols: `evaluate_durable_completion_attestation_backend`, `project_attestation_outcome_to_backend_request`, `recover_durable_completion_attestation_backend_window`, the predicate helpers `backend_outcome_authorizes_durable_attestation_submission` / `backend_outcome_projects_to_backend_submission_recorded`, the typed input/expectation/policy/kind/identity/request/response/receipt/record/digest model, the in-memory `DurableCompletionAttestationBackendLedger`, the fixture/production/MainNet/external-publication backends, the outcome/intent/fault taxonomy, and all grep-verifiable invariant helpers. No symbol substitutions were required. The helper corpus PASSes (407 checks: accepted=68, rejection=153, recovery=24, projection=74, stage_ordering=5, backend_ledger=24, non_mutation=24, reachability=35), release-binary S1-S6 surfaces PASS, and the denylist is empty. Run 257 adds **no** production source behavior change; the helper remains dead code from the production runtime. The fixture backend mutates only the in-memory `DurableCompletionAttestationBackendLedger`; production/MainNet/external-publication backends remain reachable but unavailable/fail-closed. No real attestation backend, audit ledger backend, external publication backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/marker/sequence/trust-bundle change, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is enabled. The backend does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, or write a real audit ledger. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_257.md`.## Run 258 update — source/test durable-completion audit-ledger / external-publication receipt boundary

Run 258 is **source/test only**. It extends the Run 256 modeled durable-completion attestation backend interface boundary with a typed, mockable, in-memory **audit-ledger / external-publication receipt boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_audit_publication_receipt.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_258_durable_completion_audit_publication_receipt_tests.rs`, 57 tests) that models the first post-Run-256 backend-submission receipt interface a future production audit ledger or external publication system would use **after** the Run 256 `BackendSubmissionRecorded` outcome has been recorded. It is a receipt-interface layer — not a replacement for any existing module. `evaluate_durable_completion_audit_publication_receipt` orders MainNet peer-driven apply refusal → legacy bypass → backend-outcome projection (`project_backend_submission_outcome_to_audit_receipt_request`) → pre-receipt environment/surface binding validation → receipt record, and `recover_durable_completion_audit_publication_receipt_window` fails closed on every ambiguous/unknown window. Only the Run 256 `BackendSubmissionRecorded` outcome creates a receipt request; `BackendSubmissionDuplicateIdempotent` may only match an already-recorded receipt and never creates a new one; only `AuditReceiptRecorded` authorizes a new modeled audit/publication receipt state; a duplicate identical receipt is idempotent (no second receipt) and the same receipt record id with a different digest fails closed as equivocation. Every non-submitted backend outcome produces no receipt request, no receipt sink invocation, and no receipt; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet audit-ledger/external-publication receipt path, and unsupported action never record. The Run 258 tests attach every recording case to the **actual** Run 256 `BackendSubmissionRecorded` path and the real Run 256 backend identity/request/response/receipt/transcript digests — not a faked, unattached receipt. The DevNet/TestNet `FixtureDurableCompletionAuditPublicationReceiptSink` mutates ONLY the in-memory `DurableCompletionAuditPublicationReceiptLedger` and exposes an invocation counter so tests prove non-submitting and pre-receipt-rejected paths never invoke it; the `ProductionAuditLedgerDurableCompletionReceiptSink` / `MainNetAuditLedgerDurableCompletionReceiptSink` / `ExternalPublicationDurableCompletionReceiptSink` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, or write a real audit ledger; no real audit ledger backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_258 (57) plus the regression corpus run_256 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–257. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_258.md`.## Run 259 update — release-binary governance durable-completion audit-publication receipt interface evidence

Run 259 is the **release-binary evidence** run for the Run 258 source/test durable-completion audit-ledger / external-publication receipt boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_259_durable_completion_audit_publication_receipt_release_binary_helper.rs` (driven by `scripts/devnet/run_259_durable_completion_audit_publication_receipt_release_binary.sh`) that the release-built code exposes and exercises the Run 258 boundary symbols: `evaluate_durable_completion_audit_publication_receipt`, `project_backend_submission_outcome_to_audit_receipt_request`, `recover_durable_completion_audit_publication_receipt_window`, the predicate helpers `audit_receipt_outcome_authorizes_receipt_record` / `audit_receipt_outcome_projects_to_audit_receipt_recorded`, the typed input/expectation/policy/kind/identity/request/response/receipt/record/digest model, the in-memory `DurableCompletionAuditPublicationReceiptLedger`, the fixture/production/MainNet/external-publication receipt sinks, the outcome/intent/fault taxonomy, and all grep-verifiable invariant helpers. Recording cases attach to the **actual** Run 256 `BackendSubmissionRecorded` path and real Run 256 digests. No symbol substitutions were required. The helper corpus PASSes (378 checks: accepted=65, rejection=120, recovery=27, projection=39, stage_ordering=7, receipt_ledger=56, non_mutation=27, reachability=37), release-binary S1-S6 surfaces PASS, and the denylist is empty. Run 259 adds **no** production source behavior change; the helper remains dead code from the production runtime. The fixture receipt sink mutates only the in-memory `DurableCompletionAuditPublicationReceiptLedger`; production/MainNet/external-publication receipt sinks remain reachable but unavailable/fail-closed. No real audit-publication receipt backend, audit ledger backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/marker/sequence/trust-bundle change, MainNet governance, MainNet peer-driven apply, validator-set rotation, or policy change behavior is enabled. The receipt boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, or write a real audit ledger. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_259.md`.

## Run 260 update — source/test durable-completion audit-receipt acknowledgement / external-publication confirmation boundary

Run 260 is **source/test only**. It extends the Run 258 modeled durable-completion audit-ledger / external-publication receipt boundary with a typed, mockable, in-memory **audit-receipt acknowledgement / external-publication confirmation boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_260_durable_completion_audit_receipt_acknowledgement_tests.rs`, 57 tests) that models the first post-Run-258 receipt-consumer acknowledgement interface a future production audit ledger or external publication system would use **after** the Run 258 `AuditReceiptRecorded` outcome has been recorded. It is an acknowledgement-interface layer — not a replacement for any existing module. `evaluate_durable_completion_audit_receipt_acknowledgement` orders MainNet peer-driven apply refusal → legacy bypass → receipt-outcome projection (`project_audit_receipt_outcome_to_acknowledgement_request`) → pre-acknowledgement environment/surface binding validation → acknowledgement record, and `recover_durable_completion_audit_receipt_acknowledgement_window` fails closed on every ambiguous/unknown window. Only the Run 258 `AuditReceiptRecorded` outcome creates an acknowledgement request; `AuditReceiptDuplicateIdempotent` may only match an already-recorded acknowledgement and never creates a new one; only `AcknowledgementRecorded` authorizes a new modeled acknowledgement state; a duplicate identical acknowledgement is idempotent (no second acknowledgement) and the same acknowledgement record id with a different digest fails closed as equivocation. Every non-recorded receipt outcome produces no acknowledgement request, no acknowledgement sink invocation, and no acknowledgement; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet audit-ledger acknowledgement / external-publication confirmation path, and unsupported action never record. The Run 260 tests attach every recording case to the **actual** Run 258 `AuditReceiptRecorded` path (which itself attaches to the actual Run 256 `BackendSubmissionRecorded` path) and the real Run 256 backend and Run 258 receipt identity/request/response/record/transcript digests — not a faked, unattached acknowledgement. The DevNet/TestNet `FixtureDurableCompletionAuditReceiptAcknowledgementSink` mutates ONLY the in-memory `DurableCompletionAuditReceiptAcknowledgementLedger` and exposes an invocation counter so tests prove non-recording and pre-acknowledgement-rejected paths never invoke it; the `ProductionAuditLedgerDurableCompletionAcknowledgementSink` / `MainNetAuditLedgerDurableCompletionAcknowledgementSink` / `ExternalPublicationDurableCompletionConfirmationSink` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, perform a real external-publication confirmation, or write a real audit ledger; no real audit ledger acknowledgement backend, external publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_260 (57) plus the regression corpus run_258 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–259. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_260.md`.

## Run 261 update — release-binary durable-completion audit-receipt acknowledgement / external-publication confirmation evidence

Run 261 is **release-binary evidence for Run 260** — no new production runtime behavior and no new source/test feature boundary. It adds a release-built helper (`crates/qbind-node/examples/run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper.rs`), a harness (`scripts/devnet/run_261_durable_completion_audit_receipt_acknowledgement_release_binary.sh`), an ignored evidence archive (`docs/devnet/run_261_durable_completion_audit_receipt_acknowledgement_release_binary/`, tracking only `README.md`, `summary.txt`, `.gitignore`), and a canonical report (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_261.md`). It proves on real `target/release/qbind-node` plus the release-built helper that the Run 260 audit-receipt acknowledgement / external-publication confirmation boundary symbols are present and exercised in release mode. No symbol substitutions were required. The release helper remains **dead code** from the production runtime and mutates only the in-memory `DurableCompletionAuditReceiptAcknowledgementLedger` through the DevNet/TestNet fixture acknowledgement sink; the `ProductionAuditLedgerDurableCompletionAcknowledgementSink` / `MainNetAuditLedgerDurableCompletionAcknowledgementSink` / `ExternalPublicationDurableCompletionConfirmationSink` remain reachable-but-unavailable/fail-closed. Recording cases attach to the **actual** Run 258 `AuditReceiptRecorded` path (which attaches to the actual Run 256 `BackendSubmissionRecorded` path) and the real Run 256 backend / Run 258 receipt digests. The helper corpus PASSes (256 checks across accepted/rejection/recovery/projection/stage_ordering/acknowledgement_ledger/non_mutation/reachability tables), the S1–S6 real-binary surfaces PASS (S5/S6 expected non-zero; the invalid selector fails closed before any mutation), the denylist (51 forbidden patterns) is empty across captured logs, and run_260 plus run_258 down to run_226, `--lib pqc_authority`, and `--lib` all PASS. Run 261 adds no production source behavior change and enables no real audit-receipt-acknowledgement / audit-ledger-acknowledgement / external-publication-confirmation / audit-publication-receipt / attestation / finalization / completion-report / durable-consume / persistent-replay / production-mutation / governance-execution / on-chain-verifier / KMS / HSM / RemoteSigner backend, no storage/wire/marker/sequence/trust-bundle change, no MainNet governance or peer-driven apply, no validator-set rotation, and no policy change; the acknowledgement boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, perform a real external-publication confirmation, or write a real audit ledger. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_261.md`.## Run 262 update — source/test durable-completion acknowledgement consumer / post-acknowledgement settlement interface boundary

Run 262 is **source/test only**. It extends the Run 260 modeled durable-completion audit-receipt acknowledgement / external-publication confirmation boundary with a typed, mockable, in-memory **acknowledgement consumer / post-acknowledgement settlement interface boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_acknowledgement_consumer.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_262_durable_completion_acknowledgement_consumer_tests.rs`, 57 tests) that models the first post-Run-260 acknowledgement-consumer interface a future production settlement or downstream durable-completion subsystem would use **after** the Run 260 `AcknowledgementRecorded` outcome has been recorded. It is a consumer-interface layer — not a replacement for any existing module. `evaluate_durable_completion_acknowledgement_consumer` orders MainNet peer-driven apply refusal → legacy bypass → acknowledgement-outcome projection (`project_acknowledgement_outcome_to_consumer_request`) → pre-consumer environment/surface binding validation → consumer record, and `recover_durable_completion_acknowledgement_consumer_window` fails closed on every ambiguous/unknown window. Only the Run 260 `AcknowledgementRecorded` outcome creates a consumer request; `AcknowledgementDuplicateIdempotent` may only match an already-recorded consumer record and never creates a new one; only `AcknowledgementConsumed` authorizes a new modeled consumer state; a duplicate identical consumer record is idempotent (no second record) and the same consumer record id with a different digest fails closed as equivocation. Every non-recorded acknowledgement outcome produces no consumer request, no consumer invocation, and no consumer record; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet/external settlement path, and unsupported action never record. The Run 262 tests attach every recording case to the **actual** Run 260 `AcknowledgementRecorded` path (which itself attaches to the actual Run 258 `AuditReceiptRecorded` and Run 256 `BackendSubmissionRecorded` paths) and the real Run 256 backend / Run 258 receipt / Run 260 acknowledgement identity/request/response/record/transcript digests — not a faked, unattached consumer. The DevNet/TestNet `FixtureDurableCompletionAcknowledgementConsumer` mutates ONLY the in-memory `DurableCompletionAcknowledgementConsumerLedger` and exposes an invocation counter so tests prove non-recording and pre-consumer-rejected paths never invoke it; the `ProductionDurableCompletionSettlementConsumer` / `MainNetDurableCompletionSettlementConsumer` / `ExternalDurableCompletionSettlementConsumer` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, perform a real external-publication confirmation, write a real audit ledger, or perform a real settlement; no real settlement backend, audit-ledger acknowledgement backend, external publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_262 (57) plus the regression corpus run_260 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–261. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_262.md`.

## Run 263 update — release-binary durable-completion acknowledgement consumer / post-acknowledgement settlement interface evidence

Run 263 is **release-binary evidence for Run 262** — no new production runtime behavior and no new source/test feature boundary. It adds a release-built helper (`crates/qbind-node/examples/run_263_durable_completion_acknowledgement_consumer_release_binary_helper.rs`), a harness (`scripts/devnet/run_263_durable_completion_acknowledgement_consumer_release_binary.sh`), an ignored evidence archive (`docs/devnet/run_263_durable_completion_acknowledgement_consumer_release_binary/`, tracking only `README.md`, `summary.txt`, `.gitignore`), and a canonical report (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_263.md`). It proves on real `target/release/qbind-node` plus the release-built helper that the Run 262 acknowledgement consumer / post-acknowledgement settlement interface boundary symbols are present and exercised in release mode. No symbol substitutions were required. The release helper remains **dead code** from the production runtime and mutates only the in-memory `DurableCompletionAcknowledgementConsumerLedger` through the DevNet/TestNet fixture consumer; the `ProductionDurableCompletionSettlementConsumer` / `MainNetDurableCompletionSettlementConsumer` / `ExternalDurableCompletionSettlementConsumer` remain reachable-but-unavailable/fail-closed. Recording cases attach to the **actual** Run 260 `AcknowledgementRecorded` path (which attaches to the actual Run 258 `AuditReceiptRecorded` and Run 256 `BackendSubmissionRecorded` paths) and the real Run 256 backend / Run 258 receipt / Run 260 acknowledgement digests via `input.acknowledgement_binding` and `project_acknowledgement_outcome_to_consumer_request`. The helper corpus PASSes across accepted/rejection/recovery/projection/stage_ordering/consumer_ledger/non_mutation/reachability tables, the S1–S6 real-binary surfaces PASS (S5/S6 expected non-zero; the invalid selector fails closed before any mutation), the denylist is empty across captured logs, and run_262 plus run_260 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Run 263 adds no production source behavior change and enables no real settlement / audit-ledger-acknowledgement / external-publication-confirmation / external-publication / audit-publication-receipt / attestation / finalization / completion-report / durable-consume / persistent-replay / production-mutation / governance-execution / on-chain-verifier / KMS / HSM / RemoteSigner backend, no storage/wire/marker/sequence/trust-bundle change, no MainNet governance or peer-driven apply, no validator-set rotation, and no policy change; the consumer boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, perform a real external-publication confirmation, write a real audit ledger, or perform real settlement. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_263.md`.

## Run 264 update — source/test durable-completion consumer settlement-projection sink boundary

Run 264 is **source/test only**. It extends the Run 262 modeled durable-completion acknowledgement consumer / post-acknowledgement settlement interface boundary with a typed, mockable, in-memory **consumer settlement-projection sink boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_consumer_settlement_projection.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_264_durable_completion_consumer_settlement_projection_tests.rs`, 63 tests) that models the first post-Run-262 settlement-projection step a future production settlement subsystem might use **after** the Run 262 `AcknowledgementConsumed` outcome has been recorded, converting a valid consumed-acknowledgement state into a typed settlement-projection intent and modeled in-memory settlement-projection receipt. It is a settlement-projection-interface layer — not a replacement for any existing module. `evaluate_durable_completion_consumer_settlement_projection` orders MainNet peer-driven apply refusal → legacy bypass → consumer-outcome projection (`project_consumer_outcome_to_settlement_projection_request`) → pre-settlement-projection environment/surface binding validation → settlement-projection record, and `recover_durable_completion_consumer_settlement_projection_window` fails closed on every ambiguous/unknown window. Only the Run 262 `AcknowledgementConsumed` outcome creates a settlement-projection request; `AcknowledgementConsumerDuplicateIdempotent` may only match an already-recorded settlement-projection record and never creates a new one; only `SettlementProjectionRecorded` authorizes a new modeled settlement-projection state; a duplicate identical settlement-projection record is idempotent (no second record) and the same settlement-projection record id with a different digest fails closed as equivocation. Every non-recorded consumer outcome produces no settlement-projection request, no settlement-projection invocation, and no settlement-projection record; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet/external settlement-projection path, and unsupported action never record. The Run 264 tests attach every recording case to the **actual** Run 262 `AcknowledgementConsumed` path (which itself attaches to the actual Run 260 `AcknowledgementRecorded`, Run 258 `AuditReceiptRecorded`, and Run 256 `BackendSubmissionRecorded` paths) and the real Run 256 backend / Run 258 receipt / Run 260 acknowledgement / Run 262 consumer identity/request/response/record/transcript digests — not a faked, unattached settlement projection. The DevNet/TestNet `FixtureDurableCompletionConsumerSettlementProjectionSink` mutates ONLY the in-memory `DurableCompletionConsumerSettlementProjectionLedger` and exposes an invocation counter so tests prove non-recording and pre-settlement-projection-rejected paths never invoke it; the `ProductionSettlementProjectionSink` / `MainNetSettlementProjectionSink` / `ExternalSettlementProjectionSink` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, perform a real external-publication confirmation, write a real audit ledger, or perform a real settlement; no real settlement backend, audit-ledger acknowledgement backend, external publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_264 (63) plus the regression corpus run_262 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–263. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_264.md`.
