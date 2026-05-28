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