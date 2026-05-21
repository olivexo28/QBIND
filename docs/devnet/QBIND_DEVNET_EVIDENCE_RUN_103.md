# QBIND DevNet Evidence — Run 103

**Task:** `task/RUN_103_TASK.txt` — Minimal Bundle-Signing-Key Ratification Verifier.

**Verdict:** **POSITIVE** (full minimal verifier landed; PQC signature verification works; transport-root rejection proven; all required failure cases test-proven; library-level run with no CLI/admin surface, by task design).

**Anchor:**
- Implementation: `crates/qbind-ledger/src/bundle_signing_ratification.rs` (new module, ~870 lines including helpers and tests).
- Library re-exports: `crates/qbind-ledger/src/lib.rs` (Run 103 block).
- Test-only signer helper feature: `crates/qbind-ledger/Cargo.toml` (`features.test-helpers`).
- Tests: 19 in-module unit tests + 8 integration tests in `crates/qbind-node/tests/run_103_bundle_signing_ratification_tests.rs`.

---

## 1. Investigation (per `task/RUN_103_TASK.txt` §"Required investigation")

### 1.1 Existing bundle-signing verification path

The repository contains trust-bundle signature primitives under
`qbind-net` / `qbind-crypto` (Runs 050–068) and the local-operator
reload lifecycle (Runs 069–075). Crucially, the existing trust-bundle
path takes its bundle-signing public-key input from
*locally-configured operator state* — not from a genesis-bound
authority. That is exactly the gap Run 100 spec §5 / §13 names and
Run 103 must close at the *verifier* level. Run 103 deliberately does
NOT modify any of the existing acceptance surfaces (startup load,
reload-check, reload-apply, SIGHUP, peer-candidate, propagation);
broadening the consumption boundary is Run 104 scope.

### 1.2 Genesis authority root representation (Run 101)

Run 101 added `crates/qbind-ledger/src/genesis.rs`:

- `GenesisAuthorityRoot { suite_id, key_fingerprint, label, not_before_epoch }`.
- `GenesisAuthorityRootKind { Transport, BundleSigning }`.
- `GenesisAuthorityConfig { authority_policy_version, authority_sequence, authority_epoch, pqc_transport_roots, bundle_signing_authority_roots }`.
- `GenesisConfig.authority: Option<GenesisAuthorityConfig>`.
- `compute_canonical_genesis_hash(...)` (domain `QBIND:GENESIS:v1`) hash-binds the authority block.

The `key_fingerprint` field stores either:
- a 64-hex SHA3-256 fingerprint of the authority public key (32 bytes), or
- the full ML-DSA-44 public key bytes hex-encoded (2624 hex = 1312 bytes),
- bounded above by `GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX = 16 KiB`.

**Finding:** signature verification needs the *full* key. When operators
store only the short SHA3 fingerprint, the Run 103 verifier cannot
verify without an additional authority-key-material registry — this is
the documented Run 103 boundary, surfaced as the typed
`RatificationFailure::AuthorityKeyMaterialUnavailable` reason. Run 103
**does not fake** the verification; it fails closed with a precise
operator message.

### 1.3 Existing PQC signature suite abstraction

`crates/qbind-crypto/src/signature.rs` defines `trait SignatureSuite`
(suite_id, public_key_len, signature_len, verify) and
`crates/qbind-crypto/src/ml_dsa44_signature_suite.rs` provides the
production-honest `MlDsa44SignatureSuite` adapter delegating to the
FIPS 204 / ML-DSA-44 `MlDsa44Backend::verify`. Suite id `100` =
ML-DSA-44 (Run 037; mirrored as
`qbind_ledger::GENESIS_AUTHORITY_SUITE_ML_DSA_44`).

**Finding:** reuse `MlDsa44SignatureSuite` directly. No parallel
crypto stack; no classical fallback; no dummy suite; no test-only
verifier in the production path. Run 103 does exactly this.

### 1.4 Canonical encoding conventions

The existing `compute_canonical_genesis_hash` uses a deterministic
binary preimage: domain tag prefix + length-prefixed strings/blobs +
big-endian integers + explicit `Option` tag bytes (`0u8` / `1u8`).
Run 103 mirrors this convention exactly for
`canonical_ratification_preimage` so that no JSON map-order or
whitespace ambiguity can affect the signed digest.

### 1.5 Consumption boundary decision

Run 103 implements the **verifier primitive only**. No CLI flag is
added (no new mutable startup state, no new admin API, no peer-driven
apply, no filesystem watcher). Consumption of
`verify_bundle_signing_key_ratification(...)` from trust-bundle
acceptance paths is explicitly deferred to Run 104. This satisfies the
task's "do not wire into all trust-bundle acceptance paths if doing so
would require broad redesign" rule and avoids weakening Runs 069 / 070
reload contracts.

---

## 2. What was implemented

| Component | File | Behaviour |
|---|---|---|
| `BundleSigningRatification` schema | `crates/qbind-ledger/src/bundle_signing_ratification.rs` | Versioned (`u32 version = 1`), serde-(de)serialisable, with hex-encoded byte fields. Carries `chain_id`, `environment`, `genesis_hash`, `authority_root_fingerprint`, `signature_suite_id`, full `bundle_signing_public_key` + its SHA3-256 fingerprint, and the ML-DSA-44 `signature`. |
| `RatificationEnvironment` | same | Enum (`Devnet`/`Testnet`/`Mainnet`) with stable lowercase JSON tags and a 1-to-1 mapping to/from `NetworkEnvironmentPolicy`. |
| `BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1` | same | Domain separator `b"QBIND:BUNDLE-SIGNING-RATIFICATION:v1"`. |
| `canonical_ratification_preimage` / `canonical_ratification_digest` | same | Deterministic length-prefixed binary preimage and its SHA3-256 digest. Signature field is excluded. |
| `verify_bundle_signing_key_ratification` | same | Narrow verifier API taking `RatificationVerifierInputs { ratification, authority, expected_chain_id, expected_environment, expected_genesis_hash }`. Returns `Result<RatifiedBundleSigningKey, RatificationFailure>`. Fail-closed on every error path. |
| `RatificationFailure` | same | 12 typed accept/reject reasons: `UnsupportedVersion`, `ChainMismatch`, `EnvironmentMismatch`, `GenesisHashMismatch`, `UnsupportedSuite`, `BundleSigningKeyFingerprintMismatch`, `MalformedBundleSigningPublicKey`, `MalformedSignature`, `UnknownAuthorityRoot`, `TransportRootNotAllowed`, `AuthorityRootSuiteMismatch`, `AuthorityKeyMaterialUnavailable`, `BadSignature`, `MissingAuthorityBlock` (no boolean-only result, no "invalid object" catch-all). |
| `classify_authority_root_kind` | same | Diagnostic helper that resolves a fingerprint to `Some(Transport)` / `Some(BundleSigning)` / `None`. The verifier performs the kind check inline; this helper is exposed for operator tooling. |
| `pqc_public_key_fingerprint` | same | SHA3-256 lowercase hex of a PQC public key. Convenience helper. |
| `test_helpers::build_signed_ratification` | same | `cfg(any(test, feature = "test-helpers"))` — mints a fully-signed ratification object via the existing `ml_dsa_44_sign_digest`. Not a production code path. |
| Library re-exports | `crates/qbind-ledger/src/lib.rs` | Added Run 103 block exporting the verifier surface. |
| Cargo feature | `crates/qbind-ledger/Cargo.toml` | `features.test-helpers = []` (used by `qbind-node` dev-deps only). |
| Integration tests | `crates/qbind-node/tests/run_103_bundle_signing_ratification_tests.rs` | 8 release-binary-facing scenarios. |

**Not added (by task design):** no CLI flag, no admin API, no
filesystem watcher, no network listener, no gossip publisher /
subscriber, no `<data_dir>/pqc_authority_state.json`, no trust-bundle
wire-format change, no peer-candidate wire-format change, no metric
family, no new dependency.

---

## 3. What was proven

### 3.1 Source-level proof

- Verifier uses the production `MlDsa44SignatureSuite` adapter
  (`crates/qbind-crypto/src/ml_dsa44_signature_suite.rs`) — no
  parallel crypto stack, no classical signature, no dummy verifier.
- Authority-root lookup only ever consults
  `authority.bundle_signing_authority_roots`; `pqc_transport_roots` is
  consulted **only to produce the precise `TransportRootNotAllowed`
  diagnostic** and is otherwise never accepted.
- Canonical preimage is binary, length-prefixed, big-endian — no
  JSON map-order ambiguity is possible.
- Authority-key material boundary is honest: when genesis stores only
  a short fingerprint, the verifier returns
  `AuthorityKeyMaterialUnavailable` rather than faking verification.
- All return types are typed; the only `bool` in the public surface
  is internal to the `decode_hex` helper.

### 3.2 Test proof

**In-module unit tests (`cargo test -p qbind-ledger --lib bundle_signing_ratification`):**

```
running 19 tests
test bundle_signing_ratification::tests::classify_authority_root_kind_distinguishes_sets ... ok
test bundle_signing_ratification::tests::bundle_signing_key_fingerprint_mismatch_rejected ... ok
test bundle_signing_ratification::tests::authority_root_with_only_short_fingerprint_returns_unavailable ... ok
test bundle_signing_ratification::tests::bad_signature_rejected ... ok
test bundle_signing_ratification::tests::malformed_bundle_signing_public_key_rejected ... ok
test bundle_signing_ratification::tests::known_bundle_signing_root_accepted ... ok
test bundle_signing_ratification::tests::malformed_signature_rejected ... ok
test bundle_signing_ratification::tests::preimage_is_deterministic ... ok
test bundle_signing_ratification::tests::preimage_changes_with_each_consensus_field ... ok
test bundle_signing_ratification::tests::ratification_object_round_trips_through_json ... ok
test bundle_signing_ratification::tests::mutated_preimage_rejected ... ok
test bundle_signing_ratification::tests::unknown_authority_root_rejected ... ok
test bundle_signing_ratification::tests::unsupported_suite_rejected ... ok
test bundle_signing_ratification::tests::transport_root_rejected_as_bundle_signing_authority ... ok
test bundle_signing_ratification::tests::wrong_authority_root_signature_rejected ... ok
test bundle_signing_ratification::tests::unsupported_version_rejected ... ok
test bundle_signing_ratification::tests::wrong_chain_rejected ... ok
test bundle_signing_ratification::tests::wrong_environment_rejected ... ok
test bundle_signing_ratification::tests::wrong_genesis_hash_rejected ... ok

test result: ok. 19 passed; 0 failed; 0 ignored
```

**Integration tests (`cargo test -p qbind-node --test run_103_bundle_signing_ratification_tests`):**

```
running 8 tests
test run_103_scenario_2_wrong_chain_rejected ... ok
test run_103_scenario_1_valid_ratification_accepted ... ok
test run_103_scenario_3_wrong_environment_rejected ... ok
test run_103_scenario_4_unknown_authority_root_rejected ... ok
test run_103_scenario_7_authority_key_material_unavailable ... ok
test run_103_scenario_6_bad_signature_rejected ... ok
test run_103_scenario_5_transport_root_rejected ... ok
test run_103_scenario_8_wrong_genesis_hash_rejected ... ok

test result: ok. 8 passed; 0 failed; 0 ignored
```

**Coverage map (per `task/RUN_103_TASK.txt` §"Required tests"):**

| Task requirement | Test(s) |
|---|---|
| A. canonical preimage deterministic | `preimage_is_deterministic`, Scenario 1 |
| A. domain separator included | `preimage_is_deterministic`, Scenario 1 |
| A. chain/env/genesis/root/key/suite changes alter preimage | `preimage_changes_with_each_consensus_field` |
| A. unsupported version rejected | `unsupported_version_rejected` |
| B. known bundle-signing root accepted | `known_bundle_signing_root_accepted`, Scenario 1 |
| B. unknown authority root rejected | `unknown_authority_root_rejected`, Scenario 4 |
| B. transport root rejected | `transport_root_rejected_as_bundle_signing_authority`, Scenario 5 |
| B. wrong chain / wrong environment rejected | `wrong_chain_rejected`, `wrong_environment_rejected`, Scenarios 2 & 3 |
| C. valid PQC signature accepted | `known_bundle_signing_root_accepted`, Scenario 1 |
| C. bad signature rejected | `bad_signature_rejected`, Scenario 6 |
| C. unsupported suite rejected | `unsupported_suite_rejected` |
| C. mutated preimage rejected | `mutated_preimage_rejected` |
| C. wrong authority root signature rejected | `wrong_authority_root_signature_rejected` |
| D. exact bundle-signing key fingerprint authorised | `known_bundle_signing_root_accepted` asserts returned `RatifiedBundleSigningKey.fingerprint` |
| D. different key fingerprint rejected | `bundle_signing_key_fingerprint_mismatch_rejected`, `mutated_preimage_rejected` |
| D. malformed fingerprint / key material rejected | `malformed_bundle_signing_public_key_rejected`, `malformed_signature_rejected` |
| Run 103 boundary — authority key material unavailable | `authority_root_with_only_short_fingerprint_returns_unavailable`, Scenario 7 |

**Regression (per `task/RUN_103_TASK.txt` §"Regression tests"):**

```
$ cargo test -p qbind-ledger --lib
test result: ok. 196 passed; 0 failed

$ cargo test -p qbind-node --lib
test result: ok. 1090 passed; 0 failed

$ cargo test -p qbind-crypto --lib
test result: ok. 68 passed; 0 failed

$ cargo test -p qbind-node --test run_101_genesis_authority_tests
test result: ok. (all Run 101 tests pass — green)

$ cargo test -p qbind-node --test run_102_boot_genesis_wiring_tests
test result: ok. 14 passed; 0 failed
```

### 3.3 Release-binary / process evidence

Per task §"Release-binary / process evidence": "Run 103 may be mostly
library-level if no CLI/hook is added." Run 103 is library-level by
design — no CLI flag was added (no new admin surface, no new
peer-driven path), so no release-binary smoke captures are produced.
The integration tests in `crates/qbind-node/tests/` exercise the
verifier through the *same* public re-export surface
(`qbind_ledger::verify_bundle_signing_key_ratification`) that the
`qbind-node` binary links against, which is the appropriate
release-binary-facing evidence shape for a verifier-primitive run.

The 8 integration-test scenarios directly mirror the task's listed
Scenarios 1–6 plus two extra boundary scenarios:

| Scenario | Test |
|---|---|
| 1. Valid ratification accepted | `run_103_scenario_1_valid_ratification_accepted` |
| 2. Wrong chain rejected | `run_103_scenario_2_wrong_chain_rejected` |
| 3. Wrong environment rejected | `run_103_scenario_3_wrong_environment_rejected` |
| 4. Unknown authority root rejected | `run_103_scenario_4_unknown_authority_root_rejected` |
| 5. Transport root rejected | `run_103_scenario_5_transport_root_rejected` |
| 6. Bad signature rejected | `run_103_scenario_6_bad_signature_rejected` |
| 7. (boundary) Authority key material unavailable | `run_103_scenario_7_authority_key_material_unavailable` |
| 8. (boundary) Wrong canonical genesis hash rejected | `run_103_scenario_8_wrong_genesis_hash_rejected` |

---

## 4. Key security decisions

- **No production static source-code anchors.** The verifier reads
  authority roots exclusively from the runtime's parsed
  `GenesisConfig.authority.bundle_signing_authority_roots` and has no
  built-in fallback list.
- **Genesis-bound bundle-signing authority roots.** Authority-root
  lookup is restricted to `bundle_signing_authority_roots`. The
  `pqc_transport_roots` set is *queried only to produce the precise
  `TransportRootNotAllowed` diagnostic*; it can never authorise a
  bundle-signing key.
- **PQC-only signature verification.** Verifier accepts only
  `signature_suite_id == GENESIS_AUTHORITY_SUITE_ML_DSA_44 (= 100)`
  and verifies via the existing production `MlDsa44SignatureSuite`
  (FIPS 204). No classical signatures, no dummy suite, no test-only
  verifier on the production path.
- **Transport roots cannot ratify bundle-signing keys.** Enforced both
  by ignoring `pqc_transport_roots` in the accept path and by
  producing a typed `TransportRootNotAllowed` error when a transport
  fingerprint is presented as an authority — tested in
  `transport_root_rejected_as_bundle_signing_authority` and Scenario 5.
- **Local config alone is not MainNet authority.** Run 103 is the
  verifier primitive that Run 104 will use to enforce the Run 100 spec
  requirement; calling `verify_bundle_signing_key_ratification` with
  no ratification object is impossible — every successful return
  carries a `RatifiedBundleSigningKey` bound to a genesis-anchored
  authority root.
- **No peer-driven apply.** Run 103 adds no network listener, no
  gossip publisher / subscriber, no admin API, and no filesystem
  watcher. The verifier is a pure function.
- **Domain separation.** Preimage starts with
  `b"QBIND:BUNDLE-SIGNING-RATIFICATION:v1"`, distinct from
  `b"QBIND:GENESIS:v1"`, the consensus vote domain, and the
  trust-bundle signing domain.
- **Honest key-material boundary.** When genesis carries only a
  fingerprint and not the full PK, the verifier returns
  `AuthorityKeyMaterialUnavailable` — it never fakes verification.

---

## 5. Contradictions or inconsistencies

Cross-checked against Run 100 authority model, Run 101 implementation,
Run 102 boot verification, `contradiction.md`, the runbook, and
whitepaper/protocol docs.

**No contradictions found.** Run 103 strictly narrows existing
language:

- Run 100 spec §5/§7/§13: "production authority must be
  genesis-bound; transport roots cannot authorise bundle-signing
  keys" — **enforced** by the verifier and proven by tests.
- Run 101 contradiction.md update: "Not yet consumed by any live
  ratification verifier — that is Run 102+ scope" → Run 103 lands the
  verifier primitive; the *consumption boundary* (wiring into
  trust-bundle apply paths) remains explicitly Run 104.
- Run 102 spec §18.3: "the minimal ratification verifier skeleton was
  intentionally deferred to Run 103" → addressed by this run.
- Runbook Run 102 closing: "no ratification path, no peer-driven
  apply, no source-code production trust root" — **all preserved**;
  Run 103 adds only a library-level verifier, no operator surface
  change.

---

## 6. Evidence references

- Evidence document: this file (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_103.md`).
- Tests added: 19 unit tests in `crates/qbind-ledger/src/bundle_signing_ratification.rs::tests` + 8 integration tests in `crates/qbind-node/tests/run_103_bundle_signing_ratification_tests.rs`.
- Tests run (all green): qbind-ledger lib (196), qbind-node lib (1090), qbind-crypto lib (68), Run 101 (11), Run 102 (14), Run 103 unit (19), Run 103 integration (8).
- Release-binary logs: not required — Run 103 is library-level by design (no CLI / admin / network surface added). Integration tests link through `qbind-node`'s `Cargo.toml` against the same `qbind_ledger::verify_bundle_signing_key_ratification` re-export the binary links against.
- Scripts / harnesses: none. The `test_helpers::build_signed_ratification` mint helper is gated behind `cfg(any(test, feature = "test-helpers"))` and only consumed by the `qbind-node` dev-dependency on `qbind-ledger`.

---

## 7. Explicit non-claims

Run 103 does **NOT** implement:

- signing-key rotation;
- signing-key revocation lifecycle;
- authority anti-rollback persistence (no `<data_dir>/pqc_authority_state.json`);
- KMS/HSM custody;
- peer-driven live apply (no network listener, no gossip publisher / subscriber);
- governance;
- validator-set rotation;
- full C4 closure;
- C5 closure.

Run 103 does **NOT** modify:

- trust-bundle wire format;
- peer-candidate wire format;
- consensus, fast-sync, or snapshot semantics;
- Run 102 genesis verification (preserved bit-for-bit);
- Run 069 reload-check non-mutation;
- Run 070 reload-apply ordering;
- existing signed-bundle / chain_id / environment / sequence
  anti-rollback / activation-height / `activation_epoch` / Run 065
  minimum-margin / revocation checks.

---

## 8. Residual risks and next recommended run

### Residual risks

1. **Authority-key material boundary.** When operators store only a
   64-hex SHA3 fingerprint in genesis, the verifier cannot perform
   signature verification. The fail-closed behaviour is correct, but
   for a usable production ratification flow either:
   - the operator must include the full ML-DSA-44 public key bytes
     hex-encoded in `bundle_signing_authority_roots[*].key_fingerprint`
     (Run 101 already allows this — see
     `GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX = 16 KiB`), or
   - Run 104 must introduce a separate genesis-bound authority-key
     **material** registry.
2. **Consumption boundary not closed.** Run 103 only provides the
   verifier; existing trust-bundle acceptance surfaces (startup load,
   reload-check, reload-apply, SIGHUP, peer-candidate validation,
   peer-driven propagation) still consume locally-configured signing
   keys directly. Wiring the verifier into those surfaces is Run 104.
3. **No anti-rollback for ratification objects.** Run 103
   intentionally does not include a sequence/activation-epoch field;
   re-issuance / rotation of the *same* bundle-signing key by the
   *same* authority would produce a fresh signed object that the
   verifier accepts without ordering. Acceptable for a pure verifier
   primitive; not acceptable for the apply path. Anti-rollback is
   Run 104+.
4. **No KMS/HSM custody binding.** The verifier accepts any
   well-signed ratification object; it has no opinion about where the
   authority secret key lives. KMS/HSM is Run 105.

### Next recommended run — Run 104

Run 104 candidate scope (verifier-only Run 103 leaves these open):

- Wire `verify_bundle_signing_key_ratification` into the trust-bundle
  acceptance path (startup load + reload-check + reload-apply), behind
  a disabled-by-default flag, validation-only first.
- Introduce `RatifiedSigningKeyRegistry` cache that records the
  accepted `RatifiedBundleSigningKey` identity at startup and gates
  subsequent trust-bundle verifications on a matching ratification.
- Add the authority-key material extension to `GenesisAuthorityRoot`
  (or a separate genesis-bound `authority_key_material[]` block) so
  that operators can store the SHA3 fingerprint AND the full PK
  without overloading `key_fingerprint`'s dual semantics.
- Add anti-rollback by including `authority_sequence` in the
  ratification object and persisting the highest-seen sequence in
  `<data_dir>/pqc_authority_state.json` (Run 100 spec §8).

Run 103 should **not** be claimed as full C4 closure, and **must not**
be claimed as C5 closure.

---

## 9. Verdict

**POSITIVE.** Per the task's verdict rubric:

> Use **positive** if: verifier lands and tests are strong;
> release-binary hook is absent but honestly unnecessary for this
> library-layer run.

Run 103 lands the full minimal verifier (schema, canonical preimage,
typed verifier API, PQC signature verification, authority lookup,
transport-root separation, key-material boundary), proves every
required failure case via unit + integration tests, preserves Run 101
/ Run 102 behaviour bit-for-bit, and adds no operator surface that
would require release-binary smoke evidence. The
`AuthorityKeyMaterialUnavailable` boundary is documented honestly and
surfaced as a typed verifier error rather than fudged.

The verdict is `positive` (not `strongest-positive`) because the
genesis-bound `GenesisAuthorityRoot::key_fingerprint` field overloads
"short fingerprint" and "full key" semantics; cleanly separating those
representations and lifting the `AuthorityKeyMaterialUnavailable`
boundary is Run 104 work.