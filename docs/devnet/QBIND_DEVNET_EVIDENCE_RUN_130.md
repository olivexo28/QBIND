# QBIND DevNet Evidence — Run 130

**Subject:** Ratification v2 schema, canonical preimage, domain-separated digest, and verifier primitive — implementation + unit test evidence.  
**Verdict:** **positive**  
**Date:** 2026-05-24  
**Task:** `task/RUN_130_TASK.txt`  
**Type:** Implementation (additive types + verifier tests; no production wiring).

---

## 1. Exact verdict

**positive.**

Run 130 implements the full Run 129 specification for the ratification v2 schema, canonical preimage, and verifier:

- All v2 types and constants are added.
- The canonical v2 preimage is deterministic, domain-separated, and length-prefixed per the Run 129 spec.
- The v2 verifier is fail-closed: no `Ok` path is reachable unless ALL 11 checks pass, including ML-DSA-44 signature verification.
- 32 new unit tests cover preimage determinism, per-field digest sensitivity, all three lifecycle actions (ratify/rotate/revoke), all typed failure variants, v1 regression, and v1/v2 separation.
- All 260 existing `qbind-ledger` tests pass byte-identically.
- No production enforcement surface is wired to v2.

---

## 2. What changed

### Production source

`crates/qbind-ledger/src/bundle_signing_ratification.rs` — additive additions only:

| Symbol | Kind | Description |
|--------|------|-------------|
| `BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2` | constant | Domain tag `QBIND:BUNDLE-SIGNING-RATIFICATION:v2` |
| `BUNDLE_SIGNING_RATIFICATION_VERSION_V2` | constant | Schema version `2` |
| `BundleSigningRatificationV2Action` | enum | `Ratify` / `Rotate` / `Revoke` with `as_byte()` and `tag()` |
| `BundleSigningRatificationV2` | struct | Full v2 ratification object |
| `ratification_v2_signing_preimage` | fn | Deterministic canonical preimage |
| `canonical_ratification_v2_digest` | fn | SHA3-256 of preimage |
| `RatificationV2Failure` | enum | 22-variant typed failure enum |
| `RatifiedBundleSigningKeyV2` | struct | Typed success result |
| `RatificationV2VerifierInputs` | struct | Verifier input bundle |
| `verify_bundle_signing_key_ratification_v2` | fn | Fail-closed v2 verifier |
| `v2_test_helpers::build_signed_ratification_v2` | fn | Test-only signer (cfg(any(test, feature="test-helpers"))) |

### Documentation

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_130.md` (this file)
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 130 update section added
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 130 section added
- `docs/whitepaper/contradiction.md` — Run 130 tracking entry added

**No other source files changed.**

---

## 3. Implementation details

### 3.1 BundleSigningRatificationV2 fields

```
schema_version                         u32   = 2
environment                            enum  devnet / testnet / mainnet
chain_id                               String
genesis_hash                           [u8; 32]
authority_policy_version               u32
authority_root_fingerprint             String (lowercase hex)
authority_root_suite_id                u8    (100 = ML-DSA-44)
target_bundle_signing_key_fingerprint  String (lowercase hex)
target_bundle_signing_key_suite_id     u8    (100 = ML-DSA-44)
target_bundle_signing_public_key       Vec<u8> (1312 bytes for ML-DSA-44, hex-encoded in JSON)
authority_domain_sequence              u64   (must be >= 1)
key_lifecycle_action                   enum  ratify / rotate / revoke
previous_key_fingerprint               Option<String> (rotate only)
previous_ratification_digest           Option<String> (rotate only; 64-char lowercase hex)
valid_from_epoch                       Option<u64>
valid_until_epoch                      Option<u64>
revocation_reason                      Option<String> (revoke: at least one of reason/scope required)
capabilities_scope                     Option<String>
signature                              Vec<u8> (2420 bytes, hex-encoded in JSON)
```

### 3.2 Canonical preimage layout

```
[domain_tag]                     -- QBIND:BUNDLE-SIGNING-RATIFICATION:v2
[u32 BE: schema_version]
[u32 BE: len(env_tag)][env_tag]
[u32 BE: len(chain_id)][chain_id]
[32: genesis_hash]
[u32 BE: authority_policy_version]
[u32 BE: len(auth_root_fp)][auth_root_fp]
[u8: authority_root_suite_id]
[u32 BE: len(target_fp)][target_fp]
[u8: target_suite_id]
[u32 BE: len(target_pk)][target_pk]  (raw bytes, not hex)
[u64 BE: authority_domain_sequence]
[u8: lifecycle_action_byte]      (0=ratify, 1=rotate, 2=revoke)
[u8: has_previous_key_fp]  [u32 BE: len][previous_key_fp] (if 1)
[u8: has_previous_digest]  [u32 BE: len][previous_digest] (if 1)
[u8: has_revocation_reason] [u32 BE: len][reason] (if 1)
[u8: has_valid_from]  [u64 BE: valid_from_epoch] (if 1)
[u8: has_valid_until] [u64 BE: valid_until_epoch] (if 1)
[u8: has_capabilities_scope] [u32 BE: len][scope] (if 1)
```

Signature field is excluded from the preimage (it is the output of signing this preimage's SHA3-256 digest).

### 3.3 Verifier steps

| Step | Check | Failure variant on error |
|------|-------|--------------------------|
| 1 | `schema_version == 2` | `UnsupportedSchemaVersion` |
| 2a | `environment == expected` | `WrongEnvironment` |
| 2b | `chain_id == expected` | `ChainMismatch` |
| 2c | `genesis_hash == expected` | `GenesisHashMismatch` |
| 3 | `authority_root_suite_id == ML_DSA_44` | `AuthoritySuiteUnsupported` |
| 4 | Authority root in bundle_signing_authority_roots only | `TransportRootNotAllowed` / `AuthorityRootUnknown` |
| 5 | Resolve authority PK (Run 104 resolution order) | `AuthorityKeyMaterialUnavailable` / `AuthorityKeyMaterialMalformed` / `AuthorityFingerprintMismatch` |
| 6 | `target_bundle_signing_key_suite_id == ML_DSA_44` | `TargetKeySuiteUnsupported` |
| 7a | `target_bundle_signing_public_key.len() == 1312` | `MalformedTargetPublicKey` |
| 7b | `sha3_256(target_pk) == target_fingerprint` | `TargetKeyFingerprintMismatch` |
| 8 | `authority_domain_sequence >= 1` | `InvalidAuthorityDomainSequence` |
| 9 | Lifecycle-action field constraints | `UnexpectedRotateFieldsForRatify` / `MissingPreviousKeyForRotate` / `MissingPreviousDigestForRotate` / `MalformedPreviousDigest` / `MissingRevocationFieldsForRevoke` |
| 10 | `signature.len() == 2420` | `MalformedSignature` |
| 11 | ML-DSA-44 verify(authority_pk, sha3_256(preimage), signature) | `SignatureInvalid` |

---

## 4. Test evidence

### Test matrix

| Section | Test | Coverage |
|---------|------|----------|
| A | `v2_preimage_starts_with_v2_domain_tag` | Domain tag content |
| A | `v2_preimage_is_deterministic` | Determinism |
| A | `v2_and_v1_domain_tags_are_distinct` | Domain separation |
| A | `v2_preimage_changes_with_each_security_field` | 13 fields individually mutated |
| A | `v2_preimage_rotate_fields_change_digest` | Rotation linkage fields |
| A | `v2_preimage_revoke_reason_changes_digest` | Revocation fields |
| A | `v2_same_object_produces_same_digest` | Digest determinism |
| B | `v2_ratify_verifies_successfully` | Ratify happy path |
| B | `v2_rotate_verifies_successfully_with_previous_fields` | Rotate happy path |
| B | `v2_revoke_verifies_successfully_with_revoke_fields` | Revoke happy path |
| B | `v2_authority_lookup_uses_bundle_signing_roots_only` | Root set isolation |
| C | `v2_wrong_schema_version_rejected` | UnsupportedSchemaVersion |
| C | `v2_wrong_environment_rejected` | WrongEnvironment |
| C | `v2_wrong_chain_rejected` | ChainMismatch |
| C | `v2_wrong_genesis_rejected` | GenesisHashMismatch |
| C | `v2_unknown_authority_root_rejected` | AuthorityRootUnknown |
| C | `v2_transport_root_rejected` | TransportRootNotAllowed |
| C | `v2_malformed_authority_public_key_rejected` | AuthorityKeyMaterialMalformed |
| C | `v2_target_key_fingerprint_mismatch_rejected` | TargetKeyFingerprintMismatch |
| C | `v2_bad_signature_rejected` | SignatureInvalid |
| C | `v2_missing_authority_domain_sequence_rejected` | InvalidAuthorityDomainSequence (seq=0) |
| C | `v2_rotate_missing_previous_key_rejected` | MissingPreviousKeyForRotate |
| C | `v2_rotate_missing_previous_digest_rejected` | MissingPreviousDigestForRotate |
| C | `v2_ratify_with_unexpected_rotate_fields_rejected` | UnexpectedRotateFieldsForRatify |
| C | `v2_revoke_missing_revoke_fields_rejected` | MissingRevocationFieldsForRevoke |
| C | `v2_malformed_signature_rejected` | MalformedSignature |
| D | `v1_verifier_still_rejects_v2_schema_version` | v1 regression |
| D | `v2_verifier_rejects_v1_schema_version` | v1/v2 separation |
| D | `v2_json_round_trip_preserves_object_and_still_verifies` | Serde round-trip |

### Test run output

All 260 `qbind-ledger` tests pass (`cargo test -p qbind-ledger`):
- 228 pre-existing tests: all pass, unchanged.
- 32 new v2 tests: all pass.
- 0 failures, 0 regressions.

---

## 5. Security invariants confirmed

1. **Domain separation**: `QBIND:BUNDLE-SIGNING-RATIFICATION:v2` prefix is cryptographically distinct from v1; no preimage of any v1 object equals any v2 preimage.
2. **Fail-closed verifier**: every error path in `verify_bundle_signing_key_ratification_v2` returns `Err(RatificationV2Failure::...)`; no `Ok` path is reachable unless ALL 11 checks pass.
3. **Transport root isolation**: `bundle_signing_authority_roots` only; `pqc_transport_roots` entries return `TransportRootNotAllowed` for both v1 and v2 verifiers.
4. **Sequence validity**: `authority_domain_sequence == 0` is refused before any signature check.
5. **Lifecycle field discipline**: rotation fields on a `Ratify` action are refused; rotation fields absent on a `Rotate` action are refused; revocation with no reason/scope is refused.
6. **No parallel crypto stack**: signature verification uses the existing production `MlDsa44SignatureSuite` adapter only.
7. **v1 verifier unchanged**: zero modifications to any code that was part of Run 103/104/105 or earlier; all existing verifier tests pass byte-identically.
8. **No production wiring**: `verify_bundle_signing_key_ratification_v2` is not called from any startup, reload, peer-candidate, or live-inbound surface. No marker persistence change. No CLI change.

---

## 6. Explicit non-changes

Run 130 does NOT:

- Wire v2 into any production enforcement surface (startup preflight, reload-check, peer-candidate-check, live inbound 0x05 handler, SIGHUP reload).
- Modify authority marker persistence (`pqc_authority_state.rs`).
- Modify the authority-state reset CLI (`pqc_authority_state_reset.rs` / `--authority-state-reset`).
- Implement signing-key rotation lifecycle.
- Implement signing-key revocation lifecycle.
- Change any trust-bundle or peer-candidate wire format.
- Implement KMS/HSM custody.
- Implement MainNet governance artifact verification.
- Implement peer-driven live apply.
- Claim full C4 closure.
- Claim C5 closure.
- Weaken any Run 050–129 invariant.

Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority.

---

## 7. Remaining open work

| Run | Description |
|-----|-------------|
| Run 131 | Authority marker v2 extension and migration |
| Run 132 | Production v2 enforcement wiring |
| Run 133 | Release-binary v2 evidence |
| Run 134+ | Signing-key rotation lifecycle |
| Future | Revocation lifecycle, KMS/HSM custody, MainNet governance artifact, peer-driven live apply, full C4 closure, C5 closure |