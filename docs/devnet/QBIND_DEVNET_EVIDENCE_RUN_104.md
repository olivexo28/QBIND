# QBIND DevNet Evidence — Run 104

**Task:** `task/RUN_104_TASK.txt` — Genesis-Bound Authority Key Material Registry for Bundle-Signing Ratification.

**Verdict:** **positive** (full authority key material representation lands; MainNet refuses fingerprint-only bundle-signing roots; canonical genesis hash binds the new field; Run 103 verifier verifies signatures from the genesis-bound public key with no `key_fingerprint` overloading; all required failure cases test-proven at library level; library-level run with no CLI/admin surface, by task design — no release-binary `--print-genesis-hash` regression was needed because the canonical hash framing change is additive and exercised by the existing Run 102 integration tests).

**Anchors:**
- Schema and validation: `crates/qbind-ledger/src/genesis.rs` (new `GenesisAuthorityRoot::public_key_hex`, `with_public_key_bytes`, `authority_public_key_fingerprint`, `MissingPublicKeyMaterial` / `MalformedPublicKey` / `PublicKeyFingerprintMismatch` / `PublicKeySuiteUnknown` / `DuplicateAuthorityPublicKey` validation arms).
- Canonical hash: same file, `encode_authority_root` extended to `encode_optional_str(buf, root.public_key_hex.as_deref())`.
- Verifier integration: `crates/qbind-ledger/src/bundle_signing_ratification.rs` — `verify_bundle_signing_key_ratification` now prefers `bundle_root.public_key_hex`; preserves Run 103 `AuthorityKeyMaterialUnavailable`; adds `AuthorityKeyMaterialMalformed`.
- Re-exports: `crates/qbind-ledger/src/lib.rs` Run 104 block (`authority_public_key_fingerprint`, three new size constants).
- Test fixtures touched (positive paths only): `crates/qbind-node/src/pqc_boot_genesis.rs`, `crates/qbind-node/tests/run_101_genesis_authority_tests.rs`, `crates/qbind-node/tests/run_102_boot_genesis_wiring_tests.rs`.
- New tests: 17 in-module unit tests (in `genesis.rs` and `bundle_signing_ratification.rs`) + 9 release-binary-facing integration tests in `crates/qbind-node/tests/run_104_authority_key_material_tests.rs`.

---

## 1. Investigation (per `task/RUN_104_TASK.txt` §"Required investigation")

### 1.1 Run 103 boundary — what was missing

Run 103 landed the bundle-signing ratification verifier but explicitly carried the partial boundary:

> If genesis stores only a short fingerprint for a bundle-signing authority root, the verifier cannot verify an ML-DSA-44 signature. It must fail closed with `AuthorityKeyMaterialUnavailable`.

The Run 103 verifier already had a private legacy path that recognised a 2624-hex `key_fingerprint` as the full ML-DSA-44 public key — that path is exactly the "overloading short fingerprint as key material" pattern that Run 104 must close.

### 1.2 What Run 104 changes (and what it does NOT change)

Changes:

- Introduces a structurally separate `public_key_hex` field on `GenesisAuthorityRoot`.
- Adds per-root validation: hex correctness, suite-specific byte length (ML-DSA-44 = 1312 bytes / 2624 hex chars), SHA3-256 fingerprint consistency with `key_fingerprint`.
- MainNet bundle-signing roots MUST carry full `public_key_hex` (TestNet/DevNet remain tolerant for legacy local tests).
- Adds config-level duplicate-PK rejection (no two roots may share `(suite_id, public_key_hex)`).
- Hash-binds `public_key_hex` into `compute_canonical_genesis_hash` via the existing length-prefixed framing.
- Run 103 verifier prefers `public_key_hex`; preserves the legacy 2624-hex `key_fingerprint` fallback for backward-compatible DevNet/TestNet genesis files; adds typed `AuthorityKeyMaterialMalformed`.

Does NOT change:

- The Run 103 verifier surface (`verify_bundle_signing_key_ratification`, `RatificationVerifierInputs`, `RatificationFailure` constructor pattern, canonical preimage / domain separator). Only an additive failure variant is introduced.
- Any trust-bundle apply-path call site.
- Any peer-driven path.
- Any signing-key rotation, revocation, custody, or anti-rollback persistence (all remain Run 105+).
- The `--print-genesis-hash` CLI surface byte layout; the canonical hash *value* changes on any genesis containing a `public_key_hex` field (this is the intended hash binding), but the operator workflow / format is identical.

### 1.3 Suite ID

ML-DSA-44 only (`GENESIS_AUTHORITY_SUITE_ML_DSA_44 = 100`). Unknown suites with a `public_key_hex` are rejected with `PublicKeySuiteUnknown` — no silent acceptance of malformed material.

---

## 2. Source-level proof

### 2.1 Schema (`crates/qbind-ledger/src/genesis.rs`)

```rust
pub struct GenesisAuthorityRoot {
    pub suite_id: GenesisAuthoritySuiteId,
    pub key_fingerprint: String,
    pub label: String,
    #[serde(default)]
    pub not_before_epoch: Option<u64>,
    /// Run 104: optional full PQC authority public key, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
}

pub const GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES: usize = 1312;
pub const GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN: usize = 2624;
pub const GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN: usize = 64;

pub fn authority_public_key_fingerprint(public_key_bytes: &[u8]) -> String { ... }
```

`GenesisAuthorityRoot::with_public_key_bytes(suite_id, &pk_bytes, label)` derives the canonical SHA3-256 fingerprint from the supplied PK bytes, so the on-disk shape is unambiguous by construction.

### 2.2 Per-root validation

`GenesisAuthorityRoot::validate(env, kind)` adds three failure modes when `public_key_hex` is present (`MalformedPublicKey` for hex/length issues, `PublicKeySuiteUnknown` for non-100 suites, `PublicKeyFingerprintMismatch` for SHA3 disagreement) and one new MainNet refusal when it is absent on a bundle-signing root (`MissingPublicKeyMaterial`).

### 2.3 Config-level validation

`GenesisAuthorityConfig::validate_for_environment` now rejects duplicate `(suite_id, public_key_hex)` pairs across the combined root set (`DuplicateAuthorityPublicKey`), in addition to the existing duplicate `(suite_id, key_fingerprint)` rejection.

### 2.4 Canonical hash framing

```rust
fn encode_authority_root(buf: &mut Vec<u8>, root: &GenesisAuthorityRoot) {
    buf.push(root.suite_id);
    encode_length_prefixed_str(buf, &root.key_fingerprint);
    encode_length_prefixed_str(buf, &root.label);
    encode_optional_u64(buf, root.not_before_epoch);
    // Run 104: hash-bind the full PQC authority public key bytes.
    encode_optional_str(buf, root.public_key_hex.as_deref());
}
```

Two genesis configs that differ only in `public_key_hex` (or its presence/absence) produce different canonical hashes — proven by `run_104_canonical_hash_binds_public_key_hex` and `run_104_canonical_hash_distinguishes_with_vs_without_public_key_hex`.

### 2.5 Run 103 verifier integration

`verify_bundle_signing_key_ratification` resolution order (no overloading, no fakery):

1. If `bundle_root.public_key_hex.is_some()` → decode, length-check (1312 bytes for ML-DSA-44), and (when `key_fingerprint.len() == 64`) re-check the SHA3-256 binding at verification time. Any malformity → `AuthorityKeyMaterialMalformed`.
2. Else if `bundle_root.key_fingerprint.len() == 2624` and decodes to 1312 valid bytes → legacy fallback (preserved for DevNet/TestNet backward compatibility).
3. Else → `AuthorityKeyMaterialUnavailable` (unchanged).

No fake verification path is introduced and no fallback authority is consulted under any branch.

---

## 3. Test proof

### 3.1 Library-level (qbind-ledger lib tests)

Total qbind-ledger lib tests: **213 passed** (was 196; +17 Run 104 unit tests).

Run 104 unit tests added in `crates/qbind-ledger/src/genesis.rs::tests`:

- `run_104_authority_public_key_fingerprint_is_sha3_256_lowercase_hex`
- `run_104_with_public_key_bytes_produces_consistent_root`
- `run_104_mainnet_rejects_bundle_signing_root_without_public_key_material`
- `run_104_mainnet_rejects_public_key_with_wrong_length`
- `run_104_mainnet_rejects_public_key_with_non_hex_bytes`
- `run_104_mainnet_rejects_public_key_fingerprint_mismatch`
- `run_104_rejects_duplicate_public_key_across_roots`
- `run_104_testnet_tolerates_missing_public_key_material`
- `run_104_devnet_tolerates_missing_public_key_material`
- `run_104_canonical_hash_binds_public_key_hex`
- `run_104_canonical_hash_distinguishes_with_vs_without_public_key_hex`
- `run_104_serde_roundtrip_preserves_public_key_hex`

Run 104 unit tests added in `crates/qbind-ledger/src/bundle_signing_ratification.rs::tests`:

- `run_104_verifier_uses_public_key_hex_when_present`
- `run_104_verifier_accepts_full_pk_binding_against_clean_root`
- `run_104_verifier_rejects_malformed_public_key_hex`
- `run_104_verifier_rejects_pk_hex_fingerprint_mismatch`
- `run_104_verifier_still_fails_closed_when_only_short_fingerprint_present`

### 3.2 Release-binary-facing integration tests (qbind-node)

New file: `crates/qbind-node/tests/run_104_authority_key_material_tests.rs` — 9 tests covering required §A–§F:

- §A: hash-binding and fingerprint helper canonicality.
- §B: MainNet missing PK / wrong-length PK / fingerprint mismatch.
- §C: duplicate authority root rejection.
- §D: Run 103 verifier accepts ratification signed by a genesis-bound authority key (real ML-DSA-44 keypair).
- §E: tampered `public_key_hex` after the ratification was issued → `AuthorityKeyMaterialMalformed`.
- §F: DevNet permissiveness preservation.

Run 101/102/103 integration suites continue to pass after fixture updates (MainNet test fixtures now construct full-PK authority roots via `GenesisAuthorityRoot::with_public_key_bytes`).

### 3.3 Test run summary (latest)

```
cargo test -p qbind-ledger --lib
test result: ok. 213 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p qbind-node --lib
test result: ok. 1090 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p qbind-node --test run_101_genesis_authority_tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p qbind-node --test run_102_boot_genesis_wiring_tests
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p qbind-node --test run_103_bundle_signing_ratification_tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p qbind-node --test run_104_authority_key_material_tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

(The pre-existing failure in `m16_epoch_transition_hardening_tests.rs` is unrelated to Run 104 — it depends on `RocksDbConsensusStorage` methods that do not exist on the branch, and is present before any Run 104 change.)

### 3.4 Release-binary / process evidence

Run 104 does NOT change the operator-visible release-binary surface (no new CLI flag, no new config key, no new admin endpoint). The Run 102 release-binary evidence (`QBIND_DEVNET_EVIDENCE_RUN_102.md`) continues to apply for boot-time genesis verification; with Run 104 fixtures present, the operator workflow is unchanged except that MainNet genesis files MUST now carry `public_key_hex` for every bundle-signing-authority root (failure surfaces as the existing `BootGenesisVerificationError::AuthorityValidationFailed` shell with the new `MissingPublicKeyMaterial` / `MalformedPublicKey` / `PublicKeyFingerprintMismatch` inner variants — all of which produce a clear `Display` line).

---

## 4. Key security decisions

- **No overloading of `key_fingerprint` as public key bytes.** `key_fingerprint` is the canonical 64-hex SHA3-256 fingerprint when `public_key_hex` is present, enforced by per-root validation. The legacy 2624-hex `key_fingerprint` shape is tolerated only as a DevNet/TestNet verifier fallback and is never accepted on MainNet validation.
- **No production static source-code root anchors.** Authority continues to be read only from the operator-supplied genesis file (unchanged from Run 101/102).
- **Genesis-bound authority key material.** `public_key_hex` is hash-bound into `compute_canonical_genesis_hash`, so any post-publication mutation breaks the canonical hash and is refused by Run 102 boot-time verification.
- **MainNet requires complete material.** `validate_for_environment(Mainnet)` refuses any bundle-signing-authority root without `public_key_hex` (`MissingPublicKeyMaterial`) — fail closed.
- **Transport roots cannot ratify bundle-signing keys.** Unchanged: `find_root` is still scoped to `bundle_signing_authority_roots`; the explicit transport-root rejection branch is preserved (Run 103 §B coverage carries forward).
- **No peer-driven apply.** Nothing in Run 104 changes the peer-candidate validation-only path; no trust-bundle apply call site consumes the ratification verifier (Run 105+ scope).
- **No fakery on missing key material.** When `public_key_hex` is absent and the legacy fallback does not apply, the verifier still returns `AuthorityKeyMaterialUnavailable` — never a fake "ok" path.

---

## 5. Contradictions or inconsistencies

Cross-checked against Run 100/101/102/103, `contradiction.md`, `QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, and the trust-lifecycle runbook. No silent regressions found. Two soft tensions, addressed in updates:

1. Run 101's `key_fingerprint` doc-comment described it as "either full PQC public key bytes OR SHA3-256 fingerprint". Run 104 narrows this on MainNet: `key_fingerprint` is the SHA3-256 fingerprint when `public_key_hex` is present, and any MainNet bundle-signing root MUST have `public_key_hex`. The Run 101 doc-comment has been rewritten in-line and the legacy DevNet/TestNet behavior is documented in the new `GenesisAuthorityRoot` doc-comment.
2. The Run 103 `RatificationFailure::AuthorityKeyMaterialUnavailable` Display string said "(Run 103 boundary)". Updated to refer to the genesis-bound key material registry, with the Run 104 narrowing noted in the doc-comment.

These updates are propagated to `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/whitepaper/contradiction.md`, and `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

---

## 6. Evidence references

- This document: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_104.md`.
- Tests added: 17 in-module unit tests + 9 release-binary-facing integration tests (`run_104_authority_key_material_tests.rs`).
- Tests run: see §3.3 above.
- Release-binary logs: not required (Run 104 has no operator-visible CLI surface change). Run 102 release-binary evidence remains in force; Run 102 integration tests pass against Run 104 fixtures.
- Scripts/harnesses: none added. Test fixtures use deterministic synthetic 1312-byte PKs for pure schema/validation tests and real `MlDsa44Backend::generate_keypair()` for end-to-end verifier tests.

---

## 7. Explicit non-claims

Run 104 does NOT implement:

- ratification enforcement in trust-bundle apply paths;
- signing-key rotation;
- signing-key revocation lifecycle;
- authority anti-rollback persistence;
- KMS/HSM custody;
- peer-driven live apply;
- governance;
- validator-set rotation;
- full C4 closure;
- C5 closure.

---

## 8. Residual risks and next recommended run

Residual risks (unchanged from Run 103, narrowed where noted):

- No anti-rollback persistence for `authority_sequence` / `authority_epoch` — a malicious or buggy operator could downgrade the authority block on local disk. Mitigation today: canonical genesis hash pinning via `--expect-genesis-hash` (Run 102).
- No signing-key rotation or revocation — once a `public_key_hex` is bound at genesis, it remains the bundle-signing authority indefinitely from the protocol's perspective until a future run lands rotation.
- Run 104 only narrows the `AuthorityKeyMaterialUnavailable` boundary; the verifier is still not wired into any trust-bundle apply call site.

Recommended next run: **Run 105 — wire the Run 103 verifier into the trust-bundle acceptance flow in validation-only mode** (still no peer-driven live apply; still no rotation), so that an unratified trust-bundle is refused at acceptance time with a typed reason. Authority anti-rollback persistence and rotation should follow in Runs 106+.