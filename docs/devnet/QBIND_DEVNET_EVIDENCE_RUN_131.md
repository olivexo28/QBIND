# QBIND DevNet Evidence — Run 131

**Subject:** Authority marker v2 extension, pure v1→v2 migration primitive, and Run 130 tracking-doc sync checkpoint.  
**Verdict:** **strongest-positive**  
**Date:** 2026-05-24  
**Task:** `task/RUN_131_TASK.txt`  
**Type:** Implementation (additive marker model + pure helpers; no production surface wiring).

---

## 1. Run 130 doc-sync checkpoint (required first checkpoint)

Run 131 re-verified and synchronized the Run 130 tracking statements in:

- `docs/whitepaper/contradiction.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`

Confirmed and explicitly restated:

- Run 130 implemented v2 schema/types/canonical preimage/domain-separated digest/verifier tests.
- `RatificationV2Failure` typed v2 failures landed.
- v2 verifier is **not** wired into production enforcement surfaces yet.
- marker v2 migration is Run 131 scope.
- production v2 wiring remains Run 132 scope.
- release-binary v2 evidence remains Run 133 scope.
- rotation/revocation lifecycle remains future scope.
- full C4 and C5 remain open.

---

## 2. Source changes (Run 131 scope)

### 2.1 Marker v2 schema/model and versioned representation

File: `crates/qbind-node/src/pqc_authority_state.rs`

Added:

- `AUTHORITY_STATE_DOMAIN_V2`
- `AUTHORITY_STATE_RECORD_VERSION_V2`
- `AUTHORITY_STATE_SCHEMA_VERSION_V2`
- `PersistentAuthorityStateRecordVersioned` (`V1` | `V2`)
- `PersistentAuthorityStateRecordV2` with explicit v2 fields:
  - `record_version`
  - `authority_schema_version`
  - `environment`
  - `chain_id`
  - `genesis_hash`
  - `authority_root_fingerprint`
  - `authority_root_suite_id`
  - `active_bundle_signing_key_fingerprint`
  - `active_bundle_signing_key_suite_id`
  - `latest_authority_domain_sequence`
  - `latest_lifecycle_action`
  - `previous_bundle_signing_key_fingerprint`
  - `latest_ratification_v2_digest`
  - `revoked_key_metadata`
  - `last_update_source`
  - `updated_at_unix_secs`

### 2.2 Deterministic v2 serialization/digest

File: `crates/qbind-node/src/pqc_authority_state.rs`

Added:

- `canonical_authority_state_v2_preimage(...)`
- `canonical_authority_state_v2_digest(...)`

Properties:

- domain-separated from v1 via `QBIND:AUTHORITY-STATE:v2`;
- stable length-prefixed encoding;
- includes all security-relevant v2 marker fields;
- no JSON ordering dependency in digest path.

### 2.3 v2 derivation helper from verified Run 130 outputs

File: `crates/qbind-node/src/pqc_authority_state.rs`

Added:

- `AuthorityStateDerivationV2Inputs`
- `AuthorityStateDerivationV2Error` (typed fail-closed refusals)
- `derive_authority_state_v2_from_ratification(...)`

Binding checks implemented:

- runtime environment / chain / genesis must match ratification;
- authority root must match verifier result;
- target key fingerprint/suite must match verifier result;
- authority-domain sequence must match verifier result;
- lifecycle action must match verifier result;
- rotate requires previous key + previous digest;
- revoke requires revocation metadata placeholder.

### 2.4 v2 comparison and migration primitives

File: `crates/qbind-node/src/pqc_authority_state.rs`

Added:

- `AuthorityMarkerV2ComparisonOutcome` (typed accept/reject outcomes)
- `migrate_authority_marker_v1_to_v2(...)`
- `compare_authority_marker_v2(...)`
- `prepare_v2_marker_for_acceptance(...)`
- `parse_versioned_authority_state_record_bytes(...)`
- `load_authority_state_versioned(...)`

Implemented policy outcomes:

- first v2 marker accepted;
- same sequence + same digest idempotent;
- higher sequence accepted;
- lower sequence rejected;
- same sequence + different digest rejected;
- wrong environment/chain/genesis/authority-root rejected;
- wrong key/action linkage rejected;
- v2-after-v1 allowed only via explicit migration helper;
- v1-after-v2 rejected fail-closed;
- malformed/unsupported marker rejected fail-closed.

### 2.5 Cross-crate export update for v2 symbols

File: `crates/qbind-ledger/src/lib.rs`

Added public exports for Run 130 v2 symbols used by Run 131 node helpers:

- `BundleSigningRatificationV2`
- `BundleSigningRatificationV2Action`
- `RatifiedBundleSigningKeyV2`
- `RatificationV2Failure`
- `RatificationV2VerifierInputs`
- `verify_bundle_signing_key_ratification_v2`
- `canonical_ratification_v2_digest`
- v2 domain/version constants

---

## 3. Tests added

File: `crates/qbind-node/src/pqc_authority_state.rs` (`tests::run131`)

Added focused Run 131 tests for:

- v2 digest determinism + v1/v2 domain separation;
- per-field v2 digest sensitivity (env, chain, genesis, root, active key, sequence, action, v2 digest);
- v2 derivation for ratify/rotate/revoke;
- derivation fail-closed cases (missing rotate previous key, wrong domain, wrong target binding);
- v2 comparison outcomes (first/idempotent/higher/lower/same-seq-different-digest/wrong-domain components/malformed);
- v1/v2 migration matrix (v1→v2 explicit allowed, v2→v1 rejected, v1 legacy behavior unchanged, no-marker behavior unchanged).

---

## 4. Validation evidence

Executed and passing:

- `cargo test -p qbind-ledger --lib` → **260 passed**
- `cargo test -p qbind-node --lib` → **1230 passed**
- `cargo test -p qbind-ledger --lib bundle_signing_ratification::tests::v2_` → **28 passed**
- `cargo test -p qbind-node --test run_119_authority_marker_acceptance_tests` → **4 passed**
- `cargo test -p qbind-node --test run_121_sighup_authority_marker_tests` → **7 passed**
- `cargo test -p qbind-node --test run_124_snapshot_restore_authority_marker_tests` → **7 passed**

Baseline note before edits:

- `cargo fmt --all -- --check` reported pre-existing repository formatting drift outside Run 131 scope.

---

## 5. Explicit non-claims (Run 131)

Run 131 does **not** implement:

- production v2 enforcement wiring on startup/reload/SIGHUP/reload-check/peer-candidate/live `0x05`;
- release-binary v2 evidence;
- signing-key rotation lifecycle;
- signing-key revocation lifecycle;
- peer-driven live apply;
- KMS/HSM custody;
- MainNet governance artifact support;
- validator-set rotation;
- full C4 closure;
- C5 closure.
