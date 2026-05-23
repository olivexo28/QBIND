# QBIND DevNet Evidence — Run 127

**Subject:** Offline authority-state reset CLI skeleton with typed refusal cases.
**Verdict:** **positive**
**Date:** 2026-05-23
**Task:** `task/RUN_127_TASK.txt`
**Type:** Source + unit test evidence. Release-binary evidence deferred to Run 128.

---

## 1. Exact verdict

**positive.**

Run 127 implements the Run 126 authority-state reset/recovery specification
skeleton. The `--authority-state-reset` CLI flag is now operative for
DevNet and TestNet. MainNet local reset is refused by default.

---

## 2. Run 126 doc-sync verification (Checkpoint 1)

The task required verifying Run 126 content in three tracking documents before
writing new Run 127 material.

**Verification result:** All three documents already contain explicit Run 126
updates that satisfy the required statements:

| Document | Content |
|----------|---------|
| `docs/whitepaper/contradiction.md` | Run 126 paragraph present (spec-first verdict, refusal cases, environment policy, 13 refusal conditions, audit schema) |
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | Run 126 update section present with ceremony, policy, and C4 status |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | Run 126 operator section present with next-steps table |

**No doc-sync correction was needed.** The Run 126 deliverables already
synchronized all three tracking documents.

---

## 3. New module: `pqc_authority_state_reset`

File: `crates/qbind-node/src/pqc_authority_state_reset.rs`

### 3.1 Typed refusal enum

`AuthorityResetRefusal` has 23 variants:

| Stable ID | When triggered |
|---|---|
| `MissingDataDir` | `--data-dir` absent |
| `MissingGenesisPath` | `--genesis-path` absent |
| `MissingExpectedGenesisHash` | `--expect-genesis-hash` absent |
| `MissingTrustBundle` | `--p2p-trust-bundle` absent |
| `MissingRatification` | `--p2p-trust-bundle-ratification` absent |
| `AuditOutputMissing` | `--authority-state-reset-output-audit` absent |
| `MalformedExpectedGenesisHash` | Hash not parseable as 64 lowercase hex chars |
| `GenesisLoadFailed` | Genesis file I/O or parse error |
| `GenesisHashMismatch` | Computed hash ≠ expected hash |
| `MissingAuthorityConfig` | Genesis has no authority block |
| `InvalidAuthorityConfig` | Authority block fails structural validation |
| `ChainIdMismatch` | Genesis chain_id disagrees with runtime env |
| `MainNetLocalResetUnsupported` | MainNet — fires before any file I/O |
| `InvalidTrustBundle` | Bundle load/validate failed |
| `AuthorityKeyMaterialUnavailable` | Signing-key id not in configured key set |
| `AuthorityKeyMaterialMalformed` | Bundle is DevNet-unsigned |
| `InvalidRatification` | Ratification sidecar load/parse error |
| `RatificationEnforcementFailed` | Run 103/105 enforcement failed |
| `TransportRootNotAllowed` | `LegacyUnratifiedAccepted` (never valid for reset) |
| `TargetMarkerDerivationFailed` | Run 118 derivation error |
| `ExistingMarkerCorrupt` | Corrupt on-disk marker (no auto-repair) |
| `AuditWriteFailed` | Audit file write error |
| `MarkerPersistFailed` | `persist_authority_state_atomic` error |

Every variant implements `stable_id() -> &'static str` and `detail() -> String`.
The stable IDs appear in the `refusal_reason_if_any` field of the audit record
and MUST NOT be renamed without a documented schema migration.

### 3.2 Audit record schema

`AuthorityResetAuditRecord` (17 fields, fixed Serde declaration order):

| Field | Type | Notes |
|---|---|---|
| `record_version` | `u32` | Always 1 in Run 127 |
| `action` | `String` | Always `"authority_state_reset"` |
| `environment` | `String` | `"devnet"` / `"testnet"` / `"mainnet"` |
| `chain_id` | `Option<String>` | 16 lowercase hex chars of runtime chain id |
| `genesis_hash` | `Option<String>` | 64 lowercase hex chars of canonical genesis hash |
| `old_marker_present` | `bool` | Marker file existed before reset |
| `old_marker_raw_sha256` | `Option<String>` | SHA3-256 of old marker file bytes |
| `old_marker_record_if_parseable` | `Option<PersistentAuthorityStateRecord>` | Parsed old marker or null |
| `new_marker_hash` | `Option<String>` | SHA3-256 of canonical authority-state digest |
| `new_marker_record` | `Option<PersistentAuthorityStateRecord>` | Full new marker or null |
| `ratification_hash` | `Option<String>` | `canonical_ratification_digest` hex |
| `trust_bundle_fingerprint` | `Option<String>` | Trust-bundle canonical fingerprint hex |
| `snapshot_metadata_hash_if_any` | `Option<String>` | Always null in Run 127 |
| `operator_note_hash` | `Option<String>` | SHA3-256(operator_note bytes); raw text never stored |
| `binary_sha256_or_unavailable` | `String` | SHA3-256 of binary or `"unavailable"` |
| `binary_build_id_or_unavailable` | `String` | `"qbind-node@<version>"` |
| `result` | `String` | `"success"` / `"refused"` / `"pending"` |
| `refusal_reason_if_any` | `Option<String>` | Stable ID or null |
| `refusal_detail_if_any` | `Option<String>` | Operator detail or null |
| `wall_clock_unix_secs` | `u64` | Informational only |

### 3.3 Entry points

| Function | Pure? | Side-effects |
|---|---|---|
| `verify_authority_reset_inputs` | Yes | None |
| `build_success_audit_record` | Yes | None |
| `build_refusal_audit_record` | Yes | None |
| `write_authority_reset_audit` | No | Atomic tmp+rename write to audit path |
| `execute_authority_state_reset` | No | Audit write + marker persist |

---

## 4. CLI surface

Three new hidden opt-in flags in `cli.rs`:

```
--authority-state-reset                   trigger offline reset ceremony (exits before normal startup)
--authority-state-reset-output-audit      required: path for the audit record JSON
--authority-state-reset-operator-note     optional: ceremony note (stored as SHA3-256 only)
```

Early-exit dispatch in `main.rs` fires **before**:

- `--print-genesis-hash`
- MainNet invariant validation
- P2P trust-bundle startup
- Networking / consensus / metrics / SIGHUP / reload / peer-candidate dispatch

---

## 5. Crash safety

```
verify_authority_reset_inputs()  <-- pure; no disk writes
          |
write audit record (result = "pending")   <-- disk write A
          |
persist_authority_state_atomic()          <-- disk write B
          |
write audit record (result = "success")   <-- disk write C
```

- Crash before A: no disk writes at all.
- Crash between A and B: `result = "pending"` audit artifact; marker unchanged.
- Crash between B and C: marker persisted, audit shows `"pending"`. Operator
  can inspect both to determine outcome.
- Error at B: re-write audit as `"refused"` / `MarkerPersistFailed`; marker
  unchanged (Run 117 atomic write never produces a partial file).
- Error at C: surfaced as `AuditWriteFailed` refusal; marker IS already
  written. Operator can recover by re-running the ceremony.

---

## 6. Environment policy enforcement

### MainNet

Refused immediately after structural input-presence checks, **before opening
any files**. Rationale: minimises side-channels in the audit log (the log
records only the refusal reason, not which files were or were not openable).

```
AuthorityResetRefusal::MainNetLocalResetUnsupported
```

### DevNet / TestNet

Full pipeline runs:

1. Genesis hash recomputation + match against `--expect-genesis-hash`.
2. Genesis authority block extraction.
3. Trust-bundle load via same loader as mutating surfaces.
4. Ratification sidecar load + Run 103/105 enforcement under
   `RatificationEnforcementPolicy::Strict` (never `AllowLegacyUnratified`).
5. Marker derivation via Run 118
   `derive_authority_state_from_ratification(..., AuthorityStateUpdateSource::OperatorReset)`.
6. Existing marker archive (corrupt → refusal, no auto-repair).

---

## 7. Existing marker integrity

Corrupt on-disk markers are surfaced as `ExistingMarkerCorrupt` — the reset
**never** silently auto-repairs a corrupt marker. The operator must remove the
corrupt file out-of-band and re-run the ceremony. This is intentional: an
operator-visible refusal with a paper trail is safer than a silent overwrite.

---

## 8. Non-mutating-surfaces invariant

The `execute_authority_state_reset` function calls
`persist_authority_state_atomic` on exactly one code path — the success path
after verification passes. Every refusal path returns before reaching the call.
This is structurally enforced at the Rust type level (the function returns
`Result<_, _>` and the persist call is in the `Ok` arm of the verification
result).

---

## 9. Tests

18 new unit tests in `pqc_authority_state_reset::tests`:

| Test | What it proves |
|---|---|
| `run127_refuses_when_data_dir_missing` | Correct MissingDataDir refusal |
| `run127_refuses_when_genesis_path_missing` | Correct MissingGenesisPath refusal |
| `run127_refuses_when_expected_hash_missing` | Correct MissingExpectedGenesisHash refusal |
| `run127_refuses_when_trust_bundle_missing` | Correct MissingTrustBundle refusal |
| `run127_refuses_when_ratification_missing` | Correct MissingRatification refusal |
| `run127_refuses_when_audit_output_missing` | Correct AuditOutputMissing refusal |
| `run127_refuses_mainnet_before_any_io` | MainNet refuses before opening non-existent files |
| `run127_refuses_malformed_expected_hash` | Hash parse error with original string preserved |
| `run127_refuses_when_genesis_file_nonexistent` | GenesisLoadFailed on missing file |
| `run127_execute_emits_refusal_audit_for_mainnet_and_no_marker` | Audit record written; marker not written; all fields correct |
| `run127_execute_refuses_without_audit_path_and_no_marker` | AuditOutputMissing; marker not written |
| `run127_audit_record_canonical_json_deterministic_and_no_raw_note` | Serde round-trip is byte-identical; operator note not in raw form |
| `run127_refusal_stable_ids_are_stable` | Stable-id surface contract for 11 structural variants |
| `run127_archive_absent_marker_returns_not_present` | No marker → present=false, sha256=null |
| `run127_archive_corrupt_marker_refuses_and_bytes_unchanged` | Corrupt marker → ExistingMarkerCorrupt; bytes unchanged |
| `run127_parse_expected_hash_accepts_0x_prefix` | 0x-prefixed hash parses correctly |
| `run127_parse_expected_hash_accepts_bare_hex` | Bare hex parses correctly |
| `run127_parse_expected_hash_refuses_wrong_length` | Wrong-length inputs refuse |

**Test results:** 18 / 18 pass. All 126 prior `pqc_authority*` tests pass
byte-identically. No existing test was modified.

---

## 10. Build result

```
cargo build -p qbind-node   →   Finished `dev` profile [unoptimized + debuginfo]
```

Two pre-existing `bincode::config` deprecation warnings (unrelated to Run 127;
already present in Run 126). No new warnings.

---

## 11. Explicit non-changes

- [x] No MainNet governance artifact verification implemented.
- [x] No signing-key rotation or revocation lifecycle implemented.
- [x] No per-key monotonic authority sequence implemented.
- [x] No peer-driven live apply implemented.
- [x] No KMS/HSM implemented.
- [x] No full C4 claimed.
- [x] No C5 claimed.
- [x] No Run 050–126 invariant weakened.
- [x] No wire format changed.
- [x] No persistence format changed.
- [x] No Run 117 marker write primitive changed.
- [x] No Run 118 derivation pipeline changed.
- [x] No Run 119–121 mutating surface wiring changed.
- [x] No Run 123 validation-only behavior changed.
- [x] No Run 124–125 restore conflict enforcement changed.
- [x] No peer-candidate wire format changed.
- [x] No trust-bundle sequence anti-rollback weakened.
- [x] No genesis verification weakened.
- [x] No ratification verifier weakened.
- [x] No static production source-code anchors added.
- [x] Local config alone still not enough for MainNet bundle-signing authority.

---

## 12. Contradictions or inconsistencies

Cross-checked against Runs 100–126, contradiction.md, runbook, and protocol docs.

**No contradictions found.**

Run 127 is fully consistent with the Run 126 specification:

1. All 13 Run 126 mandatory refusal conditions are implemented as typed variants.
2. The environment policy matches the Run 126 §B.1 matrix exactly.
3. The audit schema matches the 17-field Run 126 conceptual schema.
4. The 10 Run 126 reset safety invariants are structurally enforced.
5. MainNet local reset is refused by default (no local-ceremony path).
6. Ratification enforcement always uses `RatificationEnforcementPolicy::Strict`
   (transport roots and legacy ergonomics explicitly refused).
7. No snapshot synthesis path exists.
8. The marker derivation uses `AuthorityStateUpdateSource::OperatorReset`
   via the same Run 118 primitive the mutating surfaces use.

---

## 13. Residual risks and next recommended run

### Residual risks

| Risk | Severity | Mitigation |
|---|---|---|
| Release-binary evidence not yet captured | Low | Deferred to Run 128 per Run 126 plan |
| MainNet governance artifact format undefined | Medium | Intentionally deferred |
| Per-key monotonic schema does not yet exist | Medium | Reset proves key authorization under genesis authority via ratification v1 |
| No test exercises a full DevNet success path (requires real signed bundle + ratification) | Low | Structural refusal tests cover all paths short of full ceremony; Run 128 release-binary evidence will exercise success |
| `AuditWriteFailed` after a successful `MarkerPersistFailed` write leaves the marker but the audit re-write fails | Low | Operator can re-run; marker is always in a valid state |

### Next recommended run

**Run 128:** Capture release-binary evidence for `--authority-state-reset`:

- DevNet success path (real signed bundle + ratification).
- MainNet refusal.
- Missing ratification refusal.
- Wrong genesis hash refusal.
- Corrupt existing marker refusal.

Run 128 should NOT implement:

- MainNet governance artifact verification.
- Ratification v2 monotonic schema.
- Signing-key rotation / revocation.
- KMS / HSM.
- Peer-driven anything.

---

## 14. C4 status after Run 127

**OPEN.** All three mutating surfaces wired and evidenced (Runs 119/120/121/122),
all three validation-only surfaces wired (Run 123), snapshot/restore surface
wired and evidenced (Runs 124/125), reset/recovery specified (Run 126) and
CLI skeleton implemented (Run 127).

Remaining: release-binary evidence for reset (Run 128), `BundleSigningRatification`
v2 per-key monotonic field (Run 129+), signing-key rotation/revocation lifecycle,
peer-driven live apply (intentionally non-mutating), KMS/HSM custody, MainNet
governance artifact design, validator-set rotation, full C4 closure, C5 closure.

---

## 15. Evidence references

| Type | Path |
|---|---|
| Evidence document | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_127.md` (this file) |
| New module | `crates/qbind-node/src/pqc_authority_state_reset.rs` |
| CLI flags | `crates/qbind-node/src/cli.rs` (Run 127 section) |
| Dispatch | `crates/qbind-node/src/main.rs` (Run 127 early-exit block) |
| Module declaration | `crates/qbind-node/src/lib.rs` (Run 127 comment + `pub mod pqc_authority_state_reset`) |
| Authority model update | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 127 section) |
| Runbook update | `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 127 section) |
| Contradiction tracker update | `docs/whitepaper/contradiction.md` (Run 127 paragraph) |
| Task specification | `task/RUN_127_TASK.txt` |