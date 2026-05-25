# QBIND DevNet Evidence — Run 132

**Subject:** Wire v2 ratification into validation-only surfaces (reload-check, peer-candidate-check).  
**Verdict:** **strongest-positive**  
**Date:** 2026-05-25  
**Task:** `task/RUN_132_TASK.txt`  
**Type:** Implementation (validation-only surface wiring; no mutating-surface wiring; no live-apply persistence).

---

## 1. Scope summary

Run 132 wires the Run 130 v2 bundle-signing-key ratification verifier and
the Run 131 v2 authority marker primitives into the two validation-only
binary surfaces:

- **reload-check** (`--p2p-trust-bundle-reload-check`)
- **peer-candidate-check** (`--p2p-peer-candidate-check`)

These surfaces are validation-only: they verify a candidate trust bundle
against the ratification and authority marker, then exit. They NEVER persist
marker state, write sequences, or apply live trust.

Run 132 explicitly defers:

- **Live-apply (0x05) mutating surface wiring** — deferred to Run 133+.
- **Release-binary evidence** — deferred to Run 133.
- **Rotation/revocation lifecycle** — future scope.

---

## 2. Source changes

### 2.1 Versioned sidecar loader/dispatcher

File: `crates/qbind-node/src/pqc_ratification_input.rs`

Added:

- `VersionedRatificationSidecar` enum (`V1` | `V2`).
- `VersionedRatificationInputError` enum (5 variants: `Io`, `JsonParse`,
  `UnknownSchemaVersion`, `MalformedSidecar`).
- `load_versioned_ratification_from_path()` — reads once, peeks at
  `schema_version` / `version`, dispatches to typed deserialiser. Unknown
  versions fail closed. v1 behaviour unchanged.

The existing `load_ratification_from_path()` is preserved unchanged for
backward compatibility. The versioned loader is a strict superset.

### 2.2 Typed v2 validation-only errors, accept reasons, and marker check

File: `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`

Added:

- `ValidationOnlyMarkerV2Error` enum (11 variants covering unknown schema,
  malformed sidecar, v2 verifier failure, v2 marker derivation failure,
  v2 marker comparison failure, v1-after-v2 downgrade refusal, lower
  sequence, same-sequence-different-digest equivocation, unsupported
  marker version, corrupt local marker).
- `ValidationOnlyMarkerV2AcceptReason` enum (4 variants:
  `NoPersistedMarkerYet`, `Idempotent`, `UpgradeCompatible`,
  `V2AfterV1MigrationCandidate`).
- `ValidationOnlyMarkerV2Inputs` struct.
- `verify_marker_for_validation_only_v2()` — composes Run 130 v2 verifier
  + Run 131 v2 marker derivation + Run 131 v2 marker comparison. Never
  persists marker. Fail-closed on conflict/corruption/wrong-domain.
- `ValidationOnlyVersionedOutcome` and `ValidationOnlyVersionedError` —
  unified v1/v2 dispatch result types.

### 2.3 Run105ReloadCheckContextData extension

File: `crates/qbind-node/src/main.rs`

- Extended `Run105ReloadCheckContextData` with optional `ratification_v2`
  field.
- Updated `build_run_105_reload_check_context()` to use the versioned
  sidecar loader. When the operator-supplied sidecar is `schema_version=2`,
  it populates `ratification_v2` instead of `ratification`.

### 2.4 Preflight function

File: `crates/qbind-node/src/main.rs`

- Added `preflight_run_132_validation_only_v2_marker_check()`:
  1. Verifies v2 ratification via Run 130 verifier.
  2. Derives v2 marker via Run 131 derivation.
  3. Compares against persisted versioned marker.
  4. Returns typed accept/reject. Never persists.

### 2.5 Reload-check wiring

File: `crates/qbind-node/src/main.rs`

- Updated reload-check path to dispatch v1/v2 based on
  `ctx_data.ratification_v2.is_some()`:
  - v2 present → `preflight_run_132_validation_only_v2_marker_check()`
  - v2 absent → existing `preflight_run_123_validation_only_marker_check()`
    (unchanged).

### 2.6 Peer-candidate-check wiring

File: `crates/qbind-node/src/main.rs`

- Updated peer-candidate-check path identically to reload-check: v1/v2
  dispatch, same preflight function, same accept/reject exits.

---

## 3. Tests added (16 new)

### 3.1 Versioned sidecar loader (7 tests)

In `pqc_ratification_input::tests`:

| Test | Asserts |
|------|---------|
| `run132_versioned_loader_dispatches_v1` | v1 sidecar → `V1` variant |
| `run132_versioned_loader_dispatches_v2` | v2 sidecar → `V2` variant |
| `run132_versioned_loader_unknown_version_fails_closed` | version 99 → `UnknownSchemaVersion` |
| `run132_versioned_loader_malformed_json_fails_closed` | bad JSON → `JsonParse` |
| `run132_versioned_loader_missing_version_fails_closed` | no version field → `UnknownSchemaVersion` |
| `run132_versioned_loader_missing_file_fails_closed` | missing file → `Io` |
| `run132_v1_behavior_unchanged_through_versioned_loader` | v1 loader ≡ versioned loader for v1 |

### 3.2 v2 validation-only marker check (9 tests)

In `pqc_authority_marker_acceptance::tests::run132_v2_tests`:

| Test | Asserts |
|------|---------|
| `run132_v2_no_marker_passes_no_persist` | no marker → `NoPersistedMarkerYet`, no file created |
| `run132_v2_after_v1_marker_is_migration_candidate_no_persist` | v2 after v1 → `V2AfterV1MigrationCandidate`, no file change |
| `run132_v1_after_v2_marker_rejects` | v1 after v2 → `V1AfterV2Rejected` |
| `run132_v2_lower_sequence_rejects` | lower seq → `LowerV2SequenceRefused` |
| `run132_v2_same_sequence_same_digest_passes` | same seq/digest → `Idempotent` |
| `run132_v2_same_sequence_different_digest_rejects` | same seq, diff digest → `SameSequenceDifferentDigestRefused` |
| `run132_v2_higher_sequence_passes_no_persist` | higher seq → `UpgradeCompatible`, no file change |
| `run132_corrupt_local_marker_rejects` | corrupt JSON → `CorruptLocalMarker` |
| `run132_v2_no_marker_write_occurs_in_any_case` | no marker write in any path |

---

## 4. Test results

```
qbind-node:   1246 passed; 0 failed; 0 ignored (was 1230 before Run 132)
qbind-ledger:  260 passed; 0 failed; 0 ignored (unchanged)
```

---

## 5. Live-apply (0x05) deferral decision

Run 132 explicitly defers mutating-surface (live-apply, SIGHUP reload,
process-start reload-apply) v2 wiring. The decision is:

- **Validation-only surfaces (reload-check, peer-candidate-check) are
  safe to wire first** because they never persist marker state, never
  write sequences, and exit after the check.
- **Mutating surfaces require additional invariants** (v2 marker
  persistence atomicity, v1→v2 migration persistence, sequence-after-marker
  ordering) that are not yet designed or tested.
- **Live-apply v2 wiring is deferred to Run 133+** to avoid introducing
  persistence bugs on the hot path.

---

## 6. Non-goals (Run 132)

- No mutating-surface v2 wiring.
- No v2 marker persistence from validation-only paths.
- No rotation/revocation lifecycle.
- No release-binary evidence.
- No fast-sync v2 handling.
- No CLI flag changes.
- No wire-format changes.

---

## 7. Invariants maintained

- **No marker persistence from validation-only surfaces.** Verified by
  9 tests that assert no file creation or modification.
- **Fail-closed on unknown schema version.** Verified by loader tests.
- **v1 behaviour unchanged.** v1 sidecar + v1 marker path is fully
  preserved when `ratification_v2` is `None`.
- **v1-after-v2 downgrade refused.** Verified by `run132_v1_after_v2_marker_rejects`.
- **v2-after-v1 explicit migration candidate.** Verified by
  `run132_v2_after_v1_marker_is_migration_candidate_no_persist`.