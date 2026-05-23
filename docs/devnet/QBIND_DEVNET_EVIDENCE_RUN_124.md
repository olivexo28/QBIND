# QBIND Run 124 — Snapshot/Restore Authority Anti-Rollback Marker Conflict Enforcement

**Status:** Positive (source + unit + integration test evidence; release-binary evidence deferred to optional future sub-run, matching the Run 119 → Run 122 pattern).

**Scope:** Wire authority-marker conflict enforcement into the snapshot restore surface (`--restore-from-snapshot`, B3 / B5) so a restore cannot silently roll back, conflict with, or erase the locally persisted ratified bundle-signing authority marker. Compose with the existing B3 validate→materialize pipeline; do not redesign snapshot format; do not implement reset/recovery; do not invent a fake monotonic field; do not touch any wire format.

---

## Run 123 doc-sync verification (first checkpoint per RUN_124_TASK.txt)

Before Run 124 code changes, the three tracking docs were re-read end-to-end to verify the Run 123 review-found issues had been corrected:

| Doc | Status before Run 124 | Verification |
|-----|----------------------|--------------|
| `docs/whitepaper/contradiction.md` | Clean Run 123 paragraph at line 1564 with explicit "snapshot/restore conflict enforcement staged to future run" and "per-key monotonic schema bump staged to future run (likely Run 125+)" wording; explicit correction "per-key monotonic ratification schema bump is future work (Run 125+, not Run 122 as previously referenced)" at line 1641 | ✅ Already clean — no further scrubbing required |
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | `## Run 123 update` section at line 1627; explicit "Run 125+, not Run 122 as previously referenced" footer at line 1641 | ✅ Already clean — no further scrubbing required |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | Clean Run 123 operator section; "Per-key monotonic field schema bump — future run (Run 125+)" | ✅ Already clean — no further scrubbing required |

The historical references to Run 120 / Run 122 in earlier Run 116 / Run 118 / Run 119 / Run 120 paragraphs are preserved verbatim because those paragraphs document the staging plan in effect at the time those runs landed and are part of the audit trail. They are not load-bearing for any current decision and are explicitly corrected by the Run 121 / Run 122 / Run 123 paragraphs and the line-1641 footer in both `contradiction.md` and the authority-model doc.

Run 124 adds an additional, dedicated "Run 124 update" section to each of the three docs that supersedes any remaining staging language with the current state ("snapshot/restore surface wired in Run 124").

---

## Investigation (per RUN_124_TASK.txt §Required investigation)

### 1. Existing snapshot restore path

- `--restore-from-snapshot` lives entirely in `crates/qbind-node/src/snapshot_restore.rs` and is invoked from `crates/qbind-node/src/main.rs` at the `apply_snapshot_restore_if_requested(...)` call site, positioned AFTER `T185` MainNet invariants and AFTER the Run 102 boot-time canonical genesis verification, and BEFORE Run 069 trust-bundle reload, Run 077 peer-candidate check, P2P startup, and the binary-path consensus loop.
- `StateSnapshotMeta` is parsed by `validate_snapshot_dir(snapshot_dir, expected_chain_id)` in `crates/qbind-ledger/src/state_snapshot.rs` (existing T215 validator). The parser already returns the additive Run 117 `authority_state: Option<AuthorityStateSnapshotMeta>` field as part of the meta — there is nothing to add to the parser.
- The local VM-v0 RocksDB state is opened at `<data_dir>/state_vm_v0/` by `materialize_validated_snapshot(...)` (the `VM_V0_STATE_SUBDIR` constant matches `NodeConfig::vm_v0_state_dir()`).
- Run 097 epoch parity restore logic is exercised by `crates/qbind-node/tests/run_097_snapshot_epoch_parity_tests.rs` (8 unit tests in `qbind-ledger`, 7 integration tests in `qbind-node`); Run 124 does not touch the `epoch` field or the snapshot-creation side, so these tests remain green byte-identically.
- Restore acceptance is currently the absence of an `Err(RestoreError)` from `apply_snapshot_restore_if_requested`; the resulting `RestoreOutcome` is threaded into B5 binary-path consensus startup as a `RestoreBaseline`.

### 2. Authority marker storage access during restore

The restore path has access to:

- `data_dir`: passed via `NodeConfig`.
- Local authority marker path: derivable from `data_dir` via the existing `authority_state_file_path(data_dir)` from `pqc_authority_state.rs` (`<data_dir>/pqc_authority_state.json`).
- Local persisted marker load function: existing `load_authority_state(...)` (returns `Ok(None)` on file-absent, fail-closed on corruption/unsupported-version).
- Runtime environment: `config.environment` (`NetworkEnvironment`).
- Chain id: `config.chain_id()` (`ChainId`).
- Genesis hash: previously NOT available to the restore call site as a 64-hex string. **Run 124 narrowly plumbs the canonical Run 101 genesis hash from Run 102's `BootGenesisOutcome::Verified` branch as `canonical_genesis_hash_hex_for_restore: Option<String>` in `main.rs`** and passes it into the restore surface inside the new `RestoreAuthorityContext { runtime_env, runtime_chain_id, runtime_genesis_hash_hex }` struct. When Run 102 took the `SkippedNoExternalGenesis` branch (DevNet/TestNet without `--genesis-path`), the value is `None` and the legacy entry point is used, which itself fail-closes with `AuthorityContextMissing` whenever a pre-existing local marker exists — there is no silent shadowing through the no-context path either.

No other plumbing was needed.

### 3. Snapshot metadata semantics

`AuthorityStateSnapshotMeta` in `crates/qbind-ledger/src/state_snapshot.rs` is a flat record carrying every security-relevant field of `PersistentAuthorityStateRecord` EXCEPT the two informational-only audit fields (`last_update_source`, `updated_at_unix_secs`):

```text
AuthorityStateSnapshotMeta {
  chain_id_hex,
  environment,
  genesis_hash_hex,
  authority_policy_version,
  authority_sequence,
  authority_epoch,
  authority_root_fingerprint,
  ratified_bundle_signing_key_fingerprint,
  ratification_object_hash,
}
```

Reconstructing a comparable `PersistentAuthorityStateRecord` from this block is therefore byte-equivalent at the canonical-digest layer iff every field above agrees, because `canonical_authority_state_digest` (Run 117 §Canonical digest) does NOT include the two informational fields. Run 124 fills those two fields with neutral values (`AuthorityStateUpdateSource::TestOrFixture` + `0`) — neither participates in `canonical_authority_state_digest` nor in `compare_authority_state` equality rules.

Malformed snapshot metadata fails closed at parse: `StateSnapshotMeta::from_json` returns `None` for the whole meta when the `authority_state` block is structurally malformed, which surfaces through `validate_snapshot_dir` as `SnapshotValidationResult::MissingMetadata` and through the restore surface as the existing `RestoreError::SnapshotInvalid(...)` — a snapshot-layer failure, not an authority-check failure.

### 4. Missing metadata policy

- No local marker + no snapshot `authority_state` → **accept** (`NoMarkerEitherSide`). Legacy pre-Run-117 snapshot restoring into a fresh data dir; the next mutating surface will write the marker from the verified ratification.
- Local marker present + no snapshot `authority_state` → **reject fail-closed** (`RejectMissingSnapshotMarker`) on every environment, including DevNet. Accepting would silently shadow or erase the local persisted authority state. Operator recovery is the future `--allow-authority-state-reset` flag (Run 116 spec), explicitly not implemented in Run 124.

### 5. Restore conflict matrix

| # | Local marker | Snapshot `authority_state` | Decision | Variant |
|---|--------------|---------------------------|----------|---------|
| 1 | Absent | Absent | Accept | `NoMarkerEitherSide` |
| 2 | Absent | Present, matches runtime domain | Accept (no synthesis) | `AcceptSnapshotMarkerNoLocal` |
| 3 | Absent | Present, wrong chain/env/genesis | Reject | `RejectSnapshotMarkerWrongDomain { reason }` |
| 4 | Present, runtime domain | Absent | Reject (fail closed) | `RejectMissingSnapshotMarker` |
| 5 | Present, runtime domain | Present, identical | Accept (no rewrite) | `AcceptMatchingMarker` |
| 6 | Present, runtime domain | Present, lower `authority_sequence` | Reject | `RejectConflict(RollbackRefused)` |
| 7 | Present, runtime domain | Present, same `authority_sequence`, different `ratification_object_hash` | Reject | `RejectConflict(SameSequenceConflictingHash)` |
| 8 | Present, runtime domain | Present, same `authority_sequence`, different `ratified_bundle_signing_key_fingerprint` | Reject | `RejectConflict(SameSequenceConflictingKey)` |
| 9 | Present, runtime domain | Present, lower `authority_policy_version` | Reject | `RejectConflict(PolicyVersionRegression)` |
| 10 | Present, wrong-domain for runtime | Either | Reject (before snapshot compare) | `RejectLocalMarkerWrongDomain(...)` |
| 11 | Corrupt JSON / unsupported `record_version` / structurally invalid | Either | Reject (bytes preserved verbatim) | `RejectLocalMarkerCorrupt(AuthorityStateError)` |
| 12 | Present | Present, wrong chain/env/genesis | Reject | `RejectSnapshotMarkerWrongDomain { reason }` |

On every reject the on-disk state under `<data_dir>` is byte-identical to its pre-restore form: no `state_vm_v0` materialization, no `RESTORED_FROM_SNAPSHOT.json` write, and the local marker file bytes (when present) are preserved verbatim.

---

## Implementation summary

### `crates/qbind-node/src/pqc_authority_state.rs`

- New types `SnapshotRestoreAuthorityCheckInputs<'_>` and `SnapshotRestoreAuthorityCheckOutcome` (3 accept variants + 5 reject variants + `Display` + `is_accept` / `is_reject`).
- New pure helper `verify_snapshot_authority_state_for_restore(SnapshotRestoreAuthorityCheckInputs<'_>) -> SnapshotRestoreAuthorityCheckOutcome` that composes the existing Run 117 `load_authority_state` + `validate_record_for_domain` + Run 118 `compare_authority_state` primitives. No new comparison rule, no new digest, no new conflict variant.
- Two small internal helpers `check_snapshot_meta_domain(...)` and `snapshot_meta_to_record(...)` to keep the public surface minimal.

### `crates/qbind-node/src/snapshot_restore.rs`

- New `RestoreError` variants:
  - `AuthorityMarkerConflict(SnapshotRestoreAuthorityCheckOutcome)` — carries the typed reject outcome to the binary.
  - `AuthorityContextMissing` — legacy no-context entry point fail-closes when a pre-existing local marker is on disk.
- New `RestoreAuthorityContext<'_>` borrowed-bundle struct.
- New entry point `restore_from_snapshot_with_authority_marker_check(snapshot_dir, data_dir, expected_chain_id, &RestoreAuthorityContext)` — validates snapshot layout (existing B3 `validate_snapshot_dir`), then runs the Run 124 check, then materializes. On reject, no state copy, no audit-marker write, local marker bytes preserved verbatim.
- New `apply_snapshot_restore_if_requested_with_authority_context(config, &RestoreAuthorityContext)` — production entry point used by the binary.
- Existing `apply_snapshot_restore_if_requested(config)` preserved for back-compat (used by tests that have no genesis context); additionally fail-closes with `AuthorityContextMissing` whenever a pre-existing local `pqc_authority_state.json` exists.
- Existing `restore_from_snapshot(...)` preserved verbatim by refactoring the snapshot-validate and state-materialize steps into shared internal helpers (`validate_snapshot_for_restore`, `materialize_validated_snapshot`) — every prior test continues to pass byte-identically.

### `crates/qbind-node/src/main.rs`

- Capture canonical Run 101 genesis hash from the Run 102 `BootGenesisOutcome::Verified` branch as `canonical_genesis_hash_hex_for_restore: Option<String>` (64-char lowercase hex, no `0x` prefix — matches `PersistentAuthorityStateRecord.genesis_hash`).
- At the restore call site, branch on the option: when `Some(hex)`, call `apply_snapshot_restore_if_requested_with_authority_context(&config, &ctx)`; otherwise (Run 102 `SkippedNoExternalGenesis` branch — DevNet/TestNet without `--genesis-path`), call the legacy `apply_snapshot_restore_if_requested(&config)` which itself fails closed with `AuthorityContextMissing` on a pre-existing local marker.

---

## Tests

### A. Restore helper unit tests (`pqc_authority_state::tests::run124`, 15 new)

All pass:

```
test pqc_authority_state::tests::run124::no_local_no_snapshot_is_legacy_accept ... ok
test pqc_authority_state::tests::run124::no_local_snapshot_present_accepts_without_synthesising_local ... ok
test pqc_authority_state::tests::run124::matching_local_and_snapshot_is_idempotent_accept ... ok
test pqc_authority_state::tests::run124::local_present_snapshot_absent_rejects_fail_closed ... ok
test pqc_authority_state::tests::run124::rollback_snapshot_against_higher_local_rejects ... ok
test pqc_authority_state::tests::run124::same_sequence_conflicting_hash_rejects ... ok
test pqc_authority_state::tests::run124::policy_version_regression_rejects ... ok
test pqc_authority_state::tests::run124::corrupt_local_marker_rejects_and_preserves_bytes ... ok
test pqc_authority_state::tests::run124::unsupported_record_version_local_rejects ... ok
test pqc_authority_state::tests::run124::wrong_domain_local_marker_rejects_before_snapshot_compare ... ok
test pqc_authority_state::tests::run124::snapshot_marker_wrong_chain_rejects ... ok
test pqc_authority_state::tests::run124::snapshot_marker_wrong_genesis_rejects_even_without_local_marker ... ok
test pqc_authority_state::tests::run124::snapshot_marker_wrong_environment_rejects ... ok
test pqc_authority_state::tests::run124::outcome_classification_helpers ... ok
test pqc_authority_state::tests::run124::pure_helper_never_creates_marker_on_accept_paths ... ok

test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured
```

### B. Restore integration tests (`tests/run_124_snapshot_restore_authority_marker_tests.rs`, 7 new)

Drive `restore_from_snapshot_with_authority_marker_check` against real snapshot directories produced by `StateSnapshotter::create_snapshot` + the additive `AuthorityStateSnapshotMeta` block. All pass:

```
test run124_legacy_snapshot_into_fresh_data_dir_is_accepted ... ok
test run124_legacy_snapshot_into_data_dir_with_local_marker_is_rejected ... ok
test run124_matching_snapshot_and_local_marker_accepts_and_preserves_local ... ok
test run124_rollback_snapshot_against_higher_local_is_rejected ... ok
test run124_same_sequence_conflicting_hash_is_rejected ... ok
test run124_corrupt_local_marker_fails_closed_and_preserves_bytes ... ok
test run124_snapshot_with_wrong_domain_is_rejected_even_without_local_marker ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured
```

### C. Snapshot creation tests

Snapshot creation was NOT touched in Run 124 (the Run 117 `AuthorityStateSnapshotMeta` carrier and `StateSnapshotMeta::with_authority_state(...)` builder are sufficient). The existing Run 117 `state_snapshot` tests (10 `run117_*` unit tests) continue to pass byte-identically.

### D. Regression tests

| Suite | Count | Result |
|-------|-------|--------|
| `qbind-node --lib` (whole crate) | 1207 (was 1192; +15 new Run 124 unit tests) | ✅ all pass |
| `b3_snapshot_restore_tests` | 10 | ✅ all pass |
| `b5_restore_aware_consensus_start_tests` | 4 | ✅ all pass |
| `run_112_reload_apply_ratification_tests` | 10 | ✅ all pass |
| `run_114_sighup_live_reload_ratification_tests` | 14 | ✅ all pass |
| `run_119_authority_marker_acceptance_tests` | 4 | ✅ all pass |
| `run_121_sighup_authority_marker_tests` | 7 | ✅ all pass |
| `run_124_snapshot_restore_authority_marker_tests` (new) | 7 | ✅ all pass |

The `m16_epoch_transition_hardening_tests` integration target fails to compile on the base branch (missing `set_inject_write_failure` / `clear_epoch_transition_marker` methods on `RocksDbConsensusStorage`); this is a pre-existing issue verified by stashing the Run 124 changes and re-running the build, and is unrelated to Run 124.

---

## Strict non-goals — confirmed not implemented

- **`--allow-authority-state-reset` operator-recovery flag** — NOT implemented. Run 124 fail-closes the local-marker-present + snapshot-marker-absent case rather than introducing the flag.
- **Synthesis of a local marker from snapshot bytes** — NOT implemented. The restore surface never writes, rewrites, or deletes `<data_dir>/pqc_authority_state.json`.
- **Fake monotonic authority sequence** — NOT implemented. Run 124 carries the Run 117 bounded-protection limit verbatim (same-sequence different-hash is `RejectConflict(SameSequenceConflictingHash)`, NOT a silent upgrade).
- **Signing-key rotation / revocation lifecycle** — NOT implemented.
- **Peer-driven live apply** — NOT implemented. The new helper is not invoked from any peer-driven path.
- **KMS / HSM custody, governance, validator-set rotation** — NOT implemented.
- **Wire format changes** — none.
- **Snapshot or fast-sync broad redesign** — none. Only the snapshot restore acceptance gate is touched; the snapshot format, B3 layout, B5 consensus baseline plumbing, and Run 097 epoch parity are preserved bit-for-bit.
- **MainNet weakening** — none. Local-marker-present + snapshot-marker-absent fails closed on every environment, including DevNet, exactly as MainNet requires.

---

## Statement Run 124 makes true

> Snapshot restore cannot silently downgrade, conflict with, or erase the locally persisted ratified bundle-signing authority marker; conflicting snapshot authority metadata fails closed before restore acceptance.

Proven by:

- Unit tests `pqc_authority_state::tests::run124::*` (15) — pure helper conflict matrix.
- Integration tests `tests/run_124_snapshot_restore_authority_marker_tests.rs` (7) — wired restore entry point against real snapshot directories, including bit-for-bit local-marker-bytes preservation on every reject path and the explicit "no synthesis from snapshot bytes" invariant on accept paths.
- Regression suites preserve B3, B5, Run 097, and every Run 050–123 mutating / validation-only surface byte-identically.

---

## Forward staging

Run 124 narrows the "authority anti-rollback persistence" C4 sub-item to:

> OPEN, all three mutating surfaces wired (Runs 119/120/121, evidenced by Run 122), all three validation-only surfaces wired (Run 123), snapshot/restore surface wired (Run 124); `--allow-authority-state-reset` operator-recovery flag staged to future run; per-key monotonic ratification schema bump staged to future run (Run 125+).

Optional release-binary evidence sub-run (matching the Run 119 → Run 122 evidence-only pattern) may be produced when convenient; it is not a Run 124 blocker.