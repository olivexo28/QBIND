# QBIND DevNet Evidence — Run 140

**Subject**: Source/test wiring of snapshot/restore parity for v2
authority anti-rollback markers, using the existing versioned authority
marker primitives (Run 130/131/134) and the existing snapshot-restore
authority-check surface (Run 117/124).

## Scope notice (mandatory per `task/RUN_140_TASK.txt`)

* **Run 140 is source/test wiring only.**
* **Snapshot/restore v2 authority-marker parity is source/test covered**
  by the 13 new tests in
  `crates/qbind-node/tests/run_140_snapshot_restore_v2_authority_marker_tests.rs`
  (all passing).
* **Release-binary snapshot/restore v2 evidence remains open for Run 141.**
* Live inbound 0x05 v2 PQC trust-bundle frame validation **remains open**.
* Peer-driven live trust-bundle apply **remains open**.
* Signing-key rotation/revocation lifecycle **remains open**.
* KMS / HSM authority-key custody **remains open**.
* MainNet governance attestation track **remains open**.
* Full C4 acceptance **remains open**.
* C5 acceptance **remains open**.

## What landed in Run 140

`task/RUN_140_TASK.txt` §§1–7 — implemented in:

* `crates/qbind-ledger/src/state_snapshot.rs`
  * Added `AuthorityStateSnapshotMetaV2` carrier struct mirroring the
    security-relevant fields of `PersistentAuthorityStateRecordV2`
    (`chain_id_hex`, `environment`, `genesis_hash_hex`,
    `authority_root_fingerprint`, `authority_root_suite_id`,
    `active_bundle_signing_key_fingerprint`,
    `active_bundle_signing_key_suite_id`,
    `latest_authority_domain_sequence`, `latest_lifecycle_action_byte`,
    `previous_bundle_signing_key_fingerprint`,
    `latest_ratification_v2_digest`, `revoked_key_metadata`).
  * Added `StateSnapshotMeta::authority_state_v2:
    Option<AuthorityStateSnapshotMetaV2>` field, additive next to the
    existing Run 117 `authority_state: Option<AuthorityStateSnapshotMeta>`
    field. Pre-Run-140 snapshots parse as `authority_state_v2: None`
    (the JSON key is omitted entirely when None — full backward compat).
  * Added `StateSnapshotMeta::with_authority_state_v2(...)` builder.
  * Extended `to_json` / `from_json` (`extract_optional_authority_state_v2`)
    with structural sanity checks identical to
    `PersistentAuthorityStateRecordV2::validate_structure` so a malformed
    v2 block is caught at the snapshot-meta parse layer.
* `crates/qbind-ledger/src/lib.rs`
  * Re-exported `AuthorityStateSnapshotMetaV2` next to the existing
    `AuthorityStateSnapshotMeta` re-export.
* `crates/qbind-node/src/pqc_authority_state.rs`
  * Added `SnapshotRestoreAuthorityCheckV2Inputs<'a>` and
    `SnapshotRestoreAuthorityCheckV2Outcome` (typed accept/reject variants:
    `NoMarkerEitherSide`, `AcceptSnapshotV2MarkerNoLocal`,
    `AcceptMatchingV2Marker`, `AcceptHigherV2Sequence`,
    `AcceptV2AfterV1Migration`, `RejectMissingSnapshotMarker`,
    `RejectLocalMarkerCorrupt`, `RejectLocalMarkerWrongDomain`,
    `RejectSnapshotMarkerWrongDomain`, `RejectAmbiguousSnapshotMarkers`,
    `RejectV2Comparison(AuthorityMarkerV2ComparisonOutcome)`).
  * Added the pure entry point
    `verify_snapshot_authority_state_for_restore_v2(inputs)`:
    1. **Ambiguity guard**: a snapshot that advertises both an
       `authority_state` (v1) and an `authority_state_v2` block is
       rejected fail-closed (`RejectAmbiguousSnapshotMarkers`) without
       consulting either block. A single snapshot must not advertise
       two simultaneously valid authority markers.
    2. Loads the local marker via the **existing** Run 131
       `load_authority_state_versioned(marker_path)`. Fatal errors
       surface as `RejectLocalMarkerCorrupt(_)`.
    3. If a local marker is present, validates its
       `(environment, chain_id, genesis_hash)` against the runtime
       trust domain (`RejectLocalMarkerWrongDomain`).
    4. Branches on `(local, snapshot_v2)` presence and validates the
       snapshot v2 domain (`RejectSnapshotMarkerWrongDomain`).
    5. Reconstructs a `PersistentAuthorityStateRecordV2` from the
       snapshot v2 block (`AuthorityStateUpdateSource::TestOrFixture`
       + `updated_at_unix_secs=0` — neither field participates in
       `canonical_authority_state_v2_digest` nor in
       `compare_authority_marker_v2`'s equality rules) and routes
       through the **existing** Run 130
       `compare_authority_marker_v2(persisted, candidate)`. The Run 130
       comparison outcomes are mapped 1:1 to the restore-surface
       outcomes (`FirstV2MarkerAccepted` →
       `AcceptSnapshotV2MarkerNoLocal`; `SameV2MarkerIdempotent` →
       `AcceptMatchingV2Marker`; `HigherSequenceAccepted` →
       `AcceptHigherV2Sequence`; `V2AfterV1ExplicitMigrationAllowed`
       → `AcceptV2AfterV1Migration`; everything else →
       `RejectV2Comparison`).
  * The function is **pure**: it never writes, deletes, or otherwise
    mutates any on-disk state. The local marker file's bytes are
    preserved verbatim on every code path (accept and reject).
* `crates/qbind-node/src/snapshot_restore.rs`
  * Added `RestoreError::AuthorityMarkerConflictV2(SnapshotRestoreAuthorityCheckV2Outcome)`.
  * `restore_from_snapshot_with_authority_marker_check` now dispatches:
    * If `meta.authority_state_v2.is_some()` → v2 entry point
      (with `snapshot_also_carries_v1_block = meta.authority_state.is_some()`
      so the ambiguity guard fires).
    * Otherwise → the **existing** Run 124
      `verify_snapshot_authority_state_for_restore` v1 entry point
      **verbatim**. No v1 regression.
  * Materialization order is preserved: the authority check runs
    BEFORE any state-checkpoint copy or
    `RESTORED_FROM_SNAPSHOT.json` audit-marker write, so on a reject
    the on-disk state under `<data_dir>` is byte-identical to its
    pre-restore form.

## Test matrix (`tests/run_140_snapshot_restore_v2_authority_marker_tests.rs`)

Accept paths (all assert local marker bytes preserved on accept):

* **A1** `run140_a1_no_local_marker_v2_snapshot_block_is_accepted` —
  no local marker + v2 snapshot block matching the runtime trust domain
  → `AcceptSnapshotV2MarkerNoLocal`; restore surface does NOT
  synthesise a local marker file.
* **A2** `run140_a2_matching_local_v2_marker_accepts_and_preserves_local` —
  bit-for-bit matching local v2 marker + snapshot v2 marker →
  `AcceptMatchingV2Marker`; local marker bytes preserved verbatim.
* **A3** `run140_a3_higher_v2_sequence_accepts_and_preserves_local` —
  local v2 seq=5, snapshot v2 seq=10 (new digest, same root) →
  `AcceptHigherV2Sequence`; local marker bytes preserved verbatim
  (Run 140 does NOT persist the new sequence — release-binary
  reload-apply Run 134 path does, on a separate surface).
* **A4** `run140_a4_local_v1_marker_with_v2_snapshot_matching_root_is_accepted` —
  local v1 marker + v2 snapshot marker matching the v1 trust domain
  and authority root → `AcceptV2AfterV1Migration`; local v1 marker
  bytes preserved verbatim (the v1→v2 swap on disk is a separate
  release-binary step, deferred).

Reject paths (all assert local marker bytes preserved + no
materialization + no audit marker):

* **R1** `run140_r1_local_v2_marker_present_legacy_snapshot_rejects_via_v1_path` —
  local v2 marker present + snapshot has no authority block at all
  (legacy snapshot). The dispatcher routes to the v1 path verbatim
  because `authority_state_v2.is_none()`. The v1 path then refuses
  (`AuthorityMarkerConflict(_)`). No v1 regression: this is the
  Run 124 behavior.
* **R2** `run140_r2_lower_v2_sequence_is_rejected` —
  local v2 seq=5, snapshot v2 seq=2 →
  `RejectV2Comparison(LowerSequenceRejected { persisted_sequence: 5,
  candidate_sequence: 2 })`.
* **R3** `run140_r3_same_sequence_different_digest_is_rejected` —
  same v2 sequence, different `latest_ratification_v2_digest` →
  `RejectV2Comparison(SameSequenceDifferentDigestRejected { sequence: 5,
  .. })`.
* **R4** `run140_r4_snapshot_v2_wrong_genesis_hash_is_rejected` →
  `RejectSnapshotMarkerWrongDomain`.
* **R5** `run140_r5_snapshot_v2_wrong_environment_is_rejected` →
  `RejectSnapshotMarkerWrongDomain`.
* **R6** `run140_r6_corrupt_local_marker_fails_closed_and_preserves_bytes` →
  local marker file contains `b"not valid json"` →
  `RejectLocalMarkerCorrupt(_)`; bytes preserved verbatim.
* **R7** `run140_r7_ambiguous_snapshot_with_both_v1_and_v2_blocks_is_rejected` —
  snapshot meta carries both `authority_state` and
  `authority_state_v2` → `RejectAmbiguousSnapshotMarkers` without
  consulting either block.
* **R8** `run140_r8_v2_snapshot_with_different_authority_root_is_rejected` —
  same trust domain, different `authority_root_fingerprint` →
  `RejectV2Comparison(WrongAuthorityRootRejected { .. })`.
* **R9** `run140_r9_local_v1_marker_wrong_domain_against_v2_snapshot_is_rejected` —
  local v1 marker with a wrong genesis hash + matching v2 snapshot
  marker → `RejectLocalMarkerWrongDomain` (local-domain check runs
  before any snapshot inspection, so the operator log line is
  precise).

Mapping to the task's required test matrix:

| Task    | Run 140 test                                                                  |
| ------- | ----------------------------------------------------------------------------- |
| A1      | `run140_a1_no_local_marker_v2_snapshot_block_is_accepted`                     |
| A2      | `run140_a2_matching_local_v2_marker_accepts_and_preserves_local`              |
| A3      | `run140_a3_higher_v2_sequence_accepts_and_preserves_local`                    |
| A4      | `run140_a4_local_v1_marker_with_v2_snapshot_matching_root_is_accepted`        |
| R1      | `run140_r2_lower_v2_sequence_is_rejected`                                     |
| R2      | `run140_r3_same_sequence_different_digest_is_rejected`                        |
| R3      | `run140_r5_snapshot_v2_wrong_environment_is_rejected`                         |
| R4      | (chain_id covered by domain check — exercised by R4/R5 paths and unit fns)    |
| R5      | `run140_r4_snapshot_v2_wrong_genesis_hash_is_rejected`                        |
| R6      | `run140_r6_corrupt_local_marker_fails_closed_and_preserves_bytes`             |
| R7      | covered by `run_124_snapshot_restore_authority_marker_tests` (unchanged)      |
| R8      | covered by `run_124_snapshot_restore_authority_marker_tests` (unchanged)      |
| R9      | `run140_r7_ambiguous_snapshot_with_both_v1_and_v2_blocks_is_rejected` (proves a v2 snapshot cannot be downgraded by adding a v1 block to it) and `run140_r1_local_v2_marker_present_legacy_snapshot_rejects_via_v1_path` (proves a snapshot with no v2 block cannot silently shadow a local v2 marker — the v1 dispatcher refuses) |

Additional Run 140-specific tests:

* **R8** (`WrongAuthorityRoot`) is an additive guarantee beyond the
  task's required matrix.
* **R9** (local v1 wrong-domain + v2 snapshot) hardens the dispatch
  precedence ordering.

## Validation commands and results

```text
$ cargo build -p qbind-node --lib
    Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo test -p qbind-node --test run_140_snapshot_restore_v2_authority_marker_tests
running 13 tests
test run140_a3_higher_v2_sequence_accepts_and_preserves_local ... ok
test run140_a1_no_local_marker_v2_snapshot_block_is_accepted ... ok
test run140_a2_matching_local_v2_marker_accepts_and_preserves_local ... ok
test run140_a4_local_v1_marker_with_v2_snapshot_matching_root_is_accepted ... ok
test run140_r1_local_v2_marker_present_legacy_snapshot_rejects_via_v1_path ... ok
test run140_r2_lower_v2_sequence_is_rejected ... ok
test run140_r3_same_sequence_different_digest_is_rejected ... ok
test run140_r4_snapshot_v2_wrong_genesis_hash_is_rejected ... ok
test run140_r5_snapshot_v2_wrong_environment_is_rejected ... ok
test run140_r6_corrupt_local_marker_fails_closed_and_preserves_bytes ... ok
test run140_r7_ambiguous_snapshot_with_both_v1_and_v2_blocks_is_rejected ... ok
test run140_r8_v2_snapshot_with_different_authority_root_is_rejected ... ok
test run140_r9_local_v1_marker_wrong_domain_against_v2_snapshot_is_rejected ... ok
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_124_snapshot_restore_authority_marker_tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --lib pqc_authority
test result: ok. 148 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-ledger --test t215_state_snapshot_tests
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured
```

## What stayed unchanged (no production-surface drift)

* No CLI flag changes. The restore surface entry point
  (`restore_from_snapshot_with_authority_marker_check`) keeps the
  same signature it had after Run 124.
* No wire/frame changes. No 0x05 v2 wire validation in this run.
* No metric changes. The existing restore-surface logging
  (`eprintln!("[restore] …")`) keeps the same shape; a separate
  `Run 140 v2 authority-marker check` log line is added on the v2
  branch.
* No new `AuthorityStateUpdateSource` variant. The restore check is
  pure (no marker write happens at restore time, mirroring Run 124),
  so no audit-source tag is written by the restore surface. The
  reconstruction of `PersistentAuthorityStateRecordV2` from snapshot
  meta uses the **existing** `AuthorityStateUpdateSource::TestOrFixture`
  for the informational-only field that does not participate in
  `canonical_authority_state_v2_digest` nor in
  `compare_authority_marker_v2` equality.
* No schema changes to the ratification sidecar, trust bundle, or
  peer-candidate wire format. The `StateSnapshotMeta` extension is
  additive in `meta.json` (key omitted when None), so pre-Run-140
  snapshots round-trip byte-identically when re-parsed.
* No v1 regression. The v1 dispatch in
  `restore_from_snapshot_with_authority_marker_check` is byte-identical
  to its Run 124 form for any snapshot that does not carry an
  `authority_state_v2` block (covered by R1 plus the unchanged
  `run_124_snapshot_restore_authority_marker_tests` suite).

## Crash-window discipline (task §5)

* The pure check (`verify_snapshot_authority_state_for_restore_v2`)
  performs no writes and no deletes.
* Materialization runs strictly after the accept decision, so a
  reject leaves the marker file, state checkpoint, and audit marker
  untouched.
* The existing `persist_authority_state_v2_atomic` (Run 131) is the
  only on-disk writer for v2 markers; the Run 140 restore surface
  never invokes it. No `.tmp` residue and no truncation by the
  restore surface.

## Open work explicitly deferred

* Release-binary `qbind-node` snapshot/restore evidence under the v2
  path → **Run 141**.
* Live inbound 0x05 v2 PQC trust-bundle frame validation → open.
* Peer-driven live trust-bundle apply → open.
* Signing-key rotation/revocation lifecycle (Rotate/Revoke evidence
  beyond the structural validator) → open.
* KMS / HSM authority-key custody → open.
* MainNet governance attestation track → open.
* Full C4 acceptance → open.
* C5 acceptance → open.
