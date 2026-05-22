# QBIND DevNet Evidence — Run 119

**Subject:** Shared mutating-surface accept-and-persist composition over the Run 117/118 authority anti-rollback marker — wired to the process-start reload-apply surface only.
**Verdict:** **partial-positive**
**Date:** 2026-05-22
**Task:** `task/RUN_119_TASK.txt`

---

## 1. Exact verdict

**partial-positive.**

Run 119 lands the shared `decide_marker_acceptance` → `persist_accepted_marker_after_commit_boundary` composition with full typed reject coverage and 17 helper unit tests, plus 4 integration tests against a fake `LiveTrustApplyContext`, plus the narrow wiring into the **process-start reload-apply surface only** (`--p2p-trust-bundle-reload-apply-path` in `crates/qbind-node/src/main.rs`).

**What is NOT in Run 119 and is documented as deferred:**

* The startup `--p2p-trust-bundle` acceptance path. The Run 050/051 startup loader does not yet compose the marker preflight + post-persist. This is the Run 120a deliverable.
* The Run 074/114 SIGHUP live-reload path. The long-running-node trigger does not yet compose the marker preflight + post-persist. This is the Run 120b deliverable.
* The Run 077/107 peer-candidate-check path. This is intentionally validation-only and never persists the marker; no wiring is planned there (peer-candidate-check is not a mutating surface).
* Release-binary evidence per the task's §Scenario 1–4 (rollback refused at marker compare time on a released binary). The full test sweep passes in `cargo test`, but a release-binary run on a sample DevNet config is deferred to Run 120c so it can be presented alongside both startup and SIGHUP wiring evidence on the same build.
* `RatifiedBundleSigningKey` restore/snapshot conflict handling. Run 117 §C4 OPEN remains OPEN.

This matches the task spec's §"Strict scope" and §"Expected verdicts": "marker derivation/checking lands on only some surfaces; persistence is wired on at least one surface; release-binary evidence is incomplete; restore/snapshot conflict handling remains deferred."

---

## 2. What was implemented

### 2.1 New module: `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`

Single-file Rust module containing:

* `MutatingSurfaceMarkerError` — typed enum covering all reject reasons:
  * `DerivationFailed(AuthorityStateDerivationError)` — wraps Run 118 derivation errors (malformed runtime genesis hex, env mismatch, chain mismatch, root fingerprint mismatch, ratification-verifier inconsistency).
  * `LoadOrCorruption(AuthorityStateError)` — on-disk marker I/O or structural-validation failure.
  * `PersistedDomainMismatch(PersistedAuthorityStateDomainValidationFailure)` — on-disk marker exists but its `environment` / `chain_id` / `genesis_hash` disagrees with the runtime.
  * `AuthorityRootFingerprintMismatch { persisted, candidate }` — on-disk marker pinned to a different genesis-authority root.
  * `RatifiedSigningKeyFingerprintMismatch { ... }` — on-disk marker pinned to a different ratified signing key at the same authority sequence.
  * `AuthoritySequenceRollback { persisted_sequence, candidate_sequence }` — candidate sequence is strictly lower than the persisted marker's.
  * `SameSequenceConflictingHash { ... }` — same authority_sequence, same signing key, but the candidate's `ratification_object_hash` differs from the persisted one (equivocation attempt).
  * `PolicyVersionRegression { ... }` — same sequence, lower policy version (Run 118 invariant).
  * `PersistFailure(AuthorityStateError)` — atomic-write or fsync failure from `persist_authority_state_atomic`.
* `MarkerAcceptanceInputs<'a>` — borrowed input struct grouping runtime env / chain / genesis / authority block / verified ratification + ratified key + marker path + audit fields.
* `MarkerAcceptKind` — `FirstWrite | Upgrade | Idempotent` for operator logging.
* `MarkerAcceptDecision` — the typed accept-decision returned by `decide_marker_acceptance`; **never persists** by itself. Carries the candidate record, marker_path, the `MarkerAcceptKind`, and a `should_persist: bool` that is false for `Idempotent`.
* `decide_marker_acceptance(inputs) -> Result<MarkerAcceptDecision, MutatingSurfaceMarkerError>` — derive → load existing marker → compare; never touches disk; never persists. All reject reasons collapse into the typed error.
* `persist_accepted_marker_after_commit_boundary(decision) -> Result<(), MutatingSurfaceMarkerError>` — wraps `persist_authority_state_atomic`; strict no-op when `should_persist` is false. Must be called AFTER the existing `commit_sequence` callback so a crash window leaves the marker stale-by-one (which the next accepted mutation will replay as `Upgrade`), per Run 118 §D.

### 2.2 Reload-apply surface wiring: `crates/qbind-node/src/main.rs`

* New `preflight_run_119_marker_decision(...)` helper composes the Run 050/051 candidate pre-load + Run 105 `enforce_bundle_signing_key_ratification` + Run 119 `decide_marker_acceptance`. Returns `Ok(None)` on inapplicable branches (no `--data-dir`, unsigned candidate, `LegacyUnratifiedAccepted`, lookup miss, pre-load failure deferred to the apply pipeline's own typed error reporting) so behaviour is unchanged on those branches.
* The `--p2p-trust-bundle-reload-apply-path` block in `main.rs` now sandwiches the existing `apply_validated_candidate_with_previous_and_ratification` call:
  1. `gate_decision.should_invoke()` branch only (DevNet without `--p2p-trust-bundle-ratification-enforcement-enabled` is unchanged);
  2. After `build_run_105_reload_check_context(...)` succeeds, call `preflight_run_119_marker_decision(...)`;
  3. On `Err` from preflight: print operator-facing line `[run-119] FATAL: reload-apply refused by authority-marker preflight: ...`, `std::process::exit(1)` — no apply call, no sequence write, no session eviction;
  4. On `Ok(decision)`: invoke the apply pipeline as before;
  5. On `Ok(applied)` from the apply pipeline AND `Some(decision)`: call `persist_accepted_marker_after_commit_boundary(decision)`;
  6. On persist failure: print operator-facing line `[run-119] FATAL: authority-marker persist failure AFTER successful apply: ...` documenting the stale-by-one crash-window state and `std::process::exit(1)`;
  7. On persist success: print `[run-119] authority-marker persisted at ...` (or `... unchanged ... (idempotent; no rewrite).`).

### 2.3 Module registration

`crates/qbind-node/src/lib.rs` exposes `pub mod pqc_authority_marker_acceptance;` with the same Run-XXX block-comment style as Run 117 / Run 118 modules.

---

## 3. Test coverage

### 3.1 §A — helper unit tests (in-module, `pqc_authority_marker_acceptance::tests`)

17 cases, all passing:

| # | Test | Asserts |
|---|------|---------|
| A.1 | `decide_first_write_when_no_prior_marker` | clean accept on empty `data_dir` produces `FirstWrite`. |
| A.2 | `decide_missing_marker_is_first_write` | missing file (`NotFound`) is treated as no prior marker. |
| A.3 | `decide_idempotent_when_marker_matches_bitwise` | re-running with identical inputs produces `Idempotent` with `should_persist=false`. |
| A.4 | `decide_upgrade_when_persisted_sequence_strictly_lower` | strictly higher candidate sequence produces `Upgrade`. |
| A.5 | `decide_rollback_rejected` | lower candidate sequence produces `AuthoritySequenceRollback`. |
| A.6 | `decide_same_sequence_different_ratification_hash_rejects` | equivocation attempt produces `SameSequenceConflictingHash`. |
| A.7 | `decide_persisted_domain_mismatch_rejected` | wrong-domain persisted marker produces `PersistedDomainMismatch`. |
| A.8 | `decide_corrupt_marker_fails_closed` | structurally invalid persisted marker produces `LoadOrCorruption`. |
| A.9 | `decide_malformed_runtime_genesis_hex_rejects_via_derivation_error` | uppercase / wrong-length hex produces `DerivationFailed`. |
| A.10 | `decide_with_wrong_but_well_formed_genesis_hex_does_not_falsely_reject` | runtime can't catch a runtime/ratification genesis disagreement; the Run 105 verifier is the layer of record (sanity). |
| A.11 | `decide_wrong_environment_rejects_via_derivation_error` | env mismatch is caught by Run 118 derivation. |
| A.12 | `decide_wrong_chain_rejects_via_derivation_error` | chain mismatch is caught by Run 118 derivation. |
| A.13 | `decide_root_mismatch_rejects_via_derivation_error` | `ratification.authority_root_fingerprint != ratified.authority_root_fingerprint` is caught by Run 118 derivation. |
| A.14 | `decide_does_not_persist` | a single `decide_marker_acceptance` call never touches disk. |
| A.15 | `rejected_path_does_not_touch_disk` | a rejection from `decide_marker_acceptance` plus a no-op `persist_accepted_marker_after_commit_boundary` leaves disk state untouched. |
| A.16 | `persist_writes_first_write_marker` | accept + persist writes a marker whose bytes deserialise back via `load_authority_state` and whose `canonical_authority_state_digest` matches the candidate. |
| A.17 | `persist_failure_wraps_into_persist_failure_variant` | I/O failure at the rename step surfaces as `MutatingSurfaceMarkerError::PersistFailure`. |

Command + result:

```text
$ cargo test -p qbind-node --lib pqc_authority_marker_acceptance::
running 17 tests
...
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 1158 filtered out
```

### 3.2 §C — reload-apply integration tests (`tests/run_119_authority_marker_acceptance_tests.rs`)

4 scenarios, all passing, exercising the decide → apply → persist sandwich against a deterministic `FakeLiveTrustApplyContext`:

| # | Test | Asserts |
|---|------|---------|
| C.1 | `run119_clean_first_write_decide_then_apply_then_persist` | Run 070 callback ordering preserved bit-for-bit (`snapshot_active`, `swap_trust_state`, `evict_sessions`, `commit_sequence`); marker file present on disk with the expected env / chain / genesis / ratified-signing-key fingerprint. |
| C.2 | `run119_pre_persisted_marker_rollback_rejects_before_apply` | A pre-persisted marker at a strictly higher authority_sequence rejects the candidate with `AuthoritySequenceRollback`; FakeLiveTrustApplyContext records ZERO callback events; marker bytes unchanged; sequence file not created. |
| C.3 | `run119_apply_failure_after_accept_does_not_persist_marker` | decide accepts; apply pipeline returns Err from a simulated `swap_trust_state` failure; the orchestration skips persist on Err; marker file never appears on disk. |
| C.4 | `run119_idempotent_re_apply_does_not_rewrite_marker` | Second decide on bit-for-bit identical inputs yields `Idempotent` with `should_persist=false`; calling persist is a strict no-op; marker bytes after first apply == marker bytes after second apply. |

Command + result:

```text
$ cargo test -p qbind-node --test run_119_authority_marker_acceptance_tests
running 4 tests
test run119_pre_persisted_marker_rollback_rejects_before_apply ... ok
test run119_apply_failure_after_accept_does_not_persist_marker ... ok
test run119_idempotent_re_apply_does_not_rewrite_marker ... ok
test run119_clean_first_write_decide_then_apply_then_persist ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 3.3 §B / §D — explicitly deferred

* §B (startup `--p2p-trust-bundle` acceptance tests) requires the Run 050/051 startup loader to compose the marker preflight. Not in Run 119; deferred to Run 120a.
* §D (SIGHUP live-reload acceptance tests) requires the Run 074/114 SIGHUP path to compose the marker preflight. Not in Run 119; deferred to Run 120b.

---

## 4. Operator-facing log lines

Three new lines emitted on the `--p2p-trust-bundle-reload-apply-path` surface:

| Line | When |
|------|------|
| `[run-119] authority-marker preflight skipped: ...` | Pre-conditions for marker derivation are not met on this branch (no `--data-dir`, unsigned candidate, legacy-unratified accept, signing-key lookup miss, pre-load deferred to apply pipeline). The reason is included verbatim. |
| `[run-119] authority-marker persisted at <path> (<kind>; candidate authority_sequence=<n>).` | A `FirstWrite` or `Upgrade` decision was persisted after a successful apply. |
| `[run-119] authority-marker unchanged at <path> (idempotent; no rewrite).` | An `Idempotent` decision intentionally skipped the persist step (file bytes unchanged). |
| `[run-119] FATAL: reload-apply refused by authority-marker preflight: <reason>. Candidate path=<...>. No live trust apply, no sequence write, no session eviction, no metrics mutation, no marker write.` | Marker preflight rejected the candidate; fail-closed exit before any apply. |
| `[run-119] FATAL: authority-marker persist failure AFTER successful apply: <reason>. The trust-bundle sequence already committed; the on-disk authority marker is stale-by-one and will be re-derived on the next accepted mutation (Run 118 §D crash-window rule). Candidate path=<...>.` | The atomic write or fsync failed after the apply committed; documented stale-by-one operator recovery state. |

---

## 5. Files changed

* New: `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`
* New: `crates/qbind-node/tests/run_119_authority_marker_acceptance_tests.rs`
* New: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md` (this file)
* Modified: `crates/qbind-node/src/lib.rs` — `pub mod pqc_authority_marker_acceptance;` plus Run-XXX block comment.
* Modified: `crates/qbind-node/src/main.rs` — new `preflight_run_119_marker_decision(...)` helper + `hex_decode_32(...)` / `hex_nibble(...)` utilities; `--p2p-trust-bundle-reload-apply-path` block now sandwiches the apply call with the Run 119 preflight + post-persist.
* Modified: `docs/whitepaper/contradiction.md` — Run 119 update paragraph.
* Modified: `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 119 update section.
* Modified: `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 119 operator-facing notes.

No changes to release-binary build, no new dependencies, no new CLI flags, no new module entries beyond the single Run 119 module.

---

## 6. Strict-scope adherence

* `RatifiedBundleSigningKey` shape is **unchanged** from Run 116.
* `PersistentAuthorityStateRecord` shape is **unchanged** from Run 117 (`record_version=1` preserved).
* The Run 070 apply pipeline ordering (`snapshot → swap → evict → commit`) is **unchanged**; the marker persist step lives strictly OUTSIDE the apply pipeline (in `main.rs`), called only after the apply pipeline returns `Ok(applied)`.
* No new dependencies introduced.
* `cargo build -p qbind-node` clean; `cargo test -p qbind-node --lib pqc_authority_marker_acceptance::` 17/17 pass; `cargo test -p qbind-node --test run_119_authority_marker_acceptance_tests` 4/4 pass.

---

## 7. What's next (Run 120 / Run 121)

* **Run 120a** — wire `decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary` into the startup `--p2p-trust-bundle` acceptance path (Run 050/051), plus the §B test suite (10+ cases).
* **Run 120b** — wire the same helpers into the Run 074/114 SIGHUP live-reload path, plus the §D test suite.
* **Run 120c** — release-binary evidence for §Scenario 1–4 on a built `qbind-node` against a sample DevNet config.
* **Run 121** — restore/snapshot conflict handling for `RatifiedBundleSigningKey` (Run 117 §C4 OPEN).

Each of the four Run 120 sub-runs is independently small and reviewable; they should not be folded into a single PR.