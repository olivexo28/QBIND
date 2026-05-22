# QBIND DevNet Evidence — Run 121

**Subject:** SIGHUP live-reload (`spawn_run074_live_reload_task` /
`LiveReloadController`) authority-marker wiring — reuse of the Run
117/118/119 helpers on the third and final mutating surface.
**Verdict:** **positive**
**Date:** 2026-05-22
**Task:** `task/RUN_121_TASK.txt`

---

## 1. Exact verdict

**positive.**

Run 121 lands the SIGHUP live-reload marker compare-before-mutation
and persist-after-commit-boundary wiring, reusing the Run 119
`pqc_authority_marker_acceptance` module
(`decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary`)
without adding a parallel acceptance stack. With Run 121 the three
mutating surfaces — startup `--p2p-trust-bundle` (Run 120),
process-start `--p2p-trust-bundle-reload-apply-path` (Run 119), and
SIGHUP live-reload (Run 121) — now all share the same Run 119 helpers
as the **single source of truth** for marker acceptance and persist.

The new SIGHUP-specific adapter
`LiveReloadController::preflight_sighup_marker_decision(...)` lives
in `crates/qbind-node/src/pqc_live_trust_reload.rs` next to the
existing Run 114 ratification preflight on the same controller and
re-uses the same `BundleSigningKeySet`, `TrustBundle::load_from_path_*`
loader, and `enforce_bundle_signing_key_ratification` pure verifier
that the underlying apply pipeline runs internally — results are
bit-for-bit identical on every code path.

Source-level proof and integration-test proof (7 new Run 121
integration tests against the SIGHUP controller via the same
`MockP2pSessionEvictor` harness used by the existing Run 074 / Run
114 integration tests) cover the §A and §B requirements of the task
spec.

**Explicitly deferred, honestly:**

* Validation-only surfaces (`--p2p-trust-bundle-reload-check-path`,
  Run 077/107 peer-candidate-check, live inbound `0x05`). Per the
  task's §"Strict non-goals", marker persistence from
  validation-only surfaces is forbidden and is not implemented.
* Release-binary evidence per the task's §Scenario 1–4 acceptance
  table. Per the task's §"Release-binary evidence" the release-binary
  run is optional for Run 121 and is deferred to a future
  run-evidence sub-run that can present startup + reload-apply +
  SIGHUP release-binary evidence together on the same build. The
  source/test proof is presented in §3 below.
* `RatifiedBundleSigningKey` restore/snapshot conflict handling —
  Run 117 §C4 OPEN remains OPEN.
* Per-key monotonic authority-sequence schema — task spec
  §"Strict non-goals".
* `--allow-authority-state-reset` operator recovery flag — task
  spec §"Strict non-goals".
* Peer-driven live apply, signing-key rotation/revocation lifecycle,
  KMS/HSM custody — all out of scope per the task.

---

## 2. What was implemented

### 2.1 Files changed

* Modified: `crates/qbind-node/src/pqc_live_trust_reload.rs` —
  added `LiveReloadAuthorityMarkerConfig` struct; added
  `LiveReloadConfig::authority_marker: Option<...>` field; added
  `LiveReloadOutcome::MarkerRejected` and
  `LiveReloadOutcome::MarkerPersistFailureAfterCommit` variants;
  extended `is_applied()` / `is_fatal()` and added `is_marker_rejected()`;
  extended `log_line()` to render the two new variants; inserted the
  marker preflight (between sidecar load and apply call) and the
  marker post-commit persist (after `apply_validated_candidate_with_previous_and_ratification`
  returns `Ok`) inside the existing `match &self.config.ratification`
  block of `run_apply_pipeline`; added the SIGHUP-specific
  `preflight_sighup_marker_decision(...)` helper that mirrors
  `preflight_run_119_marker_decision(...)` /
  `preflight_run_120_marker_decision_for_startup(...)`.
* Modified: `crates/qbind-node/src/main.rs` — added the Run 121
  `LiveReloadAuthorityMarkerConfig` gating block inside
  `spawn_run074_live_reload_task` that populates the new
  `LiveReloadConfig::authority_marker` field only when both (a) the
  Run 114 ratification config is present (gate decision was
  `Invoke`) and (b) a `--data-dir` is configured. Two
  operator-facing `[run-121] …` log lines name the three branches:
  `INVOKED`, `SKIPPED (no --data-dir)`, `SKIPPED (gate not invoked)`.
* New: `crates/qbind-node/tests/run_121_sighup_authority_marker_tests.rs`
  — 7 integration tests against the live SIGHUP controller via the
  same harness pattern as the existing Run 114 file.
* Modified: `crates/qbind-node/tests/run_074_pqc_trust_bundle_live_reload_tests.rs`
  and `crates/qbind-node/tests/run_114_sighup_live_reload_ratification_tests.rs`
  — additive `authority_marker: None` field in the existing
  `LiveReloadConfig` builders so the existing Run 074 / Run 114
  tests compile against the extended struct shape. No assertion or
  scenario was modified.
* New: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_121.md` (this file).
* Modified: `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` —
  Run 121 update section.
* Modified: `docs/whitepaper/contradiction.md` — Run 121 update
  paragraph.
* Modified: `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` —
  Run 121 operator-facing notes.

No new modules, no new dependencies, no new CLI flags, no schema
changes, no wire-format changes.

### 2.2 SIGHUP-surface wiring (`crates/qbind-node/src/pqc_live_trust_reload.rs`)

The `LiveReloadController::run_apply_pipeline` method's existing
`match &self.config.ratification { Some(rcfg) => { ... } }` arm now
sandwiches the existing
`apply_validated_candidate_with_previous_and_ratification(...)` call
as follows:

```text
existing: per-trigger sidecar load (Run 114) — fail-closed on
          missing / malformed sidecar via LiveReloadOutcome::Invalid
existing: build RatificationEnforcementContext (Run 114)

NEW Run 121: preflight_sighup_marker_decision(rcfg, sidecar, now)
             ├─ if authority_marker config is None → Ok(None) (skip)
             ├─ re-load candidate via the same
             │   TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation
             │   loader the apply pipeline uses internally
             ├─ if Unsigned                       → Ok(None) (DevNet-unsigned skip)
             ├─ re-run enforce_bundle_signing_key_ratification
             │   (pure verifier; apply pipeline re-runs the same)
             ├─ if LegacyUnratifiedAccepted       → Ok(None) (legacy skip)
             ├─ build MarkerAcceptanceInputs with
             │   AuthorityStateUpdateSource::SighupReload
             └─ call decide_marker_acceptance(inputs)
                ├─ Ok(decision)                   → carry into apply
                └─ Err(MutatingSurfaceMarkerError) → return
                                LiveReloadOutcome::MarkerRejected

existing: apply_validated_candidate_with_previous_and_ratification(...)
          performs the unchanged Run 070 ordering bit-for-bit:
          snapshot_active → swap_trust_state → evict_sessions →
          commit_sequence

NEW Run 121: on Ok(applied) from the apply pipeline:
             ├─ if marker_decision is Some(decision):
             │   call persist_accepted_marker_after_commit_boundary(&decision)
             │     ├─ on Ok → fall through to LiveReloadOutcome::Applied
             │     └─ on Err → return LiveReloadOutcome::MarkerPersistFailureAfterCommit
             │                 { applied, marker_error }   (is_fatal == true)
             └─ if marker_decision is None       → LiveReloadOutcome::Applied (unchanged)

existing: error mapping unchanged
          SequenceCommitFailedRollbackAlsoFailed → LiveReloadOutcome::Fatal
          everything else                        → LiveReloadOutcome::Invalid
```

The `None`-ratification arm of `run_apply_pipeline` (DevNet without
operator opt-in) is **completely unchanged** — the marker preflight
is only reachable through the `Some(ratification)` arm because
marker derivation strictly requires verified ratification material
per Run 117/118/119.

### 2.3 Binary-surface wiring (`crates/qbind-node/src/main.rs`)

The existing `spawn_run074_live_reload_task` function now computes
`authority_marker_cfg_opt: Option<LiveReloadAuthorityMarkerConfig>`
just before constructing `LiveReloadConfig`:

```text
(ratification_cfg_opt.as_ref(), config.data_dir.as_ref()) match:
  (Some(_), Some(data_dir)) → Some(LiveReloadAuthorityMarkerConfig {
                                     marker_path: authority_state_file_path(data_dir),
                                  }) + log "[run-121] … INVOKED"
  (Some(_), None)           → None + log "[run-121] … SKIPPED (no --data-dir)"
                                       MainNet/TestNet never reach this
                                       (--data-dir is mandatory there).
  (None,    _)              → None + log "[run-121] … SKIPPED (gate not invoked)"
                                       Reachable only on DevNet without
                                       operator opt-in.
```

The fatal-shutdown handler in the SIGHUP signal-handler task is
**unchanged**: it already routes any `out.is_fatal()` outcome
through `shutdown_tx.send(())` for graceful shutdown. Because
`LiveReloadOutcome::MarkerPersistFailureAfterCommit` returns
`is_fatal() == true`, the Run 121 persist-failure branch reuses
the same single shutdown surface that the existing
`SequenceCommitFailedRollbackAlsoFailed` branch uses — operators
see one place to look for fatal-shutdown signals across both runs.

### 2.4 Outcome / metric / log-line semantics

| Outcome variant | `is_applied()` | `is_fatal()` | `is_marker_rejected()` | live state mutated | sequence file mutated | session evictor called | marker file mutated | `live_reload_apply_success_total` | `live_reload_apply_failure_total` |
|---|---|---|---|---|---|---|---|---|---|
| `Applied`                            | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ (Upgrade/FirstWrite) or 🔵 no-op (Idempotent) | +1 | 0 |
| `MarkerRejected`                     | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ (byte-identical) | 0 | +1 |
| `MarkerPersistFailureAfterCommit`    | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ (atomic write failed) | +1 | 0 |
| `Invalid`                            | ❌ | ❌ | ❌ | depends on Run 070 rollback | depends | depends | ❌ | 0 | +1 |
| `Fatal`                              | ❌ | ✅ | ❌ | possibly ahead | depends | ✅ | ❌ | 0 | +1 |
| `AlreadyInProgress`                  | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 0 | 0 (already-in-progress counter +1) |

Notes:

* `MarkerPersistFailureAfterCommit` counts as a successful **apply**
  in the metrics (the apply pipeline DID succeed; trust-bundle
  sequence DID commit; sessions DID evict) but the variant itself
  signals fatal because the on-disk marker is now stale-by-one
  relative to the trust-bundle sequence. Per Run 118 §D this is
  safely replayable as an `Upgrade` on the next accepted mutation
  but the operator MUST be told via the shutdown surface so the
  failure is not silently absorbed.
* `MarkerRejected` is counted as a pre-mutation refusal (apply
  failure), same shape as a Run 069 validation refusal or a Run
  114 sidecar I/O failure.

### 2.5 Operator log lines

```text
[binary] Run 074: VERDICT=applied (live trust-bundle apply on long-running
 node; session_evictions=N; sequence_commit=ok)
[binary] Run 074: VERDICT=already-in-progress (…)
[binary] Run 074: VERDICT=invalid (…). Reason: <ReloadApplyError>
[binary] Run 074: VERDICT=FATAL (…). Reason: <ReloadApplyError>

NEW:
[binary] Run 121: VERDICT=marker-rejected (SIGHUP authority-marker preflight
 refused the candidate BEFORE any snapshot, swap, eviction, or sequence
 commit; live trust state, sessions, on-disk sequence record, and on-disk
 authority-marker file are all unchanged). Reason: <MutatingSurfaceMarkerError>

[binary] Run 121: VERDICT=FATAL-marker-persist (live trust-bundle apply on
 long-running node succeeded — session_evictions=N, sequence_commit=ok — but
 authority-marker atomic persist FAILED AFTER the commit boundary; the
 on-disk marker is stale-by-one relative to the trust-bundle sequence
 (safely replayable as an Upgrade per Run 118 §D) but graceful shutdown is
 required so the operator can surface and recover the failure). Reason:
 <MutatingSurfaceMarkerError::PersistFailure>
```

---

## 3. Tests

### 3.1 New Run 121 integration tests

File: `crates/qbind-node/tests/run_121_sighup_authority_marker_tests.rs`
(7 tests, all green):

| # | Test | Asserts |
|---|---|---|
| 1 | `run121_first_write_creates_marker_with_sighup_audit_tag` | First SIGHUP under valid Strict ratification + marker config creates the marker file post-commit with `AuthorityStateUpdateSource::SighupReload` and the exact `(chain_id, environment, genesis_hash, authority_sequence, ratified_bundle_signing_key_fingerprint, ratification_object_hash)` matching the verified ratification. Live state advanced; sequence file written; eviction called exactly once. |
| 2 | `run121_re_apply_same_candidate_is_idempotent_no_marker_rewrite` | Re-applying the same candidate + ratification leaves the marker file's bytes AND mtime byte-identical (no rewrite of the audit-only `updated_at_unix_secs`). Run 119/120 idempotent contract preserved on the SIGHUP surface. |
| 3 | `run121_pre_persisted_higher_sequence_refuses_before_any_mutation` | A pre-persisted marker at a strictly higher `authority_sequence` refuses the SIGHUP fail-closed: `LiveReloadOutcome::MarkerRejected`, `is_marker_rejected() == true`, `is_fatal() == false`. Live state unchanged; sequence file NOT created; no eviction; marker bytes byte-identical pre/post-trigger; failure metric +1, success metric 0. |
| 4 | `run121_pre_persisted_different_domain_refuses_before_any_mutation` | A pre-persisted marker for a different `(chain_id)` trust domain refuses the SIGHUP fail-closed with no live trust mutation, no sequence write, no eviction. |
| 5 | `run121_corrupt_marker_file_refuses_and_is_not_overwritten` | A structurally invalid marker file (non-JSON garbage) refuses the SIGHUP fail-closed AND the controller does NOT silently overwrite the corrupt file (the bytes remain exactly as garbage on disk). No live state change, no sequence file, no eviction. |
| 6 | `run121_devnet_no_opt_in_skips_marker_and_preserves_pre_run121_path` | DevNet without operator opt-in (ratification gate `Skip`, marker config `None`) applies via the pre-Run-114 SIGHUP path and NEVER creates the marker file. Pre-Run-121 SIGHUP behaviour byte-identical. |
| 7 | `run121_persist_failure_after_commit_is_fatal_and_apply_did_succeed` | When the marker atomic-persist fails AFTER the apply pipeline's `commit_sequence` boundary: outcome is `MarkerPersistFailureAfterCommit`; `is_fatal() == true` (binary signals graceful shutdown); `is_applied() == true` (apply DID succeed; live state DID advance; sequence file DID write; eviction DID happen). `live_reload_apply_success_total +1` (apply succeeded); `live_reload_apply_failure_total 0`. Operator log line names `Run 121` and `FATAL-marker-persist`. The persist-failure is injected via a read-only marker-parent directory on Unix; the test is `#[cfg(not(unix))]`-no-op on non-unix targets. |

### 3.2 Regression — every prior test stays green

| Suite | Pre-Run-121 | Post-Run-121 | Status |
|---|---|---|---|
| `qbind-node --lib`                                           | 1184 | 1184 | ✅ unchanged |
| `qbind-node --test run_074_pqc_trust_bundle_live_reload_tests`        | 10  | 10  | ✅ unchanged |
| `qbind-node --test run_114_sighup_live_reload_ratification_tests`     | 14  | 14  | ✅ unchanged |
| `qbind-node --test run_119_authority_marker_acceptance_tests`         | 4   | 4   | ✅ unchanged |
| `qbind-node --test run_121_sighup_authority_marker_tests`             | —   | 7   | ✅ NEW |
| `qbind-ledger --lib`                                                  | 231 | 231 | ✅ unchanged |

No existing assertion in any pre-Run-121 file was modified — the only
changes to existing test files are the additive `authority_marker: None`
field on the `LiveReloadConfig` builders, required because
`LiveReloadConfig` is a public bare struct (no builder pattern).

### 3.3 What is NOT tested in this run, and why

* **Release-binary acceptance scenarios** (task §Scenario 1–4). The
  release-binary run is optional for Run 121 per the task spec.
  Source-level + integration-level proof above covers the §A and §B
  contract obligations bit-for-bit. The release-binary run is
  deferred to a future run-evidence sub-run that can present
  startup + reload-apply + SIGHUP release-binary evidence on the
  same build.
* **MainNet operability**. MainNet always reaches the `(Some, Some)`
  branch — ratification gate is default-strict (Run 106) and
  `--data-dir` is mandatory (Run 055). DevNet integration tests
  exercise the same code path bit-for-bit because the only
  per-environment difference inside the controller is the
  `RatificationEnforcementPolicy` (Strict on MainNet/TestNet,
  configurable on DevNet) and the integration tests already drive
  Strict.

---

## 4. Run 120 doc verification

The task §"Run 120 documentation status (must verify and fix before
Run 121 implementation)" required a pre-flight verification of the
three tracking documents (`docs/whitepaper/contradiction.md`,
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, and
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) for Run 120 content
coverage.

Verification result: **no fix required**. The three docs already
contain the Run 120 section with the exact required wording:

* `docs/whitepaper/contradiction.md` (line 1555–1557): the Run 120
  paragraph explicitly states that Run 120 wired the startup
  `--p2p-trust-bundle` marker compare-before-mutation and
  persist-after-commit, the SighupReload audit tag is reserved for a
  future sub-run (now Run 121), the DevNet no-opt-in branch does
  NOT write a marker, and no Run 109 contract was changed.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (line
  1581–1591): "## Run 120 update — Startup `--p2p-trust-bundle`
  acceptance surface wired with the shared Run 119 helpers
  (positive); SIGHUP wiring still OPEN" — exactly the section the
  task references. Validation-only surfaces remaining unwired, the
  release-binary evidence open item, and the no-fake-monotonic
  property are all named explicitly.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (line 5314–5366):
  "## Run 120 — Authority anti-rollback marker on the startup
  `--p2p-trust-bundle` surface" includes both the operator-required
  backup procedure for `<data_dir>/pqc_authority_state.json` and the
  explicit "Run 074/114 SIGHUP live-reload acceptance enforcement.
  The SIGHUP path still does not check or write the marker in Run
  120" deferral that Run 121 now closes.

No edits to the Run 120 sections of those documents were necessary.
Run 121 adds new sections on top (see §6).

---

## 5. Strict scope honored

Per `task/RUN_121_TASK.txt` §"Strict scope":

* ✅ SIGHUP live-reload surface only. Run 119 (reload-apply) and
  Run 120 (startup `--p2p-trust-bundle`) are unchanged.
* ✅ Reuses Run 119 `decide_marker_acceptance` +
  `persist_accepted_marker_after_commit_boundary` verbatim — no
  parallel acceptance stack, no inlined copy.
* ✅ Marker is persisted with
  `AuthorityStateUpdateSource::SighupReload` (audit-only field;
  does not enter the canonical digest per Run 117).
* ✅ DevNet no-opt-in branch is byte-identical to a Run-120 build
  (marker config is `None`; pre-Run-121 SIGHUP path runs verbatim).
* ✅ Validation-only surfaces are NOT wired (per §"Strict
  non-goals").
* ✅ No new CLI flag; no `--allow-authority-state-reset`; no
  schema bump; no wire-format change.
* ✅ Run 109 contract preserved bit-for-bit on every other surface
  (peer-driven live apply is NOT extended).
* ✅ No weakening of Run 050 / 055 / 057 / 061 / 063 / 065 / 069 /
  070 / 071 / 072 / 073 / 074 / 076 / 077 / 087 / 088 / 089 / 091–
  099 / 100 / 101 / 102 / 103 / 104 / 105 / 106 / 107 / 108 / 109 /
  110 / 111 / 112 / 113 / 114 / 115 / 116 / 117 / 118 / 119 / 120
  invariants. Specifically: the Run 070 callback ordering
  (`snapshot_active → swap_trust_state → evict_sessions →
  commit_sequence`) is preserved bit-for-bit because the marker
  persist step lives STRICTLY OUTSIDE the apply pipeline (in
  `LiveReloadController::run_apply_pipeline` after the apply call
  returns Ok), and the marker preflight runs STRICTLY BEFORE any
  apply callback fires.

Bounded protection limit (unchanged from Run 116/117/118/119/120):
the marker still cannot detect a same-sequence key-level downgrade
where two distinct candidates carrying the same
`authority_sequence` are presented in the same canonical order
(Run 122 per-key monotonic field is the long-term fix).

---

## 6. Tracking-document updates

* `docs/whitepaper/contradiction.md` — new Run 121 paragraph
  appended after the Run 120 paragraph.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — new
  Run 121 update section.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — new Run 121
  operator-facing notes section.

---

## 7. Open items rolling into Run 122+

* Release-binary evidence sub-run that exercises startup + reload-
  apply + SIGHUP marker scenarios end-to-end on the same build.
* Restore-side conflict enforcement and
  `--allow-authority-state-reset` operator-recovery flag.
* `BundleSigningRatification` v2 schema bump for the per-key
  monotonic field.
* Peer-driven live apply, signing-key rotation/revocation lifecycle,
  KMS/HSM custody, governance, validator-set rotation — all remain
  OPEN per the long-running C4/C5 contradiction analysis.