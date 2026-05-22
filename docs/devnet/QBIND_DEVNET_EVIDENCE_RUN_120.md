# QBIND DevNet Evidence — Run 120

**Subject:** Startup `--p2p-trust-bundle` authority-marker wiring — reuse of the Run 117/118/119 helpers on the startup acceptance path only.
**Verdict:** **positive**
**Date:** 2026-05-22
**Task:** `task/RUN_120_TASK.txt`

---

## 1. Exact verdict

**positive.**

Run 120 lands the startup `--p2p-trust-bundle` marker compare-before-mutation and persist-after-commit-boundary wiring, reusing the Run 119 `pqc_authority_marker_acceptance` module (`decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary`) without adding a parallel acceptance stack. The new startup-specific helper `preflight_run_120_marker_decision_for_startup(...)` lives next to the existing `preflight_run_119_marker_decision(...)` in `crates/qbind-node/src/main.rs` and is the only Run 120 new symbol.

Source-level proof and unit-test proof (26 helper unit tests including 9 new Run 120 cases against the shared `decide_marker_acceptance` / `persist_accepted_marker_after_commit_boundary` primitives with `AuthorityStateUpdateSource::StartupLoad`) cover the §A and §B requirements of the task spec.

**Explicitly deferred, honestly:**

* The Run 074/114 SIGHUP live-reload path. This was Run 120b in the Run 119 roadmap and is explicitly out-of-scope for Run 120 per `task/RUN_120_TASK.txt` §"Strict scope" and §"Strict non-goals".
* Validation-only surfaces (`--p2p-trust-bundle-reload-check-path`, Run 077/107 peer-candidate-check, live inbound `0x05`). Per §"Strict non-goals", marker persistence from validation-only surfaces is forbidden and is not implemented.
* Release-binary evidence per the task's §Scenario 1–4. Per the task's §"Release-binary evidence" the release-binary run is optional for Run 120 and is deferred to a future run-evidence sub-run so it can be presented alongside SIGHUP wiring evidence on the same build. The source/test proof is presented in §3 below.
* `RatifiedBundleSigningKey` restore/snapshot conflict handling — Run 117 §C4 OPEN remains OPEN.
* Per-key monotonic authority-sequence schema — task spec §"Strict non-goals".

---

## 2. What was implemented

### 2.1 Files changed

* Modified: `crates/qbind-node/src/main.rs` — added `preflight_run_120_marker_decision_for_startup(...)` (mirror of `preflight_run_119_marker_decision(...)`); added marker compare + persist call sites inside the startup `--p2p-trust-bundle` `Some(path) => { ... }` arm.
* Modified: `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` — added 9 new in-module unit tests under `mod tests` covering the Run 120 startup surface contract (`AuthorityStateUpdateSource::StartupLoad`).
* New: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_120.md` (this file).
* Modified: `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 120 update section.
* Modified: `docs/whitepaper/contradiction.md` — Run 120 update paragraph.
* Modified: `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 120 operator-facing notes.

No new modules, no new dependencies, no new CLI flags, no schema changes.

### 2.2 Startup-surface wiring (`crates/qbind-node/src/main.rs`)

The startup `--p2p-trust-bundle` arm of `main()` (in the `let trust_bundle_loaded = match args.p2p_trust_bundle ... Some(path) => { ... } ` block) now sandwiches the existing Run 105/106 ratification gate and the Run 055 trust-bundle sequence anti-rollback persistence as follows:

```text
existing: load_from_path_with_signing_keys_chain_id_and_activation(...)
existing: Run 057 activation gate (observability only)
existing: Run 105/106 startup ratification gate
  ↑ unchanged: apply_run_105_ratification_gate_at_startup(...) fatal-exits on refusal

  NEW (Run 120): build Run 105 enforcement context (reuses
                 build_run_105_reload_check_context — no new I/O)

  NEW (Run 120): preflight_run_120_marker_decision_for_startup(...)
                 → Ok(None)              when not applicable (data_dir absent,
                                          unsigned candidate, LegacyUnratifiedAccepted)
                 → Ok(Some(decision))    on accept
                 → Err(MutatingSurfaceMarkerError)  on conflict / corruption /
                                          wrong-domain → FATAL exit BEFORE the
                                          Run 055 sequence write, BEFORE root merge,
                                          BEFORE P2P start.

existing: Run 055 check_and_update_sequence(...)        ← startup commit boundary
existing:   Ok(SequenceCheckOutcome::{FirstLoad,Upgraded,EqualSequenceSameFingerprint})

  NEW (Run 120): persist_accepted_marker_after_commit_boundary(&decision)
                 → no-op when decision is None (gate skipped, unsigned, etc.)
                 → no-op when decision.kind() == Idempotent
                 → atomic write of <data_dir>/pqc_authority_state.json otherwise
                 → FATAL on persist failure (the sequence has already
                   committed; marker is stale-by-one per Run 118 §D)

existing: Merge bundle active_roots into `trusted_roots`
existing: rest of startup (revocation self-check, metrics, P2P node builder, ...)
```

The DevNet no-opt-in `else` branch (gate `SKIPPED`) explicitly logs:

```
[run-120] authority-marker startup write skipped: ratification gate was not invoked
         (DevNet no-opt-in legacy path). The marker file is NOT written from
         unratified state.
```

…which preserves the existing pre-Run-105 DevNet legacy behaviour bit-for-bit and proves the §E ("Preserve startup behavior when ratification is not invoked") requirement: no marker is written from unratified state.

### 2.3 The new helper

```rust
fn preflight_run_120_marker_decision_for_startup(
    loaded: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
    updated_at_unix_secs: u64,
) -> Result<Option<MarkerAcceptDecision>, MutatingSurfaceMarkerError>;
```

The function:

1. Skips on `data_dir = None` (DevNet-only convenience — TestNet/MainNet already FATAL upstream for that case).
2. Skips on `BundleSignatureStatus::Unsigned` (no ratified key to anchor a marker on; Run 105 already returned `Ok` for this case).
3. Re-runs `qbind_ledger::enforce_bundle_signing_key_ratification` (pure verifier) against the already-loaded candidate to obtain the typed `RatifiedBundleSigningKey` without changing the Run 105 gate's signature. **Same** inputs, **same** policy, **same** typed outcome semantics — the verifier is the source of truth.
4. Skips on `RatificationEnforcementOutcome::LegacyUnratifiedAccepted` (DevNet/TestNet legacy ergonomics, no ratified key).
5. Otherwise calls `decide_marker_acceptance(MarkerAcceptanceInputs { ..., update_source: AuthorityStateUpdateSource::StartupLoad, ... })`.

The marker is derived ONLY from verified ratification material (rule §B). All four forbidden derivation sources from §B (sidecar JSON alone, local config alone, trust-bundle sequence, activation height/epoch) are absent from the call.

### 2.4 No persistence on rejection / DevNet no-opt-in / validation-only

* `MutatingSurfaceMarkerError` returns from `decide_marker_acceptance` short-circuit BEFORE the Run 055 sequence write and BEFORE any root merge or P2P start — the binary `std::process::exit(1)`s.
* On `Ok(None)` (skip cases above) the binary continues startup unchanged but `startup_marker_decision` stays `None`, so the post-Run-055 `persist_accepted_marker_after_commit_boundary` call site is never reached.
* The DevNet no-opt-in branch (`startup_gate_decision.should_invoke() == false`) explicitly does not call the Run 120 preflight at all — `startup_marker_decision` stays `None` and no marker is written.
* Validation-only surfaces (Run 069/106 reload-check, Run 077/107 peer-candidate-check) are unchanged; they were never mutating in the first place.

---

## 3. What was proven

### 3.1 Source-level proof (ordering / no-marker-from-unratified-state / fail-closed)

| Invariant | Where | Mechanism |
|-----------|-------|-----------|
| Marker compare BEFORE startup mutation. | `crates/qbind-node/src/main.rs`, startup `--p2p-trust-bundle` arm. | `preflight_run_120_marker_decision_for_startup(...)` is called BEFORE `check_and_update_sequence(...)` and BEFORE the bundle-root merge. A `MutatingSurfaceMarkerError` returns `std::process::exit(1)` BEFORE either step. |
| Marker persist AFTER the existing startup commit boundary. | Same file, `Ok(outcome)` arm of `match check_and_update_sequence(...)`. | `persist_accepted_marker_after_commit_boundary(decision)` is called only inside the `Ok(...)` arm, AFTER the Run 055 sequence has already been written to disk by `check_and_update_sequence`. |
| Marker derived only from verified ratification material. | `preflight_run_120_marker_decision_for_startup`. | Inputs come exclusively from (a) the already-validated `LoadedTrustBundle`, (b) the genesis authority block re-loaded via `build_run_105_reload_check_context`, (c) the typed `RatifiedBundleSigningKey` produced by `enforce_bundle_signing_key_ratification`. No sidecar JSON, no local config alone, no trust-bundle sequence, no activation height/epoch enters the derivation. |
| No fake authority sequence. | `decide_marker_acceptance` (Run 119) consumes `authority_sequence: u64` straight from the genesis-authority block. | Run 120 passes `ctx_data.authority.authority_sequence` unchanged. No synthesis, no per-key monotonic invention. |
| DevNet no-opt-in does NOT write the marker. | Same file, `else` branch of `if startup_gate_decision.should_invoke()`. | The `else` branch logs the explicit `[run-120] authority-marker startup write skipped` line and never calls `preflight_run_120_marker_decision_for_startup`; `startup_marker_decision` stays `None`. |
| MainNet/TestNet cannot bypass marker check. | `qbind_node::pqc_ratification_policy::ratification_gate_decision` returns `Invoke` for MainNet and TestNet regardless of any CLI flag (Run 106). | Reaching the Run 120 preflight is the only path through the `Some(path)` arm on MainNet/TestNet that does not first FATAL-exit. |
| Corrupt marker fail-closed. | `decide_marker_acceptance` (Run 119) returns `MutatingSurfaceMarkerError::LoadOrCorruption(_)`. | The Run 120 call site short-circuits to FATAL exit; no auto-overwrite, no silent reset (the helper never writes on the reject path). |
| Persist failure surfaced honestly. | `Err(e)` branch of `persist_accepted_marker_after_commit_boundary(...)` in the startup arm. | Logs the stale-by-one operator recovery note (Run 118 §D crash-window rule) and `std::process::exit(1)`. |

### 3.2 Test proof — `pqc_authority_marker_acceptance::tests` (26 cases, all passing)

9 new Run 120 cases (each named `run_120_*`) on top of the 17 pre-existing Run 119 cases:

| # | Test | Asserts |
|---|------|---------|
| 120.A.1 | `run_120_startup_first_accepted_persists_marker` | First accepted startup ratification produces `FirstWrite`; persisted record carries `AuthorityStateUpdateSource::StartupLoad`. |
| 120.A.2 | `run_120_startup_same_marker_is_idempotent` | Same marker across a simulated restart → `Idempotent`; on-disk bytes NOT rewritten. |
| 120.A.3 | `run_120_startup_conflicting_marker_rejects_before_mutation` | Lower `authority_sequence` rejects with `AuthoritySequenceRollback`; on-disk marker unchanged. |
| 120.A.4 | `run_120_startup_corrupt_marker_fails_closed` | Garbage JSON in marker file fails closed with `LoadOrCorruption`; the helper does NOT auto-overwrite the garbage. |
| 120.A.5 | `run_120_startup_wrong_domain_rejects_before_mutation` | Persisted marker pinned to a foreign `genesis_hash` rejects with `PersistedDomainMismatch`; on-disk marker unchanged. |
| 120.A.6 | `run_120_startup_upgrade_accepts_strictly_higher_sequence` | Strictly higher `authority_sequence` accepts with `Upgrade` and persists. |
| 120.A.7 | `run_120_startup_same_sequence_conflicting_digest_rejects` | Same `authority_sequence`, same key, different ratification digest rejects with `SameSequenceConflictingRatificationDigest`. |
| 120.B.1 | `run_120_decide_does_not_persist_on_startup_path` | `decide_marker_acceptance` never writes — proves compare happens before any mutation. |
| 120.B.2 | `run_120_dropped_decision_does_not_persist_marker` | Dropping a decision (simulating a Run 055 sequence-write failure between preflight and persist) leaves the on-disk marker untouched. |

Command + result:

```text
$ cargo test -p qbind-node --lib pqc_authority_marker_acceptance
running 26 tests
test pqc_authority_marker_acceptance::tests::decide_does_not_persist ... ok
test pqc_authority_marker_acceptance::tests::decide_corrupt_marker_fails_closed ... ok
test pqc_authority_marker_acceptance::tests::decide_missing_marker_is_first_write ... ok
...
test pqc_authority_marker_acceptance::tests::run_120_dropped_decision_does_not_persist_marker ... ok
test pqc_authority_marker_acceptance::tests::run_120_decide_does_not_persist_on_startup_path ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_corrupt_marker_fails_closed ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_conflicting_marker_rejects_before_mutation ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_first_accepted_persists_marker ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_same_marker_is_idempotent ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_same_sequence_conflicting_digest_rejects ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_wrong_domain_rejects_before_mutation ... ok
test pqc_authority_marker_acceptance::tests::run_120_startup_upgrade_accepts_strictly_higher_sequence ... ok
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 1158 filtered out
```

### 3.3 Regression — wider lib + ledger test suites

```text
$ cargo test -p qbind-node --lib
test result: ok. 1184 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-ledger --lib
test result: ok. 231 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Run 119 reload-apply helper unit tests, Run 118 derive/prepare tests, Run 117 authority-state primitive tests, Run 105/106 startup ratification tests, Run 050 signed-bundle tests, Run 055 sequence anti-rollback tests, and Run 091–099 activation_epoch tests are all inside this lib-test sweep and all green.

### 3.4 Release-binary evidence — deferred (honest)

Per the task spec §"Release-binary evidence" — release-binary evidence is optional for Run 120. The §Scenario 1–4 release-binary smoke (first marker persisted, idempotent restart, conflicting marker rejected before network startup, corrupt marker fails closed before network startup) is deferred to a future combined release-binary evidence run alongside SIGHUP wiring, to avoid burning a release-binary build per sub-run.

---

## 4. Key security decisions

| Decision | Rationale |
|----------|-----------|
| Marker derived only from verified ratification. | `preflight_run_120_marker_decision_for_startup` consumes the typed `RatifiedBundleSigningKey` produced by `enforce_bundle_signing_key_ratification` (Run 103/105). No sidecar-only / config-only / sequence / activation-height path. Per §B "Forbidden". |
| Marker distinct from trust-bundle sequence. | The marker carries `authority_sequence` (Run 101 genesis-bound, mutated only by genesis re-issuance); the trust-bundle sequence (Run 055) is the per-bundle monotonic. They live in distinct files (`pqc_authority_state.json` vs the Run 055 sequence file). |
| No fake monotonic authority sequence. | `ctx_data.authority.authority_sequence` is passed through verbatim. Per-key rotation is **not** implemented — Run 120 §"Strict non-goals" explicit. |
| Corruption / conflict fail-closed. | `decide_marker_acceptance` typed errors (`LoadOrCorruption`, `PersistedDomainMismatch`, `AuthoritySequenceRollback`, `SameSequenceConflictingRatificationDigest`, `SameSequenceConflictingKey`, `PolicyVersionRegression`, `Conflict`) each route to a FATAL exit BEFORE the Run 055 sequence write and BEFORE root merge / P2P start. |
| Accepted startup persists marker. | After `check_and_update_sequence` returns `Ok`, `persist_accepted_marker_after_commit_boundary(&decision)` is called and FATAL-exits on persist failure (stale-by-one is honestly logged). |
| No marker on DevNet no-opt-in unratified path. | The `else` arm of `startup_gate_decision.should_invoke()` does not call the Run 120 preflight at all; the marker file remains untouched. Explicit log line emitted. |
| No validation-only persistence. | The Run 069/106 reload-check and Run 077/107 peer-candidate-check paths are unchanged; they never instantiate a `MarkerAcceptDecision`. |
| No peer-driven apply. | Out of Run 120 scope per §"Strict non-goals". |
| No rotation / revocation lifecycle. | Out of Run 120 scope per §"Strict non-goals". |
| No `--allow-authority-state-reset`. | Not introduced. Corrupt marker still fails closed. |

---

## 5. Crash-behavior analysis (task §3)

| Window | What happens on a crash here | Operator recovery |
|--------|------------------------------|--------------------|
| Before `preflight_run_120_marker_decision_for_startup`. | Marker untouched. Sequence file untouched. Equivalent to "startup never happened". | Restart unchanged. |
| Between preflight (accept) and `check_and_update_sequence` `Ok`. | Marker untouched (decision held in memory only). Sequence file untouched. | Restart unchanged — preflight will re-derive an identical decision against the unchanged on-disk marker and either accept idempotent or first-write again. |
| Between `check_and_update_sequence` `Ok` and `persist_accepted_marker_after_commit_boundary`. | **Sequence file advanced; marker stale-by-one.** This is the intentional Run 118 §D crash window — the next accepted startup with the same (or higher) ratification will replay the marker as an `Upgrade` (from the stale value) or `FirstWrite`. | Restart unchanged — Run 120 preflight will see the absent or stale marker and the equal-or-higher trust-bundle sequence in the sequence file; the bundle's authority_sequence is genesis-bound (Run 101) so the marker will re-derive correctly. |
| After `persist_accepted_marker_after_commit_boundary` returns `Ok`. | Both files in sync. | Restart is `Idempotent`. |

This matches the Run 119 §"Threading the helper into a mutating surface" pattern verbatim: marker stale-by-one is safe and replayable; marker ahead of trust sequence is prevented by ordering.

---

## 6. Operator-facing log lines (new in Run 120)

| Line | When |
|------|------|
| `[run-120] authority-marker startup preflight skipped: --data-dir is unset (...)` | DevNet convenience branch with no `--data-dir`. |
| `[run-120] authority-marker startup preflight skipped: candidate bundle is DevNet-unsigned (...)` | Unsigned DevNet bundle accepted by Run 105. |
| `[run-120] authority-marker startup preflight skipped: LegacyUnratifiedAccepted (...)` | DevNet/TestNet legacy-unratified bundle accepted by Run 105 under `--p2p-trust-bundle-allow-unratified-testnet-devnet`. |
| `[run-120] authority-marker startup write skipped: ratification gate was not invoked (...)` | DevNet no-opt-in branch; gate `SKIPPED`. |
| `[run-120] authority-marker persisted at <path> (<kind>; candidate authority_sequence=<n>).` | `FirstWrite` or `Upgrade` accepted and persisted after the Run 055 sequence write. |
| `[run-120] authority-marker unchanged at <path> (idempotent; no rewrite).` | `Idempotent` accepted; persist deliberately skipped to avoid bumping the audit-only `updated_at_unix_secs`. |
| `[run-120] FATAL: startup --p2p-trust-bundle refused by authority-marker preflight: <reason>. Path=<...>. No Run 055 sequence write, no bundle-root merge, no live trust mutation, no P2P startup, no marker write.` | Marker compare rejected the candidate; fail-closed exit BEFORE any startup mutation. |
| `[run-120] FATAL: authority-marker persist failure AFTER successful Run 055 sequence write at startup: <reason>. (...) stale-by-one (...).` | Atomic write or fsync failed after the Run 055 sequence advanced; documented stale-by-one operator recovery state. |

---

## 7. Strict-scope adherence

* Run 120 wires **only** the startup `--p2p-trust-bundle` surface — SIGHUP, validation-only, reload-apply, and peer-candidate surfaces are unchanged.
* No new module, no new CLI flag, no new dependency, no schema change to `PersistentAuthorityStateRecord`.
* The Run 119 `pqc_authority_marker_acceptance` module is reused unchanged at the API level (additive tests only).
* The Run 070 apply pipeline ordering, Run 105/106 ratification policy, Run 055 anti-rollback policy, and Run 057/065 activation-gate policy are all untouched.
* No fallback to `--p2p-trusted-root` on marker rejection — startup fails closed and exits non-zero.

---

## 8. Explicit non-claims

Run 120 does NOT implement:

* SIGHUP authority-marker wiring;
* validation-only authority-marker checks;
* signing-key rotation lifecycle;
* signing-key revocation lifecycle;
* peer-driven live apply;
* peer-driven trust synchronization marker handling;
* KMS / HSM custody;
* governance;
* validator-set rotation;
* per-key monotonic authority-sequence schema;
* `--allow-authority-state-reset`;
* full C4 closure;
* C5 closure.

Static production source-code anchors remain rejected. Local config alone is still not enough for MainNet bundle-signing authority. Transport roots cannot authorize bundle-signing keys. None of these positions change in Run 120.

---

## 9. Residual risks and next recommended run

| Risk | Status |
|------|--------|
| SIGHUP marker wiring missing → a long-running node that hot-reloads via SIGHUP does not write/compare a marker on that path. | OPEN — explicit Run 120 non-goal; next deliverable. |
| Release-binary evidence (§Scenario 1–4) not yet captured. | OPEN — task §"Release-binary evidence" marks this as optional for Run 120. |
| Restore/snapshot marker conflict (Run 117 §C4) handling. | OPEN — Run 117 deferred. |
| Per-key monotonic authority sequence (would distinguish two simultaneous ratifications at the same `authority_sequence` without relying on the ratification-digest tiebreaker). | OPEN — explicit non-goal. |

**Next recommended run:** wire `decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary` into the Run 074/114 SIGHUP live-reload path (the "Run 120b" sub-run referenced in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md` §7). It should be small, mirror the Run 120 startup-path wiring shape exactly, and bring the §"Required tests" SIGHUP-marker test suite online.