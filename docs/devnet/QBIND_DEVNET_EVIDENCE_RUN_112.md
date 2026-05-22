# Run 112 — DevNet evidence: process-start reload-apply ratification enforcement

**Status:** positive for source + integration-test surface; **partial-positive** for release-binary evidence (deferred to a follow-up evidence-only run).

**Scope (from `task/RUN_112_TASK.txt`):** wire the Run 105 bundle-signing-key ratification enforcement body into the **process-start reload-apply path** that the Run 070 / Run 073 flags `--p2p-trust-bundle-reload-apply-enabled` and `--p2p-trust-bundle-reload-apply-path` already drive, gated by the Run 106 per-environment policy, while preserving the existing Run 070 `validate → snapshot → swap → evict_sessions → commit_sequence` ordering bit-for-bit.

**Explicitly out of scope:** SIGHUP live reload, peer-driven live apply on the `0x05` wire, signing-key rotation, signing-key revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync / broader consensus-storage-restore ratification parity, governance, validator-set rotation, removal of the MainNet `local-config alone is not enough` posture, and full C4 / C5 closure.

## What changed

### Library — `crates/qbind-node/src/pqc_trust_reload.rs`
- Extracted the post-validation half of the apply pipeline into a private `apply_post_validation(loaded, validated, mode, ctx)` helper that performs `snapshot → swap → evict_sessions → commit_sequence` in the same order Run 070 / Run 073 ship. This is shared verbatim by the legacy entry and the new entries; the only difference between them is the validator they call upstream.
- Added `apply_validated_candidate_with_ratification(inputs, ratification_ctx, mode, ctx)` — calls `validate_candidate_bundle_full_with_ratification` (the existing Run 105 wrapper) and then delegates to `apply_post_validation`. On any refusal the function returns `ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))` BEFORE any post-validation step runs.
- Added `apply_validated_candidate_with_previous_and_ratification(inputs, ratification_ctx, mode, ctx, previous_fingerprint_prefix, previous_sequence)` — the entry point the binary calls from the reload-apply branch; identical to the above but additionally surfaces operator-supplied previous-state metadata on success, matching the Run 070 / Run 073 contract.

### Binary — `crates/qbind-node/src/main.rs`
- The process-start reload-apply branch now dispatches on `ratification_gate_decision(env, p2p_trust_bundle_ratification_enforcement_enabled)` — the same function already used by the reload-check and peer-candidate-check paths (Run 106). On `Invoke(_)` the binary builds the Run 105 `RatificationEnforcementContext` via the existing `build_run_105_reload_check_context` helper and calls `apply_validated_candidate_with_previous_and_ratification`. On `Skip(DevnetNoOperatorOptIn)` the binary falls through to the legacy `apply_validated_candidate_with_previous`, preserving the pre-Run-112 DevNet ergonomics bit-for-bit.
- Context-build failure (missing `--genesis-config-path`, missing `genesis.authority`, malformed Run 105 sidecar) on a path that the policy says must `Invoke` is FATAL with a typed `[run-112] FATAL` log line and a non-zero exit; this matches the Run 105 / Run 107 / Run 109 FATAL pattern.
- The Run 105 sidecar / input model is reused verbatim via `--p2p-trust-bundle-ratification`; no new operator flag was added.

### Integration tests — `crates/qbind-node/tests/run_112_reload_apply_ratification_tests.rs` (10 tests, all passing)
- `run112_valid_ratification_under_strict_completes_apply_with_run070_ordering` — Strict policy + valid ratification + matching bundle-signing key drives the recorded callback sequence `[snapshot_active, swap_trust_state, evict_sessions, commit_sequence]` bit-for-bit. Operator-supplied previous-state metadata is surfaced back on success.
- `run112_missing_ratification_under_strict_refuses_before_any_mutation` — Strict + `ratification = None` → `ValidationFailed(RatificationRefused(Missing))`; ZERO callbacks fire; the sequence persistence file is never created; the live fingerprint stays at its pre-apply value.
- `run112_bad_signature_ratification_under_strict_refuses_before_any_mutation` — Strict + tampered ratification signature (signature byte 0 XOR `0xFF`) → `ValidationFailed(RatificationRefused(Verifier(_)))`; ZERO callbacks; ZERO sequence file.
- `run112_wrong_chain_ratification_refuses_before_any_mutation` — Strict + chain-id mismatch → `ValidationFailed(RatificationRefused(Verifier(ChainMismatch{..})))`; ZERO callbacks; ZERO sequence file.
- `run112_wrong_environment_ratification_refuses_before_any_mutation` — Strict + environment mismatch (DevNet candidate, MainNet ratification env) → `ValidationFailed(RatificationRefused(_))`; ZERO callbacks; ZERO sequence file.
- `run112_unknown_authority_root_ratification_refuses_before_any_mutation` — Strict + ratification produced by an unrelated authority key (not in the genesis `bundle_signing_authority_roots`) → `ValidationFailed(RatificationRefused(_))`; ZERO callbacks; ZERO sequence file.
- `run112_ratification_for_different_key_refuses_before_any_mutation` — Strict + ratification authorising a different bundle-signing key than the candidate is signed with → `ValidationFailed(RatificationRefused(RatifiesDifferentKey{..}))`; ZERO callbacks; ZERO sequence file.
- `run112_devnet_legacy_allow_unratified_still_applies_with_run070_ordering` — DevNet `AllowLegacyUnratified` + missing ratification still drives the full Run 070 four-step ordering; proves DevNet opt-out ergonomics are preserved when the binary chooses the legacy policy.
- `run112_validate_only_mode_still_runs_ratification_gate` — `ApplyMode::ValidateOnly` + Strict + missing ratification still refuses with `ValidationFailed(RatificationRefused(_))`; the gate is part of the validation stage and is not deferred to live-apply.
- `run112_run106_policy_drives_apply_gate_consistently` — pins the Run 106 gate-decision matrix the binary now consumes (MainNet/TestNet always `Invoke` regardless of opt-in; DevNet `Skip` without opt-in, `Invoke` with opt-in).

### Regression suites (same build)
- `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests` → 13/0 passed.
- `cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests` → 10/0 passed.
- `cargo test -p qbind-node --test run_105_ratification_enforcement_tests` → 6/0 passed.
- `cargo test -p qbind-node --test run_106_ratification_policy_tests` → 7/0 passed.
- `cargo test -p qbind-node --test run_112_reload_apply_ratification_tests` → 10/0 passed.

## Ordering invariant — proof sketch

The Run 105 wrapper `validate_candidate_bundle_full_with_ratification` returns `Err(ReloadCheckError::RatificationRefused(_))` on any ratification failure. `apply_validated_candidate_with_ratification` propagates that error through `?` BEFORE invoking `apply_post_validation`, which is the only function that performs snapshot / swap / evict / commit. Therefore every refusal path bypasses the entire post-validation pipeline; the integration tests pin this with a `FakeLiveTrustApplyContext` whose `CallLog` is asserted empty on every refusal scenario. On success the function falls through to `apply_post_validation`, which performs exactly the same four steps in the same order that `apply_validated_candidate` performs — they share the same helper body byte-for-byte.

## Non-claims (explicit, per task §"Required final response format" §7)

Run 112 does NOT:
1. Implement SIGHUP live reload ratification enforcement. The SIGHUP path was explicitly out of scope and is untouched.
2. Implement peer-driven live apply on the `0x05` wire. Peer-candidate apply remains intentionally non-mutating per Run 088 / Run 109 contract.
3. Implement signing-key rotation or revocation lifecycle.
4. Implement authority anti-rollback persistence.
5. Add KMS/HSM custody, governance, or validator-set rotation.
6. Change any wire format, verifier semantics, or enforcement policy beyond binding the existing Run 105 enforcement body to a new caller.
7. Remove the MainNet `local-config alone is not enough` posture.
8. Provide a fresh release-binary multi-node DevNet capture of the reload-apply ratification scenarios. The release-binary evidence layer is deferred to a follow-up evidence-only run; this PR ships positive source + integration-test evidence only.
9. Close full C4 or C5.

## Verdict

**Positive** for source + integration-test surface (entry point landed, ordering preserved bit-for-bit, all Run 105 refusal failure variants pinned by integration tests, all Run 070 / Run 073 / Run 105 / Run 106 regressions green). **Partial-positive** for release-binary evidence (deferred).