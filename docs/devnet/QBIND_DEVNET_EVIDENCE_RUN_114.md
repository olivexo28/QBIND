# Run 114 — DevNet evidence: SIGHUP live reload ratification enforcement

**Status:** positive for source + integration-test surface; **partial-positive** for release-binary evidence (deferred to a follow-up evidence-only run).

**Scope (from `task/RUN_114_TASK.txt`):** wire the Run 105 bundle-signing-key ratification enforcement body into the **SIGHUP live trust-bundle reload-apply trigger** (Run 074) — the long-running-node path that the `--p2p-trust-bundle-live-reload-enabled` / `--p2p-trust-bundle-live-reload-path` flags already drive — gated by the same Run 106 per-environment policy already used by the reload-check (Run 069/106), peer-candidate-check (Run 077/107), peer-candidate wire (Run 100/109), and process-start reload-apply (Run 073/112) surfaces. The existing Run 074 `validate → snapshot → swap → evict_sessions → commit_sequence` ordering is preserved bit-for-bit on the accept path. On any ratification refusal the trigger surfaces `LiveReloadOutcome::Invalid(_)` BEFORE any snapshot, swap, eviction, or sequence commit step, with no live trust mutation, no session eviction, and no on-disk sequence file write.

**Explicitly out of scope** (deferred, tracked in `docs/whitepaper/contradiction.md` C4 / C5):

* Peer-driven live apply on the `0x05` peer-candidate wire (Run 100/109 already enforces ratification on the validation surface; live application from peers is not implemented).
* Signing-key rotation and revocation.
* Authority anti-rollback persistence.
* KMS/HSM custody of authority and bundle-signing private keys.
* Fast-sync / broader consensus-storage-restore ratification parity.
* Governance, validator-set rotation.
* Removal of the MainNet "local-config alone is not enough" posture.
* Full C4 / C5 closure.

No new trust-bundle / peer-candidate / ratification wire format. No new operator flag. No new metric family. No weakening of any existing Run 050/055/057/065/069/070/072/073/074/103/104/105/106/107/109/112 invariant.

## What changed

### Library — `crates/qbind-node/src/pqc_live_trust_reload.rs`

* Added `LiveReloadRatificationConfig` — owned per-controller ratification context inputs: `authority`, `expected_genesis_hash`, `expected_environment_policy`, `expected_chain_id_str`, `policy`, `ratification_sidecar_path`. Built once at controller construction time from the same data the Run 105 startup gate already consumes. Cheap to clone; held by the long-running controller for the lifetime of the node.
* Extended `LiveReloadConfig` with a single new field: `pub ratification: Option<LiveReloadRatificationConfig>`. `Some(_)` enables Run 105 enforcement on every SIGHUP trigger; `None` preserves the pre-Run-114 SIGHUP behaviour bit-for-bit. The Run 106 per-environment policy decision is made once at controller construction time and reflected in the `Some` / `None` shape — the controller does not re-evaluate the gate decision per-trigger.
* Modified `LiveReloadController::run_apply_pipeline` to branch on `self.config.ratification`:
  * On `Some(rcfg)`, the controller re-reads the sidecar JSON at `rcfg.ratification_sidecar_path` (if `Some`) for every trigger, so an operator can replace the sidecar in-place between SIGHUPs without restarting the node. Sidecar I/O / parse failures are routed to a fail-closed `LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(ReloadCheckError::Bundle(_)))`, ensuring sidecar-load failure goes through the same pre-mutation refusal pathway as any other candidate-load failure (no snapshot, no swap, no eviction, no commit). The controller then calls `apply_validated_candidate_with_previous_and_ratification(...)` — the Run 112 entry point — which runs the Run 105 ratification gate BEFORE any apply-pipeline step.
  * On `None`, the controller calls `apply_validated_candidate_with_previous(...)` exactly as before. This branch is reachable only when the Run 106 policy was `Skip` at controller construction time — i.e. DevNet without `--p2p-trust-bundle-ratification-enforcement-enabled`. MainNet and TestNet are unreachable on this branch.
* Mapping of refused outcomes to operator-visible state is unchanged: `Invalid(_)` for every ratification refusal; `Fatal(_)` is reserved (as before) exclusively for `SequenceCommitFailedRollbackAlsoFailed`.

### Binary — `crates/qbind-node/src/main.rs`

* `spawn_run074_live_reload_task` now dispatches on the existing `qbind_node::pqc_ratification_policy::ratification_gate_decision(config.environment, args.p2p_trust_bundle_ratification_enforcement_enabled)` — the SAME function used by the reload-check, peer-candidate-check, peer-candidate-wire, and process-start reload-apply paths.
* On `Invoke(_)` the binary builds the Run 105 ratification context via the existing `build_run_105_reload_check_context(args, config)` helper (no new helper introduced) and populates `LiveReloadConfig::ratification` with a `LiveReloadRatificationConfig` carrying the operator-supplied `--p2p-trust-bundle-ratification` path (re-read per-trigger by the controller).
* On `Skip(DevnetNoOperatorOptIn)` the binary leaves `LiveReloadConfig::ratification = None`, preserving the pre-Run-114 SIGHUP behaviour bit-for-bit.
* Context-build failure (missing `--genesis-path`, missing `genesis.authority`, malformed Run 105 sidecar at construction time) on a path that the policy says must `Invoke` is FATAL: the SIGHUP handler is NOT installed; the node continues running on the baseline trust bundle; no live trust mutation, no session eviction, no sequence write will occur via SIGHUP. This matches the Run 105 / Run 107 / Run 109 / Run 112 FATAL pattern.
* The Run 105 sidecar / input model is reused verbatim via `--p2p-trust-bundle-ratification`; no new operator flag was added. No change to `LiveReloadController::new` signature, the SIGHUP signal handler installation logic, the shutdown handling, or the canonical Run 074 operator-log lines.

### Integration tests — `crates/qbind-node/tests/run_114_sighup_live_reload_ratification_tests.rs` (14 tests, all passing)

* `run114_strict_valid_ratification_applies_and_preserves_run074_ordering` — Strict policy + valid ratification + matching bundle-signing key drives the existing Run 074 ordering bit-for-bit. The live state advances to the candidate fingerprint, the evictor is called exactly once, the sequence file is rewritten, and `live_reload_apply_success_total` advances by 1.
* `run114_strict_missing_sidecar_refuses_before_any_mutation` — Strict + no sidecar at all → `Invalid(ValidationFailed(RatificationRefused(Missing)))`. Live state unchanged; sequence file never created; evictor never called; failure counter advances.
* `run114_strict_bad_signature_sidecar_refuses_before_any_mutation` — Strict + tampered ratification signature → `Invalid(ValidationFailed(RatificationRefused(Verifier(BadSignature))))`. No live trust mutation, no sequence file, no eviction.
* `run114_strict_wrong_chain_sidecar_refuses_before_any_mutation` — Strict + ratification minted for a different `chain_id` → `Invalid(ValidationFailed(RatificationRefused(Verifier(ChainMismatch{..}))))`. No mutation.
* `run114_strict_wrong_environment_sidecar_refuses_before_any_mutation` — Strict + ratification minted for `RatificationEnvironment::Mainnet` on a DevNet runtime → `Invalid(ValidationFailed(RatificationRefused(Verifier(EnvironmentMismatch{..}))))`. No mutation.
* `run114_strict_unknown_authority_root_refuses_before_any_mutation` — Strict + ratification signed by a freshly-generated authority key not present in the genesis authority block → `Invalid(ValidationFailed(RatificationRefused(Verifier(UnknownAuthorityRoot{..}))))`. No mutation.
* `run114_strict_ratifies_different_key_refuses_before_any_mutation` — Strict + valid signed ratification that authorises a different bundle-signing public key than the candidate is signed with → `Invalid(ValidationFailed(RatificationRefused(RatifiesDifferentKey{..})))`. No mutation.
* `run114_strict_sidecar_io_failure_refuses_before_any_mutation` — Strict + sidecar path pointing at a missing file → `Invalid(ValidationFailed(Bundle(_)))` (sidecar I/O routes through the same pre-mutation refusal pathway as candidate-load I/O). No mutation; failure counter advances.
* `run114_strict_sidecar_parse_failure_refuses_before_any_mutation` — Strict + malformed JSON sidecar → `Invalid(ValidationFailed(Bundle(_)))`. No mutation.
* `run114_invalid_sighup_followed_by_valid_sighup_succeeds` — Operator-flow integration: first SIGHUP refused (missing sidecar), operator drops a valid sidecar at the same path, second SIGHUP applies. Proves the per-trigger sidecar re-read works and that an earlier refusal does not poison later triggers. Metrics: 2 triggers, 1 success, 1 failure.
* `run114_valid_sighup_followed_by_invalid_sighup_does_not_rollback_prior_state` — First SIGHUP applies; operator overwrites sidecar with malformed JSON; second SIGHUP refuses. The prior valid live state and the on-disk sequence record are unchanged. Proves a later refusal does not roll back an earlier accepted apply.
* `run114_repeated_invalid_sighups_do_not_mutate_or_advance_sequence` — Five consecutive SIGHUPs with no sidecar at any point each return `Invalid` without mutating live state, without creating the sequence file, and without calling the evictor. Metrics: 5 triggers, 5 failures, 0 successes, 0 sessions evicted.
* `run114_devnet_no_opt_in_skips_ratification_and_applies_via_pre_run114_path` — Controller constructed with `ratification: None` (the Run 106 `Skip` branch) applies the candidate via the pre-Run-114 path. Proves DevNet legacy ergonomics are preserved bit-for-bit.
* `run114_ratification_refusal_short_circuits_apply_pipeline` — Regression guard: the Run 105 gate must short-circuit BEFORE any other check (candidate load, sequence peek, local-leaf self-check). Proven by routing a missing sidecar through a candidate that would otherwise validate cleanly; the failure variant is `Missing`, not a later-pipeline variant.

### Library tests — `crates/qbind-node/src/pqc_live_trust_reload.rs`

* The existing in-file `pqc_live_trust_reload::tests::*` suite continues to pass (5 tests). The `devnet_config(...)` test helper now sets `ratification: None`, preserving the pre-Run-114 behaviour exercised by those tests.

### Regression coverage (all green after Run 114)

```
run_069_pqc_trust_bundle_reload_check_tests              12 passed
run_070_pqc_trust_bundle_reload_apply_tests              13 passed
run_073_pqc_trust_bundle_reload_apply_runtime_tests      10 passed
run_074_pqc_trust_bundle_live_reload_tests               10 passed
run_105_ratification_enforcement_tests                    6 passed
run_106_ratification_policy_tests                         7 passed
run_107_peer_candidate_ratification_tests                 6 passed
run_109_pqc_peer_candidate_wire_live_ratification_tests  23 passed
run_112_reload_apply_ratification_tests                  10 passed
run_114_sighup_live_reload_ratification_tests            14 passed (NEW)
```

## Per-environment behaviour (Run 106 dispatch)

| Environment | Operator flag                                                         | Gate decision                        | SIGHUP enforcement                                                                                  |
| ----------- | --------------------------------------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------- |
| **Mainnet** | (ignored — cannot enable or disable)                                  | `Invoke(MainnetDefaultStrict)`       | Ratification REQUIRED on every SIGHUP; sidecar re-read per trigger; refusal before any mutation.    |
| **Testnet** | (ignored unless paired with `--p2p-trust-bundle-allow-unratified-…`)  | `Invoke(TestnetDefaultStrict)`       | Ratification REQUIRED on every SIGHUP; sidecar re-read per trigger; refusal before any mutation.    |
| **Devnet**  | `--p2p-trust-bundle-ratification-enforcement-enabled`                 | `Invoke(DevnetOperatorOptIn)`        | Ratification REQUIRED on every SIGHUP; sidecar re-read per trigger; refusal before any mutation.    |
| **Devnet**  | (flag not supplied)                                                   | `Skip(DevnetNoOperatorOptIn)`        | Pre-Run-114 behaviour preserved bit-for-bit; no ratification check on SIGHUP.                       |

The Run 106 policy is identical to the policy already enforced on reload-check (Run 069/106), peer-candidate-check (Run 077/107), peer-candidate-wire (Run 100/109), and process-start reload-apply (Run 073/112). Run 114 closes the last `0x074` surface listed in the Run 105 / Run 106 "explicitly NOT covered" follow-ups for the SIGHUP path.

## Fail-closed invariants (proven by the test suite)

On any ratification refusal, on every SIGHUP trigger that reaches `run_apply_pipeline`:

1. The live `LivePqcTrustState` handle is unchanged. Snapshot fingerprint before and after the refused trigger is identical.
2. The on-disk sequence persistence file is unchanged. If absent before the trigger, it remains absent. If present before the trigger, its bytes and mtime are unchanged.
3. The `P2pSessionEvictor` is never invoked. `attempt_count()` does not advance.
4. The `live_reload_apply_failure_total` metric advances by 1; `live_reload_apply_success_total` does not advance; `live_reload_sessions_evicted_total` does not advance; `live_reload_last_applied_sequence` is unchanged.
5. The operator-log line is the canonical Run 074 `[binary] Run 074: VERDICT=invalid …` shape; no new operator-log line was introduced.

## Operator runbook (delta only)

* When running with `--p2p-trust-bundle-live-reload-enabled` on MainNet / TestNet, the operator MUST also supply `--p2p-trust-bundle-ratification <PATH>` — without it, every SIGHUP will be refused with the `Missing` variant. This is the same precondition that already applies to the reload-check / peer-candidate-check / process-start reload-apply paths under Run 105 / Run 106.
* The sidecar JSON at the supplied path is re-read on every SIGHUP. To rotate the sidecar without restarting the node, the operator writes the new sidecar in-place and sends `SIGHUP`. The Run 074 trigger reads the new sidecar atomically and applies the candidate iff it verifies.
* On DevNet, supplying `--p2p-trust-bundle-ratification-enforcement-enabled` switches the SIGHUP path to the same enforcement mode as MainNet / TestNet. The flag has no effect on MainNet / TestNet (those environments always enforce by default; the flag cannot disable enforcement).
* Sidecar I/O / parse failures (missing file at the configured path, permission denied, malformed JSON) surface as a fail-closed `Invalid` outcome on the SIGHUP trigger and bump `live_reload_apply_failure_total` — no live trust mutation, no session eviction, no sequence write. The node continues running on the previously-applied trust bundle.

## Files

* `crates/qbind-node/src/pqc_live_trust_reload.rs` — added `LiveReloadRatificationConfig`, extended `LiveReloadConfig`, wired the ratification preflight in `LiveReloadController::run_apply_pipeline`.
* `crates/qbind-node/src/main.rs` — wired Run 106 policy dispatch in `spawn_run074_live_reload_task`; FATAL on context-build failure under `Invoke`.
* `crates/qbind-node/tests/run_114_sighup_live_reload_ratification_tests.rs` — 14 new integration tests.
* `crates/qbind-node/tests/run_074_pqc_trust_bundle_live_reload_tests.rs` — updated `devnet_config(...)` test helper to default `ratification: None`; no behavioural change.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_114.md` — this file.
* `docs/whitepaper/contradiction.md` — Run 114 added to the closed-surface list for C4.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 114 added to the SIGHUP enforcement row.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 114 added to the per-SIGHUP-trigger runbook delta.

## Release-binary evidence (deferred)

A follow-up evidence-only run will:

1. Boot a long-running `qbind-node` on DevNet with `--p2p-mode p2p`, `--p2p-trust-bundle <baseline>`, `--p2p-trust-bundle-live-reload-enabled`, `--p2p-trust-bundle-live-reload-path <candidate>`, `--genesis-path <genesis>`, `--p2p-trust-bundle-ratification-enforcement-enabled`, `--p2p-trust-bundle-ratification <sidecar>`.
2. Record `kill -HUP <pid>` against valid / missing / bad / wrong-chain / wrong-env / different-key sidecars and assert the controller log lines and `/metrics` deltas match this evidence file.
3. Archive logs and `/metrics` under `evidence/run-114/`.

This is non-blocking for Run 114 source acceptance; the integration-test layer above proves every invariant against the same controller entry point the binary calls.