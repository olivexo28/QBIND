# QBIND DevNet Evidence — Run 105

**Task:** `task/RUN_105_TASK.txt` — Non-Mutating Bundle-Signing-Key Ratification Enforcement.

**Verdict:** **positive (partial scope, intentionally narrow)**. The Run 105 enforcement layer lands as the **smallest safe non-mutating gate** wired into the existing local validation surfaces (startup `--p2p-trust-bundle` preflight, `--p2p-trust-bundle-reload-check` validation-only path, and the new library entry points used by tests). The `--p2p-trust-bundle-peer-candidate-check` binary-side gate, the live propagation acceptance gate, the reload-apply mutation gate, and the SIGHUP wiring are explicitly **deferred to Run 106**. The deferred surfaces remain **bit-for-bit unchanged** so no existing test or release-binary smoke regresses.

**Anchors:**
- Library helper: `crates/qbind-ledger/src/bundle_signing_ratification.rs` — `enforce_bundle_signing_key_ratification`, `RatificationEnforcementInputs`, `RatificationEnforcementOutcome`, `RatificationEnforcementFailure`, `RatificationEnforcementPolicy`. 9 new in-module unit tests (`run_105_*`) covering every fail-closed branch.
- Sidecar JSON loader: `crates/qbind-node/src/pqc_ratification_input.rs` (read-only, local-file-only, no network input).
- Reload-check entry points: `crates/qbind-node/src/pqc_trust_reload.rs` — new `validate_candidate_bundle_full_with_ratification`, `validate_candidate_bundle_with_ratification`, `RatificationEnforcementContext`, `ReloadCheckError::RatificationRefused`. The original `validate_candidate_bundle*` entry points are bit-for-bit unchanged.
- CLI flags (all hidden, disabled-by-default): `crates/qbind-node/src/cli.rs` — `--p2p-trust-bundle-ratification-enforcement-enabled`, `--p2p-trust-bundle-ratification`, `--p2p-trust-bundle-allow-unratified-testnet-devnet`.
- Startup binary gate: `crates/qbind-node/src/main.rs` — `apply_run_105_ratification_gate_at_startup` runs AFTER all Run 050/051/053/057/062/065 validation succeeds and the activation gate is satisfied, BEFORE the Run 055 sequence write and BEFORE the bundle's roots are merged into `trusted_roots`.
- Reload-check binary gate: `crates/qbind-node/src/main.rs` — `build_run_105_reload_check_context` + branched call into `validate_candidate_bundle_with_ratification` when the operator opts in.
- Integration tests: `crates/qbind-node/tests/run_105_ratification_enforcement_tests.rs` (6 tests).

---

## 1. Strict scope

Run 105 is **only** the non-mutating enforcement gate. Each call site that opts in:

1. Reads the operator-supplied ratification sidecar JSON exactly once (`std::fs::read` + `serde_json::from_slice` via `pqc_ratification_input::load_ratification_from_path`).
2. Calls `qbind_ledger::enforce_bundle_signing_key_ratification`.
3. Either proceeds (logging the verdict) or fails closed with a typed reason.

It is explicitly **NOT**:

- a peer-supplied / gossiped ratification acceptance path,
- a wire propagation rebroadcast path,
- a reload-apply mutation path,
- a SIGHUP / hot-reload trigger,
- a signing-key rotation / custody / KMS / HSM mechanism,
- a network listener of any kind.

These remain Run 106+ scope.

## 2. Per-surface contract

### 2.1 Startup `--p2p-trust-bundle` preflight (`apply_run_105_ratification_gate_at_startup`)

| Step | Action |
|------|--------|
| 1 | `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation` (Run 050/051/053/057/062/065) |
| 2 | Activation gate satisfied (Run 057 / Run 091) |
| 3 | **Run 105 gate** — operator-opt-in. Disabled by default. |
| 4 | Run 055 anti-rollback sequence write (`check_and_update_sequence`) |
| 5 | Bundle roots merged into `trusted_roots` |

A refused ratification at step 3 fails closed with non-zero exit BEFORE step 4 and BEFORE step 5: no sequence record is written, no root is merged into the live PQC trust set, no session is touched.

### 2.2 `--p2p-trust-bundle-reload-check` validation-only path

| Step | Action |
|------|--------|
| 1 | `validate_candidate_bundle_full` runs the Run 069 pipeline (Run 050/051/053/057/062/065 + Run 055 read-only peek + Run 061 + Run 063). |
| 2 | **Run 105 gate** — operator-opt-in. Disabled by default. |
| 3 | Verdict logged; `std::process::exit(0/1)`. |

The validator never writes the sequence record on this path (Run 069 invariant), and the Run 105 gate adds zero additional file writes; both branches are read-only.

### 2.3 New library entry points

`validate_candidate_bundle_full_with_ratification` and `validate_candidate_bundle_with_ratification` wrap the Run 069 entry points unchanged and apply the gate after success. Pre-Run-105 callers do not need to change call shape; the existing `ReloadCheckInputs` struct is bit-for-bit unchanged. (This was a deliberate design choice to avoid touching ~18 existing test call sites.)

### 2.4 Deferred to Run 106 (explicit non-scope)

- `--p2p-trust-bundle-peer-candidate-check` binary path: still uses unchanged `validate_candidate_bundle_full`. The entire Run 076 pipeline is bit-for-bit unchanged so all 16 Run 076 tests remain green.
- Live propagation (`--p2p-trust-bundle-peer-candidate-propagation-enabled`): unchanged.
- Reload-apply (`apply_validated_candidate`) and SIGHUP path: unchanged.

## 3. Per-environment policy

| Environment | Default policy | `--p2p-trust-bundle-allow-unratified-testnet-devnet` effect |
|-------------|----------------|-------------------------------------------------------------|
| MainNet     | `Strict`       | **Refused** at the helper level (defense in depth) — see `run_105_mainnet_refuses_legacy_unratified_policy`. |
| TestNet     | `Strict`       | Permits `LegacyUnratifiedAccepted` outcome when no ratification is supplied. |
| DevNet      | `Strict`       | Permits `LegacyUnratifiedAccepted` outcome when no ratification is supplied. |

Under any policy, a *supplied* ratification that fails verification (wrong chain, wrong env, unknown root, transport-root, bad signature, bad public key, etc.) is **always** refused regardless of environment — the helper propagates the typed `RatificationFailure` through `RatificationEnforcementFailure::Verifier`.

## 4. Fail-closed branches

`RatificationEnforcementFailure` enumerates exactly the typed reasons the gate can refuse a candidate:

| Variant | When |
|---------|------|
| `Missing` | `policy = Strict` and `ratification = None`. |
| `RatifiesDifferentKey { ratified_fp, candidate_fp }` | The ratification authorises a different bundle-signing key than the candidate's signature was verified by. Proves the operator did not accidentally pair a stale ratification with a freshly-rotated key. |
| `Verifier(RatificationFailure)` | Inner Run 103/104 verifier failed (chain, env, genesis hash, unknown root, transport-root, bad signature, malformed PK, etc.). |
| `NoBundleSigningAuthorityConfigured` | Strict policy, but `genesis.authority.bundle_signing_authority_roots` is empty. |
| `MainnetLegacyUnratifiedRefused` | Defense-in-depth — `AllowLegacyUnratified` policy is refused on MainNet at the helper boundary. |

## 5. Test coverage

**qbind-ledger lib:** 222 tests pass (was 213 in Run 104), including 9 new `run_105_*` unit tests:

- `run_105_strict_mainnet_accepts_valid_ratification`
- `run_105_strict_mainnet_rejects_missing_ratification`
- `run_105_strict_testnet_rejects_missing_ratification`
- `run_105_devnet_legacy_unratified_returns_explicit_verdict`
- `run_105_mainnet_refuses_legacy_unratified_policy`
- `run_105_propagates_verifier_failure_on_wrong_chain`
- `run_105_rejects_ratification_for_different_key`
- `run_105_strict_refuses_when_authority_block_has_no_bundle_signing_roots`
- `run_105_transport_root_cannot_ratify_via_enforcer`

**qbind-node sidecar loader:** 3 unit tests (round-trip / I/O error / parse error).

**qbind-node integration:** 6 tests in `run_105_ratification_enforcement_tests.rs`:

- `run_105_strict_devnet_valid_ratification_validates_candidate`
- `run_105_strict_devnet_missing_ratification_refused_without_mutation`
- `run_105_ratification_for_different_key_refused`
- `run_105_wrong_chain_ratification_refused`
- `run_105_devnet_legacy_unratified_accepts`
- `run_105_full_entry_point_returns_loaded_bundle_and_activation`

**Regression suites called out by the task** — all green:

| Suite | Tests |
|-------|-------|
| Run 050 (trust-bundle schema) | 14 |
| Run 051 (signing) | 13 |
| Run 052 (leaf revocation) | 12 |
| Run 055 (sequence anti-rollback) | 12 |
| Run 057 (activation gate) | 12 |
| Run 061 (local-leaf self-check) | 9 |
| Run 062 (revocation activation) | 11 |
| Run 063 (issuer-root self-check) | 8 |
| Run 065 (min activation margin) | 12 |
| Run 069 (reload-check) | 12 |
| Run 070 (reload-apply) | 13 |
| Run 071 (live trust) | 13 |
| Run 073 (process-start apply) | 10 |
| Run 074 (SIGHUP live reload) | 10 |
| Run 076 (peer-candidate validator) | 16 |
| Run 078 (peer-candidate wire) | 19 |
| Run 088 (peer-candidate propagation) | 5 |
| Run 091 (activation epoch) | 15 |
| Run 101 (genesis authority) | 11 |
| Run 102 (boot-genesis wiring) | 14 |
| Run 103 (ratification verifier) | 8 |
| Run 104 (authority key material) | 9 |
| Run 105 (this run, integration) | 6 |
| **Total Run 105-related qbind-node** | **264 PASS / 0 FAIL** |

The pre-existing failure in `m16_epoch_transition_hardening_tests` is unchanged and unrelated to Run 105 (verified by checking the same failure on `HEAD~`).

## 6. Operator workflow (illustrative)

Disabled by default — running the binary with no Run 105 flag preserves bit-for-bit pre-Run-105 behaviour. Operators opt in with three flags:

1. `--p2p-trust-bundle-ratification-enforcement-enabled`
2. `--p2p-trust-bundle-ratification <PATH>` (REQUIRED on MainNet, OPTIONAL on TestNet/DevNet)
3. `--p2p-trust-bundle-allow-unratified-testnet-devnet` (TestNet/DevNet escape hatch only — refused on MainNet by the helper itself for defense in depth)

The sidecar JSON file is the operator's local artefact, produced out-of-band by the same trusted authority that owns `--p2p-trust-bundle`. There is **no network input**, **no peer input**, **no admin / RPC endpoint** that this run introduces.

## 7. Security properties (run-relative)

| Property | Status |
|----------|--------|
| Cannot install a bundle whose signing key is unknown to the genesis authority block | Enforced at startup (when opted in) and at the reload-check binary path (when opted in). |
| MainNet always refuses unratified bundles | Enforced both at the policy choice in `main.rs` (always Strict on MainNet) AND at the helper level (`MainnetLegacyUnratifiedRefused` defense in depth). |
| Refusing a candidate must NOT mutate live trust state, sequence persistence, or sessions | Proven by:<br>• Run 069 contract — `validate_candidate_bundle*` is read-only.<br>• `validate_candidate_bundle_full_with_ratification` wraps it; the Run 105 gate runs after the read-only inner call.<br>• Startup gate runs strictly before `check_and_update_sequence` and the root-merge step. |
| Run 105 cannot ratify a transport root as a bundle-signing authority | Enforced at the verifier (`AuthorityRootMustBeBundleSigning`) and re-asserted by `run_105_transport_root_cannot_ratify_via_enforcer`. |
| Operator cannot accidentally arm enforcement | The path flag without `--p2p-trust-bundle-ratification-enforcement-enabled` is ignored; the opt-in flag is hidden in `--help` to make it explicit-only. |

## 8. References

- `task/RUN_105_TASK.txt` — task source.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_103.md` — verifier landing.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_104.md` — authority key material registry.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §"Run 105 ratification enforcement".
- `docs/whitepaper/contradiction.md` — C4 PQC trust anchor authority chain.