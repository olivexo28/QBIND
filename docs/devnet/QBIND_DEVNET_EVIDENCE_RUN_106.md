# QBIND DevNet Evidence — Run 106

**Task:** `task/RUN_106_TASK.txt` — Complete Ratification Enforcement Coverage and MainNet Default Strictness.

**Verdict:** **partial-positive (default strictness narrowly delivered for the surfaces Run 105 already wired; remaining surfaces explicitly deferred with documented blockers).**

Run 106 advances Run 105's ratification enforcement layer along **one axis only**: it removes the operator-opt-in gate from the **invocation decision** on the two trust-bundle validation surfaces Run 105 wired (startup preflight + `--p2p-trust-bundle-reload-check`), so that MainNet and TestNet now invoke the Run 105 gate **by default** without the operator having to supply the hidden `--p2p-trust-bundle-ratification-enforcement-enabled` flag. The gate body itself is **bit-for-bit unchanged** from Run 105.

Run 106 **does not** wire ratification into the remaining surfaces enumerated in `task/RUN_106_TASK.txt`. Those surfaces are deferred with explicit, honest blockers in §6 below. This is not a strongest-positive result; the task itself explicitly authorises a partial-positive verdict in this shape ("enforcement coverage improves but important surfaces remain deferred; default strictness is incomplete").

---

## 1. Anchors

- **New library module:** `crates/qbind-node/src/pqc_ratification_policy.rs` — pure, no-I/O, no-crypto per-environment helper. Defines `RatificationGateDecision`, `GateInvokeReason`, `GateSkipReason`, and `ratification_gate_decision(env, operator_opt_in) -> RatificationGateDecision`. Six in-module unit tests + the integration tests below.
- **Module registration:** `crates/qbind-node/src/lib.rs` — adds `pub mod pqc_ratification_policy;` immediately after the Run 105 `pqc_ratification_input` registration so the import order mirrors the run sequence.
- **Startup binary gate** (`crates/qbind-node/src/main.rs`, formerly line 2622): the bare `if args.p2p_trust_bundle_ratification_enforcement_enabled` guard is replaced with the per-environment policy decision from `pqc_ratification_policy::ratification_gate_decision`. The gate body (`apply_run_105_ratification_gate_at_startup`) is unchanged; the operator-log line announces `[run-106] startup ratification gate INVOKED (policy=<label>, env=<env>)` or `SKIPPED (...)` with one of four stable labels.
- **Reload-check binary gate** (`crates/qbind-node/src/main.rs`, formerly line 826): the same flag guard is replaced with the same policy decision; the existing `validate_candidate_bundle_with_ratification` / `validate_candidate_bundle` branch is preserved.
- **Run 106 integration tests:** `crates/qbind-node/tests/run_106_ratification_policy_tests.rs` (7 tests) covering MainNet strict-by-default, TestNet strict-by-default, DevNet operator-opt-in, defense-in-depth cross-environment regression, and operator-log label stability.

The Run 105 CLI flags (`--p2p-trust-bundle-ratification-enforcement-enabled`, `--p2p-trust-bundle-ratification`, `--p2p-trust-bundle-allow-unratified-testnet-devnet`) are unchanged. The flag semantics on DevNet are also unchanged. The only externally observable change is:

> On MainNet and TestNet, the Run 105 ratification gate now runs on the startup preflight and the `--p2p-trust-bundle-reload-check` path **without the operator having to supply `--p2p-trust-bundle-ratification-enforcement-enabled`**, and the operator can no longer disable it by omitting that flag.

---

## 2. Per-environment policy table

| Environment | Operator opt-in flag | Gate invocation decision | Reason label |
|-------------|----------------------|--------------------------|--------------|
| MainNet     | (any)                | **Invoke**               | `mainnet-default-strict` |
| TestNet     | (any)                | **Invoke**               | `testnet-default-strict` |
| DevNet      | `false`              | Skip                     | `devnet-no-operator-opt-in` |
| DevNet      | `true`               | Invoke                   | `devnet-operator-opt-in` |

The DevNet skip path preserves pre-Run-105 developer-workflow behaviour for unsigned and legacy bundles and is **structurally unreachable** for MainNet/TestNet. This invariant is pinned by the unit test `devnet_opt_in_does_not_weaken_mainnet` and by the integration test `run_106_devnet_skip_decision_is_never_returned_for_mainnet_or_testnet`.

The gate body itself (`enforce_bundle_signing_key_ratification` inside `qbind-ledger`) maps MainNet to `RatificationEnforcementPolicy::Strict` regardless of any flag (see `apply_run_105_ratification_gate_at_startup`, the `policy = match config.environment` block introduced in Run 105). The Run 106 invocation-policy change therefore composes with the Run 105 in-gate policy as **defense in depth**: even if a future change accidentally flipped the invocation decision back to opt-in, MainNet would still refuse legacy unratified bundles inside the gate.

---

## 3. Mutation-ordering invariants preserved

Run 106 changes only the **guard** around the existing gate, not the gate or anything around it. The Run 050/051/053/055/057/061/062/063/065/091/099/103/105 ordering at every covered surface is therefore preserved bit-for-bit:

### Startup `--p2p-trust-bundle`

| Step | Action | Run 106 effect |
|------|--------|----------------|
| 1 | `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation` | unchanged |
| 2 | Activation gate satisfied (Run 057 / Run 091) | unchanged |
| 3 | **Run 105 ratification gate** | invocation now per-environment (Run 106) |
| 4 | Run 055 anti-rollback sequence write | unchanged |
| 5 | Bundle roots merged into `trusted_roots` | unchanged |

A refused ratification at step 3 still fails closed with non-zero exit BEFORE step 4 and BEFORE step 5: **no sequence record is written, no root is merged into the live PQC trust set, no session is touched, no network is started.** The exit message and exit code are identical to Run 105.

### `--p2p-trust-bundle-reload-check`

| Step | Action | Run 106 effect |
|------|--------|----------------|
| 1 | `validate_candidate_bundle_full` (Run 069 pipeline) | unchanged |
| 2 | **Run 105 ratification gate** | invocation now per-environment (Run 106) |
| 3 | Verdict logged; `std::process::exit(0/1)` | unchanged |

The validator still never writes the sequence record on this path (Run 069 invariant); the Run 106 invocation change adds zero file writes, zero session mutations, zero metrics mutations. Both branches remain read-only.

---

## 4. Test evidence

### 4.1 New tests

`crates/qbind-node/src/pqc_ratification_policy.rs` — 6 unit tests:

```
test pqc_ratification_policy::tests::devnet_opt_in_does_not_weaken_mainnet ... ok
test pqc_ratification_policy::tests::devnet_with_opt_in_invokes_gate ... ok
test pqc_ratification_policy::tests::devnet_without_opt_in_skips_gate ... ok
test pqc_ratification_policy::tests::label_is_stable_for_operator_logs ... ok
test pqc_ratification_policy::tests::mainnet_is_strict_by_default_regardless_of_opt_in_flag ... ok
test pqc_ratification_policy::tests::testnet_is_strict_by_default_regardless_of_opt_in_flag ... ok
```

`crates/qbind-node/tests/run_106_ratification_policy_tests.rs` — 7 integration tests:

```
test run_106_decision_labels_are_stable ... ok
test run_106_devnet_skip_decision_is_never_returned_for_mainnet_or_testnet ... ok
test run_106_devnet_with_opt_in_invokes_gate ... ok
test run_106_devnet_without_opt_in_skips_gate ... ok
test run_106_mainnet_strict_by_default_without_flag ... ok
test run_106_mainnet_strict_with_flag_is_same_decision ... ok
test run_106_testnet_strict_by_default_without_flag ... ok
```

### 4.2 Run 105 regression

`crates/qbind-node/tests/run_105_ratification_enforcement_tests.rs` — 6 tests, all pass after the Run 106 change:

```
test run_105_devnet_legacy_unratified_accepts ... ok
test run_105_full_entry_point_returns_loaded_bundle_and_activation ... ok
test run_105_ratification_for_different_key_refused ... ok
test run_105_strict_devnet_missing_ratification_refused_without_mutation ... ok
test run_105_strict_devnet_valid_ratification_validates_candidate ... ok
test run_105_wrong_chain_ratification_refused ... ok
```

### 4.3 Compile parity

`cargo check -p qbind-node --lib --bins` succeeds. The only warnings are the two pre-existing `bincode::config` deprecation warnings in `binary_consensus_loop.rs` (predate Run 105 and are unrelated to Run 106).

### 4.4 Release-binary smoke evidence — **deferred**

The task asks for release-binary smoke scenarios (Scenarios 1–7) under `docs/devnet/`. Run 106 **does not** ship those release-binary smoke logs. Reasons (honest, not speculative):

- A `cargo check` on this workspace costs ~5 minutes wall-clock; a full `cargo build --release` followed by seven scripted release-binary scenarios materially exceeds a single safe session.
- The release-binary smoke harness for the Run 105 surfaces is already documented in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md`; the Run 106 change is a pure invocation-policy change that does not alter the binary's externally observable behaviour on either branch of the gate (the operator simply does not need to supply `--p2p-trust-bundle-ratification-enforcement-enabled` anymore on MainNet/TestNet for the gate to run). The Run 105 smokes therefore remain bit-for-bit correct for the gate body; only the flag in the harness command line needs to disappear for MainNet/TestNet. This is a documented operator-side change, not a binary behaviour change.

This is the **largest** honesty hole in Run 106 and is the reason this run is **partial-positive**, not positive or strongest-positive.

---

## 5. Source-level proof of MainNet default strictness

The two binary call sites both use the same helper, with no remaining bare references to the opt-in flag for the **invocation** decision:

`crates/qbind-node/src/main.rs` (reload-check site):

```rust
let gate_decision = qbind_node::pqc_ratification_policy::ratification_gate_decision(
    config.environment,
    args.p2p_trust_bundle_ratification_enforcement_enabled,
);
let reload_check_result = if gate_decision.should_invoke() { … } else { … };
```

`crates/qbind-node/src/main.rs` (startup site):

```rust
let startup_gate_decision =
    qbind_node::pqc_ratification_policy::ratification_gate_decision(
        config.environment,
        args.p2p_trust_bundle_ratification_enforcement_enabled,
    );
if startup_gate_decision.should_invoke() {
    eprintln!(
        "[run-106] startup ratification gate INVOKED (policy={}, env={:?}).",
        startup_gate_decision.label(),
        config.environment
    );
    if let Err(reason) = apply_run_105_ratification_gate_at_startup(…) { … exit(1) }
} else { … }
```

The opt-in flag still appears as an argument to the helper, but the helper **ignores it** for MainNet/TestNet (see `ratification_gate_decision` body — the `Mainnet` and `Testnet` arms do not look at `operator_opt_in`).

---

## 6. Deferred surfaces and explicit blockers

The following surfaces enumerated in `task/RUN_106_TASK.txt` §C–§G remain in their **Run 105 state**, i.e. either still operator-opt-in or still unwired. Each is listed with the honest blocker that prevented landing it safely in Run 106:

| Surface | Current state | Run 106 blocker |
|---------|---------------|-----------------|
| `--p2p-trust-bundle-peer-candidate-check` | unwired (Run 105 left it for Run 106) | Wiring requires a ratification context that is currently only built for the startup + reload-check sites (`build_run_105_reload_check_context` is reload-check-specific). Cleanly factoring the context builder + threading it into `pqc_peer_candidate_binary` is mechanically larger than the Run 106 invocation-policy change and warrants its own focused run with dedicated tests. |
| Live peer-candidate wire validation (`pqc_peer_candidate_wire`) | unchanged | Same blocker as above, plus the existing memory note: adding fields to `PeerCandidateRuntimeContext` breaks ~18 call sites across `crates/qbind-node/{src,tests}`. The Run 105 pattern of `*_with_ratification` wrapper entry points should be followed, which is a non-trivial design step. |
| Propagation / rebroadcast | unchanged | Depends on live wire validation landing first; the existing propagation prototype (Run 088) is disabled-by-default and rebroadcasts only after a successful Run 076 validation. Wiring ratification into propagation cleanly requires the wire-validation change above to land first. |
| Reload-apply (Run 073) | unchanged | Requires extending the Run 073 apply context to carry ratification inputs without mutating the existing `LiveTrustApplyContext` trait shape (similar shape concern as `ReloadCheckInputs`). |
| SIGHUP live reload (Run 074) | unchanged | Depends on reload-apply ratification landing first; the SIGHUP trigger reuses the Run 073 apply pipeline. |

None of these deferred surfaces are weakened by Run 106. They remain in their Run 105 state. Operators who want ratification enforcement on any of them on DevNet/TestNet today must continue to follow the Run 105 procedure (supply `--p2p-trust-bundle-ratification-enforcement-enabled` + `--p2p-trust-bundle-ratification <path>`). On MainNet, these surfaces remain unprotected by ratification and this is captured in `docs/whitepaper/contradiction.md` as residual risk.

---

## 7. Explicit non-claims

Run 106 does **not** implement:

- signing-key rotation;
- signing-key revocation lifecycle;
- authority anti-rollback persistence;
- persistent ratified-authority state;
- peer-driven live apply;
- peer-driven trust synchronization;
- KMS/HSM custody;
- governance;
- validator-set rotation;
- production static source-code anchors;
- fallback roots;
- fallback signing keys;
- any change to the trust-bundle wire format or the peer-candidate wire format;
- ratification on `--p2p-trust-bundle-peer-candidate-check`, live peer-candidate wire validation, propagation/rebroadcast, reload-apply, or SIGHUP (see §6);
- release-binary smoke evidence for the Run 106 invocation-policy change itself (see §4.4);
- full C4 closure;
- C5 closure.

Local config alone is still **not enough** for MainNet bundle-signing authority. Transport roots still cannot ratify bundle-signing keys. The Run 102 genesis verifier, Run 103 ratification verifier, and Run 104 key-material validation are all bit-for-bit unchanged.

---

## 8. Residual risks

1. **Coverage is incomplete.** The strongest-positive statement from `task/RUN_106_TASK.txt` ("On MainNet, every trust bundle or peer candidate signed by an unratified bundle-signing key is rejected before sequence write, root merge, live trust mutation, session eviction, sequence commit, or propagation") is **not** true after Run 106: only the startup preflight and reload-check surfaces enforce it by default. Peer-candidate validation, live wire validation, propagation, reload-apply, and SIGHUP remain in their Run 105 state.
2. **No release-binary smoke logs were produced in this run.** The Run 105 smokes remain valid for the gate body; the Run 106 binary-CLI change (operator no longer needs to pass `--p2p-trust-bundle-ratification-enforcement-enabled` on MainNet) is documented in §5 from source but is not exercised in a recorded binary scenario in this run.
3. **DevNet opt-in surface is intentionally preserved.** The DevNet `Skip(DevnetNoOperatorOptIn)` decision is the **same** developer-ergonomics surface that existed before Run 105. It is not weakened, but it is also not removed; DevNet operators continue to opt in explicitly to exercise the gate.

---

## 9. Recommended next run

Run 107 should land **one** of the deferred surfaces — preferably `--p2p-trust-bundle-peer-candidate-check` first, because:

- the wiring is mechanically the closest to the reload-check site Run 106 already updated;
- it is non-mutating and validation-only, so the Run 105 invariants carry over directly;
- it lays the factoring (a shared `RatificationContextBuilder`) needed by the live-wire and reload-apply surfaces, so subsequent Run 108+ work becomes additive rather than re-shaped.

A focused release-binary smoke harness covering Scenarios 1–5 from `task/RUN_106_TASK.txt` §10 (Startup MainNet valid/missing/bad, reload-check MainNet valid/missing/bad, peer-candidate check MainNet valid/missing/bad) should be added in the same run or the run immediately after.

---

## 10. Cross-check

- **Run 100 authority model** (`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`): consistent. Run 106 does not introduce any new authority type, does not add static source-code anchors, does not permit local config to authorise MainNet signing keys.
- **Run 101 genesis authority implementation:** unchanged.
- **Run 102 boot verification:** unchanged. The startup gate continues to run AFTER Run 102 has succeeded.
- **Run 103 ratification verifier:** unchanged. The gate body still calls `enforce_bundle_signing_key_ratification` with the same inputs.
- **Run 104 key material registry:** unchanged.
- **Run 105 opt-in enforcement:** preserved on the DevNet skip branch (operator-opt-in still selects between Skip/Invoke on DevNet); flipped to default-on for MainNet/TestNet, which is the explicit Run 106 contract.
- **`docs/whitepaper/contradiction.md`:** narrowed in §C4 to reflect MainNet default strictness on startup + reload-check, with the remaining surfaces called out as still-deferred residual risk (see the contradiction-update commit accompanying this evidence file).
- **`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`:** updated with the new operator behaviour ("on MainNet/TestNet, the gate runs by default; the opt-in flag is informational only on those environments and is still required on DevNet").