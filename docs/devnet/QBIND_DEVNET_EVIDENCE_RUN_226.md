# QBIND DevNet evidence — Run 226

**Title.** Source/test governance evaluator runtime call-site wiring.

**Status.** PASS (source/test only). Run 226 routes the existing Run 220
governance-execution runtime **call sites** through the Run 224 governance
evaluator **runtime integration layer** at the source/test level. Run 224
proved the integration layer that composes the Run 222 evaluator interface
into the Run 220 runtime-consumption pipeline, but the runtime call sites
themselves (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP,
local peer-candidate-check, live inbound `0x05`, peer-driven drain) still
called the Run 220 `consume_surface` path directly. Run 226 wires the
representable call sites through the integration layer so that the
integration outcome — not the bare runtime consumption — gates each call
site, while the default Disabled legacy bypass is preserved and
production/on-chain/MainNet evaluators remain unavailable/fail-closed.

Run 226 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. Release-binary
call-site wiring evidence is deferred to **Run 227**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 227).
* Call-site wiring only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend
  implementation.
* No schema/wire/marker/sequence/trust-bundle change.
* Run 226 does not weaken any prior run (Runs 070, 130–225) and does not
  claim full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`

Run 226 adds the call-site wiring entry points to the existing Run 224
integration module (no new module, no new registration in `lib.rs`):

* `wire_governance_evaluator_runtime_callsite` — routes a call site that can
  build a full evaluator context through
  `integrate_governance_evaluator_runtime_consumption`, returning `Ok` on the
  proceed variants (`ProceedLegacyBypass`, `ProceedMutate { .. }`) and `Err`
  on the fail-closed variants (`RuntimeConsumptionFailClosed`,
  `EvaluatorRejected`, `MainNetPeerDrivenApplyRefused`), surfaced as a typed
  `GovernanceEvaluatorRuntimeCallsiteFailClosed`.
* `wire_governance_evaluator_runtime_callsite_without_evaluator_context` —
  for binary call sites whose marker/candidate metadata cannot carry a
  governance proposal/decision evaluator binding. It routes through the
  integration layer with the callable-but-unavailable production decision
  source evaluator interface so the default Disabled + absent carrier path
  short-circuits to `ProceedLegacyBypass` (preserving the Run 220 legacy
  bypass) and any present carrier fails closed (production unavailable or
  runtime-consumption rejection). This is strictly stricter than — never
  weaker than — the Run 220 behavior it replaces.

These functions are pure: they perform no network or file I/O, write no
marker, write no sequence, mutate no live trust, evict no sessions, and never
invoke Run 070 apply.

## Call sites wired

* `crates/qbind-node/src/main.rs`
  `consume_run_220_governance_execution_runtime_outcome` — used at the
  reload-apply, startup `--p2p-trust-bundle`, reload-check, and local
  peer-candidate-check surfaces — now routes through the integration layer.
* `crates/qbind-node/src/pqc_live_trust_reload.rs`
  `consume_run_220_sighup_governance_execution_marker_decision` — the SIGHUP
  surface — now routes through the integration layer, mapping a fail-closed
  outcome to the existing marker-rejection conflict path.

## Representability limitation (documented honestly)

The binary marker-decision metadata and SIGHUP candidate metadata cannot
carry governance proposal/decision evaluator bindings, so these call sites
cannot construct a fully valid `EvaluatorRequest`/`EvaluatorResponse`. They
are wired through
`wire_governance_evaluator_runtime_callsite_without_evaluator_context`, which
preserves the default Disabled bypass and fails closed for any present
carrier. The **live inbound `0x05`** and **peer-driven drain** surfaces are
covered by the same call-site wiring at the source/test level, but their full
positive evaluator binding is not yet representable from the binary. Full
positive binary acceptance and release-binary evidence are deferred to
**Run 227**.

## Ordering

The wiring preserves the Run 224 ordering: selector resolution →
sidecar/load-status derivation → runtime consumption (`consume_surface`) →
evaluator request construction → evaluator evaluation → governance execution
decision validation → reconciliation. Mutation authorization is produced
**only** when both the runtime-consumption stage and the evaluator stage
agree; either stage rejecting yields a non-mutating outcome and a typed
call-site fail-closed error.

## Tests

`crates/qbind-node/tests/run_226_governance_evaluator_runtime_callsite_wiring_tests.rs`
— 59 tests covering A1–A17, R1–R31, source reachability from the runtime
call sites into the integration layer, proof that the integration outcome is
consumed (not discarded), proof that `ProceedMutate` is the only
mutation-authorizing integration outcome, proof that
`RuntimeConsumptionFailClosed` / `EvaluatorRejected` /
`MainNetPeerDrivenApplyRefused` fail closed before mutation, ordering,
deterministic evaluator request/response digest binding, default Disabled
legacy compatibility, MainNet peer-driven apply refusal, and compatibility
with Runs 220, 222, and 224.

## Invariants restated

* Run 226 is source/test runtime call-site wiring for the governance
  evaluator integration layer.
* Representable runtime call sites now route through the integration layer.
* Default Disabled legacy bypass is preserved.
* Production/on-chain/MainNet evaluators remain unavailable/fail-closed.
* Fixture evaluator remains DevNet/TestNet source-test only.
* Emergency fixture evaluator is explicit and non-production.
* Live inbound `0x05` and peer-driven drain limitations are documented
  honestly (full positive evaluator binding not yet representable from the
  binary).
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* No real governance engine or on-chain proof verifier is implemented.
* Release-binary call-site wiring evidence is deferred to Run 227.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo build -p qbind-node --bin qbind-node`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`