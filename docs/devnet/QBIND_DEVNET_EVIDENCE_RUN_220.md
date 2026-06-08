# QBIND DevNet evidence — Run 220

**Title.** Source/test long-running governance-execution runtime
consumption wiring.

**Status.** PASS (source/test only). Run 220 makes the long-running
production runtime call sites actually **consume** the Run 217 resolved
`GovernanceExecutionPolicy` and the real governance-execution sidecar load
status, instead of discarding the `arm_surface` outcome and forcing
`GovernanceExecutionLoadStatus::Absent`. Before Run 220 the four binary
runtime hooks and the SIGHUP runtime hook resolved the policy
(`GovernanceExecutionRuntimeArmingConfig`) and called `arm_surface(...)`
but threw the outcome away (`let _outcome = ...`) and unconditionally
forced an `Absent` load status, so the Run 211 evaluator verdict never
influenced the runtime decision. Run 220 adds a consumption API on top of
the Run 217 arming carrier and wires the call sites to honor its verdict.

Run 220 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. Release-binary
governance-execution runtime-consumption evidence is deferred to
**Run 221**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 221).
* Runtime-consumption wiring only; disabled by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No authority-set rotation beyond existing lifecycle boundary checks.
* No real KMS implementation; no real HSM implementation; no real
  RemoteSigner backend; no production signing-key custody.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema/wire change; no authority-marker schema change; no
  sequence-file schema change; no trust-bundle core schema change; no
  authority lifecycle semantics change.
* Run 220 does not weaken any prior run (Runs 070, 130–219) and does not
  claim full C4 or C5 closure.

## Consumption API

`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`

Run 220 adds a thin consumption layer on top of the Run 217 arming carrier
without changing the Run 217 surface enumeration or per-surface preflight
wrappers:

* `GovernanceExecutionRuntimeConsumption` — the consumed verdict, one of:
  * `ProceedLegacyBypass` — the Run 214 default no-governance-execution
    path (Disabled policy + absent carrier); the runtime proceeds exactly
    as before Run 217.
  * `ProceedAccepted(GovernanceExecutionOutcome)` — an explicit policy
    accepted a present, valid carrier; the runtime proceeds and the
    accepted outcome is carried (not discarded).
  * `FailClosed(GovernanceExecutionPayloadCarryingDecisionOutcome)` — the
    evaluator rejected (missing/malformed/unavailable/mismatched material,
    or MainNet peer-driven apply refusal); the runtime fails closed
    **before** any mutation.
* `GovernanceExecutionRuntimeArmingConfig::consume_surface(...)` — resolves
  the surface decision through the Run 213 routing helper and the Run 211
  evaluator using the **real** governance-execution load status, then maps
  the decision outcome to a `GovernanceExecutionRuntimeConsumption`.
* `GovernanceExecutionRuntimeArmingConfig::consume_surface_from_optional_sidecar_value(...)`
  — convenience entry that derives the real load status from an optional
  parsed sidecar `serde_json::Value` (via the Run 213
  `parse_optional_governance_execution_sibling_from_json_value`) and then
  consumes.
* `governance_execution_load_status_from_optional_sidecar_value(...)` —
  free function returning the real `GovernanceExecutionLoadStatus`
  (`Absent` / `Available` / `Malformed`) from an optional parsed sidecar
  value, used to route real status into the runtime contexts.

The mapping is derived from the Run 213
`GovernanceExecutionPayloadCarryingDecisionOutcome`: a bypassed outcome
(`NoGovernanceExecutionSupplied`, i.e. Disabled + Absent) maps to
`ProceedLegacyBypass`; an accepting outcome maps to `ProceedAccepted`; any
other outcome (reject / malformed / required-but-absent / MainNet
peer-driven apply refused) maps to `FailClosed`.

## Runtime call-site consumption

### Four binary runtime hooks (`crates/qbind-node/src/main.rs`)

The Run 217 binary hook
`invoke_run_217_callsite_governance_execution_marker_decision` returned
`()`, discarded the `arm_surface` outcome, and forced `Absent`. Run 220
replaces it with `consume_run_220_governance_execution_runtime_outcome`,
which calls `consume_surface` with the **real** load status and returns
`Err(reason)` on `FailClosed`. The four production call sites consume the
verdict and fail closed before mutation:

* **reload-apply** (mutating) — `map_err` into a
  `MutatingSurfaceMarkerV2Error::Conflict(MalformedOrUnsupportedMarkerRejected)`
  and `?`-propagate, so a rejected governance-execution verdict refuses
  the apply before any Run 070 call, live trust swap, session eviction,
  sequence write, or marker write.
* **startup p2p trust-bundle** (mutating) — same fail-closed mapping
  before the startup marker is written.
* **reload-check** (validation-only) — same fail-closed mapping; the
  surface remains non-mutating on both accept and reject.
* **local-peer-candidate-check** (validation-only) — inline `match`
  emitting a `VERDICT=invalid` line on `Err`; non-mutating.

The reload-check context builder `build_run_105_reload_check_context` now
populates a `governance_execution_load: GovernanceExecutionLoadStatus`
field on `Run105ReloadCheckContextData` by reading the ratification sidecar
file, parsing it to a `serde_json::Value`, and routing it through the Run
213 `parse_optional_governance_execution_sibling_from_json_value`. Any IO
or parse failure, or the absence of a sidecar, yields `Absent` (the
Disabled default path is unaffected).

### SIGHUP runtime hook (`crates/qbind-node/src/pqc_live_trust_reload.rs`)

The Run 217 SIGHUP reachability hook is replaced with
`consume_run_220_sighup_governance_execution_marker_decision`, which is
called via `?` before the SIGHUP marker decision is returned. The SIGHUP
v2 dispatch branch computes the real load status from the sidecar path via
`governance_execution_load_status_from_optional_sidecar_value` and threads
it into `preflight_sighup_v2_marker_decision`. On a rejected verdict the
hook fails closed via
`MutatingSurfaceMarkerV2Error::Conflict(MalformedOrUnsupportedMarkerRejected)`
before any mutation.

## Representability limitations (described honestly)

* **Binary / SIGHUP candidate metadata.** The binary and SIGHUP candidate
  metadata does not yet carry governance proposal / decision bindings, so
  the derived `GovernanceExecutionExpectations` leave the proposal/decision
  identifiers empty. A present, valid carrier under an explicit policy
  therefore reaches the Run 211 evaluator and **fails closed** on the
  expectation mismatch at the binary surface; full positive binary
  acceptance is deferred to **Run 221**. Source/test acceptance is fully
  exercised in the Run 220 test target with correct expectations, so the
  consumption logic itself is proven.
* **Live inbound `0x05`.** As in Runs 215/217 the live inbound `0x05`
  decode path does not yet thread a per-connection governance-execution
  policy from its live runtime config. The `preflight_live_inbound_0x05`
  surface exposes the policy injection at the source/test level and an
  invalid live `0x05` governance-execution candidate is not propagated,
  staged, or applied. Wiring the resolved policy into the live `0x05`
  runtime config is deferred to the release-binary harness in **Run 221**.
* **Peer-driven drain.** The peer-driven drain surface consumes the policy
  at the source/test level; MainNet peer-driven apply remains refused even
  with `MainnetGovernanceRequired` and fully-valid fixture governance
  approval.

## Required behavior (as implemented)

* Runtime call sites now **consume** the selected governance-execution
  policy where representable (the `arm_surface` outcome is no longer
  discarded on surfaces that claim consumption).
* Runtime call sites now **consume** the real governance-execution sidecar
  load status where representable (the forced `Absent` is removed where
  real sidecar material should be loaded).
* Default remains `GovernanceExecutionPolicy::Disabled`; legacy
  no-governance-execution payloads remain compatible (Run 214) — Disabled +
  absent carrier maps to `ProceedLegacyBypass` and proceeds bit-for-bit as
  before Run 217.
* CLI-over-env precedence is preserved through the runtime config.
* Invalid selector values fail closed before any runtime mutation.
* Fixture governance execution passes only where the selected runtime
  policy allows; emergency-council fixture execution passes only under the
  explicit emergency fixture policy and remains non-production.
* Missing / malformed governance execution material fails closed under an
  explicit policy.
* Production / on-chain / MainNet governance execution material reaches the
  evaluator and fails closed as unavailable.
* Validation-only surfaces remain non-mutating; mutating rejection paths
  produce no Run 070 call, no live trust swap, no session eviction, no
  sequence write, and no marker write.
* MainNet peer-driven apply remains refused even with
  `MainnetGovernanceRequired` and fully-valid fixture governance approval.

## Tests

`crates/qbind-node/tests/run_220_governance_execution_runtime_consumption_tests.rs`

Covers A1–A17 and R1–R28 where representable at the runtime-consumption
layer, including:

* default consumption → legacy bypass (Disabled + absent);
* reload-check / reload-apply / surfaces consume and accept fixture
  governance under an explicit policy;
* the `arm_surface` outcome is consumed, not discarded (A16);
* the **real** sidecar load status is consumed, not forced `Absent` (A17),
  including via `consume_surface_from_optional_sidecar_value`;
* selector default / CLI / env / CLI-over-env / invalid-fail-closed;
* production / on-chain / MainNet unavailable fail-closed;
* the Run 213 payload routing reaches the Run 211 evaluator under the
  consumed policy;
* validation-only and mutating rejection purity (no mutation);
* MainNet peer-driven apply refusal even with fixture approval;
* compatibility with the Run 214 governance-execution payload path and the
  Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation
  sibling selectors (their selectors remain independent and unaffected).

The Run 220 test target follows the Run 217 `EnvGuard` discipline: the
process-wide non-reentrant `env_lock` mutex is never held by two guards on
one thread simultaneously; each guard is scoped so only one is alive at a
time.

## Validation commands and results

* `cargo build -p qbind-node --lib` — PASS.
* `cargo build -p qbind-node --bin qbind-node` — PASS (no warnings).
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
  — PASS (30 tests).
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
  — PASS (45 tests).
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
  — PASS.
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
  — PASS.
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
  — PASS.
* `cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests`
  — PASS (51 tests).
* `cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`
  — PASS (53 tests).
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
  — PASS (46 tests).
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
  — PASS (23 tests).
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
  — PASS (19 tests).
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
  — PASS (20 tests).
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
  — PASS (16 tests).
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  — PASS.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
  — PASS (11 tests).
* `cargo test -p qbind-node --lib` — PASS (1348 tests).
* Additional task-listed regression targets exercise unchanged surfaces;
  Run 220 adds only the runtime-consumption layer on the existing arming
  carrier, the call-site wiring, the new test target, and documentation, so
  they remain unaffected. If an exact target name differs in a later tree,
  locate the nearest existing target and document the exact command/result.

## Status of guarantees after Run 220

* The long-running runtime call sites now consume the selected
  governance-execution policy and the real sidecar status at the
  source/test level where representable.
* Default remains `GovernanceExecutionPolicy::Disabled`.
* Fixture governance execution remains DevNet/TestNet source/test only.
* Emergency council fixture execution is explicit and non-production.
* Production / on-chain / MainNet governance execution remains
  unavailable/fail-closed.
* MainNet peer-driven apply remains refused.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No real KMS/HSM backend is implemented.
* No real RemoteSigner backend is implemented.
* Validator-set rotation remains unsupported.
* Release-binary governance-execution runtime-consumption evidence is
  deferred to **Run 221**.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Why C4 / C5 remain OPEN

Run 220 is source/test consumption wiring only. It adds no real governance
execution engine, no real on-chain verifier, no KMS/HSM or RemoteSigner
backend, no MainNet governance enablement, no validator-set rotation, no
autonomous apply, no apply-on-receipt, no peer-majority authority, and no
schema / wire / marker / sequence / trust-bundle change. Fixture governance
remains evidence-only and refused for MainNet production purposes. **Full
C4 remains OPEN; C5 remains OPEN.**
