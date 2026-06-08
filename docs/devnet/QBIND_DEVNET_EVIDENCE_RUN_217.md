# QBIND DevNet evidence — Run 217

**Title.** Source/test governance-execution runtime policy arming wiring.

**Status.** PASS (source/test only). Run 217 wires the resolved Run 215
hidden governance-execution policy selector
(`governance_execution_policy_from_cli_or_env`) into the long-running
production runtime preflight contexts through a new runtime-config carrier
[`qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeArmingConfig`].
Before Run 217 the Run 215 selector reached the seven per-surface
preflight wrappers directly, but no runtime-config structure resolved the
selector once and routed the resolved `GovernanceExecutionPolicy` into the
runtime preflight call sites. Run 217 adds that runtime-arming carrier and
the source/test wiring that drives it.

Run 217 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. Release-binary
governance-execution runtime-arming evidence is deferred to **Run 218**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 218).
* Runtime-arming carrier only; disabled by default.
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
* Run 217 does not weaken any prior run (Runs 070, 130–216) and does not
  claim full C4 or C5 closure.

## Runtime-arming carrier

`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`

* `GovernanceExecutionRuntimeArmingConfig` — resolves the selected
  `GovernanceExecutionPolicy` once via
  `GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(cli)` (which
  calls the Run 215 `governance_execution_policy_from_cli_or_env`
  resolver) and carries it into the runtime preflight wrappers.
* **Default:** when both the CLI flag and env var are absent the resolved
  policy is `GovernanceExecutionPolicy::Disabled` bit-for-bit — legacy
  no-governance-execution payloads remain accepted (Run 214
  compatibility). `is_disabled()` reflects this.
* **Precedence (deterministic):** CLI over env, inherited from the Run 215
  resolver.
* **Fail closed on invalid input:** an empty / whitespace-only or unknown
  selector value propagates the Run 215
  `GovernanceExecutionPolicySelectorParseError` before any runtime
  mutation; the carrier never silently downgrades an explicit-but-invalid
  value to `Disabled`.

### Runtime preflight wrappers (seven production surfaces)

`GovernanceExecutionRuntimeArmingConfig` exposes one preflight entry point
per Run 213 / Run 215 production surface, each routing the carried policy
through the Run 213 per-surface routing helper to the Run 211 evaluator:

* `preflight_reload_check`;
* `preflight_reload_apply`;
* `preflight_startup_p2p_trust_bundle`;
* `preflight_sighup`;
* `preflight_local_peer_candidate_check`;
* `preflight_live_inbound_0x05`;
* `preflight_peer_driven_drain`.

`GovernanceExecutionRuntimeSurface::ALL` enumerates the seven surfaces and
`arm_surface` dispatches by surface tag, so the runtime config reaches all
seven preflight wrappers where representable.

### Live inbound `0x05` limitation

As in Run 215, the live inbound `0x05` decode path does not yet thread a
per-connection governance-execution policy from its live runtime config.
The `preflight_live_inbound_0x05` wrapper exposes the policy injection at
the source/test level so the selected policy reaches the Run 213 live
inbound `0x05` routing helper, and an invalid live `0x05`
governance-execution candidate is not propagated, staged, or applied.
Wiring the resolved policy into the live `0x05` runtime config is deferred
to the release-binary harness in **Run 218**.

## Deterministic test-hang fix

The first iteration of the Run 217 test target hung deterministically in
`compatibility_with_sibling_run_selectors`. The test's `EnvGuard::set`
helper acquires a process-wide, **non-reentrant** `std::sync::Mutex`
(`env_lock`) so that selector tests serialize their process-env
mutations. The compatibility test held the first guard (`_g`) alive while
constructing a second guard (`_g2`) on the same thread, which re-locked
the same non-reentrant mutex and self-deadlocked. The fix scopes each
`EnvGuard` so only one guard holds `env_lock` at a time — the sibling
default checks run under the first guard's scope, and the armed-selector
check runs under a second, independent guard scope. The fix is test-only;
it changes no production behavior, schema, wire, marker, or sequence, and
preserves the original assertions.

## Required behavior (as implemented)

* The hidden governance-execution selector is consumed by the runtime
  preflight config (`GovernanceExecutionRuntimeArmingConfig`) at the
  source/test level.
* Default remains `GovernanceExecutionPolicy::Disabled`; legacy
  no-governance-execution payloads remain compatible (Run 214).
* CLI-over-env precedence is preserved through the runtime config.
* Invalid selector values fail closed before any runtime mutation.
* Fixture governance execution passes only where the selected policy
  allows; emergency-council fixture execution passes only under the
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

`crates/qbind-node/tests/run_217_governance_execution_runtime_arming_tests.rs`

Covers A1–A15 and R1–R28 where representable at the runtime-arming layer,
plus selector → runtime-config resolution (default / CLI / env /
CLI-over-env / invalid value fail-closed), source reachability (the CLI/env
selector reaches the runtime config and the runtime config reaches all
seven preflight wrappers, and the Run 213 payload routing reaches the Run
211 evaluator under the armed policy), no-mutation invariants
(validation-only + mutating rejection purity), MainNet refusal invariants,
and compatibility with the Run 214 governance-execution payload path and
the Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation
sibling selectors (their selectors remain independent and unaffected).

## Validation commands and results

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
  — PASS (45 tests; passes serially with `--test-threads=1 --nocapture`
  and in the default parallel mode without hanging).
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
  — PASS (55 tests).
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
  — PASS (61 tests).
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
  — PASS (55 tests).
* `cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests`
  — PASS (51 tests).
* `cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`
  — PASS (53 tests).
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
  — PASS (46 tests).
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
  — PASS (16 tests).
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  — PASS (5 tests).
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
  — PASS (11 tests).
* `cargo test -p qbind-node --lib` — PASS (1345 tests).
* Additional task-listed regression targets exercise unchanged surfaces;
  Run 217 adds only the runtime-arming carrier source module wiring and a
  test-only hang fix plus documentation updates, so they remain
  unaffected. If an exact target name differs in a later tree, locate the
  nearest existing target and document the exact command/result.

## Status of guarantees after Run 217

* The hidden governance-execution selector is now consumed by runtime
  preflight contexts at the source/test level.
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
* Release-binary governance-execution runtime-arming evidence is deferred
  to **Run 218**.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Why C4 / C5 remain OPEN

Run 217 is source/test wiring only. It adds no real governance execution
engine, no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no
MainNet governance enablement, no validator-set rotation, no autonomous
apply, no apply-on-receipt, no peer-majority authority, and no schema /
wire / marker / sequence / trust-bundle change. Fixture governance remains
evidence-only and refused for MainNet production purposes. **Full C4
remains OPEN; C5 remains OPEN.**
