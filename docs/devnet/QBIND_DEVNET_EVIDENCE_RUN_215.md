# QBIND DevNet evidence — Run 215

**Title.** Source/test hidden governance-execution policy selector and
production preflight integration.

**Status.** PASS (source/test only). Run 215 adds a hidden,
disabled-by-default governance-execution policy selector and wires the
resolved `GovernanceExecutionPolicy` into the seven production v2
marker-decision preflight contexts through the Run 213 per-surface
routing helpers. Before Run 215 the Run 211
`GovernanceExecutionPolicy::{FixtureGovernanceAllowed,
EmergencyCouncilFixtureAllowed, ProductionGovernanceRequired,
MainnetGovernanceRequired}` could be carried and evaluated through Run 213
production-context helpers, but no hidden production preflight selector
existed to choose the policy at binary/source call sites. Run 215 adds
that selector.

Run 215 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. Release-binary
governance-execution-policy selector evidence is deferred to **Run 216**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 216).
* Hidden selector only. Disabled by default.
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
* Run 215 does not weaken any prior run (Runs 070, 130–214) and does not
  claim full C4 or C5 closure.

## Selector

* **CLI:** `--p2p-trust-bundle-governance-execution-policy <disabled |
  fixture-governance-allowed | emergency-council-fixture-allowed |
  production-governance-required | mainnet-governance-required>`, hidden
  via clap (`hide = true`).
* **Env:** `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` with the
  same value grammar.
* **Default:** when both the CLI flag and env var are absent the resolved
  policy is `GovernanceExecutionPolicy::Disabled` bit-for-bit — legacy
  no-governance-execution payloads remain accepted (Run 213
  compatibility).
* **Precedence (deterministic):** when both sources are supplied, the CLI
  flag wins. This mirrors the Run 192 authority-custody, Run 198
  RemoteSigner, and Run 209 custody-attestation policy selectors and the
  standard CLI/env convention.
* **Fail closed on invalid input:** an empty / whitespace-only value
  yields `GovernanceExecutionPolicySelectorParseError::Empty`; an unknown
  value yields `GovernanceExecutionPolicySelectorParseError::UnknownValue`.
  The resolver never silently downgrades an explicit-but-invalid value to
  `Disabled`.

## Policy constraints

* `FixtureGovernanceAllowed` — DevNet/TestNet evidence only; cannot
  satisfy MainNet production governance execution.
* `EmergencyCouncilFixtureAllowed` — DevNet/TestNet evidence only;
  emergency actions remain explicit and separate; cannot satisfy MainNet
  production governance execution.
* `ProductionGovernanceRequired` — fails closed because no real governance
  execution engine exists.
* `MainnetGovernanceRequired` — fails closed; MainNet peer-driven apply
  remains refused regardless.

## Module

`crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`

The selector parsers perform a single environment read and no other I/O.
The per-surface preflight wrappers perform no I/O beyond the Run 213
routing helper composition: no marker write, no sequence write, no live
trust swap, no session eviction, no Run 070 call.

### Selector helpers (grep-verifiable)

* `governance_execution_policy_from_selector` — pure string → policy
  parser (case-insensitive, trims ASCII whitespace).
* `governance_execution_policy_env_selector` — pure env-var readback.
* `governance_execution_policy_from_cli_or_env` — CLI/env resolver with
  CLI-over-env precedence.
* `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV` and the
  `GOVERNANCE_EXECUTION_POLICY_TAG_*` canonical selector tags.
* `GovernanceExecutionPolicySelectorParseError` (typed `Empty` /
  `UnknownValue`).

### Per-surface preflight wrappers (seven production contexts)

Each wrapper binds the resolved `GovernanceExecutionPolicy` into a Run 213
`GovernanceExecutionCallsiteContext` and dispatches to the matching Run 213
`route_loaded_governance_execution_to_*_callsite_decision` helper:

* `preflight_v2_marker_governance_execution_for_reload_check`;
* `preflight_v2_marker_governance_execution_for_reload_apply`;
* `preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle`;
* `preflight_v2_marker_governance_execution_for_sighup`;
* `preflight_v2_marker_governance_execution_for_local_peer_candidate_check`;
* `preflight_v2_marker_governance_execution_for_live_inbound_0x05`;
* `preflight_v2_marker_governance_execution_for_peer_driven_drain`.

The selected policy reaches the Run 213 governance-execution payload /
call-site routing layer and, through it, the Run 211
`evaluate_governance_execution_policy` evaluator.

### Live inbound `0x05` limitation (A16)

The live inbound `0x05` decode path does not yet thread a per-connection
governance-execution policy from its live runtime config. The Run 215
`preflight_v2_marker_governance_execution_for_live_inbound_0x05` wrapper
exposes the policy injection at the source/test level so the selected
policy reaches the Run 213 live inbound `0x05` routing helper, and an
invalid live `0x05` governance-execution candidate is not propagated,
staged, or applied. Wiring the resolved policy into the live `0x05`
runtime config is deferred to the release-binary harness in **Run 216**.

## Required behavior (as implemented)

* A hidden governance-execution policy selector exists (CLI + env);
  default remains `GovernanceExecutionPolicy::Disabled`.
* The selected policy reaches all seven production preflight contexts at
  the source/test level.
* Fixture governance execution passes only where the selected policy
  allows; emergency-council fixture execution passes only under the
  explicit emergency fixture policy and remains non-production.
* Missing / malformed / invalid governance execution material fails
  closed under an explicit policy.
* Production / on-chain / MainNet governance execution material reaches
  the evaluator and fails closed as unavailable.
* Governance execution authorizes a lifecycle action only when action,
  candidate digest, and sequence match.
* Validation-only surfaces remain non-mutating; mutating rejection paths
  produce no mutation.
* MainNet peer-driven apply remains refused even with
  `MainnetGovernanceRequired` and fixture governance approval.

## Tests

`crates/qbind-node/tests/run_215_governance_execution_policy_selector_tests.rs`

Covers A1–A16 and R1–R40 where representable at the selector +
production-context preflight layer, plus selector parsing/precedence
(default / CLI / env / CLI-over-env / invalid value fail-closed), source
reachability (the selected policy reaches all seven Run 215 per-surface
preflight wrappers and through them the Run 213/211 evaluator), action
authorization (rotate / revoke / emergency-revoke / wrong action
fail-closed), no-mutation invariants (validation-only + mutating rejection
purity), and MainNet refusal invariants.

## Validation commands and results

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
  — PASS (55 tests).
* `cargo test -p qbind-node --lib pqc_governance_execution_policy_surface`
  — PASS (7 tests).
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
  — PASS (61 tests).
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
  — PASS (55 tests).
* `cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests`
  — PASS (51 tests).
* Additional task-listed regression targets exercise unchanged surfaces;
  Run 215 adds only a new source module, a hidden CLI flag, and a new test
  target plus documentation updates, so they remain unaffected. If an
  exact target name differs in a later tree, locate the nearest existing
  target and document the exact command/result.

## Status of guarantees after Run 215

* A hidden governance-execution policy selector exists; default remains
  `GovernanceExecutionPolicy::Disabled`.
* The selector reaches production preflight contexts at the source/test
  level.
* Fixture governance execution remains DevNet/TestNet evidence-only.
* Emergency council fixture execution is explicit and non-production.
* Fixture governance cannot satisfy MainNet production governance
  execution.
* Production / on-chain / MainNet governance execution remains
  unavailable/fail-closed.
* MainNet peer-driven apply remains refused.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No real KMS/HSM backend is implemented.
* No real RemoteSigner backend is implemented.
* Validator-set rotation remains unsupported.
* Release-binary governance-execution-policy selector evidence is deferred
  to **Run 216**.
* Full C4 remains **OPEN**. C5 remains **OPEN**.