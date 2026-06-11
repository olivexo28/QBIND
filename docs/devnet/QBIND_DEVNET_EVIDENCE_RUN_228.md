# QBIND DevNet evidence — Run 228

**Title.** Source/test peer evaluator-context representation boundary for live
inbound `0x05` and peer-driven drain.

**Status.** PASS (source/test only). Run 228 adds a typed evaluator-context
representation boundary for the two governance surfaces that Run 226
documented as not-yet-fully-representable: live inbound `0x05` peer-candidate
validation and peer-driven drain. The boundary lets these surfaces carry or
reference an evaluator context in source/test plumbing where representable and
routes that context into the Run 226 call-site wiring → Run 224 governance
evaluator runtime integration layer → Run 222 evaluator interface. Where the
live wire cannot carry an evaluator binding, the boundary returns a typed
unsupported/fail-closed carrier status rather than an approval, so the default
Disabled legacy validation behavior is preserved and any present carrier is
gated by the integration outcome.

Run 228 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no** real
KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet governance
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format. Release-binary evidence is deferred
to **Run 229**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 229).
* Typed evaluator-context representation boundary only; fail-closed by
  default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend
  implementation.
* No schema/wire/marker/sequence/trust-bundle change.
* Run 228 does not weaken any prior run (Runs 070, 130–227) and does not
  claim full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`

Run 228 adds a new source module (registered in `lib.rs`) that defines a
local-only, typed evaluator-context representation for the live inbound `0x05`
and peer-driven drain surfaces:

* `PeerEvaluatorContextSurface` — `LiveInbound0x05` and `PeerDrivenDrain`,
  each mapped to its `GovernanceExecutionRuntimeSurface`.
* `PeerEvaluatorSourceClass` — the provenance of the candidate
  (`LiveInboundPeer`, `DrainStagedPeer`, `LocalSourceTest`,
  `PeerMajorityGossip`); peer-majority gossip can never satisfy evaluator
  policy.
* `PeerEvaluatorLoadStatus` — `Absent` / `Available` / `Malformed`, derived
  from the existing governance-execution load status.
* `PeerEvaluatorCarrierStatus` — the typed carrier taxonomy: `Absent`,
  `Present`, `Malformed`, `UnsupportedSurface`, `WireSchemaUnavailable`,
  `PeerMajorityUnsupported`, `MainNetRefused`. `WireSchemaUnavailable` is the
  honest representation that the live wire carries no evaluator bindings —
  typed fail-closed, never approval.
* `GovernanceEvaluatorPeerContext` — binds the surface, source class, carrier
  status, trust domain, load status, and (when present) the evaluator context
  derived from the integration material; provides a deterministic
  `context_digest()` and consistency checks.
* `PeerEvaluatorContextOutcome` — the outcome taxonomy. Only
  `RoutedProceedMutate` authorizes apply; `LegacyValidationPreserved`,
  `MissingContextRejected`, `RoutedFailClosed`, `UnsupportedCarrierRejected`,
  and `MainNetRefused` are all non-mutating.
* `evaluate_peer_evaluator_context` / `evaluate_peer_evaluator_context_wire_only`
  — the pure entry points.

These functions are pure: they perform no network or file I/O, write no
marker, write no sequence, mutate no live trust, evict no sessions, and never
invoke Run 070 apply.

## Routing and ordering

The MainNet guard runs first: a `MainNetRefused` carrier status, or a
peer-driven drain surface in a MainNet environment, yields `MainNetRefused`
before any evaluation. An absent context under the default Disabled policy
routes through the Run 226
`wire_governance_evaluator_runtime_callsite` short-circuit to
`ProceedLegacyBypass`, mapped to `LegacyValidationPreserved`. A present
context derives all evaluator digests from the integration material, so a
well-formed present context routes through the integration layer; any mutated
request/response/expectation field makes the underlying Run 222 evaluator
reject, returning a typed `RoutedFailClosed`. Unsupported carrier statuses
(`WireSchemaUnavailable`, `UnsupportedSurface`, `PeerMajorityUnsupported`,
`Malformed`) under an explicit evaluator policy are typed fail-closed.

Mutation authorization is produced **only** when the carrier is present,
well-formed, and both the runtime-consumption and evaluator stages of the
integration layer agree. Any rejection yields a non-mutating outcome:
invalid live inbound `0x05` candidates are not propagated, staged, or applied,
and invalid peer-driven drain candidates are not applied.

## Representability limitation (documented honestly)

The live inbound `0x05` and peer-driven drain wires still cannot carry a
governance proposal/decision evaluator binding without a schema/wire change,
which Run 228 explicitly does not make. The boundary therefore represents the
wire-only path as `WireSchemaUnavailable` — a typed fail-closed carrier status
— and full positive evaluator binding remains representable only in
source/test plumbing. Release-binary evidence is deferred to **Run 229**.

## Tests

`crates/qbind-node/tests/run_228_peer_evaluator_context_representation_tests.rs`
— 48 tests covering A1–A14 accepted scenarios, R1–R27 rejection scenarios,
deterministic context-digest binding, surface/runtime-surface consistency,
cross-binding consistency between the peer context and the integration
material, default Disabled legacy validation preservation, typed
unsupported/no-carrier fail-closed behavior, MainNet peer-driven apply
refusal, validator-set rotation remaining unsupported, and compatibility with
Runs 220, 222, 224, and 226.

## Invariants restated

* Run 228 is source/test representation-boundary work for live inbound `0x05`
  and peer-driven drain evaluator context.
* The boundary is local/source-test and does not change wire/schema/marker/
  sequence/trust-bundle formats.
* Missing/unsupported carrier status is typed and fail-closed under explicit
  evaluator policy.
* Invalid live inbound `0x05` candidates are not propagated, staged, or
  applied.
* Invalid peer-driven drain candidates are not applied.
* MainNet peer-driven apply remains refused.
* No real governance engine or on-chain proof verifier is implemented.
* Production/on-chain/MainNet evaluators remain unavailable/fail-closed.
* Fixture/emergency fixture evaluators remain non-production.
* Validator-set rotation remains unsupported.
* Release-binary evidence is deferred to Run 229.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo build -p qbind-node --bin qbind-node`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`