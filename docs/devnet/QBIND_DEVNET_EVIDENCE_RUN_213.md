# QBIND DevNet evidence — Run 213

**Title.** Source/test governance-execution payload carrying and
production-context preflight wiring.

**Status.** PASS (source/test only). Run 213 makes the Run 211 typed
governance-execution input/decision material *carryable* through the
production v2 ratification sidecar payload/context layer and *routable*
into the seven production v2 marker-decision call-site contexts, where it
reaches the Run 211 governance-execution evaluator. Before Run 213 the
Run 211 `GovernanceExecutionInput` / `GovernanceExecutionDecision` could
only reach the evaluator via in-process source/test construction; no
production payload/context ever delivered governance-execution material.

Run 213 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
MainNet governance enablement, and **no** validator-set rotation.
Release-binary governance-execution payload/carrying evidence is deferred
to **Run 214**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 214).
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No authority-set rotation beyond existing lifecycle boundary checks.
* No real KMS implementation; no real HSM implementation; no real
  RemoteSigner backend; no production signing-key custody.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* Additive, optional payload/context fields only; legacy
  no-governance-execution payload compatibility preserved.
* No authority-marker schema change; no sequence-file schema change; no
  trust-bundle core schema change; no authority lifecycle semantics
  change.
* Run 213 does not weaken any prior run (Runs 070, 130–212) and does not
  claim full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs`

The loaders perform read-only file I/O. The routing helpers perform no
I/O: no marker write, no sequence write, no live trust swap, no session
eviction, no Run 070 call.

### Additive optional sibling

* `GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD = "governance_execution"` —
  an additive optional sibling on the same v2 ratification sidecar JSON
  document already carrying the Run 167 `governance_authority_proof`,
  Run 184 `onchain_governance_proof`, Run 190
  `authority_custody_attestation`, Run 196 `remote_signer_attestation`,
  and Run 207 `custody_attestation` siblings.
* `GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION = 1`. An unknown
  version fails closed.

Following the Run 167 / 184 / 190 / 196 / 207 sibling-extraction pattern,
the sibling is extracted from the surrounding `serde_json::Value`
**before** the strict v2 sidecar parse, so old no-governance-execution
sidecars remain compatible, a malformed sibling fails closed, and an
absent sibling maps to a typed absent/unavailable status.

### Wire / context representation

* `GovernanceExecutionClassWire`, `GovernanceExecutionActionWire`,
  `GovernanceQuorumThresholdWire`.
* `GovernanceExecutionInputWire`, `GovernanceExecutionDecisionWire`,
  `GovernanceExecutionPayloadWire` (combining input + decision behind a
  `schema_version`).
* `GovernanceExecutionPayloadWire::to_parts` converts the wire form into
  the internal Run 211 `GovernanceExecutionInput` /
  `GovernanceExecutionDecision`; an unknown `schema_version` or an empty
  required field fails closed.
* `GovernanceExecutionLoadStatus` — `Absent` / `Available` / `Malformed`.
* `GovernanceExecutionWireParseError` /
  `GovernanceExecutionPayloadParseError` separate wire-form structural
  failures from JSON-shape failures.

The wire covers governance execution class, governance proposal id,
governance decision id, approved/rejected decision, authorized lifecycle
action, authorized authority root, authorized candidate digest, authorized
authority-domain sequence, environment, chain_id, genesis_hash, authority
root fingerprint, current / candidate / revoked signing-key fingerprints,
lifecycle action, candidate digest, authority-domain sequence, governance
proof digest, on-chain proof digest (where applicable), custody
attestation digest (where applicable), effective/activation epoch, expiry
epoch, replay nonce, quorum/threshold metadata, emergency flag, issuer /
authority class, and the placeholder decision commitment.

### Loaders + parse helper

* `parse_optional_governance_execution_sibling_from_json_value`.
* `load_v2_ratification_sidecar_with_governance_execution_from_path` and
  `..._from_bytes` returning the typed
  `qbind_ledger::BundleSigningRatificationV2` together with the Run 213
  `GovernanceExecutionLoadStatus`.

### Call-site context + routing

* `GovernanceExecutionCallsiteContext` bundles the active trust domain,
  the caller-derived `GovernanceExecutionExpectations`, and the active
  `GovernanceExecutionPolicy` (default `Disabled`).
* Seven per-surface routing helpers
  (`route_loaded_governance_execution_to_*_callsite_decision`) for
  reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local
  peer-candidate-check, live inbound `0x05`, and peer-driven drain.
* `GovernanceExecutionPayloadCarryingDecisionOutcome` adds, in front of
  the Run 211 outcome:
  * `MalformedGovernanceExecutionPayload` — present-but-malformed carrier
    fails closed before the evaluator;
  * `GovernanceExecutionRequiredButAbsent` — non-`Disabled` policy with an
    absent carrier fails closed;
  * `NoGovernanceExecutionSupplied` — `Disabled` policy + absent carrier,
    the legacy no-governance-execution payload compatibility bypass;
  * `MainNetPeerDrivenApplyRefused` — the peer-driven drain surface
    refuses MainNet unconditionally;
  * `Callsite(GovernanceExecutionOutcome)` — wraps the Run 211 outcome for
    every parsed, present carrier.
* Reachability helpers `evaluate_loaded_governance_execution` and
  `evaluate_loaded_governance_execution_with_peer_driven_guard` route the
  carried parts directly into the Run 211
  `evaluate_governance_execution_policy` /
  `evaluate_governance_execution_with_peer_driven_guard` evaluators.
* `mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying`.

## Required behavior (as implemented)

* Governance execution material can be carried through the production v2
  ratification sidecar payload/context layer at source/test level and
  routed into the seven production call-site contexts.
* Legacy no-governance-execution payloads remain accepted under the
  default `GovernanceExecutionPolicy::Disabled`.
* Fixture governance execution reaches and passes the production-context
  path on DevNet/TestNet where the explicit fixture policy allows.
* Production / on-chain / MainNet governance execution reaches the Run 211
  evaluator and fails closed as unavailable.
* Malformed / invalid governance execution material fails closed before
  the evaluator and before any mutation.
* Governance execution authorizes a lifecycle action only when the action,
  candidate digest, and sequence match.
* Validation-only surfaces remain non-mutating; mutating rejection paths
  produce no mutation.
* MainNet peer-driven apply remains refused even with fixture governance
  approval.

## Tests

`crates/qbind-node/tests/run_213_governance_execution_payload_callsite_tests.rs`

Covers A1–A16 and R1–R40 where representable at the payload/carrying +
production-context layer, serde/parse compatibility (legacy payload parses,
carrying payload parses, malformed input/decision/payload and unsupported
future schema version fail closed), digest determinism through wire
conversion (input / decision / transcript / policy digests), action
authorization (rotate / revoke / emergency-revoke / wrong action
fail-closed), source reachability (all seven surfaces reach the Run 211
evaluator), no-mutation invariants, and MainNet refusal invariants.

## Validation commands and results

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
  — PASS (61 tests).
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
  — PASS (55 tests).
* `cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests`
  — PASS.
* Additional task-listed regression targets exercise unchanged surfaces;
  Run 213 adds only a new source module and a new test target plus a
  documentation update, so they remain unaffected. If an exact target name
  differs in a later tree, locate the nearest existing target and document
  the exact command/result.

## Status of guarantees after Run 213

* Governance execution material can be carried through production
  payload/context paths at source/test level.
* Legacy no-governance-execution payloads remain compatible.
* Fixture governance execution remains DevNet/TestNet source/test only.
* Production / on-chain / MainNet governance execution remains
  unavailable/fail-closed.
* Governance execution payload/carrying evidence is source/test only.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* KMS/HSM/RemoteSigner/custody-attestation remain boundary-only.
* Release-binary governance-execution payload/carrying evidence is
  deferred to **Run 214**.
* Full C4 remains **OPEN**. C5 remains **OPEN**.