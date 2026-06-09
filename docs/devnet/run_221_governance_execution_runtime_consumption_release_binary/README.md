# Run 221 — Release-binary governance-execution runtime-consumption evidence

## Scope

Run 221 is the release-binary evidence run for the Run 220 governance-execution
runtime-**consumption** layer in
`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`:

* `GovernanceExecutionRuntimeConsumption` (`ProceedLegacyBypass` /
  `ProceedAccepted` / `FailClosed`);
* `GovernanceExecutionRuntimeArmingConfig::consume_surface`;
* `GovernanceExecutionRuntimeArmingConfig::consume_surface_from_optional_sidecar_value`;
* `governance_execution_load_status_from_optional_sidecar_value`.

Where Run 218 proved the Run 217 carrier *arms* the resolved policy and routes
it into the seven preflight surfaces (discarding the returned outcome at the
runtime call sites), Run 221 proves on real `target/release/qbind-node` plus a
release-built helper that the Run 220 consumption layer **consumes** the
`arm_surface` outcome into a typed three-way decision and acts on it:

* default remains `GovernanceExecutionPolicy::Disabled`;
* default Disabled + absent carrier consumes a `ProceedLegacyBypass` (Run 214
  legacy no-governance-execution compatibility);
* the hidden CLI flag `--p2p-trust-bundle-governance-execution-policy` and env
  var `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` reach runtime
  consumption;
* CLI-over-env precedence is deterministic at the runtime config boundary and
  invalid CLI/env values fail closed **before any runtime mutation**;
* the real governance-execution sidecar load status is consumed from the
  optional sidecar JSON value (`governance_execution_load_status_from_optional_sidecar_value`),
  not a forced `GovernanceExecutionLoadStatus::Absent`, where representable;
* the `consume_surface` verdict is consumed, not discarded
  (`consume_surface(..) == from_outcome(arm_surface(..))` for all seven
  surfaces, and the decision partitions Proceed / FailClosed exactly);
* fixture and emergency-council fixture governance are evidence-only and
  non-production;
* production/on-chain/MainNet governance execution remains
  unavailable/fail-closed;
* MainNet peer-driven apply remains refused even with
  `mainnet-governance-required` and fixture governance approval.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
exit_codes/
helper_evidence/run_221/
reachability/source_reachability.txt
reachability/cli_flag_reachability.txt
reachability/runtime_hook_reachability.txt
reachability/no_discarded_outcome.txt
reachability/no_forced_absent.txt
grep_summaries/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
test_results/
```

## Reproduce

```bash
bash scripts/devnet/run_221_governance_execution_runtime_consumption_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The hidden CLI/env selector for `GovernanceExecutionPolicy` is additive and
  disabled by default; default behaviour remains
  `GovernanceExecutionPolicy::Disabled`. An invalid CLI or env selector value
  fails closed with the Run 217 FATAL — the runtime config is never armed and
  no consumption runs — and CLI-over-env precedence is deterministic. There is
  no schema / wire / metric drift.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet governance execution always consumes the typed unavailable /
  fail-closed outcome, regardless of the resolved policy.
* No real on-chain governance proof verifier is implemented.
* Fixture governance execution remains DevNet/TestNet evidence-only and is
  refused on a MainNet trust domain.
* Emergency council fixture governance is explicit and non-production.
* The binary's marker-decision candidate metadata does not carry the
  governance proposal/decision bindings, so the derived
  `GovernanceExecutionExpectations` leave those fields empty: a present,
  well-formed carrier under an explicit policy on the real binary therefore
  reaches the Run 211 evaluator and fails closed on the expectation mismatch.
  Full positive binary acceptance with a real proposal binding is consumed
  through the release-built helper using library symbols, which exercises the
  same consumption API the runtime call sites use. Default `Disabled` + absent
  carrier remains a clean `ProceedLegacyBypass` on the real binary.
* The live inbound `0x05` runtime path does not yet thread a per-connection
  governance-execution policy from its live runtime config; the consumption
  layer exposes the policy/sidecar injection at the source/test level so the
  resolved policy reaches the Run 213 live inbound `0x05` routing helper and an
  invalid live `0x05` candidate is consumed as `FailClosed` (not propagated,
  staged, or applied). This is the documented A16/R27 limitation.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even with
  a fixture governance approval.
* Full C4 remains open. C5 remains open.