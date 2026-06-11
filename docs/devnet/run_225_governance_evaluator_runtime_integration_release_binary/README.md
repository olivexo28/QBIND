# Run 225 — Release-binary governance evaluator runtime integration evidence

## Scope

Run 225 is the release-binary evidence run for the Run 224 source/test
governance evaluator **runtime integration** layer in
`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`:

* the integration entry points
  (`integrate_governance_evaluator_runtime_consumption` and the
  sidecar-deriving convenience wrapper
  `integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value`);
* the `GovernanceEvaluatorRuntimeIntegrationContext` input bundle;
* the typed `GovernanceEvaluatorRuntimeIntegrationOutcome`
  (`ProceedLegacyBypass`, `ProceedMutate`, `RuntimeConsumptionFailClosed`,
  `EvaluatorRejected`, `MainNetPeerDrivenApplyRefused`).

The integration layer composes, in order:

* **Run 220** runtime consumption
  (`GovernanceExecutionRuntimeArmingConfig::consume_surface`);
* **Run 222** evaluator request / response / interface
  (`ProductionGovernanceExecutionEvaluator`);
* **Run 211** governance execution decision validation; and
* **Run 213** governance-execution payload material
  (`GovernanceExecutionLoadStatus`).

Where Run 224 proved the integration at the source/test level, Run 225
proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_225_governance_evaluator_runtime_integration_release_binary_helper.rs`,
driven by
`scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh`)
that the release-built code exposes and exercises the integration:

* runtime consumption composes with the evaluator interface in release mode;
* the evaluator request/response binding is deterministic and field-checked;
* mutation authorization (`ProceedMutate`) is produced only when **both** the
  Run 220 runtime-consumption stage and the Run 222 evaluator stage agree,
  after the documented ordering (selector resolution → sidecar/load-status
  derivation → runtime consumption → evaluator request construction →
  evaluator evaluation → governance execution decision validation → mutation
  only after all required checks pass);
* the default Disabled-policy + absent-carrier **legacy bypass** is preserved
  (`ProceedLegacyBypass`, Run 214 compatibility);
* the production / on-chain / MainNet evaluator boundaries are callable and
  return the typed unavailable / fail-closed `EvaluatorRejected` outcome;
* the fixture evaluator accepts only DevNet/TestNet decision sources, and the
  emergency-council fixture evaluator only an explicit emergency action;
* **MainNet peer-driven apply remains refused** even with a fixture evaluator
  approval (`MainNetPeerDrivenApplyRefused`);
* every rejection is non-mutating (the integration is a pure function).

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
exit_codes/
helper_evidence/run_225/
reachability/source_reachability.txt
reachability/module_registration.txt
reachability/run_220_consumption_reachability.txt
reachability/run_222_evaluator_reachability.txt
reachability/no_mutation_before_integration.txt
grep_summaries/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
test_results/
```

## Reproduce

```bash
bash scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 224 integration layer is typed and release-evidenced through
  library symbols. It has **no** runtime CLI/env selector and **no**
  production call-site wiring: it composes the Run 220 runtime consumption,
  the Run 222 evaluator interface, the Run 211 decision validation, and the
  Run 213 payload material as a *future* production evaluation pipeline, and
  the `Disabled` policy / `Disabled` evaluator policy remain inert, so the
  Run 221 runtime-consumption and Run 223 evaluator-interface behaviour are
  unchanged. Full positive `ProceedMutate` authorization with a real proposal
  binding is exercised through the release-built helper, which uses the same
  library symbols a future production call site would.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet evaluators are callable but always return the typed unavailable /
  fail-closed outcome, regardless of the resolved policy.
* No real on-chain governance proof verifier is implemented.
* The fixture evaluator remains DevNet/TestNet evidence-only and is refused
  on a MainNet trust domain.
* The emergency-council fixture evaluator is explicit and non-production.
* The integration layer is pure: it performs no network or file I/O, writes
  no marker, writes no sequence, mutates no live trust, evicts no sessions,
  and never invokes Run 070 apply. Validation-only and mutating-surface
  rejection paths therefore perform no mutation, and the only
  mutation-authorizing outcome is the terminal `ProceedMutate`.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even
  with a fixture evaluator approval.
* Full C4 remains open. C5 remains open.
